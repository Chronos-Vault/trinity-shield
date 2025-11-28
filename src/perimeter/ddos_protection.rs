//! DDoS protection with circuit breaker pattern

use crate::types::RequestSource;

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// DDoS protection using circuit breaker pattern
/// 
/// Monitors request patterns and trips a circuit breaker when
/// suspicious activity is detected, temporarily blocking all
/// requests from that source.
pub struct DDoSProtection {
    /// Global request threshold (requests per second)
    threshold: u32,
    /// Per-source tracking
    sources: RwLock<BTreeMap<String, SourceTracker>>,
    /// Global circuit breaker
    global_circuit_open: AtomicBool,
    /// Global request counter
    global_counter: AtomicU64,
    /// Last reset timestamp
    last_reset: AtomicU64,
}

struct SourceTracker {
    /// Request count in current window
    count: u64,
    /// Window start time
    window_start: u64,
    /// Circuit breaker state
    circuit_open: bool,
    /// Circuit open until timestamp
    circuit_open_until: u64,
    /// Consecutive circuit trips
    trip_count: u32,
}

impl SourceTracker {
    fn new(now: u64) -> Self {
        Self {
            count: 0,
            window_start: now,
            circuit_open: false,
            circuit_open_until: 0,
            trip_count: 0,
        }
    }
    
    fn record(&mut self, now: u64, threshold: u32) -> bool {
        const WINDOW_MS: u64 = 1000; // 1 second window
        
        // Check if circuit is open
        if self.circuit_open {
            if now < self.circuit_open_until {
                return false;
            }
            // Reset circuit
            self.circuit_open = false;
        }
        
        // Reset window if needed
        if now - self.window_start >= WINDOW_MS {
            self.count = 0;
            self.window_start = now;
            // Decay trip count over time
            if self.trip_count > 0 {
                self.trip_count = self.trip_count.saturating_sub(1);
            }
        }
        
        // Increment counter
        self.count += 1;
        
        // Check threshold
        if self.count > threshold as u64 {
            self.trip_circuit(now);
            return false;
        }
        
        true
    }
    
    fn trip_circuit(&mut self, now: u64) {
        self.circuit_open = true;
        self.trip_count += 1;
        
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
        let backoff = (1000u64 * (1 << self.trip_count.min(6))).min(60000);
        self.circuit_open_until = now + backoff;
    }
}

impl DDoSProtection {
    /// Create new DDoS protection
    /// 
    /// # Arguments
    /// * `threshold` - Maximum requests per second per source
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            sources: RwLock::new(BTreeMap::new()),
            global_circuit_open: AtomicBool::new(false),
            global_counter: AtomicU64::new(0),
            last_reset: AtomicU64::new(current_time_ms()),
        }
    }
    
    /// Check if request should be allowed
    /// 
    /// # Returns
    /// * `true` if allowed
    /// * `false` if blocked by DDoS protection
    pub fn check(&self, source: &RequestSource) -> bool {
        let now = current_time_ms();
        
        // Check global circuit breaker
        if self.global_circuit_open.load(Ordering::Relaxed) {
            return false;
        }
        
        // Update global counter
        self.update_global_counter(now);
        
        // Check per-source limits
        self.check_source(&source.ip_address, now)
    }
    
    fn update_global_counter(&self, now: u64) {
        let last_reset = self.last_reset.load(Ordering::Relaxed);
        
        if now - last_reset >= 1000 {
            // Reset counter every second
            if self.last_reset.compare_exchange(
                last_reset,
                now,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ).is_ok() {
                self.global_counter.store(0, Ordering::Relaxed);
            }
        }
        
        self.global_counter.fetch_add(1, Ordering::Relaxed);
    }
    
    fn check_source(&self, ip: &str, now: u64) -> bool {
        let mut sources = match self.sources.write() {
            Ok(s) => s,
            Err(_) => return false, // Fail closed on lock error
        };
        
        let tracker = sources
            .entry(ip.into())
            .or_insert_with(|| SourceTracker::new(now));
        
        tracker.record(now, self.threshold)
    }
    
    /// Trip the global circuit breaker
    pub fn trip_global(&self) {
        self.global_circuit_open.store(true, Ordering::Release);
    }
    
    /// Reset the global circuit breaker
    pub fn reset_global(&self) {
        self.global_circuit_open.store(false, Ordering::Release);
    }
    
    /// Check if global circuit is open
    pub fn is_global_circuit_open(&self) -> bool {
        self.global_circuit_open.load(Ordering::Acquire)
    }
    
    /// Get global request rate (approximate)
    pub fn global_rate(&self) -> u64 {
        self.global_counter.load(Ordering::Relaxed)
    }
    
    /// Clean up old source trackers
    pub fn cleanup(&self, max_age_ms: u64) {
        let now = current_time_ms();
        
        if let Ok(mut sources) = self.sources.write() {
            sources.retain(|_, tracker| {
                !tracker.circuit_open && 
                    now - tracker.window_start < max_age_ms
            });
        }
    }
    
    /// Get number of tracked sources
    pub fn tracked_sources(&self) -> usize {
        self.sources.read().map(|s| s.len()).unwrap_or(0)
    }
    
    /// Get number of sources with open circuits
    pub fn open_circuits(&self) -> usize {
        self.sources
            .read()
            .map(|s| s.values().filter(|t| t.circuit_open).count())
            .unwrap_or(0)
    }
}

fn current_time_ms() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    
    #[cfg(not(feature = "std"))]
    {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RequestSource;
    
    fn test_source(ip: &str) -> RequestSource {
        RequestSource {
            ip_address: ip.into(),
            user_agent: None,
            timestamp: 0,
            chain_id: None,
        }
    }
    
    #[test]
    fn test_allows_normal_traffic() {
        let ddos = DDoSProtection::new(100);
        let source = test_source("192.168.1.1");
        
        // Should allow up to threshold
        for _ in 0..50 {
            assert!(ddos.check(&source));
        }
    }
    
    #[test]
    fn test_blocks_flood() {
        let ddos = DDoSProtection::new(10);
        let source = test_source("192.168.1.1");
        
        // Flood with requests
        let mut blocked = false;
        for _ in 0..100 {
            if !ddos.check(&source) {
                blocked = true;
                break;
            }
        }
        
        assert!(blocked, "Should have blocked some requests");
    }
    
    #[test]
    fn test_separate_sources() {
        let ddos = DDoSProtection::new(5);
        
        let source1 = test_source("1.1.1.1");
        let source2 = test_source("2.2.2.2");
        
        // Exhaust source1
        for _ in 0..10 {
            ddos.check(&source1);
        }
        
        // Source2 should still work
        assert!(ddos.check(&source2));
    }
    
    #[test]
    fn test_global_circuit() {
        let ddos = DDoSProtection::new(100);
        let source = test_source("1.1.1.1");
        
        assert!(ddos.check(&source));
        
        ddos.trip_global();
        assert!(!ddos.check(&source));
        
        ddos.reset_global();
        assert!(ddos.check(&source));
    }
    
    #[test]
    fn test_cleanup() {
        let ddos = DDoSProtection::new(100);
        
        for i in 0..10 {
            let source = test_source(&format!("192.168.1.{}", i));
            ddos.check(&source);
        }
        
        assert_eq!(ddos.tracked_sources(), 10);
        
        ddos.cleanup(0); // Clean all
        assert_eq!(ddos.tracked_sources(), 0);
    }
}
