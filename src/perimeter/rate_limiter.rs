//! Token bucket rate limiter

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Token bucket rate limiter
/// 
/// Each source gets a bucket with tokens that refill over time.
/// Requests consume tokens; empty bucket = rate limited.
pub struct RateLimiter {
    /// Tokens per second (refill rate)
    rate: u32,
    /// Maximum tokens (burst capacity)
    burst: u32,
    /// Buckets per source IP
    #[cfg(feature = "std")]
    buckets: RwLock<BTreeMap<String, TokenBucket>>,
    #[cfg(not(feature = "std"))]
    buckets: RwLock<BTreeMap<String, TokenBucket>>,
}

struct TokenBucket {
    /// Current token count (scaled by 1000 for precision)
    tokens: u64,
    /// Last update timestamp (milliseconds)
    last_update: u64,
}

impl TokenBucket {
    fn new(max_tokens: u32) -> Self {
        Self {
            tokens: (max_tokens as u64) * 1000,
            last_update: current_time_ms(),
        }
    }
    
    fn refill(&mut self, rate: u32, max: u32) {
        let now = current_time_ms();
        let elapsed = now.saturating_sub(self.last_update);
        
        if elapsed > 0 {
            // Add tokens based on elapsed time
            let new_tokens = (elapsed * rate as u64) / 1000;
            self.tokens = self.tokens.saturating_add(new_tokens * 1000);
            self.tokens = self.tokens.min((max as u64) * 1000);
            self.last_update = now;
        }
    }
    
    fn consume(&mut self, tokens: u32) -> bool {
        let needed = (tokens as u64) * 1000;
        if self.tokens >= needed {
            self.tokens -= needed;
            true
        } else {
            false
        }
    }
    
    fn time_until_refill(&self, rate: u32) -> u64 {
        if self.tokens >= 1000 {
            0
        } else {
            let needed = 1000 - self.tokens;
            (needed * 1000) / (rate as u64 * 1000)
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter
    /// 
    /// # Arguments
    /// * `rate` - Tokens per second
    /// * `burst` - Maximum tokens (burst capacity)
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate,
            burst,
            buckets: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// Check if a request from source should be allowed
    /// 
    /// # Returns
    /// * `Ok(())` if allowed
    /// * `Err(retry_after_seconds)` if rate limited
    pub fn check(&self, source: &str) -> Result<(), u64> {
        self.consume(source, 1)
    }
    
    /// Consume tokens from a source's bucket
    /// 
    /// # Returns
    /// * `Ok(())` if tokens available
    /// * `Err(retry_after_seconds)` if insufficient tokens
    pub fn consume(&self, source: &str, tokens: u32) -> Result<(), u64> {
        let mut buckets = self.buckets.write()
            .map_err(|_| 1u64)?;
        
        let bucket = buckets
            .entry(source.into())
            .or_insert_with(|| TokenBucket::new(self.burst));
        
        // Refill tokens based on elapsed time
        bucket.refill(self.rate, self.burst);
        
        // Try to consume
        if bucket.consume(tokens) {
            Ok(())
        } else {
            Err(bucket.time_until_refill(self.rate).max(1))
        }
    }
    
    /// Get remaining tokens for a source
    pub fn remaining(&self, source: &str) -> u64 {
        let buckets = match self.buckets.read() {
            Ok(b) => b,
            Err(_) => return 0,
        };
        
        buckets
            .get(source)
            .map(|b| b.tokens / 1000)
            .unwrap_or(self.burst as u64)
    }
    
    /// Clear all buckets
    pub fn clear(&self) {
        if let Ok(mut buckets) = self.buckets.write() {
            buckets.clear();
        }
    }
    
    /// Clean up old buckets (call periodically)
    pub fn cleanup(&self, max_age_ms: u64) {
        let now = current_time_ms();
        
        if let Ok(mut buckets) = self.buckets.write() {
            buckets.retain(|_, bucket| {
                now.saturating_sub(bucket.last_update) < max_age_ms
            });
        }
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
        // In no_std, use a monotonic counter
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(10, 10);
        
        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.check("test").is_ok());
        }
    }
    
    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(10, 10);
        
        // Exhaust tokens
        for _ in 0..10 {
            let _ = limiter.check("test");
        }
        
        // 11th request should fail
        assert!(limiter.check("test").is_err());
    }
    
    #[test]
    fn test_rate_limiter_separate_sources() {
        let limiter = RateLimiter::new(2, 2);
        
        // Source A uses up tokens
        assert!(limiter.check("source_a").is_ok());
        assert!(limiter.check("source_a").is_ok());
        assert!(limiter.check("source_a").is_err());
        
        // Source B should still have tokens
        assert!(limiter.check("source_b").is_ok());
    }
    
    #[test]
    fn test_remaining_tokens() {
        let limiter = RateLimiter::new(10, 10);
        
        assert_eq!(limiter.remaining("new_source"), 10);
        
        limiter.check("test").unwrap();
        assert_eq!(limiter.remaining("test"), 9);
    }
}
