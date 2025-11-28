//! Perimeter Shield - Network boundary protection
//! 
//! The first line of defense in Trinity Shield, handling:
//! - Rate limiting with token bucket algorithm
//! - DDoS protection with circuit breakers
//! - IP filtering and geofencing
//! - Request validation and sanitization

use crate::config::PerimeterConfig;
use crate::error::{ShieldError, ShieldResult};
use crate::types::{PerimeterStats, RequestSource};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod rate_limiter;
mod ip_filter;
mod ddos_protection;
mod request_validator;

pub use rate_limiter::*;
pub use ip_filter::*;
pub use ddos_protection::*;
pub use request_validator::*;

/// Perimeter Shield - Network boundary protection layer
pub struct PerimeterShield {
    /// Configuration
    config: PerimeterConfig,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// IP filter
    ip_filter: IpFilter,
    /// DDoS protection
    ddos_protection: DDoSProtection,
    /// Request validator
    request_validator: RequestValidator,
    /// Statistics
    stats: PerimeterStatsInternal,
}

struct PerimeterStatsInternal {
    requests_allowed: AtomicU64,
    rate_limited: AtomicU64,
    ip_blocked: AtomicU64,
    ddos_blocked: AtomicU64,
}

impl Default for PerimeterStatsInternal {
    fn default() -> Self {
        Self {
            requests_allowed: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ip_blocked: AtomicU64::new(0),
            ddos_blocked: AtomicU64::new(0),
        }
    }
}

impl PerimeterShield {
    /// Create a new Perimeter Shield
    pub fn new(config: &PerimeterConfig) -> ShieldResult<Self> {
        let rate_limiter = RateLimiter::new(
            config.rate_limit_per_second,
            config.rate_limit_burst,
        );
        
        let ip_filter = IpFilter::new(
            config.ip_allowlist.clone(),
            config.ip_blocklist.clone(),
            config.geofencing_enabled,
            config.allowed_countries.clone(),
        );
        
        let ddos_protection = DDoSProtection::new(config.ddos_threshold);
        
        let request_validator = RequestValidator::new(config.max_request_size);
        
        Ok(Self {
            config: config.clone(),
            rate_limiter,
            ip_filter,
            ddos_protection,
            request_validator,
            stats: PerimeterStatsInternal::default(),
        })
    }
    
    /// Check rate limit for a source
    pub fn check_rate_limit(&self, source: &RequestSource) -> ShieldResult<()> {
        if !self.config.rate_limit_enabled {
            return Ok(());
        }
        
        match self.rate_limiter.check(&source.ip_address) {
            Ok(()) => {
                self.stats.requests_allowed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(retry_after) => {
                self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                Err(ShieldError::RateLimitExceeded { retry_after })
            }
        }
    }
    
    /// Check if IP address is allowed
    pub fn check_ip_allowed(&self, source: &RequestSource) -> ShieldResult<()> {
        match self.ip_filter.check(&source.ip_address) {
            IpFilterResult::Allowed => Ok(()),
            IpFilterResult::Blocked(reason) => {
                self.stats.ip_blocked.fetch_add(1, Ordering::Relaxed);
                Err(ShieldError::IpBlocked { reason })
            }
        }
    }
    
    /// Validate request size and basic format
    pub fn validate_request_size(&self, request: &[u8]) -> ShieldResult<()> {
        self.request_validator.validate_size(request)
    }
    
    /// Full request validation (size + format + DDoS check)
    pub fn validate_request(
        &self,
        request: &[u8],
        source: &RequestSource,
    ) -> ShieldResult<()> {
        // Check DDoS protection
        if self.config.ddos_protection_enabled {
            if !self.ddos_protection.check(source) {
                self.stats.ddos_blocked.fetch_add(1, Ordering::Relaxed);
                return Err(ShieldError::DDoSProtection);
            }
        }
        
        // Check IP filter
        self.check_ip_allowed(source)?;
        
        // Check rate limit
        self.check_rate_limit(source)?;
        
        // Validate request
        self.request_validator.validate(request)?;
        
        Ok(())
    }
    
    /// Add IP to blocklist
    pub fn block_ip(&mut self, ip: &str, reason: &str) {
        self.ip_filter.add_block(ip.into(), reason.into());
    }
    
    /// Remove IP from blocklist
    pub fn unblock_ip(&mut self, ip: &str) {
        self.ip_filter.remove_block(ip);
    }
    
    /// Get current statistics
    pub fn stats(&self) -> PerimeterStats {
        PerimeterStats {
            requests_allowed: self.stats.requests_allowed.load(Ordering::Relaxed),
            rate_limited: self.stats.rate_limited.load(Ordering::Relaxed),
            ip_blocked: self.stats.ip_blocked.load(Ordering::Relaxed),
            ddos_blocked: self.stats.ddos_blocked.load(Ordering::Relaxed),
        }
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        self.stats.requests_allowed.store(0, Ordering::Relaxed);
        self.stats.rate_limited.store(0, Ordering::Relaxed);
        self.stats.ip_blocked.store(0, Ordering::Relaxed);
        self.stats.ddos_blocked.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_config() -> PerimeterConfig {
        PerimeterConfig {
            rate_limit_enabled: true,
            rate_limit_per_second: 10,
            rate_limit_burst: 20,
            max_request_size: 1024,
            ddos_protection_enabled: true,
            ddos_threshold: 1000,
            ip_allowlist: vec![],
            ip_blocklist: vec!["192.168.1.100".into()],
            geofencing_enabled: false,
            allowed_countries: vec![],
        }
    }
    
    fn test_source(ip: &str) -> RequestSource {
        RequestSource {
            ip_address: ip.into(),
            user_agent: None,
            timestamp: 0,
            chain_id: None,
        }
    }
    
    #[test]
    fn test_shield_creation() {
        let config = test_config();
        let shield = PerimeterShield::new(&config);
        assert!(shield.is_ok());
    }
    
    #[test]
    fn test_ip_blocking() {
        let config = test_config();
        let shield = PerimeterShield::new(&config).unwrap();
        
        let blocked_source = test_source("192.168.1.100");
        let allowed_source = test_source("192.168.1.1");
        
        assert!(shield.check_ip_allowed(&blocked_source).is_err());
        assert!(shield.check_ip_allowed(&allowed_source).is_ok());
    }
    
    #[test]
    fn test_request_size_validation() {
        let config = test_config();
        let shield = PerimeterShield::new(&config).unwrap();
        
        let small_request = vec![0u8; 100];
        let large_request = vec![0u8; 2000];
        
        assert!(shield.validate_request_size(&small_request).is_ok());
        assert!(shield.validate_request_size(&large_request).is_err());
    }
}
