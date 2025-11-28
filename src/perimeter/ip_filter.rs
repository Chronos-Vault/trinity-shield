//! IP filtering and geofencing

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Result of IP filtering
#[derive(Debug, Clone)]
pub enum IpFilterResult {
    /// IP is allowed
    Allowed,
    /// IP is blocked with reason
    Blocked(String),
}

/// IP filter with allowlist, blocklist, and geofencing
pub struct IpFilter {
    /// Allowlist (empty = allow all not in blocklist)
    allowlist: RwLock<Vec<IpRange>>,
    /// Blocklist
    blocklist: RwLock<BTreeMap<String, String>>, // IP -> reason
    /// Enable geofencing
    geofencing_enabled: bool,
    /// Allowed country codes
    allowed_countries: Vec<String>,
}

/// IP range for CIDR notation
#[derive(Clone)]
pub struct IpRange {
    /// Base IP as bytes
    base: [u8; 4],
    /// Prefix length (e.g., 24 for /24)
    prefix_len: u8,
}

impl IpRange {
    /// Parse IP or CIDR range
    pub fn parse(input: &str) -> Option<Self> {
        let parts: Vec<&str> = input.split('/').collect();
        
        let ip_str = parts.first()?;
        let prefix_len = parts.get(1)
            .map(|s| s.parse().ok())
            .flatten()
            .unwrap_or(32);
        
        let octets: Vec<u8> = ip_str
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if octets.len() != 4 {
            return None;
        }
        
        let mut base = [0u8; 4];
        base.copy_from_slice(&octets);
        
        Some(Self { base, prefix_len })
    }
    
    /// Check if an IP is in this range
    pub fn contains(&self, ip: &str) -> bool {
        let octets: Vec<u8> = ip
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if octets.len() != 4 {
            return false;
        }
        
        let mut ip_bytes = [0u8; 4];
        ip_bytes.copy_from_slice(&octets);
        
        // Apply mask and compare
        let mask = if self.prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        
        let ip_masked = u32::from_be_bytes(ip_bytes) & mask;
        let base_masked = u32::from_be_bytes(self.base) & mask;
        
        ip_masked == base_masked
    }
}

impl IpFilter {
    /// Create a new IP filter
    pub fn new(
        allowlist: Vec<String>,
        blocklist: Vec<String>,
        geofencing_enabled: bool,
        allowed_countries: Vec<String>,
    ) -> Self {
        let allowlist: Vec<IpRange> = allowlist
            .iter()
            .filter_map(|s| IpRange::parse(s))
            .collect();
        
        let blocklist: BTreeMap<String, String> = blocklist
            .into_iter()
            .map(|ip| (ip, "Configured in blocklist".into()))
            .collect();
        
        Self {
            allowlist: RwLock::new(allowlist),
            blocklist: RwLock::new(blocklist),
            geofencing_enabled,
            allowed_countries,
        }
    }
    
    /// Check if an IP is allowed
    pub fn check(&self, ip: &str) -> IpFilterResult {
        // Check blocklist first (highest priority)
        if let Ok(blocklist) = self.blocklist.read() {
            if let Some(reason) = blocklist.get(ip) {
                return IpFilterResult::Blocked(reason.clone());
            }
            
            // Check if IP matches any blocked range
            for (blocked_ip, reason) in blocklist.iter() {
                if let Some(range) = IpRange::parse(blocked_ip) {
                    if range.contains(ip) {
                        return IpFilterResult::Blocked(reason.clone());
                    }
                }
            }
        }
        
        // Check allowlist if not empty
        if let Ok(allowlist) = self.allowlist.read() {
            if !allowlist.is_empty() {
                let allowed = allowlist.iter().any(|range| range.contains(ip));
                if !allowed {
                    return IpFilterResult::Blocked("IP not in allowlist".into());
                }
            }
        }
        
        // Check geofencing (would require GeoIP database in production)
        if self.geofencing_enabled && !self.allowed_countries.is_empty() {
            // In production, look up country from GeoIP database
            // For now, allow all if geofencing is enabled but we can't determine country
            // This is a fail-open approach; use fail-closed in production
        }
        
        IpFilterResult::Allowed
    }
    
    /// Add an IP to the blocklist
    pub fn add_block(&self, ip: String, reason: String) {
        if let Ok(mut blocklist) = self.blocklist.write() {
            blocklist.insert(ip, reason);
        }
    }
    
    /// Remove an IP from the blocklist
    pub fn remove_block(&self, ip: &str) {
        if let Ok(mut blocklist) = self.blocklist.write() {
            blocklist.remove(ip);
        }
    }
    
    /// Add an IP range to the allowlist
    pub fn add_allow(&self, range: &str) {
        if let Some(ip_range) = IpRange::parse(range) {
            if let Ok(mut allowlist) = self.allowlist.write() {
                allowlist.push(ip_range);
            }
        }
    }
    
    /// Check if blocklist is empty
    pub fn blocklist_is_empty(&self) -> bool {
        self.blocklist.read().map(|b| b.is_empty()).unwrap_or(true)
    }
    
    /// Get number of blocked IPs
    pub fn blocked_count(&self) -> usize {
        self.blocklist.read().map(|b| b.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_range_parse() {
        let range = IpRange::parse("192.168.1.0/24").unwrap();
        assert!(range.contains("192.168.1.1"));
        assert!(range.contains("192.168.1.255"));
        assert!(!range.contains("192.168.2.1"));
    }
    
    #[test]
    fn test_single_ip() {
        let range = IpRange::parse("10.0.0.1").unwrap();
        assert!(range.contains("10.0.0.1"));
        assert!(!range.contains("10.0.0.2"));
    }
    
    #[test]
    fn test_filter_blocklist() {
        let filter = IpFilter::new(
            vec![],
            vec!["192.168.1.100".into()],
            false,
            vec![],
        );
        
        match filter.check("192.168.1.100") {
            IpFilterResult::Blocked(_) => {}
            IpFilterResult::Allowed => panic!("Should be blocked"),
        }
        
        match filter.check("192.168.1.1") {
            IpFilterResult::Allowed => {}
            IpFilterResult::Blocked(_) => panic!("Should be allowed"),
        }
    }
    
    #[test]
    fn test_filter_allowlist() {
        let filter = IpFilter::new(
            vec!["10.0.0.0/8".into()],
            vec![],
            false,
            vec![],
        );
        
        match filter.check("10.1.2.3") {
            IpFilterResult::Allowed => {}
            IpFilterResult::Blocked(_) => panic!("Should be allowed"),
        }
        
        match filter.check("192.168.1.1") {
            IpFilterResult::Blocked(_) => {}
            IpFilterResult::Allowed => panic!("Should be blocked"),
        }
    }
    
    #[test]
    fn test_blocklist_priority() {
        // Blocklist should have priority over allowlist
        let filter = IpFilter::new(
            vec!["10.0.0.0/8".into()],
            vec!["10.0.0.1".into()],
            false,
            vec![],
        );
        
        match filter.check("10.0.0.1") {
            IpFilterResult::Blocked(_) => {}
            IpFilterResult::Allowed => panic!("Should be blocked"),
        }
    }
    
    #[test]
    fn test_dynamic_blocking() {
        let filter = IpFilter::new(vec![], vec![], false, vec![]);
        
        // Initially allowed
        match filter.check("1.2.3.4") {
            IpFilterResult::Allowed => {}
            _ => panic!("Should be allowed"),
        }
        
        // Block it
        filter.add_block("1.2.3.4".into(), "Suspicious activity".into());
        
        // Now blocked
        match filter.check("1.2.3.4") {
            IpFilterResult::Blocked(_) => {}
            _ => panic!("Should be blocked"),
        }
        
        // Unblock it
        filter.remove_block("1.2.3.4");
        
        // Allowed again
        match filter.check("1.2.3.4") {
            IpFilterResult::Allowed => {}
            _ => panic!("Should be allowed"),
        }
    }
}
