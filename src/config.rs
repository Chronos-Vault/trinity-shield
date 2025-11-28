//! Configuration for Trinity Shield
//! 
//! Provides secure configuration management with validation
//! and sensible defaults for all shield layers.

use crate::types::ChainId;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Main shield configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Perimeter shield configuration
    pub perimeter: PerimeterConfig,
    /// Application shield configuration
    pub application: ApplicationConfig,
    /// Data shield configuration
    pub data: DataConfig,
    /// Consensus engine configuration
    pub consensus: ConsensusConfig,
    /// Attestation service configuration
    pub attestation: AttestationConfig,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            perimeter: PerimeterConfig::default(),
            application: ApplicationConfig::default(),
            data: DataConfig::default(),
            consensus: ConsensusConfig::default(),
            attestation: AttestationConfig::default(),
        }
    }
}

impl ShieldConfig {
    /// Create configuration for a specific chain
    pub fn for_chain(chain_id: ChainId) -> Self {
        let mut config = Self::default();
        config.consensus.chain_id = chain_id;
        
        // Adjust settings based on chain characteristics
        match chain_id {
            ChainId::Arbitrum => {
                // Primary security chain - balanced settings
                config.perimeter.rate_limit_per_second = 100;
                config.data.key_rotation_interval_hours = 24;
            }
            ChainId::Solana => {
                // High-frequency monitoring - higher rate limits
                config.perimeter.rate_limit_per_second = 1000;
                config.application.session_timeout_seconds = 300;
            }
            ChainId::Ton => {
                // Quantum recovery chain - stricter security
                config.perimeter.rate_limit_per_second = 50;
                config.data.use_quantum_resistant = true;
                config.consensus.require_all_validators = true;
            }
        }
        
        config
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        self.perimeter.validate()?;
        self.application.validate()?;
        self.data.validate()?;
        self.consensus.validate()?;
        self.attestation.validate()?;
        Ok(())
    }
}

/// Perimeter shield configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerimeterConfig {
    /// Enable rate limiting
    pub rate_limit_enabled: bool,
    /// Requests per second per source
    pub rate_limit_per_second: u32,
    /// Burst capacity (token bucket)
    pub rate_limit_burst: u32,
    /// Maximum request size in bytes
    pub max_request_size: usize,
    /// Enable DDoS protection
    pub ddos_protection_enabled: bool,
    /// DDoS threshold (requests per second triggering protection)
    pub ddos_threshold: u32,
    /// IP allowlist (empty = allow all)
    pub ip_allowlist: Vec<String>,
    /// IP blocklist
    pub ip_blocklist: Vec<String>,
    /// Enable geofencing
    pub geofencing_enabled: bool,
    /// Allowed country codes (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,
}

impl Default for PerimeterConfig {
    fn default() -> Self {
        Self {
            rate_limit_enabled: true,
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            max_request_size: 1024 * 1024, // 1MB
            ddos_protection_enabled: true,
            ddos_threshold: 10000,
            ip_allowlist: Vec::new(),
            ip_blocklist: Vec::new(),
            geofencing_enabled: false,
            allowed_countries: Vec::new(),
        }
    }
}

impl PerimeterConfig {
    fn validate(&self) -> Result<(), String> {
        if self.rate_limit_per_second == 0 {
            return Err("rate_limit_per_second must be > 0".into());
        }
        if self.rate_limit_burst < self.rate_limit_per_second {
            return Err("rate_limit_burst must be >= rate_limit_per_second".into());
        }
        if self.max_request_size == 0 {
            return Err("max_request_size must be > 0".into());
        }
        Ok(())
    }
}

/// Application shield configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    /// Enable signature verification
    pub require_signatures: bool,
    /// Supported signature algorithms
    pub allowed_algorithms: Vec<String>,
    /// Session timeout in seconds
    pub session_timeout_seconds: u64,
    /// Maximum session duration in seconds
    pub max_session_duration_seconds: u64,
    /// Enable nonce checking for replay protection
    pub nonce_checking_enabled: bool,
    /// Nonce window size (how many future nonces to accept)
    pub nonce_window: u64,
    /// Enable input validation
    pub input_validation_enabled: bool,
    /// Maximum field length for validation
    pub max_field_length: usize,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            require_signatures: true,
            allowed_algorithms: vec![
                "ed25519".into(),
                "secp256k1".into(),
                "dilithium5".into(),
            ],
            session_timeout_seconds: 3600, // 1 hour
            max_session_duration_seconds: 86400, // 24 hours
            nonce_checking_enabled: true,
            nonce_window: 100,
            input_validation_enabled: true,
            max_field_length: 10000,
        }
    }
}

impl ApplicationConfig {
    fn validate(&self) -> Result<(), String> {
        if self.session_timeout_seconds == 0 {
            return Err("session_timeout_seconds must be > 0".into());
        }
        if self.max_session_duration_seconds < self.session_timeout_seconds {
            return Err("max_session_duration must be >= session_timeout".into());
        }
        if self.allowed_algorithms.is_empty() && self.require_signatures {
            return Err("must specify allowed_algorithms when requiring signatures".into());
        }
        Ok(())
    }
}

/// Data shield configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataConfig {
    /// Encryption algorithm for data at rest
    pub encryption_algorithm: String,
    /// Key size in bits
    pub key_size_bits: u32,
    /// Enable key rotation
    pub key_rotation_enabled: bool,
    /// Key rotation interval in hours
    pub key_rotation_interval_hours: u32,
    /// Enable data integrity checking
    pub integrity_checking_enabled: bool,
    /// Use quantum-resistant algorithms
    pub use_quantum_resistant: bool,
    /// Sealing policy (MRENCLAVE or MRSIGNER)
    pub seal_policy: String,
    /// Enable secure deletion
    pub secure_deletion_enabled: bool,
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            encryption_algorithm: "aes-256-gcm".into(),
            key_size_bits: 256,
            key_rotation_enabled: true,
            key_rotation_interval_hours: 168, // 1 week
            integrity_checking_enabled: true,
            use_quantum_resistant: false,
            seal_policy: "mrenclave".into(),
            secure_deletion_enabled: true,
        }
    }
}

impl DataConfig {
    fn validate(&self) -> Result<(), String> {
        let valid_algorithms = ["aes-256-gcm", "chacha20-poly1305"];
        if !valid_algorithms.contains(&self.encryption_algorithm.as_str()) {
            return Err(format!(
                "encryption_algorithm must be one of: {:?}",
                valid_algorithms
            ));
        }
        if self.key_size_bits < 128 {
            return Err("key_size_bits must be >= 128".into());
        }
        let valid_policies = ["mrenclave", "mrsigner"];
        if !valid_policies.contains(&self.seal_policy.as_str()) {
            return Err(format!(
                "seal_policy must be one of: {:?}",
                valid_policies
            ));
        }
        Ok(())
    }
}

/// Consensus engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Chain ID for this validator
    pub chain_id: ChainId,
    /// Minimum approvals required (2-of-3)
    pub required_approvals: u8,
    /// Total validators in the system
    pub total_validators: u8,
    /// Require all validators for emergency operations
    pub require_all_validators: bool,
    /// Maximum operation age in seconds
    pub max_operation_age_seconds: u64,
    /// Enable Lean proof verification
    pub lean_verification_enabled: bool,
    /// Timeout for vote collection in seconds
    pub vote_timeout_seconds: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::Arbitrum,
            required_approvals: 2,
            total_validators: 3,
            require_all_validators: false,
            max_operation_age_seconds: 300, // 5 minutes
            lean_verification_enabled: true,
            vote_timeout_seconds: 60,
        }
    }
}

impl ConsensusConfig {
    fn validate(&self) -> Result<(), String> {
        if self.required_approvals > self.total_validators {
            return Err("required_approvals cannot exceed total_validators".into());
        }
        if self.required_approvals < 2 {
            return Err("required_approvals must be >= 2 for Byzantine fault tolerance".into());
        }
        if self.total_validators < 3 {
            return Err("total_validators must be >= 3 for 2-of-3 consensus".into());
        }
        Ok(())
    }
}

/// Attestation service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Enable attestation
    pub attestation_enabled: bool,
    /// Attestation validity period in seconds
    pub attestation_validity_seconds: u64,
    /// Auto-refresh threshold (seconds before expiry)
    pub refresh_threshold_seconds: u64,
    /// Expected MRENCLAVE value (for verification)
    pub expected_mrenclave: [u8; 32],
    /// Expected MRSIGNER value
    pub expected_mrsigner: [u8; 32],
    /// Intel Attestation Service URL (for EPID attestation)
    pub ias_url: String,
    /// Use DCAP attestation instead of EPID
    pub use_dcap: bool,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            attestation_enabled: true,
            attestation_validity_seconds: 86400, // 24 hours
            refresh_threshold_seconds: 3600, // 1 hour
            expected_mrenclave: [0u8; 32], // Must be set in production
            expected_mrsigner: [0u8; 32],
            ias_url: "https://api.trustedservices.intel.com/sgx".into(),
            use_dcap: true,
        }
    }
}

impl AttestationConfig {
    fn validate(&self) -> Result<(), String> {
        if self.attestation_enabled && self.attestation_validity_seconds == 0 {
            return Err("attestation_validity_seconds must be > 0".into());
        }
        if self.refresh_threshold_seconds >= self.attestation_validity_seconds {
            return Err("refresh_threshold must be < attestation_validity".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_is_valid() {
        let config = ShieldConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_chain_specific_config() {
        let arbitrum = ShieldConfig::for_chain(ChainId::Arbitrum);
        assert_eq!(arbitrum.consensus.chain_id, ChainId::Arbitrum);
        
        let ton = ShieldConfig::for_chain(ChainId::Ton);
        assert!(ton.data.use_quantum_resistant);
        assert!(ton.consensus.require_all_validators);
    }
    
    #[test]
    fn test_invalid_config() {
        let mut config = ShieldConfig::default();
        config.consensus.required_approvals = 5;
        config.consensus.total_validators = 3;
        
        assert!(config.validate().is_err());
    }
}
