//! Error types for Trinity Shield
//! 
//! Provides comprehensive error handling with security-conscious
//! error messages that don't leak sensitive information.

use alloc::string::String;
use core::fmt;

/// Result type for Trinity Shield operations
pub type ShieldResult<T> = Result<T, ShieldError>;

/// Main error type for Trinity Shield
/// 
/// All errors are designed to be security-conscious:
/// - No sensitive data in error messages
/// - Detailed logging happens internally
/// - External errors are generic to prevent information leakage
#[derive(Debug, Clone)]
pub enum ShieldError {
    // === Perimeter Shield Errors ===
    
    /// Rate limit exceeded for this source
    RateLimitExceeded {
        /// Seconds until rate limit resets
        retry_after: u64,
    },
    
    /// IP address is blocked
    IpBlocked {
        /// Reason for block (generic)
        reason: String,
    },
    
    /// Request size exceeds maximum allowed
    RequestTooLarge {
        /// Maximum allowed size in bytes
        max_size: usize,
    },
    
    /// Request failed DDoS protection checks
    DDoSProtection,
    
    // === Application Shield Errors ===
    
    /// Authentication failed
    AuthenticationFailed(String),
    
    /// Authorization denied for this operation
    AuthorizationDenied {
        /// Required capability that was missing
        required: String,
    },
    
    /// Input validation failed
    ValidationFailed {
        /// Field that failed validation
        field: String,
        /// Reason for failure (sanitized)
        reason: String,
    },
    
    /// Signature verification failed
    SignatureInvalid,
    
    /// Session expired or invalid
    SessionExpired,
    
    // === Data Shield Errors ===
    
    /// Encryption operation failed
    EncryptionFailed,
    
    /// Decryption operation failed
    DecryptionFailed,
    
    /// Data integrity check failed
    IntegrityCheckFailed,
    
    /// Key sealing/unsealing failed
    SealingFailed(String),
    
    /// Key derivation failed
    KeyDerivationFailed,
    
    // === Consensus Errors ===
    
    /// Operation violates consensus rules
    ConsensusRuleViolation {
        /// Which rule was violated
        rule: String,
    },
    
    /// Insufficient validator approvals
    InsufficientApprovals {
        /// Number of approvals received
        received: u8,
        /// Number of approvals required
        required: u8,
    },
    
    /// Invalid cross-chain proof
    InvalidCrossChainProof,
    
    /// Operation nonce is invalid (replay protection)
    InvalidNonce,
    
    // === Attestation Errors ===
    
    /// Attestation generation failed
    AttestationFailed(String),
    
    /// Attestation verification failed
    AttestationVerificationFailed,
    
    /// Attestation has expired
    AttestationExpired,
    
    /// MRENCLAVE mismatch
    MrenclaveMismatch,
    
    // === Cryptographic Errors ===
    
    /// Random number generation failed
    RngFailed,
    
    /// Cryptographic operation failed
    CryptoError(String),
    
    /// Key not found
    KeyNotFound,
    
    // === System Errors ===
    
    /// Configuration error
    ConfigurationError(String),
    
    /// Internal error (should not happen)
    InternalError(String),
    
    /// Feature not supported in current build
    NotSupported(String),
    
    /// Enclave not initialized
    NotInitialized,
    
    /// Shield is disabled for maintenance
    ShieldDisabled,
    
    /// Lean proof verification failed
    LeanProofViolation {
        /// Which theorem was violated
        theorem: String,
    },
    
    /// IPC communication error
    IpcError(String),
    
    /// Quantum crypto feature disabled
    QuantumFeatureDisabled,
    
    /// Invalid timestamp (for SGX time updates)
    InvalidTimestamp(String),
    
    /// Feature not enabled in this build
    FeatureDisabled(String),
    
    /// Invalid key format or type
    InvalidKey(String),
    
    /// Invalid signature format
    InvalidSignature(String),
    
    /// Invalid ciphertext format
    InvalidCiphertext(String),
    
    /// Invalid input data
    InvalidInput(String),
}

impl fmt::Display for ShieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Perimeter errors
            Self::RateLimitExceeded { retry_after } => {
                write!(f, "Rate limit exceeded. Retry after {} seconds", retry_after)
            }
            Self::IpBlocked { reason } => {
                write!(f, "Request blocked: {}", reason)
            }
            Self::RequestTooLarge { max_size } => {
                write!(f, "Request too large. Maximum size: {} bytes", max_size)
            }
            Self::DDoSProtection => {
                write!(f, "Request blocked by DDoS protection")
            }
            
            // Application errors
            Self::AuthenticationFailed(msg) => {
                write!(f, "Authentication failed: {}", msg)
            }
            Self::AuthorizationDenied { required } => {
                write!(f, "Authorization denied. Required capability: {}", required)
            }
            Self::ValidationFailed { field, reason } => {
                write!(f, "Validation failed for '{}': {}", field, reason)
            }
            Self::SignatureInvalid => {
                write!(f, "Signature verification failed")
            }
            Self::SessionExpired => {
                write!(f, "Session expired or invalid")
            }
            
            // Data errors
            Self::EncryptionFailed => {
                write!(f, "Encryption operation failed")
            }
            Self::DecryptionFailed => {
                write!(f, "Decryption operation failed")
            }
            Self::IntegrityCheckFailed => {
                write!(f, "Data integrity verification failed")
            }
            Self::SealingFailed(msg) => {
                write!(f, "Sealing operation failed: {}", msg)
            }
            Self::KeyDerivationFailed => {
                write!(f, "Key derivation failed")
            }
            
            // Consensus errors
            Self::ConsensusRuleViolation { rule } => {
                write!(f, "Consensus rule violation: {}", rule)
            }
            Self::InsufficientApprovals { received, required } => {
                write!(f, "Insufficient approvals: {}/{}", received, required)
            }
            Self::InvalidCrossChainProof => {
                write!(f, "Invalid cross-chain proof")
            }
            Self::InvalidNonce => {
                write!(f, "Invalid operation nonce")
            }
            
            // Attestation errors
            Self::AttestationFailed(msg) => {
                write!(f, "Attestation failed: {}", msg)
            }
            Self::AttestationVerificationFailed => {
                write!(f, "Attestation verification failed")
            }
            Self::AttestationExpired => {
                write!(f, "Attestation has expired")
            }
            Self::MrenclaveMismatch => {
                write!(f, "Enclave measurement mismatch")
            }
            
            // Crypto errors
            Self::RngFailed => {
                write!(f, "Random number generation failed")
            }
            Self::CryptoError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
            Self::KeyNotFound => {
                write!(f, "Required key not found")
            }
            
            // System errors
            Self::ConfigurationError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            Self::InternalError(msg) => {
                write!(f, "Internal error: {}", msg)
            }
            Self::NotSupported(feature) => {
                write!(f, "Feature not supported: {}", feature)
            }
            Self::NotInitialized => {
                write!(f, "Shield not initialized")
            }
            Self::ShieldDisabled => {
                write!(f, "Shield is disabled for maintenance")
            }
            Self::LeanProofViolation { theorem } => {
                write!(f, "Lean proof violation: {}", theorem)
            }
            Self::IpcError(msg) => {
                write!(f, "IPC error: {}", msg)
            }
            Self::QuantumFeatureDisabled => {
                write!(f, "Quantum cryptography feature not enabled")
            }
            Self::InvalidTimestamp(msg) => {
                write!(f, "Invalid timestamp: {}", msg)
            }
            Self::FeatureDisabled(feature) => {
                write!(f, "Feature '{}' not enabled in this build", feature)
            }
            Self::InvalidKey(msg) => {
                write!(f, "Invalid key: {}", msg)
            }
            Self::InvalidSignature(msg) => {
                write!(f, "Invalid signature: {}", msg)
            }
            Self::InvalidCiphertext(msg) => {
                write!(f, "Invalid ciphertext: {}", msg)
            }
            Self::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
        }
    }
}

impl From<serde_json::Error> for ShieldError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidInput(e.to_string())
    }
}

impl From<hex::FromHexError> for ShieldError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidInput(e.to_string())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShieldError {}

impl ShieldError {
    /// Check if this error should be logged at error level
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::InternalError(_)
                | Self::CryptoError(_)
                | Self::AttestationFailed(_)
                | Self::MrenclaveMismatch
                | Self::SealingFailed(_)
        )
    }
    
    /// Check if this error indicates a potential attack
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            Self::RateLimitExceeded { .. }
                | Self::IpBlocked { .. }
                | Self::DDoSProtection
                | Self::SignatureInvalid
                | Self::InvalidNonce
                | Self::InvalidCrossChainProof
        )
    }
    
    /// Get a sanitized error message safe for external responses
    pub fn sanitized_message(&self) -> &'static str {
        match self {
            Self::RateLimitExceeded { .. } => "Rate limit exceeded",
            Self::IpBlocked { .. } => "Request blocked",
            Self::RequestTooLarge { .. } => "Request too large",
            Self::DDoSProtection => "Request blocked",
            Self::AuthenticationFailed(_) => "Authentication failed",
            Self::AuthorizationDenied { .. } => "Access denied",
            Self::ValidationFailed { .. } => "Invalid request",
            Self::SignatureInvalid => "Invalid signature",
            Self::SessionExpired => "Session expired",
            Self::EncryptionFailed | Self::DecryptionFailed => "Crypto error",
            Self::IntegrityCheckFailed => "Integrity check failed",
            Self::SealingFailed(_) => "Operation failed",
            Self::KeyDerivationFailed => "Operation failed",
            Self::ConsensusRuleViolation { .. } => "Consensus rule violation",
            Self::InsufficientApprovals { .. } => "Insufficient approvals",
            Self::InvalidCrossChainProof => "Invalid proof",
            Self::InvalidNonce => "Invalid request",
            Self::AttestationFailed(_) => "Attestation failed",
            Self::AttestationVerificationFailed => "Verification failed",
            Self::AttestationExpired => "Attestation expired",
            Self::MrenclaveMismatch => "Enclave error",
            Self::RngFailed => "Internal error",
            Self::CryptoError(_) => "Internal error",
            Self::KeyNotFound => "Key not found",
            Self::ConfigurationError(_) => "Configuration error",
            Self::InternalError(_) => "Internal error",
            Self::NotSupported(_) => "Not supported",
            Self::NotInitialized => "Not initialized",
            Self::ShieldDisabled => "Shield disabled",
            Self::LeanProofViolation { .. } => "Consensus rule violation",
        }
    }
    
    /// Get HTTP status code for this error
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::RateLimitExceeded { .. } => 429,
            Self::IpBlocked { .. } | Self::DDoSProtection => 403,
            Self::RequestTooLarge { .. } => 413,
            Self::AuthenticationFailed(_) | Self::SignatureInvalid => 401,
            Self::AuthorizationDenied { .. } => 403,
            Self::ValidationFailed { .. } | Self::InvalidNonce => 400,
            Self::SessionExpired => 401,
            Self::ConsensusRuleViolation { .. } | Self::InsufficientApprovals { .. } => 422,
            Self::InvalidCrossChainProof => 400,
            Self::AttestationExpired => 401,
            Self::NotSupported(_) => 501,
            Self::NotInitialized => 503,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = ShieldError::RateLimitExceeded { retry_after: 60 };
        assert!(err.to_string().contains("60"));
    }
    
    #[test]
    fn test_critical_detection() {
        assert!(ShieldError::MrenclaveMismatch.is_critical());
        assert!(!ShieldError::SessionExpired.is_critical());
    }
    
    #[test]
    fn test_suspicious_detection() {
        assert!(ShieldError::DDoSProtection.is_suspicious());
        assert!(!ShieldError::SessionExpired.is_suspicious());
    }
    
    #[test]
    fn test_http_status_codes() {
        assert_eq!(ShieldError::RateLimitExceeded { retry_after: 0 }.http_status_code(), 429);
        assert_eq!(ShieldError::AuthorizationDenied { required: "admin".into() }.http_status_code(), 403);
    }
}
