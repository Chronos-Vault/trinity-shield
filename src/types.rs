//! Core types for Trinity Shield
//! 
//! Defines all public types used throughout the shield system.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Blockchain chain identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChainId {
    /// Arbitrum (Ethereum L2) - Primary security chain
    Arbitrum = 1,
    /// Solana - High-frequency monitoring chain
    Solana = 2,
    /// TON - Quantum-resistant recovery chain
    Ton = 3,
}

impl ChainId {
    /// Get the numeric identifier for this chain
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    
    /// Create ChainId from numeric value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Arbitrum),
            2 => Some(Self::Solana),
            3 => Some(Self::Ton),
            _ => None,
        }
    }
    
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Arbitrum => "Arbitrum",
            Self::Solana => "Solana",
            Self::Ton => "TON",
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Public key for signature verification
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Raw public key bytes (32 bytes for Ed25519)
    pub bytes: [u8; 32],
    /// Key algorithm type
    pub algorithm: KeyAlgorithm,
}

impl PublicKey {
    /// Create a new public key
    pub fn new(bytes: [u8; 32], algorithm: KeyAlgorithm) -> Self {
        Self { bytes, algorithm }
    }
    
    /// Get hex-encoded representation
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..8])
    }
}

/// Key algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// Ed25519 (used for Solana)
    Ed25519,
    /// Secp256k1 (used for Ethereum/Arbitrum)
    Secp256k1,
    /// CRYSTALS-Dilithium Level 5 (post-quantum, used for TON)
    Dilithium5,
}

/// Digital signature
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Signature {
    /// Raw signature bytes
    #[zeroize(skip)]
    pub bytes: Vec<u8>,
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
}

impl Signature {
    /// Create a new signature
    pub fn new(bytes: Vec<u8>, algorithm: KeyAlgorithm) -> Self {
        Self { bytes, algorithm }
    }
    
    /// Get hex-encoded representation
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16.min(self.bytes.len() * 2)])
    }
}

/// Request source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSource {
    /// IP address of the requester
    pub ip_address: String,
    /// Optional user agent
    pub user_agent: Option<String>,
    /// Request timestamp
    pub timestamp: u64,
    /// Chain ID if from a specific chain
    pub chain_id: Option<ChainId>,
}

/// Authentication context after successful auth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Authenticated identity
    pub identity: Identity,
    /// Granted capabilities
    pub capabilities: Vec<Capability>,
    /// Session expiry timestamp
    pub expires_at: u64,
    /// Authentication method used
    pub method: AuthMethod,
}

/// Identity of an authenticated entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier
    pub id: String,
    /// Public key (if applicable)
    pub public_key: Option<PublicKey>,
    /// Chain this identity is from
    pub chain_id: Option<ChainId>,
}

/// Capability/permission token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Can submit operations for consensus
    SubmitOperation,
    /// Can vote on operations (validator only)
    Vote,
    /// Can initiate emergency recovery
    EmergencyRecovery,
    /// Can update configuration
    Configure,
    /// Can view sensitive data
    ReadSensitive,
    /// Administrative access
    Admin,
}

/// Authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Signature-based authentication
    Signature {
        /// Chain the signature is for
        chain_id: ChainId,
    },
    /// API key authentication
    ApiKey,
    /// Attestation-based (enclave-to-enclave)
    Attestation,
}

/// Validated request after passing all shield layers
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// Unique operation ID
    pub id: u64,
    /// Validated and decrypted payload
    pub payload: Vec<u8>,
    /// Authentication context
    pub auth_context: AuthContext,
    /// Validation timestamp
    pub timestamp: u64,
}

/// Operation to be voted on
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Operation type
    pub op_type: OperationType,
    /// Target chain
    pub target_chain: ChainId,
    /// Operation parameters
    pub params: Vec<u8>,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Requestor identity
    pub requestor: Identity,
    /// Timestamp
    pub timestamp: u64,
}

impl Operation {
    /// Compute hash of operation for signing
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&[self.op_type as u8]);
        hasher.update(&[self.target_chain.as_u8()]);
        hasher.update(&self.params);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(self.requestor.id.as_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        
        hasher.finalize().into()
    }
    
    /// Serialize operation to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
}

/// Type of operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OperationType {
    /// Withdraw from vault
    Withdraw = 1,
    /// Deposit to vault
    Deposit = 2,
    /// Cross-chain transfer
    CrossChainTransfer = 3,
    /// HTLC swap initiation
    HtlcInit = 4,
    /// HTLC swap claim
    HtlcClaim = 5,
    /// HTLC swap refund
    HtlcRefund = 6,
    /// Emergency recovery
    EmergencyRecovery = 7,
    /// Configuration update
    ConfigUpdate = 8,
}

impl OperationType {
    /// Create OperationType from numeric value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Withdraw),
            2 => Some(Self::Deposit),
            3 => Some(Self::CrossChainTransfer),
            4 => Some(Self::HtlcInit),
            5 => Some(Self::HtlcClaim),
            6 => Some(Self::HtlcRefund),
            7 => Some(Self::EmergencyRecovery),
            8 => Some(Self::ConfigUpdate),
            _ => None,
        }
    }
}

/// Vote on an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Chain this vote is from
    pub chain_id: ChainId,
    /// Hash of operation being voted on
    pub operation_hash: [u8; 32],
    /// Approval or rejection
    pub approved: bool,
    /// Timestamp
    pub timestamp: u64,
    /// Validator nonce
    pub nonce: u64,
}

impl Vote {
    /// Compute hash of vote for signing
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&[self.chain_id.as_u8()]);
        hasher.update(&self.operation_hash);
        hasher.update(&[self.approved as u8]);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        
        hasher.finalize().into()
    }
    
    /// Serialize vote to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
}

/// HTLC atomic swap operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcOperation {
    /// Unique HTLC identifier
    pub htlc_id: [u8; 32],
    /// SHA256 hashlock
    pub hashlock: [u8; 32],
    /// Timelock (Unix timestamp)
    pub timelock: u64,
    /// Amount in base units
    pub amount: u128,
    /// Initiator identity
    pub initiator: Identity,
    /// Recipient identity
    pub recipient: Identity,
    /// Source chain
    pub source_chain: ChainId,
    /// Target chain
    pub target_chain: ChainId,
}

/// HTLC state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcState {
    /// HTLC is pending (awaiting claim)
    Pending,
    /// HTLC has been claimed
    Claimed,
    /// HTLC has been refunded
    Refunded,
    /// HTLC has expired
    Expired,
}

/// Vault operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultOperation {
    /// Chain ID
    pub chain_id: ChainId,
    /// Amount in base units
    pub amount: u128,
    /// User identity
    pub user: Identity,
    /// Recipient address (for withdrawals)
    pub recipient: Option<String>,
}

/// Trinity Shield statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrinityStats {
    /// Total requests processed
    pub requests_processed: u64,
    /// Operations approved by consensus
    pub operations_approved: u64,
    /// Operations rejected by consensus
    pub operations_rejected: u64,
    /// HTLC swaps initiated
    pub htlc_initiated: u64,
    /// HTLC swaps claimed
    pub htlc_claimed: u64,
    /// HTLC swaps refunded
    pub htlc_refunded: u64,
    /// Vault deposits
    pub vault_deposits: u64,
    /// Vault withdrawals
    pub vault_withdrawals: u64,
    /// Perimeter shield stats
    pub perimeter: PerimeterStats,
    /// Application shield stats
    pub application: ApplicationStats,
    /// Data shield stats
    pub data: DataStats,
}

/// SGX attestation quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// Raw quote bytes
    pub quote: Vec<u8>,
    /// MRENCLAVE value
    pub mrenclave: [u8; 32],
    /// MRSIGNER value
    pub mrsigner: [u8; 32],
    /// User data included in quote
    pub report_data: [u8; 64],
}

/// Full attestation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Quote from TEE
    pub quote: AttestationQuote,
    /// Intel Attestation Service signature (if applicable)
    pub ias_signature: Option<Vec<u8>>,
    /// Report timestamp
    pub timestamp: u64,
    /// Report expiry
    pub expires_at: u64,
}

/// Attestation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    /// Valid and current
    Valid,
    /// Needs refresh (approaching expiry)
    NeedsRefresh,
    /// Expired
    Expired,
    /// Not yet generated
    NotGenerated,
}

/// Data sealed to enclave hardware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; 12],
    /// Authentication tag
    pub tag: [u8; 16],
    /// Key policy used (MRENCLAVE or MRSIGNER)
    pub policy: SealPolicy,
    /// Sealing timestamp
    pub sealed_at: u64,
}

/// Sealing key policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealPolicy {
    /// Seal to this exact enclave code (MRENCLAVE)
    MrEnclave,
    /// Seal to this signer (allows enclave updates)
    MrSigner,
}

/// Shield metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldMetrics {
    /// Total operations processed
    pub operations_processed: u64,
    /// Shield uptime in seconds
    pub uptime_seconds: u64,
    /// Perimeter shield statistics
    pub perimeter_stats: PerimeterStats,
    /// Application shield statistics
    pub application_stats: ApplicationStats,
    /// Data shield statistics
    pub data_stats: DataStats,
}

/// Perimeter shield statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerimeterStats {
    /// Requests allowed
    pub requests_allowed: u64,
    /// Requests blocked (rate limit)
    pub rate_limited: u64,
    /// Requests blocked (IP filter)
    pub ip_blocked: u64,
    /// Requests blocked (DDoS protection)
    pub ddos_blocked: u64,
}

/// Application shield statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationStats {
    /// Successful authentications
    pub auth_success: u64,
    /// Failed authentications
    pub auth_failed: u64,
    /// Authorization denials
    pub authz_denied: u64,
    /// Validation failures
    pub validation_failed: u64,
    /// Votes signed
    pub votes_signed: u64,
}

/// Data shield statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataStats {
    /// Encryption operations
    pub encryptions: u64,
    /// Decryption operations
    pub decryptions: u64,
    /// Seal operations
    pub seals: u64,
    /// Unseal operations
    pub unseals: u64,
    /// Integrity check failures
    pub integrity_failures: u64,
}

/// Input validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether input is encrypted
    pub is_encrypted: bool,
    /// Validated payload
    pub payload: Vec<u8>,
    /// Checksum for integrity verification
    pub checksum: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chain_id_conversion() {
        assert_eq!(ChainId::Arbitrum.as_u8(), 1);
        assert_eq!(ChainId::from_u8(2), Some(ChainId::Solana));
        assert_eq!(ChainId::from_u8(99), None);
    }
    
    #[test]
    fn test_operation_hash() {
        let op = Operation {
            op_type: OperationType::Withdraw,
            target_chain: ChainId::Arbitrum,
            params: vec![1, 2, 3],
            nonce: 42,
            requestor: Identity {
                id: "test".into(),
                public_key: None,
                chain_id: None,
            },
            timestamp: 1234567890,
        };
        
        let hash1 = op.hash();
        let hash2 = op.hash();
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_vote_serialization() {
        let vote = Vote {
            chain_id: ChainId::Solana,
            operation_hash: [0u8; 32],
            approved: true,
            timestamp: 1234567890,
            nonce: 1,
        };
        
        let bytes = vote.to_bytes();
        assert!(!bytes.is_empty());
    }
}
