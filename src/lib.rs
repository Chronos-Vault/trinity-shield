//! # Trinity Shield™
//! 
//! Layer 8 of the Mathematical Defense Layer (MDL) for Trinity Protocol.
//! 
//! Trinity Shield provides hardware-isolated security for multi-chain consensus
//! validators through Intel SGX and AMD SEV trusted execution environments.
//! 
//! ## Architecture
//! 
//! The shield consists of three integrated defense layers:
//! 
//! 1. **Perimeter Shield** - Network boundary protection
//!    - Rate limiting with token bucket algorithm
//!    - DDoS protection and circuit breakers
//!    - IP filtering and geofencing
//!    - Request validation and sanitization
//! 
//! 2. **Application Shield** - Application-level security
//!    - Multi-chain authentication (Arbitrum, Solana, TON)
//!    - Role-based authorization with capability tokens
//!    - Input validation against Lean-proven schemas
//!    - Enclave-protected consensus voting
//! 
//! 3. **Data Shield** - Data protection layer
//!    - AES-256-GCM encryption at rest
//!    - Hardware key sealing (SGX sealing)
//!    - Integrity verification with Merkle proofs
//!    - Quantum-resistant key encapsulation (ML-KEM-1024)
//! 
//! ## Security Model
//! 
//! Trinity Shield operates on a zero-trust model where:
//! - All inputs are considered hostile until validated
//! - Keys never exist in host memory (sealed to enclave)
//! - Every operation is logged for audit trails
//! - Defense in depth with multiple security layers
//! 
//! ## Example
//! 
//! ```rust,no_run
//! use trinity_shield::{TrinityShield, ShieldConfig, ChainId};
//! 
//! // Initialize the shield with configuration
//! let config = ShieldConfig::default();
//! let shield = TrinityShield::new(config)?;
//! 
//! // Process a consensus vote request
//! let operation = shield.validate_operation(&request)?;
//! let vote = shield.sign_vote(&operation)?;
//! 
//! // Generate attestation for on-chain verification
//! let attestation = shield.generate_attestation()?;
//! ```
//! 
//! ## Feature Flags
//! 
//! - `std` - Standard library support (default)
//! - `sgx` - Intel SGX enclave support
//! - `sev` - AMD SEV-SNP support
//! - `quantum` - Post-quantum cryptography (ML-KEM-1024, Dilithium-5)
//! - `ton` - TON validator (enables quantum features)
//! - `ipc` - IPC interface for relayer communication
//! - `simulation` - Simulation mode for testing
//! 
//! ---
//! 
//! *Trinity Shield™ — "Mathematically Proven. Hardware Protected."*
//! 
//! Website: https://chronosvault.org
//! Contact: chronosvault@chronosvault.org

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

pub mod perimeter;
pub mod application;
pub mod data;
pub mod consensus;
pub mod attestation;
pub mod crypto;
pub mod error;
pub mod types;
pub mod config;
pub mod orchestrator;
#[cfg(feature = "ipc")]
pub mod ipc;
#[cfg(feature = "quantum")]
pub mod quantum;

pub use error::{ShieldError, ShieldResult};
pub use types::*;
pub use config::ShieldConfig;
pub use orchestrator::{
    TrinityShield as TrinityShieldFull, ProcessedRequest, SubmitResult,
    SignedVote as OrchestratorSignedVote, HtlcInitResult, HtlcClaimResult,
    HtlcRefundResult, VaultResult, HtlcBridge, VaultManager, LeanVerifier,
};

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Global timestamp source for SGX environments
/// In SGX mode, this is updated via trusted time service
#[cfg(feature = "sgx")]
static SGX_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Trinity Shield - Main security orchestrator
/// 
/// Coordinates all three shield layers to provide comprehensive
/// hardware-isolated security for Trinity Protocol validators.
pub struct TrinityShield {
    /// Configuration for all shield layers
    config: ShieldConfig,
    
    /// Perimeter shield for network security
    perimeter: perimeter::PerimeterShield,
    
    /// Application shield for auth and business logic
    application: application::ApplicationShield,
    
    /// Data shield for encryption and integrity
    data: data::DataShield,
    
    /// Consensus engine for 2-of-3 voting
    consensus: consensus::ConsensusEngine,
    
    /// Attestation generator for SGX/SEV quotes
    attestation: attestation::AttestationService,
    
    /// Operation counter for nonce management
    operation_counter: AtomicU64,
    
    /// Shield initialization timestamp
    initialized_at: u64,
    
    /// Quantum-resistant signer (TON validator)
    #[cfg(feature = "quantum")]
    quantum_signer: Option<quantum::QuantumSigner>,
}

impl TrinityShield {
    /// Create a new Trinity Shield instance
    /// 
    /// # Arguments
    /// * `config` - Shield configuration
    /// 
    /// # Returns
    /// * `ShieldResult<Self>` - Initialized shield or error
    /// 
    /// # Security
    /// - Generates validator key inside enclave
    /// - Initializes all three shield layers
    /// - Performs self-attestation check
    pub fn new(config: ShieldConfig) -> ShieldResult<Self> {
        // Initialize cryptographic subsystem
        crypto::init()?;
        
        // Initialize SGX trusted time if in enclave
        #[cfg(feature = "sgx")]
        init_sgx_time()?;
        
        // Create shield layers
        let perimeter = perimeter::PerimeterShield::new(&config.perimeter)?;
        let application = application::ApplicationShield::new(&config.application)?;
        let data = data::DataShield::new(&config.data)?;
        let consensus = consensus::ConsensusEngine::new(&config.consensus)?;
        let attestation = attestation::AttestationService::new(&config.attestation)?;
        
        // Initialize quantum signer for TON validator
        #[cfg(feature = "quantum")]
        let quantum_signer = if config.consensus.chain_id == ChainId::TON {
            Some(quantum::QuantumSigner::new()?)
        } else {
            None
        };
        
        let shield = Self {
            config,
            perimeter,
            application,
            data,
            consensus,
            attestation,
            operation_counter: AtomicU64::new(0),
            initialized_at: current_timestamp(),
            #[cfg(feature = "quantum")]
            quantum_signer,
        };
        
        // Perform initial attestation to verify enclave integrity
        shield.verify_enclave_integrity()?;
        
        Ok(shield)
    }
    
    /// Process an incoming request through all shield layers
    /// 
    /// # Arguments
    /// * `request` - Raw request bytes
    /// * `source` - Request source information
    /// 
    /// # Returns
    /// * `ShieldResult<ValidatedRequest>` - Validated request or rejection
    /// 
    /// # Security Flow
    /// 1. Perimeter: Rate limit, IP check, DDoS protection
    /// 2. Application: Auth, authorization, input validation
    /// 3. Data: Decrypt if needed, verify integrity
    pub fn process_request(
        &self,
        request: &[u8],
        source: &RequestSource,
    ) -> ShieldResult<ValidatedRequest> {
        // Layer 1: Perimeter Shield
        self.perimeter.check_rate_limit(source)?;
        self.perimeter.check_ip_allowed(source)?;
        self.perimeter.validate_request_size(request)?;
        
        // Layer 2: Application Shield
        let auth_context = self.application.authenticate(request, source)?;
        self.application.authorize(&auth_context)?;
        let validated = self.application.validate_input(request)?;
        
        // Layer 3: Data Shield (if encrypted)
        let decrypted = if validated.is_encrypted {
            self.data.decrypt(&validated.payload, &auth_context)?
        } else {
            validated.payload.clone()
        };
        
        // Verify data integrity
        self.data.verify_integrity(&decrypted, &validated.checksum)?;
        
        Ok(ValidatedRequest {
            id: self.next_operation_id(),
            payload: decrypted,
            auth_context,
            timestamp: current_timestamp(),
        })
    }
    
    /// Sign a consensus vote for an operation
    /// 
    /// # Arguments
    /// * `operation` - The operation to vote on
    /// 
    /// # Returns
    /// * `ShieldResult<SignedVote>` - Signed vote with attestation
    /// 
    /// # Security
    /// - Vote signed with enclave-protected key
    /// - Includes fresh attestation proof
    /// - Enforces Lean-proven consensus rules
    /// - Uses quantum-resistant signature for TON chain
    pub fn sign_vote(&self, operation: &Operation) -> ShieldResult<SignedVote> {
        // Verify operation against Lean-proven rules
        self.consensus.verify_operation_rules(operation)?;
        
        // Create vote with enclave signature
        let vote = self.consensus.create_vote(operation)?;
        
        // Sign with appropriate key based on chain
        let signature = self.sign_vote_bytes(&vote.to_bytes())?;
        
        // Include attestation for on-chain verification
        let attestation = self.attestation.generate_quote(&vote.hash())?;
        
        Ok(SignedVote {
            vote,
            signature,
            attestation,
            timestamp: current_timestamp(),
        })
    }
    
    /// Sign vote bytes with appropriate signature scheme
    fn sign_vote_bytes(&self, data: &[u8]) -> ShieldResult<Signature> {
        #[cfg(feature = "quantum")]
        {
            // Use Dilithium-5 for TON validator
            if self.config.consensus.chain_id == ChainId::TON {
                if let Some(ref signer) = self.quantum_signer {
                    return signer.sign(data);
                }
            }
        }
        
        // Default: Ed25519/Secp256k1 for Arbitrum/Solana
        self.application.sign_with_enclave_key(data)
    }
    
    /// Generate remote attestation report
    /// 
    /// # Returns
    /// * `ShieldResult<AttestationReport>` - SGX/SEV quote for on-chain verification
    pub fn generate_attestation(&self) -> ShieldResult<AttestationReport> {
        self.attestation.generate_full_report()
    }
    
    /// Seal sensitive data to enclave hardware
    /// 
    /// # Arguments
    /// * `data` - Data to seal
    /// 
    /// # Returns
    /// * `ShieldResult<SealedData>` - Hardware-sealed data blob
    pub fn seal_data(&self, data: &[u8]) -> ShieldResult<SealedData> {
        self.data.seal(data)
    }
    
    /// Unseal data previously sealed to this enclave
    /// 
    /// # Arguments
    /// * `sealed` - Sealed data blob
    /// 
    /// # Returns
    /// * `ShieldResult<Vec<u8>>` - Unsealed plaintext
    pub fn unseal_data(&self, sealed: &SealedData) -> ShieldResult<Vec<u8>> {
        self.data.unseal(sealed)
    }
    
    /// Get the enclave's public key for external verification
    pub fn public_key(&self) -> &PublicKey {
        self.application.public_key()
    }
    
    /// Get quantum-resistant public key (TON only)
    #[cfg(feature = "quantum")]
    pub fn quantum_public_key(&self) -> Option<&quantum::DilithiumPublicKey> {
        self.quantum_signer.as_ref().map(|s| s.public_key())
    }
    
    /// Get the chain ID this enclave is configured for
    pub fn chain_id(&self) -> ChainId {
        self.config.consensus.chain_id
    }
    
    /// Get current attestation status
    pub fn attestation_status(&self) -> AttestationStatus {
        self.attestation.status()
    }
    
    /// Get shield metrics for monitoring
    pub fn metrics(&self) -> ShieldMetrics {
        ShieldMetrics {
            operations_processed: self.operation_counter.load(Ordering::Relaxed),
            uptime_seconds: current_timestamp() - self.initialized_at,
            perimeter_stats: self.perimeter.stats(),
            application_stats: self.application.stats(),
            data_stats: self.data.stats(),
        }
    }
    
    /// Update SGX timestamp from trusted source
    /// 
    /// In SGX mode, time must be provided by a trusted source since
    /// the enclave cannot access system time directly.
    #[cfg(feature = "sgx")]
    pub fn update_trusted_time(&self, timestamp: u64) -> ShieldResult<()> {
        // Verify timestamp is monotonically increasing
        let current = SGX_TIMESTAMP.load(Ordering::Acquire);
        if timestamp <= current {
            return Err(ShieldError::InvalidTimestamp(
                "Timestamp must be monotonically increasing".into()
            ));
        }
        SGX_TIMESTAMP.store(timestamp, Ordering::Release);
        Ok(())
    }
    
    // === Private Methods ===
    
    fn next_operation_id(&self) -> u64 {
        self.operation_counter.fetch_add(1, Ordering::SeqCst)
    }
    
    fn verify_enclave_integrity(&self) -> ShieldResult<()> {
        // In SGX mode, verify MRENCLAVE matches expected value
        #[cfg(feature = "sgx")]
        {
            let report = self.attestation.get_self_report()?;
            if report.mrenclave != self.config.attestation.expected_mrenclave {
                return Err(ShieldError::AttestationFailed(
                    "MRENCLAVE mismatch - enclave may be compromised".into()
                ));
            }
        }
        
        // In SEV mode, verify MEASUREMENT matches expected value
        #[cfg(feature = "sev")]
        {
            let report = self.attestation.get_sev_report()?;
            if report.measurement != self.config.attestation.expected_sev_measurement {
                return Err(ShieldError::AttestationFailed(
                    "SEV MEASUREMENT mismatch - VM may be compromised".into()
                ));
            }
        }
        
        Ok(())
    }
}

/// Initialize SGX trusted time service
#[cfg(feature = "sgx")]
fn init_sgx_time() -> ShieldResult<()> {
    // Request initial time from Intel trusted time service
    // This will be updated periodically by the relayer
    SGX_TIMESTAMP.store(0, Ordering::Release);
    Ok(())
}

/// Get current Unix timestamp in seconds
/// 
/// In standard mode, uses system time.
/// In SGX mode, uses trusted time updated by relayer.
/// In SEV mode, uses system time (SEV allows time access).
pub fn current_timestamp() -> u64 {
    #[cfg(feature = "sgx")]
    {
        // In SGX, use the trusted timestamp updated by relayer
        SGX_TIMESTAMP.load(Ordering::Acquire)
    }
    
    #[cfg(all(feature = "std", not(feature = "sgx")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    #[cfg(all(not(feature = "std"), not(feature = "sgx")))]
    {
        // In pure no_std without SGX, return 0 (should not happen in production)
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shield_creation() {
        let config = ShieldConfig::default();
        let shield = TrinityShield::new(config);
        assert!(shield.is_ok());
    }
    
    #[test]
    fn test_operation_counter() {
        let config = ShieldConfig::default();
        let shield = TrinityShield::new(config).unwrap();
        
        let id1 = shield.next_operation_id();
        let id2 = shield.next_operation_id();
        
        assert_eq!(id1 + 1, id2);
    }
    
    #[test]
    fn test_timestamp() {
        let ts = current_timestamp();
        // In test mode with std, should return a real timestamp
        #[cfg(feature = "std")]
        assert!(ts > 0);
    }
}
