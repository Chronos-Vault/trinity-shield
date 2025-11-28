//! Application Shield - Application-level security
//! 
//! The second layer of defense in Trinity Shield, handling:
//! - Multi-chain authentication (Arbitrum, Solana, TON)
//! - Role-based authorization with capability tokens
//! - Input validation against schemas
//! - Enclave-protected signing operations

use crate::config::ApplicationConfig;
use crate::crypto::KeyPair;
use crate::error::{ShieldError, ShieldResult};
use crate::types::{
    ApplicationStats, AuthContext, AuthMethod, Capability, ChainId,
    Identity, KeyAlgorithm, PublicKey, RequestSource, Signature,
    ValidationResult,
};

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod authenticator;
mod authorizer;
mod input_validator;
mod session_manager;

pub use authenticator::*;
pub use authorizer::*;
pub use input_validator::*;
pub use session_manager::*;

/// Application Shield - Application-level security layer
pub struct ApplicationShield {
    /// Configuration
    config: ApplicationConfig,
    /// Enclave signing key pair
    key_pair: KeyPair,
    /// Authenticator
    authenticator: Authenticator,
    /// Authorizer
    authorizer: Authorizer,
    /// Input validator
    input_validator: InputValidator,
    /// Session manager
    session_manager: SessionManager,
    /// Statistics
    stats: ApplicationStatsInternal,
}

struct ApplicationStatsInternal {
    auth_success: AtomicU64,
    auth_failed: AtomicU64,
    authz_denied: AtomicU64,
    validation_failed: AtomicU64,
    votes_signed: AtomicU64,
}

impl Default for ApplicationStatsInternal {
    fn default() -> Self {
        Self {
            auth_success: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
            authz_denied: AtomicU64::new(0),
            validation_failed: AtomicU64::new(0),
            votes_signed: AtomicU64::new(0),
        }
    }
}

impl ApplicationShield {
    /// Create a new Application Shield
    pub fn new(config: &ApplicationConfig) -> ShieldResult<Self> {
        // Generate enclave key pair
        // Use Ed25519 by default, but chain-specific keys can be added
        let key_pair = KeyPair::generate(KeyAlgorithm::Ed25519)?;
        
        let authenticator = Authenticator::new(config);
        let authorizer = Authorizer::new();
        let input_validator = InputValidator::new(config.max_field_length);
        let session_manager = SessionManager::new(
            config.session_timeout_seconds,
            config.max_session_duration_seconds,
        );
        
        Ok(Self {
            config: config.clone(),
            key_pair,
            authenticator,
            authorizer,
            input_validator,
            session_manager,
            stats: ApplicationStatsInternal::default(),
        })
    }
    
    /// Authenticate a request
    /// 
    /// # Arguments
    /// * `request` - Raw request bytes (must contain auth header)
    /// * `source` - Request source information
    /// 
    /// # Returns
    /// * `AuthContext` - Authentication context with identity and capabilities
    pub fn authenticate(
        &self,
        request: &[u8],
        source: &RequestSource,
    ) -> ShieldResult<AuthContext> {
        match self.authenticator.authenticate(request, source) {
            Ok(ctx) => {
                self.stats.auth_success.fetch_add(1, Ordering::Relaxed);
                
                // Register session
                self.session_manager.create_session(&ctx);
                
                Ok(ctx)
            }
            Err(e) => {
                self.stats.auth_failed.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Verify an existing session
    pub fn verify_session(&self, session_id: &str) -> ShieldResult<AuthContext> {
        self.session_manager
            .get_session(session_id)
            .ok_or(ShieldError::SessionExpired)
    }
    
    /// Check authorization for an action
    pub fn authorize(&self, auth_context: &AuthContext) -> ShieldResult<()> {
        // Check session validity
        if self.session_manager.is_expired(auth_context) {
            return Err(ShieldError::SessionExpired);
        }
        
        // Check basic authorization
        match self.authorizer.check(auth_context, Capability::SubmitOperation) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stats.authz_denied.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Check authorization for a specific capability
    pub fn authorize_capability(
        &self,
        auth_context: &AuthContext,
        capability: Capability,
    ) -> ShieldResult<()> {
        match self.authorizer.check(auth_context, capability) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stats.authz_denied.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Validate input data
    pub fn validate_input(&self, data: &[u8]) -> ShieldResult<ValidationResult> {
        match self.input_validator.validate(data) {
            Ok(result) => Ok(result),
            Err(e) => {
                self.stats.validation_failed.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
    
    /// Sign data with enclave-protected key
    pub fn sign_with_enclave_key(&self, data: &[u8]) -> ShieldResult<Signature> {
        self.stats.votes_signed.fetch_add(1, Ordering::Relaxed);
        self.key_pair.sign(data)
    }
    
    /// Sign data with chain-specific key
    pub fn sign_for_chain(
        &self,
        data: &[u8],
        chain_id: ChainId,
    ) -> ShieldResult<Signature> {
        // In production, derive chain-specific key
        // For now, use the main key
        let _ = chain_id;
        self.sign_with_enclave_key(data)
    }
    
    /// Get the enclave's public key
    pub fn public_key(&self) -> &PublicKey {
        self.key_pair.public_key()
    }
    
    /// Verify a signature from another party
    pub fn verify_signature(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8],
        algorithm: KeyAlgorithm,
    ) -> ShieldResult<bool> {
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                crate::crypto::ed25519_verify(public_key, message, signature)
            }
            KeyAlgorithm::Secp256k1 => {
                crate::crypto::secp256k1_verify(public_key, message, signature)
            }
            KeyAlgorithm::Dilithium5 => {
                #[cfg(feature = "pqcrypto-dilithium")]
                {
                    crate::crypto::dilithium_verify(public_key, message, signature)
                }
                
                #[cfg(not(feature = "pqcrypto-dilithium"))]
                Err(ShieldError::NotSupported("Dilithium not compiled in".into()))
            }
        }
    }
    
    /// Grant a capability to an identity
    pub fn grant_capability(
        &mut self,
        identity: &Identity,
        capability: Capability,
    ) {
        self.authorizer.grant(identity, capability);
    }
    
    /// Revoke a capability from an identity
    pub fn revoke_capability(
        &mut self,
        identity: &Identity,
        capability: Capability,
    ) {
        self.authorizer.revoke(identity, capability);
    }
    
    /// End a session
    pub fn end_session(&self, session_id: &str) {
        self.session_manager.revoke_session(session_id);
    }
    
    /// Get statistics
    pub fn stats(&self) -> ApplicationStats {
        ApplicationStats {
            auth_success: self.stats.auth_success.load(Ordering::Relaxed),
            auth_failed: self.stats.auth_failed.load(Ordering::Relaxed),
            authz_denied: self.stats.authz_denied.load(Ordering::Relaxed),
            validation_failed: self.stats.validation_failed.load(Ordering::Relaxed),
            votes_signed: self.stats.votes_signed.load(Ordering::Relaxed),
        }
    }
    
    /// Clean up expired sessions
    pub fn cleanup_sessions(&self) {
        self.session_manager.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApplicationConfig;
    
    #[test]
    fn test_shield_creation() {
        let config = ApplicationConfig::default();
        let shield = ApplicationShield::new(&config);
        assert!(shield.is_ok());
    }
    
    #[test]
    fn test_signing() {
        let config = ApplicationConfig::default();
        let shield = ApplicationShield::new(&config).unwrap();
        
        let message = b"Hello, Trinity Shield!";
        let signature = shield.sign_with_enclave_key(message);
        assert!(signature.is_ok());
    }
    
    #[test]
    fn test_public_key() {
        let config = ApplicationConfig::default();
        let shield = ApplicationShield::new(&config).unwrap();
        
        let pk = shield.public_key();
        assert_eq!(pk.bytes.len(), 32);
        assert_eq!(pk.algorithm, KeyAlgorithm::Ed25519);
    }
}
