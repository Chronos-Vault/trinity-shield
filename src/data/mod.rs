//! Data Shield - Data protection layer
//! 
//! The third layer of defense in Trinity Shield, handling:
//! - AES-256-GCM encryption at rest
//! - Hardware key sealing (SGX sealing)
//! - Integrity verification with Merkle proofs
//! - Secure key management and rotation

use crate::config::DataConfig;
use crate::crypto::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, derive_keys, hkdf,
    random_key, random_nonce, sha256, SymmetricAlgorithm,
};
use crate::error::{ShieldError, ShieldResult};
use crate::types::{AuthContext, DataStats, SealPolicy, SealedData};

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

mod sealing;
mod integrity;
mod key_manager;

pub use sealing::*;
pub use integrity::*;
pub use key_manager::*;

/// Data Shield - Data protection layer
pub struct DataShield {
    /// Configuration
    config: DataConfig,
    /// Key manager
    key_manager: KeyManager,
    /// Sealing service
    sealer: Sealer,
    /// Integrity verifier
    integrity: IntegrityVerifier,
    /// Statistics
    stats: DataStatsInternal,
}

struct DataStatsInternal {
    encryptions: AtomicU64,
    decryptions: AtomicU64,
    seals: AtomicU64,
    unseals: AtomicU64,
    integrity_failures: AtomicU64,
}

impl Default for DataStatsInternal {
    fn default() -> Self {
        Self {
            encryptions: AtomicU64::new(0),
            decryptions: AtomicU64::new(0),
            seals: AtomicU64::new(0),
            unseals: AtomicU64::new(0),
            integrity_failures: AtomicU64::new(0),
        }
    }
}

impl DataShield {
    /// Create a new Data Shield
    pub fn new(config: &DataConfig) -> ShieldResult<Self> {
        let key_manager = KeyManager::new(
            config.key_rotation_enabled,
            config.key_rotation_interval_hours,
        )?;
        
        let seal_policy = match config.seal_policy.as_str() {
            "mrsigner" => SealPolicy::MrSigner,
            _ => SealPolicy::MrEnclave,
        };
        
        let sealer = Sealer::new(seal_policy)?;
        let integrity = IntegrityVerifier::new();
        
        Ok(Self {
            config: config.clone(),
            key_manager,
            sealer,
            integrity,
            stats: DataStatsInternal::default(),
        })
    }
    
    /// Encrypt data for storage
    /// 
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `auth_context` - Authentication context for key derivation
    /// 
    /// # Returns
    /// * Encrypted envelope with nonce and tag
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        auth_context: &AuthContext,
    ) -> ShieldResult<Vec<u8>> {
        self.stats.encryptions.fetch_add(1, Ordering::Relaxed);
        
        // Get or derive encryption key
        let key = self.key_manager.get_encryption_key(&auth_context.identity.id)?;
        
        // Generate random nonce
        let nonce = random_nonce()?;
        
        // Additional authenticated data: identity + timestamp
        let aad = auth_context.identity.id.as_bytes();
        
        // Encrypt
        let ciphertext = if self.config.encryption_algorithm == "chacha20-poly1305" {
            SymmetricAlgorithm::ChaCha20Poly1305.encrypt(&key, &nonce, plaintext, aad)?
        } else {
            SymmetricAlgorithm::Aes256Gcm.encrypt(&key, &nonce, plaintext, aad)?
        };
        
        // Build encrypted envelope
        // Format: [magic:4][version:1][nonce:12][ciphertext_with_tag...]
        let mut envelope = Vec::with_capacity(17 + ciphertext.len());
        envelope.extend_from_slice(b"TSE\x01"); // Magic + version
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        
        Ok(envelope)
    }
    
    /// Decrypt data
    /// 
    /// # Arguments
    /// * `envelope` - Encrypted envelope
    /// * `auth_context` - Authentication context for key derivation
    pub fn decrypt(
        &self,
        envelope: &[u8],
        auth_context: &AuthContext,
    ) -> ShieldResult<Vec<u8>> {
        self.stats.decryptions.fetch_add(1, Ordering::Relaxed);
        
        // Parse envelope
        if envelope.len() < 17 {
            return Err(ShieldError::DecryptionFailed);
        }
        
        // Verify magic and version
        if &envelope[..4] != b"TSE\x01" {
            return Err(ShieldError::DecryptionFailed);
        }
        
        // Extract nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&envelope[4..16]);
        
        // Extract ciphertext
        let ciphertext = &envelope[16..];
        
        // Get decryption key
        let key = self.key_manager.get_encryption_key(&auth_context.identity.id)?;
        
        // AAD
        let aad = auth_context.identity.id.as_bytes();
        
        // Decrypt
        let plaintext = if self.config.encryption_algorithm == "chacha20-poly1305" {
            SymmetricAlgorithm::ChaCha20Poly1305.decrypt(&key, &nonce, ciphertext, aad)?
        } else {
            SymmetricAlgorithm::Aes256Gcm.decrypt(&key, &nonce, ciphertext, aad)?
        };
        
        Ok(plaintext)
    }
    
    /// Seal data to enclave hardware
    pub fn seal(&self, data: &[u8]) -> ShieldResult<SealedData> {
        self.stats.seals.fetch_add(1, Ordering::Relaxed);
        self.sealer.seal(data)
    }
    
    /// Unseal data from hardware
    pub fn unseal(&self, sealed: &SealedData) -> ShieldResult<Vec<u8>> {
        self.stats.unseals.fetch_add(1, Ordering::Relaxed);
        self.sealer.unseal(sealed)
    }
    
    /// Verify data integrity
    pub fn verify_integrity(&self, data: &[u8], expected_hash: &[u8; 32]) -> ShieldResult<()> {
        let actual_hash = sha256(data);
        
        if !crate::crypto::secure_compare(&actual_hash, expected_hash) {
            self.stats.integrity_failures.fetch_add(1, Ordering::Relaxed);
            return Err(ShieldError::IntegrityCheckFailed);
        }
        
        Ok(())
    }
    
    /// Compute integrity hash
    pub fn compute_hash(&self, data: &[u8]) -> [u8; 32] {
        sha256(data)
    }
    
    /// Create a Merkle proof for data
    pub fn create_merkle_proof(&self, data: &[&[u8]], index: usize) -> ShieldResult<Vec<[u8; 32]>> {
        self.integrity.create_proof(data, index)
    }
    
    /// Verify a Merkle proof
    pub fn verify_merkle_proof(
        &self,
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        root: &[u8; 32],
        index: usize,
    ) -> ShieldResult<bool> {
        self.integrity.verify_proof(leaf, proof, root, index)
    }
    
    /// Rotate encryption keys
    pub fn rotate_keys(&self) -> ShieldResult<()> {
        self.key_manager.rotate_keys()
    }
    
    /// Get statistics
    pub fn stats(&self) -> DataStats {
        DataStats {
            encryptions: self.stats.encryptions.load(Ordering::Relaxed),
            decryptions: self.stats.decryptions.load(Ordering::Relaxed),
            seals: self.stats.seals.load(Ordering::Relaxed),
            unseals: self.stats.unseals.load(Ordering::Relaxed),
            integrity_failures: self.stats.integrity_failures.load(Ordering::Relaxed),
        }
    }
    
    /// Securely delete data by overwriting
    pub fn secure_delete(&self, data: &mut [u8]) {
        if self.config.secure_deletion_enabled {
            crate::crypto::secure_zeroize(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataConfig;
    use crate::types::{AuthMethod, Capability, Identity};
    
    fn test_auth_context() -> AuthContext {
        AuthContext {
            identity: Identity {
                id: "test_user".into(),
                public_key: None,
                chain_id: None,
            },
            capabilities: vec![Capability::SubmitOperation],
            expires_at: u64::MAX,
            method: AuthMethod::ApiKey,
        }
    }
    
    #[test]
    fn test_shield_creation() {
        let config = DataConfig::default();
        let shield = DataShield::new(&config);
        assert!(shield.is_ok());
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let config = DataConfig::default();
        let shield = DataShield::new(&config).unwrap();
        let ctx = test_auth_context();
        
        let plaintext = b"Hello, Trinity Shield!";
        let encrypted = shield.encrypt(plaintext, &ctx).unwrap();
        
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.starts_with(b"TSE\x01"));
        
        let decrypted = shield.decrypt(&encrypted, &ctx).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
    
    #[test]
    fn test_seal_unseal() {
        let config = DataConfig::default();
        let shield = DataShield::new(&config).unwrap();
        
        let data = b"Sensitive data to seal";
        let sealed = shield.seal(data).unwrap();
        
        let unsealed = shield.unseal(&sealed).unwrap();
        assert_eq!(unsealed.as_slice(), data);
    }
    
    #[test]
    fn test_integrity() {
        let config = DataConfig::default();
        let shield = DataShield::new(&config).unwrap();
        
        let data = b"Data to verify";
        let hash = shield.compute_hash(data);
        
        assert!(shield.verify_integrity(data, &hash).is_ok());
        
        let wrong_hash = [0u8; 32];
        assert!(shield.verify_integrity(data, &wrong_hash).is_err());
    }
}
