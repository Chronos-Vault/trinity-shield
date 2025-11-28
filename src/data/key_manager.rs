//! Key management and rotation

use crate::crypto::{derive_chain_key, hkdf, random_key};
use crate::error::{ShieldError, ShieldResult};

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Key manager for encryption key lifecycle
pub struct KeyManager {
    /// Master key (sealed in production)
    master_key: [u8; 32],
    /// Derived keys cache
    derived_keys: RwLock<BTreeMap<String, DerivedKey>>,
    /// Key rotation enabled
    rotation_enabled: bool,
    /// Rotation interval in hours
    rotation_interval_hours: u32,
    /// Current key version
    key_version: AtomicU64,
    /// Key generation timestamp
    created_at: u64,
}

struct DerivedKey {
    key: [u8; 32],
    version: u64,
    created_at: u64,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new(rotation_enabled: bool, rotation_interval_hours: u32) -> ShieldResult<Self> {
        // Generate master key
        let master_key = random_key()?;
        
        Ok(Self {
            master_key,
            derived_keys: RwLock::new(BTreeMap::new()),
            rotation_enabled,
            rotation_interval_hours,
            key_version: AtomicU64::new(1),
            created_at: current_timestamp(),
        })
    }
    
    /// Create key manager with existing master key
    pub fn with_master_key(
        master_key: [u8; 32],
        rotation_enabled: bool,
        rotation_interval_hours: u32,
    ) -> Self {
        Self {
            master_key,
            derived_keys: RwLock::new(BTreeMap::new()),
            rotation_enabled,
            rotation_interval_hours,
            key_version: AtomicU64::new(1),
            created_at: current_timestamp(),
        }
    }
    
    /// Get encryption key for an identity
    pub fn get_encryption_key(&self, identity_id: &str) -> ShieldResult<[u8; 32]> {
        let version = self.key_version.load(Ordering::Acquire);
        let cache_key = format!("{}:{}", identity_id, version);
        
        // Check cache
        if let Ok(keys) = self.derived_keys.read() {
            if let Some(dk) = keys.get(&cache_key) {
                if !self.is_key_expired(dk) {
                    return Ok(dk.key);
                }
            }
        }
        
        // Derive new key
        let key = self.derive_key(identity_id, "encryption")?;
        
        // Cache it
        if let Ok(mut keys) = self.derived_keys.write() {
            keys.insert(cache_key, DerivedKey {
                key,
                version,
                created_at: current_timestamp(),
            });
        }
        
        Ok(key)
    }
    
    /// Get signing key for a chain
    pub fn get_signing_key(&self, chain_id: u8) -> ShieldResult<[u8; 32]> {
        derive_chain_key(&self.master_key, chain_id, "signing")
    }
    
    /// Derive a key for a specific purpose
    fn derive_key(&self, context: &str, purpose: &str) -> ShieldResult<[u8; 32]> {
        let info = format!("{}:{}:{}", context, purpose, self.key_version.load(Ordering::Acquire));
        let derived = hkdf(&[], &self.master_key, info.as_bytes(), 32)?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(key)
    }
    
    /// Check if a derived key is expired
    fn is_key_expired(&self, key: &DerivedKey) -> bool {
        if !self.rotation_enabled {
            return false;
        }
        
        let now = current_timestamp();
        let age_hours = (now - key.created_at) / 3600;
        
        age_hours >= self.rotation_interval_hours as u64
    }
    
    /// Rotate keys (increment version)
    pub fn rotate_keys(&self) -> ShieldResult<()> {
        // Increment key version
        self.key_version.fetch_add(1, Ordering::Release);
        
        // Clear cache
        if let Ok(mut keys) = self.derived_keys.write() {
            keys.clear();
        }
        
        Ok(())
    }
    
    /// Get current key version
    pub fn key_version(&self) -> u64 {
        self.key_version.load(Ordering::Acquire)
    }
    
    /// Check if rotation is due
    pub fn needs_rotation(&self) -> bool {
        if !self.rotation_enabled {
            return false;
        }
        
        let now = current_timestamp();
        let age_hours = (now - self.created_at) / 3600;
        
        age_hours >= self.rotation_interval_hours as u64
    }
    
    /// Clean up expired keys from cache
    pub fn cleanup_cache(&self) {
        if let Ok(mut keys) = self.derived_keys.write() {
            keys.retain(|_, key| !self.is_key_expired(key));
        }
    }
    
    /// Get number of cached keys
    pub fn cached_keys(&self) -> usize {
        self.derived_keys.read().map(|k| k.len()).unwrap_or(0)
    }
    
    /// Export master key (for backup/migration)
    /// 
    /// # Security
    /// This should only be called to seal the key for backup.
    /// Never expose the raw key outside the enclave.
    pub fn export_master_key(&self) -> &[u8; 32] {
        &self.master_key
    }
    
    /// Derive a data encryption key (DEK) for a specific resource
    pub fn derive_dek(&self, resource_id: &str) -> ShieldResult<[u8; 32]> {
        let info = format!("dek:{}", resource_id);
        let derived = hkdf(&[], &self.master_key, info.as_bytes(), 32)?;
        
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&derived);
        Ok(dek)
    }
    
    /// Derive a key encryption key (KEK) for wrapping other keys
    pub fn derive_kek(&self, purpose: &str) -> ShieldResult<[u8; 32]> {
        let info = format!("kek:{}", purpose);
        let derived = hkdf(&[], &self.master_key, info.as_bytes(), 32)?;
        
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&derived);
        Ok(kek)
    }
    
    /// Wrap a key with the KEK
    pub fn wrap_key(&self, key: &[u8; 32], kek_purpose: &str) -> ShieldResult<Vec<u8>> {
        let kek = self.derive_kek(kek_purpose)?;
        let nonce = crate::crypto::random_nonce()?;
        
        let ciphertext = crate::crypto::aes256_gcm_encrypt(&kek, &nonce, key, b"")?;
        
        // Format: [nonce:12][ciphertext_with_tag]
        let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ciphertext);
        
        Ok(wrapped)
    }
    
    /// Unwrap a key with the KEK
    pub fn unwrap_key(&self, wrapped: &[u8], kek_purpose: &str) -> ShieldResult<[u8; 32]> {
        if wrapped.len() < 44 { // 12 nonce + 32 key + 16 tag
            return Err(ShieldError::KeyDerivationFailed);
        }
        
        let kek = self.derive_kek(kek_purpose)?;
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&wrapped[..12]);
        
        let ciphertext = &wrapped[12..];
        
        let plaintext = crate::crypto::aes256_gcm_decrypt(&kek, &nonce, ciphertext, b"")?;
        
        if plaintext.len() != 32 {
            return Err(ShieldError::KeyDerivationFailed);
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(key)
    }
}

fn current_timestamp() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    #[cfg(not(feature = "std"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_manager_creation() {
        let manager = KeyManager::new(true, 24);
        assert!(manager.is_ok());
    }
    
    #[test]
    fn test_get_encryption_key() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let key1 = manager.get_encryption_key("user1").unwrap();
        let key2 = manager.get_encryption_key("user1").unwrap();
        
        // Same identity should give same key
        assert_eq!(key1, key2);
    }
    
    #[test]
    fn test_different_identities() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let key1 = manager.get_encryption_key("user1").unwrap();
        let key2 = manager.get_encryption_key("user2").unwrap();
        
        // Different identities should give different keys
        assert_ne!(key1, key2);
    }
    
    #[test]
    fn test_key_rotation() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let key1 = manager.get_encryption_key("user1").unwrap();
        
        // Rotate keys
        manager.rotate_keys().unwrap();
        
        let key2 = manager.get_encryption_key("user1").unwrap();
        
        // After rotation, key should be different
        assert_ne!(key1, key2);
    }
    
    #[test]
    fn test_chain_keys() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let key1 = manager.get_signing_key(1).unwrap();
        let key2 = manager.get_signing_key(2).unwrap();
        
        // Different chains should have different keys
        assert_ne!(key1, key2);
    }
    
    #[test]
    fn test_key_wrap_unwrap() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let original_key = random_key().unwrap();
        
        let wrapped = manager.wrap_key(&original_key, "test").unwrap();
        let unwrapped = manager.unwrap_key(&wrapped, "test").unwrap();
        
        assert_eq!(original_key, unwrapped);
    }
    
    #[test]
    fn test_dek_derivation() {
        let manager = KeyManager::new(false, 24).unwrap();
        
        let dek1 = manager.derive_dek("resource1").unwrap();
        let dek2 = manager.derive_dek("resource2").unwrap();
        
        assert_ne!(dek1, dek2);
    }
}
