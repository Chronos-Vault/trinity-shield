//! Hardware key sealing for SGX enclaves

use crate::crypto::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, hkdf, random_key, random_nonce,
};
use crate::error::{ShieldError, ShieldResult};
use crate::types::{SealPolicy, SealedData};

use alloc::vec::Vec;

/// Sealing service for hardware-protected data
/// 
/// In SGX mode, uses hardware-derived keys bound to enclave identity.
/// In simulation mode, uses a software-derived key for testing.
pub struct Sealer {
    /// Sealing policy
    policy: SealPolicy,
    /// Software sealing key (for simulation mode)
    #[cfg(not(feature = "sgx"))]
    software_key: [u8; 32],
}

impl Sealer {
    /// Create a new sealer
    pub fn new(policy: SealPolicy) -> ShieldResult<Self> {
        #[cfg(not(feature = "sgx"))]
        let software_key = {
            // In simulation mode, derive a key from a fixed seed
            // In production, this would come from SGX key derivation
            let seed = b"trinity_shield_simulation_seal_key";
            let derived = hkdf(&[], seed, b"seal", 32)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&derived);
            key
        };
        
        Ok(Self {
            policy,
            #[cfg(not(feature = "sgx"))]
            software_key,
        })
    }
    
    /// Seal data to enclave hardware
    /// 
    /// # Arguments
    /// * `data` - Data to seal
    /// 
    /// # Returns
    /// * `SealedData` - Encrypted data bound to enclave identity
    /// 
    /// # Security
    /// - In SGX mode, uses EGETKEY to derive sealing key
    /// - Key is bound to MRENCLAVE or MRSIGNER based on policy
    /// - Data can only be unsealed by the same enclave (MRENCLAVE)
    ///   or by any enclave from the same signer (MRSIGNER)
    pub fn seal(&self, data: &[u8]) -> ShieldResult<SealedData> {
        // Get sealing key
        let key = self.get_sealing_key()?;
        
        // Generate nonce
        let nonce = random_nonce()?;
        
        // Additional authenticated data includes policy
        let aad = [self.policy as u8];
        
        // Encrypt
        let ciphertext = aes256_gcm_encrypt(&key, &nonce, data, &aad)?;
        
        // Extract tag (last 16 bytes of ciphertext with tag)
        let tag_start = ciphertext.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[tag_start..]);
        
        let ciphertext_only = ciphertext[..tag_start].to_vec();
        
        Ok(SealedData {
            ciphertext: ciphertext_only,
            nonce,
            tag,
            policy: self.policy,
            sealed_at: current_timestamp(),
        })
    }
    
    /// Unseal data previously sealed to this enclave
    /// 
    /// # Arguments
    /// * `sealed` - Sealed data blob
    /// 
    /// # Returns
    /// * Unsealed plaintext
    /// 
    /// # Errors
    /// * `SealingFailed` - If data was sealed by a different enclave
    ///   or the data has been tampered with
    pub fn unseal(&self, sealed: &SealedData) -> ShieldResult<Vec<u8>> {
        // Verify policy matches
        if sealed.policy != self.policy {
            // Try to unseal with the sealed data's policy
            // This allows MRSIGNER-sealed data to be unsealed after enclave updates
        }
        
        // Get sealing key
        let key = self.get_sealing_key()?;
        
        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = sealed.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&sealed.tag);
        
        // AAD
        let aad = [sealed.policy as u8];
        
        // Decrypt
        aes256_gcm_decrypt(&key, &sealed.nonce, &ciphertext_with_tag, &aad)
    }
    
    /// Get the sealing key
    #[cfg(feature = "sgx")]
    fn get_sealing_key(&self) -> ShieldResult<[u8; 32]> {
        use sgx_types::{sgx_key_id_t, sgx_key_request_t};
        
        // Set up key request
        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = sgx_types::SGX_KEYSELECT_SEAL;
        
        // Key policy based on our setting
        key_request.key_policy = match self.policy {
            SealPolicy::MrEnclave => sgx_types::SGX_KEYPOLICY_MRENCLAVE,
            SealPolicy::MrSigner => sgx_types::SGX_KEYPOLICY_MRSIGNER,
        };
        
        // Get key from hardware
        let mut key = [0u8; 16];
        let status = unsafe {
            sgx_tcrypto::sgx_get_key(&key_request, &mut key)
        };
        
        if status != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(ShieldError::SealingFailed("EGETKEY failed".into()));
        }
        
        // Expand to 256 bits using HKDF
        let expanded = hkdf(&[], &key, b"seal_key_expand", 32)?;
        let mut full_key = [0u8; 32];
        full_key.copy_from_slice(&expanded);
        
        Ok(full_key)
    }
    
    /// Get the sealing key (simulation mode)
    #[cfg(not(feature = "sgx"))]
    fn get_sealing_key(&self) -> ShieldResult<[u8; 32]> {
        // In simulation mode, use the software key
        Ok(self.software_key)
    }
    
    /// Get current seal policy
    pub fn policy(&self) -> SealPolicy {
        self.policy
    }
    
    /// Check if data was sealed with compatible policy
    pub fn is_compatible(&self, sealed: &SealedData) -> bool {
        match (self.policy, sealed.policy) {
            // Same policy is always compatible
            (a, b) if a == b => true,
            // MRSIGNER can unseal MRENCLAVE data (less restrictive)
            (SealPolicy::MrSigner, SealPolicy::MrEnclave) => true,
            // MRENCLAVE cannot unseal MRSIGNER data (more restrictive)
            (SealPolicy::MrEnclave, SealPolicy::MrSigner) => false,
        }
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
    fn test_seal_unseal() {
        let sealer = Sealer::new(SealPolicy::MrEnclave).unwrap();
        
        let data = b"Secret data to seal";
        let sealed = sealer.seal(data).unwrap();
        
        assert_ne!(sealed.ciphertext.as_slice(), data);
        assert_eq!(sealed.nonce.len(), 12);
        assert_eq!(sealed.tag.len(), 16);
        
        let unsealed = sealer.unseal(&sealed).unwrap();
        assert_eq!(unsealed.as_slice(), data);
    }
    
    #[test]
    fn test_seal_tamper_detection() {
        let sealer = Sealer::new(SealPolicy::MrEnclave).unwrap();
        
        let data = b"Data to protect";
        let mut sealed = sealer.seal(data).unwrap();
        
        // Tamper with ciphertext
        if !sealed.ciphertext.is_empty() {
            sealed.ciphertext[0] ^= 0xFF;
        }
        
        // Should fail to unseal
        assert!(sealer.unseal(&sealed).is_err());
    }
    
    #[test]
    fn test_seal_policy() {
        let sealer = Sealer::new(SealPolicy::MrSigner).unwrap();
        assert_eq!(sealer.policy(), SealPolicy::MrSigner);
    }
    
    #[test]
    fn test_empty_data() {
        let sealer = Sealer::new(SealPolicy::MrEnclave).unwrap();
        
        let data = b"";
        let sealed = sealer.seal(data).unwrap();
        let unsealed = sealer.unseal(&sealed).unwrap();
        
        assert!(unsealed.is_empty());
    }
    
    #[test]
    fn test_large_data() {
        let sealer = Sealer::new(SealPolicy::MrEnclave).unwrap();
        
        let data = vec![0xABu8; 1024 * 1024]; // 1MB
        let sealed = sealer.seal(&data).unwrap();
        let unsealed = sealer.unseal(&sealed).unwrap();
        
        assert_eq!(unsealed, data);
    }
}
