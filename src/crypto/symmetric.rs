//! Symmetric encryption for Trinity Shield

use crate::error::{ShieldError, ShieldResult};
use alloc::vec::Vec;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

/// Encrypt data using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 256-bit (32 byte) encryption key
/// * `nonce` - 96-bit (12 byte) nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (optional, can be empty)
/// 
/// # Returns
/// * Ciphertext with 16-byte authentication tag appended
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> ShieldResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ShieldError::EncryptionFailed)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        })
        .map_err(|_| ShieldError::EncryptionFailed)
}

/// Decrypt data using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 256-bit (32 byte) encryption key
/// * `nonce` - 96-bit (12 byte) nonce used during encryption
/// * `ciphertext` - Encrypted data with tag appended
/// * `aad` - Additional authenticated data (must match encryption)
/// 
/// # Returns
/// * Decrypted plaintext
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> ShieldResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| ShieldError::DecryptionFailed)?;
    
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        })
        .map_err(|_| ShieldError::DecryptionFailed)
}

/// Encrypt data using ChaCha20-Poly1305
/// 
/// # Arguments
/// * `key` - 256-bit (32 byte) encryption key
/// * `nonce` - 96-bit (12 byte) nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (optional)
/// 
/// # Returns
/// * Ciphertext with 16-byte authentication tag appended
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> ShieldResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ShieldError::EncryptionFailed)?;
    
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    
    cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        })
        .map_err(|_| ShieldError::EncryptionFailed)
}

/// Decrypt data using ChaCha20-Poly1305
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> ShieldResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ShieldError::DecryptionFailed)?;
    
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad,
        })
        .map_err(|_| ShieldError::DecryptionFailed)
}

/// Encryption algorithm choice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM (NIST standard, hardware acceleration)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (constant-time, no timing attacks)
    ChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    /// Encrypt with the selected algorithm
    pub fn encrypt(
        self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ShieldResult<Vec<u8>> {
        match self {
            Self::Aes256Gcm => aes256_gcm_encrypt(key, nonce, plaintext, aad),
            Self::ChaCha20Poly1305 => chacha20_poly1305_encrypt(key, nonce, plaintext, aad),
        }
    }
    
    /// Decrypt with the selected algorithm
    pub fn decrypt(
        self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> ShieldResult<Vec<u8>> {
        match self {
            Self::Aes256Gcm => aes256_gcm_decrypt(key, nonce, ciphertext, aad),
            Self::ChaCha20Poly1305 => chacha20_poly1305_decrypt(key, nonce, ciphertext, aad),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{random_key, random_nonce};
    
    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let plaintext = b"Hello, Trinity Shield!";
        let aad = b"additional data";
        
        let ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aes256_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes256_gcm_wrong_key() {
        let key1 = random_key().unwrap();
        let key2 = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let plaintext = b"secret";
        
        let ciphertext = aes256_gcm_encrypt(&key1, &nonce, plaintext, b"").unwrap();
        let result = aes256_gcm_decrypt(&key2, &nonce, &ciphertext, b"");
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aes256_gcm_wrong_aad() {
        let key = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let plaintext = b"secret";
        
        let ciphertext = aes256_gcm_encrypt(&key, &nonce, plaintext, b"aad1").unwrap();
        let result = aes256_gcm_decrypt(&key, &nonce, &ciphertext, b"aad2");
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_chacha20_roundtrip() {
        let key = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let plaintext = b"Hello, ChaCha20!";
        
        let ciphertext = chacha20_poly1305_encrypt(&key, &nonce, plaintext, b"").unwrap();
        let decrypted = chacha20_poly1305_decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_algorithm_enum() {
        let key = random_key().unwrap();
        let nonce = random_nonce().unwrap();
        let plaintext = b"test";
        
        for alg in [SymmetricAlgorithm::Aes256Gcm, SymmetricAlgorithm::ChaCha20Poly1305] {
            let ct = alg.encrypt(&key, &nonce, plaintext, b"").unwrap();
            let pt = alg.decrypt(&key, &nonce, &ct, b"").unwrap();
            assert_eq!(plaintext.as_slice(), pt.as_slice());
        }
    }
}
