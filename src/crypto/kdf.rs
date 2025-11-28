//! Key derivation functions for Trinity Shield

use crate::error::{ShieldError, ShieldResult};
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HKDF-SHA256 Extract
/// 
/// Extracts a pseudorandom key from input key material.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() {
        &[0u8; 32]
    } else {
        salt
    };
    
    let mut mac = HmacSha256::new_from_slice(salt)
        .expect("HMAC key length is valid");
    mac.update(ikm);
    
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 Expand
/// 
/// Expands a pseudorandom key to the desired length.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> ShieldResult<Vec<u8>> {
    if length > 255 * 32 {
        return Err(ShieldError::KeyDerivationFailed);
    }
    
    let n = (length + 31) / 32;
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut mac = HmacSha256::new_from_slice(prk)
            .expect("HMAC key length is valid");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        
        t = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&t);
    }
    
    output.truncate(length);
    Ok(output)
}

/// HKDF-SHA256 (combined Extract + Expand)
/// 
/// # Arguments
/// * `salt` - Optional salt (can be empty)
/// * `ikm` - Input key material
/// * `info` - Context-specific info
/// * `length` - Desired output length
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> ShieldResult<Vec<u8>> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// Derive multiple keys from a master key
pub fn derive_keys(
    master_key: &[u8; 32],
    labels: &[&str],
) -> ShieldResult<Vec<[u8; 32]>> {
    labels
        .iter()
        .map(|label| {
            let derived = hkdf(&[], master_key, label.as_bytes(), 32)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&derived);
            Ok(key)
        })
        .collect()
}

/// PBKDF2-HMAC-SHA256 for password-based key derivation
/// 
/// # Arguments
/// * `password` - User password
/// * `salt` - Unique salt (should be random)
/// * `iterations` - Number of iterations (recommend >= 100,000)
/// * `output_len` - Desired output length
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> ShieldResult<Vec<u8>> {
    if iterations == 0 {
        return Err(ShieldError::KeyDerivationFailed);
    }
    
    let num_blocks = (output_len + 31) / 32;
    let mut result = Vec::with_capacity(output_len);
    
    for block_num in 1..=(num_blocks as u32) {
        let block = pbkdf2_f(password, salt, iterations, block_num)?;
        result.extend_from_slice(&block);
    }
    
    result.truncate(output_len);
    Ok(result)
}

fn pbkdf2_f(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    block_num: u32,
) -> ShieldResult<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(password)
        .expect("HMAC key length is valid");
    
    // U_1 = PRF(Password, Salt || INT(i))
    mac.update(salt);
    mac.update(&block_num.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut result = u;
    
    // U_2 ... U_c
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password)
            .expect("HMAC key length is valid");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        
        // XOR into result
        for (r, u) in result.iter_mut().zip(u.iter()) {
            *r ^= u;
        }
    }
    
    Ok(result.into())
}

/// Derive a chain-specific key
pub fn derive_chain_key(
    master_key: &[u8; 32],
    chain_id: u8,
    purpose: &str,
) -> ShieldResult<[u8; 32]> {
    let info = [
        &[chain_id],
        purpose.as_bytes(),
    ].concat();
    
    let derived = hkdf(&[], master_key, &info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hkdf_extract() {
        let salt = b"salt";
        let ikm = b"input key material";
        
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), 32);
        
        // Should be deterministic
        let prk2 = hkdf_extract(salt, ikm);
        assert_eq!(prk, prk2);
    }
    
    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; 32];
        let info = b"context info";
        
        let key32 = hkdf_expand(&prk, info, 32).unwrap();
        assert_eq!(key32.len(), 32);
        
        let key64 = hkdf_expand(&prk, info, 64).unwrap();
        assert_eq!(key64.len(), 64);
        
        // First 32 bytes should match
        assert_eq!(&key32[..], &key64[..32]);
    }
    
    #[test]
    fn test_hkdf_full() {
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"application";
        
        let key = hkdf(salt, ikm, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_derive_multiple_keys() {
        let master = [0x42u8; 32];
        let labels = vec!["encryption", "signing", "auth"];
        
        let keys = derive_keys(&master, &labels).unwrap();
        assert_eq!(keys.len(), 3);
        
        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }
    
    #[test]
    fn test_pbkdf2() {
        let password = b"password";
        let salt = b"salt";
        
        let key = pbkdf2(password, salt, 1000, 32).unwrap();
        assert_eq!(key.len(), 32);
        
        // Should be deterministic
        let key2 = pbkdf2(password, salt, 1000, 32).unwrap();
        assert_eq!(key, key2);
    }
    
    #[test]
    fn test_derive_chain_key() {
        let master = [0x42u8; 32];
        
        let key1 = derive_chain_key(&master, 1, "signing").unwrap();
        let key2 = derive_chain_key(&master, 2, "signing").unwrap();
        let key3 = derive_chain_key(&master, 1, "encryption").unwrap();
        
        // Different chains = different keys
        assert_ne!(key1, key2);
        // Different purposes = different keys
        assert_ne!(key1, key3);
    }
}
