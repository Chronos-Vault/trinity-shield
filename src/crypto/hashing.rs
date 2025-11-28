//! Hash functions for Trinity Shield

use sha2::{Sha256, Sha512, Digest};
use sha3::{Sha3_256, Keccak256};
use alloc::vec::Vec;

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-512 hash
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Keccak-256 hash (Ethereum compatible)
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256 (Bitcoin style)
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Hash multiple items together
pub fn hash_concat(items: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for item in items {
        hasher.update(item);
    }
    hasher.finalize().into()
}

/// Merkle tree root computation
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        
        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_concat(&[&chunk[0], &chunk[1]])
            } else {
                hash_concat(&[&chunk[0], &chunk[0]]) // Duplicate for odd
            };
            next_level.push(hash);
        }
        
        current_level = next_level;
    }
    
    current_level[0]
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC key length is invalid");
    mac.update(data);
    
    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(key, data);
    crate::crypto::secure_compare(&computed, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
        
        // Known test vector
        let expected = hex::decode(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ).unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }
    
    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_merkle_root() {
        let leaves = vec![
            sha256(b"a"),
            sha256(b"b"),
            sha256(b"c"),
            sha256(b"d"),
        ];
        
        let root = merkle_root(&leaves);
        assert_eq!(root.len(), 32);
        
        // Root should be deterministic
        let root2 = merkle_root(&leaves);
        assert_eq!(root, root2);
    }
    
    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"message";
        
        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));
        
        let wrong_mac = [0u8; 32];
        assert!(!hmac_sha256_verify(key, data, &wrong_mac));
    }
}
