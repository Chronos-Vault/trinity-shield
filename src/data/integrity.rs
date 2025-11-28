//! Data integrity verification using Merkle proofs

use crate::crypto::{merkle_root, sha256};
use crate::error::{ShieldError, ShieldResult};

use alloc::vec::Vec;

/// Integrity verifier using Merkle trees
pub struct IntegrityVerifier {
    // No state needed currently
}

impl IntegrityVerifier {
    /// Create a new integrity verifier
    pub fn new() -> Self {
        Self {}
    }
    
    /// Compute hash of data
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        sha256(data)
    }
    
    /// Compute Merkle root of multiple data items
    pub fn compute_root(&self, items: &[&[u8]]) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = items.iter().map(|item| sha256(item)).collect();
        merkle_root(&leaves)
    }
    
    /// Create a Merkle proof for an item at a given index
    /// 
    /// # Arguments
    /// * `items` - All items in the tree
    /// * `index` - Index of the item to prove
    /// 
    /// # Returns
    /// * Proof path (sibling hashes from leaf to root)
    pub fn create_proof(&self, items: &[&[u8]], index: usize) -> ShieldResult<Vec<[u8; 32]>> {
        if items.is_empty() {
            return Err(ShieldError::ValidationFailed {
                field: "items".into(),
                reason: "Cannot create proof for empty tree".into(),
            });
        }
        
        if index >= items.len() {
            return Err(ShieldError::ValidationFailed {
                field: "index".into(),
                reason: "Index out of bounds".into(),
            });
        }
        
        // Compute all leaf hashes
        let mut leaves: Vec<[u8; 32]> = items.iter().map(|item| sha256(item)).collect();
        
        // Pad to power of 2
        let target_len = leaves.len().next_power_of_two();
        while leaves.len() < target_len {
            leaves.push(leaves[leaves.len() - 1]); // Duplicate last
        }
        
        // Build proof
        let mut proof = Vec::new();
        let mut idx = index;
        let mut level = leaves;
        
        while level.len() > 1 {
            // Get sibling
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < level.len() {
                proof.push(level[sibling_idx]);
            }
            
            // Move to parent level
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }
            
            level = next_level;
            idx /= 2;
        }
        
        Ok(proof)
    }
    
    /// Verify a Merkle proof
    /// 
    /// # Arguments
    /// * `leaf` - Hash of the leaf to verify
    /// * `proof` - Proof path
    /// * `root` - Expected Merkle root
    /// * `index` - Position of the leaf
    /// 
    /// # Returns
    /// * `Ok(true)` if proof is valid
    pub fn verify_proof(
        &self,
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        root: &[u8; 32],
        index: usize,
    ) -> ShieldResult<bool> {
        let mut computed = *leaf;
        let mut idx = index;
        
        for sibling in proof {
            computed = if idx % 2 == 0 {
                hash_pair(&computed, sibling)
            } else {
                hash_pair(sibling, &computed)
            };
            idx /= 2;
        }
        
        Ok(crate::crypto::secure_compare(&computed, root))
    }
    
    /// Verify data against a known hash
    pub fn verify_hash(&self, data: &[u8], expected: &[u8; 32]) -> bool {
        let actual = sha256(data);
        crate::crypto::secure_compare(&actual, expected)
    }
    
    /// Compute and verify HMAC for data
    pub fn verify_hmac(&self, data: &[u8], key: &[u8], expected: &[u8; 32]) -> bool {
        crate::crypto::hmac_sha256_verify(key, data, expected)
    }
    
    /// Create an integrity-protected envelope
    /// 
    /// Format: [data...][hmac:32]
    pub fn protect(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let hmac = crate::crypto::hmac_sha256(key, data);
        let mut protected = data.to_vec();
        protected.extend_from_slice(&hmac);
        protected
    }
    
    /// Verify and extract data from protected envelope
    pub fn verify_and_extract(&self, protected: &[u8], key: &[u8]) -> ShieldResult<Vec<u8>> {
        if protected.len() < 32 {
            return Err(ShieldError::IntegrityCheckFailed);
        }
        
        let data_len = protected.len() - 32;
        let data = &protected[..data_len];
        let expected_hmac: [u8; 32] = protected[data_len..].try_into()
            .map_err(|_| ShieldError::IntegrityCheckFailed)?;
        
        if !self.verify_hmac(data, key, &expected_hmac) {
            return Err(ShieldError::IntegrityCheckFailed);
        }
        
        Ok(data.to_vec())
    }
}

impl Default for IntegrityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash two nodes together (for Merkle tree)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash() {
        let verifier = IntegrityVerifier::new();
        
        let data = b"test data";
        let hash = verifier.hash(data);
        
        assert_eq!(hash.len(), 32);
        assert!(verifier.verify_hash(data, &hash));
    }
    
    #[test]
    fn test_merkle_root() {
        let verifier = IntegrityVerifier::new();
        
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let root = verifier.compute_root(&items);
        
        assert_eq!(root.len(), 32);
        
        // Same items should give same root
        let root2 = verifier.compute_root(&items);
        assert_eq!(root, root2);
    }
    
    #[test]
    fn test_merkle_proof() {
        let verifier = IntegrityVerifier::new();
        
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let root = verifier.compute_root(&items);
        
        // Create and verify proof for each item
        for (i, item) in items.iter().enumerate() {
            let proof = verifier.create_proof(&items, i).unwrap();
            let leaf = sha256(item);
            
            let valid = verifier.verify_proof(&leaf, &proof, &root, i).unwrap();
            assert!(valid, "Proof failed for item {}", i);
        }
    }
    
    #[test]
    fn test_merkle_proof_invalid() {
        let verifier = IntegrityVerifier::new();
        
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let root = verifier.compute_root(&items);
        
        let proof = verifier.create_proof(&items, 0).unwrap();
        let wrong_leaf = sha256(b"wrong");
        
        let valid = verifier.verify_proof(&wrong_leaf, &proof, &root, 0).unwrap();
        assert!(!valid);
    }
    
    #[test]
    fn test_hmac_protection() {
        let verifier = IntegrityVerifier::new();
        let key = b"secret_key";
        let data = b"important data";
        
        let protected = verifier.protect(data, key);
        let extracted = verifier.verify_and_extract(&protected, key).unwrap();
        
        assert_eq!(extracted.as_slice(), data);
    }
    
    #[test]
    fn test_hmac_tamper_detection() {
        let verifier = IntegrityVerifier::new();
        let key = b"secret_key";
        let data = b"important data";
        
        let mut protected = verifier.protect(data, key);
        
        // Tamper with data
        if !protected.is_empty() {
            protected[0] ^= 0xFF;
        }
        
        let result = verifier.verify_and_extract(&protected, key);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_empty_items() {
        let verifier = IntegrityVerifier::new();
        
        let items: Vec<&[u8]> = vec![];
        let result = verifier.create_proof(&items, 0);
        assert!(result.is_err());
    }
}
