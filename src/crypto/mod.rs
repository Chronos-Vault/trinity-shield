//! Cryptographic primitives for Trinity Shield
//! 
//! Provides secure cryptographic operations including:
//! - Key generation and management
//! - Digital signatures (Ed25519, Secp256k1, Dilithium)
//! - Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
//! - Hash functions (SHA-256, SHA-3, BLAKE3)
//! - Key derivation (HKDF)

use crate::error::{ShieldError, ShieldResult};
use crate::types::{KeyAlgorithm, PublicKey, Signature};

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

mod symmetric;
mod signing;
mod hashing;
mod kdf;

pub use symmetric::*;
pub use signing::*;
pub use hashing::*;
pub use kdf::*;

/// Global initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the cryptographic subsystem
/// 
/// Must be called before any cryptographic operations.
/// Safe to call multiple times.
pub fn init() -> ShieldResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }
    
    // Verify cryptographic primitives
    verify_primitives()?;
    
    Ok(())
}

/// Verify cryptographic primitives are working correctly
fn verify_primitives() -> ShieldResult<()> {
    // Test hash function
    let hash = sha256(b"test");
    if hash.len() != 32 {
        return Err(ShieldError::CryptoError("SHA-256 test failed".into()));
    }
    
    // Test CSPRNG
    let random_bytes = random_bytes(32)?;
    if random_bytes.iter().all(|&b| b == 0) {
        return Err(ShieldError::RngFailed);
    }
    
    Ok(())
}

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> ShieldResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    
    #[cfg(feature = "std")]
    {
        use getrandom::getrandom;
        getrandom(&mut bytes).map_err(|_| ShieldError::RngFailed)?;
    }
    
    #[cfg(not(feature = "std"))]
    {
        // In no_std, use SGX random or panic
        #[cfg(feature = "sgx")]
        {
            use sgx_tcrypto::rsgx_read_rand;
            rsgx_tcrypto::rsgx_read_rand(&mut bytes)
                .map_err(|_| ShieldError::RngFailed)?;
        }
        
        #[cfg(not(feature = "sgx"))]
        {
            return Err(ShieldError::NotSupported(
                "no_std requires SGX for random".into()
            ));
        }
    }
    
    Ok(bytes)
}

/// Generate a random nonce (12 bytes for AES-GCM)
pub fn random_nonce() -> ShieldResult<[u8; 12]> {
    let bytes = random_bytes(12)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Generate a random 256-bit key
pub fn random_key() -> ShieldResult<[u8; 32]> {
    let bytes = random_bytes(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Secure memory comparison (constant time)
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Securely zeroize memory
pub fn secure_zeroize(data: &mut [u8]) {
    data.zeroize();
}

/// Key pair for asymmetric operations
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    /// Secret key (zeroized on drop)
    secret_key: Vec<u8>,
    /// Public key
    #[zeroize(skip)]
    public_key: PublicKey,
    /// Algorithm type
    #[zeroize(skip)]
    algorithm: KeyAlgorithm,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(algorithm: KeyAlgorithm) -> ShieldResult<Self> {
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let secret = random_bytes(32)?;
                let (sk, pk) = ed25519_keypair_from_seed(&secret)?;
                Ok(Self {
                    secret_key: sk.to_vec(),
                    public_key: PublicKey::new(pk, algorithm),
                    algorithm,
                })
            }
            KeyAlgorithm::Secp256k1 => {
                let secret = random_bytes(32)?;
                let pk = secp256k1_public_key(&secret)?;
                Ok(Self {
                    secret_key: secret,
                    public_key: PublicKey::new(pk, algorithm),
                    algorithm,
                })
            }
            KeyAlgorithm::Dilithium5 => {
                #[cfg(feature = "pqcrypto-dilithium")]
                {
                    let (pk, sk) = dilithium_keypair()?;
                    Ok(Self {
                        secret_key: sk,
                        public_key: PublicKey::new(pk, algorithm),
                        algorithm,
                    })
                }
                
                #[cfg(not(feature = "pqcrypto-dilithium"))]
                Err(ShieldError::NotSupported("Dilithium not compiled in".into()))
            }
        }
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> ShieldResult<Signature> {
        let sig_bytes = match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                ed25519_sign(&self.secret_key, message)?
            }
            KeyAlgorithm::Secp256k1 => {
                secp256k1_sign(&self.secret_key, message)?
            }
            KeyAlgorithm::Dilithium5 => {
                #[cfg(feature = "pqcrypto-dilithium")]
                {
                    dilithium_sign(&self.secret_key, message)?
                }
                
                #[cfg(not(feature = "pqcrypto-dilithium"))]
                return Err(ShieldError::NotSupported("Dilithium not compiled in".into()));
            }
        };
        
        Ok(Signature::new(sig_bytes, self.algorithm))
    }
    
    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    
    /// Get the algorithm
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
    
    /// Export secret key bytes (use with caution!)
    /// 
    /// # Security
    /// The returned bytes must be handled securely and zeroized after use.
    pub fn export_secret(&self) -> &[u8] {
        &self.secret_key
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("algorithm", &self.algorithm)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
    
    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        
        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
    }
    
    #[test]
    fn test_secure_compare() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";
        
        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
    }
    
    #[test]
    fn test_keypair_ed25519() {
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let message = b"test message";
        
        let sig = kp.sign(message).unwrap();
        assert!(!sig.bytes.is_empty());
    }
    
    #[test]
    fn test_keypair_secp256k1() {
        let kp = KeyPair::generate(KeyAlgorithm::Secp256k1).unwrap();
        let message = b"test message";
        
        let sig = kp.sign(message).unwrap();
        assert!(!sig.bytes.is_empty());
    }
}
