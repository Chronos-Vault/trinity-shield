//! # Quantum-Resistant Cryptography Module
//!
//! Provides post-quantum cryptographic primitives for Trinity Shield:
//! - **ML-KEM-1024** (CRYSTALS-Kyber): Key encapsulation for secure key exchange
//! - **CRYSTALS-Dilithium-5**: Digital signatures resistant to quantum attacks
//!
//! ## Security Level
//!
//! Both algorithms provide NIST Level 5 security (equivalent to AES-256):
//! - Secure against both classical and quantum computers
//! - Required for TON validator (quantum-resistant recovery chain)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use trinity_shield::quantum::{QuantumSigner, QuantumKeyExchange};
//!
//! // Create quantum-resistant signer
//! let signer = QuantumSigner::new()?;
//! let signature = signer.sign(b"message")?;
//!
//! // Key encapsulation
//! let kex = QuantumKeyExchange::new()?;
//! let (ciphertext, shared_secret) = kex.encapsulate(&peer_public_key)?;
//! ```

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::{ShieldError, ShieldResult};

/// Dilithium-5 signature size (4627 bytes)
pub const DILITHIUM_SIG_SIZE: usize = 4627;

/// Dilithium-5 public key size (2592 bytes)
pub const DILITHIUM_PK_SIZE: usize = 2592;

/// Dilithium-5 secret key size (4896 bytes)
pub const DILITHIUM_SK_SIZE: usize = 4896;

/// ML-KEM-1024 public key size (1568 bytes)
pub const MLKEM_PK_SIZE: usize = 1568;

/// ML-KEM-1024 secret key size (3168 bytes)
pub const MLKEM_SK_SIZE: usize = 3168;

/// ML-KEM-1024 ciphertext size (1568 bytes)
pub const MLKEM_CT_SIZE: usize = 1568;

/// ML-KEM-1024 shared secret size (32 bytes)
pub const MLKEM_SS_SIZE: usize = 32;

/// Dilithium-5 public key
#[derive(Clone)]
pub struct DilithiumPublicKey {
    bytes: [u8; DILITHIUM_PK_SIZE],
}

impl DilithiumPublicKey {
    /// Get public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> ShieldResult<Self> {
        if bytes.len() != DILITHIUM_PK_SIZE {
            return Err(ShieldError::InvalidKey(
                format!("Invalid Dilithium public key size: {} (expected {})", bytes.len(), DILITHIUM_PK_SIZE)
            ));
        }
        let mut pk = [0u8; DILITHIUM_PK_SIZE];
        pk.copy_from_slice(bytes);
        Ok(Self { bytes: pk })
    }
}

/// Dilithium-5 secret key (zeroized on drop)
pub struct DilithiumSecretKey {
    bytes: [u8; DILITHIUM_SK_SIZE],
}

impl Drop for DilithiumSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Dilithium-5 signature
pub struct DilithiumSignature {
    bytes: [u8; DILITHIUM_SIG_SIZE],
}

impl DilithiumSignature {
    /// Get signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> ShieldResult<Self> {
        if bytes.len() != DILITHIUM_SIG_SIZE {
            return Err(ShieldError::InvalidSignature(
                format!("Invalid Dilithium signature size: {} (expected {})", bytes.len(), DILITHIUM_SIG_SIZE)
            ));
        }
        let mut sig = [0u8; DILITHIUM_SIG_SIZE];
        sig.copy_from_slice(bytes);
        Ok(Self { bytes: sig })
    }
}

/// Quantum-resistant digital signature using CRYSTALS-Dilithium-5
pub struct QuantumSigner {
    public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,
}

impl QuantumSigner {
    /// Generate new Dilithium-5 keypair
    pub fn new() -> ShieldResult<Self> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::*;
            
            let (pk, sk) = dilithium5::keypair();
            
            let mut pk_bytes = [0u8; DILITHIUM_PK_SIZE];
            let mut sk_bytes = [0u8; DILITHIUM_SK_SIZE];
            
            pk_bytes.copy_from_slice(pk.as_bytes());
            sk_bytes.copy_from_slice(sk.as_bytes());
            
            Ok(Self {
                public_key: DilithiumPublicKey { bytes: pk_bytes },
                secret_key: DilithiumSecretKey { bytes: sk_bytes },
            })
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Sign message with Dilithium-5
    pub fn sign(&self, message: &[u8]) -> ShieldResult<crate::types::Signature> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::*;
            
            let sk = dilithium5::SecretKey::from_bytes(&self.secret_key.bytes)
                .map_err(|_| ShieldError::InvalidKey("Failed to parse Dilithium secret key".into()))?;
            
            let sig = dilithium5::detached_sign(message, &sk);
            
            let mut sig_bytes = Vec::with_capacity(DILITHIUM_SIG_SIZE);
            sig_bytes.extend_from_slice(sig.as_bytes());
            
            Ok(crate::types::Signature::Dilithium(sig_bytes))
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Verify Dilithium-5 signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> ShieldResult<bool> {
        Self::verify_with_key(&self.public_key, message, signature)
    }
    
    /// Verify signature with explicit public key
    pub fn verify_with_key(public_key: &DilithiumPublicKey, message: &[u8], signature: &[u8]) -> ShieldResult<bool> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::*;
            
            let pk = dilithium5::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|_| ShieldError::InvalidKey("Failed to parse Dilithium public key".into()))?;
            
            let sig = dilithium5::DetachedSignature::from_bytes(signature)
                .map_err(|_| ShieldError::InvalidSignature("Failed to parse Dilithium signature".into()))?;
            
            Ok(dilithium5::verify_detached_signature(&sig, message, &pk).is_ok())
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Get public key
    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.public_key
    }
}

/// ML-KEM-1024 public key
#[derive(Clone)]
pub struct MlKemPublicKey {
    bytes: [u8; MLKEM_PK_SIZE],
}

impl MlKemPublicKey {
    /// Get public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> ShieldResult<Self> {
        if bytes.len() != MLKEM_PK_SIZE {
            return Err(ShieldError::InvalidKey(
                format!("Invalid ML-KEM public key size: {} (expected {})", bytes.len(), MLKEM_PK_SIZE)
            ));
        }
        let mut pk = [0u8; MLKEM_PK_SIZE];
        pk.copy_from_slice(bytes);
        Ok(Self { bytes: pk })
    }
}

/// ML-KEM-1024 secret key (zeroized on drop)
pub struct MlKemSecretKey {
    bytes: [u8; MLKEM_SK_SIZE],
}

impl Drop for MlKemSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Quantum-resistant key exchange using ML-KEM-1024 (CRYSTALS-Kyber)
pub struct QuantumKeyExchange {
    public_key: MlKemPublicKey,
    secret_key: MlKemSecretKey,
}

impl QuantumKeyExchange {
    /// Generate new ML-KEM-1024 keypair
    pub fn new() -> ShieldResult<Self> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_kyber::kyber1024;
            use pqcrypto_traits::kem::*;
            
            let (pk, sk) = kyber1024::keypair();
            
            let mut pk_bytes = [0u8; MLKEM_PK_SIZE];
            let mut sk_bytes = [0u8; MLKEM_SK_SIZE];
            
            pk_bytes.copy_from_slice(pk.as_bytes());
            sk_bytes.copy_from_slice(sk.as_bytes());
            
            Ok(Self {
                public_key: MlKemPublicKey { bytes: pk_bytes },
                secret_key: MlKemSecretKey { bytes: sk_bytes },
            })
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Encapsulate shared secret to peer's public key
    pub fn encapsulate(&self, peer_public_key: &MlKemPublicKey) -> ShieldResult<(Vec<u8>, [u8; MLKEM_SS_SIZE])> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_kyber::kyber1024;
            use pqcrypto_traits::kem::*;
            
            let pk = kyber1024::PublicKey::from_bytes(&peer_public_key.bytes)
                .map_err(|_| ShieldError::InvalidKey("Failed to parse ML-KEM public key".into()))?;
            
            let (ss, ct) = kyber1024::encapsulate(&pk);
            
            let mut shared_secret = [0u8; MLKEM_SS_SIZE];
            shared_secret.copy_from_slice(ss.as_bytes());
            
            Ok((ct.as_bytes().to_vec(), shared_secret))
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Decapsulate shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext: &[u8]) -> ShieldResult<[u8; MLKEM_SS_SIZE]> {
        #[cfg(feature = "quantum")]
        {
            use pqcrypto_kyber::kyber1024;
            use pqcrypto_traits::kem::*;
            
            let sk = kyber1024::SecretKey::from_bytes(&self.secret_key.bytes)
                .map_err(|_| ShieldError::InvalidKey("Failed to parse ML-KEM secret key".into()))?;
            
            let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| ShieldError::InvalidCiphertext("Failed to parse ML-KEM ciphertext".into()))?;
            
            let ss = kyber1024::decapsulate(&ct, &sk);
            
            let mut shared_secret = [0u8; MLKEM_SS_SIZE];
            shared_secret.copy_from_slice(ss.as_bytes());
            
            Ok(shared_secret)
        }
        
        #[cfg(not(feature = "quantum"))]
        {
            Err(ShieldError::FeatureDisabled("quantum".into()))
        }
    }
    
    /// Get public key
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public_key
    }
}

#[cfg(all(test, feature = "quantum"))]
mod tests {
    use super::*;
    
    #[test]
    fn test_dilithium_sign_verify() {
        let signer = QuantumSigner::new().unwrap();
        let message = b"Hello, quantum world!";
        
        let signature = signer.sign(message).unwrap();
        
        if let crate::types::Signature::Dilithium(sig_bytes) = signature {
            assert!(signer.verify(message, &sig_bytes).unwrap());
            
            // Wrong message should fail
            assert!(!signer.verify(b"wrong message", &sig_bytes).unwrap());
        } else {
            panic!("Expected Dilithium signature");
        }
    }
    
    #[test]
    fn test_mlkem_encapsulate_decapsulate() {
        let alice = QuantumKeyExchange::new().unwrap();
        let bob = QuantumKeyExchange::new().unwrap();
        
        // Alice encapsulates to Bob
        let (ciphertext, alice_shared) = alice.encapsulate(bob.public_key()).unwrap();
        
        // Bob decapsulates
        let bob_shared = bob.decapsulate(&ciphertext).unwrap();
        
        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_key_sizes() {
        let signer = QuantumSigner::new().unwrap();
        assert_eq!(signer.public_key().as_bytes().len(), DILITHIUM_PK_SIZE);
        
        let kex = QuantumKeyExchange::new().unwrap();
        assert_eq!(kex.public_key().as_bytes().len(), MLKEM_PK_SIZE);
    }
}
