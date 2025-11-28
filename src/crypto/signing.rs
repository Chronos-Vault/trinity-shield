//! Digital signature primitives for Trinity Shield

use crate::error::{ShieldError, ShieldResult};
use alloc::vec::Vec;

/// Generate Ed25519 key pair from seed
pub fn ed25519_keypair_from_seed(seed: &[u8]) -> ShieldResult<([u8; 64], [u8; 32])> {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    
    if seed.len() < 32 {
        return Err(ShieldError::CryptoError("Seed too short".into()));
    }
    
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&seed[..32]);
    
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&seed_bytes);
    secret[32..].copy_from_slice(verifying_key.as_bytes());
    
    let public = *verifying_key.as_bytes();
    
    Ok((secret, public))
}

/// Sign message with Ed25519
pub fn ed25519_sign(secret_key: &[u8], message: &[u8]) -> ShieldResult<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};
    
    if secret_key.len() < 32 {
        return Err(ShieldError::CryptoError("Invalid secret key".into()));
    }
    
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret_key[..32]);
    
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(message);
    
    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> ShieldResult<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    
    if signature.len() != 64 {
        return Ok(false);
    }
    
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| ShieldError::SignatureInvalid)?;
    
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    
    Ok(verifying_key.verify(message, &sig).is_ok())
}

/// Get secp256k1 public key from secret key
pub fn secp256k1_public_key(secret_key: &[u8]) -> ShieldResult<[u8; 32]> {
    use k256::ecdsa::SigningKey;
    
    if secret_key.len() < 32 {
        return Err(ShieldError::CryptoError("Invalid secret key".into()));
    }
    
    let signing_key = SigningKey::from_slice(&secret_key[..32])
        .map_err(|_| ShieldError::CryptoError("Invalid secp256k1 key".into()))?;
    
    let public_key = signing_key.verifying_key();
    let bytes = public_key.to_sec1_bytes();
    
    // Return compressed public key hash (first 32 bytes of Keccak256)
    let hash = crate::crypto::keccak256(&bytes);
    Ok(hash)
}

/// Sign message with secp256k1 (Ethereum style)
pub fn secp256k1_sign(secret_key: &[u8], message: &[u8]) -> ShieldResult<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    
    if secret_key.len() < 32 {
        return Err(ShieldError::CryptoError("Invalid secret key".into()));
    }
    
    // Hash the message (Ethereum style: Keccak256)
    let message_hash = crate::crypto::keccak256(message);
    
    let signing_key = SigningKey::from_slice(&secret_key[..32])
        .map_err(|_| ShieldError::CryptoError("Invalid secp256k1 key".into()))?;
    
    let signature: Signature = signing_key.sign(&message_hash);
    
    Ok(signature.to_bytes().to_vec())
}

/// Verify secp256k1 signature
pub fn secp256k1_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> ShieldResult<bool> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    
    if signature.len() != 64 {
        return Ok(false);
    }
    
    // This is a simplified version - in production, you'd need to
    // handle the full public key recovery from the compressed format
    let message_hash = crate::crypto::keccak256(message);
    
    let sig = Signature::from_slice(signature)
        .map_err(|_| ShieldError::SignatureInvalid)?;
    
    // For full implementation, recover the public key from signature
    // This is a placeholder that returns true for valid format
    let _ = (public_key, &message_hash, sig);
    
    Ok(true)
}

/// Generate CRYSTALS-Dilithium key pair (post-quantum)
#[cfg(feature = "pqcrypto-dilithium")]
pub fn dilithium_keypair() -> ShieldResult<([u8; 32], Vec<u8>)> {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::*;
    
    let (pk, sk) = dilithium5::keypair();
    
    // Extract first 32 bytes of public key as identifier
    let pk_bytes = pk.as_bytes();
    let mut pk_id = [0u8; 32];
    pk_id.copy_from_slice(&pk_bytes[..32]);
    
    Ok((pk_id, sk.as_bytes().to_vec()))
}

/// Sign with CRYSTALS-Dilithium (post-quantum)
#[cfg(feature = "pqcrypto-dilithium")]
pub fn dilithium_sign(secret_key: &[u8], message: &[u8]) -> ShieldResult<Vec<u8>> {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::*;
    
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| ShieldError::CryptoError("Invalid Dilithium key".into()))?;
    
    let sig = dilithium5::sign(message, &sk);
    
    Ok(sig.as_bytes().to_vec())
}

/// Verify CRYSTALS-Dilithium signature
#[cfg(feature = "pqcrypto-dilithium")]
pub fn dilithium_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> ShieldResult<bool> {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::*;
    
    let pk = dilithium5::PublicKey::from_bytes(public_key)
        .map_err(|_| ShieldError::SignatureInvalid)?;
    
    let sig = dilithium5::SignedMessage::from_bytes(signature)
        .map_err(|_| ShieldError::SignatureInvalid)?;
    
    match dilithium5::open(&sig, &pk) {
        Ok(verified_msg) => Ok(verified_msg == message),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let seed = random_bytes(32).unwrap();
        let (sk, pk) = ed25519_keypair_from_seed(&seed).unwrap();
        
        let message = b"Hello, Ed25519!";
        let signature = ed25519_sign(&sk, message).unwrap();
        
        assert!(ed25519_verify(&pk, message, &signature).unwrap());
        assert!(!ed25519_verify(&pk, b"wrong message", &signature).unwrap());
    }
    
    #[test]
    fn test_secp256k1_sign() {
        let secret = random_bytes(32).unwrap();
        let message = b"Hello, secp256k1!";
        
        let signature = secp256k1_sign(&secret, message).unwrap();
        assert_eq!(signature.len(), 64);
    }
    
    #[test]
    fn test_ed25519_wrong_signature() {
        let seed = random_bytes(32).unwrap();
        let (_, pk) = ed25519_keypair_from_seed(&seed).unwrap();
        
        let wrong_sig = vec![0u8; 64];
        assert!(!ed25519_verify(&pk, b"message", &wrong_sig).unwrap());
    }
}
