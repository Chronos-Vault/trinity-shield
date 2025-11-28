//! Multi-chain authentication

use crate::config::ApplicationConfig;
use crate::error::{ShieldError, ShieldResult};
use crate::types::{
    AuthContext, AuthMethod, Capability, ChainId, Identity,
    KeyAlgorithm, PublicKey, RequestSource,
};

use alloc::string::String;
use alloc::vec::Vec;

/// Multi-chain authenticator
/// 
/// Supports authentication via:
/// - Signature verification (Arbitrum/Ethereum, Solana, TON)
/// - API keys (for internal services)
/// - Attestation (enclave-to-enclave)
pub struct Authenticator {
    /// Configuration
    config: ApplicationConfig,
}

impl Authenticator {
    /// Create a new authenticator
    pub fn new(config: &ApplicationConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
    
    /// Authenticate a request
    pub fn authenticate(
        &self,
        request: &[u8],
        source: &RequestSource,
    ) -> ShieldResult<AuthContext> {
        // Try to parse authentication header from request
        let auth_header = self.extract_auth_header(request)?;
        
        match auth_header {
            AuthHeader::Signature { chain_id, public_key, signature, message } => {
                self.authenticate_signature(chain_id, &public_key, &signature, &message, source)
            }
            AuthHeader::ApiKey(key) => {
                self.authenticate_api_key(&key, source)
            }
            AuthHeader::Attestation(quote) => {
                self.authenticate_attestation(&quote, source)
            }
        }
    }
    
    fn extract_auth_header(&self, request: &[u8]) -> ShieldResult<AuthHeader> {
        // Parse request to extract auth header
        // Format: [type:1][length:2][data...]
        
        if request.len() < 3 {
            return Err(ShieldError::AuthenticationFailed(
                "Request too short for auth header".into()
            ));
        }
        
        let auth_type = request[0];
        let length = u16::from_le_bytes([request[1], request[2]]) as usize;
        
        if request.len() < 3 + length {
            return Err(ShieldError::AuthenticationFailed(
                "Incomplete auth header".into()
            ));
        }
        
        let data = &request[3..3 + length];
        
        match auth_type {
            0 => self.parse_signature_auth(data),
            1 => self.parse_api_key_auth(data),
            2 => self.parse_attestation_auth(data),
            _ => Err(ShieldError::AuthenticationFailed(
                "Unknown auth type".into()
            )),
        }
    }
    
    fn parse_signature_auth(&self, data: &[u8]) -> ShieldResult<AuthHeader> {
        // Format: [chain_id:1][pubkey:32][sig_len:2][signature][msg_len:2][message]
        if data.len() < 37 {
            return Err(ShieldError::AuthenticationFailed("Invalid signature auth".into()));
        }
        
        let chain_id = ChainId::from_u8(data[0])
            .ok_or_else(|| ShieldError::AuthenticationFailed("Invalid chain ID".into()))?;
        
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[1..33]);
        
        let sig_len = u16::from_le_bytes([data[33], data[34]]) as usize;
        if data.len() < 35 + sig_len + 2 {
            return Err(ShieldError::AuthenticationFailed("Invalid signature length".into()));
        }
        
        let signature = data[35..35 + sig_len].to_vec();
        
        let msg_start = 35 + sig_len;
        let msg_len = u16::from_le_bytes([data[msg_start], data[msg_start + 1]]) as usize;
        
        if data.len() < msg_start + 2 + msg_len {
            return Err(ShieldError::AuthenticationFailed("Invalid message length".into()));
        }
        
        let message = data[msg_start + 2..msg_start + 2 + msg_len].to_vec();
        
        Ok(AuthHeader::Signature {
            chain_id,
            public_key,
            signature,
            message,
        })
    }
    
    fn parse_api_key_auth(&self, data: &[u8]) -> ShieldResult<AuthHeader> {
        let key = String::from_utf8(data.to_vec())
            .map_err(|_| ShieldError::AuthenticationFailed("Invalid API key encoding".into()))?;
        Ok(AuthHeader::ApiKey(key))
    }
    
    fn parse_attestation_auth(&self, data: &[u8]) -> ShieldResult<AuthHeader> {
        Ok(AuthHeader::Attestation(data.to_vec()))
    }
    
    fn authenticate_signature(
        &self,
        chain_id: ChainId,
        public_key: &[u8; 32],
        signature: &[u8],
        message: &[u8],
        _source: &RequestSource,
    ) -> ShieldResult<AuthContext> {
        // Determine algorithm based on chain
        let algorithm = match chain_id {
            ChainId::Arbitrum => KeyAlgorithm::Secp256k1,
            ChainId::Solana => KeyAlgorithm::Ed25519,
            ChainId::Ton => KeyAlgorithm::Ed25519, // Or Dilithium5 for quantum-resistant
        };
        
        // Check if algorithm is allowed
        let alg_name = match algorithm {
            KeyAlgorithm::Ed25519 => "ed25519",
            KeyAlgorithm::Secp256k1 => "secp256k1",
            KeyAlgorithm::Dilithium5 => "dilithium5",
        };
        
        if !self.config.allowed_algorithms.iter().any(|a| a.to_lowercase() == alg_name) {
            return Err(ShieldError::AuthenticationFailed(
                "Signature algorithm not allowed".into()
            ));
        }
        
        // Verify signature
        let valid = match algorithm {
            KeyAlgorithm::Ed25519 => {
                crate::crypto::ed25519_verify(public_key, message, signature)?
            }
            KeyAlgorithm::Secp256k1 => {
                crate::crypto::secp256k1_verify(public_key, message, signature)?
            }
            KeyAlgorithm::Dilithium5 => {
                #[cfg(feature = "pqcrypto-dilithium")]
                {
                    crate::crypto::dilithium_verify(public_key, message, signature)?
                }
                #[cfg(not(feature = "pqcrypto-dilithium"))]
                {
                    return Err(ShieldError::NotSupported("Dilithium".into()));
                }
            }
        };
        
        if !valid {
            return Err(ShieldError::SignatureInvalid);
        }
        
        // Create identity from public key
        let identity = Identity {
            id: hex::encode(public_key),
            public_key: Some(PublicKey::new(*public_key, algorithm)),
            chain_id: Some(chain_id),
        };
        
        // Default capabilities for authenticated users
        let capabilities = vec![Capability::SubmitOperation];
        
        // Calculate session expiry
        let now = current_timestamp();
        let expires_at = now + self.config.session_timeout_seconds;
        
        Ok(AuthContext {
            identity,
            capabilities,
            expires_at,
            method: AuthMethod::Signature { chain_id },
        })
    }
    
    fn authenticate_api_key(
        &self,
        key: &str,
        _source: &RequestSource,
    ) -> ShieldResult<AuthContext> {
        // In production, validate against stored API keys
        // For now, accept any key starting with "trinity_"
        
        if !key.starts_with("trinity_") {
            return Err(ShieldError::AuthenticationFailed("Invalid API key".into()));
        }
        
        let identity = Identity {
            id: format!("apikey:{}", &key[..16.min(key.len())]),
            public_key: None,
            chain_id: None,
        };
        
        let now = current_timestamp();
        
        Ok(AuthContext {
            identity,
            capabilities: vec![Capability::SubmitOperation],
            expires_at: now + self.config.session_timeout_seconds,
            method: AuthMethod::ApiKey,
        })
    }
    
    fn authenticate_attestation(
        &self,
        quote: &[u8],
        _source: &RequestSource,
    ) -> ShieldResult<AuthContext> {
        // Verify SGX attestation quote
        // In production, this would validate against Intel's attestation service
        
        if quote.len() < 64 {
            return Err(ShieldError::AttestationFailed("Quote too short".into()));
        }
        
        // Extract MRENCLAVE from quote (simplified)
        let mut mrenclave = [0u8; 32];
        mrenclave.copy_from_slice(&quote[..32]);
        
        let identity = Identity {
            id: format!("enclave:{}", hex::encode(&mrenclave[..8])),
            public_key: None,
            chain_id: None,
        };
        
        let now = current_timestamp();
        
        Ok(AuthContext {
            identity,
            capabilities: vec![
                Capability::SubmitOperation,
                Capability::Vote, // Enclaves can vote
            ],
            expires_at: now + self.config.session_timeout_seconds,
            method: AuthMethod::Attestation,
        })
    }
}

/// Authentication header types
enum AuthHeader {
    Signature {
        chain_id: ChainId,
        public_key: [u8; 32],
        signature: Vec<u8>,
        message: Vec<u8>,
    },
    ApiKey(String),
    Attestation(Vec<u8>),
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
    fn test_authenticator_creation() {
        let config = ApplicationConfig::default();
        let _auth = Authenticator::new(&config);
    }
    
    #[test]
    fn test_api_key_format() {
        let config = ApplicationConfig::default();
        let auth = Authenticator::new(&config);
        
        let source = RequestSource {
            ip_address: "127.0.0.1".into(),
            user_agent: None,
            timestamp: 0,
            chain_id: None,
        };
        
        // Build API key auth request
        let key = "trinity_test_key_123";
        let key_bytes = key.as_bytes();
        let mut request = vec![1u8]; // Type 1 = API key
        request.extend_from_slice(&(key_bytes.len() as u16).to_le_bytes());
        request.extend_from_slice(key_bytes);
        
        let result = auth.authenticate(&request, &source);
        assert!(result.is_ok());
        
        let ctx = result.unwrap();
        assert!(ctx.identity.id.starts_with("apikey:"));
    }
}
