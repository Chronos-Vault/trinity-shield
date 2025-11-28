//! Input validation against schemas

use crate::crypto::sha256;
use crate::error::{ShieldError, ShieldResult};
use crate::types::ValidationResult;

use alloc::string::String;
use alloc::vec::Vec;

/// Input validator for request payloads
pub struct InputValidator {
    /// Maximum field length
    max_field_length: usize,
}

impl InputValidator {
    /// Create a new input validator
    pub fn new(max_field_length: usize) -> Self {
        Self { max_field_length }
    }
    
    /// Validate input data
    pub fn validate(&self, data: &[u8]) -> ShieldResult<ValidationResult> {
        // Check if empty
        if data.is_empty() {
            return Err(ShieldError::ValidationFailed {
                field: "payload".into(),
                reason: "Empty payload".into(),
            });
        }
        
        // Check for encryption envelope
        let is_encrypted = self.is_encrypted_envelope(data);
        
        // Compute checksum
        let checksum = sha256(data);
        
        // Validate structure based on content type
        let payload = if is_encrypted {
            // For encrypted data, just pass through
            data.to_vec()
        } else {
            // Validate as plaintext
            self.validate_plaintext(data)?
        };
        
        Ok(ValidationResult {
            is_encrypted,
            payload,
            checksum,
        })
    }
    
    /// Check if data is an encrypted envelope
    fn is_encrypted_envelope(&self, data: &[u8]) -> bool {
        // Encrypted envelope format:
        // [magic:4][version:1][nonce:12][ciphertext...]
        const MAGIC: [u8; 4] = *b"TSE\x01"; // Trinity Shield Encrypted v1
        
        data.len() > 17 && data[..4] == MAGIC
    }
    
    /// Validate plaintext data
    fn validate_plaintext(&self, data: &[u8]) -> ShieldResult<Vec<u8>> {
        // Check for valid UTF-8 if it looks like text
        if data.iter().all(|&b| b < 128) {
            if let Ok(text) = core::str::from_utf8(data) {
                self.validate_text(text)?;
            }
        }
        
        // Check for protocol buffers or JSON structure
        if data.first() == Some(&b'{') || data.first() == Some(&b'[') {
            self.validate_json_structure(data)?;
        }
        
        Ok(data.to_vec())
    }
    
    /// Validate text content
    fn validate_text(&self, text: &str) -> ShieldResult<()> {
        // Check field length
        if text.len() > self.max_field_length {
            return Err(ShieldError::ValidationFailed {
                field: "text".into(),
                reason: format!("Exceeds maximum length of {}", self.max_field_length),
            });
        }
        
        // Check for control characters
        for (i, c) in text.chars().enumerate() {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                return Err(ShieldError::ValidationFailed {
                    field: "text".into(),
                    reason: format!("Invalid control character at position {}", i),
                });
            }
        }
        
        Ok(())
    }
    
    /// Basic JSON structure validation
    fn validate_json_structure(&self, data: &[u8]) -> ShieldResult<()> {
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escape = false;
        
        for (i, &byte) in data.iter().enumerate() {
            if escape {
                escape = false;
                continue;
            }
            
            match byte {
                b'\\' if in_string => escape = true,
                b'"' => in_string = !in_string,
                b'{' | b'[' if !in_string => {
                    depth += 1;
                    if depth > 100 {
                        return Err(ShieldError::ValidationFailed {
                            field: "json".into(),
                            reason: "Nesting too deep".into(),
                        });
                    }
                }
                b'}' | b']' if !in_string => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(ShieldError::ValidationFailed {
                            field: "json".into(),
                            reason: format!("Unbalanced bracket at position {}", i),
                        });
                    }
                }
                _ => {}
            }
        }
        
        if depth != 0 {
            return Err(ShieldError::ValidationFailed {
                field: "json".into(),
                reason: "Unbalanced brackets".into(),
            });
        }
        
        if in_string {
            return Err(ShieldError::ValidationFailed {
                field: "json".into(),
                reason: "Unclosed string".into(),
            });
        }
        
        Ok(())
    }
    
    /// Validate an operation payload
    pub fn validate_operation(&self, data: &[u8]) -> ShieldResult<()> {
        // Operation format:
        // [op_type:1][chain_id:1][nonce:8][params_len:4][params...]
        
        if data.len() < 14 {
            return Err(ShieldError::ValidationFailed {
                field: "operation".into(),
                reason: "Operation too short".into(),
            });
        }
        
        let op_type = data[0];
        if op_type == 0 || op_type > 8 {
            return Err(ShieldError::ValidationFailed {
                field: "op_type".into(),
                reason: "Invalid operation type".into(),
            });
        }
        
        let chain_id = data[1];
        if chain_id == 0 || chain_id > 3 {
            return Err(ShieldError::ValidationFailed {
                field: "chain_id".into(),
                reason: "Invalid chain ID".into(),
            });
        }
        
        let params_len = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
        
        if data.len() < 14 + params_len {
            return Err(ShieldError::ValidationFailed {
                field: "params".into(),
                reason: "Truncated parameters".into(),
            });
        }
        
        Ok(())
    }
    
    /// Validate a vote payload
    pub fn validate_vote(&self, data: &[u8]) -> ShieldResult<()> {
        // Vote format:
        // [chain_id:1][op_hash:32][approved:1][timestamp:8][nonce:8]
        
        if data.len() != 50 {
            return Err(ShieldError::ValidationFailed {
                field: "vote".into(),
                reason: format!("Invalid vote size: expected 50, got {}", data.len()),
            });
        }
        
        let chain_id = data[0];
        if chain_id == 0 || chain_id > 3 {
            return Err(ShieldError::ValidationFailed {
                field: "chain_id".into(),
                reason: "Invalid chain ID".into(),
            });
        }
        
        let approved = data[33];
        if approved > 1 {
            return Err(ShieldError::ValidationFailed {
                field: "approved".into(),
                reason: "Invalid approval flag".into(),
            });
        }
        
        Ok(())
    }
    
    /// Validate an address
    pub fn validate_address(&self, address: &str, chain: u8) -> ShieldResult<()> {
        match chain {
            1 => {
                // Ethereum/Arbitrum: 0x + 40 hex chars
                if !address.starts_with("0x") || address.len() != 42 {
                    return Err(ShieldError::ValidationFailed {
                        field: "address".into(),
                        reason: "Invalid Ethereum address format".into(),
                    });
                }
                if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ShieldError::ValidationFailed {
                        field: "address".into(),
                        reason: "Invalid hex in address".into(),
                    });
                }
            }
            2 => {
                // Solana: base58, 32-44 chars
                if address.len() < 32 || address.len() > 44 {
                    return Err(ShieldError::ValidationFailed {
                        field: "address".into(),
                        reason: "Invalid Solana address length".into(),
                    });
                }
                // Check base58 characters
                const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
                if !address.chars().all(|c| BASE58.contains(c)) {
                    return Err(ShieldError::ValidationFailed {
                        field: "address".into(),
                        reason: "Invalid base58 in address".into(),
                    });
                }
            }
            3 => {
                // TON: base64 or raw format
                if address.len() < 48 {
                    return Err(ShieldError::ValidationFailed {
                        field: "address".into(),
                        reason: "Invalid TON address length".into(),
                    });
                }
            }
            _ => {
                return Err(ShieldError::ValidationFailed {
                    field: "chain".into(),
                    reason: "Unknown chain".into(),
                });
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_validation() {
        let validator = InputValidator::new(1000);
        assert!(validator.validate(&[]).is_err());
    }
    
    #[test]
    fn test_simple_text() {
        let validator = InputValidator::new(1000);
        let result = validator.validate(b"Hello, World!");
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert!(!result.is_encrypted);
        assert_eq!(result.payload, b"Hello, World!");
    }
    
    #[test]
    fn test_json_validation() {
        let validator = InputValidator::new(1000);
        
        assert!(validator.validate(b"{}").is_ok());
        assert!(validator.validate(b"[]").is_ok());
        assert!(validator.validate(br#"{"key": "value"}"#).is_ok());
        assert!(validator.validate(br#"[1, 2, 3]"#).is_ok());
        assert!(validator.validate(br#"{"nested": {"deep": true}}"#).is_ok());
        
        // Invalid
        assert!(validator.validate(b"{").is_err());
        assert!(validator.validate(b"}").is_err());
    }
    
    #[test]
    fn test_ethereum_address() {
        let validator = InputValidator::new(1000);
        
        assert!(validator.validate_address(
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            1
        ).is_ok());
        
        assert!(validator.validate_address("invalid", 1).is_err());
        assert!(validator.validate_address("0x123", 1).is_err());
    }
    
    #[test]
    fn test_solana_address() {
        let validator = InputValidator::new(1000);
        
        assert!(validator.validate_address(
            "AjWeKXXgLpb2Cy3LfmqPjms3UkN1nAi596qBi8fRdLLQ",
            2
        ).is_ok());
        
        assert!(validator.validate_address("short", 2).is_err());
    }
    
    #[test]
    fn test_encrypted_detection() {
        let validator = InputValidator::new(1000);
        
        // Not encrypted
        let result = validator.validate(b"plain text").unwrap();
        assert!(!result.is_encrypted);
        
        // Encrypted envelope
        let mut encrypted = b"TSE\x01".to_vec();
        encrypted.extend_from_slice(&[0u8; 100]); // Fake nonce + ciphertext
        
        let result = validator.validate(&encrypted).unwrap();
        assert!(result.is_encrypted);
    }
}
