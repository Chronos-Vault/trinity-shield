//! Request validation and sanitization

use crate::error::{ShieldError, ShieldResult};

/// Request validator
pub struct RequestValidator {
    /// Maximum request size in bytes
    max_size: usize,
}

impl RequestValidator {
    /// Create a new request validator
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }
    
    /// Validate request size
    pub fn validate_size(&self, request: &[u8]) -> ShieldResult<()> {
        if request.len() > self.max_size {
            Err(ShieldError::RequestTooLarge {
                max_size: self.max_size,
            })
        } else {
            Ok(())
        }
    }
    
    /// Full request validation
    pub fn validate(&self, request: &[u8]) -> ShieldResult<()> {
        // Check size
        self.validate_size(request)?;
        
        // Check for null bytes in unexpected places (basic sanitization)
        // This is a simple check; more sophisticated validation depends on protocol
        
        // Check minimum size for any meaningful request
        if request.is_empty() {
            return Err(ShieldError::ValidationFailed {
                field: "request".into(),
                reason: "Empty request".into(),
            });
        }
        
        Ok(())
    }
    
    /// Validate and sanitize JSON-like content
    pub fn validate_json(&self, data: &[u8]) -> ShieldResult<()> {
        self.validate_size(data)?;
        
        // Check for valid UTF-8
        if core::str::from_utf8(data).is_err() {
            return Err(ShieldError::ValidationFailed {
                field: "content".into(),
                reason: "Invalid UTF-8".into(),
            });
        }
        
        // Check for balanced braces (basic JSON structure check)
        let mut brace_count = 0i32;
        let mut bracket_count = 0i32;
        let mut in_string = false;
        let mut escape_next = false;
        
        for &byte in data {
            if escape_next {
                escape_next = false;
                continue;
            }
            
            match byte {
                b'\\' if in_string => escape_next = true,
                b'"' => in_string = !in_string,
                b'{' if !in_string => brace_count += 1,
                b'}' if !in_string => brace_count -= 1,
                b'[' if !in_string => bracket_count += 1,
                b']' if !in_string => bracket_count -= 1,
                _ => {}
            }
            
            // Check for negative counts (unbalanced closing)
            if brace_count < 0 || bracket_count < 0 {
                return Err(ShieldError::ValidationFailed {
                    field: "content".into(),
                    reason: "Unbalanced brackets".into(),
                });
            }
        }
        
        // Check final balance
        if brace_count != 0 || bracket_count != 0 {
            return Err(ShieldError::ValidationFailed {
                field: "content".into(),
                reason: "Unbalanced brackets".into(),
            });
        }
        
        Ok(())
    }
    
    /// Check for common injection patterns
    pub fn check_injection(&self, data: &[u8]) -> ShieldResult<()> {
        let data_str = match core::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Ok(()), // Binary data, skip string checks
        };
        
        // Check for SQL injection patterns
        let sql_patterns = [
            "' OR ", "' AND ", "'; DROP", "--", "/*", "*/",
            "UNION SELECT", "1=1", "1 = 1",
        ];
        
        let lower = data_str.to_lowercase();
        for pattern in &sql_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return Err(ShieldError::ValidationFailed {
                    field: "content".into(),
                    reason: "Potential injection detected".into(),
                });
            }
        }
        
        // Check for script injection
        let script_patterns = ["<script", "javascript:", "onerror=", "onload="];
        for pattern in &script_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return Err(ShieldError::ValidationFailed {
                    field: "content".into(),
                    reason: "Potential script injection".into(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate hexadecimal data
    pub fn validate_hex(&self, data: &str) -> ShieldResult<()> {
        // Remove 0x prefix if present
        let hex_str = data.strip_prefix("0x").unwrap_or(data);
        
        if hex_str.is_empty() {
            return Err(ShieldError::ValidationFailed {
                field: "hex_data".into(),
                reason: "Empty hex string".into(),
            });
        }
        
        if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ShieldError::ValidationFailed {
                field: "hex_data".into(),
                reason: "Invalid hex characters".into(),
            });
        }
        
        if hex_str.len() % 2 != 0 {
            return Err(ShieldError::ValidationFailed {
                field: "hex_data".into(),
                reason: "Odd number of hex digits".into(),
            });
        }
        
        Ok(())
    }
    
    /// Validate address format (blockchain address)
    pub fn validate_address(&self, address: &str, prefix: &str) -> ShieldResult<()> {
        if !address.starts_with(prefix) {
            return Err(ShieldError::ValidationFailed {
                field: "address".into(),
                reason: format!("Address must start with '{}'", prefix),
            });
        }
        
        // For Ethereum-like addresses
        if prefix == "0x" {
            let hex_part = &address[2..];
            if hex_part.len() != 40 {
                return Err(ShieldError::ValidationFailed {
                    field: "address".into(),
                    reason: "Invalid address length".into(),
                });
            }
            self.validate_hex(hex_part)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_size_validation() {
        let validator = RequestValidator::new(100);
        
        assert!(validator.validate_size(&[0u8; 50]).is_ok());
        assert!(validator.validate_size(&[0u8; 100]).is_ok());
        assert!(validator.validate_size(&[0u8; 101]).is_err());
    }
    
    #[test]
    fn test_empty_request() {
        let validator = RequestValidator::new(100);
        assert!(validator.validate(&[]).is_err());
    }
    
    #[test]
    fn test_json_validation() {
        let validator = RequestValidator::new(1000);
        
        assert!(validator.validate_json(b"{}").is_ok());
        assert!(validator.validate_json(b"[]").is_ok());
        assert!(validator.validate_json(br#"{"key": "value"}"#).is_ok());
        assert!(validator.validate_json(br#"[1, 2, 3]"#).is_ok());
        
        // Unbalanced
        assert!(validator.validate_json(b"{").is_err());
        assert!(validator.validate_json(b"}").is_err());
        assert!(validator.validate_json(b"[}").is_err());
    }
    
    #[test]
    fn test_injection_detection() {
        let validator = RequestValidator::new(1000);
        
        assert!(validator.check_injection(b"normal text").is_ok());
        assert!(validator.check_injection(b"SELECT * FROM users").is_ok()); // Simple SELECT is ok
        
        // SQL injection
        assert!(validator.check_injection(b"' OR 1=1").is_err());
        assert!(validator.check_injection(b"'; DROP TABLE users;--").is_err());
        
        // Script injection
        assert!(validator.check_injection(b"<script>alert(1)</script>").is_err());
        assert!(validator.check_injection(b"javascript:alert(1)").is_err());
    }
    
    #[test]
    fn test_hex_validation() {
        let validator = RequestValidator::new(1000);
        
        assert!(validator.validate_hex("0x1234abcd").is_ok());
        assert!(validator.validate_hex("1234abcd").is_ok());
        assert!(validator.validate_hex("ABCD").is_ok());
        
        // Invalid
        assert!(validator.validate_hex("").is_err());
        assert!(validator.validate_hex("0x").is_err());
        assert!(validator.validate_hex("0xGG").is_err());
        assert!(validator.validate_hex("123").is_err()); // Odd length
    }
    
    #[test]
    fn test_address_validation() {
        let validator = RequestValidator::new(1000);
        
        // Valid Ethereum address
        assert!(validator.validate_address(
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            "0x"
        ).is_ok());
        
        // Wrong prefix
        assert!(validator.validate_address("1234", "0x").is_err());
        
        // Wrong length
        assert!(validator.validate_address("0x1234", "0x").is_err());
    }
}
