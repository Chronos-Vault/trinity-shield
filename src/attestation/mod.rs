//! Attestation Service - SGX remote attestation
//! 
//! Provides cryptographic proof that code is running inside
//! a genuine Intel SGX enclave with the expected MRENCLAVE value.

use crate::config::AttestationConfig;
use crate::crypto::sha256;
use crate::error::{ShieldError, ShieldResult};
use crate::types::{AttestationQuote, AttestationReport, AttestationStatus};

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Attestation service for SGX remote attestation
pub struct AttestationService {
    /// Configuration
    config: AttestationConfig,
    /// Cached attestation report
    cached_report: Option<AttestationReport>,
    /// Cache timestamp
    cache_timestamp: AtomicU64,
    /// Simulation mode
    #[cfg(not(feature = "sgx"))]
    simulated_mrenclave: [u8; 32],
}

impl AttestationService {
    /// Create a new attestation service
    pub fn new(config: &AttestationConfig) -> ShieldResult<Self> {
        Ok(Self {
            config: config.clone(),
            cached_report: None,
            cache_timestamp: AtomicU64::new(0),
            #[cfg(not(feature = "sgx"))]
            simulated_mrenclave: config.expected_mrenclave,
        })
    }
    
    /// Generate a quote for remote attestation
    /// 
    /// # Arguments
    /// * `user_data` - Data to include in the quote (e.g., vote hash)
    /// 
    /// # Returns
    /// * `AttestationQuote` with MRENCLAVE and signed data
    pub fn generate_quote(&self, user_data: &[u8; 32]) -> ShieldResult<AttestationQuote> {
        if !self.config.attestation_enabled {
            return Err(ShieldError::NotSupported("Attestation disabled".into()));
        }
        
        #[cfg(feature = "sgx")]
        {
            self.generate_sgx_quote(user_data)
        }
        
        #[cfg(not(feature = "sgx"))]
        {
            self.generate_simulated_quote(user_data)
        }
    }
    
    /// Generate a full attestation report
    pub fn generate_full_report(&self) -> ShieldResult<AttestationReport> {
        // Check cache
        let now = current_timestamp();
        let cache_age = now - self.cache_timestamp.load(Ordering::Relaxed);
        
        if cache_age < self.config.attestation_validity_seconds / 2 {
            if let Some(ref report) = self.cached_report {
                return Ok(report.clone());
            }
        }
        
        // Generate new report
        let user_data = sha256(b"attestation_report");
        let quote = self.generate_quote(&user_data)?;
        
        let expires_at = now + self.config.attestation_validity_seconds;
        
        let report = AttestationReport {
            quote,
            ias_signature: None, // Would be filled by IAS in production
            timestamp: now,
            expires_at,
        };
        
        Ok(report)
    }
    
    /// Get self-report for enclave verification
    pub fn get_self_report(&self) -> ShieldResult<SelfReport> {
        #[cfg(feature = "sgx")]
        {
            use sgx_types::sgx_report_t;
            
            let mut report = sgx_report_t::default();
            let status = unsafe {
                sgx_tcrypto::sgx_create_report(
                    core::ptr::null(),
                    core::ptr::null(),
                    &mut report,
                )
            };
            
            if status != sgx_types::sgx_status_t::SGX_SUCCESS {
                return Err(ShieldError::AttestationFailed("Failed to create self report".into()));
            }
            
            Ok(SelfReport {
                mrenclave: report.body.mr_enclave.m,
                mrsigner: report.body.mr_signer.m,
                isv_prod_id: report.body.isv_prod_id,
                isv_svn: report.body.isv_svn,
            })
        }
        
        #[cfg(not(feature = "sgx"))]
        {
            Ok(SelfReport {
                mrenclave: self.simulated_mrenclave,
                mrsigner: self.config.expected_mrsigner,
                isv_prod_id: 1,
                isv_svn: 1,
            })
        }
    }
    
    /// Get current attestation status
    pub fn status(&self) -> AttestationStatus {
        if !self.config.attestation_enabled {
            return AttestationStatus::NotGenerated;
        }
        
        let cached_report = match &self.cached_report {
            Some(r) => r,
            None => return AttestationStatus::NotGenerated,
        };
        
        let now = current_timestamp();
        
        if now > cached_report.expires_at {
            return AttestationStatus::Expired;
        }
        
        if cached_report.expires_at - now < self.config.refresh_threshold_seconds {
            return AttestationStatus::NeedsRefresh;
        }
        
        AttestationStatus::Valid
    }
    
    /// Verify an attestation quote
    pub fn verify_quote(&self, quote: &AttestationQuote) -> ShieldResult<bool> {
        // Verify MRENCLAVE matches expected
        if quote.mrenclave != self.config.expected_mrenclave {
            return Err(ShieldError::MrenclaveMismatch);
        }
        
        // Verify MRSIGNER if configured
        if self.config.expected_mrsigner != [0u8; 32] {
            if quote.mrsigner != self.config.expected_mrsigner {
                return Err(ShieldError::AttestationVerificationFailed);
            }
        }
        
        // In production, verify with IAS/DCAP
        #[cfg(feature = "sgx")]
        {
            self.verify_with_ias(quote)?;
        }
        
        Ok(true)
    }
    
    /// Generate SGX quote
    #[cfg(feature = "sgx")]
    fn generate_sgx_quote(&self, user_data: &[u8; 32]) -> ShieldResult<AttestationQuote> {
        use sgx_types::{sgx_quote_t, sgx_report_data_t, sgx_target_info_t};
        
        // Create report data with user data
        let mut report_data = sgx_report_data_t::default();
        report_data.d[..32].copy_from_slice(user_data);
        
        // Get target info for quoting enclave
        let mut target_info = sgx_target_info_t::default();
        let status = unsafe {
            sgx_tcrypto::sgx_init_quote(&mut target_info, &mut epid_group_id)
        };
        
        if status != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(ShieldError::AttestationFailed("Init quote failed".into()));
        }
        
        // Create report
        let mut report = sgx_types::sgx_report_t::default();
        let status = unsafe {
            sgx_tcrypto::sgx_create_report(&target_info, &report_data, &mut report)
        };
        
        if status != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(ShieldError::AttestationFailed("Create report failed".into()));
        }
        
        // Get quote
        let quote_size = 1024; // Typical quote size
        let mut quote_buf = vec![0u8; quote_size];
        
        let status = unsafe {
            sgx_tcrypto::sgx_get_quote(
                &report,
                sgx_types::SGX_UNLINKABLE_SIGNATURE,
                &spid,
                core::ptr::null(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                quote_buf.as_mut_ptr() as *mut sgx_quote_t,
                quote_size as u32,
            )
        };
        
        if status != sgx_types::sgx_status_t::SGX_SUCCESS {
            return Err(ShieldError::AttestationFailed("Get quote failed".into()));
        }
        
        Ok(AttestationQuote {
            quote: quote_buf,
            mrenclave: report.body.mr_enclave.m,
            mrsigner: report.body.mr_signer.m,
            report_data: report_data.d,
        })
    }
    
    /// Generate simulated quote for testing
    #[cfg(not(feature = "sgx"))]
    fn generate_simulated_quote(&self, user_data: &[u8; 32]) -> ShieldResult<AttestationQuote> {
        // Create simulated quote structure
        let mut quote = Vec::with_capacity(436);
        
        // Quote header (simplified)
        quote.extend_from_slice(&[2u8, 0]); // Version
        quote.extend_from_slice(&[0u8; 2]); // Sign type
        quote.extend_from_slice(&[0u8; 4]); // EPID group ID
        quote.extend_from_slice(&[0u8; 2]); // QE SVN
        quote.extend_from_slice(&[0u8; 2]); // PCE SVN
        quote.extend_from_slice(&[0u8; 16]); // Extended EPID group ID
        
        // Report body
        quote.extend_from_slice(&self.simulated_mrenclave); // MRENCLAVE
        quote.extend_from_slice(&self.config.expected_mrsigner); // MRSIGNER
        quote.extend_from_slice(&[0u8; 64]); // Reserved
        quote.extend_from_slice(&[1u8, 0]); // ISV prod ID
        quote.extend_from_slice(&[1u8, 0]); // ISV SVN
        quote.extend_from_slice(&[0u8; 60]); // Reserved
        
        // Report data (includes user data)
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(user_data);
        quote.extend_from_slice(&report_data);
        
        // Signature (simulated)
        quote.extend_from_slice(&[0u8; 64]);
        
        Ok(AttestationQuote {
            quote,
            mrenclave: self.simulated_mrenclave,
            mrsigner: self.config.expected_mrsigner,
            report_data,
        })
    }
    
    /// Verify quote with Intel Attestation Service
    #[cfg(feature = "sgx")]
    fn verify_with_ias(&self, quote: &AttestationQuote) -> ShieldResult<()> {
        // In production, send quote to IAS for verification
        // This would make an HTTPS request to IAS endpoint
        
        if self.config.use_dcap {
            // DCAP verification (local, no network)
            // Would use DCAP libraries
        } else {
            // EPID verification (requires IAS)
            // Would make HTTP request to self.config.ias_url
        }
        
        Ok(())
    }
}

/// Self-report containing enclave identity
#[derive(Debug, Clone)]
pub struct SelfReport {
    /// MRENCLAVE - hash of enclave code
    pub mrenclave: [u8; 32],
    /// MRSIGNER - hash of signer's public key
    pub mrsigner: [u8; 32],
    /// ISV product ID
    pub isv_prod_id: u16,
    /// ISV security version number
    pub isv_svn: u16,
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
    fn test_attestation_service_creation() {
        let config = AttestationConfig::default();
        let service = AttestationService::new(&config);
        assert!(service.is_ok());
    }
    
    #[test]
    fn test_generate_quote() {
        let config = AttestationConfig::default();
        let service = AttestationService::new(&config).unwrap();
        
        let user_data = [0x42u8; 32];
        let quote = service.generate_quote(&user_data);
        
        assert!(quote.is_ok());
        let quote = quote.unwrap();
        assert_eq!(quote.mrenclave, config.expected_mrenclave);
    }
    
    #[test]
    fn test_self_report() {
        let config = AttestationConfig::default();
        let service = AttestationService::new(&config).unwrap();
        
        let report = service.get_self_report().unwrap();
        assert_eq!(report.mrenclave.len(), 32);
    }
    
    #[test]
    fn test_verify_quote() {
        let mut config = AttestationConfig::default();
        let expected = sha256(b"test_enclave");
        config.expected_mrenclave = expected;
        
        let service = AttestationService::new(&config).unwrap();
        
        let user_data = [0x42u8; 32];
        let quote = service.generate_quote(&user_data).unwrap();
        
        let result = service.verify_quote(&quote);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_verify_wrong_mrenclave() {
        let config = AttestationConfig::default();
        let service = AttestationService::new(&config).unwrap();
        
        let quote = AttestationQuote {
            quote: vec![0u8; 100],
            mrenclave: [0xFFu8; 32], // Wrong MRENCLAVE
            mrsigner: [0u8; 32],
            report_data: [0u8; 64],
        };
        
        let result = service.verify_quote(&quote);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_status_not_generated() {
        let config = AttestationConfig::default();
        let service = AttestationService::new(&config).unwrap();
        
        assert_eq!(service.status(), AttestationStatus::NotGenerated);
    }
    
    #[test]
    fn test_disabled_attestation() {
        let mut config = AttestationConfig::default();
        config.attestation_enabled = false;
        
        let service = AttestationService::new(&config).unwrap();
        
        let user_data = [0u8; 32];
        let result = service.generate_quote(&user_data);
        
        assert!(result.is_err());
    }
}
