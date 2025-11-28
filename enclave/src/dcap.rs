//! DCAP (Data Center Attestation Primitives) Integration
//!
//! This module handles SGX remote attestation using Intel's DCAP framework.
//! DCAP allows attestation without contacting Intel's servers, using a local
//! Provisioning Certificate Caching Service (PCCS).

#![no_std]

extern crate alloc;
extern crate sgx_types;
extern crate sgx_tse;

use alloc::vec::Vec;
use alloc::string::String;
use sgx_types::*;
use sgx_tse::*;

/// DCAP Quote Version 3 structure
#[repr(C, packed)]
pub struct DCAPQuoteHeader {
    /// Quote version (3 for DCAP)
    pub version: u16,
    /// Attestation key type (2 = ECDSA-256-with-P-256)
    pub att_key_type: u16,
    /// TEE type (0 = SGX)
    pub tee_type: u32,
    /// Reserved
    pub reserved: [u8; 2],
    /// QE SVN
    pub qe_svn: u16,
    /// PCE SVN
    pub pce_svn: u16,
    /// QE Vendor ID
    pub qe_vendor_id: [u8; 16],
    /// User data
    pub user_data: [u8; 20],
}

/// ISV Enclave Report structure (384 bytes)
#[repr(C, packed)]
pub struct ISVEnclaveReport {
    /// CPU SVN
    pub cpu_svn: [u8; 16],
    /// Miscellaneous select
    pub misc_select: u32,
    /// Reserved
    pub reserved1: [u8; 12],
    /// ISV Extended Product ID
    pub isv_ext_prod_id: [u8; 16],
    /// Attributes
    pub attributes: [u8; 16],
    /// MRENCLAVE - Hash of enclave code
    pub mrenclave: [u8; 32],
    /// Reserved
    pub reserved2: [u8; 32],
    /// MRSIGNER - Hash of enclave signer's public key
    pub mrsigner: [u8; 32],
    /// Reserved
    pub reserved3: [u8; 32],
    /// Config ID
    pub config_id: [u8; 64],
    /// ISV Product ID
    pub isv_prod_id: u16,
    /// ISV SVN
    pub isv_svn: u16,
    /// Config SVN
    pub config_svn: u16,
    /// Reserved
    pub reserved4: [u8; 42],
    /// ISV Family ID
    pub isv_family_id: [u8; 16],
    /// Report Data (application-specific, 64 bytes)
    pub report_data: [u8; 64],
}

/// DCAP Attestation Manager
pub struct DCAPAttestationManager {
    /// Current attestation report
    current_report: Option<Vec<u8>>,
    /// Last attestation timestamp
    last_attestation: u64,
    /// Attestation refresh interval (seconds)
    refresh_interval: u64,
}

impl DCAPAttestationManager {
    /// Create new DCAP attestation manager
    pub fn new() -> Self {
        Self {
            current_report: None,
            last_attestation: 0,
            refresh_interval: 3600, // 1 hour default
        }
    }

    /// Set attestation refresh interval
    pub fn set_refresh_interval(&mut self, seconds: u64) {
        self.refresh_interval = seconds;
    }

    /// Generate attestation report with custom report data
    ///
    /// The report data (64 bytes) is included in the attestation and can be
    /// verified by the verifier. Typically contains:
    /// - Validator public key hash (32 bytes)
    /// - Chain ID (1 byte)
    /// - Nonce (8 bytes)
    /// - Reserved (23 bytes)
    pub fn generate_attestation(&mut self, report_data: &[u8; 64]) -> Result<Vec<u8>, DCAPError> {
        // Create SGX report with custom report data
        let report = self.create_report(report_data)?;
        
        // Get DCAP quote from Quoting Enclave via OCALL
        let quote = self.get_dcap_quote(&report)?;
        
        // Store for caching
        self.current_report = Some(quote.clone());
        self.last_attestation = self.get_current_timestamp();
        
        Ok(quote)
    }

    /// Check if attestation needs refresh
    pub fn needs_refresh(&self, current_time: u64) -> bool {
        self.last_attestation == 0 ||
        current_time - self.last_attestation >= self.refresh_interval
    }

    /// Get cached attestation report
    pub fn get_cached_report(&self) -> Option<&Vec<u8>> {
        self.current_report.as_ref()
    }

    /// Create SGX report for local attestation
    fn create_report(&self, report_data: &[u8; 64]) -> Result<sgx_report_t, DCAPError> {
        // Get target info for the Quoting Enclave
        let mut qe_target_info = sgx_target_info_t::default();
        let ret = unsafe { sgx_qe_get_target_info(&mut qe_target_info) };
        if ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
            return Err(DCAPError::TargetInfoFailed);
        }
        
        // Create report data structure
        let mut rd = sgx_report_data_t::default();
        rd.d.copy_from_slice(report_data);
        
        // Generate report
        let mut report = sgx_report_t::default();
        let ret = unsafe { sgx_create_report(&qe_target_info, &rd, &mut report) };
        if ret != sgx_status_t::SGX_SUCCESS {
            return Err(DCAPError::ReportCreationFailed);
        }
        
        Ok(report)
    }

    /// Get DCAP quote from Quoting Enclave
    fn get_dcap_quote(&self, report: &sgx_report_t) -> Result<Vec<u8>, DCAPError> {
        // Get quote size
        let mut quote_size: u32 = 0;
        let ret = unsafe { sgx_qe_get_quote_size(&mut quote_size) };
        if ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
            return Err(DCAPError::QuoteSizeFailed);
        }
        
        // Allocate quote buffer
        let mut quote = vec![0u8; quote_size as usize];
        
        // Get quote
        let ret = unsafe {
            sgx_qe_get_quote(
                report,
                quote_size,
                quote.as_mut_ptr() as *mut sgx_quote3_t,
            )
        };
        if ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
            return Err(DCAPError::QuoteGenerationFailed);
        }
        
        Ok(quote)
    }

    /// Get current timestamp via OCALL
    fn get_current_timestamp(&self) -> u64 {
        let mut timestamp: u64 = 0;
        unsafe { ocall_get_timestamp(&mut timestamp); }
        timestamp
    }
}

/// Build report data for Trinity Shield attestation
///
/// Format:
/// - bytes 0-31: SHA256(validator_pubkey)
/// - byte 32: chain_id
/// - bytes 33-40: nonce (little-endian u64)
/// - bytes 41-63: reserved (zeros)
pub fn build_report_data(
    pubkey_hash: &[u8; 32],
    chain_id: u8,
    nonce: u64,
) -> [u8; 64] {
    let mut report_data = [0u8; 64];
    
    // Copy public key hash
    report_data[..32].copy_from_slice(pubkey_hash);
    
    // Chain ID
    report_data[32] = chain_id;
    
    // Nonce (little-endian)
    report_data[33..41].copy_from_slice(&nonce.to_le_bytes());
    
    report_data
}

/// Parse DCAP quote and extract key fields
pub fn parse_dcap_quote(quote: &[u8]) -> Result<ParsedQuote, DCAPError> {
    if quote.len() < 436 {
        return Err(DCAPError::InvalidQuoteFormat);
    }
    
    // Parse header
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    if version < 3 {
        return Err(DCAPError::UnsupportedVersion);
    }
    
    // Parse ISV Enclave Report (starts at offset 48)
    let report_offset = 48;
    
    // MRENCLAVE at offset 112 (48 + 64)
    let mut mrenclave = [0u8; 32];
    mrenclave.copy_from_slice(&quote[112..144]);
    
    // MRSIGNER at offset 176 (48 + 128)
    let mut mrsigner = [0u8; 32];
    mrsigner.copy_from_slice(&quote[176..208]);
    
    // Report Data at offset 368 (48 + 320)
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&quote[368..432]);
    
    // ISV Product ID at offset 304 (48 + 256)
    let isv_prod_id = u16::from_le_bytes([quote[304], quote[305]]);
    
    // ISV SVN at offset 306 (48 + 258)
    let isv_svn = u16::from_le_bytes([quote[306], quote[307]]);
    
    Ok(ParsedQuote {
        version,
        mrenclave,
        mrsigner,
        report_data,
        isv_prod_id,
        isv_svn,
    })
}

/// Parsed DCAP quote
pub struct ParsedQuote {
    pub version: u16,
    pub mrenclave: [u8; 32],
    pub mrsigner: [u8; 32],
    pub report_data: [u8; 64],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
}

/// DCAP attestation errors
#[derive(Debug)]
pub enum DCAPError {
    TargetInfoFailed,
    ReportCreationFailed,
    QuoteSizeFailed,
    QuoteGenerationFailed,
    InvalidQuoteFormat,
    UnsupportedVersion,
    VerificationFailed,
}

/// Verify DCAP quote locally (without PCCS)
///
/// This performs basic verification. Full verification requires
/// contacting PCCS for TCB status and revocation checks.
pub fn verify_quote_locally(quote: &[u8]) -> Result<ParsedQuote, DCAPError> {
    // Parse quote
    let parsed = parse_dcap_quote(quote)?;
    
    // Verify quote structure
    if parsed.version < 3 {
        return Err(DCAPError::UnsupportedVersion);
    }
    
    // In production, would verify:
    // 1. ECDSA signature on the quote
    // 2. Certificate chain to Intel Root CA
    // 3. TCB status via PCCS
    // 4. Revocation status
    
    Ok(parsed)
}

/// TCB (Trusted Computing Base) status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TCBStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

/// Collateral for DCAP verification
pub struct QuoteCollateral {
    pub pck_crl: Vec<u8>,
    pub root_ca_crl: Vec<u8>,
    pub tcb_info: Vec<u8>,
    pub tcb_info_issuer_chain: Vec<u8>,
    pub qe_identity: Vec<u8>,
    pub qe_identity_issuer_chain: Vec<u8>,
}

// External declarations for DCAP SDK functions
extern "C" {
    fn sgx_qe_get_target_info(qe_target_info: *mut sgx_target_info_t) -> sgx_quote3_error_t;
    fn sgx_qe_get_quote_size(quote_size: *mut u32) -> sgx_quote3_error_t;
    fn sgx_qe_get_quote(
        app_report: *const sgx_report_t,
        quote_size: u32,
        quote: *mut sgx_quote3_t,
    ) -> sgx_quote3_error_t;
    fn ocall_get_timestamp(timestamp: *mut u64);
}

// SGX types (normally from SDK headers)
#[repr(C)]
#[derive(Default)]
struct sgx_target_info_t {
    mr_enclave: [u8; 32],
    attributes: [u8; 16],
    reserved1: [u8; 2],
    config_svn: u16,
    misc_select: u32,
    reserved2: [u8; 8],
    config_id: [u8; 64],
    reserved3: [u8; 384],
}

#[repr(C)]
#[derive(Default)]
struct sgx_report_data_t {
    d: [u8; 64],
}

#[repr(C)]
#[derive(Default)]
struct sgx_report_t {
    body: sgx_report_body_t,
    key_id: [u8; 32],
    mac: [u8; 16],
}

#[repr(C)]
#[derive(Default)]
struct sgx_report_body_t {
    cpu_svn: [u8; 16],
    misc_select: u32,
    reserved1: [u8; 12],
    isv_ext_prod_id: [u8; 16],
    attributes: [u8; 16],
    mr_enclave: [u8; 32],
    reserved2: [u8; 32],
    mr_signer: [u8; 32],
    reserved3: [u8; 32],
    config_id: [u8; 64],
    isv_prod_id: u16,
    isv_svn: u16,
    config_svn: u16,
    reserved4: [u8; 42],
    isv_family_id: [u8; 16],
    report_data: [u8; 64],
}

#[repr(C)]
struct sgx_quote3_t {
    header: DCAPQuoteHeader,
    report_body: ISVEnclaveReport,
    signature_data_len: u32,
    // Signature data follows (variable length)
}

#[repr(i32)]
#[derive(PartialEq)]
enum sgx_quote3_error_t {
    SGX_QL_SUCCESS = 0,
    SGX_QL_ERROR_UNEXPECTED = 0x0001,
    SGX_QL_ERROR_INVALID_PARAMETER = 0x0002,
    SGX_QL_ERROR_OUT_OF_MEMORY = 0x0003,
    // ... other error codes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_report_data() {
        let pubkey_hash = [1u8; 32];
        let chain_id = 2;
        let nonce = 12345u64;
        
        let report_data = build_report_data(&pubkey_hash, chain_id, nonce);
        
        assert_eq!(&report_data[..32], &pubkey_hash);
        assert_eq!(report_data[32], chain_id);
        assert_eq!(u64::from_le_bytes(report_data[33..41].try_into().unwrap()), nonce);
    }
}
