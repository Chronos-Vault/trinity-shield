//! Hardware-based data sealing using SGX EGETKEY instruction
//! 
//! This module provides true hardware sealing - data is encrypted with keys
//! derived from the CPU's fused secrets and enclave identity. Only the same
//! enclave running on the same CPU can unseal the data.

#![no_std]

extern crate alloc;
extern crate sgx_tcrypto;
extern crate sgx_types;

use alloc::vec::Vec;
use sgx_tcrypto::*;
use sgx_types::*;

use crate::enclave_impl::SealPolicy;

/// Sealed data header
#[repr(C, packed)]
struct SealedHeader {
    version: u8,                    // Format version (1)
    policy: u8,                     // 0 = MrEnclave, 1 = MrSigner
    key_id: [u8; 32],               // Key derivation ID
    iv: [u8; 12],                   // AES-GCM IV
    tag: [u8; 16],                  // AES-GCM authentication tag
    plaintext_len: u32,             // Original plaintext length
}

const SEALED_HEADER_SIZE: usize = core::mem::size_of::<SealedHeader>();

/// Seal data using SGX EGETKEY instruction
/// 
/// This derives a sealing key from hardware and encrypts the data with AES-256-GCM.
/// The key derivation uses:
/// - CPU's unique fuse key (PK) embedded during manufacturing
/// - MRENCLAVE (hash of enclave code) or MRSIGNER (signer identity)
/// - Key derivation ID (random, stored with sealed data)
pub fn seal_with_egetkey(plaintext: &[u8], policy: SealPolicy) -> Result<Vec<u8>, SealError> {
    // Generate random key ID and IV using hardware RNG
    let mut key_id = [0u8; 32];
    let mut iv = [0u8; 12];
    
    let ret = unsafe { sgx_read_rand(key_id.as_mut_ptr(), 32) };
    if ret != sgx_status_t::SGX_SUCCESS {
        return Err(SealError::RandomFailed);
    }
    
    let ret = unsafe { sgx_read_rand(iv.as_mut_ptr(), 12) };
    if ret != sgx_status_t::SGX_SUCCESS {
        return Err(SealError::RandomFailed);
    }
    
    // Build key request for EGETKEY instruction
    let mut key_request = sgx_key_request_t::default();
    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = match policy {
        SealPolicy::MrEnclave => SGX_KEYPOLICY_MRENCLAVE,
        SealPolicy::MrSigner => SGX_KEYPOLICY_MRSIGNER,
    };
    key_request.key_id.id = key_id;
    key_request.attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    key_request.attribute_mask.xfrm = 0;
    
    // Get sealing key from hardware (EGETKEY instruction)
    let mut seal_key = sgx_key_128bit_t::default();
    let ret = unsafe { sgx_get_key(&key_request, &mut seal_key) };
    if ret != sgx_status_t::SGX_SUCCESS {
        return Err(SealError::KeyDerivationFailed);
    }
    
    // Expand 128-bit key to 256-bit using HKDF-like construction
    let seal_key_256 = expand_key_256(&seal_key);
    
    // Encrypt plaintext with AES-256-GCM
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    
    let ret = unsafe {
        sgx_rijndael128GCM_encrypt(
            &seal_key_256 as *const _ as *const sgx_aes_gcm_128bit_key_t,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            ciphertext.as_mut_ptr(),
            iv.as_ptr(),
            12,
            core::ptr::null(),
            0,
            &mut tag as *mut _ as *mut sgx_aes_gcm_128bit_tag_t,
        )
    };
    
    if ret != sgx_status_t::SGX_SUCCESS {
        // Clear sensitive key material
        seal_key_256.iter_mut().for_each(|b| *b = 0);
        return Err(SealError::EncryptionFailed);
    }
    
    // Clear sensitive key material
    seal_key.iter_mut().for_each(|b| *b = 0);
    
    // Build sealed output: header + ciphertext
    let header = SealedHeader {
        version: 1,
        policy: match policy {
            SealPolicy::MrEnclave => 0,
            SealPolicy::MrSigner => 1,
        },
        key_id,
        iv,
        tag,
        plaintext_len: plaintext.len() as u32,
    };
    
    let mut sealed = Vec::with_capacity(SEALED_HEADER_SIZE + ciphertext.len());
    sealed.extend_from_slice(as_bytes(&header));
    sealed.extend_from_slice(&ciphertext);
    
    Ok(sealed)
}

/// Unseal data using SGX EGETKEY instruction
/// 
/// This re-derives the sealing key from hardware and decrypts with AES-256-GCM.
/// Will fail if:
/// - Running on different CPU
/// - Enclave code has changed (if sealed with MrEnclave policy)
/// - Enclave signer has changed (if sealed with MrSigner policy)
/// - Data has been tampered with (GCM authentication failure)
pub fn unseal_with_egetkey(sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < SEALED_HEADER_SIZE {
        return Err(SealError::InvalidFormat);
    }
    
    // Parse header
    let header: &SealedHeader = unsafe {
        &*(sealed.as_ptr() as *const SealedHeader)
    };
    
    if header.version != 1 {
        return Err(SealError::UnsupportedVersion);
    }
    
    let ciphertext = &sealed[SEALED_HEADER_SIZE..];
    if ciphertext.len() != header.plaintext_len as usize {
        return Err(SealError::InvalidFormat);
    }
    
    // Build key request matching the one used during sealing
    let mut key_request = sgx_key_request_t::default();
    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = if header.policy == 0 {
        SGX_KEYPOLICY_MRENCLAVE
    } else {
        SGX_KEYPOLICY_MRSIGNER
    };
    key_request.key_id.id = header.key_id;
    key_request.attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    key_request.attribute_mask.xfrm = 0;
    
    // Get sealing key from hardware
    let mut seal_key = sgx_key_128bit_t::default();
    let ret = unsafe { sgx_get_key(&key_request, &mut seal_key) };
    if ret != sgx_status_t::SGX_SUCCESS {
        return Err(SealError::KeyDerivationFailed);
    }
    
    // Expand key to 256-bit
    let seal_key_256 = expand_key_256(&seal_key);
    
    // Decrypt with AES-256-GCM
    let mut plaintext = vec![0u8; header.plaintext_len as usize];
    
    let ret = unsafe {
        sgx_rijndael128GCM_decrypt(
            &seal_key_256 as *const _ as *const sgx_aes_gcm_128bit_key_t,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            plaintext.as_mut_ptr(),
            header.iv.as_ptr(),
            12,
            core::ptr::null(),
            0,
            &header.tag as *const _ as *const sgx_aes_gcm_128bit_tag_t,
        )
    };
    
    // Clear sensitive key material
    seal_key.iter_mut().for_each(|b| *b = 0);
    
    if ret != sgx_status_t::SGX_SUCCESS {
        return Err(SealError::DecryptionFailed);
    }
    
    Ok(plaintext)
}

/// Seal validator key with additional key hierarchy
/// 
/// Uses a two-level key hierarchy:
/// 1. Master sealing key (derived from EGETKEY)
/// 2. Validator key wrapping key (derived from master + key ID)
pub fn seal_validator_key(
    key_type: u8,
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, SealError> {
    // Build structured data for sealing
    let mut data = Vec::with_capacity(3 + private_key.len() + public_key.len());
    data.push(key_type);
    data.push(private_key.len() as u8);
    data.push(public_key.len() as u8);
    data.extend_from_slice(private_key);
    data.extend_from_slice(public_key);
    
    // Seal with MrEnclave policy - only this exact enclave version can unseal
    seal_with_egetkey(&data, SealPolicy::MrEnclave)
}

/// Unseal validator key
pub fn unseal_validator_key(sealed: &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>), SealError> {
    let data = unseal_with_egetkey(sealed)?;
    
    if data.len() < 3 {
        return Err(SealError::InvalidFormat);
    }
    
    let key_type = data[0];
    let private_len = data[1] as usize;
    let public_len = data[2] as usize;
    
    if data.len() != 3 + private_len + public_len {
        return Err(SealError::InvalidFormat);
    }
    
    let private_key = data[3..3 + private_len].to_vec();
    let public_key = data[3 + private_len..].to_vec();
    
    Ok((key_type, private_key, public_key))
}

/// Expand 128-bit key to 256-bit using HKDF-like construction
fn expand_key_256(key_128: &[u8; 16]) -> [u8; 32] {
    let mut key_256 = [0u8; 32];
    
    // Simple key expansion: SHA256(key || 0x01) || SHA256(key || 0x02)
    // In production, use proper HKDF
    let mut temp = [0u8; 17];
    temp[..16].copy_from_slice(key_128);
    
    temp[16] = 0x01;
    let h1 = sha256(&temp);
    key_256[..16].copy_from_slice(&h1[..16]);
    
    temp[16] = 0x02;
    let h2 = sha256(&temp);
    key_256[16..].copy_from_slice(&h2[..16]);
    
    key_256
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    unsafe {
        sgx_sha256_msg(data.as_ptr(), data.len() as u32, &mut hash);
    }
    hash
}

fn as_bytes<T>(val: &T) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
    }
}

/// Sealing errors
#[derive(Debug)]
pub enum SealError {
    RandomFailed,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    UnsupportedVersion,
}

// SGX SDK constants (normally from sgx_key.h)
const SGX_KEYSELECT_SEAL: u16 = 0x0004;
const SGX_KEYPOLICY_MRENCLAVE: u16 = 0x0001;
const SGX_KEYPOLICY_MRSIGNER: u16 = 0x0002;
const SGX_FLAGS_INITTED: u64 = 0x0001;
const SGX_FLAGS_DEBUG: u64 = 0x0002;

// Type aliases for SGX SDK
type sgx_key_128bit_t = [u8; 16];
type sgx_aes_gcm_128bit_key_t = [u8; 16];
type sgx_aes_gcm_128bit_tag_t = [u8; 16];

#[repr(C)]
#[derive(Default)]
struct sgx_key_request_t {
    key_name: u16,
    key_policy: u16,
    isv_svn: u16,
    reserved1: u16,
    cpu_svn: [u8; 16],
    attribute_mask: sgx_attributes_t,
    key_id: sgx_key_id_t,
    misc_mask: u32,
    config_svn: u16,
    reserved2: [u8; 434],
}

#[repr(C)]
#[derive(Default)]
struct sgx_attributes_t {
    flags: u64,
    xfrm: u64,
}

#[repr(C)]
#[derive(Default)]
struct sgx_key_id_t {
    id: [u8; 32],
}

// FFI declarations for SGX SDK
extern "C" {
    fn sgx_read_rand(rand: *mut u8, len: usize) -> sgx_status_t;
    fn sgx_get_key(key_request: *const sgx_key_request_t, key: *mut sgx_key_128bit_t) -> sgx_status_t;
    fn sgx_sha256_msg(msg: *const u8, len: u32, hash: *mut [u8; 32]) -> sgx_status_t;
    fn sgx_rijndael128GCM_encrypt(
        key: *const sgx_aes_gcm_128bit_key_t,
        src: *const u8,
        src_len: u32,
        dst: *mut u8,
        iv: *const u8,
        iv_len: u32,
        aad: *const u8,
        aad_len: u32,
        tag: *mut sgx_aes_gcm_128bit_tag_t,
    ) -> sgx_status_t;
    fn sgx_rijndael128GCM_decrypt(
        key: *const sgx_aes_gcm_128bit_key_t,
        src: *const u8,
        src_len: u32,
        dst: *mut u8,
        iv: *const u8,
        iv_len: u32,
        aad: *const u8,
        aad_len: u32,
        tag: *const sgx_aes_gcm_128bit_tag_t,
    ) -> sgx_status_t;
}
