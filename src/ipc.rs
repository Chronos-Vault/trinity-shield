//! # IPC Module for Trinity Shield
//!
//! Provides Inter-Process Communication between the Rust enclave
//! and the TypeScript relayer service.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     Unix Socket      ┌─────────────────┐
//! │  Trinity Shield │◄───────────────────►│ TypeScript      │
//! │   (Rust/SGX)    │  /run/trinity.sock  │ Relayer Service │
//! └─────────────────┘                      └─────────────────┘
//! ```
//!
//! ## Protocol
//!
//! The IPC uses a simple JSON-RPC style protocol:
//! - Request: `{"method": "...", "params": {...}, "id": 1}`
//! - Response: `{"result": {...}, "id": 1}` or `{"error": {...}, "id": 1}`

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::{ShieldError, ShieldResult, TrinityShield};
use crate::types::{ChainId, AttestationReport};

/// IPC socket path
pub const SOCKET_PATH: &str = "/run/trinity-shield.sock";

/// IPC request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// JSON-RPC method name
    pub method: String,
    /// Method parameters
    pub params: serde_json::Value,
    /// Request ID for correlation
    pub id: u64,
}

/// IPC response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Result (if success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error (if failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
    /// Request ID for correlation
    pub id: u64,
}

/// IPC error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
}

/// IPC method types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcMethod {
    /// Generate attestation quote
    GenerateAttestation,
    /// Sign a consensus vote
    SignVote,
    /// Update trusted time
    UpdateTime,
    /// Get shield metrics
    GetMetrics,
    /// Get public key
    GetPublicKey,
    /// Seal data
    SealData,
    /// Unseal data
    UnsealData,
    /// Health check
    Ping,
}

impl IpcMethod {
    /// Parse method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "generate_attestation" => Some(Self::GenerateAttestation),
            "sign_vote" => Some(Self::SignVote),
            "update_time" => Some(Self::UpdateTime),
            "get_metrics" => Some(Self::GetMetrics),
            "get_public_key" => Some(Self::GetPublicKey),
            "seal_data" => Some(Self::SealData),
            "unseal_data" => Some(Self::UnsealData),
            "ping" => Some(Self::Ping),
            _ => None,
        }
    }
}

/// IPC Server for handling relayer requests
#[cfg(feature = "std")]
pub struct IpcServer {
    shield: TrinityShield,
}

#[cfg(feature = "std")]
impl IpcServer {
    /// Create a new IPC server
    pub fn new(shield: TrinityShield) -> Self {
        Self { shield }
    }
    
    /// Start the IPC server (async)
    pub async fn start(self) -> ShieldResult<()> {
        use tokio::net::UnixListener;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        
        // Remove existing socket if present
        let _ = std::fs::remove_file(SOCKET_PATH);
        
        let listener = UnixListener::bind(SOCKET_PATH)
            .map_err(|e| ShieldError::IpcError(e.to_string()))?;
        
        tracing::info!("IPC server listening on {}", SOCKET_PATH);
        
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let shield_ref = &self.shield;
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();
                    
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break, // EOF
                            Ok(_) => {
                                let response = self.handle_request(&line);
                                let response_json = serde_json::to_string(&response)
                                    .unwrap_or_else(|_| r#"{"error":{"code":-1,"message":"Serialization error"},"id":0}"#.to_string());
                                
                                if let Err(e) = writer.write_all(response_json.as_bytes()).await {
                                    tracing::error!("Failed to write response: {}", e);
                                    break;
                                }
                                if let Err(e) = writer.write_all(b"\n").await {
                                    tracing::error!("Failed to write newline: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to read request: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
    
    /// Handle an IPC request
    fn handle_request(&self, request_json: &str) -> IpcResponse {
        let request: IpcRequest = match serde_json::from_str(request_json) {
            Ok(r) => r,
            Err(e) => {
                return IpcResponse {
                    result: None,
                    error: Some(IpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                    id: 0,
                };
            }
        };
        
        let method = match IpcMethod::from_str(&request.method) {
            Some(m) => m,
            None => {
                return IpcResponse {
                    result: None,
                    error: Some(IpcError {
                        code: -32601,
                        message: format!("Method not found: {}", request.method),
                    }),
                    id: request.id,
                };
            }
        };
        
        match self.dispatch(method, request.params) {
            Ok(result) => IpcResponse {
                result: Some(result),
                error: None,
                id: request.id,
            },
            Err(e) => IpcResponse {
                result: None,
                error: Some(IpcError {
                    code: -32000,
                    message: e.to_string(),
                }),
                id: request.id,
            },
        }
    }
    
    /// Dispatch method to handler
    fn dispatch(&self, method: IpcMethod, params: serde_json::Value) -> ShieldResult<serde_json::Value> {
        match method {
            IpcMethod::GenerateAttestation => {
                let report = self.shield.generate_attestation()?;
                Ok(serde_json::to_value(AttestationReportDto::from(report))?)
            }
            IpcMethod::SignVote => {
                let vote_request: SignVoteRequest = serde_json::from_value(params)?;
                let operation = vote_request.to_operation()?;
                let signed = self.shield.sign_vote(&operation)?;
                Ok(serde_json::to_value(SignedVoteDto::from(signed))?)
            }
            IpcMethod::UpdateTime => {
                #[cfg(feature = "sgx")]
                {
                    let time_update: TimeUpdateRequest = serde_json::from_value(params)?;
                    self.shield.update_trusted_time(time_update.timestamp)?;
                    Ok(serde_json::json!({"success": true}))
                }
                #[cfg(not(feature = "sgx"))]
                {
                    Ok(serde_json::json!({"success": true, "note": "Time update not needed in non-SGX mode"}))
                }
            }
            IpcMethod::GetMetrics => {
                let metrics = self.shield.metrics();
                Ok(serde_json::to_value(metrics)?)
            }
            IpcMethod::GetPublicKey => {
                let pubkey = self.shield.public_key();
                Ok(serde_json::json!({
                    "public_key": hex::encode(pubkey.as_bytes()),
                    "chain_id": self.shield.chain_id() as u8,
                }))
            }
            IpcMethod::SealData => {
                let seal_request: SealDataRequest = serde_json::from_value(params)?;
                let data = hex::decode(&seal_request.data)
                    .map_err(|e| ShieldError::InvalidInput(e.to_string()))?;
                let sealed = self.shield.seal_data(&data)?;
                Ok(serde_json::json!({
                    "sealed": hex::encode(sealed.to_bytes()),
                }))
            }
            IpcMethod::UnsealData => {
                let unseal_request: UnsealDataRequest = serde_json::from_value(params)?;
                let sealed_bytes = hex::decode(&unseal_request.sealed)
                    .map_err(|e| ShieldError::InvalidInput(e.to_string()))?;
                let sealed = crate::types::SealedData::from_bytes(&sealed_bytes)?;
                let data = self.shield.unseal_data(&sealed)?;
                Ok(serde_json::json!({
                    "data": hex::encode(data),
                }))
            }
            IpcMethod::Ping => {
                Ok(serde_json::json!({
                    "status": "ok",
                    "version": env!("CARGO_PKG_VERSION"),
                    "chain_id": self.shield.chain_id() as u8,
                }))
            }
        }
    }
}

// === DTO Types for IPC ===

#[derive(Debug, Serialize, Deserialize)]
struct AttestationReportDto {
    quote: String,
    mrenclave: String,
    mrsigner: String,
    report_data: String,
    timestamp: u64,
}

impl From<AttestationReport> for AttestationReportDto {
    fn from(r: AttestationReport) -> Self {
        Self {
            quote: hex::encode(&r.quote),
            mrenclave: hex::encode(&r.mrenclave),
            mrsigner: hex::encode(&r.mrsigner),
            report_data: hex::encode(&r.report_data),
            timestamp: r.timestamp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignVoteRequest {
    operation_id: String,
    operation_type: String,
    vault: String,
    amount: String,
    chain_id: u8,
}

impl SignVoteRequest {
    fn to_operation(&self) -> ShieldResult<crate::types::Operation> {
        use crate::types::{Operation, OperationType};
        
        let op_type = match self.operation_type.as_str() {
            "deposit" => OperationType::Deposit,
            "withdrawal" => OperationType::Withdrawal,
            "transfer" => OperationType::Transfer,
            _ => return Err(ShieldError::InvalidInput("Unknown operation type".into())),
        };
        
        Ok(Operation {
            id: hex::decode(&self.operation_id)
                .map_err(|e| ShieldError::InvalidInput(e.to_string()))?
                .try_into()
                .map_err(|_| ShieldError::InvalidInput("Invalid operation ID length".into()))?,
            operation_type: op_type,
            vault: hex::decode(&self.vault)
                .map_err(|e| ShieldError::InvalidInput(e.to_string()))?
                .try_into()
                .map_err(|_| ShieldError::InvalidInput("Invalid vault address length".into()))?,
            amount: self.amount.parse()
                .map_err(|e: core::num::ParseIntError| ShieldError::InvalidInput(e.to_string()))?,
            chain_id: ChainId::try_from(self.chain_id)
                .map_err(|_| ShieldError::InvalidInput("Invalid chain ID".into()))?,
            timestamp: crate::current_timestamp(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedVoteDto {
    vote_hash: String,
    signature: String,
    attestation_quote: String,
    timestamp: u64,
}

impl From<crate::types::SignedVote> for SignedVoteDto {
    fn from(v: crate::types::SignedVote) -> Self {
        Self {
            vote_hash: hex::encode(v.vote.hash()),
            signature: hex::encode(v.signature.as_bytes()),
            attestation_quote: hex::encode(&v.attestation.quote),
            timestamp: v.timestamp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TimeUpdateRequest {
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealDataRequest {
    data: String, // hex-encoded
}

#[derive(Debug, Serialize, Deserialize)]
struct UnsealDataRequest {
    sealed: String, // hex-encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_method_parsing() {
        assert_eq!(IpcMethod::from_str("ping"), Some(IpcMethod::Ping));
        assert_eq!(IpcMethod::from_str("generate_attestation"), Some(IpcMethod::GenerateAttestation));
        assert_eq!(IpcMethod::from_str("unknown"), None);
    }
    
    #[test]
    fn test_request_serialization() {
        let request = IpcRequest {
            method: "ping".into(),
            params: serde_json::json!({}),
            id: 1,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("ping"));
    }
}
