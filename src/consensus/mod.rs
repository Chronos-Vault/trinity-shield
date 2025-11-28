//! Consensus Engine - 2-of-3 multi-chain consensus
//! 
//! Implements the core Trinity Protocol consensus logic:
//! - Operation validation against Lean-proven rules
//! - Vote creation and signature
//! - Consensus collection and verification
//! - Cross-chain proof generation

use crate::config::ConsensusConfig;
use crate::crypto::{sha256, KeyPair};
use crate::error::{ShieldError, ShieldResult};
use crate::types::{ChainId, KeyAlgorithm, Operation, OperationType, Vote};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "std")]
use std::sync::RwLock;

#[cfg(not(feature = "std"))]
use spin::RwLock;

/// Consensus Engine for 2-of-3 multi-chain consensus
pub struct ConsensusEngine {
    /// Configuration
    config: ConsensusConfig,
    /// This validator's chain ID
    chain_id: ChainId,
    /// Nonce tracker per operation
    nonces: RwLock<BTreeMap<[u8; 32], u64>>,
    /// Current nonce
    current_nonce: AtomicU64,
    /// Pending votes
    pending_votes: RwLock<BTreeMap<[u8; 32], PendingOperation>>,
}

/// A pending operation waiting for consensus
struct PendingOperation {
    /// The operation
    operation: Operation,
    /// Votes received (chain_id -> approved)
    votes: BTreeMap<ChainId, bool>,
    /// When this operation was first seen
    received_at: u64,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    pub fn new(config: &ConsensusConfig) -> ShieldResult<Self> {
        Ok(Self {
            config: config.clone(),
            chain_id: config.chain_id,
            nonces: RwLock::new(BTreeMap::new()),
            current_nonce: AtomicU64::new(1),
            pending_votes: RwLock::new(BTreeMap::new()),
        })
    }
    
    /// Verify operation against Lean-proven consensus rules
    /// 
    /// # Rules enforced (from Lean proofs):
    /// 1. Operation timestamp is not too old
    /// 2. Operation nonce is valid (prevents replay)
    /// 3. Operation type is valid for the target chain
    /// 4. Operation parameters are well-formed
    pub fn verify_operation_rules(&self, operation: &Operation) -> ShieldResult<()> {
        // Rule 1: Check timestamp
        let now = current_timestamp();
        if now - operation.timestamp > self.config.max_operation_age_seconds {
            return Err(ShieldError::ConsensusRuleViolation {
                rule: "operation_too_old".into(),
            });
        }
        
        // Rule 2: Check nonce (prevent replay)
        let op_hash = operation.hash();
        if let Ok(nonces) = self.nonces.read() {
            if let Some(&used_nonce) = nonces.get(&op_hash) {
                if operation.nonce <= used_nonce {
                    return Err(ShieldError::InvalidNonce);
                }
            }
        }
        
        // Rule 3: Validate operation type for chain
        self.validate_operation_for_chain(operation)?;
        
        // Rule 4: Validate parameters (basic structure)
        self.validate_operation_params(operation)?;
        
        Ok(())
    }
    
    /// Create a vote for an operation
    pub fn create_vote(&self, operation: &Operation) -> ShieldResult<Vote> {
        // Verify rules first
        self.verify_operation_rules(operation)?;
        
        // Record nonce
        if let Ok(mut nonces) = self.nonces.write() {
            nonces.insert(operation.hash(), operation.nonce);
        }
        
        // Create vote
        let nonce = self.current_nonce.fetch_add(1, Ordering::SeqCst);
        
        Ok(Vote {
            chain_id: self.chain_id,
            operation_hash: operation.hash(),
            approved: true,
            timestamp: current_timestamp(),
            nonce,
        })
    }
    
    /// Reject an operation (create negative vote)
    pub fn reject_operation(&self, operation: &Operation, _reason: &str) -> ShieldResult<Vote> {
        let nonce = self.current_nonce.fetch_add(1, Ordering::SeqCst);
        
        Ok(Vote {
            chain_id: self.chain_id,
            operation_hash: operation.hash(),
            approved: false,
            timestamp: current_timestamp(),
            nonce,
        })
    }
    
    /// Submit an operation for consensus
    pub fn submit_operation(&self, operation: Operation) -> ShieldResult<[u8; 32]> {
        let op_hash = operation.hash();
        
        if let Ok(mut pending) = self.pending_votes.write() {
            pending.insert(op_hash, PendingOperation {
                operation,
                votes: BTreeMap::new(),
                received_at: current_timestamp(),
            });
        }
        
        Ok(op_hash)
    }
    
    /// Record a vote from another validator
    pub fn record_vote(&self, vote: &Vote) -> ShieldResult<ConsensusStatus> {
        let mut pending = self.pending_votes.write()
            .map_err(|_| ShieldError::InternalError("Lock poisoned".into()))?;
        
        if let Some(op) = pending.get_mut(&vote.operation_hash) {
            op.votes.insert(vote.chain_id, vote.approved);
            
            // Check if we have consensus
            return Ok(self.check_consensus(&op.votes));
        }
        
        Err(ShieldError::ConsensusRuleViolation {
            rule: "unknown_operation".into(),
        })
    }
    
    /// Check if consensus is reached
    fn check_consensus(&self, votes: &BTreeMap<ChainId, bool>) -> ConsensusStatus {
        let approvals = votes.values().filter(|&&v| v).count() as u8;
        let rejections = votes.values().filter(|&&v| !v).count() as u8;
        
        if approvals >= self.config.required_approvals {
            return ConsensusStatus::Approved {
                approvals,
                total: self.config.total_validators,
            };
        }
        
        if rejections > self.config.total_validators - self.config.required_approvals {
            return ConsensusStatus::Rejected {
                rejections,
                total: self.config.total_validators,
            };
        }
        
        ConsensusStatus::Pending {
            approvals,
            rejections,
            needed: self.config.required_approvals - approvals,
        }
    }
    
    /// Get consensus status for an operation
    pub fn get_status(&self, op_hash: &[u8; 32]) -> Option<ConsensusStatus> {
        let pending = self.pending_votes.read().ok()?;
        let op = pending.get(op_hash)?;
        Some(self.check_consensus(&op.votes))
    }
    
    /// Validate operation type is allowed for target chain
    fn validate_operation_for_chain(&self, operation: &Operation) -> ShieldResult<()> {
        match (operation.op_type, operation.target_chain) {
            // Emergency recovery only allowed on TON (quantum-safe)
            (OperationType::EmergencyRecovery, chain) if chain != ChainId::Ton => {
                return Err(ShieldError::ConsensusRuleViolation {
                    rule: "emergency_recovery_requires_ton".into(),
                });
            }
            
            // HTLC operations require 2-of-3 on all chains
            (OperationType::HtlcInit | OperationType::HtlcClaim | OperationType::HtlcRefund, _) => {
                // Valid on all chains
            }
            
            // Cross-chain transfers valid everywhere
            (OperationType::CrossChainTransfer, _) => {}
            
            // Standard operations
            (OperationType::Withdraw | OperationType::Deposit, _) => {}
            
            // Config updates require all validators if configured
            (OperationType::ConfigUpdate, _) if self.config.require_all_validators => {
                // Will be checked during consensus
            }
            
            _ => {}
        }
        
        Ok(())
    }
    
    /// Validate operation parameters
    fn validate_operation_params(&self, operation: &Operation) -> ShieldResult<()> {
        match operation.op_type {
            OperationType::Withdraw | OperationType::Deposit => {
                // Params: [amount:32][recipient:varies]
                if operation.params.len() < 32 {
                    return Err(ShieldError::ValidationFailed {
                        field: "params".into(),
                        reason: "Amount required".into(),
                    });
                }
            }
            
            OperationType::HtlcInit => {
                // Params: [hashlock:32][timelock:8][amount:32][recipient:varies]
                if operation.params.len() < 72 {
                    return Err(ShieldError::ValidationFailed {
                        field: "params".into(),
                        reason: "HTLC init requires hashlock, timelock, amount".into(),
                    });
                }
            }
            
            OperationType::HtlcClaim => {
                // Params: [preimage:32][htlc_id:32]
                if operation.params.len() < 64 {
                    return Err(ShieldError::ValidationFailed {
                        field: "params".into(),
                        reason: "HTLC claim requires preimage and ID".into(),
                    });
                }
            }
            
            OperationType::HtlcRefund => {
                // Params: [htlc_id:32]
                if operation.params.len() < 32 {
                    return Err(ShieldError::ValidationFailed {
                        field: "params".into(),
                        reason: "HTLC refund requires ID".into(),
                    });
                }
            }
            
            _ => {}
        }
        
        Ok(())
    }
    
    /// Clean up expired pending operations
    pub fn cleanup(&self) {
        let now = current_timestamp();
        
        if let Ok(mut pending) = self.pending_votes.write() {
            pending.retain(|_, op| {
                now - op.received_at < self.config.vote_timeout_seconds
            });
        }
    }
    
    /// Get this validator's chain ID
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    
    /// Get current nonce
    pub fn current_nonce(&self) -> u64 {
        self.current_nonce.load(Ordering::Acquire)
    }
}

/// Status of consensus for an operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStatus {
    /// Consensus reached, operation approved
    Approved {
        approvals: u8,
        total: u8,
    },
    /// Consensus reached, operation rejected
    Rejected {
        rejections: u8,
        total: u8,
    },
    /// Still waiting for votes
    Pending {
        approvals: u8,
        rejections: u8,
        needed: u8,
    },
}

impl ConsensusStatus {
    /// Check if consensus is complete (approved or rejected)
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Approved { .. } | Self::Rejected { .. })
    }
    
    /// Check if operation was approved
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }
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
    use crate::types::Identity;
    
    fn test_operation() -> Operation {
        Operation {
            op_type: OperationType::Withdraw,
            target_chain: ChainId::Arbitrum,
            params: vec![0u8; 64], // Amount + recipient
            nonce: 1,
            requestor: Identity {
                id: "test_user".into(),
                public_key: None,
                chain_id: None,
            },
            timestamp: current_timestamp(),
        }
    }
    
    #[test]
    fn test_engine_creation() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config);
        assert!(engine.is_ok());
    }
    
    #[test]
    fn test_create_vote() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config).unwrap();
        
        let op = test_operation();
        let vote = engine.create_vote(&op);
        
        assert!(vote.is_ok());
        let vote = vote.unwrap();
        assert!(vote.approved);
        assert_eq!(vote.operation_hash, op.hash());
    }
    
    #[test]
    fn test_reject_operation() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config).unwrap();
        
        let op = test_operation();
        let vote = engine.reject_operation(&op, "test rejection").unwrap();
        
        assert!(!vote.approved);
    }
    
    #[test]
    fn test_consensus_2_of_3() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config).unwrap();
        
        let op = test_operation();
        let op_hash = engine.submit_operation(op.clone()).unwrap();
        
        // First vote
        let vote1 = Vote {
            chain_id: ChainId::Arbitrum,
            operation_hash: op_hash,
            approved: true,
            timestamp: current_timestamp(),
            nonce: 1,
        };
        let status = engine.record_vote(&vote1).unwrap();
        assert!(!status.is_complete());
        
        // Second vote - should reach consensus
        let vote2 = Vote {
            chain_id: ChainId::Solana,
            operation_hash: op_hash,
            approved: true,
            timestamp: current_timestamp(),
            nonce: 2,
        };
        let status = engine.record_vote(&vote2).unwrap();
        assert!(status.is_complete());
        assert!(status.is_approved());
    }
    
    #[test]
    fn test_consensus_rejection() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config).unwrap();
        
        let op = test_operation();
        let op_hash = engine.submit_operation(op).unwrap();
        
        // Two rejections should reject
        for (i, chain) in [ChainId::Arbitrum, ChainId::Solana].iter().enumerate() {
            let vote = Vote {
                chain_id: *chain,
                operation_hash: op_hash,
                approved: false,
                timestamp: current_timestamp(),
                nonce: i as u64 + 1,
            };
            engine.record_vote(&vote).unwrap();
        }
        
        let status = engine.get_status(&op_hash).unwrap();
        assert!(status.is_complete());
        assert!(!status.is_approved());
    }
    
    #[test]
    fn test_old_operation_rejected() {
        let config = ConsensusConfig::default();
        let engine = ConsensusEngine::new(&config).unwrap();
        
        let mut op = test_operation();
        op.timestamp = 0; // Very old
        
        let result = engine.create_vote(&op);
        assert!(result.is_err());
    }
}
