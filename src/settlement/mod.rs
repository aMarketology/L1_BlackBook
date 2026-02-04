//! Settlement Module - Batch Settlements with Merkle Proofs
//!
//! Enables L2 to settle prediction markets with 100+ winners in a single L1 transaction.
//! Uses Merkle trees for efficient batch verification and prevents double-claiming.
//!
//! ## Flow:
//! 1. L2 resolves market with N winners
//! 2. L2 creates Merkle tree from all payouts
//! 3. L2 submits batch settlement with merkle_root + L2 signature
//! 4. Users claim their winnings by providing merkle_proof
//! 5. L1 verifies proof against stored root and credits winners
//!
//! ## Security:
//! - Each withdrawal can only be claimed once (tracked in claims registry)
//! - L2 signature prevents unauthorized batch submissions
//! - Merkle proofs prevent payout manipulation

pub mod merkle;
pub mod batch;
pub mod claims;

pub use merkle::{MerkleTree, MerkleProof, create_merkle_tree, verify_merkle_proof};
pub use batch::{BatchSettlement, BatchSettlementManager, BatchRecord, Withdrawal, SettlementStatus};
pub use claims::{ClaimRegistry, ClaimStatus, generate_withdrawal_id};

use serde::{Serialize, Deserialize};

/// Result type for settlement operations
pub type SettlementResult<T> = Result<T, SettlementError>;

/// Settlement errors
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum SettlementError {
    #[error("Invalid merkle proof")]
    InvalidMerkleProof,
    
    #[error("Withdrawal already claimed")]
    AlreadyClaimed,
    
    #[error("Invalid L2 signature")]
    InvalidL2Signature,
    
    #[error("Batch not found: {0}")]
    BatchNotFound(String),
    
    #[error("Zero-sum violation: payouts {payouts} != collateral {collateral} - fees {fees}")]
    ZeroSumViolation {
        payouts: f64,
        collateral: f64,
        fees: f64,
    },
    
    #[error("Insufficient balance: {available} < {required}")]
    InsufficientBalance {
        available: f64,
        required: f64,
    },
    
    #[error("Invalid batch: {0}")]
    InvalidBatch(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settlement_error_display() {
        let err = SettlementError::ZeroSumViolation {
            payouts: 100.0,
            collateral: 95.0,
            fees: 5.0,
        };
        assert!(err.to_string().contains("Zero-sum violation"));
    }
}
