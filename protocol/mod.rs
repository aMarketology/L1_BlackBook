//! Layer1 Protocol - Core Types
//!
//! Minimal blockchain types for 1:1 USDC-backed token system.

pub mod blockchain;
pub mod helpers;

// Re-export core types
pub use blockchain::{
    Block, Transaction, TxType,
    Account, AccountType,
    LockRecord, LockPurpose,
    SettlementProof,
    GENESIS_TIMESTAMP, LAMPORTS_PER_BB,
    compute_genesis_hash,
};
