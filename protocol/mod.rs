//! Layer1 Protocol - The Sweepstakes Ledger
//!
//! Only 4 operations: MINT, LOCK, SETTLE, BURN
//! Zero-sum invariant enforced on all operations.

pub mod blockchain;
pub mod helpers;

// Re-export core types
pub use blockchain::{
    // Constants
    GENESIS_TIMESTAMP, LAMPORTS_PER_BB, DEFAULT_ESCROW_EXPIRY_SECS,
    compute_genesis_hash,
    // State
    L1State, EscrowVault,
    // Transactions
    Transaction, TxType, TxData,
    LockParticipant, Payout,
    // Errors
    ChainError,
    // Blocks
    Block,
};
