//! Unified Wallet Architecture
//! 
//! L1 = Bank/Vault (Source of Truth) - $BC tokens
//! L2 = Casino/Prediction Market (Active Bets Only) - $BB tokens
//! 
//! Key Invariant: L2.available == 0 ALWAYS (enforced structurally - no available field)
//! 
//! EXCEPTION: The ORACLE account oversees both layers and provides bridge liquidity.
//! The Oracle validates L1↔L2 state transitions and ensures 1:1 $BC:$BB backing.
//!
//! NOTE: Settlement logic (User L1 → Oracle L1) lives in src/rpc/settlement.rs
//! L1 is a bank, not a casino - it doesn't know about bets.

pub mod accounts;
pub mod oracle;
pub mod storage;

pub use accounts::*;
pub use oracle::*;
pub use storage::*;
