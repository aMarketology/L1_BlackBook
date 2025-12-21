//! Unified Wallet Architecture
//! 
//! L1 = Bank/Vault (Source of Truth)
//! L2 = Ledger/Prediction Market (Active Bets Only)
//! 
//! Key Invariant: L2.available == 0 ALWAYS (enforced structurally - no available field)
//! 
//! EXCEPTION: The DEALER account is L2-native and CAN hold available balance.
//! The Dealer is the "House" - it provides liquidity for the prediction market.
//!
//! NOTE: Settlement logic (User L1 → Dealer L1) lives in src/rpc/settlement.rs
//! L1 is a bank teller, not a pit boss - it doesn't know about bets.

pub mod accounts;
pub mod dealer;
pub mod storage;

pub use accounts::*;
pub use dealer::*;
pub use storage::*;
