//! Layer1 Protocol - Digital Central Bank & Vault
//!
//! Three Core Jobs:
//!   1. GATEKEEPER (Tier 1): USDT → $BB at 1:10 ratio
//!   2. TIME MACHINE (Tier 2): $BB → $DIME with vintage stamps
//!   3. SSS WALLET: Shamir Secret Sharing (in wallet_mnemonic)

pub mod blockchain;
pub mod helpers;

// Re-export core types
pub use blockchain::{
    // Constants
    Transaction, TxData,
};
