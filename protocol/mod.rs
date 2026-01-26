//! Layer1 Protocol - Treasury & Blockchain Layer
//!
//! Architecture:
//!   1. Bridge Contract (Base) - Holds USDC, multi-sig controlled
//!   2. Wrapped USDC (L1) - 1:1 mint when bridge detects deposit
//!   3. BlackBook Token ($BB) - Only Cashier mints, only Redemption burns
//!   4. Cashier Contract - wUSDC → FanGold (L2) + $BB (L1)
//!   5. Redemption Contract - Burns $BB, releases value

pub mod blockchain;
pub mod helpers;

// Re-export core types
pub use blockchain::{
    // Token Ledgers
    WusdcLedger, BlackBookLedger,
    // Contracts
    BridgeAuthority, CashierContract, RedemptionContract, PendingRelease,
    // Bundles
    Bundle,
    // Events (for L2 indexer)
    L1Event,
    // Transactions
    Transaction, TxData,
    // State
    L1State,
    // Errors
    ChainError,
    // Compliance
    ProofOfReserves,
};
