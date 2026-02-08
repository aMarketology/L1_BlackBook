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
    USDT_TO_BB_RATIO, TOKEN_DECIMALS, DEFAULT_BASE_CPI,
    
    // Token Ledgers
    BlackBookLedger, DimeLedger,
    
    // Tier 1: USDT → $BB Gateway
    Tier1Gateway, Tier1Deposit,
    
    // Tier 2: $BB → $DIME Vault
    Tier2Vault, DimeVintage,
    
    // Events
    L1Event,
    
    // Transactions
    Transaction, TxData,
    
    // State & Security
    L1State, AccountSecurity,
    
    // Errors
    ChainError,
    
    // Compliance
    ProofOfReserves,
};
