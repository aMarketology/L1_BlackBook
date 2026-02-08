//! BlackBook Layer1 Blockchain - Digital Central Bank & Vault
//!
//! Three Core Jobs:
//!   1. GATEKEEPER (Tier 1): USDT → $BB at 1:10 ratio
//!   2. TIME MACHINE (Tier 2): $BB → $DIME with vintage stamps
//!   3. SSS WALLET: Shamir Secret Sharing for security

// Core modules
pub mod storage;
pub mod poh_blockchain;
pub mod wallet_mnemonic; // BIP-39 24-word wallet with SSS backup

// Supporting modules (for compatibility)
pub mod social_mining;
pub mod consensus;
pub mod grpc;

// Infrastructure
#[path = "../protocol/mod.rs"]
pub mod protocol;
#[path = "../runtime/mod.rs"]
pub mod runtime;

// ============================================================================
// PUBLIC API
// ============================================================================

// Storage
pub use storage::{ConcurrentBlockchain, BlockchainStats, AssetManager, CreditSession, SettlementResult};

// Protocol - Two-Tier Vault System
pub use protocol::blockchain::{
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

// Social mining (legacy compatibility)
pub use social_mining::{SocialMiningSystem, SocialActionType, SocialAction, DailyLimits};

// Runtime
pub use runtime::{
    PoHConfig, PoHService, SharedPoHService, 
    create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};

// PoH-Integrated Blockchain
pub use poh_blockchain::{
    BlockProducer, FinalizedBlock, OrderedTransaction,
    MerkleTree, MerkleProof, FinalityTracker,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
};


