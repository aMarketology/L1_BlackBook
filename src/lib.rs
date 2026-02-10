//! BlackBook L1 — Digital Central Bank
//!
//! Two Core Jobs (see MANIFESTO.md):
//!   1. GATEKEEPER: USDT → $BB at 1:10 ratio (vault solvency)
//!   2. INVISIBLE SECURITY: SSS 2-of-3 Shamir wallets (key never whole)
//!
//! Engine: Solana-style PoH + Sealevel parallel execution

// Core modules
pub mod storage;
pub mod poh_blockchain;
pub mod wallet_unified; // Hybrid FROST + Mnemonic
pub mod consensus;
pub mod supabase;
pub mod vault_manager;

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

// Protocol — Tier 1 Vault (Gatekeeper)
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

// Runtime — Solana-style consensus
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


