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
pub mod svm;
pub mod solana_rpc;

// Infrastructure
#[path = "../protocol/mod.rs"]
pub mod protocol;
#[path = "../runtime/mod.rs"]
pub mod runtime;

// ============================================================================
// PUBLIC API
// ============================================================================

// Storage
pub use storage::{ConcurrentBlockchain, BlockchainStats, AssetManager, SettlementResult};

// Protocol — Transactions
pub use protocol::blockchain::{Transaction, TxData};

// Runtime — Solana-style consensus
pub use runtime::{
    PoHConfig, SharedPoHService, 
    create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};
pub use runtime::poh_service::PoHService;

// PoH-Integrated Blockchain
pub use poh_blockchain::{
    BlockProducer, FinalizedBlock, OrderedTransaction,
    MerkleTree, MerkleProof, FinalityTracker,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
};


