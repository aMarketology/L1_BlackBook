//! BlackBook Layer1 Blockchain
//!
//! High-performance blockchain with 1:1 USDC backing.
//!
//! ## Architecture (V3)
//!
//! - **Storage**: ReDB (ACID) + DashMap (lock-free cache)
//! - **Server**: Axum (fast, no recursion limits)
//! - **Auth**: Ed25519 signatures (no JWT)
//! - **Token**: 1:1 USDC backed (no treasury)

// Core modules
pub mod social_mining;
pub mod storage;
pub mod poh_blockchain;

// Stub modules (simplified for MVP)
pub mod integration;
pub mod routes_v2;
pub mod unified_wallet;
pub mod consensus;
pub mod grpc;
pub mod rpc;

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

// Blockchain types - The 4 Critical Functions
pub use protocol::blockchain::{
    // State
    L1State, EscrowVault,
    // Transactions (MINT, LOCK, SETTLE, BURN)
    Transaction, TxType, TxData,
    LockParticipant, Payout,
    // Errors
    ChainError,
    // Blocks
    Block,
    // Constants
    GENESIS_TIMESTAMP, LAMPORTS_PER_BB, DEFAULT_ESCROW_EXPIRY_SECS,
    compute_genesis_hash,
};

// Social mining
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

// Authentication
pub use integration::unified_auth::{
    SignedRequest, AuthError, generate_keypair,
    CHAIN_ID_L1, CHAIN_ID_L2,
};
