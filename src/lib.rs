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

// Blockchain types
pub use protocol::blockchain::{
    Block, Transaction, TxType,
    Account, AccountType,
    LockRecord, LockPurpose,
    SettlementProof,
    GENESIS_TIMESTAMP, LAMPORTS_PER_BB,
    compute_genesis_hash,
};

// Social mining
pub use social_mining::{SocialMiningSystem, SocialActionType, SocialAction, DailyLimits};

// Runtime
pub use runtime::{
    PoHConfig, PoHService, SharedPoHService, 
    create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule,
};

// Authentication
pub use integration::unified_auth::{
    SignedRequest, AuthError, generate_keypair,
    CHAIN_ID_L1, CHAIN_ID_L2,
};
