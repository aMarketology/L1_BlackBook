//! Layer1 Blockchain Library
//! 
//! Re-exports core types for use in tests and external crates.
//!
//! ## Authentication Model (V2 - Pure Signature-Based)
//! 
//! This library uses STATELESS signature-based authentication:
//! - No JWT tokens
//! - Every request signed with Ed25519
//! - 5-minute replay protection via timestamp + nonce
//! 
//! See `SignedRequest` for the core authentication primitive.

// Core modules
pub mod social_mining;
pub mod integration;            // Integration modules (supabase, unified_auth)
pub mod routes_v2;              // Route handlers (NEW - Pure signature auth)
pub mod rpc;                    // Internal & Cross-Layer RPC
pub mod unified_wallet;         // Unified wallet system (L1/L2 address logic)
pub mod consensus;              // Consensus (hot upgrades, validator selection, P2P)
pub mod storage;                // RocksDB + Merkle state (production storage layer)

// Note: USDC Reserve System (usdc/) is staged but not integrated yet
pub mod grpc;                   // gRPC Settlement (L1 ↔ L2 internal communication)

// Root-level modules (infrastructure)
#[path = "../protocol/mod.rs"]
pub mod protocol;
#[path = "../runtime/mod.rs"]
pub mod runtime;

// ============================================================================
// PUBLIC API - Exports for tests and external crates
// ============================================================================

// Core blockchain types (used by tests)
pub use protocol::blockchain::EnhancedBlockchain;
pub use runtime::core::{TransactionType, Transaction, Block};

// Storage layer (Sled + Borsh - production persistence)
pub use storage::{
    StorageEngine, StorageBridge, StoredAccount, StoredBlockHeader, 
    StoredSocialData, TxLocation, DbStats, StorageError, StorageResult,
    MerkleState, AccountProof, PersistentBlockchain, PROTOCOL_VERSION, UpgradeHook,
};

// Social mining (used by tests)
pub use social_mining::{SocialMiningSystem, SocialActionType, SocialAction, DailyLimits};

// Persistence (used by tests) - LEGACY, use StorageBridge for new code
pub use protocol::EnhancedPersistence;

// PoH runtime (used internally and by advanced tests)
pub use runtime::{PoHConfig, PoHEntry, PoHService, SharedPoHService, create_poh_service, run_poh_clock};

// Authentication (SignedRequest is the core API)
pub use integration::unified_auth::{
    SignedRequest, 
    with_signature_auth, 
    AuthError,
    generate_keypair,
    // Domain separation for L1/L2 replay attack prevention
    CHAIN_ID_L1,
    CHAIN_ID_L2,
};
