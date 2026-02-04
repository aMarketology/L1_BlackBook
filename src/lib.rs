//! BlackBook Layer1 Blockchain
//!
//! Treasury & Blockchain Layer for Sweepstakes
//!
//! ## Architecture
//!
//! 1. Bridge Contract (Base) - Holds USDC, multi-sig controlled
//! 2. Wrapped USDC (L1) - 1:1 mint when bridge detects deposit
//! 3. BlackBook Token ($BB) - Only Cashier mints, only Redemption burns
//! 4. Cashier Contract - wUSDC → FanGold (L2) + $BB (L1)
//! 5. Redemption Contract - Burns $BB, releases value

// Core modules
pub mod social_mining;
pub mod storage;
pub mod poh_blockchain;
pub mod settlement;  // Batch settlements with Merkle proofs
pub mod vault;       // HashiCorp Vault integration for pepper management

// Stub modules (simplified for MVP)
pub mod integration;
pub mod routes_v2;
pub mod unified_wallet;
pub mod wallet_mnemonic;  // BIP-39 24-word wallet with SSS backup
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

// Protocol - Treasury Architecture
pub use protocol::blockchain::{
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
    // Security
    AccountSecurity,
    // State
    // State
    L1State,
    // Errors
    ChainError,
    // Compliance
    ProofOfReserves,
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
