//! Layer1 Runtime - Ideal Hybrid Stablecoin Blockchain
//! 
//! High-performance, secure stablecoin-focused L1 with:
//! - Type-safe Program Derived Addresses (PDAs) - immune to account confusion
//! - Stake-weighted throttling (QUIC-style) - spam resistant
//! - Localized fee markets - no global fee spikes  
//! - Circuit breakers - automatic protection against bank runs
//! - Tower BFT: Vote-based consensus with exponential lockouts for finality
//!
//! Architecture vs Solana:
//! | Feature              | Solana               | BlackBook L1          |
//! |----------------------|----------------------|-----------------------|
//! | Transaction Ingest   | Unfiltered UDP       | QUIC + Stake-Weighted |
//! | Fee Structure        | Global (spike all)   | Localized Fee Markets |
//! | Account Safety       | Manual verification  | Declarative/Framework |
//! | Consensus Speed      | 400ms (fragile)      | 600ms (stable+fast)   |

pub mod core;
pub mod consensus;
pub mod poh_service;

// Core types (used by main_v2.rs and tests)

// PoH Service (used by main_v2.rs)
pub use poh_service::{
    PoHService, SharedPoHService, create_poh_service, run_poh_clock, 
    TransactionPipeline, SharedPipeline, verify_poh_chain,
    PipelinePacket,
    // Finality constants
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};

// Consensus types (used by main_v2.rs and services.rs)
pub use consensus::{PoHConfig, PoHEntry, LeaderSchedule, GulfStreamService};

// Tower BFT Consensus - P2P ready!
pub use consensus::{
    // Vote types
    Vote, TowerLockout, VoteTower, TowerSync, ForkInfo,
    // Tower BFT service
    TowerBFT, ConsensusStatus, TowerBFTStats,
    // Block validity
    verify_block_validity, check_vote_threshold,
    // Constants
    MAX_TOWER_DEPTH, SUPERMAJORITY_THRESHOLD, MIN_FORK_VOTES,
};

// Parallel Execution (Sealevel-style)
pub use core::{
    ParallelScheduler, AccountLockManager, 
    Transaction as RuntimeTransaction,
};

// ============================================================================
// SECURITY INFRASTRUCTURE - Ideal Hybrid Design
// ============================================================================

// Program Derived Addresses (PDAs) - Type-safe account derivation
pub use core::{
    pda_namespace,
    AccountType, ProgramDerivedAddress, AccountMetadata, PDAInfo,
};

// Declarative Account Validation - Compile-time safety
pub use core::{
    AccountAccess, AccountValidationError, AccountValidator,
};

// Network Spam Protection - Stake-weighted throttling
pub use core::{
    NetworkThrottler, RateLimitEntry,
};

// Circuit Breakers - Bank run protection
pub use core::{
    CircuitBreaker, ValueFlowEntry,
    SINGLE_BLOCK_VALUE_THRESHOLD, HOURLY_VALUE_THRESHOLD, CIRCUIT_BREAKER_COOLDOWN_SECS,
};

// Localized Fee Markets - No global fee spikes
pub use core::{
    LocalizedFeeMarket, FeeMarketEntry,
};

