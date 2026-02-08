//! BlackBook L1 Runtime — Settlement Layer Engine
//!
//! Two Core Jobs: Gatekeeper (USDT→$BB) + Invisible Security (SSS wallets)
//!
//! Solana-inspired, improved:
//!   - 600ms slots (stable vs Solana's fragile 400ms)
//!   - Localized fee markets (spam only affects the spammer)
//!   - Circuit breakers (automatic bank-run protection)
//!   - Sealevel parallel execution with account-level locking

pub mod core;
pub mod consensus;
pub mod poh_service;

// PoH Service
pub use poh_service::{
    PoHService, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, SharedPipeline, verify_poh_chain,
    PipelinePacket,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};

// Consensus — Tower BFT + PoH + Gulf Stream
pub use consensus::{PoHConfig, PoHEntry, LeaderSchedule, GulfStreamService};
pub use consensus::{
    Vote, TowerLockout, VoteTower, TowerSync, ForkInfo,
    TowerBFT, ConsensusStatus, TowerBFTStats,
    verify_block_validity, check_vote_threshold,
    MAX_TOWER_DEPTH, SUPERMAJORITY_THRESHOLD, MIN_FORK_VOTES,
};

// Sealevel Parallel Execution
pub use core::{
    ParallelScheduler, AccountLockManager,
    Transaction as RuntimeTransaction,
};

// Account System (PDA + Metadata)
pub use core::{
    pda_namespace, AccountType, ProgramDerivedAddress, AccountMetadata, PDAInfo,
    AccountAccess, AccountValidationError, AccountValidator,
};

// Security Infrastructure
pub use core::{NetworkThrottler, RateLimitEntry};
pub use core::{CircuitBreaker, ValueFlowEntry, SINGLE_BLOCK_VALUE_THRESHOLD, HOURLY_VALUE_THRESHOLD, CIRCUIT_BREAKER_COOLDOWN_SECS};
pub use core::{LocalizedFeeMarket, FeeMarketEntry};

