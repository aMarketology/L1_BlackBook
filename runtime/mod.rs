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
pub mod sealevel;
pub mod consensus;
pub mod poh_service;
pub mod tpu;
pub mod turbine;

// PoH Service
pub use poh_service::{
    SharedPoHService, create_poh_service, create_poh_service_with_slot, run_poh_clock,
    TransactionPipeline,
    PipelinePacket,
    TickShred,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};

pub use tpu::TpuService;

// Consensus — Tower BFT + PoH + Gulf Stream
pub use consensus::{PoHConfig, PoHEntry, LeaderSchedule, GulfStreamService};
pub use consensus::TowerBFT;

// Sealevel Parallel Execution
pub use sealevel::{ParallelScheduler, SchedulerStats, TransactionResult as SealevelTxResult};

