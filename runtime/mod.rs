//! BlackBook L1 Runtime — Consensus & Execution Engine
//!
//! The runtime is the state-machine core of the L1: it advances the Proof of
//! History clock, schedules parallel transaction execution, runs Tower BFT
//! consensus, and propagates blocks across the permissioned validator mesh.
//!
//! Solana-inspired, fully custom-implemented:
//!   - 400ms PoH slots driven by a dedicated OS-thread clock
//!   - Sealevel parallel execution with account-level read/write locking
//!   - Localized fee markets (spam only affects the spammer)
//!   - Circuit breakers (automatic bank-run protection)
//!   - Permissioned Turbine shred gossip (whitelisted validators only)

pub mod core;
pub mod sealevel;
pub mod consensus;
pub mod poh_service;
pub mod tpu;
pub mod turbine;
pub mod validator_registry;

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
pub use consensus::{PoHConfig, PoHEntry, LeaderSchedule, GulfStreamService, LEADER_TENURE_SLOTS};
pub use consensus::TowerBFT;

// Sealevel Parallel Execution
pub use sealevel::{ParallelScheduler, SchedulerStats, TransactionResult as SealevelTxResult};

