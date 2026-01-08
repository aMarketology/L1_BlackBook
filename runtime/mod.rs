//! Layer1 Runtime - Proof of History Blockchain
//! 
//! Sequencer-based transaction ordering with two-lane execution
//! 
//! Solana-style performance features:
//! - Enhanced Sealevel: Parallel transaction execution with fine-grained locking
//! - Pipeline: 4-stage async transaction processing (fetch→verify→execute→commit)
//! - Gulf Stream: Transaction forwarding to upcoming leaders

pub mod core;
pub mod consensus;
pub mod poh_service;

// Core types (used by main_v2.rs and tests)

// PoH Service (used by main_v2.rs)
pub use poh_service::{
    PoHService, SharedPoHService, create_poh_service, run_poh_clock, 
    TransactionPipeline, SharedPipeline, verify_poh_chain,
    PipelinePacket, CommittedPacket,
    // Finality constants
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
    // Pruning constants
    PRUNED_SLOTS_RETENTION, NodePruningMode,
};

// Consensus types (used by main_v2.rs and services.rs)
pub use consensus::{PoHConfig, PoHEntry, LeaderSchedule, GulfStreamService};

