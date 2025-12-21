//! Layer1 Protocol - PoH-aware blockchain state management
//!
//! Solana-style infrastructure:
//! - Turbine: Block propagation via shreds
//! - Cloudbreak: High-performance account database
//! - Archivers: Distributed ledger storage

pub mod blockchain;
pub mod blockchain_state;
pub mod persistence;
pub mod helpers;

// Core blockchain (used everywhere)

// Persistence (used by tests and main)
pub use persistence::EnhancedPersistence;

// Solana-style services (used by routes_v2/services.rs)
