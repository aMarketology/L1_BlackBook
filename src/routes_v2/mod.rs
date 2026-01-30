//! Routes V2 - ZKP Auth Module
//!
//! NOTE: Legacy Warp routes have been moved to Axum in main_v3.rs.
//! This module provides ZKP authentication types and functions.

pub mod auth;

// Re-export ZKP types for use in main_v3.rs
pub use auth::*;
