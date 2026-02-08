//! USDC Reserve System
//! 
//! This module handles the 1:1 USDC-BB token bridge.
//! Users deposit USDC on Ethereum, and BB tokens are minted on L1.
//! Users burn BB tokens on L1, and USDC is released back on Ethereum.
//!
//! Architecture:
//! - Reserve: Tracks locked USDC and user reserves
//! - Oracle: Watches Ethereum for USDC deposits
//! - Bridge: Handles deposit/withdrawal requests

pub mod reserve;
pub mod oracle;
pub mod bridge;

pub use reserve::*;
pub use oracle::*;
pub use bridge::*;
