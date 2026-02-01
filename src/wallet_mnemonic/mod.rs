//! # Wallet Mnemonic Module - Consumer Track
//!
//! This module implements the "Consumer Track" of BlackBook's Hybrid Custody system.
//! 
//! ## Architecture: Hybrid Custody (Adaptive Security)
//!
//! BlackBook supports TWO wallet modes:
//!
//! ### 1. Institutional Track (FROST TSS) - `src/unified_wallet/`
//! - Key is **born distributed** via DKG (never exists in full)
//! - Signing requires multi-party ceremony
//! - No recovery phrase (social/guardian recovery)
//! - Target: DAOs, treasuries, $1M+ accounts
//!
//! ### 2. Consumer Track (Mnemonic SSS) - THIS MODULE
//! - Standard BIP-39 (24 words, 256-bit entropy)
//! - Key CAN exist in full (during signing)
//! - Shamir 2-of-3 protection at rest
//! - MetaMask/Ledger exportable
//! - Target: Everyday users, DeFi traders
//!
//! ## Security Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    MNEMONIC SSS ARCHITECTURE                     │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! 24-Word Mnemonic (256-bit entropy)
//!           │
//!           ▼
//!    ┌──────────────┐
//!    │  Shamir SSS  │  (2-of-3 threshold)
//!    │   Split      │
//!    └──────────────┘
//!           │
//!    ┌──────┼──────┐
//!    ▼      ▼      ▼
//! Share A  Share B  Share C
//! (Client) (L1 Chain) (Vault)
//!    │        │        │
//!    ▼        ▼        ▼
//! Password  ZKP-Gated  Pepper
//! Bound     Release    Encrypted
//!
//! Recovery Combinations:
//! ✅ A + B = User + L1 (normal operation)
//! ✅ A + C = User + Vault (L1 down)
//! ❌ B + C = Impossible (no password knowledge)
//! ```
//!
//! ## Comparison with FROST Track
//!
//! | Feature          | FROST (Institutional)    | Mnemonic (Consumer)      |
//! |------------------|--------------------------|--------------------------|
//! | Key Generation   | DKG (born in pieces)     | BIP-39 (24 words)        |
//! | Signing          | Multi-party ceremony     | Single-party hash        |
//! | Trust Model      | Trust in math/network    | Trust in physical backup |
//! | Recovery         | Guardian shards          | "Paper in the safe"      |
//! | Portability      | Zero (FROST-only)        | High (MetaMask ready)    |
//! | Target Users     | $1M+ / DAOs              | Everyday users           |

pub mod mnemonic;
pub mod sss;
pub mod signer;
pub mod handlers;

pub use mnemonic::*;
pub use sss::*;
pub use signer::*;
pub use handlers::*;

use serde::{Deserialize, Serialize};

// ============================================================================
// WALLET SECURITY MODE ENUM
// ============================================================================

/// Defines which security track a wallet uses.
/// 
/// This is the "bridge" that lets the blockchain treat all wallets uniformly
/// while maintaining different security models underneath.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletSecurityMode {
    /// Institutional Track: Key exists only as threshold shards.
    /// Requires FROST ceremony to sign. No recovery phrase.
    Threshold(ThresholdConfig),
    
    /// Consumer Track: Key derived from 24-word mnemonic.
    /// Shamir 2-of-3 protection. MetaMask exportable.
    Deterministic(MnemonicConfig),
}

/// Configuration for FROST threshold wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Threshold required (e.g., 2 of 3)
    pub threshold: u16,
    /// Total number of participants
    pub participants: u16,
    /// Guardian shard ID (server-held)
    pub guardian_shard_id: String,
    /// Whether this wallet has a recovery guardian
    pub has_recovery_guardian: bool,
}

/// Configuration for mnemonic-based wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MnemonicConfig {
    /// Share A derivation path (password-bound)
    pub share_a_salt: String,
    /// Share B location (L1 chain address)
    pub share_b_location: String,
    /// Share C encryption key ID (Vault pepper)
    pub share_c_vault_key: String,
    /// BIP-44 derivation path used
    pub derivation_path: String,
    /// Whether mnemonic has been exported (security flag)
    pub has_been_exported: bool,
}

impl Default for MnemonicConfig {
    fn default() -> Self {
        Self {
            share_a_salt: String::new(),
            share_b_location: String::new(),
            share_c_vault_key: "blackbook/pepper".to_string(),
            derivation_path: "m/44'/501'/0'/0'".to_string(), // Ed25519 path
            has_been_exported: false,
        }
    }
}

// ============================================================================
// WALLET METADATA
// ============================================================================

/// Unified wallet metadata stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// The L1 address (bb_...)
    pub address: String,
    /// Public key (hex)
    pub public_key: String,
    /// Security mode (Threshold or Deterministic)
    pub security_mode: WalletSecurityMode,
    /// Creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_active: u64,
}
