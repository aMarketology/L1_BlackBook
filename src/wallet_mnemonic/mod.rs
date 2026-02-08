//! # Wallet Mnemonic Module - Consumer Track
//!
//! This module implements the Consumer Wallet system for BlackBook L1.
//! 
//! ## Current Implementation: Mnemonic SSS (Shamir Secret Sharing)
//!
//! BlackBook L1 MVP launches with consumer-grade wallets only:
//! - Standard BIP-39 (24 words, 256-bit entropy)
//! - Shamir 2-of-3 protection at rest
//! - MetaMask/Ledger exportable
//! - Target: Everyday users, DeFi traders
//!
//! ## Future: FROST Institutional Wallets (Hot Upgrade Phase 2)
//!
//! After mainnet launch, the first hot upgrade will add:
//! - FROST TSS (Threshold Signature Scheme)
//! - Key born distributed via DKG (never exists in full)
//! - Multi-party signing ceremony
//! - Social/guardian recovery
//! - Target: DAOs, treasuries, $1M+ accounts
//!
//! See `docs/HOT_UPGRADE_GUIDE.md` for implementation details.
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
/// BlackBook L1 currently supports only the Consumer Track (Deterministic).
/// FROST Institutional Wallets will be added via hot upgrade in Phase 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletSecurityMode {
    /// Consumer Track: Key derived from 24-word mnemonic.
    /// Shamir 2-of-3 protection. MetaMask exportable.
    Deterministic(MnemonicConfig),
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
    /// Username/alias for the wallet (for ledger display)
    #[serde(default)]
    pub username: Option<String>,
}
