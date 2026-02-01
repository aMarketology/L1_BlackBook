//! # BlackBook L1 - Unified Wallet System (S+ Tier)
//!
//! ## Architecture: Zero-Key Disclosure via FROST TSS + OPAQUE
//!
//! This module implements a professional-grade wallet system where:
//! - The private key NEVER exists in full (not even momentarily in RAM)
//! - Keys are born distributed via DKG (Distributed Key Generation)
//! - Signing happens via MPC (Multi-Party Computation)
//! - Authentication uses OPAQUE (server can't see password OR hash)
//!
//! ## Share Distribution (2-of-3 TSS)
//!
//! | Share | Name           | Storage                  | Access Control       |
//! |-------|----------------|--------------------------|----------------------|
//! | 1     | Device Shard   | User's device            | Biometrics/Local PIN |
//! | 2     | Guardian Shard | Server / DHT             | OPAQUE Protocol      |
//! | 3     | Recovery Shard | Offline / Social / Cloud | Manual Import        |
//!
//! ## Why This Is S+ Tier
//!
//! | Feature          | Old (C+)                    | New (S+)                        |
//! |------------------|-----------------------------|---------------------------------|
//! | Key Location     | RAM (reconstructed)         | NOWHERE (never exists fully)    |
//! | Server Hack      | Total Loss                  | Zero Loss (math fragment only)  |
//! | Auth             | SHA256 (crackable)          | OPAQUE (mathematically blind)   |
//! | Recovery         | Need password for Share B   | Share 3 works independently     |
//!
//! ## Module Structure
//!
//! - `dkg.rs` - Distributed Key Generation (FROST DKG)
//! - `tss.rs` - Threshold Signature Scheme (FROST signing)
//! - `opaque_auth.rs` - OPAQUE password authentication
//! - `storage.rs` - Shard storage and retrieval
//! - `types.rs` - Common types and structures
//! - `handlers.rs` - HTTP API handlers

pub mod types;
pub mod dkg;
pub mod tss;
pub mod opaque_auth;
pub mod storage;
pub mod handlers;

// Re-export main types for convenience
pub use types::*;
pub use dkg::FrostDKG;
pub use tss::ThresholdSigner;
pub use opaque_auth::OpaqueAuth;
pub use storage::ShardStorage;
pub use handlers::WalletHandlers;

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

/// Central wallet system state
/// 
/// This is the main entry point for all wallet operations.
/// It coordinates DKG, signing, and authentication.
#[derive(Clone)]
pub struct UnifiedWalletSystem {
    /// FROST DKG coordinator
    pub dkg: Arc<FrostDKG>,
    
    /// Threshold signer (FROST)
    pub signer: Arc<ThresholdSigner>,
    
    /// OPAQUE authentication
    pub auth: Arc<OpaqueAuth>,
    
    /// Shard storage (server-side guardian shards)
    pub storage: Arc<ShardStorage>,
    
    /// Active signing sessions (for multi-round protocols)
    pub signing_sessions: Arc<DashMap<String, SigningSession>>,
    
    /// DKG sessions in progress
    pub dkg_sessions: Arc<DashMap<String, DKGSession>>,
}

impl UnifiedWalletSystem {
    /// Create a new unified wallet system
    pub fn new() -> Self {
        Self {
            dkg: Arc::new(FrostDKG::new()),
            signer: Arc::new(ThresholdSigner::new()),
            auth: Arc::new(OpaqueAuth::new()),
            storage: Arc::new(ShardStorage::new()),
            signing_sessions: Arc::new(DashMap::new()),
            dkg_sessions: Arc::new(DashMap::new()),
        }
    }
    
    /// Create a new wallet using FROST DKG
    /// 
    /// This is the main wallet creation flow:
    /// 1. Client initiates DKG
    /// 2. Server participates in DKG
    /// 3. Each party receives their shard (key fragment)
    /// 4. Public key is derived (can be used as address)
    /// 5. NO party ever sees the full private key
    pub async fn create_wallet(&self, session_id: &str) -> Result<WalletCreationResult, WalletError> {
        self.dkg.create_wallet(session_id).await
    }
    
    /// Sign a message using threshold signatures
    /// 
    /// Flow:
    /// 1. Client sends signing request with their partial signature
    /// 2. Server computes its partial signature (never sees client's shard)
    /// 3. Partial signatures are combined into a valid Ed25519 signature
    /// 4. The private key NEVER exists in RAM
    pub async fn sign_message(
        &self,
        wallet_address: &str,
        message: &[u8],
        client_commitment: &[u8],
    ) -> Result<SignatureResult, WalletError> {
        self.signer.sign(wallet_address, message, client_commitment).await
    }
    
    /// Authenticate user via OPAQUE
    /// 
    /// OPAQUE is a Password Authenticated Key Exchange (PAKE) protocol.
    /// The server can verify the user knows their password WITHOUT:
    /// - Seeing the password
    /// - Seeing a hash of the password
    /// - Being able to perform offline brute-force attacks
    pub async fn authenticate(
        &self,
        wallet_address: &str,
        opaque_message: &[u8],
    ) -> Result<AuthResult, WalletError> {
        self.auth.authenticate(wallet_address, opaque_message).await
    }
}

impl Default for UnifiedWalletSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_system_creation() {
        let system = UnifiedWalletSystem::new();
        assert!(system.signing_sessions.is_empty());
        assert!(system.dkg_sessions.is_empty());
    }
}
