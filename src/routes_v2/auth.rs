// ============================================================================
// AUTH ROUTES - ZKP Types Only
// ============================================================================
//
// This module re-exports ZKP types from unified_auth for use in main_v3.rs
// All actual route handlers are in main_v3.rs using Axum.

// Re-export ZKP types
pub use crate::integration::unified_auth::{
    WalletZKPData,
    ZKPLoginRequest,
    SSSShare,
    ZKProof,
    store_share_b,
    release_share_b,
    verify_zk_proof,
    get_wallet_zkp_data,
    is_wallet_registered,
};
