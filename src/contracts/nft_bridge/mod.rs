//! L3 NFT Bridge — On-Chain Anchor Contract
//!
//! Stores NFT ownership and metadata hashes on L1 via the `ConcurrentBlockchain`
//! storage gateway (`db` is strictly private inside `storage/mod.rs`).

use serde::Deserialize;
use tracing::info;
use axum::{extract::{Path, State}, response::IntoResponse, http::StatusCode, Json};
use crate::AppState;

pub use layer1::storage::AnchoredNft;

/// GET /nft/:collection_id/:token_id — query NFT state
pub async fn get_nft_handler(
    State(state): State<AppState>,
    Path((collection_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.blockchain.get_nft(&collection_id, &token_id) {
        Ok(Some(nft)) => (StatusCode::OK, Json(serde_json::json!({
            "found": true,
            "collection_id": nft.collection_id,
            "token_id": nft.token_id,
            "owner": nft.owner,
            "metadata_hash": nft.metadata_hash,
            "metadata_uri": nft.metadata_uri,
            "minted_slot": nft.minted_slot,
            "last_transfer_slot": nft.last_transfer_slot,
            "transfer_count": nft.transfer_count,
        }))),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "found": false,
            "error": "NFT not found",
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "found": false,
            "error": format!("Storage read failed: {e}"),
        }))),
    }
}

/// GET /nft/:collection_id/:token_id/owner — quick owner lookup
pub async fn get_nft_owner_handler(
    State(state): State<AppState>,
    Path((collection_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.blockchain.get_nft(&collection_id, &token_id) {
        Ok(Some(nft)) => (StatusCode::OK, Json(serde_json::json!({
            "owner": nft.owner,
        }))),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "NFT not found",
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Storage read failed: {e}"),
        }))),
    }
}

// ─────────────────────────── Transfer (HTTP) ─────────────────────────────────

#[derive(Deserialize)]
pub struct NftTransferRequest {
    pub collection_id: String,
    pub token_id: String,
    pub from: String,
    pub to: String,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

/// POST /nft/transfer — owner-signed NFT transfer
pub async fn transfer_nft_handler(
    State(state): State<AppState>,
    Json(req): Json<NftTransferRequest>,
) -> impl IntoResponse {
    // Auth: "NFT_TRANSFER:{collection}:{token}:{from}:{to}:{ts}:{nonce}"
    let body_str = format!("{}:{}:{}:{}", req.collection_id, req.token_id, req.from, req.to);
    if let Err((code, body)) = crate::auth::verify_signed_action(
        &state, "NFT_TRANSFER", &req.from,
        &req.public_key, &req.signature,
        req.timestamp, &req.nonce, &body_str,
    ) {
        return (code, body);
    }

    // Rate limit
    if let Err(msg) = state.throttler.check_transaction(&req.from, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": msg })));
    }

    let mut nft = match state.blockchain.get_nft(&req.collection_id, &req.token_id) {
        Ok(Some(n)) => n,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "NFT not found" }))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Storage read failed: {e}")
        }))),
    };
    if nft.owner != req.from {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Not the owner" })));
    }
    if req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "to address required" })));
    }

    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    nft.owner = req.to.clone();
    nft.last_transfer_slot = height;
    nft.transfer_count += 1;

    if let Err(e) = state.blockchain.put_nft(&nft) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Persist failed: {e}")
        })));
    }

    info!("🖼️ NFT TRANSFER: {}:{} from {} → {} (#{} transfer)",
        nft.collection_id, nft.token_id, req.from, req.to, nft.transfer_count);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "collection_id": nft.collection_id,
        "token_id": nft.token_id,
        "new_owner": nft.owner,
        "transfer_count": nft.transfer_count,
    })))
}
