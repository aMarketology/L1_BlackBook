//! L3 NFT Bridge — On-Chain Anchor Contract
//!
//! Stores NFT ownership and metadata hashes on L1, providing an immutable
//! provenance record for NFTs minted on the L3 engine.
//!
//! Each NFT is keyed by `(collection_id, token_id)` and stores:
//!   - Current owner (base58 address)
//!   - SHA-256 of the full metadata JSON (content-addressed)
//!   - Metadata URI (IPFS/Arweave)
//!   - Transfer history count
//!
//! Write operations require Ed25519 signatures:
//!   - `anchor_nft` — signed by the L3 sequencer (allowlist-gated)
//!   - `transfer_nft` — signed by the current owner

use serde::{Deserialize, Serialize};
use tracing::info;

// ─────────────────────────── On-Chain NFT State ──────────────────────────────

/// A single anchored NFT on L1.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnchoredNft {
    pub collection_id: String,
    pub token_id: String,
    pub owner: String,
    /// SHA-256 of the metadata JSON (32 bytes, hex-encoded for storage).
    pub metadata_hash: String,
    /// IPFS/Arweave URI pointing to the full metadata.
    pub metadata_uri: String,
    pub minted_slot: u64,
    pub last_transfer_slot: u64,
    pub transfer_count: u32,
}

/// Composite key for NFT lookups: "collection_id:token_id"
pub fn nft_key(collection_id: &str, token_id: &str) -> String {
    format!("{}:{}", collection_id, token_id)
}

// ─────────────────────────── ReDB Table ──────────────────────────────────────

/// ReDB table: nft_key (str) → AnchoredNft (JSON bytes)
pub const NFT_TABLE: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("nft_anchors");

// ─────────────────────────── Storage Helpers ─────────────────────────────────

pub fn put_nft(db: &redb::Database, nft: &AnchoredNft) -> Result<(), redb::Error> {
    let key = nft_key(&nft.collection_id, &nft.token_id);
    let bytes = serde_json::to_vec(nft).expect("serialize AnchoredNft");
    let txn = db.begin_write()?;
    {
        let mut tbl = txn.open_table(NFT_TABLE)?;
        tbl.insert(key.as_str(), bytes.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

pub fn get_nft(db: &redb::Database, collection_id: &str, token_id: &str) -> Option<AnchoredNft> {
    let key = nft_key(collection_id, token_id);
    let txn = db.begin_read().ok()?;
    let tbl = txn.open_table(NFT_TABLE).ok()?;
    let val = tbl.get(key.as_str()).ok()??;
    serde_json::from_slice(val.value()).ok()
}

// ─────────────────────────── HTTP Endpoints ──────────────────────────────────
// These complement the gRPC bridge for direct L1 access.

use axum::{extract::{Path, State}, response::IntoResponse, http::StatusCode, Json};
use crate::AppState;

/// GET /nft/:collection_id/:token_id — query NFT state
pub async fn get_nft_handler(
    State(state): State<AppState>,
    Path((collection_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match get_nft(&state.blockchain.db, &collection_id, &token_id) {
        Some(nft) => (StatusCode::OK, Json(serde_json::json!({
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
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "found": false,
            "error": "NFT not found",
        }))),
    }
}

/// GET /nft/:collection_id/:token_id/owner — quick owner lookup
pub async fn get_nft_owner_handler(
    State(state): State<AppState>,
    Path((collection_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match get_nft(&state.blockchain.db, &collection_id, &token_id) {
        Some(nft) => (StatusCode::OK, Json(serde_json::json!({
            "owner": nft.owner,
        }))),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "NFT not found",
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

    let mut nft = match get_nft(&state.blockchain.db, &req.collection_id, &req.token_id) {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "NFT not found" }))),
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

    if let Err(e) = put_nft(&state.blockchain.db, &nft) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Persist failed: {:?}", e)
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
