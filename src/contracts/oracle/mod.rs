pub mod finalize;
use std::sync::atomic::Ordering;
use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use tracing::{info, warn};

use crate::AppState;
use crate::storage::{OracleNode, PendingRootStatus, Disputer};
use crate::svm::{SplTokenEngine, maxx_mint_bytes, MAXX_UNIT};

// ── ORACLE CONSTANTS ──────────────────────────────────────────────────────────
const MIN_DISPUTE_STAKE_PICO_XX: u64 = 100 * MAXX_UNIT;
const DISPUTE_ESCALATION_THRESHOLD: u64 = 1_000 * MAXX_UNIT;

// ============================================================================
// ORACLE SYSTEM — Step 1: Registry + Read Endpoints
// ============================================================================
//
// Architecture: Option B — Optimistic Dispute Window with $XX governance.
// See docs/oracle.md for the full design.
//
// Step 1 (this file): oracle node registration + read endpoints.
// Step 2: SubmitPendingRoot gRPC + dispute window + finalize background task.
// Step 3: $XX weighted voting + oracle bond slashing.
// ============================================================================

// ── REGISTER ORACLE NODE (admin-only) ────────────────────────────────────────

/// Request body for POST /oracle/register
#[cfg(feature = "unsafe_admin")]
#[derive(serde::Deserialize)]
pub struct RegisterOracleRequest {
    /// Ed25519 public key of the oracle node — 64 hex chars (32 bytes).
    pub pubkey_hex: String,
    /// Human-readable label, e.g. "oracle-node-1". Max 64 chars.
    pub name: String,
    /// $XX bond in pico-MAXX (12 decimals). Min 1,000 $XX = 1_000 * MAXX_UNIT.
    /// The bond is slashable if the oracle signs a wrong outcome.
    pub bond_pico_xx: u64,
}

/// POST /oracle/register  (unsafe_admin feature only)
///
/// Register a new oracle committee node.  Requires a non-zero $XX bond.
/// The bond amount is recorded but NOT automatically deducted here —
/// Step 3 will enforce the deduction via SplTokenEngine when slashing is live.
#[cfg(feature = "unsafe_admin")]
pub async fn register_oracle_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterOracleRequest>,
) -> impl IntoResponse {
    // ── Validation ──────────────────────────────────────────────────────
    if req.pubkey_hex.len() != 64 || hex::decode(&req.pubkey_hex).is_err() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "pubkey_hex must be exactly 64 valid hex chars (32 bytes)"
        })));
    }
    if req.name.is_empty() || req.name.len() > 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "name must be 1–64 chars"
        })));
    }
    if req.bond_pico_xx == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "bond_pico_xx must be > 0"
        })));
    }

    // ── Duplicate guard ──────────────────────────────────────────────────
    if state.blockchain.load_oracle_node(&req.pubkey_hex).is_some() {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Oracle node with this pubkey already registered"
        })));
    }

    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let node = OracleNode {
        pubkey_hex: req.pubkey_hex.clone(),
        name: req.name.clone(),
        registered_at_slot: current_slot,
        active: true,
        total_resolutions: 0,
        correct_resolutions: 0,
        slash_balance_pico_xx: req.bond_pico_xx,
    };

    match state.blockchain.store_oracle_node(&node) {
        Ok(()) => {
            info!(pubkey = %req.pubkey_hex, name = %req.name, slot = current_slot, "Oracle node registered");
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "pubkey_hex": req.pubkey_hex,
                "name": req.name,
                "registered_at_slot": current_slot,
            })))
        }
        Err(e) => {
            warn!(error = %e, "Failed to store oracle node");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Storage error: {}", e)
            })))
        }
    }
}

// ── LIST ORACLE NODES ─────────────────────────────────────────────────────────

/// GET /oracle/nodes
///
/// Returns all registered oracle nodes and their track records.
pub async fn list_oracle_nodes_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let nodes = state.blockchain.load_all_oracle_nodes();
    let count = nodes.len();
    (StatusCode::OK, Json(serde_json::json!({
        "nodes": nodes,
        "count": count,
    })))
}

// ── ORACLE EVENT STATUS ───────────────────────────────────────────────────────

/// GET /oracle/event/:market_id
///
/// Returns the current resolution state for a market.
/// Checks PENDING_ROOTS first (populated in Step 2), then falls back to
/// ESCROW_MARKET_ROOTS (legacy dealer path / already-finalized markets).
///
/// L3 NFT engine polls this endpoint to embed `oracle_event_hash` in metadata.
pub async fn oracle_event_handler(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    if market_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "market_id is required"
        })));
    }

    // ── Check PENDING_ROOTS first (Step 2+ path) ─────────────────────────
    if let Some(root) = state.blockchain.load_pending_root(&market_id) {
        let status_str = match &root.status {
            PendingRootStatus::Pending   => "Pending",
            PendingRootStatus::Disputed  => "Disputed",
            PendingRootStatus::Finalized => "Finalized",
            PendingRootStatus::Discarded => "Discarded",
        };
        let oracle_event_hash = compute_oracle_event_hash(&root.market_id, &root.outcome, &root.merkle_root);
        return (StatusCode::OK, Json(serde_json::json!({
            "market_id": market_id,
            "status": status_str,
            "outcome": root.outcome,
            "merkle_root": hex::encode(root.merkle_root),
            "proposed_at_slot": root.proposed_at_slot,
            "finalize_at_slot": root.finalize_at_slot,
            "dispute_stake_pico_xx": root.dispute_stake_pico_xx.to_string(),
            "oracle_event_hash": oracle_event_hash,
        })));
    }

    // ── Fall back to ESCROW_MARKET_ROOTS (legacy finalized markets) ───────
    match state.blockchain.get_escrow_market_root(&market_id) {
        Ok(Some(root_bytes)) if !root_bytes.is_empty() => {
            (StatusCode::OK, Json(serde_json::json!({
                "market_id": market_id,
                "status": "Finalized",
                "outcome": null,
                "merkle_root": hex::encode(&root_bytes),
                "note": "Finalized via legacy dealer path — no oracle attestation on record",
            })))
        }
        _ => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "market_id": market_id,
                "status": "Unknown",
            })))
        }
    }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

/// Deterministic oracle event hash: SHA-256(market_id || outcome || merkle_root).
/// Embedded in L3 NFT metadata for on-chain provenance verification.
fn compute_oracle_event_hash(market_id: &str, outcome: &str, merkle_root: &[u8; 32]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(market_id.as_bytes());
    hasher.update(outcome.as_bytes());
    hasher.update(merkle_root);
    format!("{:x}", hasher.finalize())
}

// ── DISPUTE A PENDING ROOT ────────────────────────────────────────────────────

/// POST /oracle/dispute
///
/// Any user can stake $XX to challenge a pending root during the dispute window.
/// Canonical signed message: `ORACLE_DISPUTE:{market_id}:{xx_stake_pico}:{timestamp}:{nonce}`
///
/// If total staked $XX reaches DISPUTE_ESCALATION_THRESHOLD, the root moves to
/// `Disputed` status and awaits a $XX governance vote (Step 3).
#[derive(serde::Deserialize)]
pub struct DisputeRequest {
    pub market_id: String,
    /// $XX stake in pico-MAXX (12 decimals). Min 100 $XX = 100 * MAXX_UNIT.
    pub xx_stake_pico: u64,
    /// Hex-encoded Ed25519 public key (64 chars, 32 bytes) of the disputer.
    pub public_key: String,
    /// Hex-encoded Ed25519 signature (128 chars, 64 bytes).
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

pub async fn oracle_dispute_handler(
    State(state): State<AppState>,
    Json(req): Json<DisputeRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────────
    if req.market_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "market_id is required"
        })));
    }
    if req.xx_stake_pico < MIN_DISPUTE_STAKE_PICO_XX {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("xx_stake_pico must be >= {} pico-MAXX (100 $XX)", MIN_DISPUTE_STAKE_PICO_XX)
        })));
    }

    // ── Timestamp freshness (60-second window) ──────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp too old or too far in the future (60s window)"
        })));
    }

    // ── Decode keys ─────────────────────────────────────────────────────────
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "public_key must be 64 valid hex chars (32 bytes)"
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 128 valid hex chars (64 bytes)"
        }))),
    };

    // ── Ed25519 signature verification ──────────────────────────────────────
    // Canonical message: "ORACLE_DISPUTE:{market_id}:{xx_stake_pico}:{timestamp}:{nonce}"
    {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let msg = format!("ORACLE_DISPUTE:{}:{}:{}:{}",
            req.market_id, req.xx_stake_pico, req.timestamp, req.nonce);
        let vk = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0u8;32])) {
            Ok(k) => k,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid public key"
            }))),
        };
        let sig = match Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap_or(&[0u8;64])) {
            s => s,
        };
        if vk.verify(msg.as_bytes(), &sig).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Signature verification failed"
            })));
        }
    }

    // Derive wallet address from public key (base58)
    let wallet = bs58::encode(&pk_bytes).into_string();

    // ── Nonce replay protection ──────────────────────────────────────────────
    let nonce_key = format!("oracle_dispute:{}:{}", wallet, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used"
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(e) => { e.insert(req.timestamp); }
    }

    // ── Rate limiting ────────────────────────────────────────────────────────
    if state.throttler.check_transaction(&wallet, 0.0).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "error": "Rate limit exceeded"
        })));
    }

    // ── Load pending root ────────────────────────────────────────────────────
    let mut pending = match state.blockchain.load_pending_root(&req.market_id) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No pending root found for market_id={}", req.market_id)
        }))),
    };

    // ── Check root is still disputable ──────────────────────────────────────
    match pending.status {
        PendingRootStatus::Finalized => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Root is already finalized — dispute window has closed"
            })));
        }
        PendingRootStatus::Discarded => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Root has already been discarded"
            })));
        }
        PendingRootStatus::Pending | PendingRootStatus::Disputed => {}
    }

    let current_slot = state.current_slot.load(Ordering::Relaxed);
    if current_slot >= pending.finalize_at_slot {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Dispute window has expired (current_slot >= finalize_at_slot)",
            "current_slot": current_slot,
            "finalize_at_slot": pending.finalize_at_slot,
        })));
    }

    // ── Debit disputer's $XX → dispute pool address ──────────────────────────
    let svm = &state.blockchain.svm_accounts;
    let maxx_mint = maxx_mint_bytes();
    let disputer_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&wallet);
    // Dispute pool: deterministic address per market_id ("oracle_dispute_pool_{market_id}")
    let pool_addr = format!("oracle_dispute_pool_{}", req.market_id);
    let pool_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&pool_addr);

    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &maxx_mint, &disputer_pk, &pool_pk, req.xx_stake_pico) {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
            "error": format!("Failed to lock $XX stake: {}", e)
        })));
    }

    // ── Update PendingRoot ───────────────────────────────────────────────────
    pending.dispute_stake_pico_xx = pending.dispute_stake_pico_xx.saturating_add(req.xx_stake_pico);
    pending.disputers.push(Disputer {
        wallet: wallet.clone(),
        stake_pico_xx: req.xx_stake_pico,
    });

    let escalated = pending.dispute_stake_pico_xx >= DISPUTE_ESCALATION_THRESHOLD
        && pending.status != PendingRootStatus::Disputed;
    if escalated {
        pending.status = PendingRootStatus::Disputed;
    }

    // ── ReDB first, then respond ─────────────────────────────────────────────
    if let Err(e) = state.blockchain.store_pending_root(&pending) {
        // Roll back the $XX transfer
        let _ = SplTokenEngine::transfer_tokens(svm, &maxx_mint, &pool_pk, &disputer_pk, req.xx_stake_pico);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to persist dispute: {}", e)
        })));
    }

    info!("⚖️  Dispute filed: market={} wallet={} stake={} total_stake={} escalated={}",
        req.market_id, wallet, req.xx_stake_pico, pending.dispute_stake_pico_xx, escalated);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "market_id": req.market_id,
        "total_dispute_stake_pico_xx": pending.dispute_stake_pico_xx.to_string(),
        "escalated_to_vote": escalated,
        "disputer_count": pending.disputers.len(),
    })))
}

// ── GOVERNANCE VOTE ──────────────────────────────────────────────────────────

/// POST /oracle/vote
///
/// $XX holders vote on escalated disputes (only when `status == Disputed`).
/// Canonical signed message: `ORACLE_VOTE:{market_id}:{vote}:{timestamp}:{nonce}`
/// `vote` = "true" to uphold the root, "false" to discard it.
///
/// Note: actual $XX-weighted vote tallying (Step 3). For now, votes are
/// recorded and the root is discarded if any vote casts "false" (conservative default).
#[derive(serde::Deserialize)]
pub struct VoteRequest {
    pub market_id: String,
    /// true = uphold root (oracle was correct), false = discard (oracle was wrong).
    pub vote: bool,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

pub async fn oracle_vote_handler(
    State(state): State<AppState>,
    Json(req): Json<VoteRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────────
    if req.market_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "market_id is required"
        })));
    }

    // ── Timestamp freshness ──────────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp too old or too far in the future (60s window)"
        })));
    }

    // ── Decode keys ─────────────────────────────────────────────────────────
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "public_key must be 64 valid hex chars (32 bytes)"
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 128 valid hex chars (64 bytes)"
        }))),
    };

    // ── Ed25519 verification ─────────────────────────────────────────────────
    // Canonical message: "ORACLE_VOTE:{market_id}:{vote}:{timestamp}:{nonce}"
    {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let msg = format!("ORACLE_VOTE:{}:{}:{}:{}",
            req.market_id, req.vote, req.timestamp, req.nonce);
        let vk = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0u8;32])) {
            Ok(k) => k,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid public key"
            }))),
        };
        let sig = match Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap_or(&[0u8;64])) {
            s => s,
        };
        if vk.verify(msg.as_bytes(), &sig).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Signature verification failed"
            })));
        }
    }

    let wallet = bs58::encode(&pk_bytes).into_string();

    // ── Nonce replay protection ──────────────────────────────────────────────
    let nonce_key = format!("oracle_vote:{}:{}", wallet, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used"
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(e) => { e.insert(req.timestamp); }
    }

    // ── Load pending root ────────────────────────────────────────────────────
    let mut pending = match state.blockchain.load_pending_root(&req.market_id) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No pending root found for market_id={}", req.market_id)
        }))),
    };

    if pending.status != PendingRootStatus::Disputed {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Root is not in Disputed state — only escalated roots can be voted on",
            "status": format!("{:?}", pending.status),
        })));
    }

    // ── Check voter has any $XX ──────────────────────────────────────────────
    let svm = &state.blockchain.svm_accounts;
    let maxx_mint = maxx_mint_bytes();
    let voter_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&wallet);
    let voter_xx_balance = SplTokenEngine::get_token_balance(svm, &maxx_mint, &voter_pk);
    if voter_xx_balance == 0 {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "No $XX balance — must hold $XX to vote"
        })));
    }

    // ── Step 2 vote logic: discard if any "false" vote (conservative).
    // Step 3 will replace with $XX-weighted supermajority.
    // ────────────────────────────────────────────────────────────────────────
    if !req.vote {
        pending.status = PendingRootStatus::Discarded;
        if let Err(e) = state.blockchain.store_pending_root(&pending) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to persist vote: {}", e)
            })));
        }
        // Return disputer stakes (best-effort; Step 3 will add slash logic)
        let pool_addr = format!("oracle_dispute_pool_{}", req.market_id);
        let pool_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&pool_addr);
        for d in &pending.disputers {
            let d_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&d.wallet);
            let _ = SplTokenEngine::transfer_tokens(svm, &maxx_mint, &pool_pk, &d_pk, d.stake_pico_xx);
        }
        info!("🗳️  Vote DISCARD: market={} voter={} xx_weight={}", req.market_id, wallet, voter_xx_balance);
        return (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "market_id": req.market_id,
            "outcome": "Discarded",
            "voter_xx_weight": voter_xx_balance.to_string(),
        })));
    }

    // Uphold vote — root stays Disputed until finalize_at_slot
    info!("🗳️  Vote UPHOLD: market={} voter={} xx_weight={}", req.market_id, wallet, voter_xx_balance);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "market_id": req.market_id,
        "outcome": "Uphold recorded — root remains in dispute window",
        "voter_xx_weight": voter_xx_balance.to_string(),
    })))
}
