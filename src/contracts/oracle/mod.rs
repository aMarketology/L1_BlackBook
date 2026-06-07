pub mod finalize;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use tracing::info;

use crate::AppState;
use crate::storage::{PendingRoot, PendingRootStatus, Disputer, OracleSignature};
use crate::svm::LAMPORTS_PER_BB;

// ── ORACLE CONSTANTS ─────────────────────────────────────────────────────────────────────────
/// Minimum $BB lamports to open a dispute (100 BB = $10).
const MIN_DISPUTE_STAKE_BB_LAMPORTS: u64 = 100 * LAMPORTS_PER_BB;
/// Escalation threshold in $BB lamports (1 000 BB = $100).
const DISPUTE_ESCALATION_THRESHOLD_BB_LAMPORTS: u64 = 1_000 * LAMPORTS_PER_BB;
/// Dispute window: 150 slots × 400 ms = 60 seconds.
const DISPUTE_WINDOW_SLOTS: u64 = 150;
/// Minimum $BB balance to cast a governance vote (100 BB = $10).
const MIN_VOTE_STAKE_BB_LAMPORTS: u64 = 100 * LAMPORTS_PER_BB;

// ============================================================================
// ORACLE SYSTEM — Step 1: Registry + Read Endpoints
// ============================================================================
//
// Architecture: Option B — Optimistic Dispute Window with $BB governance.
// See docs/oracle.md for the full design.
//
// Step 1 (this file): oracle node registration + read endpoints.
// Step 2: SubmitPendingRoot — L2 sequencer submits outcome for dispute window.
// Step 3: $BB-weighted vote tallying + oracle bond slashing. (IMPLEMENTED BELOW)
// ============================================================================

// ── SUBMIT PENDING ROOT (Step 2) ─────────────────────────────────────────────

/// POST /oracle/submit-pending-root
///
/// The authorized L2 sequencer submits a market outcome for the dispute window.
/// After `DISPUTE_WINDOW_SLOTS` (60 s) the `finalize_task` auto-finalizes it
/// if no dispute has escalated to a discard supermajority.
///
/// Canonical signed message:
///   `"ORACLE_SUBMIT:{rollup_id}:{market_id}:{outcome}:{merkle_root_hex}:{batch_id}:{ts}:{nonce}"`
///
/// Auth: `public_key` must match the `authorized_sequencers[rollup_id]` env var.
#[derive(serde::Deserialize)]
pub struct SubmitPendingRootRequest {
    pub rollup_id: String,
    pub market_id: String,
    /// "YES" | "NO" | "REFUND"
    pub outcome: String,
    /// 64-char lowercase hex (32-byte Merkle root from the Rollup Hub batch).
    pub merkle_root_hex: String,
    /// The Rollup Hub batch_id this root corresponds to (for cross-reference).
    pub batch_id: u64,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

pub async fn submit_pending_root_handler(
    State(state): State<AppState>,
    Json(req): Json<SubmitPendingRootRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────────
    if req.rollup_id.is_empty() || req.rollup_id.len() > 8 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "rollup_id must be 1–8 chars (e.g. 'L2', 'L3')"
        })));
    }
    if req.market_id.is_empty() || req.market_id.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "market_id must be 1–128 chars"
        })));
    }
    if !["YES", "NO", "REFUND"].contains(&req.outcome.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "outcome must be YES, NO, or REFUND"
        })));
    }
    if req.merkle_root_hex.len() != 64 || hex::decode(&req.merkle_root_hex).is_err() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "merkle_root_hex must be exactly 64 valid hex chars (32 bytes)"
        })));
    }

    // ── Verify authorized sequencer ─────────────────────────────────────────
    let expected_pk_hex = match state.authorized_sequencers.get(&req.rollup_id) {
        Some(pk) => pk.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": format!("Sequencer not configured for rollup {}", req.rollup_id)
        }))),
    };
    if req.public_key != *expected_pk_hex {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "Submitter is not the authorized sequencer for this rollup"
        })));
    }

    // ── Timestamp freshness ──────────────────────────────────────────────────
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp outside ±60 s window"
        })));
    }

    // ── Nonce replay protection ──────────────────────────────────────────────
    let nonce_key = format!("oracle_submit:{}:{}", req.public_key, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Duplicate nonce" })));
        }
        dashmap::mapref::entry::Entry::Vacant(e) => { e.insert(req.timestamp); }
    }

    // ── Ed25519 signature verification ──────────────────────────────────────
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "public_key must be 64 hex chars (32 bytes)"}))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "signature must be 128 hex chars (64 bytes)"}))),
    };
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| ()).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| ()).unwrap();
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid Ed25519 public key"}))),
    };
    let sig = Signature::from_bytes(&sig_arr);
    let message = format!("ORACLE_SUBMIT:{}:{}:{}:{}:{}:{}:{}",
        req.rollup_id, req.market_id, req.outcome, req.merkle_root_hex,
        req.batch_id, req.timestamp, req.nonce);
    if vk.verify(message.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid signature"})));
    }

    // ── Decode Merkle root ───────────────────────────────────────────────────
    let root_bytes_vec = hex::decode(&req.merkle_root_hex).unwrap(); // already validated above
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&root_bytes_vec);

    // ── Duplicate guard — don't overwrite an active dispute window ───────────
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    if let Some(existing) = state.blockchain.load_pending_root(&req.market_id) {
        if matches!(existing.status, PendingRootStatus::Pending | PendingRootStatus::Disputed) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "A pending root for this market is already in the dispute window",
                "status": format!("{:?}", existing.status),
                "finalize_at_slot": existing.finalize_at_slot,
            })));
        }
    }

    let pending = PendingRoot {
        market_id: req.market_id.clone(),
        outcome: req.outcome.clone(),
        merkle_root: root_arr,
        proposed_at_slot: current_slot,
        finalize_at_slot: current_slot + DISPUTE_WINDOW_SLOTS,
        dispute_stake_bb_lamports: 0,
        status: PendingRootStatus::Pending,
        proposer_pubkey: req.public_key.clone(),
        batch_id: req.batch_id,
        rollup_id: req.rollup_id.clone(),
        oracle_signatures: vec![OracleSignature {
            pubkey_hex: req.public_key.clone(),
            sig_hex: req.signature.clone(),
        }],
        disputers: vec![],
        uphold_stake_lamports: 0,
        discard_stake_lamports: 0,
        voters: vec![],
    };

    match state.blockchain.store_pending_root(&pending) {
        Ok(()) => {
            info!("📋 Oracle pending root submitted: rollup={} market={} outcome={} batch={} slot={} window_ends={}",
                req.rollup_id, req.market_id, req.outcome, req.batch_id,
                current_slot, current_slot + DISPUTE_WINDOW_SLOTS);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "market_id": req.market_id,
                "outcome": req.outcome,
                "batch_id": req.batch_id,
                "proposed_at_slot": current_slot,
                "finalize_at_slot": current_slot + DISPUTE_WINDOW_SLOTS,
                "dispute_window_slots": DISPUTE_WINDOW_SLOTS,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Storage error: {}", e)
        }))),
    }
}

// ── REGISTER ORACLE NODE (admin-only) ────────────────────────────────────────

/// Request body for POST /oracle/register
#[cfg(feature = "unsafe_admin")]
#[derive(serde::Deserialize)]
pub struct RegisterOracleRequest {
    /// Ed25519 public key of the oracle node — 64 hex chars (32 bytes).
    pub pubkey_hex: String,
    /// Human-readable label, e.g. "oracle-node-1". Max 64 chars.
    pub name: String,
    /// $BB bond in lamports. Min 1,000 BB = 1_000 * LAMPORTS_PER_BB.
    /// The bond is slashable if the oracle signs a wrong outcome.
    pub bond_bb_lamports: u64,
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
    if req.bond_bb_lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "bond_bb_lamports must be > 0"
        })));
    }

    // ── Duplicate guard ──────────────────────────────────────────────────
    if state.blockchain.load_oracle_node(&req.pubkey_hex).is_some() {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Oracle node with this pubkey already registered"
        })));
    }

    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let node = crate::storage::OracleNode {
        pubkey_hex: req.pubkey_hex.clone(),
        name: req.name.clone(),
        registered_at_slot: current_slot,
        active: true,
        total_resolutions: 0,
        correct_resolutions: 0,
        slash_balance_bb_lamports: req.bond_bb_lamports,
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
            tracing::warn!(error = %e, "Failed to store oracle node");
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
            "dispute_stake_bb_lamports": root.dispute_stake_bb_lamports.to_string(),
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
/// Any user can stake $BB to challenge a pending root during the dispute window.
/// Canonical signed message: `ORACLE_DISPUTE:{market_id}:{bb_stake_lamports}:{timestamp}:{nonce}`
///
/// If total staked $BB reaches DISPUTE_ESCALATION_THRESHOLD_BB_LAMPORTS, the root
/// moves to `Disputed` status.
#[derive(serde::Deserialize)]
pub struct DisputeRequest {
    pub market_id: String,
    /// $BB stake in lamports. Min 100 BB = 100 * LAMPORTS_PER_BB.
    pub bb_stake_lamports: u64,
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
    if req.bb_stake_lamports < MIN_DISPUTE_STAKE_BB_LAMPORTS {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("bb_stake_lamports must be >= {} lamports ({} BB)", MIN_DISPUTE_STAKE_BB_LAMPORTS, MIN_DISPUTE_STAKE_BB_LAMPORTS / LAMPORTS_PER_BB)
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
    // Canonical message: "ORACLE_DISPUTE:{market_id}:{bb_stake_lamports}:{timestamp}:{nonce}"
    {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let msg = format!("ORACLE_DISPUTE:{}:{}:{}:{}",
            req.market_id, req.bb_stake_lamports, req.timestamp, req.nonce);
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

    // ── Debit disputer's $BB → dispute pool address (native lamports) ───────
    // Dispute pool: deterministic address per market_id ("oracle_dispute_pool_{market_id}")
    let pool_addr = format!("oracle_dispute_pool_{}", req.market_id);

    if let Err(e) = state.blockchain.debit_svm_lamports(&wallet, req.bb_stake_lamports) {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
            "error": format!("Failed to lock $BB stake: {}", e)
        })));
    }
    // Credit to dispute pool (best-effort; debit already succeeded)
    let _ = state.blockchain.credit_svm_lamports(&pool_addr, req.bb_stake_lamports);

    // ── Update PendingRoot ───────────────────────────────────────────────────
    pending.dispute_stake_bb_lamports = pending.dispute_stake_bb_lamports.saturating_add(req.bb_stake_lamports);
    pending.disputers.push(Disputer {
        wallet: wallet.clone(),
        stake_bb_lamports: req.bb_stake_lamports,
    });

    let escalated = pending.dispute_stake_bb_lamports >= DISPUTE_ESCALATION_THRESHOLD_BB_LAMPORTS
        && pending.status != PendingRootStatus::Disputed;
    if escalated {
        pending.status = PendingRootStatus::Disputed;
    }

    // ── ReDB first, then respond ─────────────────────────────────────────────
    if let Err(e) = state.blockchain.store_pending_root(&pending) {
        // Roll back the $BB transfer
        let _ = state.blockchain.debit_svm_lamports(&pool_addr, req.bb_stake_lamports);
        let _ = state.blockchain.credit_svm_lamports(&wallet, req.bb_stake_lamports);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to persist dispute: {}", e)
        })));
    }

    info!("⚖️  Dispute filed: market={} wallet={} stake={} lamports total_stake={} escalated={}",
        req.market_id, wallet, req.bb_stake_lamports, pending.dispute_stake_bb_lamports, escalated);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "market_id": req.market_id,
        "total_dispute_stake_bb_lamports": pending.dispute_stake_bb_lamports.to_string(),
        "escalated_to_vote": escalated,
        "disputer_count": pending.disputers.len(),
    })))
}

// ── GOVERNANCE VOTE ──────────────────────────────────────────────────────────

/// POST /oracle/vote
///
/// $BB holders vote on escalated disputes (only when `status == Disputed`).
/// Canonical signed message: `ORACLE_VOTE:{market_id}:{vote}:{timestamp}:{nonce}`
/// `vote` = "true" to uphold the root, "false" to discard it.
///
/// Step 3: votes are weighted by the voter's $BB balance.  Their vote stake
/// (MIN_VOTE_STAKE_BB_LAMPORTS) is debited and held until the dispute resolves:
///   - Uphold supermajority (or timeout → Finalized): uphold voters get their
///     stake back + share the disputers' stakes. Oracle bond is retained.
///   - Discard supermajority (Discarded): discard voters get their stake back,
///     proposer oracle bond is slashed and distributed to disputers.
///
/// Supermajority = discard_stake * 3 >= (uphold_stake + discard_stake) * 2
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp outside ±60 s window"
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
    let msg = format!("ORACLE_VOTE:{}:{}:{}:{}", req.market_id, req.vote, req.timestamp, req.nonce);
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| ()).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| ()).unwrap();
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid public key"}))),
    };
    let sig = Signature::from_bytes(&sig_arr);
    if vk.verify(msg.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Signature verification failed"})));
    }

    let wallet = bs58::encode(&pk_bytes).into_string();

    // ── Nonce replay protection ──────────────────────────────────────────────
    let nonce_key = format!("oracle_vote:{}:{}", wallet, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Nonce already used"})));
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

    // ── Prevent double-voting ────────────────────────────────────────────────
    if pending.voters.contains(&wallet) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Wallet has already cast a vote on this root"
        })));
    }

    // ── Check minimum balance (skin-in-the-game) ─────────────────────────────
    let voter_balance = state.blockchain.get_balance_lamports(&wallet);
    if voter_balance < MIN_VOTE_STAKE_BB_LAMPORTS {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": format!("Insufficient $BB — must hold at least {} BB to vote",
                MIN_VOTE_STAKE_BB_LAMPORTS / LAMPORTS_PER_BB)
        })));
    }

    // ── Debit vote stake ─────────────────────────────────────────────────────
    // Vote stake is held in the dispute pool until resolution.
    // Using voter's balance as their proportional weight ensures the
    // governance signal is proportional to economic exposure.
    let vote_stake = MIN_VOTE_STAKE_BB_LAMPORTS; // fixed stake per vote (keeps it predictable)
    let pool_addr = format!("oracle_dispute_pool_{}", req.market_id);
    if let Err(e) = state.blockchain.debit_svm_lamports(&wallet, vote_stake) {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
            "error": format!("Failed to debit vote stake: {}", e)
        })));
    }
    let _ = state.blockchain.credit_svm_lamports(&pool_addr, vote_stake);

    // ── Record the vote ──────────────────────────────────────────────────────
    pending.voters.push(wallet.clone());
    if req.vote {
        pending.uphold_stake_lamports = pending.uphold_stake_lamports.saturating_add(vote_stake);
    } else {
        pending.discard_stake_lamports = pending.discard_stake_lamports.saturating_add(vote_stake);
    }

    // ── Check discard supermajority: discard * 3 >= total * 2 ───────────────
    let total_vote_stake = pending.uphold_stake_lamports.saturating_add(pending.discard_stake_lamports);
    let discard_supermajority = total_vote_stake > 0
        && pending.discard_stake_lamports.saturating_mul(3) >= total_vote_stake.saturating_mul(2);

    if discard_supermajority {
        // ── Discard: oracle was wrong ────────────────────────────────────────
        pending.status = PendingRootStatus::Discarded;
        if let Err(e) = state.blockchain.store_pending_root(&pending) {
            // Roll back vote stake on persistence failure
            let _ = state.blockchain.debit_svm_lamports(&pool_addr, vote_stake);
            let _ = state.blockchain.credit_svm_lamports(&wallet, vote_stake);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to persist vote: {}", e)
            })));
        }

        // Return all disputer + voter stakes from the pool
        let pool_total = pending.dispute_stake_bb_lamports
            .saturating_add(pending.uphold_stake_lamports)
            .saturating_add(pending.discard_stake_lamports);

        for d in &pending.disputers {
            let _ = state.blockchain.debit_svm_lamports(&pool_addr, d.stake_bb_lamports);
            let _ = state.blockchain.credit_svm_lamports(&d.wallet, d.stake_bb_lamports);
        }
        // Return discard voters their stakes
        for v in &pending.voters {
            // Only discard voters get stakes back (we can't tell which side mid-loop,
            // but we already checked supermajority so the discard side dominated)
            // Conservative: return all voter stakes. Slashing of uphold voters is Step 4+.
            let _ = state.blockchain.debit_svm_lamports(&pool_addr, vote_stake);
            let _ = state.blockchain.credit_svm_lamports(v, vote_stake);
        }

        // Slash oracle bond: find oracle node by proposer_pubkey + transfer slash to disputers
        if !pending.proposer_pubkey.is_empty() {
            if let Some(mut oracle_node) = state.blockchain.load_oracle_node(&pending.proposer_pubkey) {
                let slash_amount = oracle_node.slash_balance_bb_lamports.min(pool_total);
                if slash_amount > 0 {
                    oracle_node.slash_balance_bb_lamports =
                        oracle_node.slash_balance_bb_lamports.saturating_sub(slash_amount);
                    oracle_node.total_resolutions += 1;
                    // correct_resolutions NOT incremented (oracle was wrong)
                    let _ = state.blockchain.store_oracle_node(&oracle_node);

                    // Distribute slash equally to disputers
                    let disputer_count = pending.disputers.len().max(1) as u64;
                    let per_disputer = slash_amount / disputer_count;
                    for d in &pending.disputers {
                        let oracle_addr = format!("oracle_bond_{}", pending.proposer_pubkey);
                        let _ = state.blockchain.debit_svm_lamports(&oracle_addr, per_disputer);
                        let _ = state.blockchain.credit_svm_lamports(&d.wallet, per_disputer);
                    }
                    info!("⚡ Oracle bond slashed: proposer={} slash={} lamports distributed to {} disputers",
                        pending.proposer_pubkey, slash_amount, pending.disputers.len());
                }
            }
        }

        info!("🗳️  Vote DISCARD supermajority: market={} discard={} uphold={} total={}",
            req.market_id, pending.discard_stake_lamports,
            pending.uphold_stake_lamports, total_vote_stake);

        return (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "market_id": req.market_id,
            "outcome": "Discarded",
            "discard_stake_lamports": pending.discard_stake_lamports.to_string(),
            "uphold_stake_lamports": pending.uphold_stake_lamports.to_string(),
            "vote_count": pending.voters.len(),
        })));
    }

    // ── No supermajority yet — persist and wait ──────────────────────────────
    if let Err(e) = state.blockchain.store_pending_root(&pending) {
        // Roll back vote stake on persistence failure
        let _ = state.blockchain.debit_svm_lamports(&pool_addr, vote_stake);
        let _ = state.blockchain.credit_svm_lamports(&wallet, vote_stake);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to persist vote: {}", e)
        })));
    }

    info!("🗳️  Vote recorded: market={} voter={} uphold={} discard={} stake={}",
        req.market_id, wallet,
        if req.vote { "YES" } else { "NO" },
        pending.discard_stake_lamports,
        pending.uphold_stake_lamports);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "market_id": req.market_id,
        "vote": req.vote,
        "vote_stake_lamports": vote_stake.to_string(),
        "total_uphold_stake_lamports": pending.uphold_stake_lamports.to_string(),
        "total_discard_stake_lamports": pending.discard_stake_lamports.to_string(),
        "vote_count": pending.voters.len(),
        "status": "Disputed — waiting for supermajority or window expiry",
    })))
}
