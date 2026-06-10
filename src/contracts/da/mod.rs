// ============================================================================
// DATA AVAILABILITY (DA) LAYER — L1 endpoints
// ============================================================================
//
// BlackBook L1 is the *vault and settlement layer*, not a data store.
// It holds only:
//   1. A 32-byte state root per finalized market  (ESCROW_MARKET_ROOTS)
//   2. A double-claim guard per (market_id, address) (ESCROW_CLAIMS)
//
// The full ledger of winners, payouts, and proofs lives on the L2 sequencer.
// Users query L2 for their proof, then submit it here for on-chain settlement.
//
// ── Endpoints ────────────────────────────────────────────────────────────────
//
//   GET  /da/:market_id
//     Returns the Oracle-finalized state root + status for a market.
//     L2 state (DA receipt) is NOT stored here — only the 32-byte root.
//
//   GET  /da/:market_id/pool
//     Returns the dealer's rollup vault $BB balance (house bankroll liquidity).
//
//   POST /da/claim
//     Relayer path: user submits their Merkle proof + Ed25519 wallet sig.
//     L1 verifies proof against ESCROW_MARKET_ROOTS[market_id], checks the
//     double-claim guard, then releases from the per-rollup vault PDA → user.
//
// ── Merkle leaf format (must match L2 sequencer EXACTLY) ─────────────────────
//
//   BB leaf preimage:  "{rollup_id}:BB:{address_lowercased}:{balance_lamports}"
//   Combine two nodes: SHA256( min(a,b) || max(a,b) )  ← lexicographic on hex strings
//
// ── Signed claim message ─────────────────────────────────────────────────────
//
//   "DA_CLAIM:{rollup_id}:{market_id}:{wallet_address}:{balance_lamports}:{timestamp}:{nonce}"
//
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::AppState;
use crate::svm::pda::rollup_vault_address;
// Re-use the Borsh leaf hash helpers from the rollup module so the DA claim
// path is guaranteed to produce the identical leaf as the rollup exit path.
use crate::contracts::rollup::bb_leaf_hash;

// ── Leaf + proof helpers (identical to rollup/mod.rs) ────────────────────────

fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    format!("{:x}", h.finalize())
}

/// Sorted-pair combine: SHA256( min(a,b) || max(a,b) ) over hex strings.
/// Matches the TypeScript `hashPair` in sequencer/shared/src/merkle.ts.
fn hash_pair(a: &str, b: &str) -> String {
    if a <= b {
        sha256_hex(&format!("{}{}", a, b))
    } else {
        sha256_hex(&format!("{}{}", b, a))
    }
}

/// Walk the Merkle proof and return the computed root hex.
/// `siblings` are 64-char lowercase hex digests; `is_right[i]` tells whether
/// siblings[i] is the RIGHT child (true) or LEFT child (false) at that level.
fn verify_merkle_proof(leaf_hash: &str, siblings: &[String], is_right: &[bool]) -> String {
    let mut current = leaf_hash.to_string();
    for (i, sibling) in siblings.iter().enumerate() {
        let sib_right = is_right.get(i).copied().unwrap_or(false);
        current = if sib_right {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
    }
    current
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /da/:market_id  — Oracle-finalized state for a market
// ─────────────────────────────────────────────────────────────────────────────
//
// Returns:
//   { market_id, status, merkle_root_hex, outcome, finalized_at_slot,
//     dispute_window_slots, note }
//
// `status` values:
//   "Pending"   — submitted, dispute window open
//   "Disputed"  — challenged, governance vote in progress
//   "Finalized" — dispute window closed, state root usable for claims
//   "Discarded" — governance voted to discard, root is invalid
//   "Unknown"   — no record found
//
// The actual per-winner ledger (DA receipt) is NOT stored on L1.
// Query the L2 sequencer at GET /da/:market_id for the full receipt.

pub async fn get_da_market_handler(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    use crate::storage::PendingRootStatus;

    if market_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "market_id is required" })),
        );
    }

    // ── PENDING_ROOTS is the authoritative path (Oracle-attested) ────────────
    if let Some(root) = state.blockchain.load_pending_root(&market_id) {
        let status_str = match &root.status {
            PendingRootStatus::Pending => "Pending",
            PendingRootStatus::Disputed => "Disputed",
            PendingRootStatus::Finalized => "Finalized",
            PendingRootStatus::Discarded => "Discarded",
        };
        let claimable = matches!(root.status, PendingRootStatus::Finalized);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "market_id": market_id,
                "rollup_id": root.rollup_id,
                "status": status_str,
                "claimable": claimable,
                "merkle_root_hex": hex::encode(root.merkle_root),
                "outcome": root.outcome,
                "batch_id": root.batch_id,
                "proposed_at_slot": root.proposed_at_slot,
                "finalize_at_slot": root.finalize_at_slot,
                "dispute_window_slots": root.finalize_at_slot.saturating_sub(root.proposed_at_slot),
                "proposer_pubkey": root.proposer_pubkey,
                "note": "Full DA receipt (winner list + proofs) available on the L2 sequencer."
            })),
        );
    }

    // ── Fall back: finalized via legacy ESCROW_MARKET_ROOTS ──────────────────
    if let Ok(Some(root_bytes)) = state.blockchain.get_escrow_market_root(&market_id) {
        if !root_bytes.is_empty() {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "market_id": market_id,
                    "status": "Finalized",
                    "claimable": true,
                    "merkle_root_hex": hex::encode(&root_bytes),
                    "note": "Finalized via legacy escrow path — no Oracle dispute record."
                })),
            );
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "market_id": market_id,
            "status": "Unknown",
            "claimable": false,
        })),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /da/:rollup_id/pool  — Dealer vault balance (house bankroll on L1)
// ─────────────────────────────────────────────────────────────────────────────
//
// Returns the $BB balance locked in the per-rollup vault PDA.
// This is the Dealer's on-chain liquidity that backs all active markets.

pub async fn get_da_pool_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
) -> impl IntoResponse {
    use crate::svm::types::LAMPORTS_PER_BB;

    let vault_address = rollup_vault_address(&rollup_id);
    let lamports = state.blockchain.get_balance_lamports(&vault_address);
    let bb = lamports as f64 / LAMPORTS_PER_BB as f64;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "rollup_id": rollup_id,
            "vault_address": vault_address,
            "balance_lamports": lamports,
            "balance_bb": bb,
        })),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /da/claim  — Relayer: Merkle proof → release from rollup vault → user
// ─────────────────────────────────────────────────────────────────────────────
//
// Request body:
//   {
//     "rollup_id":        "L2",
//     "market_id":        "market_btc_42",
//     "wallet_address":   "<base58>",
//     "balance_lamports": 500000,            ← must match the leaf exactly
//     "proof_siblings":   ["<hex>", ...],    ← from L2 GET /da/:id/claim/:addr
//     "sibling_is_right": [false, true, ...],
//     "public_key":       "<64-char hex>",
//     "signature":        "<128-char hex>",
//     "timestamp":        1234567890,
//     "nonce":            "<random hex>"
//   }
//
// Canonical signed message:
//   "DA_CLAIM:{rollup_id}:{market_id}:{wallet_address}:{balance_lamports}:{timestamp}:{nonce}"
//
// L1 verifies:
//   1. Ed25519 signature (proves wallet ownership)
//   2. Timestamp freshness (±60 s)
//   3. Nonce replay protection
//   4. Market is Finalized (ESCROW_MARKET_ROOTS exists)
//   5. Merkle proof: leaf preimage "{rollup_id}:BB:{addr_lower}:{lamports}" ∈ root
//   6. Double-claim guard: ESCROW_CLAIMS["{market_id}:{address}"] not set
//   7. Vault has sufficient balance
//
// On success: rollup vault PDA → user wallet, seal claim in ESCROW_CLAIMS.

#[derive(serde::Deserialize)]
pub struct DaClaimRequest {
    /// "L2", "L3", or "L5"
    pub rollup_id: String,
    /// Oracle-finalized market identifier
    pub market_id: String,
    /// L1 wallet address receiving the payout
    pub wallet_address: String,
    /// Exact $BB lamports from the Merkle leaf (must match leaf precisely)
    pub balance_lamports: u64,
    /// Merkle proof sibling hashes (64-char lowercase hex), leaf→root
    pub proof_siblings: Vec<String>,
    /// true = sibling is the right child at that level
    pub sibling_is_right: Vec<bool>,
    /// Ed25519 public key (64-char hex, 32 bytes)
    pub public_key: String,
    /// Ed25519 signature (128-char hex, 64 bytes)
    pub signature: String,
    /// Unix timestamp (seconds)
    pub timestamp: u64,
    /// Random replay-protection nonce
    pub nonce: String,
}

pub async fn da_claim_handler(
    State(state): State<AppState>,
    Json(req): Json<DaClaimRequest>,
) -> impl IntoResponse {
    // ── Input guards ──────────────────────────────────────────────────────────
    if req.rollup_id.is_empty()
        || req.market_id.is_empty()
        || req.wallet_address.is_empty()
        || req.balance_lamports == 0
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "rollup_id, market_id, wallet_address, and balance_lamports are required" })),
        );
    }
    if !["L2", "L3", "L5"].contains(&req.rollup_id.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "rollup_id must be L2, L3, or L5" })),
        );
    }

    // ── Timestamp freshness (±60 s) ───────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Timestamp outside ±60 s freshness window" })),
        );
    }

    // ── Ed25519 signature verification ────────────────────────────────────────
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "public_key must be 64 hex chars (32 bytes)" })),
            )
        }
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "signature must be 128 hex chars (64 bytes)" })),
            )
        }
    };
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid Ed25519 public key" })),
            )
        }
    };
    let sig = Signature::from_bytes(&sig_arr);
    let message = format!(
        "DA_CLAIM:{}:{}:{}:{}:{}:{}",
        req.rollup_id,
        req.market_id,
        req.wallet_address,
        req.balance_lamports,
        req.timestamp,
        req.nonce
    );
    if vk.verify(message.as_bytes(), &sig).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid Ed25519 signature" })),
        );
    }

    // ── Nonce replay protection ───────────────────────────────────────────────
    let nonce_key = format!("da_claim:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "Duplicate nonce — possible replay attack" })),
            );
        }
        dashmap::mapref::entry::Entry::Vacant(e) => {
            e.insert(req.timestamp);
        }
    }

    // ── Double-claim guard ────────────────────────────────────────────────────
    let claim_key = format!("{}:{}", req.market_id, req.wallet_address);
    if state.withdrawal_claims.contains_key(&claim_key) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Already claimed for this market",
                "market_id": req.market_id,
                "wallet_address": req.wallet_address,
            })),
        );
    }

    // ── Look up the finalized Oracle state root for this market ───────────────
    // Priority: PENDING_ROOTS (Oracle path) → ESCROW_MARKET_ROOTS (legacy path)
    let expected_root_hex: String = {
        use crate::storage::PendingRootStatus;
        if let Some(pending) = state.blockchain.load_pending_root(&req.market_id) {
            if !matches!(pending.status, PendingRootStatus::Finalized) {
                let status = match &pending.status {
                    PendingRootStatus::Pending => "Pending",
                    PendingRootStatus::Disputed => "Disputed",
                    PendingRootStatus::Discarded => "Discarded",
                    PendingRootStatus::Finalized => "Finalized",
                };
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "Market is not yet finalized — dispute window is still open",
                        "status": status,
                        "finalize_at_slot": pending.finalize_at_slot,
                    })),
                );
            }
            hex::encode(pending.merkle_root)
        } else {
            match state.blockchain.get_escrow_market_root(&req.market_id) {
                Ok(Some(bytes)) if !bytes.is_empty() => hex::encode(&bytes),
                _ => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({
                            "error": "No finalized state root found for this market",
                            "market_id": req.market_id,
                        })),
                    )
                }
            }
        }
    };

    // ── Decode wallet address bytes (base58 → [u8;32]) ──────────────────────
    let addr_bytes: [u8; 32] = match bs58::decode(&req.wallet_address).into_vec() {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "wallet_address must be a base58-encoded 32-byte Ed25519 public key" })),
        ),
    };

    // ── Merkle proof verification ───────────────────────────────────────────────
    // leaf_hash = SHA-256( borsh(BbClaimLeaf { rollup_id, "BB", address[32], lamports }) )
    // This is the Borsh-canonical format — identical to the leaf the L2 sequencer
    // builds in merkle.ts buildLeafBytes() / serializeBbLeaf().
    let leaf_hash = bb_leaf_hash(&req.rollup_id, addr_bytes, req.balance_lamports);
    let computed_root = verify_merkle_proof(&leaf_hash, &req.proof_siblings, &req.sibling_is_right);

    if computed_root != expected_root_hex {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Merkle proof verification failed — computed root does not match finalized state root",
                "computed_root": computed_root,
                "expected_root": expected_root_hex,
            })),
        );
    }

    // ── Vault solvency check ──────────────────────────────────────────────────
    let vault_address = rollup_vault_address(&req.rollup_id);
    let vault_balance = state.blockchain.get_balance_lamports(&vault_address);
    if vault_balance < req.balance_lamports {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "error": "Rollup vault has insufficient balance to cover this claim",
                "vault_balance_lamports": vault_balance,
                "claim_lamports": req.balance_lamports,
                "vault_address": vault_address,
            })),
        );
    }

    // ── Atomic: debit vault → credit user + seal claim in ESCROW_CLAIMS ──────
    if let Err(e) = state.blockchain.atomic_escrow_claim_and_pay(
        &claim_key,
        &vault_address,
        &req.wallet_address,
        req.balance_lamports,
        now,
    ) {
        tracing::error!("DA claim atomic write failed: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Claim aborted — storage error: {}", e) })),
        );
    }

    // ── Update in-memory claim guard (ReDB is already sealed above) ──────────
    state.withdrawal_claims.insert(claim_key.clone(), true);

    let new_balance = state.blockchain.get_balance_lamports(&req.wallet_address);
    let new_balance_bb = new_balance as f64 / 100_000.0;

    info!(
        "💸 DA CLAIM: {} lamports from {} vault → {} (market: {}, merkle root: {})",
        req.balance_lamports, req.rollup_id, req.wallet_address, req.market_id, &expected_root_hex[..16]
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "rollup_id": req.rollup_id,
            "market_id": req.market_id,
            "wallet_address": req.wallet_address,
            "released_lamports": req.balance_lamports,
            "released_bb": req.balance_lamports as f64 / 100_000.0,
            "new_balance_bb": new_balance_bb,
            "state_root": expected_root_hex,
        })),
    )
}
