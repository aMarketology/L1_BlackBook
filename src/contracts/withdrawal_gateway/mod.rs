use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use serde::Deserialize;
use tracing::{info, warn};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use crate::AppState;
use crate::storage::WithdrawalRecord;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// WITHDRAWAL GATEWAY SMART CONTRACT (Native Module)
// ============================================================================
//
// Handles the wUSDC → real USDC cashout lifecycle:
//
//   1. User calls POST /withdraw/request (Ed25519 signed)
//      → wUSDC burned from user's SVM account (transferred to dealer)
//      → WithdrawalRecord{status:"pending"} created in ReDB + DashMap
//      → Returns a withdrawal_id (UUID)
//
//   2. Dealer sees pending withdrawal, sends real USDC on Solana from
//      custody wallet to user's solana_destination address.
//
//   3. Dealer calls POST /admin/withdraw/release with:
//        { withdrawal_id, solana_tx_hash }
//      → Record updated to status:"released"
//      → Solana TX hash recorded for audit trail
//
// ============================================================================

// ── POST /withdraw/request ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WithdrawRequestBody {
    /// BB wallet address (base58) — must match public_key
    pub wallet_address: String,
    /// Solana wallet address (base58) where the dealer should send real USDC
    pub solana_destination: String,
    /// Amount of wUSDC to withdraw (must equal real USDC owed: 1 wUSDC = 1 real USDC)
    pub wusdc_amount: f64,
    /// Ed25519 public key (hex, 32 bytes) — must match wallet_address
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes) over message below
    pub signature: String,
    /// Unix timestamp for replay protection
    pub timestamp: u64,
    /// Unique nonce for replay protection
    pub nonce: String,
}

/// POST /withdraw/request — Burn user's wUSDC and create a withdrawal record.
///
/// The user burns their wUSDC on L1 by transferring it to the dealer.
/// The dealer is then obligated to send real USDC on Solana.
/// Message signed: "WITHDRAW_REQUEST:{wallet}:{solana_dest}:{amount}:{ts}:{nonce}"
pub async fn withdraw_request_handler(
    State(state): State<AppState>,
    Json(req): Json<WithdrawRequestBody>,
) -> impl IntoResponse {
    // ── Input validation ──────────────────────────────────────────────────
    if req.wallet_address.is_empty() || req.solana_destination.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "wallet_address and solana_destination are required"
        })));
    }
    if req.wusdc_amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "wusdc_amount must be greater than 0"
        })));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── Timestamp / replay protection ─────────────────────────────────────
    if now.saturating_sub(req.timestamp) > 120 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request timestamp too old (>120s)"
        })));
    }
    let nonce_key = format!("withdraw:{}:{}", req.wallet_address, req.nonce);
    // Atomic nonce check+insert via DashMap entry() — prevents TOCTOU race
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack"
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── Ed25519 signature verification ────────────────────────────────────
    let message = format!(
        "WITHDRAW_REQUEST:{}:{}:{:.6}:{}:{}",
        req.wallet_address, req.solana_destination,
        req.wusdc_amount, req.timestamp, req.nonce
    );
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid public_key (must be 32 bytes hex)"
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid signature (must be 64 bytes hex)"
        }))),
    };
    let pubkey_arr = match pubkey_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr = match sig_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature length" }))),
    };
    let signature = Signature::from_bytes(sig_arr);
    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // Confirm public key maps to the claimed wallet address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address",
            "derived": derived_address,
        })));
    }

    // ── Check dealer address is configured ───────────────────────────────
    if state.dealer_address.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Withdrawal gateway not configured (DEALER_PRIVATE_KEY missing)"
        })));
    }

    // ── Parse wallet pubkeys ──────────────────────────────────────────────
    let user_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid wallet_address (must be base58)"
        }))),
    };
    let dealer_pubkey = match Pubkey::from_str(&state.dealer_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Dealer address configuration error"
        }))),
    };

    // ── Check user wUSDC balance ──────────────────────────────────────────
    let mint = usdc_mint_bytes();
    let raw_required = (req.wusdc_amount * USDC_UNIT as f64) as u64;
    let user_wusdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &user_pubkey);
    if user_wusdc < raw_required {
        let user_balance_human = user_wusdc as f64 / USDC_UNIT as f64;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Insufficient wUSDC balance",
            "required": req.wusdc_amount,
            "available": user_balance_human,
        })));
    }

    // ── Transfer wUSDC from user to dealer (dealer holds as withdrawal obligation) ──
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &user_pubkey,
        &dealer_pubkey,
        raw_required,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("wUSDC burn failed: {}", e)
        })));
    }

    // ── Nonce consumed after funds are moved (prevents replay) ────────────

    // ── Create withdrawal record ──────────────────────────────────────────
    let withdrawal_id = uuid::Uuid::new_v4().to_string();
    let record = WithdrawalRecord {
        withdrawal_id: withdrawal_id.clone(),
        wallet_address: req.wallet_address.clone(),
        solana_destination: req.solana_destination.clone(),
        wusdc_amount: req.wusdc_amount,
        status: "pending".to_string(),
        requested_at: now,
        released_at: None,
        solana_tx_hash: None,
    };

    if let Err(e) = state.blockchain.store_withdrawal(&record) {
        tracing::error!("Failed to persist withdrawal record to ReDB: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to persist withdrawal record — transaction aborted"
        })));
    }
    state.withdrawal_requests.insert(withdrawal_id.clone(), record);

    info!("💸 WITHDRAWAL REQUEST: {:.6} wUSDC from {} → Solana {} (id: {})",
        req.wusdc_amount,
        &req.wallet_address[..8.min(req.wallet_address.len())],
        &req.solana_destination[..8.min(req.solana_destination.len())],
        &withdrawal_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "withdrawal_id": withdrawal_id,
        "status": "pending",
        "wallet_address": req.wallet_address,
        "solana_destination": req.solana_destination,
        "wusdc_burned": req.wusdc_amount,
        "message": "wUSDC burned. The dealer will send real USDC to your Solana address shortly.",
    })))
}

// ── GET /withdraw/status/:id ───────────────────────────────────────────────

/// GET /withdraw/status/:id — Check the status of a pending withdrawal.
pub async fn withdraw_status_handler(
    State(state): State<AppState>,
    Path(withdrawal_id): Path<String>,
) -> impl IntoResponse {
    if let Some(record) = state.withdrawal_requests.get(&withdrawal_id) {
        return Json(serde_json::json!({
            "found": true,
            "withdrawal_id": record.withdrawal_id,
            "wallet_address": record.wallet_address,
            "solana_destination": record.solana_destination,
            "wusdc_amount": record.wusdc_amount,
            "status": record.status,
            "requested_at": record.requested_at,
            "released_at": record.released_at,
            "solana_tx_hash": record.solana_tx_hash,
        }));
    }
    Json(serde_json::json!({
        "found": false,
        "error": "No withdrawal record found for this ID"
    }))
}

// ── POST /admin/withdraw/release ───────────────────────────────────────────

#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
pub struct WithdrawReleaseBody {
    /// The UUID returned by /withdraw/request
    pub withdrawal_id: String,
    /// Solana transaction hash proving the dealer sent real USDC to the user
    pub solana_tx_hash: String,
}

/// POST /admin/withdraw/release — Dealer marks a withdrawal as released.
///
/// Call this after sending real USDC on Solana to the user's destination address.
/// Records the Solana TX hash for the on-chain audit trail.
#[cfg(feature = "unsafe_admin")]
pub async fn withdraw_release_handler(
    State(state): State<AppState>,
    Json(req): Json<WithdrawReleaseBody>,
) -> impl IntoResponse {
    if req.withdrawal_id.is_empty() || req.solana_tx_hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "withdrawal_id and solana_tx_hash are required"
        })));
    }

    let record = match state.withdrawal_requests.get(&req.withdrawal_id) {
        Some(r) => r.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "No withdrawal record found for this ID"
        }))),
    };

    if record.status != "pending" {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": format!("Withdrawal is already '{}'", record.status)
        })));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── BURN wUSDC from dealer (zero-sum: real USDC leaves custody, wUSDC leaves supply) ─
    {
        let mint = usdc_mint_bytes();
        let raw_amount = (record.wusdc_amount * USDC_UNIT as f64) as u64;
        if let Ok(dealer_pubkey) = state.dealer_address.parse::<solana_sdk::pubkey::Pubkey>() {
            match crate::svm::SplTokenEngine::burn(
                &state.blockchain.svm_accounts,
                &mint,
                &dealer_pubkey,
                raw_amount,
            ) {
                Ok(_) => {
                    let _ = state.blockchain.svm_accounts.flush_block();
                    info!("🔥 Burned {:.6} wUSDC from dealer (withdrawal {})", record.wusdc_amount, &req.withdrawal_id[..8]);
                }
                Err(e) => warn!("⚠️  wUSDC burn on release failed — supply may be inflated: {:?}", e),
            }
        }
    }

    let mut updated = record.clone();
    updated.status = "released".to_string();
    updated.released_at = Some(now);
    updated.solana_tx_hash = Some(req.solana_tx_hash.clone());

    if let Err(e) = state.blockchain.store_withdrawal(&updated) {
        tracing::error!("Failed to persist withdrawal release to ReDB: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to persist withdrawal release — transaction aborted"
        })));
    }
    state.withdrawal_requests.insert(req.withdrawal_id.clone(), updated.clone());

    info!("✅ WITHDRAWAL RELEASED: {:.6} wUSDC → {} on Solana (tx: {}) (id: {})",
        record.wusdc_amount,
        &record.solana_destination[..8.min(record.solana_destination.len())],
        &req.solana_tx_hash[..16.min(req.solana_tx_hash.len())],
        &req.withdrawal_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "withdrawal_id": req.withdrawal_id,
        "status": "released",
        "wallet_address": record.wallet_address,
        "solana_destination": record.solana_destination,
        "wusdc_amount": record.wusdc_amount,
        "solana_tx_hash": req.solana_tx_hash,
        "released_at": now,
    })))
}
