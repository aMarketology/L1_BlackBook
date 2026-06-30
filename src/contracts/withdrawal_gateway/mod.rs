use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use serde::Deserialize;
use tracing::info;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use crate::AppState;
use crate::storage::WithdrawalRecord;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};
use crate::svm::spl_token::derive_ata_address;
use crate::svm::swap_pool_pda;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// WITHDRAWAL GATEWAY SMART CONTRACT (Native Module)
// ============================================================================
//
// Handles the wUSDT → real USDC cashout lifecycle:
//
//   1. User calls POST /withdraw/request (Ed25519 signed)
//      → wUSDT burned from user's SVM account (transferred to dealer)
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
    /// Amount of wUSDT to withdraw in micro-units (must equal real USDC owed)
    pub wusdt_amount_micro: u64,
    /// Ed25519 public key (hex, 32 bytes) — must match wallet_address
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes) over message below
    pub signature: String,
    /// Unix timestamp for replay protection
    pub timestamp: u64,
    /// Unique nonce for replay protection
    pub nonce: String,
}

/// POST /withdraw/request — Burn user's wUSDT and create a withdrawal record.
///
/// The user burns their wUSDT on L1 by transferring it to the dealer.
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
    if req.wusdt_amount_micro == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "wusdt_amount_micro must be greater than 0"
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
        "WITHDRAW_REQUEST:{}:{}:{}:{}:{}",
        req.wallet_address, req.solana_destination,
        req.wusdt_amount_micro, req.timestamp, req.nonce
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

    // ── Protocol reserve PDA (replaces legacy dealer address) ────────────

    // ── Rolling 24h withdrawal cap ────────────────────────────────────────
    // Prevents a compromised DEALER_PRIVATE_KEY from draining all wUSDT.
    // Cap is per 24h window, tracked atomically. 0 = unlimited.
    if state.withdrawal_daily_cap_micro > 0 {
        const WINDOW_SECS: u64 = 86_400; // 24 hours
        let window_start = state.withdrawal_window_start.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(window_start) >= WINDOW_SECS {
            // New window — reset counters atomically
            state.withdrawal_window_start.store(now, std::sync::atomic::Ordering::Relaxed);
            state.withdrawal_window_total.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        let current_total = state.withdrawal_window_total.load(std::sync::atomic::Ordering::Relaxed);
        let new_total = current_total.saturating_add(req.wusdt_amount_micro);
        if new_total > state.withdrawal_daily_cap_micro {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
                "error": "Withdrawal exceeds 24h rolling cap — retry tomorrow or contact support",
                "cap_wusdt": state.withdrawal_daily_cap_micro as f64 / 1_000_000.0,
                "used_wusdt": current_total as f64 / 1_000_000.0,
                "requested_wusdt": req.wusdt_amount_micro as f64 / 1_000_000.0,
            })));
        }
        // Reserve the amount (will be committed after successful transfer below)
        state.withdrawal_window_total.store(new_total, std::sync::atomic::Ordering::Relaxed);
    }

    // ── Parse wallet pubkeys ──────────────────────────────────────────────
    let user_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid wallet_address (must be base58)"
        }))),
    };
    let dealer_pubkey = swap_pool_pda();

    // ── Check user wUSDT balance ──────────────────────────────────────────
    let mint = usdc_mint_bytes();
    let raw_required = req.wusdt_amount_micro;
    let user_wusdt = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &user_pubkey);
    if user_wusdt < raw_required {
        let user_balance_human = user_wusdt as f64 / USDC_UNIT as f64;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Insufficient wUSDT balance",
            "required": req.wusdt_amount_micro as f64 / USDC_UNIT as f64,
            "available": user_balance_human,
        })));
    }

    // ── Transfer wUSDT from user to dealer (dealer holds as withdrawal obligation) ──
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &user_pubkey,
        &dealer_pubkey,
        raw_required,
    ) {
        // Refund the cap reservation since the transfer failed
        if state.withdrawal_daily_cap_micro > 0 {
            state.withdrawal_window_total.fetch_sub(req.wusdt_amount_micro, std::sync::atomic::Ordering::Relaxed);
        }
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("wUSDT burn failed: {}", e)
        })));
    }

    // ── Nonce consumed after funds are moved (prevents replay) ────────────

    // ── ATOMIC: flush both ATAs to ReDB + write withdrawal record in one txn ──
    // Prevents the double-payment window where the withdrawal record lands in ReDB
    // (dealer sends USDC) but the wUSDT debit is absent after a crash, leaving
    // the user with both the USDC payout and the original wUSDT on restart.
    let user_ata_key   = Pubkey::new_from_array(derive_ata_address(&user_pubkey.to_bytes(),   &mint));
    let dealer_ata_key = Pubkey::new_from_array(derive_ata_address(&dealer_pubkey.to_bytes(), &mint));

    let withdrawal_id = uuid::Uuid::new_v4().to_string();
    let mut record = WithdrawalRecord {
        withdrawal_id: withdrawal_id.clone(),
        withdrawal_seq: 0, // assigned atomically inside atomic_withdrawal_flush_and_record
        wallet_address: req.wallet_address.clone(),
        solana_destination: req.solana_destination.clone(),
        wusdt_amount_micro: req.wusdt_amount_micro,
        status: "pending".to_string(),
        requested_at: now,
        released_at: None,
        solana_tx_hash: None,
    };

    let assigned_seq = match state.blockchain.atomic_withdrawal_flush_and_record(
        &user_ata_key, &dealer_ata_key, &record,
    ) {
        Ok(seq) => seq,
        Err(e) => {
            tracing::error!("Atomic withdrawal commit failed: {}", e);
            // Rollback the SPL transfer — best effort
            let _ = SplTokenEngine::transfer_tokens(
                &state.blockchain.svm_accounts, &mint, &dealer_pubkey, &user_pubkey, raw_required,
            );
            if state.withdrawal_daily_cap_micro > 0 {
                state.withdrawal_window_total.fetch_sub(req.wusdt_amount_micro, std::sync::atomic::Ordering::Relaxed);
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to commit withdrawal to disk — transaction aborted"
            })));
        }
    };
    // Stamp the seq into the hot-cache record so in-memory queries reflect it.
    record.withdrawal_seq = assigned_seq;
    state.withdrawal_seq_counter.store(assigned_seq + 1, std::sync::atomic::Ordering::Relaxed);
    state.withdrawal_requests.insert(withdrawal_id.clone(), record);

    info!("💸 WITHDRAWAL REQUEST: {:.6} wUSDT from {} → Solana {} (seq={}, id: {})",
        req.wusdt_amount_micro as f64 / USDC_UNIT as f64,
        &req.wallet_address[..8.min(req.wallet_address.len())],
        &req.solana_destination[..8.min(req.solana_destination.len())],
        assigned_seq,
        &withdrawal_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "withdrawal_id": withdrawal_id,
        "status": "pending",
        "wallet_address": req.wallet_address,
        "solana_destination": req.solana_destination,
        "wusdt_burned": req.wusdt_amount_micro as f64 / USDC_UNIT as f64,
        "message": "wUSDT burned. The dealer will send real USDC to your Solana address shortly.",
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
            "wusdt_amount": record.wusdt_amount_micro as f64 / USDC_UNIT as f64,
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

    // ── BURN wUSDT from protocol reserve (zero-sum: real USDC leaves custody, wUSDT leaves supply) ─
    {
        let mint = usdc_mint_bytes();
        let raw_amount = record.wusdt_amount_micro;
        let dealer_pubkey = swap_pool_pda();
        match crate::svm::SplTokenEngine::burn(
            &state.blockchain.svm_accounts,
            &mint,
            &dealer_pubkey,
            raw_amount,
        ) {
            Ok(_) => {
                let _ = state.blockchain.svm_accounts.flush_block();
                info!("🔥 Burned {:.6} wUSDT from protocol reserve (withdrawal {})", record.wusdt_amount_micro as f64 / USDC_UNIT as f64, &req.withdrawal_id[..8]);
            }
            Err(e) => tracing::warn!("⚠️  wUSDT burn on release failed — supply may be inflated: {:?}", e),
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

    info!("✅ WITHDRAWAL RELEASED: {:.6} wUSDT → {} on Solana (tx: {}) (id: {})",
        record.wusdt_amount_micro as f64 / USDC_UNIT as f64,
        &record.solana_destination[..8.min(record.solana_destination.len())],
        &req.solana_tx_hash[..16.min(req.solana_tx_hash.len())],
        &req.withdrawal_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "withdrawal_id": req.withdrawal_id,
        "status": "released",
        "wallet_address": record.wallet_address,
        "solana_destination": record.solana_destination,
        "wusdt_amount": record.wusdt_amount_micro as f64 / USDC_UNIT as f64,
        "solana_tx_hash": req.solana_tx_hash,
        "released_at": now,
    })))
}
