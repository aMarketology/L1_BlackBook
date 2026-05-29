use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::Deserialize;
use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use tracing::{info, warn};

use crate::AppState;
use crate::storage::DepositRecord;

// ============================================================================
// DEPOSIT GATEWAY SMART CONTRACT (Native Module)
// ============================================================================
//
// Flow:
//   1. User sends wUSDT or wUSDT to the custody wallet (off-chain, one key)
//   2. User calls POST /deposit/request with:
//        - their BB wallet address
//        - the external tx hash proving the on-chain transfer
//        - the stablecoin amount
//        - an Ed25519 signature proving they own the BB wallet
//   3. Dealer calls POST /admin/deposit/approve with the tx hash
//        - L1 mints BB at the fixed 10:1 ratio (1 USDC = 10 BB — $0.10/BB)
//        - The external tx hash is permanently recorded as processed
//          (double-mint protection via PROCESSED_BRIDGE_TXS table)
//
// Rate: 1 USDC/USDT = 1 BB  (BB is a 1:1 USD stablecoin)
//
// This module is intentionally minimal. Future upgrades:
//   - Oracle verification of the external tx (on-chain proof)
//   - Automatic approval via relayer
//   - Support for multiple custody wallets / asset types
// ============================================================================

// ── Request types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DepositRequestBody {
    /// BB wallet address (base58) where minted tokens will land
    pub wallet_address: String,
    /// Transaction hash from the external chain (unique key, replay prevention)
    pub external_tx_hash: String,
    /// "USDC" or "USDT"
    pub asset: String,
    /// Amount of stablecoin sent to the custody wallet (in 6-decimal micro-units)
    pub amount_micro_stablecoin: u64,
    /// Ed25519 public key (hex, 32 bytes) matching wallet_address
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes)
    /// Signs: "DEPOSIT_REQUEST:{wallet_address}:{external_tx_hash}:{amount_micro_stablecoin}:{asset}:{timestamp}:{nonce}"
    pub signature: String,
    /// Unix timestamp (must be within 60s of server time)
    pub timestamp: u64,
    /// Random nonce for replay protection
    pub nonce: String,
}

#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
pub struct DepositApproveBody {
    /// The external_tx_hash from the DepositRecord to approve
    pub external_tx_hash: String,
}

// ── POST /deposit/request ─────────────────────────────────────────────────

/// POST /deposit/request — User submits a wUSDT/wUSDT → BB deposit request.
///
/// The user proves ownership of their BB wallet via Ed25519 signature.
/// The dealer will verify the external tx and call /admin/deposit/approve.
pub async fn deposit_request_handler(
    State(state): State<AppState>,
    Json(req): Json<DepositRequestBody>,
) -> impl IntoResponse {
    // ── BASIC VALIDATION ──────────────────────────────────────────────────
    if state.custody_wallet_address.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Deposit gateway not configured (CUSTODY_WALLET_ADDRESS not set)"
        })));
    }

    if req.wallet_address.is_empty() || req.external_tx_hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing required fields" })));
    }
    if req.amount_micro_stablecoin == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "amount_micro_stablecoin must be > 0" })));
    }
    if req.asset != "USDC" && req.asset != "USDT" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "asset must be 'USDC' or 'USDT'" })));
    }

    // ── ADDRESS FORMAT VALIDATION ─────────────────────────────────────────
    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid wallet_address. Must be a base58 Solana-style address, not an 0x EVM address."
        })));
    }

    // ── REPLAY PROTECTION (nonce) ─────────────────────────────────────────
    let nonce_key = format!("deposit_request:{}:{}", req.wallet_address, req.nonce);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request too old (>60s)"
        })));
    }
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

    // ── ALREADY PROCESSED? (durable ReDB check) ────────────────────────────
    // Note: the "pending" duplicate check is enforced atomically below via
    // entry() — no separate contains_key needed here.
    if state.blockchain.is_bridge_tx_processed(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This external_tx_hash has already been minted. Possible double-submission."
        })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION ───────────────────────────────────
    let message = format!(
        "DEPOSIT_REQUEST:{}:{}:{}:{}:{}:{}",
        req.wallet_address, req.external_tx_hash,
        req.amount_micro_stablecoin, req.asset,
        req.timestamp, req.nonce
    );
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public_key (must be 32 bytes hex)" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" }))),
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

    // Confirm the public key matches the claimed wallet address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address",
            "derived": derived_address,
        })));
    }

    // ── CREATE RECORD ─────────────────────────────────────────────────────
    // Use u64 directly from API boundary
    let amount_micro_stablecoin = req.amount_micro_stablecoin;
    let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(amount_micro_stablecoin);
    let record = DepositRecord {
        wallet_address: req.wallet_address.clone(),
        external_tx_hash: req.external_tx_hash.clone(),
        asset: req.asset.clone(),
        amount_micro_stablecoin,
        bb_lamports,
        status: "pending".to_string(),
        submitted_at: now,
        approved_at: None,
        contest_id: None,
    };

    // Atomically claim the request slot — single entry() call eliminates
    // TOCTOU between check and insert when concurrent requests share a tx_hash.
    match state.deposit_requests.entry(req.external_tx_hash.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "A deposit request for this tx hash already exists. Check /deposit/status/:tx_hash"
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            if let Err(e) = state.blockchain.store_deposit_request(&record) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Storage error: {}", e) })));
            }
            slot.insert(record.clone());
        }
    }

    info!("📥 DEPOSIT REQUEST: {:.6} {} → {:.5} BB for {} (tx: {})",
        req.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64, req.asset,
        bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        &req.wallet_address[..8.min(req.wallet_address.len())],
        &req.external_tx_hash[..12.min(req.external_tx_hash.len())]);

    // ── IMMEDIATE ON-CHAIN VERIFICATION ──────────────────────────────────────
    // Route to the correct chain verifier based on tx hash format:
    //   0x…  → BSC (EVM receipt verification)
    //   else → Solana (getTransaction verification)
    let is_bsc_tx = req.external_tx_hash.starts_with("0x") || req.external_tx_hash.starts_with("0X");

    if is_bsc_tx {
        if let Some(ref bsc_watcher) = state.bsc_watcher {
            match bsc_watcher.verify_and_approve(&req.external_tx_hash).await {
                Ok(bb_minted) => {
                    let new_balance = state.blockchain.get_balance(&req.wallet_address);
                    return (StatusCode::OK, Json(serde_json::json!({
                        "success": true,
                        "status": "approved",
                        "chain": "bsc",
                        "message": "BSC deposit verified on-chain and approved instantly.",
                        "wallet_address": req.wallet_address,
                        "external_tx_hash": req.external_tx_hash,
                        "asset": req.asset,
                        "amount_stablecoin": req.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
                        "bb_minted": bb_minted,
                        "new_balance": new_balance,
                    })));
                }
                Err(e) => {
                    info!("💡 BSC auto-verify deferred ({}): {}",
                        &req.external_tx_hash[..12.min(req.external_tx_hash.len())], e);
                }
            }
        }
    } else if let Some(ref watcher) = state.custody_watcher {
        match watcher.verify_and_approve(&req.external_tx_hash).await {
            Ok(bb_minted) => {
                let new_balance = state.blockchain.get_balance(&req.wallet_address);
                return (StatusCode::OK, Json(serde_json::json!({
                    "success": true,
                    "status": "approved",
                    "message": "Deposit verified on-chain and approved instantly.",
                    "wallet_address": req.wallet_address,
                    "external_tx_hash": req.external_tx_hash,
                    "asset": req.asset,
                    "amount_stablecoin": req.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
                    "bb_minted": bb_minted,
                    "new_balance": new_balance,
                    "custody_wallet": state.custody_wallet_address,
                })));
            }
            Err(e) => {
                // Not yet finalized, wrong amounts, or RPC unavailable.
                // The watcher background task will re-attempt on the next poll.
                info!("💡 Auto-verify deferred ({}): {}",
                    &req.external_tx_hash[..12.min(req.external_tx_hash.len())], e);
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "status": "pending",
        "wallet_address": record.wallet_address,
        "external_tx_hash": record.external_tx_hash,
        "asset": record.asset,
        "amount_stablecoin": record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
        "bb_to_mint": record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        "custody_wallet": state.custody_wallet_address,
        "message": "Request received. The dealer will verify your deposit and mint BB shortly."
    })))
}

// ── GET /deposit/status/:tx_hash ──────────────────────────────────────────

/// GET /deposit/status/:tx_hash — Check the status of a pending deposit request.
pub async fn deposit_status_handler(
    State(state): State<AppState>,
    Path(tx_hash): Path<String>,
) -> impl IntoResponse {
    // Check hot DashMap first
    if let Some(record) = state.deposit_requests.get(&tx_hash) {
        return Json(serde_json::json!({
            "found": true,
            "external_tx_hash": record.external_tx_hash,
            "wallet_address": record.wallet_address,
            "asset": record.asset,
            "amount_stablecoin": record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
            "bb_to_mint": record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
            "status": record.status,
            "submitted_at": record.submitted_at,
            "approved_at": record.approved_at,
        }));
    }
    // Fallback: check if it was processed before this node started
    if state.blockchain.is_bridge_tx_processed(&tx_hash) {
        return Json(serde_json::json!({
            "found": true,
            "external_tx_hash": tx_hash,
            "status": "approved",
            "note": "Approved prior to current session. Full record not in memory."
        }));
    }
    Json(serde_json::json!({
        "found": false,
        "status": "pending",
        "external_tx_hash": tx_hash,
        "note": "No deposit request found yet — it may still be processing."
    }))
}

// ── POST /admin/deposit/approve ───────────────────────────────────────────

/// POST /admin/deposit/approve — Dealer approves a pending deposit, mints BB.
///
/// The dealer must verify the external tx off-chain (confirm the user actually
/// sent the stablecoin to the custody wallet) before calling this.
///
/// Double-mint protection: the external_tx_hash is permanently recorded in the
/// PROCESSED_BRIDGE_TXS table — approving the same hash a second time fails.
#[cfg(feature = "unsafe_admin")]
pub async fn deposit_approve_handler(
    State(state): State<AppState>,
    Json(req): Json<DepositApproveBody>,
) -> impl IntoResponse {
    if req.external_tx_hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "external_tx_hash required" })));
    }

    // ── DOUBLE-MINT PROTECTION ────────────────────────────────────────────
    if state.blockchain.is_bridge_tx_processed(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This tx hash has already been minted — double-mint blocked."
        })));
    }

    // ── FIND THE PENDING REQUEST ──────────────────────────────────────────
    let record = match state.deposit_requests.get(&req.external_tx_hash) {
        Some(r) => r.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "No pending deposit request found for this tx hash. User must call /deposit/request first."
        }))),
    };

    if record.status != "pending" {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": format!("Deposit is already '{}'", record.status)
        })));
    }

    // ── MINT BB (Bug #2: reserve-before-mint, no TOCTOU race) ──────────────
    let mint_tx_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = state.blockchain.reserve_bridge_tx(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": format!("Double-mint blocked: {}", e)
        })));
    }
    match state.blockchain.credit_lamports(&record.wallet_address, record.bb_lamports) {
        Ok(_) => {
            if let Err(e) = state.blockchain.commit_bridge_tx(&req.external_tx_hash, &mint_tx_id) {
                warn!("⚠️  Failed to persist bridge tx committed flag: {}", e);
            }
        }
        Err(e) => {
            state.blockchain.cancel_bridge_tx(&req.external_tx_hash);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB mint failed: {}", e) })));
        }
    }
    let new_balance = state.blockchain.get_balance(&record.wallet_address);

    // ── UPDATE RECORD ─────────────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut updated = record.clone();
    updated.status = "approved".to_string();
    updated.approved_at = Some(now);

    if let Err(e) = state.blockchain.store_deposit_request(&updated) {
        tracing::error!("Failed to persist deposit approval to ReDB: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to persist deposit approval — transaction aborted"
        })));
    }
    state.deposit_requests.insert(req.external_tx_hash.clone(), updated.clone());

    // ── RECORD IN POH BLOCK ───────────────────────────────────────────────
    {
        use crate::protocol::Transaction as ProtoTx;
        use crate::protocol::TxData;
        let tx = ProtoTx {
            hash: mint_tx_id.clone(),
            from: "DEPOSIT_GATEWAY".to_string(),
            timestamp: now,
            data: TxData::DepositUsdt {
                usdt_amount: record.amount_micro_stablecoin,
                external_tx_hash: Some(req.external_tx_hash.clone()),
            },
            signature: "dealer_approved".to_string(),
            signer_pubkey: "DEALER".to_string(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    // ── CREATE VISUAL LEDGER RECEIPT ─────────────────────────────────────
    let new_balance_micro = (new_balance * crate::svm::LAMPORTS_PER_BB as f64).round() as u64;
    let tx_record = crate::storage::TransactionRecord::with_id(
        mint_tx_id.clone(),
        crate::storage::TxType::BridgeIn,
        "DEPOSIT_GATEWAY",
        &record.wallet_address,
        record.amount_micro_stablecoin,
        0,                // nonce
        0u64,             // from_balance_before
        0u64,             // from_balance_after
        new_balance_micro, // to_balance_after
        crate::storage::AuthType::SystemInternal,
    );
    if let Err(e) = state.blockchain.log_transaction(tx_record) {
        warn!("⚠️ Failed to log transaction receipt for deposit: {}", e);
    }

    info!("✅ DEPOSIT APPROVED: {:.6} {} → {:.5} BB → {} (ext_tx: {})",
        record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
        record.asset,
        record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        &record.wallet_address[..8.min(record.wallet_address.len())],
        &req.external_tx_hash[..12.min(req.external_tx_hash.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "external_tx_hash": req.external_tx_hash,
        "wallet_address": record.wallet_address,
        "asset": record.asset,
        "amount_stablecoin": record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
        "bb_minted": record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        "new_balance": new_balance,
        "mint_tx_id": mint_tx_id,
    })))
}

// ── POST /deposit/claim ────────────────────────────────────────────────────

/// Request body for claiming an unattributed deposit.
#[derive(Deserialize)]
pub struct ClaimDepositBody {
    /// BB wallet address (base58) to receive the minted BB
    pub wallet_address: String,
    /// The on-chain tx hash of the unattributed deposit
    pub external_tx_hash: String,
    /// Ed25519 public key (hex, 32 bytes) matching wallet_address
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes)
    /// Signs: "CLAIM_DEPOSIT:{wallet_address}:{external_tx_hash}:{timestamp}:{nonce}"
    pub signature: String,
    /// Unix timestamp (must be within 60s of server time)
    pub timestamp: u64,
    /// Random nonce for replay protection
    pub nonce: String,
}

/// POST /deposit/claim — Claim an unattributed deposit by proving wallet ownership.
///
/// Called by users who sent stablecoin directly to the custody wallet without
/// calling /deposit/request first. The watcher queued their deposit as
/// "unattributed"; this endpoint lets them prove ownership and receive BB.
pub async fn deposit_claim_handler(
    State(state): State<AppState>,
    Json(req): Json<ClaimDepositBody>,
) -> impl IntoResponse {
    if req.wallet_address.is_empty() || req.external_tx_hash.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing required fields" })));
    }

    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid wallet_address. Must be a base58 address."
        })));
    }

    // ── Timestamp freshness ───────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Request too old (>60s)" })));
    }

    // ── Nonce / replay protection ─────────────────────────────────────────
    let nonce_key = format!("deposit_claim:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => { v.insert(now); }
    }

    // ── Ed25519 signature verification ─────────────────────────────────────
    let message = format!(
        "CLAIM_DEPOSIT:{}:{}:{}:{}",
        req.wallet_address, req.external_tx_hash, req.timestamp, req.nonce
    );
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public_key" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature" }))),
    };
    let pubkey_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad pubkey length" }))),
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad sig length" }))),
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig_arr);
    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }
    let derived = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address"
        })));
    }

    // ── Look up the unattributed deposit ──────────────────────────────────
    let record = match state.blockchain.get_unattributed_deposit(&req.external_tx_hash) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "No unattributed deposit found for this tx hash. It may already be attributed or never existed."
        }))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    };

    if record.claimed_by.is_some() {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This deposit has already been claimed.",
            "claimed_by": record.claimed_by,
        })));
    }

    // ── Reserve → credit → commit (Bug #2 atomic pattern) ────────────────
    let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(record.amount_micro_stablecoin);
    let mint_tx_id = uuid::Uuid::new_v4().to_string();

    if let Err(e) = state.blockchain.reserve_bridge_tx(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": format!("Double-mint blocked: {}", e) })));
    }
    match state.blockchain.credit_lamports(&req.wallet_address, bb_lamports) {
        Ok(_) => {
            if let Err(e) = state.blockchain.commit_bridge_tx(&req.external_tx_hash, &mint_tx_id) {
                tracing::warn!("⚠️  claim commit_bridge_tx: {}", e);
            }
        }
        Err(e) => {
            state.blockchain.cancel_bridge_tx(&req.external_tx_hash);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB mint failed: {}", e) })));
        }
    }

    // ── Mark claimed in ReDB ──────────────────────────────────────────────
    if let Err(e) = state.blockchain.mark_unattributed_claimed(&req.external_tx_hash, &req.wallet_address) {
        tracing::warn!("⚠️  Failed to mark unattributed deposit claimed: {}", e);
    }

    let new_balance = state.blockchain.get_balance(&req.wallet_address);

    tracing::info!("✅ CLAIM: {:.6} {} → {:.5} BB → {} (tx: {})",
        record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
        record.asset,
        bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        &req.wallet_address[..8.min(req.wallet_address.len())],
        &req.external_tx_hash[..16.min(req.external_tx_hash.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "external_tx_hash": req.external_tx_hash,
        "wallet_address": req.wallet_address,
        "asset": record.asset,
        "amount_stablecoin": record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
        "bb_minted": bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        "new_balance": new_balance,
        "mint_tx_id": mint_tx_id,
    })))
}
