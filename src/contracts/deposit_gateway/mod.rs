use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::Deserialize;
use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use tracing::{info, warn};

use crate::AppState;
use crate::storage::DepositRecord;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

// ============================================================================
// DEPOSIT GATEWAY SMART CONTRACT (Native Module)
// ============================================================================
//
// Flow:
//   1. User sends wUSDC or wUSDT to the custody wallet (off-chain, one key)
//   2. User calls POST /deposit/request with:
//        - their BB wallet address
//        - the external tx hash proving the on-chain transfer
//        - the stablecoin amount
//        - an Ed25519 signature proving they own the BB wallet
//   3. Dealer calls POST /admin/deposit/approve with the tx hash
//        - L1 mints BB at the fixed 10:1 ratio (10 USDC = 1 BB)
//        - The external tx hash is permanently recorded as processed
//          (double-mint protection via PROCESSED_BRIDGE_TXS table)
//
// Rate: 1 USDC/USDT = 10 BB  (BB_PER_STABLECOIN = 10.0)
//
// This module is intentionally minimal. Future upgrades:
//   - Oracle verification of the external tx (on-chain proof)
//   - Automatic approval via relayer
//   - Support for multiple custody wallets / asset types
// ============================================================================

pub const BB_PER_STABLECOIN: f64 = 10.0; // 1 USDC = 10 BB

// ── Request types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DepositRequestBody {
    /// BB wallet address (base58) where minted tokens will land
    pub wallet_address: String,
    /// Transaction hash from the external chain (unique key, replay prevention)
    pub external_tx_hash: String,
    /// "USDC" or "USDT"
    pub asset: String,
    /// Amount of stablecoin sent to the custody wallet
    pub amount_stablecoin: f64,
    /// Ed25519 public key (hex, 32 bytes) matching wallet_address
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes)
    /// Signs: "DEPOSIT_REQUEST:{wallet_address}:{external_tx_hash}:{amount_stablecoin}:{asset}:{timestamp}:{nonce}"
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

/// POST /deposit/request — User submits a wUSDC/wUSDT → BB deposit request.
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
    if req.amount_stablecoin <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "amount_stablecoin must be > 0" })));
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
    if state.used_nonces.contains_key(&nonce_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used — possible replay attack"
        })));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request too old (>60s)"
        })));
    }
    state.used_nonces.insert(nonce_key, now);

    // ── ALREADY PROCESSED OR PENDING? ─────────────────────────────────────
    if state.blockchain.is_bridge_tx_processed(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This external_tx_hash has already been minted. Possible double-submission."
        })));
    }
    if state.deposit_requests.contains_key(&req.external_tx_hash) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "A deposit request for this tx hash already exists. Check /deposit/status/:tx_hash"
        })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION ───────────────────────────────────
    let message = format!(
        "DEPOSIT_REQUEST:{}:{}:{}:{}:{}:{}",
        req.wallet_address, req.external_tx_hash,
        req.amount_stablecoin, req.asset,
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
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
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
    let bb_to_mint = req.amount_stablecoin * BB_PER_STABLECOIN;
    let record = DepositRecord {
        wallet_address: req.wallet_address.clone(),
        external_tx_hash: req.external_tx_hash.clone(),
        asset: req.asset.clone(),
        amount_stablecoin: req.amount_stablecoin,
        bb_to_mint,
        status: "pending".to_string(),
        submitted_at: now,
        approved_at: None,
    };

    // Persist to ReDB + hot DashMap
    if let Err(e) = state.blockchain.store_deposit_request(&record) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Storage error: {}", e) })));
    }
    state.deposit_requests.insert(req.external_tx_hash.clone(), record.clone());

    info!("📥 DEPOSIT REQUEST: {} {} → {} BB for {} (tx: {})",
        req.amount_stablecoin, req.asset, bb_to_mint,
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
                        "amount_stablecoin": req.amount_stablecoin,
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
                    "amount_stablecoin": req.amount_stablecoin,
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
        "amount_stablecoin": record.amount_stablecoin,
        "bb_to_mint": record.bb_to_mint,
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
            "amount_stablecoin": record.amount_stablecoin,
            "bb_to_mint": record.bb_to_mint,
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
        "error": "No deposit request found for this tx hash"
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

    // ── MINT BB ───────────────────────────────────────────────────────────
    if let Err(e) = state.blockchain.credit(&record.wallet_address, record.bb_to_mint) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB mint failed: {}", e) })));
    }
    let new_balance = state.blockchain.get_balance(&record.wallet_address);

    // ── MINT wUSDC (1:1 with stablecoin deposited) ────────────────────────
    let wusdc_minted = {
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;
        match Pubkey::from_str(&record.wallet_address) {
            Ok(wallet_pubkey) => {
                let mint = usdc_mint_bytes();
                let raw_units = (record.amount_stablecoin * USDC_UNIT as f64) as u64;
                match SplTokenEngine::mint_to(&state.blockchain.svm_accounts, &mint, &wallet_pubkey, raw_units) {
                    Ok(_) => {
                        info!("💵 wUSDC minted: {:.6} → {}",
                            record.amount_stablecoin,
                            &record.wallet_address[..8.min(record.wallet_address.len())]);
                        record.amount_stablecoin
                    }
                    Err(e) => {
                        warn!("⚠️  wUSDC mint failed (BB already minted): {:?}", e);
                        0.0
                    }
                }
            }
            Err(_) => { warn!("⚠️  Invalid wallet pubkey for wUSDC mint"); 0.0 }
        }
    };

    // ── MARK AS PROCESSED (double-mint lock) ─────────────────────────────
    let mint_tx_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = state.blockchain.mark_bridge_tx_processed(&req.external_tx_hash, &mint_tx_id) {
        warn!("⚠️  Failed to persist bridge tx processed flag: {}", e);
        // Non-fatal: DashMap is already updated, server restart would re-check
    }

    // ── UPDATE RECORD ─────────────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut updated = record.clone();
    updated.status = "approved".to_string();
    updated.approved_at = Some(now);
    state.deposit_requests.insert(req.external_tx_hash.clone(), updated.clone());
    let _ = state.blockchain.store_deposit_request(&updated);

    // ── RECORD IN POH BLOCK ───────────────────────────────────────────────
    {
        use crate::protocol::Transaction as ProtoTx;
        use crate::protocol::TxData;
        let tx = ProtoTx {
            hash: mint_tx_id.clone(),
            from: "DEPOSIT_GATEWAY".to_string(),
            timestamp: now,
            data: TxData::DepositUsdt {
                usdt_amount: (record.amount_stablecoin * crate::svm::USDC_UNIT as f64) as u64,
                external_tx_hash: Some(req.external_tx_hash.clone()),
            },
            signature: "dealer_approved".to_string(),
            signer_pubkey: "DEALER".to_string(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    info!("✅ DEPOSIT APPROVED: {} {} → {} BB + {:.6} wUSDC → {} (ext_tx: {})",
        record.amount_stablecoin, record.asset, record.bb_to_mint,
        wusdc_minted,
        &record.wallet_address[..8.min(record.wallet_address.len())],
        &req.external_tx_hash[..12.min(req.external_tx_hash.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "external_tx_hash": req.external_tx_hash,
        "wallet_address": record.wallet_address,
        "asset": record.asset,
        "amount_stablecoin": record.amount_stablecoin,
        "bb_minted": record.bb_to_mint,
        "wusdc_minted": wusdc_minted,
        "new_balance": new_balance,
        "mint_tx_id": mint_tx_id,
    })))
}
