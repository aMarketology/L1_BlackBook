use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::AppState;
use crate::svm::{USDC_UNIT, LAMPORTS_PER_BB, BB_PER_USDT_DEFAULT, swap_pool_address};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// PROTOCOL-OWNED LIQUIDITY (POL) SWAP CONTRACT
// ============================================================================
//
// Closed-loop BB ↔ wUSDT swap where `swap_pool_pda()` is the sole protocol-owned
// liquidity provider:
//   - No external LP tokens exist; liquidity cannot flee during market panic.
//   - Base exchange rate is strictly fixed at 10 BB = 1 wUSDT ($0.10 / BB).
//   - 100% of swap fees (`POL_SWAP_FEE_BPS`, default 30 bps = 0.30%) remain
//     inside `swap_pool_pda()`, monotonically strengthening pool reserves.
//   - All 4 SVM account updates commit in a single ACID ReDB transaction before
//     updating DashMap hot_state — zero crash window or partial rollback risk.
// ============================================================================

/// Default closed-loop POL swap fee in basis points (30 bps = 0.30%).
pub const POL_DEFAULT_SWAP_FEE_BPS: u64 = 30;
/// Maximum allowed POL swap fee in basis points (1000 bps = 10.00%).
pub const POL_MAX_SWAP_FEE_BPS: u64 = 1_000;

/// Active POL swap fee in basis points (100% retained in `swap_pool_pda`).
pub fn pol_swap_fee_bps() -> u64 {
    std::env::var("POL_SWAP_FEE_BPS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|bps| bps.min(POL_MAX_SWAP_FEE_BPS))
        .unwrap_or(POL_DEFAULT_SWAP_FEE_BPS)
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub enum SwapInstruction {
    SwapBbForUsdc {
        /// BB amount in lamports (1 BB = 100_000 lamports)
        bb_amount: u64,
        wallet_address: String,
    },
    SwapUsdcForBb {
        /// wUSDT amount in micro-units (1 wUSDT = 1_000_000 micro)
        usdc_amount: u64,
        wallet_address: String,
    },
}

#[derive(Deserialize)]
pub struct SwapBbToUsdcRequest {
    #[serde(alias = "wallet")]
    pub wallet_address: String,
    /// BB amount in lamports (1 BB = 100_000 lamports)
    #[serde(alias = "amount")]
    pub bb_amount: u64,
    pub timestamp: u64,
    pub nonce: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct SwapUsdcToBbRequest {
    #[serde(alias = "wallet")]
    pub wallet_address: String,
    /// wUSDT amount in micro-units (1 wUSDT = 1_000_000 micro)
    #[serde(alias = "amount")]
    pub usdc_amount: u64,
    pub timestamp: u64,
    pub nonce: String,
    pub public_key: String,
    pub signature: String,
}

fn verify_swap_signature_and_owner(
    wallet_address: &str,
    public_key_hex: &str,
    signature_hex: &str,
    expected_message: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};

    let pubkey_bytes = hex::decode(public_key_hex).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key hex" })))
    })?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature hex" })))
    })?;

    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key length" })))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" })))
    })?;

    let derived_addr = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_addr != wallet_address {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Public key does not match wallet address"
        }))));
    }

    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature length" })))
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(expected_message.as_bytes(), &signature).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })))
    })
}

/// POST /swap/bb-to-usdc
pub async fn swap_bb_for_usdc_handler(
    State(state): State<AppState>,
    Json(req): Json<SwapBbToUsdcRequest>,
) -> impl IntoResponse {
    if req.wallet_address.is_empty() || req.bb_amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }

    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet address (must be base58)" }))),
    };
    if crate::svm::pda::is_reserved_pda(&wallet_pubkey) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Reserved protocol PDA cannot initiate swaps" })));
    }

    // ── TIMESTAMP FRESHNESS (±60s) ──
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Transaction timestamp outside ±60s window" })));
    }

    // ── SIGNATURE & PUBKEY BINDING (checked BEFORE consuming nonce) ──
    let expected_msg = format!("SWAP_BB_USDC:{}:{}:{}:{}", req.wallet_address, req.bb_amount, req.timestamp, req.nonce);
    if let Err(e) = verify_swap_signature_and_owner(&req.wallet_address, &req.public_key, &req.signature, &expected_msg) {
        return e;
    }

    // ── ATOMIC NONCE REPLAY GUARD ──
    let nonce_key = format!("swap:bb_usdc:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── FIXED 10:1 POL QUOTE + CLOSED-LOOP FEE ──
    let fee_bps = pol_swap_fee_bps();
    let gross_usdc_micro = (req.bb_amount as u128 * USDC_UNIT as u128
        / (LAMPORTS_PER_BB as u128 * BB_PER_USDT_DEFAULT as u128)) as u64;
    let fee_usdc_micro = (gross_usdc_micro as u128 * fee_bps as u128 / 10_000) as u64;
    let net_usdc_output = gross_usdc_micro.saturating_sub(fee_usdc_micro);
    if net_usdc_output == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Amount too small for swap" })));
    }

    // ── SINGLE-TRANSACTION ACID POL COMMIT ──
    let pool_address = swap_pool_address();
    if let Err(e) = state.blockchain.atomic_pol_swap_bb_for_usdc(
        &req.wallet_address,
        &wallet_pubkey,
        req.bb_amount,
        net_usdc_output,
    ) {
        let code = if e.contains("Insufficient BB") {
            StatusCode::BAD_REQUEST
        } else if e.contains("Insufficient wUSDT liquidity") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return (code, Json(serde_json::json!({ "error": e })));
    }

    info!(
        "🔄 POL SWAP (BB→wUSDT): {} paid {} BB lamports → received {} micro-wUSDT (fee={} micro retained in pool)",
        req.wallet_address, req.bb_amount, net_usdc_output, fee_usdc_micro
    );

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "bb_debited_lamports": req.bb_amount,
        "wusdt_gross_micro": gross_usdc_micro,
        "fee_bps": fee_bps,
        "fee_retained_wusdt_micro": fee_usdc_micro,
        "wusdt_credited_micro": net_usdc_output,
        "pool_address": pool_address,
    })))
}

/// POST /swap/usdc-to-bb
pub async fn swap_usdc_for_bb_handler(
    State(state): State<AppState>,
    Json(req): Json<SwapUsdcToBbRequest>,
) -> impl IntoResponse {
    if req.wallet_address.is_empty() || req.usdc_amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }

    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet address (must be base58)" }))),
    };
    if crate::svm::pda::is_reserved_pda(&wallet_pubkey) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Reserved protocol PDA cannot initiate swaps" })));
    }

    // ── TIMESTAMP FRESHNESS (±60s) ──
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Transaction timestamp outside ±60s window" })));
    }

    // ── SIGNATURE & PUBKEY BINDING (checked BEFORE consuming nonce) ──
    let expected_msg = format!("SWAP_USDC_BB:{}:{}:{}:{}", req.wallet_address, req.usdc_amount, req.timestamp, req.nonce);
    if let Err(e) = verify_swap_signature_and_owner(&req.wallet_address, &req.public_key, &req.signature, &expected_msg) {
        return e;
    }

    // ── ATOMIC NONCE REPLAY GUARD ──
    let nonce_key = format!("swap:usdc_bb:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── FIXED 10:1 POL QUOTE + CLOSED-LOOP FEE ──
    let fee_bps = pol_swap_fee_bps();
    let gross_bb_lamports = (req.usdc_amount as u128 * LAMPORTS_PER_BB as u128
        * BB_PER_USDT_DEFAULT as u128 / USDC_UNIT as u128) as u64;
    let fee_bb_lamports = (gross_bb_lamports as u128 * fee_bps as u128 / 10_000) as u64;
    let net_bb_output = gross_bb_lamports.saturating_sub(fee_bb_lamports);
    if net_bb_output == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Amount too small for swap" })));
    }

    // ── SINGLE-TRANSACTION ACID POL COMMIT ──
    let pool_address = swap_pool_address();
    if let Err(e) = state.blockchain.atomic_pol_swap_usdc_for_bb(
        &req.wallet_address,
        &wallet_pubkey,
        req.usdc_amount,
        net_bb_output,
    ) {
        let code = if e.contains("Insufficient wUSDT") {
            StatusCode::BAD_REQUEST
        } else if e.contains("Insufficient BB liquidity") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return (code, Json(serde_json::json!({ "error": e })));
    }

    info!(
        "🔄 POL SWAP (wUSDT→BB): {} paid {} micro-wUSDT → received {} BB lamports (fee={} lamports retained in pool)",
        req.wallet_address, req.usdc_amount, net_bb_output, fee_bb_lamports
    );

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "wusdt_debited_micro": req.usdc_amount,
        "bb_gross_lamports": gross_bb_lamports,
        "fee_bps": fee_bps,
        "fee_retained_bb_lamports": fee_bb_lamports,
        "bb_credited_lamports": net_bb_output,
        "pool_address": pool_address,
    })))
}
