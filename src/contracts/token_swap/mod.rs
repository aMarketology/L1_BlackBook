use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::AppState;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT, LAMPORTS_PER_BB, swap_pool_pda, swap_pool_address};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// TOKEN SWAP / AMM SMART CONTRACT (Native Module)
// ============================================================================
//
// Fixed-rate BB ↔ wUSDT swap backed by the swap pool PDA's on-chain liquidity.
// The pool PDA (swap_pool_pda()) holds both $BB and wUSDT — no private key exists
// for this address; only the swap handlers below can move funds from it.
//
// Rate: 10 BB = 1 wUSDT  (same as deposit gateway)
// ============================================================================

/// 10 BB = 1 wUSDT (integer ratio)
pub const BB_TO_USDC_RATE: u64 = 10;

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
    }
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

fn verify_swap_signature(
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

    // ── REPLAY PROTECTION & TIMESTAMP ──
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Transaction too old" })));
    }
    let nonce_key = format!("swap:bb_usdc:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key.clone()) {

        dashmap::mapref::entry::Entry::Occupied(_) => {

            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));

        }

        dashmap::mapref::entry::Entry::Vacant(v) => {

            v.insert(now);

        }

    }

    // ── SIGNATURE VERIFICATION ──
    // Payload: SWAP_BB_USDC:<wallet>:<bb>:<ts>:<nonce>
    let expected_msg = format!("SWAP_BB_USDC:{}:{}:{}:{}", req.wallet_address, req.bb_amount, req.timestamp, req.nonce);
    if let Err(e) = verify_swap_signature(&req.public_key, &req.signature, &expected_msg) {
        return e;
    }
    
    // Check that pubkey matches address
    let pubkey_decoded = match hex::decode(&req.public_key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key hex" }))),
    };
    let expected_addr = bs58::encode(&pubkey_decoded).into_string();
    if expected_addr != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Public key does not match wallet address" })));
    }


    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet address (must be base58)" }))),
    };
    let pool_pubkey  = swap_pool_pda();
    let pool_address = swap_pool_address();

    // Integer math: bb_lamports / (LAMPORTS_PER_BB * RATE) * USDC_UNIT
    // = bb_lamports * USDC_UNIT / (LAMPORTS_PER_BB * RATE)
    let usdc_raw_output = (req.bb_amount as u128 * USDC_UNIT as u128
        / (LAMPORTS_PER_BB as u128 * BB_TO_USDC_RATE as u128)) as u64;
    if usdc_raw_output == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Amount too small for swap" })));
    }

    // 1. Check user BB balance (u64 lamports)
    let user_bb_lamports = state.blockchain.get_balance_lamports(&req.wallet_address);
    if user_bb_lamports < req.bb_amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Insufficient BB balance" })));
    }

    // 2. Check pool wUSDT reserve
    let mint = usdc_mint_bytes();
    let pre_pool_bb = state.blockchain.get_balance_lamports(&pool_address);
    let pre_pool_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &pool_pubkey);
    if pre_pool_usdc < usdc_raw_output {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Insufficient wUSDT liquidity in swap pool" })));
    }

    // 3. Execute swap atomically:
    let bb_amount_f64 = req.bb_amount as f64 / LAMPORTS_PER_BB as f64;
    //    A) Debit user BB → Credit pool BB
    if let Err(e) = state.blockchain.debit(&req.wallet_address, bb_amount_f64) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB debit failed: {}", e) })));
    }
    let _ = state.blockchain.credit(&pool_address, bb_amount_f64);

    //    B) Transfer wUSDT from pool → user
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &pool_pubkey,
        &wallet_pubkey,
        usdc_raw_output,
    ) {
        // Rollback BB
        let _ = state.blockchain.debit(&pool_address, bb_amount_f64);
        let _ = state.blockchain.credit(&req.wallet_address, bb_amount_f64);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("wUSDT transfer failed: {}", e) })));
    }

    // ── POOL DELTA INVARIANT CHECK ────────────────────────────────────────
    // After the swap, verify the pool balance changes exactly match the
    // computed amounts. A mismatch indicates a double-apply bug or state
    // corruption — rollback immediately before any funds escape.
    let post_pool_bb   = state.blockchain.get_balance_lamports(&pool_address);
    let post_pool_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &pool_pubkey);
    let actual_bb_gained   = post_pool_bb.saturating_sub(pre_pool_bb);
    let actual_usdc_lost   = pre_pool_usdc.saturating_sub(post_pool_usdc);
    if actual_bb_gained != req.bb_amount || actual_usdc_lost != usdc_raw_output {
        tracing::error!(
            "🚨 POOL INVARIANT VIOLATED (BB→wUSDT): expected Δbb={} Δusdc={} got Δbb={} Δusdc={} — rolling back",
            req.bb_amount, usdc_raw_output, actual_bb_gained, actual_usdc_lost
        );
        // Rollback: undo pool BB credit, undo user BB debit, undo wUSDT transfer
        let _ = state.blockchain.debit(&pool_address, bb_amount_f64);
        let _ = state.blockchain.credit(&req.wallet_address, bb_amount_f64);
        let _ = SplTokenEngine::transfer_tokens(&state.blockchain.svm_accounts, &mint, &wallet_pubkey, &pool_pubkey, usdc_raw_output);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Pool invariant violated — transaction rolled back" })));
    }

    info!("🔄 SWAP: {} swapped {} lamports BB for {} micro-wUSDT", req.wallet_address, req.bb_amount, usdc_raw_output);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "bb_debited_lamports": req.bb_amount,
        "wusdt_credited_micro": usdc_raw_output,
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

    // ── REPLAY PROTECTION & TIMESTAMP ──
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Transaction too old" })));
    }
    let nonce_key = format!("swap:usdc_bb:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key.clone()) {

        dashmap::mapref::entry::Entry::Occupied(_) => {

            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));

        }

        dashmap::mapref::entry::Entry::Vacant(v) => {

            v.insert(now);

        }

    }

    // ── SIGNATURE VERIFICATION ──
    // Payload: SWAP_USDC_BB:<wallet>:<usdc>:<ts>:<nonce>
    let expected_msg = format!("SWAP_USDC_BB:{}:{}:{}:{}", req.wallet_address, req.usdc_amount, req.timestamp, req.nonce);
    if let Err(e) = verify_swap_signature(&req.public_key, &req.signature, &expected_msg) {
        return e;
    }
    
    // Check that pubkey matches address
    let pubkey_decoded = match hex::decode(&req.public_key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key hex" }))),
    };
    let expected_addr = bs58::encode(&pubkey_decoded).into_string();
    if expected_addr != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Public key does not match wallet address" })));
    }


    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet address (must be base58)" }))),
    };
    let pool_pubkey  = swap_pool_pda();
    let pool_address = swap_pool_address();

    // Integer math: usdc_micro * LAMPORTS_PER_BB * RATE / USDC_UNIT
    let bb_lamports_output = (req.usdc_amount as u128 * LAMPORTS_PER_BB as u128
        * BB_TO_USDC_RATE as u128 / USDC_UNIT as u128) as u64;
    if bb_lamports_output == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Amount too small for swap" })));
    }

    // 1. Check user wUSDT balance
    let mint = usdc_mint_bytes();
    let user_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    if user_usdc < req.usdc_amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Insufficient wUSDT balance" })));
    }

    // 2. Check pool BB reserve (u64 lamports) and capture pre-swap state
    let pre_pool_bb   = state.blockchain.get_balance_lamports(&pool_address);
    let pre_pool_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &pool_pubkey);
    if pre_pool_bb < bb_lamports_output {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Insufficient BB liquidity in swap pool" })));
    }

    // 3. Execute swap atomically:
    let bb_output_f64 = bb_lamports_output as f64 / LAMPORTS_PER_BB as f64;
    //    A) Transfer wUSDT from user → pool
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &wallet_pubkey,
        &pool_pubkey,
        req.usdc_amount,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("wUSDT debit failed: {}", e) })));
    }

    //    B) Debit BB from pool → credit user
    if let Err(e) = state.blockchain.debit(&pool_address, bb_output_f64) {
        // Rollback wUSDT
        let _ = SplTokenEngine::transfer_tokens(&state.blockchain.svm_accounts, &mint, &pool_pubkey, &wallet_pubkey, req.usdc_amount);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB debit from pool failed: {}", e) })));
    }
    let _ = state.blockchain.credit(&req.wallet_address, bb_output_f64);

    // ── POOL DELTA INVARIANT CHECK ───────────────────────────────────────────
    // Verify pool gained exactly usdc_amount wUSDT and lost exactly bb_lamports_output BB.
    let post_pool_bb   = state.blockchain.get_balance_lamports(&pool_address);
    let post_pool_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &pool_pubkey);
    let actual_bb_lost    = pre_pool_bb.saturating_sub(post_pool_bb);
    let actual_usdc_gained = post_pool_usdc.saturating_sub(pre_pool_usdc);
    if actual_bb_lost != bb_lamports_output || actual_usdc_gained != req.usdc_amount {
        tracing::error!(
            "🚨 POOL INVARIANT VIOLATED (wUSDT→BB): expected Δbb={} Δusdc={} got Δbb={} Δusdc={} — rolling back",
            bb_lamports_output, req.usdc_amount, actual_bb_lost, actual_usdc_gained
        );
        // Rollback: undo pool BB debit, undo user credit, undo wUSDT transfer
        let _ = state.blockchain.credit(&pool_address, bb_output_f64);
        let _ = state.blockchain.debit(&req.wallet_address, bb_output_f64);
        let _ = SplTokenEngine::transfer_tokens(&state.blockchain.svm_accounts, &mint, &pool_pubkey, &wallet_pubkey, req.usdc_amount);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Pool invariant violated — transaction rolled back" })));
    }

    info!("🔄 SWAP: {} swapped {} micro-wUSDT for {} BB lamports", req.wallet_address, req.usdc_amount, bb_lamports_output);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "wusdt_debited_micro": req.usdc_amount,
        "bb_credited_lamports": bb_lamports_output,
        "pool_address": pool_address,
    })))
}
