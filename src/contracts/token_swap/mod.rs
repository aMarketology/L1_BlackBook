use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::AppState;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// TOKEN SWAP / AMM SMART CONTRACT (Native Module)
// ============================================================================
//
// Fixed-rate BB ↔ wUSDC swap backed by the dealer's on-chain liquidity.
// The dealer holds both $BB and wUSDC and acts as the sole market maker.
//
// Rate: 10 BB = 1 wUSDC  (same as deposit gateway)
// ============================================================================

pub const BB_TO_USDC_RATE: f64 = 10.0; // 10 BB = 1 wUSDC

#[derive(Serialize, Deserialize, Debug)]
pub enum SwapInstruction {
    SwapBbForUsdc {
        bb_amount: f64,
        wallet_address: String,
    },
    SwapUsdcForBb {
        usdc_amount: f64,
        wallet_address: String,
    }
}

#[derive(Deserialize)]
pub struct SwapBbToUsdcRequest {
    pub wallet_address: String,
    pub bb_amount: f64,
    pub timestamp: u64,
    pub nonce: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct SwapUsdcToBbRequest {
    pub wallet_address: String,
    pub usdc_amount: f64,
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
    if req.wallet_address.is_empty() || req.bb_amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }
    if state.dealer_address.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Swap not available: dealer not configured" })));
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
    let dealer_pubkey = match Pubkey::from_str(&state.dealer_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Dealer address config error" }))),
    };

    let bb_required = req.bb_amount;
    let usdc_output = req.bb_amount / BB_TO_USDC_RATE;
    let usdc_raw_output = (usdc_output * USDC_UNIT as f64) as u64;

    // 1. Check user BB balance
    let user_bb_balance = state.blockchain.get_balance(&req.wallet_address);
    if user_bb_balance < bb_required {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Insufficient BB balance" })));
    }

    // 2. Check dealer wUSDC balance
    let mint = usdc_mint_bytes();
    let dealer_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &dealer_pubkey);
    if dealer_usdc < usdc_raw_output {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Insufficient wUSDC liquidity" })));
    }

    // 3. Execute swap atomically:
    //    A) Debit user BB → Credit dealer BB
    if let Err(e) = state.blockchain.debit(&req.wallet_address, bb_required) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB debit failed: {}", e) })));
    }
    let _ = state.blockchain.credit(&state.dealer_address, bb_required);

    //    B) Transfer wUSDC from dealer → user
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &dealer_pubkey,
        &wallet_pubkey,
        usdc_raw_output,
    ) {
        // Rollback BB
        let _ = state.blockchain.debit(&state.dealer_address, bb_required);
        let _ = state.blockchain.credit(&req.wallet_address, bb_required);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("wUSDC transfer failed: {}", e) })));
    }

    info!("🔄 SWAP: {} swapped {} BB for {:.6} wUSDC", req.wallet_address, bb_required, usdc_output);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Swap executed",
        "bb_debited": bb_required,
        "wusdc_credited": usdc_output,
    })))
}

/// POST /swap/usdc-to-bb
pub async fn swap_usdc_for_bb_handler(
    State(state): State<AppState>,
    Json(req): Json<SwapUsdcToBbRequest>,
) -> impl IntoResponse {
    if req.wallet_address.is_empty() || req.usdc_amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }
    if state.dealer_address.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Swap not available: dealer not configured" })));
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
    let dealer_pubkey = match Pubkey::from_str(&state.dealer_address) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Dealer address config error" }))),
    };

    let usdc_required = req.usdc_amount;
    let usdc_raw_required = (usdc_required * USDC_UNIT as f64) as u64;
    let bb_output = req.usdc_amount * BB_TO_USDC_RATE;

    // 1. Check user wUSDC balance
    let mint = usdc_mint_bytes();
    let user_usdc = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    if user_usdc < usdc_raw_required {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Insufficient wUSDC balance" })));
    }

    // 2. Check dealer BB balance
    let dealer_bb = state.blockchain.get_balance(&state.dealer_address);
    if dealer_bb < bb_output {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "Insufficient BB liquidity" })));
    }

    // 3. Execute swap atomically:
    //    A) Transfer wUSDC from user → dealer
    if let Err(e) = SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts,
        &mint,
        &wallet_pubkey,
        &dealer_pubkey,
        usdc_raw_required,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("wUSDC debit failed: {}", e) })));
    }

    //    B) Transfer BB from dealer → user
    if let Err(e) = state.blockchain.debit(&state.dealer_address, bb_output) {
        // Rollback wUSDC
        let _ = SplTokenEngine::transfer_tokens(&state.blockchain.svm_accounts, &mint, &dealer_pubkey, &wallet_pubkey, usdc_raw_required);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("BB credit failed: {}", e) })));
    }
    let _ = state.blockchain.credit(&req.wallet_address, bb_output);

    info!("🔄 SWAP: {} swapped {:.6} wUSDC for {} BB", req.wallet_address, usdc_required, bb_output);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Swap executed",
        "wusdc_debited": usdc_required,
        "bb_credited": bb_output,
    })))
}
