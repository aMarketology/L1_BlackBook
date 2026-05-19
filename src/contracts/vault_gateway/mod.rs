use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::Deserialize;
use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use std::sync::atomic::Ordering;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, warn, error};

use crate::AppState;
use crate::svm::{SplTokenEngine, usdc_mint_bytes, LAMPORTS_PER_BB};

// ============================================================================
// VAULT GATEWAY — BB Burn → wUSDT Credit  (Cross-Chain Bridge Step 1)
// ============================================================================
//
// Immutable Law: For every bb_lamports destroyed, an equal number of
// wUSDT micro-units are created. wusdt_credited == bb_burned always.
//
// Flow:
//   POST /vault/burn { wallet_address, bb_lamports, public_key, signature, ts, nonce }
//   ↓
//   Ed25519 verify(VAULT_BURN:{wallet}:{bb_lamports}:{ts}:{nonce})
//   ↓
//   ATOMIC: debit BB (supply ↓) + mint wUSDT (supply ↑) + store BurnRecord
//   ↓
//   Returns { poh_slot, bb_burned, wusdt_credited }
//   User may later call POST /vault/claim-attestation to bridge to Solana.
// ============================================================================

#[derive(Deserialize)]
pub struct BurnRequest {
    pub wallet_address: String,
    /// Amount of $BB to burn, in lamports (5 decimals: 1 BB = 100_000 lamports).
    pub bb_lamports: u64,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

/// POST /vault/burn
///
/// Destroys bb_lamports of $BB from the caller's wallet and creates an equal
/// number of wUSDT micro-units (the Immutable Law). Returns a BurnRecord keyed
/// by the current PoH slot that can later be redeemed via /vault/claim-attestation.
pub async fn burn_handler(
    State(state): State<AppState>,
    Json(req): Json<BurnRequest>,
) -> impl IntoResponse {
    // ── Basic validation ─────────────────────────────────────────────────
    if req.wallet_address.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing wallet_address" })));
    }
    if req.bb_lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "bb_lamports must be > 0" })));
    }
    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet_address" })));
    }

    // ── Timestamp freshness (60s) ────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Request too old (>60s)" })));
    }

    // ── Nonce / replay protection ────────────────────────────────────────
    let nonce_key = format!("vault_burn:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => { v.insert(now); }
    }

    // ── Rate limit ───────────────────────────────────────────────────────
    if let Err(msg) = state.throttler.check_transaction(&req.wallet_address, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": msg })));
    }

    // ── Ed25519 signature verification ───────────────────────────────────
    let message = format!(
        "VAULT_BURN:{}:{}:{}:{}",
        req.wallet_address, req.bb_lamports, req.timestamp, req.nonce
    );
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public_key (must be 32 bytes hex)" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" }))),
    };
    let pubkey_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad sig length" }))),
    };
    let sig = Signature::from_bytes(sig_arr);
    if verifying_key.verify(message.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }
    // Derived public key must match the claimed wallet address
    let derived = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address"
        })));
    }

    // ── Check BB balance ─────────────────────────────────────────────────
    let balance_lamports = state.blockchain.get_balance_lamports(&req.wallet_address);
    if balance_lamports < req.bb_lamports {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!(
                "Insufficient BB balance: have {} lamports, need {}",
                balance_lamports, req.bb_lamports
            )
        })));
    }

    // ── THE IMMUTABLE LAW ────────────────────────────────────────────────
    // wUSDT micro-units to create = BB lamports to destroy (1:1 identity).
    // Proof: 10 BB = 1,000,000 lamports = 1,000,000 microUSDT = 1 wUSDT.
    let wusdt_micro: u64 = req.bb_lamports;

    // Get current PoH slot (serves as BurnRecord primary key)
    let poh_slot = state.current_slot.load(Ordering::Relaxed);

    // ── Resolve wallet Pubkey for SPL ops ────────────────────────────────
    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet pubkey" }))),
    };

    // ── ATOMIC: Destroy BB, Create wUSDT ──────────────────────────────────
    // Step A: Debit BB lamports (permanently destroys from supply — no f64)
    if let Err(e) = state.blockchain.debit_svm_lamports(&req.wallet_address, req.bb_lamports) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("BB burn failed: {}", e)
        })));
    }

    // Step B: Mint wUSDT to wallet (equal supply increase)
    let mint = usdc_mint_bytes();
    if let Err(e) = SplTokenEngine::mint_to(&state.blockchain.svm_accounts, &mint, &wallet_pubkey, wusdt_micro) {
        // Rollback: restore user's BB
        if let Err(re) = state.blockchain.credit_svm_lamports(&req.wallet_address, req.bb_lamports) {
            error!("CRITICAL: wUSDT mint failed AND BB rollback failed for wallet {}: mint_err={} rollback_err={}", req.wallet_address, e, re);
        } else {
            warn!("wUSDT mint failed, BB rollback successful: {}", e);
        }
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("wUSDT mint failed: {}", e)
        })));
    }

    // Step C: Persist BurnRecord to ReDB (durable receipt for claim-attestation)
    let record = crate::storage::BurnRecord {
        wallet: req.wallet_address.clone(),
        poh_slot,
        amount_usdt_micro: wusdt_micro,
        attestation_issued: false,
        claimed_on_solana: false,
        redeemable: true,
        created_at: now,
    };
    if let Err(e) = state.blockchain.store_burn(&record) {
        // Monetary state is already mutated — log critical but don't abort.
        // The user has their wUSDT; the burn record can be reconstructed from PoH.
        error!("CRITICAL: BurnRecord persistence failed for slot {}: {}", poh_slot, e);
    }

    // ── Record to PoH block ──────────────────────────────────────────────
    {
        use layer1::protocol::Transaction as ProtoTx;
        use layer1::protocol::TxData;
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.wallet_address.clone(),
            timestamp: now,
            data: TxData::VaultBurn {
                bb_burned: req.bb_lamports,
                wusdt_credited: wusdt_micro,
                poh_slot,
            },
            signature: req.signature.clone(),
            signer_pubkey: req.public_key.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    info!("🔥 VAULT BURN: {} lamports BB destroyed, {} microUSDT minted → wallet {} (slot {})",
        req.bb_lamports, wusdt_micro, &req.wallet_address[..8.min(req.wallet_address.len())], poh_slot);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "poh_slot": poh_slot,
        "bb_burned": req.bb_lamports,
        "wusdt_credited": wusdt_micro,
        "burn_id": poh_slot.to_string(),
    })))
}


//
// Flow:
//   1. User burned $BB on the L1 (recorded in PoH, stored in BURN_RECORDS).
//   2. User calls POST /vault/claim-attestation with:
//        - their wallet address
//        - the PoH slot of the burn
//        - the USDT amount to claim
//        - an Ed25519 signature proving wallet ownership
//   3. L1 verifies the burn record exists and matches, then signs the claim
//      message using the VaultSigner (KMS or local Ed25519).
//   4. Returns { signature_hex, kms_pubkey_hex, message, poh_slot, amount }.
//   5. User's React frontend uses this to build a 2-instruction Solana tx:
//        ix[0] = Ed25519Program.createInstructionWithPublicKey(...)
//        ix[1] = program.methods.claimUsdt(poh_slot, amount).accounts({...})
// ============================================================================

#[derive(Deserialize)]
pub struct ClaimAttestationRequest {
    pub wallet_address: String,
    pub poh_slot: u64,
    pub amount_usdt_micro: u64,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

/// POST /vault/claim-attestation
pub async fn claim_attestation_handler(
    State(state): State<AppState>,
    Json(req): Json<ClaimAttestationRequest>,
) -> impl IntoResponse {
    // ── Check vault signer is configured ─────────────────────────────────
    let signer = match &state.vault_signer {
        Some(s) => s,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Vault signer not configured (set AWS_KMS_KEY_ID or VAULT_SIGNER_PRIVATE_KEY)"
        }))),
    };

    // ── Basic validation ─────────────────────────────────────────────────
    if req.wallet_address.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing wallet_address" })));
    }
    if req.amount_usdt_micro == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "amount_usdt_micro must be > 0" })));
    }
    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid wallet_address. Must be a base58 address."
        })));
    }

    // ── Timestamp freshness ──────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Request too old (>60s)" })));
    }

    // ── Nonce / replay protection ────────────────────────────────────────
    let nonce_key = format!("claim_attestation:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => { v.insert(now); }
    }

    // ── Ed25519 signature verification ───────────────────────────────────
    let message = format!(
        "CLAIM_ATTESTATION:{}:{}:{}:{}:{}",
        req.wallet_address, req.poh_slot, req.amount_usdt_micro, req.timestamp, req.nonce
    );
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public_key (must be 32 bytes hex)" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" }))),
    };
    let pubkey_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad sig length" }))),
    };
    let sig = Signature::from_bytes(sig_arr);
    if verifying_key.verify(message.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }
    let derived = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address"
        })));
    }

    // ── Verify burn record exists in ReDB ────────────────────────────────
    let burn = match state.blockchain.load_burn(req.poh_slot) {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No burn record found for PoH slot {}", req.poh_slot)
        }))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Storage error: {}", e)
        }))),
    };

    // Verify the burn belongs to this wallet, amount matches, and is redeemable
    if burn.wallet != req.wallet_address {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "Burn record wallet does not match requesting wallet"
        })));
    }
    if burn.amount_usdt_micro != req.amount_usdt_micro {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Amount mismatch: burn={} requested={}", burn.amount_usdt_micro, req.amount_usdt_micro)
        })));
    }
    if !burn.redeemable {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This burn has already been redeemed for an attestation"
        })));
    }
    if burn.attestation_issued {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Attestation already issued for this burn"
        })));
    }
    if burn.claimed_on_solana {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "This burn has already been claimed on Solana"
        })));
    }

    // ── Verify user still holds the wUSDT (may have spent it since burn) ─
    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet pubkey" }))),
    };
    let mint = usdc_mint_bytes();
    let wusdt_balance = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    if wusdt_balance < req.amount_usdt_micro {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!(
                "Insufficient wUSDT balance: have {} micro, need {}",
                wusdt_balance, req.amount_usdt_micro
            )
        })));
    }

    // ── ATOMIC DOUBLE-SPEND PREVENTION: Burn wUSDT BEFORE signing ────────
    // We burn the user's wUSDT first. If the KMS sign fails after this,
    // the user loses wUSDT but cannot claim on Solana. This is the safe
    // failure mode — prevents any double-spend scenario.
    if let Err(e) = SplTokenEngine::burn(&state.blockchain.svm_accounts, &mint, &wallet_pubkey, req.amount_usdt_micro) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("wUSDT burn failed: {}", e)
        })));
    }

    // Mark record consumed in ReDB (redeemable=false, attestation_issued=true)
    if let Err(e) = state.blockchain.consume_burn_record(req.poh_slot) {
        // wUSDT is already burned — log critical but continue to issue signature.
        // The record state will be inconsistent but the user can't double-spend.
        error!("CRITICAL: consume_burn_record failed after wUSDT burn for slot {}: {}", req.poh_slot, e);
    }

    // ── Sign the claim attestation ───────────────────────────────────────
    let attestation = match signer.sign_claim(req.poh_slot, req.amount_usdt_micro, &req.wallet_address) {
        Ok(a) => a,
        Err(e) => {
            warn!("⚠️  Vault signer failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Signing failed: {}", e)
            })));
        }
    };

    info!("✅ Claim attestation issued: slot={} amount={} wallet={}",
        req.poh_slot, req.amount_usdt_micro,
        &req.wallet_address[..8.min(req.wallet_address.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "signature_hex": attestation.signature_hex,
        "kms_pubkey_hex": attestation.kms_pubkey_hex,
        "message": attestation.message,
        "poh_slot": attestation.poh_slot,
        "amount": attestation.amount,
    })))
}
