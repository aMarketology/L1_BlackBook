use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::Deserialize;
use axum::{extract::State, response::IntoResponse, http::StatusCode, Json};
use std::sync::atomic::Ordering;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, warn, error};

use crate::AppState;
use crate::svm::{SplTokenEngine, usdc_mint_bytes};

// ============================================================================
// GET /vault/kms-pubkey
// ============================================================================
//
// Returns the Ed25519 public key of the configured vault signer (KMS or local).
// Operators use this during `initialize_vault` to register the oracle pubkey in
// the Solana Anchor program.
//
// Response: { "pubkey_hex": "<64-char lowercase hex>",
//             "pubkey_base58": "<base58-encoded Solana pubkey>",
//             "source": "local" | "kms" }
// 503 when no signer is configured.
// ============================================================================

/// GET /vault/kms-pubkey
pub async fn kms_pubkey_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match &state.vault_signer {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Vault signer not configured (set AWS_KMS_KEY_ID or VAULT_SIGNER_PRIVATE_KEY)"
            })),
        ),
        Some(signer) => {
            let hex = signer.pubkey_hex();
            let raw = signer.pubkey_bytes();
            let base58 = bs58::encode(&raw).into_string();
            let source = match signer.as_ref() {
                layer1::kms::VaultSigner::Local(_) => "local",
                // Future: VaultSigner::Kms(_) => "kms",
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "pubkey_hex":    hex,
                    "pubkey_base58": base58,
                    "source":        source,
                })),
            )
        }
    }
}

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

    // Get current PoH slot (retained in the record for the KMS attestation message)
    let poh_slot = state.current_slot.load(Ordering::Relaxed);

    // ── Generate collision-free burn_id ──────────────────────────────────
    // burn_id = hex(SHA-256(wallet_bytes || poh_slot_le8 || nonce_utf8)).
    // Two burns in the same 400 ms slot produce different burn_ids because
    // replay-protection already guarantees each (wallet, nonce) pair is unique.
    let burn_id: String = {
        use sha2::{Sha256, Digest};
        let wallet_bytes = match bs58::decode(&req.wallet_address).into_vec() {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet_address bytes" }))),
        };
        let mut h = Sha256::new();
        h.update(&wallet_bytes);
        h.update(poh_slot.to_le_bytes());
        h.update(req.nonce.as_bytes());
        hex::encode(h.finalize())
    };

    // ── Resolve wallet Pubkey for SPL ops ────────────────────────────────
    let wallet_pubkey = match Pubkey::from_str(&req.wallet_address) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid wallet pubkey" }))),
    };

    // ── ATOMIC: Debit BB + Mint wUSDT + Persist BurnRecord in one ReDB txn ─
    //
    // All three mutations (BB debit, wUSDT mint, BurnRecord) are written in a
    // single write_txn.commit(). A crash at any point before the commit leaves
    // all tables unchanged — no partial state, no rollback needed.
    let record = crate::storage::BurnRecord {
        burn_id: burn_id.clone(),
        wallet: req.wallet_address.clone(),
        poh_slot,
        amount_usdt_micro: wusdt_micro,
        attestation_issued: false,
        claimed_on_solana: false,
        redeemable: true,
        created_at: now,
    };
    if let Err(e) = state.blockchain.atomic_vault_burn(
        &req.wallet_address,
        &wallet_pubkey,
        req.bb_lamports,
        wusdt_micro,
        &record,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Vault burn failed: {}", e)
        })));
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

    info!("🔥 VAULT BURN: {} lamports BB destroyed, {} microUSDT minted → wallet {} (slot {} burn_id {})",
        req.bb_lamports, wusdt_micro, &req.wallet_address[..8.min(req.wallet_address.len())],
        poh_slot, &burn_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "poh_slot": poh_slot,
        "bb_burned": req.bb_lamports,
        "wusdt_credited": wusdt_micro,
        "burn_id": burn_id,
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
    /// The burn_id returned by POST /vault/burn — hex SHA-256 of (wallet+slot+nonce).
    /// Replaces the old poh_slot field: uniquely identifies the burn record even when
    /// multiple burns land in the same PoH slot.
    pub burn_id: String,
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
    let signer: &layer1::kms::VaultSigner = match &state.vault_signer {
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

    // ── Load burn record first — poh_slot is needed for signature verification ──
    // We look up by burn_id (not poh_slot) so records never collide within a slot.
    // Fail fast before touching expensive sig-verify / crypto if the ID is wrong.
    let burn = match state.blockchain.load_burn(&req.burn_id) {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No burn record found for burn_id {}", req.burn_id)
        }))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Storage error: {}", e)
        }))),
    };

    // ── Ed25519 signature verification ───────────────────────────────────
    // The signed message encodes poh_slot (from the burn record) — clients include
    // it when they sign so the attestation is cryptographically bound to the slot.
    let message = format!(
        "CLAIM_ATTESTATION:{}:{}:{}:{}:{}",
        req.wallet_address, burn.poh_slot, req.amount_usdt_micro, req.timestamp, req.nonce
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
    if let Err(e) = state.blockchain.consume_burn_record(&req.burn_id) {
        // wUSDT is already burned — log critical but continue to issue signature.
        // The record state will be inconsistent but the user can't double-spend.
        error!("CRITICAL: consume_burn_record failed after wUSDT burn for burn_id {}: {}", req.burn_id, e);
    }

    // ── Sign the claim attestation ───────────────────────────────────────
    let attestation = match signer.sign_claim(burn.poh_slot, req.amount_usdt_micro, &req.wallet_address) {
        Ok(a) => a,
        Err(e) => {
            warn!("⚠️  Vault signer failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Signing failed: {}", e)
            })));
        }
    };

    info!("✅ Claim attestation issued: slot={} burn_id={} amount={} wallet={}",
        burn.poh_slot, &req.burn_id[..8], req.amount_usdt_micro,
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
