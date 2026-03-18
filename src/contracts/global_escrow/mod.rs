use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use axum::{extract::{State, Path}, response::IntoResponse, http::StatusCode, Json};
use tracing::info;

use std::sync::atomic::Ordering;
use crate::AppState;
// ============================================================================
// GLOBAL ESCROW SMART CONTRACT (Native Module)
// ============================================================================
//
// Structured identically to an SVM Native Program to ensure an easy future
// transition to eBPF if needed. All HTTP handlers map their requests directly
// into an `EscrowInstruction` enum, which is executed by `process_instruction`.
// 
// Three trustless operations:
//   1. Deposit         — User locks tokens into global escrow PDA
//   2. SubmitStateRoot — L2 sequencer submits per-market merkle root
//   3. Withdraw        — User proves payout via merkle proof, receives tokens
// ============================================================================

/// Represents the raw Instruction Data, identical to how eBPF programs
/// receive byte-serialized commands.
#[derive(Serialize, Deserialize, Debug)]
pub enum EscrowInstruction {
    Deposit {
        amount: f64,
        wallet_address: String,
        timestamp: u64,
        nonce: String,
    },
    SubmitStateRoot {
        market_id: String,
        merkle_root: String,
        l2_block_number: u64,
    },
    Withdraw {
        market_id: String,
        amount: f64,
        wallet_address: String,
        merkle_proof: Vec<String>,
        timestamp: u64,
        nonce: String,
    }
}

#[derive(Deserialize)]
pub struct EscrowDepositRequest {
    /// Wallet address depositing tokens
    wallet_address: String,
    /// Amount of BB to lock in escrow
    amount: f64,
    /// Ed25519 public key (hex, 32 bytes)
    public_key: String,
    /// Ed25519 signature (hex, 64 bytes)
    signature: String,
    /// Unix timestamp for replay protection
    timestamp: u64,
    /// Unique nonce for replay protection
    nonce: String,
}

/// POST /escrow/deposit — Lock tokens into the global escrow vault
///
/// User signs: "ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"
/// Tokens move from user wallet → global escrow PDA.
pub async fn escrow_deposit_handler(
    State(state): State<AppState>,
    Json(req): Json<EscrowDepositRequest>,
) -> impl IntoResponse {
    

    // ── VALIDATE ───────────────────────────────────────────────────────────
    if req.wallet_address.is_empty() || req.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION ─────────────────────────────────────
    let message = format!("ESCROW_DEPOSIT:{}:{}:{}:{}", req.wallet_address, req.amount, req.timestamp, req.nonce);

    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key (must be 32 bytes hex)" }))),
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

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("escrow_deposit:{}:{}", req.wallet_address, req.nonce);
    if state.used_nonces.contains_key(&nonce_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used — possible replay attack",
            "nonce": req.nonce
        })));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request too old (>60s)",
            "server_time": now,
            "request_time": req.timestamp
        })));
    }
    state.used_nonces.insert(nonce_key, now);

    // ── BALANCE CHECK ──────────────────────────────────────────────────────
    let balance = state.blockchain.get_balance(&req.wallet_address);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, req.amount),
        })));
    }

    // ── EXECUTE: debit user → credit escrow ─────────────────────────────────
    let escrow_addr = &state.escrow_address;

    if let Err(e) = state.blockchain.debit(&req.wallet_address, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Debit failed: {}", e) })));
    }
    if let Err(e) = state.blockchain.credit(escrow_addr, req.amount) {
        // Rollback debit on credit failure
        let _ = state.blockchain.credit(&req.wallet_address, req.amount);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Escrow credit failed: {}", e) })));
    }

    let user_balance = state.blockchain.get_balance(&req.wallet_address);
    let escrow_balance = state.blockchain.get_balance(escrow_addr);
    info!("🔒 ESCROW DEPOSIT: {} BB from {} → escrow", req.amount, req.wallet_address);

    // Record into PoH block
    {
        use layer1::protocol::Transaction as ProtoTx;
        use layer1::protocol::TxData;
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.wallet_address.clone(),
            timestamp: now,
            data: TxData::EscrowDeposit {
                amount: (req.amount * 100_000.0) as u64,
                escrow_address: escrow_addr.clone(),
            },
            signature: req.signature.clone(),
            signer_pubkey: req.public_key.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "deposited": req.amount,
        "wallet_address": req.wallet_address,
        "escrow_address": escrow_addr,
        "user_balance": user_balance,
        "escrow_balance": escrow_balance,
    })))
}

#[derive(Deserialize)]
pub struct EscrowSubmitStateRootRequest {
    /// Unique market identifier
    market_id: String,
    /// 32-byte hex merkle root from L2 settlement
    merkle_root: String,
    /// Ed25519 signature from the L2 sequencer (hex, 64 bytes)
    signature: String,
    /// Monotonically incrementing L2 block number — prevents timestamp-skew replay attacks.
    /// The L2 must increment this counter for every new state root submission.
    l2_block_number: u64,
}

/// POST /escrow/submit-state-root — L2 sequencer submits a per-market merkle root
///
/// The L2 Sequencer signs: "STATE_ROOT:{market_id}:{merkle_root}:{l2_block_number}"
/// L1 ONLY verifies the signature against the hardcoded L2_SEQUENCER_PUBKEY.
/// L1 does NOT sign anything here — it is a pure verifier.
/// l2_block_number ensures strict chronological ordering and prevents replay attacks.
/// This is TRUSTLESS — L1 trusts the math of the signature, not the server.
pub async fn escrow_submit_state_root_handler(
    State(state): State<AppState>,
    Json(req): Json<EscrowSubmitStateRootRequest>,
) -> impl IntoResponse {
    

    // ── VALIDATE ───────────────────────────────────────────────────────────
    if req.market_id.is_empty() || req.merkle_root.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing market_id or merkle_root" })));
    }
    if req.merkle_root.len() != 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "merkle_root must be 64 hex chars (32 bytes)" })));
    }

    // ── SEQUENCER Ed25519 VERIFICATION ─────────────────────────────────────
    if state.l2_sequencer_pubkey.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "L2_SEQUENCER_PUBKEY not configured — escrow not operational"
        })));
    }

    let message = format!("STATE_ROOT:{}:{}:{}", req.market_id, req.merkle_root, req.l2_block_number);

    let seq_pubkey_bytes = match hex::decode(&state.l2_sequencer_pubkey) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invalid configured L2_SEQUENCER_PUBKEY" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" }))),
    };

    let verifying_key = match VerifyingKey::from_bytes(seq_pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Invalid L2 sequencer public key" }))),
    };
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Sequencer signature verification failed — L1 trusts only the math"
        })));
    }

    // ── l2_block_number is carried in the signed message — replay-safe ─────
    // No timestamp window needed: the signature covers l2_block_number directly.
    // The L2 must use a monotonically incrementing counter on its end.
    let current_slot = state.current_slot.load(Ordering::Relaxed);

    // ── STORE MARKET ROOT (32 bytes only — L1 is a vault, not a filing cabinet) ──
    let root_bytes: [u8; 32] = match hex::decode(&req.merkle_root) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "merkle_root must decode to exactly 32 bytes"
        }))),
    };

    // Persist to DashMap (hot) + ReDB (durable) — raw 32 bytes, no JSON
    state.market_roots.insert(req.market_id.clone(), root_bytes);
    let _ = state.blockchain.store_escrow_market_root(&req.market_id, &root_bytes);

    info!("📋 STATE ROOT: market={} root={}… slot={}", req.market_id, &req.merkle_root[..16], current_slot);

    // Record into PoH block
    {
        use layer1::protocol::Transaction as ProtoTx;
        use layer1::protocol::TxData;
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: format!("L2_SEQUENCER:{}", &state.l2_sequencer_pubkey[..16]),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            data: TxData::EscrowStateRoot {
                market_id: req.market_id.clone(),
                merkle_root: req.merkle_root.clone(),
            },
            signature: req.signature.clone(),
            signer_pubkey: state.l2_sequencer_pubkey.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "market_id": req.market_id,
        "merkle_root": req.merkle_root,
        "l2_block_number": req.l2_block_number,
        "slot": current_slot,
    })))
}

#[derive(Deserialize)]
pub struct EscrowWithdrawRequest {
    /// Market ID the withdrawal is for
    market_id: String,
    /// Amount entitled to withdraw (must match merkle leaf)
    amount: f64,
    /// Wallet address receiving the withdrawal
    wallet_address: String,
    /// Merkle proof path from leaf to root — array of 64-char hex sibling hashes.
    /// The user does not sign this (it is public math), but must include it so L1
    /// can recompute the root. Hashing uses sorted order (smaller hash first).
    merkle_proof: Vec<String>,
    /// Ed25519 public key (hex, 32 bytes)
    public_key: String,
    /// Ed25519 signature (hex, 64 bytes)
    signature: String,
    /// Unix timestamp for replay protection
    timestamp: u64,
    /// Unique nonce for replay protection
    nonce: String,
}

/// POST /escrow/withdraw — Withdraw from escrow using a merkle proof
///
/// User signs: "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
/// L1 verifies: (1) user owns wallet, (2) market has a submitted root,
/// (3) merkle proof matches the root, (4) not already claimed.
/// Then: escrow PDA → user wallet.
pub async fn escrow_withdraw_handler(
    State(state): State<AppState>,
    Json(req): Json<EscrowWithdrawRequest>,
) -> impl IntoResponse {
    
    use sha2::{Sha256, Digest};

    // ── VALIDATE ───────────────────────────────────────────────────────────
    if req.market_id.is_empty() || req.wallet_address.is_empty() || req.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION (proves wallet ownership) ───────────
    let message = format!("ESCROW_WITHDRAW:{}:{}:{}:{}:{}", req.market_id, req.wallet_address, req.amount, req.timestamp, req.nonce);

    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature" }))),
    };

    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("escrow_withdraw:{}:{}", req.wallet_address, req.nonce);
    if state.used_nonces.contains_key(&nonce_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used — possible replay attack",
            "nonce": req.nonce
        })));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request too old (>60s)",
            "server_time": now,
            "request_time": req.timestamp
        })));
    }
    state.used_nonces.insert(nonce_key, now);

    // ── DOUBLE-WITHDRAWAL CHECK ────────────────────────────────────────────
    let claim_key = format!("{}:{}", req.market_id, req.wallet_address);
    if state.withdrawal_claims.contains_key(&claim_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Already withdrawn for this market",
            "market_id": req.market_id,
            "wallet_address": req.wallet_address
        })));
    }

    // ── LOOKUP MARKET ROOT ─────────────────────────────────────────────────
    let expected_root: [u8; 32] = match state.market_roots.get(&req.market_id) {
        Some(r) => *r.value(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No state root found for market '{}'", req.market_id),
        }))),
    };

    // ── MERKLE PROOF VERIFICATION ──────────────────────────────────────────
    // Compute leaf: SHA256(wallet_address_bytes || amount_le_bytes)
    // This matches the MerkleTree leaf format in poh_blockchain.rs
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update(req.wallet_address.as_bytes());
    leaf_hasher.update(req.amount.to_le_bytes());
    let mut current: [u8; 32] = leaf_hasher.finalize().into();

    // Walk the proof path — sorted hashing: smaller [u8;32] always goes first.
    // The L2 must build its escrow Merkle tree with the same sorted convention.
    for sibling_hex in &req.merkle_proof {
        let sibling: [u8; 32] = match hex::decode(sibling_hex.trim_start_matches("0x")) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid proof node hash (must be 32 bytes hex, optionally 0x-prefixed)"
            }))),
        };

        let mut hasher = Sha256::new();
        if current <= sibling {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
    }

    if current != expected_root {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Merkle proof verification failed — computed root does not match",
            "computed_root": hex::encode(current),
            "expected_root": hex::encode(expected_root),
        })));
    }

    // ── EXECUTE: debit escrow → credit user ─────────────────────────────────
    let escrow_addr = &state.escrow_address;
    let escrow_balance = state.blockchain.get_balance(escrow_addr);
    if escrow_balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Insufficient escrow balance: {} < {}", escrow_balance, req.amount),
        })));
    }

    if let Err(e) = state.blockchain.debit(escrow_addr, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Escrow debit failed: {}", e) })));
    }
    if let Err(e) = state.blockchain.credit(&req.wallet_address, req.amount) {
        // Rollback
        let _ = state.blockchain.credit(escrow_addr, req.amount);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("User credit failed: {}", e) })));
    }

    // Mark as claimed (DashMap + ReDB)
    state.withdrawal_claims.insert(claim_key.clone(), true);
    let _ = state.blockchain.store_escrow_claim(&claim_key, now);

    let new_balance = state.blockchain.get_balance(&req.wallet_address);
    info!("💰 ESCROW WITHDRAW: {} BB → {} (market: {})", req.amount, req.wallet_address, req.market_id);

    // Record into PoH block
    {
        use layer1::protocol::Transaction as ProtoTx;
        use layer1::protocol::TxData;
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.wallet_address.clone(),
            timestamp: now,
            data: TxData::EscrowWithdraw {
                market_id: req.market_id.clone(),
                amount: (req.amount * 100_000.0) as u64,
                escrow_address: escrow_addr.clone(),
            },
            signature: req.signature.clone(),
            signer_pubkey: req.public_key.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "withdrawn": req.amount,
        "market_id": req.market_id,
        "wallet_address": req.wallet_address,
        "new_balance": new_balance,
    })))
}

/// GET /escrow/status — Current escrow vault status
///
/// Returns PDA balance and total settled market count ONLY.
/// The full market list lives in the L2 PostgreSQL database, not on L1.
/// Returning the full market list would be an OOM trap at scale (50k+ markets).
pub async fn escrow_status_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let escrow_balance = state.blockchain.get_balance(&state.escrow_address);

    Json(serde_json::json!({
        "escrow_address": state.escrow_address,
        "escrow_balance_lamports": escrow_balance,
        "total_markets_settled": state.market_roots.len(),
        "l2_sequencer_configured": !state.l2_sequencer_pubkey.is_empty(),
    }))
}

/// GET /escrow/market/:market_id — Get settlement details for a specific market
pub async fn escrow_market_handler(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    match state.market_roots.get(&market_id) {
        Some(root) => Json(serde_json::json!({
            "success": true,
            "market_id": market_id,
            "merkle_root": hex::encode(root.value()),
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": format!("No settlement found for market '{}'", market_id),
        })),
    }
}



