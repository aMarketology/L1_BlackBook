// ============================================================================
// UNIVERSAL ROLLUP HUB — Multi-Tenant L2/L3/L5 Bridge
// ============================================================================
//
// URL shape: /rollup/:rollup_id/<action>
//   :rollup_id  —  "L2" | "L3" | "L5"  (maps to an authorized sequencer pubkey)
//
// POST /rollup/:rollup_id/lock_bb
//   Creators lock native $BB on L1 to seed initial liquidity.
//   Funds go to the rollup-specific vault PDA.
//
// POST /rollup/:rollup_id/submit_root
//   The registered sequencer posts the 32-byte Merkle root after each batch.
//   Stored in ROLLUP_STATE_ROOTS (ReDB) keyed by "{rollup_id}:{batch_id}".
//
// POST /rollup/:rollup_id/exit
//   Users exit back to L1 by supplying a Merkle proof of their balance.
//   Supports asset_type="BB" (release lamports) and asset_type="NFT" (mint NFT).
//
// GET  /rollup/:rollup_id/locks/:lock_id
//   L5/L2/L3 sequencer reads a specific lock record before crediting rollup funds.
//
// GET  /rollup/:rollup_id/locks/creator/:creator_address
//   Wallet UI lists unconsumed locks for the signed-in address. Read-only.
//
// POST /rollup/:rollup_id/locks/:lock_id/consume
//   Sequencer marks a lock as spent (idempotent, prevents double-credit).
// ============================================================================

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::Deserialize;
use axum::{
    extract::{State, Path},
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use borsh::BorshSerialize;
use sha2::{Sha256, Digest};
use tracing::info;

use crate::AppState;
use crate::storage::RollupLockRecord;
use crate::svm::pda::rollup_vault_address;

// ─── Borsh-canonical Merkle leaf structs ──────────────────────────────────────
//
// These structs define the wire format for Merkle leaf serialization.
// Using Borsh (not JSON or UTF-8 strings) guarantees byte-identical output
// between this Rust verifier and the TypeScript L2 sequencer (merkle.ts).
//
// Borsh encoding rules:
//   String  → u32_LE(len) || utf8_bytes
//   [u8;32] → 32 raw bytes (fixed-size, no length prefix)
//   u64     → 8 bytes little-endian
//
// CRITICAL: field order must match `buildLeafBytes()` in merkle.ts exactly.

/// Canonical BB balance leaf.
#[derive(BorshSerialize)]
struct BbClaimLeaf<'a> {
    /// "L2", "L3", or "L5"
    rollup_id: &'a str,
    /// Always "BB"
    token: &'a str,
    /// 32-byte Ed25519 public key (bs58-decoded wallet address)
    address: [u8; 32],
    /// Balance in $BB lamports (1 BB = 100_000 lamports)
    lamports: u64,
}

/// Canonical NFT ownership leaf.
#[derive(BorshSerialize)]
struct NftClaimLeaf<'a> {
    rollup_id: &'a str,
    /// Always "NFT"
    token: &'a str,
    collection_id: &'a str,
    token_id: &'a str,
    /// 32-byte Ed25519 public key of the current owner
    owner: [u8; 32],
    /// SHA-256 hex of the NFT metadata JSON (64 ASCII chars)
    metadata_hash: &'a str,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Request / response shapes
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LockBbRequest {
    /// Creator's L1 wallet address.
    pub wallet_address: String,
    /// Amount to lock, in $BB lamports (1 BB = 100_000 lamports). No floats.
    pub bb_lamports: u64,
    /// Optional symbol the creator intends to launch on L5 (informational only).
    #[serde(default)]
    pub token_symbol_hint: Option<String>,
    /// Ed25519 public key of the creator (hex, 32 bytes).
    pub public_key: String,
    /// Ed25519 signature (hex, 64 bytes).
    /// Signed message: "ROLLUP_LOCK_BB:{rollup_id}:{wallet_address}:{bb_lamports}:{token_symbol_hint}:{timestamp}:{nonce}"
    pub signature: String,
    /// Unix timestamp (seconds) for freshness check (±60 s window).
    pub timestamp: u64,
    /// Unique nonce for replay protection.
    pub nonce: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────────────────────

/// POST /rollup/:rollup_id/lock_bb — Creator locks $BB to seed rollup initial liquidity.
pub async fn lock_bb_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
    Json(req): Json<LockBbRequest>,
) -> impl IntoResponse {
    // ── Validate rollup_id ─────────────────────────────────────────────────────────────
    if rollup_id.is_empty() || rollup_id.len() > 8 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid rollup_id"
        })));
    }
    // ── BASIC VALIDATION ───────────────────────────────────────────────────
    if req.wallet_address.is_empty() || req.bb_lamports == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "wallet_address and bb_lamports are required and must be non-zero"
        })));
    }
    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "wallet_address must be a valid 32-byte base58 Ed25519 address"
        })));
    }

    if let Some(ref sym) = req.token_symbol_hint {
        // Only uppercase alphanumeric + underscore, 1–12 chars
        if sym.is_empty() || sym.len() > 12 || !sym.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "token_symbol_hint must be 1–12 uppercase alphanumeric/underscore chars"
            })));
        }
    }

    // ── TIMESTAMP FRESHNESS (±60s) ─────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp out of ±60s freshness window",
            "server_time": now,
            "request_time": req.timestamp
        })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION + PUBKEY → WALLET BINDING ───────────
    let symbol_hint_str = req.token_symbol_hint.as_deref().unwrap_or("");
    let message = format!(
        "ROLLUP_LOCK_BB:{}:{}:{}:{}:{}:{}",
        rollup_id, req.wallet_address, req.bb_lamports, symbol_hint_str, req.timestamp, req.nonce
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

    let pubkey_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };

    // CRITICAL P0 GUARD: signing public_key MUST own wallet_address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match wallet_address",
            "derived": derived_address,
        })));
    }
    let signer_pk = solana_sdk::pubkey::Pubkey::new_from_array(*pubkey_arr);
    if crate::svm::pda::is_reserved_pda(&signer_pk) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "Reserved protocol PDA cannot lock funds"
        })));
    }

    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature length" }))),
    };
    let signature = Signature::from_bytes(sig_arr);

    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Signature verification failed"
        })));
    }

    // ── ATOMIC REPLAY PROTECTION ───────────────────────────────────────────
    let nonce_key = format!("rollup_lock:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": req.nonce
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
            let _ = state.blockchain.record_used_nonce(&nonce_key, now);
        }
    }

    // ── ATOMIC: debit user + credit vault + persist lock record — single ReDB txn ─
    let vault_addr = rollup_vault_address(&rollup_id);
    // Replaces the previous three-step write (debit hot, credit hot, persist ReDB).
    // A single commit means there is no double-spend window where the lock record
    // is readable by the sequencer but the user's L1 debit was never persisted.
    let lock_id = uuid::Uuid::new_v4().to_string();
    let record = RollupLockRecord {
        lock_id: lock_id.clone(),        rollup_id: rollup_id.clone(),        creator_address: req.wallet_address.clone(),
        bb_lamports: req.bb_lamports,
        token_symbol_hint: req.token_symbol_hint.clone(),
        locked_at: now,
        vault_address: vault_addr.clone(),
        consumed: false,
    };

    if let Err(e) = state.blockchain.atomic_rollup_lock_bb(
        &req.wallet_address, &vault_addr, req.bb_lamports, &record,
    ) {
        tracing::error!("Atomic rollup lock failed: {}", e);
        if e.contains("Insufficient funds") {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": e
            })));
        }
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Lock aborted — {}", e)
        })));
    }

    // Hot-cache so the rollup sequencer poller can read without hitting ReDB
    state.rollup_lock_records.insert(lock_id.clone(), record);

    // Anchor the 1:1 $BB lock onto the L1 PoH clock + transparent ledger
    // (TransferBb from user → rollup vault keeps Reader nodes and SubscribeBalances in sync)
    {
        use crate::protocol::{Transaction as ProtoTx, TxData};
        let proto_tx = ProtoTx {
            hash: lock_id.clone(),
            from: req.wallet_address.clone(),
            timestamp: now,
            data: TxData::TransferBb {
                to: vault_addr.clone(),
                amount: req.bb_lamports,
            },
            signature: req.signature.clone(),
            signer_pubkey: req.public_key.clone(),
        };
        state.poh.write().queue_transaction(lock_id.clone());
        state.block_producer.record_executed_transaction(proto_tx);

        let user_after = state.blockchain.get_balance_lamports(&req.wallet_address);
        let vault_after = state.blockchain.get_balance_lamports(&vault_addr);
        let mut tx_record = crate::storage::TransactionRecord::with_id(
            lock_id.clone(),
            crate::storage::TxType::Lock,
            &req.wallet_address,
            &vault_addr,
            req.bb_lamports,
            0,
            user_after.saturating_add(req.bb_lamports),
            user_after,
            vault_after,
            crate::storage::AuthType::Ed25519,
        );
        tx_record.metadata = Some(serde_json::json!({
            "kind": "rollup_lock",
            "rollup_id": rollup_id,
            "lock_id": lock_id,
            "token_symbol_hint": req.token_symbol_hint,
        }));
        if let Err(e) = state.blockchain.log_transaction(tx_record) {
            tracing::warn!("Failed to log rollup lock receipt: {}", e);
        } else if let Err(e) = state.blockchain.flush_tx_log_buffer() {
            tracing::warn!("Failed to flush rollup lock receipt: {}", e);
        }
    }

    info!(
        "🔒 ROLLUP LOCK: {} lamports ({:.5} BB) from {} → vault {} (lock_id: {})",
        req.bb_lamports,
        req.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        req.wallet_address,
        vault_addr,
        lock_id,
    );

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "lock_id": lock_id,
        "vault_address": vault_addr,
        "creator_address": req.wallet_address,
        "delta_lamports": req.bb_lamports,
        "token_symbol_hint": req.token_symbol_hint,
        "poh_slot": state.current_slot.load(std::sync::atomic::Ordering::Relaxed)
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /rollup/locks/:lock_id
//  L5 sequencer verifies a specific lock before crediting rollup-$BB.
// ─────────────────────────────────────────────────────────────────────────────

/// GET /rollup/:rollup_id/locks/:lock_id
/// Returns the full RollupLockRecord for a given lock_id so the sequencer
/// can verify the lock exists, is unconsumed, and the amounts are correct.
pub async fn get_lock_by_id_handler(
    State(state): State<AppState>,
    Path((_rollup_id, lock_id)): Path<(String, String)>,
) -> impl IntoResponse {
    // Try hot cache first for latency
    if let Some(record) = state.rollup_lock_records.get(&lock_id) {
        return (StatusCode::OK, Json(serde_json::to_value(record.value()).unwrap_or(serde_json::Value::Null)));
    }
    // Fall back to ReDB (lock may have been loaded before cache was populated)
    match state.blockchain.load_rollup_lock_by_id(&lock_id) {
        Some(record) => (StatusCode::OK, Json(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null))),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("Lock {} not found", lock_id) }))),
    }
}

/// GET /rollup/:rollup_id/locks/creator/:creator_address
/// Unconsumed locks for one wallet. Read-only. Does not move funds.
pub async fn get_locks_by_creator_handler(
    State(state): State<AppState>,
    Path((rollup_id, creator_address)): Path<(String, String)>,
) -> impl IntoResponse {
    if rollup_id.is_empty() || rollup_id.len() > 8 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid rollup_id"
        }))).into_response();
    }
    if creator_address.is_empty() || creator_address.len() > 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid creator address"
        }))).into_response();
    }
    match state.blockchain.load_rollup_locks_by_creator(&creator_address) {
        Ok(locks) => {
            let pending: Vec<RollupLockRecord> = locks
                .into_iter()
                .filter(|lock| lock.rollup_id == rollup_id && !lock.consumed)
                .collect();
            (StatusCode::OK, Json(pending)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to load locks: {e}")
        }))).into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /rollup/:rollup_id/roots/:batch_id
//  Read a stored Merkle state root for debugging / smoke tests.
// ─────────────────────────────────────────────────────────────────────────────

/// GET /rollup/:rollup_id/roots/:batch_id — return the 64-char hex Merkle root
/// that was anchored on-chain for the given batch, or 404 if not found.
/// GET /rollup/:rollup_id/exited/:address — lamports already released to this wallet.
/// Read-only. Does not change the watermark.
pub async fn get_exit_watermark_handler(
    State(state): State<AppState>,
    Path((rollup_id, address)): Path<(String, String)>,
) -> impl IntoResponse {
    let exit_id_input = format!("{}:BB:{}", rollup_id, address.to_lowercase());
    let exit_id = sha256_hex(&exit_id_input);
    let withdrawn = match state.blockchain.get_cumulative_exit(&exit_id) {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to read exit watermark (fail-closed): {}", e)
                })),
            );
        }
    };
    (StatusCode::OK, Json(serde_json::json!({
        "rollup_id": rollup_id,
        "address": address,
        "already_withdrawn_lamports": withdrawn,
    })))
}

pub async fn get_root_handler(
    State(state): State<AppState>,
    Path((rollup_id, batch_id)): Path<(String, u64)>,
) -> impl IntoResponse {
    match state.blockchain.load_rollup_state_root(&rollup_id, batch_id) {
        Some(root_bytes) => {
            let root_hex = hex::encode(root_bytes);
            (StatusCode::OK, Json(serde_json::json!({
                "rollup_id": rollup_id,
                "batch_id": batch_id,
                "merkle_root": root_hex,
            })))
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No root found for rollup={} batch={}", rollup_id, batch_id)
        }))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /rollup/locks/:lock_id/consume
//  L5 sequencer marks a lock as spent after crediting rollup-$BB.
//  Idempotent — safe to call again if the sequencer retries.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConsumeLockRequest {
    /// Ed25519 public key of the L5 sequencer (hex, 32 bytes).
    pub sequencer_public_key: String,
    /// Signature over "CONSUME_LOCK:{lock_id}:{timestamp}".
    pub signature: String,
    /// Unix timestamp (seconds) — freshness window ±60 s.
    pub timestamp: u64,
}

/// POST /rollup/:rollup_id/locks/:lock_id/consume
/// Marks a lock as consumed. Only the registered sequencer for this rollup may call this.
pub async fn consume_lock_handler(
    State(state): State<AppState>,
    Path((rollup_id, lock_id)): Path<(String, String)>,
    Json(req): Json<ConsumeLockRequest>,
) -> impl IntoResponse {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── Freshness ──────────────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp out of ±60 s window."
        })));
    }

    // ── Sequencer identity: look up the registered pubkey for this rollup_id ─
    let expected_pubkey = match state.authorized_sequencers.get(&rollup_id) {
        Some(pk) => pk.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": format!("No sequencer registered for rollup_id '{}'", rollup_id)
        }))),
    };
    if req.sequencer_public_key != expected_pubkey {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": format!("Only the registered {} sequencer can consume locks.", rollup_id)
        })));
    }

    // ── Ed25519 signature ─────────────────────────────────────────────────
    let pk_bytes = match hex::decode(&req.sequencer_public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "sequencer_public_key must be 32-byte hex."
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 64-byte hex."
        }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad sequencer key." }))),
    };
    let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    let message = format!("CONSUME_LOCK:{}:{}:{}", rollup_id, lock_id, req.timestamp);
    if verifying_key.verify(message.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Signature verification failed."
        })));
    }

    // ── Mark consumed. A second consume is a hard error, not a no-op. ─────
    if let Err(e) = state.blockchain.consume_rollup_lock(&lock_id) {
        if e == "already_consumed" {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Lock already consumed",
                "lock_id": lock_id
            })));
        }
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": e })));
    }

    // Update hot cache
    if let Some(mut entry) = state.rollup_lock_records.get_mut(&lock_id) {
        entry.consumed = true;
    }

    info!("✅ LOCK CONSUMED: {}", lock_id);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "lock_id": lock_id,
        "message": "Lock marked as consumed. Rollup-$BB already credited on L5."
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /rollup/submit_root
//  L5 sequencer posts a new Merkle root after sealing each batch.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubmitRootRequest {
    /// Strictly-increasing batch index (L5 Sequencer.batchIndex).
    pub batch_id: u64,
    /// 64-char hex string representing the 32-byte SHA-256 Merkle root.
    pub merkle_root_hex: String,
    /// Ed25519 public key of the sequencer (hex, 32 bytes).
    pub sequencer_public_key: String,
    /// Ed25519 signature over "ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{timestamp}".
    pub signature: String,
    /// Unix timestamp (seconds) — freshness window ±60 s.
    pub timestamp: u64,
    /// Optional cumulative sum of all exit leaves in this Merkle root (lamports).
    /// When supplied, L1 verifies `total_cumulative_lamports <= total_locked_ever_lamports`
    /// so even a compromised sequencer cannot anchor a root exceeding locked supply.
    #[serde(default)]
    pub total_cumulative_lamports: Option<u64>,
}

/// POST /rollup/:rollup_id/submit_root — anchor a new state root on L1.
pub async fn submit_root_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
    Json(req): Json<SubmitRootRequest>,
) -> impl IntoResponse {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── Timestamp freshness ─────────────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp out of ±60 s freshness window."
        })));
    }

    // ── Sequencer identity: verify against registered pubkey for this rollup ──
    let expected_pubkey = match state.authorized_sequencers.get(&rollup_id) {
        Some(pk) => pk.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": format!("No sequencer registered for rollup_id '{}'", rollup_id)
        }))),
    };
    if req.sequencer_public_key != expected_pubkey {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": format!("Signature key does not match the registered {} sequencer.", rollup_id)
        })));
    }

    // ── Merkle root format ─────────────────────────────────────────────────
    if req.merkle_root_hex.len() != 64 || !req.merkle_root_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "merkle_root_hex must be exactly 64 lowercase hex characters (32 bytes)."
        })));
    }

    // ── Ed25519 signature verification ─────────────────────────────────────
    let pk_bytes = match hex::decode(&req.sequencer_public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "sequencer_public_key must be 32-byte hex."
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 64-byte hex."
        }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid sequencer public key."
        }))),
    };
    let signature = match Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap()) {
        sig => sig,
    };
    let message = format!(
        "ROLLUP_SUBMIT_ROOT:{}:{}:{}:{}",
        rollup_id, req.batch_id, req.merkle_root_hex, req.timestamp
    );
    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid sequencer signature."
        })));
    }

    // ── Decode root bytes ──────────────────────────────────────────────────
    let root_hex_lower = req.merkle_root_hex.to_lowercase();
    let mut root_bytes = [0u8; 32];
    for i in 0..32 {
        root_bytes[i] = u8::from_str_radix(&root_hex_lower[i * 2..i * 2 + 2], 16)
            .expect("hex already validated");
    }

    // ── Supply cap guard: cumulative exit total must never exceed on-chain locked supply ──
    let total_locked_ever = state.blockchain.get_rollup_total_locked(&rollup_id);
    if let Some(claimed_total) = req.total_cumulative_lamports {
        if claimed_total > total_locked_ever {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": format!(
                    "Root rejected: claimed cumulative exits ({} lamports) exceed total locked ever ({} lamports) for rollup '{}'",
                    claimed_total, total_locked_ever, rollup_id
                ),
                "claimed_cumulative_lamports": claimed_total,
                "total_locked_ever_lamports": total_locked_ever,
            })));
        }
    }

    // ── Persist (per-rollup monotonicity enforced inside storage) ─────────────────
    if let Err(e) = state.blockchain.store_rollup_state_root(&rollup_id, req.batch_id, root_bytes) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": format!("Root rejected: {}", e)
        })));
    }

    // Anchor the rollup Merkle state root on the L1 PoH clock
    {
        use crate::protocol::{Transaction as ProtoTx, TxData};
        let tx_hash = format!("rollup_root_{}_{}", rollup_id, req.batch_id);
        let proto_tx = ProtoTx {
            hash: tx_hash.clone(),
            from: req.sequencer_public_key.clone(),
            timestamp: now,
            data: TxData::EscrowStateRoot {
                market_id: format!("{}:batch:{}", rollup_id, req.batch_id),
                merkle_root: req.merkle_root_hex.clone(),
            },
            signature: req.signature.clone(),
            signer_pubkey: req.sequencer_public_key.clone(),
        };
        state.poh.write().queue_transaction(tx_hash);
        state.block_producer.record_executed_transaction(proto_tx);
    }

    info!(
        "🌳 ROLLUP ROOT: rollup={} batch_id={} root={}",
        rollup_id, req.batch_id, req.merkle_root_hex
    );

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "rollup_id": rollup_id,
        "batch_id": req.batch_id,
        "merkle_root_hex": req.merkle_root_hex,
        "poh_slot": state.current_slot.load(std::sync::atomic::Ordering::Relaxed),
        "message": format!("{} state root anchored on L1.", rollup_id)
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /rollup/:rollup_id/exit
//  Universal exit handler: verifies Borsh-canonical Merkle proof, then routes
//  to either $BB lamport release or L3 NFT mint depending on asset_type.
//
//  Leaf encoding (Borsh binary — sequencer MUST use buildLeafBytes() in merkle.ts):
//
//   BB leaf:  SHA-256( borsh(BbClaimLeaf { rollup_id, "BB", address[32], lamports }) )
//   NFT leaf: SHA-256( borsh(NftClaimLeaf { rollup_id, "NFT", collection_id, token_id, owner[32], metadata_hash }) )
//
//  Borsh guarantees identical byte layout across Rust + TypeScript:
//   String → u32_LE(len) || utf8  |  [u8;32] → raw bytes  |  u64 → 8 bytes LE
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ExitRequest {
    /// Rollup wallet address that owns the balance being claimed.
    pub address: String,
    /// Asset type: "BB" (release lamports) or "NFT" (mint NFT on L1).
    pub asset_type: String,

    // ── BB-specific fields (required when asset_type == "BB") ──────────────
    /// Claimed balance in $BB lamports (omit for NFT exits).
    pub balance_lamports: Option<u64>,

    // ── NFT-specific fields (required when asset_type == "NFT") ───────────
    /// NFT collection identifier (e.g. "BLACKBOOK_GENESIS").
    pub collection_id: Option<String>,
    /// Token ID within the collection (arbitrary string, e.g. "genesis-001" or "42").
    pub nft_token_id: Option<String>,
    /// IPFS / Arweave URI for the NFT metadata JSON.
    pub metadata_uri: Option<String>,
    /// SHA-256 hex of the metadata JSON (content-addressed integrity check).
    pub metadata_hash: Option<String>,

    // ── Common proof fields ────────────────────────────────────────────────
    /// batch_id whose stored state root to verify against.
    pub batch_id: u64,
    /// Merkle proof sibling hashes (hex strings, bottom-up from leaf to root).
    pub proof_siblings: Vec<String>,
    /// For each sibling: true = sibling is on the right of current node.
    pub sibling_is_right: Vec<bool>,
    /// Ed25519 public key of the exiting user (hex, 32 bytes).
    pub public_key: String,
    /// Signature over "ROLLUP_EXIT:{rollup_id}:{asset_type}:{address}:{batch_id}:{timestamp}:{nonce}".
    pub signature: String,
    /// Unix timestamp (seconds) — freshness window ±60 s.
    pub timestamp: u64,
    /// Random nonce for replay protection.
    pub nonce: String,
}

/// SHA-256 of raw bytes → lowercase hex digest.
fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// SHA-256 of a UTF-8 string → lowercase hex (used for sibling combines only).
fn sha256_hex(data: &str) -> String {
    sha256_hex_bytes(data.as_bytes())
}

/// Hash two sibling nodes sorted so order is deterministic (same as sequencer logic).
/// Siblings are 64-char hex strings; concatenated as ASCII then SHA-256'd.
fn hash_pair(a: &str, b: &str) -> String {
    if a <= b {
        sha256_hex(&format!("{}{}", a, b))
    } else {
        sha256_hex(&format!("{}{}", b, a))
    }
}

/// Compute the Borsh-canonical leaf hash for a BB balance entry.
/// leaf_hash = SHA-256( borsh(BbClaimLeaf) )
pub(crate) fn bb_leaf_hash(rollup_id: &str, address_bytes: [u8; 32], lamports: u64) -> String {
    let leaf = BbClaimLeaf { rollup_id, token: "BB", address: address_bytes, lamports };
    let bytes = borsh::to_vec(&leaf).expect("BbClaimLeaf borsh serialize is infallible");
    sha256_hex_bytes(&bytes)
}

/// Compute the Borsh-canonical leaf hash for an NFT ownership entry.
/// leaf_hash = SHA-256( borsh(NftClaimLeaf) )
pub(crate) fn nft_leaf_hash(
    rollup_id: &str,
    collection_id: &str,
    token_id: &str,
    owner_bytes: [u8; 32],
    metadata_hash: &str,
) -> String {
    let leaf = NftClaimLeaf {
        rollup_id, token: "NFT", collection_id, token_id,
        owner: owner_bytes, metadata_hash,
    };
    let bytes = borsh::to_vec(&leaf).expect("NftClaimLeaf borsh serialize is infallible");
    sha256_hex_bytes(&bytes)
}

/// Walk the Merkle proof and return the computed root hash.
/// The leaf_hash is already a 64-char hex string (output of bb_leaf_hash / nft_leaf_hash).
/// Sibling combine uses sorted-pair hex-string SHA-256 (same as merkle.ts hashPair).
fn verify_merkle_proof(
    leaf_hash: &str,
    siblings: &[String],
    is_right: &[bool],
) -> String {
    let mut current = leaf_hash.to_string();
    for (i, sibling) in siblings.iter().enumerate() {
        let sib_is_right = is_right.get(i).copied().unwrap_or(false);
        current = if sib_is_right {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
    }
    current
}

/// POST /rollup/:rollup_id/exit — universal exit: verify Merkle proof, route to BB or NFT.
pub async fn exit_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
    Json(req): Json<ExitRequest>,
) -> impl IntoResponse {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── Timestamp freshness ────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp out of ±60 s freshness window."
        })));
    }

    // ── asset_type validation ──────────────────────────────────────────────
    let asset_type = req.asset_type.to_uppercase();
    if asset_type != "BB" && asset_type != "NFT" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "asset_type must be \"BB\" or \"NFT\"."
        })));
    }

    // ── Ed25519 signature verification + pubkey → address binding ─────────
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "public_key must be 32-byte hex."
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 64-byte hex."
        }))),
    };
    let pk_arr: &[u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "public_key must be 32 bytes."
        }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid public key."
        }))),
    };

    // CRITICAL P0 GUARD: signing public_key MUST own req.address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "public_key does not match address",
            "derived": derived_address,
        })));
    }
    let signer_pk = solana_sdk::pubkey::Pubkey::new_from_array(*pk_arr);
    if crate::svm::pda::is_reserved_pda(&signer_pk) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "Reserved protocol PDA cannot exit"
        })));
    }

    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 64 bytes."
        }))),
    };
    let sig = Signature::from_bytes(sig_arr);
    // Canonical signed message — asset_type and rollup_id are both bound into the sig
    let signed_msg = format!(
        "ROLLUP_EXIT:{}:{}:{}:{}:{}:{}",
        rollup_id, asset_type, req.address, req.batch_id, req.timestamp, req.nonce
    );
    if verifying_key.verify(signed_msg.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid signature."
        })));
    }

    // ── Atomic replay protection (entry() eliminates TOCTOU race) ──────────
    let replay_key = format!("rollup_exit:{}:{}", req.address, req.nonce);
    match state.used_nonces.entry(replay_key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used."
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── Validate proof shape ───────────────────────────────────────────────
    if req.proof_siblings.len() != req.sibling_is_right.len() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "proof_siblings and sibling_is_right must have equal length."
        })));
    }

    // ── Load stored Merkle root for this rollup + batch ────────────────────
    let stored_root = match state.blockchain.load_rollup_state_root(&rollup_id, req.batch_id) {
        Some(r) => hex::encode(r),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No root found for rollup={} batch_id={}.", rollup_id, req.batch_id)
        }))),
    };

    // ── Build and verify the leaf based on asset_type ──────────────────────
    // ── Decode address bytes (base58 → [u8;32]) — shared by BB and NFT ──────
    let addr_bytes: [u8; 32] = match bs58::decode(&req.address).into_vec() {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "address must be a base58-encoded 32-byte Ed25519 public key."
        }))),
    };

    let (leaf_hash, exit_id_input) = match asset_type.as_str() {
        "BB" => {
            let lamports = match req.balance_lamports {
                Some(v) if v > 0 => v,
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "balance_lamports is required and must be > 0 for BB exits."
                }))),
            };
            // Borsh leaf: SHA-256( borsh(BbClaimLeaf { rollup_id, "BB", address[32], lamports }) )
            let leaf = bb_leaf_hash(&rollup_id, addr_bytes, lamports);
            // Exit key is batch-agnostic — cumulative withdrawal guard.
            let addr_lower = req.address.to_lowercase();
            let exit_id = format!("{}:BB:{}", rollup_id, addr_lower);
            (leaf, exit_id)
        }
        "NFT" => {
            let col = match &req.collection_id {
                Some(s) if !s.is_empty() => s.clone(),
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "collection_id is required for NFT exits."
                }))),
            };
            let tok = match &req.nft_token_id {
                Some(v) if !v.is_empty() => v.clone(),
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "nft_token_id is required for NFT exits."
                }))),
            };
            let mhash = match &req.metadata_hash {
                Some(s) if s.len() == 64 => s.clone(),
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "metadata_hash must be a 64-char hex string (SHA-256 of metadata JSON)."
                }))),
            };
            // Borsh leaf: SHA-256( borsh(NftClaimLeaf { rollup_id, "NFT", collection_id, token_id, owner[32], metadata_hash }) )
            let leaf = nft_leaf_hash(&rollup_id, &col, &tok, addr_bytes, &mhash);
            // NFT exit_id: keyed by (collection, token) — once exited, never again.
            let exit_id = format!("{}:NFT:{}:{}", rollup_id, col, tok);
            (leaf, exit_id)
        }
        _ => unreachable!(),
    };

    let computed_root = verify_merkle_proof(&leaf_hash, &req.proof_siblings, &req.sibling_is_right);

    if computed_root != stored_root {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "Merkle proof verification failed.",
            "computed_root": computed_root,
            "stored_root": stored_root,
        })));
    }

    // ── Compute the batch-agnostic exit key (SHA-256 of the exit_id_input string) ───
    let exit_id = sha256_hex(&exit_id_input);

    // ── Route to asset-specific execution ─────────────────────────────────
    let vault_addr = rollup_vault_address(&rollup_id);

    match asset_type.as_str() {
        // ── BB branch: cumulative-capped release from per-rollup vault ──────
        "BB" => {
            let proven = req.balance_lamports.unwrap(); // validated above

            // How much has this address already withdrawn across all batches?
            let cumulative = match state.blockchain.get_cumulative_exit(&exit_id) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": format!("Failed to read cumulative exit watermark (fail-closed): {}", e)
                        })),
                    );
                }
            };

            // Release only the unclaimed delta of the latest proven balance.
            // Replaying an old root, or re-proving an unchanged balance, yields 0.
            let withdrawable = proven.saturating_sub(cumulative);
            if withdrawable == 0 {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({
                    "error": "Already exited up to the proven balance — nothing to withdraw.",
                    "rollup_id": rollup_id,
                    "proven_balance_lamports": proven,
                    "already_withdrawn_lamports": cumulative,
                })));
            }
            let new_cumulative = match cumulative.checked_add(withdrawable) {
                Some(v) => v,
                None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": "Cumulative withdrawal overflow."
                }))),
            };

            // Solvency: vault must cover the delta (also re-checked inside the txn).
            let vault_balance = state.blockchain.get_balance_lamports(&vault_addr);
            if vault_balance < withdrawable {
                return (StatusCode::CONFLICT, Json(serde_json::json!({
                    "error": format!(
                        "{} vault has {} lamports, exit requires {} lamports.",
                        rollup_id, vault_balance, withdrawable
                    )
                })));
            }

            // Atomic: re-check race + solvency, debit vault, credit user, advance
            // cumulative — single durable ReDB commit before any cache mirror.
            if let Err(e) = state.blockchain.atomic_rollup_bb_exit(
                &req.address, &vault_addr, &exit_id, cumulative, withdrawable, new_cumulative,
            ) {
                let (code, msg) = match e.as_str() {
                    "exit_raced" => (StatusCode::CONFLICT,
                        "Concurrent exit detected — retry with a fresh proof.".to_string()),
                    "vault_insolvent" => (StatusCode::CONFLICT,
                        format!("{} vault cannot cover the exit.", rollup_id)),
                    "nothing_to_withdraw" => (StatusCode::FORBIDDEN,
                        "Nothing to withdraw.".to_string()),
                    other => (StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Exit failed: {}", other)),
                };
                return (code, Json(serde_json::json!({ "error": msg })));
            }

            let bal_after = state.blockchain.get_balance_lamports(&req.address);
            let vault_after = state.blockchain.get_balance_lamports(&vault_addr);
            let exit_tx_id = uuid::Uuid::new_v4().to_string();

            // Anchor the 1:1 $BB exit payout onto the L1 PoH clock + transparent ledger
            {
                use crate::protocol::{Transaction as ProtoTx, TxData};
                let proto_tx = ProtoTx {
                    hash: exit_tx_id.clone(),
                    from: vault_addr.clone(),
                    timestamp: now,
                    data: TxData::TransferBb {
                        to: req.address.clone(),
                        amount: withdrawable,
                    },
                    signature: req.signature.clone(),
                    signer_pubkey: req.public_key.clone(),
                };
                state.poh.write().queue_transaction(exit_tx_id.clone());
                state.block_producer.record_executed_transaction(proto_tx);

                let mut tx_record = crate::storage::TransactionRecord::with_id(
                    exit_tx_id.clone(),
                    crate::storage::TxType::Unlock,
                    &vault_addr,
                    &req.address,
                    withdrawable,
                    0,
                    vault_after.saturating_add(withdrawable),
                    vault_after,
                    bal_after,
                    crate::storage::AuthType::Ed25519,
                );
                tx_record.metadata = Some(serde_json::json!({
                    "kind": "rollup_exit",
                    "rollup_id": rollup_id,
                    "batch_id": req.batch_id,
                }));
                if let Err(e) = state.blockchain.log_transaction(tx_record) {
                    tracing::warn!("Failed to log rollup exit receipt: {}", e);
                } else if let Err(e) = state.blockchain.flush_tx_log_buffer() {
                    tracing::warn!("Failed to flush rollup exit receipt: {}", e);
                }
            }

            info!(
                "🚀 BB EXIT: {} lamports → {} (rollup={} batch={} proven={} cumulative={} proof_depth={})",
                withdrawable, req.address, rollup_id, req.batch_id, proven, new_cumulative,
                req.proof_siblings.len()
            );

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "asset_type": "BB",
                "tx_id": exit_tx_id,
                "poh_slot": state.current_slot.load(std::sync::atomic::Ordering::Relaxed),
                "released_lamports": withdrawable,
                "released_bb": withdrawable as f64 / crate::svm::LAMPORTS_PER_BB as f64,
                "proven_balance_lamports": proven,
                "cumulative_withdrawn_lamports": new_cumulative,
                "recipient": req.address,
                "rollup_id": rollup_id,
                "batch_id": req.batch_id,
                "l1_balance_after_lamports": bal_after,
                "l1_balance_after_bb": bal_after as f64 / crate::svm::LAMPORTS_PER_BB as f64,
                "message": "Rollup $BB balance successfully exited to L1."
            })))
        }

        // ── NFT branch: verify uniqueness → mint on L1 via nft_bridge ──────
        "NFT" => {
            let col = req.collection_id.as_ref().unwrap().clone();
            let tok = req.nft_token_id.clone().unwrap();
            let metadata_uri = match &req.metadata_uri {
                Some(u) if !u.is_empty() => u.clone(),
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "metadata_uri is required for NFT exits."
                }))),
            };
            let metadata_hash = req.metadata_hash.as_ref().unwrap().clone(); // validated above

            // Batch-agnostic double-spend seal: once this (collection, token) has
            // exited, it can never exit again regardless of historical root.
            if state.blockchain.is_exit_consumed(&exit_id) {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({
                    "error": "This NFT has already been exited.",
                    "rollup_id": rollup_id,
                    "collection_id": col,
                    "token_id": tok,
                })));
            }

            // Defense-in-depth: reject if NFT already exists on L1 (fail-closed on storage error)
            match state.blockchain.get_nft(&col, &tok) {
                Ok(Some(_)) => {
                    return (StatusCode::CONFLICT, Json(serde_json::json!({
                        "error": format!("NFT {}:{} already exists on L1.", col, tok)
                    })));
                }
                Ok(None) => {}
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                        "error": format!("Failed to inspect NFT state: {}", e)
                    })));
                }
            }

            let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
            let nft = crate::contracts::nft_bridge::AnchoredNft {
                collection_id: col.clone(),
                token_id: tok.clone(),
                owner: req.address.clone(),
                metadata_hash: metadata_hash.clone(),
                metadata_uri: metadata_uri.clone(),
                minted_slot: current_slot,
                last_transfer_slot: current_slot,
                transfer_count: 0,
            };

            if let Err(e) = state.blockchain.put_nft(&nft) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": format!("NFT mint failed: {}", e)
                })));
            }

            // Persist double-spend seal AFTER successful mint
            if let Err(e) = state.blockchain.mark_exit_consumed(&exit_id, now) {
                if e == "already_consumed" {
                    return (StatusCode::FORBIDDEN, Json(serde_json::json!({
                        "error": "Concurrent double-spend detected."
                    })));
                }
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": format!("Failed to persist NFT exit record: {}", e)
                })));
            }

            info!(
                "🖼️  NFT EXIT: {}:{} → {} (rollup={} batch={})",
                col, tok, req.address, rollup_id, req.batch_id
            );

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "asset_type": "NFT",
                "collection_id": col,
                "token_id": tok,
                "owner": req.address,
                "metadata_uri": metadata_uri,
                "metadata_hash": metadata_hash,
                "rollup_id": rollup_id,
                "batch_id": req.batch_id,
                "message": "NFT successfully minted on L1 from rollup exit proof."
            })))
        }

        _ => unreachable!(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /rollup/:rollup_id/settle_payouts
//  Sequencer-pushed direct prediction-market settlement payouts.
//
//  Unlike `POST /rollup/:rollup_id/exit` (user-signed self-claim for refunds,
//  disputes, and sweepstakes winnings), direct prediction market payouts are
//  pushed immediately upon resolution by the authorized rollup sequencer.
//
//  Security & Accounting Invariants:
//   - Authenticated by `authorized_sequencers[rollup_id]` Ed25519 signature over
//     `"ROLLUP_SETTLE_PAYOUTS:{rollup_id}:{batch_id}:{market_id}:{timestamp}"`.
//   - Every recipient leaf MUST verify cryptographically against the anchored
//     Merkle root stored for `(rollup_id, batch_id)`.
//   - Uses the exact same batch-agnostic cumulative exit watermark
//     (`SHA-256("{rollup_id}:BB:{address_lower}")`) and `atomic_rollup_bb_exit`
//     as `/exit`, making double-payout or subsequent double-claim impossible.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SettlePayoutLeaf {
    /// Base58 recipient wallet address (32-byte Ed25519 pubkey).
    pub address: String,
    /// Cumulative proven balance in $BB lamports in `batch_id`.
    pub balance_lamports: u64,
    /// Merkle proof sibling hashes (bottom-up hex strings).
    pub proof_siblings: Vec<String>,
    /// For each sibling: true = sibling is on the right of current node.
    pub sibling_is_right: Vec<bool>,
}

#[derive(Deserialize)]
pub struct SettlePayoutsRequest {
    /// Anchored batch_id whose stored Merkle root to verify against.
    pub batch_id: u64,
    /// Resolved market identifier (bound into the sequencer signature for auditability).
    pub market_id: String,
    /// Winner leaves to pay directly from the rollup vault.
    pub payouts: Vec<SettlePayoutLeaf>,
    /// Ed25519 public key of the rollup sequencer (64-char hex).
    pub sequencer_public_key: String,
    /// Ed25519 signature (128-char hex) over
    /// `"ROLLUP_SETTLE_PAYOUTS:{rollup_id}:{batch_id}:{market_id}:{timestamp}"`.
    pub signature: String,
    /// Unix timestamp (seconds) — freshness window ±60 s.
    pub timestamp: u64,
}

/// POST /rollup/:rollup_id/settle_payouts — sequencer-pushed direct BB payouts
/// for resolved prediction markets, verified against the anchored Merkle root.
pub async fn settle_payouts_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
    Json(req): Json<SettlePayoutsRequest>,
) -> impl IntoResponse {
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── Timestamp freshness ────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Timestamp out of ±60 s freshness window."
        })));
    }

    if req.market_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "market_id is required."
        })));
    }
    if req.payouts.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "payouts list must not be empty."
        })));
    }

    // ── Sequencer identity: verify against registered pubkey for this rollup ──
    let expected_pubkey = match state.authorized_sequencers.get(&rollup_id) {
        Some(pk) => pk.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": format!("No sequencer registered for rollup_id '{}'", rollup_id)
        }))),
    };
    if req.sequencer_public_key != expected_pubkey {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": format!("Signature key does not match the registered {} sequencer.", rollup_id)
        })));
    }

    // ── Ed25519 signature verification ─────────────────────────────────────
    let pk_bytes = match hex::decode(&req.sequencer_public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "sequencer_public_key must be 32-byte hex."
        }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "signature must be 64-byte hex."
        }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid sequencer public key."
        }))),
    };
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    let signed_msg = format!(
        "ROLLUP_SETTLE_PAYOUTS:{}:{}:{}:{}",
        rollup_id, req.batch_id, req.market_id, req.timestamp
    );
    if verifying_key.verify(signed_msg.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid sequencer signature."
        })));
    }

    // ── Load stored Merkle root for this rollup + batch ────────────────────
    let stored_root = match state.blockchain.load_rollup_state_root(&rollup_id, req.batch_id) {
        Some(r) => hex::encode(r),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("No root found for rollup={} batch_id={}.", rollup_id, req.batch_id)
        }))),
    };

    let vault_addr = rollup_vault_address(&rollup_id);
    let mut paid_count: usize = 0;
    let mut already_paid_count: usize = 0;
    let mut failed_count: usize = 0;
    let mut total_released_lamports: u64 = 0;
    let mut results: Vec<serde_json::Value> = Vec::with_capacity(req.payouts.len());

    for leaf in &req.payouts {
        if leaf.balance_lamports == 0 {
            failed_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": false,
                "already_paid": false,
                "released_lamports": 0,
                "error": "balance_lamports must be > 0",
            }));
            continue;
        }
        if leaf.proof_siblings.len() != leaf.sibling_is_right.len() {
            failed_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": false,
                "already_paid": false,
                "released_lamports": 0,
                "error": "proof_siblings and sibling_is_right length mismatch",
            }));
            continue;
        }

        let addr_bytes: [u8; 32] = match bs58::decode(&leaf.address).into_vec() {
            Ok(b) if b.len() == 32 => b.try_into().unwrap(),
            _ => {
                failed_count += 1;
                results.push(serde_json::json!({
                    "address": leaf.address,
                    "success": false,
                    "already_paid": false,
                    "released_lamports": 0,
                    "error": "address must be a base58-encoded 32-byte pubkey",
                }));
                continue;
            }
        };

        let recipient_pk = solana_sdk::pubkey::Pubkey::new_from_array(addr_bytes);
        if crate::svm::pda::is_reserved_pda(&recipient_pk) {
            failed_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": false,
                "already_paid": false,
                "released_lamports": 0,
                "error": "Reserved protocol PDA cannot receive direct payouts",
            }));
            continue;
        }

        let leaf_hash = bb_leaf_hash(&rollup_id, addr_bytes, leaf.balance_lamports);
        let computed_root = verify_merkle_proof(&leaf_hash, &leaf.proof_siblings, &leaf.sibling_is_right);
        if computed_root != stored_root {
            failed_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": false,
                "already_paid": false,
                "released_lamports": 0,
                "error": "Merkle proof verification failed",
            }));
            continue;
        }

        let exit_id_input = format!("{}:BB:{}", rollup_id, leaf.address.to_lowercase());
        let exit_id = sha256_hex(&exit_id_input);
        let cumulative = match state.blockchain.get_cumulative_exit(&exit_id) {
            Ok(c) => c,
            Err(e) => {
                results.push(serde_json::json!({
                    "address": leaf.address,
                    "success": false,
                    "already_paid": false,
                    "released_lamports": 0,
                    "error": format!("Watermark read failed (fail-closed): {}", e),
                }));
                continue;
            }
        };
        let withdrawable = leaf.balance_lamports.saturating_sub(cumulative);

        if withdrawable == 0 {
            already_paid_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": true,
                "already_paid": true,
                "released_lamports": 0,
                "cumulative_withdrawn_lamports": cumulative,
            }));
            continue;
        }

        let new_cumulative = match cumulative.checked_add(withdrawable) {
            Some(v) => v,
            None => {
                failed_count += 1;
                results.push(serde_json::json!({
                    "address": leaf.address,
                    "success": false,
                    "already_paid": false,
                    "released_lamports": 0,
                    "error": "Cumulative withdrawal overflow",
                }));
                continue;
            }
        };

        if let Err(e) = state.blockchain.atomic_rollup_bb_exit(
            &leaf.address,
            &vault_addr,
            &exit_id,
            cumulative,
            withdrawable,
            new_cumulative,
        ) {
            failed_count += 1;
            results.push(serde_json::json!({
                "address": leaf.address,
                "success": false,
                "already_paid": false,
                "released_lamports": 0,
                "error": format!("Atomic payout failed: {}", e),
            }));
            continue;
        }

        let bal_after = state.blockchain.get_balance_lamports(&leaf.address);
        let vault_after = state.blockchain.get_balance_lamports(&vault_addr);
        let tx_id = uuid::Uuid::new_v4().to_string();

        // Anchor the direct 1:1 $BB payout onto L1 PoH + block producer + tx log
        // so Reader nodes, explorer, and SubscribeBalances stay in sync.
        {
            use crate::protocol::{Transaction as ProtoTx, TxData};
            let proto_tx = ProtoTx {
                hash: tx_id.clone(),
                from: vault_addr.clone(),
                timestamp: now,
                data: TxData::TransferBb {
                    to: leaf.address.clone(),
                    amount: withdrawable,
                },
                signature: req.signature.clone(),
                signer_pubkey: req.sequencer_public_key.clone(),
            };
            state.poh.write().queue_transaction(tx_id.clone());
            state.block_producer.record_executed_transaction(proto_tx);

            let mut tx_record = crate::storage::TransactionRecord::with_id(
                tx_id.clone(),
                crate::storage::TxType::Unlock,
                &vault_addr,
                &leaf.address,
                withdrawable,
                0,
                vault_after.saturating_add(withdrawable),
                vault_after,
                bal_after,
                crate::storage::AuthType::Ed25519,
            );
            tx_record.metadata = Some(serde_json::json!({
                "kind": "direct_settlement_payout",
                "rollup_id": rollup_id,
                "market_id": req.market_id,
                "batch_id": req.batch_id,
            }));
            if let Err(e) = state.blockchain.log_transaction(tx_record) {
                tracing::warn!("Failed to log direct settlement payout receipt: {}", e);
            } else if let Err(e) = state.blockchain.flush_tx_log_buffer() {
                tracing::warn!("Failed to flush direct settlement payout receipt: {}", e);
            }
        }

        paid_count += 1;
        total_released_lamports = total_released_lamports.saturating_add(withdrawable);
        info!(
            "💸 DIRECT SETTLEMENT PAYOUT: {} lamports ({:.5} BB) → {} (rollup={} market={} batch={} cumulative={})",
            withdrawable,
            withdrawable as f64 / crate::svm::LAMPORTS_PER_BB as f64,
            leaf.address,
            rollup_id,
            req.market_id,
            req.batch_id,
            new_cumulative,
        );

        results.push(serde_json::json!({
            "address": leaf.address,
            "success": true,
            "already_paid": false,
            "tx_id": tx_id,
            "released_lamports": withdrawable,
            "released_bb": withdrawable as f64 / crate::svm::LAMPORTS_PER_BB as f64,
            "cumulative_withdrawn_lamports": new_cumulative,
            "l1_balance_after_lamports": bal_after,
            "l1_balance_after_bb": bal_after as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        }));
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": failed_count == 0,
        "rollup_id": rollup_id,
        "market_id": req.market_id,
        "batch_id": req.batch_id,
        "poh_slot": state.current_slot.load(std::sync::atomic::Ordering::Relaxed),
        "paid_count": paid_count,
        "already_paid_count": already_paid_count,
        "failed_count": failed_count,
        "total_released_lamports": total_released_lamports,
        "total_released_bb": total_released_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
        "results": results,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};
    use axum::{Router, routing::post};
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::{Signer, SigningKey};
    use parking_lot::RwLock;
    use tempfile::tempdir;
    use tower::ServiceExt;

    use crate::svm::LAMPORTS_PER_BB;

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn gen_keypair() -> (SigningKey, String, [u8; 32], String) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk_bytes);
        let addr = bs58::encode(pk_bytes).into_string();
        (sk, pk_hex, pk_bytes, addr)
    }

    fn build_test_app() -> (tempfile::TempDir, AppState, SigningKey, String, Router) {
        let dir = tempdir().unwrap();
        let blockchain = crate::storage::ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
        let current_slot = Arc::new(AtomicU64::new(1));
        let poh = crate::create_poh_service_with_slot(crate::PoHConfig::default(), current_slot.clone());
        let leader_schedule = Arc::new(RwLock::new(crate::LeaderSchedule::new()));
        let (pipeline, _rx) = crate::TransactionPipeline::new();
        let parallel_scheduler = Arc::new(
            crate::runtime::ParallelScheduler::new().with_svm(blockchain.svm_accounts.clone()),
        );
        let gulf_stream = crate::runtime::GulfStreamService::new(leader_schedule.clone(), current_slot.clone());
        let validator_id = "test-validator".to_string();
        let block_producer = Arc::new(crate::poh_blockchain::BlockProducer::new(
            blockchain.clone(),
            poh.clone(),
            leader_schedule.clone(),
            current_slot.clone(),
            validator_id.clone(),
        ));
        let finality_tracker = Arc::new(crate::poh_blockchain::FinalityTracker::new(current_slot.clone()));
        let tower_bft = crate::runtime::TowerBFT::new(validator_id.clone(), current_slot.clone());
        let (block_tx, _) = tokio::sync::broadcast::channel(16);
        let (balance_event_tx, _) = tokio::sync::broadcast::channel(16);

        let (seq_sk, seq_pk_hex, _, _) = gen_keypair();
        let authorized_sequencers = Arc::new(dashmap::DashMap::new());
        authorized_sequencers.insert("L2".to_string(), seq_pk_hex.clone());

        let state = AppState {
            blockchain,
            poh,
            current_slot,
            leader_schedule,
            pipeline,
            parallel_scheduler,
            gulf_stream,
            block_producer,
            finality_tracker,
            tower_bft,
            node_mode: crate::NodeMode::Writer,
            validator_id,
            throttler: Arc::new(crate::NetworkThrottler::new()),
            ws_subscriptions: Arc::new(crate::WsSubscriptions::new()),
            block_tx,
            balance_event_tx,
            circuit_breaker: Arc::new(crate::CircuitBreaker::new()),
            fee_market: Arc::new(crate::LocalizedFeeMarket::new()),
            account_metadata: Arc::new(dashmap::DashMap::new()),
            used_nonces: Arc::new(dashmap::DashMap::new()),
            faucet_claims: Arc::new(dashmap::DashMap::new()),
            l2_sequencer_pubkey: seq_pk_hex.clone(),
            l2_sequencer_allowlist: std::iter::once(seq_pk_hex.clone()).collect(),
            authorized_sequencers,
            custody_wallet_address: String::new(),
            deposit_requests: Arc::new(dashmap::DashMap::new()),
            custody_watcher: None,
            bsc_watcher: None,
            bridge_authority_pubkey: String::new(),
            dealer_address: String::new(),
            withdrawal_requests: Arc::new(dashmap::DashMap::new()),
            withdrawal_seq_counter: Arc::new(AtomicU64::new(0)),
            withdrawal_window_start: Arc::new(AtomicU64::new(0)),
            withdrawal_window_total: Arc::new(AtomicU64::new(0)),
            withdrawal_daily_cap_micro: 0,
            rollup_lock_records: Arc::new(dashmap::DashMap::new()),
            backup_last_at: Arc::new(AtomicU64::new(0)),
            backup_last_size: Arc::new(AtomicU64::new(0)),
            approved_validators: Arc::new(crate::runtime::validator_registry::ValidatorRegistry::empty()),
            writer_http_url: None,
        };

        let router = Router::new()
            .route("/rollup/:rollup_id/lock_bb", post(lock_bb_handler))
            .route("/rollup/:rollup_id/submit_root", post(submit_root_handler))
            .route("/rollup/:rollup_id/settle_payouts", post(settle_payouts_handler))
            .route("/rollup/:rollup_id/exit", post(exit_handler))
            .with_state(state.clone());

        (dir, state, seq_sk, seq_pk_hex, router)
    }

    async fn post_json(router: &Router, path: &str, payload: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, json)
    }

    async fn lock_bb_for(
        router: &Router,
        sk: &SigningKey,
        pk_hex: &str,
        addr: &str,
        lamports: u64,
        nonce: &str,
    ) -> serde_json::Value {
        let ts = now_secs();
        let hint = "MLS_TEST";
        let msg = format!("ROLLUP_LOCK_BB:L2:{addr}:{lamports}:{hint}:{ts}:{nonce}");
        let sig_hex = hex::encode(sk.sign(msg.as_bytes()).to_bytes());
        let (status, body) = post_json(router, "/rollup/L2/lock_bb", serde_json::json!({
            "wallet_address": addr,
            "bb_lamports": lamports,
            "token_symbol_hint": hint,
            "public_key": pk_hex,
            "signature": sig_hex,
            "timestamp": ts,
            "nonce": nonce,
        })).await;
        assert_eq!(status, StatusCode::OK, "lock_bb failed: {body}");
        body
    }

    async fn submit_two_leaf_root(
        router: &Router,
        seq_sk: &SigningKey,
        seq_pk_hex: &str,
        batch_id: u64,
        leaf_a: ([u8; 32], u64),
        leaf_b: ([u8; 32], u64),
    ) -> (String, String, String) {
        let hash_a = bb_leaf_hash("L2", leaf_a.0, leaf_a.1);
        let hash_b = bb_leaf_hash("L2", leaf_b.0, leaf_b.1);
        let root_hex = hash_pair(&hash_a, &hash_b);
        let total = leaf_a.1 + leaf_b.1;
        let ts = now_secs();
        let msg = format!("ROLLUP_SUBMIT_ROOT:L2:{batch_id}:{root_hex}:{ts}");
        let sig_hex = hex::encode(seq_sk.sign(msg.as_bytes()).to_bytes());
        let (status, body) = post_json(router, "/rollup/L2/submit_root", serde_json::json!({
            "batch_id": batch_id,
            "merkle_root_hex": root_hex,
            "sequencer_public_key": seq_pk_hex,
            "signature": sig_hex,
            "timestamp": ts,
            "total_cumulative_lamports": total,
        })).await;
        assert_eq!(status, StatusCode::OK, "submit_root failed: {body}");
        (root_hex, hash_a, hash_b)
    }

    #[tokio::test]
    async fn lock_bb_flushes_tx_log_immediately_before_response() {
        let (_dir, state, _seq_sk, _seq_pk, router) = build_test_app();
        let (alice_sk, alice_pk_hex, _, alice_addr) = gen_keypair();
        state.blockchain.mint_lamports(&alice_addr, 100 * LAMPORTS_PER_BB).unwrap();

        let lock_body = lock_bb_for(&router, &alice_sk, &alice_pk_hex, &alice_addr, 25 * LAMPORTS_PER_BB, "n-lock-1").await;
        let lock_id = lock_body["lock_id"].as_str().unwrap();

        // Without running any background Sealevel loop, the LOCK tx must already be durable in ReDB.
        let persisted = state.blockchain.get_tx_by_id(lock_id).unwrap()
            .expect("LOCK transaction must be flushed to ReDB before HTTP 200 returns");
        assert_eq!(persisted.tx_type, "LOCK");
        assert_eq!(persisted.from_address, alice_addr);
        assert_eq!(persisted.amount, 25 * LAMPORTS_PER_BB);
        assert_eq!(persisted.metadata.as_ref().unwrap()["kind"], "rollup_lock");

        let history = state.blockchain.get_transactions(Some(&alice_addr), 10, 0).unwrap();
        assert_eq!(history.len(), 2); // MINT + LOCK both flushed to ReDB
        assert!(history.iter().any(|tx| tx.tx_id == lock_id && tx.tx_type == "LOCK"));
    }

    #[tokio::test]
    async fn settle_payouts_rejects_invalid_sequencer_signature_and_wrong_key() {
        let (_dir, state, seq_sk, seq_pk_hex, router) = build_test_app();
        let (funder_sk, funder_pk_hex, _, funder_addr) = gen_keypair();
        let (_, _, alice_bytes, alice_addr) = gen_keypair();
        let (_, _, bob_bytes, _) = gen_keypair();

        state.blockchain.mint_lamports(&funder_addr, 100 * LAMPORTS_PER_BB).unwrap();
        lock_bb_for(&router, &funder_sk, &funder_pk_hex, &funder_addr, 80 * LAMPORTS_PER_BB, "n-fund-1").await;

        let (_root, _ha, hb) = submit_two_leaf_root(
            &router, &seq_sk, &seq_pk_hex, 1,
            (alice_bytes, 40 * LAMPORTS_PER_BB),
            (bob_bytes, 20 * LAMPORTS_PER_BB),
        ).await;

        // 1. Rogue sequencer key must be rejected with 401 UNAUTHORIZED.
        let (rogue_sk, rogue_pk_hex, _, _) = gen_keypair();
        let ts = now_secs();
        let rogue_msg = format!("ROLLUP_SETTLE_PAYOUTS:L2:1:MKT-AUTH:{ts}");
        let rogue_sig = hex::encode(rogue_sk.sign(rogue_msg.as_bytes()).to_bytes());
        let (status1, _) = post_json(&router, "/rollup/L2/settle_payouts", serde_json::json!({
            "batch_id": 1,
            "market_id": "MKT-AUTH",
            "payouts": [{
                "address": alice_addr,
                "balance_lamports": 40 * LAMPORTS_PER_BB,
                "proof_siblings": [hb],
                "sibling_is_right": [true],
            }],
            "sequencer_public_key": rogue_pk_hex,
            "signature": rogue_sig,
            "timestamp": ts,
        })).await;
        assert_eq!(status1, StatusCode::UNAUTHORIZED);
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 0);

        // 2. Authorized pubkey with signature over a different market_id must be rejected with 401.
        let bad_sig = hex::encode(seq_sk.sign(format!("ROLLUP_SETTLE_PAYOUTS:L2:1:OTHER-MKT:{ts}").as_bytes()).to_bytes());
        let (status2, _) = post_json(&router, "/rollup/L2/settle_payouts", serde_json::json!({
            "batch_id": 1,
            "market_id": "MKT-AUTH",
            "payouts": [{
                "address": alice_addr,
                "balance_lamports": 40 * LAMPORTS_PER_BB,
                "proof_siblings": [hb],
                "sibling_is_right": [true],
            }],
            "sequencer_public_key": seq_pk_hex,
            "signature": bad_sig,
            "timestamp": ts,
        })).await;
        assert_eq!(status2, StatusCode::UNAUTHORIZED);
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 0);
    }

    #[tokio::test]
    async fn settle_payouts_rejects_tampered_merkle_proof_and_inflated_amount() {
        let (_dir, state, seq_sk, seq_pk_hex, router) = build_test_app();
        let (funder_sk, funder_pk_hex, _, funder_addr) = gen_keypair();
        let (_, _, alice_bytes, alice_addr) = gen_keypair();
        let (_, _, bob_bytes, _) = gen_keypair();

        state.blockchain.mint_lamports(&funder_addr, 100 * LAMPORTS_PER_BB).unwrap();
        lock_bb_for(&router, &funder_sk, &funder_pk_hex, &funder_addr, 80 * LAMPORTS_PER_BB, "n-fund-2").await;

        let (_root, _ha, hb) = submit_two_leaf_root(
            &router, &seq_sk, &seq_pk_hex, 1,
            (alice_bytes, 40 * LAMPORTS_PER_BB),
            (bob_bytes, 20 * LAMPORTS_PER_BB),
        ).await;

        let ts = now_secs();
        let msg = format!("ROLLUP_SETTLE_PAYOUTS:L2:1:MKT-TAMPER:{ts}");
        let sig_hex = hex::encode(seq_sk.sign(msg.as_bytes()).to_bytes());

        // Inflated balance (+1 lamport) + tampered sibling must both fail Merkle verification.
        let (status, body) = post_json(&router, "/rollup/L2/settle_payouts", serde_json::json!({
            "batch_id": 1,
            "market_id": "MKT-TAMPER",
            "payouts": [
                {
                    "address": alice_addr,
                    "balance_lamports": 40 * LAMPORTS_PER_BB + 1,
                    "proof_siblings": [hb],
                    "sibling_is_right": [true],
                },
                {
                    "address": alice_addr,
                    "balance_lamports": 40 * LAMPORTS_PER_BB,
                    "proof_siblings": ["00".repeat(32)],
                    "sibling_is_right": [true],
                }
            ],
            "sequencer_public_key": seq_pk_hex,
            "signature": sig_hex,
            "timestamp": ts,
        })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], false);
        assert_eq!(body["paid_count"], 0);
        assert_eq!(body["failed_count"], 2);
        assert_eq!(body["total_released_lamports"], 0);
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 0);
    }

    #[tokio::test]
    async fn settle_payouts_happy_path_replay_idempotency_and_cross_endpoint_exit_rejection() {
        let (_dir, state, seq_sk, seq_pk_hex, router) = build_test_app();
        let (funder_sk, funder_pk_hex, _, funder_addr) = gen_keypair();
        let (alice_sk, alice_pk_hex, alice_bytes, alice_addr) = gen_keypair();
        let (_, _, bob_bytes, bob_addr) = gen_keypair();

        state.blockchain.mint_lamports(&funder_addr, 100 * LAMPORTS_PER_BB).unwrap();
        lock_bb_for(&router, &funder_sk, &funder_pk_hex, &funder_addr, 100 * LAMPORTS_PER_BB, "n-fund-3").await;
        let vault_addr = rollup_vault_address("L2");

        let (_root, ha, hb) = submit_two_leaf_root(
            &router, &seq_sk, &seq_pk_hex, 1,
            (alice_bytes, 40 * LAMPORTS_PER_BB),
            (bob_bytes, 25 * LAMPORTS_PER_BB),
        ).await;

        // 1. Direct payout push credits Alice (40 BB) and Bob (25 BB) + flushes UNLOCK txs immediately.
        let ts = now_secs();
        let msg = format!("ROLLUP_SETTLE_PAYOUTS:L2:1:MLS-E2E:{ts}");
        let sig_hex = hex::encode(seq_sk.sign(msg.as_bytes()).to_bytes());
        let payload = serde_json::json!({
            "batch_id": 1,
            "market_id": "MLS-E2E",
            "payouts": [
                {
                    "address": alice_addr,
                    "balance_lamports": 40 * LAMPORTS_PER_BB,
                    "proof_siblings": [hb.clone()],
                    "sibling_is_right": [true],
                },
                {
                    "address": bob_addr,
                    "balance_lamports": 25 * LAMPORTS_PER_BB,
                    "proof_siblings": [ha.clone()],
                    "sibling_is_right": [false],
                }
            ],
            "sequencer_public_key": seq_pk_hex,
            "signature": sig_hex,
            "timestamp": ts,
        });
        let (status1, body1) = post_json(&router, "/rollup/L2/settle_payouts", payload.clone()).await;
        assert_eq!(status1, StatusCode::OK, "settle_payouts failed: {body1}");
        assert_eq!(body1["success"], true);
        assert_eq!(body1["paid_count"], 2);
        assert_eq!(body1["already_paid_count"], 0);
        assert_eq!(body1["total_released_lamports"], 65 * LAMPORTS_PER_BB);
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 40 * LAMPORTS_PER_BB);
        assert_eq!(state.blockchain.get_balance_lamports(&bob_addr), 25 * LAMPORTS_PER_BB);
        assert_eq!(state.blockchain.get_balance_lamports(&vault_addr), 35 * LAMPORTS_PER_BB);

        // Verify UNLOCK payout receipt was immediately flushed to ReDB with market metadata.
        let alice_txs = state.blockchain.get_transactions(Some(&alice_addr), 10, 0).unwrap();
        assert_eq!(alice_txs.len(), 1);
        assert_eq!(alice_txs[0].tx_type, "UNLOCK");
        assert_eq!(alice_txs[0].amount, 40 * LAMPORTS_PER_BB);
        assert_eq!(alice_txs[0].metadata.as_ref().unwrap()["market_id"], "MLS-E2E");

        // 2. Replay idempotency: re-sending the exact payout batch releases 0 additional lamports.
        let (status2, body2) = post_json(&router, "/rollup/L2/settle_payouts", payload).await;
        assert_eq!(status2, StatusCode::OK);
        assert_eq!(body2["success"], true);
        assert_eq!(body2["paid_count"], 0);
        assert_eq!(body2["already_paid_count"], 2);
        assert_eq!(body2["total_released_lamports"], 0);
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 40 * LAMPORTS_PER_BB);
        assert_eq!(state.blockchain.get_balance_lamports(&vault_addr), 35 * LAMPORTS_PER_BB);

        // 3. Cross-endpoint double-claim guard: Alice calling POST /rollup/L2/exit against Batch #1 must be rejected.
        let exit_ts = now_secs();
        let exit_nonce = "exit-after-direct-1";
        let exit_msg = format!("ROLLUP_EXIT:L2:BB:{alice_addr}:1:{exit_ts}:{exit_nonce}");
        let exit_sig = hex::encode(alice_sk.sign(exit_msg.as_bytes()).to_bytes());
        let (status3, body3) = post_json(&router, "/rollup/L2/exit", serde_json::json!({
            "address": alice_addr,
            "asset_type": "BB",
            "balance_lamports": 40 * LAMPORTS_PER_BB,
            "batch_id": 1,
            "proof_siblings": [hb],
            "sibling_is_right": [true],
            "public_key": alice_pk_hex,
            "signature": exit_sig,
            "timestamp": exit_ts,
            "nonce": exit_nonce,
        })).await;
        assert_eq!(status3, StatusCode::FORBIDDEN, "cross-endpoint /exit must reject already-settled balance: {body3}");
        assert_eq!(state.blockchain.get_balance_lamports(&alice_addr), 40 * LAMPORTS_PER_BB);
        assert_eq!(state.blockchain.get_balance_lamports(&vault_addr), 35 * LAMPORTS_PER_BB);
    }
}
