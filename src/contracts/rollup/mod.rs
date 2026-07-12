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

    if let Some(ref sym) = req.token_symbol_hint {
        // Only uppercase alphanumeric + underscore, 1–12 chars
        if sym.is_empty() || sym.len() > 12 || !sym.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "token_symbol_hint must be 1–12 uppercase alphanumeric/underscore chars"
            })));
        }
    }

    // ── Ed25519 SIGNATURE VERIFICATION ─────────────────────────────────────
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

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
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

    let nonce_key = format!("rollup_lock:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": req.nonce
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => { v.insert(now); }
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

    // Hot-cache so the L5 sequencer poller can read without hitting ReDB
    state.rollup_lock_records.insert(lock_id.clone(), record);

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
        "token_symbol_hint": req.token_symbol_hint
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

// ─────────────────────────────────────────────────────────────────────────────
//  GET /rollup/:rollup_id/roots/:batch_id
//  Read a stored Merkle state root for debugging / smoke tests.
// ─────────────────────────────────────────────────────────────────────────────

/// GET /rollup/:rollup_id/roots/:batch_id — return the 64-char hex Merkle root
/// that was anchored on-chain for the given batch, or 404 if not found.
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

    // ── Mark consumed (idempotent) ─────────────────────────────────────────
    if let Err(e) = state.blockchain.consume_rollup_lock(&lock_id) {
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

    // ── Persist (per-rollup monotonicity enforced inside storage) ─────────────────
    if let Err(e) = state.blockchain.store_rollup_state_root(&rollup_id, req.batch_id, root_bytes) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": format!("Root rejected: {}", e)
        })));
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

    // ── Replay protection ──────────────────────────────────────────────────
    let replay_key = format!("exit_nonce:{}", req.nonce);
    if state.used_nonces.contains_key(&replay_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used."
        })));
    }

    // ── Ed25519 signature verification ─────────────────────────────────────
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
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid public key."
        }))),
    };
    let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
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
            let cumulative = state.blockchain.get_cumulative_exit(&exit_id);

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

            state.used_nonces.insert(replay_key, now);
            let bal_after = state.blockchain.get_balance_lamports(&req.address);

            info!(
                "🚀 BB EXIT: {} lamports → {} (rollup={} batch={} proven={} cumulative={} proof_depth={})",
                withdrawable, req.address, rollup_id, req.batch_id, proven, new_cumulative,
                req.proof_siblings.len()
            );

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "asset_type": "BB",
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

            // Defense-in-depth: reject if NFT already exists on L1
            if crate::contracts::nft_bridge::get_nft(&state.blockchain.db, &col, &tok).is_some() {
                return (StatusCode::CONFLICT, Json(serde_json::json!({
                    "error": format!("NFT {}:{} already exists on L1.", col, tok)
                })));
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

            if let Err(e) = crate::contracts::nft_bridge::put_nft(&state.blockchain.db, &nft) {
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

            state.used_nonces.insert(replay_key, now);

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
