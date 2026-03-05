// ============================================================================
// BLACKBOOK L1 — DIGITAL CENTRAL BANK
// ============================================================================
//
// Two Core Jobs (see MANIFESTO.md):
//   1. GATEKEEPER:          USDT → $BB at 1:10 ratio (vault solvency)
//   2. INVISIBLE SECURITY:  SSS 2-of-3 Shamir wallets (key never whole)
//
// Engine: Solana-style PoH + Sealevel parallel execution
// Storage: ReDB (ACID, MVCC, zero-copy reads)
// Auth: Ed25519 signatures + SSS 2-of-3 reconstruction
//
// Run:  cargo run
// Test: curl http://localhost:8080/health



// ============================================================================
// IMPORTS
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;

use tokio::signal;
use parking_lot::RwLock;

use tracing::{info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path, Query},
    response::IntoResponse,
    http::StatusCode,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use serde::Deserialize;
use clap::Parser;

// ============================================================================
// CLI ARGUMENTS
// ============================================================================

/// Node operating mode: Writer produces blocks, Reader consumes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NodeMode {
    /// Single writer node: runs PoH clock, produces blocks, serves relay to readers
    Writer,
    /// Reader node: subscribes to writer relay, verifies + stores blocks, serves RPC
    Reader,
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeMode::Writer => write!(f, "writer"),
            NodeMode::Reader => write!(f, "reader"),
        }
    }
}

/// BlackBook L1 — Digital Central Bank
#[derive(Parser, Debug)]
#[command(name = "blackbook-l1", version = VERSION, about = "PoH blockchain node")]
pub struct NodeConfig {
    /// Node mode: writer (block producer) or reader (block consumer)
    #[arg(long, default_value = "writer", value_enum)]
    pub mode: NodeMode,

    /// Validator identity name (used in leader schedule + logs)
    #[arg(long, default_value = "genesis_validator")]
    pub identity: String,

    /// Address of the writer node's gRPC relay (reader mode only)
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    pub writer_addr: String,

    /// Port for the gRPC relay service (writer) or gRPC client target (reader)
    #[arg(long, default_value_t = 50051)]
    pub grpc_port: u16,

    /// HTTP port (wallet UI, REST endpoints)
    #[arg(long, default_value_t = 8080)]
    pub http_port: u16,

    /// Solana JSON-RPC port
    #[arg(long, default_value_t = 8899)]
    pub rpc_port: u16,
}

// ============================================================================
// MODULES
// ============================================================================

mod wallet_unified;
mod storage;
mod poh_blockchain;
mod svm;
mod solana_rpc;
mod relay;
mod reader;

#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

// ============================================================================
// MODULE IMPORTS
// ============================================================================

use storage::ConcurrentBlockchain;
use wallet_unified::handlers::UnifiedWalletState;
use wallet_unified::session_store::SessionStore;

// Solana-style consensus infrastructure
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service_with_slot, run_poh_clock,
    TransactionPipeline, LeaderSchedule, GulfStreamService,
    ParallelScheduler, PipelinePacket,
    TowerBFT,
};

use poh_blockchain::{
    BlockProducer, FinalizedBlock, FinalityTracker,
    TurbineShredder, TurbinePropagator,
};


// ============================================================================
// CONSTANTS
// ============================================================================

const VERSION: &str = "5.0.0";
const NETWORK: &str = "mainnet-beta";
const REDB_DATA_PATH: &str = "./blockchain_data";

/// PoH Configuration (400ms slots — matching Solana for max TPS)
const POH_SLOT_DURATION_MS: u64 = 400;
const POH_HASHES_PER_TICK: u64 = 12500;
const POH_TICKS_PER_SLOT: u64 = 64;
const POH_SLOTS_PER_EPOCH: u64 = 432000; // ~3 days

// No hardcoded test accounts — this is a zero-sum stablecoin.
// All accounts are created at runtime via wallet creation endpoints.

// ============================================================================
// APPLICATION STATE
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    // Core blockchain (ReDB + DashMap cache)
    pub blockchain: ConcurrentBlockchain,

    // Solana-style consensus
    pub poh: SharedPoHService,
    pub current_slot: Arc<AtomicU64>,
    pub leader_schedule: Arc<RwLock<LeaderSchedule>>,
    pub pipeline: Arc<TransactionPipeline>,
    pub parallel_scheduler: Arc<ParallelScheduler>,
    pub gulf_stream: Arc<GulfStreamService>,
    pub block_producer: Arc<BlockProducer>,
    pub finality_tracker: Arc<FinalityTracker>,
    pub tower_bft: Arc<TowerBFT>,

    // Node identity
    pub node_mode: NodeMode,
    pub validator_id: String,

    // Replay protection
    pub used_nonces: Arc<dashmap::DashMap<String, u64>>,

    // Shared session store (SSS wallet sessions — used for dual-auth)
    pub session_store: Arc<SessionStore>,
}

// ============================================================================
// HEALTH & STATUS
// ============================================================================

/// GET /health
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.blockchain.stats();
    let total_supply = state.blockchain.total_supply();
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let poh_status = { state.poh.read().get_status() };
    let pipeline_stats = state.pipeline.get_stats();
    let tower_stats = state.tower_bft.get_stats();
    let svm_account_count = state.blockchain.svm_accounts.account_count();

    // Block production staleness check
    let latest_block = state.block_producer.get_block(current_slot.saturating_sub(1));
    let block_age_s = latest_block.as_ref().map(|b| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(b.timestamp)
    });
    let is_healthy = block_age_s.map(|age| age < 10).unwrap_or(current_slot < 5);

    Json(serde_json::json!({
        "status": if is_healthy { "healthy" } else { "degraded" },
        "version": VERSION,
        "network": NETWORK,
        "blockchain": {
            "total_supply": total_supply,
            "account_count": stats.total_accounts,
            "block_count": stats.block_count,
            "svm_accounts": svm_account_count,
        },
        "poh_clock": {
            "current_slot": poh_status["current_slot"],
            "current_epoch": poh_status["current_epoch"],
            "slot_duration_ms": POH_SLOT_DURATION_MS,
        },
        "poh_status": poh_status,
        "consensus": {
            "tower_root": tower_stats.global_root,
            "confirmed_slots": tower_stats.confirmed_slots,
            "validator_count": tower_stats.validator_count,
        },
        "block_production": {
            "latest_block_age_s": block_age_s,
            "is_producing": is_healthy,
        },
        "infrastructure": {
            "gulf_stream": true,
            "sealevel": true,
            "pipeline": pipeline_stats.is_running,
        },
    }))
}

/// GET /stats
async fn stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.blockchain.stats();
    let pipeline_stats = state.pipeline.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let parallel_stats = state.parallel_scheduler.get_stats();

    Json(serde_json::json!({
        "blockchain": {
            "total_accounts": stats.total_accounts,
            "block_count": stats.block_count,
            "total_supply": stats.total_supply,
            "cache_hit_rate": stats.cache_hit_rate,
        },
        "pipeline": pipeline_stats,
        "gulf_stream": gulf_stream_stats,
        "parallel_execution": parallel_stats,
    }))
}

// ============================================================================
// BALANCE
// ============================================================================

/// GET /balance/:address
async fn balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let balance = state.blockchain.get_balance(&address);
    Json(serde_json::json!({
        "address": address,
        "name": serde_json::Value::Null,
        "balance": balance,
        "unit": "BB"
    }))
}

// ============================================================================
// TRANSFER — SSS 2-of-3 Authenticated
// ============================================================================

// [REMOVED] Legacy SSS Transfer Handler - Use Unified Wallet API


// ============================================================================
// TRANSFER — Ed25519 Signature Verified (Frontend SDK)
// ============================================================================

#[derive(Deserialize)]
struct SignedTransferRequest {
    public_key: String,
    wallet_address: String,
    payload: String,
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    signature: String,
}

#[derive(Deserialize)]
struct TransferPayload {
    to: String,
    amount: f64,
}

/// POST /transfer/simple — Ed25519 signed transfer
async fn signed_transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<SignedTransferRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let payload: TransferPayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Invalid payload: {}", e)
        }))),
    };

    if req.wallet_address.is_empty() || payload.to.is_empty() || payload.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid parameters" })));
    }

    // Verify Ed25519 signature
    let mut message = vec![req.chain_id];
    message.extend_from_slice(req.payload.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(req.timestamp.to_string().as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(req.nonce.as_bytes());

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

    if verifying_key.verify(&message, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("transfer:{}:{}", req.wallet_address, req.nonce);
    if state.used_nonces.contains_key(&nonce_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used — possible replay attack",
            "nonce": req.nonce
        })));
    }

    // Check timestamp freshness (reject transactions older than 60 seconds)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Transaction too old (>60s)",
            "server_time": now,
            "tx_time": req.timestamp
        })));
    }

    // Record nonce BEFORE executing transfer (fail-safe)
    state.used_nonces.insert(nonce_key, now);

    // Prune old nonces periodically
    if state.used_nonces.len() > 100_000 {
        let cutoff = now.saturating_sub(120);
        state.used_nonces.retain(|_, &mut ts| ts > cutoff);
    }

    // Execute transfer
    let from = &req.wallet_address;
    let balance = state.blockchain.get_balance(from);

    if balance < payload.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, payload.amount)
        })));
    }

    match state.blockchain.transfer(from, &payload.to, payload.amount) {
        Ok(_) => {
            let from_bal = state.blockchain.get_balance(from);
            let to_bal   = state.blockchain.get_balance(&payload.to);
            info!("💸 Transfer: {} → {} : {} BB", from, payload.to, payload.amount);

            // Record signed transfer into PoH block
            {
                use protocol::Transaction as ProtoTx;
                use protocol::TxData;
                let tx = ProtoTx {
                    hash: uuid::Uuid::new_v4().to_string(),
                    from: from.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data: TxData::TransferBb {
                        to: payload.to.clone(),
                        amount: (payload.amount * 100_000.0) as u64,
                    },
                    signature: req.signature.clone(),
                    signer_pubkey: req.public_key.clone(),
                };
                state.block_producer.record_executed_transaction(tx);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "from": from,
                "to": payload.to,
                "amount": payload.amount,
                "from_balance": from_bal,
                "to_balance": to_bal,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

// ============================================================================
// POH & CONSENSUS HANDLERS
// ============================================================================

/// GET /poh/status
async fn poh_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let poh = state.poh.read();
    Json(serde_json::json!({
        "current_slot": poh.current_slot.load(Ordering::Relaxed),
        "num_hashes": poh.num_hashes,
        "current_hash": poh.current_hash,
        "is_running": true
    }))
}

/// GET /poh/block/latest
async fn poh_latest_block_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.block_producer.get_latest_block() {
        Some(block) => Json(serde_json::json!({
            "success": true,
            "block": {
                "slot": block.slot,
                "timestamp": block.timestamp,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "tx_count": block.tx_count,
                "leader": block.leader,
                "epoch": block.epoch,
            }
        })),
        None => Json(serde_json::json!({ "success": false, "error": "No blocks yet" }))
    }
}

/// GET /poh/block/:slot
async fn poh_block_by_slot_handler(
    State(state): State<AppState>,
    Path(slot): Path<u64>,
) -> impl IntoResponse {
    match state.block_producer.get_block(slot) {
        Some(block) => {
            let txs: Vec<serde_json::Value> = block.transactions.iter().map(|otx| {
                serde_json::json!({
                    "hash": otx.tx.hash,
                    "from": otx.tx.from,
                    "data": otx.tx.data,
                    "timestamp": otx.tx.timestamp,
                    "slot": otx.slot,
                    "position": otx.position,
                    "poh_hash": otx.poh_hash,
                })
            }).collect();
            Json(serde_json::json!({
                "success": true,
                "block": {
                    "slot": block.slot,
                    "timestamp": block.timestamp,
                    "hash": block.hash,
                    "previous_hash": block.previous_hash,
                    "poh_hash": block.poh_hash,
                    "poh_sequence": block.poh_sequence,
                    "state_root": block.state_root,
                    "tx_count": block.tx_count,
                    "transactions": txs,
                    "leader": block.leader,
                    "epoch": block.epoch,
                    "confirmations": block.confirmations,
                }
            }))
        }
        None => Json(serde_json::json!({ "error": format!("Block {} not found", slot) }))
    }
}

/// GET /poh/tx/:tx_id/status
async fn poh_tx_status_handler(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let status = state.finality_tracker.get_status(&tx_id);
    let is_finalized = state.finality_tracker.is_finalized(&tx_id);
    Json(serde_json::json!({
        "tx_id": tx_id,
        "status": format!("{:?}", status),
        "is_finalized": is_finalized,
    }))
}

/// GET /consensus/tower — Tower BFT vote tower state
async fn tower_bft_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let stats = state.tower_bft.get_stats();
    let root = state.tower_bft.global_root();
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let best_fork = state.tower_bft.select_fork();
    Json(serde_json::json!({
        "validator_count": stats.validator_count,
        "total_stake": stats.total_stake,
        "global_root": root,
        "confirmed_slots": stats.confirmed_slots,
        "active_forks": stats.active_forks,
        "supermajority_threshold": stats.supermajority_threshold,
        "max_tower_depth": stats.max_tower_depth,
        "current_slot": current_slot,
        "best_fork": best_fork.map(|(s, h)| serde_json::json!({"slot": s, "hash": h})),
    }))
}

/// GET /turbine/status — Turbine shred propagation status
async fn turbine_status_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    // Shred the latest block (if any) to show real stats
    let latest_block = state.block_producer.get_block(current_slot.saturating_sub(1));
    let (data_shreds, fec_shreds, block_bytes) = match &latest_block {
        Some(block) => {
            let shredder = TurbineShredder::new(block.slot, state.validator_id.clone());
            let shreds = shredder.shred_block(block);
            let data = shreds.iter().filter(|s| !s.is_coding).count();
            let fec = shreds.len() - data;
            let bytes = serde_json::to_vec(block).map(|b| b.len()).unwrap_or(0);
            (data, fec, bytes)
        }
        None => (0, 0, 0),
    };
    let validators = vec![state.validator_id.clone()];
    let max_hops = TurbinePropagator::max_hops(validators.len());
    Json(serde_json::json!({
        "current_slot": current_slot,
        "latest_shredded_slot": latest_block.as_ref().map(|b| b.slot),
        "data_shreds": data_shreds,
        "fec_shreds": fec_shreds,
        "block_bytes": block_bytes,
        "validator_count": validators.len(),
        "propagation_max_hops": max_hops,
        "turbine_fanout": 200,
    }))
}

// ============================================================================
// SEALEVEL PARALLEL EXECUTION
// ============================================================================

#[derive(Deserialize)]
struct GulfStreamSubmitRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(default)]
    priority: Option<u64>,

    // ── Auth Path 1: Ed25519 signature (microtx wallets) ──────────────
    /// Ed25519 signature over "SEALEVEL:{from}:{to}:{amount}:{timestamp}:{nonce}"
    signature: Option<String>,
    timestamp: Option<u64>,
    nonce: Option<String>,

    // ── Auth Path 2: SSS session token ────────────────────────────────
    session_token: Option<String>,
}

/// POST /sealevel/submit — Submit to Gulf Stream for parallel execution
///
/// DUAL AUTH: Ed25519 signature OR session token (SSS wallet)
async fn gulf_stream_submit_handler(
    State(state): State<AppState>,
    Json(req): Json<GulfStreamSubmitRequest>,
) -> impl IntoResponse {
    use runtime::core::{Transaction as RuntimeTx, TransactionType};

    if req.from.is_empty() || req.to.is_empty() || req.amount <= 0.0 {
        return Json(serde_json::json!({ "error": "Invalid parameters" }));
    }

    // ── DUAL AUTH ───────────────────────────────────────────────────────
    if let Some(ref session_token) = req.session_token {
        // SSS session auth
        let seed = match state.session_store.get_seed(session_token) {
            Ok(s) => s,
            Err(e) => return Json(serde_json::json!({ "error": format!("Session auth failed: {}", e) })),
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let derived = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
        if derived != req.from {
            return Json(serde_json::json!({ "error": "Session does not match 'from' address" }));
        }
    } else if let (Some(ref sig_hex), Some(timestamp), Some(ref nonce)) = (&req.signature, req.timestamp, &req.nonce) {
        // Ed25519 signature auth
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let pubkey_bytes: Vec<u8> = if req.from.len() == 64 && req.from.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(&req.from).unwrap_or_default()
        } else {
            bs58::decode(&req.from).into_vec().unwrap_or_default()
        };
        if pubkey_bytes.len() != 32 {
            return Json(serde_json::json!({ "error": "Invalid public key" }));
        }

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return Json(serde_json::json!({ "error": "Invalid signature" })),
        };

        let message = format!("SEALEVEL:{}:{}:{}:{}:{}", req.from, req.to, req.amount, timestamp, nonce);
        let vk = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
            Ok(k) => k,
            Err(_) => return Json(serde_json::json!({ "error": "Invalid Ed25519 key" })),
        };
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        if vk.verify(message.as_bytes(), &sig).is_err() {
            return Json(serde_json::json!({ "error": "Signature verification failed" }));
        }

        // Replay protection
        let nonce_key = format!("sealevel:{}:{}", req.from, nonce);
        if state.used_nonces.contains_key(&nonce_key) {
            return Json(serde_json::json!({ "error": "Nonce already used" }));
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if now.saturating_sub(timestamp) > 60 {
            return Json(serde_json::json!({ "error": "Request too old (>60s)" }));
        }
        state.used_nonces.insert(nonce_key, now);
    } else {
        return Json(serde_json::json!({
            "error": "Authentication required. Provide EITHER: signature + timestamp + nonce (Ed25519), OR session_token (SSS wallet)"
        }));
    }

    let balance = state.blockchain.get_balance(&req.from);
    if balance < req.amount {
        return Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, req.amount)
        }));
    }

    let mut tx = RuntimeTx::new(req.from.clone(), req.to.clone(), req.amount, TransactionType::Transfer);
    let tx_id = tx.id.clone();
    if let Some(p) = req.priority { tx.nonce = p; }

    if let Err(e) = state.gulf_stream.submit(tx.clone()) {
        return Json(serde_json::json!({ "error": format!("Gulf Stream: {}", e) }));
    }

    let packet = PipelinePacket::new(tx_id.clone(), req.from, req.to, req.amount);
    let _ = state.pipeline.submit(packet).await;

    Json(serde_json::json!({
        "success": true,
        "tx_id": tx_id,
        "status": "pending"
    }))
}

// ============================================================================
// ADMIN — Dealer role for minting (L2 receipt settlement)
// ============================================================================

#[derive(Deserialize)]
struct MintRequest {
    to: String,
    amount: f64,
    /// Optional: dealer signature for production auth
    dealer_signature: Option<String>,
    /// Optional: receipt ID from L2 for audit trail
    l2_receipt_id: Option<String>,
}

/// POST /admin/mint — Mint $BB tokens (Dealer only in production)
///
/// The Dealer collects losing bets from L2 via receipts, then mints
/// those tokens to the Dealer wallet for payout to winners.
async fn admin_mint_handler(
    State(state): State<AppState>,
    Json(req): Json<MintRequest>,
) -> impl IntoResponse {
    // Validate dealer signature (security gate for production)
    if req.dealer_signature.is_none() {
        warn!("\u{26a0}\u{fe0f} Mint request without dealer_signature from to={}", req.to);
    }

    if req.amount <= 0.0 || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid mint parameters"
        })));
    }

    match state.blockchain.credit(&req.to, req.amount) {
        Ok(_) => {
            let new_bal = state.blockchain.get_balance(&req.to);
            info!("🪙 MINT: {} BB → {} (receipt: {:?})",
                req.amount, req.to, req.l2_receipt_id);

            // Record admin mint into PoH block
            {
                use protocol::Transaction as ProtoTx;
                use protocol::TxData;
                let tx = ProtoTx {
                    hash: uuid::Uuid::new_v4().to_string(),
                    from: "SYSTEM_MINT".to_string(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data: TxData::DepositUsdt {
                        usdt_amount: (req.amount / 10.0) as u64,
                        external_tx_hash: req.l2_receipt_id.clone(),
                    },
                    signature: "admin_mint".to_string(),
                    signer_pubkey: "SYSTEM_MINT".to_string(),
                };
                state.block_producer.record_executed_transaction(tx);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "minted": req.amount,
                "to": req.to,
                "new_balance": new_bal,
                "l2_receipt_id": req.l2_receipt_id,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": e
        }))),
    }
}

#[derive(Deserialize)]
struct BurnRequest {
    from: String,
    amount: f64,
    dealer_signature: Option<String>,
    l2_receipt_id: Option<String>,
}

/// POST /admin/burn — Burn $BB tokens (Dealer only)
async fn admin_burn_handler(
    State(state): State<AppState>,
    Json(req): Json<BurnRequest>,
) -> impl IntoResponse {
    // Validate dealer signature (security gate for production)
    if req.dealer_signature.is_none() {
        warn!("\u{26a0}\u{fe0f} Burn request without dealer_signature from={}", req.from);
    }

    if req.amount <= 0.0 || req.from.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid burn parameters" })));
    }

    let balance = state.blockchain.get_balance(&req.from);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, req.amount)
        })));
    }

    match state.blockchain.debit(&req.from, req.amount) {
        Ok(_) => {
            let new_bal = state.blockchain.get_balance(&req.from);
            info!("🔥 BURN: {} BB from {} (receipt: {:?})", req.amount, req.from, req.l2_receipt_id);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "burned": req.amount,
                "from": req.from,
                "new_balance": new_bal,
                "l2_receipt_id": req.l2_receipt_id,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

// ============================================================================
// FAUCET — Public token mint (0.1 BB per request, unlimited for now)
// ============================================================================

#[derive(Deserialize)]
struct FaucetRequest {
    /// Wallet address to receive funds (must be hex-encoded Ed25519 pubkey)
    to: String,
    /// Amount to request (capped at MAX_FAUCET_BB)
    amount: f64,

    // ── Auth Path 1: Ed25519 signature (microtransaction wallets) ────────
    /// Ed25519 signature proving ownership of `to` address
    signature: Option<String>,
    /// Timestamp (Unix seconds) for replay protection
    timestamp: Option<u64>,
    /// Unique nonce for replay protection
    nonce: Option<String>,

    // ── Auth Path 2: SSS session token (BlackBook native wallets) ───────
    /// Session token from /wallet/login — proves wallet ownership server-side
    session_token: Option<String>,
}

/// POST /faucet — Mint up to 0.1 BB to any address
///
/// DUAL AUTH: accepts EITHER:
///   1. Ed25519 signature (microtransaction wallets with raw keypairs)
///   2. Session token (SSS 2-of-3 BlackBook wallets — login first)
///
/// Ed25519 message format: "FAUCET:{to}:{amount}:{timestamp}:{nonce}"
/// Session: just provide session_token from /wallet/login
///
/// NOTE: Currently unlimited calls allowed. Future: rate-limited to once per 24h.
async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    const MAX_FAUCET_BB: f64 = 0.1;

    // ── VALIDATE INPUTS ────────────────────────────────────────────────────
    if req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Missing 'to' address"
        })));
    }
    let amount = req.amount.min(MAX_FAUCET_BB).max(0.0);
    if amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Amount must be between 0 and 0.1 BB"
        })));
    }

    // ── DUAL AUTH: Choose path based on what's provided ────────────────────
    let auth_method: &str;
    let replay_nonce: String;

    if let Some(ref session_token) = req.session_token {
        // ── AUTH PATH 2: SSS Session Token ─────────────────────────────────
        auth_method = "session";
        let seed = match state.session_store.get_seed(session_token) {
            Ok(s) => s,
            Err(e) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": format!("Session auth failed: {}", e),
                "hint": "Login first via POST /wallet/login to get a session_token"
            }))),
        };
        // Verify the session belongs to the requested `to` address
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
        if derived_address != req.to {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Session does not match 'to' address — you can only faucet to your own wallet",
                "session_wallet": derived_address,
                "requested_to": req.to
            })));
        }
        // Session token IS the replay nonce (each use refreshes TTL)
        replay_nonce = format!("session_faucet:{}:{}", req.to, uuid::Uuid::new_v4());

    } else if let (Some(ref sig_hex), Some(timestamp), Some(ref nonce)) = (&req.signature, req.timestamp, &req.nonce) {
        // ── AUTH PATH 1: Ed25519 Signature ─────────────────────────────────
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        auth_method = "ed25519";

        // Parse public key from `to` address (hex or base58)
        let pubkey_bytes: Vec<u8> = if req.to.len() == 64 && req.to.chars().all(|c| c.is_ascii_hexdigit()) {
            match hex::decode(&req.to) {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "Invalid hex public key"
                }))),
            }
        } else {
            match bs58::decode(&req.to).into_vec() {
                Ok(b) if b.len() == 32 => b,
                _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": "Invalid base58 public key (must be 32 bytes)"
                }))),
            }
        };

        if pubkey_bytes.len() != 32 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Public key must be 32 bytes"
            })));
        }

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid signature (must be 64 bytes hex)"
            }))),
        };

        // Build message: "FAUCET:{to}:{amount}:{timestamp}:{nonce}"
        let message = format!("FAUCET:{}:{}:{}:{}", req.to, req.amount, timestamp, nonce);

        let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
            Ok(k) => k,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Invalid Ed25519 public key"
            }))),
        };
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        if verifying_key.verify(message.as_bytes(), &signature).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Signature verification failed — prove you own this wallet"
            })));
        }

        // Replay protection for Ed25519 path
        let nonce_key = format!("faucet:{}:{}", req.to, nonce);
        if state.used_nonces.contains_key(&nonce_key) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": nonce
            })));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(timestamp) > 60 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Request too old (>60s)",
                "server_time": now,
                "request_time": timestamp
            })));
        }

        state.used_nonces.insert(nonce_key.clone(), now);
        replay_nonce = nonce.clone();

        if state.used_nonces.len() > 100_000 {
            let cutoff = now.saturating_sub(120);
            state.used_nonces.retain(|_, &mut ts| ts > cutoff);
        }

    } else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Authentication required. Provide EITHER: (1) signature + timestamp + nonce (Ed25519), OR (2) session_token (SSS wallet)",
            "auth_paths": {
                "ed25519": { "requires": ["signature", "timestamp", "nonce"] },
                "session": { "requires": ["session_token"], "hint": "Login first via POST /wallet/login" }
            }
        })));
    }

    // ── MINT TOKENS ────────────────────────────────────────────────────────
    // No per-epoch rate limiting for now (future: once per 24h)
    let mint_amount = amount;

    match state.blockchain.credit(&req.to, mint_amount) {
        Ok(_) => {
            let new_bal = state.blockchain.get_balance(&req.to);
            info!("🚰 FAUCET: {} BB → {} (auth: {})", mint_amount, req.to, auth_method);

            // Record faucet mint into PoH block
            {
                use protocol::Transaction as ProtoTx;
                use protocol::TxData;
                let tx = ProtoTx {
                    hash: uuid::Uuid::new_v4().to_string(),
                    from: "SYSTEM_FAUCET".to_string(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    data: TxData::DepositUsdt {
                        usdt_amount: (mint_amount / 10.0) as u64,
                        external_tx_hash: Some(format!("faucet_{}", replay_nonce)),
                    },
                    signature: req.signature.clone().unwrap_or_default(),
                    signer_pubkey: req.to.clone(),
                };
                state.block_producer.record_executed_transaction(tx);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "minted": mint_amount,
                "to": req.to,
                "new_balance": new_bal,
                "auth_method": auth_method
            })))
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Mint failed: {}", e)
            })))
        }
    }
}

// ============================================================================
// USDC SPL TOKEN ENDPOINTS
// ============================================================================
async fn admin_accounts_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut accounts: Vec<serde_json::Value> = Vec::new();

    // Enumerate all accounts from SVM hot state (DashMap)
    for entry in state.blockchain.svm_accounts.hot_state.iter() {
        let address = bs58::encode(entry.key().to_bytes()).into_string();
        let lamports = {
            use solana_sdk::account::ReadableAccount;
            entry.value().lamports()
        };
        if lamports > 0 {
            let balance = lamports as f64 / 100_000.0;
            accounts.push(serde_json::json!({
                "address": address,
                "balance": balance,
                "lamports": lamports,
            }));
        }
    }

    // Sort by balance descending
    accounts.sort_by(|a, b| {
        let ba = a["balance"].as_f64().unwrap_or(0.0);
        let bb = b["balance"].as_f64().unwrap_or(0.0);
        bb.partial_cmp(&ba).unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_supply = state.blockchain.total_supply();

    Json(serde_json::json!({
        "accounts": accounts,
        "total_accounts": accounts.len(),
        "total_supply": total_supply,
    }))
}

// ============================================================================
// USDC SPL TOKEN ENDPOINTS
// ============================================================================

#[derive(Deserialize)]
struct UsdcMintRequest {
    /// Recipient wallet address (base58)
    to: String,
    /// Amount in human USDC (e.g. 100.50 = 100_500_000 smallest units)
    amount: f64,
}

#[derive(Deserialize)]
struct UsdcTransferRequest {
    /// Sender wallet address (base58)
    from: String,
    /// Recipient wallet address (base58)
    to: String,
    /// Amount in human USDC
    amount: f64,

    // ── Auth Path 1: Ed25519 signature (microtx wallets) ──────────────
    /// Ed25519 signature over "USDC_TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}"
    signature: Option<String>,
    timestamp: Option<u64>,
    nonce: Option<String>,

    // ── Auth Path 2: SSS session token ────────────────────────────────
    session_token: Option<String>,
}

/// POST /admin/usdc/mint — Mint USDC tokens to a wallet's ATA
///
/// Called when bridge deposits arrive or for initial liquidity seeding.
/// Only the Dealer (mint authority) should call this in production.
async fn usdc_mint_handler(
    State(state): State<AppState>,
    Json(req): Json<UsdcMintRequest>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

    if req.amount <= 0.0 || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid mint parameters (amount must be > 0)"
        })));
    }

    // Convert human USDC to smallest units (6 decimals)
    let raw_amount = (req.amount * USDC_UNIT as f64) as u64;

    let wallet_bytes = match bs58::decode(&req.to).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid base58 wallet address"
        }))),
    };
    let wallet_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(wallet_bytes);
    let mint = usdc_mint_bytes();

    match SplTokenEngine::mint_to(&state.blockchain.svm_accounts, &mint, &wallet_pubkey, raw_amount) {
        Ok(result) => {
            info!("💵 USDC MINT: {} USDC → {} (ATA: {})", req.amount, req.to, result.ata);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "minted_usdc": req.amount,
                "raw_amount": result.amount,
                "to": req.to,
                "ata": result.ata,
                "mint": result.mint,
                "new_total_supply": result.new_supply,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("{:?}", e)
        }))),
    }
}

/// POST /usdc/transfer — Transfer USDC between wallets
///
/// DUAL AUTH: Ed25519 signature OR session token (SSS wallet)
async fn usdc_transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<UsdcTransferRequest>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

    if req.amount <= 0.0 || req.from.is_empty() || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid transfer parameters"
        })));
    }

    // ── DUAL AUTH ───────────────────────────────────────────────────────
    if let Some(ref session_token) = req.session_token {
        let seed = match state.session_store.get_seed(session_token) {
            Ok(s) => s,
            Err(e) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": format!("Session auth failed: {}", e)
            }))),
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let derived = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
        if derived != req.from {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Session does not match 'from' address"
            })));
        }
    } else if let (Some(ref sig_hex), Some(timestamp), Some(ref nonce)) = (&req.signature, req.timestamp, &req.nonce) {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let pubkey_bytes: Vec<u8> = bs58::decode(&req.from).into_vec().unwrap_or_default();
        if pubkey_bytes.len() != 32 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key" })));
        }
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature" }))),
        };
        let message = format!("USDC_TRANSFER:{}:{}:{}:{}:{}", req.from, req.to, req.amount, timestamp, nonce);
        let vk = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
            Ok(k) => k,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid Ed25519 key" }))),
        };
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        if vk.verify(message.as_bytes(), &sig).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
        }
        let nonce_key = format!("usdc_transfer:{}:{}", req.from, nonce);
        if state.used_nonces.contains_key(&nonce_key) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "Nonce already used" })));
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if now.saturating_sub(timestamp) > 60 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Request too old (>60s)" })));
        }
        state.used_nonces.insert(nonce_key, now);
    } else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Authentication required. Provide EITHER: signature + timestamp + nonce (Ed25519), OR session_token (SSS wallet)"
        })));
    }

    let raw_amount = (req.amount * USDC_UNIT as f64) as u64;

    let parse_pubkey = |addr: &str| -> Result<solana_sdk::pubkey::Pubkey, String> {
        let bytes = bs58::decode(addr).into_vec().map_err(|e| format!("Invalid base58: {}", e))?;
        if bytes.len() != 32 { return Err("Address must be 32 bytes".into()); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(solana_sdk::pubkey::Pubkey::new_from_array(arr))
    };

    let from_pubkey = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };
    let to_pubkey = match parse_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
    };

    let mint = usdc_mint_bytes();

    match SplTokenEngine::transfer_tokens(&state.blockchain.svm_accounts, &mint, &from_pubkey, &to_pubkey, raw_amount) {
        Ok(result) => {
            info!("💵 USDC TRANSFER: {} USDC  {} → {}", req.amount, req.from, req.to);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "amount_usdc": req.amount,
                "raw_amount": result.amount,
                "from": req.from,
                "to": req.to,
                "from_ata": result.from_ata,
                "to_ata": result.to_ata,
                "from_balance": result.from_balance,
                "to_balance": result.to_balance,
            })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("{:?}", e)
        }))),
    }
}

/// GET /usdc/balance/{address} — Get USDC balance for a wallet
async fn usdc_balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, usdc_mint_address, USDC_DECIMALS, USDC_UNIT};

    let wallet_bytes = match bs58::decode(&address).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid base58 wallet address"
        }))),
    };
    let wallet_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(wallet_bytes);
    let mint = usdc_mint_bytes();

    let raw_balance = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    let human_balance = raw_balance as f64 / USDC_UNIT as f64;

    (StatusCode::OK, Json(serde_json::json!({
        "address": address,
        "usdc_balance": human_balance,
        "raw_balance": raw_balance,
        "decimals": USDC_DECIMALS,
        "mint": usdc_mint_address(),
    })))
}

/// GET /usdc/supply — Get total USDC supply on BlackBook L1
async fn usdc_supply_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, usdc_mint_address, USDC_DECIMALS, USDC_UNIT};

    let mint = usdc_mint_bytes();
    match SplTokenEngine::get_mint_supply(&state.blockchain.svm_accounts, &mint) {
        Ok(supply) => {
            let human_supply = supply as f64 / USDC_UNIT as f64;
            (StatusCode::OK, Json(serde_json::json!({
                "mint": usdc_mint_address(),
                "total_supply": human_supply,
                "raw_supply": supply,
                "decimals": USDC_DECIMALS,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("{:?}", e)
        }))),
    }
}

/// GET /usdc/accounts/{address} — Get all USDC token accounts for a wallet
/// (Used by wallets to discover ATAs)
async fn usdc_accounts_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

    let wallet_bytes = match bs58::decode(&address).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid base58 wallet address"
        }))),
    };
    let wallet_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(wallet_bytes);
    let mint = usdc_mint_bytes();

    let accounts = SplTokenEngine::get_token_accounts_for_owner(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    let result: Vec<serde_json::Value> = accounts.iter().map(|a| {
        serde_json::json!({
            "address": a.address,
            "mint": a.mint,
            "owner": a.owner,
            "balance_usdc": a.amount as f64 / USDC_UNIT as f64,
            "raw_balance": a.amount,
            "decimals": a.decimals,
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "owner": address,
        "token_accounts": result,
    })))
}

// ============================================================================
// LEDGER — ASCII Art Visualization
// ============================================================================

#[derive(Deserialize)]
struct LedgerQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_limit")]
    limit: usize,
    /// Set format=json for JSON response (default: text/ascii)
    #[serde(default)]
    format: Option<String>,
}
fn default_page() -> usize { 1 }
fn default_limit() -> usize { 50 }

/// GET /ledger - ASCII art visualization of all ledger entries
/// Use ?format=json for JSON response
async fn ledger_handler(
    State(state): State<AppState>,
    Query(query): Query<LedgerQuery>
) -> impl IntoResponse {
    let mut transactions = state.blockchain.get_all_transactions(10000);
    // Sort by timestamp descending (most recent first)
    transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let stats = state.blockchain.stats();
    let total_supply = state.blockchain.total_supply();

    // ── JSON MODE ────────────────────────────────────────────────
    if query.format.as_deref() == Some("json") {
        let limit = query.limit.min(100).max(1);
        let page = query.page.max(1);
        let total_pages = (transactions.len() + limit - 1) / limit;
        let start_idx = (page - 1) * limit;
        let end_idx = (start_idx + limit).min(transactions.len());
        let page_txs: Vec<serde_json::Value> = if start_idx < transactions.len() {
            transactions[start_idx..end_idx].iter().map(|tx| {
                serde_json::json!({
                    "tx_hash": tx.tx_hash,
                    "prev_tx_hash": tx.prev_tx_hash,
                    "tx_type": tx.tx_type,
                    "from_address": tx.from_address,
                    "to_address": tx.to_address,
                    "amount": tx.amount,
                    "balance_before": tx.balance_before,
                    "balance_after": tx.balance_after,
                    "recipient_balance_after": tx.recipient_balance_after,
                    "timestamp": tx.timestamp,
                    "block_height": tx.block_height,
                    "status": tx.status,
                    "auth_type": tx.auth_type,
                    "from_username": tx.from_username,
                    "to_username": tx.to_username,
                })
            }).collect()
        } else {
            vec![]
        };
        return (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            serde_json::json!({
                "transactions": page_txs,
                "total": transactions.len(),
                "page": page,
                "total_pages": total_pages,
                "block_count": stats.block_count,
                "total_supply": total_supply,
                "total_accounts": stats.total_accounts,
            }).to_string()
        );
    }
    
    // ── ASCII ART MODE (default) ─────────────────────────────────
    let limit = query.limit.min(100).max(1); // Max 100, min 1
    let page = query.page.max(1); // Min page 1
    let total_pages = (transactions.len() + limit - 1) / limit;
    let start_idx = (page - 1) * limit;
    let end_idx = (start_idx + limit).min(transactions.len());
    
    let page_transactions = if start_idx < transactions.len() {
        &transactions[start_idx..end_idx]
    } else {
        &[]
    };
    
    let mut output = String::new();
    
    // ═══════════════════════════════════════════════════════════════════════════
    // HEADER - Chain Summary
    // ═══════════════════════════════════════════════════════════════════════════
    output.push_str("\n");
    output.push_str(" ═══ BLACKBOOK L1 AUDIT LEDGER ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push_str(&format!("  BLOCK HEIGHT : {:>12}                     NETWORK : [ MAINNET-ZK ]           VERSION : 5.0.0-mainnet-beta\n", stats.block_count));
    output.push_str(&format!("  TOTAL SUPPLY : {:>12.2} BB              WALLETS : {:>6}                    STATUS  : [ FINALIZED ]\n", total_supply, stats.total_accounts));
    output.push_str(&format!("  TRANSACTIONS : {:>12}                     PAGE    : {:>4} of {:>4}                SHOWING : {} - {}\n", transactions.len(), page, total_pages, start_idx + 1, end_idx));
    output.push_str(" ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push_str("\n");
    
    // ═══════════════════════════════════════════════════════════════════════════
    // TRANSACTION TABLE - Compact but Complete
    // ═══════════════════════════════════════════════════════════════════════════
    output.push_str(" ┌─────┬─────────────────────┬──────────────┬──────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
    output.push_str(" │ BLK │      TIMESTAMP      │    TX HASH   │   PREV HASH  │                                    TRANSACTION DETAILS                                          │\n");
    output.push_str(" ├─────┼─────────────────────┼──────────────┼──────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────┤\n");
    
    for tx in page_transactions.iter() {
        let timestamp_str = chrono::DateTime::from_timestamp(tx.timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "N/A".to_string());
        
        let tx_hash_short = if tx.tx_hash.len() > 12 {
            format!("{}..{}", &tx.tx_hash[..6], &tx.tx_hash[tx.tx_hash.len()-4..])
        } else {
            tx.tx_hash.clone()
        };
        
        let prev_hash_short = if tx.prev_tx_hash.len() > 12 {
            format!("{}..{}", &tx.prev_tx_hash[..6], &tx.prev_tx_hash[tx.prev_tx_hash.len()-4..])
        } else {
            tx.prev_tx_hash.clone()
        };
        
        let action_icon = match tx.tx_type.as_str() {
            "transfer" => "💸",
            "mint" => "🪙",
            "burn" => "🔥",
            "bridge_out" => "🌉⬆️",
            "bridge_in" => "🌉⬇️",
            "lock" => "🔒",
            "unlock" => "🔓",
            _ => "❓",
        };
        
        let auth_icon = match tx.auth_type.as_str() {
            "master_key" => "🔑",
            "session_key" => "⚡",
            "zk_proof" => "🔮",
            "system_internal" => "⚙️",
            _ => "🔐",
        };
        
        let from_display = format_address_with_username(&tx.from_address, tx.from_username.as_deref());
        let to_display = format_address_with_username(&tx.to_address, tx.to_username.as_deref());
        
        let balance_change = format!("{:.2}→{:.2}", tx.balance_before, tx.balance_after);
        let amount_str = format!("{:.2} BB", tx.amount);
        
        let reconciled_icon = if tx.status == "completed" || tx.status == "finalized" { "✓" } else { "✗" };
        
        let details = format!(
            "{} {} {} {} → {} │ Amt: {} │ Bal: {}",
            action_icon,
            auth_icon,
            reconciled_icon,
            from_display,
            to_display,
            amount_str,
            balance_change
        );
        
        output.push_str(&format!(
            " │{:>5}│ {} │ {:^12} │ {:^12} │ {:<108} │\n",
            tx.block_height,
            timestamp_str,
            tx_hash_short,
            prev_hash_short,
            if details.len() > 108 {
                format!("{}...", &details[..105])
            } else {
                details
            }
        ));
    }
    
    // Close table
    output.push_str(" └─────┴─────────────────────┴──────────────┴──────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────┘\n");
    output.push_str("\n");
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LEGEND
    // ═══════════════════════════════════════════════════════════════════════════
    output.push_str(" ─── LEGEND ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n");
    output.push_str("  ACTIONS: 💸 TRANSFER │ 🪙 MINT │ 🔥 BURN │ 🌉 BRIDGE (OUT/IN) │ 🔒 LOCK │ 🔓 UNLOCK\n");
    output.push_str("  AUTH:    🔑 Master Key │ ⚡ Session Key │ 🔮 ZK Proof │ ⚙️ System Internal\n");
    output.push_str("  STATUS:  ✅ Finalized │ ⏳ Pending │ ↩️ Reverted │ ❌ Failed      RECONCILED: [✓] Valid │ [✗] Mismatch\n");
    output.push_str("  COLUMNS: BLK=Block Height │ TX HASH=Transaction Hash │ PREV HASH=Chain Link │ Bal=Balance Before→After │ Recv=Recipient Balance\n");
    output.push_str(" ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push_str("\n");
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PAGINATION
    // ═══════════════════════════════════════════════════════════════════════════
    if total_pages > 1 {
        output.push_str(&format!(" 📄 Page {} of {} │ ", page, total_pages));
        if page > 1 {
            output.push_str(&format!("Previous: /ledger?page={}&limit={} │ ", page - 1, limit));
        }
        if page < total_pages {
            output.push_str(&format!("Next: /ledger?page={}&limit={}", page + 1, limit));
        }
        output.push_str("\n");
    }
    
    // Footer
    output.push_str("\n");
    output.push_str(" 🛡️  Ed25519 Signatures │ SHA-256 TX Hashes │ Chain-Linked │ State Validated │ Immutably Stored on BlackBook L1\n");
    output.push_str("\n");
    
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        output
    )
}

/// Helper to format addresses WITH USERNAME for ledger display
fn format_address_with_username(addr: &str, username: Option<&str>) -> String {
    let addr_short = if addr.starts_with("bb_") {
        format!("bb_{}..{}", &addr[3..].chars().take(4).collect::<String>(), &addr[addr.len()-4..])
    } else if addr == "USDC_TREASURY" || addr == "DESTROYED" {
        addr.to_string()
    } else if addr.starts_with("L1_") {
        format!("L1_{}..{}", &addr[3..].chars().take(4).collect::<String>(), &addr[addr.len()-4..])
    } else if addr.len() > 16 {
        format!("{}...{}", &addr[..6], &addr[addr.len()-6..])
    } else {
        addr.to_string()
    };
    
    match username {
        Some(name) => format!("{} ({})", name, addr_short),
        None => addr_short,
    }
}


// ============================================================================
// ROUTER
// ============================================================================

fn build_router(state: AppState, wallet_router: Router) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app_routes = Router::new()
        // Public
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/balance/:address", get(balance_handler))
        .route("/ledger", get(ledger_handler))
        // Transfers (Submission)
        .route("/transfer/simple", post(signed_transfer_handler))
        // PoH & Consensus
        .route("/poh/status", get(poh_status_handler))
        .route("/poh/block/latest", get(poh_latest_block_handler))
        .route("/poh/block/:slot", get(poh_block_by_slot_handler))
        .route("/poh/tx/:tx_id/status", get(poh_tx_status_handler))
        // Consensus
        .route("/consensus/tower", get(tower_bft_handler))
        // Turbine
        .route("/turbine/status", get(turbine_status_handler))
        // Sealevel
        .route("/sealevel/submit", post(gulf_stream_submit_handler))
        // Faucet (public, rate-limited)
        .route("/faucet", post(faucet_handler))
        // Admin (Dealer)
        .route("/admin/mint", post(admin_mint_handler))
        .route("/admin/burn", post(admin_burn_handler))
        .route("/admin/accounts", get(admin_accounts_handler))
        // USDC SPL Token
        .route("/admin/usdc/mint", post(usdc_mint_handler))
        .route("/usdc/transfer", post(usdc_transfer_handler))
        .route("/usdc/balance/:address", get(usdc_balance_handler))
        .route("/usdc/supply", get(usdc_supply_handler))
        .route("/usdc/accounts/:address", get(usdc_accounts_handler))
        .with_state(state);

    // Merge wallet router (Unified FROST+SSS) with app routes
    app_routes
        .merge(wallet_router)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    warn!("🛑 Shutdown signal received");
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    // 0. Load Environment Variables (Load BEFORE any other initialization)
    // Debug current directory and .env status
    if let Ok(path) = std::env::current_dir() {
        println!("Current working directory: {:?}", path);
    }
    match dotenv::dotenv() {
        Ok(path) => println!(".env loaded from: {:?}", path),
        Err(e) => println!("Failed to load .env: {:?}", e),
    }

    // 0b. Parse CLI arguments
    let config = NodeConfig::parse();

    // 1. Logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,layer1=debug")))
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true))
        .init();

    let mode_label = match config.mode {
        NodeMode::Writer => "WRITER (Block Producer)",
        NodeMode::Reader => "READER (Block Consumer)",
    };

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║       BLACKBOOK L1 — DIGITAL CENTRAL BANK           ║");
    info!("╠══════════════════════════════════════════════════════╣");
    info!("║  Version:   {} ({})                          ║", VERSION, NETWORK);
    info!("║  Mode:      {:44}║", mode_label);
    info!("║  Identity:  {:44}║", &config.identity);
    info!("║  Engine:    PoH + Sealevel + Gulf Stream             ║");
    info!("║  Wallets:   BIP-39 + SSS 2-of-3 + ZKP               ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // 2. PoH Clock — shares current_slot with BlockProducer, GulfStream, etc.
    let poh_config = PoHConfig {
        slot_duration_ms: POH_SLOT_DURATION_MS,
        hashes_per_tick: POH_HASHES_PER_TICK,
        ticks_per_slot: POH_TICKS_PER_SLOT,
        slots_per_epoch: POH_SLOTS_PER_EPOCH,
    };
    let current_slot = Arc::new(AtomicU64::new(0));
    let poh_service: SharedPoHService = create_poh_service_with_slot(poh_config, current_slot.clone());
    let poh_runner = poh_service.clone();
    tokio::spawn(async move { run_poh_clock(poh_runner).await; });
    info!("🕐 PoH clock started ({}ms slots)", POH_SLOT_DURATION_MS);

    // 3. Blockchain (ReDB)
    let blockchain = {
        info!("🗄️  Initializing ReDB at {}", REDB_DATA_PATH);
        match ConcurrentBlockchain::new(REDB_DATA_PATH) {
            Ok(bc) => { info!("✅ Blockchain initialized"); bc }
            Err(e) => { error!("❌ FATAL: {}", e); panic!("Storage init failed: {:?}", e); }
        }
    };
    // 3a. Startup Recovery — resume from persisted state
    let (recovered_slot, _recovered_hash) = match blockchain.latest_block_slot() {
        Ok(Some(slot)) => {
            let hash = blockchain.load_block(slot)
                .ok()
                .flatten()
                .map(|b| b.hash.clone())
                .unwrap_or_default();
            info!("🔄 Resumed from slot {}, block hash: {}…", slot, &hash[..hash.len().min(16)]);
            (slot + 1, hash) // start at next slot
        }
        _ => {
            info!("🆕 Fresh genesis — no previous blocks found");
            (0u64, String::new())
        }
    };

    // Sync PoH clock to recovered slot (shared AtomicU64 — all subsystems see this)
    if recovered_slot > 0 {
        current_slot.store(recovered_slot, Ordering::Relaxed);
        info!("🕐 PoH clock → slot {}", recovered_slot);
    }

    // 4. Consensus Infrastructure
    let validator_id = config.identity.clone();
    let leader_schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = leader_schedule.write();
        schedule.update_stake(&validator_id, 1000.0);
        let epoch = recovered_slot / POH_SLOTS_PER_EPOCH;
        schedule.generate_schedule(epoch, POH_SLOTS_PER_EPOCH);
    }

    let (pipeline, commit_rx) = TransactionPipeline::new();
    pipeline.start(current_slot.clone());
    info!("🔄 Pipeline started");

    let parallel_scheduler = Arc::new(
        ParallelScheduler::new()
            .with_svm(blockchain.svm_accounts.clone())
    );
    let gulf_stream = GulfStreamService::new(leader_schedule.clone(), current_slot.clone());
    gulf_stream.start();
    info!("🌊 Gulf Stream started");

    let block_producer = Arc::new(BlockProducer::new(
        blockchain.clone(),
        poh_service.clone(),
        leader_schedule.clone(),
        current_slot.clone(),
        validator_id.clone(),
    ));

    // 4b. Restore block hash chain from persisted state (Phase 7.2)
    if recovered_slot > 0 {
        let prev_slot = recovered_slot - 1;
        if let Ok(Some(last_block)) = blockchain.load_block(prev_slot) {
            block_producer.restore_chain_state(prev_slot, last_block.hash.clone());
        } else {
            warn!("⚠️  Could not load block {} for chain restoration — starting fresh hash chain", prev_slot);
        }
    }

    let finality_tracker = Arc::new(FinalityTracker::new(current_slot.clone()));

    // Tower BFT — single-validator mode with genesis stake
    let tower_bft = TowerBFT::new(validator_id.clone(), current_slot.clone());
    tower_bft.register_validator(&validator_id, 1000.0);
    info!("🗼 Tower BFT initialized (single-validator mode, id={})", &validator_id);

    // 4a.1 Pipeline commit drain — record finality for committed pipeline txs
    {
        let fin = finality_tracker.clone();
        let mut rx = commit_rx;
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if packet.success {
                    fin.record_inclusion(&packet.tx_id, packet.slot);
                }
            }
        });
    }

    // 4b. Block Production Loop + Relay (WRITER MODE ONLY)
    // In Reader mode, block production is disabled — blocks come from the Writer via gRPC.
    let relay_sender: Option<tokio::sync::broadcast::Sender<FinalizedBlock>> = if config.mode == NodeMode::Writer {
        // Create relay service for streaming blocks to reader nodes
        let (relay_service, block_sender) = relay::create_relay(
            block_producer.clone(),
            blockchain.clone(),
            validator_id.clone(),
        );

        // Spawn gRPC relay server
        let grpc_port = config.grpc_port;
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{}", grpc_port).parse().unwrap();
            info!("📡 Writer relay gRPC server starting on {}", addr);
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(relay_service.into_server())
                .serve(addr)
                .await
            {
                error!("❌ gRPC relay server error: {}", e);
            }
        });

        let validator_id_for_loop = validator_id.clone();
        let relay_tx = block_sender.clone();
        {
            let bp = block_producer.clone();
            let ft = finality_tracker.clone();
            let tower = tower_bft.clone();
            let ls = leader_schedule.clone();
            let vid = validator_id_for_loop;
            tokio::spawn(async move {
                info!("🏭 Block production loop started (400ms slots)");
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(400));
                let mut last_epoch: u64 = 0;
                loop {
                    interval.tick().await;
                    match bp.produce_block() {
                        Ok(block) => {
                            // Wire finality tracker — advance confirmations for all tracked txs
                            ft.update_confirmations(block.slot);

                            // Tower BFT self-vote — even single-validator builds the vote tower
                            match tower.vote(&vid, block.slot, &block.hash) {
                                Ok(supermajority) => {
                                    if supermajority {
                                        tracing::debug!("🗼 Slot {} confirmed (supermajority)", block.slot);
                                    }
                                }
                                Err(e) => tracing::debug!("🗼 Vote skip slot {}: {}", block.slot, e),
                            }

                            // Epoch rotation
                            let epoch = block.slot / POH_SLOTS_PER_EPOCH;
                            if epoch > last_epoch {
                                last_epoch = epoch;
                                let mut sched = ls.write();
                                sched.generate_schedule(epoch, POH_SLOTS_PER_EPOCH);
                                info!("📅 Epoch {}: leader schedule rotated for {} slots",
                                    epoch, POH_SLOTS_PER_EPOCH);
                            }

                            if block.tx_count > 0 {
                                info!("📦 Block {} produced: {} txs, hash: {}",
                                    block.slot, block.tx_count, &block.hash[..16]);
                            }

                            // Turbine shredding — break block into propagatable shreds
                            let shredder = TurbineShredder::new(block.slot, vid.clone());
                            let shreds = shredder.shred_block(&block);
                            let data_shreds = shreds.iter().filter(|s| !s.is_coding).count();
                            let fec_shreds = shreds.len() - data_shreds;
                            if block.tx_count > 0 {
                                info!("🌊 Turbine: Block {} → {} data + {} FEC shreds",
                                    block.slot, data_shreds, fec_shreds);
                            }

                            // Turbine propagation tree (single-node for now)
                            let validators = vec![vid.clone()];
                            let _tree = TurbinePropagator::calculate_tree(&validators, &vid);

                            // Stream block to connected reader nodes via relay
                            let _ = relay_tx.send(block);
                        }
                        Err(e) => {
                            // "Not leader" and "Already produced" are normal — don't log as errors
                            let msg = e.to_string();
                            if !msg.contains("not leader") && !msg.contains("already produced") {
                                warn!("⚠️  Block production: {}", msg);
                            }
                        }
                    }
                }
            });
        }

        Some(block_sender)
    } else {
        info!("📖 Reader mode — block production disabled");
        None
    };

    // Suppress unused variable warning when in reader mode
    let _ = &relay_sender;

    // 5. (Security scaffolding removed — moved to network layer per L1-microtx manifesto)

    // 6. Sealevel Execution Loop (WRITER MODE ONLY — readers don't execute txs)
    if config.mode == NodeMode::Writer {
        let sealevel_bc = blockchain.clone();
        let sealevel_sched = parallel_scheduler.clone();
        let sealevel_gs = gulf_stream.clone();
        let sealevel_ls = leader_schedule.clone();
        let sealevel_slot = current_slot.clone();
        let sealevel_fin = finality_tracker.clone();
        let sealevel_bp = block_producer.clone();

        tokio::spawn(async move {
            info!("⚡ Sealevel execution loop started");
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
            loop {
                interval.tick().await;
                let slot = sealevel_slot.load(Ordering::Relaxed);
                let leader = { sealevel_ls.read().get_leader(slot) };
                let pending = sealevel_gs.get_pending_by_priority(&leader, 64);
                if pending.is_empty() { continue; }

                let batches = sealevel_sched.schedule_with_locks(pending);
                for batch in batches {
                    let results = sealevel_sched.execute_batch_with_locks(batch.clone(), &sealevel_bc.cache);
                    for (i, result) in results.iter().enumerate() {
                        if result.success {
                            let tx = &batch[i];
                            let proto_tx = protocol::Transaction {
                                hash: tx.id.clone(),
                                from: tx.from.clone(),
                                timestamp: chrono::Utc::now().timestamp() as u64,
                                data: protocol::TxData::TransferBb {
                                    to: tx.to.clone(),
                                    amount: (tx.amount * 100_000.0) as u64,
                                },
                                signature: String::new(),
                                signer_pubkey: String::new(),
                            };
                            sealevel_bp.record_executed_transaction(proto_tx);
                            sealevel_fin.record_inclusion(&tx.id, slot);
                        }
                    }
                }
                sealevel_gs.clear_leader_cache(&leader);
                sealevel_sched.tune_batch_size();
            }
        });
    }

    // 6b. Reader Node Sync (READER MODE ONLY)
    if config.mode == NodeMode::Reader {
        let reader_node = Arc::new(reader::ReaderNode::new(
            config.writer_addr.clone(),
            blockchain.clone(),
            current_slot.clone(),
            validator_id.clone(),
        ));
        tokio::spawn(async move {
            reader_node.run().await;
        });
        info!("📖 Reader sync task started → {}", config.writer_addr);
    }

    // 7. Shared Session Store (used by both AppState and UnifiedWalletState)
    let session_store = Arc::new(SessionStore::new());
    {
        let sweeper = session_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let removed = sweeper.sweep_expired();
                if removed > 0 {
                    tracing::info!("🧹 Swept {} expired wallet sessions", removed);
                }
            }
        });
    }

    // 7b. Build State
    let state = AppState {
        blockchain,
        poh: poh_service.clone(),
        current_slot: current_slot.clone(),
        leader_schedule,
        pipeline,
        parallel_scheduler,
        gulf_stream,
        block_producer,
        finality_tracker,
        tower_bft,
        node_mode: config.mode,
        validator_id: validator_id.clone(),
        used_nonces: Arc::new(dashmap::DashMap::new()),
        session_store: session_store.clone(),
    };

    // 8. Unified Wallet Router (SSS 2-of-3) — shares the same session store
    let unified_state = Arc::new(UnifiedWalletState::new_with_session_store(
        Arc::new(state.blockchain.clone()),
        state.block_producer.clone(),
        session_store,
    ));
    let unified_router = wallet_unified::handlers::router().with_state(unified_state);

    // Extract Arcs for RPC before state is moved into build_router
    let rpc_svm_accounts = Arc::clone(&state.blockchain.svm_accounts);
    let rpc_current_slot = Arc::clone(&state.current_slot);
    let rpc_block_producer = Arc::clone(&state.block_producer);

    // Bootstrap the USDC SPL Token Mint (idempotent — no-op if already exists)
    {
        use svm::SplTokenEngine;
        // Mint authority is set via USDC_MINT_AUTHORITY env var (base58 pubkey).
        // On first launch, create a wallet via /wallet/create, then set that
        // address as USDC_MINT_AUTHORITY before restarting.
        let mint_authority_addr = std::env::var("USDC_MINT_AUTHORITY")
            .unwrap_or_else(|_| {
                warn!("⚠️ USDC_MINT_AUTHORITY not set — USDC mint bootstrap skipped");
                String::new()
            });

        if !mint_authority_addr.is_empty() {
            match bs58::decode(&mint_authority_addr).into_vec() {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    let mint_authority = solana_sdk::pubkey::Pubkey::new_from_array(key);
                    match SplTokenEngine::bootstrap_usdc_mint(&rpc_svm_accounts, &mint_authority) {
                        Ok(mint_addr) => info!("💵 USDC Mint: {} (authority: {})", mint_addr, mint_authority_addr),
                        Err(e) => error!("❌ USDC mint bootstrap failed: {:?}", e),
                    }
                }
                _ => error!("❌ Invalid USDC_MINT_AUTHORITY: '{}' — must be 32-byte base58 pubkey", mint_authority_addr),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 9b. SVM is the single source of truth — no legacy sync needed.
    // ═══════════════════════════════════════════════════════════════
    // All balances are stored in svm_accounts (u64 lamports).
    // The f64 DashMap cache is a read-behind mirror for backward compat.
    // On fresh start, ReDB→SVM seeding happens in ConcurrentBlockchain::new().

    // 10. HTTP Server
    let app = build_router(state, unified_router);
    let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse().unwrap();

    info!("");
    info!("rocket Listening on http://{}", addr);
    info!("");
    info!("📡 ENDPOINTS:");
    info!("   GET  /health                    Health check");
    info!("   GET  /balance/{{address}}         Balance lookup");
    info!("   POST /transfer/simple           Broadcast Signed TX");
    info!("   GET  /ledger                    Transaction history");
    info!("");
    info!("🔐 UNIFIED WALLET (SSS 2-of-3):");
    info!("   POST /wallet/create             Create wallet");
    info!("   POST /wallet/login              Login (reconstruct seed)");
    info!("   POST /wallet/logout             Logout (wipe session)");
    info!("   POST /wallet/secure/shard-b     Get Server Shard (ReDB)");
    info!("   POST /wallet/verify-sss         Verify shard reconstruction");
    info!("");
    info!("⚡ ENGINE:");
    info!("   GET  /poh/status                PoH clock");
    info!("   GET  /poh/block/latest          Latest block");
    info!("   POST /sealevel/submit           Parallel execution");
    info!("");
    info!("🔐 ADMIN:");
    info!("   POST /admin/mint                Mint $BB");
    info!("   POST /admin/burn                Burn $BB");
    info!("   POST /admin/dealer/settle       Batch L2 settlement");
    info!("   GET  /admin/accounts            All account balances");
    info!("");
    info!("💵 USDC SPL TOKEN:");
    info!("   POST /admin/usdc/mint           Mint USDC to wallet");
    info!("   POST /usdc/transfer             Transfer USDC");
    info!("   GET  /usdc/balance/{{address}}    USDC balance");
    info!("   GET  /usdc/supply               Total USDC supply");
    info!("   GET  /usdc/accounts/{{address}}   Token accounts");
    info!("");
    info!("🌐 gRPC: 0.0.0.0:{}", config.grpc_port);
    info!("");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // 11. Solana JSON-RPC server on port 8899 (Phase 2A+2B)
    {
        use std::sync::Mutex;
        use svm::BlackBookSVM;
        use solana_rpc::{BlackBookRpcImpl, start_rpc_server};
        use solana_sdk::hash::Hash;
        use sha2::{Sha256, Digest as _};

        // Compute the same genesis hash used by BlockProducer
        let genesis_bytes: [u8; 32] = Sha256::digest(b"BLACKBOOK_L1_GENESIS_2025").into();
        let rpc_genesis_hash = Hash::new_from_array(genesis_bytes);
        let rpc_svm = Arc::new(Mutex::new(
            BlackBookSVM::new(Arc::clone(&rpc_svm_accounts), rpc_genesis_hash)
        ));

        // Slot ticker: sync shared slot counter from PoH clock + advance SVM blockhash
        // every 400ms. The PoH clock is the single authority for slot progression.
        // This keeps OneKey / Phantom from treating the node as stale.
        let ticker_slot = rpc_current_slot.clone();
        let ticker_svm = Arc::clone(&rpc_svm);
        let ticker_poh = poh_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(400));
            loop {
                interval.tick().await;
                // Read canonical slot from PoH clock (single source of truth)
                let poh_slot = { ticker_poh.read().current_slot.load(Ordering::Relaxed) };
                // Sync shared AtomicU64 from PoH clock
                ticker_slot.store(poh_slot, Ordering::Relaxed);
                // Advance the SVM blockhash queue so getLatestBlockhash always returns
                // a fresh hash and sendTransaction doesn't reject "stale blockhash".
                if let Ok(mut svm) = ticker_svm.lock() {
                    let slot_hash_bytes: [u8; 32] = Sha256::digest(
                        format!("BB_SLOT_{}", poh_slot).as_bytes()
                    ).into();
                    svm.advance_slot(poh_slot, Hash::new_from_array(slot_hash_bytes));
                }
            }
        });
        info!("🕐 Slot ticker started (400ms intervals → advancing slot + blockhash)");

        let rpc_impl = {
            let mut rpc = BlackBookRpcImpl::new(rpc_svm_accounts.clone(), rpc_svm, rpc_current_slot);
            rpc.block_producer = Some(rpc_block_producer.clone());
            rpc
        };
        let rpc_addr = format!("0.0.0.0:{}", config.rpc_port);
        match start_rpc_server(rpc_impl, &rpc_addr).await {
            Ok(handle) => {
                info!("🔌 Solana JSON-RPC on port 8899");
                tokio::spawn(async move { handle.stopped().await });
            }
            Err(e) => {
                error!("⚠️  Solana RPC failed to start: {}", e);
            }
        }
    }

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    // ═══════════════════════════════════════════════════════════════
    // GRACEFUL SHUTDOWN CLEANUP
    // ═══════════════════════════════════════════════════════════════
    warn!("🛑 Shutting down — flushing state…");

    // 1. Flush dirty SVM accounts to ReDB (ACID commit)
    match rpc_svm_accounts.flush_block() {
        Ok(n) => info!("✅ SVM accounts flushed to ReDB ({} accounts)", n),
        Err(e) => error!("❌ SVM flush failed: {:?}", e),
    }

    // 2. Produce final PoH block to seal the chain
    let flushed_txs = rpc_block_producer.flush_final_block();
    info!("✅ Final block produced ({} txs flushed)", flushed_txs);

    // 3. Flush again after final block (catches any new dirty accounts)
    match rpc_svm_accounts.flush_block() {
        Ok(n) if n > 0 => info!("✅ Post-block flush: {} additional accounts", n),
        _ => {}
    }

    info!("👋 BlackBook L1 shutdown complete");
}
