mod contracts;

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
use futures_util::{stream::StreamExt, SinkExt};
use solana_sdk::account::ReadableAccount;
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

use layer1::storage;
use layer1::poh_blockchain;
use layer1::svm;
use layer1::solana_rpc;
use layer1::relay;
use layer1::settlement;
use layer1::reader;
use layer1::watcher;
use layer1::protocol;
use layer1::runtime;

// ============================================================================
// MODULE IMPORTS
// ============================================================================

use storage::ConcurrentBlockchain;

// Solana-style consensus infrastructure
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service_with_slot, run_poh_clock,
    TransactionPipeline, LeaderSchedule, GulfStreamService,
    ParallelScheduler, PipelinePacket,
    TowerBFT,
};
use runtime::core::{
    NetworkThrottler, CircuitBreaker, LocalizedFeeMarket, AccountMetadata,
};

use poh_blockchain::{
    BlockProducer, FinalizedBlock, FinalityTracker,
    TurbineShredder, TurbinePropagator,
};


use runtime::tpu::TpuService;

/// JSON request body for the HTTP `/sealevel/submit` endpoint.
/// For the binary UDP equivalent, see `runtime::tpu::TpuPacket`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GulfStreamSubmitRequest {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
    pub chain_id: u8,
    #[serde(default)]
    pub priority: Option<u64>,
    #[serde(default)]
    pub tx_type: Option<String>,
}

// ============================================================================
// CONSTANTS
// ============================================================================

const VERSION: &str = "5.0.0";
const NETWORK: &str = "mainnet-beta";
const REDB_DATA_PATH_DEFAULT: &str = "./blockchain_data";

/// PoH Configuration (400ms slots — matching Solana for max TPS)
const POH_SLOT_DURATION_MS: u64 = 400;
const POH_HASHES_PER_TICK: u64 = 12500;
const POH_TICKS_PER_SLOT: u64 = 64;
const POH_SLOTS_PER_EPOCH: u64 = 432000; // ~3 days

// No hardcoded test accounts — this is a zero-sum stablecoin.
// All accounts are created at runtime via wallet creation endpoints.

// ============================================================================
// SVM LIVE-SYNC HELPER
// ============================================================================

// ============================================================================
// APPLICATION STATE
// ============================================================================

use tokio::sync::mpsc;

#[derive(serde::Deserialize)]
struct RpcRequest {
    method: String,
    params: Option<Vec<serde_json::Value>>,
    id: Option<u64>,
}

#[derive(serde::Serialize)]
struct RpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<u64>, // Subscription ID
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>, // "accountNotification"
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<RpcParams>,
}

#[derive(serde::Serialize)]
struct RpcParams {
    subscription: u64,
    result: RpcAccountResult,
}

#[derive(serde::Serialize)]
struct RpcAccountResult {
    context: RpcContext,
    value: RpcAccountValue,
}

#[derive(serde::Serialize)]
struct RpcContext {
    slot: u64,
}

#[derive(serde::Serialize)]
struct RpcAccountValue {
    lamports: u64,
    data: Vec<String>,
    owner: String,
    executable: bool,
    #[serde(rename = "rentEpoch")]
    rent_epoch: u64,
}

pub type WsSender = mpsc::UnboundedSender<axum::extract::ws::Message>;
pub struct WsSubscriptions {
    pub clients: dashmap::DashMap<std::net::SocketAddr, WsSender>,
    pub account_subs: dashmap::DashMap<String, dashmap::DashSet<std::net::SocketAddr>>,
}

impl WsSubscriptions {
    pub fn new() -> Self {
        Self {
            clients: dashmap::DashMap::new(),
            account_subs: dashmap::DashMap::new(),
        }
    }
}

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

    // Security infrastructure
    pub throttler: Arc<NetworkThrottler>,
    pub ws_subscriptions: Arc<WsSubscriptions>,
    pub block_tx: tokio::sync::broadcast::Sender<FinalizedBlock>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub fee_market: Arc<LocalizedFeeMarket>,
    pub account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>>,
    pub used_nonces: Arc<dashmap::DashMap<String, u64>>,

    // Faucet rate-limiter: address → (epoch_at_claim, total_minted_this_epoch)
    pub faucet_claims: Arc<dashmap::DashMap<String, (u64, f64)>>,

    // ===== Global Escrow Smart Contract =====
    /// Single global escrow PDA address (derived at startup)
    pub escrow_address: String,
    /// Ed25519 public key of the authorized L2 sequencer (hex)
    pub l2_sequencer_pubkey: String,
    /// Per-market merkle roots: market_id → [u8; 32] (raw SHA-256 root)
    /// L1 stores ONLY the 32-byte math. Metadata lives in L2 PostgreSQL.
    pub market_roots: Arc<dashmap::DashMap<String, [u8; 32]>>,
    /// Double-withdrawal protection: "{market_id}:{address}" → true
    pub withdrawal_claims: Arc<dashmap::DashMap<String, bool>>,

    // ===== Contest Settlement State =====
    /// Per-contest lifecycle state: contest_id → ContestState
    /// Hot cache, ReDB-backed via ConcurrentBlockchain.store_contest_state().
    pub contest_states: Arc<dashmap::DashMap<String, storage::ContestState>>,

    // ===== Deposit Gateway =====
    /// Custody wallet address users send wUSDT/wUSDT to (from CUSTODY_WALLET_ADDRESS env)
    pub custody_wallet_address: String,
    /// All deposit requests: external_tx_hash → DepositRecord (hot cache, ReDB-backed)
    pub deposit_requests: Arc<dashmap::DashMap<String, storage::DepositRecord>>,
    /// Background watcher that polls Solana RPC for custody wallet USDC/USDT balances.
    /// None when CUSTODY_WALLET_ADDRESS is not set.
    pub custody_watcher: Option<Arc<watcher::CustodyWatcher>>,
    /// Background watcher that polls BSC (BNB Chain) for BEP-20 USDC/USDT transfers.
    /// None when BSC_CUSTODY_WALLET is not set.
    pub bsc_watcher: Option<Arc<watcher::BscWatcher>>,

    // ===== Withdrawal Gateway =====
    /// Dealer address (base58) derived from DEALER_PRIVATE_KEY at startup.
    /// Empty string when DEALER_PRIVATE_KEY is not set.
    pub dealer_address: String,
    /// All withdrawal requests: withdrawal_id (UUID) → WithdrawalRecord (hot cache, ReDB-backed)
    pub withdrawal_requests: Arc<dashmap::DashMap<String, storage::WithdrawalRecord>>,

    // ===== Layer 5: Creator Coin Launchpad =====
    /// Registry of all launched creator coins — ticker → CreatorCoinRecord.
    pub creator_coins: Arc<dashmap::DashMap<String, storage::CreatorCoinRecord>>,
    /// AMM pool state — ticker → CoinPoolState (constant-product AMM reserves).
    pub coin_pools: Arc<dashmap::DashMap<String, storage::CoinPoolState>>,
    /// User coin balances — "{ticker}:{wallet}" → coin units (6 decimals).
    pub coin_balances: Arc<dashmap::DashMap<String, u64>>,
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

    // Block production staleness check — get_latest_block() is correct even when
    // produced slots are non-contiguous (e.g. right after startup or a gap).
    let latest_block = state.block_producer.get_latest_block();
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
// ADDRESS VALIDATION
// ============================================================================

/// Validates a BlackBook / Solana-style base58 wallet address.
/// Rules:
///  - Must NOT start with "0x" (EVM addresses are invalid here)
///  - Must decode as valid base58 to exactly 32 bytes (Ed25519 pubkey)
fn is_valid_bb_address(addr: &str) -> bool {
    if addr.starts_with("0x") || addr.starts_with("0X") {
        return false;
    }
    match bs58::decode(addr).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

// ============================================================================
// BALANCE
// ============================================================================

/// GET /balance/:address
async fn balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    if !is_valid_bb_address(&address) {
        return Json(serde_json::json!({
            "error": "Invalid address format. Expected base58 Solana-style address (32 bytes), not an 0x EVM address."
        }));
    }
    let balance = state.blockchain.get_balance(&address);
    Json(serde_json::json!({
        "address": address,
        "name": serde_json::Value::Null,
        "balance": balance,
        "unit": "BB"
    }))
}


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
    if !is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid sender address. Expected base58 Solana-style address, not an 0x EVM address."
        })));
    }
    if !is_valid_bb_address(&payload.to) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid recipient address. Expected base58 Solana-style address, not an 0x EVM address."
        })));
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

    let pubkey_arr = match pubkey_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr = match sig_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature length" }))),
    };
    let signature = Signature::from_bytes(sig_arr);

    if verifying_key.verify(&message, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("transfer:{}:{}", req.wallet_address, req.nonce);

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

    // Atomic nonce check+insert via DashMap entry() — prevents TOCTOU race
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": req.nonce
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // Prune old nonces periodically
    if state.used_nonces.len() > 100_000 {
        let cutoff = now.saturating_sub(120);
        state.used_nonces.retain(|_, &mut ts| ts > cutoff);
    }

    // ── BALANCE PRE-CHECK (fast reject before queuing) ─────────────────────
    let from = req.wallet_address.clone();
    let balance = state.blockchain.get_balance(&from);
    if balance < payload.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, payload.amount)
        })));
    }

    // ── SUBMIT TO GULF STREAM → SEALEVEL PIPELINE ─────────────────────────
    // All transfers must go through the parallel execution engine.
    // Direct blockchain.transfer() is intentionally not used here.
    use runtime::core::{Transaction as RuntimeTx, TransactionType};
    let mut tx = RuntimeTx::new(from.clone(), payload.to.clone(), payload.amount, TransactionType::Transfer);
    let tx_id = tx.id.clone();
    // Carry the Ed25519 signature as the nonce priority field for ordering
    tx.nonce = req.timestamp;

    if let Err(e) = state.gulf_stream.submit(tx.clone()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Gulf Stream: {}", e) })));
    }

    let packet = PipelinePacket::new(tx_id.clone(), from.clone(), payload.to.clone(), payload.amount);
    let _ = state.pipeline.submit(packet).await;

    info!("💸 Transfer queued → Sealevel: {} → {} : {} BB (tx: {})", from, payload.to, payload.amount, &tx_id[..8]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "tx_id": tx_id,
        "status": "pending",
        "from": from,
        "to": payload.to,
        "amount": payload.amount,
    })))
}

// ============================================================================
// POH & CONSENSUS HANDLERS
// ============================================================================

/// GET /poh/status
async fn poh_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let poh = state.poh.read();
    let slot = poh.current_slot.load(Ordering::Relaxed);
    Json(serde_json::json!({
        "current_slot": slot,
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
    let validators = [state.validator_id.clone()];
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

/// POST /sealevel/submit — Submit to Gulf Stream for parallel execution
///
/// Requires a valid Ed25519 signature over:
///   `[chain_id] || payload_json || '\n' || timestamp || '\n' || nonce`
/// where payload_json = `{"to":"<addr>","amount":<f64>}`
///
/// This uses the same signature scheme as /transfer/simple, ensuring
/// that every transaction entering the Sealevel pipeline is authenticated.
async fn gulf_stream_submit_handler(
    State(state): State<AppState>,
    Json(req): Json<GulfStreamSubmitRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use runtime::core::{Transaction as RuntimeTx, TransactionType};

    if req.from.is_empty() || req.to.is_empty() || req.amount <= 0.0 {
        return Json(serde_json::json!({ "error": "Invalid parameters" }));
    }

    // ── ED25519 SIGNATURE VERIFICATION ─────────────────────────────────────
    // Reconstruct the canonical message
    let payload_json = if let Some(ref t) = req.tx_type {
        format!(r#"{{"to":"{}","amount":{},"tx_type":"{}"}}"#, req.to, req.amount, t)
    } else {
        format!(r#"{{"to":"{}","amount":{}}}"#, req.to, req.amount)
    };
    let mut message = vec![req.chain_id];
    message.extend_from_slice(payload_json.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(req.timestamp.to_string().as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(req.nonce.as_bytes());

    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return Json(serde_json::json!({ "error": "Invalid public key (must be 32 bytes hex)" })),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" })),
    };

    let pubkey_arr = match pubkey_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Json(serde_json::json!({ "error": "Invalid pubkey length" })),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return Json(serde_json::json!({ "error": "Bad public key" })),
    };
    let sig_arr = match sig_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Json(serde_json::json!({ "error": "Invalid signature length" })),
    };
    let signature = Signature::from_bytes(sig_arr);

    if verifying_key.verify(&message, &signature).is_err() {
        return Json(serde_json::json!({ "error": "Signature verification failed" }));
    }

    // Verify public key matches the claimed sender address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.from {
        return Json(serde_json::json!({
            "error": "Public key does not match sender address",
            "derived": derived_address,
            "claimed": req.from
        }));
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("sealevel:{}:{}", req.from, req.nonce);

    // Check timestamp freshness
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return Json(serde_json::json!({
            "error": "Transaction too old (>60s)",
            "server_time": now,
            "tx_time": req.timestamp
        }));
    }

    // Atomic nonce check+insert via DashMap entry() — prevents TOCTOU race
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": req.nonce
            }));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── BALANCE CHECK & SUBMIT ─────────────────────────────────────────────
    let balance = state.blockchain.get_balance(&req.from);
    if balance < req.amount {
        return Json(serde_json::json!({
            "error": format!("Insufficient balance: {} < {}", balance, req.amount)
        }));
    }

    let tx_type_enum = match req.tx_type.as_deref() {
        Some("SwapUsdcForBb") => TransactionType::SwapUsdcForBb,
        Some("SwapBbForUsdc") => TransactionType::SwapBbForUsdc,
        _ => TransactionType::Transfer,
    };
    let mut tx = RuntimeTx::new(req.from.clone(), req.to.clone(), req.amount, tx_type_enum);
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
#[cfg(feature = "unsafe_admin")]
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
#[cfg(feature = "unsafe_admin")]
async fn admin_mint_handler(
    State(state): State<AppState>,
    Json(req): Json<MintRequest>,
) -> impl IntoResponse {
    // Validate dealer signature (security gate for production)
    if req.dealer_signature.is_none() {
        warn!("\u{26a0}\u{fe0f} Mint request without dealer_signature from to={}", req.to);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing dealer signature for admin mint"
        })));
    }

    if req.amount <= 0.0 || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid mint parameters"
        })));
    }
    if !is_valid_bb_address(&req.to) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid address format. Expected base58 Solana-style address, not an 0x EVM address."
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
#[cfg(feature = "unsafe_admin")]
struct BurnRequest {
    from: String,
    amount: f64,
    dealer_signature: Option<String>,
    l2_receipt_id: Option<String>,
}

/// POST /admin/burn — Burn $BB tokens (Dealer only)
#[cfg(feature = "unsafe_admin")]
async fn admin_burn_handler(
    State(state): State<AppState>,
    Json(req): Json<BurnRequest>,
) -> impl IntoResponse {
    // Validate dealer signature (security gate for production)
    if req.dealer_signature.is_none() {
        warn!("\u{26a0}\u{fe0f} Burn request without dealer_signature from={}", req.from);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Missing dealer signature for admin burn"
        })));
    }

    if req.amount <= 0.0 || req.from.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid burn parameters" })));
    }
    if !is_valid_bb_address(&req.from) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid address format. Expected base58 Solana-style address, not an 0x EVM address."
        })));
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
// FAUCET — Ed25519 Signature-Verified Token Mint (0.1 BB per request)
// ============================================================================

#[derive(Deserialize)]
struct FaucetRequest {
    /// Wallet address to receive funds
    wallet_address: String,
    /// Amount to request (capped at MAX_FAUCET_BB)
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

/// POST /faucet — Mint up to 0.1 BB to any wallet with Ed25519 proof-of-ownership
///
/// User signs: "FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"
/// L1 verifies the signature, then mints tokens to the wallet.
/// Rate-limited: once per epoch per address.
async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const MAX_FAUCET_BB: f64 = 0.1;

    // ── VALIDATE INPUTS ────────────────────────────────────────────────────
    if req.wallet_address.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Missing 'wallet_address'"
        })));
    }
    let amount = req.amount.min(MAX_FAUCET_BB).max(0.0);
    if amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Amount must be between 0 and 0.1 BB"
        })));
    }

    // ── Ed25519 SIGNATURE VERIFICATION ─────────────────────────────────────
    let message = format!("FAUCET:{}:{}:{}:{}", req.wallet_address, amount, req.timestamp, req.nonce);

    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid public key (must be 32 bytes hex)" }))),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature (must be 64 bytes hex)" }))),
    };

    let pubkey_arr = match pubkey_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid pubkey length" }))),
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Bad public key" }))),
    };
    let sig_arr = match sig_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid signature length" }))),
    };
    let signature = Signature::from_bytes(sig_arr);

    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // Verify the public key matches the claimed wallet address
    let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
    if derived_address != req.wallet_address {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Public key does not match wallet_address",
            "derived": derived_address,
            "claimed": req.wallet_address
        })));
    }

    // ── EPOCH RATE LIMITING ─────────────────────────────────────────────────
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let current_epoch = current_slot / POH_SLOTS_PER_EPOCH;
    if let Some(entry) = state.faucet_claims.get(&req.wallet_address) {
        let (claimed_epoch, _claimed_amount) = *entry;
        if claimed_epoch >= current_epoch {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
                "error": "Faucet: already claimed this epoch",
                "wallet": req.wallet_address,
                "epoch": current_epoch,
                "retry_after_slot": (current_epoch + 1) * POH_SLOTS_PER_EPOCH
            })));
        }
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────────
    let nonce_key = format!("faucet:{}:{}", req.wallet_address, req.nonce);

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

    // Atomic nonce check+insert via DashMap entry() — prevents TOCTOU race
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used — possible replay attack",
                "nonce": req.nonce
            })));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // ── MINT TOKENS ────────────────────────────────────────────────────────
    match state.blockchain.credit(&req.wallet_address, amount) {
        Ok(_) => {
            let new_bal = state.blockchain.get_balance(&req.wallet_address);
            info!("🚰 FAUCET: {} BB → {} (Ed25519 verified)", amount, req.wallet_address);

            // Record epoch claim for rate limiting
            state.faucet_claims.insert(req.wallet_address.clone(), (current_epoch, amount));

            // Record faucet mint into PoH block
            {
                use protocol::Transaction as ProtoTx;
                use protocol::TxData;
                let tx = ProtoTx {
                    hash: uuid::Uuid::new_v4().to_string(),
                    from: "SYSTEM_FAUCET".to_string(),
                    timestamp: now,
                    data: TxData::DepositUsdt {
                        usdt_amount: (amount / 10.0) as u64,
                        external_tx_hash: Some(format!("faucet_{}", req.nonce)),
                    },
                    signature: req.signature.clone(),
                    signer_pubkey: req.public_key.clone(),
                };
                state.block_producer.record_executed_transaction(tx);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "minted": amount,
                "to": req.wallet_address,
                "new_balance": new_bal,
                "auth_method": "ed25519_signature"
            })))
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Mint failed: {}", e)
            })))
        }
    }
}

/// POST /admin/dealer/settle — Dealer settles L2 receipts in batch
///
/// Flow: L2 sends receipts of losing bets → Dealer mints to self → pays winners
#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
struct DealerSettlementRequest {
    /// List of payouts: (address, amount) pairs
    payouts: Vec<PayoutEntry>,
    /// L2 batch receipt ID
    batch_receipt_id: String,
}

#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
struct PayoutEntry {
    address: String,
    amount: f64,
}

#[cfg(feature = "unsafe_admin")]
async fn dealer_settle_handler(
    State(state): State<AppState>,
    Json(req): Json<DealerSettlementRequest>,
) -> impl IntoResponse {
    let mut results = Vec::new();
    let mut total_paid = 0.0;

    for payout in &req.payouts {
        if payout.amount <= 0.0 { continue; }

        // Mint to recipient directly
        match state.blockchain.credit(&payout.address, payout.amount) {
            Ok(_) => {
                total_paid += payout.amount;
                let new_bal = state.blockchain.get_balance(&payout.address);
                results.push(serde_json::json!({
                    "address": payout.address,
                    "amount": payout.amount,
                    "status": "paid",
                    "new_balance": new_bal,
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "address": payout.address,
                    "amount": payout.amount,
                    "status": "failed",
                    "error": e,
                }));
            }
        }
    }

    info!("🎰 DEALER SETTLEMENT: {} BB across {} payouts (batch: {})", 
        total_paid, req.payouts.len(), req.batch_receipt_id);

    Json(serde_json::json!({
        "success": true,
        "batch_receipt_id": req.batch_receipt_id,
        "total_paid": total_paid,
        "payout_count": req.payouts.len(),
        "results": results,
    }))
}

// ============================================================================
// ADMIN — Operations
// ============================================================================

/// GET /admin/accounts — View all on-chain account balances (dynamic)
#[cfg(feature = "unsafe_admin")]
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

/// GET /admin/security/stats
#[cfg(feature = "unsafe_admin")]
async fn security_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "throttler": state.throttler.get_stats(),
        "circuit_breaker": state.circuit_breaker.get_stats(),
        "fee_market": state.fee_market.get_stats(),
    }))
}

// ============================================================================
// USDC SPL TOKEN ENDPOINTS
// ============================================================================

#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
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
}

#[derive(Deserialize)]
#[cfg(feature = "unsafe_admin")]
struct DealerSendWusdcRequest {
    /// Recipient wallet address (base58) — the buyer's BB wallet
    to: String,
    /// Amount of wUSDT to send (human units, e.g. 5.0 = 5 wUSDT)
    amount: f64,
}

/// POST /admin/dealer/send_wusdt — Transfer wUSDT from the dealer's ATA to a buyer's ATA.
///
/// Used when a user has purchased wUSDT and the dealer owes them the on-chain tokens.
/// Requires DEALER_PRIVATE_KEY to be set — the dealer address is the sender.
#[cfg(feature = "unsafe_admin")]
async fn dealer_send_wusdt_handler(
    State(state): State<AppState>,
    Json(req): Json<DealerSendWusdcRequest>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

    if state.dealer_address.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "DEALER_PRIVATE_KEY not configured on this node"
        })));
    }
    if req.amount <= 0.0 || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "amount must be > 0 and to must not be empty"
        })));
    }

    let dealer_pubkey = match bs58::decode(&state.dealer_address).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(&v);
            solana_sdk::pubkey::Pubkey::new_from_array(arr)
        }
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Dealer address is invalid"
        }))),
    };
    let to_pubkey = match bs58::decode(&req.to).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(&v);
            solana_sdk::pubkey::Pubkey::new_from_array(arr)
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid recipient address"
        }))),
    };

    let mint       = usdc_mint_bytes();
    let raw_amount = (req.amount * USDC_UNIT as f64).round() as u64;

    match SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts, &mint, &dealer_pubkey, &to_pubkey, raw_amount,
    ) {
        Ok(result) => {
            info!("💸 DEALER→BUYER wUSDT: {:.6} to {} (dealer bal: {:.6})",
                req.amount, req.to,
                result.from_balance as f64 / USDC_UNIT as f64);
            let _ = state.blockchain.svm_accounts.flush_block();
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "sent_wusdt": req.amount,
                "from": state.dealer_address,
                "to": req.to,
                "dealer_ata": result.from_ata,
                "recipient_ata": result.to_ata,
                "dealer_remaining_wusdt": result.from_balance as f64 / USDC_UNIT as f64,
                "recipient_wusdt_balance": result.to_balance as f64 / USDC_UNIT as f64,
            })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("{:?}", e)
        }))),
    }
}

/// POST /admin/usdc/mint — Mint USDC tokens to a wallet's ATA
///
/// Called when bridge deposits arrive or for initial liquidity seeding.
/// Only the Dealer (mint authority) should call this in production.
#[cfg(feature = "unsafe_admin")]
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

/// GET /maxx/balance/{address} — Get MAXX ($XX) balance for a wallet
async fn maxx_balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, maxx_mint_bytes, maxx_mint_address, MAXX_DECIMALS, MAXX_UNIT};

    let wallet_bytes = match bs58::decode(&address).into_vec() {
        Ok(v) if v.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&v); a }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid base58 wallet address" }))),
    };
    let wallet_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(wallet_bytes);
    let mint = maxx_mint_bytes();
    let raw_balance = SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &mint, &wallet_pubkey);
    let human_balance = raw_balance as f64 / MAXX_UNIT as f64;

    (StatusCode::OK, Json(serde_json::json!({
        "address": address,
        "maxx_balance": human_balance,
        "ticker": "$XX",
        "raw_balance": raw_balance,
        "decimals": MAXX_DECIMALS,
        "mint": maxx_mint_address(),
    })))
}

/// GET /maxx/supply — Get total MAXX ($XX) supply on BlackBook L1
async fn maxx_supply_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, maxx_mint_bytes, maxx_mint_address, MAXX_DECIMALS, MAXX_UNIT};

    let mint = maxx_mint_bytes();
    match SplTokenEngine::get_mint_supply(&state.blockchain.svm_accounts, &mint) {
        Ok(supply) => {
            let human_supply = supply as f64 / MAXX_UNIT as f64;
            (StatusCode::OK, Json(serde_json::json!({
                "ticker": "$XX",
                "token_name": "MAXX",
                "mint": maxx_mint_address(),
                "total_supply": human_supply,
                "raw_supply": supply,
                "decimals": MAXX_DECIMALS,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("{:?}", e) }))),
    }
}

/// GET /maxx/vault — Get the bonding-curve vault's wUSDT reserve and MAXX market state
async fn maxx_vault_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, maxx_vault_address, USDC_UNIT};
    use contracts::maxx_token::get_maxx_state;

    // wUSDT balance held in the bonding-curve vault
    let vault_addr = maxx_vault_address();
    let vault_bytes = bs58::decode(&vault_addr).into_vec().unwrap_or_default();
    let vault_usdt = if vault_bytes.len() == 32 {
        let mut k = [0u8; 32]; k.copy_from_slice(&vault_bytes);
        let vk = solana_sdk::pubkey::Pubkey::new_from_array(k);
        let usdt_mint = usdc_mint_bytes();
        SplTokenEngine::get_token_balance(&state.blockchain.svm_accounts, &usdt_mint, &vk) as f64 / USDC_UNIT as f64
    } else { 0.0 };

    let market_state = get_maxx_state(&state.blockchain.db).unwrap_or_default();

    (StatusCode::OK, Json(serde_json::json!({
        "vault_address": vault_addr,
        "vault_usdt_balance": vault_usdt,
        "ticker": "$XX",
        "token_name": "MAXX",
        "total_supply": market_state.total_supply as f64 / 1_000_000_000_000_f64,
        "spot_price_usd": market_state.spot_price,
        "reserve_currency": market_state.reserve_currency,
        "last_update_height": market_state.last_update_height,
    })))
}

/// POST /usdc/transfer - Direct REST transfer of USDC
async fn usdc_transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<UsdcTransferRequest>,
) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

    if req.amount <= 0.0 || req.to.is_empty() || req.from.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid parameters"
        })));
    }

    let from_pubkey = match bs58::decode(&req.from).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(&v);
            solana_sdk::pubkey::Pubkey::new_from_array(arr)
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid from address"
        }))),
    };

    let to_pubkey = match bs58::decode(&req.to).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(&v);
            solana_sdk::pubkey::Pubkey::new_from_array(arr)
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid to address"
        }))),
    };

    let mint       = usdc_mint_bytes();
    let raw_amount = (req.amount * USDC_UNIT as f64).round() as u64;

    match SplTokenEngine::transfer_tokens(
        &state.blockchain.svm_accounts, &mint, &from_pubkey, &to_pubkey, raw_amount,
    ) {
        Ok(result) => {
            let _ = state.blockchain.svm_accounts.flush_block();
            // Add block history
            let tx_id = format!("usdc_{}", uuid::Uuid::new_v4());
            let proto_tx = protocol::Transaction {
                hash: tx_id.clone(),
                from: req.from.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                data: protocol::TxData::TransferBb { // using this data structure as generic log
                    to: req.to.clone(),
                    amount: raw_amount,
                },
                signature: String::new(),
                signer_pubkey: String::new(),
            };
            
            let r_tx_type = crate::storage::TxType::Transfer;
            let tx_record = crate::storage::TransactionRecord::with_id(
                tx_id.clone(),
                r_tx_type,
                &req.from,
                &req.to,
                raw_amount,
                0,
                result.from_balance.saturating_add(raw_amount),
                result.from_balance,
                result.to_balance,
                crate::storage::AuthType::SystemInternal,
            );
            
            if let Err(e) = state.blockchain.log_transaction(tx_record) {
                tracing::warn!("Failed to log USDC REST transfer: {}", e);
            }
            state.block_producer.record_executed_transaction(proto_tx);
            if let Some(slot) = state.blockchain.latest_block_slot().unwrap_or(Some(0)) {
                state.finality_tracker.record_inclusion(&tx_id, slot);
            }

            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "amount_usdc": req.amount,
                "from": req.from,
                "to": req.to,
                "tx_id": tx_id
            })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("{:?}", e)
        }))),
    }
}

// ============================================================================
/// GET /tx/:tx_id - Get full transaction details
async fn transaction_details_handler(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    // Try lookup by tx_id first, then fall back to tx_hash
    let found = state.blockchain.get_tx_by_id(&tx_id)
        .ok()
        .flatten()
        .or_else(|| state.blockchain.get_tx_by_hash(&tx_id).ok().flatten());

    if let Some(record) = found {
        Json(serde_json::json!({
            "success": true,
            "status": "Finalized",
            "transaction": record
        }))
    } else {
        // If not finalized, check if it's pending in memory
        let status = state.finality_tracker.get_status(&tx_id);
        match status {
            crate::runtime::poh_service::ConfirmationStatus::Pending | crate::runtime::poh_service::ConfirmationStatus::Processing { .. } => {
                Json(serde_json::json!({
                    "success": true,
                    "status": "Pending",
                    "transaction": null
                }))
            },
            _ => {
                Json(serde_json::json!({
                    "success": false,
                    "error": "Transaction not found"
                }))
            }
        }
    }
}

/// GET /address/:address/transactions - Get transaction history for a specific wallet
async fn address_transactions_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(query): Query<LedgerQuery> // Reuse LedgerQuery for pagination
) -> impl IntoResponse {
    let limit = query.limit.min(100).max(1);
    let offset = (query.page.max(1) - 1) * limit;
    
    // Fallback to searching all or mapping via the fast index if available
    let all_txs = state.blockchain.get_all_transactions(10000); // Temporary brute force until full index
    let filtered_txs: Vec<_> = all_txs.into_iter().filter(|tx| {
        tx.from_address == address || tx.to_address == address
    }).collect();
    
    let total = filtered_txs.len();
    let start = offset.min(total);
    let end = (offset + limit).min(total);
    let paginated = &filtered_txs[start..end];

    Json(serde_json::json!({
        "success": true,
        "address": address,
        "page": query.page,
        "limit": limit,
        "total": total,
        "transactions": paginated
    }))
}

// LEDGER — ASCII Art Visualization
// ============================================================================

#[derive(Deserialize)]
struct LedgerQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_page() -> usize { 1 }
fn default_limit() -> usize { 50 }

/// GET /ledger - ASCII art visualization of all ledger entries
async fn ledger_handler(
    State(state): State<AppState>,
    Query(query): Query<LedgerQuery>
) -> impl IntoResponse {
    let mut transactions = state.blockchain.get_all_transactions(10000);
    // Sort by timestamp descending (most recent first)
    transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let stats = state.blockchain.stats();
    let total_supply = state.blockchain.total_supply();
    
    // Pagination
    let limit = query.limit.min(100).max(1); // Max 100, min 1
    let page = query.page.max(1); // Min page 1
    let total_pages = transactions.len().div_ceil(limit);
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
    output.push('\n');
    output.push_str(" ═══ BLACKBOOK L1 AUDIT LEDGER ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push_str(&format!("  BLOCK HEIGHT : {:>12}                     NETWORK : [ MAINNET-ZK ]           VERSION : 5.0.0-mainnet-beta\n", stats.block_count));
    output.push_str(&format!("  TOTAL SUPPLY : {:>12.2} BB              WALLETS : {:>6}                    STATUS  : [ FINALIZED ]\n", total_supply, stats.total_accounts));
    output.push_str(&format!("  TRANSACTIONS : {:>12}                     PAGE    : {:>4} of {:>4}                SHOWING : {} - {}\n", transactions.len(), page, total_pages, start_idx + 1, end_idx));
    output.push_str(" ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push('\n');
    
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
    output.push('\n');
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LEGEND
    // ═══════════════════════════════════════════════════════════════════════════
    output.push_str(" ─── LEGEND ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n");
    output.push_str("  ACTIONS: 💸 TRANSFER │ 🪙 MINT │ 🔥 BURN │ 🌉 BRIDGE (OUT/IN) │ 🔒 LOCK │ 🔓 UNLOCK\n");
    output.push_str("  AUTH:    🔑 Master Key │ ⚡ Session Key │ 🔮 ZK Proof │ ⚙️ System Internal\n");
    output.push_str("  STATUS:  ✅ Finalized │ ⏳ Pending │ ↩️ Reverted │ ❌ Failed      RECONCILED: [✓] Valid │ [✗] Mismatch\n");
    output.push_str("  COLUMNS: BLK=Block Height │ TX HASH=Transaction Hash │ PREV HASH=Chain Link │ Bal=Balance Before→After │ Recv=Recipient Balance\n");
    output.push_str(" ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    output.push('\n');
    
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
        output.push('\n');
    }
    
    // Footer
    output.push('\n');
    output.push_str(" 🛡️  Ed25519 Signatures │ SHA-256 TX Hashes │ Chain-Linked │ State Validated │ Immutably Stored on BlackBook L1\n");
    output.push('\n');
    
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        output
    )
}

/// Helper to format addresses WITH USERNAME for ledger display
/// Format: "username (bb_1234...abcd)" or just "bb_1234...abcd" if no username
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
// SUPPLY AUDIT — Invariant: total_bb == total_wUSDT * 10
// ============================================================================

/// GET /supply/audit
///
/// Returns BB total supply, wUSDT total supply, and whether the 10:1 backing
/// invariant holds.  A healthy chain should always have:
///   total_bb == total_wUSDT * 10  (within floating-point tolerance)
async fn supply_audit_handler(State(state): State<AppState>) -> impl IntoResponse {
    use svm::{SplTokenEngine, usdc_mint_bytes, usdc_mint_address, USDC_UNIT};

    let bb_supply = state.blockchain.total_supply();

    let usdc_mint = usdc_mint_bytes();
    let raw_wusdt = match SplTokenEngine::get_mint_supply(&state.blockchain.svm_accounts, &usdc_mint) {
        Ok(s) => s,
        Err(_) => 0,
    };
    let wusdt_supply = raw_wusdt as f64 / USDC_UNIT as f64;

    // Expected BB = wUSDT * 10
    let expected_bb = wusdt_supply * 10.0;
    let delta = (bb_supply - expected_bb).abs();
    let tolerance = 0.000_001_f64.max(expected_bb * 0.000_001); // 1 ppm or 0.000001 BB
    let invariant_ok = delta <= tolerance;

    let ratio = if wusdt_supply > 0.0 { bb_supply / wusdt_supply } else { 0.0 };

    Json(serde_json::json!({
        "bb_total_supply": bb_supply,
        "wusdt_total_supply": wusdt_supply,
        "wusdt_mint": usdc_mint_address(),
        "backing_ratio": ratio,
        "target_ratio": 10.0,
        "delta_from_target": delta,
        "invariant_ok": invariant_ok,
        "note": "Invariant: bb_total_supply == wusdt_total_supply * 10",
    }))
}

// ============================================================================
// ROUTER
// ============================================================================

// ============================================================================ 
// EVENT BROADCASTER
// ============================================================================ 

pub fn spawn_account_notification_broadcaster(state: AppState) {
    let mut rx = state.block_tx.subscribe();
    let ws_state = state.clone();
    
    tokio::spawn(async move {
        while let Ok(block) = rx.recv().await {
            let mut modified_keys = std::collections::HashSet::new();
            for otx in &block.transactions {
                // Target recipient
                match &otx.tx.data {
                    crate::protocol::blockchain::TxData::TransferBb { to, .. } => {
                        modified_keys.insert(crate::storage::ConcurrentBlockchain::addr_to_pubkey(to));
                    }
                    _ => {}
                }
            }

            for pubkey in modified_keys {
                // In Solana, pubkeys are tracked via base58 string.
                let pubkey_b58 = solana_sdk::bs58::encode(pubkey).into_string(); 
                if let Some(subs) = ws_state.ws_subscriptions.account_subs.get(&pubkey_b58) {
                    if subs.is_empty() { continue; }
                    
                    if let Some(acct) = ws_state.blockchain.svm_accounts.get_account(&pubkey) {
                        let res = RpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: None,
                            result: None,
                            method: Some("accountNotification".to_string()),
                            params: Some(RpcParams {
                                subscription: 1, // Dummy fixed ID
                                result: RpcAccountResult {
                                    context: RpcContext { slot: block.slot },
                                    value: RpcAccountValue {
                                        lamports: acct.lamports(),
                                        data: vec!["".to_string(), "base64".to_string()],
                                        owner: "11111111111111111111111111111111".to_string(),
                                        executable: false,
                                        rent_epoch: 0,
                                    }
                                }
                            })
                        };
                        
                        let msg_text = match serde_json::to_string(&res) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        for client_addr in subs.iter() {
                            if let Some(tx) = ws_state.ws_subscriptions.clients.get(&*client_addr) {
                                let _ = tx.send(axum::extract::ws::Message::Text(msg_text.clone().into()));
                            }
                        }
                    }
                }
            }
        }
    });
}

// ============================================================================ 
// ROUTER
// ============================================================================ 

async fn ws_handler(
    ws: axum::extract::ws::WebSocketUpgrade,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, addr, state))
}

async fn handle_socket(socket: axum::extract::ws::WebSocket, who: std::net::SocketAddr, state: AppState) {
    use futures_util::stream::StreamExt;
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    
    state.ws_subscriptions.clients.insert(who, tx);
    
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            use futures_util::SinkExt;
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut recv_task = {
        let state = state.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = receiver.next().await {
                if let axum::extract::ws::Message::Text(text) = msg {
                    if let Ok(req) = serde_json::from_str::<RpcRequest>(&text) {
                        if req.method == "accountSubscribe" {
                            if let Some(params) = req.params {
                                if let Some(pubkey_val) = params.get(0) {
                                    if let Some(pubkey) = pubkey_val.as_str() {
                                        state.ws_subscriptions.account_subs
                                            .entry(pubkey.to_string())
                                            .or_insert_with(dashmap::DashSet::new)
                                            .insert(who);

                                        let res = RpcResponse {
                                            jsonrpc: "2.0".to_string(),
                                            id: req.id,
                                            result: Some(1), // Sub ID
                                            method: None,
                                            params: None,
                                        };
                                        if let Some(tx) = state.ws_subscriptions.clients.get(&who) {
                                            if let Ok(text) = serde_json::to_string(&res) {
                                                let _ = tx.send(axum::extract::ws::Message::Text(text.into()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    };

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Cleanup
    state.ws_subscriptions.clients.remove(&who);
    for mut entry in state.ws_subscriptions.account_subs.iter_mut() {
        entry.value_mut().remove(&who);
    }
}

fn build_router(state: AppState) -> Router {

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    #[allow(unused_mut)]
    let mut router = Router::new()
        // Public
        .route("/health", get(health_handler))
        .route("/ws", get(ws_handler))
        .route("/stats", get(stats_handler))
        .route("/supply/audit", get(supply_audit_handler))
        .route("/balance/:address", get(balance_handler))
        .route("/tx/:tx_id", get(transaction_details_handler))
        .route("/address/:address/transactions", get(address_transactions_handler))
        .route("/ledger", get(ledger_handler))
        // Max Token Market (MAXX / $XX)
        .route("/maxx/buy", post(contracts::maxx_token::buy_maxx_handler))
        .route("/maxx/sell", post(contracts::maxx_token::sell_maxx_handler))
        .route("/maxx/manifest", get(contracts::maxx_token::maxx_market_manifest_handler))
        .route("/maxx/balance/:address", get(maxx_balance_handler))
        .route("/maxx/supply", get(maxx_supply_handler))
        .route("/maxx/vault", get(maxx_vault_handler))
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
        // Global Escrow Smart Contract
        .route("/escrow/deposit", post(contracts::global_escrow::escrow_deposit_handler))
        .route("/escrow/submit-state-root", post(contracts::global_escrow::escrow_submit_state_root_handler))
        .route("/escrow/withdraw", post(contracts::global_escrow::escrow_withdraw_handler))
        .route("/escrow/status", get(contracts::global_escrow::escrow_status_handler))
        .route("/escrow/market/:market_id", get(contracts::global_escrow::escrow_market_handler))
        .route("/escrow/contest/:contest_id", get(contracts::global_escrow::escrow_contest_handler))
        // Faucet (public, rate-limited, Ed25519 verified)
        .route("/faucet", post(faucet_handler))
        // Deposit Gateway (public submit + status)
        .route("/deposit/request", post(contracts::deposit_gateway::deposit_request_handler))
        .route("/deposit/status/:tx_hash", get(contracts::deposit_gateway::deposit_status_handler))
        // Withdrawal Gateway (public request + status)
        .route("/withdraw/request", post(contracts::withdrawal_gateway::withdraw_request_handler))
        .route("/withdraw/status/:id", get(contracts::withdrawal_gateway::withdraw_status_handler))
        // Swap
        .route("/swap/bb-to-usdc", post(contracts::token_swap::swap_bb_for_usdc_handler))
        .route("/swap/usdc-to-bb", post(contracts::token_swap::swap_usdc_for_bb_handler))
        // USDC SPL Token (Public read, private write)
        .route("/usdc/balance/:address", get(usdc_balance_handler))
        .route("/usdc/supply", get(usdc_supply_handler))
        .route("/usdc/accounts/:address", get(usdc_accounts_handler))
        .route("/usdc/transfer", post(usdc_transfer_handler));

    #[cfg(feature = "unsafe_admin")]
    {
        router = router
            // Admin (Dealer)
            .route("/admin/mint", post(admin_mint_handler))
            .route("/admin/burn", post(admin_burn_handler))
            .route("/admin/dealer/settle", post(dealer_settle_handler))
            .route("/admin/accounts", get(admin_accounts_handler))
            .route("/admin/security/stats", get(security_stats_handler))
            // Admin USDC
            .route("/admin/usdc/mint", post(usdc_mint_handler))
            .route("/admin/dealer/send_wusdt", post(dealer_send_wusdt_handler))
            // Deposit Gateway (admin approve)
            .route("/admin/deposit/approve", post(contracts::deposit_gateway::deposit_approve_handler))
            // Withdrawal Gateway (admin release)
            .route("/admin/withdraw/release", post(contracts::withdrawal_gateway::withdraw_release_handler));
    }

    router
        .with_state(state)
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
            .unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true))
        .init();

    let (block_tx, _) = tokio::sync::broadcast::channel(256);

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
    info!("║  Auth:      Ed25519 Signature Verification           ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // Shared slot counter — PoH clock, BlockProducer, GulfStream, and the health
    // handler all read/write the same Arc<AtomicU64> so the slot is always in sync.
    // Starts at 0 and is bumped to recovered_slot once the blockchain is loaded.
    let current_slot = Arc::new(AtomicU64::new(0u64));

    // 2. PoH Clock — shares slot counter with the rest of the system
    let poh_config = PoHConfig {
        slot_duration_ms: POH_SLOT_DURATION_MS,
        hashes_per_tick: POH_HASHES_PER_TICK,
        ticks_per_slot: POH_TICKS_PER_SLOT,
        slots_per_epoch: POH_SLOTS_PER_EPOCH,
    };
    let poh_service: SharedPoHService = create_poh_service_with_slot(poh_config, current_slot.clone());
    let poh_runner = poh_service.clone();
    tokio::spawn(async move { run_poh_clock(poh_runner).await; });
    info!("🕐 PoH clock started ({}ms slots)", POH_SLOT_DURATION_MS);

    // 3. Blockchain (ReDB)
    let blockchain = {
        // REDB_PATH env var: used in Docker (set to /data/blockchain_data/blockchain.redb)
        // Falls back to ./blockchain_data for local dev
        let redb_path = std::env::var("REDB_PATH")
            .unwrap_or_else(|_| REDB_DATA_PATH_DEFAULT.to_string());
        info!("🗄️  Initializing ReDB at {}", redb_path);
        match ConcurrentBlockchain::new(&redb_path) {
            Ok(bc) => { info!("✅ Blockchain initialized"); bc }
            Err(e) => { error!("❌ FATAL: {}", e); panic!("Storage init failed: {:?}", e); }
        }
    };

    // ── Global Escrow: derive PDA, load sequencer key, recover state ──
    let escrow_address = {
        use runtime::core::ProgramDerivedAddress;
        let pda = ProgramDerivedAddress::derive(
            runtime::core::AccountType::EscrowVault,
            "GLOBAL_ESCROW",
            None,
        ).unwrap_or_else(|e| {
            error!("Failed to derive escrow PDA: {} — using fallback", e);
            ProgramDerivedAddress {
                address: "ESCROW_FALLBACK".to_string(),
                account_type: runtime::core::AccountType::EscrowVault,
                namespace: "escrow_vault".to_string(),
                owner: "GLOBAL_ESCROW".to_string(),
                bump: 0,
            }
        });
        let addr = pda.address.clone();
        info!("🔐 Escrow PDA: {}", addr);
        addr
    };
    let l2_sequencer_pubkey = std::env::var("L2_SEQUENCER_PUBKEY")
        .unwrap_or_else(|_| {
            warn!("⚠️  L2_SEQUENCER_PUBKEY not set — using dev default");
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });
    info!("🔑 L2 Sequencer pubkey: {}…", &l2_sequencer_pubkey[..l2_sequencer_pubkey.len().min(16)]);

    // ── Deposit Gateway: custody wallet + reload pending requests ──
    let custody_wallet_address = std::env::var("CUSTODY_WALLET_ADDRESS")
        .unwrap_or_else(|_| {
            warn!("⚠️  CUSTODY_WALLET_ADDRESS not set — deposit gateway disabled");
            String::new()
        });
    if !custody_wallet_address.is_empty() {
        info!("🏦 Custody wallet: {}", custody_wallet_address);
    }
    let deposit_requests: Arc<dashmap::DashMap<String, storage::DepositRecord>> =
        Arc::new(dashmap::DashMap::new());
    if let Ok(records) = blockchain.load_all_deposit_requests() {
        let count = records.len();
        for record in records {
            deposit_requests.insert(record.external_tx_hash.clone(), record);
        }
        info!("📥 Loaded {} deposit request(s) from ReDB", count);
    }

    // ── Withdrawal requests: recover from ReDB ────────────────────────────
    let withdrawal_requests: Arc<dashmap::DashMap<String, storage::WithdrawalRecord>> =
        Arc::new(dashmap::DashMap::new());
    if let Ok(records) = blockchain.load_all_withdrawals() {
        let count = records.len();
        for record in records {
            withdrawal_requests.insert(record.withdrawal_id.clone(), record);
        }
        info!("💸 Loaded {} withdrawal record(s) from ReDB", count);
    }

    // ── Layer 5: Creator coin launchpad — recover from ReDB ───────────────
    let creator_coins_map: Arc<dashmap::DashMap<String, storage::CreatorCoinRecord>> =
        Arc::new(dashmap::DashMap::new());
    if let Ok(coins) = blockchain.load_all_creator_coins() {
        let count = coins.len();
        for c in coins { creator_coins_map.insert(c.ticker.clone(), c); }
        info!("🚀 L5: loaded {} creator coin(s) from ReDB", count);
    }
    let coin_pools_map: Arc<dashmap::DashMap<String, storage::CoinPoolState>> =
        Arc::new(dashmap::DashMap::new());
    if let Ok(pools) = blockchain.load_all_coin_pools() {
        let count = pools.len();
        for p in pools { coin_pools_map.insert(p.ticker.clone(), p); }
        info!("🚀 L5: loaded {} AMM pool(s) from ReDB", count);
    }
    let coin_balances_map: Arc<dashmap::DashMap<String, u64>> =
        Arc::new(dashmap::DashMap::new());
    if let Ok(bals) = blockchain.load_all_coin_balances() {
        let count = bals.len();
        for (k, v) in bals { coin_balances_map.insert(k, v); }
        info!("🚀 L5: loaded {} coin balance record(s) from ReDB", count);
    }

    // ── Dealer address: derive from DEALER_PRIVATE_KEY ───────────────────
    let dealer_address: String = match std::env::var("DEALER_PRIVATE_KEY") {
        Ok(hex_key) if hex_key.len() == 64 => {
            match hex::decode(&hex_key) {
                Ok(bytes) => match bytes.as_slice().try_into() as Result<[u8; 32], _> {
                    Ok(arr) => {
                        use ed25519_dalek::SigningKey;
                        let sk = SigningKey::from_bytes(&arr);
                        let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();
                        info!("💼 Dealer address: {}", addr);
                        addr
                    }
                    Err(_) => { warn!("⚠️  DEALER_PRIVATE_KEY wrong length"); String::new() }
                },
                Err(_) => { warn!("⚠️  DEALER_PRIVATE_KEY invalid hex"); String::new() }
            }
        }
        _ => { info!("ℹ️  DEALER_PRIVATE_KEY not set — dealer swap/withdrawal disabled"); String::new() }
    };

    // Recover escrow state from ReDB (market roots + claims)
    let market_roots: Arc<dashmap::DashMap<String, [u8; 32]>> = Arc::new(dashmap::DashMap::new());
    let withdrawal_claims: Arc<dashmap::DashMap<String, bool>> = Arc::new(dashmap::DashMap::new());
    let contest_states: Arc<dashmap::DashMap<String, storage::ContestState>> = Arc::new(dashmap::DashMap::new());
    {
        // Reload market roots (raw 32-byte SHA-256 hashes)
        if let Ok(roots) = blockchain.load_all_escrow_market_roots() {
            for (market_id, data) in roots {
                if data.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&data);
                    market_roots.insert(market_id, arr);
                } else {
                    warn!("Skipping corrupt market root for '{}' ({} bytes, expected 32)", market_id, data.len());
                }
            }
            info!("🔄 Recovered {} escrow market roots from ReDB", market_roots.len());
        }
        // Reload withdrawal claims
        if let Ok(claims) = blockchain.load_all_escrow_claims() {
            for (claim_key, _ts) in claims {
                withdrawal_claims.insert(claim_key, true);
            }
            info!("🔄 Recovered {} withdrawal claims from ReDB", withdrawal_claims.len());
        }
        // Reload contest states
        if let Ok(contests) = blockchain.load_all_contest_states() {
            for c in &contests {
                contest_states.insert(c.contest_id.clone(), c.clone());
            }
            info!("🔄 Recovered {} contest states from ReDB", contests.len());
        }
    }

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

    // Jump the shared slot counter to the recovered position.
    // Both the PoH clock and BlockProducer read this same Arc, so one store is enough.
    if recovered_slot > 0 {
        current_slot.store(recovered_slot, Ordering::Relaxed);
        info!("🕐 Slot counter → slot {}", recovered_slot);
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
            block_tx.clone(),
        );

        // Spawn gRPC relay server
        let grpc_port = config.grpc_port;
        tokio::spawn(async move {
            let addr: std::net::SocketAddr = match format!("0.0.0.0:{}", grpc_port).parse() {
                Ok(a) => a,
                Err(e) => { error!("Invalid gRPC relay address: {}", e); return; }
            };
            info!("📡 Writer relay gRPC server starting on {}", addr);
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(relay_service.into_server())
                .serve(addr)
                .await
            {
                error!("❌ gRPC relay server error: {}", e);
            }
        });

        // Spawn Settlement gRPC server (L2↔L1 bridge RPCs)
        {
            let settlement_port: u16 = std::env::var("SETTLEMENT_GRPC_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(config.grpc_port + 1); // default: 50052 (relay + 1)
            let settlement_svc = settlement::BlackBookSettlementService::new(
                blockchain.clone(),
                market_roots.clone(),
                contest_states.clone(),
                current_slot.clone(),
                l2_sequencer_pubkey.clone(),
                escrow_address.clone(),
                block_producer.clone(),
                deposit_requests.clone(),
                dealer_address.clone(),
            );
            tokio::spawn(async move {
                let addr: std::net::SocketAddr = match format!("0.0.0.0:{}", settlement_port).parse() {
                    Ok(a) => a,
                    Err(e) => { error!("Invalid settlement gRPC address: {}", e); return; }
                };
                info!("🔗 Settlement gRPC server starting on {}", addr);
                if let Err(e) = tonic::transport::Server::builder()
                    .add_service(settlement_svc.into_server())
                    .serve(addr)
                    .await
                {
                    error!("❌ Settlement gRPC server error: {}", e);
                }
            });
        }

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
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(POH_SLOT_DURATION_MS));
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

    // 5. Security
    let throttler = Arc::new(NetworkThrottler::new());
    let circuit_breaker = Arc::new(CircuitBreaker::new());
    circuit_breaker.add_exemption("genesis");
    circuit_breaker.add_exemption("system");
    let fee_market = Arc::new(LocalizedFeeMarket::new());
    let account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>> = Arc::new(dashmap::DashMap::new());
    info!("🛡️  Security initialized");

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
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(POH_SLOT_DURATION_MS / 4));
            loop {
                interval.tick().await;
                let slot = sealevel_slot.load(Ordering::Relaxed);
                let leader = { sealevel_ls.read().get_leader(slot) };
                let pending = sealevel_gs.get_pending_by_priority(&leader, poh_blockchain::MAX_TXS_PER_BLOCK);
                if pending.is_empty() { continue; }

                let batches = sealevel_sched.schedule_with_locks(pending);
                for batch in batches {
                    let results = sealevel_sched.execute_batch_with_locks(batch.clone());
                    for (i, result) in results.iter().enumerate() {
                        let tx = &batch[i];
                        if result.success {
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

                            let r_tx_type = match tx.tx_type {
                                runtime::core::TransactionType::Mint => crate::storage::TxType::Mint,
                                runtime::core::TransactionType::Burn => crate::storage::TxType::Burn,
                                runtime::core::TransactionType::BridgeLock => crate::storage::TxType::Lock,
                                runtime::core::TransactionType::BridgeUnlock => crate::storage::TxType::Unlock,
                                runtime::core::TransactionType::SwapUsdcForBb => crate::storage::TxType::SwapUsdcForBb,
                                runtime::core::TransactionType::SwapBbForUsdc => crate::storage::TxType::SwapBbForUsdc,
                                _ => crate::storage::TxType::Transfer,
                            };
                            let amount_lamports = (tx.amount * 100_000.0).round() as u64;
                            let from_bal = sealevel_bc.get_balance_lamports(&tx.from);
                            let tx_record = crate::storage::TransactionRecord::with_id(
                                tx.id.clone(),
                                r_tx_type,
                                &tx.from,
                                &tx.to,
                                amount_lamports,
                                tx.nonce,
                                from_bal.saturating_add(amount_lamports),
                                from_bal,
                                sealevel_bc.get_balance_lamports(&tx.to),
                                crate::storage::AuthType::Ed25519,
                            );
                            if let Err(e) = sealevel_bc.log_transaction(tx_record) {
                                tracing::warn!("Failed to log sealevel transaction history {}: {}", tx.id, e);
                            }
                        } else {
                            tracing::error!("❌ Sealevel Tx Failed ({}): {:?}", tx.id, result.error);
                        }
                    }
                }
                sealevel_gs.clear_leader_cache(&leader);
                sealevel_sched.tune_batch_size();

                // Flush buffered transaction logs to ReDB in one ACID commit
                match sealevel_bc.flush_tx_log_buffer() {
                    Ok(n) if n > 0 => tracing::debug!("💾 Flushed {} tx log entries to ReDB", n),
                    Err(e) => warn!("⚠️  tx log flush failed: {}", e),
                    _ => {}
                }
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
            block_tx.clone(),
        ));
        tokio::spawn(async move {
            reader_node.run().await;
        });
        info!("📖 Reader sync task started → {}", config.writer_addr);
    }

    // ── Custody Watcher — Solana RPC balance poller + auto-approver ───────────
    let custody_watcher: Option<Arc<watcher::CustodyWatcher>> = if !custody_wallet_address.is_empty() {
        let rpc_url = std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
        let poll_secs = std::env::var("WATCHER_POLL_SECS")
            .ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);
        let usdc_mint_addr = std::env::var("USDC_MINT")
            .unwrap_or_else(|_| watcher::USDC_MINT.to_string());
        let usdt_mint_addr = std::env::var("USDT_MINT")
            .unwrap_or_else(|_| watcher::USDT_MINT.to_string());
        info!("👀 Custody watcher: rpc={} poll={}s", rpc_url, poll_secs);
        Some(Arc::new(watcher::CustodyWatcher::new(
            rpc_url,
            custody_wallet_address.clone(),
            usdc_mint_addr,
            usdt_mint_addr,
            poll_secs,
            blockchain.clone(),
            Arc::clone(&deposit_requests),
            Arc::clone(&block_producer),
        )))
    } else {
        None
    };

    // ── BSC watcher — construct before state so it can be stored in AppState ──
    let bsc_watcher_arc: Option<Arc<watcher::BscWatcher>> = {
        let bsc_custody = std::env::var("BSC_CUSTODY_WALLET").unwrap_or_default();
        if !bsc_custody.is_empty() {
            let bsc_rpc = std::env::var("BSC_RPC_URL")
                .unwrap_or_else(|_| "https://bsc-dataseed.binance.org/".to_string());
            let bsc_poll_secs = std::env::var("BSC_WATCHER_POLL_SECS")
                .ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);
            let bsc_usdc = std::env::var("BSC_USDC_CONTRACT")
                .unwrap_or_else(|_| watcher::BSC_USDC_CONTRACT.to_string());
            let bsc_usdt = std::env::var("BSC_USDT_CONTRACT")
                .unwrap_or_else(|_| watcher::BSC_USDT_CONTRACT.to_string());
            info!("⛓️  BSC watcher: rpc={} wallet={} poll={}s", bsc_rpc, bsc_custody, bsc_poll_secs);
            Some(Arc::new(watcher::BscWatcher::new(
                bsc_rpc,
                bsc_custody,
                bsc_usdc,
                bsc_usdt,
                bsc_poll_secs,
                blockchain.clone(),
                Arc::clone(&deposit_requests),
                Arc::clone(&block_producer),
            )))
        } else {
            None
        }
    };

    // 7. Build State
    let state = AppState {
        blockchain,
        poh: poh_service.clone(),
        current_slot: current_slot.clone(),
        leader_schedule: leader_schedule.clone(),
        pipeline,
        parallel_scheduler,
        gulf_stream: gulf_stream.clone(),
        block_producer,
        finality_tracker,
        tower_bft,
        node_mode: config.mode,
        validator_id: validator_id.clone(),
        throttler,
        ws_subscriptions: Arc::new(WsSubscriptions::new()),
        block_tx: block_tx.clone(),
        circuit_breaker,
        fee_market,
        account_metadata,
        used_nonces: Arc::new(dashmap::DashMap::new()),
        faucet_claims: Arc::new(dashmap::DashMap::new()),
        escrow_address,
        l2_sequencer_pubkey,
        market_roots,
        withdrawal_claims,
        contest_states: contest_states.clone(),
        custody_wallet_address,
        deposit_requests,
        custody_watcher: custody_watcher.clone(),
        bsc_watcher: bsc_watcher_arc.clone(),
        dealer_address,
        withdrawal_requests,
        // Layer 5: creator coin hot caches (pre-loaded before state construction)
        creator_coins: creator_coins_map,
        coin_pools: coin_pools_map,
        coin_balances: coin_balances_map,
    };

    // Start custody watcher background task (if custody wallet is configured)
    if let Some(w) = custody_watcher {
        w.start();
    }

    // Start BSC watcher background task (if BSC custody wallet is configured)
    if let Some(w) = bsc_watcher_arc {
        w.start();
    }

    // ── Startup wUSDT invariant reconcile (unconditional on every boot) ──────────
    // If BB supply exceeds wUSDT supply × 10 (legacy chain or first upgrade after
    // the wUSDT feature was added), mint the deficit wUSDT to restore the 10:1
    // backing invariant before any user activity begins.
    // Recipient: dealer if configured, otherwise a deterministic protocol-reserve address.
    {
        use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};

        // Deterministic protocol-reserve pubkey used when no dealer/authority is set.
        let reserve_key = solana_sdk::pubkey::Pubkey::new_from_array(
            *b"bb_protocol_reserve_v1__________"
        );

        let mint_authority: solana_sdk::pubkey::Pubkey = if !state.dealer_address.is_empty() {
            bs58::decode(&state.dealer_address)
                .into_vec()
                .ok()
                .and_then(|v| v.as_slice().try_into().ok())
                .map(solana_sdk::pubkey::Pubkey::new_from_array)
                .unwrap_or(reserve_key)
        } else {
            reserve_key
        };

        // Ensure the wUSDT mint account exists (idempotent — no-op if already bootstrapped)
        let mint = usdc_mint_bytes();
        match SplTokenEngine::bootstrap_usdc_mint(&state.blockchain.svm_accounts, &mint_authority) {
            Ok(_)  => { let _ = state.blockchain.svm_accounts.flush_block(); }
            Err(e) => warn!("⚠️  wUSDT mint bootstrap failed: {:?}", e),
        }

        let total_bb      = state.blockchain.total_supply();
        let current_wusdt = SplTokenEngine::get_mint_supply(&state.blockchain.svm_accounts, &mint)
            .map(|s| s as f64 / USDC_UNIT as f64)
            .unwrap_or(0.0);
        let expected_wusdt = total_bb / 10.0;
        let missing        = expected_wusdt - current_wusdt;

        let tolerance = 0.000_001_f64.max(expected_wusdt * 0.000_001);
        if missing > tolerance {
            // Under-issued — mint deficit wUSDT to authority
            warn!(
                "⚠️  Invariant mismatch at startup: {:.6} BB / {:.6} wUSDT — minting {:.6} wUSDT to {}",
                total_bb, current_wusdt, missing, mint_authority
            );
            let raw_amount = (missing * USDC_UNIT as f64).round() as u64;
            match SplTokenEngine::mint_to(
                &state.blockchain.svm_accounts,
                &mint,
                &mint_authority,
                raw_amount,
            ) {
                Ok(_)  => {
                    info!("✅  Invariant restored: minted {:.6} wUSDT to {}", missing, mint_authority);
                    match state.blockchain.svm_accounts.flush_block() {
                        Ok(n)  => info!("💾  Flushed {} svm_accounts entries to ReDB", n),
                        Err(e) => warn!("⚠️  svm_accounts flush failed: {:?}", e),
                    }
                }
                Err(e) => warn!("❌  Invariant reconcile failed: {:?}", e),
            }
        } else if (-missing) > tolerance {
            // Over-issued — burn excess wUSDT from the authority's ATA
            let excess = -missing;
            warn!(
                "⚠️  wUSDT over-issued at startup: {:.6} wUSDT but only {:.6} expected — burning {:.6} from {}",
                current_wusdt, expected_wusdt, excess, mint_authority
            );
            let raw_amount = (excess * USDC_UNIT as f64).round() as u64;
            match SplTokenEngine::burn(
                &state.blockchain.svm_accounts,
                &mint,
                &mint_authority,
                raw_amount,
            ) {
                Ok(new_supply) => {
                    info!("✅  Excess burned: new wUSDT supply = {:.6}", new_supply as f64 / USDC_UNIT as f64);
                    match state.blockchain.svm_accounts.flush_block() {
                        Ok(n)  => info!("💾  Flushed {} svm_accounts entries to ReDB", n),
                        Err(e) => warn!("⚠️  svm_accounts flush failed: {:?}", e),
                    }
                }
                Err(e) => warn!("❌  Invariant burn failed: {:?}", e),
            }
        } else {
            info!(
                "✅  Invariant OK at startup — {:.6} BB / {:.6} wUSDT",
                total_bb, current_wusdt
            );
        }
    }

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
                    // Bootstrap MAXX ($XX) mint alongside USDC
                    use svm::maxx_mint_bytes as _maxx_bytes;
                    match SplTokenEngine::bootstrap_maxx_mint(&rpc_svm_accounts, &mint_authority) {
                        Ok(mint_addr) => info!("🟣 MAXX ($XX) Mint: {} (authority: {})", mint_addr, mint_authority_addr),
                        Err(e) => error!("❌ MAXX mint bootstrap failed: {:?}", e),
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

    // 9. Start WS Broadcaster
    spawn_account_notification_broadcaster(state.clone());

    // 10. HTTP Server
    let app = build_router(state.clone());
    let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()
        .expect("Failed to parse HTTP listen address — check http_port config");

    info!("");
    info!("rocket Listening on http://{}", addr);
    info!("");
    info!("📡 CORE ENDPOINTS:");
    info!("   GET  /health                    Health check");
    info!("   GET  /balance/{{address}}         Balance lookup");
    info!("   GET  /ledger                    Transaction history");
    info!("");
    info!("⚡ SEALEVEL EXECUTION ENGINE (all transfers):");
    info!("   POST /transfer/simple           Ed25519 signed → Gulf Stream → Sealevel");
    info!("   POST /sealevel/submit           Ed25519 signed → Gulf Stream → Sealevel");
    info!("   POST /faucet                    Faucet (Ed25519 verified, rate-limited)");
    info!("");
    info!("🕐 PoH / CONSENSUS:");
    info!("   GET  /poh/status                PoH clock");
    info!("   GET  /poh/block/latest          Latest block");
    info!("   GET  /poh/block/:slot           Block by slot");
    info!("   GET  /poh/tx/:tx_id/status      TX finality status");
    info!("   GET  /consensus/tower           Tower BFT state");
    info!("   GET  /turbine/status            Turbine shred status");
    info!("");
    info!("🏦 GLOBAL ESCROW:");
    info!("   POST /escrow/deposit            Lock tokens into escrow");
    info!("   POST /escrow/submit-state-root  L2 sequencer merkle root");
    info!("   POST /escrow/withdraw           Withdraw via merkle proof");
    info!("   GET  /escrow/status             PDA balance + settled markets");
    info!("");
    info!("💵 wUSDT READ (write = admin only):");
    info!("   GET  /usdc/balance/{{address}}    wUSDT balance");
    info!("   GET  /usdc/supply               Total wUSDT supply");
    info!("");
    info!("🔐 ADMIN (unsafe_admin feature):");
    info!("   POST /admin/mint  /admin/burn  /admin/dealer/settle");
    info!("");
    info!("🌐 gRPC: 0.0.0.0:{}", config.grpc_port);
    info!("");

    let listener = tokio::net::TcpListener::bind(addr).await
        .expect("Failed to bind HTTP listener — port may be in use");

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
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(POH_SLOT_DURATION_MS));
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

    // 12. Start TPU Service (UDP ingestion — high-throughput binary pipeline)
    let tpu_port = 8003;
    let tpu_addr: std::net::SocketAddr = format!("0.0.0.0:{}", tpu_port).parse()
        .expect("Failed to parse TPU listen address");
    let tpu_service = TpuService::new(
        state.gulf_stream.clone(),
        state.pipeline.clone(),
        state.blockchain.clone(),
        state.used_nonces.clone(),
    );
    tokio::spawn(async move {
        tpu_service.run(tpu_addr).await;
    });

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    // ═══════════════════════════════════════════════════════════════
    // GRACEFUL SHUTDOWN CLEANUP
    // ═══════════════════════════════════════════════════════════════
    warn!("🛑 Shutting down — flushing state…");

    // 0. Capture mempool and nominate next leader
    let slot = current_slot.load(std::sync::atomic::Ordering::SeqCst);
    let pending_txs = gulf_stream.get_all_pending();
    warn!("📦 Captured {} in-flight transactions from GulfStream", pending_txs.len());
    
    let next_leader = leader_schedule.read().nominate_next_writer(slot);
    warn!("👑 Nominated next leader for handoff: {}", next_leader);

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

