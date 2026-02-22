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

#![allow(dead_code)]
#![allow(unused_imports)]

// ============================================================================
// IMPORTS
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;
use std::collections::HashMap;

use tokio::signal;
use tokio::sync::Mutex as TokioMutex;
use parking_lot::RwLock;

use tracing::{info, warn, error, debug, Level};
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
use serde::{Deserialize, Serialize};

// ============================================================================
// MODULES
// ============================================================================

mod wallet_unified;
mod wallet_page;
mod storage;
mod consensus;
mod poh_blockchain;
mod supabase;
mod vault_manager;
mod svm;
mod solana_rpc;

#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

// ============================================================================
// MODULE IMPORTS
// ============================================================================

use storage::{ConcurrentBlockchain, AssetManager, TransactionRecord, TxType, AuthType};
use wallet_unified::handlers::UnifiedWalletState;
use supabase::SupabaseManager;
use vault_manager::VaultManager;

// Solana-style consensus infrastructure
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule, GulfStreamService, PoHEntry,
    ParallelScheduler, PipelinePacket,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
    // Security infrastructure
    NetworkThrottler, CircuitBreaker, LocalizedFeeMarket,
    AccountValidator, AccountType, AccountMetadata, PDAInfo,
    AccountAccess, ProgramDerivedAddress,
};

use poh_blockchain::{
    BlockProducer, FinalizedBlock, MerkleTree, FinalityTracker,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
};

use protocol::Transaction as ProtocolTransaction;

// ============================================================================
// CONSTANTS
// ============================================================================

const VERSION: &str = "5.0.0";
const NETWORK: &str = "mainnet-beta";
const REDB_DATA_PATH: &str = "./blockchain_data";

/// PoH Configuration (600ms slots — stable vs Solana's fragile 400ms)
const POH_SLOT_DURATION_MS: u64 = 600;
const POH_HASHES_PER_TICK: u64 = 12500;
const POH_TICKS_PER_SLOT: u64 = 64;
const POH_SLOTS_PER_EPOCH: u64 = 432000; // ~3 days

/// Gatekeeper: 1 USDT = 10 $BB
const USDT_TO_BB_RATIO: f64 = 10.0;

/// Dealer address — the house/admin wallet (collects L2 losing bets via receipts)
const DEALER_ADDRESS: &str = "bb_6a2944608156ffc470bdaea36018a3e9";
/// Dealer public key for signature verification
const DEALER_PUBKEY: &str = "6a2944608156ffc470bdaea36018a3e9bef58db318dc4f8ce86cd9f3e9e690a7";

/// Known test accounts (for display names in ledger)
fn account_name(addr: &str) -> Option<&'static str> {
    match addr {
        // v2 Shamir wallets (current)
        "GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV" => Some("Max"),
        "EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk" => Some("Alice"),
        "mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd"  => Some("Bob"),
        "EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb" => Some("Apollo"),
        "3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp" => Some("Dealer"),
        // v1 FROST wallets (legacy)
        "bb_7707fe614ad679b84a6cbc128999c1b5" => Some("Alice (v1)"),
        "bb_2123862491cdd1865e06cc684f57e7cb" => Some("Bob (v1)"),
        "bb_54c74820ffa82db9dca554329e521f98" => Some("Max (v1)"),
        "bb_d49a03bf45f92bb9d9f9d0a85b4af5e6" => Some("Apollo (v1)"),
        "bb_6a2944608156ffc470bdaea36018a3e9" => Some("Dealer (v1)"),
        _ => None,
    }
}

// ============================================================================
// APPLICATION STATE
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    // Core blockchain (ReDB + DashMap cache)
    pub blockchain: ConcurrentBlockchain,
    pub assets: AssetManager,
    pub supabase: Arc<SupabaseManager>,

    // Solana-style consensus
    pub poh: SharedPoHService,
    pub current_slot: Arc<AtomicU64>,
    pub leader_schedule: Arc<RwLock<LeaderSchedule>>,
    pub pipeline: Arc<TransactionPipeline>,
    pub parallel_scheduler: Arc<ParallelScheduler>,
    pub gulf_stream: Arc<GulfStreamService>,
    pub block_producer: Arc<BlockProducer>,
    pub finality_tracker: Arc<FinalityTracker>,

    // Security infrastructure
    pub throttler: Arc<NetworkThrottler>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub fee_market: Arc<LocalizedFeeMarket>,
    pub account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>>,
    pub used_nonces: Arc<dashmap::DashMap<String, u64>>,

    // Faucet rate-limiter: address → (epoch_at_claim, total_minted_this_epoch)
    pub faucet_claims: Arc<dashmap::DashMap<String, (u64, f64)>>,
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

    Json(serde_json::json!({
        "status": "healthy",
        "version": VERSION,
        "network": NETWORK,
        "blockchain": {
            "total_supply": total_supply,
            "account_count": stats.total_accounts,
            "block_count": stats.block_count,
        },
        "poh_clock": {
            "current_slot": poh_status["current_slot"],
            "current_epoch": poh_status["current_epoch"],
            "slot_duration_ms": POH_SLOT_DURATION_MS,
        },
        "infrastructure": {
            "gulf_stream": true,
            "sealevel": true,
            "pipeline": pipeline_stats.is_running,
        },
        "manifesto": {
            "job_1": "Gatekeeper (USDT → $BB 1:10)",
            "job_2": "Invisible Security (SSS 2-of-3)",
        }
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
        "name": account_name(&address),
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
            info!("💸 Transfer: {} → {} : {} BB", from, payload.to, payload.amount);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "from": from,
                "to": payload.to,
                "amount": payload.amount,
                "from_balance": state.blockchain.get_balance(from),
                "to_balance": state.blockchain.get_balance(&payload.to),
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
        "current_slot": poh.current_slot,
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
        Some(block) => Json(serde_json::json!({
            "success": true,
            "block": {
                "slot": block.slot,
                "hash": block.hash,
                "tx_count": block.tx_count,
                "transactions": block.transactions.len()
            }
        })),
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
}

/// POST /sealevel/submit — Submit to Gulf Stream for parallel execution
async fn gulf_stream_submit_handler(
    State(state): State<AppState>,
    Json(req): Json<GulfStreamSubmitRequest>,
) -> impl IntoResponse {
    use runtime::core::{Transaction as RuntimeTx, TransactionType};

    if req.from.is_empty() || req.to.is_empty() || req.amount <= 0.0 {
        return Json(serde_json::json!({ "error": "Invalid parameters" }));
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
    if req.amount <= 0.0 || req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid mint parameters"
        })));
    }

    match state.blockchain.credit(&req.to, req.amount) {
        Ok(_) => {
            info!("🪙 MINT: {} BB → {} (receipt: {:?})", 
                req.amount, req.to, req.l2_receipt_id);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "minted": req.amount,
                "to": req.to,
                "new_balance": state.blockchain.get_balance(&req.to),
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
            info!("🔥 BURN: {} BB from {} (receipt: {:?})", req.amount, req.from, req.l2_receipt_id);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "burned": req.amount,
                "from": req.from,
                "new_balance": state.blockchain.get_balance(&req.from),
                "l2_receipt_id": req.l2_receipt_id,
            })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))),
    }
}

// ============================================================================
// FAUCET — Public token mint (max 100 BB per address per epoch)
// ============================================================================

#[derive(Deserialize)]
struct FaucetRequest {
    to: String,
    amount: f64,
}

/// POST /faucet — Mint up to 100 BB to any address (rate-limited per epoch)
async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    const MAX_FAUCET_BB: f64 = 100.0;

    if req.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Missing 'to' address"
        })));
    }
    let amount = req.amount.min(MAX_FAUCET_BB).max(0.0);
    if amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Amount must be between 0 and 100 BB"
        })));
    }

    // Determine current epoch (432,000 slots per epoch, ~2 days at 400ms)
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let current_epoch = current_slot / 432_000;

    // Rate-limit: one faucet per address per epoch, up to 100 BB total
    {
        let mut entry = state.faucet_claims.entry(req.to.clone()).or_insert((current_epoch, 0.0));
        let (claimed_epoch, claimed_total) = entry.value_mut();

        // Reset if new epoch
        if *claimed_epoch != current_epoch {
            *claimed_epoch = current_epoch;
            *claimed_total = 0.0;
        }

        let remaining = MAX_FAUCET_BB - *claimed_total;
        if remaining <= 0.0 {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
                "error": "Faucet limit reached for this epoch (100 BB)",
                "epoch": current_epoch,
                "claimed": *claimed_total,
                "next_epoch_slot": (current_epoch + 1) * 432_000
            })));
        }

        let mint_amount = amount.min(remaining);

        match state.blockchain.credit(&req.to, mint_amount) {
            Ok(_) => {
                *claimed_total += mint_amount;
                info!("🚰 FAUCET: {} BB → {} (epoch {})", mint_amount, req.to, current_epoch);
                return (StatusCode::OK, Json(serde_json::json!({
                    "success": true,
                    "minted": mint_amount,
                    "to": req.to,
                    "new_balance": state.blockchain.get_balance(&req.to),
                    "epoch": current_epoch,
                    "remaining_this_epoch": MAX_FAUCET_BB - *claimed_total
                })));
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": format!("Mint failed: {}", e)
                })));
            }
        }
    }
}

/// POST /admin/dealer/settle — Dealer settles L2 receipts in batch
///
/// Flow: L2 sends receipts of losing bets → Dealer mints to self → pays winners
#[derive(Deserialize)]
struct DealerSettlementRequest {
    /// List of payouts: (address, amount) pairs
    payouts: Vec<PayoutEntry>,
    /// L2 batch receipt ID
    batch_receipt_id: String,
}

#[derive(Deserialize)]
struct PayoutEntry {
    address: String,
    amount: f64,
}

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
                results.push(serde_json::json!({
                    "address": payout.address,
                    "amount": payout.amount,
                    "status": "paid",
                    "new_balance": state.blockchain.get_balance(&payout.address),
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
// ADMIN — Wallet Hot Upgrade Migration
// ============================================================================

/// Request body for POST /admin/wallet/migrate
#[derive(Deserialize)]
struct MigrateWalletsRequest {
    /// List of (name, old_address, new_address) mappings
    mappings: Vec<MigrateMapping>,
    /// Whether to drain old wallets to zero after migration (default: true)
    #[serde(default = "default_true")]
    drain_old: bool,
    /// Whether to copy Share B data (only for same-format migrations)
    #[serde(default)]
    migrate_shares: bool,
}

#[derive(Deserialize)]
struct MigrateMapping {
    name: String,
    old_address: String,
    new_address: String,
}

fn default_true() -> bool { true }

/// POST /admin/wallet/migrate — Execute a wallet balance migration
///
/// Atomically transfers all balances from old addresses to new addresses.
/// Used when wallet structure changes (e.g. FROST v1 → Shamir v2).
///
/// This is safe to run while the server is live. Each wallet transfer is
/// atomic via ReDB MVCC. The endpoint is idempotent — running it again
/// on already-migrated (zero balance) wallets is a no-op.
async fn wallet_migrate_handler(
    State(state): State<AppState>,
    Json(req): Json<MigrateWalletsRequest>,
) -> impl IntoResponse {
    use wallet_unified::migration::*;

    let mappings: Vec<(&str, &str, &str)> = req.mappings.iter()
        .map(|m| (m.name.as_str(), m.old_address.as_str(), m.new_address.as_str()))
        .collect();

    let plan = build_balance_migration_plan(
        WalletVersion::V1Frost,
        WalletVersion::V2Shamir,
        mappings,
        req.migrate_shares,
    );

    // Override drain setting from request
    let plan = MigrationPlan {
        drain_old_wallets: req.drain_old,
        ..plan
    };

    let report = execute_migration(&state.blockchain, &plan);

    let status = if report.failed == 0 {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    };

    (status, Json(serde_json::json!(report)))
}

/// GET /admin/accounts — View all known account balances
async fn admin_accounts_handler(State(state): State<AppState>) -> impl IntoResponse {
    // v1 FROST wallets (legacy — may have zero balance after migration)
    let v1_wallets = vec![
        ("Alice (v1)",  "bb_7707fe614ad679b84a6cbc128999c1b5"),
        ("Bob (v1)",    "bb_2123862491cdd1865e06cc684f57e7cb"),
        ("Max (v1)",    "bb_54c74820ffa82db9dca554329e521f98"),
        ("Apollo (v1)", "bb_d49a03bf45f92bb9d9f9d0a85b4af5e6"),
        ("Dealer (v1)", "bb_6a2944608156ffc470bdaea36018a3e9"),
    ];

    // v2 Shamir wallets (current — SVM-compatible Ed25519)
    let v2_wallets = vec![
        ("Max",    "GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV"),
        ("Alice",  "EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk"),
        ("Bob",    "mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd"),
        ("Apollo", "EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb"),
        ("Dealer", "3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp"),
    ];

    let mut accounts: Vec<serde_json::Value> = Vec::new();

    // Add v2 wallets first (active)
    for (name, addr) in &v2_wallets {
        let balance = state.blockchain.get_balance(addr);
        accounts.push(serde_json::json!({
            "name": name,
            "address": addr,
            "balance": balance,
            "version": "v2-shamir",
            "role": if *name == "Dealer" { "admin" } else { "user" },
            "active": true,
        }));
    }

    // Add v1 wallets (legacy — only if they still have balance)
    for (name, addr) in &v1_wallets {
        let balance = state.blockchain.get_balance(addr);
        if balance > 0.0 {
            accounts.push(serde_json::json!({
                "name": name,
                "address": addr,
                "balance": balance,
                "version": "v1-frost",
                "role": "legacy",
                "active": false,
            }));
        }
    }

    let total_supply = state.blockchain.total_supply();

    Json(serde_json::json!({
        "accounts": accounts,
        "total_supply": total_supply,
        "dealer_address": "3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp",
        "wallet_version": "v2-shamir",
    }))
}

/// GET /admin/security/stats
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
struct UsdcBalanceQuery {
    /// Optional mint address (defaults to USDC if omitted)
    mint: Option<String>,
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
        let timestamp_str = chrono::NaiveDateTime::from_timestamp_opt(tx.timestamp as i64, 0)
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
    output.push_str(" 🛡️  Ed25519 Signatures │ MD5 TX Hashes │ Chain-Linked │ State Validated │ ZKP Auth Ready │ Immutably Stored on BlackBook L1\n");
    output.push_str("\n");
    
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; charset=utf-8")],
        output
    )
}

/// Helper to format addresses for display - show meaningful parts
fn format_address_readable(addr: &str) -> String {
    if addr.starts_with("bb_") {
        format!("bb_{}", &addr[3..].chars().take(8).collect::<String>())
    } else if addr.starts_with("L1_") {
        format!("L1_{}", &addr[3..].chars().take(8).collect::<String>())
    } else if addr.starts_with("L2_") || addr.contains("ESCROW") || addr.contains("escrow") {
        "L2_ESCROW_POOL".to_string()
    } else if addr.len() > 20 {
        format!("{}...{}", &addr[..8], &addr[addr.len()-8..])
    } else {
        addr.to_string()
    }
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
// CREDIT SESSIONS (L2 Bridge Support)
// ============================================================================

#[derive(Deserialize)]
struct CreditOpenRequest {
    wallet: String,
    amount: f64,
    session_id: Option<String>,
}

/// POST /credit/open — Lock tokens for L2 session
async fn credit_open_handler(
    State(state): State<AppState>,
    Json(req): Json<CreditOpenRequest>,
) -> impl IntoResponse {
    let balance = state.blockchain.get_balance(&req.wallet);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Insufficient balance",
            "available": balance,
        })));
    }

    if let Err(e) = state.blockchain.debit(&req.wallet, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })));
    }

    let session_id = req.session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    match state.assets.open_market_session(&req.wallet, req.amount, &session_id) {
        Ok(session) => {
            info!("🔒 Lock: {} BB from {} (session: {})", req.amount, req.wallet, session.id);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "session_id": session.id,
                "locked_amount": req.amount,
            })))
        }
        Err(e) => {
            let _ = state.blockchain.credit(&req.wallet, req.amount);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })))
        }
    }
}

#[derive(Deserialize)]
struct CreditSettleRequest {
    session_id: String,
    net_pnl: f64,
}

/// POST /credit/settle — Settle L2 session, return tokens ± PnL
async fn credit_settle_handler(
    State(state): State<AppState>,
    Json(req): Json<CreditSettleRequest>,
) -> impl IntoResponse {
    match state.assets.settle_market_session(&req.session_id, req.net_pnl) {
        Ok(result) => {
            if let Some(wallet) = &result.wallet {
                let final_amount = result.locked_amount + req.net_pnl;
                if final_amount > 0.0 {
                    if let Err(e) = state.blockchain.credit(wallet, final_amount) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })));
                    }
                }
                info!("🔓 Settle: {} BB to {} (pnl: {:+})", final_amount.max(0.0), wallet, req.net_pnl);
                (StatusCode::OK, Json(serde_json::json!({
                    "success": true,
                    "session_id": req.session_id,
                    "net_pnl": req.net_pnl,
                    "returned": final_amount.max(0.0),
                    "new_balance": state.blockchain.get_balance(wallet),
                })))
            } else {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "No wallet for session" })))
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))),
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
        // Web Wallet UI
        .route("/wallet", get(wallet_page::wallet_page_handler))
        // Public
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/balance/{address}", get(balance_handler))
        .route("/ledger", get(ledger_handler))
        // Transfers (Submission)
        .route("/transfer/simple", post(signed_transfer_handler))
        // PoH & Consensus
        .route("/poh/status", get(poh_status_handler))
        .route("/poh/block/latest", get(poh_latest_block_handler))
        .route("/poh/block/{slot}", get(poh_block_by_slot_handler))
        .route("/poh/tx/{tx_id}/status", get(poh_tx_status_handler))
        // Sealevel
        .route("/sealevel/submit", post(gulf_stream_submit_handler))
        // Credit/Bridge (L2 sessions)
        .route("/credit/open", post(credit_open_handler))
        .route("/credit/settle", post(credit_settle_handler))
        // Admin (Dealer)
        // Faucet (public)
        .route("/faucet", post(faucet_handler))
        // Admin (Dealer)
        .route("/admin/mint", post(admin_mint_handler))
        .route("/admin/burn", post(admin_burn_handler))
        .route("/admin/dealer/settle", post(dealer_settle_handler))
        .route("/admin/wallet/migrate", post(wallet_migrate_handler))
        .route("/admin/accounts", get(admin_accounts_handler))
        .route("/admin/security/stats", get(security_stats_handler))
        // USDC SPL Token
        .route("/admin/usdc/mint", post(usdc_mint_handler))
        .route("/usdc/transfer", post(usdc_transfer_handler))
        .route("/usdc/balance/{address}", get(usdc_balance_handler))
        .route("/usdc/supply", get(usdc_supply_handler))
        .route("/usdc/accounts/{address}", get(usdc_accounts_handler))
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

    // 1. Logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,layer1=debug")))
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true))
        .init();

    info!("╔══════════════════════════════════════════════════════╗");
    info!("║       BLACKBOOK L1 — DIGITAL CENTRAL BANK           ║");
    info!("╠══════════════════════════════════════════════════════╣");
    info!("║  Version:   {} ({})                          ║", VERSION, NETWORK);
    info!("║  Jobs:      Gatekeeper + Invisible Security          ║");
    info!("║  Engine:    PoH + Sealevel + Gulf Stream             ║");
    info!("║  Wallets:   BIP-39 + SSS 2-of-3 + ZKP               ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // 2. PoH Clock
    let poh_config = PoHConfig {
        slot_duration_ms: POH_SLOT_DURATION_MS,
        hashes_per_tick: POH_HASHES_PER_TICK,
        ticks_per_slot: POH_TICKS_PER_SLOT,
        slots_per_epoch: POH_SLOTS_PER_EPOCH,
    };
    let poh_service: SharedPoHService = create_poh_service(poh_config);
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
    let assets = AssetManager::new();
    let supabase = Arc::new(SupabaseManager::new());
    info!("🔐 Supabase Vault initialized");

    // 4. Consensus Infrastructure
    let current_slot = Arc::new(AtomicU64::new(0));
    let leader_schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = leader_schedule.write();
        schedule.update_stake("genesis_validator", 1000.0);
        schedule.generate_schedule(0, POH_SLOTS_PER_EPOCH);
    }

    let (pipeline, _commit_rx) = TransactionPipeline::new();
    pipeline.start(current_slot.clone());
    info!("🔄 Pipeline started");

    let parallel_scheduler = Arc::new(ParallelScheduler::new());
    let gulf_stream = GulfStreamService::new(leader_schedule.clone(), current_slot.clone());
    gulf_stream.start();
    info!("🌊 Gulf Stream started");

    let block_producer = Arc::new(BlockProducer::new(
        blockchain.clone(),
        poh_service.clone(),
        leader_schedule.clone(),
        current_slot.clone(),
        "genesis_validator".to_string(),
    ));
    let finality_tracker = Arc::new(FinalityTracker::new(current_slot.clone()));

    // 5. Security
    let throttler = Arc::new(NetworkThrottler::new());
    let circuit_breaker = Arc::new(CircuitBreaker::new());
    circuit_breaker.add_exemption("genesis");
    circuit_breaker.add_exemption("system");
    let fee_market = Arc::new(LocalizedFeeMarket::new());
    let account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>> = Arc::new(dashmap::DashMap::new());
    info!("🛡️  Security initialized");

    // 6. Sealevel Execution Loop
    let sealevel_bc = blockchain.clone();
    let sealevel_sched = parallel_scheduler.clone();
    let sealevel_gs = gulf_stream.clone();
    let sealevel_ls = leader_schedule.clone();
    let sealevel_slot = current_slot.clone();
    let sealevel_fin = finality_tracker.clone();
    let sealevel_poh = poh_service.clone();

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
                        if sealevel_bc.transfer(&tx.from, &tx.to, tx.amount).is_ok() {
                            sealevel_poh.write().queue_transaction(tx.id.clone());
                            sealevel_fin.record_inclusion(&tx.id, slot);
                        }
                    }
                }
            }
            sealevel_gs.clear_leader_cache(&leader);
            sealevel_sched.tune_batch_size();
        }
    });

    // 7. Build State
    let state = AppState {
        blockchain,
        assets,
        supabase,
        poh: poh_service.clone(),
        current_slot: current_slot.clone(),
        leader_schedule,
        pipeline,
        parallel_scheduler,
        gulf_stream,
        block_producer,
        finality_tracker,
        throttler,
        circuit_breaker,
        fee_market,
        account_metadata,
        used_nonces: Arc::new(dashmap::DashMap::new()),
        faucet_claims: Arc::new(dashmap::DashMap::new()),
    };

    // 8. Unified Wallet Router (FROST + SSS + Mnemonic)
    let vault_manager = Arc::new(VaultManager::new().expect("CRITICAL: Vault Connection Required for Production"));

    let unified_state = Arc::new(UnifiedWalletState::new(
        Arc::new(state.blockchain.clone()),
        state.supabase.clone(),
        vault_manager
    ));
    let unified_router = wallet_unified::handlers::router().with_state(unified_state);

    // Extract Arcs for RPC before state is moved into build_router
    let rpc_svm_accounts = Arc::clone(&state.blockchain.svm_accounts);
    let rpc_current_slot = Arc::clone(&state.current_slot);

    // Bootstrap the USDC SPL Token Mint (idempotent — no-op if already exists)
    {
        use svm::SplTokenEngine;
        // Dealer v2 wallet is the mint authority for USDC on BlackBook L1
        let dealer_v2_bytes = bs58::decode("3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp")
            .into_vec().unwrap();
        let mut dealer_key = [0u8; 32];
        dealer_key.copy_from_slice(&dealer_v2_bytes);
        let mint_authority = solana_sdk::pubkey::Pubkey::new_from_array(dealer_key);

        match SplTokenEngine::bootstrap_usdc_mint(&rpc_svm_accounts, &mint_authority) {
            Ok(mint_addr) => info!("💵 USDC Mint: {}", mint_addr),
            Err(e) => error!("❌ USDC mint bootstrap failed: {:?}", e),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 9b. Sync legacy L1 balances → SVM AccountsDB
    // ═══════════════════════════════════════════════════════════════
    // Wallet extensions (Backpack, Nightly, Phantom) read balances via
    // the Solana JSON-RPC `getBalance` which queries the SVM accounts DB.
    // Legacy L1 balances live in the f64 cache — we seed them into SVM
    // so wallets show correct balances immediately on connect.
    {
        use crate::svm::types::LAMPORTS_PER_BB;
        use solana_sdk::account::AccountSharedData;
        use solana_sdk::pubkey::Pubkey;

        let mut synced = 0u32;
        for entry in state.blockchain.cache.iter() {
            let addr = entry.key();
            let bb_balance = *entry.value();

            // Skip legacy bb_ prefixed addresses (v1 wallets aren't base58 pubkeys)
            if addr.starts_with("bb_") {
                continue;
            }

            // Parse as Solana pubkey
            let pk = match bs58::decode(addr.as_str()).into_vec() {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Pubkey::new_from_array(arr)
                }
                _ => continue, // skip non-pubkey addresses
            };

            // Seed if SVM has no account or has 0 lamports but legacy has balance
            let lamports = (bb_balance * LAMPORTS_PER_BB as f64) as u64;
            if lamports > 0 {
                let existing = rpc_svm_accounts.get_account(&pk);
                let existing_lamports = existing.as_ref()
                    .map(|a| {
                        use solana_sdk::account::ReadableAccount;
                        a.lamports()
                    })
                    .unwrap_or(0);

                if existing_lamports == 0 {
                    let account = AccountSharedData::new(
                        lamports,
                        0,
                        &solana_sdk::system_program::id(),
                    );
                    rpc_svm_accounts.store_account(&pk, account);
                    synced += 1;
                    info!("💰 SVM sync: {} → {} lamports ({} BB)", addr, lamports, bb_balance);
                }
            }
        }
        if synced > 0 {
            info!("✅ Synced {} legacy accounts → SVM AccountsDB", synced);
        }
    }

    // 10. HTTP Server
    let app = build_router(state, unified_router);
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();

    info!("");
    info!("rocket Listening on http://{}", addr);
    info!("");
    info!("📡 ENDPOINTS:");
    info!("   GET  /health                    Health check");
    info!("   GET  /balance/{{address}}         Balance lookup");
    info!("   POST /transfer/simple           Broadcast Signed TX");
    info!("   GET  /ledger                    Transaction history");
    info!("");
    info!("🔐 UNIFIED WALLET (FROST 2-of-3):");
    info!("   POST /wallet/create             Create (Triple-Write)");
    info!("   POST /wallet/sign               Sign (FROST Aggregation)");
    info!("   POST /wallet/share_b            Get Cloud Shard (ReDB)");
    info!("   POST /wallet/secure/shard-b     Get Cloud Shard (Supabase)");
    info!("   POST /wallet/secure/recover-shard-c  Get Vault Shard (Recovery)");
    info!("");
    info!("⚡ ENGINE:");
    info!("   GET  /poh/status                PoH clock");
    info!("   GET  /poh/block/latest          Latest block");
    info!("   POST /sealevel/submit           Parallel execution");
    info!("");
    info!("🎰 ADMIN (Dealer):");
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
    info!("🌐 gRPC: 0.0.0.0:50051");
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

        // Slot ticker: advance the shared slot counter + SVM blockhash queue
        // every 600ms (matching PoH slot interval). This keeps OneKey / Phantom
        // from treating the node as stale.
        let ticker_slot = rpc_current_slot.clone();
        let ticker_svm = Arc::clone(&rpc_svm);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(600));
            loop {
                interval.tick().await;
                let new_slot = ticker_slot.fetch_add(1, Ordering::Relaxed) + 1;
                // Advance the SVM blockhash queue so getLatestBlockhash always returns
                // a fresh hash and sendTransaction doesn't reject "stale blockhash".
                if let Ok(mut svm) = ticker_svm.lock() {
                    let slot_hash_bytes: [u8; 32] = Sha256::digest(
                        format!("BB_SLOT_{}", new_slot).as_bytes()
                    ).into();
                    svm.advance_slot(new_slot, Hash::new_from_array(slot_hash_bytes));
                }
            }
        });
        info!("🕐 Slot ticker started (600ms intervals → advancing slot + blockhash)");

        let rpc_impl = BlackBookRpcImpl::new(rpc_svm_accounts, rpc_svm, rpc_current_slot);
        match start_rpc_server(rpc_impl, "0.0.0.0:8899").await {
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

    info!("✅ Server shutdown complete");
}
