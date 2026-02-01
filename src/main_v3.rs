// ============================================================================
// LAYER1 BLOCKCHAIN SERVER V3 - Production Core (Axum + ReDB + Concurrency)
// ============================================================================
//
// BlackBook L1 - High-Performance Blockchain Server
// 
// ARCHITECTURE UPGRADES (V3):
// - Framework: Warp → Axum (no recursion limits, 10x faster compile)
// - Storage: Sled → ReDB (ACID safety, MVCC, stable format)
// - Concurrency: Mutex<Blockchain> → DashMap + ConcurrentBlockchain
// - Observability: println! → tracing (structured logs)
// - State: BridgeState + CreditState → AssetManager (unified L2 integration)
//
// CONCURRENCY MODEL:
// - Lock-free balance reads via DashMap cache
// - MVCC reads via ReDB (multiple concurrent readers)
// - Write serialization only when necessary
// - All 64 cores can work simultaneously
//
// Run: cargo run
// Test: curl http://localhost:8080/health

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::net::SocketAddr;
use std::fs;

use tokio::signal;
use tokio::sync::Mutex as TokioMutex;
use parking_lot::RwLock;

use tracing::{info, warn, error, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use axum::{
    routing::{get, post},
    Router,
    Extension,
    Json,
    extract::{State, Path, Query},
    response::IntoResponse,
    http::StatusCode,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

// ============================================================================
// MODULES
// ============================================================================

mod social_mining;
mod integration;
mod routes_v2;
mod unified_wallet;
mod wallet_mnemonic;
mod consensus;
mod grpc;
mod storage;

#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

mod poh_blockchain;

// ============================================================================
// IMPORTS
// ============================================================================

use social_mining::SocialMiningSystem;
use storage::{ConcurrentBlockchain, AssetManager, TransactionRecord};
use integration::unified_auth::SignedRequest;
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule, GulfStreamService, PoHEntry,
    ParallelScheduler,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
    // Ideal Hybrid Security Infrastructure
    NetworkThrottler, CircuitBreaker, LocalizedFeeMarket,
    AccountValidator, AccountType, AccountMetadata, PDAInfo,
    AccountAccess, ProgramDerivedAddress,
};
use protocol::Transaction as ProtocolTransaction;
use poh_blockchain::{
    BlockProducer, FinalizedBlock, MerkleTree, FinalityTracker,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
    TurbineShredder, TurbinePropagator, TURBINE_FANOUT,
};

// S+ Tier Wallet System (FROST + OPAQUE)
use unified_wallet::{
    WalletHandlers, FrostDKG, ThresholdSigner, OpaqueAuth, ShardStorage,
};

// Mnemonic Wallet System (Consumer Track)
use wallet_mnemonic::handlers::MnemonicHandlers;

// ============================================================================
// CONSTANTS
// ============================================================================

const SOCIAL_DATA_FILE: &str = "social_mining_data.json";
const REDB_DATA_PATH: &str = "./blockchain_data";

// Tiered Security - High-value transaction threshold
const HIGH_VALUE_THRESHOLD: f64 = 100_000.0;
const DEFAULT_SECURITY_PIN: &str = "1234"; // Dev mode - replace with proper PIN system

// Test account addresses (derived from Ed25519 seeds)
const ALICE_L1: &str = "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8";
const BOB_L1: &str = "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433";
const DEALER_L1: &str = "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D";

// ============================================================================
// APPLICATION STATE (Shared across all handlers)
// ============================================================================

/// Central application state - passed to all Axum handlers via State<AppState>
#[derive(Clone)]
pub struct AppState {
    /// Lock-free blockchain access (DashMap cache + ReDB MVCC)
    pub blockchain: ConcurrentBlockchain,
    
    /// Unified L2 integration (replaces BridgeState + CreditState)
    pub assets: AssetManager,
    
    /// Social mining system
    pub social: Arc<TokioMutex<SocialMiningSystem>>,
    
    /// Proof of History service
    pub poh: SharedPoHService,
    
    /// Current slot tracker
    pub current_slot: Arc<AtomicU64>,
    
    /// Leader schedule for consensus
    pub leader_schedule: Arc<RwLock<LeaderSchedule>>,
    
    /// Transaction pipeline
    pub pipeline: Arc<TransactionPipeline>,
    
    /// Sealevel-style parallel transaction execution
    pub parallel_scheduler: Arc<ParallelScheduler>,
    
    /// Gulf Stream - transaction forwarding to upcoming leaders
    pub gulf_stream: Arc<GulfStreamService>,
    
    /// PoH-integrated block producer
    pub block_producer: Arc<BlockProducer>,
    
    /// Transaction finality tracker
    pub finality_tracker: Arc<FinalityTracker>,
    
    // =========================================================================
    // IDEAL HYBRID SECURITY INFRASTRUCTURE
    // =========================================================================
    
    /// Network throttler - Stake-weighted rate limiting (QUIC-style)
    /// Prevents spam by limiting tx/sec based on sender's stake
    pub throttler: Arc<NetworkThrottler>,
    
    /// Circuit breaker - Automatic protection against bank runs
    /// Trips if >20% of account value moved in one block
    pub circuit_breaker: Arc<CircuitBreaker>,
    
    /// Localized fee market - Per-account-group fees (not global spikes)
    /// Spam only raises fees for the spammer, not everyone
    pub fee_market: Arc<LocalizedFeeMarket>,
    
    /// Account metadata - Type-safe PDA accounts (immune to confusion attacks)
    pub account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>>,
    
    // =========================================================================
    // S+ TIER WALLET SYSTEM (FROST + OPAQUE)
    // =========================================================================
    
    /// Unified wallet handlers (MPC threshold signing, OPAQUE auth)
    pub wallet_handlers: Arc<WalletHandlers>,
}

// ============================================================================
// AXUM HANDLERS (Clean, type-safe, no Warp boilerplate)
// ============================================================================

/// GET /health - Health check with full Solana-style infrastructure status
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let total_supply = state.blockchain.total_supply();
    let stats = state.blockchain.stats();
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let parallel_stats = state.parallel_scheduler.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let pipeline_stats = state.pipeline.get_stats();
    
    // PoH status
    let poh_status = {
        let poh = state.poh.read();
        poh.get_status()
    };
    
    // Calculate TPS metrics
    // 10,000 txs/block ÷ 0.4s = 25,000 TPS theoretical max
    let theoretical_max_tps = (MAX_TXS_PER_BLOCK as f64 / (BLOCK_INTERVAL_MS as f64 / 1000.0)) as u64;
    let finality_time_ms = CONFIRMATIONS_REQUIRED * BLOCK_INTERVAL_MS;
    
    // Current throughput estimate
    let current_tps = if parallel_stats.total_batches > 0 {
        // txs processed × 2.5 slots/sec
        (parallel_stats.total_processed as f64 / parallel_stats.total_batches as f64) * 2.5
    } else {
        0.0
    };
    
    Json(serde_json::json!({
        "status": "ok",
        "version": "3.0.0",
        "engine": "axum",
        "storage": "redb",
        "total_supply": total_supply,
        "account_count": stats.total_accounts,
        
        // ═══════════════════════════════════════════════════════════
        // SOLANA-STYLE INFRASTRUCTURE STATUS
        // ═══════════════════════════════════════════════════════════
        
        "poh_clock": {
            "status": "running",
            "current_slot": poh_status["current_slot"],
            "current_epoch": poh_status["current_epoch"],
            "num_hashes": poh_status["num_hashes"],
            "slot_duration_ms": BLOCK_INTERVAL_MS,
            "slots_per_second": 2.5,
            "hash_rate": poh_status["hashes_per_second"],
        },
        
        "gulf_stream": {
            "status": if gulf_stream_stats.is_active { "active" } else { "inactive" },
            "description": "Mempool-less transaction forwarding to upcoming leaders",
            "transactions_received": gulf_stream_stats.transactions_received,
            "transactions_forwarded": gulf_stream_stats.transactions_forwarded,
            "cache_size": gulf_stream_stats.cache_size,
            "leaders_cached": gulf_stream_stats.current_leaders_cached,
            "avg_forward_latency_us": gulf_stream_stats.avg_forward_latency_us,
        },
        
        "sealevel": {
            "status": "active",
            "description": "Parallel transaction execution with fine-grained account locking",
            "total_processed": parallel_stats.total_processed,
            "total_batches": parallel_stats.total_batches,
            "current_batch_size": parallel_stats.current_batch_size,
            "conflict_rate_percent": format!("{:.2}", parallel_stats.conflict_rate * 100.0),
            "thread_count": parallel_stats.thread_count,
        },
        
        "turbine": {
            "status": "ready",
            "description": "Block propagation via shreds with erasure coding",
            "fanout": TURBINE_FANOUT,
            "max_hops_1000_validators": TurbinePropagator::max_hops(1000),
            "max_hops_10000_validators": TurbinePropagator::max_hops(10000),
        },
        
        "pipeline": {
            "status": if pipeline_stats.is_running { "running" } else { "stopped" },
            "description": "4-stage async processing: fetch → verify → execute → commit",
            "packets_received": pipeline_stats.packets_received,
            "packets_verified": pipeline_stats.packets_verified,
            "packets_executed": pipeline_stats.packets_executed,
            "packets_committed": pipeline_stats.packets_committed,
            "avg_latency_us": pipeline_stats.avg_pipeline_latency_us,
        },
        
        // ═══════════════════════════════════════════════════════════
        // PERFORMANCE METRICS
        // ═══════════════════════════════════════════════════════════
        
        "performance": {
            "theoretical_max_tps": theoretical_max_tps,
            "current_tps": format!("{:.1}", current_tps),
            "max_txs_per_block": MAX_TXS_PER_BLOCK,
            "block_interval_ms": BLOCK_INTERVAL_MS,
            "finality_time_ms": finality_time_ms,
            "finality_time_human": format!("{:.1}s", finality_time_ms as f64 / 1000.0),
            "confirmations_required": CONFIRMATIONS_REQUIRED,
        },
        
        // ═══════════════════════════════════════════════════════════
        // VALIDATOR REQUIREMENTS
        // ═══════════════════════════════════════════════════════════
        
        "validator_requirements": {
            "cpu_cores_min": 32,
            "cpu_cores_recommended": 64,
            "ram_gb_min": 128,
            "storage_type": "NVMe SSD",
            "storage_tb_min": 2,
            "network_gbps_min": 1,
            "os_recommended": "Ubuntu 22.04 LTS",
        },
        
        // ═══════════════════════════════════════════════════════════
        // IDEAL HYBRID SECURITY INFRASTRUCTURE
        // ═══════════════════════════════════════════════════════════
        // These systems differentiate BlackBook L1 from Solana:
        // - Stake-weighted throttling (vs unfiltered UDP)
        // - Localized fee markets (vs global fee spikes)
        // - Circuit breakers (vs unlimited withdrawals)
        // - Type-safe PDAs (vs manual account verification)
        
        "security": {
            "throttler": state.throttler.get_stats(),
            "circuit_breaker": state.circuit_breaker.get_stats(),
            "fee_market": state.fee_market.get_stats(),
            "account_metadata_count": state.account_metadata.len(),
            "design": "Ideal Hybrid Stablecoin L1",
            "vs_solana": {
                "transaction_ingest": "QUIC + Stake-Weighted (vs Unfiltered UDP)",
                "fee_structure": "Localized Fee Markets (vs Global Spikes)",
                "account_safety": "Declarative Framework (vs Manual Verification)",
                "consensus_speed": "600ms Stable (vs 400ms Fragile)",
                "pda_system": "Type-safe Namespaced (vs Manual Seeds)"
            }
        }
    }))
}

/// GET /stats - Blockchain statistics
async fn stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.blockchain.stats();
    let pipeline_stats = state.pipeline.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let parallel_stats = state.parallel_scheduler.get_stats();
    let lock_stats = state.parallel_scheduler.lock_manager.get_stats();
    
    Json(serde_json::json!({
        "blockchain": {
            "total_accounts": stats.total_accounts,
            "current_slot": stats.current_slot,
            "block_count": stats.block_count,
            "total_supply": stats.total_supply,
            "cache_hit_rate": stats.cache_hit_rate,
        },
        "pipeline": pipeline_stats,
        "gulf_stream": gulf_stream_stats,
        "parallel_execution": parallel_stats,
        "account_locks": lock_stats,
        "confirmations_required": CONFIRMATIONS_REQUIRED,
    }))
}

/// GET /balance/:address - Public balance lookup
async fn balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let balance = state.blockchain.get_balance(&address);
    Json(serde_json::json!({
        "address": address,
        "balance": balance,
        "unit": "BB"
    }))
}

/// GET /ledger - ASCII art visualization of all ledger entries
#[derive(serde::Deserialize)]
struct LedgerQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_page() -> usize { 1 }
fn default_limit() -> usize { 50 }

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
    output.push_str(&format!("  BLOCK HEIGHT : {:>12}                     NETWORK : [ MAINNET-ZK ]           VERSION : 2.0.0-zkp\n", stats.block_count));
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
        // Format timestamp
        let datetime = chrono::DateTime::from_timestamp(tx.timestamp as i64, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
        let time_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Format addresses
        let from_display = format_address_readable(&tx.from_address);
        let to_display = format_address_readable(&tx.to_address);
        
        // Short hashes
        let tx_hash_short = if tx.tx_hash.len() > 8 { format!("{}..{}", &tx.tx_hash[..4], &tx.tx_hash[tx.tx_hash.len()-4..]) } else { tx.tx_hash.clone() };
        let prev_hash_short = if tx.prev_tx_hash.len() > 8 { 
            format!("{}..{}", &tx.prev_tx_hash[..4], &tx.prev_tx_hash[tx.prev_tx_hash.len()-4..]) 
        } else if tx.prev_tx_hash.is_empty() || tx.prev_tx_hash == "GENESIS" { 
            "GENESIS".to_string() 
        } else { 
            tx.prev_tx_hash.clone() 
        };
        
        // Auth icon
        let auth_lower = tx.auth_type.to_lowercase();
        let auth_icon = match auth_lower.as_str() {
            "master_key" | "masterkey" => "🔑",
            "session_key" | "sessionkey" => "⚡",
            "zk_proof" | "zkproof" | "zkp_session" => "🔮",
            "system_internal" | "systeminternal" | "system" => "⚙️",
            _ => "❓",
        };
        
        // Status icon
        let status_icon = match tx.status.as_str() {
            "finalized" | "completed" => "✅",
            "pending" => "⏳",
            "reverted" => "↩️",
            "failed" => "❌",
            _ => "❓",
        };
        
        // Reconciliation check
        let reconciled_icon = if tx.is_reconciled() { "✓" } else { "✗" };
        
        // Action icon and type
        let (action_icon, action_name) = match tx.tx_type.to_lowercase().as_str() {
            "transfer" => ("💸", "TRANSFER"),
            "mint" => ("🪙", "MINT"),
            "burn" => ("🔥", "BURN"),
            "bridge_out" | "bridgeout" | "lock" => ("🌉", "BRIDGE_OUT"),
            "bridge_in" | "bridgein" | "unlock" => ("🌉", "BRIDGE_IN"),
            "market_lock" => ("🔒", "MARKET_LOCK"),
            "market_settle" => ("🔓", "MARKET_SETTLE"),
            _ => ("❓", "UNKNOWN"),
        };
        
        // Line 1: Block, Time, Hashes, Action & Flow
        output.push_str(&format!(
            " │{:>4} │ {} │ {:>12} │ {:>12} │ {} {} {} ───▶ {}                              │\n",
            tx.block_height, time_str, tx_hash_short, prev_hash_short, action_icon, action_name, from_display, to_display
        ));
        
        // Line 2: Value, Auth, State, Integrity
        output.push_str(&format!(
            " │     │                     │              │              │   {} {} │ {:>10.2} BB │ Bal: {:>10.2} → {:>10.2} │ Recv: {:>10.2} │ [{}] │\n",
            status_icon, auth_icon, tx.amount, tx.balance_before, tx.balance_after, tx.recipient_balance_after, reconciled_icon
        ));
        
        // Separator between transactions
        output.push_str(" ├─────┼─────────────────────┼──────────────┼──────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────┤\n");
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
        output.push_str(" ─── NAVIGATION ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n");
        if page > 1 {
            output.push_str(&format!("  ◀ Previous:  /ledger?page={}&limit={}\n", page - 1, limit));
        }
        if page < total_pages {
            output.push_str(&format!("  ▶ Next:      /ledger?page={}&limit={}\n", page + 1, limit));
        }
        output.push_str(&format!("  📋 Total: {} transactions │ {} pages │ Showing {} per page\n", transactions.len(), total_pages, limit));
        output.push_str(" ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    }
    
    // Footer
    output.push_str("\n");
    output.push_str(" 🛡️  Ed25519 Signatures │ MD5 TX Hashes │ Chain-Linked │ State Validated │ ZKP Auth Ready │ Immutably Stored on BlackBook L1\n");
    output.push_str("\n");
    
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        output
    )
}

/// Helper to format addresses for display - show meaningful parts
fn format_address_readable(addr: &str) -> String {
    if addr.starts_with("L1_") {
        // Show L1_ prefix + first 4 and last 8 chars
        let hex_part = &addr[3..];
        if hex_part.len() > 12 {
            format!("L1_{}...{}", &hex_part[..4], &hex_part[hex_part.len()-8..])
        } else {
            addr.to_string()
        }
    } else if addr.starts_with("L2_") || addr.contains("ESCROW") || addr.contains("escrow") {
        "L2_ESCROW_POOL".to_string()
    } else if addr.len() > 20 {
        format!("{}...{}", &addr[..8], &addr[addr.len()-8..])
    } else {
        addr.to_string()
    }
}

/// GET /transactions - Query transaction history
#[derive(serde::Deserialize)]
struct TransactionsQuery {
    address: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn transactions_handler(
    State(state): State<AppState>,
    Query(query): Query<TransactionsQuery>,
) -> impl IntoResponse {
    match state.blockchain.get_transactions(
        query.address.as_deref(),
        query.limit,
        query.offset
    ) {
        Ok(transactions) => Json(serde_json::json!({
            "success": true,
            "transactions": transactions,
            "count": transactions.len(),
            "limit": query.limit,
            "offset": query.offset
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e,
            "transactions": []
        }))
    }
}

/// GET /poh/status - PoH clock status
async fn poh_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let poh = state.poh.read();
    Json(serde_json::json!({
        "current_slot": poh.current_slot,
        "num_hashes": poh.num_hashes,
        "current_hash": poh.current_hash,
        "is_running": true
    }))
}

/// GET /performance/stats - All service statistics
async fn performance_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "pipeline": state.pipeline.get_stats(),
        "blockchain": state.blockchain.stats(),
        "assets": state.assets.stats(),
        "gulf_stream": state.gulf_stream.get_stats(),
        "parallel_execution": state.parallel_scheduler.get_stats(),
        "account_locks": state.parallel_scheduler.lock_manager.get_stats(),
        "current_slot": state.current_slot.load(std::sync::atomic::Ordering::Relaxed),
        "status": "all_services_running"
    }))
}

// ============================================================================
// SEALEVEL EXECUTION HANDLERS (Solana-style)
// ============================================================================

/// POST /sealevel/submit - Submit transaction to Gulf Stream for forwarding
/// 
/// This is the HIGH-PERFORMANCE entry point for transactions:
/// 1. Validates basic fields
/// 2. Submits to Gulf Stream for forwarding to upcoming leaders
/// 3. Also submits to Pipeline for 4-stage processing
/// 4. Returns immediately (non-blocking) with tx_id
/// 
/// Transactions are then executed in parallel batches by the Sealevel loop.
#[derive(serde::Deserialize)]
struct GulfStreamSubmitRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(default)]
    tx_type: String,  // "transfer", "bet", "social"
    #[serde(default)]
    priority: Option<u64>,  // Optional priority boost (higher = faster processing)
}

async fn gulf_stream_submit_handler(
    State(state): State<AppState>,
    Json(req): Json<GulfStreamSubmitRequest>,
) -> impl IntoResponse {
    use runtime::core::{Transaction as RuntimeTx, TransactionType};
    use runtime::PipelinePacket;
    
    // Basic validation
    if req.from.is_empty() || req.to.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Invalid from/to addresses"
        }));
    }
    if req.amount <= 0.0 {
        return Json(serde_json::json!({
            "success": false,
            "error": "Amount must be positive"
        }));
    }
    
    // =========================================================================
    // IDEAL HYBRID SECURITY CHECK 1: Stake-Weighted Rate Limiting
    // =========================================================================
    // Unlike Solana's unfiltered UDP, we enforce per-sender throttling
    // Higher stake = more transactions allowed per second
    let sender_stake = state.blockchain.get_balance(&req.from); // Use balance as proxy for stake
    if let Err(e) = state.throttler.check_transaction(&req.from, sender_stake) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Rate limited: {}", e),
            "throttler_stats": state.throttler.get_stats()
        }));
    }
    
    // =========================================================================
    // IDEAL HYBRID SECURITY CHECK 2: Localized Fee Market
    // =========================================================================
    // Calculate fee based on sender's group congestion (not global!)
    let required_fee = state.fee_market.calculate_fee(&req.from);
    // For now, we don't charge fees but we log them for monitoring
    if required_fee > 0.0 {
        info!("💰 Localized fee for {}: {:.6} wUSDC", &req.from[..20.min(req.from.len())], required_fee);
    }
    
    // =========================================================================
    // IDEAL HYBRID SECURITY CHECK 3: Circuit Breaker (Bank Run Protection)
    // =========================================================================
    // Check if this transfer would trip the circuit breaker
    let current_balance = state.blockchain.get_balance(&req.from);
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    
    if let Err(e) = state.circuit_breaker.check_transfer(&req.from, req.amount, current_balance, current_slot) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Circuit breaker tripped: {}", e),
            "circuit_breaker_stats": state.circuit_breaker.get_stats()
        }));
    }
    
    // Balance check (fast, lock-free)
    let balance = state.blockchain.get_balance(&req.from);
    if balance < req.amount {
        // Mark transaction completed (for throttler accounting)
        state.throttler.transaction_completed();
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: have {:.2}, need {:.2}", balance, req.amount)
        }));
    }
    
    let tx_type = match req.tx_type.as_str() {
        "bet" => TransactionType::BetPlacement,
        "social" => TransactionType::SocialAction,
        _ => TransactionType::Transfer,
    };
    
    // Create runtime transaction with auto-detected read/write accounts
    let mut tx = RuntimeTx::new(req.from.clone(), req.to.clone(), req.amount, tx_type);
    let tx_id = tx.id.clone();
    
    // Apply priority boost if provided (higher value transactions or explicit priority)
    if let Some(p) = req.priority {
        // Priority will be used by Gulf Stream for ordering
        tx.nonce = p; // Reuse nonce field for priority in Gulf Stream
    }
    
    // Submit to Gulf Stream (forwarding to upcoming leaders)
    if let Err(e) = state.gulf_stream.submit(tx.clone()) {
        state.throttler.transaction_completed();
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Gulf Stream submission failed: {}", e)
        }));
    }
    
    // Also submit to Pipeline for 4-stage processing (fetch → verify → execute → commit)
    let packet = PipelinePacket::new(tx_id.clone(), req.from.clone(), req.to.clone(), req.amount);
    if let Err(e) = state.pipeline.submit(packet).await {
        warn!("Pipeline submission failed (Gulf Stream will still process): {}", e);
    }
    
    // Note: transaction_completed() will be called after execution completes
    
    Json(serde_json::json!({
        "success": true,
        "tx_id": tx_id,
        "message": "Transaction submitted to Gulf Stream + Pipeline for parallel execution",
        "status": "pending",
        "estimated_slot": current_slot + 1,
        "gulf_stream_cache_size": state.gulf_stream.get_stats().cache_size,
        "localized_fee": required_fee,
        "security_checks_passed": ["rate_limit", "circuit_breaker", "balance"]
    }))
}

/// GET /sealevel/stats - Get Sealevel execution statistics  
/// 
/// Returns comprehensive stats for all Solana-style infrastructure:
/// - ParallelScheduler: Batch processing, conflict rate, thread count
/// - AccountLockManager: Fine-grained locking statistics
/// - GulfStream: Transaction forwarding metrics
/// - Pipeline: 4-stage processing throughput
async fn sealevel_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let parallel_stats = state.parallel_scheduler.get_stats();
    let lock_stats = state.parallel_scheduler.lock_manager.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let pipeline_stats = state.pipeline.get_stats();
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    
    // Calculate throughput metrics
    let txs_per_slot = if parallel_stats.total_batches > 0 {
        parallel_stats.total_processed as f64 / parallel_stats.total_batches as f64
    } else {
        0.0
    };
    
    Json(serde_json::json!({
        "sealevel": {
            "parallel_scheduler": {
                "total_processed": parallel_stats.total_processed,
                "total_batches": parallel_stats.total_batches,
                "current_batch_size": parallel_stats.current_batch_size,
                "conflict_rate_percent": parallel_stats.conflict_rate * 100.0,
                "thread_count": parallel_stats.thread_count,
                "avg_txs_per_batch": txs_per_slot,
            },
            "account_locks": lock_stats,
            "gulf_stream": {
                "transactions_received": gulf_stream_stats.transactions_received,
                "transactions_forwarded": gulf_stream_stats.transactions_forwarded,
                "transactions_expired": gulf_stream_stats.transactions_expired,
                "cache_size": gulf_stream_stats.cache_size,
                "leaders_cached": gulf_stream_stats.current_leaders_cached,
                "avg_forward_latency_us": gulf_stream_stats.avg_forward_latency_us,
                "is_active": gulf_stream_stats.is_active,
            },
            "pipeline": {
                "packets_received": pipeline_stats.packets_received,
                "packets_verified": pipeline_stats.packets_verified,
                "packets_executed": pipeline_stats.packets_executed,
                "packets_committed": pipeline_stats.packets_committed,
                "packets_failed": pipeline_stats.packets_failed,
                "avg_latency_us": pipeline_stats.avg_pipeline_latency_us,
                "is_running": pipeline_stats.is_running,
            },
        },
        "consensus": {
            "current_slot": current_slot,
            "confirmations_required": CONFIRMATIONS_REQUIRED,
            "slot_duration_ms": 400,  // Tuned to Solana-speed
        },
        "status": {
            "parallel_execution": true,
            "gulf_stream_active": gulf_stream_stats.is_active,
            "pipeline_running": pipeline_stats.is_running,
            "performance_mode": "SEALEVEL_ENABLED",
        }
    }))
}

/// POST /sealevel/batch - Submit multiple transactions in a single request
/// 
/// High-throughput batch submission endpoint for maximum efficiency.
/// All transactions are validated and submitted atomically.
#[derive(serde::Deserialize)]
struct BatchSubmitRequest {
    transactions: Vec<GulfStreamSubmitRequest>,
}

async fn sealevel_batch_handler(
    State(state): State<AppState>,
    Json(req): Json<BatchSubmitRequest>,
) -> impl IntoResponse {
    use runtime::core::{Transaction as RuntimeTx, TransactionType};
    
    if req.transactions.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Empty transaction batch"
        }));
    }
    
    if req.transactions.len() > 1_024 {
        return Json(serde_json::json!({
            "success": false,
            "error": "Batch too large (max 1,024 transactions)"
        }));
    }
    
    let mut submitted = Vec::new();
    let mut failed = Vec::new();
    
    for tx_req in req.transactions {
        // Validate
        if tx_req.from.is_empty() || tx_req.to.is_empty() || tx_req.amount <= 0.0 {
            failed.push(serde_json::json!({
                "from": tx_req.from,
                "to": tx_req.to,
                "error": "Invalid transaction fields"
            }));
            continue;
        }
        
        // Balance check
        let balance = state.blockchain.get_balance(&tx_req.from);
        if balance < tx_req.amount {
            failed.push(serde_json::json!({
                "from": tx_req.from,
                "to": tx_req.to,
                "error": format!("Insufficient balance: {:.2} < {:.2}", balance, tx_req.amount)
            }));
            continue;
        }
        
        let tx_type = match tx_req.tx_type.as_str() {
            "bet" => TransactionType::BetPlacement,
            "social" => TransactionType::SocialAction,
            _ => TransactionType::Transfer,
        };
        
        let tx = RuntimeTx::new(tx_req.from.clone(), tx_req.to.clone(), tx_req.amount, tx_type);
        let tx_id = tx.id.clone();
        
        if state.gulf_stream.submit(tx).is_ok() {
            submitted.push(serde_json::json!({
                "tx_id": tx_id,
                "from": tx_req.from,
                "to": tx_req.to,
                "amount": tx_req.amount
            }));
        } else {
            failed.push(serde_json::json!({
                "from": tx_req.from,
                "to": tx_req.to,
                "error": "Gulf Stream submission failed"
            }));
        }
    }
    
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    
    Json(serde_json::json!({
        "success": failed.is_empty(),
        "submitted_count": submitted.len(),
        "failed_count": failed.len(),
        "submitted": submitted,
        "failed": failed,
        "estimated_slot": current_slot + 1,
        "gulf_stream_cache_size": state.gulf_stream.get_stats().cache_size
    }))
}

/// GET /sealevel/pending/:leader - Get pending transactions for a leader
async fn sealevel_pending_handler(
    State(state): State<AppState>,
    Path(leader): Path<String>,
) -> impl IntoResponse {
    let pending = state.gulf_stream.get_pending_for_leader(&leader);
    let priority_pending = state.gulf_stream.get_pending_by_priority(&leader, 100);
    
    Json(serde_json::json!({
        "leader": leader,
        "pending_count": pending.len(),
        "top_100_by_priority": priority_pending.len(),
        "transactions": priority_pending.iter().map(|tx| {
            serde_json::json!({
                "id": tx.id,
                "from": tx.from,
                "to": tx.to,
                "amount": tx.amount,
            })
        }).collect::<Vec<_>>()
    }))
}

// ============================================================================
// AUTH HANDLERS (Legacy - Migrated to unified_wallet module for S+ Tier)
// ============================================================================
// 
// The old C+ grade wallet handlers have been removed in favor of the S+ Tier
// implementation in src/unified_wallet/. The new system uses:
// - FROST TSS (Threshold Signature Scheme) - key NEVER exists in full
// - OPAQUE (Password Authenticated Key Exchange) - server never sees password
// - DKG (Distributed Key Generation) - key born distributed
//
// See: src/unified_wallet/handlers.rs for the new API endpoints
// See: blackbook-wallet.md for documentation
//

// ============================================================================
// TRANSFER HANDLER
// ============================================================================

#[derive(serde::Deserialize)]
struct TransferRequest {
    public_key: String,
    payload_hash: String,
    payload_fields: TransferPayload,
    operation_type: String,
    schema_version: u8,
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    request_path: String,
    signature: String,
    #[serde(default)]
    security_pin: Option<String>, // Required for transactions > 100,000 BB
}

#[derive(serde::Deserialize)]
struct TransferPayload {
    from: String,
    to: String,
    amount: f64,
    timestamp: u64,
    nonce: String,
}

/// Simple transfer request format (for frontend compatibility)
#[derive(serde::Deserialize)]
struct SimpleTransferRequest {
    public_key: String,
    wallet_address: String,
    payload: String,  // JSON string: {"to": "...", "amount": ...}
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    schema_version: u8,
    signature: String,
}

#[derive(serde::Deserialize)]
struct SimplePayload {
    to: String,
    amount: f64,
}

/// POST /transfer/simple - Simple transfer for frontend
async fn simple_transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<SimpleTransferRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    
    // Parse the payload JSON
    let payload: SimplePayload = match serde_json::from_str(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": format!("Invalid payload JSON: {}", e)
            })));
        }
    };
    
    let from = &req.wallet_address;
    let to = &payload.to;
    let amount = payload.amount;
    
    // Basic validation
    if from.is_empty() || to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid from/to addresses"
        })));
    }

    if amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be positive"
        })));
    }

    // Verify signature
    // Frontend signs: chain_id byte + payload + newline + timestamp + newline + nonce
    let chain_id_byte = vec![req.chain_id];
    let mut message_bytes = chain_id_byte;
    message_bytes.extend_from_slice(req.payload.as_bytes());
    message_bytes.extend_from_slice(b"\n");
    message_bytes.extend_from_slice(req.timestamp.to_string().as_bytes());
    message_bytes.extend_from_slice(b"\n");
    message_bytes.extend_from_slice(req.nonce.as_bytes());
    
    // Decode public key and signature
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            })));
        }
    };
    
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature format"
            })));
        }
    };
    
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key format"
            })));
        }
    };
    
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    
    // Verify signature
    if verifying_key.verify(&message_bytes, &signature).is_err() {
        // Log for debugging
        warn!("Signature verification failed");
        warn!("  Public key: {}", req.public_key);
        warn!("  Message hex: {}", hex::encode(&message_bytes));
        warn!("  Signature: {}", req.signature);
        
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Signature verification failed"
        })));
    }

    // =========================================================================
    // IDEAL HYBRID SECURITY CHECKS
    // =========================================================================
    
    // 1. STAKE-WEIGHTED RATE LIMITING
    let sender_stake = state.blockchain.get_balance(from) / 1000.0;
    if let Err(e) = state.throttler.check_transaction(from, sender_stake) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "rate_limit",
            "stake": sender_stake
        })));
    }
    
    // 2. LOCALIZED FEE MARKET
    let localized_fee = state.fee_market.calculate_fee(from);
    
    // 3. CIRCUIT BREAKER
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let from_balance = state.blockchain.get_balance(from);
    if let Err(e) = state.circuit_breaker.check_transfer(from, amount, from_balance, current_slot) {
        state.throttler.transaction_completed();
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "circuit_breaker"
        })));
    }

    // Check balance (already have from_balance)
    if from_balance < amount {
        state.throttler.transaction_completed();
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: {} < {}", from_balance, amount),
            "localized_fee": localized_fee
        })));
    }

    // Execute transfer
    match state.blockchain.transfer(from, to, amount) {
        Ok(_) => {
            info!("💸 Transfer: {} → {} : {} BB", from, to, amount);
            state.throttler.transaction_completed();
            
            let from_new = state.blockchain.get_balance(from);
            let to_new = state.blockchain.get_balance(to);
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "from": from,
                "to": to,
                "amount": amount,
                "from_balance": from_new,
                "to_balance": to_new,
                "timestamp": req.timestamp,
                "nonce": req.nonce,
                "localized_fee": localized_fee,
                "security_checks_passed": ["rate_limit", "circuit_breaker", "balance"]
            })))
        }
        Err(e) => {
            state.throttler.transaction_completed();
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e
            })))
        }
    }
}

/// POST /transfer - Transfer tokens between addresses
async fn transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Sha256, Digest};
    
    // Basic validation
    if req.operation_type != "transfer" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid operation type"
        })));
    }

    if req.payload_fields.from.is_empty() || req.payload_fields.to.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid from/to addresses"
        })));
    }

    if req.payload_fields.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be positive"
        })));
    }

    // TIERED SECURITY: Require PIN for high-value transactions (> 100,000 BB)
    if req.payload_fields.amount > HIGH_VALUE_THRESHOLD {
        match &req.security_pin {
            Some(pin) if pin == DEFAULT_SECURITY_PIN => {
                info!("🔐 High-value transfer ({} BB) - PIN verified", req.payload_fields.amount);
            }
            Some(_) => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid security PIN for high-value transaction",
                    "amount": req.payload_fields.amount,
                    "threshold": HIGH_VALUE_THRESHOLD
                })));
            }
            None => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "success": false,
                    "error": "Security PIN required for transactions over 100,000 BB",
                    "amount": req.payload_fields.amount,
                    "threshold": HIGH_VALUE_THRESHOLD,
                    "hint": "Include security_pin in request body"
                })));
            }
        }
    }

    // Verify signature (V2 SDK format)
    // 1. Recreate canonical payload hash
    let canonical = format!(
        "{}|{}|{}|{}|{}",
        req.payload_fields.from,
        req.payload_fields.to,
        req.payload_fields.amount,
        req.payload_fields.timestamp,
        req.payload_fields.nonce
    );
    
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let payload_hash = format!("{:x}", hasher.finalize());
    
    // 2. Verify payload hash matches
    if payload_hash != req.payload_hash {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Payload hash mismatch"
        })));
    }
    
    // 3. Recreate signing message
    let domain_prefix = format!("BLACKBOOK_L{}{}", req.chain_id, req.request_path);
    let message = format!("{}\n{}\n{}\n{}", 
        domain_prefix, 
        req.payload_hash,
        req.timestamp,
        req.nonce
    );
    
    // 4. Verify Ed25519 signature
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            })));
        }
    };
    
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature"
            })));
        }
    };
    
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key format"
            })));
        }
    };
    
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    
    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Signature verification failed"
        })));
    }

    // =========================================================================
    // IDEAL HYBRID SECURITY CHECKS
    // =========================================================================
    
    // 1. STAKE-WEIGHTED RATE LIMITING (QUIC-style, not unfiltered UDP)
    // Stake calculated as 1 stake per 1000 BB balance
    let sender_stake = state.blockchain.get_balance(&req.payload_fields.from) / 1000.0;
    if let Err(e) = state.throttler.check_transaction(&req.payload_fields.from, sender_stake) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "rate_limit",
            "stake": sender_stake,
            "hint": "Increase stake or wait for rate limit window to reset"
        })));
    }
    
    // 2. LOCALIZED FEE MARKET (spam only affects spammer, not everyone)
    let localized_fee = state.fee_market.calculate_fee(&req.payload_fields.from);
    // Note: Fee is informational - could deduct in production
    
    // 3. CIRCUIT BREAKER (automatic protection against exploits/bank runs)
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let from_balance = state.blockchain.get_balance(&req.payload_fields.from);
    if let Err(e) = state.circuit_breaker.check_transfer(
        &req.payload_fields.from,
        req.payload_fields.amount,
        from_balance,
        current_slot,
    ) {
        state.throttler.transaction_completed(); // Release throttle slot
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "circuit_breaker",
            "hint": "Large withdrawals are rate-limited for security"
        })));
    }

    // Check balance (already fetched from_balance above)
    if from_balance < req.payload_fields.amount {
        state.throttler.transaction_completed(); // Release throttle slot
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: {} < {}", from_balance, req.payload_fields.amount),
            "localized_fee": localized_fee
        })));
    }

    // Execute transfer
    match state.blockchain.debit(&req.payload_fields.from, req.payload_fields.amount) {
        Ok(_) => {
            match state.blockchain.credit(&req.payload_fields.to, req.payload_fields.amount) {
                Ok(_) => {
                    info!(
                        "💸 Transfer: {} → {} : {} BB",
                        req.payload_fields.from,
                        req.payload_fields.to,
                        req.payload_fields.amount
                    );
                    
                    let from_new = state.blockchain.get_balance(&req.payload_fields.from);
                    let to_new = state.blockchain.get_balance(&req.payload_fields.to);
                    
                    // Log transaction to history with enhanced fields
                    let nonce_num: u64 = req.nonce.parse().unwrap_or(0);
                    let tx_record = storage::TransactionRecord::new(
                        storage::TxType::Transfer,
                        &req.payload_fields.from,
                        &req.payload_fields.to,
                        req.payload_fields.amount,
                        nonce_num,
                        from_balance,
                        from_new,
                        to_new,
                        storage::AuthType::MasterKey,
                    );
                    let tx_id = tx_record.tx_id.clone();
                    
                    if let Err(e) = state.blockchain.log_transaction(tx_record) {
                        warn!("Failed to log transaction: {}", e);
                    }
                    
                    // Release throttle slot on success
                    state.throttler.transaction_completed();
                    
                    (StatusCode::OK, Json(serde_json::json!({
                        "success": true,
                        "tx_id": tx_id,
                        "from": req.payload_fields.from,
                        "to": req.payload_fields.to,
                        "amount": req.payload_fields.amount,
                        "from_balance": from_new,
                        "to_balance": to_new,
                        "timestamp": req.timestamp,
                        "nonce": req.nonce,
                        "localized_fee": localized_fee,
                        "security_checks_passed": ["rate_limit", "circuit_breaker", "balance"]
                    })))
                }
                Err(e) => {
                    // Rollback debit
                    let _ = state.blockchain.credit(&req.payload_fields.from, req.payload_fields.amount);
                    state.throttler.transaction_completed(); // Release on failure too
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                        "success": false,
                        "error": format!("Failed to credit recipient: {}", e)
                    })))
                }
            }
        }
        Err(e) => {
            state.throttler.transaction_completed(); // Release on failure
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to debit sender: {}", e)
            })))
        }
    }
}

// ============================================================================
// CREDIT/BRIDGE HANDLERS (Unified via AssetManager)
// ============================================================================

#[derive(serde::Deserialize)]
struct OpenCreditRequest {
    wallet: String,
    amount: f64,
    session_id: Option<String>,
}

/// POST /credit/open - Reserve BB tokens for prediction market session
/// 
/// This implements token locking for prediction markets:
/// 1. Debit the amount from user's L1 balance (actual lock)
/// 2. Create a MarketSession tracking the locked BB tokens
/// 3. User can now trade on prediction markets with locked balance
/// Note: All operations use L1 BB tokens directly - no separate L2 token
async fn credit_open_handler(
    State(state): State<AppState>,
    Json(req): Json<OpenCreditRequest>,
) -> impl IntoResponse {
    // Check L1 balance
    let balance = state.blockchain.get_balance(&req.wallet);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Insufficient balance",
            "available": balance,
            "requested": req.amount
        })));
    }
    
    // CRITICAL: Actually lock the tokens by debiting from available balance
    // This ensures tokens can't be double-spent while trading on prediction markets
    if let Err(e) = state.blockchain.debit(&req.wallet, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to lock tokens: {}", e)
        })));
    }
    
    // Create market session via AssetManager
    let session_id = req.session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    match state.assets.open_market_session(&req.wallet, req.amount, &session_id) {
        Ok(session) => {
            info!(
                "🔒 BB tokens locked for prediction market: {} BB from {} (session: {})",
                req.amount, req.wallet, session.id
            );
            
            // Log the lock transaction with enhanced fields
            let new_balance = state.blockchain.get_balance(&req.wallet);
            let tx_record = storage::TransactionRecord::new(
                storage::TxType::Lock,
                &req.wallet,
                "MARKET_ESCROW",
                req.amount,
                0,
                new_balance + req.amount, // balance before lock
                new_balance,
                req.amount, // escrow balance after
                storage::AuthType::MasterKey,
            );
            let _ = state.blockchain.log_transaction(tx_record);
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "session_id": session.id,
                "wallet": req.wallet,
                "locked_amount": req.amount,
                "available_balance": session.available_balance,
                "l1_balance_after_lock": new_balance,
                "expires_at": session.expires_at
            })))
        },
        Err(e) => {
            // Rollback the debit if session creation fails
            let _ = state.blockchain.credit(&req.wallet, req.amount);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e
            })))
        }
    }
}

#[derive(serde::Deserialize)]
struct SettleCreditRequest {
    session_id: String,
    net_pnl: f64, // Positive = player won, Negative = player lost
}

/// POST /credit/settle - Settle prediction market session and apply P&L
/// 
/// This implements settlement of BB tokens:
/// 1. Get the locked amount from the session
/// 2. Calculate final balance: locked_amount + net_pnl
/// 3. Credit the final BB amount back to user's L1 balance
/// 4. Close the session
async fn credit_settle_handler(
    State(state): State<AppState>,
    Json(req): Json<SettleCreditRequest>,
) -> impl IntoResponse {
    match state.assets.settle_market_session(&req.session_id, req.net_pnl) {
        Ok(result) => {
            // Credit back the full final amount (locked + P&L)
            // The tokens were debited when session opened, now credit back what they deserve
            if let Some(wallet) = &result.wallet {
                let final_amount = result.locked_amount + req.net_pnl;
                
                if final_amount > 0.0 {
                    // Credit back whatever they're owed (original lock + winnings, or original lock - losses)
                    if let Err(e) = state.blockchain.credit(wallet, final_amount) {
                        error!("Failed to credit settlement: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                            "success": false,
                            "error": format!("Failed to credit settlement: {}", e)
                        })));
                    }
                    
                    info!(
                        "🔓 Settlement complete: {} BB returned to {} (locked: {}, pnl: {:+})",
                        final_amount, wallet, result.locked_amount, req.net_pnl
                    );
                    
                    // Log the settlement transaction with enhanced fields
                    let new_balance = state.blockchain.get_balance(wallet);
                    let tx_record = storage::TransactionRecord::new(
                        storage::TxType::Unlock,
                        "MARKET_ESCROW",
                        wallet,
                        final_amount,
                        0,
                        result.locked_amount, // escrow balance before
                        0.0, // escrow balance after
                        new_balance,
                        storage::AuthType::SystemInternal,
                    );
                    let _ = state.blockchain.log_transaction(tx_record);
                }
                // If final_amount <= 0, user lost everything (or more with credit), nothing to return
                
                let new_balance = state.blockchain.get_balance(wallet);
                
                (StatusCode::OK, Json(serde_json::json!({
                    "success": true,
                    "session_id": req.session_id,
                    "locked_amount": result.locked_amount,
                    "net_pnl": req.net_pnl,
                    "amount_returned": if final_amount > 0.0 { final_amount } else { 0.0 },
                    "l1_balance_after_settle": new_balance,
                    "settled_at": chrono::Utc::now().to_rfc3339()
                })))
            } else {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "success": false,
                    "error": "No wallet found for session"
                })))
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": e
        })))
    }
}

/// GET /credit/status/:wallet - Check credit session status
async fn credit_status_handler(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let l1_balance = state.blockchain.get_balance(&wallet);
    let session = state.assets.get_active_session(&wallet);
    
    Json(serde_json::json!({
        "wallet": wallet,
        "l1_balance": l1_balance,
        "has_active_session": session.is_some(),
        "session": session.map(|s| serde_json::json!({
            "id": s.id,
            "locked_amount": s.locked_amount,
            "available_balance": s.available_balance,
            "used_amount": s.used_amount,
            "expires_at": s.expires_at
        }))
    }))
}

// ============================================================================
// ADMIN HANDLERS (Feature-gated in production)
// ============================================================================

/// POST /bridge/initiate - Lock tokens for L1→L2 bridge transfer (with signature validation)
async fn bridge_initiate_handler(
    State(state): State<AppState>,
    Json(signed_req): Json<SignedRequest>,
) -> impl IntoResponse {
    // 🔐 VALIDATE SIGNATURE FIRST
    let wallet = match signed_req.verify() {
        Ok(w) => w,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "success": false,
                "error": format!("Signature validation failed: {}", e)
            })));
        }
    };

    // Parse payload to get amount and target_layer
    let payload_str = signed_req.payload.unwrap_or_else(|| "{}".to_string());
    let payload: serde_json::Value = match serde_json::from_str(&payload_str) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": format!("Invalid payload JSON: {}", e)
            })));
        }
    };

    let amount = match payload.get("amount").and_then(|v| v.as_f64()) {
        Some(a) if a > 0.0 => a,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid or missing amount in payload"
            })));
        }
    };

    let target = payload.get("target_layer")
        .and_then(|v| v.as_str())
        .unwrap_or("L2")
        .to_string();
    
    // Check L1 balance
    let balance = state.blockchain.get_balance(&wallet);
    if balance < amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Insufficient balance",
            "available": balance,
            "requested": amount
        })));
    }
    
    // Lock tokens (debit from spendable balance)
    if let Err(e) = state.blockchain.debit(&wallet, amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to lock tokens: {}", e)
        })));
    }
    
    // Create bridge lock record
    match state.assets.initiate_bridge(&wallet, amount, &target) {
        Ok(lock) => {
            info!("🌉 Bridge initiated: {} - {} BB from {} to {}", 
                lock.lock_id, amount, wallet, target);
            
            // 🔥 LOG BRIDGE TRANSACTION TO LEDGER with enhanced fields
            let balance_after = state.blockchain.get_balance(&wallet);
            let nonce_num: u64 = signed_req.nonce.parse().unwrap_or(0);
            let tx_record = TransactionRecord::new(
                storage::TxType::BridgeOut,
                &wallet,
                &format!("{}_ESCROW", target),
                amount,
                nonce_num,
                balance_after + amount, // balance before
                balance_after,
                amount, // escrow balance after
                storage::AuthType::MasterKey,
            );
            
            if let Err(e) = state.blockchain.log_transaction(tx_record) {
                warn!("Failed to log bridge transaction: {}", e);
            }
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "lock_id": lock.lock_id,
                "wallet": wallet,
                "amount": amount,
                "target_layer": target,
                "status": "pending",
                "expires_at": lock.expires_at,
                "message": "Tokens locked on L1. Awaiting L2 confirmation."
            })))
        }
        Err(e) => {
            // Refund if bridge creation failed
            let _ = state.blockchain.credit(&wallet, amount);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e
            })))
        }
    }
}

/// GET /bridge/status/:lock_id - Get bridge transfer status
async fn bridge_status_handler(
    State(state): State<AppState>,
    Path(lock_id): Path<String>,
) -> impl IntoResponse {
    match state.assets.get_bridge_lock(&lock_id) {
        Some(lock) => Json(serde_json::json!({
            "success": true,
            "lock_id": lock.lock_id,
            "wallet": lock.wallet,
            "amount": lock.amount,
            "target_layer": lock.target_layer,
            "status": format!("{:?}", lock.status),
            "created_at": lock.created_at,
            "expires_at": lock.expires_at,
            "l2_tx_hash": lock.l2_tx_hash
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "Bridge lock not found"
        }))
    }
}

/// GET /bridge/pending/:wallet - Get pending bridges for a wallet
async fn bridge_pending_handler(
    State(state): State<AppState>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let pending = state.assets.get_pending_bridges(&wallet);
    Json(serde_json::json!({
        "success": true,
        "wallet": wallet,
        "pending": pending.iter().map(|l| serde_json::json!({
            "lock_id": l.lock_id,
            "amount": l.amount,
            "target_layer": l.target_layer,
            "created_at": l.created_at,
            "expires_at": l.expires_at
        })).collect::<Vec<_>>(),
        "count": pending.len()
    }))
}

/// GET /bridge/stats - Get bridge statistics
async fn bridge_stats_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let stats = state.assets.bridge_stats();
    Json(serde_json::json!({
        "success": true,
        "stats": stats
    }))
}

// ============================================================================
// SOFT-LOCK HANDLERS (Seamless L1↔L2 Balance)
// ============================================================================

#[derive(serde::Deserialize)]
struct SoftLockRequest {
    wallet: String,
    amount: f64,
    reason: Option<String>,
    market_id: Option<String>,
    auto_release: Option<bool>,
}

/// POST /bridge/soft-lock - Soft-lock tokens for L2 position
/// 
/// Unlike bridge/initiate, this doesn't require L2 confirmation.
/// The tokens remain on L1 but are reserved for L2 use.
/// Auto-releases when position closes.
async fn soft_lock_handler(
    State(state): State<AppState>,
    Json(req): Json<SoftLockRequest>,
) -> impl IntoResponse {
    // Check balance
    let balance = state.blockchain.get_balance(&req.wallet);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Insufficient balance",
            "available": balance,
            "requested": req.amount
        })));
    }

    // Use bridge lock with auto_release flag
    let reason = req.reason.unwrap_or_else(|| "l2_position".to_string());
    
    // Lock the tokens (debit from available)
    if let Err(e) = state.blockchain.debit(&req.wallet, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to soft-lock: {}", e)
        })));
    }

    // Create lock record (can use existing bridge infrastructure)
    match state.assets.initiate_bridge(&req.wallet, req.amount, "L2_SOFT") {
        Ok(lock) => {
            info!("🔒 Soft-locked {} BB from {} for {}", req.amount, req.wallet, reason);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "lock_id": lock.lock_id,
                "wallet": req.wallet,
                "amount": req.amount,
                "reason": reason,
                "market_id": req.market_id,
                "auto_release": req.auto_release.unwrap_or(true),
                "status": "soft_locked",
                "message": "Tokens reserved for L2. Auto-releases when position closes."
            })))
        }
        Err(e) => {
            // Refund on failure
            let _ = state.blockchain.credit(&req.wallet, req.amount);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e
            })))
        }
    }
}

#[derive(serde::Deserialize)]
struct ReleaseRequest {
    lock_id: String,
    #[serde(default)]
    pnl: f64,  // Profit/Loss from L2 position
}

/// POST /bridge/release - Release soft-locked tokens back to wallet
/// 
/// Called when L2 position closes. Applies P&L and releases funds.
async fn bridge_release_handler(
    State(state): State<AppState>,
    Json(req): Json<ReleaseRequest>,
) -> impl IntoResponse {
    // Find the lock
    let lock = match state.assets.get_bridge_lock(&req.lock_id) {
        Some(l) => l,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "success": false,
            "error": "Lock not found"
        })))
    };

    // Calculate release amount (original + P&L)
    let release_amount = lock.amount + req.pnl;
    
    // Credit back to wallet (with P&L)
    if release_amount > 0.0 {
        if let Err(e) = state.blockchain.credit(&lock.wallet, release_amount) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to release: {}", e)
            })));
        }
    }

    // Mark lock as released
    if let Err(e) = state.assets.release_soft_lock(&req.lock_id) {
        // Non-critical - funds already released
        warn!("Failed to mark lock released: {}", e);
    }

    info!(
        "🔓 Released {} BB to {} (original: {}, pnl: {})",
        release_amount, lock.wallet, lock.amount, req.pnl
    );

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "lock_id": req.lock_id,
        "wallet": lock.wallet,
        "original_amount": lock.amount,
        "pnl": req.pnl,
        "released_amount": release_amount,
        "new_balance": state.blockchain.get_balance(&lock.wallet),
        "message": "Funds released back to L1 wallet"
    })))
}

/// GET /balance/:address/unified - Get unified balance (L1 + locked view)
/// 
/// Returns both available and locked balance for seamless L2 integration.
async fn unified_balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Get L1 balance
    let total_balance = state.blockchain.get_balance(&address);
    
    // Get pending locks (soft-locked for L2)
    let pending_bridges = state.assets.get_pending_bridges(&address);
    let soft_locked: f64 = pending_bridges.iter().map(|l| l.amount).sum();
    
    // Calculate available
    let available = total_balance; // Balance is already reduced by locks
    
    // Get active credit session if any
    let credit_session = state.assets.get_active_session(&address);
    let session_locked = credit_session.as_ref().map(|s| s.locked_amount).unwrap_or(0.0);
    
    Json(serde_json::json!({
        "address": address,
        "total": total_balance + soft_locked + session_locked,  // True total
        "available": available,  // Available for new operations
        "soft_locked": soft_locked,  // Locked for L2 positions
        "session_locked": session_locked,  // In active credit session
        "pending_locks": pending_bridges.len(),
        "unit": "BC",
        // For L2 - this is what user can spend on L2
        "l2_available": available,
        // Breakdown for UI
        "breakdown": {
            "wallet_balance": total_balance,
            "in_bridge": soft_locked,
            "in_credit_session": session_locked
        }
    }))
}

#[derive(serde::Deserialize)]
struct MintRequest {
    to: String,
    amount: f64,
}

/// POST /admin/mint - Mint tokens (dev mode enabled)
async fn admin_mint_handler(
    State(state): State<AppState>,
    Json(req): Json<MintRequest>,
) -> impl IntoResponse {
    match state.blockchain.credit(&req.to, req.amount) {
        Ok(_) => {
            info!("🪙 Minted {} BB to {}", req.amount, req.to);
            Json(serde_json::json!({
                "success": true,
                "minted": req.amount,
                "to": req.to,
                "new_balance": state.blockchain.get_balance(&req.to)
            }))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}

// ============================================================================
// BURN HANDLER (Secure)
// ============================================================================

#[derive(serde::Deserialize)]
struct BurnRequest {
    public_key: String,
    payload_hash: String,
    payload_fields: BurnPayload,
    operation_type: String,
    // schema_version: u8, // Optional/Unused
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    request_path: String,
    signature: String,
    #[serde(default)]
    security_pin: Option<String>, // Required for burns > 100,000 BB
}

#[derive(serde::Deserialize)]
struct BurnPayload {
    from: String,
    amount: f64,
    timestamp: u64,
    nonce: String,
}

/// POST /burn - Burn tokens (requires owner signature)
async fn admin_burn_handler(
    State(state): State<AppState>,
    Json(req): Json<BurnRequest>,
) -> impl IntoResponse {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Sha256, Digest};
    
    // Basic validation
    if req.operation_type != "burn" {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid operation type"
        })));
    }

    if req.payload_fields.from.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid from address"
        })));
    }

    if req.payload_fields.amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Amount must be positive"
        })));
    }

    // TIERED SECURITY: Require PIN for high-value burns (> 100,000 BB)
    if req.payload_fields.amount > HIGH_VALUE_THRESHOLD {
        match &req.security_pin {
            Some(pin) if pin == DEFAULT_SECURITY_PIN => {
                info!("🔐 High-value burn ({} BB) - PIN verified", req.payload_fields.amount);
            }
            Some(_) => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid security PIN for high-value burn",
                    "amount": req.payload_fields.amount,
                    "threshold": HIGH_VALUE_THRESHOLD
                })));
            }
            None => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "success": false,
                    "error": "Security PIN required for burns over 100,000 BB",
                    "amount": req.payload_fields.amount,
                    "threshold": HIGH_VALUE_THRESHOLD,
                    "hint": "Include security_pin in request body"
                })));
            }
        }
    }

    // Verify signature (Standard V2 SDK format)
    // 1. Recreate canonical payload hash
    // Canonical format: from|amount|timestamp|nonce
    let canonical = format!(
        "{}|{}|{}|{}",
        req.payload_fields.from,
        req.payload_fields.amount,
        req.payload_fields.timestamp,
        req.payload_fields.nonce
    );
    
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let payload_hash = format!("{:x}", hasher.finalize());
    
    // 2. Verify payload hash matches
    if payload_hash != req.payload_hash {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Payload hash mismatch"
        })));
    }
    
    // 3. Recreate signing message
    let domain_prefix = format!("BLACKBOOK_L{}{}", req.chain_id, req.request_path);
    let message = format!("{}\n{}\n{}\n{}", 
        domain_prefix, 
        req.payload_hash,
        req.timestamp,
        req.nonce
    );
    
    // 4. Verify Ed25519 signature
    let pubkey_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            })));
        }
    };
    
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature"
            })));
        }
    };
    
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": "Invalid public key format"
            })));
        }
    };
    
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    
    if verifying_key.verify(message.as_bytes(), &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Signature verification failed"
        })));
    }

    // Check balance
    let current_balance = state.blockchain.get_balance(&req.payload_fields.from);
    if current_balance < req.payload_fields.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance to burn: {} < {}", current_balance, req.payload_fields.amount)
        })));
    }

    // Execute burn
    match state.blockchain.debit(&req.payload_fields.from, req.payload_fields.amount) {
        Ok(_) => {
            info!(
                "🔥 BURN: {} burned {} BB",
                req.payload_fields.from,
                req.payload_fields.amount
            );
            
            let new_balance = state.blockchain.get_balance(&req.payload_fields.from);
            let balance_before = new_balance + req.payload_fields.amount;
            
            // Log transaction with enhanced fields
            let nonce_num: u64 = req.nonce.parse().unwrap_or(0);
            let tx_record = storage::TransactionRecord::new(
                storage::TxType::Burn,
                &req.payload_fields.from,
                "DESTROYED",
                req.payload_fields.amount,
                nonce_num,
                balance_before,
                new_balance,
                0.0, // destroyed tokens have no recipient
                storage::AuthType::MasterKey,
            );
            let tx_id = tx_record.tx_id.clone();
            
            if let Err(e) = state.blockchain.log_transaction(tx_record) {
                warn!("Failed to log burn transaction: {}", e);
            }
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "tx_id": tx_id,
                "from": req.payload_fields.from,
                "burned_amount": req.payload_fields.amount,
                "new_balance": new_balance,
                "timestamp": req.timestamp
            })))
        },
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to burn tokens: {}", e)
            })))
        }
    }
}

// ============================================================================
// SECURITY ADMIN HANDLERS - Ideal Hybrid Infrastructure Controls
// ============================================================================

/// GET /admin/security/stats - Comprehensive security infrastructure status
async fn security_stats_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let throttler_stats = state.throttler.get_stats();
    let circuit_breaker_stats = state.circuit_breaker.get_stats();
    let fee_market_stats = state.fee_market.get_stats();
    
    // Get tripped accounts (for monitoring)
    let tripped_count = state.account_metadata.iter()
        .filter(|entry| state.circuit_breaker.is_tripped(entry.key()))
        .count();
    
    Json(serde_json::json!({
        "success": true,
        "infrastructure": "Ideal Hybrid Stablecoin L1",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        
        "throttler": throttler_stats,
        "circuit_breaker": circuit_breaker_stats,
        "fee_market": fee_market_stats,
        
        "accounts": {
            "total_registered": state.account_metadata.len(),
            "tripped_by_circuit_breaker": tripped_count,
        },
        
        "security_features": {
            "stake_weighted_rate_limiting": true,
            "localized_fee_markets": true,
            "circuit_breakers": true,
            "type_safe_pdas": true,
            "declarative_account_validation": true
        },
        
        "vs_solana": {
            "transaction_ingest": "QUIC + Stake-Weighted (vs Unfiltered UDP)",
            "fee_structure": "Localized Fee Markets (vs Global Spikes)", 
            "account_safety": "Declarative Framework (vs Manual Verification)",
            "consensus_speed": "600ms Stable (vs 400ms Fragile)",
            "pda_system": "Type-safe Namespaced (vs Manual Seeds)"
        }
    }))
}

/// POST /admin/security/circuit-breaker/reset/:account - Reset a tripped circuit breaker
async fn circuit_breaker_reset_handler(
    State(state): State<AppState>,
    Path(account): Path<String>,
) -> impl IntoResponse {
    if state.circuit_breaker.is_tripped(&account) {
        state.circuit_breaker.admin_reset(&account);
        Json(serde_json::json!({
            "success": true,
            "account": account,
            "action": "circuit_breaker_reset",
            "message": "Circuit breaker reset, account can transact normally"
        }))
    } else {
        Json(serde_json::json!({
            "success": false,
            "account": account,
            "error": "Account is not currently tripped"
        }))
    }
}

/// POST /admin/security/circuit-breaker/exempt/:account - Exempt account from circuit breaker
async fn circuit_breaker_exempt_handler(
    State(state): State<AppState>,
    Path(account): Path<String>,
) -> impl IntoResponse {
    state.circuit_breaker.add_exemption(&account);
    Json(serde_json::json!({
        "success": true,
        "account": account,
        "action": "circuit_breaker_exempt",
        "message": "Account exempted from circuit breaker limits (use for treasury/bridge)"
    }))
}

/// POST /admin/security/throttler/halt - Emergency halt all transactions
async fn throttler_halt_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    state.throttler.emergency_halt();
    warn!("🚨 EMERGENCY HALT activated via admin endpoint");
    Json(serde_json::json!({
        "success": true,
        "action": "emergency_halt",
        "message": "All transactions halted. Use /admin/security/throttler/resume to restore."
    }))
}

/// POST /admin/security/throttler/resume - Resume from emergency halt
async fn throttler_resume_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    state.throttler.resume();
    info!("✅ Emergency halt lifted via admin endpoint");
    Json(serde_json::json!({
        "success": true,
        "action": "resume",
        "message": "Transaction processing resumed"
    }))
}

/// GET /admin/security/pda/:address - Get PDA info for an account
async fn pda_info_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    if let Some(metadata) = state.account_metadata.get(&address) {
        Json(serde_json::json!({
            "success": true,
            "address": address,
            "account_type": format!("{:?}", metadata.account_type),
            "owner": metadata.owner,
            "created_at": metadata.created_at,
            "frozen": metadata.frozen,
            "pda_info": metadata.pda_info.as_ref().map(|p| serde_json::json!({
                "namespace": p.namespace,
                "index": p.index,
                "bump": p.bump
            })),
            "is_circuit_breaker_tripped": state.circuit_breaker.is_tripped(&address)
        }))
    } else {
        // Try to derive PDA info even if not registered
        let derived = ProgramDerivedAddress::derive(
            AccountType::UserWallet,
            &address,
            None,
        );
        let pda_info = derived.ok().map(|d| serde_json::json!({
            "address": d.address,
            "bump": d.bump
        }));
        Json(serde_json::json!({
            "success": false,
            "address": address,
            "error": "Account not registered in metadata store",
            "hint": "Create account via /auth/keypair to auto-register",
            "derived_pda": pda_info
        }))
    }
}


// Insecure admin burn handler removed in favor of secure implementation upstream


// ============================================================================
// POH BLOCKCHAIN HANDLERS - Production-Ready Block Operations
// ============================================================================

/// GET /poh/block/latest - Get the latest produced block
async fn poh_latest_block_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.block_producer.get_latest_block() {
        Some(block) => Json(serde_json::json!({
            "success": true,
            "block": {
                "slot": block.slot,
                "timestamp": block.timestamp,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "state_root": block.state_root,
                "poh_hash": block.poh_hash,
                "poh_sequence": block.poh_sequence,
                "tx_count": block.tx_count,
                "leader": block.leader,
                "epoch": block.epoch,
                "confirmations": block.confirmations,
                "finality_status": format!("{:?}", block.confirmation_status())
            }
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "No blocks produced yet"
        }))
    }
}

/// GET /poh/block/:slot - Get block by slot number
async fn poh_block_by_slot_handler(
    State(state): State<AppState>,
    Path(slot): Path<u64>,
) -> impl IntoResponse {
    match state.block_producer.get_block(slot) {
        Some(block) => Json(serde_json::json!({
            "success": true,
            "block": {
                "slot": block.slot,
                "timestamp": block.timestamp,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "state_root": block.state_root,
                "poh_hash": block.poh_hash,
                "poh_sequence": block.poh_sequence,
                "tx_count": block.tx_count,
                "leader": block.leader,
                "epoch": block.epoch,
                "confirmations": block.confirmations,
                "transactions": block.transactions.iter().map(|tx| {
                    serde_json::json!({
                        "hash": tx.tx.hash,
                        "from": tx.tx.from,
                        "timestamp": tx.tx.timestamp,
                        "poh_hash": tx.poh_hash,
                        "poh_sequence": tx.poh_sequence,
                        "position": tx.position
                    })
                }).collect::<Vec<_>>()
            }
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": format!("Block at slot {} not found", slot)
        }))
    }
}

/// GET /poh/block/verify/:slot - Verify block integrity
async fn poh_verify_block_handler(
    State(state): State<AppState>,
    Path(slot): Path<u64>,
) -> impl IntoResponse {
    let block = match state.block_producer.get_block(slot) {
        Some(b) => b,
        None => return Json(serde_json::json!({
            "success": false,
            "error": format!("Block at slot {} not found", slot)
        }))
    };
    
    // Get previous block for hash verification
    let previous_hash = if slot > 0 {
        state.block_producer.get_block(slot - 1)
            .map(|b| b.hash)
            .unwrap_or_else(|| "0".repeat(64))
    } else {
        "0".repeat(64)
    };
    
    let is_valid = verify_block(&block, &previous_hash);
    
    Json(serde_json::json!({
        "success": true,
        "slot": slot,
        "is_valid": is_valid,
        "checks": {
            "hash_chain": block.previous_hash == previous_hash,
            "hash_computed": FinalizedBlock::compute_hash(
                block.slot,
                &block.previous_hash,
                &block.state_root,
                &block.poh_hash,
                block.timestamp,
            ) == block.hash,
            "tx_count_match": block.transactions.len() == block.tx_count as usize
        }
    }))
}

/// GET /poh/chain/verify - Verify entire chain integrity
async fn poh_verify_chain_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let block_count = state.block_producer.block_count();
    
    // Collect all blocks for verification
    let mut blocks = Vec::new();
    for slot in 0..block_count as u64 {
        if let Some(block) = state.block_producer.get_block(slot) {
            blocks.push(block);
        }
    }
    
    let is_valid = verify_chain(&blocks);
    
    Json(serde_json::json!({
        "success": true,
        "chain_valid": is_valid,
        "block_count": block_count,
        "latest_slot": blocks.last().map(|b| b.slot).unwrap_or(0),
        "latest_hash": blocks.last().map(|b| b.hash.clone()).unwrap_or_default()
    }))
}

/// GET /poh/chain/stats - Get chain statistics
async fn poh_chain_stats_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let block_count = state.block_producer.block_count();
    let pending_txs = state.block_producer.pending_tx_count();
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    
    let poh_stats = {
        let poh = state.poh.read();
        serde_json::json!({
            "num_hashes": poh.num_hashes,
            "current_hash": poh.current_hash.chars().take(16).collect::<String>(),
            "current_slot": poh.current_slot,
            "current_epoch": poh.current_epoch,
            "entries_in_slot": poh.current_entries.len()
        })
    };
    
    Json(serde_json::json!({
        "success": true,
        "blocks": {
            "produced": block_count,
            "pending_txs": pending_txs
        },
        "consensus": {
            "current_slot": current_slot,
            "confirmations_required": CONFIRMATIONS_REQUIRED
        },
        "poh": poh_stats
    }))
}

/// GET /poh/tx/:tx_id/status - Get transaction finality status
async fn poh_tx_status_handler(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> impl IntoResponse {
    let status = state.finality_tracker.get_status(&tx_id);
    let is_finalized = state.finality_tracker.is_finalized(&tx_id);
    
    Json(serde_json::json!({
        "success": true,
        "tx_id": tx_id,
        "status": format!("{:?}", status),
        "is_finalized": is_finalized,
        "confirmations_required": CONFIRMATIONS_REQUIRED
    }))
}

/// GET /poh/proof/:address - Generate merkle state proof for address
async fn poh_state_proof_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let balance = state.blockchain.get_balance(&address);
    
    match state.block_producer.generate_account_proof(&address) {
        Some(proof) => Json(serde_json::json!({
            "success": true,
            "address": address,
            "balance": balance,
            "proof": {
                "leaf_index": proof.leaf_index,
                "root": proof.root,
                "path_length": proof.proof.len(),
                "proof_nodes": proof.proof.iter().map(|n| {
                    serde_json::json!({
                        "hash": n.hash,
                        "is_left": n.is_left
                    })
                }).collect::<Vec<_>>()
            },
            "verification": "proof.verify(address, balance) should return true"
        })),
        None => {
            // Generate a standalone merkle proof from current state
            let mut accounts = std::collections::BTreeMap::new();
            accounts.insert(address.clone(), balance);
            let tree = MerkleTree::from_accounts(&accounts);
            
            Json(serde_json::json!({
                "success": true,
                "address": address,
                "balance": balance,
                "state_root": tree.root_hex(),
                "note": "Single-account proof generated"
            }))
        }
    }
}

/// POST /poh/produce - Produce a new block (admin/validator endpoint)
async fn poh_produce_block_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Check if we are the leader
    if !state.block_producer.is_current_leader() {
        let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
        let leader = {
            let schedule = state.leader_schedule.read();
            schedule.get_leader(current_slot)
        };
        
        return Json(serde_json::json!({
            "success": false,
            "error": "Not the current leader",
            "current_slot": current_slot,
            "expected_leader": leader
        }));
    }
    
    match state.block_producer.produce_block() {
        Ok(block) => {
            // Update finality tracker for all transactions in block
            for tx in &block.transactions {
                state.finality_tracker.record_inclusion(&tx.tx.hash, block.slot);
            }
            state.finality_tracker.update_confirmations(block.slot);
            
            Json(serde_json::json!({
                "success": true,
                "block": {
                    "slot": block.slot,
                    "hash": block.hash,
                    "state_root": block.state_root,
                    "poh_hash": block.poh_hash,
                    "tx_count": block.tx_count,
                    "timestamp": block.timestamp
                }
            }))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}

/// GET /poh/leader/current - Get current leader info
async fn poh_current_leader_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let schedule = state.leader_schedule.read();
    
    let leader = schedule.get_leader(current_slot);
    let next_leader = schedule.get_leader(current_slot + 1);
    
    let is_our_slot = state.block_producer.is_current_leader();
    
    Json(serde_json::json!({
        "success": true,
        "current_slot": current_slot,
        "current_leader": leader,
        "next_leader": next_leader,
        "is_our_slot": is_our_slot,
        "epoch": schedule.epoch
    }))
}

/// GET /poh/leader/schedule - Get leader schedule
async fn poh_leader_schedule_handler(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let count = params.get("count")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10);
    
    let current_slot = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let schedule = state.leader_schedule.read();
    
    let upcoming: Vec<_> = (0..count)
        .map(|i| {
            let slot = current_slot + i;
            serde_json::json!({
                "slot": slot,
                "leader": schedule.get_leader(slot)
            })
        })
        .collect();
    
    // Get validator addresses
    let validators: Vec<_> = schedule.validator_stakes.keys().cloned().collect();
    
    Json(serde_json::json!({
        "success": true,
        "current_slot": current_slot,
        "upcoming_leaders": upcoming,
        "validators": validators
    }))
}

// ============================================================================
// ROUTER BUILDERS
// ============================================================================

fn build_public_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/balance/:address", get(balance_handler))
        .route("/balance/:address/unified", get(unified_balance_handler))
        .route("/poh/status", get(poh_status_handler))
        .route("/performance/stats", get(performance_stats_handler))
        .route("/transactions", get(transactions_handler))
        .route("/ledger", get(ledger_handler))
        .route("/transfer", post(transfer_handler))
        .route("/transfer/simple", post(simple_transfer_handler))
}

fn build_sealevel_routes() -> Router<AppState> {
    Router::new()
        .route("/submit", post(gulf_stream_submit_handler))
        .route("/batch", post(sealevel_batch_handler))  // NEW: High-throughput batch submission
        .route("/stats", get(sealevel_stats_handler))
        .route("/pending/:leader", get(sealevel_pending_handler))
}

fn build_auth_routes() -> Router<AppState> {
    // Legacy ZKP routes removed - migrated to S+ Tier unified_wallet module
    // New endpoints: /wallet/register/*, /wallet/login/*, /wallet/sign/*
    // See: src/unified_wallet/handlers.rs
    Router::new()
}

fn build_credit_routes() -> Router<AppState> {
    Router::new()
        .route("/open", post(credit_open_handler))
        .route("/settle", post(credit_settle_handler))
        .route("/status/:wallet", get(credit_status_handler))
}

fn build_bridge_routes() -> Router<AppState> {
    Router::new()
        .route("/initiate", post(bridge_initiate_handler))
        .route("/status/:lock_id", get(bridge_status_handler))
        .route("/pending/:wallet", get(bridge_pending_handler))
        .route("/stats", get(bridge_stats_handler))
        // Soft-lock routes for seamless L2 access
        .route("/soft-lock", post(soft_lock_handler))
        .route("/release", post(bridge_release_handler))
}

fn build_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/mint", post(admin_mint_handler))
        .route("/burn", post(admin_burn_handler))
        // Security admin endpoints (Ideal Hybrid Infrastructure)
        .route("/security/stats", get(security_stats_handler))
        .route("/security/circuit-breaker/reset/:account", post(circuit_breaker_reset_handler))
        .route("/security/circuit-breaker/exempt/:account", post(circuit_breaker_exempt_handler))
        .route("/security/throttler/halt", post(throttler_halt_handler))
        .route("/security/throttler/resume", post(throttler_resume_handler))
        .route("/security/pda/:address", get(pda_info_handler))
}

fn build_poh_blockchain_routes() -> Router<AppState> {
    Router::new()
        // Block queries
        .route("/block/latest", get(poh_latest_block_handler))
        .route("/block/:slot", get(poh_block_by_slot_handler))
        .route("/block/verify/:slot", get(poh_verify_block_handler))
        
        // Chain verification
        .route("/chain/verify", get(poh_verify_chain_handler))
        .route("/chain/stats", get(poh_chain_stats_handler))
        
        // Transaction finality
        .route("/tx/:tx_id/status", get(poh_tx_status_handler))
        
        // State proofs
        .route("/proof/:address", get(poh_state_proof_handler))
        
        // Block production (admin/validator)
        .route("/produce", post(poh_produce_block_handler))
        
        // Leader schedule
        .route("/leader/current", get(poh_current_leader_handler))
        .route("/leader/schedule", get(poh_leader_schedule_handler))
}

// ============================================================================
// INITIALIZATION HELPERS
// ============================================================================

fn load_blockchain() -> ConcurrentBlockchain {
    info!("🗄️  Initializing ReDB storage at {}", REDB_DATA_PATH);
    
    match ConcurrentBlockchain::new(REDB_DATA_PATH) {
        Ok(bc) => {
            info!("✅ ConcurrentBlockchain initialized (lock-free reads enabled)");
            display_balances(&bc);
            bc
        }
        Err(e) => {
            error!("❌ FATAL: Failed to initialize storage: {:?}", e);
            panic!("Storage initialization failed: {:?}", e);
        }
    }
}

fn display_balances(bc: &ConcurrentBlockchain) {
    let alice_bal = bc.get_balance(ALICE_L1);
    let bob_bal = bc.get_balance(BOB_L1);
    let dealer_bal = bc.get_balance(DEALER_L1);
    let total = bc.total_supply();
    
    info!("📊 Account Balances (1:1 USDC Backed):");
    info!("   💵 Total Supply: {:>12.2} BB", total);
    info!("   👛 Alice:        {:>12.2} BB", alice_bal);
    info!("   👛 Bob:          {:>12.2} BB", bob_bal);
    info!("   🎰 Dealer:       {:>12.2} BB", dealer_bal);
    
    if alice_bal == 0.0 && bob_bal == 0.0 {
        info!("   ⚠️  Test accounts have 0 balance. Use POST /admin/mint to fund.");
    }
}

fn load_social_system() -> SocialMiningSystem {
    if let Ok(data) = fs::read_to_string(SOCIAL_DATA_FILE) {
        if let Ok(system) = serde_json::from_str(&data) {
            info!("📂 Loaded social mining from {}", SOCIAL_DATA_FILE);
            return system;
        }
    }
    info!("🆕 Creating new social mining system");
    SocialMiningSystem::new()
}

fn save_social_system(social_system: &SocialMiningSystem) {
    if let Ok(data) = serde_json::to_string_pretty(social_system) {
        let _ = fs::write(SOCIAL_DATA_FILE, data);
    }
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    warn!("🛑 Shutdown signal received. Saving state...");
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() {
    // ========================================================================
    // 1. INITIALIZE STRUCTURED LOGGING (tracing)
    // ========================================================================
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,layer1=debug")))
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true))
        .init();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║    BLACKBOOK L1 V3 - Production Core (Axum + ReDB)            ║");
    info!("╠═══════════════════════════════════════════════════════════════╣");
    info!("║  Framework: Axum 0.7 (no recursion limits)                    ║");
    info!("║  Storage:   ReDB + Borsh (ACID, MVCC, zero-copy)              ║");
    info!("║  Concurrency: DashMap cache (lock-free reads)                 ║");
    info!("║  Auth:      Ed25519 Signatures (NO JWT!)                      ║");
    info!("║  PoH:       Continuous Proof of History Clock                 ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    // ========================================================================
    // 2. INITIALIZE PROOF OF HISTORY (PoH) SERVICE
    // ========================================================================
    // IDEAL HYBRID: 600ms slots for stability (vs Solana's fragile 400ms)
    // This gives us ~1.67 slots/second with better network tolerance
    let poh_config = PoHConfig {
        slot_duration_ms: 600,       // 600ms = stable+fast (vs Solana's 400ms)
        hashes_per_tick: 12500,      // ~12.5k SHA256 hashes per tick
        ticks_per_slot: 64,          // 64 ticks per slot
        slots_per_epoch: 432000,     // ~3 days at 600ms slots
    };
    let poh_service: SharedPoHService = create_poh_service(poh_config);
    
    let poh_runner = poh_service.clone();
    tokio::spawn(async move {
        run_poh_clock(poh_runner).await;
    });
    info!("🎟️  PoH clock started");

    // ========================================================================
    // 3. INITIALIZE CONCURRENT BLOCKCHAIN (NO MUTEX!)
    // ========================================================================
    let blockchain = load_blockchain();
    
    // ========================================================================
    // 4. INITIALIZE ASSET MANAGER (Unified L2 Integration)
    // ========================================================================
    let assets = AssetManager::new();
    info!("💰 AssetManager initialized (unified bridge + credit)");

    // ========================================================================
    // 5. INITIALIZE SUPPORTING SERVICES
    // ========================================================================
    let current_slot = Arc::new(AtomicU64::new(0));
    
    let leader_schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = leader_schedule.write();
        schedule.update_stake("genesis_validator", 1000.0);
        schedule.generate_schedule(0, 432000);
    }

    let (pipeline, commit_rx) = TransactionPipeline::new();
    pipeline.start(current_slot.clone());
    info!("🔄 Transaction Pipeline started");

    // ========================================================================
    // 5B. INITIALIZE SEALEVEL-STYLE PARALLEL EXECUTION
    // ========================================================================
    let parallel_scheduler = Arc::new(ParallelScheduler::new());
    info!("⚡ ParallelScheduler initialized (Sealevel-style execution)");
    
    // ========================================================================
    // 5C. INITIALIZE GULF STREAM SERVICE
    // ========================================================================
    let gulf_stream = GulfStreamService::new(
        leader_schedule.clone(),
        current_slot.clone(),
    );
    gulf_stream.start();
    info!("🌊 GulfStream service started (transaction forwarding)");

    let social_system = Arc::new(TokioMutex::new(load_social_system()));

    // ========================================================================
    // 5D. INITIALIZE POH-INTEGRATED BLOCK PRODUCER
    // ========================================================================
    let block_producer = Arc::new(BlockProducer::new(
        blockchain.clone(),
        poh_service.clone(),
        leader_schedule.clone(),
        current_slot.clone(),
        "genesis_validator".to_string(),
    ));
    info!("🏭 BlockProducer initialized (PoH-integrated block production)");

    let finality_tracker = Arc::new(FinalityTracker::new(current_slot.clone()));
    info!("✅ FinalityTracker initialized (confirmation tracking)");

    // ========================================================================
    // 5F. IDEAL HYBRID SECURITY INFRASTRUCTURE
    // ========================================================================
    // These systems make BlackBook L1 immune to Solana's vulnerabilities:
    // - Spam attacks: Stake-weighted throttling (not unfiltered UDP)
    // - Bank runs: Circuit breakers (automatic slowdown on large outflows)
    // - Fee spikes: Localized fee markets (spam only affects spammer)
    // - Account confusion: Type-safe PDAs (namespace + owner + bump)
    
    let throttler = Arc::new(NetworkThrottler::new());
    info!("🛡️ NetworkThrottler initialized (stake-weighted rate limiting)");
    
    let circuit_breaker = Arc::new(CircuitBreaker::new());
    // Exempt system accounts from circuit breakers
    circuit_breaker.add_exemption("genesis");
    circuit_breaker.add_exemption("mining_reward");
    circuit_breaker.add_exemption("social_mining");
    circuit_breaker.add_exemption("system");
    info!("🔌 CircuitBreaker initialized (bank run protection)");
    
    let fee_market = Arc::new(LocalizedFeeMarket::new());
    info!("💰 LocalizedFeeMarket initialized (per-group fees, no global spikes)");
    
    let account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>> = Arc::new(dashmap::DashMap::new());
    info!("🔐 AccountMetadata initialized (type-safe PDA accounts)");

    // ========================================================================
    // 5G. SEALEVEL EXECUTION LOOP - WIRE UP PARALLEL PROCESSING
    // ========================================================================
    // This is the critical integration that makes ParallelScheduler actually execute!
    // It consumes from Gulf Stream and executes batches in parallel.
    let sealevel_blockchain = blockchain.clone();
    let sealevel_scheduler = parallel_scheduler.clone();
    let sealevel_gulf_stream = gulf_stream.clone();
    let sealevel_leader_schedule = leader_schedule.clone();
    let sealevel_current_slot = current_slot.clone();
    let sealevel_finality = finality_tracker.clone();
    let sealevel_poh = poh_service.clone();
    
    tokio::spawn(async move {
        info!("⚡ Sealevel execution loop started - processing Gulf Stream transactions");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100)); // 10x per slot
        
        loop {
            interval.tick().await;
            
            // Get current leader for this slot
            let slot = sealevel_current_slot.load(std::sync::atomic::Ordering::Relaxed);
            let leader = {
                let schedule = sealevel_leader_schedule.read();
                schedule.get_leader(slot)
            };
            
            // Pull pending transactions from Gulf Stream for this leader
            let pending = sealevel_gulf_stream.get_pending_by_priority(&leader, 64); // Batch of 64
            
            if pending.is_empty() {
                continue;
            }
            
            // Convert to runtime transactions and schedule into non-conflicting batches
            let batches = sealevel_scheduler.schedule_with_locks(pending);
            
            if batches.is_empty() {
                continue;
            }
            
            // Execute each batch in parallel using Sealevel-style execution
            for batch in batches {
                let batch_size = batch.len();
                
                // Execute with fine-grained account locks
                let results = sealevel_scheduler.execute_batch_with_locks(
                    batch.clone(),
                    &sealevel_blockchain.cache,
                );
                
                // Process results and update blockchain state
                let mut success_count = 0;
                let mut fail_count = 0;
                
                for (i, result) in results.iter().enumerate() {
                    if result.success {
                        let tx = &batch[i];
                        
                        // Persist to ReDB (DashMap already updated by execute_batch_with_locks)
                        if let Err(e) = sealevel_blockchain.transfer(&tx.from, &tx.to, tx.amount) {
                            warn!("Sealevel persist failed: {}", e);
                            fail_count += 1;
                        } else {
                            // Mix transaction into PoH for ordering proof
                            {
                                let mut poh = sealevel_poh.write();
                                poh.queue_transaction(tx.id.clone());
                            }
                            
                            // Track for finality (record_inclusion is the correct method)
                            sealevel_finality.record_inclusion(&tx.id, slot);
                            success_count += 1;
                        }
                    } else {
                        fail_count += 1;
                    }
                }
                
                if success_count > 0 || fail_count > 0 {
                    info!(
                        "⚡ Sealevel batch executed: {} txs ({} success, {} failed) @ slot {}",
                        batch_size, success_count, fail_count, slot
                    );
                }
            }
            
            // Clear processed transactions from Gulf Stream
            sealevel_gulf_stream.clear_leader_cache(&leader);
            
            // Tune batch size based on conflict rate
            sealevel_scheduler.tune_batch_size();
        }
    });
    info!("⚡ Sealevel execution loop WIRED (parallel batch processing active)");

    // ========================================================================
    // 6. BUILD S+ TIER WALLET SYSTEM (FROST + OPAQUE)
    // ========================================================================
    let frost_dkg = Arc::new(FrostDKG::new());
    let threshold_signer = Arc::new(ThresholdSigner::new());
    let opaque_auth = Arc::new(OpaqueAuth::new());
    let shard_storage = Arc::new(ShardStorage::new());
    
    let wallet_handlers = Arc::new(WalletHandlers::new(
        frost_dkg,
        threshold_signer,
        opaque_auth,
        shard_storage,
    ));
    info!("🔐 S+ Tier Wallet System initialized (FROST TSS + OPAQUE PAKE)");

    // ========================================================================
    // 7. BUILD APPLICATION STATE
    // ========================================================================
    let state = AppState {
        blockchain,
        assets,
        social: social_system.clone(),
        poh: poh_service.clone(),
        current_slot: current_slot.clone(),
        leader_schedule: leader_schedule.clone(),
        pipeline,
        parallel_scheduler,
        gulf_stream,
        block_producer,
        finality_tracker,
        // Ideal Hybrid Security Infrastructure
        throttler,
        circuit_breaker,
        fee_market,
        account_metadata,
        // S+ Tier Wallet System
        wallet_handlers: wallet_handlers.clone(),
    };

    // ========================================================================
    // 7. BUILD AXUM ROUTER
    // ========================================================================
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build wallet routers with separate states
    let wallet_router = WalletHandlers::router()
        .with_state((*wallet_handlers).clone());
    
    let mnemonic_router = MnemonicHandlers::router()
        .with_state(MnemonicHandlers::new());
    
    // Build the main router with AppState
    let app = Router::new()
        // Public routes at root
        .merge(build_public_routes())
        // S+ Tier Wallet System (FROST - Institutional Track)
        .merge(wallet_router)
        // Mnemonic Wallet System (Consumer Track)
        .merge(mnemonic_router)
        // Legacy routes (auth routes migrated to /wallet/*)
        .nest("/auth", build_auth_routes())
        .nest("/credit", build_credit_routes())
        .nest("/bridge", build_bridge_routes())
        .nest("/admin", build_admin_routes())
        .nest("/sealevel", build_sealevel_routes())
        .nest("/poh", build_poh_blockchain_routes())
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        // Shared state
        .with_state(state.clone());

    // ========================================================================
    // 8. START GRPC SERVER (L1 ↔ L2 Internal Communication)
    // ========================================================================
    let grpc_blockchain = Arc::new(state.blockchain.clone());
    let grpc_assets = Arc::new(state.assets.clone());
    let grpc_pipeline = state.pipeline.clone();
    tokio::spawn(async move {
        let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
        info!("🌐 gRPC server starting on {}", addr);
        if let Err(e) = grpc::start_grpc_server_with_pipeline(grpc_blockchain, grpc_assets, grpc_pipeline, addr).await {
            error!("❌ gRPC server error: {}", e);
        }
    });

    // ========================================================================
    // 9. START BACKGROUND TASKS
    // ========================================================================
    
    // Periodic flush (ReDB auto-commits, but we sync social data)
    let social_save = social_system.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let data = social_save.lock().await.clone();
            save_social_system(&data);
            info!("💾 Social data saved");
        }
    });

    // Lock expiration cleanup task (runs every 5 minutes)
    let cleanup_blockchain = state.blockchain.clone();
    let cleanup_assets = state.assets.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            
            // Get expired locks and credit back to users
            let expired = cleanup_assets.cleanup_expired_locks();
            if !expired.is_empty() {
                info!("🧹 Lock cleanup: {} expired locks found", expired.len());
                for (wallet, amount) in expired {
                    if let Err(e) = cleanup_blockchain.credit(&wallet, amount) {
                        error!("Failed to credit expired lock to {}: {}", wallet, e);
                    } else {
                        info!("✅ Returned {} BB to {} from expired lock", amount, wallet);
                    }
                }
            }
        }
    });

    // ========================================================================
    // 11. START HTTP SERVER
    // ========================================================================
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!("🚀 Server listening on http://{}", addr);
    info!("");
    info!("🔐 S+ TIER WALLET ENDPOINTS (FROST + OPAQUE MPC - Institutional Track):");
    info!("   POST /wallet/register/start  - Start DKG + OPAQUE registration");
    info!("   POST /wallet/register/round1 - Exchange DKG round 1");
    info!("   POST /wallet/register/round2 - Exchange DKG round 2");
    info!("   POST /wallet/register/finish - Finalize wallet creation");
    info!("   POST /wallet/login/start     - Start OPAQUE authentication");
    info!("   POST /wallet/login/finish    - Complete login, get session");
    info!("   POST /wallet/sign/start      - Begin threshold signing");
    info!("   POST /wallet/sign/commitment - Exchange commitments");
    info!("   POST /wallet/sign/finish     - Aggregate signatures");
    info!("   GET  /wallet/info/:address   - Wallet public info");
    info!("   GET  /wallet/health          - Wallet system health");
    info!("");
    info!("🌱 MNEMONIC WALLET ENDPOINTS (Consumer Track - 24-Word BIP-39):");
    info!("   POST /mnemonic/create        - Create wallet (Shamir 2-of-3)");
    info!("   POST /mnemonic/sign          - Sign transaction");
    info!("   POST /mnemonic/recover       - Recover from 24 words");
    info!("   POST /mnemonic/export/:addr  - Export mnemonic (requires 2FA)");
    info!("   POST /mnemonic/share-b       - Store Share B on-chain");
    info!("   GET  /mnemonic/share-b/:addr - Get Share B (ZKP-gated)");
    info!("   GET  /mnemonic/info/:addr    - Wallet metadata");
    info!("   GET  /mnemonic/health        - Health check");
    info!("");
    info!("📡 CORE ENDPOINTS:");
    info!("   GET  /health              - Health check");
    info!("   GET  /stats               - Blockchain + Sealevel stats");
    info!("   GET  /balance/:address    - Public balance lookup");
    info!("   GET  /poh/status          - PoH clock status");
    info!("   GET  /performance/stats   - All service statistics");
    info!("   POST /transfer            - Transfer (V2 SDK format)");
    info!("   POST /transfer/simple     - Transfer (simple frontend format)");
    info!("   POST /credit/open         - Open credit session");
    info!("   POST /credit/settle       - Settle session");
    info!("   GET  /credit/status/:wallet - Session status");
    info!("   POST /bridge/initiate     - Start L1→L2 bridge");
    info!("   POST /bridge/soft-lock    - Create soft-lock for L2");
    info!("   POST /bridge/release      - Release soft-lock");
    info!("   GET  /bridge/stats        - Bridge statistics");
    info!("   POST /admin/mint          - Mint tokens (dev only)");
    info!("");
    info!("⚡ SEALEVEL ENDPOINTS (Solana-style):");
    info!("   POST /sealevel/submit     - Submit tx to Gulf Stream");
    info!("   GET  /sealevel/stats      - Parallel execution stats");
    info!("   GET  /sealevel/pending/:leader - Pending txs for leader");
    info!("");
    info!("🌐 gRPC: 0.0.0.0:50051 (L1↔L2 settlement)");
    info!("");
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    
    // Final cleanup
    let social_data = social_system.lock().await.clone();
    save_social_system(&social_data);
    info!("⚔️  You have chosen the path of the Jedi Knight");
}
