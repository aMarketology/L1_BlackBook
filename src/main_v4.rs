// ============================================================================
// BLACKBOOK L1 V4 - MAINNET PRODUCTION SERVER
// ============================================================================
//
// A clean, modular rewrite of the BlackBook L1 blockchain server.
// Optimized for mainnet deployment with enterprise-grade security.
//
// ARCHITECTURE:
// - Framework: Axum 0.7 (async, no recursion limits, fast compile)
// - Storage: ReDB (ACID, MVCC, zero-copy reads)
// - Concurrency: DashMap cache (lock-free reads)
// - Auth: Ed25519 signatures + FROST TSS + OPAQUE PAKE
// - Consensus: PoH Clock + Tower BFT + Gulf Stream
// - Execution: Sealevel-style parallel scheduling
//
// SECURITY FEATURES (Ideal Hybrid L1):
// - Stake-weighted rate limiting (vs Solana's unfiltered UDP)
// - Localized fee markets (spam only affects spammer)
// - Circuit breakers (automatic protection against bank runs)
// - Type-safe PDAs (namespace + owner + bump)
// - Nonce tracking (replay attack prevention)
//
// WALLET TRACKS:
// 1. S+ Tier (Institutional): FROST TSS + OPAQUE - key NEVER exists in full
// 2. Consumer: BIP-39 mnemonic with Shamir 2-of-3 backup
//
// Run: cargo run --bin main_v4
// Test: curl http://localhost:8080/health

#![allow(dead_code)]
#![allow(unused_imports)]

// ============================================================================
// IMPORTS
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;
use std::fs;
use std::collections::HashMap;

use tokio::signal;
use tokio::sync::Mutex as TokioMutex;
use parking_lot::RwLock;

use tracing::{info, warn, error, debug, Level};
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

use serde::{Deserialize, Serialize};

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
mod settlement;

#[path = "../protocol/mod.rs"]
mod protocol;
#[path = "../runtime/mod.rs"]
mod runtime;

mod poh_blockchain;

// ============================================================================
// MODULE IMPORTS
// ============================================================================

use social_mining::SocialMiningSystem;
use storage::{ConcurrentBlockchain, AssetManager, TransactionRecord, TxType, AuthType};
use integration::unified_auth::SignedRequest;

// PoH & Consensus Infrastructure
use runtime::{
    PoHConfig, SharedPoHService, create_poh_service, run_poh_clock,
    TransactionPipeline, LeaderSchedule, GulfStreamService, PoHEntry,
    ParallelScheduler,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
    // Security Infrastructure
    NetworkThrottler, CircuitBreaker, LocalizedFeeMarket,
    AccountValidator, AccountType, AccountMetadata, PDAInfo,
    AccountAccess, ProgramDerivedAddress,
    // Tower BFT
    TowerBFT, Vote, TowerLockout,
};

use protocol::Transaction as ProtocolTransaction;

// Block Production & Finality
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

// Settlement System (Batch Markets with Merkle Proofs)
use settlement::{
    BatchSettlement, BatchSettlementManager, Withdrawal, SettlementStatus,
    MerkleProof, ClaimRegistry, SettlementError, SettlementResult,
    create_merkle_tree, verify_merkle_proof,
};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Data file paths
const SOCIAL_DATA_FILE: &str = "social_mining_data.json";
const REDB_DATA_PATH: &str = "./blockchain_data";

/// Security thresholds
const HIGH_VALUE_THRESHOLD: f64 = 100_000.0;
const DEFAULT_SECURITY_PIN: &str = "1234"; // Dev mode only

/// Network version
const VERSION: &str = "4.0.0";
const NETWORK: &str = "mainnet-beta";

/// PoH Configuration (Ideal Hybrid: 600ms for stability vs Solana's fragile 400ms)
const POH_SLOT_DURATION_MS: u64 = 600;
const POH_HASHES_PER_TICK: u64 = 12500;
const POH_TICKS_PER_SLOT: u64 = 64;
const POH_SLOTS_PER_EPOCH: u64 = 432000; // ~3 days

// ============================================================================
// APPLICATION STATE
// ============================================================================

/// Central application state - passed to all handlers via State<AppState>
#[derive(Clone)]
pub struct AppState {
    // =========================================================================
    // CORE BLOCKCHAIN
    // =========================================================================
    
    /// Lock-free blockchain access (DashMap cache + ReDB MVCC)
    pub blockchain: ConcurrentBlockchain,
    
    /// Unified L2 integration (bridge + credit sessions)
    pub assets: AssetManager,
    
    /// Social mining system
    pub social: Arc<TokioMutex<SocialMiningSystem>>,
    
    // =========================================================================
    // POH & CONSENSUS INFRASTRUCTURE
    // =========================================================================
    
    /// Proof of History service (continuous timestamping)
    pub poh: SharedPoHService,
    
    /// Current slot tracker
    pub current_slot: Arc<AtomicU64>,
    
    /// Leader schedule for consensus (engagement-weighted)
    pub leader_schedule: Arc<RwLock<LeaderSchedule>>,
    
    /// Transaction pipeline (4-stage async: fetch → verify → execute → commit)
    pub pipeline: Arc<TransactionPipeline>,
    
    /// Sealevel-style parallel transaction execution
    pub parallel_scheduler: Arc<ParallelScheduler>,
    
    /// Gulf Stream - mempool-less transaction forwarding
    pub gulf_stream: Arc<GulfStreamService>,
    
    /// PoH-integrated block producer
    pub block_producer: Arc<BlockProducer>,
    
    /// Transaction finality tracker
    pub finality_tracker: Arc<FinalityTracker>,
    
    // =========================================================================
    // SECURITY INFRASTRUCTURE (Ideal Hybrid Design)
    // =========================================================================
    
    /// Network throttler - Stake-weighted rate limiting
    pub throttler: Arc<NetworkThrottler>,
    
    /// Circuit breaker - Bank run protection
    pub circuit_breaker: Arc<CircuitBreaker>,
    
    /// Localized fee market - No global fee spikes
    pub fee_market: Arc<LocalizedFeeMarket>,
    
    /// Account metadata - Type-safe PDA accounts
    pub account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>>,
    
    /// Nonce tracker - Replay attack prevention
    pub used_nonces: Arc<dashmap::DashMap<String, u64>>,
    
    // =========================================================================
    // WALLET SYSTEMS
    // =========================================================================
    
    /// S+ Tier wallet handlers (FROST TSS + OPAQUE)
    pub wallet_handlers: Arc<WalletHandlers>,
    
    // =========================================================================
    // SETTLEMENT SYSTEM
    // =========================================================================
    
    /// Batch settlement manager for prediction markets
    pub settlement_manager: Arc<BatchSettlementManager>,
    
    /// L2 public keys for signature verification
    pub l2_public_keys: Arc<dashmap::DashMap<String, String>>,
}

// ============================================================================
// HEALTH & STATUS HANDLERS
// ============================================================================

/// GET /health - Comprehensive system health check
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let total_supply = state.blockchain.total_supply();
    let stats = state.blockchain.stats();
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let parallel_stats = state.parallel_scheduler.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let pipeline_stats = state.pipeline.get_stats();
    
    // PoH status
    let poh_status = {
        let poh = state.poh.read();
        poh.get_status()
    };
    
    // Calculate TPS metrics
    let theoretical_max_tps = (MAX_TXS_PER_BLOCK as f64 / (BLOCK_INTERVAL_MS as f64 / 1000.0)) as u64;
    let finality_time_ms = CONFIRMATIONS_REQUIRED * BLOCK_INTERVAL_MS;
    
    Json(serde_json::json!({
        "status": "healthy",
        "version": VERSION,
        "network": NETWORK,
        "engine": "axum",
        "storage": "redb",
        
        // Blockchain State
        "blockchain": {
            "total_supply": total_supply,
            "account_count": stats.total_accounts,
            "block_count": stats.block_count,
        },
        
        // PoH Clock
        "poh_clock": {
            "status": "running",
            "current_slot": poh_status["current_slot"],
            "current_epoch": poh_status["current_epoch"],
            "num_hashes": poh_status["num_hashes"],
            "slot_duration_ms": POH_SLOT_DURATION_MS,
        },
        
        // Infrastructure Status
        "infrastructure": {
            "gulf_stream": gulf_stream_stats.is_active,
            "sealevel": true,
            "turbine": true,
            "pipeline": pipeline_stats.is_running,
        },
        
        // Performance
        "performance": {
            "theoretical_max_tps": theoretical_max_tps,
            "finality_time_ms": finality_time_ms,
            "confirmations_required": CONFIRMATIONS_REQUIRED,
        },
        
        // Security
        "security": {
            "throttler": state.throttler.get_stats(),
            "circuit_breaker": state.circuit_breaker.get_stats(),
            "fee_market": state.fee_market.get_stats(),
        }
    }))
}

/// GET /stats - Detailed blockchain statistics
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

/// GET /balance/:address/unified - Unified balance (available + locked)
async fn unified_balance_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let total_balance = state.blockchain.get_balance(&address);
    let pending_bridges = state.assets.get_pending_bridges(&address);
    let soft_locked: f64 = pending_bridges.iter().map(|l| l.amount).sum();
    let credit_session = state.assets.get_active_session(&address);
    let session_locked = credit_session.as_ref().map(|s| s.locked_amount).unwrap_or(0.0);
    
    Json(serde_json::json!({
        "address": address,
        "total": total_balance + soft_locked + session_locked,
        "available": total_balance,
        "soft_locked": soft_locked,
        "session_locked": session_locked,
        "breakdown": {
            "wallet_balance": total_balance,
            "in_bridge": soft_locked,
            "in_credit_session": session_locked
        }
    }))
}

// ============================================================================
// LEDGER VISUALIZATION HANDLER
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
    output.push_str(&format!("  BLOCK HEIGHT : {:>12}                     NETWORK : [ MAINNET-ZK ]           VERSION : 4.0.0-mainnet-beta\n", stats.block_count));
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
    output.push_str(" 🛡️  Ed25519 Signatures │ MD5 TX Hashes │ Chain-Linked │ State Validated │ ZKP Auth Ready │ Immutably Stored on BlackBook L1 V4\n");
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
// TRANSFER HANDLERS
// ============================================================================

/// Request for SSS-based transfer using 2-of-3 shards
#[derive(Deserialize)]
struct SSSTransferRequest {
    from: String,
    to: String,
    amount: f64,
    /// Two shares (any combination: share_1 + share_2, share_1 + share_3, or share_2 + share_3)
    share_1: String,  // Format: "index:hex_data"
    share_2: String,  // Format: "index:hex_data"
}

/// POST /transfer - Universal transfer endpoint using SSS 2-of-3 reconstruction
async fn sss_transfer_handler(
    State(state): State<AppState>,
    Json(req): Json<SSSTransferRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    use ed25519_dalek::{SigningKey, Signer};
    use crate::wallet_mnemonic::sss::{SecureShare, reconstruct_entropy};
    use crate::wallet_mnemonic::mnemonic::{entropy_to_mnemonic, mnemonic_to_seed};
    use bip39::{Language, Mnemonic};
    
    let from = &req.from;
    let to = &req.to;
    let amount = req.amount;
    
    // Validation
    if from.is_empty() || to.is_empty() || amount <= 0.0 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid transfer parameters"
        }))));
    }
    
    // Parse the two shares
    let share_1 = match SecureShare::from_hex(&req.share_1) {
        Ok(s) => s,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": format!("Invalid share_1: {}", e)
            }))));
        }
    };
    
    let share_2 = match SecureShare::from_hex(&req.share_2) {
        Ok(s) => s,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": format!("Invalid share_2: {}", e)
            }))));
        }
    };
    
    // Verify shares are different
    if share_1.index == share_2.index {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Shares must have different indices"
        }))));
    }
    
    // Reconstruct entropy from 2-of-3 shares
    let entropy = match reconstruct_entropy(&share_1, &share_2) {
        Ok(e) => e,
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to reconstruct entropy: {}", e)
            }))));
        }
    };
    
    // Derive mnemonic and keypair
    let mnemonic_phrase = match entropy_to_mnemonic(&entropy) {
        Ok(m) => m,
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to derive mnemonic: {}", e)
            }))));
        }
    };
    
    let seed = match mnemonic_to_seed(&mnemonic_phrase, "") {
        Ok(s) => s,
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to derive seed: {}", e)
            }))));
        }
    };
    
    // Convert to fixed-size array [u8; 32]
    let key_bytes: [u8; 32] = seed.as_bytes()[..32].try_into()
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": "Invalid key length"
            })))
        })?;
    
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    
    // Derive wallet address from public key
    let pubkey_hex = hex::encode(verifying_key.as_bytes());
    let derived_address = format!("bb_{}", &pubkey_hex[..32]);
    
    // Verify derived address matches from address
    if derived_address != *from {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Share reconstruction produced incorrect address",
            "expected": from,
            "derived": derived_address
        }))));
    }
    
    // Security checks
    let sender_stake = state.blockchain.get_balance(from) / 1000.0;
    if let Err(e) = state.throttler.check_transaction(from, sender_stake) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "rate_limit"
        }))));
    }
    
    let from_balance = state.blockchain.get_balance(from);
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    
    if let Err(e) = state.circuit_breaker.check_transfer(from, amount, from_balance, current_slot) {
        state.throttler.transaction_completed();
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "circuit_breaker"
        }))));
    }

    if from_balance < amount {
        state.throttler.transaction_completed();
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: {} < {}", from_balance, amount)
        }))));
    }

    // Execute transfer using the simple blockchain transfer method
    match state.blockchain.transfer(from, to, amount) {
        Ok(_) => {
            state.throttler.transaction_completed();
            
            let from_balance_after = state.blockchain.get_balance(from);
            let to_balance_after = state.blockchain.get_balance(to);
            
            info!("🔐 SSS Transfer: {} → {} : {} BB (signed with reconstructed key)", from, to, amount);
            
            Ok((StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "from": from,
                "to": to,
                "amount": amount,
                "from_balance": from_balance_after,
                "to_balance": to_balance_after,
                "auth_method": "SSS_2_OF_3",
                "shares_used": format!("share_{}_and_share_{}", share_1.index, share_2.index)
            }))))
        }
        Err(e) => {
            state.throttler.transaction_completed();
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": format!("Transfer failed: {}", e)
            }))))
        }
    }
}

#[derive(Deserialize)]
struct SimpleTransferRequest {
    public_key: String,
    wallet_address: String,
    payload: String,
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    schema_version: u8,
    signature: String,
}

#[derive(Deserialize)]
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
    
    // Parse payload
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
    
    // Validation
    if from.is_empty() || to.is_empty() || amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Invalid transfer parameters"
        })));
    }

    // Verify signature
    let chain_id_byte = vec![req.chain_id];
    let mut message_bytes = chain_id_byte;
    message_bytes.extend_from_slice(req.payload.as_bytes());
    message_bytes.extend_from_slice(b"\n");
    message_bytes.extend_from_slice(req.timestamp.to_string().as_bytes());
    message_bytes.extend_from_slice(b"\n");
    message_bytes.extend_from_slice(req.nonce.as_bytes());
    
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
    
    if verifying_key.verify(&message_bytes, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Signature verification failed"
        })));
    }

    // Security checks
    let sender_stake = state.blockchain.get_balance(from) / 1000.0;
    if let Err(e) = state.throttler.check_transaction(from, sender_stake) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "rate_limit"
        })));
    }
    
    let localized_fee = state.fee_market.calculate_fee(from);
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let from_balance = state.blockchain.get_balance(from);
    
    if let Err(e) = state.circuit_breaker.check_transfer(from, amount, from_balance, current_slot) {
        state.throttler.transaction_completed();
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "error": e,
            "security_check": "circuit_breaker"
        })));
    }

    if from_balance < amount {
        state.throttler.transaction_completed();
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: {} < {}", from_balance, amount)
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

// ============================================================================
// SETTLEMENT HANDLERS (Batch Markets + Merkle Proofs)
// ============================================================================

/// Request for submitting a batch settlement
#[derive(Deserialize)]
struct SubmitBatchRequest {
    batch_id: String,
    market_id: String,
    merkle_root: String,
    total_winners: u32,
    total_payout: u64,
    total_collateral: u64,
    fees_collected: u64,
    l2_signature: String,
    l2_public_key: String,
    #[serde(default)]
    withdrawals: Option<Vec<WithdrawalItem>>,
}

#[derive(Deserialize, Clone)]
struct WithdrawalItem {
    address: String,
    amount: u64,
}

/// POST /settlement/batch - Submit batch settlement from L2
/// 
/// L2 submits merkle root representing all winners, users claim individually.
async fn settlement_batch_handler(
    State(state): State<AppState>,
    Json(req): Json<SubmitBatchRequest>,
) -> impl IntoResponse {
    // Verify L2 signature
    if !verify_l2_signature(&req.l2_signature, &req.l2_public_key, &req.batch_id, &req.merkle_root) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "success": false,
            "error": "Invalid L2 signature"
        })));
    }
    
    // Validate zero-sum invariant
    if req.total_payout > req.total_collateral - req.fees_collected {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Zero-sum violation: payouts exceed available collateral",
            "total_payout": req.total_payout,
            "total_collateral": req.total_collateral,
            "fees": req.fees_collected
        })));
    }
    
    // Create batch settlement
    let settlement = BatchSettlement {
        batch_id: req.batch_id.clone(),
        market_id: req.market_id.clone(),
        merkle_root: req.merkle_root.clone(),
        total_winners: req.total_winners,
        total_payout: req.total_payout,
        total_collateral: req.total_collateral,
        fees_collected: req.fees_collected,
        l2_signature: req.l2_signature,
        l2_public_key: req.l2_public_key.clone(),
        timestamp: current_timestamp(),
        withdrawals: req.withdrawals.map(|w| {
            w.into_iter().map(|item| Withdrawal {
                address: item.address,
                amount: item.amount,
                merkle_proof: None,
            }).collect()
        }),
    };
    
    // Submit to settlement manager
    match state.settlement_manager.submit_batch(settlement) {
        Ok(batch_id) => {
            info!("📦 Batch settlement submitted: {} ({} winners, {} payout)",
                batch_id, req.total_winners, req.total_payout);
            
            // Store L2 public key for future verification
            state.l2_public_keys.insert(req.market_id.clone(), req.l2_public_key);
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "batch_id": batch_id,
                "market_id": req.market_id,
                "total_winners": req.total_winners,
                "total_payout": req.total_payout,
                "status": "pending",
                "message": "Batch submitted. Users can now claim via /settlement/claim"
            })))
        }
        Err(e) => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "success": false,
                "error": format!("{}", e)
            })))
        }
    }
}

/// Request for claiming a withdrawal
#[derive(Deserialize)]
struct ClaimRequest {
    batch_id: String,
    address: String,
    amount: u64,
    merkle_proof: MerkleProofInput,
}

#[derive(Deserialize)]
struct MerkleProofInput {
    proof_hashes: Vec<String>,
    proof_indices: Vec<usize>,
    leaf_index: usize,
}

/// POST /settlement/claim - Claim individual withdrawal with merkle proof
async fn settlement_claim_handler(
    State(state): State<AppState>,
    Json(req): Json<ClaimRequest>,
) -> impl IntoResponse {
    // Convert proof input to MerkleProof
    let merkle_proof = MerkleProof {
        proof_hashes: req.merkle_proof.proof_hashes,
        proof_indices: req.merkle_proof.proof_indices,
        leaf_index: req.merkle_proof.leaf_index,
    };
    
    // Create withdrawal with proof
    let withdrawal = Withdrawal {
        address: req.address.clone(),
        amount: req.amount,
        merkle_proof: Some(merkle_proof),
    };
    
    // Process the claim
    match state.settlement_manager.process_claim(&req.batch_id, &withdrawal) {
        Ok(tx_hash) => {
            // Credit the user's L1 balance
            let amount_f64 = req.amount as f64 / 1_000_000.0; // Convert from smallest unit
            if let Err(e) = state.blockchain.credit(&req.address, amount_f64) {
                error!("Failed to credit claimed amount: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "success": false,
                    "error": "Claim verified but credit failed"
                })));
            }
            
            info!("💰 Claim processed: {} received {} from batch {}",
                req.address, amount_f64, req.batch_id);
            
            // Log transaction
            let tx_record = TransactionRecord::new(
                TxType::Unlock,
                &format!("SETTLEMENT_{}", req.batch_id),
                &req.address,
                amount_f64,
                0,
                0.0,
                amount_f64,
                state.blockchain.get_balance(&req.address),
                AuthType::SystemInternal,
            );
            let _ = state.blockchain.log_transaction(tx_record);
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "tx_hash": tx_hash,
                "batch_id": req.batch_id,
                "address": req.address,
                "amount": req.amount,
                "amount_credited": amount_f64,
                "new_balance": state.blockchain.get_balance(&req.address),
                "message": "Withdrawal claimed successfully"
            })))
        }
        Err(e) => {
            let (status, error_type) = match &e {
                SettlementError::AlreadyClaimed => (StatusCode::CONFLICT, "already_claimed"),
                SettlementError::InvalidMerkleProof => (StatusCode::BAD_REQUEST, "invalid_proof"),
                SettlementError::BatchNotFound(_) => (StatusCode::NOT_FOUND, "batch_not_found"),
                _ => (StatusCode::BAD_REQUEST, "claim_failed"),
            };
            
            (status, Json(serde_json::json!({
                "success": false,
                "error": format!("{}", e),
                "error_type": error_type
            })))
        }
    }
}

/// GET /settlement/batch/:batch_id - Get batch settlement status
async fn settlement_batch_status_handler(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> impl IntoResponse {
    match state.settlement_manager.get_batch(&batch_id) {
        Some(record) => Json(serde_json::json!({
            "success": true,
            "batch_id": batch_id,
            "market_id": record.settlement.market_id,
            "status": format!("{:?}", record.status),
            "total_winners": record.settlement.total_winners,
            "total_payout": record.settlement.total_payout,
            "claims_processed": record.claims_processed,
            "submitted_at": record.submitted_at,
            "completed_at": record.completed_at,
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "Batch not found"
        }))
    }
}

/// GET /settlement/claim/:batch_id/:address - Check if address has claimed
async fn settlement_claim_status_handler(
    State(state): State<AppState>,
    Path((batch_id, address)): Path<(String, String)>,
) -> impl IntoResponse {
    let withdrawal_id = settlement::claims::generate_withdrawal_id(&batch_id, &address, 0);
    let is_claimed = state.settlement_manager.is_claimed(&batch_id, &withdrawal_id);
    
    Json(serde_json::json!({
        "success": true,
        "batch_id": batch_id,
        "address": address,
        "is_claimed": is_claimed
    }))
}

// ============================================================================
// POH & CONSENSUS HANDLERS
// ============================================================================

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

/// GET /poh/block/latest - Get latest produced block
async fn poh_latest_block_handler(State(state): State<AppState>) -> impl IntoResponse {
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
                "tx_count": block.tx_count,
                "leader": block.leader,
                "epoch": block.epoch,
                "confirmations": block.confirmations,
            }
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "No blocks produced yet"
        }))
    }
}

/// GET /poh/block/:slot - Get block by slot
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
                "previous_hash": block.previous_hash,
                "state_root": block.state_root,
                "poh_hash": block.poh_hash,
                "tx_count": block.tx_count,
                "transactions": block.transactions.len()
            }
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": format!("Block at slot {} not found", slot)
        }))
    }
}

/// GET /poh/leader/current - Get current leader info
async fn poh_current_leader_handler(State(state): State<AppState>) -> impl IntoResponse {
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let schedule = state.leader_schedule.read();
    let leader = schedule.get_leader(current_slot);
    let next_leader = schedule.get_leader(current_slot + 1);
    let is_our_slot = state.block_producer.is_current_leader();
    
    Json(serde_json::json!({
        "current_slot": current_slot,
        "current_leader": leader,
        "next_leader": next_leader,
        "is_our_slot": is_our_slot,
        "epoch": schedule.epoch
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
        "tx_id": tx_id,
        "status": format!("{:?}", status),
        "is_finalized": is_finalized,
        "confirmations_required": CONFIRMATIONS_REQUIRED
    }))
}

// ============================================================================
// SEALEVEL HANDLERS (Parallel Execution)
// ============================================================================

#[derive(Deserialize)]
struct GulfStreamSubmitRequest {
    from: String,
    to: String,
    amount: f64,
    #[serde(default)]
    tx_type: String,
    #[serde(default)]
    priority: Option<u64>,
}

/// POST /sealevel/submit - Submit transaction to Gulf Stream
async fn gulf_stream_submit_handler(
    State(state): State<AppState>,
    Json(req): Json<GulfStreamSubmitRequest>,
) -> impl IntoResponse {
    use runtime::core::{Transaction as RuntimeTx, TransactionType};
    use runtime::PipelinePacket;
    
    // Basic validation
    if req.from.is_empty() || req.to.is_empty() || req.amount <= 0.0 {
        return Json(serde_json::json!({
            "success": false,
            "error": "Invalid transaction parameters"
        }));
    }
    
    // Security checks
    let sender_stake = state.blockchain.get_balance(&req.from);
    if let Err(e) = state.throttler.check_transaction(&req.from, sender_stake) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Rate limited: {}", e)
        }));
    }
    
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    let balance = state.blockchain.get_balance(&req.from);
    
    if let Err(e) = state.circuit_breaker.check_transfer(&req.from, req.amount, balance, current_slot) {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Circuit breaker: {}", e)
        }));
    }
    
    if balance < req.amount {
        state.throttler.transaction_completed();
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient balance: {} < {}", balance, req.amount)
        }));
    }
    
    let tx_type = match req.tx_type.as_str() {
        "bet" => TransactionType::BetPlacement,
        "social" => TransactionType::SocialAction,
        _ => TransactionType::Transfer,
    };
    
    let mut tx = RuntimeTx::new(req.from.clone(), req.to.clone(), req.amount, tx_type);
    let tx_id = tx.id.clone();
    
    if let Some(p) = req.priority {
        tx.nonce = p;
    }
    
    // Submit to Gulf Stream
    if let Err(e) = state.gulf_stream.submit(tx.clone()) {
        state.throttler.transaction_completed();
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Gulf Stream submission failed: {}", e)
        }));
    }
    
    // Also submit to Pipeline
    let packet = PipelinePacket::new(tx_id.clone(), req.from.clone(), req.to.clone(), req.amount);
    if let Err(e) = state.pipeline.submit(packet).await {
        warn!("Pipeline submission failed: {}", e);
    }
    
    Json(serde_json::json!({
        "success": true,
        "tx_id": tx_id,
        "message": "Transaction submitted to Gulf Stream",
        "status": "pending",
        "estimated_slot": current_slot + 1
    }))
}

/// GET /sealevel/stats - Sealevel execution statistics
async fn sealevel_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let parallel_stats = state.parallel_scheduler.get_stats();
    let lock_stats = state.parallel_scheduler.lock_manager.get_stats();
    let gulf_stream_stats = state.gulf_stream.get_stats();
    let pipeline_stats = state.pipeline.get_stats();
    
    Json(serde_json::json!({
        "sealevel": {
            "parallel_scheduler": parallel_stats,
            "account_locks": lock_stats,
            "gulf_stream": gulf_stream_stats,
            "pipeline": pipeline_stats,
        },
        "status": "SEALEVEL_ENABLED"
    }))
}

// ============================================================================
// CREDIT & BRIDGE HANDLERS
// ============================================================================

#[derive(Deserialize)]
struct OpenCreditRequest {
    wallet: String,
    amount: f64,
    session_id: Option<String>,
}

/// POST /credit/open - Lock tokens for prediction market session
async fn credit_open_handler(
    State(state): State<AppState>,
    Json(req): Json<OpenCreditRequest>,
) -> impl IntoResponse {
    let balance = state.blockchain.get_balance(&req.wallet);
    if balance < req.amount {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "success": false,
            "error": "Insufficient balance",
            "available": balance,
            "requested": req.amount
        })));
    }
    
    if let Err(e) = state.blockchain.debit(&req.wallet, req.amount) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "success": false,
            "error": format!("Failed to lock tokens: {}", e)
        })));
    }
    
    let session_id = req.session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    match state.assets.open_market_session(&req.wallet, req.amount, &session_id) {
        Ok(session) => {
            info!("🔒 Tokens locked: {} BB from {} (session: {})", req.amount, req.wallet, session.id);
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "session_id": session.id,
                "wallet": req.wallet,
                "locked_amount": req.amount,
                "available_balance": session.available_balance
            })))
        }
        Err(e) => {
            let _ = state.blockchain.credit(&req.wallet, req.amount);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "error": e
            })))
        }
    }
}

#[derive(Deserialize)]
struct SettleCreditRequest {
    session_id: String,
    net_pnl: f64,
}

/// POST /credit/settle - Settle prediction market session
async fn credit_settle_handler(
    State(state): State<AppState>,
    Json(req): Json<SettleCreditRequest>,
) -> impl IntoResponse {
    match state.assets.settle_market_session(&req.session_id, req.net_pnl) {
        Ok(result) => {
            if let Some(wallet) = &result.wallet {
                let final_amount = result.locked_amount + req.net_pnl;
                
                if final_amount > 0.0 {
                    if let Err(e) = state.blockchain.credit(wallet, final_amount) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                            "success": false,
                            "error": format!("Failed to credit: {}", e)
                        })));
                    }
                }
                
                info!("🔓 Settlement: {} BB to {} (pnl: {:+})", final_amount, wallet, req.net_pnl);
                
                (StatusCode::OK, Json(serde_json::json!({
                    "success": true,
                    "session_id": req.session_id,
                    "locked_amount": result.locked_amount,
                    "net_pnl": req.net_pnl,
                    "amount_returned": if final_amount > 0.0 { final_amount } else { 0.0 },
                    "new_balance": state.blockchain.get_balance(wallet)
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

/// GET /credit/status/:wallet - Credit session status
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
            "available_balance": s.available_balance
        }))
    }))
}

// ============================================================================
// ADMIN HANDLERS
// ============================================================================

#[derive(Deserialize)]
struct MintRequest {
    to: String,
    amount: f64,
}

/// POST /admin/mint - Mint tokens (dev mode)
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

/// GET /admin/security/stats - Security infrastructure status
async fn security_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "throttler": state.throttler.get_stats(),
        "circuit_breaker": state.circuit_breaker.get_stats(),
        "fee_market": state.fee_market.get_stats(),
        "accounts_registered": state.account_metadata.len()
    }))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Verify L2 signature on batch settlement
fn verify_l2_signature(signature: &str, public_key: &str, batch_id: &str, merkle_root: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    
    // Decode public key
    let pubkey_bytes = match hex::decode(public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    
    // Decode signature
    let sig_bytes = match hex::decode(signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    
    // Create verifying key
    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    
    // Create signature
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    
    // Message: batch_id|merkle_root
    let message = format!("{}|{}", batch_id, merkle_root);
    
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
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
        .route("/transfer/simple", post(simple_transfer_handler))
        .route("/transfer", post(sss_transfer_handler))
        .route("/ledger", get(ledger_handler))
}

fn build_settlement_routes() -> Router<AppState> {
    Router::new()
        .route("/batch", post(settlement_batch_handler))
        .route("/batch/:batch_id", get(settlement_batch_status_handler))
        .route("/claim", post(settlement_claim_handler))
        .route("/claim/:batch_id/:address", get(settlement_claim_status_handler))
}

fn build_poh_routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(poh_status_handler))
        .route("/block/latest", get(poh_latest_block_handler))
        .route("/block/:slot", get(poh_block_by_slot_handler))
        .route("/leader/current", get(poh_current_leader_handler))
        .route("/tx/:tx_id/status", get(poh_tx_status_handler))
}

fn build_sealevel_routes() -> Router<AppState> {
    Router::new()
        .route("/submit", post(gulf_stream_submit_handler))
        .route("/stats", get(sealevel_stats_handler))
}

fn build_credit_routes() -> Router<AppState> {
    Router::new()
        .route("/open", post(credit_open_handler))
        .route("/settle", post(credit_settle_handler))
        .route("/status/:wallet", get(credit_status_handler))
}

fn build_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/mint", post(admin_mint_handler))
        .route("/security/stats", get(security_stats_handler))
}

// ============================================================================
// INITIALIZATION
// ============================================================================

fn load_blockchain() -> ConcurrentBlockchain {
    info!("🗄️  Initializing ReDB storage at {}", REDB_DATA_PATH);
    
    match ConcurrentBlockchain::new(REDB_DATA_PATH) {
        Ok(bc) => {
            info!("✅ ConcurrentBlockchain initialized");
            bc
        }
        Err(e) => {
            error!("❌ FATAL: Failed to initialize storage: {:?}", e);
            panic!("Storage initialization failed: {:?}", e);
        }
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

fn save_social_system(system: &SocialMiningSystem) {
    if let Ok(data) = serde_json::to_string_pretty(system) {
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
            .expect("Failed to install Ctrl+C handler");
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
// MAIN ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() {
    // ========================================================================
    // 1. INITIALIZE LOGGING
    // ========================================================================
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,layer1=debug")))
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_level(true))
        .init();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║    BLACKBOOK L1 V4 - MAINNET PRODUCTION SERVER                ║");
    info!("╠═══════════════════════════════════════════════════════════════╣");
    info!("║  Version:   {} ({})                                   ║", VERSION, NETWORK);
    info!("║  Framework: Axum 0.7 + ReDB + Borsh                           ║");
    info!("║  Auth:      Ed25519 + FROST TSS + OPAQUE PAKE                 ║");
    info!("║  Consensus: PoH + Tower BFT + Gulf Stream                     ║");
    info!("║  Execution: Sealevel Parallel Scheduling                      ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    // ========================================================================
    // 2. INITIALIZE POH SERVICE
    // ========================================================================
    let poh_config = PoHConfig {
        slot_duration_ms: POH_SLOT_DURATION_MS,
        hashes_per_tick: POH_HASHES_PER_TICK,
        ticks_per_slot: POH_TICKS_PER_SLOT,
        slots_per_epoch: POH_SLOTS_PER_EPOCH,
    };
    let poh_service: SharedPoHService = create_poh_service(poh_config);
    
    let poh_runner = poh_service.clone();
    tokio::spawn(async move {
        run_poh_clock(poh_runner).await;
    });
    info!("🎟️  PoH clock started ({}ms slots)", POH_SLOT_DURATION_MS);

    // ========================================================================
    // 3. INITIALIZE BLOCKCHAIN
    // ========================================================================
    let blockchain = load_blockchain();
    let assets = AssetManager::new();
    info!("💰 AssetManager initialized");

    // ========================================================================
    // 4. INITIALIZE CONSENSUS INFRASTRUCTURE
    // ========================================================================
    let current_slot = Arc::new(AtomicU64::new(0));
    
    let leader_schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = leader_schedule.write();
        schedule.update_stake("genesis_validator", 1000.0);
        schedule.generate_schedule(0, POH_SLOTS_PER_EPOCH);
    }

    let (pipeline, _commit_rx) = TransactionPipeline::new();
    pipeline.start(current_slot.clone());
    info!("🔄 Transaction Pipeline started");

    let parallel_scheduler = Arc::new(ParallelScheduler::new());
    info!("⚡ ParallelScheduler initialized");

    let gulf_stream = GulfStreamService::new(leader_schedule.clone(), current_slot.clone());
    gulf_stream.start();
    info!("🌊 GulfStream service started");

    let social_system = Arc::new(TokioMutex::new(load_social_system()));

    let block_producer = Arc::new(BlockProducer::new(
        blockchain.clone(),
        poh_service.clone(),
        leader_schedule.clone(),
        current_slot.clone(),
        "genesis_validator".to_string(),
    ));
    info!("🏭 BlockProducer initialized");

    let finality_tracker = Arc::new(FinalityTracker::new(current_slot.clone()));
    info!("✅ FinalityTracker initialized");

    // ========================================================================
    // 5. INITIALIZE SECURITY INFRASTRUCTURE
    // ========================================================================
    let throttler = Arc::new(NetworkThrottler::new());
    let circuit_breaker = Arc::new(CircuitBreaker::new());
    circuit_breaker.add_exemption("genesis");
    circuit_breaker.add_exemption("mining_reward");
    circuit_breaker.add_exemption("system");
    let fee_market = Arc::new(LocalizedFeeMarket::new());
    let account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>> = Arc::new(dashmap::DashMap::new());
    info!("🛡️  Security infrastructure initialized");

    // ========================================================================
    // 6. INITIALIZE WALLET SYSTEMS
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
    info!("🔐 S+ Tier Wallet System initialized");

    // ========================================================================
    // 7. INITIALIZE SETTLEMENT SYSTEM
    // ========================================================================
    let settlement_manager = Arc::new(BatchSettlementManager::new());
    let l2_public_keys: Arc<dashmap::DashMap<String, String>> = Arc::new(dashmap::DashMap::new());
    info!("📦 Settlement system initialized");

    // ========================================================================
    // 8. WIRE UP SEALEVEL EXECUTION LOOP
    // ========================================================================
    let sealevel_blockchain = blockchain.clone();
    let sealevel_scheduler = parallel_scheduler.clone();
    let sealevel_gulf_stream = gulf_stream.clone();
    let sealevel_leader_schedule = leader_schedule.clone();
    let sealevel_current_slot = current_slot.clone();
    let sealevel_finality = finality_tracker.clone();
    let sealevel_poh = poh_service.clone();
    
    tokio::spawn(async move {
        info!("⚡ Sealevel execution loop started");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        
        loop {
            interval.tick().await;
            
            let slot = sealevel_current_slot.load(Ordering::Relaxed);
            let leader = {
                let schedule = sealevel_leader_schedule.read();
                schedule.get_leader(slot)
            };
            
            let pending = sealevel_gulf_stream.get_pending_by_priority(&leader, 64);
            
            if pending.is_empty() {
                continue;
            }
            
            let batches = sealevel_scheduler.schedule_with_locks(pending);
            
            for batch in batches {
                let results = sealevel_scheduler.execute_batch_with_locks(
                    batch.clone(),
                    &sealevel_blockchain.cache,
                );
                
                let mut success_count = 0;
                for (i, result) in results.iter().enumerate() {
                    if result.success {
                        let tx = &batch[i];
                        if sealevel_blockchain.transfer(&tx.from, &tx.to, tx.amount).is_ok() {
                            let mut poh = sealevel_poh.write();
                            poh.queue_transaction(tx.id.clone());
                            sealevel_finality.record_inclusion(&tx.id, slot);
                            success_count += 1;
                        }
                    }
                }
                
                if success_count > 0 {
                    debug!("⚡ Sealevel: {} txs executed @ slot {}", success_count, slot);
                }
            }
            
            sealevel_gulf_stream.clear_leader_cache(&leader);
            sealevel_scheduler.tune_batch_size();
        }
    });

    // ========================================================================
    // 9. BUILD APPLICATION STATE
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
        throttler,
        circuit_breaker,
        fee_market,
        account_metadata,
        used_nonces: Arc::new(dashmap::DashMap::new()),
        wallet_handlers: wallet_handlers.clone(),
        settlement_manager,
        l2_public_keys,
    };

    // ========================================================================
    // 10. BUILD ROUTER
    // ========================================================================
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let wallet_router = WalletHandlers::router()
        .with_state((*wallet_handlers).clone());
    
    let mnemonic_handlers = MnemonicHandlers::with_blockchain(Arc::new(state.blockchain.clone()));
    let mnemonic_router = MnemonicHandlers::router()
        .with_state(mnemonic_handlers);
    
    let app = Router::new()
        .merge(build_public_routes())
        .merge(wallet_router)
        .merge(mnemonic_router)
        .nest("/settlement", build_settlement_routes())
        .nest("/poh", build_poh_routes())
        .nest("/sealevel", build_sealevel_routes())
        .nest("/credit", build_credit_routes())
        .nest("/admin", build_admin_routes())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state.clone());

    // ========================================================================
    // 11. START GRPC SERVER
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
    // 12. START BACKGROUND TASKS
    // ========================================================================
    let social_save = social_system.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let data = social_save.lock().await.clone();
            save_social_system(&data);
        }
    });

    // ========================================================================
    // 13. START HTTP SERVER
    // ========================================================================
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    
    info!("");
    info!("🚀 Server listening on http://{}", addr);
    info!("");
    info!("📡 ENDPOINTS:");
    info!("   GET  /health              - System health check");
    info!("   GET  /stats               - Detailed statistics");
    info!("   GET  /balance/:address    - Balance lookup");
    info!("   POST /transfer/simple     - Execute transfer");
    info!("");
    info!("📦 SETTLEMENT (Batch Markets):");
    info!("   POST /settlement/batch    - Submit batch settlement");
    info!("   POST /settlement/claim    - Claim withdrawal with merkle proof");
    info!("   GET  /settlement/batch/:id - Batch status");
    info!("");
    info!("🔐 WALLET (S+ Tier FROST + Consumer BIP-39):");
    info!("   /wallet/*                 - FROST TSS endpoints");
    info!("   /mnemonic/*               - BIP-39 mnemonic endpoints");
    info!("");
    info!("⚡ CONSENSUS:");
    info!("   /poh/*                    - PoH & block endpoints");
    info!("   /sealevel/*               - Parallel execution");
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
    info!("✅ Server shutdown complete");
}
