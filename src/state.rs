//! BlackBook L1 ΓÇö Application state, CLI config, constants, and request/response types.
//!
//! This module contains all the type definitions used across the codebase:
//! - CLI argument parsing (`NodeConfig`, `NodeMode`)
//! - Application state (`AppState`)
//! - WebSocket subscription types
//! - JSON-RPC request/response types
//! - Shared constants (version, PoH config, etc.)

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use clap::Parser;
use parking_lot::RwLock;

use layer1::storage::ConcurrentBlockchain;
use layer1::poh_blockchain::{BlockProducer, FinalizedBlock, FinalityTracker};
use layer1::runtime::{
    SharedPoHService, TransactionPipeline, LeaderSchedule,
    GulfStreamService, ParallelScheduler, TowerBFT,
};
use layer1::runtime::core::{NetworkThrottler, CircuitBreaker, LocalizedFeeMarket, AccountMetadata};
use layer1::{settlement, watcher};

// ============================================================================
// CONSTANTS
// ============================================================================

pub const VERSION: &str = "5.0.2";
pub const NETWORK: &str = "mainnet-beta";
pub const REDB_DATA_PATH_DEFAULT: &str = "./blockchain_data";

/// PoH Configuration (400ms slots ΓÇö matching Solana for max TPS)
pub const POH_SLOT_DURATION_MS: u64 = 400;
pub const POH_HASHES_PER_TICK: u64 = 12500;
pub const POH_TICKS_PER_SLOT: u64 = 64;
pub const POH_SLOTS_PER_EPOCH: u64 = 432000; // ~3 days

// ============================================================================
// CLI ARGUMENTS
// ============================================================================

/// Node operating mode: Writer produces blocks, Reader consumes them,
/// Validator dynamically switches roles based on the leader schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NodeMode {
    /// Single writer node: runs PoH clock, produces blocks, serves relay to readers
    Writer,
    /// Reader node: subscribes to writer relay, verifies + stores blocks, serves RPC
    Reader,
    /// Consortium validator: consults LeaderSchedule at every slot, produces
    /// blocks when scheduled, syncs as reader otherwise. Multi-validator mode.
    Validator,
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeMode::Writer => write!(f, "writer"),
            NodeMode::Reader => write!(f, "reader"),
            NodeMode::Validator => write!(f, "validator"),
        }
    }
}

/// BlackBook L1 ΓÇö Consortium / Permissioned Settlement Layer
#[derive(Parser, Debug)]
#[command(name = "blackbook-l1", version = VERSION, about = "PoH blockchain node")]
pub struct NodeConfig {
    /// Node mode: writer (block producer), reader (block consumer), or
    /// validator (consults LeaderSchedule, dynamic role switching)
    #[arg(long, default_value = "writer", value_enum)]
    pub mode: NodeMode,

    /// Validator identity name (used in leader schedule + logs).
    /// In Validator mode, must match one of the [[validators]] labels in config.toml.
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

    /// Override the ReDB database path (defaults to REDB_PATH env var)
    /// Useful for running a Reader node alongside a local Writer without
    /// sharing the same database file.
    #[arg(long)]
    pub redb_path: Option<String>,
}

// ============================================================================
// REQUEST / RESPONSE TYPES
// ============================================================================

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
// WEBSOCKET / JSON-RPC TYPES
// ============================================================================

use tokio::sync::mpsc;

#[derive(serde::Deserialize)]
pub struct RpcRequest {
    pub method: String,
    pub params: Option<Vec<serde_json::Value>>,
    pub id: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<u64>, // Subscription ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>, // "accountNotification"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<RpcParams>,
}

#[derive(serde::Serialize)]
pub struct RpcParams {
    pub subscription: u64,
    pub result: RpcAccountResult,
}

#[derive(serde::Serialize)]
pub struct RpcAccountResult {
    pub context: RpcContext,
    pub value: RpcAccountValue,
}

#[derive(serde::Serialize)]
pub struct RpcContext {
    pub slot: u64,
}

#[derive(serde::Serialize)]
pub struct RpcAccountValue {
    pub lamports: u64,
    pub data: Vec<String>,
    pub owner: String,
    pub executable: bool,
    #[serde(rename = "rentEpoch")]
    pub rent_epoch: u64,
}

pub type WsSender = mpsc::UnboundedSender<axum::extract::ws::Message>;

pub struct WsSubscriptions {
    pub clients: dashmap::DashMap<std::net::SocketAddr, WsSender>,
    pub account_subs: dashmap::DashMap<String, dashmap::DashSet<std::net::SocketAddr>>,
    /// Clients subscribed to PoH slot notifications (`slotSubscribe`).
    pub slot_subs: dashmap::DashSet<std::net::SocketAddr>,
}

impl WsSubscriptions {
    pub fn new() -> Self {
        Self {
            clients: dashmap::DashMap::new(),
            account_subs: dashmap::DashMap::new(),
            slot_subs: dashmap::DashSet::new(),
        }
    }
}

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

    // Security infrastructure
    pub throttler: Arc<NetworkThrottler>,
    pub ws_subscriptions: Arc<WsSubscriptions>,
    pub block_tx: tokio::sync::broadcast::Sender<FinalizedBlock>,
    /// Broadcast channel for per-block BB balance update events pushed to L2 subscribers.
    pub balance_event_tx: tokio::sync::broadcast::Sender<settlement::BalanceUpdateEvent>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub fee_market: Arc<LocalizedFeeMarket>,
    pub account_metadata: Arc<dashmap::DashMap<String, AccountMetadata>>,
    pub used_nonces: Arc<dashmap::DashMap<String, u64>>,

    // Faucet rate-limiter: address ΓåÆ (epoch_at_claim, total_minted_this_epoch)
    pub faucet_claims: Arc<dashmap::DashMap<String, (u64, u64)>>,

    // ===== Global Escrow Smart Contract =====
    /// Ed25519 public key of the authorized L2 sequencer (hex)
    pub l2_sequencer_pubkey: String,
    /// Allowlist of L2 sequencer hex pubkeys (superset of l2_sequencer_pubkey).
    pub l2_sequencer_allowlist: std::collections::HashSet<String>,
    /// Per-market merkle roots: market_id ΓåÆ [u8; 32] (raw SHA-256 root)
    pub market_roots: Arc<dashmap::DashMap<String, [u8; 32]>>,
    /// Double-withdrawal protection: "{market_id}:{address}" ΓåÆ true
    pub withdrawal_claims: Arc<dashmap::DashMap<String, bool>>,

    // ===== Universal Rollup Hub Auth =====
    /// Maps rollup_id ("L2", "L3", "L5") ΓåÆ authorized sequencer pubkey (64-char hex).
    pub authorized_sequencers: Arc<dashmap::DashMap<String, String>>,

    // ===== Contest Settlement State =====
    pub contest_states: Arc<dashmap::DashMap<String, layer1::storage::ContestState>>,

    // ===== Deposit Gateway =====
    pub custody_wallet_address: String,
    pub deposit_requests: Arc<dashmap::DashMap<String, layer1::storage::DepositRecord>>,
    pub custody_watcher: Option<Arc<watcher::CustodyWatcher>>,
    pub bsc_watcher: Option<Arc<watcher::BscWatcher>>,
    pub bridge_authority_pubkey: String,

    // ===== Withdrawal Gateway =====
    pub withdrawal_requests: Arc<dashmap::DashMap<String, layer1::storage::WithdrawalRecord>>,
    pub withdrawal_seq_counter: Arc<std::sync::atomic::AtomicU64>,
    pub withdrawal_window_start: Arc<std::sync::atomic::AtomicU64>,
    pub withdrawal_window_total: Arc<std::sync::atomic::AtomicU64>,
    pub withdrawal_daily_cap_micro: u64,

    // ===== Layer 5: Rollup Liquidity Bridge =====
    pub rollup_lock_records: Arc<dashmap::DashMap<String, layer1::storage::RollupLockRecord>>,

    // ===== Backup State =====
    pub backup_last_at: Arc<AtomicU64>,
    pub backup_last_size: Arc<AtomicU64>,

    /// Cumulative count of slots skipped due to leader timeout (Phase 6 skip-slot).
    pub skip_slot_total: Arc<AtomicU64>,

    // ===== Turbine Tick Streaming (Phase 7A) =====
    pub approved_validators: Arc<layer1::runtime::validator_registry::ValidatorRegistry>,

    // ===== Reader Mode: Writer Proxy =====
    pub writer_http_url: Option<String>,

    // ===== Vault Claim Signer (KMS / Local Ed25519) =====
    pub vault_signer: Option<Arc<layer1::kms::VaultSigner>>,
}
