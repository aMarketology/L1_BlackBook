//! Internal RPC - TCP Socket + Zero-Copy Shared Memory for L1 ↔ L2 Communication
//! 
//! Two transport modes:
//! 1. TCP (Port 8090) - Fallback, always available
//! 2. Shared Memory (memmap2 ring buffer) - Zero-copy, microsecond latency, preferred
//!
//! L1 acts as SUBSCRIBER (receives from L2), L2 is PUBLISHER

use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
#[allow(unused_imports)]  // Reserved for shared-memory IPC (Phase 2)
use std::fs::{File, OpenOptions};
#[allow(unused_imports)]  // Reserved for shared-memory IPC (Phase 2)
use std::path::PathBuf;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]  // Reserved for shared-memory IPC (Phase 2)
use memmap2::{MmapMut, MmapOptions};
use crate::protocol::blockchain::EnhancedBlockchain;

pub const INTERNAL_RPC_PORT: u16 = 8090;

// ============================================================================
// ZERO-COPY IPC: Shared Memory Ring Buffer Types
// ============================================================================
// Uses memory-mapped files for cross-process communication
// ⚠️ CRITICAL: These MUST match EXACTLY in L2 Sequencer (separate repo)

/// Shared memory file paths (Windows/Linux compatible)
pub mod ipc_paths {
    use std::path::PathBuf;
    
    fn get_base_dir() -> PathBuf {
        if cfg!(windows) {
            // Windows: use temp directory with unique name
            std::env::temp_dir().join("blackbook_ipc")
        } else {
            // Linux/macOS: use /tmp
            PathBuf::from("/tmp/blackbook_ipc")
        }
    }
    
    pub fn bets_buffer() -> PathBuf { get_base_dir().join("bets.mmap") }
    pub fn settlements_buffer() -> PathBuf { get_base_dir().join("settlements.mmap") }
    pub fn bridge_buffer() -> PathBuf { get_base_dir().join("bridge.mmap") }
    pub fn balance_buffer() -> PathBuf { get_base_dir().join("balances.mmap") }
    pub fn blocks_buffer() -> PathBuf { get_base_dir().join("blocks.mmap") }
    
    pub fn ensure_dir() -> std::io::Result<()> {
        std::fs::create_dir_all(get_base_dir())
    }
}

/// Ring buffer header (at start of each mmap file)
#[repr(C)]
#[derive(Debug)]
pub struct RingBufferHeader {
    pub magic: u64,           // 0xBB_L1_L2_IPC
    pub version: u32,
    pub entry_size: u32,
    pub capacity: u32,        // Number of entries
    pub write_index: AtomicU64,  // Next write position
    pub read_index: AtomicU64,   // Next read position
}

impl RingBufferHeader {
    pub const MAGIC: u64 = 0xBB_A1_A2_1234;
    pub const VERSION: u32 = 1;
}

/// Bet intent from L2 (zero-copy message)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpcBetIntent {
    pub valid: u8,                   // 1 if entry is valid
    pub user_address: [u8; 18],      // L1_ALICE000000001 + null
    pub market_id: [u8; 37],         // UUID + null
    pub outcome: u8,
    pub amount_microtokens: u64,     // 1 BB = 1_000_000
    pub timestamp: u64,
    pub nonce: u64,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl IpcBetIntent {
    pub fn user_address_str(&self) -> String {
        let end = self.user_address.iter().position(|&b| b == 0).unwrap_or(18);
        String::from_utf8_lossy(&self.user_address[..end]).to_string()
    }
    pub fn market_id_str(&self) -> String {
        let end = self.market_id.iter().position(|&b| b == 0).unwrap_or(37);
        String::from_utf8_lossy(&self.market_id[..end]).to_string()
    }
    pub fn amount_bb(&self) -> f64 { self.amount_microtokens as f64 / 1_000_000.0 }
}

/// Settlement request from L2 Dealer (zero-copy message)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpcSettlement {
    pub valid: u8,
    pub settlement_id: [u8; 37],
    pub from_address: [u8; 18],
    pub to_address: [u8; 18],
    pub amount_microtokens: u64,
    pub market_id: [u8; 37],
    pub timestamp: u64,
    pub user_signature: [u8; 64],
    pub user_public_key: [u8; 32],
}

impl IpcSettlement {
    pub fn from_address_str(&self) -> String {
        let end = self.from_address.iter().position(|&b| b == 0).unwrap_or(18);
        String::from_utf8_lossy(&self.from_address[..end]).to_string()
    }
    pub fn to_address_str(&self) -> String {
        let end = self.to_address.iter().position(|&b| b == 0).unwrap_or(18);
        String::from_utf8_lossy(&self.to_address[..end]).to_string()
    }
    pub fn amount_bb(&self) -> f64 { self.amount_microtokens as f64 / 1_000_000.0 }
}

/// Bridge request from L2 (zero-copy message)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpcBridgeRequest {
    pub valid: u8,
    pub request_type: u8,            // 0=Lock (L1→L2), 1=Unlock (L2→L1)
    pub user_address: [u8; 18],
    pub amount_microtokens: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl IpcBridgeRequest {
    pub const TYPE_LOCK: u8 = 0;
    pub const TYPE_UNLOCK: u8 = 1;
    pub fn user_address_str(&self) -> String {
        let end = self.user_address.iter().position(|&b| b == 0).unwrap_or(18);
        String::from_utf8_lossy(&self.user_address[..end]).to_string()
    }
    pub fn amount_bb(&self) -> f64 { self.amount_microtokens as f64 / 1_000_000.0 }
}

/// Balance update notification L1 → L2 (zero-copy message)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpcBalanceUpdate {
    pub valid: u8,
    pub user_address: [u8; 18],
    pub l1_available: u64,
    pub l1_locked: u64,
    pub block_height: u64,
    pub timestamp: u64,
}

impl IpcBalanceUpdate {
    pub fn new(addr: &str, available: f64, locked: f64, block: u64) -> Self {
        let mut user_address = [0u8; 18];
        let bytes = addr.as_bytes();
        user_address[..bytes.len().min(17)].copy_from_slice(&bytes[..bytes.len().min(17)]);
        Self {
            valid: 1,
            user_address,
            l1_available: (available * 1_000_000.0) as u64,
            l1_locked: (locked * 1_000_000.0) as u64,
            block_height: block,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        }
    }
}

/// Block hash notification L1 → L2 (zero-copy message)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpcBlockHash {
    pub valid: u8,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub tx_count: u32,
}

/// Messages received from L2 via shared memory
#[derive(Debug, Clone)]
pub enum L2Message {
    Bet(IpcBetIntent),
    Settlement(IpcSettlement),
    Bridge(IpcBridgeRequest),
}

fn get_secret() -> String {
    std::env::var("INTERNAL_RPC_SECRET").unwrap_or_else(|_| "blackbook_internal_2024".into())
}

// ============================================================================
// PROTOCOL TYPES
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
    #[serde(default)]
    pub auth: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok(id: u64, result: serde_json::Value) -> Self {
        Self { id, result: Some(result), error: None }
    }
    fn err(id: u64, msg: &str) -> Self {
        Self { id, result: None, error: Some(msg.into()) }
    }
}

// ============================================================================
// SERVER
// ============================================================================

pub struct InternalRpcServer {
    blockchain: Arc<tokio::sync::RwLock<EnhancedBlockchain>>,
    port: u16,
    secret: String,
}

impl InternalRpcServer {
    pub fn new(blockchain: Arc<tokio::sync::RwLock<EnhancedBlockchain>>, port: Option<u16>) -> Self {
        Self { blockchain, port: port.unwrap_or(INTERNAL_RPC_PORT), secret: get_secret() }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| e.to_string())?;
        println!("🔌 Internal RPC on {}", addr);

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let server = Arc::clone(&self);
                tokio::spawn(async move { let _ = server.handle(stream).await; });
            }
        }
    }

    async fn handle(&self, stream: TcpStream) -> Result<(), String> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            if reader.read_line(&mut line).await.map_err(|e| e.to_string())? == 0 { break; }
            
            let resp = self.dispatch(&line).await;
            let json = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"error":"serialize"}"#.into());
            writer.write_all(format!("{}\n", json).as_bytes()).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn dispatch(&self, line: &str) -> Response {
        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => return Response::err(0, &format!("parse: {}", e)),
        };

        // Auth check for write methods
        let needs_auth = matches!(req.method.as_str(), "lock" | "unlock" | "transfer" | "credit");
        if needs_auth && req.auth.as_deref() != Some(&self.secret) {
            return Response::err(req.id, "unauthorized");
        }

        match req.method.as_str() {
            "health" => Response::ok(req.id, serde_json::json!({"status": "ok", "layer": "L1"})),
            "balance" => self.get_balance(req.id, req.params).await,
            "lock" => self.lock_tokens(req.id, req.params).await,
            "unlock" => self.unlock_tokens(req.id, req.params).await,
            "transfer" => self.transfer(req.id, req.params).await,
            "credit" => self.credit(req.id, req.params).await,
            _ => Response::err(req.id, "unknown method"),
        }
    }

    async fn get_balance(&self, id: u64, p: serde_json::Value) -> Response {
        let addr = match p.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => return Response::err(id, "missing address"),
        };
        let bc = self.blockchain.read().await;
        let balance = bc.get_balance(addr);
        let available = bc.get_spendable_balance(addr);
        let locked = bc.get_locked_balance(addr);
        Response::ok(id, serde_json::json!({ "balance": balance, "available": available, "locked": locked }))
    }

    async fn lock_tokens(&self, id: u64, p: serde_json::Value) -> Response {
        let addr = match p.get("address").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, "missing address"),
        };
        let amount = match p.get("amount").and_then(|v| v.as_f64()) {
            Some(a) if a > 0.0 => a,
            _ => return Response::err(id, "invalid amount"),
        };

        let mut bc = self.blockchain.write().await;
        if bc.get_spendable_balance(&addr) < amount {
            return Response::err(id, "insufficient balance");
        }

        match bc.lock_tokens(&addr, amount, crate::protocol::blockchain::LockPurpose::BridgeToL2, None) {
            Ok(lock_id) => Response::ok(id, serde_json::json!({ "lock_id": lock_id, "amount": amount })),
            Err(e) => Response::err(id, &e),
        }
    }

    async fn unlock_tokens(&self, id: u64, p: serde_json::Value) -> Response {
        let addr = match p.get("address").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, "missing address"),
        };
        let pnl = p.get("pnl").and_then(|v| v.as_f64()).unwrap_or(0.0);

        let mut bc = self.blockchain.write().await;
        
        // Find lock for address
        let locks = bc.get_locks_for_address(&addr);
        let lock_id = match locks.first() {
            Some(l) => l.lock_id.clone(),
            None => return Response::err(id, "no lock found"),
        };

        // Authorize and release
        let proof = crate::protocol::blockchain::SettlementProof {
            market_id: "internal".into(),
            outcome: if pnl >= 0.0 { "profit" } else { "loss" }.into(),
            l2_block_height: 0,
            l2_signature: "rpc_auth".into(),
            verified_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        if let Err(e) = bc.authorize_release(&lock_id, proof) {
            return Response::err(id, &e);
        }

        match bc.release_tokens(&lock_id) {
            Ok((_, amount)) => {
                if pnl != 0.0 {
                    *bc.balances.entry(addr.clone()).or_insert(0.0) += pnl;
                }
                Response::ok(id, serde_json::json!({ "unlocked": amount, "pnl": pnl, "balance": bc.get_balance(&addr) }))
            }
            Err(e) => Response::err(id, &e),
        }
    }

    async fn transfer(&self, id: u64, p: serde_json::Value) -> Response {
        let from = match p.get("from").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, "missing from"),
        };
        let to = match p.get("to").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, "missing to"),
        };
        let amount = match p.get("amount").and_then(|v| v.as_f64()) {
            Some(a) if a > 0.0 => a,
            _ => return Response::err(id, "invalid amount"),
        };

        let mut bc = self.blockchain.write().await;
        if bc.get_spendable_balance(&from) < amount {
            return Response::err(id, "insufficient balance");
        }

        let tx_id = bc.create_transaction(from.clone(), to.clone(), amount);
        let _ = bc.mine_pending_transactions("rpc".into());
        Response::ok(id, serde_json::json!({ "tx": tx_id, "from": from, "to": to, "amount": amount }))
    }

    async fn credit(&self, id: u64, p: serde_json::Value) -> Response {
        let addr = match p.get("address").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => return Response::err(id, "missing address"),
        };
        let amount = match p.get("amount").and_then(|v| v.as_f64()) {
            Some(a) if a > 0.0 => a,
            _ => return Response::err(id, "invalid amount"),
        };

        let mut bc = self.blockchain.write().await;
        *bc.balances.entry(addr.clone()).or_insert(0.0) += amount;
        Response::ok(id, serde_json::json!({ "credited": amount, "balance": bc.get_balance(&addr) }))
    }
}

// ============================================================================
// CLIENT
// ============================================================================

pub struct InternalRpcClient {
    addr: String,
    secret: String,
}

impl InternalRpcClient {
    pub fn new(host: &str, port: u16, secret: &str) -> Self {
        Self { addr: format!("{}:{}", host, port), secret: secret.into() }
    }

    pub fn localhost() -> Self {
        Self::new("127.0.0.1", INTERNAL_RPC_PORT, &get_secret())
    }

    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let stream = TcpStream::connect(&self.addr).await.map_err(|e| e.to_string())?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let req = Request { id: 1, method: method.into(), params, auth: Some(self.secret.clone()) };
        let json = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        writer.write_all(format!("{}\n", json).as_bytes()).await.map_err(|e| e.to_string())?;

        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|e| e.to_string())?;

        let resp: Response = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        resp.error.map(Err).unwrap_or_else(|| resp.result.ok_or_else(|| "empty response".into()))
    }

    pub async fn health(&self) -> Result<serde_json::Value, String> { self.call("health", serde_json::json!({})).await }
    pub async fn get_balance(&self, addr: &str) -> Result<f64, String> {
        self.call("balance", serde_json::json!({"address": addr})).await?
            .get("balance").and_then(|v| v.as_f64()).ok_or_else(|| "invalid".into())
    }
    pub async fn lock(&self, addr: &str, amount: f64) -> Result<String, String> {
        self.call("lock", serde_json::json!({"address": addr, "amount": amount})).await?
            .get("lock_id").and_then(|v| v.as_str()).map(|s| s.into()).ok_or_else(|| "invalid".into())
    }
    pub async fn unlock(&self, addr: &str, pnl: f64) -> Result<f64, String> {
        self.call("unlock", serde_json::json!({"address": addr, "pnl": pnl})).await?
            .get("balance").and_then(|v| v.as_f64()).ok_or_else(|| "invalid".into())
    }
    pub async fn transfer(&self, from: &str, to: &str, amount: f64) -> Result<String, String> {
        self.call("transfer", serde_json::json!({"from": from, "to": to, "amount": amount})).await?
            .get("tx").and_then(|v| v.as_str()).map(|s| s.into()).ok_or_else(|| "invalid".into())
    }
}

// ============================================================================
// ZERO-COPY IPC SUBSCRIBER (L1 receives from L2 via shared memory)
// ============================================================================

/// L1 Subscriber - receives messages from L2 with zero-copy shared memory
pub struct IpcSubscriber {
    running: Arc<AtomicBool>,
    message_tx: mpsc::Sender<L2Message>,
    poll_interval_us: u64,
}

impl IpcSubscriber {
    /// Create a new IPC subscriber
    pub fn new(buffer_size: usize, poll_interval_us: u64) -> (Self, mpsc::Receiver<L2Message>) {
        let (tx, rx) = mpsc::channel(buffer_size);
        (Self {
            running: Arc::new(AtomicBool::new(false)),
            message_tx: tx,
            poll_interval_us,
        }, rx)
    }

    /// Stop the subscriber
    pub fn stop(&self) { self.running.store(false, Ordering::Relaxed); }

    /// Check if running
    pub fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }

    /// Start the subscriber (spawns background task)
    pub async fn start(&self) -> Result<(), String> {
        self.running.store(true, Ordering::Relaxed);
        let running = self.running.clone();
        let tx = self.message_tx.clone();
        let interval = self.poll_interval_us;

        tokio::spawn(async move {
            println!("🚀 IPC: Starting iceoryx2 zero-copy subscriber...");
            match Self::run_loop(running.clone(), tx, interval).await {
                Ok(_) => println!("🛑 IPC: Subscriber stopped"),
                Err(e) => {
                    println!("⚠️  IPC: Shared memory unavailable - {}", e);
                    println!("📡 IPC: Falling back to TCP mode (port {})", INTERNAL_RPC_PORT);
                    running.store(false, Ordering::Relaxed);
                }
            }
        });
        Ok(())
    }

    async fn run_loop(
        _running: Arc<AtomicBool>,
        _tx: mpsc::Sender<L2Message>,
        _poll_us: u64,
    ) -> Result<(), String> {
        // IPC removed - using gRPC/REST only
        println!("⚠️  IPC disabled - use gRPC for L1↔L2 communication");
        Err("IPC not implemented".to_string())
    }
}

// ============================================================================
// ZERO-COPY IPC PUBLISHER (L1 sends to L2 via shared memory)
// ============================================================================

/// L1 Publisher - sends balance updates and block hashes to L2
/// TODO: Implement when IPC types are available
pub struct IpcPublisher {
    // node: Option<Node<ipc::Service>>,
    // balance_pub: Option<Publisher<ipc::Service, IpcBalanceUpdate, ()>>,
    // block_pub: Option<Publisher<ipc::Service, IpcBlockHash, ()>>,
    enabled: bool,
}

impl IpcPublisher {
    /// Create publisher (lazy init)
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Initialize publishers - IPC DISABLED, use gRPC instead
    pub fn initialize(&mut self) -> Result<(), String> {
        if !self.enabled { return Ok(()); }
        println!("⚠️  IPC disabled - use gRPC for L1→L2 communication");
        Ok(())
        
        /* IPC CODE REMOVED
        let node = NodeBuilder::new()
            .name(&"blackbook_l1_pub".try_into().unwrap())
            .create::<ipc::Service>()
            .map_err(|e| format!("Publisher node failed: {:?}", e))?;

        let bal_svc = node.service_builder(&ipc_services::BALANCE_UPDATES.try_into().unwrap())
            .publish_subscribe::<IpcBalanceUpdate>()
            .open_or_create()
            .map_err(|e| format!("Balance service failed: {:?}", e))?;
        let balance_pub = bal_svc.publisher_builder().create()
            .map_err(|e| format!("Balance publisher failed: {:?}", e))?;

        let blk_svc = node.service_builder(&ipc_services::BLOCK_HASHES.try_into().unwrap())
            .publish_subscribe::<IpcBlockHash>()
            .open_or_create()
            .map_err(|e| format!("Block service failed: {:?}", e))?;
        let block_pub = blk_svc.publisher_builder().create()
            .map_err(|e| format!("Block publisher failed: {:?}", e))?;

        println!("✅ IPC: L1→L2 publishers ready");
        self.node = Some(node);
        self.balance_pub = Some(balance_pub);
        self.block_pub = Some(block_pub);
        Ok(())
        */
    }

    /// Publish balance update to L2 - IPC DISABLED, use gRPC
    pub fn publish_balance(&self, _update: IpcBalanceUpdate) -> Result<(), String> {
        // TODO: Use gRPC streaming instead
        Ok(())
    }

    /// Publish block hash to L2 - IPC DISABLED, use gRPC
    pub fn publish_block(&self, _block: IpcBlockHash) -> Result<(), String> {
        // TODO: Use gRPC streaming instead
        Ok(())
    }
}

/// Start IPC subscriber with default settings (10K buffer, 100μs poll)
pub async fn start_ipc_subscriber() -> Result<(IpcSubscriber, mpsc::Receiver<L2Message>), String> {
    let (sub, rx) = IpcSubscriber::new(10_000, 100);
    sub.start().await?;
    Ok((sub, rx))
}
