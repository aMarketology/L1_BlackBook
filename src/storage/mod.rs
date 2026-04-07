// ============================================================================
// BLACKBOOK L1 — UNIFIED STORAGE LAYER (v2 — SVM-native)
// ============================================================================
//
// **Single source of truth: SVM AccountsDB (u64 lamports)**
//
// All balances are stored as u64 lamports in the SVM AccountsDB.
// 1 BB = 100,000 lamports (5 decimals).
//
// The legacy f64 DashMap cache is kept ONLY as a read-through mirror
// for backward-compatible REST API responses and audit logging.
// It is NEVER consulted for authoritative balance data.
//
// ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────┐
// │                        AppState                                 │
// │                            │                                    │
// │              ┌─────────────┴─────────────┐                     │
// │              ▼                           ▼                     │
// │    ConcurrentBlockchain           Global Escrow                │
// │         │                               │                      │
// │    ┌────┴──────────────┐          ┌─────┴───────┐             │
// │    │  SVM AccountsDB   │          │  DashMap    │             │
// │    │  (u64 lamports)   │          │ (market     │             │
// │    │  SINGLE SOURCE    │          │  roots)     │             │
// │    │  OF TRUTH         │          └─────────────┘             │
// │    └────┬──────────────┘                                      │
// │         │                                                     │
// │    ┌────┴────┐     ┌────────────────┐                        │
// │    │ DashMap │     │     ReDB       │                        │
// │    │ (f64   ◄─────┤  (Persistent)  │                        │
// │    │ mirror) │     │  audit trail   │                        │
// │    └─────────┘     └────────────────┘                        │
// └─────────────────────────────────────────────────────────────────┘
//
// CONCURRENCY MODEL:
// - Reads:  Lock-free via SVM DashMap hot_state (100,000+ concurrent)
// - Writes: SVM store_account → then mirror to ReDB for persistence
//
// CRITICAL: No f64 in the balance hot path. f64 only at API boundaries.
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use redb::{Database, TableDefinition, ReadableTable};
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::{info, warn};
use crate::svm::accounts_db::SvmAccountsDB;
use crate::svm::types::LAMPORTS_PER_BB;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::account::AccountSharedData;
use solana_sdk::account::ReadableAccount;

// ============================================================================
// REDB TABLE DEFINITIONS (Type-Safe!)
// ============================================================================

/// Committed blocks: BlockHeight (u64) → BlockData (Vec<u8>)
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");

/// Metadata: Key (String) → Value (bytes)
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

/// Transaction history: TxID (String) → TransactionData (Vec<u8>)
const TRANSACTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("transactions");

/// Processed bridge transactions: ExternalTxHash (String) → MintTxID (String)
/// This is CRITICAL for replay protection - prevents double-minting from same USDC lock
const PROCESSED_BRIDGE_TXS: TableDefinition<&str, &str> = TableDefinition::new("processed_bridge_txs");

/// Escrow market roots: MarketID (String) → MerkleRoot (32 bytes, SHA-256)
/// Stores ONLY the raw 32-byte merkle root per market. No metadata.
/// L1 is a vault — it stores the math, not the floor plan.
pub const ESCROW_MARKET_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("escrow_market_roots");

/// Escrow withdrawal claims: "{market_id}:{address}" (String) → ClaimTimestamp (u64)
/// Prevents double-withdrawal per market — durable across restarts
pub const ESCROW_CLAIMS: TableDefinition<&str, u64> = TableDefinition::new("escrow_claims");

/// Slot metadata: Slot (u64) -> SlotMeta JSON (bytes)
pub const SLOT_META: TableDefinition<u64, &[u8]> = TableDefinition::new("slot_meta");

/// Incremental Sparse Merkle Tree interior nodes.
/// Schema: (Slot u64, NodePath &[u8]) → NodeHash [u8; 32]
///
/// Keyed by (slot, path) instead of NodeHash alone so fork branches never
/// overwrite each other. GC prunes entries where slot < current - FINALIZATION_DEPTH.
pub const MERKLE_NODES: TableDefinition<(u64, &[u8]), &[u8]> = TableDefinition::new("merkle_nodes");

/// Deposit gateway requests: external_tx_hash (String) → DepositRecord JSON (bytes)
/// Durable record of every wUSDC/wUSDT → BB deposit request submitted by users.
const DEPOSIT_REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("deposit_requests");

/// Withdrawal gateway requests: withdrawal_id (UUID) → WithdrawalRecord JSON (bytes)
/// Durable record of every wUSDC → real USDC withdrawal initiated by users.
const WITHDRAWALS: TableDefinition<&str, &[u8]> = TableDefinition::new("withdrawals");

/// Per-contest settlement state: contest_id → ContestState JSON (bytes)
/// Tracks lifecycle (Open → Settled → Expired), Merkle root, payout accounting,
/// and claim deadline per BB market.
const CONTEST_STATES: TableDefinition<&str, &[u8]> = TableDefinition::new("contest_states");

/// Layer 5 creator coin registry: ticker → CreatorCoinRecord JSON (bytes)
const CREATOR_COINS: TableDefinition<&str, &[u8]> = TableDefinition::new("creator_coins");

/// Layer 5 AMM pool state: ticker → CoinPoolState JSON (bytes)
const COIN_POOLS: TableDefinition<&str, &[u8]> = TableDefinition::new("coin_pools");

/// Layer 5 user coin balances: "{ticker}:{wallet}" → coin_units (u64, 6 decimals)
const COIN_BALANCES: TableDefinition<&str, u64> = TableDefinition::new("coin_balances");

// NOTE: Two-tier vault table constants (TIER1_STATE, TIER2_STATE,
// DIME_VINTAGES, CPI_HISTORY, DIME_BALANCES) were removed — the DIME/vault
// feature was designed but never wired up. Recoverable from git history.

// ============================================================================
// ENHANCED LEDGER ENUMS (Type-Safe Blockchain Integrity)
// ============================================================================

/// Metadata about a generated slot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlotMeta {
    pub slot: u64,
    pub terminal_hash: String,
}

/// Transaction type enum for type-safe categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxType {
    Transfer,
    Mint,
    Burn,
    BridgeOut,
    BridgeIn,
    Lock,
    Unlock,
    SwapUsdcForBb,
    SwapBbForUsdc,
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxType::Transfer => write!(f, "TRANSFER"),
            TxType::Mint => write!(f, "MINT"),
            TxType::Burn => write!(f, "BURN"),
            TxType::BridgeOut => write!(f, "BRIDGE_OUT"),
            TxType::BridgeIn => write!(f, "BRIDGE_IN"),
            TxType::Lock => write!(f, "LOCK"),
            TxType::Unlock => write!(f, "UNLOCK"),
            TxType::SwapUsdcForBb => write!(f, "SWAP_USDC_FOR_BB"),
            TxType::SwapBbForUsdc => write!(f, "SWAP_BB_FOR_USDC"),
        }
    }
}

// NOTE: TxStatus enum removed — tx lifecycle is tracked by
// FinalityTracker (ConfirmationStatus::Processing → Confirmed → Finalized).

/// Authentication type for ZKP/SSS tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    SystemInternal, // Internal system operation (mints, etc)
    Ed25519,        // Ed25519 Signature Authentication
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::SystemInternal => write!(f, "SYSTEM"),
            AuthType::Ed25519 => write!(f, "ED25519"),
        }
    }
}

// ============================================================================
// ENHANCED TRANSACTION RECORD (Full Blockchain Integrity)
// ============================================================================

/// Enhanced transaction record with full blockchain integrity fields
/// 
/// This structure provides:
/// - Chain Integrity: block_height, tx_hash, prev_tx_hash, merkle_root
/// - Auth & ZK: zk_proof_ref, session_id, auth_type, gas_fee
/// - State Validation: nonce, balance_before, balance_after, validator_sig
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionRecord {
    // === CORE IDENTITY ===
    pub tx_id: String,
    pub tx_type: String,  // "transfer", "mint", "burn", "bridge_out", "bridge_in"
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub timestamp: u64,  // Unix timestamp (seconds)
    pub status: String,  // "completed", "failed", "pending", "finalized"
    
    // === CHAIN INTEGRITY (The Backbone) ===
    /// Block height - chronological index in the chain
    #[serde(default)]
    pub block_height: u64,
    /// Transaction hash - SHA256 fingerprint of this transaction
    #[serde(default)]
    pub tx_hash: String,
    /// Previous transaction hash - links to prior tx for chain continuity
    #[serde(default)]
    pub prev_tx_hash: String,
    /// Merkle root of the block this tx belongs to
    #[serde(default)]
    pub merkle_root: String,
    
    // === AUTH & ZK (The Security Guard) ===
    /// Reference to ZK-SNARK proof (UUID or hash)
    #[serde(default)]
    pub zk_proof_ref: Option<String>,
    /// Session ID for scoped session key tracking
    #[serde(default)]
    pub session_id: Option<String>,
    /// Authentication type used
    #[serde(default)]
    pub auth_type: String,
    /// Gas/computational fee (0 for users, tracked for health)
    #[serde(default)]
    pub gas_fee: u64,
    
    // === STATE VALIDATION (The Health Check) ===
    /// Transaction nonce - prevents replay attacks
    #[serde(default)]
    pub nonce: u64,
    /// Sender's balance before transaction
    #[serde(default)]
    pub balance_before: u64,
    /// Sender's balance after transaction
    #[serde(default)]
    pub balance_after: u64,
    /// Recipient's balance after transaction
    #[serde(default)]
    pub recipient_balance_after: u64,
    /// Validator's Ed25519 signature (hex)
    #[serde(default)]
    pub validator_sig: Option<String>,
    
    // === USERNAME FIELDS (For Human-Readable Ledger) ===
    /// Sender's username/alias
    #[serde(default)]
    pub from_username: Option<String>,
    /// Recipient's username/alias
    #[serde(default)]
    pub to_username: Option<String>,
    
    // === LEGACY FIELDS ===
    pub signature: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl TransactionRecord {
    /// Create a new transaction record with computed hash, and optionally a specific ID
    pub fn with_id(
        tx_id: String,
        tx_type: TxType,
        from: &str,
        to: &str,
        amount: u64,
        nonce: u64,
        balance_before: u64,
        balance_after: u64,
        recipient_balance_after: u64,
        auth_type: AuthType,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        // Compute transaction hash (SHA-256 — cryptographically secure)
        use sha2::{Sha256, Digest};
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx_id, tx_type, from, to, amount, timestamp, nonce
        );
        let hash_bytes = Sha256::digest(hash_input.as_bytes());
        let tx_hash = format!("{:x}", hash_bytes);
        
        Self {
            tx_id,
            tx_type: tx_type.to_string(),
            from_address: from.to_string(),
            to_address: to.to_string(),
            amount,
            timestamp,
            status: "finalized".to_string(),
            
            block_height: 0,
            tx_hash,
            prev_tx_hash: String::new(),
            merkle_root: String::new(),
            
            zk_proof_ref: None,
            session_id: None,
            auth_type: auth_type.to_string(),
            gas_fee: 0,
            
            nonce,
            balance_before,
            balance_after,
            recipient_balance_after,
            validator_sig: None,
            
            from_username: None,
            to_username: None,
            
            signature: None,
            metadata: None,
        }
    }

    /// Create a new transaction record with computed hash (autogenerates ID)
    pub fn new(
        tx_type: TxType,
        from: &str,
        to: &str,
        amount: u64,
        nonce: u64,
        balance_before: u64,
        balance_after: u64,
        recipient_balance_after: u64,
        auth_type: AuthType,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let tx_id = format!("tx_{}", chrono::Utc::now().timestamp_millis());
        
        // Compute transaction hash (SHA-256 — cryptographically secure)
        use sha2::{Sha256, Digest};
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx_id, tx_type, from, to, amount, timestamp, nonce
        );
        let hash_bytes = Sha256::digest(hash_input.as_bytes());
        let tx_hash = format!("{:x}", hash_bytes);
        
        Self {
            tx_id,
            tx_type: tx_type.to_string().to_lowercase(),
            from_address: from.to_string(),
            to_address: to.to_string(),
            amount,
            timestamp,
            status: "finalized".to_string(),
            block_height: 0,
            tx_hash,
            prev_tx_hash: String::new(),
            merkle_root: String::new(),
            zk_proof_ref: None,
            session_id: None,
            auth_type: auth_type.to_string().to_lowercase(),
            gas_fee: 0,
            nonce,
            balance_before,
            balance_after,
            recipient_balance_after,
            validator_sig: None,
            from_username: None,
            to_username: None,
            signature: None,
            metadata: None,
        }
    }
    
    /// Check if balance reconciles: BEFORE - AMOUNT - GAS == AFTER
    pub fn is_reconciled(&self) -> bool {
        let expected = self.balance_before.saturating_sub(self.amount).saturating_sub(self.gas_fee);
        expected == self.balance_after
    }
    
    /// Get abbreviated tx_hash (first 8 + last 4 chars)
    pub fn short_hash(&self) -> String {
        if self.tx_hash.len() > 12 {
            format!("{}...{}", &self.tx_hash[..8], &self.tx_hash[self.tx_hash.len()-4..])
        } else {
            self.tx_hash.clone()
        }
    }
}

// ============================================================================
// CONCURRENT BLOCKCHAIN
// ============================================================================

/// High-performance blockchain storage — SVM-native.
///
/// **Single source of truth: SVM AccountsDB (u64 lamports).**
///
/// The DashMap `cache` is a f64 mirror kept for backward-compatible API
/// responses and audit logging. It is populated FROM SVM on writes, never
/// the other way around. Balance reads go directly to SVM.
///
/// # Thread Safety
/// - `Clone` is cheap (Arc handles)
/// - `get_balance()` is lock-free (reads SVM hot_state)
/// - `credit()`/`debit()` write to SVM first, then mirror
///
/// # No More Dual-Write
/// - Old system: write f64 to DashMap/ReDB → sync to SVM (dual source of truth)
/// - New system: write u64 to SVM → mirror f64 to DashMap/ReDB (single source of truth)
#[derive(Clone)]
pub struct ConcurrentBlockchain {
    /// ReDB database handle (Arc allows sharing across threads)
    db: Arc<Database>,
    pub cache: Arc<DashMap<String, f64>>,
    #[allow(dead_code)]
    processed_bridge_txs: Arc<DashMap<String, String>>,
    block_height: Arc<AtomicU64>,
    total_supply: Arc<AtomicU64>,
    
    pub svm_accounts: Arc<SvmAccountsDB>,

    /// Per-account nonce tracker (prevents replay attacks)
    pub account_nonces: Arc<DashMap<String, u64>>,
    /// This eliminates synchronous ReDB writes from the hot path.
    tx_log_buffer: Arc<Mutex<Vec<TransactionRecord>>>,
}

impl ConcurrentBlockchain {
    /// Try to parse a string address as a Solana Pubkey (32-byte base58)
    fn try_parse_pubkey(address: &str) -> Option<Pubkey> {
        if address.starts_with("bb_") { return None; }
        let bytes = bs58::decode(address).into_vec().ok()?;
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Pubkey::new_from_array(arr))
    }

    /// Convert ANY address to a Solana Pubkey.
    ///
    /// - Base58 pubkeys: parsed directly
    /// - Legacy `bb_*` addresses: SHA-256 hashed to a deterministic 32-byte key
    /// - Other strings: SHA-256 hashed (same as bb_ path)
    ///
    /// This is the UNIFIED address resolver — every address maps to exactly
    /// one SVM account. No more "SVM path vs legacy path" branching.
    pub fn addr_to_pubkey(address: &str) -> Pubkey {
        // Fast path: valid base58 Solana pubkey
        if let Some(pk) = Self::try_parse_pubkey(address) {
            return pk;
        }
        // Legacy/fallback: deterministic SHA-256 hash
        use sha2::{Sha256, Digest};
        let stripped = address.strip_prefix("bb_").unwrap_or(address);
        let bytes: [u8; 32] = Sha256::digest(stripped.as_bytes()).into();
        Pubkey::new_from_array(bytes)
    }

    /// Mirror a balance to the legacy f64 DashMap cache.
    /// Called AFTER writing to SVM. The cache is a read-behind mirror,
    /// not a source of truth. SVM AccountsDB is the single authoritative store.
    pub fn mirror_balance_to_cache(&self, address: &str, lamports: u64) {
        let bb = lamports as f64 / LAMPORTS_PER_BB as f64;
        self.cache.insert(address.to_string(), bb);
    }

    /// Retrieve the slot metadata (e.g. terminal hash) for a given slot
    pub fn get_slot_meta(&self, slot: u64) -> Option<SlotMeta> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(SLOT_META).ok()?;
        let value = table.get(&slot).ok()??;
        serde_json::from_slice(value.value()).ok()
    }

    /// Save the slot metadata (e.g. terminal hash) for a given slot
    pub fn save_slot_meta(&self, slot: u64, meta: &SlotMeta) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SLOT_META)?;
            let json = serde_json::to_vec(meta)?;
            table.insert(&slot, json.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ========================================================================
    // MERKLE NODE STORAGE (Phase 2 — Incremental SMT)
    // ========================================================================

    /// Finalization window: nodes from slots older than current - FINALIZATION_DEPTH
    /// are safe to garbage-collect.
    const FINALIZATION_DEPTH: u64 = 32;

    /// Read a persisted Merkle interior node for a given (slot, path).
    pub fn read_merkle_node(&self, slot: u64, path: &[u8]) -> Option<[u8; 32]> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(MERKLE_NODES).ok()?;
        let guard = table.get(&(slot, path)).ok()??;
        let bytes: &[u8] = guard.value();
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        } else {
            None
        }
    }

    /// Write a Merkle interior node for a given (slot, path) in a batch.
    /// `nodes` is a slice of (path_bytes, hash_32) pairs — all written in a
    /// single ACID transaction to avoid per-node I/O overhead.
    pub fn write_merkle_nodes(&self, slot: u64, nodes: &[(&[u8], [u8; 32])]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if nodes.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(MERKLE_NODES)?;
            for (path, hash) in nodes {
                table.insert(&(slot, *path), hash.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Garbage-collect Merkle interior nodes for all slots older than
    /// `current_slot - FINALIZATION_DEPTH`.
    ///
    /// Redb does NOT shrink the .redb file when rows are deleted — it marks
    /// those pages as free for future writes.  The file size will stabilise
    /// (stop growing) once GC is running steadily.  A shrinking file is NOT
    /// required for the GC to be considered working correctly.
    pub fn gc_merkle_nodes(&self, current_slot: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        if current_slot < Self::FINALIZATION_DEPTH {
            return Ok(0);
        }
        let cutoff = current_slot - Self::FINALIZATION_DEPTH;

        let write_txn = self.db.begin_write()?;
        let pruned;
        {
            let mut table = write_txn.open_table(MERKLE_NODES)?;
            // Collect keys to delete (can't delete while iterating over a mutable table)
            let to_delete: Vec<(u64, Vec<u8>)> = {
                let read_txn_inner = self.db.begin_read()?;
                let read_table = read_txn_inner.open_table(MERKLE_NODES)?;
                let mut keys = Vec::new();
                let mut iter = read_table.iter()?;
                while let Some(Ok((k, _))) = iter.next() {
                    let (slot, path) = k.value();
                    if slot < cutoff {
                        keys.push((slot, path.to_vec()));
                    }
                }
                keys
            };

            pruned = to_delete.len() as u64;
            for (slot, path) in &to_delete {
                table.remove(&(*slot, path.as_slice()))?;
            }
        }
        write_txn.commit()?;

        if pruned > 0 {
            tracing::info!(pruned_nodes = pruned, cutoff_slot = cutoff, "gc_merkle_nodes: pruned orphaned Merkle nodes");
        }
        Ok(pruned)
    }

    /// Create or open a unified SVM-backed blockchain layer.
    /// Accepts either:
    ///   - A full file path ending in .redb (e.g. "/data/blockchain_data/blockchain.redb")
    ///   - A directory path (e.g. "./blockchain_data") — appends "/blockchain.redb"
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db_file = if path.ends_with(".redb") {
            path.to_string()
        } else {
            format!("{}/blockchain.redb", path)
        };
        info!(path = %db_file, "Opening ReDB database");

        // Create database directory if needed
        if let Some(parent) = std::path::Path::new(&db_file).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Database::create(&db_file)?;
        
        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(BLOCKS)?;
            let _ = write_txn.open_table(METADATA)?;
            let _ = write_txn.open_table(TRANSACTIONS)?;
            let _ = write_txn.open_table(PROCESSED_BRIDGE_TXS)?;
            // Escrow tables
            let _ = write_txn.open_table(ESCROW_MARKET_ROOTS)?;
            let _ = write_txn.open_table(ESCROW_CLAIMS)?;
            let _ = write_txn.open_table(SLOT_META)?;
            let _ = write_txn.open_table(MERKLE_NODES)?;
            let _ = write_txn.open_table(DEPOSIT_REQUESTS)?;
            let _ = write_txn.open_table(WITHDRAWALS)?;
            let _ = write_txn.open_table(CONTEST_STATES)?;

            // SVM tables (behind feature flag)
            {
                let _ = write_txn.open_table(crate::svm::accounts_db::SVM_ACCOUNTS)?;
                let _ = write_txn.open_table(crate::svm::accounts_db::SVM_PROGRAMS)?;
                let _ = write_txn.open_table(crate::svm::accounts_db::BLOCKHASH_QUEUE)?;
                let _ = write_txn.open_table(crate::svm::accounts_db::SVM_SIGNATURES)?;
                // Phase 2B tables
                let _ = write_txn.open_table(crate::svm::accounts_db::SVM_TX_LOG)?;
                let _ = write_txn.open_table(crate::svm::accounts_db::SVM_ADDR_SIGS)?;
            }
        }
        write_txn.commit()?;
        
        // Load existing data into cache
        let cache = Arc::new(DashMap::new());
        let processed_bridge_txs = Arc::new(DashMap::new());
        
        {
            let read_txn = db.begin_read()?;
            
            // Load processed bridge TXs into cache
            if let Ok(bridge_table) = read_txn.open_table(PROCESSED_BRIDGE_TXS) {
                let iter = bridge_table.iter()?;
                for result in iter {
                    let (key, value) = result?;
                    let tx_hash = key.value().to_string();
                    let status = value.value().to_string();
                    processed_bridge_txs.insert(tx_hash, status);
                }
            }
        }

        let bridge_tx_count = processed_bridge_txs.len();
        info!(processed_bridge_txs = bridge_tx_count, "Database loaded (balances in SVM AccountsDB)");

        let db_arc = Arc::new(db);
        let svm_accounts = Arc::new(SvmAccountsDB::new(Arc::clone(&db_arc)).map_err(|e| e.to_string())?);

        // ═══ HYDRATE DashMap cache from SVM hot_state on startup ═══
        // This ensures legacy code paths that read `cache` see correct
        // balances immediately after restart (no stale zeros).
        let mut hydrated = 0usize;
        for entry in svm_accounts.hot_state.iter() {
            let pubkey = entry.key();
            let lamports = entry.value().lamports();
            let address = bs58::encode(pubkey.to_bytes()).into_string();
            let bb = lamports as f64 / LAMPORTS_PER_BB as f64;
            cache.insert(address, bb);
            hydrated += 1;
        }
        info!(hydrated_accounts = hydrated, "DashMap cache hydrated from SVM hot_state");

        Ok(Self {
            db: db_arc,
            cache,
            processed_bridge_txs,
            block_height: Arc::new(AtomicU64::new(0)),
            total_supply: Arc::new(AtomicU64::new(0)),
            svm_accounts,
            account_nonces: Arc::new(DashMap::new()),
            tx_log_buffer: Arc::new(Mutex::new(Vec::with_capacity(1024))),
        })
    }

    // ========================================================================
    // READ OPERATIONS (Lock-Free)
    // ========================================================================

    /// Get balance for an address — LOCK FREE, SVM-NATIVE
    /// 
    /// Always reads from SVM AccountsDB (the single source of truth).
    /// Returns f64 BB for API backward compatibility.
    /// Internally: SVM u64 lamports → f64 BB at the boundary.
    #[inline]
    pub fn get_balance(&self, address: &str) -> f64 {
        let pk = Self::addr_to_pubkey(address);
        let lamports = self.svm_accounts.get_lamports(&pk);
        lamports as f64 / LAMPORTS_PER_BB as f64
    }

    /// Get balance in raw lamports (u64) — no f64 conversion.
    /// Use this for internal operations to avoid floating-point dust.
    #[inline]
    pub fn get_balance_lamports(&self, address: &str) -> u64 {
        let pk = Self::addr_to_pubkey(address);
        self.svm_accounts.get_lamports(&pk)
    }

    /// Get total supply — LOCK FREE, SVM-NATIVE
    /// Pure SVM read. No more dual-system merge.
    #[inline]
    pub fn total_supply(&self) -> f64 {
        let svm_lamports = self.svm_accounts.total_lamports();
        svm_lamports as f64 / LAMPORTS_PER_BB as f64
    }

    /// Get block height - LOCK FREE
    #[inline]
    pub fn block_height(&self) -> u64 {
        self.block_height.load(Ordering::Relaxed)
    }

    // ========================================================================
    // WRITE OPERATIONS (ReDB MVCC - Safe, Serialized)
    // ========================================================================

    /// Credit (add) tokens to an address — SVM-native
    ///
    /// Converts f64 BB → u64 lamports ONCE at entry, then operates entirely
    /// in u64 through the SVM AccountsDB. Mirrors to cache/ReDB after.
    pub fn credit(&self, address: &str, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }

        // ═══ SINGLE CONVERSION: f64 → u64 at the boundary ═══
        let add_lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        if add_lamports == 0 {
            return Err("Amount too small to represent in lamports".to_string());
        }

        // ═══ SVM: Read current, compute new, write ═══
        let pk = Self::addr_to_pubkey(address);
        let current_lamports = self.svm_accounts.get_lamports(&pk);
        let new_lamports = current_lamports.checked_add(add_lamports)
            .ok_or("Balance overflow")?;
        
        let account = AccountSharedData::new(
            new_lamports,
            0,
            &solana_sdk::system_program::id(),
        );
        self.svm_accounts.store_account(&pk, account);

        // ═══ MIRROR to cache/ReDB (non-authoritative) ═══
        self.mirror_balance_to_cache(address, new_lamports);
        
        // Update total supply tracker
        self.total_supply.fetch_add(add_lamports, Ordering::Relaxed);
        
        let is_new_wallet = current_lamports == 0;
        
        if is_new_wallet {
            let total_wallets = self.cache.len();
            info!("🆕 NEW WALLET CREATED! Total wallets on chain: {}", total_wallets);
        }
        
        // Log mint transaction to ledger with enhanced fields
        let tx_record = TransactionRecord::new(
            TxType::Mint,
            "USDC_TREASURY",
            address,
            add_lamports,
            0, // nonce
            0, // balance_before (treasury has unlimited)
            0, // balance_after (treasury unchanged)
            new_lamports, // recipient_balance_after
            AuthType::SystemInternal,
        );
        
        if let Err(e) = self.log_transaction(tx_record) {
            warn!("Failed to log mint transaction: {}", e);
        }
        
        // ═══ SVM TX RECEIPT: So faucet mints show in explorer ═══
        {
            use sha2::{Sha256, Digest};
            let slot = self.block_height.load(Ordering::Relaxed);
            let lamport_amount = add_lamports as i64;
            // Deterministic signature from mint details
            let sig_input = format!("MINT:{}:{}:{}", address, amount, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
            let sig_hash: [u8; 32] = Sha256::digest(sig_input.as_bytes()).into();
            let sig_b58 = bs58::encode(&sig_hash).into_string();
            let stored = crate::svm::types::StoredTransactionResult {
                signature: sig_b58,
                slot,
                success: true,
                error_msg: String::new(),
                compute_units_consumed: 100,
                fee: 0,
                account_keys: vec!["TREASURY".to_string(), address.to_string()],
                lamport_deltas: vec![
                    ("TREASURY".to_string(), -lamport_amount),
                    (address.to_string(), lamport_amount),
                ],
                block_time: chrono::Utc::now().timestamp(),
            };
            if let Err(e) = self.svm_accounts.store_transaction_result(&stored) {
                warn!("Failed to store SVM mint receipt: {}", e);
            }
        }
        
        info!(address = %address, amount = amount, new_balance = new_lamports as f64 / LAMPORTS_PER_BB as f64, "✅ Tokens ADDED to wallet");
        Ok(())
    }

    /// Debit (subtract) tokens from an address — SVM-native
    ///
    /// Converts f64 BB → u64 lamports ONCE at entry, then operates entirely
    /// in u64 through the SVM AccountsDB. Mirrors to cache/ReDB after.
    pub fn debit(&self, address: &str, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }

        // ═══ SINGLE CONVERSION: f64 → u64 at the boundary ═══
        let sub_lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        if sub_lamports == 0 {
            return Err("Amount too small to represent in lamports".to_string());
        }

        // ═══ SVM: Read current, check sufficient, write ═══
        let pk = Self::addr_to_pubkey(address);
        let current_lamports = self.svm_accounts.get_lamports(&pk);
        
        if current_lamports < sub_lamports {
            return Err(format!(
                "Insufficient funds: have {:.6}, need {:.6}",
                current_lamports as f64 / LAMPORTS_PER_BB as f64, amount
            ));
        }
        
        let new_lamports = current_lamports - sub_lamports;
        
        let account = AccountSharedData::new(
            new_lamports,
            0,
            &solana_sdk::system_program::id(),
        );
        self.svm_accounts.store_account(&pk, account);

        // ═══ MIRROR to cache/ReDB (non-authoritative) ═══
        self.mirror_balance_to_cache(address, new_lamports);
        
        // Update total supply
        self.total_supply.fetch_sub(sub_lamports, Ordering::Relaxed);
        
        let new_balance_bb = new_lamports as f64 / LAMPORTS_PER_BB as f64;
        // Log burn transaction to ledger with enhanced fields
        let tx_record = TransactionRecord::new(
            TxType::Burn,
            address,
            "DESTROYED",
            sub_lamports,
            0, // nonce
            current_lamports,
            new_lamports,
            0, // recipient_balance_after (destroyed)
            AuthType::SystemInternal,
        );
        
        if let Err(e) = self.log_transaction(tx_record) {
            warn!("Failed to log burn transaction: {}", e);
        }
        
        info!(address = %address, amount = amount, new_balance = new_balance_bb, "✅ Tokens SUBTRACTED from wallet");
        Ok(())
    }

    /// Buffer a transaction for batch persistence at block boundaries.
    ///
    /// Instead of opening a ReDB write transaction per tx (which forces an
    /// fsync each time and caps throughput at ~500 TPS), we accumulate
    /// records in memory and flush them all in one ACID commit via
    /// `flush_tx_log_buffer()`.
    pub fn log_transaction(&self, mut tx_record: TransactionRecord) -> Result<(), String> {
        // Set block height from current chain state
        tx_record.block_height = self.block_height.load(Ordering::Relaxed);
        
        // Get previous transaction hash for chain linking
        tx_record.prev_tx_hash = self.get_last_tx_hash().unwrap_or_else(|| "GENESIS".to_string());
        
        // Increment block height for next transaction
        self.block_height.fetch_add(1, Ordering::Relaxed);

        // Push into the in-memory buffer — NO disk I/O here
        self.tx_log_buffer.lock().push(tx_record);
        
        Ok(())
    }

    /// Flush all buffered transaction logs to ReDB in a single ACID commit.
    ///
    /// Called once per slot (400ms) by the block production loop.
    /// This converts N per-tx fsyncs into 1 batched fsync — critical for
    /// achieving 600K TPS throughput.
    pub fn flush_tx_log_buffer(&self) -> Result<usize, String> {
        let records: Vec<TransactionRecord> = {
            let mut buf = self.tx_log_buffer.lock();
            if buf.is_empty() { return Ok(0); }
            std::mem::take(&mut *buf)
        };

        let count = records.len();
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(TRANSACTIONS).map_err(|e| e.to_string())?;
            for record in &records {
                let tx_json = serde_json::to_vec(record)
                    .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
                table.insert(record.tx_id.as_str(), tx_json.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        Ok(count)
    }
    
    /// Get the hash of the last transaction for chain linking
    fn get_last_tx_hash(&self) -> Option<String> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(TRANSACTIONS).ok()?;
        
        let mut latest_tx: Option<TransactionRecord> = None;
        let iter = table.iter().ok()?;
        
        for (_, value) in iter.flatten() {
            if let Ok(tx) = serde_json::from_slice::<TransactionRecord>(value.value()) {
                if latest_tx.is_none() || tx.timestamp > latest_tx.as_ref().unwrap().timestamp {
                    latest_tx = Some(tx);
                }
            }
        }
        
        latest_tx.map(|tx| tx.tx_hash)
    }

    /// Get all transactions (optionally filtered by address)
    pub fn get_transactions(&self, address: Option<&str>, limit: usize, offset: usize) -> Result<Vec<TransactionRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(TRANSACTIONS).map_err(|e| e.to_string())?;
        
        let mut transactions = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        
        for result in iter {
            let (_, value) = result.map_err(|e| e.to_string())?;
            let tx_data = value.value();
            
            if let Ok(tx_record) = serde_json::from_slice::<TransactionRecord>(tx_data) {
                // Filter by address if specified
                if let Some(addr) = address {
                    if tx_record.from_address != addr && tx_record.to_address != addr {
                        continue;
                    }
                }
                transactions.push(tx_record);
            }
        }
        
        // Sort by timestamp (newest first)
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Apply pagination
        let end = std::cmp::min(offset + limit, transactions.len());
        Ok(transactions.get(offset..end).unwrap_or(&[]).to_vec())
    }

    /// Get all recent transactions (for ledger display)
    pub fn get_all_transactions(&self, limit: usize) -> Vec<TransactionRecord> {
        self.get_transactions(None, limit, 0).unwrap_or_default()
    }

    /// Retrieve a specific transaction by its tx_id
    pub fn get_tx_by_id(&self, tx_id: &str) -> Result<Option<TransactionRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(TRANSACTIONS).map_err(|e| e.to_string())?;
        let result = table.get(tx_id).map_err(|e| e.to_string())?;
        
        if let Some(guard) = result {
            let record: TransactionRecord = serde_json::from_slice(guard.value()).map_err(|e| e.to_string())?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Retrieve a specific transaction by its tx_hash (hex string).
    /// Falls back to a full scan — use only for explorer lookup.
    pub fn get_tx_by_hash(&self, tx_hash: &str) -> Result<Option<TransactionRecord>, String> {
        let all = self.get_transactions(None, usize::MAX, 0).unwrap_or_default();
        Ok(all.into_iter().find(|r| r.tx_hash == tx_hash))
    }

    /// Transfer tokens between addresses (atomic) — legacy API (no SVM receipt).
    pub fn transfer(&self, from: &str, to: &str, amount: f64) -> Result<(), String> {
        self.transfer_inner(from, to, amount, AuthType::SystemInternal)
    }

    /// Core atomic transfer — SVM-native.
    ///
    /// Converts f64 → u64 ONCE, then does the entire debit/credit in u64
    /// lamports through SVM AccountsDB. Mirrors to cache/ReDB after.
    fn transfer_inner(&self, from: &str, to: &str, amount: f64, auth_type: AuthType) -> Result<(), String> {
        if amount <= 0.0 {
            return Err("Amount must be positive".to_string());
        }
        if from == to {
            return Err("Cannot transfer to self".to_string());
        }

        // ═══ SINGLE CONVERSION: f64 → u64 at the boundary ═══
        let lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        if lamports == 0 {
            return Err("Amount too small to represent in lamports".to_string());
        }

        // ═══ SVM: Atomic debit sender + credit receiver ═══
        let from_pk = Self::addr_to_pubkey(from);
        let to_pk = Self::addr_to_pubkey(to);
        
        let from_current = self.svm_accounts.get_lamports(&from_pk);
        if from_current < lamports {
            return Err(format!(
                "Insufficient funds: have {:.6}, need {:.6}",
                from_current as f64 / LAMPORTS_PER_BB as f64, amount
            ));
        }
        
        let from_new_lamports = from_current - lamports;
        let to_current = self.svm_accounts.get_lamports(&to_pk);
        let to_new_lamports = to_current.checked_add(lamports)
            .ok_or("Receiver balance overflow")?;
        
        // Write both accounts to SVM
        let from_account = AccountSharedData::new(
            from_new_lamports, 0, &solana_sdk::system_program::id(),
        );
        let to_account = AccountSharedData::new(
            to_new_lamports, 0, &solana_sdk::system_program::id(),
        );
        self.svm_accounts.store_account(&from_pk, from_account);
        self.svm_accounts.store_account(&to_pk, to_account);
        
        // ═══ MIRROR to cache/ReDB (non-authoritative) ═══
        self.mirror_balance_to_cache(from, from_new_lamports);
        self.mirror_balance_to_cache(to, to_new_lamports);
        
        // Compute f64 values for logging only
        
        // Log transaction to ledger with enhanced fields
        let tx_record = TransactionRecord::new(
            TxType::Transfer,
            from,
            to,
            lamports,
            {
                let mut entry = self.account_nonces.entry(from.to_string()).or_insert(0);
                *entry.value_mut() += 1;
                *entry.value()
            },
            from_current,
            from_new_lamports,
            to_new_lamports,
            auth_type,
        );
        
        if let Err(e) = self.log_transaction(tx_record) {
            warn!("Failed to log transaction: {}", e);
        }
        
        info!(
            from = %from, 
            to = %to, 
            amount = amount,
            "Transfer successful"
        );
        Ok(())
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /// Get blockchain statistics
    pub fn stats(&self) -> BlockchainStats {
        let account_count = self.cache.len();
        BlockchainStats {
            total_accounts: account_count as u64,
            block_count: self.block_height.load(Ordering::Relaxed),
            total_supply: self.total_supply(),
            cache_hit_rate: 0.99, // DashMap is extremely fast
        }
    }

    // ========================================================================
    // BLOCK PERSISTENCE (PoH Blocks → ReDB)
    // ========================================================================

    /// Persist a FinalizedBlock to ReDB (BLOCKS table: slot → bincode)
    pub fn store_block(&self, slot: u64, block: &crate::poh_blockchain::FinalizedBlock) -> Result<(), String> {
        let encoded = serde_json::to_vec(block)
            .map_err(|e| format!("Block serialization failed: {e}"))?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(BLOCKS).map_err(|e| e.to_string())?;
            table.insert(slot, encoded.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        self.block_height.fetch_max(slot + 1, Ordering::Relaxed);
        Ok(())
    }

    /// Load a FinalizedBlock from ReDB by slot number
    pub fn load_block(&self, slot: u64) -> Result<Option<crate::poh_blockchain::FinalizedBlock>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(BLOCKS).map_err(|e| e.to_string())?;
        match table.get(slot).map_err(|e| e.to_string())? {
            Some(data) => {
                let block: crate::poh_blockchain::FinalizedBlock = serde_json::from_slice(data.value())
                    .map_err(|e| format!("Block deserialization failed: {e}"))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get the highest stored block slot from ReDB
    pub fn latest_block_slot(&self) -> Result<Option<u64>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(BLOCKS).map_err(|e| e.to_string())?;
        let result = match table.last().map_err(|e| e.to_string())? {
            Some((slot, _)) => Ok(Some(slot.value())),
            None => Ok(None),
        };
        result
    }

    // ========================================================================
    // ESCROW STORAGE (ReDB-backed)
    // ========================================================================

    /// Store a merkle root for a market settlement (strictly 32 bytes — SHA-256)
    pub fn store_escrow_market_root(&self, market_id: &str, data: &[u8; 32]) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(ESCROW_MARKET_ROOTS).map_err(|e| e.to_string())?;
            table.insert(market_id, data.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        info!(market_id = %market_id, "Stored escrow market root in ReDB");
        Ok(())
    }

    /// Fetch a single market root (used when verifying a user's Merkle proof)
    pub fn get_escrow_market_root(&self, market_id: &str) -> Result<Option<Vec<u8>>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(ESCROW_MARKET_ROOTS).map_err(|e| e.to_string())?;
        let result = table.get(market_id).map_err(|e| e.to_string())?;
        Ok(result.map(|guard| guard.value().to_vec()))
    }

    /// Record that a user has claimed their withdrawal for a market
    /// claim_key MUST be formatted as "{market_id}:{user_pubkey}"
    pub fn store_escrow_claim(&self, claim_key: &str, timestamp: u64) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(ESCROW_CLAIMS).map_err(|e| e.to_string())?;
            table.insert(claim_key, timestamp).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        info!(claim_key = %claim_key, "Stored escrow claim in ReDB");
        Ok(())
    }

    /// Check if a user has already claimed their payout
    pub fn has_escrow_claim(&self, claim_key: &str) -> Result<bool, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(ESCROW_CLAIMS).map_err(|e| e.to_string())?;
        let result = table.get(claim_key).map_err(|e| e.to_string())?;
        Ok(result.is_some())
    }

    /// Load all market roots from ReDB (startup recovery)
    pub fn load_all_escrow_market_roots(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(ESCROW_MARKET_ROOTS).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (key, value) = entry.map_err(|e| e.to_string())?;
            results.push((key.value().to_string(), value.value().to_vec()));
        }
        Ok(results)
    }

    // ========================================================================
    // DEPOSIT GATEWAY STORAGE (ReDB-backed)
    // ========================================================================

    /// Store (or overwrite) a deposit request record, keyed by external_tx_hash.
    pub fn store_deposit_request(&self, record: &DepositRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(DEPOSIT_REQUESTS).map_err(|e| e.to_string())?;
            table.insert(record.external_tx_hash.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load all deposit request records from ReDB (called at startup).
    pub fn load_all_deposit_requests(&self) -> Result<Vec<DepositRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(DEPOSIT_REQUESTS).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<DepositRecord>(value.value()) {
                results.push(record);
            }
        }
        Ok(results)
    }

    /// Check if an external tx hash has already been minted (replay protection).
    pub fn is_bridge_tx_processed(&self, tx_hash: &str) -> bool {
        self.processed_bridge_txs.contains_key(tx_hash)
    }

    /// Mark an external tx hash as processed and persist to ReDB.
    pub fn mark_bridge_tx_processed(&self, tx_hash: &str, mint_tx_id: &str) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(PROCESSED_BRIDGE_TXS).map_err(|e| e.to_string())?;
            table.insert(tx_hash, mint_tx_id).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        self.processed_bridge_txs.insert(tx_hash.to_string(), mint_tx_id.to_string());
        Ok(())
    }

    /// Persist a withdrawal record (insert or overwrite).
    pub fn store_withdrawal(&self, record: &WithdrawalRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(WITHDRAWALS).map_err(|e| e.to_string())?;
            table.insert(record.withdrawal_id.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load all withdrawal records from ReDB (for startup recovery).
    pub fn load_all_withdrawals(&self) -> Result<Vec<WithdrawalRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(WITHDRAWALS).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_key, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<WithdrawalRecord>(value.value()) {
                results.push(record);
            }
        }
        Ok(results)
    }

    // ========================================================================
    // CONTEST STATE STORAGE (ReDB-backed)
    // ========================================================================

    /// Persist (insert or overwrite) a contest state record, keyed by contest_id.
    pub fn store_contest_state(&self, state: &ContestState) -> Result<(), String> {
        let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(CONTEST_STATES).map_err(|e| e.to_string())?;
            table.insert(state.contest_id.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load a single contest state by contest_id.
    pub fn load_contest_state(&self, contest_id: &str) -> Result<Option<ContestState>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(CONTEST_STATES).map_err(|e| e.to_string())?;
        let result = table.get(contest_id).map_err(|e| e.to_string())?;
        match result {
            None => Ok(None),
            Some(guard) => serde_json::from_slice::<ContestState>(guard.value())
                .map(Some)
                .map_err(|e| e.to_string()),
        }
    }

    /// Load all contest states from ReDB (startup recovery).
    pub fn load_all_contest_states(&self) -> Result<Vec<ContestState>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(CONTEST_STATES).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_key, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<ContestState>(value.value()) {
                results.push(record);
            }
        }
        Ok(results)
    }

    /// Load all claims from ReDB (startup recovery)
    pub fn load_all_escrow_claims(&self) -> Result<Vec<(String, u64)>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(ESCROW_CLAIMS).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (key, value) = entry.map_err(|e| e.to_string())?;
            results.push((key.value().to_string(), value.value()));
        }
        Ok(results)
    }

    // ── Layer 5: Creator Coin storage ─────────────────────────────────────────

    pub fn store_creator_coin(&self, record: &CreatorCoinRecord) -> Result<(), String> {
        let json = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(CREATOR_COINS).map_err(|e| e.to_string())?;
            table.insert(record.ticker.as_str(), json.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    pub fn load_all_creator_coins(&self) -> Result<Vec<CreatorCoinRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read_txn.open_table(CREATOR_COINS) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()), // table not yet created
        };
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_key, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<CreatorCoinRecord>(value.value()) {
                results.push(record);
            }
        }
        Ok(results)
    }

    pub fn store_coin_pool(&self, pool: &CoinPoolState) -> Result<(), String> {
        let json = serde_json::to_vec(pool).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(COIN_POOLS).map_err(|e| e.to_string())?;
            table.insert(pool.ticker.as_str(), json.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    pub fn load_all_coin_pools(&self) -> Result<Vec<CoinPoolState>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read_txn.open_table(COIN_POOLS) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_key, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(pool) = serde_json::from_slice::<CoinPoolState>(value.value()) {
                results.push(pool);
            }
        }
        Ok(results)
    }

    pub fn store_coin_balance(&self, key: &str, amount: u64) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(COIN_BALANCES).map_err(|e| e.to_string())?;
            table.insert(key, amount).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    pub fn load_all_coin_balances(&self) -> Result<Vec<(String, u64)>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read_txn.open_table(COIN_BALANCES) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (key, value) = entry.map_err(|e| e.to_string())?;
            results.push((key.value().to_string(), value.value()));
        }
        Ok(results)
    }
}

// ============================================================================
// DEPOSIT GATEWAY RECORD
// ============================================================================

/// A single on-chain record of a user's wUSDC → BB deposit request.
/// Keyed by the external chain tx hash.  Minimal — extend later as needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositRecord {
    /// BB wallet address (base58) that will receive the minted tokens
    pub wallet_address: String,
    /// Transaction hash from the external chain (Ethereum, Solana, etc.)
    pub external_tx_hash: String,
    /// "USDC" or "USDT"
    pub asset: String,
    /// Amount of stablecoin the user deposited to the custody wallet
    pub amount_stablecoin: f64,
    /// BB to mint: amount_stablecoin / 10  (10 USDC = 1 BB)
    pub bb_to_mint: f64,
    /// "pending" | "approved" | "rejected"
    pub status: String,
    /// Unix timestamp of the original user request
    pub submitted_at: u64,
    /// Unix timestamp when the dealer approved (None if still pending)
    pub approved_at: Option<u64>,
}

// ============================================================================
// WITHDRAWAL GATEWAY RECORD
// ============================================================================

/// A record of a user's wUSDC → real USDC (Solana) withdrawal request.
/// Keyed by withdrawal_id (UUID). Created atomically when the user burns wUSDC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalRecord {
    /// UUID assigned at request time — used as the primary key
    pub withdrawal_id: String,
    /// BB wallet address (base58) whose wUSDC was burned
    pub wallet_address: String,
    /// Solana wallet address (base58) where the dealer should send real USDC
    pub solana_destination: String,
    /// Amount of wUSDC burned (= amount of real USDC owed to user)
    pub wusdc_amount: f64,
    /// "pending" | "released" | "rejected"
    pub status: String,
    /// Unix timestamp of the original user request
    pub requested_at: u64,
    /// Unix timestamp when the dealer released (None if still pending)
    pub released_at: Option<u64>,
    /// Solana transaction hash the dealer used to send real USDC (set on release)
    pub solana_tx_hash: Option<String>,
}

// ============================================================================
// CONTEST STATE
// ============================================================================

/// Lifecycle status of a BB market settlement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ContestStatus {
    /// Accepting deposits; no merkle root yet.
    Open,
    /// Merkle root submitted and finalized; users may claim.
    Settled,
    /// Claim window (6,480,000 slots ≈ 30 days) elapsed.
    Expired,
}

/// Per-contest settlement record stored in ReDB.
///
/// All balance fields are in SPL units (1 BB = 1_000_000 units, 6 decimals).
/// The zero-sum invariant MUST hold on every `Settled` record:
///   `total_deposited == total_payout + house_rake`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContestState {
    pub contest_id: String,
    pub status: ContestStatus,
    /// SHA-256 Merkle root over all (pubkey, payout) winner leaves.
    /// Zero bytes while `status == Open`.
    pub merkle_root: [u8; 32],
    /// Total SPL units deposited into this contest escrow.
    pub total_deposited: u64,
    /// Total SPL units successfully claimed by winners so far.
    pub total_claimed: u64,
    pub winner_count: u32,
    /// Platform rake (SPL units). `total_deposited - total_payout`.
    pub house_rake: u64,
    /// Last L1 slot at which a claim is still valid.
    /// `submit_slot + CLAIM_WINDOW_SLOTS` (≈ 6_480_000).
    pub claim_deadline_slot: u64,
    /// Hash of the L1 transaction that finalized the settlement.
    pub l1_tx_hash: String,
    pub last_l2_block: u64,
    /// Unix timestamp (seconds) when the contest was first opened.
    pub created_at: u64,
}

// ============================================================================
// LAYER 5 — CREATOR COIN RECORDS
// ============================================================================

/// Metadata for a creator coin launched via the Layer 5 launchpad.
/// Immutable after launch — stored in the CREATOR_COINS ReDB table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreatorCoinRecord {
    /// Ticker symbol (2–10 uppercase alphanumeric). e.g. "MAX".
    pub ticker: String,
    /// Human-readable coin name. e.g. "Max Token".
    pub name: String,
    /// Base58 BB wallet of the creator (receives trade fees + 50% initial supply).
    pub creator_wallet: String,
    /// Unix timestamp of launch.
    pub launched_at: u64,
    /// Fixed total supply in base units (6 decimals). Always 1,000,000,000,000,000.
    pub total_supply: u64,
    /// Optional description / tagline (max 280 chars).
    pub description: Option<String>,
}

/// Constant-product AMM pool state for a creator coin.
/// Updated on every trade — stored in the COIN_POOLS ReDB table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoinPoolState {
    /// Ticker symbol (mirrors CreatorCoinRecord.ticker).
    pub ticker: String,
    /// BB in the pool, in lamports (u64, 5 decimals: 1 BB = 100_000 lamports).
    pub reserve_bb: u64,
    /// Creator coin units in the pool (6 decimals: 1 coin = 1_000_000 units).
    pub reserve_coin: u64,
    /// Cumulative BB fees sent to the creator wallet.
    pub total_fees_bb: u64,
    /// Cumulative coin fees sent to the creator wallet (from sells).
    pub total_fees_coins: u64,
    /// All-time trading volume in BB lamports.
    pub volume_bb: u64,
    /// Total number of trades executed against this pool.
    pub tx_count: u64,
    /// Unix timestamp when the pool was created.
    pub created_at: u64,
    /// Unix timestamp of the most recent trade.
    pub last_trade_at: u64,
}

// ============================================================================
// BLOCKCHAIN STATS
// ============================================================================

/// Statistics snapshot for the blockchain
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockchainStats {
    pub total_accounts: u64,

    pub block_count: u64,
    pub total_supply: f64,
    pub cache_hit_rate: f64,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_credit_debit() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        // Credit
        bc.credit("alice", 100.0).unwrap();
        assert_eq!(bc.get_balance("alice"), 100.0);

        // Debit
        bc.debit("alice", 30.0).unwrap();
        assert_eq!(bc.get_balance("alice"), 70.0);

        // Insufficient funds
        let result = bc.debit("alice", 100.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        bc.credit("alice", 100.0).unwrap();
        bc.transfer("alice", "bob", 40.0).unwrap();

        assert_eq!(bc.get_balance("alice"), 60.0);
        assert_eq!(bc.get_balance("bob"), 40.0);
    }
}
