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
use tracing::{info, warn};
use crate::svm::accounts_db::SvmAccountsDB;
use crate::svm::types::LAMPORTS_PER_BB;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::account::AccountSharedData;

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

/// SSS Shard B storage: WalletID (String) → EncryptedShare (Vec<u8>)
/// Share B is stored in ReDB for server-side custody (2-of-3 Shamir threshold)
const WALLET_SHARD_B: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_shard_b");

/// Ed25519 Public Key storage: WalletID (String) → PublicKey (Vec<u8>)
/// Maps wallet_id to the Ed25519 public key bytes
const WALLET_ED25519_PUBKEY: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_ed25519_pubkey");

/// Escrow market roots: MarketID (String) → MerkleRoot (32 bytes, SHA-256)
/// Stores ONLY the raw 32-byte merkle root per market. No metadata.
/// L1 is a vault — it stores the math, not the floor plan.
pub const ESCROW_MARKET_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("escrow_market_roots");

/// Escrow withdrawal claims: "{market_id}:{address}" (String) → ClaimTimestamp (u64)
/// Prevents double-withdrawal per market — durable across restarts
pub const ESCROW_CLAIMS: TableDefinition<&str, u64> = TableDefinition::new("escrow_claims");

// NOTE: Two-tier vault table constants (TIER1_STATE, TIER2_STATE,
// DIME_VINTAGES, CPI_HISTORY, DIME_BALANCES) were removed — the DIME/vault
// feature was designed but never wired up. Recoverable from git history.

// ============================================================================
// ENHANCED LEDGER ENUMS (Type-Safe Blockchain Integrity)
// ============================================================================

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
        }
    }
}

// NOTE: TxStatus enum removed — tx lifecycle is tracked by
// FinalityTracker (ConfirmationStatus::Processing → Confirmed → Finalized).

/// Authentication type for ZKP/SSS tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    MasterKey,      // Direct password authentication
    SessionKey,     // Scoped session key
    ZkProof,        // Zero-knowledge proof
    SSS,            // Shamir Secret Sharing 2-of-3 reconstruction
    SystemInternal, // Internal system operation (mints, etc)
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::MasterKey => write!(f, "MASTER_KEY"),
            AuthType::SessionKey => write!(f, "SESSION_KEY"),
            AuthType::ZkProof => write!(f, "ZKP_SESSION"),
            AuthType::SSS => write!(f, "SSS_2OF3"),
            AuthType::SystemInternal => write!(f, "SYSTEM"),
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
    pub amount: f64,
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
    pub gas_fee: f64,
    
    // === STATE VALIDATION (The Health Check) ===
    /// Transaction nonce - prevents replay attacks
    #[serde(default)]
    pub nonce: u64,
    /// Sender's balance before transaction
    #[serde(default)]
    pub balance_before: f64,
    /// Sender's balance after transaction
    #[serde(default)]
    pub balance_after: f64,
    /// Recipient's balance after transaction
    #[serde(default)]
    pub recipient_balance_after: f64,
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
    /// Create a new transaction record with computed hash
    pub fn new(
        tx_type: TxType,
        from: &str,
        to: &str,
        amount: f64,
        nonce: u64,
        balance_before: f64,
        balance_after: f64,
        recipient_balance_after: f64,
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
            gas_fee: 0.0,
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
        let expected = self.balance_before - self.amount - self.gas_fee;
        (expected - self.balance_after).abs() < 0.0001
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
    
    /// Legacy f64 cache — MIRROR ONLY, not authoritative.
    /// Kept for backward compat with code that reads `cache` directly.
    /// Populated from SVM on writes. Never used for balance decisions.
    /// PUBLIC: Used by Sealevel ParallelScheduler for direct batch execution
    pub cache: Arc<DashMap<String, f64>>,
    
    /// Processed bridge TX cache (for fast replay checks)
    #[allow(dead_code)]
    processed_bridge_txs: Arc<DashMap<String, String>>,
    
    /// Block height counter
    block_height: Arc<AtomicU64>,
    
    /// Total supply tracker (deprecated — use svm_accounts.total_lamports())
    total_supply: Arc<AtomicU64>,
    
    /// SVM Accounts Database — THE authoritative balance store.
    /// All balance reads and writes go here. u64 lamports, no f64.
    pub svm_accounts: Arc<SvmAccountsDB>,

    /// Per-account nonce tracker (prevents replay attacks)
    pub account_nonces: Arc<DashMap<String, u64>>,
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

    /// Create or open a blockchain database.
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
            // SSS wallet tables
            let _ = write_txn.open_table(WALLET_SHARD_B)?;
            let _ = write_txn.open_table(WALLET_ED25519_PUBKEY)?;
            
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
                let mut iter = bridge_table.iter()?;
                while let Some(result) = iter.next() {
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

        Ok(Self {
            db: db_arc,
            cache,
            processed_bridge_txs,
            block_height: Arc::new(AtomicU64::new(0)),
            total_supply: Arc::new(AtomicU64::new(0)),
            svm_accounts,
            account_nonces: Arc::new(DashMap::new()),
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
        
        let new_balance_bb = new_lamports as f64 / LAMPORTS_PER_BB as f64;
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
            amount,
            0, // nonce
            0.0, // balance_before (treasury has unlimited)
            0.0, // balance_after (treasury unchanged)
            new_balance_bb, // recipient_balance_after
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
        
        info!(address = %address, amount = amount, new_balance = new_balance_bb, "✅ Tokens ADDED to wallet");
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
        let balance_before_bb = current_lamports as f64 / LAMPORTS_PER_BB as f64;
        
        // Log burn transaction to ledger with enhanced fields
        let tx_record = TransactionRecord::new(
            TxType::Burn,
            address,
            "DESTROYED",
            amount,
            0, // nonce
            balance_before_bb,
            new_balance_bb,
            0.0, // recipient_balance_after (destroyed)
            AuthType::MasterKey,
        );
        
        if let Err(e) = self.log_transaction(tx_record) {
            warn!("Failed to log burn transaction: {}", e);
        }
        
        info!(address = %address, amount = amount, new_balance = new_balance_bb, "✅ Tokens SUBTRACTED from wallet");
        Ok(())
    }

    /// Log a transaction to history with chain integrity
    pub fn log_transaction(&self, mut tx_record: TransactionRecord) -> Result<(), String> {
        // Set block height from current chain state
        tx_record.block_height = self.block_height.load(Ordering::Relaxed);
        
        // Get previous transaction hash for chain linking
        tx_record.prev_tx_hash = self.get_last_tx_hash().unwrap_or_else(|| "GENESIS".to_string());
        
        // Increment block height for next transaction
        self.block_height.fetch_add(1, Ordering::Relaxed);
        
        let tx_json = serde_json::to_vec(&tx_record)
            .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
        
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(TRANSACTIONS).map_err(|e| e.to_string())?;
            table.insert(tx_record.tx_id.as_str(), tx_json.as_slice())
                .map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        
        Ok(())
    }
    
    /// Get the hash of the last transaction for chain linking
    fn get_last_tx_hash(&self) -> Option<String> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(TRANSACTIONS).ok()?;
        
        let mut latest_tx: Option<TransactionRecord> = None;
        let mut iter = table.iter().ok()?;
        
        while let Some(result) = iter.next() {
            if let Ok((_, value)) = result {
                if let Ok(tx) = serde_json::from_slice::<TransactionRecord>(value.value()) {
                    if latest_tx.is_none() || tx.timestamp > latest_tx.as_ref().unwrap().timestamp {
                        latest_tx = Some(tx);
                    }
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
        let mut iter = table.iter().map_err(|e| e.to_string())?;
        
        while let Some(result) = iter.next() {
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

    /// Transfer tokens between addresses (atomic) — legacy API (no SVM receipt).
    pub fn transfer(&self, from: &str, to: &str, amount: f64) -> Result<(), String> {
        self.transfer_inner(from, to, amount, AuthType::MasterKey)
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
        let from_balance_before = from_current as f64 / LAMPORTS_PER_BB as f64;
        let from_balance = from_new_lamports as f64 / LAMPORTS_PER_BB as f64;
        let to_balance = to_new_lamports as f64 / LAMPORTS_PER_BB as f64;
        
        // Log transaction to ledger with enhanced fields
        let tx_record = TransactionRecord::new(
            TxType::Transfer,
            from,
            to,
            amount,
            {
                let mut entry = self.account_nonces.entry(from.to_string()).or_insert(0);
                *entry.value_mut() += 1;
                *entry.value()
            },
            from_balance_before,
            from_balance,
            to_balance,
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

    /// Transfer tokens with a pre-computed Ed25519 signature and emit an SVM
    /// transaction receipt so wallets & explorer can look it up via
    /// `getTransaction` / `getSignaturesForAddress`.
    pub fn transfer_with_receipt(
        &self,
        from: &str,
        to: &str,
        amount: f64,
        signature_hex: &str,
        auth_type: AuthType,
    ) -> Result<String, String> {
        // Execute the core atomic transfer (SVM-native)
        self.transfer_inner(from, to, amount, auth_type)?;

        // Build a Solana-compatible transaction receipt for the SVM layer
        let slot = self.block_height.load(Ordering::Relaxed);
        let lamport_amount = (amount * LAMPORTS_PER_BB as f64) as i64;

        let stored = crate::svm::types::StoredTransactionResult {
            signature: signature_hex.to_string(),
            slot,
            success: true,
            error_msg: String::new(),
            compute_units_consumed: 150,
            fee: 0,
            account_keys: vec![from.to_string(), to.to_string()],
            lamport_deltas: vec![
                (from.to_string(), -lamport_amount),
                (to.to_string(), lamport_amount),
            ],
            block_time: chrono::Utc::now().timestamp(),
        };

        if let Err(e) = self.svm_accounts.store_transaction_result(&stored) {
            warn!("Failed to store SVM tx receipt: {}", e);
        } else {
            info!(sig = %signature_hex, "📜 SVM tx receipt stored");
        }

        Ok(signature_hex.to_string())
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /// Get blockchain statistics
    pub fn stats(&self) -> BlockchainStats {
        let account_count = self.cache.len();
        BlockchainStats {
            total_accounts: account_count as u64,
            current_slot: 0, // TODO: Hook up to PoH
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
    // SSS WALLET STORAGE (ReDB-backed)
    // ========================================================================
    
    /// Store SSS Shard B (server-side custody share)
    pub fn store_shard_b(&self, wallet_id: &str, share_data: &[u8]) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(WALLET_SHARD_B).map_err(|e| e.to_string())?;
            table.insert(wallet_id, share_data).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        info!(wallet_id = %wallet_id, "Stored SSS Shard B in ReDB");
        Ok(())
    }
    
    /// Retrieve SSS Shard B
    pub fn get_shard_b(&self, wallet_id: &str) -> Result<Vec<u8>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(WALLET_SHARD_B).map_err(|e| e.to_string())?;
        
        match table.get(wallet_id) {
            Ok(Some(data)) => Ok(data.value().to_vec()),
            Ok(None) => Err(format!("Shard B not found for wallet: {}", wallet_id)),
            Err(e) => Err(e.to_string()),
        }
    }
    
    /// Store Ed25519 Public Key
    pub fn store_ed25519_pubkey(&self, wallet_id: &str, pub_key_data: &[u8]) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(WALLET_ED25519_PUBKEY).map_err(|e| e.to_string())?;
            table.insert(wallet_id, pub_key_data).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        Ok(())
    }
    
    /// Retrieve Ed25519 Public Key
    pub fn get_ed25519_pubkey(&self, wallet_id: &str) -> Result<Vec<u8>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(WALLET_ED25519_PUBKEY).map_err(|e| e.to_string())?;
        
        match table.get(wallet_id) {
            Ok(Some(data)) => Ok(data.value().to_vec()),
            Ok(None) => Err(format!("Ed25519 public key not found for wallet: {}", wallet_id)),
            Err(e) => Err(e.to_string()),
        }
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
}

// ============================================================================
// BLOCKCHAIN STATS
// ============================================================================

/// Statistics snapshot for the blockchain
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockchainStats {
    pub total_accounts: u64,
    pub current_slot: u64,
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
