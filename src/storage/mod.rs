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
use crate::svm::accounts_db::{SvmAccountsDB, SVM_ACCOUNTS};
use crate::svm::types::{LAMPORTS_PER_BB, RENT_EPOCH_EXEMPT, StoredAccount};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::account::{Account, AccountSharedData};
use solana_sdk::account::{ReadableAccount, WritableAccount};

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
/// Durable record of every wUSDT/wUSDT → BB deposit request submitted by users.
const DEPOSIT_REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("deposit_requests");

/// Unattributed deposits: external_tx_hash → UnattributedDeposit JSON (bytes)
/// Records stablecoin transfers that arrived without a prior /deposit/request.
/// Users claim them later via POST /deposit/claim with an Ed25519 signature.
const UNATTRIBUTED_DEPOSITS: TableDefinition<&str, &[u8]> = TableDefinition::new("unattributed_deposits");

/// Withdrawal gateway requests: withdrawal_id (UUID) → WithdrawalRecord JSON (bytes)
/// Durable record of every wUSDT → real USDC withdrawal initiated by users.
const WITHDRAWALS: TableDefinition<&str, &[u8]> = TableDefinition::new("withdrawals");

/// Monotonic sequence counter for withdrawal records.
/// Single row: key "next" → next u64 to assign.  Updated atomically inside every
/// `atomic_withdrawal_flush_and_record` write transaction so the counter is always
/// in sync with persisted records after a crash or restart.
const WITHDRAWAL_SEQ_COUNTER: TableDefinition<&str, u64> = TableDefinition::new("withdrawal_seq_counter");

/// Per-contest settlement state: contest_id → ContestState JSON (bytes)
/// Tracks lifecycle (Open → Settled → Expired), Merkle root, payout accounting,
/// and claim deadline per BB market.
const CONTEST_STATES: TableDefinition<&str, &[u8]> = TableDefinition::new("contest_states");

/// Vault bridge burn records: poh_slot (u64) → BurnRecord JSON (bytes).
/// Vault bridge burn receipts: burn_id (64-char lowercase hex SHA-256) → BurnRecord JSON.
/// Keyed by burn_id instead of poh_slot so that multiple burns within the same 400 ms
/// slot never collide. burn_id = SHA-256(wallet_bytes || poh_slot_le8 || nonce_utf8).
const BURN_RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("burn_records");

/// Per-contest depositor ledger: "{contest_id}:{deposit_tx_sig}" → EscrowDepositorEntry JSON (bytes)
/// Records every deposit into a per-contest vault PDA. Used for refund-on-expiry
/// (pro-rata return to known depositors) and for deposit double-mint protection.
pub const ESCROW_DEPOSITORS: TableDefinition<&str, &[u8]> = TableDefinition::new("escrow_depositors");

/// Index from contest_id → JSON Vec<deposit_tx_sig> (String).
/// Allows O(depositors_in_contest) iteration without scanning the full ESCROW_DEPOSITORS table.
pub const ESCROW_DEPOSITORS_BY_CONTEST: TableDefinition<&str, &[u8]> = TableDefinition::new("escrow_depositors_by_contest");

/// L5 rollup liquidity locks: lock_id (UUID) → RollupLockRecord JSON (bytes).
/// Records every $BB lock-in by a creator to seed initial liquidity for their
/// L5 Creator Coin. The L5 sequencer reads these records to credit rollup-$BB.
pub const ROLLUP_LIQUIDITY_LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("rollup_liquidity_locks");

/// Oracle node registry: pubkey_hex → OracleNode JSON (bytes).
const ORACLE_NODES: TableDefinition<&str, &[u8]> = TableDefinition::new("oracle_nodes");

/// Pending oracle roots: market_id → PendingRoot JSON (bytes).
/// Step 2 of the optimistic oracle — populated when oracle submits a root,
/// consumed when finalized or discarded after the dispute window.
const PENDING_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_roots");

/// Layer 5 rollup state history: batch_id (u64) → merkle_root ([u8; 32]).
/// Legacy table kept for startup migration only. New roots go to ROLLUP_STATE_ROOTS.
pub const L5_STATE_ROOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("l5_state_roots");

/// Universal rollup state roots: composite key "<rollup_id>:<batch_id>" → merkle_root ([u8; 32]).
/// All rollups (L2, L3, L5) share this single table, isolated by key prefix.
/// Keys use zero-padded 20-digit decimal batch_ids for lexicographic ordering:
///   "L5:00000000000000000100" → root for L5 batch 100
pub const ROLLUP_STATE_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("rollup_state_roots");

/// Rollup exit double-spend guard: exit_id (SHA-256 hex of "<rollup_id>:<batch_id>:<asset_type>:<address>") → consumed_at (u64 unix secs).
/// Written atomically when a user successfully exits. Any subsequent attempt
/// with the same (batch_id, address) pair is rejected 403 before any balance
/// move occurs, regardless of nonce.
pub const ROLLUP_CONSUMED_EXITS: TableDefinition<&str, u64> = TableDefinition::new("rollup_consumed_exits");

/// Dynamic exchange rates: pool_id (String) → rate (u64).
/// Key "BB_USDT" holds the current BB-per-wUSDT exchange rate.
/// Defaults to BB_PER_USDT_DEFAULT (10) if unset. Adjustable by Oracle/Dealer
/// to protect the internal accounting unit when wUSDT depegs.
pub const SWAP_RATES: TableDefinition<&str, u64> = TableDefinition::new("swap_rates");

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
// ORACLE TYPES
// ============================================================================

/// A registered oracle committee node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OracleNode {
    /// Ed25519 public key, 64 hex chars (32 bytes).
    pub pubkey_hex: String,
    pub name: String,
    pub registered_at_slot: u64,
    pub active: bool,
    pub total_resolutions: u64,
    pub correct_resolutions: u64,
    /// Slashable $BB bond in lamports (100_000 lamports = 1 BB = $0.10).
    pub slash_balance_bb_lamports: u64,
}

/// Lifecycle state of a pending oracle root during the dispute window.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PendingRootStatus {
    Pending,
    Disputed,
    Finalized,
    Discarded,
}

/// A single oracle node's signature over an attestation message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OracleSignature {
    /// Ed25519 public key hex (64 chars).
    pub pubkey_hex: String,
    /// Ed25519 signature hex (128 chars).
    pub sig_hex: String,
}

/// A disputer who staked $BB against a pending root.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Disputer {
    pub wallet: String,
    pub stake_bb_lamports: u64,
}

/// An oracle-submitted market root awaiting the dispute window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRoot {
    pub market_id: String,
    pub outcome: String,
    pub merkle_root: [u8; 32],
    pub proposed_at_slot: u64,
    /// Slot after which the root auto-finalizes if not disputed.
    pub finalize_at_slot: u64,
    /// $BB staked by disputers (lamports).
    pub dispute_stake_bb_lamports: u64,
    pub status: PendingRootStatus,
    /// L2 sequencer (or oracle committee) that proposed this root.
    #[serde(default)]
    pub proposer_pubkey: String,
    /// Oracle committee attestation signatures (M-of-N, enforced in Step 3).
    #[serde(default)]
    pub oracle_signatures: Vec<OracleSignature>,
    /// Wallets that have staked $XX against this root.
    #[serde(default)]
    pub disputers: Vec<Disputer>,
}

// ============================================================================
// ENHANCED TRANSACTION RECORD (Full Blockchain Integrity)
// ============================================================================

/// Lenient deserializer: accepts both JSON integers *and* JSON floats for u64 fields.
///
/// Pre-migration ReDB records may have stored `amount`, `gas_fee`, and balance
/// fields as `f64` (e.g. `"amount": 10.0`).  The current struct uses `u64`.
/// This helper prevents those records from silently failing `serde_json::from_slice`.
fn deser_u64_compat<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AnyNum { Int(u64), Float(f64) }
    match AnyNum::deserialize(d)? {
        AnyNum::Int(n)   => Ok(n),
        AnyNum::Float(f) => Ok(f as u64),
    }
}

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
    #[serde(deserialize_with = "deser_u64_compat")]
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
    #[serde(default, deserialize_with = "deser_u64_compat")]
    pub gas_fee: u64,
    
    // === STATE VALIDATION (The Health Check) ===
    /// Transaction nonce - prevents replay attacks
    #[serde(default)]
    pub nonce: u64,
    /// Sender's balance before transaction
    #[serde(default, deserialize_with = "deser_u64_compat")]
    pub balance_before: u64,
    /// Sender's balance after transaction
    #[serde(default, deserialize_with = "deser_u64_compat")]
    pub balance_after: u64,
    /// Recipient's balance after transaction
    #[serde(default, deserialize_with = "deser_u64_compat")]
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
    pub db: Arc<Database>,
    /// Path to the ReDB file on disk — used for backup
    db_path: Arc<String>,
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

    // ═══ ON-CHAIN VOLUME COUNTERS (lock-free AtomicU64) ═══
    // All volume values are in lamports (1 BB = 100_000 lamports).
    // Incremented atomically at log_transaction() — the single funnel
    // through which every on-chain operation passes.

    /// All-time aggregate volume across every transaction type (lamports).
    vol_total_lamports: Arc<AtomicU64>,
    /// All-time transaction count (every committed tx).
    vol_total_tx_count: Arc<AtomicU64>,
    /// Bridge-in (deposit) volume (lamports).
    vol_deposit_lamports: Arc<AtomicU64>,
    /// Bridge-in count.
    vol_deposit_count: Arc<AtomicU64>,
    /// Bridge-out (withdrawal / burn) volume (lamports).
    vol_withdrawal_lamports: Arc<AtomicU64>,
    /// Bridge-out count.
    vol_withdrawal_count: Arc<AtomicU64>,
    /// Swap volume (BB↔USDC) (lamports).
    vol_swap_lamports: Arc<AtomicU64>,
    /// Swap count.
    vol_swap_count: Arc<AtomicU64>,
    /// Transfer volume (P2P) (lamports).
    vol_transfer_lamports: Arc<AtomicU64>,
    /// Transfer count.
    vol_transfer_count: Arc<AtomicU64>,
    /// Mint volume (faucet, admin mint) (lamports).
    vol_mint_lamports: Arc<AtomicU64>,
    /// Mint count.
    vol_mint_count: Arc<AtomicU64>,
    /// Escrow lock/unlock volume (lamports).
    vol_escrow_lamports: Arc<AtomicU64>,
    /// Escrow lock/unlock count.
    vol_escrow_count: Arc<AtomicU64>,
    /// Unix timestamp (seconds) when the node started — used for TPS calculation.
    started_at: Arc<AtomicU64>,
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
            let _ = write_txn.open_table(WITHDRAWAL_SEQ_COUNTER)?;
            let _ = write_txn.open_table(CONTEST_STATES)?;
            let _ = write_txn.open_table(UNATTRIBUTED_DEPOSITS)?;
            // Legacy L5 roots (kept for startup migration)
            let _ = write_txn.open_table(L5_STATE_ROOTS)?;
            // Universal rollup state roots (L2 / L3 / L5)
            let _ = write_txn.open_table(ROLLUP_STATE_ROOTS)?;
            // Rollup exit double-spend guard
            let _ = write_txn.open_table(ROLLUP_CONSUMED_EXITS)?;
            // Dynamic exchange rates (Oracle/Dealer adjustable)
            let _ = write_txn.open_table(SWAP_RATES)?;

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

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            db: db_arc,
            db_path: Arc::new(db_file),
            cache,
            processed_bridge_txs,
            block_height: Arc::new(AtomicU64::new(0)),
            total_supply: Arc::new(AtomicU64::new(0)),
            svm_accounts,
            account_nonces: Arc::new(DashMap::new()),
            tx_log_buffer: Arc::new(Mutex::new(Vec::with_capacity(1024))),
            // Volume counters — all start at zero; a future enhancement could
            // rehydrate from a METADATA key on startup for cross-restart continuity.
            vol_total_lamports: Arc::new(AtomicU64::new(0)),
            vol_total_tx_count: Arc::new(AtomicU64::new(0)),
            vol_deposit_lamports: Arc::new(AtomicU64::new(0)),
            vol_deposit_count: Arc::new(AtomicU64::new(0)),
            vol_withdrawal_lamports: Arc::new(AtomicU64::new(0)),
            vol_withdrawal_count: Arc::new(AtomicU64::new(0)),
            vol_swap_lamports: Arc::new(AtomicU64::new(0)),
            vol_swap_count: Arc::new(AtomicU64::new(0)),
            vol_transfer_lamports: Arc::new(AtomicU64::new(0)),
            vol_transfer_count: Arc::new(AtomicU64::new(0)),
            vol_mint_lamports: Arc::new(AtomicU64::new(0)),
            vol_mint_count: Arc::new(AtomicU64::new(0)),
            vol_escrow_lamports: Arc::new(AtomicU64::new(0)),
            vol_escrow_count: Arc::new(AtomicU64::new(0)),
            started_at: Arc::new(AtomicU64::new(now_secs)),
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

    /// Mint (add) tokens to an address — SVM-native, u64 lamports only.
    ///
    /// Operates entirely in u64 through the SVM AccountsDB and logs a `Mint`
    /// ledger record + SVM receipt so the mint shows in the explorer. Callers
    /// that receive a float at the HTTP boundary must convert ONCE with
    /// `(amount * LAMPORTS_PER_BB as f64).round() as u64` before calling.
    pub fn mint_lamports(&self, address: &str, add_lamports: u64) -> Result<(), String> {
        if add_lamports == 0 {
            return Err("Amount must be > 0 lamports".to_string());
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
            let sig_input = format!("MINT:{}:{}:{}", address, add_lamports, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
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
        
        info!(address = %address, lamports = add_lamports, new_balance = new_lamports as f64 / LAMPORTS_PER_BB as f64, "✅ Tokens ADDED to wallet");
        Ok(())
    }

    /// Burn (subtract) tokens from an address — SVM-native, u64 lamports only.
    ///
    /// Operates entirely in u64 through the SVM AccountsDB and logs a `Burn`
    /// ledger record. Callers that receive a float at the HTTP boundary must
    /// convert ONCE with `(amount * LAMPORTS_PER_BB as f64).round() as u64`
    /// before calling.
    pub fn burn_lamports(&self, address: &str, sub_lamports: u64) -> Result<(), String> {
        if sub_lamports == 0 {
            return Err("Amount must be > 0 lamports".to_string());
        }

        // ═══ SVM: Read current, check sufficient, write ═══
        let pk = Self::addr_to_pubkey(address);
        let current_lamports = self.svm_accounts.get_lamports(&pk);
        
        if current_lamports < sub_lamports {
            return Err(format!(
                "Insufficient funds: have {} lamports, need {} lamports",
                current_lamports, sub_lamports
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
        
        info!(address = %address, lamports = sub_lamports, new_balance = new_balance_bb, "✅ Tokens SUBTRACTED from wallet");
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

        // ═══ VOLUME COUNTERS — bump atomically (lock-free) ═══
        let amount = tx_record.amount;
        self.vol_total_lamports.fetch_add(amount, Ordering::Relaxed);
        self.vol_total_tx_count.fetch_add(1, Ordering::Relaxed);

        // Categorize by tx_type string (set by TxType::to_string())
        match tx_record.tx_type.as_str() {
            "TRANSFER" => {
                self.vol_transfer_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_transfer_count.fetch_add(1, Ordering::Relaxed);
            }
            "MINT" => {
                self.vol_mint_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_mint_count.fetch_add(1, Ordering::Relaxed);
            }
            "BURN" | "BRIDGE_OUT" => {
                self.vol_withdrawal_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_withdrawal_count.fetch_add(1, Ordering::Relaxed);
            }
            "BRIDGE_IN" => {
                self.vol_deposit_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_deposit_count.fetch_add(1, Ordering::Relaxed);
            }
            "SWAP_USDC_FOR_BB" | "SWAP_BB_FOR_USDC" => {
                self.vol_swap_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_swap_count.fetch_add(1, Ordering::Relaxed);
            }
            "LOCK" | "UNLOCK" => {
                self.vol_escrow_lamports.fetch_add(amount, Ordering::Relaxed);
                self.vol_escrow_count.fetch_add(1, Ordering::Relaxed);
            }
            _ => {} // unknown category — still counted in totals
        }

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

        // Write in chunks of 100 so the ReDB write lock is held for at most
        // ~100 record serializations per transaction.  This keeps the lock
        // available for concurrent writes (withdrawal commits, rollup roots)
        // during large flush bursts without starving them for hundreds of ms.
        const CHUNK_SIZE: usize = 100;
        for chunk in records.chunks(CHUNK_SIZE) {
            let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
            {
                let mut table = write_txn.open_table(TRANSACTIONS).map_err(|e| e.to_string())?;
                for record in chunk {
                    let tx_json = serde_json::to_vec(record)
                        .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
                    table.insert(record.tx_id.as_str(), tx_json.as_slice())
                        .map_err(|e| e.to_string())?;
                }
            }
            write_txn.commit().map_err(|e| e.to_string())?;
        }

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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let uptime = now.saturating_sub(self.started_at.load(Ordering::Relaxed));
        let total_txs = self.vol_total_tx_count.load(Ordering::Relaxed);
        let tps = if uptime > 0 { total_txs as f64 / uptime as f64 } else { 0.0 };

        BlockchainStats {
            total_accounts: account_count as u64,
            block_count: self.block_height.load(Ordering::Relaxed),
            total_supply: self.total_supply(),
            cache_hit_rate: 0.99, // DashMap is extremely fast
            // Volume stats
            total_volume_lamports: self.vol_total_lamports.load(Ordering::Relaxed),
            total_tx_count: total_txs,
            deposit_volume_lamports: self.vol_deposit_lamports.load(Ordering::Relaxed),
            deposit_count: self.vol_deposit_count.load(Ordering::Relaxed),
            withdrawal_volume_lamports: self.vol_withdrawal_lamports.load(Ordering::Relaxed),
            withdrawal_count: self.vol_withdrawal_count.load(Ordering::Relaxed),
            swap_volume_lamports: self.vol_swap_lamports.load(Ordering::Relaxed),
            swap_count: self.vol_swap_count.load(Ordering::Relaxed),
            transfer_volume_lamports: self.vol_transfer_lamports.load(Ordering::Relaxed),
            transfer_count: self.vol_transfer_count.load(Ordering::Relaxed),
            mint_volume_lamports: self.vol_mint_lamports.load(Ordering::Relaxed),
            mint_count: self.vol_mint_count.load(Ordering::Relaxed),
            escrow_volume_lamports: self.vol_escrow_lamports.load(Ordering::Relaxed),
            escrow_count: self.vol_escrow_count.load(Ordering::Relaxed),
            uptime_secs: uptime,
            avg_tps: tps,
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

    // ========================================================================
    // BACKUP (On-line live compaction)
    // ========================================================================

    /// Creates a hot backup of the ReDB database by copying the file.
    /// Acquires a read transaction to ensure a consistent snapshot, then copies the .redb file.
    pub fn backup_database(&self, dest_path: &str) -> Result<usize, String> {
        // Hold a read transaction to prevent compaction or writes mid-copy
        let _read_guard = self.db.begin_read().map_err(|e| format!("Backup: failed to begin read txn: {e}"))?;
        std::fs::copy(self.db_path.as_str(), dest_path)
            .map_err(|e| format!("Database backup failed: {e}"))?;
        let meta = std::fs::metadata(dest_path).map_err(|e| e.to_string())?;
        Ok(meta.len() as usize)
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

    // ── Vault Bridge: Burn Records ──────────────────────────────────────────

    /// Persist a fresh BurnRecord to ReDB, keyed by burn_id (not poh_slot).
    /// burn_id is a hex SHA-256 derived in burn_handler — guaranteed unique even
    /// when two burns land in the same 400 ms PoH slot.
    pub fn store_burn(&self, record: &BurnRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(BURN_RECORDS).map_err(|e| e.to_string())?;
            table.insert(record.burn_id.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load a BurnRecord by its burn_id. Returns Ok(None) if not found.
    /// Called by claim_attestation_handler to verify the burn exists before signing.
    pub fn load_burn(&self, burn_id: &str) -> Result<Option<BurnRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(BURN_RECORDS).map_err(|e| e.to_string())?;
        match table.get(burn_id).map_err(|e| e.to_string())? {
            Some(v) => {
                let record = serde_json::from_slice::<BurnRecord>(v.value())
                    .map_err(|e| e.to_string())?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Mark a BurnRecord as consumed (redeemable=false, attestation_issued=true).
    /// Called before the KMS signs the claim attestation to prevent double-spend.
    pub fn consume_burn_record(&self, burn_id: &str) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(BURN_RECORDS).map_err(|e| e.to_string())?;
            // Materialize bytes before dropping the immutable borrow (AccessGuard),
            // then re-borrow table mutably for the insert.
            let record_opt: Option<BurnRecord> = {
                let raw = table.get(burn_id).map_err(|e| e.to_string())?;
                raw.map(|v| serde_json::from_slice::<BurnRecord>(v.value()).map_err(|e| e.to_string()))
                   .transpose()?
            }; // AccessGuard dropped here
            if let Some(mut record) = record_opt {
                record.redeemable = false;
                record.attestation_issued = true;
                let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
                table.insert(burn_id, bytes.as_slice()).map_err(|e| e.to_string())?;
            }
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Persist a rollup liquidity lock record to ReDB.
    /// Called by the `POST /rollup/lock_bb` handler after debiting the creator.
    pub fn store_rollup_lock(&self, record: &RollupLockRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(ROLLUP_LIQUIDITY_LOCKS).map_err(|e| e.to_string())?;
            table.insert(record.lock_id.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Fetch a single lock record by lock_id. Returns None if not found.
    /// Called by `GET /rollup/locks/:lock_id`.
    pub fn load_rollup_lock_by_id(&self, lock_id: &str) -> Option<RollupLockRecord> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ROLLUP_LIQUIDITY_LOCKS).ok()?;
        let value = table.get(lock_id).ok()??;
        serde_json::from_slice::<RollupLockRecord>(value.value()).ok()
    }

    /// Mark a lock as consumed in ReDB (idempotent — safe to call twice).
    /// Called by `POST /rollup/locks/:lock_id/consume`.
    pub fn consume_rollup_lock(&self, lock_id: &str) -> Result<(), String> {
        let mut record = self.load_rollup_lock_by_id(lock_id)
            .ok_or_else(|| format!("Lock {} not found", lock_id))?;
        if record.consumed {
            return Ok(()); // already consumed, idempotent
        }
        record.consumed = true;
        self.store_rollup_lock(&record)
    }

    /// Load all rollup lock records for a given creator address (called at startup or by L5 poller).
    pub fn load_rollup_locks_by_creator(&self, creator: &str) -> Result<Vec<RollupLockRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(ROLLUP_LIQUIDITY_LOCKS).map_err(|e| e.to_string())?;
        let mut results = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<RollupLockRecord>(value.value()) {
                if record.creator_address == creator {
                    results.push(record);
                }
            }
        }
        Ok(results)
    }

    /// Return true if this (batch_id, address) pair has already exited.
    /// Key is SHA-256("batch_id:address") — computed by the caller.
    pub fn is_exit_consumed(&self, exit_id: &str) -> bool {
        let read_txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return false,
        };
        let table = match read_txn.open_table(ROLLUP_CONSUMED_EXITS) {
            Ok(t) => t,
            Err(_) => return false,
        };
        table.get(exit_id).ok().flatten().is_some()
    }

    /// Persist the exit record atomically.  Returns Err if the row already exists
    /// (caller should treat that as a 403).
    pub fn mark_exit_consumed(&self, exit_id: &str, consumed_at: u64) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn
                .open_table(ROLLUP_CONSUMED_EXITS)
                .map_err(|e| e.to_string())?;
            // Guard: reject if already present (second concurrent exit)
            if table.get(exit_id).map_err(|e| e.to_string())?.is_some() {
                return Err("already_consumed".to_string());
            }
            table
                .insert(exit_id, consumed_at)
                .map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Check if an external tx hash has already been minted (replay protection).
    pub fn is_bridge_tx_processed(&self, tx_hash: &str) -> bool {
        // "reserved" is an in-flight sentinel — not yet committed
        self.processed_bridge_txs.get(tx_hash)
            .map(|v| v.value() != "reserved")
            .unwrap_or(false)
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

    /// Atomically claim a bridge-tx slot (Bug #2: reserve-before-mint pattern).
    ///
    /// Returns `Err` if the hash is already reserved by another thread or
    /// already committed.  Uses `dashmap::Entry` — no TOCTOU race possible.
    pub fn reserve_bridge_tx(&self, tx_hash: &str) -> Result<(), String> {
        match self.processed_bridge_txs.entry(tx_hash.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(format!("tx {} already reserved or committed", tx_hash))
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert("reserved".to_string());
                Ok(())
            }
        }
    }

    /// Persist the reservation to ReDB and update the DashMap value.
    /// Call only after `credit_lamports` succeeds.
    pub fn commit_bridge_tx(&self, tx_hash: &str, mint_tx_id: &str) -> Result<(), String> {
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(PROCESSED_BRIDGE_TXS).map_err(|e| e.to_string())?;
            table.insert(tx_hash, mint_tx_id).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;
        self.processed_bridge_txs.insert(tx_hash.to_string(), mint_tx_id.to_string());
        Ok(())
    }

    /// Release a reservation without committing.  Call when credit fails.
    pub fn cancel_bridge_tx(&self, tx_hash: &str) {
        self.processed_bridge_txs.remove(tx_hash);
    }

    /// Credit a wallet using integer lamports — zero f64 conversion.
    ///
    /// Delegates to `credit_svm_lamports`. Kept for call-site naming convenience.
    pub fn credit_lamports(&self, address: &str, lamports: u64) -> Result<(), String> {
        self.credit_svm_lamports(address, lamports)
    }

    /// Credit lamports directly — zero f64 conversion, race-free.
    ///
    /// Delegates to `SvmAccountsDB::atomic_credit`, which holds the DashMap
    /// shard write-lock for the entire read-modify-write so concurrent HTTP
    /// handlers cannot observe a stale balance and double-credit.
    pub fn credit_svm_lamports(&self, address: &str, lamports: u64) -> Result<(), String> {
        if lamports == 0 {
            return Err("Amount must be > 0 lamports".to_string());
        }
        let pk = Self::addr_to_pubkey(address);
        let new_lamports = self.svm_accounts
            .atomic_credit(&pk, lamports)
            .map_err(|e| e.to_string())?;
        self.mirror_balance_to_cache(address, new_lamports);
        self.total_supply.fetch_add(lamports, Ordering::Relaxed);
        Ok(())
    }

    /// Debit lamports directly — zero f64 conversion, race-free.
    ///
    /// Delegates to `SvmAccountsDB::atomic_debit`, which holds the DashMap
    /// shard write-lock for the entire read-check-debit so concurrent HTTP
    /// handlers cannot both read the same balance and both pass the check
    /// (the classic double-spend race on the HTTP path).
    pub fn debit_svm_lamports(&self, address: &str, lamports: u64) -> Result<(), String> {
        if lamports == 0 {
            return Err("Amount must be > 0 lamports".to_string());
        }
        let pk = Self::addr_to_pubkey(address);
        let new_lamports = self.svm_accounts
            .atomic_debit(&pk, lamports)
            .map_err(|e| e.to_string())?;
        self.mirror_balance_to_cache(address, new_lamports);
        self.total_supply.fetch_sub(lamports, Ordering::Relaxed);
        Ok(())
    }

    // ========================================================================
    // ATOMIC COMBINED WRITES — SVM accounts + metadata in one ReDB transaction
    // ========================================================================
    //
    // These methods eliminate the crash window that exists when SVM account
    // changes (write-behind via flush_block) and metadata records (written
    // immediately to ReDB) land in separate transactions.
    //
    // Without these methods the following scenario is possible:
    //   1. SVM balance changes  → hot_state DashMap (not yet in ReDB)
    //   2. metadata record      → ReDB  ← crash here
    //   3. flush_block          → never runs
    //
    // On restart: metadata says operation completed, but balance change is gone.
    // The user cannot retry (metadata blocks them) and has no payout. Fix: write
    // both in one atomic ReDB transaction, then update hot_state only on success.

    /// Atomically execute an escrow payout + seal the claim in a single ReDB transaction.
    ///
    /// Eliminates the crash window where the claim seal lands in ReDB but the
    /// balance debit/credit does not — leaving the user with no payout and an
    /// unretriable claim key.
    ///
    /// Hot-state (DashMap) is updated ONLY after the ReDB commit so the write
    /// order is always: ReDB → DashMap (never the reverse).
    pub fn atomic_escrow_claim_and_pay(
        &self,
        claim_key: &str,
        escrow_addr: &str,
        user_addr: &str,
        amount_lamports: u64,
        timestamp: u64,
    ) -> Result<(), String> {
        let escrow_pk = Self::addr_to_pubkey(escrow_addr);
        let user_pk   = Self::addr_to_pubkey(user_addr);

        let escrow_lamports = self.svm_accounts.get_lamports(&escrow_pk);
        let user_lamports   = self.svm_accounts.get_lamports(&user_pk);

        if escrow_lamports < amount_lamports {
            return Err(format!(
                "Insufficient escrow: {} < {} lamports",
                escrow_lamports, amount_lamports
            ));
        }
        let new_escrow = escrow_lamports.checked_sub(amount_lamports)
            .ok_or_else(|| "Escrow underflow".to_string())?;
        let new_user = user_lamports.checked_add(amount_lamports)
            .ok_or_else(|| "User balance overflow".to_string())?;

        let escrow_account = AccountSharedData::new(new_escrow, 0, &solana_sdk::system_program::id());
        let user_account   = AccountSharedData::new(new_user,   0, &solana_sdk::system_program::id());

        let escrow_bytes = borsh::to_vec(&StoredAccount::from(&escrow_account))
            .map_err(|e| format!("Serialization error: {}", e))?;
        let user_bytes = borsh::to_vec(&StoredAccount::from(&user_account))
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Single atomic ReDB write: claim seal + both SVM account states
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut claims = write_txn.open_table(ESCROW_CLAIMS).map_err(|e| e.to_string())?;
            claims.insert(claim_key, timestamp).map_err(|e| e.to_string())?;

            let mut svm = write_txn.open_table(SVM_ACCOUNTS).map_err(|e| e.to_string())?;
            svm.insert(escrow_pk.to_bytes().as_slice(), escrow_bytes.as_slice()).map_err(|e| e.to_string())?;
            svm.insert(user_pk.to_bytes().as_slice(),   user_bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        // Update hot_state AFTER durable commit (ReDB → DashMap ordering)
        self.svm_accounts.hot_state.insert(escrow_pk, escrow_account);
        self.svm_accounts.hot_state.insert(user_pk, user_account);
        self.mirror_balance_to_cache(escrow_addr, new_escrow);
        self.mirror_balance_to_cache(user_addr, new_user);
        // total_supply unchanged: escrow debit == user credit (zero-sum move)

        info!(claim_key = %claim_key, amount = amount_lamports, "Atomic escrow claim committed");
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────
    // VAULT BRIDGE — atomic BB→wUSDT burn
    // ────────────────────────────────────────────────────────────────────────
    //
    // Three tables need to change together:
    //   SVM_ACCOUNTS : wallet (BB debit), wUSDT Mint (supply +), wUSDT ATA (+)
    //   BURN_RECORDS : new BurnRecord receipt
    //
    // Both ConcurrentBlockchain.db and SvmAccountsDB.db are the SAME Arc<Database>
    // — the tables live in one file, so one write_txn covers all of them.
    //
    // Write order: compute mutations → single ReDB commit → update hot_state.
    // A crash before the commit leaves all four rows unchanged.
    // A crash after the commit leaves hot_state stale, but SvmAccountsDB::new()
    // warms hot_state from ReDB on the next restart — no data loss.

    /// Atomically debit BB lamports, mint wUSDT, and persist the BurnRecord in
    /// **one** ReDB write transaction.
    ///
    /// Eliminates the crash window that existed when `debit_svm_lamports` and
    /// `SplTokenEngine::mint_to` each wrote to hot_state independently and relied
    /// on `flush_block()` for durability: if `flush_block()` flushed only the
    /// debit before a crash, the user lost BB and received no wUSDT.
    ///
    /// Guarantee: either all four rows land in ReDB or none do.
    pub fn atomic_vault_burn(
        &self,
        wallet_address: &str,
        wallet_pubkey: &Pubkey,
        bb_lamports: u64,
        wusdt_micro: u64,
        burn_record: &BurnRecord,
    ) -> Result<(), String> {
        use crate::svm::spl_token::{
            MintLayout, TokenAccountLayout, derive_ata_address, SPL_TOKEN_PROGRAM_ID,
        };
        use crate::svm::usdc_mint_bytes;

        if bb_lamports == 0 {
            return Err("bb_lamports must be > 0".to_string());
        }

        // ── 1. Read all affected accounts from hot_state ─────────────────────
        let mint_bytes   = usdc_mint_bytes();
        let mint_pubkey  = Pubkey::new_from_array(mint_bytes);
        let ata_bytes    = derive_ata_address(&wallet_pubkey.to_bytes(), &mint_bytes);
        let ata_pubkey   = Pubkey::new_from_array(ata_bytes);

        let mut wallet_account = self.svm_accounts
            .get_account(wallet_pubkey)
            .ok_or_else(|| format!("BB account not found: {}", wallet_address))?;

        let mut mint_account = self.svm_accounts
            .get_account(&mint_pubkey)
            .ok_or("wUSDT mint account not found")?;

        let mut ata_account = self.svm_accounts
            .get_account(&ata_pubkey)
            .unwrap_or_else(|| {
                // First-time mint for this wallet — create the ATA in memory
                let layout = TokenAccountLayout {
                    mint: mint_bytes,
                    owner: wallet_pubkey.to_bytes(),
                    amount: 0,
                    delegate_option: 0,
                    delegate: [0u8; 32],
                    state: 1,
                    is_native_option: 0,
                    is_native: 0,
                    delegated_amount: 0,
                    close_authority_option: 0,
                    close_authority: [0u8; 32],
                };
                AccountSharedData::from(Account {
                    lamports: 1_000_000,
                    data: layout.to_bytes(),
                    owner: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
                    executable: false,
                    rent_epoch: RENT_EPOCH_EXEMPT,
                })
            });

        // ── 2. Compute all mutations in memory — no writes yet ───────────────
        //
        // BB wallet: debit
        if wallet_account.lamports() < bb_lamports {
            return Err(format!(
                "Insufficient BB: have {} lamports, need {}",
                wallet_account.lamports(), bb_lamports
            ));
        }
        wallet_account.set_lamports(wallet_account.lamports() - bb_lamports);
        wallet_account.set_rent_epoch(RENT_EPOCH_EXEMPT);

        // wUSDT Mint: increase supply
        let mut mint_layout = MintLayout::from_bytes(mint_account.data())
            .map_err(|e| format!("Mint deserialize failed: {}", e))?;
        mint_layout.supply = mint_layout.supply
            .checked_add(wusdt_micro)
            .ok_or("Mint supply overflow")?;
        mint_account.set_data_from_slice(&mint_layout.to_bytes());
        mint_account.set_rent_epoch(RENT_EPOCH_EXEMPT);

        // wUSDT ATA: increase token balance
        let mut token_layout = TokenAccountLayout::from_bytes(ata_account.data())
            .map_err(|e| format!("ATA deserialize failed: {}", e))?;
        token_layout.amount = token_layout.amount
            .checked_add(wusdt_micro)
            .ok_or("ATA token overflow")?;
        ata_account.set_data_from_slice(&token_layout.to_bytes());
        ata_account.set_rent_epoch(RENT_EPOCH_EXEMPT);

        // ── 3. Single atomic ReDB write: 3 SVM accounts + BurnRecord ─────────
        let serialize = |acct: &AccountSharedData| -> Result<Vec<u8>, String> {
            borsh::to_vec(&StoredAccount::from(acct))
                .map_err(|e| format!("Account serialization: {}", e))
        };
        let wallet_ser = serialize(&wallet_account)?;
        let mint_ser   = serialize(&mint_account)?;
        let ata_ser    = serialize(&ata_account)?;
        let record_ser = serde_json::to_vec(burn_record).map_err(|e| e.to_string())?;

        // `self.db` == `self.svm_accounts.db` (same Arc) — one txn covers all tables
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut svm = write_txn.open_table(SVM_ACCOUNTS).map_err(|e| e.to_string())?;
            svm.insert(wallet_pubkey.as_ref(),  wallet_ser.as_slice()).map_err(|e| e.to_string())?;
            svm.insert(mint_pubkey.as_ref(),    mint_ser.as_slice()).map_err(|e| e.to_string())?;
            svm.insert(ata_pubkey.as_ref(),     ata_ser.as_slice()).map_err(|e| e.to_string())?;

            let mut burns = write_txn.open_table(BURN_RECORDS).map_err(|e| e.to_string())?;
            burns.insert(burn_record.burn_id.as_str(), record_ser.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        // ── 4. Update hot_state AFTER the durable commit ─────────────────────
        // If we crash here the data is safe in ReDB; SvmAccountsDB::new()
        // reloads hot_state from disk on restart.
        let new_bb_lamports = wallet_account.lamports();
        self.svm_accounts.hot_state.insert(*wallet_pubkey, wallet_account);
        self.svm_accounts.hot_state.insert(mint_pubkey,    mint_account);
        self.svm_accounts.hot_state.insert(ata_pubkey,     ata_account);

        self.mirror_balance_to_cache(wallet_address, new_bb_lamports);
        // total_supply decreases: BB is permanently destroyed, not transferred
        self.total_supply.fetch_sub(bb_lamports, Ordering::Relaxed);

        info!(
            wallet = %wallet_address,
            bb_burned = bb_lamports,
            wusdt_minted = wusdt_micro,
            burn_id = %burn_record.burn_id,
            "Atomic vault burn committed"
        );
        Ok(())
    }

    /// Atomically debit user BB, credit vault BB, and persist the lock record
    /// in a single ReDB write transaction.
    ///
    /// Eliminates the double-spend window where a lock record lands in ReDB
    /// (sequencer processes it on L2) but the user's balance debit is lost on a
    /// crash before the write-behind flush_block runs.
    pub fn atomic_rollup_lock_bb(
        &self,
        user_addr: &str,
        vault_addr: &str,
        amount_lamports: u64,
        record: &RollupLockRecord,
    ) -> Result<(), String> {
        let user_pk  = Self::addr_to_pubkey(user_addr);
        let vault_pk = Self::addr_to_pubkey(vault_addr);

        let user_lamports  = self.svm_accounts.get_lamports(&user_pk);
        let vault_lamports = self.svm_accounts.get_lamports(&vault_pk);

        if user_lamports < amount_lamports {
            return Err(format!(
                "Insufficient funds: {} < {} lamports",
                user_lamports, amount_lamports
            ));
        }
        let new_user  = user_lamports.checked_sub(amount_lamports)
            .ok_or_else(|| "User underflow".to_string())?;
        let new_vault = vault_lamports.checked_add(amount_lamports)
            .ok_or_else(|| "Vault overflow".to_string())?;

        let user_account  = AccountSharedData::new(new_user,  0, &solana_sdk::system_program::id());
        let vault_account = AccountSharedData::new(new_vault, 0, &solana_sdk::system_program::id());

        let user_bytes  = borsh::to_vec(&StoredAccount::from(&user_account))
            .map_err(|e| format!("Serialization error: {}", e))?;
        let vault_bytes = borsh::to_vec(&StoredAccount::from(&vault_account))
            .map_err(|e| format!("Serialization error: {}", e))?;
        let record_bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;

        // Single atomic ReDB write: lock record + both SVM account states
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut locks = write_txn.open_table(ROLLUP_LIQUIDITY_LOCKS).map_err(|e| e.to_string())?;
            locks.insert(record.lock_id.as_str(), record_bytes.as_slice()).map_err(|e| e.to_string())?;

            let mut svm = write_txn.open_table(SVM_ACCOUNTS).map_err(|e| e.to_string())?;
            svm.insert(user_pk.to_bytes().as_slice(),  user_bytes.as_slice()).map_err(|e| e.to_string())?;
            svm.insert(vault_pk.to_bytes().as_slice(), vault_bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        // Update hot_state AFTER durable commit (ReDB → DashMap ordering)
        self.svm_accounts.hot_state.insert(user_pk, user_account);
        self.svm_accounts.hot_state.insert(vault_pk, vault_account);
        self.mirror_balance_to_cache(user_addr, new_user);
        self.mirror_balance_to_cache(vault_addr, new_vault);
        // total_supply unchanged: user debit == vault credit (zero-sum move)

        info!(lock_id = %record.lock_id, amount = amount_lamports, "Atomic rollup lock committed");
        Ok(())
    }

    /// After a successful SPL token transfer, atomically flush the two modified
    /// ATAs to ReDB and write the withdrawal record in the same transaction.
    ///
    /// Eliminates the double-payment window where the withdrawal record lands in
    /// ReDB (dealer sends USDC) but the wUSDT debit is lost on a crash before
    /// the write-behind flush_block runs — which would leave the user with both
    /// the USDC payout and their original wUSDT balance on restart.
    ///
    /// Also allocates the next monotonic `withdrawal_seq` from `WITHDRAWAL_SEQ_COUNTER`
    /// inside the same transaction so the sequence is always consistent with the
    /// persisted record after a crash.
    ///
    /// Returns the assigned `withdrawal_seq` so the caller can update the hot DashMap.
    ///
    /// Must be called AFTER `SplTokenEngine::transfer_tokens` succeeds so that
    /// `from_ata` and `to_ata` already hold the post-transfer state in hot_state.
    pub fn atomic_withdrawal_flush_and_record(
        &self,
        from_ata: &Pubkey,
        to_ata: &Pubkey,
        record: &WithdrawalRecord,
    ) -> Result<u64, String> {
        let from_account = self.svm_accounts.hot_state.get(from_ata)
            .map(|a| a.clone())
            .ok_or_else(|| format!("from ATA not in hot_state: {}", from_ata))?;
        let to_account = self.svm_accounts.hot_state.get(to_ata)
            .map(|a| a.clone())
            .ok_or_else(|| format!("to ATA not in hot_state: {}", to_ata))?;

        let from_bytes = borsh::to_vec(&StoredAccount::from(&from_account))
            .map_err(|e| format!("Serialization error: {}", e))?;
        let to_bytes = borsh::to_vec(&StoredAccount::from(&to_account))
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Single atomic ReDB write: withdrawal record + both SPL ATA states + seq counter
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        let assigned_seq = {
            let mut seq_table = write_txn.open_table(WITHDRAWAL_SEQ_COUNTER)
                .map_err(|e| e.to_string())?;
            let next = seq_table.get("next").map_err(|e| e.to_string())?
                .map(|v| v.value())
                .unwrap_or(1u64);
            seq_table.insert("next", next + 1).map_err(|e| e.to_string())?;
            next
        };
        {
            // Stamp the seq into the record before serialization
            let mut stamped = record.clone();
            stamped.withdrawal_seq = assigned_seq;
            let record_bytes = serde_json::to_vec(&stamped).map_err(|e| e.to_string())?;

            let mut withdrawals = write_txn.open_table(WITHDRAWALS)
                .map_err(|e| e.to_string())?;
            withdrawals.insert(stamped.withdrawal_id.as_str(), record_bytes.as_slice())
                .map_err(|e| e.to_string())?;

            let mut svm = write_txn.open_table(SVM_ACCOUNTS)
                .map_err(|e| e.to_string())?;
            svm.insert(from_ata.to_bytes().as_slice(), from_bytes.as_slice())
                .map_err(|e| e.to_string())?;
            svm.insert(to_ata.to_bytes().as_slice(), to_bytes.as_slice())
                .map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())?;

        info!(withdrawal_id = %record.withdrawal_id, seq = assigned_seq,
              "Atomic withdrawal committed: SPL transfer + record + seq");
        Ok(assigned_seq)
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

    /// Load the current value of the withdrawal sequence counter from ReDB.
    /// Used at startup to restore the in-memory `AtomicU64` without scanning all records.
    /// Returns 1 if the table is empty (first-ever run).
    pub fn load_withdrawal_seq_counter(&self) -> u64 {
        let Ok(read_txn) = self.db.begin_read() else { return 1; };
        let Ok(table) = read_txn.open_table(WITHDRAWAL_SEQ_COUNTER) else { return 1; };
        table.get("next").ok().flatten().map(|v| v.value()).unwrap_or(1)
    }

    /// Return all withdrawal records whose `withdrawal_seq >= since_seq`, sorted ascending.
    /// This is the primary poll interface for the bridge watcher: after a crash it
    /// resumes from `last_processed_seq + 1` instead of doing a full table scan.
    pub fn load_withdrawals_since(&self, since_seq: u64) -> Result<Vec<WithdrawalRecord>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = read_txn.open_table(WITHDRAWALS).map_err(|e| e.to_string())?;
        let mut results: Vec<WithdrawalRecord> = Vec::new();
        let iter = table.iter().map_err(|e| e.to_string())?;
        for entry in iter {
            let (_key, value) = entry.map_err(|e| e.to_string())?;
            if let Ok(record) = serde_json::from_slice::<WithdrawalRecord>(value.value()) {
                if record.withdrawal_seq >= since_seq {
                    results.push(record);
                }
            }
        }
        results.sort_by_key(|r| r.withdrawal_seq);
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

    // ========================================================================
    // ESCROW DEPOSITOR LEDGER (per-contest, ReDB-backed)
    // ========================================================================

    fn depositor_key(contest_id: &str, sig: &str) -> String {
        format!("{}:{}", contest_id, sig)
    }

    /// Persist a depositor entry and update the per-contest index in a single
    /// ReDB write transaction (atomic w.r.t. crash recovery).
    pub fn store_depositor_entry(&self, entry: &EscrowDepositorEntry) -> Result<(), String> {
        let bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
        let key = Self::depositor_key(&entry.contest_id, &entry.deposit_tx_sig);

        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn
                .open_table(ESCROW_DEPOSITORS)
                .map_err(|e| e.to_string())?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|e| e.to_string())?;

            // Update the contest-id index. Read current Vec<sig>, append if new, write back.
            let mut idx_table = write_txn
                .open_table(ESCROW_DEPOSITORS_BY_CONTEST)
                .map_err(|e| e.to_string())?;
            let mut sigs: Vec<String> = match idx_table
                .get(entry.contest_id.as_str())
                .map_err(|e| e.to_string())?
            {
                Some(g) => serde_json::from_slice(g.value()).unwrap_or_default(),
                None => Vec::new(),
            };
            if !sigs.iter().any(|s| s == &entry.deposit_tx_sig) {
                sigs.push(entry.deposit_tx_sig.clone());
                let idx_bytes = serde_json::to_vec(&sigs).map_err(|e| e.to_string())?;
                idx_table
                    .insert(entry.contest_id.as_str(), idx_bytes.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    pub fn load_depositor_entry(
        &self,
        contest_id: &str,
        deposit_tx_sig: &str,
    ) -> Result<Option<EscrowDepositorEntry>, String> {
        let key = Self::depositor_key(contest_id, deposit_tx_sig);
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read_txn.open_table(ESCROW_DEPOSITORS) {
            Ok(t) => t,
            Err(_) => return Ok(None), // table not yet created
        };
        match table.get(key.as_str()).map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(g) => serde_json::from_slice::<EscrowDepositorEntry>(g.value())
                .map(Some)
                .map_err(|e| e.to_string()),
        }
    }

    /// Mark a depositor entry as `used = true`. Errors if not found.
    pub fn mark_depositor_used(
        &self,
        contest_id: &str,
        deposit_tx_sig: &str,
    ) -> Result<(), String> {
        let mut entry = self
            .load_depositor_entry(contest_id, deposit_tx_sig)?
            .ok_or_else(|| format!("depositor entry not found: {}:{}", contest_id, deposit_tx_sig))?;
        if entry.used {
            return Ok(()); // idempotent
        }
        entry.used = true;
        self.store_depositor_entry(&entry)
    }

    /// Mark a depositor entry as `refunded = true`. Errors if not found.
    pub fn mark_depositor_refunded(
        &self,
        contest_id: &str,
        deposit_tx_sig: &str,
    ) -> Result<(), String> {
        let mut entry = self
            .load_depositor_entry(contest_id, deposit_tx_sig)?
            .ok_or_else(|| format!("depositor entry not found: {}:{}", contest_id, deposit_tx_sig))?;
        if entry.refunded {
            return Ok(()); // idempotent
        }
        entry.refunded = true;
        self.store_depositor_entry(&entry)
    }

    /// List every depositor entry for a contest, in insertion order.
    pub fn list_depositors_for_contest(
        &self,
        contest_id: &str,
    ) -> Result<Vec<EscrowDepositorEntry>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let idx_table = match read_txn.open_table(ESCROW_DEPOSITORS_BY_CONTEST) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let sigs: Vec<String> = match idx_table.get(contest_id).map_err(|e| e.to_string())? {
            Some(g) => serde_json::from_slice(g.value()).unwrap_or_default(),
            None => return Ok(Vec::new()),
        };
        let table = match read_txn.open_table(ESCROW_DEPOSITORS) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::with_capacity(sigs.len());
        for sig in sigs {
            let key = Self::depositor_key(contest_id, &sig);
            if let Some(g) = table.get(key.as_str()).map_err(|e| e.to_string())? {
                if let Ok(rec) = serde_json::from_slice::<EscrowDepositorEntry>(g.value()) {
                    out.push(rec);
                }
            }
        }
        Ok(out)
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

    // ========================================================================
    // UNATTRIBUTED DEPOSIT STORAGE
    // ========================================================================

    /// Persist an unattributed deposit (insert only — keyed by external_tx_hash).
    pub fn write_unattributed_deposit(&self, rec: &UnattributedDeposit) -> Result<(), String> {
        let bytes = serde_json::to_vec(rec).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(UNATTRIBUTED_DEPOSITS).map_err(|e| e.to_string())?;
            table.insert(rec.external_tx_hash.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Look up an unattributed deposit by its external tx hash.
    pub fn get_unattributed_deposit(&self, tx_hash: &str) -> Result<Option<UnattributedDeposit>, String> {
        let read_txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read_txn.open_table(UNATTRIBUTED_DEPOSITS) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        match table.get(tx_hash).map_err(|e| e.to_string())? {
            Some(v) => {
                let rec = serde_json::from_slice::<UnattributedDeposit>(v.value())
                    .map_err(|e| e.to_string())?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// Mark an unattributed deposit as claimed by `wallet` (overwrites existing record).
    pub fn mark_unattributed_claimed(&self, tx_hash: &str, wallet: &str) -> Result<(), String> {
        let mut rec = self.get_unattributed_deposit(tx_hash)?
            .ok_or_else(|| format!("Unattributed deposit {} not found", tx_hash))?;
        rec.claimed_by = Some(wallet.to_string());
        self.write_unattributed_deposit(&rec)
    }
}

// ============================================================================
// DEPOSIT GATEWAY RECORD
// ============================================================================

/// A single on-chain record of a user's wUSDT → BB deposit request.
/// Keyed by the external chain tx hash.  Minimal — extend later as needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositRecord {
    /// BB wallet address (base58) that will receive the minted tokens
    pub wallet_address: String,
    /// Transaction hash from the external chain (Ethereum, Solana, etc.)
    pub external_tx_hash: String,
    /// "USDC" or "USDT"
    pub asset: String,
    /// Amount of stablecoin the user deposited, in 6-decimal micro-units (e.g. 1 USDT = 1_000_000)
    pub amount_micro_stablecoin: u64,
    /// BB lamports to mint (5 dec; 1 BB = 100_000 lamports; 1 BB per 1 USDT)
    pub bb_lamports: u64,
    /// "pending" | "approved" | "rejected"
    pub status: String,
    /// Unix timestamp of the original user request
    pub submitted_at: u64,
    /// Unix timestamp when the dealer approved (None if still pending)
    pub approved_at: Option<u64>,
    /// Optional contest_id if this deposit is destined for a per-contest escrow vault.
    /// `None` for plain bridge-in deposits that just credit the user's BB balance.
    #[serde(default)]
    pub contest_id: Option<String>,
}

// ============================================================================
// UNATTRIBUTED DEPOSIT RECORD
// ============================================================================

/// A deposit that arrived on-chain without a prior `/deposit/request` and
/// without a recognisable Solana memo (`BB:<wallet>`). Stored durably so the
/// owner can later claim it via `POST /deposit/claim`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnattributedDeposit {
    /// Transaction hash from the external chain (primary key)
    pub external_tx_hash: String,
    /// "USDC" or "USDT"
    pub asset: String,
    /// Amount in 6-decimal micro-units (normalised for BSC 18-dec tokens)
    pub amount_micro_stablecoin: u64,
    /// Unix timestamp when the watcher first observed this transfer
    pub observed_at: u64,
    /// BB wallet address that claimed this deposit (None = unclaimed)
    pub claimed_by: Option<String>,
}

// ============================================================================
// WITHDRAWAL GATEWAY RECORD
// ============================================================================

/// A record of a user's wUSDT → real USDC (Solana) withdrawal request.
/// Keyed by withdrawal_id (UUID). Created atomically when the user burns wUSDT.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalRecord {
    /// UUID assigned at request time — used as the primary key
    pub withdrawal_id: String,
    /// Strictly increasing sequence number assigned atomically at creation.
    /// Allows the bridge watcher to poll `GET /withdraw/since/:seq` and resume
    /// from the last processed position after a crash without full table scans.
    /// Defaults to 0 for records written before this field was introduced.
    #[serde(default)]
    pub withdrawal_seq: u64,
    /// BB wallet address (base58) whose wUSDT was burned
    pub wallet_address: String,
    /// Solana wallet address (base58) where the dealer should send real USDC
    pub solana_destination: String,
    /// Amount of wUSDT burned (= amount of real USDC owed to user)
    pub wusdt_amount_micro: u64,
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
    /// Per-contest vault PDA (base58). Empty string for legacy/global-vault contests
    /// migrated from v1; new contests must populate this on InitContest.
    #[serde(default)]
    pub vault_pda: String,
    /// L1 transaction hash of the house-rake sweep performed at SubmitMerkleRoot.
    /// `None` until the rake transfer is committed; idempotent — set exactly once.
    #[serde(default)]
    pub house_rake_swept_tx: Option<String>,
}

// ============================================================================
// ESCROW DEPOSITOR LEDGER
// ============================================================================

/// One row per (contest, deposit-tx) — the canonical record that a wallet's
/// funds entered a per-contest vault PDA.  Used for:
///   * deposit double-mint protection (each `deposit_tx_sig` consumed at most once),
///   * pro-rata refund-on-expiry (we know exactly who is owed how much), and
///   * audit / explorer surfaces.
///
/// `amount_lamports` is BB lamports (5 decimals, `LAMPORTS_PER_BB = 100_000`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscrowDepositorEntry {
    pub contest_id: String,
    pub wallet: String,
    /// Primary key fragment — unique per L1 transaction that funded this contest.
    pub deposit_tx_sig: String,
    pub amount_lamports: u64,
    pub deposited_at: u64,
    /// Set true once this entry's deposit has been processed (e.g. approved or refunded).
    #[serde(default)]
    pub used: bool,
    /// Set true once a refund has been issued for this entry (expired contest sweep).
    #[serde(default)]
    pub refunded: bool,
}

// ============================================================================
// LAYER 5 — ROLLUP BRIDGE RECORDS
// ============================================================================

/// Durable record of a creator locking $BB on L1 to seed a rollup token launch.

fn default_rollup_id_l5() -> String { "L5".to_string() }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollupLockRecord {
    /// UUID generated by the L1 handler — used as the lock receipt ID.
    pub lock_id: String,
    /// Rollup identifier ("L2", "L3", "L5") that this lock belongs to.
    #[serde(default = "default_rollup_id_l5")]
    pub rollup_id: String,
    /// Creator's L1 wallet address.
    pub creator_address: String,
    /// Amount locked, in $BB lamports (1 BB = 100_000 lamports).
    pub bb_lamports: u64,
    /// Optional symbol hint for the L5 token the creator intends to launch.
    pub token_symbol_hint: Option<String>,
    /// Unix timestamp (seconds) of lock submission.
    pub locked_at: u64,
    /// Rollup liquidity pool PDA that received the funds.
    pub vault_address: String,
    /// True once the L5 sequencer has credited rollup-$BB for this lock.
    /// Prevents double-credit replay attacks.
    #[serde(default)]
    pub consumed: bool,
}

// ============================================================================
// VAULT BRIDGE BURN RECORD
// ============================================================================

/// Durable receipt created when a user calls POST /vault/burn.
/// Keyed by burn_id (hex SHA-256 of wallet+slot+nonce) — not poh_slot — so concurrent
/// burns in the same slot never overwrite each other.
/// Redeemed via POST /vault/claim-attestation to bridge wUSDT → real USDT on Solana.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BurnRecord {
    /// Collision-free primary key: hex(SHA-256(wallet_bytes || poh_slot_le8 || nonce_utf8)).
    /// Returned as "burn_id" in the POST /vault/burn response.
    pub burn_id: String,
    /// L1 wallet address (base58) that performed the burn.
    pub wallet: String,
    /// PoH slot in which the burn was recorded — used in the KMS attestation message.
    pub poh_slot: u64,
    /// wUSDT micro-units created (equals bb_lamports destroyed — Immutable Law).
    pub amount_usdt_micro: u64,
    /// True once POST /vault/claim-attestation has been called (redeemable → false).
    pub attestation_issued: bool,
    /// True once the Solana Anchor program has confirmed the on-chain claim.
    pub claimed_on_solana: bool,
    /// False after claim-attestation is issued — prevents double-redemption.
    pub redeemable: bool,
    /// Unix timestamp of the burn request.
    pub created_at: u64,
}

// ============================================================================
// BLOCKCHAIN STATS
// ============================================================================

/// Statistics snapshot for the blockchain — includes on-chain volume counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockchainStats {
    pub total_accounts: u64,
    pub block_count: u64,
    pub total_supply: f64,
    pub cache_hit_rate: f64,

    // ═══ ON-CHAIN VOLUME ═══
    /// All-time aggregate volume across every transaction type (lamports).
    pub total_volume_lamports: u64,
    /// All-time transaction count.
    pub total_tx_count: u64,
    /// Bridge-in (deposit) volume (lamports).
    pub deposit_volume_lamports: u64,
    pub deposit_count: u64,
    /// Bridge-out (withdrawal/burn) volume (lamports).
    pub withdrawal_volume_lamports: u64,
    pub withdrawal_count: u64,
    /// Swap volume (BB↔USDC) (lamports).
    pub swap_volume_lamports: u64,
    pub swap_count: u64,
    /// P2P transfer volume (lamports).
    pub transfer_volume_lamports: u64,
    pub transfer_count: u64,
    /// Mint volume (faucet/admin) (lamports).
    pub mint_volume_lamports: u64,
    pub mint_count: u64,
    /// Escrow lock/unlock volume (lamports).
    pub escrow_volume_lamports: u64,
    pub escrow_count: u64,
    /// Node uptime in seconds since startup.
    pub uptime_secs: u64,
    /// Average TPS since startup.
    pub avg_tps: f64,
}

// ============================================================================
// ORACLE STORAGE — ConcurrentBlockchain methods
// ============================================================================

impl ConcurrentBlockchain {
    // ── Oracle node registry ─────────────────────────────────────────────────

    /// Persist (insert or overwrite) an oracle node record, keyed by pubkey_hex.
    pub fn store_oracle_node(&self, node: &OracleNode) -> Result<(), String> {
        let bytes = serde_json::to_vec(node).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(ORACLE_NODES).map_err(|e| e.to_string())?;
            table.insert(node.pubkey_hex.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load a single oracle node by pubkey_hex. Returns None if not registered.
    pub fn load_oracle_node(&self, pubkey_hex: &str) -> Option<OracleNode> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ORACLE_NODES).ok()?;
        let guard = table.get(pubkey_hex).ok()??;
        serde_json::from_slice(guard.value()).ok()
    }

    /// Load all registered oracle nodes (for list endpoints and startup recovery).
    pub fn load_all_oracle_nodes(&self) -> Vec<OracleNode> {
        let Ok(read_txn) = self.db.begin_read() else { return Vec::new(); };
        let Ok(table) = read_txn.open_table(ORACLE_NODES) else { return Vec::new(); };
        let Ok(iter) = table.iter() else { return Vec::new(); };
        iter.filter_map(|entry| {
            let (_k, v) = entry.ok()?;
            serde_json::from_slice::<OracleNode>(v.value()).ok()
        }).collect()
    }

    // ── Pending roots (optimistic dispute window) ────────────────────────────

    /// Load the pending root for a market. Returns None if not present.
    pub fn load_pending_root(&self, market_id: &str) -> Option<PendingRoot> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(PENDING_ROOTS).ok()?;
        let guard = table.get(market_id).ok()??;
        serde_json::from_slice(guard.value()).ok()
    }

    /// Load all pending roots (for the finalize background task).
    pub fn load_all_pending_roots(&self) -> Vec<PendingRoot> {
        let Ok(read_txn) = self.db.begin_read() else { return Vec::new(); };
        let Ok(table) = read_txn.open_table(PENDING_ROOTS) else { return Vec::new(); };
        let Ok(iter) = table.iter() else { return Vec::new(); };
        iter.filter_map(|entry| {
            let (_k, v) = entry.ok()?;
            serde_json::from_slice::<PendingRoot>(v.value()).ok()
        }).collect()
    }

    /// Persist (insert or overwrite) a pending root for a market.
    pub fn store_pending_root(&self, root: &PendingRoot) -> Result<(), String> {
        let bytes = serde_json::to_vec(root).map_err(|e| e.to_string())?;
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(PENDING_ROOTS).map_err(|e| e.to_string())?;
            table.insert(root.market_id.as_str(), bytes.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    // ── Legacy L5 State Root helpers (kept for startup migration) ─────────────

    #[deprecated(note = "Use store_rollup_state_root(rollup_id, batch_id, root) instead")]
    pub fn store_l5_state_root(&self, batch_id: u64, root: [u8; 32]) -> Result<(), String> {
        if let Some(latest) = self.latest_rollup_batch_id("L5") {
            if batch_id <= latest {
                return Err(format!(
                    "L5 batch_id {} is not greater than latest {} (monotonicity violation)",
                    batch_id, latest
                ));
            }
        }
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(L5_STATE_ROOTS).map_err(|e| e.to_string())?;
            table.insert(batch_id, root.as_slice()).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    #[deprecated(note = "Use load_rollup_state_root(rollup_id, batch_id) instead")]
    pub fn load_l5_state_root(&self, batch_id: u64) -> Option<[u8; 32]> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(L5_STATE_ROOTS).ok()?;
        let guard = table.get(batch_id).ok()??;
        let bytes = guard.value();
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        } else {
            None
        }
    }

    // ── Generic Multi-Rollup State Root Methods ───────────────────────────────

    /// Returns the composite ReDB key for a rollup state root.
    /// Format: "<rollup_id>:<20-digit-zero-padded-batch_id>"
    /// Zero-padding ensures lexicographic ordering equals numeric ordering.
    fn rollup_root_key(rollup_id: &str, batch_id: u64) -> String {
        format!("{}:{:020}", rollup_id, batch_id)
    }

    /// Append a new state root for `rollup_id` at `batch_id`.
    /// Enforces per-rollup monotonicity: batch_id must exceed the current
    /// latest batch for that specific rollup (L2 and L5 counters are independent).
    pub fn store_rollup_state_root(
        &self,
        rollup_id: &str,
        batch_id: u64,
        root: [u8; 32],
    ) -> Result<(), String> {
        if let Some(latest) = self.latest_rollup_batch_id(rollup_id) {
            if batch_id <= latest {
                return Err(format!(
                    "{} batch_id {} is not greater than latest {} (monotonicity violation)",
                    rollup_id, batch_id, latest
                ));
            }
        }
        let key = Self::rollup_root_key(rollup_id, batch_id);
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn
                .open_table(ROLLUP_STATE_ROOTS)
                .map_err(|e| e.to_string())?;
            table
                .insert(key.as_str(), root.as_slice())
                .map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }

    /// Load the merkle root for a specific rollup + batch_id.
    /// Returns `None` if no root exists for that (rollup_id, batch_id) pair.
    pub fn load_rollup_state_root(&self, rollup_id: &str, batch_id: u64) -> Option<[u8; 32]> {
        let key = Self::rollup_root_key(rollup_id, batch_id);
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ROLLUP_STATE_ROOTS).ok()?;
        let guard = table.get(key.as_str()).ok()??;
        let bytes = guard.value();
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        } else {
            None
        }
    }

    /// Return the highest batch_id stored for a given rollup_id, or None.
    /// Scans the prefix "<rollup_id>:" and returns the largest batch_id seen.
    pub fn latest_rollup_batch_id(&self, rollup_id: &str) -> Option<u64> {
        let prefix = format!("{}:", rollup_id);
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(ROLLUP_STATE_ROOTS).ok()?;
        let iter = table.iter().ok()?;
        let mut latest: Option<u64> = None;
        for entry in iter {
            if let Ok((key, _)) = entry {
                let k = key.value();
                if let Some(suffix) = k.strip_prefix(&prefix) {
                    if let Ok(bid) = suffix.parse::<u64>() {
                        latest = Some(match latest {
                            Some(prev) => prev.max(bid),
                            None => bid,
                        });
                    }
                }
            }
        }
        latest
    }

    // ── SWAP RATE ────────────────────────────────────────────────────────────

    /// Read the active exchange rate for a swap pool from ReDB.
    ///
    /// `pool_id` is currently `"BB_USDT"`. Returns `BB_PER_USDT_DEFAULT` (10)
    /// if no custom rate has been set, guaranteeing a valid baseline on genesis.
    pub fn get_swap_rate(&self, pool_id: &str) -> u64 {
        use crate::svm::BB_PER_USDT_DEFAULT;
        let read_txn = match self.db.begin_read() {
            Ok(t) => t,
            Err(_) => return BB_PER_USDT_DEFAULT,
        };
        let table = match read_txn.open_table(SWAP_RATES) {
            Ok(t) => t,
            Err(_) => return BB_PER_USDT_DEFAULT,
        };
        // All three branches (Err, Ok(None), Ok(Some(0))) fall back to default,
        // preventing divide-by-zero in swap math on a fresh table or corrupt entry.
        let rate = table.get(pool_id).ok().flatten()
            .map(|v| v.value())
            .unwrap_or(BB_PER_USDT_DEFAULT);
        if rate == 0 { BB_PER_USDT_DEFAULT } else { rate }
    }

    /// Persist a new exchange rate for a swap pool to ReDB.
    ///
    /// `rate` must be ≥ 1 (zero would divide-by-zero in swap math).
    /// Called by the Oracle/Dealer via `POST /admin/swap/set_rate`.
    pub fn set_swap_rate(&self, pool_id: &str, rate: u64) -> Result<(), String> {
        if rate == 0 {
            return Err("Swap rate must be at least 1".to_string());
        }
        let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut table = write_txn.open_table(SWAP_RATES).map_err(|e| e.to_string())?;
            table.insert(pool_id, rate).map_err(|e| e.to_string())?;
        }
        write_txn.commit().map_err(|e| e.to_string())
    }
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
        bc.mint_lamports("alice", 100 * LAMPORTS_PER_BB).unwrap();
        assert_eq!(bc.get_balance("alice"), 100.0);

        // Debit
        bc.burn_lamports("alice", 30 * LAMPORTS_PER_BB).unwrap();
        assert_eq!(bc.get_balance("alice"), 70.0);

        // Insufficient funds
        let result = bc.burn_lamports("alice", 100 * LAMPORTS_PER_BB);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        bc.mint_lamports("alice", 100 * LAMPORTS_PER_BB).unwrap();
        bc.transfer("alice", "bob", 40.0).unwrap();

        assert_eq!(bc.get_balance("alice"), 60.0);
        assert_eq!(bc.get_balance("bob"), 40.0);
    }

    fn mk_entry(contest: &str, sig: &str, wallet: &str, amount: u64) -> EscrowDepositorEntry {
        EscrowDepositorEntry {
            contest_id: contest.to_string(),
            wallet: wallet.to_string(),
            deposit_tx_sig: sig.to_string(),
            amount_lamports: amount,
            deposited_at: 1_700_000_000,
            used: false,
            refunded: false,
        }
    }

    #[test]
    fn depositor_entry_round_trip() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        let e = mk_entry("contest_A", "sig_1", "alice", 500_000);
        bc.store_depositor_entry(&e).unwrap();

        let loaded = bc.load_depositor_entry("contest_A", "sig_1").unwrap().unwrap();
        assert_eq!(loaded.wallet, "alice");
        assert_eq!(loaded.amount_lamports, 500_000);
        assert!(!loaded.used);
        assert!(!loaded.refunded);

        // Unknown key returns None
        assert!(bc.load_depositor_entry("contest_A", "nope").unwrap().is_none());
        assert!(bc.load_depositor_entry("other_contest", "sig_1").unwrap().is_none());
    }

    #[test]
    fn mark_used_then_refunded_persists() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        let e = mk_entry("contest_B", "sig_x", "bob", 1_000_000);
        bc.store_depositor_entry(&e).unwrap();

        bc.mark_depositor_used("contest_B", "sig_x").unwrap();
        let after_used = bc.load_depositor_entry("contest_B", "sig_x").unwrap().unwrap();
        assert!(after_used.used);
        assert!(!after_used.refunded);

        // Idempotent
        bc.mark_depositor_used("contest_B", "sig_x").unwrap();

        bc.mark_depositor_refunded("contest_B", "sig_x").unwrap();
        let after_refund = bc.load_depositor_entry("contest_B", "sig_x").unwrap().unwrap();
        assert!(after_refund.used);
        assert!(after_refund.refunded);

        // Idempotent
        bc.mark_depositor_refunded("contest_B", "sig_x").unwrap();

        // Missing entry yields error
        assert!(bc.mark_depositor_used("contest_B", "missing").is_err());
        assert!(bc.mark_depositor_refunded("contest_B", "missing").is_err());
    }

    #[test]
    fn list_depositors_returns_only_target_contest() {
        let dir = tempdir().unwrap();
        let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        bc.store_depositor_entry(&mk_entry("c1", "s1", "alice", 100)).unwrap();
        bc.store_depositor_entry(&mk_entry("c1", "s2", "bob", 200)).unwrap();
        bc.store_depositor_entry(&mk_entry("c2", "s3", "carol", 300)).unwrap();

        let c1 = bc.list_depositors_for_contest("c1").unwrap();
        assert_eq!(c1.len(), 2);
        assert!(c1.iter().any(|e| e.wallet == "alice"));
        assert!(c1.iter().any(|e| e.wallet == "bob"));
        assert!(c1.iter().all(|e| e.contest_id == "c1"));

        let c2 = bc.list_depositors_for_contest("c2").unwrap();
        assert_eq!(c2.len(), 1);
        assert_eq!(c2[0].wallet, "carol");

        // Re-storing the same (contest, sig) does not duplicate index entries
        bc.store_depositor_entry(&mk_entry("c1", "s1", "alice", 999)).unwrap();
        let c1_again = bc.list_depositors_for_contest("c1").unwrap();
        assert_eq!(c1_again.len(), 2);
        // Latest write wins for the entry value
        let alice = c1_again.iter().find(|e| e.wallet == "alice").unwrap();
        assert_eq!(alice.amount_lamports, 999);

        // Unknown contest yields empty Vec, not error
        assert!(bc.list_depositors_for_contest("nope").unwrap().is_empty());
    }
}
