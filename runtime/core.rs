//! BlackBook L1 Runtime Core — Sealevel Parallel Execution Engine
//!
//! Streamlined for the manifesto's two core jobs:
//!   1. GATEKEEPER: USDT → $BB settlement (fast, secure transfers)
//!   2. INVISIBLE SECURITY: SSS wallet signing with circuit breakers
//!
//! Solana-inspired design, improved:
//!   - 600ms slots (stable vs Solana's fragile 400ms)
//!   - Localized fee markets (spam only affects the spammer)
//!   - Circuit breakers (automatic bank-run protection)
//!   - Stake-weighted throttling (fair resource allocation)

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicBool, AtomicU64, Ordering};
use borsh::{BorshSerialize, BorshDeserialize};
use tracing::{info, warn, debug};

// ============================================================================
// SEALEVEL CONSTANTS
// ============================================================================

pub const OPTIMAL_BATCH_SIZE: usize = 256;
pub const MAX_BATCH_SIZE: usize = 1_024;
pub const MIN_BATCH_SIZE: usize = 32;
pub const CONFLICT_THRESHOLD: f64 = 0.25;

// ============================================================================
// ACCOUNT TYPES (Minimal — L1 Settlement Only)
// ============================================================================

/// PDA namespace constants
pub mod pda_namespace {
    pub const WALLET: &str = "wallet";
    pub const VAULT: &str = "vault";
    pub const CONFIG: &str = "config";
    pub const TREASURY: &str = "treasury";
    pub const BRIDGE_ESCROW: &str = "bridge-escrow";
}

/// Account types on L1 — kept minimal for settlement layer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum AccountType {
    UserWallet,
    EscrowVault,
    SystemConfig,
    Treasury,
    BridgeEscrow,
    Dealer,
}

impl AccountType {
    pub fn namespace(&self) -> &'static str {
        match self {
            AccountType::UserWallet => pda_namespace::WALLET,
            AccountType::EscrowVault => pda_namespace::VAULT,
            AccountType::SystemConfig => pda_namespace::CONFIG,
            AccountType::Treasury => pda_namespace::TREASURY,
            AccountType::BridgeEscrow => pda_namespace::BRIDGE_ESCROW,
            AccountType::Dealer => pda_namespace::WALLET,
        }
    }

    pub fn can_hold_tokens(&self) -> bool {
        matches!(self, AccountType::UserWallet | AccountType::EscrowVault |
                       AccountType::Treasury | AccountType::BridgeEscrow | AccountType::Dealer)
    }
}

/// PDA derivation — deterministic off-curve address from seeds
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProgramDerivedAddress {
    pub address: String,
    pub account_type: AccountType,
    pub namespace: String,
    pub owner: String,
    pub bump: u8,
}

impl ProgramDerivedAddress {
    pub fn derive(account_type: AccountType, owner: &str, index: Option<&str>) -> Result<Self, String> {
        let namespace = account_type.namespace();
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(namespace.as_bytes());
        seed_data.extend_from_slice(owner.as_bytes());
        if let Some(idx) = index { seed_data.extend_from_slice(idx.as_bytes()); }

        for bump in (0u8..=255).rev() {
            let mut hasher = Sha256::new();
            hasher.update(&seed_data);
            hasher.update(&[bump]);
            hasher.update(b"PDA");
            let hash = hasher.finalize();

            if hash[31] & 0x80 == 0 {
                let address = format!("L1_{}", hex::encode(&hash[..20]).to_uppercase());
                return Ok(Self { address, account_type, namespace: namespace.to_string(), owner: owner.to_string(), bump });
            }
        }
        Err("Could not find valid bump for PDA".to_string())
    }
}

/// Account metadata stored alongside each account
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountMetadata {
    pub account_type: AccountType,
    pub owner: String,
    pub pda_info: Option<PDAInfo>,
    pub created_at: u64,
    pub updated_at: u64,
    pub frozen: bool,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PDAInfo {
    pub namespace: String,
    pub bump: u8,
    pub index: Option<String>,
}

/// Declarative account access (for future validation framework)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAccess {
    pub address: String,
    pub expected_type: AccountType,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Account validation error types
#[derive(Debug, Clone)]
pub enum AccountValidationError {
    AccountNotFound(String),
    InvalidType { expected: AccountType, found: AccountType },
    Frozen(String),
    PermissionDenied(String),
}

impl std::fmt::Display for AccountValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountNotFound(a) => write!(f, "Account not found: {}", a),
            Self::InvalidType { expected, found } => write!(f, "Expected {:?}, found {:?}", expected, found),
            Self::Frozen(a) => write!(f, "Account frozen: {}", a),
            Self::PermissionDenied(a) => write!(f, "Permission denied: {}", a),
        }
    }
}

/// Account validator stub (validates account accesses before execution)
pub struct AccountValidator {
    accounts: Arc<DashMap<String, AccountMetadata>>,
}

impl AccountValidator {
    pub fn new(accounts: Arc<DashMap<String, AccountMetadata>>) -> Self {
        Self { accounts }
    }
}

// ============================================================================
// NETWORK THROTTLER — Stake-Weighted Rate Limiting
// ============================================================================

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub tx_count: u64,
    pub window_start: Instant,
    pub stake: f64,
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        Self { tx_count: 0, window_start: Instant::now(), stake: 0.0 }
    }
}

pub struct NetworkThrottler {
    account_limits: DashMap<String, RateLimitEntry>,
    pending_count: AtomicU64,
    max_pending: u64,
    window_duration: Duration,
    base_tx_limit: u64,
    stake_multiplier: f64,
    emergency_halt: AtomicBool,
    pub total_accepted: AtomicU64,
    pub total_rejected: AtomicU64,
    pub total_throttled: AtomicU64,
}

impl NetworkThrottler {
    pub fn new() -> Self {
        Self {
            account_limits: DashMap::new(),
            pending_count: AtomicU64::new(0),
            max_pending: 100_000,
            window_duration: Duration::from_secs(1),
            base_tx_limit: 10,
            stake_multiplier: 0.1,
            emergency_halt: AtomicBool::new(false),
            total_accepted: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_throttled: AtomicU64::new(0),
        }
    }

    pub fn check_transaction(&self, sender: &str, stake: f64) -> Result<f64, String> {
        if self.emergency_halt.load(Ordering::Relaxed) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err("Network is in emergency halt".to_string());
        }

        let pending = self.pending_count.load(Ordering::Relaxed);
        if pending >= self.max_pending {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(format!("Memory guard: {} pending (max: {})", pending, self.max_pending));
        }

        let now = Instant::now();
        let mut entry = self.account_limits.entry(sender.to_string()).or_default();

        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.tx_count = 0;
            entry.window_start = now;
            entry.stake = stake;
        }

        let tx_limit = self.base_tx_limit + (stake * self.stake_multiplier) as u64;

        if entry.tx_count >= tx_limit {
            self.total_throttled.fetch_add(1, Ordering::Relaxed);
            return Err(format!("Rate limited: {}/{} txs this window", entry.tx_count, tx_limit));
        }

        entry.tx_count += 1;
        self.pending_count.fetch_add(1, Ordering::Relaxed);
        self.total_accepted.fetch_add(1, Ordering::Relaxed);
        Ok(0.0)
    }

    pub fn transaction_completed(&self) {
        self.pending_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "pending": self.pending_count.load(Ordering::Relaxed),
            "accepted": self.total_accepted.load(Ordering::Relaxed),
            "rejected": self.total_rejected.load(Ordering::Relaxed),
            "throttled": self.total_throttled.load(Ordering::Relaxed),
            "emergency_halt": self.emergency_halt.load(Ordering::Relaxed),
        })
    }
}

impl Default for NetworkThrottler {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// CIRCUIT BREAKER — Bank Run Protection
// ============================================================================

pub const SINGLE_BLOCK_VALUE_THRESHOLD: f64 = 0.20;
pub const HOURLY_VALUE_THRESHOLD: f64 = 0.50;
pub const CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 3600;

#[derive(Debug, Clone, Default)]
pub struct ValueFlowEntry {
    pub initial_value: f64,
    pub block_outflow: f64,
    pub hourly_outflow: f64,
    pub current_block: u64,
    pub hour_start: u64,
    pub tripped: bool,
    pub tripped_at: Option<u64>,
}

pub struct CircuitBreaker {
    flows: DashMap<String, ValueFlowEntry>,
    block_threshold: f64,
    hourly_threshold: f64,
    cooldown_secs: u64,
    exemptions: DashMap<String, bool>,
    pub trips_triggered: AtomicU64,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            flows: DashMap::new(),
            block_threshold: SINGLE_BLOCK_VALUE_THRESHOLD,
            hourly_threshold: HOURLY_VALUE_THRESHOLD,
            cooldown_secs: CIRCUIT_BREAKER_COOLDOWN_SECS,
            exemptions: DashMap::new(),
            trips_triggered: AtomicU64::new(0),
        }
    }

    pub fn check_transfer(&self, from: &str, amount: f64, balance: f64, block: u64) -> Result<(), String> {
        if self.exemptions.contains_key(from) { return Ok(()); }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut entry = self.flows.entry(from.to_string()).or_default();

        // Cooldown check
        if entry.tripped {
            if let Some(at) = entry.tripped_at {
                if now - at < self.cooldown_secs {
                    return Err(format!("Circuit breaker tripped. {} secs remaining.", self.cooldown_secs - (now - at)));
                }
                entry.tripped = false;
                entry.tripped_at = None;
                entry.block_outflow = 0.0;
                entry.hourly_outflow = 0.0;
            }
        }

        if block != entry.current_block { entry.current_block = block; entry.block_outflow = 0.0; }
        if now - entry.hour_start >= 3600 { entry.hour_start = now; entry.hourly_outflow = 0.0; entry.initial_value = balance; }
        if entry.initial_value == 0.0 { entry.initial_value = balance; entry.hour_start = now; }

        let block_limit = entry.initial_value * self.block_threshold;
        let hourly_limit = entry.initial_value * self.hourly_threshold;

        if entry.block_outflow + amount > block_limit {
            self.trip(from, now);
            return Err(format!("Circuit breaker: block outflow exceeds {}% threshold", (self.block_threshold * 100.0) as u32));
        }
        if entry.hourly_outflow + amount > hourly_limit {
            self.trip(from, now);
            return Err(format!("Circuit breaker: hourly outflow exceeds {}% threshold", (self.hourly_threshold * 100.0) as u32));
        }

        entry.block_outflow += amount;
        entry.hourly_outflow += amount;
        Ok(())
    }

    fn trip(&self, account: &str, now: u64) {
        if let Some(mut entry) = self.flows.get_mut(account) {
            entry.tripped = true;
            entry.tripped_at = Some(now);
        }
        self.trips_triggered.fetch_add(1, Ordering::Relaxed);
        warn!("🔌 Circuit breaker TRIPPED: {}", account);
    }

    pub fn add_exemption(&self, account: &str) {
        self.exemptions.insert(account.to_string(), true);
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "trips": self.trips_triggered.load(Ordering::Relaxed),
            "tracked": self.flows.len(),
            "exemptions": self.exemptions.len(),
            "block_threshold": format!("{}%", (self.block_threshold * 100.0) as u32),
            "hourly_threshold": format!("{}%", (self.hourly_threshold * 100.0) as u32),
        })
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// LOCALIZED FEE MARKET — Per-Account Fees (Spam Isolation)
// ============================================================================

#[derive(Debug, Clone)]
pub struct FeeMarketEntry {
    pub tx_count: u64,
    pub window_start: Instant,
    pub base_fee: f64,
}

pub struct LocalizedFeeMarket {
    groups: DashMap<String, FeeMarketEntry>,
    min_fee: f64,
    max_fee: f64,
    target_tx_per_group: u64,
}

impl LocalizedFeeMarket {
    pub fn new() -> Self {
        Self {
            groups: DashMap::new(),
            min_fee: 0.0,
            max_fee: 1.0,
            target_tx_per_group: 100,
        }
    }

    pub fn calculate_fee(&self, sender: &str) -> f64 {
        let group: String = sender.chars().take(8).collect();
        let now = Instant::now();

        let mut entry = self.groups.entry(group).or_insert(FeeMarketEntry {
            tx_count: 0, window_start: now, base_fee: self.min_fee,
        });

        if now.duration_since(entry.window_start) >= Duration::from_secs(1) {
            if entry.tx_count > self.target_tx_per_group {
                entry.base_fee = (entry.base_fee + 0.1).min(self.max_fee);
            } else if entry.tx_count < self.target_tx_per_group / 2 {
                entry.base_fee = (entry.base_fee - 0.1).max(self.min_fee);
            }
            entry.tx_count = 0;
            entry.window_start = now;
        }

        entry.tx_count += 1;
        entry.base_fee
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "active_groups": self.groups.len(),
            "min_fee": self.min_fee,
            "max_fee": self.max_fee,
        })
    }
}

impl Default for LocalizedFeeMarket {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// TRANSACTION — L1 Settlement Transaction
// ============================================================================

/// Transaction types for L1 settlement layer
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default, PartialEq)]
pub enum TransactionType {
    #[default]
    Transfer,
    Mint,
    Burn,
    BridgeLock,
    BridgeUnlock,
    Vote,
    SystemReward,
}

/// L1 Transaction with explicit read/write accounts for Sealevel parallel scheduling
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub read_accounts: Vec<String>,
    #[serde(default)]
    pub write_accounts: Vec<String>,
    #[serde(default)]
    pub tx_type: TransactionType,
}

impl Transaction {
    pub fn new(from: String, to: String, amount: f64, tx_type: TransactionType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let read_accounts = vec![from.clone()];
        let write_accounts = vec![from.clone(), to.clone()];

        Self {
            id: id.clone(),
            from, to, amount, timestamp,
            signature: format!("sig_{}", &id[..8]),
            nonce: 0,
            read_accounts, write_accounts,
            tx_type,
        }
    }

    pub fn conflicts_with(&self, other: &Transaction) -> bool {
        for w in &self.write_accounts {
            if other.write_accounts.contains(w) || other.read_accounts.contains(w) { return true; }
        }
        for r in &self.read_accounts {
            if other.write_accounts.contains(r) { return true; }
        }
        false
    }

    pub fn is_financial(&self) -> bool {
        matches!(self.tx_type, TransactionType::Transfer | TransactionType::Mint |
                 TransactionType::Burn | TransactionType::BridgeLock | TransactionType::BridgeUnlock)
    }
}

// ============================================================================
// ACCOUNT LOCK MANAGER — Sealevel Read/Write Locking
// ============================================================================

#[derive(Debug)]
pub struct AccountLockManager {
    read_locks: DashMap<String, AtomicU32>,
    write_locks: DashMap<String, AtomicBool>,
    pub total_acquisitions: AtomicU64,
    pub total_conflicts: AtomicU64,
}

impl AccountLockManager {
    pub fn new() -> Self {
        Self {
            read_locks: DashMap::new(),
            write_locks: DashMap::new(),
            total_acquisitions: AtomicU64::new(0),
            total_conflicts: AtomicU64::new(0),
        }
    }

    pub fn try_acquire_locks(&self, tx: &Transaction) -> bool {
        self.total_acquisitions.fetch_add(1, Ordering::Relaxed);

        for account in &tx.write_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            if let Some(lock) = self.read_locks.get(account) {
                if lock.load(Ordering::Acquire) > 0 {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }

        for account in &tx.read_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }

        for account in &tx.write_accounts {
            self.write_locks.entry(account.clone()).or_insert_with(|| AtomicBool::new(false)).store(true, Ordering::Release);
        }
        for account in &tx.read_accounts {
            self.read_locks.entry(account.clone()).or_insert_with(|| AtomicU32::new(0)).fetch_add(1, Ordering::Release);
        }
        true
    }

    pub fn release_locks(&self, tx: &Transaction) {
        for account in &tx.write_accounts {
            if let Some(lock) = self.write_locks.get(account) { lock.store(false, Ordering::Release); }
        }
        for account in &tx.read_accounts {
            if let Some(lock) = self.read_locks.get(account) { lock.fetch_sub(1, Ordering::Release); }
        }
    }

    pub fn get_conflict_rate(&self) -> f64 {
        let total = self.total_acquisitions.load(Ordering::Relaxed);
        if total == 0 { 0.0 } else { self.total_conflicts.load(Ordering::Relaxed) as f64 / total as f64 }
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "acquisitions": self.total_acquisitions.load(Ordering::Relaxed),
            "conflicts": self.total_conflicts.load(Ordering::Relaxed),
            "conflict_rate": self.get_conflict_rate(),
        })
    }
}

impl Default for AccountLockManager {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// PARALLEL SCHEDULER — Sealevel Execution Engine
// ============================================================================

pub struct ParallelScheduler {
    thread_pool: rayon::ThreadPool,
    pub lock_manager: Arc<AccountLockManager>,
    current_batch_size: AtomicU64,
    pub total_processed: AtomicU64,
    pub total_batches: AtomicU64,
}

impl ParallelScheduler {
    pub fn new() -> Self {
        let num_threads = num_cpus::get().max(4);
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

        info!("⚡ Sealevel: {} threads, batch: {}", num_threads, OPTIMAL_BATCH_SIZE);

        Self {
            thread_pool,
            lock_manager: Arc::new(AccountLockManager::new()),
            current_batch_size: AtomicU64::new(OPTIMAL_BATCH_SIZE as u64),
            total_processed: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
        }
    }

    pub fn get_batch_size(&self) -> usize {
        self.current_batch_size.load(Ordering::Relaxed) as usize
    }

    pub fn tune_batch_size(&self) {
        let rate = self.lock_manager.get_conflict_rate();
        let current = self.current_batch_size.load(Ordering::Relaxed) as usize;
        let new = if rate > CONFLICT_THRESHOLD {
            (current / 2).max(MIN_BATCH_SIZE)
        } else if rate < CONFLICT_THRESHOLD / 2.0 {
            (current * 3 / 2).min(MAX_BATCH_SIZE)
        } else {
            current
        };
        if new != current {
            self.current_batch_size.store(new as u64, Ordering::Relaxed);
        }
    }

    /// Schedule into non-conflicting batches using lock manager
    pub fn schedule_with_locks(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() { return vec![]; }

        let batch_size = self.get_batch_size();
        let mut batches: Vec<Vec<Transaction>> = vec![];
        let mut remaining = transactions;

        while !remaining.is_empty() {
            let mut batch: Vec<Transaction> = vec![];
            let mut next: Vec<Transaction> = vec![];

            for tx in remaining {
                if batch.len() >= batch_size {
                    next.push(tx);
                    continue;
                }
                if self.lock_manager.try_acquire_locks(&tx) {
                    batch.push(tx);
                } else {
                    next.push(tx);
                }
            }

            for tx in &batch { self.lock_manager.release_locks(tx); }
            if !batch.is_empty() { batches.push(batch); }
            remaining = next;
        }

        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        batches
    }

    /// Execute batch with lock acquisition (thread-safe parallel)
    pub fn execute_batch_with_locks(&self, batch: Vec<Transaction>, balances: &DashMap<String, f64>) -> Vec<TransactionResult> {
        let len = batch.len();
        let lm = self.lock_manager.clone();

        let results = self.thread_pool.install(|| {
            batch.par_iter().map(|tx| {
                while !lm.try_acquire_locks(tx) { std::hint::spin_loop(); }
                let result = Self::execute_single(tx, balances);
                lm.release_locks(tx);
                result
            }).collect()
        });

        self.total_processed.fetch_add(len as u64, Ordering::Relaxed);
        results
    }

    fn execute_single(tx: &Transaction, balances: &DashMap<String, f64>) -> TransactionResult {
        if !Self::is_system_account(&tx.from) {
            let balance = balances.get(&tx.from).map(|b| *b).unwrap_or(0.0);
            if balance < tx.amount {
                return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("Insufficient: {} < {}", balance, tx.amount)) };
            }
            balances.entry(tx.from.clone()).and_modify(|b| *b -= tx.amount);
        }

        if tx.to != "burned_tokens" {
            balances.entry(tx.to.clone()).and_modify(|b| *b += tx.amount).or_insert(tx.amount);
        }

        TransactionResult { tx_id: tx.id.clone(), success: true, error: None }
    }

    fn is_system_account(account: &str) -> bool {
        matches!(account, "genesis" | "mining_reward" | "system" | "poh_validator" | "signup_bonus")
    }

    pub fn schedule_batch(&self, transactions: &[Transaction]) -> Vec<Vec<Transaction>> {
        self.schedule_with_locks(transactions.to_vec())
    }

    pub fn get_stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_processed: self.total_processed.load(Ordering::Relaxed),
            total_batches: self.total_batches.load(Ordering::Relaxed),
            current_batch_size: self.current_batch_size.load(Ordering::Relaxed) as usize,
            conflict_rate: self.lock_manager.get_conflict_rate(),
            thread_count: self.thread_pool.current_num_threads(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SchedulerStats {
    pub total_processed: u64,
    pub total_batches: u64,
    pub current_batch_size: usize,
    pub conflict_rate: f64,
    pub thread_count: usize,
}

#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub tx_id: String,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_new() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "bob");
        assert_eq!(tx.amount, 100.0);
        assert!(!tx.id.is_empty());
    }

    #[test]
    fn test_conflict_detection() {
        let tx1 = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 50.0, TransactionType::Transfer);
        let tx3 = Transaction::new("dave".into(), "eve".into(), 25.0, TransactionType::Transfer);

        assert!(tx1.conflicts_with(&tx2)); // same sender
        assert!(!tx1.conflicts_with(&tx3)); // independent
    }

    #[test]
    fn test_parallel_scheduling() {
        let scheduler = ParallelScheduler::new();
        let tx1 = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 50.0, TransactionType::Transfer);
        let tx3 = Transaction::new("dave".into(), "eve".into(), 25.0, TransactionType::Transfer);

        let batches = scheduler.schedule_batch(&[tx1, tx2, tx3]);
        assert!(batches.len() >= 2); // tx1+tx2 conflict, tx3 is independent
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new();
        cb.add_exemption("genesis");
        assert!(cb.check_transfer("genesis", 1000.0, 100.0, 1).is_ok());

        // Normal account: 20% block threshold
        assert!(cb.check_transfer("alice", 10.0, 100.0, 1).is_ok());
        assert!(cb.check_transfer("alice", 15.0, 100.0, 1).is_err()); // exceeds 20%
    }

    #[test]
    fn test_throttler() {
        let throttler = NetworkThrottler::new();
        for _ in 0..10 {
            assert!(throttler.check_transaction("alice", 0.0).is_ok());
        }
        assert!(throttler.check_transaction("alice", 0.0).is_err()); // 11th throttled
    }
}
