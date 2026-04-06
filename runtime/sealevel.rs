//! Sealevel — Parallel Transaction Execution Engine
//!
//! Solana-inspired parallel execution with account-level read/write locking.
//! Non-conflicting transactions execute concurrently across all available CPU cores.
//!
//! Key components:
//!   - [`AccountLockManager`]: enforces read/write account exclusivity per batch
//!   - [`ParallelScheduler`]: partitions transaction streams into non-conflicting
//!     batches and drives them through a rayon thread pool
//!   - [`TransactionResult`] / [`SchedulerStats`]: result and metrics types

use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicBool, AtomicU64, Ordering};
use serde::Serialize;
use tracing::info;

use super::core::{Transaction, TransactionType, AccountValidator, AccountAccess, AccountType};

// ============================================================================
// SEALEVEL CONSTANTS
// ============================================================================

pub const OPTIMAL_BATCH_SIZE: usize = 2_048;
pub const MAX_BATCH_SIZE: usize = 20_000;
pub const MIN_BATCH_SIZE: usize = 128;
pub const CONFLICT_THRESHOLD: f64 = 0.25;

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

    /// SVM accounts database — when set, Transfer transactions execute via
    /// SvmAccountsDB.system_transfer() instead of the legacy f64 balance map.
    /// DashMap hot_state is lock-free so parallel threads never contend here.
    svm_db: Option<Arc<crate::svm::SvmAccountsDB>>,

    pub account_validator: Arc<AccountValidator>,
}

impl Default for ParallelScheduler {
    fn default() -> Self {
        Self::new()
    }
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
            svm_db: None,
            account_validator: Arc::new(AccountValidator::new(Arc::new(DashMap::new()))),
        }
    }

    /// Attach an SVM accounts database so Transfer transactions go through
    /// the lamport-based execution path instead of the legacy f64 map.
    pub fn with_svm(mut self, db: Arc<crate::svm::SvmAccountsDB>) -> Self {
        self.svm_db = Some(db);
        self
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

    /// Execute batch with lock acquisition (thread-safe parallel).
    /// When an SvmAccountsDB is attached, `TransactionType::Transfer` transactions
    /// are routed through the lamport execution path; all other types use the
    /// legacy f64 balance map.
    pub fn execute_batch_with_locks(&self, batch: Vec<Transaction>, balances: &DashMap<String, f64>) -> Vec<TransactionResult> {
        let len = batch.len();
        let lm = self.lock_manager.clone();
        let svm_db_ref = self.svm_db.clone();
        let validator = self.account_validator.clone();

        let results = self.thread_pool.install(|| {
            batch.par_iter().map(|tx| {
                let mut backoff = 1;
                while !lm.try_acquire_locks(tx) {
                    if backoff < 1024 {
                        for _ in 0..backoff { std::hint::spin_loop(); }
                        backoff *= 2;
                    } else {
                        std::thread::yield_now();
                    }
                }

                // Account validation before mutation
                let mut validation_err = None;
                for account in tx.read_accounts.iter().chain(tx.write_accounts.iter()) {
                    let access = AccountAccess {
                        address: account.clone(),
                        expected_type: AccountType::UserWallet,
                        is_signer: false, // Defaulting: specific signer checks require deeper Tx parsing
                        is_writable: tx.write_accounts.contains(account),
                        pda_owner: None, // Stub
                        pda_index: None, // Stub
                    };
                    if let Err(e) = validator.validate(&access) {
                        validation_err = Some(e.to_string());
                        break;
                    }
                }

                let result = if let Some(err) = validation_err {
                    TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(err) }
                } else {
                    match (&tx.tx_type, &svm_db_ref) {
                        (TransactionType::Transfer, Some(db)) =>
                            Self::execute_single_svm(tx, db),
                        (TransactionType::SwapUsdcForBb, Some(db)) =>
                            Self::execute_swap_usdc_for_bb(tx, db),
                        (TransactionType::SwapBbForUsdc, Some(db)) =>
                            Self::execute_swap_bb_for_usdc(tx, db),
                        _ => Self::execute_single(tx, balances),
                    }
                };

                lm.release_locks(tx);
                result
            }).collect()
        });

        self.total_processed.fetch_add(len as u64, Ordering::Relaxed);
        results
    }

    /// Execute a single Transfer via SvmAccountsDB (lamport path).
    ///
    /// Address resolution matches `ConcurrentBlockchain::addr_to_pubkey`:
    ///   1. Try base58 decode (Solana-style 32-byte pubkey) — fast path for real wallets.
    ///   2. Fall back to SHA-256 of the stripped string — for legacy internal addresses.
    ///
    /// This MUST stay in sync with `addr_to_pubkey` in `src/storage/mod.rs`.
    fn execute_single_svm(tx: &Transaction, db: &crate::svm::SvmAccountsDB) -> TransactionResult {
        use sha2::{Sha256, Digest};
        use solana_sdk::pubkey::Pubkey;
        use crate::svm::LAMPORTS_PER_BB;

        // Resolve an address string to a Pubkey using the same logic as 
        // `ConcurrentBlockchain::addr_to_pubkey`.
        let addr_to_pk = |addr: &str| -> Pubkey {
            // Fast path: valid base58-encoded 32-byte Ed25519 pubkey (real wallets)
            if let Ok(bytes) = bs58::decode(addr).into_vec() {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Pubkey::new_from_array(arr);
                }
            }
            // Fallback: deterministic SHA-256 (legacy / internal addresses)
            let stripped = addr.strip_prefix("bb_").unwrap_or(addr);
            Pubkey::new_from_array(Sha256::digest(stripped.as_bytes()).into())
        };

        let from_pk = addr_to_pk(&tx.from);
        let to_pk   = addr_to_pk(&tx.to);
        let lamports = (tx.amount * LAMPORTS_PER_BB as f64) as u64;

        match db.system_transfer(&from_pk, &to_pk, lamports) {
            Ok(()) => TransactionResult { tx_id: tx.id.clone(), success: true, error: None },
            Err(e) => TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(e.to_string()) },
        }
    }

    fn execute_swap_usdc_for_bb(tx: &Transaction, db: &crate::svm::SvmAccountsDB) -> TransactionResult {
        use sha2::{Sha256, Digest};
        use solana_sdk::pubkey::Pubkey;
        use crate::svm::{LAMPORTS_PER_BB, USDC_UNIT, usdc_mint_bytes, SplTokenEngine};

        let addr_to_pk = |addr: &str| -> Pubkey {
            if let Ok(bytes) = bs58::decode(addr).into_vec() {
                if bytes.len() == 32 {
                    return Pubkey::new_from_array(bytes.try_into().unwrap());
                }
            }
            let stripped = addr.replace("0x", "").to_lowercase();
            Pubkey::new_from_array(Sha256::digest(stripped.as_bytes()).into())
        };

        let from_pk = addr_to_pk(&tx.from);
        let to_pk = addr_to_pk(&tx.to);

        let usdc_amount_f64 = tx.amount;
        let usdc_raw = (usdc_amount_f64 * USDC_UNIT as f64) as u64;
        let bb_amount_f64 = usdc_amount_f64 * 10.0;
        let bb_lamports = (bb_amount_f64 * LAMPORTS_PER_BB as f64) as u64;
        let mint = usdc_mint_bytes();

        // 1. Debit wUSDC from user, credit wUSDC to dealer
        if let Err(e) = SplTokenEngine::transfer_tokens(db, &mint, &from_pk, &to_pk, usdc_raw) {
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("wUSDC transfer failed: {}", e)) };
        }

        // 2. Debit BB from dealer, credit BB to user (using system_transfer)
        if let Err(e) = db.system_transfer(&to_pk, &from_pk, bb_lamports) {
            // Unwind wUSDC since BB failed
            let _ = SplTokenEngine::transfer_tokens(db, &mint, &to_pk, &from_pk, usdc_raw);
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("BB transfer failed: {}", e)) };
        }

        TransactionResult { tx_id: tx.id.clone(), success: true, error: None }
    }

    fn execute_swap_bb_for_usdc(tx: &Transaction, db: &crate::svm::SvmAccountsDB) -> TransactionResult {
        use sha2::{Sha256, Digest};
        use solana_sdk::pubkey::Pubkey;
        use crate::svm::{LAMPORTS_PER_BB, USDC_UNIT, usdc_mint_bytes, SplTokenEngine};

        let addr_to_pk = |addr: &str| -> Pubkey {
            if let Ok(bytes) = bs58::decode(addr).into_vec() {
                if bytes.len() == 32 {
                    return Pubkey::new_from_array(bytes.try_into().unwrap());
                }
            }
            let stripped = addr.replace("0x", "").to_lowercase();
            Pubkey::new_from_array(Sha256::digest(stripped.as_bytes()).into())
        };

        let from_pk = addr_to_pk(&tx.from);
        let to_pk = addr_to_pk(&tx.to);

        let bb_amount_f64 = tx.amount;
        let bb_lamports = (bb_amount_f64 * LAMPORTS_PER_BB as f64) as u64;
        let usdc_amount_f64 = bb_amount_f64 / 10.0;
        let usdc_raw = (usdc_amount_f64 * USDC_UNIT as f64) as u64;
        let mint = usdc_mint_bytes();

        // 1. Debit BB from user, credit BB to dealer
        if let Err(e) = db.system_transfer(&from_pk, &to_pk, bb_lamports) {
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("BB transfer failed: {}", e)) };
        }

        // 2. Debit wUSDC from dealer, credit wUSDC to user
        if let Err(e) = SplTokenEngine::transfer_tokens(db, &mint, &to_pk, &from_pk, usdc_raw) {
            // Unwind BB
            let _ = db.system_transfer(&to_pk, &from_pk, bb_lamports);
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("wUSDC transfer failed: {}", e)) };
        }

        TransactionResult { tx_id: tx.id.clone(), success: true, error: None }
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

// ============================================================================
// RESULT & STATS TYPES
// ============================================================================

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
    use crate::runtime::core::{Transaction, TransactionType};

    #[test]
    fn test_parallel_scheduling() {
        let scheduler = ParallelScheduler::new();
        let tx1 = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 50.0, TransactionType::Transfer);
        let tx3 = Transaction::new("dave".into(), "eve".into(), 25.0, TransactionType::Transfer);

        let batches = scheduler.schedule_batch(&[tx1, tx2, tx3]);
        assert!(batches.len() >= 2); // tx1+tx2 conflict, tx3 is independent
    }
}
