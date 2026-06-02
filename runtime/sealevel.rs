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
use std::collections::HashMap;
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

    /// Schedule transactions into non-conflicting batches — **O(N)** per-account queue algorithm.
    ///
    /// ### Algorithm
    /// Maintains a `next_free` map: `account → earliest_batch_index` where that account
    /// is available. For each transaction (sorted by priority desc):
    ///   1. `slot = max(next_free[a] for all accounts a)` — the first conflict-free batch.
    ///   2. If `slot` is full, walk forward until a non-full slot is found (amortized O(1)).
    ///   3. Place the tx in `batches[slot]`, advance `next_free[a] = slot + 1`.
    ///
    /// ### Complexity
    /// O(N × W) where W = avg write accounts per tx (≈ 2 for transfers).
    /// The previous O(N²) scan-and-retry loop is eliminated entirely.
    ///
    /// ### Local Fee Market
    /// Transactions are sorted by `priority` (descending) before scheduling.
    /// When multiple txs contend on the same hot account (e.g. swap pool),
    /// the highest-priority tx wins the earliest execution slot.
    pub fn schedule_with_locks(&self, mut transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() { return vec![]; }

        // Local Fee Market: high-priority txs claim the earliest conflict-free slot.
        transactions.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

        let batch_size = self.get_batch_size();

        // `next_free[account]` = smallest batch index where this account is unlocked.
        // Accounts absent from the map are free at batch 0.
        let mut next_free: HashMap<String, usize> = HashMap::with_capacity(transactions.len() * 2);
        let mut batch_counts: Vec<usize> = Vec::new();
        let mut batches: Vec<Vec<Transaction>> = Vec::new();

        let total = transactions.len() as u64;
        let mut deferred: u64 = 0;

        for tx in transactions {
            // Step 1 — find the earliest batch slot where ALL accounts are free.
            // Read-accounts are treated as write-accounts conservatively to
            // prevent read-after-write hazards across concurrent Rayon threads.
            let conflict_slot = tx
                .write_accounts
                .iter()
                .chain(tx.read_accounts.iter())
                .map(|a| next_free.get(a).copied().unwrap_or(0))
                .max()
                .unwrap_or(0);

            // Step 2 — within that conflict-free slot, find one that has room.
            // `conflict_slot` is already free of account contention; any later slot
            // is too, so we only need to advance for capacity reasons (amortized O(1)).
            let mut slot = conflict_slot;
            while batch_counts.get(slot).copied().unwrap_or(0) >= batch_size {
                slot += 1;
            }

            if slot > 0 { deferred += 1; }

            // Step 3 — grow storage if needed.
            while batches.len() <= slot {
                batches.push(Vec::new());
                batch_counts.push(0);
            }

            // Step 4 — assign and advance per-account free pointers.
            batch_counts[slot] += 1;
            for a in tx.write_accounts.iter().chain(tx.read_accounts.iter()) {
                let e = next_free.entry(a.clone()).or_insert(0);
                if *e <= slot {
                    *e = slot + 1;
                }
            }
            batches[slot].push(tx);
        }

        // Update conflict stats for tune_batch_size adaptive logic.
        self.lock_manager.total_acquisitions.fetch_add(total, Ordering::Relaxed);
        self.lock_manager.total_conflicts.fetch_add(deferred, Ordering::Relaxed);

        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        batches
    }

    /// Execute a pre-scheduled conflict-free batch in parallel via Rayon.
    ///
    /// Batches supplied here MUST come from `schedule_with_locks`, which already
    /// partitions transactions so that no two entries in the same batch share a
    /// write account. Phase-two runtime locking is therefore unnecessary and has
    /// been removed. Rayon threads execute every transaction concurrently with
    /// zero spin-wait overhead. All transaction types are routed through
    /// `SvmAccountsDB` — the legacy f64 balance map is gone.
    pub fn execute_batch_with_locks(&self, batch: Vec<Transaction>) -> Vec<TransactionResult> {
        let len = batch.len();
        let svm_db_ref = self.svm_db.clone();
        let validator = self.account_validator.clone();

        let results = self.thread_pool.install(|| {
            batch.par_iter().map(|tx| {
                // Account validation before mutation
                let mut validation_err = None;
                for account in tx.read_accounts.iter().chain(tx.write_accounts.iter()) {
                    let access = AccountAccess {
                        address: account.clone(),
                        expected_type: AccountType::UserWallet,
                        is_signer: false,
                        is_writable: tx.write_accounts.contains(account),
                        pda_owner: None,
                        pda_index: None,
                    };
                    if let Err(e) = validator.validate(&access) {
                        validation_err = Some(e.to_string());
                        break;
                    }
                }

                if let Some(err) = validation_err {
                    return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(err) };
                }

                match (&tx.tx_type, &svm_db_ref) {
                    (TransactionType::Transfer, Some(db)) =>
                        Self::execute_single_svm(tx, db),
                    (TransactionType::SwapUsdcForBb, Some(db)) =>
                        Self::execute_swap_usdc_for_bb(tx, db),
                    (TransactionType::SwapBbForUsdc, Some(db)) =>
                        Self::execute_swap_bb_for_usdc(tx, db),
                    (_, None) => TransactionResult {
                        tx_id: tx.id.clone(),
                        success: false,
                        error: Some("SVM database not attached to scheduler".to_string()),
                    },
                    _ => TransactionResult {
                        tx_id: tx.id.clone(),
                        success: false,
                        error: Some(format!("Unsupported transaction type for SVM: {:?}", tx.tx_type)),
                    },
                }
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
        // tx.amount is already lamports (u64)
        let lamports = tx.amount;

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
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Pubkey::new_from_array(arr);
                }
            }
            let stripped = addr.replace("0x", "").to_lowercase();
            Pubkey::new_from_array(Sha256::digest(stripped.as_bytes()).into())
        };

        let from_pk = addr_to_pk(&tx.from);
        let to_pk = addr_to_pk(&tx.to);

        // tx.amount is microUSDT (u64) for SwapUsdcForBb
        let usdc_raw = tx.amount;
        // 1 wUSDT = 10 BB  →  (microUSDT / USDC_UNIT) * 10 * LAMPORTS_PER_BB
        let bb_lamports = (usdc_raw as u128 * 10 * LAMPORTS_PER_BB as u128 / USDC_UNIT as u128) as u64;
        let mint = usdc_mint_bytes();

        // 1. Debit wUSDT from user, credit wUSDT to dealer
        if let Err(e) = SplTokenEngine::transfer_tokens(db, &mint, &from_pk, &to_pk, usdc_raw) {
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("wUSDT transfer failed: {}", e)) };
        }

        // 2. Debit BB from dealer, credit BB to user (using system_transfer)
        if let Err(e) = db.system_transfer(&to_pk, &from_pk, bb_lamports) {
            // Unwind wUSDT since BB failed
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
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Pubkey::new_from_array(arr);
                }
            }
            let stripped = addr.replace("0x", "").to_lowercase();
            Pubkey::new_from_array(Sha256::digest(stripped.as_bytes()).into())
        };

        let from_pk = addr_to_pk(&tx.from);
        let to_pk = addr_to_pk(&tx.to);

        // tx.amount is lamports (u64) for SwapBbForUsdc
        let bb_lamports = tx.amount;
        // 1 wUSDT = 10 BB  →  (lamports / LAMPORTS_PER_BB / 10) * USDC_UNIT
        let usdc_raw = (bb_lamports as u128 * USDC_UNIT as u128 / (LAMPORTS_PER_BB as u128 * 10)) as u64;
        let mint = usdc_mint_bytes();

        // 1. Debit BB from user, credit BB to dealer
        if let Err(e) = db.system_transfer(&from_pk, &to_pk, bb_lamports) {
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("BB transfer failed: {}", e)) };
        }

        // 2. Debit wUSDT from dealer, credit wUSDT to user
        if let Err(e) = SplTokenEngine::transfer_tokens(db, &mint, &to_pk, &from_pk, usdc_raw) {
            // Unwind BB
            let _ = db.system_transfer(&to_pk, &from_pk, bb_lamports);
            return TransactionResult { tx_id: tx.id.clone(), success: false, error: Some(format!("wUSDT transfer failed: {}", e)) };
        }

        TransactionResult { tx_id: tx.id.clone(), success: true, error: None }
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
        let tx1 = Transaction::new("alice".into(), "bob".into(), 100u64, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 50u64, TransactionType::Transfer);
        let tx3 = Transaction::new("dave".into(), "eve".into(), 25u64, TransactionType::Transfer);

        let batches = scheduler.schedule_batch(&[tx1, tx2, tx3]);
        // tx1 and tx2 both write to "alice" — they must be in different batches.
        // tx3 is fully independent and fits in batch 0 alongside one of them.
        assert!(batches.len() >= 2, "conflicting txs must be separated");
        // Total tx count must be preserved
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_hot_account_linear_batches() {
        // N transactions all writing to the same "hot" account.
        // Old algorithm: O(N²). New algorithm: O(N), produces N batches of 1.
        let scheduler = ParallelScheduler::new();
        let n = 100;
        let txs: Vec<Transaction> = (0..n)
            .map(|i| Transaction::new("hot_pool".into(), format!("user_{}", i), 1u64, TransactionType::Transfer))
            .collect();
        let batches = scheduler.schedule_with_locks(txs);
        assert_eq!(batches.len(), n, "each conflicting tx gets its own batch");
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, n);
    }

    #[test]
    fn test_priority_wins_hot_account() {
        // Two txs conflict on "hot". High-priority tx should land in batch 0.
        let scheduler = ParallelScheduler::new();
        let mut low = Transaction::new("hot".into(), "a".into(), 1u64, TransactionType::Transfer);
        low.priority = 10;
        let mut high = Transaction::new("hot".into(), "b".into(), 1u64, TransactionType::Transfer);
        high.priority = 9_999;
        let batches = scheduler.schedule_with_locks(vec![low, high]);
        assert_eq!(batches.len(), 2);
        // batch 0 should contain the high-priority tx (to="b")
        assert_eq!(batches[0][0].to, "b", "high-priority tx must be in batch 0");
        assert_eq!(batches[1][0].to, "a", "low-priority tx must be deferred");
    }
}
