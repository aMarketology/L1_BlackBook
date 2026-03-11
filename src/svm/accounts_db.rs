// ============================================================================
// BLACKBOOK SVM — ACCOUNTS DATABASE
// ============================================================================
//
// SvmAccountsDB is the single source of truth for SVM account state.
//
// DESIGN: Two-layer state with scheduler-safe flush semantics
// ─────────────────────────────────────────────────────────────
//
//   ┌──────────────────────────────────────────────────────────┐
//   │             Parallel Scheduler (Rayon)                   │
//   │  ┌────────────────────────────────────────────────────┐  │
//   │  │  1. Lock account addresses (conflict detection)    │  │
//   │  │  2. SVM executes — reads/writes hot_state only     │  │
//   │  │  3. Scheduler releases locks after execution       │  │
//   │  └────────────────────────────────────────────────────┘  │
//   │             ↓  end of block                              │
//   │  ┌────────────────────────────────────────────────────┐  │
//   │  │  flush_block() — single ACID ReDB write txn        │  │
//   │  │  Entire block's dirty state committed atomically   │  │
//   │  └────────────────────────────────────────────────────┘  │
//   └──────────────────────────────────────────────────────────┘
//
//   Layer 1 — hot_state: Arc<DashMap<Pubkey, AccountSharedData>>
//     Lock-free reads. The VM reads/writes this exclusively during execution.
//     Zero mutex contention for independent accounts.
//
//   Layer 2 — ReDB: svm_accounts table (Pubkey → StoredAccount borsh)
//     Durable, ACID. Written once per block via flush_block().
//     The ReDB database instance is SHARED with ConcurrentBlockchain —
//     same file, different table namespace, safe coexistence.
//
// ZERO f64 RULE: All balances in lamports (u64). No floating-point math
// anywhere in this file. See types.rs for the canonical explanation.
//
// ============================================================================

use std::sync::Arc;
use redb::{Database, TableDefinition, ReadableTable};
use dashmap::DashMap;
use borsh::BorshDeserialize;
use tracing::{info, warn, debug};

use crate::svm::types::{StoredAccount, SvmError, RENT_EPOCH_EXEMPT};
use solana_sdk::{
    account::AccountSharedData,
    account::ReadableAccount,
    account::WritableAccount,
    pubkey::Pubkey,
};

// ============================================================================
// REDB TABLE DEFINITIONS
// ============================================================================

// All SVM tables use a distinct namespace prefix — they coexist safely with
// the existing `accounts` (f64) table used by ConcurrentBlockchain.

/// Solana-format accounts: Pubkey bytes (32) → StoredAccount (borsh)
pub const SVM_ACCOUNTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("svm_accounts");

/// Program ELF binaries: ProgramId bytes (32) → ELF .so bytes
pub const SVM_PROGRAMS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("svm_programs");

/// Blockhash queue: Slot (u64) → Hash bytes (32)
pub const BLOCKHASH_QUEUE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("blockhash_queue");

/// Signature dedup / replay protection: Signature bytes (64) → Slot processed (u64)
pub const SVM_SIGNATURES: TableDefinition<&[u8], u64> =
    TableDefinition::new("svm_signatures");

// ═══════════════════════════════════════════════════════════════
// Phase 2B: Transaction log + address index tables
// ═══════════════════════════════════════════════════════════════

/// Transaction log: Signature (base58 string bytes) → StoredTransactionResult (borsh)
/// Stores the full execution result for every confirmed transaction.
pub const SVM_TX_LOG: TableDefinition<&str, &[u8]> =
    TableDefinition::new("svm_tx_log");

/// Address → signature index: "addr:signature" composite key → slot (u64)
/// Supports getSignaturesForAddress by prefix scanning for "addr:*".
pub const SVM_ADDR_SIGS: TableDefinition<&str, u64> =
    TableDefinition::new("svm_addr_sigs");

// ============================================================================
// SERDE HELPERS — u64 key tag for hot_state iteration
// ============================================================================



// ============================================================================
// SEALEVEL HOT-STATE WRAPPER (feature-independent shell)
// ============================================================================

/// Tracks which pubkeys have been mutated since the last flush.
/// Uses a lock-free set so the scheduler can mark dirty accounts
/// concurrently with other reads.
pub struct DirtySet {
    inner: DashMap<[u8; 32], ()>,
}

impl Default for DirtySet {
    fn default() -> Self {
        Self::new()
    }
}

impl DirtySet {
    pub fn new() -> Self {
        Self { inner: DashMap::new() }
    }

    pub fn mark(&self, key: [u8; 32]) {
        self.inner.insert(key, ());
    }

    pub fn drain(&self) -> Vec<[u8; 32]> {
        let keys: Vec<[u8; 32]> = self.inner.iter().map(|e| *e.key()).collect();
        self.inner.clear();
        keys
    }

    #[allow(dead_code)] // Used in flush_block diagnostics
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ============================================================================
// SvmAccountsDB
// ============================================================================

/// Manages all SVM account state for BlackBook L1.
///
/// Thread-safety:
///   - `get_account` / `store_account` are lock-free (DashMap sharding).
///   - `flush_block` is serialized via a ReDB write transaction; it must be
///     called only by the block producer after the current slot's batch
///     completes.
///
/// Invariants:
///   - `hot_state` is always a superset of ReDB `svm_accounts`.
///   - Every `store_account` call marks the account dirty.
///   - `flush_block` atomically persists all dirty accounts and clears the
///     dirty set.
///   - Lamports are always u64. No f64 conversions happen in this struct.
pub struct SvmAccountsDB {
    /// Shared ReDB instance (SAME Arc<Database> as ConcurrentBlockchain).
    db: Arc<Database>,

    /// Hot in-memory state — the VM's working set during a block.
    /// DashMap provides lock-free concurrent reads and fine-grained shard
    /// locks for writes. The scheduler does NOT need an external mutex.
    pub hot_state: Arc<DashMap<Pubkey, AccountSharedData>>,

    /// Set of accounts mutated since the last flush.
    /// Populated by store_account; consumed by flush_block.
    dirty: Arc<DirtySet>,
}

impl SvmAccountsDB {
    // ========================================================================
    // CONSTRUCTION
    // ========================================================================

    /// Open (or create) SVM tables in the shared ReDB instance and warm the
    /// hot-state cache from disk.
    ///
    /// This is cheap — it reads existing accounts into DashMap then returns.
    /// The `db` argument must be the same `Arc<Database>` used by
    /// `ConcurrentBlockchain::new()`.
    pub fn new(db: Arc<Database>) -> Result<Self, SvmError> {
        // Ensure tables exist (idempotent — safe to call on every startup)
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(SVM_ACCOUNTS)?;
            let _ = write_txn.open_table(SVM_PROGRAMS)?;
            let _ = write_txn.open_table(BLOCKHASH_QUEUE)?;
            let _ = write_txn.open_table(SVM_SIGNATURES)?;
            // Phase 2B tables
            let _ = write_txn.open_table(SVM_TX_LOG)?;
            let _ = write_txn.open_table(SVM_ADDR_SIGS)?;
        }
        write_txn.commit()?;

        // Warm hot_state from persisted accounts
        let hot_state: Arc<DashMap<Pubkey, AccountSharedData>> = Arc::new(DashMap::new());

        let mut loaded = 0usize;
        {
            let read_txn = db.begin_read().map_err(|e| SvmError::StorageError(e.to_string()))?;
            if let Ok(table) = read_txn.open_table(SVM_ACCOUNTS) {
                let mut iter = table.iter().map_err(|e| SvmError::StorageError(e.to_string()))?;
                while let Some(Ok((key_guard, val_guard))) = iter.next() {
                    let key_bytes: &[u8] = key_guard.value();
                    let val_bytes: &[u8] = val_guard.value();

                    if key_bytes.len() != 32 {
                        warn!("SVM_ACCOUNTS: skipping malformed key of len {}", key_bytes.len());
                        continue;
                    }
                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(key_bytes);

                    match StoredAccount::try_from_slice(val_bytes) {
                        Ok(stored) => {
                            {
                                let pubkey = Pubkey::new_from_array(key_arr);
                                let account: AccountSharedData = stored.into();
                                hot_state.insert(pubkey, account);
                            }
                            loaded += 1;
                        }
                        Err(e) => {
                            warn!("SVM_ACCOUNTS: borsh decode error for key {:?}: {}", key_arr, e);
                        }
                    }
                }
            }
        }

        info!(accounts_loaded = loaded, "SvmAccountsDB warm-started from ReDB");

        Ok(Self {
            db,
            hot_state,
            dirty: Arc::new(DirtySet::new()),
        })
    }

    // ========================================================================
    // READ  (lock-free)
    // ========================================================================

    /// Fetch an account from hot state.
    ///
    /// Returns `None` if the account has never been created.
    /// O(1) — DashMap shard lookup, no I/O.
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.hot_state.get(pubkey).map(|r| r.clone())
    }

    /// Returns `true` if the account exists in hot state.
    pub fn account_exists(&self, pubkey: &Pubkey) -> bool {
        self.hot_state.contains_key(pubkey)
    }

    /// Returns current lamport balance, or 0 if the account does not exist.
    pub fn get_lamports(&self, pubkey: &Pubkey) -> u64 {
        self.hot_state
            .get(pubkey)
            .map(|acc| acc.lamports())
            .unwrap_or(0)
    }

    // ========================================================================
    // WRITE  (mark-and-defer — actual persistence happens at flush_block)
    // ========================================================================

    /// Write a single account to hot state and mark it dirty.
    ///
    /// This is the ONLY way the SVM should mutate account state during
    /// execution. The actual ReDB write is deferred to `flush_block()`.
    ///
    /// INVARIANT: rent_epoch is always set to RENT_EPOCH_EXEMPT here.
    /// Accounts on BlackBook L1 never pay rent.
    pub fn store_account(&self, pubkey: &Pubkey, mut account: AccountSharedData) {
        account.set_rent_epoch(RENT_EPOCH_EXEMPT);
        self.dirty.mark(pubkey.to_bytes());
        self.hot_state.insert(*pubkey, account);
    }

    /// Atomically write a batch of accounts (single DashMap operation per
    /// account — no higher-level lock needed — each DashMap shard is
    /// independently locked).
    ///
    /// INVARIANT: rent_epoch is always set to RENT_EPOCH_EXEMPT.
    pub fn store_accounts_batch(&self, updates: &[(Pubkey, AccountSharedData)]) {
        for (pubkey, account) in updates {
            let mut account = account.clone();
            account.set_rent_epoch(RENT_EPOCH_EXEMPT);
            self.dirty.mark(pubkey.to_bytes());
            self.hot_state.insert(*pubkey, account);
        }
    }

    // ========================================================================
    // FLUSH — single ACID ReDB write transaction per block
    // ========================================================================

    /// Persist all dirty accounts to ReDB in a single atomic write transaction.
    ///
    /// CALL ONLY FROM THE BLOCK PRODUCER after the current slot's parallel
    /// batch finishes. This is the "end of block" commit that makes the block
    /// durable.
    ///
    /// Guarantees:
    ///   - All dirty accounts land in the same ReDB transaction → ACID.
    ///   - If this function returns Ok, the block is durable on disk.
    ///   - If it returns Err, no accounts were written (retry is safe).
    ///   - After a successful flush, the dirty set is cleared.
    pub fn flush_block(&self) -> Result<usize, SvmError> {
        let dirty_keys = self.dirty.drain();
        if dirty_keys.is_empty() {
            debug!("flush_block: nothing to flush");
            return Ok(0);
        }

        let count = dirty_keys.len();
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(SVM_ACCOUNTS)?;

            for key_bytes in &dirty_keys {
                {
                    let pubkey = Pubkey::new_from_array(*key_bytes);
                    if let Some(account) = self.hot_state.get(&pubkey) {
                        let stored = StoredAccount::from(account.value());
                        let serialized = borsh::to_vec(&stored)
                            .map_err(|e| SvmError::SerializationError(e.to_string()))?;
                        table.insert(key_bytes.as_slice(), serialized.as_slice())?;
                    }
                    // If account was deleted (lamports=0), tombstone it
                    // (leave in table with 0 lamports — account stays but empty)
                }
            }
        }

        write_txn.commit()?;

        info!(accounts_flushed = count, "flush_block: ACID commit OK");
        Ok(count)
    }

    // ========================================================================
    // SYSTEM TRANSFER — pure-Rust implementation (Phase 1B.1)
    // ========================================================================
    //
    // Validates and executes a lamport transfer between two accounts without
    // invoking the rBPF VM. This mirrors the System Program's transfer logic
    // exactly so we can validate the full account load → mutate → store path
    // before wiring in the actual instruction processor.
    //
    // Invariants enforced:
    //   1. from_lamports >= amount                       (no overdraft)
    //   2. to_lamports + amount <= u64::MAX              (zero-sum: no creation)
    //   3. Both accounts land in hot_state after transfer (storage always updated)
    //
    pub fn system_transfer(
        &self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
    ) -> Result<(), SvmError> {
        use solana_sdk::account::WritableAccount;

        if lamports == 0 {
            return Err(SvmError::InvalidTransaction(
                "Transfer amount must be > 0".into(),
            ));
        }

        // Load sender — must exist
        let mut from_account = self
            .hot_state
            .get(from)
            .map(|r| r.clone())
            .ok_or_else(|| SvmError::AccountNotFound(from.to_string()))?;

        // Check sender has enough lamports
        if from_account.lamports() < lamports {
            return Err(SvmError::InsufficientFunds {
                available: from_account.lamports(),
                required: lamports,
            });
        }

        // Load or create recipient
        let mut to_account = self
            .hot_state
            .get(to)
            .map(|r| r.clone())
            .unwrap_or_else(|| {
                // New account: System Program owned, rent-exempt, empty data
                AccountSharedData::create(
                    0,
                    vec![],
                    solana_sdk::system_program::id(),
                    false,
                    RENT_EPOCH_EXEMPT,
                )
            });

        // Zero-sum guard: recipient balance must not overflow u64
        let new_to = to_account
            .lamports()
            .checked_add(lamports)
            .ok_or(SvmError::LamportOverflow)?;

        // Debit sender
        from_account.set_lamports(from_account.lamports() - lamports);
        // Credit recipient
        to_account.set_lamports(new_to);

        // Persist to hot_state (dirty-marked — will flush at end of block)
        self.store_account(from, from_account);
        self.store_account(to, to_account);

        Ok(())
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /// Total number of accounts in hot state.
    pub fn account_count(&self) -> usize {
        self.hot_state.len()
    }

    /// Number of accounts pending flush.
    pub fn dirty_count(&self) -> usize {
        self.dirty.inner.len()
    }

    /// Compute total lamports across all hot-state accounts.
    ///
    /// Used by proof-of-reserves: the sum must equal total BB supply × LAMPORTS_PER_BB.
    pub fn total_lamports(&self) -> u64 {
        use solana_sdk::account::ReadableAccount;
        self.hot_state
            .iter()
            .map(|e| e.value().lamports())
            .fold(0u64, |acc, l| acc.saturating_add(l))
    }

    // ========================================================================
    // TRANSACTION LOG — Phase 2B: persistent tx results + address index
    // ========================================================================
    //
    // These methods write to SVM_TX_LOG, SVM_SIGNATURES, and SVM_ADDR_SIGS
    // tables. They are called after a transaction has been confirmed and the
    // block is committed.
    //
    // FLOW:
    //   1. execute_transfer() builds TransactionExecutionResult (in-memory)
    //   2. end_of_block() flushes accounts (existing)
    //   3. store_transaction_result() persists the tx log + signature index
    //      (called from the RPC sendTransaction path after execution)
    //
    // For getTransaction: read from SVM_TX_LOG by signature.
    // For getSignaturesForAddress: prefix-scan SVM_ADDR_SIGS for "addr:*".

    /// Persist a confirmed transaction result to the tx log and address index.
    ///
    /// This makes the transaction discoverable via `getTransaction` and
    /// `getSignaturesForAddress`. The write is a single ACID ReDB transaction.
    pub fn store_transaction_result(
        &self,
        result: &crate::svm::types::StoredTransactionResult,
    ) -> Result<(), SvmError> {
        let serialized = borsh::to_vec(result)
            .map_err(|e| SvmError::SerializationError(e.to_string()))?;

        let write_txn = self.db.begin_write()?;
        {
            // 1. Store in tx log: signature → full result
            let mut tx_log = write_txn.open_table(SVM_TX_LOG)?;
            tx_log.insert(result.signature.as_str(), serialized.as_slice())?;

            // 2. Store in signature dedup table
            let mut sigs = write_txn.open_table(SVM_SIGNATURES)?;
            let sig_bytes = result.signature.as_bytes();
            sigs.insert(sig_bytes, result.slot)?;

            // 3. Index each involved address → this signature
            let mut addr_sigs = write_txn.open_table(SVM_ADDR_SIGS)?;
            for addr in &result.account_keys {
                // Composite key: "addr:signature" so we can prefix-scan by address
                let composite = format!("{}:{}", addr, result.signature);
                addr_sigs.insert(composite.as_str(), result.slot)?;
            }
        }
        write_txn.commit()?;

        debug!(
            signature = %result.signature,
            slot = result.slot,
            success = result.success,
            accounts = result.account_keys.len(),
            "Transaction result persisted to ReDB"
        );
        Ok(())
    }

    /// Look up a confirmed transaction by its signature (base58).
    ///
    /// Returns `None` if the transaction has not been confirmed yet or
    /// does not exist in the log.
    pub fn get_transaction_result(
        &self,
        signature: &str,
    ) -> Result<Option<crate::svm::types::StoredTransactionResult>, SvmError> {
        let read_txn = self.db.begin_read()
            .map_err(|e| SvmError::StorageError(e.to_string()))?;
        let table = read_txn.open_table(SVM_TX_LOG)
            .map_err(|e| SvmError::StorageError(e.to_string()))?;

        match table.get(signature) {
            Ok(Some(val_guard)) => {
                let bytes: &[u8] = val_guard.value();
                let stored = crate::svm::types::StoredTransactionResult::try_from_slice(bytes)
                    .map_err(|e| SvmError::SerializationError(e.to_string()))?;
                Ok(Some(stored))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SvmError::StorageError(e.to_string())),
        }
    }

    /// Check if a signature has already been processed (persistent dedup).
    ///
    /// Complements the in-memory `seen_tx_ids` in BlackBookSVM. This catches
    /// replays across restarts where the in-memory set has been cleared.
    pub fn signature_exists(&self, signature: &str) -> bool {
        let Ok(read_txn) = self.db.begin_read() else { return false };
        let Ok(table) = read_txn.open_table(SVM_TX_LOG) else { return false };
        matches!(table.get(signature), Ok(Some(_)))
    }

    /// Get all transaction signatures for a given address (base58-encoded pubkey).
    ///
    /// Returns signatures ordered by slot (newest first), up to `limit` entries.
    /// Supports the `getSignaturesForAddress` RPC method.
    pub fn get_signatures_for_address(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<crate::svm::types::StoredTransactionResult>, SvmError> {
        let read_txn = self.db.begin_read()
            .map_err(|e| SvmError::StorageError(e.to_string()))?;
        let addr_table = read_txn.open_table(SVM_ADDR_SIGS)
            .map_err(|e| SvmError::StorageError(e.to_string()))?;
        let tx_table = read_txn.open_table(SVM_TX_LOG)
            .map_err(|e| SvmError::StorageError(e.to_string()))?;

        // Prefix scan: all keys starting with "address:"
        let prefix = format!("{}:", address);
        let mut signatures = Vec::new();

        // ReDB range scan: from "addr:" to "addr;", where ';' is one past ':'
        let range_end = format!("{};", address);
        let range = addr_table.range(prefix.as_str()..range_end.as_str())
            .map_err(|e| SvmError::StorageError(e.to_string()))?;

        for entry in range {
            let (key_guard, _slot) = entry.map_err(|e| SvmError::StorageError(e.to_string()))?;
            let composite_key: &str = key_guard.value();

            // Extract the signature from "addr:signature"
            if let Some(sig) = composite_key.strip_prefix(&prefix) {
                // Look up the full tx result
                if let Ok(Some(val_guard)) = tx_table.get(sig) {
                    let bytes: &[u8] = val_guard.value();
                    if let Ok(stored) = crate::svm::types::StoredTransactionResult::try_from_slice(bytes) {
                        signatures.push(stored);
                    }
                }
            }

            if signatures.len() >= limit {
                break;
            }
        }

        // Sort by slot descending (newest first) — Solana convention
        signatures.sort_by(|a, b| b.slot.cmp(&a.slot));
        Ok(signatures)
    }
}
