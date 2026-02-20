// ============================================================================
// BLACKBOOK SVM — RUNTIME  (BlackBookSVM)
// ============================================================================
//
// BlackBookSVM is the execution engine that wraps SvmAccountsDB and drives
// transaction execution through either:
//   A) Native Rust implementations of built-in programs (Phase 1B.1, current)
//   B) Solana's actual instruction processors via InvokeContext (Phase 1B.2)
//   C) Arbitrary BPF programs loaded from ELF binaries (Phase 3)
//
// BLOCKHASH QUEUE
// ───────────────
// Mirrors Solana's recent-blockhashes scheme:
//   - Up to MAX_RECENT_BLOCKHASHES (150) slot hashes kept.
//   - Entries older than 150 slots are evicted.
//   - Any transaction referencing an evicted hash is rejected (replay protection).
//
// EXECUTION MODEL (Phase 1)
// ─────────────────────────
// execute_transaction() is intentionally synchronous — the Rayon-based
// ParallelScheduler calls it in parallel via execute_batch().
// Thread-safety flows from SvmAccountsDB (DashMap sharding) — no lock here.
//
// RENT = 0
// ────────
// BlackBookSVM never charges rent. Accounts are created with
// rent_epoch = RENT_EPOCH_EXEMPT everywhere. This is enforced in types.rs
// and accounts_db.rs; there is no rent-collection pass here.
//
// ============================================================================

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, warn};

use crate::svm::accounts_db::SvmAccountsDB;
use crate::svm::types::{
    SvmError, TransactionExecutionResult, MAX_COMPUTE_UNITS, MAX_RECENT_BLOCKHASHES,
};

#[cfg(feature = "svm")]
use solana_sdk::{
    hash::Hash,
    pubkey::Pubkey,
    signature::Signature,
};

// ============================================================================
// BLOCKHASH QUEUE — in-memory ring buffer
// ============================================================================

/// In-memory blockhash queue (mirrors Solana's 150-slot window).
///
/// ReDB persistence: BLOCKHASH_QUEUE table is written at flush_block time.
/// The in-memory queue is authoritative during execution; the ReDB copy is
/// for restart recovery only.
pub struct BlockhashQueue {
    /// (slot, hash_bytes) ordered from oldest→newest.
    entries: VecDeque<(u64, [u8; 32])>,
    /// Quick O(1) lookup: hash bytes → slot it was recorded at.
    #[cfg(feature = "svm")]
    index: DashMap<[u8; 32], u64>,
}

impl BlockhashQueue {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_RECENT_BLOCKHASHES as usize + 1),
            #[cfg(feature = "svm")]
            index: DashMap::new(),
        }
    }

    /// Seed the queue with the genesis hash at slot 0.
    #[cfg(feature = "svm")]
    pub fn seed_genesis(&mut self, genesis_hash: Hash) {
        self.record(0, genesis_hash);
    }

    /// Record a new blockhash for `slot` and evict entries older than 150 slots.
    #[cfg(feature = "svm")]
    pub fn record(&mut self, slot: u64, hash: Hash) {
        let bytes = hash.to_bytes();
        self.entries.push_back((slot, bytes));
        self.index.insert(bytes, slot);

        // Evict entries if the queue exceeds MAX_RECENT_BLOCKHASHES
        while self.entries.len() > MAX_RECENT_BLOCKHASHES as usize {
            if let Some((_, evicted)) = self.entries.pop_front() {
                self.index.remove(&evicted);
            }
        }
    }

    /// Returns `true` if the hash is in the recent window.
    #[cfg(feature = "svm")]
    pub fn is_valid(&self, hash: &Hash) -> bool {
        let bytes = hash.to_bytes();
        self.index.contains_key(&bytes)
    }

    /// Returns `true` if the hash is in the recent window (raw bytes variant).
    pub fn is_valid_bytes(&self, bytes: &[u8; 32]) -> bool {
        self.entries.iter().any(|(_, h)| h == bytes)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the most recently recorded hash, or `None` if the queue is empty.
    #[cfg(feature = "svm")]
    pub fn latest_hash(&self) -> Option<Hash> {
        self.entries.back().map(|(_, bytes)| Hash::new_from_array(*bytes))
    }
}

// ============================================================================
// SIMPLE TRANSFER REQUEST — Phase 1 input type
// ============================================================================

/// A parsed, validated transfer request for Phase 1 SVM execution.
///
/// During the transition period, the legacy `TxData::TransferBb` variant is
/// converted to this struct by the tx_adapter. Future phases will replace
/// this with a full `SanitizedTransaction`.
#[cfg(feature = "svm")]
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Transaction identifier (hex-encoded, used as idempotency key).
    pub tx_id: String,

    /// Sender public key (32 bytes, Solana-format).
    pub from: Pubkey,

    /// Recipient public key (32 bytes, Solana-format).
    pub to: Pubkey,

    /// Amount in lamports. 1 BB = LAMPORTS_PER_BB lamports.
    /// INVARIANT: always u64. This was already the f64 that was converted.
    pub lamports: u64,

    /// Recent blockhash that this transaction was signed against.
    pub recent_blockhash: Hash,
}

// ============================================================================
// BlackBookSVM
// ============================================================================

/// The SVM execution engine for BlackBook L1.
///
/// One instance exists per block producer. The `accounts_db` is shared via
/// Arc with the `ParallelScheduler` so both see the same hot-state.
pub struct BlackBookSVM {
    /// Account state — shared with scheduler and block producer.
    pub accounts_db: Arc<SvmAccountsDB>,

    /// Recent blockhash queue (not shared — owned by the SVM alone).
    blockhash_queue: BlockhashQueue,

    /// Per-transaction compute-unit limit.
    max_compute_units: u64,

    /// Seen transaction IDs for intra-block deduplication.
    /// Cleared after each block flush. The persistent dedup lives in
    /// SVM_SIGNATURES table (ReDB).
    seen_tx_ids: DashMap<String, u64>,

    /// Current slot number (set by BlockProducer at the start of each slot).
    current_slot: u64,
}

impl BlackBookSVM {
    // ========================================================================
    // CONSTRUCTION
    // ========================================================================

    /// Create a new SVM instance.
    ///
    /// `genesis_hash` seeds the blockhash queue so that slot-0 transactions
    /// have a valid recent blockhash to reference.
    #[cfg(feature = "svm")]
    pub fn new(accounts_db: Arc<SvmAccountsDB>, genesis_hash: Hash) -> Self {
        let mut blockhash_queue = BlockhashQueue::new();
        blockhash_queue.seed_genesis(genesis_hash);

        Self {
            accounts_db,
            blockhash_queue,
            max_compute_units: MAX_COMPUTE_UNITS,
            seen_tx_ids: DashMap::new(),
            current_slot: 0,
        }
    }

    /// Variant for builds without the svm feature (keeps type available).
    #[cfg(not(feature = "svm"))]
    pub fn new_stub(accounts_db: Arc<SvmAccountsDB>) -> Self {
        Self {
            accounts_db,
            blockhash_queue: BlockhashQueue::new(),
            max_compute_units: MAX_COMPUTE_UNITS,
            seen_tx_ids: DashMap::new(),
            current_slot: 0,
        }
    }

    // ========================================================================
    // SLOT MANAGEMENT
    // ========================================================================

    /// Called by BlockProducer at the start of each slot.
    ///
    /// Records the new blockhash into the queue and advances the slot counter.
    /// The `slot_hash` is the PoH hash for this slot (from `PoHService`).
    #[cfg(feature = "svm")]
    pub fn advance_slot(&mut self, slot: u64, slot_hash: Hash) {
        self.current_slot = slot;
        self.blockhash_queue.record(slot, slot_hash);
        debug!(slot = slot, "SVM slot advanced");
    }

    pub fn current_slot(&self) -> u64 {
        self.current_slot
    }

    // ========================================================================
    // BLOCKHASH VALIDATION
    // ========================================================================

    #[cfg(feature = "svm")]
    pub fn is_valid_blockhash(&self, hash: &Hash) -> bool {
        self.blockhash_queue.is_valid(hash)
    }

    /// Return the most recent blockhash in the queue (for seeding tx requests).
    #[cfg(feature = "svm")]
    pub fn current_blockhash(&self) -> Hash {
        self.blockhash_queue
            .latest_hash()
            .unwrap_or_else(Hash::default)
    }

    pub fn blockhash_queue_len(&self) -> usize {
        self.blockhash_queue.len()
    }

    // ========================================================================
    // EXECUTION — Phase 1B.1: native Rust System Transfer
    // ========================================================================

    /// Execute a direct lamport transfer between two accounts.
    ///
    /// This is the Phase 1 entry point. It does NOT use rBPF — it calls the
    /// pure-Rust system_transfer on SvmAccountsDB.  Phase 1B.2 will replace
    /// this with the actual `system_processor::process_instruction` once
    /// `InvokeContext` setup is validated.
    ///
    /// Returns a `TransactionExecutionResult` that the scheduler records in the
    /// block. The scheduler calls `flush_block()` after the batch completes.
    #[cfg(feature = "svm")]
    pub fn execute_transfer(
        &self,
        req: &TransferRequest,
    ) -> TransactionExecutionResult {
        // 1. Blockhash validation — reject stale / replayed transactions
        if !self.blockhash_queue.is_valid(&req.recent_blockhash) {
            return TransactionExecutionResult::err(
                req.tx_id.clone(),
                SvmError::InvalidBlockhash,
            );
        }

        // 2. Intra-block dedup
        if self.seen_tx_ids.contains_key(&req.tx_id) {
            return TransactionExecutionResult::err(
                req.tx_id.clone(),
                SvmError::DuplicateSignature(req.tx_id.clone()),
            );
        }

        // 3. Execute
        match self.accounts_db.system_transfer(&req.from, &req.to, req.lamports) {
            Ok(()) => {
                // Mark as seen (intra-block dedup only; persist in flush if needed)
                self.seen_tx_ids.insert(req.tx_id.clone(), self.current_slot);

                // Build delta record for the scheduler / explorer
                let deltas = vec![
                    (req.from.to_string(), -(req.lamports as i64)),
                    (req.to.to_string(), req.lamports as i64),
                ];

                TransactionExecutionResult::ok(
                    req.tx_id.clone(),
                    21_000, // Baseline compute units for a system transfer
                    deltas,
                )
            }
            Err(e) => TransactionExecutionResult::err(req.tx_id.clone(), e),
        }
    }

    /// Execute a batch of transfers (called by ParallelScheduler).
    ///
    /// Rayon can call this method on multiple threads simultaneously because
    /// `SvmAccountsDB::system_transfer` uses `DashMap` sharding internally.
    /// Conflicts are resolved upstream by `AccountLockManager`.
    #[cfg(feature = "svm")]
    pub fn execute_transfer_batch(
        &self,
        requests: &[TransferRequest],
    ) -> Vec<TransactionExecutionResult> {
        requests
            .iter()
            .map(|r| self.execute_transfer(r))
            .collect()
    }

    // ========================================================================
    // END-OF-BLOCK
    // ========================================================================

    /// Flush all dirty accounts to ReDB and reset intra-block state.
    ///
    /// Called by BlockProducer AFTER all transactions in the slot have been
    /// executed. Returns the number of accounts persisted.
    pub fn end_of_block(&mut self) -> Result<usize, SvmError> {
        let flushed = self.accounts_db.flush_block()?;
        self.seen_tx_ids.clear();
        Ok(flushed)
    }
}
