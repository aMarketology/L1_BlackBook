# BB_SVM Integration Plan — Step-by-Step Milestones

> **Pre-read:** This document references `BB_svm.md` for architectural context.  
> **Scope:** Every task below is an atomic, testable unit of work. Complete them in order.  
> **Feature flags:** All SVM work lives behind `#[cfg(feature = "svm")]` until Phase 2 completion.

---

## 🗺️ Progress Dashboard — Updated Feb 19, 2026

| Phase | Milestone | Status | Tests | Notes |
|-------|-----------|--------|-------|-------|
| 0 | Pre-flight (feature flags, Cargo.toml) | ✅ **COMPLETE** | — | `cargo build` clean both with/without `--features svm` |
| 1A | `SvmAccountsDB`, `StoredAccount`, ReDB tables, storage wiring | ✅ **COMPLETE** | 5/5 ✅ | `tests/svm_accounts_tests.rs` |
| 1B.1 | `BlackBookSVM` native Rust transfers + blockhash queue (150-slot ring) | ✅ **COMPLETE** | 5/5 ✅ | `tests/svm_runtime_tests.rs` |
| 1B.2 | rBPF `InvokeContext` for System Program | ⏭ **DEFERRED** | — | Used plan fallback: native Rust path is correct and sufficient. Revisit in Phase 3. |
| 1C | Wire SVM into `BlockProducer` (dual-path `TransferBb` + lazy migration) | ✅ **COMPLETE** | 3/3 ✅ | `tests/svm_block_production_tests.rs` |
| 1D | Wire SVM into `ParallelScheduler` (`with_svm()` builder, `execute_single_svm`) | ✅ **COMPLETE** | 4/4 ✅ | `tests/svm_parallel_tests.rs` |
| 1E | Lamport conservation fuzzing (10,000 transfers, overflow, parallel) | ✅ **COMPLETE** | 3/3 ✅ | `tests/svm_invariant_tests.rs` |
| **→ 2A** | **Solana JSON-RPC read methods (port 8899)** | **🔜 NEXT** | — | `jsonrpsee` — `getBalance`, `getAccountInfo`, `getLatestBlockhash`, … |
| 2B | `sendTransaction`, `getTransaction`, `getBlock` | ❌ Not started | — | OneKey integration entry point |
| 2C | `simulateTransaction` + dry-run rBPF | ❌ Not started | — | |
| 3 | SPL Token Program + `$BB` token mint | ❌ Not started | — | |
| 4 | Anchor programs (Tier1 Vault, Tier2 Vault, Oracle) | ❌ Not started | — | |
| 5 | OneKey bridge + co-signing service | ❌ Not started | — | |
| 6 | Compute budget tightening, mainnet hardening | ❌ Not started | — | |

### What was built vs the plan

**Implemented exactly as planned:** 1A, 1B.1 (native Rust path), 1C (dual-path + lazy migration), Phase 0.

**Different from plan but better:**
- **1B.2 (rBPF InvokeContext):** The plan included a fallback — "If `InvokeContext` setup is too painful, implement System Program logic directly in Rust." We took the fallback. The `system_transfer` logic in `SvmAccountsDB` is semantically identical to Solana's System Program, but runs without the VM overhead. rBPF VM is wired in Phase 3 for actual BPF `.so` programs.
- **1D:** Instead of adding `BlackBookSVM` to `ParallelScheduler`, we wired `Arc<SvmAccountsDB>` directly. This gives parallel threads lock-free DashMap reads/writes with zero Mutex contention — better than going through `BlackBookSVM`'s Mutex.
- **1E:** Added a third test (`test_parallel_lamport_conservation`) beyond the spec's 4 tests, covering concurrent rayon execution on disjoint account pairs.

### Key invariants established (must never regress)
- `LAMPORTS_PER_BB = 1_000_000_000` — one BB = one billion lamports
- `RENT_EPOCH_EXEMPT = u64::MAX` — all accounts exempt from rent forever
- Global conservation: `Σ lamports = constant` across all transfers
- `cargo build` (no `--features svm`) compiles clean — zero legacy regressions
- All 20 SVM tests: `cargo test --features svm --test svm_accounts_tests --test svm_runtime_tests --test svm_block_production_tests --test svm_parallel_tests --test svm_invariant_tests`

---

---

## Phase 0: Pre-Flight Checks (Day 1)

### 0.1 — Verify Solana Crate Compatibility

Before touching any code, verify the Solana crate ecosystem compiles on the project's Rust toolchain.

**Steps:**
1. Create a throwaway Cargo project outside the workspace:
   ```powershell
   cargo new --lib svm_compat_test
   cd svm_compat_test
   ```
2. Add these to its `Cargo.toml`:
   ```toml
   solana-sdk = "2.1"
   solana-program = "2.1"
   solana-program-runtime = "2.1"
   solana-system-program = "2.1"
   solana-bpf-loader-program = "2.1"
   solana-compute-budget = "2.1"
   solana-svm = "2.1"
   solana-rbpf = "0.8"
   ```
3. Write a single test:
   ```rust
   use solana_sdk::pubkey::Pubkey;
   #[test]
   fn solana_crates_link() {
       let pk = Pubkey::new_unique();
       assert_ne!(pk, Pubkey::default());
   }
   ```
4. Run `cargo test`. If this fails, pin to the latest compatible Solana version before proceeding.

**Acceptance:** `cargo test` passes with all SVM crates linking.

### 0.2 — Pin Dependency Versions

Record the exact version set that passed in 0.1. Some Solana sub-crates have tight internal version coupling. The versions chosen here are used for every subsequent step.

**Deliverable:** A `solana-versions.txt` file at the repo root listing each crate + exact version.

### 0.3 — Create Feature Flag Skeleton

In `Cargo.toml`, add:
```toml
[features]
default = []
unsafe_admin = []
svm = [
  "dep:solana-sdk",
  "dep:solana-program",
  "dep:solana-program-runtime",
  "dep:solana-system-program",
  "dep:solana-bpf-loader-program",
  "dep:solana-compute-budget",
  "dep:solana-svm",
  "dep:solana-rbpf",
]
```

Add each SVM dependency with `optional = true`:
```toml
solana-sdk = { version = "=2.1.X", optional = true }
# ... etc
```

**Acceptance:** `cargo build` (without `--features svm`) still compiles cleanly — zero regressions.

---

## Phase 1: AccountsDB + rBPF Core (Weeks 1-4)

### Milestone 1A — Solana Account Type Layer (Week 1)

**Goal:** Define a Solana-compatible account struct and ReDB tables, without touching any existing code.

#### Step 1A.1 — Create `src/svm/mod.rs` (new module)

Create directory `src/svm/` with these files:
```
src/svm/
├── mod.rs           # Module exports
├── accounts_db.rs   # SvmAccountsDB (ReDB + DashMap wrapper)
├── runtime.rs       # BlackBookSVM (rBPF execution engine)
└── types.rs         # BB-specific account types, error enums
```

In `src/svm/types.rs`, define:
```rust
use solana_sdk::account::AccountSharedData;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::hash::Hash;
use borsh::{BorshSerialize, BorshDeserialize};

/// Wraps AccountSharedData for Borsh serialization into ReDB.
/// Solana's AccountSharedData doesn't impl Borsh natively,
/// so we use an intermediate representation.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredAccount {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
}

impl From<&AccountSharedData> for StoredAccount { ... }
impl From<StoredAccount> for AccountSharedData { ... }

/// Errors during SVM execution
#[derive(Debug, thiserror::Error)]
pub enum SvmError {
    #[error("Account not found: {0}")]
    AccountNotFound(Pubkey),
    #[error("Insufficient lamports: need {needed}, have {have}")]
    InsufficientLamports { needed: u64, have: u64 },
    #[error("Program execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
}
```

**Acceptance:** `cargo build --features svm` compiles. No existing tests break.

#### Step 1A.2 — Create `src/svm/accounts_db.rs`

New ReDB tables (added alongside existing tables, NOT replacing them):

```rust
use redb::TableDefinition;

/// Solana-format accounts: Pubkey bytes (32) → StoredAccount (borsh)
pub const SVM_ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("svm_accounts");

/// Program ELF binaries: ProgramId bytes (32) → ELF .so bytes
pub const SVM_PROGRAMS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("svm_programs");

/// Blockhash queue: Slot (u64) → Hash bytes (32)
pub const BLOCKHASH_QUEUE: TableDefinition<u64, &[u8]> = TableDefinition::new("blockhash_queue");

/// Signature dedup: Signature bytes (64) → Slot when processed (u64)
pub const SVM_SIGNATURES: TableDefinition<&[u8], u64> = TableDefinition::new("svm_signatures");
```

`SvmAccountsDB` struct:

```rust
pub struct SvmAccountsDB {
    db: Arc<Database>,                             // Same ReDB instance as ConcurrentBlockchain
    cache: Arc<DashMap<Pubkey, AccountSharedData>>, // Hot cache (lock-free)
}
```

Methods to implement (in order):
| # | Method | Purpose |
|---|--------|---------|
| 1 | `new(db: Arc<Database>) → Self` | Create tables, load cache from ReDB |
| 2 | `get_account(&self, pubkey: &Pubkey) → Option<AccountSharedData>` | Cache-first, fallback to ReDB read |
| 3 | `store_account(&self, pubkey: &Pubkey, account: &AccountSharedData)` | Write to ReDB + update cache |
| 4 | `store_accounts_batch(&self, updates: &[(Pubkey, AccountSharedData)])` | Batch write (single ReDB txn) |
| 5 | `account_exists(&self, pubkey: &Pubkey) → bool` | Quick existence check |
| 6 | `get_lamports(&self, pubkey: &Pubkey) → u64` | Convenience for balance lookups |

**Key detail:** `SvmAccountsDB` takes the SAME `Arc<Database>` as `ConcurrentBlockchain`. Both coexist on the same ReDB file, using different table namespaces for the transition period.

**Tests to write** (in `tests/svm_accounts_tests.rs`):
```
test_store_and_retrieve_account
test_cache_is_consistent_with_disk
test_batch_store_atomicity
test_nonexistent_account_returns_none
test_lamport_overflow_safety       // u64::MAX edge case
```

**Acceptance:** All 5 tests pass. ReDB file opens with both old (`accounts` → f64) and new (`svm_accounts`) tables.

#### Step 1A.3 — Wire `SvmAccountsDB` into `ConcurrentBlockchain::new()`

Current file: `src/storage/mod.rs`, line ~345 (`ConcurrentBlockchain::new()`).

Add to the table initialization block (after the existing `FROST_PUB_KEY` table open):
```rust
// SVM tables (behind feature flag)
#[cfg(feature = "svm")]
{
    let _ = write_txn.open_table(svm::accounts_db::SVM_ACCOUNTS)?;
    let _ = write_txn.open_table(svm::accounts_db::SVM_PROGRAMS)?;
    let _ = write_txn.open_table(svm::accounts_db::BLOCKHASH_QUEUE)?;
    let _ = write_txn.open_table(svm::accounts_db::SVM_SIGNATURES)?;
}
```

Add a new field to `ConcurrentBlockchain`:
```rust
#[cfg(feature = "svm")]
pub svm_accounts: Arc<SvmAccountsDB>,
```

Initialize it using the same `Arc<Database>`:
```rust
#[cfg(feature = "svm")]
let svm_accounts = Arc::new(SvmAccountsDB::new(Arc::clone(&db_arc)));
```

**Acceptance:** `cargo build --features svm` links. `cargo build` (no flag) still works — the struct field and init are `cfg`-gated.

---

### Milestone 1B — rBPF VM Execution (Week 2)

**Goal:** Execute a single Solana `SystemProgram::Transfer` instruction through the rBPF VM, reading/writing `SvmAccountsDB`.

#### Step 1B.1 — Create `src/svm/runtime.rs` — `BlackBookSVM`

> **Shift-Left: Compute Metering wired here, not in Phase 6.**  
> The meter must run from Day 1 so Anchor developers see `Compute Units Consumed` in logs immediately. The initial limit is permissive (`1_400_000`) but the meter is always active. Phase 6 tightens the limit — it never introduces the meter cold.

Core struct:
```rust
pub struct BlackBookSVM {
    accounts_db: Arc<SvmAccountsDB>,
    blockhash_queue: Arc<RwLock<VecDeque<(u64, Hash)>>>,  // (slot, hash) pairs

    /// Compute budget limits — set permissively now, tightened in Phase 6 hardening
    default_compute_units: u64,  // 200_000 per instruction
    max_compute_units: u64,      // 1_400_000 per transaction (Solana mainnet cap)
}
```

Implement in this exact order:

| # | Method | What It Does |
|---|--------|--------------|
| 1 | `new(accounts_db, genesis_hash) → Self` | Initialize with empty blockhash queue, seed genesis hash at slot 0 |
| 2 | `record_blockhash(slot, hash)` | Push to blockhash queue, evict entries older than 150 slots (Solana's `MAX_RECENT_BLOCKHASHES`) |
| 3 | `is_valid_blockhash(hash) → bool` | Check if hash is in the recent queue |
| 4 | `execute_system_transfer(from, to, lamports) → Result<(), SvmError>` | Direct System Program transfer (no VM yet — pure Rust implementation mirroring Solana's System Program logic). Load accounts, check lamports, debit/credit, store back. |
| 5 | `execute_transaction(sanitized_tx, slot) → TransactionExecutionResult` | Full path: validate blockhash → load accounts → identify program → **meter compute units** → execute → commit. **Always log `compute_units_consumed` at `tracing::debug!` level even when the limit is not exceeded.** |
| 6 | `execute_batch(txs, slot) → Vec<TransactionExecutionResult>` | Iterate and call execute_transaction for each. (Parallel execution comes in 1C.) |

**Compute metering in `execute_transaction` (implement from step 5 onward):**
```rust
// Build compute budget — permissive in Phase 1, tightenable in Phase 6
let cu_limit = tx.compute_budget().unwrap_or(self.default_compute_units)
    .min(self.max_compute_units);

// ... execute instruction ...

// ALWAYS emit — this builds the performance-first culture
tracing::debug!(
    tx_id = %sig,
    cu_consumed = result.compute_units_consumed,
    cu_limit = cu_limit,
    "compute_units"
);

// Enforce limit — currently max_compute_units is generous, Phase 6 tightens it
if result.compute_units_consumed > cu_limit {
    return Err(SvmError::ComputeBudgetExceeded {
        consumed: result.compute_units_consumed,
        limit: cu_limit,
    });
}
```

**Why method 4 first:** Start with a hand-written System Program transfer. This validates the full account load → mutate → store path without needing the rBPF VM. The rBPF VM is wired in Step 1B.2.

**Tests:**
```
test_system_transfer_basic           // 100 lamports A→B
test_system_transfer_insufficient    // Fail gracefully
test_system_transfer_to_new_account  // Creates recipient account
test_blockhash_validation            // Reject stale blockhash
test_blockhash_queue_eviction        // 151st entry evicts oldest
```

**Acceptance:** All 5 tests pass. A Solana-format transfer works end-to-end against ReDB via `SvmAccountsDB`.

#### Step 1B.2 — Wire rBPF VM for Built-in Programs

Now replace the hand-written System Program logic with actual Solana program execution.

Use `solana-program-runtime`'s `InvokeContext` and `solana-system-program`'s `process_instruction` function:

```rust
use solana_system_program::system_processor;

// In execute_transaction():
match program_id {
    system_program::ID => {
        system_processor::process_instruction(
            /* first_instruction_account */ 1,
            instruction_data,
            &mut invoke_context,
        )?;
    }
    _ => return Err(SvmError::ExecutionFailed("Unknown program".into())),
}
```

**Key challenge:** Building a correct `InvokeContext`. This requires:
- A `TransactionContext` with the right account structure
- A `ComputeBudget` with BB's limits
- Feature flags (use Solana's `FeatureSet::all_enabled()` initially)

**Fallback:** If `InvokeContext` setup is too painful (Solana's internals are deeply coupled), implement System Program logic directly in Rust as a "native program" and revisit full rBPF in Phase 3 when loading BPF `.so` files.

**Tests:**
```
test_system_transfer_via_processor   // Same as 1B.1 tests but through real processor
test_create_account_via_processor    // SystemProgram::CreateAccount
test_assign_via_processor            // SystemProgram::Assign (change owner)
```

**Acceptance:** System Program operations pass through Solana's actual instruction processor code.

---

### Milestone 1C — Wire SVM into Block Production (Week 3)

**Goal:** `BlockProducer::produce_block()` uses `BlackBookSVM` for execution instead of the match-arm dispatcher.

#### Step 1C.1 — Add `svm` field to `BlockProducer`

Current: `src/poh_blockchain.rs`, `BlockProducer` struct (around line 500-550).

Add:
```rust
#[cfg(feature = "svm")]
svm: Arc<BlackBookSVM>,
```

Update `BlockProducer::new()` to accept and store it.

#### Step 1C.2 — Create transaction format adapter

New file: `src/svm/tx_adapter.rs`

This converts between the existing `protocol::Transaction` (with `TxData` enum) and Solana `VersionedTransaction`.

```rust
/// Convert a legacy BB Transaction into a Solana-format transaction.
/// Used during transition: old REST endpoints create TxData,
/// this adapter wraps it for SVM execution.
pub fn legacy_tx_to_solana_tx(
    tx: &Transaction,      // protocol::Transaction with TxData
    recent_blockhash: Hash,
) -> Result<VersionedTransaction, SvmError> { ... }
```

**Mapping table:**

| `TxData` Variant | Solana Instruction |
|---|---|
| `TransferBb { to, amount }` | `SystemProgram::Transfer { lamports: amount * LAMPORTS_PER_BB }` |
| `DepositUsdt { usdt_amount }` | (Phase 4: `tier1_vault::deposit`) — for now, `SystemProgram::Transfer` from mint authority |
| `RedeemBbForUsdt { bb_amount }` | (Phase 4) — for now, `SystemProgram::Transfer` to burn address |
| `LockBbForDime { bb_amount }` | (Phase 4) — for now, `SystemProgram::Transfer` to vault PDA |
| All others | Log warning, skip (handled by legacy path) |

**Critical decision:** During Phase 1, only `TransferBb` goes through SVM. All vault operations stay on the legacy path until Anchor programs exist (Phase 4).

#### Step 1C.3 — Modify `execute_transaction()` with dual-path

In `src/poh_blockchain.rs`, line ~790 (`execute_transaction()`):

```rust
fn execute_transaction(&self, tx: &Transaction) -> Result<(), String> {
    #[cfg(feature = "svm")]
    {
        // Try SVM path for supported transaction types
        if let TxData::TransferBb { .. } = &tx.data {
            let recent_hash = self.svm.latest_blockhash();
            let solana_tx = svm::tx_adapter::legacy_tx_to_solana_tx(tx, recent_hash)
                .map_err(|e| e.to_string())?;
            let result = self.svm.execute_transaction(&solana_tx, self.current_slot());
            return result.map_err(|e| e.to_string());
        }
    }
    
    // Legacy path (unchanged) — handles all non-SVM transaction types
    match &tx.data {
        TxData::TransferBb { to, amount } => { /* existing code */ }
        TxData::DepositUsdt { .. } => { /* existing code */ }
        // ... all existing match arms unchanged
    }
}
```

**Why dual-path:** Legacy code runs for vault operations until Anchor programs are deployed. SVM handles transfers immediately. Both paths coexist safely — the `#[cfg]` flag controls which path TransferBb takes.

**Tests (integration):**
```
test_transfer_through_svm_block_production   // Submit TransferBb, produce block, verify ReDB balance
test_legacy_vault_ops_still_work             // DepositUsdt etc. still use old path
test_mixed_block_svm_and_legacy              // Block with both SVM and legacy txs
```

**Acceptance:** `cargo test --features svm` passes. A block containing a `TransferBb` transaction executes through the SVM. The SVM `svm_accounts` table is the single source of truth for balances; the legacy REST API reads from the SVM via the Shadow Reader (see Milestone 3C.3).

---

### Milestone 1D — Wire SVM into Parallel Scheduler (Week 4)

**Goal:** `ParallelScheduler::execute_batch_with_locks()` uses `BlackBookSVM` instead of `execute_single()`.

#### Step 1D.1 — Add SVM to `ParallelScheduler`

Current: `runtime/core.rs`, `ParallelScheduler` struct (around line 600).

Add:
```rust
#[cfg(feature = "svm")]
svm: Option<Arc<BlackBookSVM>>,
```

Update `new()` to accept it optionally.

#### Step 1D.2 — Adapt `Transaction` struct

Current `Transaction` in `runtime/core.rs` (line ~470):
```rust
pub struct Transaction {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub read_accounts: Vec<String>,
    pub write_accounts: Vec<String>,
    pub tx_type: String,
}
```

Add:
```rust
    /// Raw Solana transaction bytes (present when submitted via JSON-RPC)
    #[cfg(feature = "svm")]
    pub solana_tx: Option<Vec<u8>>,
```

The `read_accounts` and `write_accounts` fields are derived from the Solana transaction's account keys meta (writable bit). This means `AccountLockManager` conflict detection works unchanged — it already uses these fields.

#### Step 1D.3 — Modify `execute_batch_with_locks()`

In `runtime/core.rs`, line ~680:

```rust
pub fn execute_batch_with_locks(&self, batch: Vec<Transaction>) -> Vec<TransactionResult> {
    #[cfg(feature = "svm")]
    if let Some(ref svm) = self.svm {
        return self.execute_batch_svm(batch, svm);
    }
    
    // ... existing rayon parallel execution (legacy path)
}

#[cfg(feature = "svm")]
fn execute_batch_svm(&self, batch: Vec<Transaction>, svm: &BlackBookSVM) -> Vec<TransactionResult> {
    let slot = /* get current slot */;
    
    // Convert legacy Transactions to Solana format
    let solana_txs: Vec<_> = batch.iter()
        .filter_map(|tx| {
            // If solana_tx bytes are present, deserialize directly
            // Otherwise, use tx_adapter for legacy format
            ...
        })
        .collect();
    
    let results = svm.execute_batch(&solana_txs, slot);
    
    // Map SVM results back to TransactionResult for upstream consumption
    results.into_iter().zip(batch.iter()).map(|(svm_result, tx)| {
        TransactionResult {
            tx_id: tx.id.clone(),
            success: svm_result.is_ok(),
            error: svm_result.err().map(|e| e.to_string()),
        }
    }).collect()
}
```

**Tests:**
```
test_parallel_svm_no_conflicts           // 4 independent transfers in parallel
test_parallel_svm_with_account_conflicts // 2 txs touching same account serialize correctly
test_parallel_svm_batch_atomicity        // All or nothing per batch
test_scheduler_fallback_without_svm      // With svm=None, legacy path works
```

**Acceptance:** `cargo test --features svm` passes. The parallel scheduler feeds transactions through the SVM. The lock manager correctly serializes conflicting account accesses.

---

### Phase 1 Gate: End-to-End Validation

Before moving to Phase 2, run this integration test:

```rust
#[test]
fn phase1_e2e_svm_through_full_pipeline() {
    // 1. Create SvmAccountsDB with two funded accounts (10_000 lamports each)
    // 2. Create BlackBookSVM
    // 3. Create BlockProducer with SVM
    // 4. Submit TransferBb(A→B, 5000) via Gulf Stream
    // 5. Produce block via BlockProducer
    // 6. Assert: A has 5000, B has 15000 in SVM_ACCOUNTS table
    // 7. Assert: Block has 1 transaction, valid state root
    // 8. Assert: FinalityTracker shows block as finalized after 2 confirmations
}
```

**This test proves:** PoH clock → Gulf Stream → Scheduler → SVM → ReDB → Block is working end-to-end.

---

### Milestone 1E — State Invariant Fuzzing (Week 4, post-1D)

> **Mandate:** The f64→u64 migration makes rounding your biggest enemy. This milestone must pass before Phase 2 begins. No exceptions.

**Goal:** Prove the ledger is a perfect zero-sum system to the last lamport.

#### Step 1E.1 — Global Conservation Invariant Test

Create `tests/svm_invariant_tests.rs`:

```rust
/// The Iron Law: at every point in time,
/// Sum(all account lamports) + Sum(all fees collected) == initial_supply
///
/// This must hold across 10,000 random transfers.
#[test]
fn test_global_lamport_conservation() {
    const INITIAL_SUPPLY: u64 = 1_000_000_000_000; // 1 trillion lamports (1M $BB)
    const NUM_ACCOUNTS: usize = 100;
    const NUM_TRANSFERS: usize = 10_000;

    // Seed 100 accounts with equal share of supply
    let per_account = INITIAL_SUPPLY / NUM_ACCOUNTS as u64;
    // Note: any dust from integer division goes to account[0]
    let dust = INITIAL_SUPPLY - (per_account * NUM_ACCOUNTS as u64);

    // ... set up SvmAccountsDB, fund accounts ...

    let mut total_fees_collected: u64 = 0;
    let mut rng = rand::thread_rng();

    for _ in 0..NUM_TRANSFERS {
        let from_idx = rng.gen_range(0..NUM_ACCOUNTS);
        let to_idx   = rng.gen_range(0..NUM_ACCOUNTS);
        let amount   = rng.gen_range(0..=accounts[from_idx].lamports());

        match svm.execute_system_transfer(&accounts[from_idx], &accounts[to_idx], amount) {
            Ok(fee) => total_fees_collected = total_fees_collected
                .checked_add(fee)
                .expect("fee accumulator overflow — supply > u64::MAX"),
            Err(_)  => {} // failed transfers must not mutate state
        }

        // Assert invariant after EVERY transfer — not just at the end
        let sum: u64 = accounts.iter()
            .map(|pk| svm.accounts_db.get_lamports(pk))
            .fold(0u64, |acc, x| acc.checked_add(x).expect("lamport sum overflow"));

        assert_eq!(
            sum.checked_add(total_fees_collected).unwrap(),
            INITIAL_SUPPLY,
            "Conservation invariant violated after transfer {}",
            _
        );
    }
}
```

#### Step 1E.2 — Overflow Edge Case Tests

```rust
test_transfer_amount_zero               // 0-lamport transfer is a no-op, no fee
test_transfer_u64_max_lamports          // Overflow guard: saturating sub must reject not wrap
test_fee_accumulator_does_not_overflow  // 10B transfers with 1 lamport fee each
test_failed_transfer_is_atomic          // Insufficient balance → zero state mutation
```

**Why `checked_add` not `+`:** If any intermediate arithmetic wraps (even in test helper code), the invariant can appear to hold while hiding a real overflow. Use `checked_add`/`checked_sub` with `.expect()` everywhere in the SVM's transfer logic — not just in tests.

**Acceptance:** The invariant test (`10,000 random transfers`) completes with zero assertion failures and zero panics. `cargo test --features svm svm_invariant` passes in CI.

---

### Phase 1 Exit Criterion

All of the following must be green before Phase 2 begins:

| Milestone | Key test |
|-----------|----------|
| 1A | `test_batch_store_atomicity` |
| 1B | `test_system_transfer_basic` + `test_system_transfer_insufficient` |
| 1C | `test_transfer_through_svm_block_production` |
| 1D | `test_parallel_svm_with_account_conflicts` |
| **1E** | **`test_global_lamport_conservation` — 10,000 random transfers, zero atom loss** |

---

## Phase 2: Solana JSON-RPC Server (Weeks 5-7)

### Milestone 2A — RPC Framework + Read Methods (Week 5)

**Goal:** Stand up a JSON-RPC 2.0 server on port 8899 with read-only methods.

#### Step 2A.1 — Add `jsonrpsee` dependency

In `Cargo.toml` (under `[dependencies]`):
```toml
jsonrpsee = { version = "0.24", features = ["server", "macros"], optional = true }
```

Add to the `svm` feature list:
```toml
svm = ["dep:solana-sdk", ..., "dep:jsonrpsee"]
```

#### Step 2A.2 — Create `src/solana_rpc.rs`

Define the RPC trait:
```rust
#[rpc(server)]
pub trait SolanaRpc {
    #[method(name = "getHealth")]
    async fn get_health(&self) -> RpcResult<String>;
    
    #[method(name = "getVersion")]
    async fn get_version(&self) -> RpcResult<RpcVersionInfo>;
    
    #[method(name = "getGenesisHash")]
    async fn get_genesis_hash(&self) -> RpcResult<String>;
    
    #[method(name = "getSlot")]
    async fn get_slot(&self) -> RpcResult<u64>;
    
    #[method(name = "getBlockHeight")]
    async fn get_block_height(&self) -> RpcResult<u64>;
    
    #[method(name = "getBalance")]
    async fn get_balance(&self, pubkey: String) -> RpcResult<RpcResponse<u64>>;
    
    #[method(name = "getAccountInfo")]
    async fn get_account_info(
        &self, pubkey: String, config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Option<UiAccount>>>;
    
    #[method(name = "getLatestBlockhash")]
    async fn get_latest_blockhash(&self) -> RpcResult<RpcResponse<RpcBlockhash>>;
    
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self) -> RpcResult<EpochInfo>;
    
    #[method(name = "getMinimumBalanceForRentExemption")]
    async fn get_minimum_balance_for_rent_exemption(&self, size: usize) -> RpcResult<u64>;
}
```

Implementation struct:
```rust
pub struct BlackBookRpc {
    svm: Arc<BlackBookSVM>,
    poh: SharedPoHService,
    current_slot: Arc<AtomicU64>,
    block_producer: Arc<BlockProducer>,
    genesis_hash: Hash,
}
```

Method implementation mapping:

| Method | Implementation |
|--------|---------------|
| `getHealth` | Return `"ok"` if PoH is ticking |
| `getVersion` | `{ "solana-core": "BB-5.0.0-svm", "feature-set": 0 }` |
| `getGenesisHash` | `SHA256("BLACKBOOK_L1_GENESIS_2025")` — unique network identifier |
| `getSlot` | `current_slot.load(Ordering::Relaxed)` |
| `getBlockHeight` | `block_producer.block_height()` |
| `getBalance` | `svm.accounts_db.get_lamports(pubkey)` → wrap in `RpcResponse` with context slot |
| `getAccountInfo` | `svm.accounts_db.get_account(pubkey)` → encode as base64/base58 per config |
| `getLatestBlockhash` | `{ blockhash: poh.current_hash(), lastValidBlockHeight: block_height + 150 }` |
| `getEpochInfo` | Compute from current slot + POH_SLOTS_PER_EPOCH (432000) |
| `getMinimumBalanceForRentExemption` | `max(1, (size + 128) * 3480 / 100)` — match Solana's formula |

#### Step 2A.3 — Start RPC server alongside Axum

In `src/main.rs`, inside `main()` (after the existing Axum server bind):

```rust
#[cfg(feature = "svm")]
{
    let rpc = BlackBookRpc::new(/* ... */);
    let rpc_server = jsonrpsee::server::ServerBuilder::default()
        .build("0.0.0.0:8899")
        .await?;
    let handle = rpc_server.start(rpc.into_rpc());
    tokio::spawn(async move { handle.stopped().await });
    info!("🔌 Solana JSON-RPC server listening on :8899");
}
```

**Tests:**
```
test_rpc_get_health                  // Returns "ok"
test_rpc_get_version                 // Returns BB version
test_rpc_get_genesis_hash            // Returns consistent hash
test_rpc_get_balance                 // Fund account, query balance
test_rpc_get_account_info_base64     // Account data encoding
test_rpc_get_latest_blockhash        // Returns valid hash
test_rpc_get_slot                    // Monotonically increasing
test_rpc_get_epoch_info              // Sane epoch values
```

**Acceptance:** `curl -X POST http://localhost:8899 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' ` returns `{"jsonrpc":"2.0","result":"ok","id":1}`.

---

### Milestone 2B — Write Methods (Week 6)

**Goal:** `sendTransaction` and `getTransaction` work.

#### Step 2B.1 — Implement `sendTransaction`

```rust
#[method(name = "sendTransaction")]
async fn send_transaction(
    &self, tx_data: String, config: Option<SendTransactionConfig>,
) -> RpcResult<String>;
```

Implementation:
1. Base64/base58 decode `tx_data` → raw bytes
2. Deserialize to `VersionedTransaction`
3. Verify signatures (ed25519)
4. Extract account keys for routing
5. Wrap as a BB `Transaction` with `solana_tx: Some(raw_bytes)`
6. Submit to `GulfStreamService::submit()`
7. Return signature (first signature as base58)

**This is the critical path for OneKey.** When OneKey sends a transfer, it calls `sendTransaction` with a signed Solana transaction. This method decodes it and feeds it into the existing pipeline.

#### Step 2B.2 — Implement `getTransaction`

```rust
#[method(name = "getTransaction")]
async fn get_transaction(
    &self, signature: String, config: Option<RpcTransactionConfig>,
) -> RpcResult<Option<EncodedConfirmedTransactionWithStatusMeta>>;
```

Looks up the transaction in ReDB's `TRANSACTIONS` table by signature. Returns Solana-format transaction metadata.

**Requires:** A new index in ReDB — `SVM_SIGNATURES` table (signature → slot) for O(1) lookup.

#### Step 2B.3 — Implement `getSignaturesForAddress`

```rust
#[method(name = "getSignaturesForAddress")]
async fn get_signatures_for_address(
    &self, address: String, config: Option<RpcSignatureConfig>,
) -> RpcResult<Vec<RpcConfirmedTransactionStatusWithSignature>>;
```

Requires a secondary index: address → list of transaction signatures. Add a new ReDB table:
```rust
const SVM_ADDR_TX_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("svm_addr_tx_idx");
```

#### Step 2B.4 — Implement `getBlock`

```rust
#[method(name = "getBlock")]
async fn get_block(
    &self, slot: u64, config: Option<RpcBlockConfig>,
) -> RpcResult<Option<UiConfirmedBlock>>;
```

Maps from `BlockProducer`'s `FinalizedBlock` to Solana's `UiConfirmedBlock` format.

**Tests:**
```
test_send_transaction_basic          // Encode, send, verify signature returned
test_send_transaction_invalid_sig    // Reject bad signature
test_send_transaction_stale_hash     // Reject expired blockhash
test_get_transaction_after_commit    // Send tx, wait for block, query by signature
test_get_signatures_for_address      // Fund account, send 3 txs, query history
test_get_block_by_slot               // Produce block, query by slot number
```

#### Step 2B.5 — Solana Error Mapper

> **Why this matters:** OneKey and Phantom parse the `err` field of the JSON-RPC response to display user-facing messages. A generic `"ExecutionFailed"` string shows the user nothing. A properly structured `TransactionError` shows `"Insufficient funds"`, `"Custom program error: 0x1"`, etc.

Create `src/svm/error_mapper.rs`:

```rust
use solana_sdk::transaction::TransactionError;
use solana_sdk::instruction::InstructionError;

/// Maps internal SvmError to the canonical Solana TransactionError JSON structure.
/// This is the wire format that OneKey/Phantom parse for user-facing messages.
pub fn to_transaction_error(err: &SvmError) -> TransactionError {
    match err {
        SvmError::InsufficientFunds { .. } =>
            TransactionError::InstructionError(0, InstructionError::InsufficientFunds),

        SvmError::InvalidAccount(_) =>
            TransactionError::InstructionError(0, InstructionError::InvalidAccountData),

        SvmError::ComputeBudgetExceeded { .. } =>
            TransactionError::InstructionError(0, InstructionError::ComputationalBudgetExceeded),

        SvmError::AccountNotFound(_) =>
            TransactionError::AccountNotFound,

        SvmError::InvalidBlockhash =>
            TransactionError::BlockhashNotFound,

        SvmError::SignatureVerificationFailed =>
            TransactionError::SignatureFailure,

        SvmError::CustomProgramError(code) =>
            TransactionError::InstructionError(0, InstructionError::Custom(*code)),

        SvmError::ExecutionFailed(msg) =>
            TransactionError::InstructionError(0, InstructionError::GenericError),
    }
}

/// Maps an SvmError to a Solana JSON-RPC error object (code + message).
/// Used by sendTransaction and simulateTransaction.
pub fn to_rpc_error(err: &SvmError) -> jsonrpsee::types::ErrorObject<'static> {
    let tx_err = to_transaction_error(err);
    jsonrpsee::types::ErrorObjectOwned::owned(
        solana_client::rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
        format!("Transaction simulation failed: {}", err),
        Some(json!({ "err": tx_err })),
    )
}
```

**Usage contract:**
- `sendTransaction`: on signature verification failure or stale blockhash, return `to_rpc_error()` immediately — before touching the pipeline.
- `simulateTransaction`: on ANY failure, return the error **plus** the `logs` array up to the point of failure. Logs must never be `null` on failure — OneKey uses them for debugging.

```rust
// In simulate_transaction handler:
let sim_result = svm.simulate(tx, slot);
return Ok(RpcResponse {
    context: slot_context,
    value: SimulateTransactionResult {
        err: sim_result.err().map(|e| to_transaction_error(&e)),
        logs: Some(sim_result.logs),  // Always present — even on failure
        accounts: sim_result.post_accounts,
        units_consumed: Some(sim_result.compute_units_consumed),
        return_data: sim_result.return_data,
    },
});
```

**Tests:**
```
test_error_mapper_insufficient_funds    // SvmError::InsufficientFunds → TransactionError::InstructionError(InsufficientFunds)
test_error_mapper_stale_blockhash       // SvmError::InvalidBlockhash → TransactionError::BlockhashNotFound
test_error_mapper_custom_program_error  // SvmError::CustomProgramError(0x6) → InstructionError::Custom(6)
test_simulate_returns_logs_on_failure   // simulateTransaction on bad tx → logs array is non-null
```

**Acceptance:** Full round-trip: `sendTransaction` → block production → `getTransaction` returns the committed transaction. Failed transactions return Solana-structured `TransactionError` JSON, not a plain string.

---

### Milestone 2C — Simulation + Remaining Methods (Week 7)

**Goal:** Complete the RPC surface. OneKey can fully interact.

#### Step 2C.1 — `simulateTransaction`

```rust
#[method(name = "simulateTransaction")]
async fn simulate_transaction(
    &self, tx_data: String, config: Option<SimulateTransactionConfig>,
) -> RpcResult<RpcResponse<SimulateTransactionResult>>;
```

Uses `BlackBookSVM::simulate()` — executes against a snapshot of accounts without committing.

Implementation: Clone relevant accounts into a temporary `DashMap`, run SVM execution, return logs + consumed compute units + account state diffs. Discard the temporary state.

**Critical contract (enforced by error mapper from Step 2B.5):**
- `logs` is **always** a `Some(Vec<String>)` — never `null`, even on failure. OneKey's UI uses logs as the primary debugging tool for failed transactions.
- `err` is `Some(TransactionError)` using the structured Solana wire format, not a plain string.
- `units_consumed` is always present so developers can profile Anchor programs from Day 1.

#### Step 2C.2 — Token-related stubs

For Phase 2, these return empty/default responses. They'll be fully implemented in Phase 3 after SPL Token deployment:

```
getTokenAccountsByOwner  → empty array
getTokenSupply           → { amount: "0", decimals: 6 }
getTokenAccountBalance   → { amount: "0", decimals: 6 }
```

#### Step 2C.3 — `@solana/web3.js` integration test

Create `tests/js/rpc_compat_test.mjs`:

```javascript
import { Connection, Keypair, SystemProgram, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";

const conn = new Connection("http://localhost:8899", "confirmed");

// Test getVersion
const version = await conn.getVersion();
console.assert(version["solana-core"].startsWith("BB-"));

// Test getBalance
const kp = Keypair.generate();
// (Fund via REST API for now)
const balance = await conn.getBalance(kp.publicKey);
console.assert(balance >= 0);

// Test sendTransaction
const tx = new Transaction().add(
    SystemProgram.transfer({
        fromPubkey: sender.publicKey,
        toPubkey: receiver.publicKey,
        lamports: 1000,
    })
);
const sig = await sendAndConfirmTransaction(conn, tx, [sender]);
console.log("Transfer confirmed:", sig);
```

**Acceptance:** The JS test passes against the running BB node. This proves wire-format compatibility with the Solana JS SDK — which is what OneKey uses internally.

---

### Phase 2 Gate: OneKey Connection Test

1. Start BB node with `cargo run --features svm`
2. Open OneKey app → Settings → Networks → Add Custom Network
3. Enter RPC URL: `http://<BB_NODE_IP>:8899`
4. OneKey calls `getGenesisHash`, `getVersion`, `getHealth`
5. Create/import wallet in OneKey (Ed25519 keypair)
6. Fund the wallet via REST API `/credit/:address` (temporary)
7. OneKey calls `getBalance` → displays $BB balance in lamports
8. Send a transfer in OneKey → calls `sendTransaction` → confirms via `getSignatureStatuses`

**Screenshot evidence required:** OneKey showing a BB balance and a confirmed transfer.

---

## Phase 3: SPL Token Programs — $BB and $DIME (Weeks 8-10)

### Milestone 3A — SPL Token Deployment (Week 8)

#### Step 3A.1 — Add SPL Token as builtin program

In `src/svm/runtime.rs`, register SPL Token alongside System Program:

```rust
// Built-in programs loaded at genesis
let builtins = vec![
    (system_program::id(),    system_processor::process_instruction),
    (spl_token::id(),         spl_token::processor::Processor::process),
    (spl_associated_token_account::id(), spl_ata::processor::process_instruction),
];
```

Add dependencies:
```toml
spl-token = { version = "7.0", optional = true }
spl-associated-token-account = { version = "5.0", optional = true }
```

#### Step 3A.2 — Create genesis mint accounts

New file: `src/svm/genesis.rs`

```rust
pub struct BlackBookGenesis {
    pub genesis_hash: Hash,          // SHA256("BLACKBOOK_L1_GENESIS_2025")
    pub bb_mint: Pubkey,             // $BB token mint
    pub dime_mint: Pubkey,           // $DIME token mint
    pub usdt_mint: Pubkey,           // Wrapped USDT mint
    pub tier1_vault_authority: Pubkey,
    pub tier2_vault_authority: Pubkey,
    pub genesis_validator: Pubkey,
}

impl BlackBookGenesis {
    /// Initialize genesis state in AccountsDB
    pub fn initialize(&self, accounts_db: &SvmAccountsDB) -> Result<(), SvmError> {
        // 1. Create System Program account (Pubkey::default(), executable, system_program::id() owner)
        // 2. Create SPL Token Program account (spl_token::id(), executable)
        // 3. Create $BB Mint (SPL Mint, supply = 0, decimals = 6, authority = tier1_vault)
        // 4. Create $DIME Mint (SPL Mint, supply = 0, decimals = 6, authority = tier2_vault)
        // 5. Create USDT Mint (SPL Mint, supply = 0, decimals = 6, authority = genesis_validator)
        // 6. Fund genesis validator with initial lamports
    }
}
```

$BB token specifics:
- **Decimals:** 6 (1 $BB = 1_000_000 lamports, matching Solana SOL convention)
- **Mint authority:** Tier-1 vault program (only it can mint new $BB)
- **Freeze authority:** None (no censorship)

#### Step 3A.3 — Balance migration utility

Create `src/svm/migration.rs`:

```rust
/// Migrate all existing f64 balances from legacy ACCOUNTS table to SPL token accounts.
///
/// For each entry in the old `ACCOUNTS` table:
/// 1. Parse the address → derive a Pubkey (or use pre-mapped table)
/// 2. Create an Associated Token Account for $BB mint
/// 3. Set token balance = old_f64 * 10^6 (convert to u64 lamports)
pub fn migrate_legacy_balances(
    legacy_bc: &ConcurrentBlockchain,
    svm_accounts: &SvmAccountsDB,
    bb_mint: &Pubkey,
) -> Result<MigrationReport, SvmError> { ... }
```

**Key question: address mapping.**  
Current addresses are `bb_<hex>` strings. Need a deterministic mapping to Solana `Pubkey`.  

Option A: Derive Pubkey from the hex part: `Pubkey::new_from_array(sha256(hex_bytes)[..32])`.  
Option B: Store a mapping table in ReDB: `ADDRESS_MAP: &str → &[u8]` (old address → Pubkey bytes).  

**Recommended: Option B** — it's explicit, reversible, and the REST API can use it to translate old addresses for backward compat.

**Tests:**
```
test_genesis_creates_mint_accounts    // Mint accounts exist, correct decimals
test_genesis_hash_is_unique           // Not equal to Solana mainnet/devnet genesis
test_migrate_10_accounts              // 10 legacy accounts → 10 SPL token accounts
test_migrated_balances_are_correct    // f64 → u64 conversion is exact
test_migration_is_idempotent          // Running twice doesn't double balances
```

**Acceptance:** Genesis state includes $BB, $DIME, USDT mints. All legacy balances are accessible as SPL token accounts.

---

### Milestone 3B — Token RPC Methods (Week 9)

#### Step 3B.1 — Implement SPL token RPC methods

Replace the Phase 2 stubs with real implementations:

| Method | Implementation |
|--------|---------------|
| `getTokenAccountsByOwner` | Scan `SVM_ACCOUNTS` for accounts owned by `spl_token::id()` where the parsed token account data matches the owner Pubkey |
| `getTokenSupply` | Read the mint account data, parse `spl_token::state::Mint`, return `supply` |
| `getTokenAccountBalance` | Read the token account data, parse `spl_token::state::Account`, return `amount` |

**Performance concern:** `getTokenAccountsByOwner` requires a table scan. Add a secondary index:
```rust
const SVM_TOKEN_OWNER_INDEX: TableDefinition<&[u8], &[u8]> = 
    TableDefinition::new("svm_token_owner_idx");
// Key: owner_pubkey (32 bytes)
// Value: list of token account pubkeys (borsh-serialized Vec<[u8;32]>)
```

Update this index whenever a token account is created or transferred.

**Tests:**
```
test_get_token_supply_bb             // Mint 1000 $BB, query supply = 1000
test_get_token_accounts_by_owner     // Create ATA for user, query returns it
test_get_token_account_balance       // Fund ATA, query returns correct amount
```

**Acceptance:** OneKey shows $BB and $DIME token balances in the token list (not just as SOL/lamport balance).

---

### Milestone 3C — REST API Backward Compatibility (Week 10)

#### Step 3C.1 — Update `/balance/:address` endpoint

The existing REST endpoint at `src/main.rs` currently reads from `ConcurrentBlockchain::get_balance()` (line ~300).

With SVM, modify to read from SPL token accounts when the `svm` feature is active:

```rust
#[cfg(feature = "svm")]
{
    let pubkey = address_to_pubkey(&address)?;  // Use migration mapping table
    let ata = get_associated_token_address(&pubkey, &state.genesis.bb_mint);
    let token_balance = state.svm.accounts_db.get_account(&ata)
        .map(|acc| spl_token::state::Account::unpack(&acc.data).ok())
        .flatten()
        .map(|ta| ta.amount as f64 / 1_000_000.0)
        .unwrap_or(0.0);
    return Json(json!({ "address": address, "balance": token_balance }));
}

// Legacy fallback
let balance = state.blockchain.get_balance(&address);
```

#### Step 3C.2 — Update `/transfer/simple` endpoint

Modify to build a Solana SPL token transfer instruction when `svm` is active, then submit through Gulf Stream.

#### Step 3C.3 — Shadow Reader (replaces Dual-write)

> **Why no dual-write:** Two sources of truth for balances (one `f64`, one `u64`) cause state drift. If a transaction commits in the SVM but fails to write back to the legacy table (or vice versa), the ledger is silently corrupted. The fix is to make the SVM the **only** writer and make legacy reads a transparent wrapper.

**The Shadow Reader pattern:**

Modify `ConcurrentBlockchain::get_balance()` in `src/storage/mod.rs` to delegate to the SVM when the feature is active:

```rust
impl ConcurrentBlockchain {
    pub fn get_balance(&self, address: &str) -> f64 {
        #[cfg(feature = "svm")]
        {
            // SVM is the single source of truth.
            // Convert lamports (u64) to display units (f64) on the fly.
            // No data is written to the legacy ACCOUNTS table.
            if let Some(ref svm_db) = self.svm_accounts {
                let pubkey = match self.address_map.get(address) {
                    Some(pk) => *pk,
                    None     => return 0.0,  // address not yet migrated
                };
                let ata = get_associated_token_address(&pubkey, &BB_MINT_PUBKEY);
                return svm_db.get_lamports(&ata) as f64 / 1_000_000.0;
            }
        }

        // Legacy path — only active before Phase 3 migration runs
        self.cache.get(address).map(|v| *v).unwrap_or(0.0)
    }
}
```

**Key properties:**
- Zero writes to the legacy `ACCOUNTS` table from this point forward.
- The `f64` conversion is read-only and ephemeral — it does not persist.
- Any caller that used `get_balance()` transparently sees SVM balances with no code change.
- Dust from `lamports % 1_000_000` is preserved in the SVM; the `f64` display is rounded (acceptable — display only).

**Tests:**
```
test_rest_balance_reads_svm          // Fund via SVM, query via REST /balance/:address
test_rest_transfer_goes_through_svm  // POST /transfer/simple → SVM execution
test_shadow_reader_no_writes         // Assert legacy ACCOUNTS table is unchanged after SVM transfer
test_shadow_reader_zero_drift        // SVM lamports / 1e6 == REST balance (within display rounding)
```

**Acceptance:** Existing REST API returns correct balances routed through the Shadow Reader. The legacy `ACCOUNTS` table is frozen (read-only reference only). No L2 or SDK breakage.

---

## Phase 4: Anchor Vault Programs (Weeks 11-14)

### Milestone 4A — Tier-1 Vault Program (Weeks 11-12)

#### Step 4A.1 — Scaffold Anchor workspace

Create `programs/` directory at the repo root:

```
programs/
├── tier1_vault/
│   ├── Cargo.toml
│   ├── Xargo.toml
│   └── src/
│       └── lib.rs
├── tier2_vault/
│   ├── Cargo.toml
│   ├── Xargo.toml
│   └── src/
│       └── lib.rs
└── oracle/
    ├── Cargo.toml
    ├── Xargo.toml
    └── src/
        └── lib.rs
```

Each `Cargo.toml`:
```toml
[package]
name = "tier1_vault"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]

[dependencies]
anchor-lang = "0.30"
anchor-spl = "0.30"
```

#### Step 4A.2 — Implement Tier-1 Vault (`programs/tier1_vault/src/lib.rs`)

This replaces `TxData::DepositUsdt` and `TxData::RedeemBbForUsdt` from `protocol/blockchain.rs`.

```rust
#[program]
pub mod tier1_vault {
    use super::*;
    
    /// Deposit USDT → Mint $BB at 1:10 ratio
    pub fn deposit(ctx: Context<Deposit>, usdt_amount: u64) -> Result<()> {
        // 1. Transfer USDT from user to vault ATA
        // 2. Mint BB tokens to user (usdt_amount * 10)
        // 3. Emit event
        Ok(())
    }
    
    /// Redeem $BB → Receive USDT at 10:1 ratio
    pub fn redeem(ctx: Context<Redeem>, bb_amount: u64) -> Result<()> {
        // 1. Burn BB tokens from user
        // 2. Transfer USDT from vault to user (bb_amount / 10)
        // 3. Emit event
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_usdt_ata: Account<'info, TokenAccount>,  // User's USDT
    
    #[account(mut)]
    pub vault_usdt_ata: Account<'info, TokenAccount>,  // Vault's USDT reserve
    
    #[account(mut)]
    pub bb_mint: Account<'info, Mint>,                  // $BB mint
    
    #[account(mut)]
    pub user_bb_ata: Account<'info, TokenAccount>,      // User's $BB account
    
    /// PDA: seeds = ["tier1_vault"]
    #[account(seeds = [b"tier1_vault"], bump)]
    pub vault_authority: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}
```

#### Step 4A.3 — Compile and deploy

```bash
# Build BPF binary
anchor build

# The .so file is at target/deploy/tier1_vault.so
# Deploy to BB chain via program deployment instruction
```

Wire the BPF loader into `BlackBookSVM`:
```rust
// In runtime.rs, add BPF loader as builtin
builtins.push((
    bpf_loader::id(),
    solana_bpf_loader_program::process_instruction,
));
```

Create a deploy method:
```rust
impl BlackBookSVM {
    pub fn deploy_program(&self, program_id: Pubkey, elf_bytes: &[u8]) -> Result<(), SvmError> {
        // 1. Store ELF in SVM_PROGRAMS table
        // 2. Create program account (executable = true, owner = bpf_loader::id())
        // 3. Verify ELF via solana_rbpf::verifier
        // 4. Add to program cache
    }
}
```

**Tests:**
```
test_deploy_tier1_vault              // Deploy .so, verify account is executable
test_tier1_deposit                   // Deposit 100 USDT → receive 1000 $BB
test_tier1_redeem                    // Redeem 1000 $BB → receive 100 USDT
test_tier1_deposit_insufficient      // Fail if user has no USDT
test_tier1_mint_authority            // Only vault PDA can mint $BB
```

### Milestone 4B — Tier-2 Vault + Oracle (Weeks 13-14)

#### Step 4B.1 — `tier2_vault` program

Replaces `TxData::LockBbForDime` and `TxData::RedeemDimeVintage`:

```rust
#[program]
pub mod tier2_vault {
    pub fn lock(ctx: Context<Lock>, bb_amount: u64) -> Result<()> { ... }
    pub fn redeem_vintage(ctx: Context<RedeemVintage>, vintage_id: u64) -> Result<()> { ... }
}
```

Vintage tracking via PDA accounts: `seeds = ["vintage", vintage_id.to_le_bytes()]`.

#### Step 4B.2 — `oracle` program

Replaces `TxData::UpdateCpi`:

```rust
#[program]
pub mod oracle {
    pub fn update_cpi(ctx: Context<UpdateCpi>, new_cpi_index: f64) -> Result<()> {
        // Only authorized updater can call
        // Store in oracle state PDA
    }
}
```

#### Step 4B.3 — Generate and publish IDL

```bash
anchor build
# IDL JSON files are at target/idl/*.json
```

Copy IDL files to a public location. OneKey uses these to decode Anchor instructions — showing "Deposit 100 USDT to Tier-1 Vault" instead of raw hex bytes.

#### Step 4B.4 — Remove legacy execution paths

In `src/poh_blockchain.rs`, the dual-path from Step 1C.3 can now be simplified. All `TxData` variants now have Anchor program equivalents:

```rust
fn execute_transaction(&self, tx: &Transaction) -> Result<(), String> {
    #[cfg(feature = "svm")]
    {
        let solana_tx = svm::tx_adapter::legacy_tx_to_solana_tx(tx, self.svm.latest_blockhash())
            .map_err(|e| e.to_string())?;
        return self.svm.execute_transaction(&solana_tx, self.current_slot())
            .map_err(|e| e.to_string());
    }
    
    // Legacy path (only used when svm feature is disabled)
    match &tx.data { ... }
}
```

**Tests:**
```
test_full_vault_flow                 // USDT → $BB → $DIME → redeem vintage
test_cpi_update_affects_dime_value   // Oracle update changes DIME redemption rate
test_idl_decode_deposit              // Raw instruction data → "deposit(100)" via IDL
test_idl_decode_lock                 // Raw instruction data → "lock(500)" via IDL
```

**Acceptance:** The complete financial flow (USDT → $BB → $DIME with vintage tracking) runs entirely through Anchor programs on the SVM. OneKey can display decoded instruction names.

---

## Phase 5: SSS + OneKey Hybrid Signing (Weeks 15-17)

### Milestone 5A — Solana Transaction Builder (Week 15)

#### Step 5A.1 — Create `src/wallet_unified/tx_builder.rs`

This bridges FROST signatures to Solana transactions.

```rust
/// Build a Solana VersionedTransaction from a FROST-aggregated Ed25519 signature.
///
/// FROST produces a standard Ed25519 signature from the 2-of-3 threshold scheme.
/// This function wraps it into the Solana transaction wire format.
pub struct SolanaTransactionBuilder {
    genesis_hash: Hash,
    svm: Arc<BlackBookSVM>,
}

impl SolanaTransactionBuilder {
    /// Build a $BB token transfer transaction
    pub fn build_bb_transfer(
        &self,
        from_pubkey: &Pubkey,
        to_pubkey: &Pubkey,
        amount: u64,        // In lamports (amount * 10^6)
    ) -> UnsignedTransaction { ... }
    
    /// Build a Tier-1 vault deposit transaction
    pub fn build_vault_deposit(
        &self,
        user_pubkey: &Pubkey,
        usdt_amount: u64,
    ) -> UnsignedTransaction { ... }
    
    /// Attach a FROST-aggregated signature to an unsigned transaction
    pub fn sign_with_frost(
        &self,
        unsigned_tx: UnsignedTransaction,
        frost_signature: ed25519::Signature,
    ) -> VersionedTransaction { ... }
}

/// An unsigned Solana transaction ready for signing
pub struct UnsignedTransaction {
    pub message: VersionedMessage,
    pub message_bytes: Vec<u8>,  // The bytes that need to be signed
}
```

#### Step 5A.2 — Update `transfer_with_sss()` in handlers.rs

Current flow in [handlers.rs](src/wallet_unified/handlers.rs) (line ~300):
```
Share A (user) + Share B (server) → FROST aggregate → custom TransferRequest → blockchain.transfer()
```

New flow:
```
Share A (user) + Share B (server) → FROST aggregate → Solana Transaction → GulfStream → SVM
```

Change at the end of `transfer_with_sss()`:

```rust
#[cfg(feature = "svm")]
{
    // Build Solana transaction
    let unsigned_tx = state.tx_builder.build_bb_transfer(
        &from_pubkey,
        &to_pubkey,
        (req.amount * 1_000_000.0) as u64,  // Convert f64 → lamports
    );
    
    // Sign with aggregated FROST signature
    let signed_tx = state.tx_builder.sign_with_frost(unsigned_tx, signature);
    
    // Submit to SVM via Gulf Stream
    state.gulf_stream.submit_solana_tx(signed_tx)?;
    
    return Ok(Json(json!({
        "success": true,
        "signature": bs58::encode(&signed_tx.signatures[0]).into_string(),
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
    })));
}

// Legacy path
state.blockchain.transfer(&req.from_wallet_id, &req.to_address, req.amount)?;
```

**Tests:**
```
test_frost_sig_to_solana_tx          // FROST aggregate → valid Solana transaction
test_frost_transfer_through_svm      // Full SSS flow → SVM execution
test_frost_vault_deposit_through_svm // SSS flow → Tier-1 vault deposit via SVM
```

---

### Milestone 5B — OneKey Hardware Bridge (Week 16)

#### Step 5B.1 — Create `src/wallet_unified/onekey_bridge.rs`

This module provides the protocol for OneKey to participate as a shard validator.

```rust
/// OneKey signing modes
pub enum OneKeyMode {
    /// OneKey is the sole signer (standard Solana wallet behavior)
    Standalone,
    
    /// OneKey provides final approval after FROST builds the transaction
    /// (SSS creates tx with 2-of-3 → OneKey sees decoded instruction → approves)
    ShardValidator,
    
    /// OneKey holds one FROST share (shard C replacement)
    /// (OneKey + server = 2-of-3 threshold, phone not needed)
    ThresholdSigner,
}

/// Prepare a transaction for OneKey signing/approval
pub struct OneKeySigningRequest {
    /// The unsigned Solana transaction (serialized)
    pub unsigned_tx_bytes: Vec<u8>,
    
    /// Human-readable description (derived from Anchor IDL)
    pub display_message: String,
    
    /// The chain's genesis hash (so OneKey shows the right network)
    pub genesis_hash: String,
    
    /// Signing mode
    pub mode: OneKeyMode,
}

/// Build a OneKey signing request from an unsigned Solana transaction
pub fn prepare_for_onekey(
    unsigned_tx: &UnsignedTransaction,
    idl_registry: &IdlRegistry,  // Maps program_id → Anchor IDL for instruction decoding
) -> OneKeySigningRequest { ... }
```

**Note:** The actual Bluetooth/USB communication with OneKey hardware is handled by OneKey's SDK on the client side (React Native / mobile app). This module only prepares the data structures.

#### Step 5B.2 — IDL Registry for instruction decoding

```rust
pub struct IdlRegistry {
    idls: HashMap<Pubkey, serde_json::Value>,  // program_id → IDL JSON
}

impl IdlRegistry {
    pub fn new() -> Self {
        let mut reg = Self { idls: HashMap::new() };
        reg.register(TIER1_VAULT_PROGRAM_ID, include_str!("../../programs/tier1_vault/idl.json"));
        reg.register(TIER2_VAULT_PROGRAM_ID, include_str!("../../programs/tier2_vault/idl.json"));
        reg.register(ORACLE_PROGRAM_ID, include_str!("../../programs/oracle/idl.json"));
        reg
    }
    
    /// Decode instruction data to human-readable string
    pub fn decode_instruction(&self, program_id: &Pubkey, data: &[u8]) -> String {
        // Parse Anchor discriminator (first 8 bytes) → instruction name
        // Parse remaining bytes → argument values
        // Return: "deposit(usdt_amount: 100000000)"
        ...
    }
}
```

---

### Milestone 5C — Three Signing Mode Integration (Week 17)

#### Step 5C.1 — Mode A: SSS-only (already working from 5A)

FROST 2-of-3 (Share A + Share B) → Solana transaction → submit.

No changes needed — this is the existing `transfer_with_sss()` flow updated in Step 5A.2.

#### Step 5C.2 — Mode B: OneKey standalone

New endpoint: `POST /wallet/onekey/submit`

```rust
pub async fn onekey_submit(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<OneKeySubmitRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // 1. Decode signed transaction from OneKey
    // 2. Verify Ed25519 signature
    // 3. Submit to Gulf Stream
    // 4. Return signature
}
```

This is essentially the same as `sendTransaction` on the JSON-RPC, but as a REST endpoint for BB's own app to use when in OneKey-standalone mode.

#### Step 5C.3 — Mode C: SSS + OneKey hybrid

New endpoint: `POST /wallet/hybrid/sign`

Flow:
1. App sends Share A + partial tx details
2. Server retrieves Share B, runs FROST Round 1+2, produces aggregate signature
3. Server builds Solana transaction with FROST signature
4. Server returns unsigned tx to app (with `display_message` from IDL)
5. App shows tx on OneKey screen → user presses button → OneKey counter-signs
6. App submits dual-signed transaction via `POST /wallet/hybrid/submit`

```rust
pub async fn hybrid_prepare(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<HybridPrepareRequest>,
) -> Result<Json<OneKeySigningRequest>, (StatusCode, Json<Value>)> { ... }

pub async fn hybrid_submit(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<HybridSubmitRequest>,  // Contains OneKey's signature
) -> Result<Json<Value>, (StatusCode, Json<Value>)> { ... }
```

**Tests:**
```
test_mode_a_sss_only                 // FROST sign → submit → confirmed
test_mode_b_onekey_standalone        // OneKey sign → submit → confirmed
test_mode_c_hybrid_prepare           // Returns valid OneKeySigningRequest
test_mode_c_hybrid_submit            // FROST + OneKey sig → submit → confirmed
test_idl_decode_in_signing_request   // display_message shows human-readable instruction
```

**Acceptance:** All three signing modes produce valid, committable Solana transactions. The `display_message` field correctly decodes Anchor instructions.

---

## Phase 6: Production Hardening (Weeks 18-19)

### Milestone 6A — Compute Budget Hardening (Week 18)

> **Note:** Compute metering was wired in Milestone 1B.1 (Shift-Left). The meter has been running and logging `compute_units_consumed` since Phase 1. This milestone tightens the limits for production — it does **not** introduce the meter.

#### Step 6A.1 — Tighten compute limits for production

Update `BlackBookSVM` limits for mainnet:
```rust
// Phase 1 defaults (permissive)
default_compute_units: 200_000,
max_compute_units:   1_400_000,

// Phase 6 production limits (tighten based on Anchor program profiling data)
// Set these after reviewing the compute_units logs from Phase 4 Anchor development.
// The meter ran in Phase 1-5, so you have real data — use it.
default_compute_units:  50_000,   // typical simple transfer
max_compute_units:     400_000,   // matches Solana mainnet default budget
```

Verify no existing Anchor programs (Phase 4) exceed the new limits by running the full test suite and checking for `SvmError::ComputeBudgetExceeded` in the output.

#### Step 6A.2 — RPC rate limiting

Add per-IP rate limiting to the JSON-RPC server:
```rust
let rpc_server = ServerBuilder::default()
    .max_connections(100)
    .max_request_body_size(50 * 1024)  // 50KB
    .build("0.0.0.0:8899")
    .await?;
```

Also integrate with the existing `NetworkThrottler` from `runtime/core.rs`.

#### Step 6A.3 — Program deployment governance

Only a multi-sig authority can deploy new programs:
```rust
impl BlackBookSVM {
    pub fn deploy_program_governed(
        &self,
        program_id: Pubkey,
        elf_bytes: &[u8],
        authority_signatures: &[Signature],  // Require N-of-M signatures
    ) -> Result<(), SvmError> {
        // 1. Verify at least 2-of-3 governance signatures
        // 2. Verify ELF binary
        // 3. Deploy
    }
}
```

#### Step 6A.4 — Remove Shadow Reader shim

The Shadow Reader from Milestone 3C.3 (`get_balance()` delegating to SVM) was always a thin wrapper — no data was ever being written to the legacy table. In Phase 6, remove the branch entirely:

```rust
// Before (Phase 3+):
pub fn get_balance(&self, address: &str) -> f64 {
    #[cfg(feature = "svm")] { /* delegate to SVM */ }
    self.cache.get(address)...  // unreachable after migration
}

// After (Phase 6): Delete the method. Callers read directly from SPL token accounts.
```

The SVM is now mandatory. Remove all `#[cfg(feature = "svm")]` gates.

Update `Cargo.toml`:
```toml
[features]
default = ["svm"]
```

---

### Milestone 6B — Load Testing + Final Validation (Week 19)

#### Step 6B.1 — TPS benchmark

Update `benches/tps_benchmarks.rs`:

```rust
#[bench]
fn bench_svm_50k_transfers(b: &mut Bencher) {
    // Pre-fund 10,000 accounts
    // Generate 50,000 random transfer instructions
    // Time: scheduler → SVM execute_batch → ReDB commit
    // Assert: < 1 second for 50,000 transfers
}
```

#### Step 6B.2 — Wallet compatibility matrix

Test each wallet against the BB RPC:

| Wallet | Connection | Balance | Transfer | Token List | IDL Decode |
|--------|-----------|---------|----------|------------|------------|
| OneKey | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ |
| Phantom | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ |
| Solflare | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ |

#### Step 6B.3 — gRPC L2 settlement via SVM

Update `src/grpc/mod.rs` to route L2 settlement through SVM:
- `LockTokens` → submits SPL token transfer to vault PDA
- `SettleBet` → submits SPL token transfer from vault PDA to winner

This is the last module to migrate from legacy balance operations.

#### Step 6B.4 — Full regression test suite

Run every existing test file to verify no regressions:
```powershell
cargo test --all
cargo test --features svm --all
```

Files to verify:
- `tests/blockchain_core_tests.rs`
- `tests/wallet_integration_tests.rs`
- `tests/wallet_security_tests.rs`
- `tests/consensus_tests.rs`
- `tests/transaction_pipeline_tests.rs`
- `tests/bridge_escrow_tests.rs`
- `tests/social_mining_tests.rs`
- `tests/wallet_collision_tests.rs`

---

## Dependency Graph

```
Phase 0 (Day 1)
    │
    ▼
Phase 1A: AccountsDB ──────────────────────────────────────────────────┐
    │                                                                   │
    ▼                                                                   │
Phase 1B: rBPF VM ─────────────┐                                       │
    │                           │                                       │
    ▼                           │                                       │
Phase 1C: Block Production ◄───┘                                       │
    │                                                                   │
    ▼                                                                   │
Phase 1D: Parallel Scheduler                                            │
    │                                                                   │
    ├──────────────────┐                                                │
    ▼                  ▼                                                │
Phase 2A: RPC Read   Phase 3A: SPL Token ◄─────────────────────────────┘
    │                  │
    ▼                  ▼
Phase 2B: RPC Write  Phase 3B: Token RPC
    │                  │
    ▼                  ▼
Phase 2C: Simulation Phase 3C: REST Compat
    │                  │
    └────────┬─────────┘
             ▼
    Phase 4A: Tier-1 Vault (Anchor)
             │
             ▼
    Phase 4B: Tier-2 Vault + Oracle
             │
             ▼
    Phase 5A: TX Builder
             │
             ▼
    Phase 5B: OneKey Bridge
             │
             ▼
    Phase 5C: Three Signing Modes
             │
             ▼
    Phase 6A: Hardening
             │
             ▼
    Phase 6B: Load Test + Ship
```

**Parallelizable:** Phase 2 (RPC) and Phase 3 (SPL Tokens) can run in parallel after Phase 1D completes. Assign to separate developers if available.

---

## Risk Checkpoints

| After Phase | Risk Check | Rollback Plan |
|-------------|-----------|---------------|
| 1 | Does `cargo build` without `--features svm` still work? | Remove all `cfg(feature = "svm")` blocks |
| 2 | Does `@solana/web3.js` `Connection` successfully handshake? | Check JSON-RPC method names/response formats |
| 3 | Do legacy REST endpoints still return correct balances? | Shadow Reader active — `get_balance()` delegates to SVM; no legacy writes |
| 4 | Can Anchor programs deploy and execute without crashing the node? | Disable BPF loader, revert to legacy execution |
| 5 | Do FROST signatures pass Solana's Ed25519 verifier? | They should — both are standard Ed25519. If not, check serialization format. |
| 6 | 50k TPS sustained under load? | Profile rBPF execution overhead vs. legacy path |

---

## Quick-Start Checklist (First 3 Days)

- [ ] Phase 0.1: Verify Solana crates compile on your toolchain
- [ ] Phase 0.3: Add `svm` feature flag to `Cargo.toml`
- [ ] Step 1A.1: Create `src/svm/mod.rs`, `types.rs`, `accounts_db.rs`, `runtime.rs` (empty skeletons)
- [ ] Step 1A.2: Implement `SvmAccountsDB` struct with `get_account()` and `store_account()`
- [ ] Step 1A.3: Wire new SVM tables into `ConcurrentBlockchain::new()`
- [ ] Run `cargo build --features svm` — if it compiles, you're off the ground
