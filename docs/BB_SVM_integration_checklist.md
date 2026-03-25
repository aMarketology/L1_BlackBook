# BB SVM Integration — Checklist
> Last updated: Feb 21, 2026  
> Build command: `cargo build --features svm`  
> Test suite: `cargo test --features svm`

---

## Phase 0 — Pre-Flight
- [x] Feature flag skeleton (`svm` optional feature in `Cargo.toml`)
- [x] `cargo build` (no `--features svm`) compiles clean — zero legacy regressions

---

## Phase 1 — AccountsDB + SVM Core

### 1A — SvmAccountsDB
- [x] `src/svm/mod.rs`, `accounts_db.rs`, `runtime.rs`, `types.rs` created
- [x] `StoredAccount` (Borsh) — serializes `AccountSharedData` into ReDB
- [x] `SvmError` enum (`AccountNotFound`, `InsufficientLamports`, `ExecutionFailed`, `StorageError`, `InvalidTransaction`)
- [x] ReDB tables: `svm_accounts`, `svm_programs`, `blockhash_queue`, `svm_signatures`
- [x] `SvmAccountsDB::new(Arc<Database>)` — tables created alongside legacy `accounts` table (no migration)
- [x] `get_account`, `store_account`, `store_accounts_batch`, `account_exists`, `get_lamports`
- [x] `SvmAccountsDB` wired into `ConcurrentBlockchain` as `pub svm_accounts: Arc<SvmAccountsDB>`
- [x] **Tests — `tests/svm_accounts_tests.rs` — 5/5 ✅**
  - [x] `test_store_and_retrieve_account`
  - [x] `test_cache_is_consistent_with_disk`
  - [x] `test_batch_store_atomicity`
  - [x] `test_nonexistent_account_returns_none`
  - [x] `test_lamport_overflow_safety`

### 1B — BlackBookSVM (Native Rust execution path)
- [x] `BlackBookSVM` struct (`accounts_db`, `current_blockhash`, `blockhash_queue`, `slot`, `max_compute_units`)
- [x] `BlackBookSVM::new(accounts_db, genesis_hash)` — 150-slot blockhash ring initialized
- [x] `system_transfer(&from, &to, lamports)` — debit/credit with overflow guard
- [x] `advance_blockhash(slot)` — SHA256 chain, ring of 150 slots
- [x] `current_blockhash()` — returns latest `Hash`
- [x] `is_blockhash_valid(hash)` — checks ring
- [x] **`1B.2 rBPF InvokeContext` — DEFERRED** (native Rust path is sufficient; revisit Phase 3)
- [x] **Tests — `tests/svm_runtime_tests.rs` — 5/5 ✅**
  - [x] `test_system_transfer_basic`
  - [x] `test_system_transfer_insufficient_funds`
  - [x] `test_blockhash_advances`
  - [x] `test_blockhash_expiry`
  - [x] `test_identity_transfer_is_noop`

### 1C — BlockProducer Wiring
- [x] `BlockProducer` holds `Arc<SvmAccountsDB>` (same instance as `ConcurrentBlockchain`)
- [x] Dual-path `produce_block()` — `TransferBb` → `svm_accounts.system_transfer()`; legacy path unchanged
- [x] Lazy migration: old f64 accounts pulled into SVM table on first access
- [x] `addr_to_pk(addr: &str) → Pubkey` — SHA256 of address string → `[u8;32]`
- [x] **Tests — `tests/svm_block_production_tests.rs` — 3/3 ✅**
  - [x] `test_block_production_with_svm_transfer`
  - [x] `test_svm_migration_on_first_access`
  - [x] `test_block_rejects_double_spend`

### 1D — ParallelScheduler Wiring
- [x] `ParallelScheduler` gains `svm_db: Option<Arc<SvmAccountsDB>>` field
- [x] `with_svm(Arc<SvmAccountsDB>) → Self` builder method
- [x] `execute_single_svm()` — SHA256 addr → Pubkey → `svm_db.system_transfer()`
- [x] `execute_batch_with_locks()` routes `TransactionType::Transfer + Some(db)` → SVM path
- [x] **Tests — `tests/svm_parallel_tests.rs` — 4/4 ✅**
  - [x] `test_parallel_scheduler_with_svm`
  - [x] `test_parallel_routes_non_transfer_to_legacy`
  - [x] `test_scheduler_without_svm_uses_legacy`
  - [x] `test_parallel_batch_consistency`

### 1E — Lamport Conservation Fuzzing
- [x] **Tests — `tests/svm_invariant_tests.rs` — 3/3 ✅**
  - [x] `test_global_lamport_conservation` — 10,000 random transfers, checked every 100
  - [x] `test_overflow_is_rejected` — near-`u64::MAX` recipient guard
  - [x] `test_parallel_lamport_conservation` — rayon, 50 disjoint pairs, no race conditions

---

## Phase 2 — Solana JSON-RPC Server (port 8899)

### 2A — Read-Only Methods ← **CURRENT**
- [x] Add `jsonrpsee = { version = "0.24", features = ["server","macros"], optional = true }` to `Cargo.toml`
- [x] Add `bs58 = { version = "0.5", optional = true }` to `Cargo.toml`
- [x] Both deps added to `svm` feature list
- [x] `src/solana_rpc/mod.rs` created
  - [x] `#[rpc(server)]` trait `BlackBookRpc` with 9 methods
  - [x] `BlackBookRpcImpl { svm_db, svm, current_slot, genesis_hash }`
  - [x] `BlackBookRpcImpl::new()` — computes genesis hash = SHA256("BLACKBOOK_L1_GENESIS_2025")
  - [x] Response types with `Clone`: `RpcResponse<T>`, `RpcContext`, `UiAccount`, `UiAccountData`, `RpcBlockhash`, `RpcEpochInfo`, `RpcVersionInfo`, `RpcAccountInfoConfig`
  - [x] `get_health` → `"ok"`
  - [x] `get_version` → `"BB-5.0.0-svm"`, `feature_set = 0xBB500000`
  - [x] `get_genesis_hash` → base58 SHA256("BLACKBOOK_L1_GENESIS_2025")
  - [x] `get_slot` → `current_slot.load()`
  - [x] `get_block_height` → same as slot
  - [x] `get_balance` → `svm_db.get_lamports()`
  - [x] `get_account_info` → base64-encoded account data + owner + lamports
  - [x] `get_latest_blockhash` → current blockhash + `last_valid = slot + 150`
  - [x] `get_epoch_info` → `epoch = slot / 432000`, `slot_index = slot % 432000`
  - [x] `get_minimum_balance_for_rent_exemption` → `(128 + data_len) × 3480 × 2`
  - [x] `get_multiple_accounts` → Vec of UiAccount (None for missing)
  - [x] `start_rpc_server(rpc, addr)` — `jsonrpsee` tokio server
- [x] `src/lib.rs` — `#[cfg(feature = "svm")] pub mod solana_rpc;`
- [x] `src/main.rs` — Extract Arcs before `build_router` move, start server on `0.0.0.0:8899`
- [x] `cargo build --features svm` — **clean ✅**
- [x] **Tests — `tests/rpc_tests.rs` — 9/9 ✅**
  - [x] `test_rpc_get_health`
  - [x] `test_rpc_get_version`
  - [x] `test_rpc_get_genesis_hash`
  - [x] `test_rpc_get_balance`
  - [x] `test_rpc_get_balance_unknown_returns_zero`
  - [x] `test_rpc_get_account_info_base64`
  - [x] `test_rpc_get_latest_blockhash`
  - [x] `test_rpc_get_slot`
  - [x] `test_rpc_get_epoch_info`

### 2B — Write Methods ← **COMPLETE**
- [x] `sendTransaction` — base64 decode → `VersionedTransaction` → execute System Program transfer
- [x] `getTransaction` — lookup by signature in `SVM_TX_LOG` ReDB table
- [x] `getSignaturesForAddress` — secondary index table `SVM_ADDR_SIGS` in ReDB (prefix scan by address)
- [x] Signature dedup via `SVM_TX_LOG` table (reject replay across restarts)
- [x] `StoredTransactionResult` Borsh type for persistent tx log
- [x] `SvmAccountsDB::store_transaction_result()`, `get_transaction_result()`, `get_signatures_for_address()`
- [x] `cargo build --features svm` — **clean ✅**
- [x] `cargo build` (no svm flag) — **clean ✅** (zero regressions)
- [x] **Tests — `tests/rpc_send_tests.rs` — 5/5 ✅**
  - [x] `test_send_transaction_system_transfer`
  - [x] `test_send_transaction_rejected_when_insufficient_funds`
  - [x] `test_send_transaction_rejects_replay`
  - [x] `test_get_transaction_returns_confirmed`
  - [x] `test_get_signatures_for_address`

### 2B — Deferred to Phase 2B.2
- [ ] `getBlock` — map `FinalizedBlock` → `UiConfirmedBlock` (requires block-level storage integration)

### 2C — simulateTransaction
- [ ] `simulateTransaction` — dry-run without committing state
- [ ] Error log field populated on failure
- [ ] **Tests — `tests/rpc_simulate_tests.rs`**
  - [ ] `test_simulate_valid_transfer`
  - [ ] `test_simulate_insufficient_funds_returns_error`

### Phase 2A Exit Smoke Test (live, manual)
```bash
# Server must be running: cargo run --features svm
curl -s -X POST http://localhost:8899 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
# Expected: {"jsonrpc":"2.0","result":"ok","id":1}
```

---

## Phase 3 — SPL Token + $BB Mint

- [ ] Deploy System Program (native Rust, not rBPF) for account creation
- [ ] Deploy SPL Token Program ELF into `svm_programs` table
- [ ] Create `$BB` token mint account via SPL Token `initialize_mint`
- [ ] `mintTo`, `transfer`, `burn` via SPL Token instructions
- [ ] Map existing `ConcurrentBlockchain` `mint` / `burn` admin endpoints to SPL Token CPI
- [ ] `getTokenAccountBalance` RPC method
- [ ] **Tests**
  - [ ] `test_spl_mint_initialize`
  - [ ] `test_spl_mint_to_alice`
  - [ ] `test_spl_transfer_alice_to_bob`
  - [ ] `test_spl_burn`

---

## Phase 4 — Anchor Programs

- [ ] Tier1 Vault program (Anchor) — USDT → $BB 1:10 gatekeeper
- [ ] Tier2 Vault program (Anchor) — L2 dealer settlement receipts
- [ ] Oracle program — price feed + CPI guard
- [ ] Deploy via `solana program deploy` against port 8899
- [ ] **Tests**
  - [ ] `test_tier1_vault_deposit`
  - [ ] `test_tier1_vault_withdraw`
  - [ ] `test_dealer_settle_batch`
  - [ ] `test_oracle_price_update`

---

## Phase 5 — OneKey / Phantom Bridge

- [ ] `sendTransaction` round-trip confirmed with OneKey hardware wallet
- [ ] `getAccountInfo` used by OneKey to show $BB balance
- [ ] Co-signing service wired to `BlackBookRpcImpl`
- [ ] Network config JSON served at `GET /` (Solana cluster info endpoint)
- [ ] **Tests**
  - [ ] `test_onekey_sign_and_send`
  - [ ] `test_phantom_connect_getBalance`
  - [ ] `test_wallet_adapter_sendTransaction`

---

## Phase 6 — Mainnet Hardening

- [ ] Compute budget: reject transactions exceeding `200_000` CUs
- [ ] Fee market: `LocalizedFeeMarket` gates RPC `sendTransaction` with priority fee
- [ ] Rate limiting: jsonrpsee middleware, 100 req/s per IP
- [ ] Snapshot: `SvmAccountsDB` periodic checkpoint to separate ReDB file
- [ ] Observability: Prometheus metrics endpoint `/metrics`
  - [ ] `bb_rpc_requests_total` (by method)
  - [ ] `bb_lamports_total` (global conservation check exported)
  - [ ] `bb_slot_height`
- [ ] Load test: 10,000 TPS sustained for 60s without lamport conservation violation
- [ ] Security: Fuzz `sendTransaction` input with `cargo fuzz`

---

## Invariants — Must Never Regress

| Invariant | Verified by |
|-----------|------------|
| `LAMPORTS_PER_BB = 100_000` | `svm_invariant_tests.rs` |
| `RENT_EPOCH_EXEMPT = u64::MAX` | `svm_accounts_tests.rs` |
| `Σ lamports = constant` across all transfers | `test_global_lamport_conservation` |
| `cargo build` (no svm flag) compiles clean | CI |
| `cargo build --features svm` compiles clean | CI |
| All 34 SVM+RPC tests pass | `cargo test --features svm` |

---

## Test Count Summary

| File | Tests | Status |
|------|-------|--------|
| `tests/svm_accounts_tests.rs` | 5 | ✅ |
| `tests/svm_runtime_tests.rs` | 5 | ✅ |
| `tests/svm_block_production_tests.rs` | 3 | ✅ |
| `tests/svm_parallel_tests.rs` | 4 | ✅ |
| `tests/svm_invariant_tests.rs` | 3 | ✅ |
| `tests/rpc_tests.rs` | 9 | ✅ |
| `tests/rpc_send_tests.rs` | 5 | ✅ |
| **Total** | **34** | **34/34 ✅** |

---

## Quick Commands

```powershell
# Full SVM build
cargo build --features svm

# All SVM tests (34 tests)
cargo test --features svm --test svm_accounts_tests --test svm_runtime_tests --test svm_block_production_tests --test svm_parallel_tests --test svm_invariant_tests --test rpc_tests --test rpc_send_tests

# RPC read tests only (Phase 2A)
cargo test --features svm --test rpc_tests

# RPC write tests only (Phase 2B)
cargo test --features svm --test rpc_send_tests

# Run the server (port 8080 HTTP + port 8899 Solana RPC)
cargo run --features svm

# Smoke test the RPC
curl -s -X POST http://localhost:8899 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
```
