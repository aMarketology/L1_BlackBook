# BB_SVM: Embedded Solana Virtual Machine Upgrade Plan

## Executive Summary

BlackBook L1 currently runs a custom execution engine: transactions hit Axum REST endpoints, get verified via Ed25519, and are processed by hand-written Rust logic that debits/credits f64 balances in ReDB. This works — but it means **zero compatibility** with Solana wallets (OneKey, Phantom), explorers (Solscan), or the Anchor smart contract framework.

The fix is **not** to rewrite the chain. It's to **embed the Solana Virtual Machine (rBPF)** into the execution pipeline — exactly what Eclipse and Sonic do. Your PoH clock, Gulf Stream, Sealevel scheduler, Turbine shredding, and Tower BFT consensus all stay. Only the "execute this transaction" step changes from custom Rust logic to the standard Solana rBPF VM.

The result: OneKey treats your chain like a Solana subnet. Anchor programs compile and deploy. Your 50k TPS engine stays intact.

---

## Part 1: How the Current System Works

### 1.1 The Transaction Lifecycle (Today)

```
User (SDK/Wallet)
        │
        ▼
  HTTP REST (Axum :8080)               gRPC (:50051)
  POST /transfer/simple                 L1Settlement service
  POST /sealevel/submit                 LockTokens / SettleBet
        │                                      │
        ▼                                      ▼
  Ed25519 Signature Verify              Ed25519 Signature Verify
  (ed25519-dalek in handler)            (ed25519-dalek in gRPC impl)
        │                                      │
        ▼                                      ▼
  Gulf Stream (Mempool)                 Direct blockchain.credit/debit
  flume channels, priority sorted
        │
        ▼
  Sealevel Parallel Scheduler
  (rayon thread pool + AccountLockManager)
  schedule_with_locks() → batches
        │
        ▼
  execute_batch_with_locks()
  ┌─────────────────────────────────────────────┐
  │  ParallelScheduler::execute_single()        │
  │  - Check balance from DashMap cache         │
  │  - Debit sender (cache update)              │
  │  - Credit receiver (cache update)           │
  │  - Return TransactionResult                 │
  └─────────────────────────────────────────────┘
        │
        ▼
  blockchain.transfer(from, to, amount)
  ┌─────────────────────────────────────────────┐
  │  ConcurrentBlockchain                       │
  │  - ReDB ACID write (debit + credit)         │
  │  - DashMap cache update                     │
  │  - TransactionRecord logged                 │
  │  - Total supply atomic update               │
  └─────────────────────────────────────────────┘
        │
        ▼
  PoH Mix → BlockProducer::produce_block()
  ┌─────────────────────────────────────────────┐
  │  - Collect pending transactions             │
  │  - Execute each via execute_transaction()   │
  │    (match on TxData enum variants)          │
  │  - Compute Merkle state root                │
  │  - Build FinalizedBlock                     │
  │  - Turbine shredding for propagation        │
  └─────────────────────────────────────────────┘
        │
        ▼
  FinalityTracker (2 confirmations = finalized)
```

### 1.2 Key Files and What They Do

| File | Purpose | Lines | SVM Impact |
|------|---------|-------|------------|
| `src/main.rs` | HTTP routes, AppState, startup | 1185 | Replace REST routes with JSON-RPC 2.0. Keep startup/PoH/security. |
| `runtime/core.rs` | ParallelScheduler, AccountLockManager, CircuitBreaker, NetworkThrottler, fee market, Transaction struct | 804 | **Keep all of it.** Scheduler feeds SVM instead of `execute_single()`. Transaction struct needs Solana format adapter. |
| `runtime/poh_service.rs` | PoH clock, 4-stage pipeline, confirmations | 823 | **Keep all of it.** Pipeline Stage 3 (Execute) calls rBPF VM instead of direct balance updates. |
| `runtime/consensus.rs` | Tower BFT, PoH entries, Gulf Stream, LeaderSchedule | — | **Keep all of it.** Consensus is decoupled from execution. |
| `src/poh_blockchain.rs` | BlockProducer, FinalizedBlock, MerkleTree, Turbine, FinalityTracker | 1111 | `execute_transaction()` match on TxData → replaced by rBPF VM call. Rest stays. |
| `src/storage/mod.rs` | ConcurrentBlockchain (ReDB + DashMap), TransactionRecord, credit/debit, FROST key storage | 1488 | ReDB becomes the **AccountsDB** backing store for SVM. Need to add Solana account format (owner, lamports, data, executable). |
| `protocol/blockchain.rs` | Tier1Gateway, Tier2Vault, DimeVintage, TxData enum, L1Events | 1061 | Vault logic moves into **Anchor programs**. TxData enum replaced by SVM instruction parsing. |
| `src/wallet_unified/handlers.rs` | FROST 2-of-3 wallet creation, SSS signing, shard management | 454 | **Keep all of it.** SSS signing produces standard Ed25519 signatures that the SVM validates natively. Add OneKey shard-validator bridge. |
| `src/grpc/mod.rs` | L2 Settlement service (lock, settle, credit sessions) | 757 | Keep for L2 communication. Add SVM instruction submission path. |
| `Cargo.toml` | Dependencies | 185 | Add `solana-rbpf`, `solana-sdk`, `solana-program-runtime`, `anchor-lang`. |

### 1.3 Current Execution Engine (What Gets Replaced)

The custom execution lives in **two places**:

**Place 1: `poh_blockchain.rs` → `BlockProducer::execute_transaction()`** (line ~800)
```rust
fn execute_transaction(&self, tx: &Transaction) -> Result<(), String> {
    match &tx.data {
        TxData::DepositUsdt { usdt_amount, .. } => {
            let bb_amount = usdt_amount * 10;
            self.blockchain.credit(&tx.from, bb_amount as f64)
        }
        TxData::TransferBb { to, amount } => {
            self.blockchain.debit(&tx.from, *amount as f64)?;
            self.blockchain.credit(to, *amount as f64)
        }
        // ... 8 more match arms for each tx type
    }
}
```

**Place 2: `runtime/core.rs` → `ParallelScheduler::execute_single()`** (line ~710)
```rust
fn execute_single(tx: &Transaction, balances: &DashMap<String, f64>) -> TransactionResult {
    // Check balance, debit sender, credit receiver
    // All in-memory via DashMap
}
```

Both of these get replaced by: **"Deserialize the SVM transaction → Load accounts from ReDB → Run rBPF VM → Write results back to ReDB."**

### 1.4 Current Account Model

```
ReDB Table: "accounts"
Key:   &str  (address like "bb_7707fe614ad679b84a6cbc128999c1b5")
Value: f64   (balance like 1000.50)

DashMap Cache: HashMap<String, f64>
(Mirror of ReDB for lock-free reads)
```

**Problem:** Solana accounts are not just a balance. They are:
```rust
struct SolanaAccount {
    lamports: u64,           // Balance (integer, not float!)
    data: Vec<u8>,           // Arbitrary program data (vault state, etc.)
    owner: Pubkey,           // Which program owns this account
    executable: bool,        // Is this a program (smart contract)?
    rent_epoch: u64,         // Rent tracking
}
```

This is the **biggest structural change** — ReDB needs to store full Solana accounts, not just f64 balances.

### 1.5 Current Signature Model

- **Ed25519** via `ed25519-dalek` (Solana uses the same curve)
- **FROST Ed25519** 2-of-3 threshold signatures for SSS wallets
- Signature format: `chain_id_byte + payload + timestamp + nonce`

**Good news:** Ed25519 is Solana's native signature. FROST signatures are valid Ed25519 signatures after aggregation. The SVM will validate them without modification.

**Bad news:** Solana's transaction format is different from your custom `SignedTransferRequest`. This needs an adapter.

---

## Part 2: The Embedded SVM Architecture

### 2.1 High-Level Architecture (After Upgrade)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     BLACKBOOK L1 — EMBEDDED SVM                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   CONSENSUS LAYER (UNCHANGED - Your Custom Engine)                       │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  PoH Clock (600ms slots) → Gulf Stream → Tower BFT → Turbine    │   │
│   │  LeaderSchedule → ParallelScheduler → AccountLockManager         │   │
│   │  CircuitBreaker → NetworkThrottler → LocalizedFeeMarket          │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                    [Ordered Transaction Batch]                            │
│                              │                                           │
│                              ▼                                           │
│   EXECUTION LAYER (NEW - Solana rBPF VM)                                │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │                                                                   │   │
│   │   1. Deserialize Solana Transaction (versioned or legacy)        │   │
│   │   2. Load accounts from AccountsDB (ReDB + DashMap)             │   │
│   │   3. Execute via solana_rbpf VM                                  │   │
│   │      - System Program (transfers, account creation)              │   │
│   │      - SPL Token Program ($BB token, $DIME token)               │   │
│   │      - Anchor Programs (Tier1 Vault, Tier2 Vault, Oracle)       │   │
│   │   4. Verify compute budget (CU metering)                        │   │
│   │   5. Commit account state changes to ReDB                       │   │
│   │                                                                   │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                    [Updated Account States]                               │
│                              │                                           │
│                              ▼                                           │
│   STORAGE LAYER (UPGRADED - Solana Account Format)                       │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  ReDB "accounts_v2" table:                                       │   │
│   │    Key:   Pubkey (32 bytes)                                      │   │
│   │    Value: AccountSharedData {                                    │   │
│   │      lamports: u64,                                              │   │
│   │      data: Vec<u8>,       // Program state (vault data, etc.)   │   │
│   │      owner: Pubkey,       // Which program owns this account    │   │
│   │      executable: bool,    // Is this a deployed program?        │   │
│   │      rent_epoch: u64,                                            │   │
│   │    }                                                             │   │
│   │                                                                   │   │
│   │  DashMap<Pubkey, AccountSharedData>  (hot cache, lock-free)      │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                              ▼                                           │
│   RPC LAYER (NEW - Solana JSON-RPC 2.0)                                 │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  Port 8899 (standard Solana RPC port)                            │   │
│   │                                                                   │   │
│   │  getAccountInfo       → ReDB lookup                              │   │
│   │  getBalance           → ReDB lookup (lamports)                   │   │
│   │  getLatestBlockhash   → PoH current hash                        │   │
│   │  sendTransaction      → Gulf Stream submit                      │   │
│   │  getTransaction       → ReDB transaction log                    │   │
│   │  getSlot              → current_slot AtomicU64                   │   │
│   │  getBlock             → BlockProducer block cache                │   │
│   │  getSignaturesFor...  → ReDB transaction index                  │   │
│   │  simulateTransaction  → Dry-run rBPF execution                  │   │
│   │  getGenesisHash       → Unique BB genesis identifier            │   │
│   │  getHealth            → Existing health check                    │   │
│   │  getVersion           → { "solana-core": "BB-5.0.0" }          │   │
│   │                                                                   │   │
│   │  + Keep existing REST on :8080 for backward compat               │   │
│   │  + Keep gRPC on :50051 for L2 settlement                        │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   WALLET LAYER (ENHANCED - SSS + OneKey Hybrid)                         │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  FROST 2-of-3 SSS (unchanged)                                   │   │
│   │    + OneKey as Shard Validator (new)                              │   │
│   │    + Output: Standard Solana Ed25519 transaction                 │   │
│   │    + OneKey reads & displays Anchor IDL instructions             │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   PROGRAMS (NEW - Anchor Smart Contracts on Your Chain)                  │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  bb_token_program     → SPL Token for $BB (mint/transfer/burn)  │   │
│   │  dime_token_program   → SPL Token for $DIME                     │   │
│   │  tier1_vault_program  → Anchor: USDT→$BB at 1:10 gateway       │   │
│   │  tier2_vault_program  → Anchor: $BB→$DIME with vintage stamps   │   │
│   │  oracle_program       → Anchor: CPI index updates               │   │
│   │  governance_program   → Anchor: Multi-sig parameter updates     │   │
│   └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Part 3: What Changes, File by File

### 3.1 `Cargo.toml` — New Dependencies

```toml
# ═══════════════════════════════════════════════════════════════
# EMBEDDED SVM (Solana Virtual Machine)
# ═══════════════════════════════════════════════════════════════

# The BPF VM that executes Solana smart contracts
solana-bpf-loader-program = "2.1"
solana-rbpf = "0.8"

# Solana account types, Pubkey, transaction format
solana-sdk = "2.1"
solana-program = "2.1"

# Program runtime (loads and executes BPF programs)
solana-program-runtime = "2.1"
solana-compute-budget = "2.1"

# System programs (transfer, account creation)
solana-system-program = "2.1"

# SPL Token program ($BB and $DIME as native SPL tokens)
spl-token = "7.0"
spl-associated-token-account = "5.0"

# Transaction processing
solana-svm = "2.1"             # The full SVM transaction processor
solana-transaction-status = "2.1"

# RPC compatibility
solana-rpc-client-api = "2.1"  # Request/response types
solana-account-decoder = "2.1" # Account encoding (base58, base64)

# Anchor framework support (for vault programs)
anchor-lang = "0.30"
```

> **Note:** Exact version pins will depend on compatibility testing. The `solana-svm` crate is the cleanest integration point — it wraps the full transaction processor including the rBPF VM, loader, and sysvars.

### 3.2 `src/storage/mod.rs` — AccountsDB Upgrade

**Current state:** ReDB stores `&str → f64` (address → balance).

**Target state:** ReDB stores `[u8; 32] → AccountSharedData` (Pubkey → full Solana account).

#### What changes:

1. **New ReDB table** `ACCOUNTS_V2` with Pubkey keys and borsh-serialized account values
2. **New `SvmAccountsDB` struct** that implements the Solana `AccountsDB` trait so the rBPF VM can load/store accounts
3. **DashMap cache upgrade** from `DashMap<String, f64>` to `DashMap<Pubkey, AccountSharedData>`
4. **Migration:** Existing f64 balances converted to SPL token accounts during genesis
5. **Keep old tables** for backward compat during transition

#### New table definitions:
```rust
// Solana-format accounts: Pubkey (32 bytes) → AccountSharedData (borsh serialized)
const SVM_ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("svm_accounts");

// Program executable storage: ProgramId (32 bytes) → ELF binary (.so file)
const SVM_PROGRAMS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("svm_programs");

// Blockhash queue: Slot (u64) → Blockhash (32 bytes) — needed for recent_blockhash validation
const BLOCKHASH_QUEUE: TableDefinition<u64, &[u8]> = TableDefinition::new("blockhash_queue");
```

### 3.3 `src/svm_runtime.rs` — NEW FILE: The rBPF Execution Engine

This is the core new module. It wraps `solana-svm`'s `TransactionBatchProcessor` (or builds a custom one from `solana-rbpf` + `solana-program-runtime`).

#### Responsibilities:
1. Accept a batch of Solana `VersionedTransaction` from the scheduler
2. Load required accounts from ReDB/DashMap
3. Execute each transaction through the rBPF VM
4. Enforce compute budget limits (200k CU default, configurable)
5. Return updated account states
6. Write results back to ReDB

#### Key struct:
```rust
pub struct BlackBookSVM {
    /// Account loader backed by ReDB + DashMap
    accounts_db: Arc<SvmAccountsDB>,
    
    /// Program cache (compiled BPF programs)
    program_cache: Arc<RwLock<ProgramCache>>,
    
    /// Blockhash queue for recent_blockhash validation
    blockhash_queue: Arc<RwLock<BlockhashQueue>>,
    
    /// Built-in programs (System, SPL Token, BB Vault programs)
    builtin_programs: Vec<BuiltinProgram>,
    
    /// Compute budget defaults
    default_compute_units: u64,
    max_compute_units: u64,
}

impl BlackBookSVM {
    /// Execute a batch of transactions (called by ParallelScheduler)
    pub fn execute_batch(
        &self,
        transactions: &[SanitizedTransaction],
        slot: u64,
    ) -> Vec<TransactionExecutionResult> { ... }
    
    /// Deploy a new program (BPF .so binary)
    pub fn deploy_program(
        &self,
        program_id: Pubkey,
        elf_bytes: &[u8],
    ) -> Result<(), SvmError> { ... }
    
    /// Simulate a transaction without committing (for RPC simulateTransaction)
    pub fn simulate(
        &self,
        transaction: &SanitizedTransaction,
    ) -> SimulationResult { ... }
}
```

### 3.4 `src/poh_blockchain.rs` — BlockProducer Changes

**Current:** `execute_transaction()` matches on `TxData` enum (line ~800).

**After:** `execute_transaction()` calls `BlackBookSVM::execute_batch()`.

```
BEFORE:
  BlockProducer::produce_block()
    → for tx in transactions:
        execute_transaction(tx)  // match TxData::TransferBb, etc.

AFTER:
  BlockProducer::produce_block()
    → sanitized_txs = transactions.map(deserialize_solana_tx)
    → results = svm.execute_batch(sanitized_txs, slot)
    → for (tx, result) in zip(txs, results):
        if result.is_ok() { add to block }
```

**What stays:** MerkleTree, FinalizedBlock, Turbine shredding, FinalityTracker, verification functions.

### 3.5 `runtime/core.rs` — Scheduler Integration

**Current:** `execute_single()` does `DashMap.get → check balance → debit → credit`.

**After:** `execute_single()` delegates to `BlackBookSVM`.

The `ParallelScheduler` stays — it's about **ordering and conflict detection**, not execution. The change is:
- `Transaction` struct gets a `raw_solana_tx: Option<Vec<u8>>` field for the serialized Solana transaction
- `read_accounts` and `write_accounts` are derived from the Solana transaction's account keys
- `execute_batch_with_locks()` calls `svm.execute_batch()` instead of `execute_single()`

### 3.6 `src/solana_rpc.rs` — NEW FILE: JSON-RPC 2.0 Server

Implements the standard Solana JSON-RPC interface on port 8899.

#### Core methods mapped to existing infrastructure:

| Solana RPC Method | Maps To |
|---|---|
| `getAccountInfo(pubkey)` | `SvmAccountsDB::get_account(pubkey)` → ReDB lookup |
| `getBalance(pubkey)` | `SvmAccountsDB::get_account(pubkey).lamports` |
| `getLatestBlockhash` | `PoHService::current_hash` + `current_slot` |
| `sendTransaction(tx_bytes)` | Deserialize → `GulfStreamService::submit()` |
| `getTransaction(sig)` | ReDB `TRANSACTIONS` table lookup |
| `getSlot` | `current_slot.load(Ordering::Relaxed)` |
| `getBlock(slot)` | `BlockProducer::get_block(slot)` |
| `getSignaturesForAddress` | ReDB index scan |
| `simulateTransaction(tx)` | `BlackBookSVM::simulate(tx)` |
| `getGenesisHash` | Hardcoded unique hash for BB network |
| `getHealth` | Existing health check logic |
| `getVersion` | `{ "solana-core": "BB-5.0.0-svm" }` |
| `getEpochInfo` | PoH epoch data |
| `getMinimumBalanceForRentExemption` | Compute from account size |
| `getTokenAccountsByOwner` | ReDB SPL token account index |
| `getTokenSupply` | $BB and $DIME mint account data |

#### Implementation approach:
Use `jsonrpsee` crate (Solana's own RPC uses `jsonrpsee`). Wire each method to existing `AppState` fields.

### 3.7 `protocol/blockchain.rs` — Vault Logic → Anchor Programs

**Current:** `Tier1Gateway`, `Tier2Vault`, `DimeVintage`, `TxData` enum are Rust structs processed by `execute_transaction()` match arms.

**After:** These become **Anchor programs** compiled to BPF `.so` files and deployed to the chain.

The `TxData` enum effectively becomes Anchor instruction discriminators:
| Current `TxData` Variant | Anchor Instruction |
|---|---|
| `DepositUsdt { usdt_amount }` | `tier1_vault::deposit(amount)` |
| `RedeemBbForUsdt { bb_amount }` | `tier1_vault::redeem(amount)` |
| `LockBbForDime { bb_amount }` | `tier2_vault::lock(amount)` |
| `RedeemDimeVintage { vintage_id }` | `tier2_vault::redeem_vintage(vintage_id)` |
| `UpdateCpi { new_cpi_index }` | `oracle::update_cpi(new_index)` |
| `TransferBb { to, amount }` | SPL Token `transfer` instruction |
| `TransferDime { to, amount }` | SPL Token `transfer` instruction |

**The protocol/blockchain.rs file stays as documentation** but is no longer the execution path.

### 3.8 `src/wallet_unified/handlers.rs` — SSS + OneKey Bridge

**Current SSS flow stays identical.** The change is in the **output format**:

```
BEFORE:
  SSS reconstruct → FROST sign → custom TransferRequest → blockchain.transfer()

AFTER:
  SSS reconstruct → FROST sign → Solana Transaction (with Anchor instruction)
                                       │
                                       ├─→ Direct submit to Gulf Stream
                                       │
                                       └─→ Pass to OneKey via Bluetooth for
                                           hardware co-signing (new path)
```

#### OneKey as Shard Validator (New Feature):

```
┌─────────────────────────────────────────────────────────────────────┐
│                 SSS + OneKey Hybrid Signing Flow                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User initiates transaction in BB wallet app                      │
│                                                                      │
│  2. App loads Share A (phone, encrypted with password)               │
│     App requests Share B from server (ReDB, encrypted with master)   │
│                                                                      │
│  3. FROST Round 1: Generate commitments for Share A + Share B        │
│                                                                      │
│  4. FROST Round 2: Compute partial signatures                        │
│     sig_share_a = sign(Share A, signing_package)                     │
│     sig_share_b = sign(Share B, signing_package)                     │
│                                                                      │
│  5. Aggregate → Standard Ed25519 signature                           │
│                                                                      │
│  6. Build Solana Transaction:                                        │
│     {                                                                │
│       signatures: [aggregated_ed25519_sig],                          │
│       message: {                                                     │
│         recent_blockhash: <from PoH>,                                │
│         instructions: [{                                             │
│           program_id: tier1_vault_program,                           │
│           accounts: [user, vault, token_mint, ...],                  │
│           data: anchor_ix_data("deposit", { amount: 100 })           │
│         }]                                                           │
│       }                                                              │
│     }                                                                │
│                                                                      │
│  7. OneKey Finality (Optional Hardware Approval):                    │
│     ┌────────────────────────────────────────────────────────────┐   │
│     │  App sends unsigned tx to OneKey via Bluetooth/USB         │   │
│     │  OneKey displays: "Deposit 100 USDT to Tier-1 Vault"      │   │
│     │  (Decoded from Anchor IDL — human-readable!)               │   │
│     │  User presses physical button → OneKey signs               │   │
│     │  OneKey signature replaces or co-signs with FROST sig      │   │
│     └────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  8. Submit signed transaction to Solana RPC on :8899                 │
│     → sendTransaction(tx_bytes)                                      │
│     → Gulf Stream → Sealevel → rBPF VM → ReDB commit                │
│                                                                      │
│  MODES:                                                              │
│  A) SSS-only:    Share A + Share B → FROST → submit (current flow)  │
│  B) OneKey-only:  OneKey hardware → Ed25519 sign → submit            │
│  C) SSS + OneKey: FROST builds tx → OneKey gives final approval     │
│     (Ultimate security: threshold + hardware)                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.9 Genesis Configuration — NEW FILE: `src/genesis.rs`

Defines the genesis state for the BB network:

```rust
pub struct BlackBookGenesis {
    // Unique genesis hash (identifies BB network vs Solana mainnet)
    pub genesis_hash: Hash,       // SHA256 of "BLACKBOOK_L1_GENESIS_2025"
    
    // System accounts
    pub system_program: Pubkey,   // 1111...1111 (standard)
    pub spl_token_program: Pubkey,// Token program for $BB and $DIME
    
    // Token mints
    pub bb_mint: Pubkey,          // $BB mint authority (controlled by Tier1 vault)
    pub dime_mint: Pubkey,        // $DIME mint authority (controlled by Tier2 vault)
    pub usdt_mint: Pubkey,        // Wrapped USDT on BB chain
    
    // Vault programs
    pub tier1_vault_program: Pubkey,
    pub tier2_vault_program: Pubkey,
    pub oracle_program: Pubkey,
    
    // Initial validator
    pub genesis_validator: Pubkey,
    
    // Initial parameters
    pub usdt_to_bb_ratio: u64,   // 10 (1 USDT = 10 BB)
    pub slot_duration_ms: u64,    // 600
    pub base_cpi: f64,            // 100.0
}
```

When OneKey connects and calls `getGenesisHash`, it gets back the unique BB hash — preventing accidental cross-chain transactions.

---

## Part 4: Implementation Phases

### Phase 1: Foundation — AccountsDB + rBPF Integration (Weeks 1-4)

**Goal:** ReDB stores Solana accounts. rBPF VM executes basic System Program instructions (transfer SOL/lamports).

| Week | Task | Files |
|------|------|-------|
| 1 | Add `solana-sdk`, `solana-rbpf`, `solana-program-runtime` to Cargo.toml. Create `SvmAccountsDB` struct wrapping ReDB with Solana account format. New ReDB tables. | `Cargo.toml`, `src/storage/mod.rs` |
| 2 | Create `src/svm_runtime.rs` — initialize rBPF VM, load System Program as builtin, execute basic `Transfer` instructions. Unit tests. | `src/svm_runtime.rs` |
| 3 | Wire `svm_runtime` into `BlockProducer::produce_block()`. Replace `execute_transaction()` match arms with SVM batch execution. Keep old path as fallback. | `src/poh_blockchain.rs` |
| 4 | Wire `ParallelScheduler` to use SVM. Adapt `Transaction` struct to carry Solana tx bytes. Integration tests. | `runtime/core.rs` |

**Milestone:** `cargo test` passes. A Solana `Transfer` instruction debits/credits accounts via rBPF VM and persists to ReDB.

### Phase 2: Solana RPC Server (Weeks 5-7)

**Goal:** OneKey can connect via Custom RPC and query balances / send transactions.

| Week | Task | Files |
|------|------|-------|
| 5 | Create `src/solana_rpc.rs` with `jsonrpsee`. Implement `getAccountInfo`, `getBalance`, `getLatestBlockhash`, `getSlot`, `getHealth`, `getVersion`, `getGenesisHash`. | `src/solana_rpc.rs` |
| 6 | Implement `sendTransaction` (deserialize → Gulf Stream submit → SVM execute). Implement `getTransaction`, `getBlock`, `getSignaturesForAddress`. | `src/solana_rpc.rs` |
| 7 | Implement `simulateTransaction`, `getEpochInfo`, `getMinimumBalanceForRentExemption`. Start RPC server on :8899 alongside existing :8080. End-to-end test with `@solana/web3.js`. | `src/solana_rpc.rs`, `src/main.rs` |

**Milestone:** OneKey connects to `http://your-server:8899` as Custom RPC. Shows balance. Can send a basic transfer.

### Phase 3: SPL Token Programs — $BB and $DIME (Weeks 8-10)

**Goal:** $BB and $DIME are native SPL tokens. OneKey displays token balances.

| Week | Task | Files |
|------|------|-------|
| 8 | Deploy SPL Token program as builtin. Create $BB mint, $DIME mint, and USDT mint in genesis. Migrate existing f64 balances to SPL token accounts. | `src/genesis.rs`, `src/svm_runtime.rs` |
| 9 | Implement `getTokenAccountsByOwner`, `getTokenSupply` RPC methods. OneKey shows token balances. Token transfers work via standard SPL `transfer` instruction. | `src/solana_rpc.rs` |
| 10 | Balance migration tool — convert all existing ReDB f64 balances to SPL token accounts. Backward compat: `/balance/:address` REST endpoint reads from SPL accounts. | `src/storage/mod.rs`, `src/main.rs` |

**Milestone:** OneKey shows $BB and $DIME balances. Token transfers work through OneKey's standard Solana UI.

### Phase 4: Anchor Vault Programs (Weeks 11-14)

**Goal:** Tier 1 ($USDT → $BB) and Tier 2 ($BB → $DIME) vaults are Anchor programs deployed to the chain.

| Week | Task | Files |
|------|------|-------|
| 11 | Write `tier1_vault` Anchor program: `deposit(usdt_amount)`, `redeem(bb_amount)`. Enforces 1:10 ratio. Compile to BPF .so. | `programs/tier1_vault/` |
| 12 | Write `tier2_vault` Anchor program: `lock(bb_amount)`, `redeem_vintage(vintage_id)`. Vintage tracking, CPI-adjusted $DIME minting. | `programs/tier2_vault/` |
| 13 | Write `oracle` Anchor program: `update_cpi(new_index)`. Multi-sig authority for CPI updates. Deploy BPF loader support to SVM runtime. | `programs/oracle/`, `src/svm_runtime.rs` |
| 14 | Generate IDL JSON files. Publish to block explorer. OneKey can decode: "You are locking 100 USDT into the Tier-1 Vault". End-to-end test: USDT → $BB → $DIME flow through OneKey. | `programs/*/idl/` |

**Milestone:** Full vault lifecycle works through OneKey. IDL transparency — users see human-readable instruction descriptions.

### Phase 5: SSS + OneKey Hybrid Signing (Weeks 15-17)

**Goal:** OneKey acts as a shard validator in the SSS flow.

| Week | Task | Files |
|------|------|-------|
| 15 | Build `SolanaTransactionBuilder` — takes FROST-signed message and wraps it into a valid Solana `VersionedTransaction`. | `src/wallet_unified/tx_builder.rs` |
| 16 | OneKey hardware signing bridge: pass unsigned Solana transaction to OneKey device. OneKey displays decoded Anchor instruction. User approves with hardware button. OneKey returns signature. | `src/wallet_unified/onekey_bridge.rs` |
| 17 | Three signing modes: (A) SSS-only, (B) OneKey-only, (C) SSS + OneKey hybrid. Integration tests for all three modes. | `src/wallet_unified/handlers.rs` |

**Milestone:** User can sign a $DIME mint transaction using FROST aggregation + OneKey hardware approval.

### Phase 6: Production Hardening (Weeks 18-19)

| Week | Task |
|------|------|
| 18 | Compute budget enforcement. Rate limiting on RPC. Program deployment governance (multi-sig for new programs). Rent exemption for permanent accounts. |
| 19 | Load testing: 50k TPS with SVM execution. Block explorer web UI with IDL decoding. gRPC L2 settlement via SVM instructions. Full regression test suite. |

**Milestone:** Production-ready. 50k TPS sustained. OneKey + Phantom + Solflare all work. Anchor programs auditable.

---

## Part 5: What Does NOT Change

These components are **kept as-is** throughout the upgrade:

| Component | File(s) | Reason |
|---|---|---|
| PoH Clock | `runtime/poh_service.rs` | Consensus is decoupled from execution |
| Gulf Stream | `runtime/consensus.rs` | Transaction forwarding is VM-agnostic |
| Tower BFT | `runtime/consensus.rs` | Voting/forking is consensus, not execution |
| Turbine Shredding | `src/poh_blockchain.rs` | Block propagation is consensus-layer |
| Leader Schedule | `runtime/consensus.rs` | Validator rotation is consensus |
| Circuit Breaker | `runtime/core.rs` | Security policy stays, applied before SVM |
| Network Throttler | `runtime/core.rs` | Rate limiting stays, applied before SVM |
| Localized Fee Market | `runtime/core.rs` | Fee logic stays, SVM adds CU metering on top |
| Finality Tracker | `src/poh_blockchain.rs` | Confirmation counting is consensus-layer |
| FROST Key Distribution | `src/wallet_unified/` | Triple-write (ReDB + Supabase + Vault) stays |
| gRPC L2 Settlement | `src/grpc/mod.rs` | Stays for L2 backend communication |
| Supabase Sync | `src/supabase.rs` | Shard A cloud backup stays |
| HashiCorp Vault | `src/vault_manager.rs` | Shard C cold storage stays |
| ReDB Persistence | `src/storage/mod.rs` | Upgraded but not replaced — new tables added |

---

## Part 6: Risk Mitigation

### 6.1 Backward Compatibility

- **Dual-mode operation:** REST API on :8080 stays operational throughout. New Solana RPC on :8899 runs in parallel.
- **Account migration:** Existing f64 balances auto-migrated to SPL token accounts during genesis initialization. Old read paths still work.
- **Feature flags:** Each phase behind a Cargo feature flag (`svm_execution`, `solana_rpc`, `anchor_programs`). Can roll back per-feature.

### 6.2 Performance

- **rBPF overhead:** The Solana VM adds ~5-10μs per instruction on top of raw Rust. For transfer instructions, this is negligible vs. the 600ms slot time.
- **Account loading:** DashMap hot cache eliminates ReDB reads for 99%+ of transactions (same as today).
- **Compute budget:** Prevents runaway programs from consuming block time. Default 200k CU, cap at 1.4M CU per transaction.

### 6.3 Security

- **BPF verifier:** Solana's BPF verifier runs before any program executes, preventing invalid memory access, infinite loops, and syscall abuse.
- **Program deployment:** Only governance multi-sig can deploy new programs (no permissionless deployment initially).
- **Existing protections stay:** Circuit breaker, throttler, localized fees all run before transactions reach the SVM.

---

## Part 7: Directory Structure After Upgrade

```
L1_BlackBook/
├── src/
│   ├── main.rs                    # Startup, REST routes (:8080), PoH init
│   ├── lib.rs                     # Library exports
│   ├── solana_rpc.rs              # NEW: JSON-RPC 2.0 server (:8899)
│   ├── svm_runtime.rs             # NEW: rBPF VM wrapper + AccountsDB adapter
│   ├── genesis.rs                 # NEW: Genesis hash, mint PDAs, initial state
│   ├── poh_blockchain.rs          # BlockProducer (execute_transaction → SVM)
│   ├── proof_of_reserves.rs       # PoR Merkle proofs (reads from SPL accounts)
│   ├── social_mining.rs           # Social mining logic
│   ├── supabase.rs                # Supabase cloud sync
│   ├── vault_manager.rs           # HashiCorp Vault integration
│   ├── storage/
│   │   └── mod.rs                 # ReDB + DashMap (upgraded with SVM account tables)
│   ├── consensus/
│   │   └── mod.rs                 # Simplified consensus stub
│   ├── grpc/
│   │   └── mod.rs                 # L2 Settlement gRPC (stays)
│   ├── wallet_unified/
│   │   ├── mod.rs
│   │   ├── handlers.rs            # FROST 2-of-3 creation + signing
│   │   ├── tx_builder.rs          # NEW: FROST sig → Solana Transaction builder
│   │   ├── onekey_bridge.rs       # NEW: OneKey hardware signing bridge
│   │   ├── opaque_impl.rs
│   │   └── security.rs            # AES-256-GCM encryption
│   └── usdc/
│       └── reserve.rs
├── runtime/
│   ├── mod.rs                     # Runtime exports
│   ├── core.rs                    # ParallelScheduler (feeds SVM), locks, security
│   ├── consensus.rs               # Tower BFT, PoH, Gulf Stream, LeaderSchedule
│   └── poh_service.rs             # PoH clock, 4-stage pipeline
├── protocol/
│   ├── mod.rs
│   ├── blockchain.rs              # Tier structs (kept as reference, not execution path)
│   └── helpers.rs
├── programs/                       # NEW: Anchor smart contracts
│   ├── tier1_vault/
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs             # deposit(), redeem()
│   │   └── idl/tier1_vault.json   # Generated IDL for wallets
│   ├── tier2_vault/
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs             # lock(), redeem_vintage()
│   │   └── idl/tier2_vault.json
│   └── oracle/
│       ├── Cargo.toml
│       ├── src/lib.rs             # update_cpi()
│       └── idl/oracle.json
├── sdk/
│   ├── blackbook_sdk.js           # Existing JS SDK (upgraded for Solana tx format)
│   └── package.json
└── tests/
    ├── svm_integration_tests.rs   # NEW: End-to-end SVM execution tests
    ├── solana_rpc_tests.rs        # NEW: RPC compatibility tests
    ├── anchor_vault_tests.rs      # NEW: Vault program integration tests
    ├── onekey_signing_tests.rs    # NEW: SSS + OneKey hybrid signing tests
    └── ... (existing tests)
```

---

## Part 8: Success Criteria

| Criterion | How to Verify |
|---|---|
| OneKey connects via Custom RPC | Add `http://your-server:8899` in OneKey → shows $BB balance |
| Token transfers via OneKey | Send $BB from OneKey → arrives in recipient's wallet |
| Vault deposit via OneKey | "Lock 100 USDT" → OneKey shows "Deposit 100 USDT to Tier-1 Vault" (IDL decoded) |
| FROST + OneKey hybrid signing | SSS wallet creates tx → OneKey hardware approves → tx executes |
| 50k TPS sustained | Load test: 50k SVM transactions/second for 60 seconds, <1% failure |
| Genesis hash uniqueness | OneKey identifies BB as separate network from Solana mainnet |
| Anchor IDL transparency | Block explorer shows decoded instruction data for all vault operations |
| Backward compat | Existing REST API on :8080 still serves balance/transfer for L2 |

---

## Part 9: Quick-Reference — What to Build First

If you want to see something working in the shortest time:

1. **Week 1-2:** Add `solana-sdk` + `solana-rbpf` to Cargo.toml. Create `SvmAccountsDB` in storage. Create `svm_runtime.rs` that can execute a single System Program `Transfer` instruction against ReDB.

2. **Week 3:** Wire it into `produce_block()`. One compile, one test: a Solana-format transfer works end-to-end through your PoH → Sealevel → rBPF → ReDB pipeline.

3. **Week 5:** Stand up `solana_rpc.rs` with `getBalance` + `sendTransaction`. Point OneKey at it. See your balance.

That's your **proof of concept** in ~5 weeks. Everything after that is expanding the surface area (SPL tokens, Anchor vaults, OneKey signing).
