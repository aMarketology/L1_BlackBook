# BlackBook L1 — Production Blockchain Roadmap
## PoH · Sealevel · Turbine · Full Integration Plan

**Goal:** Transform BlackBook from a working prototype into a production-grade PoH blockchain that competes with Solana. Every transaction lands in a real block, every block is cryptographically chained, and the full Solana-class pipeline (Gulf Stream → Sealevel → Turbine → Tower BFT) is wired end-to-end.

**Deployment Target:** Digital Ocean (via Railway or direct droplet)

---

## Current State — As of 2026-02-24

| Subsystem | Status | What Works | Notes |
|-----------|--------|------------|-------|
| **PoH Clock** | ✅ FULLY WIRED | SHA-256 hash chain ticks every 9ms, 64 ticks/slot, 600ms slots | — |
| **SVM Engine** | ✅ FULLY WIRED | Account storage, system transfers, blockhash queue, SPL tokens, CU enforcement | — |
| **JSON-RPC** | ✅ FULLY WIRED | 28 Solana-compatible methods on port 8899 incl. `getBlock`, `getBlocks`, `getBlockProduction` | Missing WebSockets |
| **Gulf Stream** | ✅ FULLY WIRED | Tx forwarding, priority sorting, leader-aware caching | — |
| **Storage (ReDB)** | ✅ FULLY WIRED | 20+ tables, ACID writes, DashMap cache, `store_block()`/`load_block()` | — |
| **Wallet + SSS** | ✅ FULLY WIRED | BIP-39, Shamir 2/3, SSS-authenticated transfers, SVM receipts, PIN security | — |
| **Block Production Loop** | ✅ FULLY WIRED | `tokio::spawn` produces blocks every 600ms | Writer mode only |
| **SSS Transfers → Blocks** | ✅ FULLY WIRED | Every wallet transfer recorded via `record_executed_transaction()` | Appears in PoH blocks |
| **Faucet Mints → Blocks** | ✅ FULLY WIRED | Faucet credits recorded in blocks | Appears in PoH blocks |
| **Slot Counter** | ✅ UNIFIED | Single canonical slot from BlockProducer drives SVM + PoH | No more dual drift |
| **ParallelScheduler** | ✅ SVM PATH | `with_svm()` called — uses lamport transfers not f64 | Sealevel runs real SVM |
| **Sealevel Loop** | ✅ ROUTES TO BLOCKS | Gulf Stream txs go through `submit_transaction()` → BlockProducer | Writer mode only |
| **Pipeline Commit Stage** | ✅ WIRED | `commit_rx` read, committed packets recorded in blocks | Full 4-stage pipeline |
| **Finality Tracker** | ✅ WIRED | `update_confirmations()` called after each block | Txns advance to Finalized after 31 slots |
| **Tower BFT** | ✅ WIRED | Instantiated, self-votes after every block, `GET /consensus/tower` endpoint live | Single-validator mode |
| **Leader Schedule** | ✅ EPOCH ROTATION | Rotates at epoch boundaries, logs transitions | Ready for multi-validator |
| **Turbine Shredding** | ✅ WIRED | Every block shredded into data + FEC shreds post-production | `shred_count` in block response |
| **Turbine Propagation** | ✅ WIRED | `TurbinePropagator` instantiated, tree computed, `GET /turbine/status` live | No P2P layer yet |
| **CLI + Node Mode** | ✅ WIRED | `--mode writer\|reader`, `--identity`, `--grpc-port`, `--http-port`, `--rpc-port` | clap 4 |
| **1W/100R Relay (gRPC)** | ✅ WIRED | Writer streams blocks via `ValidatorRelay` gRPC service, reader verifies + stores | Phase 9 |
| **Startup Recovery** | ✅ PARTIAL | `restore_chain_state()` restores slot + hash from ReDB on startup | Phase 7.2 partial |
| **Build** | ✅ CLEAN | 0 errors, 0 warnings | Dead code removed or suppressed with rationale |
| **getBlock / getBlocks** | ✅ IMPLEMENTED | `getBlock(slot)`, `getBlocks(start,end)`, `getBlockProduction` all wired to BlockProducer | Phase 5 complete |
| **WebSocket Subscriptions** | ❌ NOT IMPLEMENTED | — | Phase 5 stretch |
| **Block Explorer UI** | ❌ NOT IMPLEMENTED | — | Phase 6 |
| **Graceful Shutdown** | ❌ PARTIAL | `flush_final_block()` method exists, shutdown section stub | Phase 7.1 |

**Bottom line:** Phases 1–5.2 + Phase 9 (1-Writer/100-Reader) complete. CLI parses `--mode writer|reader`. Writer produces blocks, streams via gRPC relay. Reader catches up, subscribes to live stream, verifies hash chain, stores to local ReDB. Build is clean (0 errors, 0 warnings).

---

## Phase 1: BLOCK PRODUCTION (Critical Path)
> *"If it's not in a block, it didn't happen"*

### Milestone 1.1 — Spawn Block Production Loop
**Files:** `src/main.rs`
**What:** Add a `tokio::spawn` after `BlockProducer::new()` that calls `produce_block()` every 600ms (matching slot interval).
**Why:** Without this, BlockProducer is dead code. This is THE critical missing piece.
**Details:**
- Spawn right after line ~1515 where `block_producer` is created
- Use `tokio::time::interval(600ms)` matching the slot ticker
- Handle `Err` from `produce_block()` gracefully (not leader, already produced = skip, not panic)
- Log blocks with tx_count > 0 (suppress empty block spam)

**Acceptance:** After restart, `GET /poh/block/latest` returns a real block with a valid slot, hash, and timestamp. Blocks accumulate in ReDB.

### Milestone 1.2 — Route SSS Transfers Into Blocks
**Files:** `src/wallet_unified/handlers.rs`, `src/main.rs` (AppState)
**What:** After `transfer_with_receipt()` succeeds, call `block_producer.record_executed_transaction()` to package the tx into the next block.
**Why:** Currently, SSS transfers go to ReDB but never appear in any PoH block.
**Details:**
- Add `block_producer: Arc<BlockProducer>` to `UnifiedWalletState`
- Thread it through from `AppState` during wallet state construction (~line 1590)
- In `transfer_with_sss()`, after successful transfer, build a `Transaction` with `TxData::TransferBb` and call `record_executed_transaction()`
- The transaction is already executed — this just records it for PoH ordering

**Acceptance:** After sending BB via the wallet UI, `GET /poh/block/{slot}` shows the transfer in the block's transaction list.

### Milestone 1.3 — Route Faucet Mints Into Blocks
**Files:** `src/main.rs`
**What:** After `blockchain.credit()` succeeds in `faucet_handler`, build a mint `Transaction` and call `block_producer.record_executed_transaction()`.
**Why:** Faucet mints are the most common operation — they must be in blocks.
**Details:**
- Build a `Transaction` with `TxData::DepositUsdt` (or add a new `TxData::Mint` variant)
- Use `from: "SYSTEM_FAUCET"`, `hash: uuid`
- Record via `state.block_producer.record_executed_transaction()`

**Acceptance:** After minting via faucet, the mint tx appears in the next block.

### Milestone 1.4 — Unify Slot Counter
**Files:** `src/main.rs`, `runtime/poh_service.rs`
**What:** Remove the separate slot ticker. Let `produce_block()` be the single authority that advances the shared `current_slot`. PoH clock's internal slot counter syncs from the shared atomic.
**Why:** Currently two things advance slots independently — the slot ticker (every 600ms) and the PoH clock (on its own schedule). This causes drift.
**Details:**
- BlockProducer's `produce_block()` already stores to `last_produced_slot`
- The 600ms slot ticker in main.rs should remain (for SVM blockhash advancement) but read from the PoH clock's canonical slot, not independently increment
- Sync PoH service's `current_slot` with the shared `AtomicU64`

**Acceptance:** `GET /poh/status` slot == `GET /health` slot == latest block slot ± 1.

---

## Phase 2: SEALEVEL EXECUTION (Parallel Transaction Processing)
> *"Execute 50,000 transactions per second or go home"*

### Milestone 2.1 — Wire ParallelScheduler to SVM
**Files:** `src/main.rs`, `runtime/core.rs`
**What:** Call `parallel_scheduler.with_svm(svm_accounts)` so the Sealevel loop uses actual SVM lamport transfers instead of the legacy f64 balance path.
**Why:** Without this, the parallel scheduler's SVM branch is dead code. All concurrent execution uses the slower f64 DashMap path.
**Details:**
- After `ParallelScheduler::new()` at ~line 1510, call `.with_svm(blockchain.svm_accounts.clone())`
- Verify that `execute_batch_with_locks()` takes the SVM path when `svm_db` is Some
- Test with concurrent transfers to verify no double-spend

**Acceptance:** Server logs show "SVM transfer" instead of "legacy transfer" during Sealevel execution.

### Milestone 2.2 — Sealevel Loop Routes Through BlockProducer
**Files:** `src/main.rs`
**What:** Instead of `blockchain.transfer()`, the Sealevel loop calls `block_producer.submit_transaction()` for Gulf Stream txs, letting `produce_block()` execute them.
**Why:** Gulf Stream transactions currently bypass blocks entirely.
**Details:**
- Change the inner loop: instead of `sealevel_bc.transfer()`, build a `Transaction` and call `block_producer.submit_transaction(tx)`
- `produce_block()` will execute these pending txs in its next block
- Remove the direct `blockchain.transfer()` call from the Sealevel loop
- Keep `sealevel_fin.record_inclusion()` — but call it after block production confirms the tx

**Acceptance:** Gulf Stream-submitted transactions appear in blocks alongside HTTP-handler transactions.

### Milestone 2.3 — Connect Transaction Pipeline Commit Stage
**Files:** `src/main.rs`
**What:** Actually read from `commit_rx` instead of dropping it. Route committed packets into the BlockProducer.
**Why:** The 4-stage pipeline (Fetch→Verify→Execute→Commit) runs but its output is discarded.
**Details:**
- Store `commit_rx` (don't prefix with `_`)
- Spawn a task that reads from `commit_rx` and calls `block_producer.record_executed_transaction()` for each committed packet
- This completes the pipeline: submit → verify sigs → execute → commit → block inclusion

**Acceptance:** Pipeline commit completions show up in blocks.

---

## Phase 3: FINALITY & CONSENSUS (Tower BFT)
> *"31 confirmations = mathematically irreversible"*

### Milestone 3.1 — Wire Finality Tracker to Block Production
**Files:** `src/poh_blockchain.rs`, `src/main.rs`
**What:** After each block is produced, call `finality_tracker.update_confirmations(current_slot)` for all transactions in previous blocks.
**Why:** Currently `update_confirmations()` is never called — transactions never reach "Finalized" status.
**Details:**
- In `produce_block()`, after storing the block, iterate previous block transactions and bump confirmations
- Or spawn a separate confirmation-advancement task that runs after each block
- `CONFIRMATIONS_REQUIRED = 31` (already defined) — after 31 blocks, a tx is finalized

**Acceptance:** `GET /poh/tx/{id}/status` transitions from `Processing` → `Finalized` after 31 slots (~18.6 seconds).

### Milestone 3.2 — Instantiate Tower BFT (Single-Validator Mode)
**Files:** `src/main.rs`, `runtime/consensus.rs`
**What:** Create a `TowerBFT` instance and have the block producer self-vote after producing each block.
**Why:** Even in single-validator mode, Tower BFT provides the mathematical guarantee of finality via exponential lockouts.
**Details:**
- Instantiate `TowerBFT::new()` in main.rs alongside other consensus infra
- After `produce_block()`, cast a vote: `tower.vote(slot, block_hash)`
- Log vote stack depth for observability
- Add `GET /consensus/tower` endpoint exposing vote tower state

**Acceptance:** Tower vote stack accumulates after each block. Lockout doubles per confirmation level.

### Milestone 3.3 — Leader Schedule Epoch Rotation
**Files:** `runtime/consensus.rs`, `src/poh_blockchain.rs`
**What:** When `current_slot % SLOTS_PER_EPOCH == 0`, regenerate the leader schedule for the new epoch.
**Why:** Currently the leader schedule is generated once for epoch 0 and never rotates.
**Details:**
- In `produce_block()`, check for epoch transition
- Call `leader_schedule.generate_schedule(new_epoch, SLOTS_PER_EPOCH)`
- For single-validator, this changes nothing functionally (same leader), but proves the rotation mechanism works
- Log epoch transitions with ceremony: `"📅 Epoch {n}: leader schedule rotated for {SLOTS_PER_EPOCH} slots"`

**Acceptance:** Server logs show epoch transitions. `GET /poh/status` reflects correct epoch number.

---

## Phase 4: TURBINE BLOCK PROPAGATION
> *"Shred it, FEC it, tree it"*

### Milestone 4.1 — Wire Turbine Shredding to Block Production
**Files:** `src/poh_blockchain.rs`
**What:** After `produce_block()`, shred the block into Turbine shreds using the existing `TurbineShredder`.
**Why:** Turbine shreds are the unit of block propagation. Even without P2P, this proves blocks are shred-compatible.
**Details:**
- After block storage in `produce_block()`, call `TurbineShredder::shred_block(&block)`
- Store shred count + FEC recovery count in the block's metadata
- Log: `"🌊 Turbine: Block {slot} shredded into {n} data + {m} FEC shreds"`
- Verify `reassemble_block()` can reconstruct from shreds (round-trip test)

**Acceptance:** Each produced block generates shreds. `GET /poh/block/{slot}` includes shred_count in response.

### Milestone 4.2 — Turbine Propagation Tree
**Files:** `src/poh_blockchain.rs`, `src/main.rs`
**What:** Instantiate `TurbinePropagator` with the current validator set (just 1 for MVP) and compute propagation trees.
**Why:** Demonstrates the O(log n) propagation structure even with a single validator.
**Details:**
- Create `TurbinePropagator::new(fanout=200)` (Solana default)
- After shredding, compute tree: `propagator.calculate_tree(&validators, source_validator)`
- Log tree structure for observability
- Add `GET /turbine/status` endpoint with shred stats

**Acceptance:** Turbine status endpoint returns valid propagation tree structure and shred statistics.

---

## Phase 5: RPC COMPLETENESS (Wallet Compatibility)
> *"If Phantom can't connect, it's not a blockchain"*

### Milestone 5.1 — `getBlock` RPC Method
**Files:** `src/solana_rpc/mod.rs`
**What:** Implement `getBlock(slot)` returning Solana-compatible block structure with transactions.
**Why:** Block explorers and wallets use this to display transaction history.
**Details:**
- Read from `blockchain.load_block(slot)`
- Transform `FinalizedBlock` → Solana `UiConfirmedBlock` JSON format
- Include `transactions`, `rewards`, `blockTime`, `blockHeight`, `parentSlot`

**Acceptance:** `curl -X POST -d '{"jsonrpc":"2.0","method":"getBlock","params":[SLOT]}' :8899` returns a valid block.

### Milestone 5.2 — `getBlocks` + `getBlockProduction` RPC Methods
**Files:** `src/solana_rpc/mod.rs`
**What:** Range queries for blocks and block production statistics.
**Details:**
- `getBlocks(startSlot, endSlot)` → array of slot numbers that have blocks
- `getBlockProduction` → leader slot assignments vs produced slots

### Milestone 5.3 — WebSocket Subscriptions (Stretch)
**Files:** `src/solana_rpc/mod.rs` (new ws module)
**What:** Implement `accountSubscribe`, `slotSubscribe`, `signatureSubscribe`.
**Why:** Real-time updates for wallets without polling.
**Details:**
- Use tokio broadcast channels
- `slotSubscribe`: emit on each slot tick
- `signatureSubscribe`: emit when tx reaches confirmation threshold
- `accountSubscribe`: emit on balance change

**Acceptance:** Phantom/Nightly can subscribe to account changes in real-time.

---

## Phase 6: BLOCK EXPLORER UI
> *"See every block, every transaction, every hash"*

### Milestone 6.1 — Explorer Tab in Wallet Page
**Files:** `src/wallet_page.rs`
**What:** Add a 5th tab "Explorer" showing recent blocks, slot progression, and transaction details.
**Details:**
- Real-time block feed (poll `/poh/block/latest` every 2s)
- Block detail view: slot, hash, PoH hash, tx count, leader
- Transaction list within block
- Click tx → show TransferBb details (from, to, amount)
- Slot progress bar (time within current 600ms slot)
- Epoch progress bar
- PoH hash visualization (last 8 chars cycling)

### Milestone 6.2 — Network Stats Dashboard
**Files:** `src/wallet_page.rs`
**What:** Live TPS counter, block production rate, finality gauge.
**Details:**
- TPS: count transactions across last 10 blocks / time span
- Block rate: blocks per second (target: 1.67)
- Finality: average time from submission to 31 confirmations
- Validator info: leader identity, stake, uptime

**Acceptance:** Explorer tab shows real blocks with real transactions flowing in real-time.

---

## Phase 7: HARDENING FOR PRODUCTION
> *"If it crashes once, it's not production"*

### Milestone 7.1 — Graceful Shutdown & State Flush
**Files:** `src/main.rs`
**What:** On SIGTERM/SIGINT, flush all in-flight blocks to ReDB, drain pending transactions, close cleanly.
**Details:**
- Block producer writes final block before exit
- SVM flushes dirty accounts
- ReDB compacts
- Log: `"✅ Clean shutdown: {n} blocks, {m} accounts flushed"`

### Milestone 7.2 — Startup Recovery from ReDB
**Files:** `src/main.rs`, `src/poh_blockchain.rs`
**What:** On startup, load the latest block from ReDB, set `current_slot` to `latest_slot + 1`, restore block hash chain continuity.
**Why:** Currently every restart starts from slot 0 with a fresh genesis. That's not a blockchain.
**Details:**
- `blockchain.latest_block_slot()` → set initial slot
- Load last block hash → set `BlockProducer.latest_hash`
- Resume PoH from last known sequence number
- Load account balances from ReDB into DashMap cache (already done)
- Log: `"🔄 Resumed from slot {n}, block hash: {hash}…"`

**Acceptance:** Kill server, restart, `GET /poh/block/latest` returns the same block as before shutdown.

### Milestone 7.3 — Health Checks & Monitoring
**Files:** `src/main.rs`
**What:** Enhanced `/health` endpoint with production readiness checks.
**Details:**
- Block production: last block age < 5s (if stale → unhealthy)
- ReDB: write latency < 100ms
- PoH: hash rate within 10% of target
- Memory: DashMap size, SVM account count
- Expose as Prometheus metrics (`/metrics` endpoint)

### Milestone 7.4 — Rate Limiting & DoS Protection
**Files:** `src/main.rs`
**What:** Production-grade request throttling.
**Details:**
- Per-IP rate limiting on all POST endpoints
- Priority fee market for tx ordering (already exists in `LocalizedFeeMarket`)
- Circuit breaker for cascade failure protection (exists, needs wiring)
- NetworkThrottler bandwidth limits (exists, needs wiring)

---

## Phase 8: DEPLOYMENT (Digital Ocean)
> *"Ship it"*

### Milestone 8.1 — Docker Image Optimization
**Files:** `Dockerfile`
**What:** Multi-stage build producing a minimal production image.
**Details:**
- Stage 1: `rust:1.82-slim` builder with cargo build --release
- Stage 2: `debian:bookworm-slim` runtime (< 100MB)
- Copy binary + static assets only
- Health check: `HEALTHCHECK CMD curl -f http://localhost:8080/health`
- Env vars: `SERVER_MASTER_KEY`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`

### Milestone 8.2 — Digital Ocean Droplet / App Platform
**What:** Deploy to DO with persistent volume for ReDB.
**Details:**
- Minimum: 2 vCPU, 4GB RAM (PoH hashing is CPU-bound)
- Persistent volume mounted at `/data/blockchain.redb`
- Environment variables via DO secrets
- Custom domain + TLS via DO load balancer
- Ports: 8080 (HTTP), 8899 (JSON-RPC)

### Milestone 8.3 — Railway Alternative (Already Configured)
**Files:** `railway.toml`
**What:** Railway deployment as backup/staging.
**Details:**
- `railway.toml` already exists — verify it works with current binary
- Persistent storage for ReDB
- Auto-deploy on git push

### Milestone 8.4 — DNS + TLS + Monitoring
**What:** Production domain, HTTPS, uptime monitoring.
**Details:**
- Domain: e.g., `l1.blackbook.io` or `rpc.blackbook.network`
- TLS: Let's Encrypt via DO or Cloudflare
- Uptime: StatusPage or BetterUptime
- Alerts: Slack/Discord webhook on downtime

---

## Phase 9: 1-WRITER / 100-READER ARCHITECTURE
> *"One node produces, 100 nodes verify — trustless at scale"*

### Milestone 9.1 — CLI + Node Mode
**Files:** `Cargo.toml`, `src/main.rs`
**What:** Add `clap` CLI parsing with `--mode writer|reader`, `--identity`, `--grpc-port`, `--http-port`, `--rpc-port`, `--writer-addr`.
**Why:** Nodes must be configurable per deployment role. Writer produces blocks; Reader consumes them.
**Status:** ✅ COMPLETE

### Milestone 9.2 — gRPC Proto (ValidatorRelay)
**Files:** `proto/validator_relay.proto`, `build.rs`
**What:** Define `ValidatorRelay` gRPC service with `SubscribeBlocks` (server-streaming), `CatchupBlocks`, `ForwardTransaction`, `GetStatus`.
**Why:** gRPC streaming is the transport layer between Writer and Reader nodes.
**Status:** ✅ COMPLETE

### Milestone 9.3 — Writer Relay Service
**Files:** `src/relay/mod.rs`
**What:** `WriterRelayService` wraps a `tokio::broadcast::Sender<FinalizedBlock>`. Block production loop calls `send(block)` after each produced block. Readers subscribe via gRPC.
**Why:** Writer must push blocks to all connected Readers in real-time.
**Details:**
- `SubscribeBlocks`: creates a `broadcast::Receiver`, yields blocks as server-streaming responses
- `CatchupBlocks`: reads historical blocks from BlockProducer cache + ReDB
- `ForwardTransaction`: readers forward user txs to writer's mempool
- Broadcast buffer: 256 blocks — lagging readers must do catchup
**Status:** ✅ COMPLETE

### Milestone 9.4 — Reader Node Client
**Files:** `src/reader/mod.rs`
**What:** `ReaderNode` connects to Writer gRPC, catches up missed blocks, subscribes to live stream, verifies each block (`verify_block()`), stores to local ReDB, updates DashMap cache.
**Why:** Readers serve RPC from local verified storage — no trust required in the writer beyond cryptographic verification.
**Details:**
- Automatic reconnect on disconnect (3s delay)
- `verify_block()`: checks hash chain, PoH entries, tx count
- `apply_block_balances()`: updates local DashMap cache from block transactions
- Reader does NOT re-execute SVM — trusts writer's state after hash verification
**Status:** ✅ COMPLETE

### Milestone 9.5 — main() Mode Branching
**Files:** `src/main.rs`
**What:** `if config.mode == Writer` runs block production + Sealevel + relay gRPC server. `else` runs ReaderNode sync task. Both share: blockchain storage, HTTP server, JSON-RPC.
**Why:** Single binary, two roles.
**Status:** ✅ COMPLETE

### Usage
```bash
# Writer node (default — produces blocks, serves relay on :50051)
cargo run -- --mode writer --identity genesis_validator

# Reader node (connects to writer, verifies blocks, serves RPC on :8899)
cargo run -- --mode reader --identity reader_1 --writer-addr http://127.0.0.1:50051 --http-port 8081 --rpc-port 9899

# Check writer status from reader
grpcurl -plaintext 127.0.0.1:50051 validator_relay.ValidatorRelay/GetStatus
```

---

## Execution Order (Priority Sequence)

```
WEEK 1: Foundation (Phases 1-2)
├── 1.1  Spawn block production loop          ← THE critical fix
├── 1.2  Route SSS transfers into blocks
├── 1.3  Route faucet mints into blocks
├── 1.4  Unify slot counter
├── 2.1  Wire ParallelScheduler to SVM
└── 2.2  Sealevel loop → BlockProducer

WEEK 2: Consensus + Polish (Phases 3-4)
├── 3.1  Finality tracker wiring
├── 3.2  Tower BFT single-validator
├── 3.3  Leader schedule epoch rotation
├── 4.1  Turbine shredding
├── 4.2  Turbine propagation tree
└── 2.3  Pipeline commit stage

WEEK 3: Explorer + RPC (Phases 5-6)
├── 5.1  getBlock RPC method
├── 5.2  getBlocks + getBlockProduction
├── 6.1  Explorer tab in wallet page
└── 6.2  Network stats dashboard

WEEK 4: Production Hardening + Deploy (Phases 7-8)
├── 7.1  Graceful shutdown
├── 7.2  Startup recovery from ReDB
├── 7.3  Health checks
├── 7.4  Rate limiting
├── 8.1  Docker optimization
├── 8.2  Digital Ocean deploy
├── 8.3  Railway staging
└── 8.4  DNS + TLS + monitoring

STRETCH: Phase 5.3 (WebSocket subscriptions)
```

---

## Architecture After Completion

```
                    ┌─────────────────────────────────────────────┐
                    │              CLIENT (Wallet UI)              │
                    │  /wallet (HTML) │ Phantom │ SDK │ curl      │
                    └────────┬──────────────────┬─────────────────┘
                             │ HTTP :8080       │ JSON-RPC :8899
                    ┌────────▼──────────────────▼─────────────────┐
                    │              AXUM SERVER                      │
                    │  Handlers   │  Solana RPC  │  WebSocket      │
                    └────────┬──────────┬────────┬────────────────┘
                             │          │        │
              ┌──────────────▼──────────▼────────▼────────────────┐
              │                 GULF STREAM                         │
              │  Transaction forwarding → leader-aware priority Q  │
              └──────────────────────┬────────────────────────────┘
                                     │
              ┌──────────────────────▼────────────────────────────┐
              │               TRANSACTION PIPELINE                 │
              │  Fetch → Verify Sigs → Execute → Commit           │
              └──────────────────────┬────────────────────────────┘
                                     │
              ┌──────────────────────▼────────────────────────────┐
              │                 BLOCK PRODUCER                     │
              │  collect pending txs + pre-executed txs            │
              │  PoH snapshot → execute → build FinalizedBlock     │
              │  persist to ReDB → shred via Turbine               │
              └────┬─────────────┬───────────────┬────────────────┘
                   │             │               │
        ┌──────────▼──┐  ┌──────▼──────┐  ┌─────▼────────┐
        │  PoH CLOCK  │  │  SEALEVEL   │  │   TURBINE    │
        │ SHA-256     │  │  Parallel   │  │  Shred+FEC   │
        │ 12.5K/tick  │  │  Scheduler  │  │  Propagation │
        │ 64 tick/slot│  │  + SVM      │  │  Tree        │
        └─────────────┘  └──────┬──────┘  └──────────────┘
                                │
              ┌─────────────────▼─────────────────────────────────┐
              │                    SVM ENGINE                       │
              │  AccountsDB (DashMap) → System Transfers            │
              │  SPL Token → Blockhash Queue → Replay Protection   │
              └─────────────────┬─────────────────────────────────┘
                                │
              ┌─────────────────▼─────────────────────────────────┐
              │                STORAGE (ReDB + DashMap)             │
              │  BLOCKS │ ACCOUNTS │ TRANSACTIONS │ SVM_TX_LOG     │
              │  WALLET_SHARES │ FROST_SHARE_B │ METADATA          │
              └───────────────────────────────────────────────────┘
              
              ┌───────────────────────────────────────────────────┐
              │              TOWER BFT CONSENSUS                   │
              │  Vote Towers → Exponential Lockout → Fork Choice  │
              │  31 confirmations = Finalized                      │
              └───────────────────────────────────────────────────┘
```

---

## Key Metrics (Production Targets)

| Metric | Target | How |
|--------|--------|-----|
| Block time | 600ms | PoH clock + BlockProducer loop |
| TPS (theoretical) | 50,000+ | Sealevel parallel execution |
| TPS (realistic single-node) | 1,000-5,000 | Depends on ReDB write throughput |
| Time to finality | ~18.6s | 31 confirmations × 600ms |
| Block size | Up to 64 txs/block | `MAX_TXS_PER_BLOCK` constant |
| PoH hash rate | 800K hashes/sec | 12,500 hashes × 64 ticks/slot ÷ 0.6s |
| Storage per block | ~2-10 KB | JSON-serialized FinalizedBlock |
| Slots per epoch | 432,000 | ~3 days at 600ms |

---

## File Map (Where Everything Lives)

| File | Responsibility |
|------|---------------|
| `src/main.rs` | Server startup, route wiring, task spawning, Sealevel loop, mode branching |
| `src/poh_blockchain.rs` | BlockProducer, FinalizedBlock, Turbine, Merkle trees, Finality, verify_block |
| `src/storage/mod.rs` | ReDB tables, DashMap cache, balance R/W, block persistence |
| `src/relay/mod.rs` | Writer gRPC relay: SubscribeBlocks, CatchupBlocks, ForwardTransaction |
| `src/reader/mod.rs` | Reader node: catchup, live subscribe, verify, store to local ReDB |
| `proto/validator_relay.proto` | ValidatorRelay gRPC service definition |
| `proto/settlement.proto` | L1Settlement gRPC service (L1↔L2 casino) |
| `runtime/poh_service.rs` | PoH clock, tick/hash chain, TransactionPipeline |
| `runtime/consensus.rs` | Gulf Stream, Leader Schedule, Tower BFT |
| `runtime/core.rs` | ParallelScheduler, AccountLockManager, batch execution |
| `src/svm/` | SVM engine: accounts, runtime, SPL tokens, types |
| `src/solana_rpc/mod.rs` | Solana-compatible JSON-RPC server |
| `src/wallet_unified/handlers.rs` | SSS wallet handlers (create, transfer, shard management) |
| `src/wallet_page.rs` | Embedded wallet UI (HTML/CSS/JS) |
| `protocol/blockchain.rs` | Transaction, TxData enum, L1Event types |

---

## Status Tracking

- [x] **Phase 1.1** — Spawn block production loop
- [x] **Phase 1.2** — Route SSS transfers into blocks
- [x] **Phase 1.3** — Route faucet mints into blocks
- [x] **Phase 1.4** — Unify slot counter
- [x] **Phase 2.1** — Wire ParallelScheduler to SVM
- [x] **Phase 2.2** — Sealevel loop → BlockProducer
- [x] **Phase 2.3** — Pipeline commit stage
- [x] **Phase 3.1** — Finality tracker wiring
- [x] **Phase 3.2** — Tower BFT single-validator
- [x] **Phase 3.3** — Leader schedule epoch rotation
- [x] **Phase 4.1** — Turbine shredding
- [x] **Phase 4.2** — Turbine propagation tree
- [x] **Phase 5.1** — getBlock RPC method
- [x] **Phase 5.2** — getBlocks + getBlockProduction
- [ ] **Phase 5.3** — WebSocket subscriptions (stretch)
- [ ] **Phase 6.1** — Explorer tab in wallet page
- [ ] **Phase 6.2** — Network stats dashboard
- [ ] **Phase 7.1** — Graceful shutdown
- [x] **Phase 7.2** — Startup recovery from ReDB (partial: slot + hash restored)
- [ ] **Phase 7.3** — Health checks & monitoring
- [ ] **Phase 7.4** — Rate limiting & DoS protection
- [ ] **Phase 8.1** — Docker image optimization
- [ ] **Phase 8.2** — Digital Ocean deploy
- [ ] **Phase 8.3** — Railway staging
- [ ] **Phase 8.4** — DNS + TLS + monitoring
- [x] **Phase 9.1** — CLI + Node Mode (`--mode writer|reader`, clap 4)
- [x] **Phase 9.2** — gRPC proto (`validator_relay.proto`: SubscribeBlocks, CatchupBlocks, ForwardTransaction)
- [x] **Phase 9.3** — Writer Relay Service (`src/relay/mod.rs`: broadcast blocks to readers)
- [x] **Phase 9.4** — Reader Node Client (`src/reader/mod.rs`: catchup + live subscribe + verify + store)
- [x] **Phase 9.5** — main() mode branching (writer runs production+relay, reader runs sync+RPC)

---

*Last updated: 2026-02-24 — Phases 1–5.2 + 9.1–9.5 complete, 0 errors, 0 warnings. 1-Writer/100-Reader architecture wired: CLI `--mode writer|reader`, gRPC block relay, reader catchup+verify+store. settlement.proto populated. Quick fixes applied.*
