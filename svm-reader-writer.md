# BlackBook L1 — SVM & Reader/Writer Architecture

> Last updated: 2025-06-24

---

## 1. Where the Blockchain Is At

BlackBook L1 is a **production-grade, single-binary Rust blockchain** that runs its own Proof-of-History clock, executes transactions through a native Solana Virtual Machine, stores state in ACID-safe ReDB, and exposes 28 Solana-compatible JSON-RPC methods. It is not a fork of Solana — it is a **clean-room re-implementation** of Solana's core architecture, purpose-built for low-latency micro-transaction workloads.

### Completed Phases

| Phase | Milestone | Status |
|-------|-----------|--------|
| 1 | PoH block production (SHA-256 hash chain, 600 ms slots) | ✅ Complete |
| 2A | SVM accounts database + read RPCs (14 methods) | ✅ Complete |
| 2B | SVM transaction execution + write RPCs (14 methods) | ✅ Complete |
| 3 | Solana JSON-RPC compatibility (28 total methods) | ✅ Complete |
| 4 | Tower BFT consensus + vote-based finality | ✅ Complete |
| 5.1 | Turbine block propagation (shreds, erasure coding, fanout) | ✅ Complete |
| 5.2 | Gulf Stream transaction forwarding to upcoming leaders | ✅ Complete |
| 9 | 1-Writer / 100-Reader multi-node architecture (gRPC relay) | ✅ Complete |

### What This Means

A single Writer node produces blocks at 600 ms intervals while up to 100 Reader nodes subscribe to its block stream over gRPC, independently verify every block, and serve their own RPC endpoints. The result is a horizontally-scalable read layer backed by a single authoritative writer — the same pattern as a replicated database, but with cryptographic proof of ordering (PoH) and vote-based finality (Tower BFT).

---

## 2. Feature Inventory

### 2.1 Proof of History (PoH)

A continuous SHA-256 hash chain that acts as the blockchain's clock:

| Parameter | Value |
|-----------|-------|
| Slot duration | 600 ms |
| Ticks per slot | 64 |
| Hashes per tick | 12,500 |
| Hashes per slot | 800,000 |
| Max transactions per block | 10,000 |
| Theoretical max TPS | 16,667 |

Every transaction submitted to the Writer is **mixed into the PoH stream**, giving it a cryptographic timestamp that any node can verify without trusting the producer. PoH entries (`hash`, `num_hashes`, `transactions`) are embedded in every finalized block.

### 2.2 Solana Virtual Machine (SVM)

The SVM is BlackBook's execution engine. It is built from real Solana crates (`solana-sdk 2.1`, `solana-program 2.1`, `solana-program-runtime 2.1`, `solana-system-program 2.1`) and uses native Solana types — `Pubkey`, `AccountSharedData`, `Hash`, `Lamports` — throughout the entire money path.

Core components:

| Component | Role |
|-----------|------|
| **`BlackBookSVM`** | Execution engine. Manages blockhash queue, intra-block dedup, slot advancement, end-of-block flush. |
| **`SvmAccountsDB`** | Two-layer account store: DashMap (hot) + ReDB (durable). Lock-free concurrent reads, atomic block flush. |
| **`SplTokenEngine`** | Native Rust SPL-Token implementation (no rBPF). Binary-compatible mint (82 bytes) and token-account (165 bytes) layouts. |
| **`BlockhashQueue`** | Ring buffer of 150 recent slot hashes (mirrors Solana mainnet). O(1) lookup. |

Key invariants:
- **All balances are `u64` lamports** — no floating-point anywhere in the money path.
- 1 BB = 1,000,000,000 lamports (`LAMPORTS_PER_BB = 10^9`).
- Rent is always 0 (`rent_epoch = u64::MAX`). Fees are 0 in Phase 1.
- Max compute units per transaction: 1,400,000.

ReDB table namespaces:
- `svm_accounts` — Pubkey → `StoredAccount` (Borsh)
- `svm_programs` — ProgramId → ELF bytes
- `blockhash_queue` — Slot → Hash
- `svm_signatures` — Signature → Slot (replay protection)
- `svm_tx_log` — Signature → `StoredTransactionResult` (confirmed tx records)
- `svm_addr_sigs` — `addr:signature` composite → Slot (address index)

### 2.3 Sealevel (Parallel Execution)

Named after Solana's parallel runtime, BlackBook's Sealevel path processes non-overlapping transactions concurrently using Rayon thread pools. The optimal batch size is 256 transactions; the maximum is 1,024. Transactions that touch the same accounts within a batch are serialized; independent transactions execute in parallel.

### 2.4 Turbine (Block Propagation)

Block data is split into **shreds** (1,232-byte chunks matching UDP MTU) with Reed-Solomon erasure coding:
- 32 data shreds + 32 coding shreds = 50% redundancy per FEC set
- Tree-based fanout of 200 per level → 40,000 nodes reached in 2 hops
- Each shred carries a Merkle proof for independent verification

### 2.5 Gulf Stream (Transaction Forwarding)

Transactions are forwarded to the next 8 upcoming leaders before their slot arrives, pre-filling their mempool:
- Priority queue per leader (amount-based sorting)
- Dedup via `seen` set (tx_id → slot)
- Background expiry: transactions older than 20 slots are purged every second
- Max cached transactions: 50,000

### 2.6 Tower BFT (Consensus & Finality)

Vote-based finality inspired by Solana's Tower BFT:
- Each reader validates blocks and submits votes
- **Exponential lockout**: `lockout = 2^(depth+1)` slots (max depth: 32)
- **Confirmed**: 2/3+ of total stake votes on a slot
- **Rooted (finalized)**: 32 consecutive confirmed slots → irreversible; old vote data pruned
- Consensus statuses: `Rooted`, `Confirmed`, `Processed`
- Supermajority threshold: 66.7% of stake

### 2.7 JSON-RPC (28 Methods)

All methods run on port 8899, implemented via `jsonrpsee`. Full Solana wallet/explorer compatibility:

**Standard Solana methods (26):**
`getHealth`, `getVersion`, `getGenesisHash`, `getSlot`, `getBlockHeight`, `getBalance`, `getAccountInfo`, `getLatestBlockhash`, `getEpochInfo`, `getMinimumBalanceForRentExemption`, `getMultipleAccounts`, `sendTransaction`, `getTransaction`, `getSignaturesForAddress`, `getTokenAccountsByOwner`, `getTokenSupply`, `getTokenAccountBalance`, `getFeeForMessage`, `getRecentPrioritizationFees`, `isBlockhashValid`, `getIdentity`, `getSupply`, `getSignatureStatuses`, `getBlock`, `getBlocks`, `getBlockProduction`

**BlackBook-custom methods (2):**
`blackbook_getProfile`, `blackbook_isRegistered`

### 2.8 SPL Token (Native)

A native Rust SPL-Token engine (no BPF VM needed):
- `MintLayout` (82 bytes) — binary-compatible with Solana mainnet
- `TokenAccountLayout` (165 bytes) — binary-compatible with Solana mainnet
- USDC mint: deterministic address derived from `"USDC"` seed, 6 decimals, Dealer as mint authority
- `getTokenAccountsByOwner`, `getTokenSupply`, `getTokenAccountBalance` all work against this engine

---

## 3. How BlackBook Compares to Solana

| Dimension | Solana Mainnet | BlackBook L1 |
|-----------|----------------|--------------|
| **Slot time** | 400 ms | 600 ms |
| **PoH hash chain** | SHA-256 | SHA-256 (identical algorithm) |
| **Ticks per slot** | 64 | 64 |
| **Hashes per tick** | 12,500 | 12,500 |
| **Consensus** | Tower BFT (on-chain votes) | Tower BFT (in-memory votes, same lockout math) |
| **Block propagation** | Turbine (UDP shreds + erasure) | Turbine (identical shred format, 1,232 bytes) |
| **Tx forwarding** | Gulf Stream | Gulf Stream (8-leader lookahead, priority queues) |
| **Parallel execution** | Sealevel (rBPF) | Sealevel (native Rust, Rayon) |
| **Account model** | Pubkey → AccountSharedData | Pubkey → AccountSharedData (same Solana types) |
| **Storage** | RocksDB (Accounts DB) | ReDB (ACID, zero-config, single-file) |
| **Networking** | QUIC gossip (10,000+ nodes) | gRPC relay (1 Writer → 100 Readers) |
| **Binary** | Multi-binary (validator, RPC, etc.) | Single binary (`cargo run`) |
| **SPL Token** | rBPF program on-chain | Native Rust (binary-compatible layouts) |
| **RPC** | JSON-RPC (jsonrpsee) | JSON-RPC (jsonrpsee, 28 compatible methods) |
| **Fees** | Dynamic (priority fees) | 0 in Phase 1 (fee model TBD) |
| **Rent** | Rent-exempt threshold | Always 0 (`rent_epoch = MAX`) |
| **Lamports** | 1 SOL = 10^9 lamports | 1 BB = 10^9 lamports |
| **Cluster** | Gossip-based discovery | CLI-configured writer address |

### What's Shared

- **PoH**: Identical hash-chain algorithm. Same tick rate, same hash rate, same slot structure.
- **SVM**: Real Solana SDK types (`Pubkey`, `Hash`, `AccountSharedData`). Lamport arithmetic is identical.
- **Sealevel**: Parallel execution of non-overlapping transactions.
- **Turbine**: Same shred size, same erasure coding ratio, same tree fanout model.
- **Tower BFT**: Same exponential lockout, same 2/3 supermajority, same root advancement.
- **RPC**: Wallet tooling (`@solana/web3.js`) can point at BlackBook's RPC and work.

### What's Different

- **No gossip protocol**: BlackBook uses a gRPC relay for block distribution instead of Solana's QUIC-based gossip. This is simpler, deterministic, and sufficient for the 1-Writer/100-Reader model.
- **No rBPF VM**: SPL Token is implemented as native Rust, not as an on-chain BPF program. This means zero rBPF overhead but custom programs are not yet supported.
- **ReDB, not RocksDB**: ReDB is a pure-Rust, zero-dependency, single-file ACID database. It's simpler to deploy and reason about, at the cost of some throughput at extreme scale.
- **Single binary**: Writer and Reader are the same binary, differentiated by a `--mode` flag. No separate validator/RPC/gossip binaries.
- **600 ms slots**: Slightly slower than Solana's 400 ms to give more headroom for block propagation over gRPC.

---

## 4. The 1-Writer / 100-Reader Architecture

### 4.1 The Problem

A single-node blockchain can only serve as many RPC requests as one machine can handle. If 100 clients all call `getBalance` or `getTransaction`, they compete for the same CPU, memory, and disk on the block-producing node. Block production latency degrades under read load.

### 4.2 The Solution

Separate **writes** (block production) from **reads** (RPC serving):

```
                   ┌─────────────────────────────┐
                   │         WRITER NODE          │
                   │  • Produces blocks (PoH)     │
                   │  • Executes transactions     │
                   │  • Authoritative state       │
                   │  • gRPC relay on :50051      │
                   └─────────┬───────────────────┘
                             │
              gRPC SubscribeBlocks (streaming)
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
    │  READER #1  │   │  READER #2  │   │  READER #N  │
    │  RPC :8899  │   │  RPC :8900  │   │  RPC :8901  │
    │  HTTP :8080 │   │  HTTP :8081 │   │  HTTP :8082 │
    │  Verify +   │   │  Verify +   │   │  Verify +   │
    │  Store      │   │  Store      │   │  Store      │
    └─────────────┘   └─────────────┘   └─────────────┘
```

### 4.3 How It Works

#### Writer Side

1. **Block Production**: The Writer runs the PoH clock and produces finalized blocks every 600 ms.
2. **Broadcast**: After each block is produced, it is sent to a `tokio::broadcast` channel (256-block buffer).
3. **gRPC Relay Server**: `WriterRelayService` listens on the gRPC port and exposes four RPCs:

| RPC | Type | Purpose |
|-----|------|---------|
| `SubscribeBlocks` | Server-stream | Live block feed for readers |
| `CatchupBlocks` | Server-stream | Historical block range fetch |
| `ForwardTransaction` | Unary | Reader forwards a user's tx to writer |
| `GetStatus` | Unary | Health check (slot, hash, epoch, reader count) |

#### Reader Side

1. **Connect**: Reader opens a gRPC channel to the Writer's relay endpoint.
2. **Catchup**: Fetches all blocks it missed since its last stored slot via `CatchupBlocks`.
3. **Subscribe**: Opens a `SubscribeBlocks` stream for real-time blocks.
4. **Verify**: Each received block is passed through `verify_block()` — the same PoH + hash-chain verification the Writer uses. Invalid blocks are rejected and counted (`blocks_failed`).
5. **Store**: Verified blocks are persisted to the Reader's own local ReDB and DashMap balance cache.
6. **Serve**: The Reader runs its own HTTP + JSON-RPC servers, answering queries from its local state.
7. **Forward Writes**: If a user submits a transaction to a Reader, it forwards the transaction to the Writer via `ForwardTransaction` gRPC.
8. **Reconnect**: If the Writer goes down, the Reader retries every 5 seconds indefinitely.

#### Transaction Forwarding

Readers are not just passive consumers. When a user calls `sendTransaction` on a Reader:

```
User → Reader (HTTP/RPC) → ForwardTransaction (gRPC) → Writer → Execute → Block → Broadcast
```

The Writer executes the transaction, includes it in the next block, and the block propagates back to all Readers — including the one that forwarded it.

### 4.4 CLI Usage

**Start a Writer** (default — just `cargo run`):
```bash
cargo run
# Equivalent to:
cargo run -- --mode writer --identity genesis_validator --grpc-port 50051 --http-port 8080 --rpc-port 8899
```

**Start a Reader**:
```bash
cargo run -- --mode reader --identity reader_1 --writer-addr http://127.0.0.1:50051 --http-port 8081 --rpc-port 8900
```

**Multiple Readers on one machine**:
```bash
# Reader 2
cargo run -- --mode reader --identity reader_2 --writer-addr http://127.0.0.1:50051 --http-port 8082 --rpc-port 8901

# Reader 3
cargo run -- --mode reader --identity reader_3 --writer-addr http://127.0.0.1:50051 --http-port 8083 --rpc-port 8902
```

**Remote Reader** (Writer on a different machine):
```bash
cargo run -- --mode reader --identity edge_reader --writer-addr http://writer.blackbook.io:50051 --http-port 8080 --rpc-port 8899
```

### 4.5 Design Decisions

| Decision | Rationale |
|----------|-----------|
| **gRPC over gossip** | Deterministic, ordered delivery. No peer discovery overhead. Simpler to debug and monitor. |
| **Broadcast channel (256 buffer)** | If a Reader falls behind by more than 256 blocks (~2.5 min), it must use `CatchupBlocks` to resync. This prevents unbounded memory growth. |
| **Reader-side verification** | Every Reader independently verifies PoH + hash chain. A compromised Writer cannot trick Readers into accepting invalid blocks. |
| **Local ReDB per Reader** | Each Reader owns its data. If the Writer goes down, Readers continue serving reads from local storage. |
| **Forward writes, don't execute locally** | Only the Writer executes transactions. This eliminates state divergence between nodes. Readers are eventually consistent (within one slot). |

---

## 5. What "SVM" Means in BlackBook

### The Short Answer

SVM stands for **Solana Virtual Machine**. In BlackBook's context, it is the execution engine that processes every transaction — validating blockhashes, deducting lamports, updating account state, and recording results — using real Solana SDK types and the same account model as Solana mainnet.

### The Long Answer

Solana's SVM is the layer between "a user submitted a transaction" and "the account balances changed." It:

1. **Deserializes** the transaction (signature, recent blockhash, instructions).
2. **Validates** the blockhash (must be within the last 150 slots).
3. **Deduplicates** (rejects already-seen signatures).
4. **Loads accounts** from the account database.
5. **Executes** the instruction (system transfer, SPL token operation, etc.).
6. **Commits** the resulting account mutations atomically.

BlackBook implements this full pipeline natively in Rust:

```
sendTransaction(base64)
        │
        ▼
  Decode + verify signature
        │
        ▼
  BlockhashQueue.check(recent_blockhash)
  → Must be within 150 slots
        │
        ▼
  IntraBlockDedup.check(signature)
  → Reject replayed transactions
        │
        ▼
  SvmAccountsDB.get(from_pubkey)
  → Load sender account from DashMap (hot) or ReDB (cold)
        │
        ▼
  Execute: system_transfer(from, to, lamports)
  → Debit sender, credit receiver (u64 arithmetic, no floats)
  → Track lamport_deltas for block metadata
        │
        ▼
  Mark accounts dirty in DirtySet
        │
        ▼
  end_of_block()
  → SvmAccountsDB.flush_block()
  → Atomically persist all dirty accounts to ReDB
  → Clear DirtySet
  → Log StoredTransactionResult to svm_tx_log
```

### Why It Matters

Because BlackBook uses real Solana types (`Pubkey`, `Hash`, `AccountSharedData`, `Lamports`) and the same account model:

- **Solana wallets work**. Point `@solana/web3.js` at `http://localhost:8899` and call `getBalance`, `sendTransaction`, `getTransaction` — it just works.
- **Solana explorers work**. Any explorer that speaks the standard JSON-RPC dialect can display BlackBook blocks and transactions.
- **SPL tokens are compatible**. The mint and token-account layouts are byte-for-byte identical to Solana mainnet. Tools that parse SPL token accounts will parse BlackBook's.
- **Account model is portable**. If BlackBook ever bridges to Solana, account data can move without transformation.

### What SVM Is NOT in BlackBook (Yet)

- **No rBPF VM**: BlackBook does not run on-chain BPF programs. SPL Token is implemented natively. Custom smart contracts are a future milestone.
- **No CPI (Cross-Program Invocation)**: Since there's no BPF VM, there's no instruction-level program composition yet.
- **No on-chain programs**: All execution logic is compiled into the validator binary, not deployed as accounts.

These are deliberate trade-offs — native execution is faster and simpler for the current use case (micro-transactions, SPL-USDC, settlement). The rBPF path exists in the dependency tree (`solana_rbpf 0.8`) and can be activated when custom programs are needed.

---

## 6. End-to-End Transaction Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. SUBMIT                                                               │
│    User → HTTP/RPC on Writer (or Reader → ForwardTransaction → Writer)  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. GULF STREAM                                                          │
│    GulfStreamService.submit(tx)                                         │
│    → Dedup (seen set)                                                   │
│    → Forward to next 8 leaders' priority queues                         │
│    → Sorted by priority when leader drains mempool                      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. BLOCK PRODUCER                                                       │
│    BlockProducer.submit_transaction(tx)                                 │
│    → Mix tx_id into PoH hash chain (cryptographic timestamp)            │
│    → Push to pending_txs (capped at 10,000)                            │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. SEALEVEL EXECUTION (every 600 ms)                                    │
│    BlockProducer.produce_block()                                        │
│    a. SVM.advance_slot(slot, slot_hash) — seed blockhash queue          │
│    b. For each pending tx → BlackBookSVM.execute_transfer():            │
│       • Validate blockhash against 150-slot window                      │
│       • Intra-block dedup (reject replayed signatures)                  │
│       • system_transfer: debit sender, credit receiver (u64 lamports)   │
│       • Record lamport_deltas + 21,000 compute units consumed           │
│    c. Build FinalizedBlock:                                             │
│       • Ordered transactions + PoH entries                              │
│       • SHA-256 state root (Merkle over all accounts)                   │
│       • Previous-block hash linkage                                     │
│    d. SVM.end_of_block() → flush dirty accounts atomically to ReDB      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. PROPAGATION                                                          │
│    a. broadcast::send(block) → relay channel (256-block buffer)         │
│    b. WriterRelayService → SubscribeBlocks gRPC stream → all Readers    │
│    c. Turbine: shred block → 1,232-byte shreds + Reed-Solomon FEC      │
│       → Tree fanout (200 per level) → 40,000 nodes in 2 hops           │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 6. READER VERIFICATION                                                  │
│    a. ReaderNode receives block (catchup or live stream)                │
│    b. verify_block(): validate PoH entries + hash chain linkage         │
│    c. Store verified block to local ReDB                                │
│    d. Update DashMap balance cache (TransferBb, DepositUsdt)            │
│    e. Tower BFT: vote on slot → exponential lockout                     │
│       → 2/3+ stake → CONFIRMED                                         │
│       → 32 consecutive confirmed → ROOTED (irreversible)               │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7. QUERY                                                                │
│    User → Reader RPC (getBalance, getTransaction, etc.)                 │
│    → Served from Reader's local ReDB + DashMap                          │
│    → No load on Writer                                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. File Map

| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point. CLI parsing, mode branching, route wiring. |
| `src/poh_blockchain.rs` | PoH clock, BlockProducer, Turbine, verify_block, verify_chain. |
| `src/svm/runtime.rs` | BlackBookSVM execution engine, blockhash queue, slot management. |
| `src/svm/accounts_db.rs` | SvmAccountsDB — DashMap (hot) + ReDB (cold), atomic flush. |
| `src/svm/spl_token.rs` | Native SPL Token engine (mint, transfer, account layouts). |
| `src/svm/types.rs` | StoredAccount, TransactionExecutionResult, constants. |
| `src/svm/tx_adapter.rs` | Transaction adapter between BB and SVM formats. |
| `src/relay/mod.rs` | WriterRelayService — gRPC server streaming blocks to readers. |
| `src/reader/mod.rs` | ReaderNode — gRPC client, catchup, verify, store, reconnect. |
| `src/solana_rpc/mod.rs` | 28 JSON-RPC methods (jsonrpsee). |
| `runtime/consensus.rs` | Tower BFT, Gulf Stream, PoH config. |
| `runtime/core.rs` | Sealevel parallel execution, batch tuning. |
| `proto/validator_relay.proto` | gRPC service definition for Writer↔Reader relay. |
| `proto/settlement.proto` | gRPC service definition for L1↔L2 settlement. |

---

## 8. Summary

BlackBook L1 is a Solana-architecture blockchain implemented from scratch in Rust. It uses the same PoH clock, the same account model, the same consensus algorithm, and the same block propagation design as Solana — but packaged as a single binary with a simpler storage engine (ReDB) and a gRPC relay instead of gossip.

The 1-Writer/100-Reader architecture separates block production from read serving. One Writer does all the work of producing blocks and executing transactions. Readers subscribe to the Writer's block stream, independently verify every block, store it locally, and serve RPC queries from their own state. This scales read throughput linearly with the number of Readers while keeping the write path fast and deterministic.

The SVM (Solana Virtual Machine) is the heart of execution — it ensures every lamport transfer follows the same rules as Solana mainnet, every account is stored in the same format, and every RPC response matches what Solana wallets and explorers expect.
