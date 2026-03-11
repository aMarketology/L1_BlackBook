# BlackBook L1 — Chain Specification

**Version 5.0.0** · Ed25519 / PoH / Sealevel / SVM · March 2026

---

## Table of Contents

1. [Network Identity](#1-network-identity)
2. [Economic Model](#2-economic-model)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Proof of History Clock](#4-proof-of-history-clock)
5. [Tower BFT Consensus](#5-tower-bft-consensus)
6. [Transaction Pipeline](#6-transaction-pipeline)
7. [Sealevel Parallel Execution](#7-sealevel-parallel-execution)
8. [Gulf Stream (Mempool-less Forwarding)](#8-gulf-stream-mempool-less-forwarding)
9. [Turbine Block Propagation](#9-turbine-block-propagation)
10. [Block Structure](#10-block-structure)
11. [SVM Execution Engine](#11-svm-execution-engine)
12. [SPL Token Support (USDC)](#12-spl-token-support-usdc)
13. [Storage Layer](#13-storage-layer)
14. [Wallet Architecture](#14-wallet-architecture)
15. [Address Space & Collision Resistance](#15-address-space--collision-resistance)
16. [Authentication Model](#16-authentication-model)
17. [API Surface](#17-api-surface)
18. [gRPC Validator Relay](#18-grpc-validator-relay)
19. [Performance Envelope](#19-performance-envelope)
20. [Test Coverage](#20-test-coverage)
21. [Dependency Stack](#21-dependency-stack)
22. [Deployment](#22-deployment)
23. [Roadmap Phases](#23-roadmap-phases)

---

## 1. Network Identity

| Parameter | Value |
|-----------|-------|
| Package | `layer1` |
| Version | `5.0.0` |
| Rust Edition | 2021 |
| Network Label | `mainnet-beta` |
| Genesis Hash | `SHA-256("BLACKBOOK_L1_GENESIS_2025")` → base58 |
| RPC API Version | `BB-5.0` |
| Chain ID | `0xBB` (187) |

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| **8080** | HTTP (Axum) | REST API — transfers, wallets, ledger, admin |
| **8899** | HTTP (jsonrpsee) | Solana-compatible JSON-RPC 2.0 |
| **50051** | gRPC (tonic) | Validator relay — block streaming, tx forwarding |

### Node Modes

| Mode | Flag | Role |
|------|------|------|
| Writer | `--mode writer` (default) | Block producer, source of truth |
| Reader | `--mode reader` | Subscribes to writer via gRPC, serves read-only queries |

---

## 2. Economic Model

| Parameter | Value | Notes |
|-----------|-------|-------|
| Native Token | **BB** | BlackBook |
| Decimals | **5** | 1 BB = 100,000 lamports |
| `LAMPORTS_PER_BB` | 100,000 | Smallest unit = 0.00001 BB |
| Smallest unit @ $0.10/BB | $0.000001 | Sub-cent microtransactions |
| Transaction Fees | **0** | Phase 1 — zero fees |
| Account Rent | **0** | `RENT_EPOCH_EXEMPT = u64::MAX` — accounts never pay rent |
| Faucet Cap | **0.1 BB** per request | Session-token or Ed25519 authenticated |
| USDT→BB Ratio | 1:10 | Vault solvency reference |
| USDC Decimals | **6** | Matches Solana USDC standard |

### Token Supply

BB supply is uncapped in Phase 1. Minting is gated behind dealer-authenticated admin endpoints with optional L2 receipt IDs for audit trails. Supply visibility:

- `getSupply` (RPC) — total and circulating lamports
- `/admin/accounts` (REST) — all non-zero balances
- `/usdc/supply` (REST) — total USDC minted on-chain

---

## 3. Cryptographic Primitives

| Function | Algorithm | Library |
|----------|-----------|---------|
| Signing | **Ed25519** | `ed25519-dalek 2.0` |
| PoH Hash Chain | **SHA-256** | `sha2 0.10` |
| Block Hashing | **SHA-256** | `sha2 0.10` |
| State Root | **SHA-256 Merkle Tree** | `rs_merkle 1.4` |
| KDF (Wallet) | **Argon2id** | `argon2 0.5` |
| Symmetric Encryption | **AES-256-GCM** | `aes-gcm 0.10` |
| CSPRNG | **OsRng** | Operating system entropy |
| Address Encoding | **Base58** | `bs58` (Solana-compatible) |
| Account Serialization | **Borsh** | `borsh 1.3` |

### Signature Verification

Ed25519 signature verification is parallelized across **8 worker threads** (`SIGVERIFY_WORKERS = 8`) using Rayon. Batch verification is supported for throughput-critical paths.

### Replay Protection

| Parameter | Value |
|-----------|-------|
| Timestamp Window | **60 seconds** — reject if `|now - timestamp| > 60s` |
| Nonce Tracking | `DashMap<String, u64>` (nonce → timestamp) |
| Pruning Threshold | When > **100,000** entries, evict entries older than **120 seconds** |

---

## 4. Proof of History Clock

BlackBook runs a continuous SHA-256 hash chain as a verifiable delay function (VDF). Every hash proves elapsed time, enabling orderless consensus.

| Parameter | Value |
|-----------|-------|
| Hash Algorithm | SHA-256 (recursive chaining) |
| `slot_duration_ms` | **400 ms** |
| `hashes_per_tick` | **12,500** |
| `ticks_per_slot` | **64** |
| Hashes per Slot | 800,000 (12,500 × 64) |
| `slots_per_epoch` | **432,000** |
| Epoch Duration | **~48 hours** (432,000 × 400ms) |
| Tick Interval | **6.25 ms** (400ms / 64 ticks) |
| Genesis Seed | `SHA-256("LAYER1_POH_GENESIS_2024_CONTINUOUS_PROOF_OF_HISTORY")` |

### PoH Entry Structure

Each tick produces a `PoHEntry`:
- `hash`: SHA-256 output (32 bytes)
- `num_hashes`: iterations since previous entry
- `transactions`: ordered batch hashed into the chain

This creates a cryptographic proof that a specific sequence of events occurred in a specific order, without requiring wall-clock synchronization between nodes.

---

## 5. Tower BFT Consensus

Tower BFT is a PoH-optimized variant of PBFT. Validators vote on slots; votes are exponentially locked out to prevent equivocation.

| Parameter | Value |
|-----------|-------|
| `MAX_TOWER_DEPTH` | **32** votes |
| `SUPERMAJORITY_THRESHOLD` | **66.7%** (2/3 stake) |
| `MIN_FORK_VOTES` | **1** |
| Lockout Formula | $2^{(c + 1)}$ slots, where $c$ = confirmation count |
| Finality | **2 confirmations** (~1.2s at 600ms slots) |
| Root | 32 consecutive confirmed slots → **ROOTED** (irreversible) |
| Stake Weighting | Logarithmic: $w = \ln(1.0 + \text{engagement})$ |

### Node Topology (Phase 1)

| Role | Count | Purpose |
|------|-------|---------|
| Writer (Leader) | 1 | Block production, state authority |
| Reader (Validator) | Up to 100 | Block verification, RPC serving |

Writer–Reader replication happens over gRPC streaming (port 50051). Readers subscribe at startup and catch up via `CatchupBlocks` RPC.

---

## 6. Transaction Pipeline

BlackBook processes transactions through a 4-stage asynchronous pipeline with configurable parallelism.

```
┌─────────┐    ┌───────────┐    ┌───────────┐    ┌──────────┐
│  FETCH   │ →  │  VERIFY    │ →  │  EXECUTE   │ →  │  COMMIT   │
│ receive  │    │ Ed25519    │    │ Sealevel   │    │ finalize  │
│ packets  │    │ 8 workers  │    │ parallel   │    │ broadcast │
└─────────┘    └───────────┘    └───────────┘    └──────────┘
```

| Constant | Value |
|----------|-------|
| `PIPELINE_BUFFER_SIZE` | **100,000** transactions |
| `SIGVERIFY_WORKERS` | **8** parallel verifiers |
| `COMMIT_BATCH_SIZE` | **128** transactions per commit |

---

## 7. Sealevel Parallel Execution

Sealevel is BlackBook's parallel transaction execution engine. Non-conflicting transactions are batched and executed concurrently across all available CPU cores.

| Parameter | Value |
|-----------|-------|
| Thread Pool | `num_cpus::get().max(4)` (Rayon) |
| `OPTIMAL_BATCH_SIZE` | **256** |
| `MAX_BATCH_SIZE` | **1,024** |
| `MIN_BATCH_SIZE` | **32** |
| `CONFLICT_THRESHOLD` | **25%** — halve batch if exceeded |
| Growth Rate | **1.5×** batch size when conflicts < 12.5% |
| Lock Model | DashMap-based read/write lock manager |

### Conflict Detection

Transactions touching the **same account** are serialized. Sealevel builds a conflict graph per batch:
- If two transactions both write to account `X`, they execute sequentially.
- If one reads `X` and another writes `Y`, they execute in parallel.

Adaptive tuning adjusts batch sizes in real-time based on observed conflict rates.

### Transaction Types

`Transfer` · `Mint` · `Burn` · `BridgeLock` · `BridgeUnlock` · `Vote` · `SystemReward`

### Account Types

`UserWallet` · `EscrowVault` · `SystemConfig` · `Treasury` · `BridgeEscrow` · `Dealer`

### PDA Namespaces

`wallet` · `vault` · `config` · `treasury` · `bridge-escrow`

---

## 8. Gulf Stream (Mempool-less Forwarding)

Gulf Stream eliminates the traditional mempool. Transactions are forwarded directly to the expected leader for the upcoming slot.

| Parameter | Value |
|-----------|-------|
| Leader Lookahead | **8 slots** |
| `MAX_CACHED_TXS` | **50,000** per leader |
| `CACHE_EXPIRY_SLOTS` | **20 slots** (8 seconds at 400ms) |
| Priority Scoring | `amount × 100` (higher = executed first) |

---

## 9. Turbine Block Propagation

Turbine splits blocks into shreds for parallel network propagation, inspired by BitTorrent.

| Parameter | Value |
|-----------|-------|
| `SHRED_SIZE` | **1,232 bytes** (fits UDP MTU) |
| `DATA_SHREDS_PER_FEC_SET` | **32** |
| FEC Redundancy | **50%** (32 data + 32 coding shreds) |
| Erasure Coding | XOR-based (Phase 1) → Reed-Solomon (future) |
| `TURBINE_FANOUT` | **200** nodes per hop |
| 2-Hop Reach | **40,000 nodes** |

A block is shredded → erasure-coded → fanned out to 200 peers → each peer fans to 200 more. Full block recovery requires only 50% of shreds thanks to FEC.

---

## 10. Block Structure

### FinalizedBlock

```
FinalizedBlock {
    slot:           u64,
    timestamp:      i64,
    previous_hash:  String,
    hash:           String,          // SHA-256(slot + prev + state_root + poh + tx_count + leader + epoch)
    state_root:     String,          // Merkle root of all account balance hashes
    accounts_hash:  String,
    poh_hash:       String,
    poh_sequence:   u64,
    poh_entries:    Vec<PoHEntry>,
    transactions:   Vec<OrderedTransaction>,
    tx_count:       usize,
    leader:         String,
    epoch:          u64,
    confirmations:  u32,
}
```

| Parameter | Value |
|-----------|-------|
| `MAX_TXS_PER_BLOCK` | **50,000** |
| `BLOCK_INTERVAL_MS` | **400 ms** |
| Theoretical Max TPS | **125,000** (50K × 2.5 blocks/s) |
| State Root | SHA-256 Merkle tree of all account balance hashes |

---

## 11. SVM Execution Engine

BlackBook's SVM is binary-compatible with Solana's runtime, enabling future program portability.

| Parameter | Value |
|-----------|-------|
| `MAX_COMPUTE_UNITS` | **1,400,000** per transaction |
| `MAX_RECENT_BLOCKHASHES` | **150** slot window |
| Account Serialization | Borsh (`lamports: u64`, `data: Vec<u8>`, `owner: [u8; 32]`, `executable: bool`, `rent_epoch: u64`) |
| Rent | **Disabled** (`RENT_EPOCH_EXEMPT = u64::MAX`) |

### Balance Source of Truth

SVM `AccountsDB` stores native `u64` lamports (not floating-point). All balance queries resolve to `svm_accounts` first. The DashMap cache is a hot mirror, rebuilt on startup from ReDB.

---

## 12. SPL Token Support (USDC)

| Parameter | Value |
|-----------|-------|
| SPL Token Program ID | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| ATA Program ID | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` |
| Mint Account Layout | **82 bytes** (Solana binary-compatible) |
| Token Account Layout | **165 bytes** (Solana binary-compatible) |
| USDC Mint Address | `SHA-256("BlackBook_USDC_Mint_v1")` → deterministic |
| ATA Derivation | `SHA-256(wallet ∥ SPL_TOKEN_PROGRAM_ID ∥ mint ∥ ATA_PROGRAM_ID)` |
| Mint Authority | Set via `USDC_MINT_AUTHORITY` environment variable |

Both data layouts are byte-for-byte compatible with Solana mainnet SPL Token. This enables future cross-chain token bridging without format conversion.

---

## 13. Storage Layer

### Database

**ReDB 2.4** — pure Rust, single-file, ACID, MVCC, single-writer/multi-reader, zero-copy reads. No external database process required.

Data path: `./blockchain_data/blockchain.redb`

### Tables

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `svm_accounts` | `[u8; 32]` | Borsh | **Source of truth for all balances** |
| `svm_programs` | `[u8; 32]` | `[u8]` | Program ELF binaries |
| `svm_signatures` | `[u8; 64]` | `u64` | Signature deduplication |
| `svm_tx_log` | `&str` | Borsh | Transaction execution receipts |
| `svm_addr_sigs` | `&str` | `u64` | Address → signature index |
| `blockhash_queue` | `u64` | `[u8; 32]` | Recent blockhash history |
| `blocks` | `u64` | `[u8]` | Committed finalized blocks |
| `transactions` | `&str` | `[u8]` | Transaction history by signature |
| `metadata` | `&str` | `[u8]` | Chain metadata (slot, epoch, etc.) |
| `accounts` | `&str` | `f64` | Legacy balance mirror |
| `frost_share_b` | `&str` | `[u8]` | SSS shard B (encrypted) |
| `frost_pub_key` | `&str` | `[u8]` | Wallet public keys |
| `frost_pub_key_pkg` | `&str` | `[u8]` | FROST public key packages |
| `wallet_shares` | `&str` | `[u8]` | Encrypted wallet shares |
| `wallet_metadata` | `&str` | `[u8]` | Wallet metadata |
| `processed_bridge_txs` | `&str` | `&str` | Bridge replay protection |

### Concurrency Model

- **Hot state**: `DashMap<Pubkey, AccountSharedData>` — lock-free concurrent reads
- **Persistence**: SVM `store_account()` → `flush_block()` ACID commit to ReDB
- **Startup**: ReDB → DashMap hydration (zero-downtime restarts)

### Pruning (Phase 7+)

| Mode | Retention |
|------|-----------|
| Archive | All slots (full history) |
| Pruned | Last **300,000 slots** (~3.5 days at 400ms) |

---

## 14. Wallet Architecture

BlackBook wallets use **Shamir's Secret Sharing (2-of-3)** to split Ed25519 private keys. The full key never exists on any single device after creation.

### Key Derivation

```
32 bytes (OsRng) → BIP-39 Mnemonic (24 words) → BIP-39 Seed (64 bytes)
  → first 32 bytes → Ed25519 Signing Key → Verifying Key (32 bytes)
    → Base58 encode → Wallet Address (Solana-format)
```

### Shamir 2-of-3 Split

```
                    Ed25519 Seed (32 bytes)
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌─────────┐
         │ SHARD A  │ │ SHARD B  │ │ SHARD C  │
         │ (User)   │ │ (Server) │ │ (Cold)   │
         │          │ │          │ │          │
         │ Encrypted│ │ Encrypted│ │ Raw hex  │
         │ Argon2id │ │ SERVER   │ │ offline  │
         │ +AES-256 │ │ MASTER   │ │ storage  │
         │ -GCM     │ │ KEY      │ │          │
         └─────────┘ └─────────┘ └─────────┘

         Any 2 shards reconstruct the full seed:
           A+B = Normal login (user + server)
           A+C = Self-custody (user + cold)
           B+C = Emergency recovery (server + cold)
```

### Encryption Details

| Component | Specification |
|-----------|---------------|
| KDF | Argon2id (default `argon2 0.5` parameters) |
| Cipher | AES-256-GCM |
| Salt | 128-bit (random) |
| Nonce | 96-bit (random) |
| Shard A Format | `salt_b64:nonce_hex:ciphertext_hex` |
| Server Master Key | `SERVER_MASTER_KEY` environment variable |

### Session Management

| Parameter | Value |
|-----------|-------|
| TTL | **30 minutes** (idle timeout) |
| Storage | In-memory `DashMap` (seed is `Zeroize`-on-Drop) |
| Sweeper | Background thread every **60 seconds** |
| Concurrency | One session per wallet (new login revokes old) |
| Token Format | UUID v4 |

---

## 15. Address Space & Collision Resistance

### Theoretical Capacity

| Metric | Value |
|--------|-------|
| Key Type | Ed25519 (32-byte public key) |
| Address Format | Base58-encoded Ed25519 verifying key |
| Curve Order | $\approx 2^{252.6}$ ($\approx 7.24 \times 10^{75}$) |
| Entropy Source | 32 bytes from OS CSPRNG (`OsRng`) |
| Average Address Length | ~44 base58 characters |

### Collision Analysis

| Scenario | Value |
|----------|-------|
| Total address space | $\approx 2^{252}$ |
| Birthday-paradox 50% collision threshold | $\approx 2^{126}$ wallets ($\approx 8.5 \times 10^{37}$) |
| At 1B wallets/second to reach 50% collision | $\approx 2.7 \times 10^{21}$ years |
| Atoms in observable universe (for reference) | $\approx 10^{80}$ |

### Empirical Verification

Collision test (50 wallets, rapid-fire creation against a live node):
- ✅ All 50 addresses unique
- ✅ All 50 mnemonics unique
- ✅ All 50 Shard A values unique (random salt/nonce)
- ✅ All 50 Shard C values unique
- ✅ All 50 public keys unique
- ✅ 58/58 base58 characters observed (full charset)
- ✅ 908 unique BIP-39 words across 1,200 generated words

Two wallets sharing an address is computationally infeasible.

---

## 16. Authentication Model

BlackBook supports two authentication paths, purpose-separated by SDK:

### Path 1: Ed25519 Signature (AI Agents — `blackbook_sdk.js`)

```
Message = format-specific string (e.g. "SEALEVEL:{from}:{to}:{amount}:{ts}:{nonce}")
Signature = Ed25519.sign(privateKey, Message)
Server verifies: Ed25519.verify(publicKey, Message, Signature)
```

| Endpoint | Message Format |
|----------|---------------|
| `/transfer/simple` | `chain_id_byte ∥ payload_json ∥ "\n" ∥ timestamp ∥ "\n" ∥ nonce` |
| `/sealevel/submit` | `"SEALEVEL:{from}:{to}:{amount}:{timestamp}:{nonce}"` |
| `/faucet` | `"FAUCET:{to}:{amount}:{timestamp}:{nonce}"` |
| `/usdc/transfer` | `"USDC_TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}"` |

### Path 2: SSS Session Token (Human Users — `wallet_sdk.js`)

```
Login: Send encrypted Shard A + password → server reconstructs seed → returns session_token
Transfer: Send session_token → server uses cached seed to sign → zeroize after use
```

Session tokens are valid for 30 minutes after last use. The reconstructed seed lives only in RAM and is `Zeroize`d on session expiry or server shutdown.

---

## 17. API Surface

### REST Endpoints (Port 8080)

#### Read (Unauthenticated)

| Method | Route | Returns |
|--------|-------|---------|
| GET | `/health` | Node health, chain stats, block production |
| GET | `/stats` | Pipeline, Gulf Stream, Sealevel metrics |
| GET | `/balance/:address` | BB balance for address |
| GET | `/ledger` | Transaction history (supports `?format=json`) |
| GET | `/poh/status` | PoH clock state |
| GET | `/poh/block/latest` | Latest finalized block |
| GET | `/poh/block/:slot` | Block by slot number |
| GET | `/poh/tx/:tx_id/status` | Transaction finality status |
| GET | `/consensus/tower` | Tower BFT vote state |
| GET | `/turbine/status` | Turbine shred propagation |
| GET | `/admin/accounts` | All non-zero account balances |
| GET | `/usdc/balance/:address` | USDC balance |
| GET | `/usdc/supply` | Total USDC supply |
| GET | `/usdc/accounts/:address` | Token accounts for wallet |

#### Write (Authenticated)

| Method | Route | Auth | Purpose |
|--------|-------|------|---------|
| POST | `/transfer/simple` | Ed25519 | Signed BB transfer |
| POST | `/sealevel/submit` | Ed25519 or Session | Gulf Stream parallel submit |
| POST | `/faucet` | Ed25519 or Session | Mint BB (capped 0.1 per request) |
| POST | `/usdc/transfer` | Ed25519 or Session | USDC transfer |
| POST | `/admin/mint` | Dealer | Mint BB |
| POST | `/admin/burn` | Dealer | Burn BB |
| POST | `/admin/usdc/mint` | Dealer | Mint USDC |
| POST | `/wallet/create` | None | Create BIP-39 + SSS wallet |
| POST | `/wallet/login` | SSS shards | Login (reconstruct seed) |
| POST | `/wallet/logout` | Session | Revoke session |
| POST | `/transfer` | SSS shards | SSS-authenticated transfer |
| POST | `/transfer/session` | Session | Fast-path session transfer |
| POST | `/wallet/secure/shard-b` | None | Retrieve server shard |
| POST | `/wallet/verify-sss` | SSS shards | Verify reconstruction |

### Solana JSON-RPC 2.0 (Port 8899)

#### Read Methods

`getHealth` · `getVersion` · `getGenesisHash` · `getSlot` · `getBlockHeight` · `getBalance` · `getAccountInfo` · `getMultipleAccounts` · `getLatestBlockhash` · `getEpochInfo` · `getMinimumBalanceForRentExemption` · `getTokenAccountsByOwner` · `getTokenSupply` · `getTokenAccountBalance` · `getFeeForMessage` · `getRecentPrioritizationFees` · `isBlockhashValid` · `getIdentity` · `getSupply` · `getSignatureStatuses` · `getBlock` · `getBlocks` · `getBlockProduction`

#### Write Methods

`sendTransaction` · `getTransaction` · `getSignaturesForAddress`

#### BlackBook Extensions

`blackbook_getProfile` · `blackbook_isRegistered`

---

## 18. gRPC Validator Relay

Port **50051** · Proto: `validator_relay.proto`

| RPC Method | Type | Purpose |
|------------|------|---------|
| `SubscribeBlocks` | Server-streaming | Writer pushes new blocks to readers |
| `CatchupBlocks` | Server-streaming | Reader requests block range for sync |
| `ForwardTransaction` | Unary | Reader forwards tx to writer's mempool |
| `GetStatus` | Unary | Health/status query |

### Messages

- `BlockData`: slot, timestamp, previous_hash, hash, state_root, poh_hash, leader, epoch, transactions, poh_entries
- `BlockTransaction`: from, to, amount, signature, timestamp, tx_type, slot
- `PoHEntry`: hash, num_hashes, transaction_ids
- `ForwardTransactionRequest/Response`: transaction forwarding with signature

---

## 19. Performance Envelope

### Block Production

| Metric | Value |
|--------|-------|
| Block Time | **400 ms** |
| Max Transactions per Block | **50,000** |
| Theoretical Max TPS | **125,000** |
| Measured TPS (stress test, 14/14 passed) | **230 TPS** (3,460 txs in 15s) |

### Pipeline Capacity

| Stage | Throughput |
|-------|-----------|
| Signature Verification | 8 parallel workers × batch verify |
| Sealevel Scheduling | Adaptive 32–1,024 tx batches |
| Parallel Execution | `num_cpus` Rayon threads, DashMap lock-free |
| Pipeline Buffer | 100,000 in-flight transactions |

### Measured Benchmarks (Criterion)

| Benchmark | Coverage |
|-----------|----------|
| PoH Hashing | Single tick, 1,000 ticks, mixed tx batches |
| Ed25519 | Single, batch (10/100/1K), parallel (1K/10K) |
| Sealevel | Non-conflicting (100/1K/10K), conflicting (100/1K) |
| Parallel Execution | 1K/10K/50K balance updates on 100K accounts |
| Storage | DashMap write/read/mixed (80:20) at 10K ops |
| End-to-End | Full pipeline simulation |

---

## 20. Test Coverage

### Integration Test Suites

| Suite | Tests | Coverage |
|-------|-------|----------|
| `microtx_ai_agents.rs` | AI agent microtransactions | Sub-cent precision (1 lamport), 50 concurrent agents, nonce/replay protection, circuit breakers, Ed25519 throughput |
| `poh_consensus.rs` | PoH & consensus | Clock ticks, hash chains, 50K txs/block, Merkle trees, Turbine shred/reassembly, Tower BFT votes, supermajority, fork selection |
| `sealevel_parallel.rs` | Parallel execution | Lock manager conflicts, batch splitting, circuit breaker, localized fee market, stake-weighted throttling, adaptive tuning |
| `signature_verification.rs` | Cryptography | Ed25519 signed transfers, SSS reconstruction, PoH pipeline sigverify, faucet gates, replay protection |
| `storage_svm.rs` | Storage & SVM | u64 lamports source of truth, credit/debit atomicity, address resolution, 5-decimal precision, ACID block persistence, SPL Token ops |
| `stress_test_production.rs` | Production load | Production constants, 10+ thread concurrency, 5K+ tx Sealevel, Turbine large blocks, Merkle 10K leaves, full pipeline end-to-end |

### SDK Test Suites

| Suite | Tests | Result |
|-------|-------|--------|
| `test_wallet_sdk.mjs` | 28 | **28/28 passed** — full wallet lifecycle |
| `test_wallet_collision.mjs` | 50 wallets | **0 collisions** — address, mnemonic, shard, pubkey all unique |

---

## 21. Dependency Stack

### Runtime & Framework

| Crate | Version | Role |
|-------|---------|------|
| `tokio` | 1.0 | Async runtime (multi-thread) |
| `axum` | 0.7 | HTTP framework |
| `jsonrpsee` | 0.24 | Solana-compatible JSON-RPC |
| `tonic` | 0.12 | gRPC server/client |
| `prost` | 0.13 | Protobuf codegen |

### Cryptography

| Crate | Version | Role |
|-------|---------|------|
| `ed25519-dalek` | 2.0 | Ed25519 signing + verification |
| `sha2` | 0.10 | SHA-256 (PoH, blocks) |
| `blake3` | 1.5 | Fast hashing (auxiliary) |
| `bip39` | 2.0 | BIP-39 mnemonic generation |
| `sharks` | 0.5 | Shamir Secret Sharing |
| `aes-gcm` | 0.10 | AES-256-GCM encryption |
| `argon2` | 0.5 | Argon2id key derivation |

### SVM Compatibility

| Crate | Version | Role |
|-------|---------|------|
| `solana-sdk` | 2.1 | Types, pubkeys, transactions |
| `solana-program` | 2.1 | Program interfaces |
| `solana-program-runtime` | 2.1 | Compute budget, logging |
| `solana_rbpf` | 0.8 | BPF VM (future program execution) |

### Storage & Concurrency

| Crate | Version | Role |
|-------|---------|------|
| `redb` | 2.4 | Embedded ACID database |
| `dashmap` | 6.0 | Lock-free concurrent hash map |
| `rayon` | 1.10 | Work-stealing thread pool |
| `crossbeam` | 0.8 | Concurrent channels |
| `rs_merkle` | 1.4 | Merkle tree (state roots) |

### Serialization

| Crate | Version | Role |
|-------|---------|------|
| `borsh` | 1.3 | SVM account serialization |
| `serde` | 1.0 | JSON serialization |
| `bincode` | 1.3 | Binary encoding |
| `bs58` | 0.5 | Base58 address encoding |

---

## 22. Deployment

### Container

| Field | Value |
|-------|-------|
| Base Image | Debian Bookworm (multi-stage Rust build) |
| Binary | `/usr/local/bin/layer1` |
| Ports Exposed | 8080, 8899, 50051 |
| Health Check | `GET /health` |
| Orchestration | `docker-compose.prod.yml` |
| Platform | Railway (`railway.toml`) or Hetzner bare metal |

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `SERVER_MASTER_KEY` | Yes | Encrypts Shard B at rest |
| `USDC_MINT_AUTHORITY` | Optional | Base58 pubkey authorized to mint USDC |
| `DEALER_ADDRESS` | Optional | Authorized dealer for admin mint/burn |
| `RUST_LOG` | Optional | Logging verbosity (`info`, `debug`, etc.) |

### Feature Flags

| Flag | Effect |
|------|--------|
| `unsafe_admin` | Enables `/admin/mint`, `/admin/burn`, `/admin/usdc/mint` without signature verification |

---

## 23. Roadmap Phases

| Phase | Status | Scope |
|-------|--------|-------|
| **1 — Core** | ✅ Complete | PoH clock, Tower BFT, Sealevel, ReDB, REST API |
| **2A — RPC Read** | ✅ Complete | Solana JSON-RPC (read-only methods) |
| **2B — RPC Write** | ✅ Complete | `sendTransaction`, `getTransaction`, `getSignaturesForAddress` |
| **2C — Token/Fee** | ✅ Complete | SPL Token queries, fee methods, identity |
| **3 — Wallet** | ✅ Complete | BIP-39 + SSS 2-of-3, session management |
| **4 — USDC** | ✅ Complete | SPL-compatible mint, transfer, ATA derivation |
| **5 — Blocks** | ✅ Complete | `getBlock`, `getBlocks`, `getBlockProduction` |
| **6 — SDKs** | ✅ Complete | `blackbook_sdk.js` (AI agents), `wallet_sdk.js` (users), `explorer_sdk.js` |
| **7 — Pruning** | Planned | Archive vs. Pruned modes, 300K slot retention |
| **8 — L2 Bridge** | Planned | gRPC `CreditLineService` (settlement.proto), prediction market integration |
| **9 — Multi-Writer** | Planned | Leader rotation, multi-validator block production |
| **10 — Programs** | Planned | On-chain BPF program execution via `solana_rbpf` |

---

*This document is the canonical technical reference for BlackBook L1. All values are sourced directly from the codebase at version 5.0.0.*
