# BlackBook: A Purpose-Built Layer 1 Blockchain for Prediction Markets and Creator Copyright Enforcement

**Version 1.0 — April 2026**

---

## Abstract

BlackBook is a Solana-architecture-inspired Layer 1 blockchain written entirely in Rust, purpose-built to serve as a high-throughput settlement layer for prediction market rollups (Layer 2) and creator copyright enforcement systems (Layer 3). The chain achieves 400-millisecond slot times through a continuous SHA-256 Proof of History clock, parallel transaction execution via the Sealevel engine, and mempool-less transaction forwarding via Gulf Stream. Finality is provided today by a single trusted writer node (PoH-ordered, 2-confirmation tracker); the Tower BFT exponential-lockout voting scheme with 32-confirmation rooting described in §3.2 is implemented as scaffolding for a future multi-validator deployment but is **not yet load-bearing** — see §3.2.1.

Unlike general-purpose smart contract platforms, BlackBook's six native contracts are engineered for a single, high-value use case: trustlessly locking collateral on L1 while high-frequency prediction markets execute on L2, settling outcomes back to L1 through cryptographically verifiable Merkle proofs. The L1 never holds user logic — it holds user money and mathematical truth.

This paper describes the architecture, consensus mechanism, execution model, settlement bridge, economic model, security properties, and legal positioning of the BlackBook protocol.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Three-Layer Architecture](#2-three-layer-architecture)
3. [Consensus: Proof of History + Tower BFT](#3-consensus-proof-of-history--tower-bft)
4. [Execution: Sealevel Parallel Processing](#4-execution-sealevel-parallel-processing)
5. [Transaction Pipeline](#5-transaction-pipeline)
6. [Block Propagation: Turbine Shredding](#6-block-propagation-turbine-shredding)
7. [Native Smart Contracts](#7-native-smart-contracts)
8. [Settlement Bridge: L2 ↔ L1](#8-settlement-bridge-l2--l1)
9. [Merkle Proof Settlement](#9-merkle-proof-settlement)
10. [Token Economics](#10-token-economics)
11. [Storage Architecture](#11-storage-architecture)
12. [Cryptographic Primitives](#12-cryptographic-primitives)
13. [Security Model](#13-security-model)
14. [Performance Characteristics](#14-performance-characteristics)
15. [Network Topology](#15-network-topology)
16. [Legal & Regulatory Positioning](#16-legal--regulatory-positioning)
17. [Technology Stack](#17-technology-stack)
18. [Roadmap](#18-roadmap)

---

## 1. Introduction

### The Problem

Prediction markets are among the highest-value applications in decentralized finance, yet no existing blockchain is optimized for them. General-purpose L1s (Ethereum, Solana, Avalanche) force prediction market operators to compete for blockspace with DEX swaps, NFT mints, and memecoin launches. During high-demand events — elections, major sporting finals, breaking news — gas fees spike unpredictably, and settlement latency becomes untenable.

Simultaneously, the creator economy loses billions annually to unauthorized content reuse. NFT platforms offer provenance records, but no existing system provides automated internet monitoring with cryptographic enforcement backed by an immutable on-chain record.

### The Solution

BlackBook solves both problems with a purpose-built three-layer blockchain stack:

- **Layer 1** settles transactions in 400ms slots, locks collateral in a trustless global escrow, and verifies cryptographic proofs — nothing else.
- **Layer 2** executes high-frequency prediction markets at scale, periodically anchoring Merkle state roots to L1 for trustless settlement.
- **Layer 3** monitors the internet for unauthorized content reuse and anchors copyright enforcement actions to L1 for immutable legal provenance.

The L1 does not try to be a general-purpose smart contract platform. It is a purpose-built **settlement vessel** — optimized for speed, capital safety, and cryptographic verification.

---

## 2. Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 LAYER 3 — CREATOR SHIELD                │
│   NFT Copyright Minting • Internet Monitoring •         │
│   Royalty Enforcement • License Tracking                │
│                                                         │
│   Anchors Merkle roots to L1 periodically               │
│   Sends enforcement messages to L1/L2                   │
└──────────────────────┬──────────────────────────────────┘
                       │  State Roots / Messages
                       ▼
┌─────────────────────────────────────────────────────────┐
│              LAYER 2 — PREDICTION MARKET ROLLUP         │
│   High-Frequency Betting • Real-Time Odds •             │
│   Market Resolution • Merkle Proof Generation           │
│                                                         │
│   Submits Merkle roots to L1 for settlement             │
│   All collateral locked in L1 Global Escrow             │
└──────────────────────┬──────────────────────────────────┘
                       │  Merkle Roots / Proofs
                       ▼
┌─────────────────────────────────────────────────────────┐
│               LAYER 1 — THE VESSEL (BlackBook)          │
│                                                         │
│   PoH + Tower BFT Consensus (400ms slots)               │
│   Sealevel Parallel Execution (all CPU cores)           │
│   Gulf Stream (mempool-less tx forwarding)              │
│   Turbine Shredding (2-hop global propagation)          │
│                                                         │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│   │   Global     │  │   Deposit    │  │  Withdrawal  │  │
│   │   Escrow     │  │   Gateway    │  │  Gateway     │  │
│   └─────────────┘  └──────────────┘  └──────────────┘  │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│   │   Token      │  │   Layer2     │  │  Creator     │  │
│   │   Swap       │  │   Market     │  │  Coin        │  │
│   └─────────────┘  └──────────────┘  └──────────────┘  │
│                                                         │
│   Storage: ReDB (ACID) + DashMap (lock-free hot cache)  │
│   Protocols: HTTP (8080), JSON-RPC (8899), gRPC (50051) │
└─────────────────────────────────────────────────────────┘
```

### Design Principle: The L1 Is the Court, Not the Marketplace

All heavy computation happens on L2 and L3. The L1 only stores cryptographic truth and enforces financial rules. This separation ensures that L2 prediction market spikes (e.g., election night) never congest L1 settlement, and L3 copyright enforcement never delays L2 payouts.

---

## 3. Consensus: Proof of History + Tower BFT

### 3.1 Proof of History (PoH)

BlackBook uses a continuous SHA-256 hash chain as a Verifiable Delay Function (VDF) to create a cryptographic clock. Every transaction is timestamped against this clock, eliminating consensus delays caused by clock-skew debates between nodes.

| Parameter | Value |
|-----------|-------|
| Hash Function | SHA-256 |
| Hashes per Tick | 12,500 |
| Ticks per Slot | 64 |
| Hashes per Slot | 800,000 |
| Slot Duration | 400 ms |
| Epoch Length | 432,000 slots (~2 days) |
| Genesis Hash | `SHA-256("LAYER1_POH_GENESIS_2024_CONTINUOUS_PROOF_OF_HISTORY")` |

The PoH clock runs as a continuous service. Each tick produces a hash derived from the previous tick's hash, creating an append-only chain that proves elapsed time without requiring external clock synchronization. Transactions are mixed into the hash chain at the point of receipt, creating a verifiable ordering of events.

### 3.2 Tower BFT

Tower BFT is a PBFT-like consensus mechanism that uses the PoH clock as a source of time, eliminating the need for timeout-based view changes.

**Voting Mechanics:**

Validators vote on slots. Each vote carries an exponential lockout: a validator who votes on slot $S$ at confirmation depth $d$ is locked out for $2^{d+1}$ slots before they can vote on a conflicting fork. This makes rollbacks exponentially expensive.

$$\text{lockout}(d) = 2^{d+1} \text{ slots}$$

At depth 31, the lockout is $2^{32} = 4,294,967,296$ slots (~54 years at 400ms per slot), making the vote effectively irreversible.

**Finality:**

A slot is **confirmed** when validators representing ≥ 66.7% of total stake have voted on it. A slot is **rooted** (irreversibly finalized) when 32 consecutive confirmed slots have been produced on top of it.

$$\text{finality time} = 32 \times 400\text{ms} = 12.8\text{s}$$

**Fork Selection:**

When forks exist, Tower BFT selects the heaviest subtree — the fork with the most cumulative stake-weighted votes. Ties are broken by preferring the higher slot number.

### 3.2.1 Implementation Status (Honest Disclosure)

The mechanics above describe the **target multi-validator design**. The current production deployment runs a **single writer node**, so:

- The writer self-votes with a fixed stake, making "≥ 66.7% supermajority" trivially 100% — it is not a Byzantine quorum.
- `Vote::signature` (`runtime/consensus.rs`) is a SHA-256 digest of the vote's public fields, **not an Ed25519 signature** — votes are currently unauthenticated and not gossiped between nodes.
- `FinalizedBlock` is **not signed** by the leader; Reader nodes verify the hash-chain and PoH linkage, then trust the writer's state root rather than re-executing transactions (`src/reader/mod.rs`).
- Turbine shred signatures are placeholder strings (`src/poh_blockchain.rs`).

For everyday users this means finality is fast and deterministic but **trust-based** (custodial-equivalent): security currently rests on the honesty/availability of the writer operator, not on a decentralized validator set. Closing this gap — leader block-signing, Ed25519-signed and gossiped votes, reader-side state verification, and ≥ 2 independent validators — is the core of the planned Layer 0 work and the §18 roadmap.

### 3.3 Gulf Stream

BlackBook eliminates the traditional mempool. Instead of broadcasting transactions to all nodes for local ordering, Reader nodes forward transactions directly to the predicted block producer with an 8-slot lookahead.

| Parameter | Value |
|-----------|-------|
| Lookahead | 8 slots (3.2 seconds) |
| Cache Capacity | 300,000 transactions |
| Cache Expiry | 20 slots |
| Priority Ordering | `amount × 100` (higher value = first execution) |

This pre-fills the leader's execution queue before the slot arrives, eliminating the latency of mempool gossip and enabling deterministic transaction ordering.

---

## 4. Execution: Sealevel Parallel Processing

Sealevel is BlackBook's parallel transaction execution engine. Instead of processing transactions sequentially, Sealevel identifies non-conflicting transactions and executes them across all available CPU cores simultaneously.

### 4.1 Account Lock Manager

Every transaction declares the accounts it reads and writes. The `AccountLockManager` enforces exclusivity:

- **Read lock:** Multiple transactions can read the same account concurrently.
- **Write lock:** Only one transaction can write to an account at a time.
- A write lock on any account blocks all other reads and writes to that account.

Non-conflicting transactions (those touching different accounts) execute in parallel. An NFT copyright anchor on L3, a stablecoin transfer, and a prediction market settlement can all execute in the same slot without interfering.

### 4.2 Batch Tuning

| Parameter | Value |
|-----------|-------|
| Optimal Batch | 2,048 transactions |
| Maximum Batch | 20,000 transactions |
| Minimum Batch | 128 transactions |
| Conflict Threshold | 25% |
| Thread Pool | `num_cpus::get()` (minimum 4) |

The scheduler dynamically adjusts batch size based on observed conflict rates:

- If conflict rate > 25%: batch size shrinks by 50%
- If conflict rate < 12.5%: batch size grows by 150%

This ensures optimal CPU utilization regardless of workload composition.

### 4.3 Bounded Retry (Deadlock Prevention)

When a transaction cannot acquire its locks, it does not spin indefinitely. The engine applies bounded exponential backoff:

1. Spin hints: 1 → 2 → 4 → 8 → ... → 1,024 (10 rounds)
2. Thread yields: up to 10 `yield_now()` calls
3. If still blocked: clean abort with `"Lock contention timeout"` error

This guarantees that a hot-spot (e.g., a viral prediction market on a single token) cannot starve the rest of the chain.

---

## 5. Transaction Pipeline

BlackBook processes transactions through a 4-stage asynchronous pipeline, inspired by Solana's architecture:

```
FETCH (100K buffer) → VERIFY (16 parallel Ed25519 workers)
  → EXECUTE (Sealevel parallel engine)
    → COMMIT (128 tx per batch write)
```

| Stage | Buffer | Workers | Purpose |
|-------|--------|---------|---------|
| Fetch | 100,000 packets | async I/O | Receive from HTTP, UDP, gRPC |
| Verify | 100,000 packets | 16 threads | Ed25519 signature verification |
| Execute | 100,000 packets | `num_cpus` | Sealevel parallel state transitions |
| Commit | 100,000 packets | 1 writer | Batch ReDB flush + broadcast |

Each stage operates independently, connected by bounded channels. Backpressure at any stage triggers upstream flow control, preventing memory exhaustion during traffic spikes.

---

## 6. Block Propagation: Turbine Shredding

Blocks are never broadcast whole. Instead, they are shredded into 1,232-byte UDP packets with 50% Reed-Solomon erasure coding, enabling any node to reconstruct the full block from any 50% of the shreds received.

| Parameter | Value |
|-----------|-------|
| Shred Size | 1,232 bytes (UDP MTU-safe) |
| Data Shreds per FEC Set | 32 |
| Coding Shreds per FEC Set | 32 |
| Erasure Recovery | Any 32 of 64 shreds reconstructs the full set |
| Fanout per Tree Level | 200 nodes |
| Hops to 40,000 Nodes | 2 |

The propagation tree is structured so that the block producer sends shreds to 200 Level-1 nodes, each of which forwards to 200 Level-2 nodes, reaching 40,000 nodes in just 2 network hops. Lost shreds are recovered via erasure coding without requiring retransmission requests.

---

## 7. Native Smart Contracts

BlackBook ships with six native contracts compiled directly into the validator binary. These are not interpreted bytecode (no eBPF/WASM VM overhead) — they execute as native Rust functions at bare-metal speed.

### 7.1 Global Escrow

The financial backbone of the L2 prediction market system. A Program-Derived Address (PDA) vault that holds all $BB tokens for every open market, verified by Merkle proofs.

**Instructions:**

| Instruction | Signer | Action |
|-------------|--------|--------|
| `deposit` | User wallet | Lock $BB from user → escrow PDA |
| `submit-state-root` | L2 sequencer | Anchor Merkle root + enforce zero-sum |
| `withdraw` | User wallet + Merkle proof | Release $BB from escrow → user |

**Zero-Sum Invariant:**

On every state root submission, the L1 enforces:

$$\text{total\_deposited} = \text{total\_payout} + \text{house\_rake}$$

If this equation fails, the submission is rejected. No funds can be created or destroyed during settlement.

**Claim Window:** 6,480,000 slots (~30 days at 400ms per slot). After expiry, unclaimed funds remain in escrow.

### 7.2 Deposit Gateway

Bridges external stablecoins (USDT on Solana and BSC) into the BlackBook economy at a fixed 1:10 ratio.

$$1\ \text{USDT} = 10\ \$\text{BB}$$

The gateway supports two approval paths:

1. **Automated:** Custody wallet watchers poll Solana/BSC RPCs every 30 seconds. When a deposit is detected and confirmed on-chain, $BB is minted instantly.
2. **Dealer-approved:** For manual verification, the Dealer operator approves pending deposits after independent verification of the external transaction.

Double-mint prevention: every external transaction hash is stored in ReDB and checked before minting. A Solana transaction can only mint $BB once.

### 7.3 Withdrawal Gateway

Converts $BB back to external stablecoins. Users burn wUSDT on L1, then the Dealer operator sends real USDT on Solana/BSC and records the external transaction hash on L1.

### 7.4 Token Swap

Fixed-rate atomic swap between $BB and wUSDT at 10:1. Both legs execute atomically — if either fails, both revert. No slippage risk (the rate is fixed).

### 7.5 Layer2 Market

Tracks prediction market contest state on L1: contest registration, outcome recording, and Merkle root storage. Each market transitions through: `Open → Settled → Expired`.

### 7.6 Creator Coin

Launchpad for user-created tokens with constant-product AMM pools (the $x \times y = k$ invariant). Per-ticker registry with on-chain balances and decentralized trading.

---

## 8. Settlement Bridge: L2 ↔ L1

The settlement bridge is the most critical piece of infrastructure. It connects the L2 prediction market to the L1 escrow via a gRPC service (port 50052, Tonic/Protobuf).

### 8.1 Settlement RPCs

| RPC | Direction | Purpose |
|-----|-----------|---------|
| `VerifyDeposit` | L2 → L1 | Confirm user's L1 deposit before allowing L2 entry |
| `InitContestReserve` | L2 → L1 | Lock dealer's $BB as prize reserve |
| `SubmitMerkleRoot` | L2 → L1 | Finalize market with Merkle root + zero-sum proof |
| `GetContestStatus` | L2 → L1 | Poll contest state (Open/Settled/Expired) |
| `SyncBridge` | Bidirectional | Heartbeat and TPS monitoring |

### 8.2 Identity Trust Model

A critical security property: when a user enters an L2 market, the L2 sequencer calls `VerifyDeposit` on L1. The L1 response includes `depositor_wallet` — the canonical wallet address that made the deposit. **The L2 must use this L1-echoed identity as the user's canonical address**, not any self-reported wallet. This prevents identity spoofing attacks where users claim to own deposits they didn't make.

### 8.3 Full Settlement Cycle

```
Phase 1: Market Opening
  L2 → gRPC InitContestReserve(contest_id, dealer, reserve_bb)
  L1 debits dealer wallet → credits escrow PDA

Phase 2: User Entry
  User → POST /escrow/deposit (signed, locks BB in escrow)
  L2 → gRPC VerifyDeposit(contest_id, tx_sig)
  L1 returns canonical depositor_wallet + verified amount

Phase 3: Market Execution
  (All betting happens on L2 — L1 has no involvement)

Phase 4: Resolution
  L2 computes winner list → builds Merkle tree → signs root
  L2 → gRPC SubmitMerkleRoot(root, signature, zero-sum proof)
  L1 verifies Ed25519 + zero-sum → stores root → opens 30-day claim window

Phase 5: User Claims
  User obtains Merkle proof from L2
  User → POST /escrow/withdraw (signed + proof)
  L1 verifies Merkle inclusion → releases BB from escrow → user wallet
```

---

## 9. Merkle Proof Settlement

The Merkle tree is the cryptographic mechanism enabling trustless payouts without requiring L1 to store the full list of winners.

### 9.1 Leaf Construction

Each winner's payout is encoded as a 40-byte preimage, then hashed:

$$\text{leaf} = \text{SHA-256}(\text{wallet\_raw}_{32} \ \|\ \text{amount\_spl\_u64\_le}_{8})$$

Where `wallet_raw` is the 32-byte Ed25519 public key (bs58-decoded) and `amount_spl` is the payout in SPL units (1 $BB = 1,000,000 SPL units), encoded as an 8-byte little-endian unsigned integer.

### 9.2 Tree Construction

Parent nodes use sorted-pair hashing to ensure deterministic tree construction regardless of sibling ordering:

$$\text{parent} = \text{SHA-256}(\min(left, right) \ \|\ \max(left, right))$$

Where $\min$ and $\max$ are determined by lexicographic comparison of the 32-byte hashes.

### 9.3 Proof Verification

To claim, a user submits their wallet address, claimed amount, and an array of sibling hashes (the proof). L1 reconstructs the leaf, walks the proof to compute the root, and verifies it matches the stored root. If verified, funds are released atomically.

**Double-claim prevention:** Each `(market_id, wallet_address)` pair can only claim once. The claim record is stored in a DashMap with atomic `entry()` insertion.

---

## 10. Token Economics

### 10.1 The $BB Token

$BB (BlackBook) is the native unit of account on L1. All prediction market collateral, escrow balances, and settlement payouts are denominated in $BB.

| Property | Value |
|----------|-------|
| Ticker | $BB |
| Decimals | 6 |
| SPL Unit | 1 $BB = 1,000,000 lamports |
| Backing | 1 USDT = 10 $BB (fixed gateway rate) |
| Supply Model | Mint-on-deposit, burn-on-withdrawal |

### 10.2 Supply Invariant

The core economic invariant ensures $BB is always fully backed:

$$\text{vault\_usdt} \times 10 = \text{total\_bb\_supply}$$

Every $BB in circulation was minted by a verified USDT deposit through the gateway. Every withdrawal burns the corresponding $BB. The supply audit endpoint (`GET /supply/audit`) verifies this invariant in real-time and is callable by any external auditor.

### 10.3 wUSDT (Wrapped USDT)

wUSDT is an SPL-compatible token on L1 that represents the stablecoin backing. When a user deposits 100 USDT, they receive:
- 1,000 $BB (for trading/prediction markets)
- 100 wUSDT (redeemable 1:1 for USDT on Solana/BSC)

The fixed-rate Token Swap contract allows users to convert between $BB and wUSDT at any time at the 10:1 rate, with no slippage.

### 10.4 Custody Model

$BB tokens **never leave L1**. The L2 prediction market does not hold $BB balances — it references the L1 escrow. Users deposit $BB into the global escrow PDA before entering L2 markets, and claim winnings from the escrow after settlement. The L2 only tracks bet positions internally.

---

## 11. Storage Architecture

BlackBook uses a two-tier storage model optimized for both crash safety and low-latency reads.

### Tier 1: ReDB (Durable)

ReDB is an embedded, single-writer ACID key-value store with MVCC (Multi-Version Concurrency Control). Readers never block writers.

| Table | Key | Value |
|-------|-----|-------|
| `blocks` | slot | FinalizedBlock |
| `transactions` | tx_hash | TransactionRecord |
| `svm_accounts` | pubkey_b58 | Solana-style Account |
| `bridge_txs_processed` | external_tx_hash | bool |
| `deposit_requests` | external_tx_hash | DepositRecord |
| `withdrawals` | withdrawal_id | WithdrawalRecord |
| `escrow_claims` | `{market}:{wallet}` | timestamp |
| `contest_states` | contest_id | ContestState |

### Tier 2: DashMap (Hot Cache)

DashMap provides zero-copy, lock-free concurrent reads. All active state is served from DashMap for microsecond-latency lookups. ReDB is the authoritative source of truth on crash recovery.

### SVM Account Model

BlackBook uses a Solana-compatible account model:

```
Account {
    lamports: u64,      // balance in raw SPL units
    owner: Pubkey,      // program that owns this account
    executable: bool,   // whether this account contains program code
    data: Vec<u8>,      // arbitrary account data
}
```

This ensures future compatibility with Solana tooling, wallets, and developer ecosystems.

---

## 12. Cryptographic Primitives

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Consensus Clock | SHA-256 | Continuous PoH hash chain (VDF) |
| Transaction Signing | Ed25519 | All endpoints require wallet signatures |
| Block Hashing | SHA-256 | `hash = SHA-256(slot \|\| prev_hash \|\| state_root)` |
| Merkle Settlement | SHA-256 | Sorted-pair tree for escrow proofs |
| Address Encoding | Base58 (bs58) | Solana-compatible wallet addresses |
| Erasure Coding | Reed-Solomon GF(2⁸) | Turbine shred recovery |
| PDA Derivation | SHA-256 | Program-Derived Address seeds |

All signing uses the Ed25519 curve (via `ed25519-dalek`). Private keys are 32-byte seeds; public keys are 32-byte compressed points encoded as base58 strings. Signatures are 64 bytes.

---

## 13. Security Model

### 13.1 Transaction-Level Security

- **Ed25519 signature required on every state-changing endpoint.** No unsigned writes are possible.
- **Replay protection:** Every transaction includes a unique nonce. L1 stores and rejects previously-seen nonces using atomic DashMap `entry()` operations (no TOCTOU race conditions).
- **Timestamp validation:** Transactions older than 60 seconds are rejected, preventing delayed replay attacks.
- **Chain ID enforcement:** The UDP TPU validates `chain_id == 1`, preventing cross-chain replay.

### 13.2 Escrow Security

- **Zero-sum enforcement:** State root submissions must prove `total_deposited == total_payout + house_rake`.
- **Sequencer authentication:** Only Ed25519 keys registered in the L2 sequencer allowlist can submit state roots.
- **Monotonic block numbers:** Each state root must reference a block number strictly greater than the last seen, preventing state regression attacks.
- **Double-claim prevention:** Each `(market_id, wallet)` pair can only claim once, enforced atomically.
- **Claim window:** 30-day deadline after settlement. Unclaimed funds remain locked.

### 13.3 Network Security

- **UDP TPU rate limiting:** 5,000 packets/second per IP address. Excess traffic is silently dropped.
- **Network throttler:** 20% supply cap per single transfer (circuit breaker).
- **Graceful error handling:** No `.unwrap()` or `.expect()` on user-controlled input paths. Malformed payloads return HTTP errors without crashing the node.
- **Sealevel deadlock prevention:** Bounded retry with exponential backoff. No transaction can spin-lock indefinitely.

### 13.4 Custody Security

- **No plaintext key storage in production.** Dealer private keys are injected via HashiCorp Vault (AppRole + Vault Agent) at runtime.
- **External transaction deduplication:** Every Solana/BSC transaction hash is stored in ReDB before minting, preventing double-mint attacks.
- **Supply reconciliation:** On every node startup, the BB/wUSDT supply invariant is verified and corrected if necessary.

---

## 14. Performance Characteristics

### Throughput

| Metric | Value | Source |
|--------|-------|--------|
| Slot Time | 400 ms | `main.rs::POH_SLOT_DURATION_MS` |
| Max Transactions per Slot (block cap) | 240,000 | `poh_blockchain.rs::MAX_TXS_PER_BLOCK` |
| Theoretical Peak TPS | 600,000 (240k ÷ 0.4s) | derived |
| Sustained TPS (single-node, tested) | ~230 | informal — not yet load-tested at scale |
| Optimal Sealevel Batch | 2,048 tx | `runtime/sealevel.rs` |
| Pipeline Buffer Depth | 100,000 packets × 4 stages | `runtime/tpu.rs` |
| UDP TPU Capacity | configurable per-IP × 8 workers | `runtime/tpu.rs` |

> Note: theoretical peak assumes a full 240k-tx block every slot and is bounded in practice by signature-verification throughput, Sealevel conflict rate, and disk I/O. The legacy `verify_block_validity` helper still hard-caps proposed blocks at 10,000 txs, but it sits on the not-yet-active multi-validator path and does not gate the live single-writer producer.

### Latency

| Operation | Latency |
|-----------|---------|
| Ed25519 Signature Verification | ~10 μs per tx |
| Sealevel Batch Execution | 1–10 ms (conflict-dependent) |
| Block Production | 400 ms (fixed slot time) |
| Finality (tx tracker, live) | ~0.8 s (2 × 400ms, `CONFIRMATIONS_REQUIRED = 2`) |
| Finality (Tower Rooted, multi-validator design) | 12.8 s (32 × 400ms) — not yet load-bearing, see §3.2.1 |
| gRPC Settlement Round-trip | < 400 ms (same network) |

### Memory Footprint

| Component | Allocation |
|-----------|-----------|
| Gulf Stream Cache | ~60 MB (300K tx) |
| Pipeline Buffers | ~20 MB (4 × 100K packets) |
| Hot SVM Accounts | 500 MB – 2 GB |
| ReDB (memory-mapped) | Grows with chain |

---

## 15. Network Topology

BlackBook uses a Writer/Reader model:

- **Writer (Block Producer):** Runs the PoH clock, produces blocks, executes transactions via Sealevel. One active Writer per epoch.
- **Reader (Validator/RPC):** Receives blocks via Turbine shreds, validates via Tower BFT voting, serves RPC queries. Up to 100 Readers.

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP (Axum) | REST API for wallets and clients |
| 8899 | JSON-RPC 2.0 | Solana-compatible RPC interface |
| 50051 | gRPC (Tonic) | Writer → Reader block relay |
| 50052 | gRPC (Tonic) | L2 ↔ L1 settlement bridge |
| 8003 | UDP | Transaction Processing Unit (TPU) |

Reader nodes can be deployed globally behind GeoDNS for geographic load balancing. The Writer node should be isolated from direct client traffic — dedicated RPC nodes convert HTTP JSON to bincode and blast to the Writer's UDP TPU.

---

## 16. Legal & Regulatory Positioning

### 16.1 Classification of $BB

$BB is a utility token backed 1:10 by USDT held in custody. It functions as an in-protocol unit of account for prediction market collateral, not as a security or investment contract.

**Key characteristics:**
- **Not a security.** $BB does not represent equity, profit-sharing, or voting rights in any entity. It is a unit of exchange within the BlackBook protocol, analogous to chips at a casino or credits on a gaming platform.
- **Fully backed.** Every $BB in circulation is redeemable through the withdrawal gateway at the fixed rate of 10 $BB = 1 USDT. The supply audit endpoint provides real-time verification of backing.
- **No expectation of profit.** The value of $BB is fixed by the deposit/withdrawal gateway rate. There is no market-making, speculation, or price appreciation mechanism for $BB itself.

### 16.2 Prediction Market Regulatory Framework

Prediction markets operate in a complex regulatory landscape. BlackBook's L1 is deliberately designed to be jurisdiction-neutral infrastructure:

- **The L1 does not operate prediction markets.** It stores collateral and verifies mathematical proofs. The L2 prediction market operator is the regulated entity.
- **Trustless settlement.** Users claim winnings directly from the L1 escrow using Merkle proofs. No entity can prevent or delay a valid claim. This non-custodial model avoids money transmitter classifications in most jurisdictions.
- **On-chain auditability.** Every deposit, settlement, and withdrawal is recorded on-chain with Ed25519 signatures and SHA-256 hashes. Regulators can independently verify the complete flow of funds.

**Relevant frameworks by jurisdiction:**

| Jurisdiction | Framework | $BB Classification |
|-------------|-----------|-------------------|
| United States | Howey Test (SEC) | Utility token — no investment contract |
| United States | CFTC | Prediction market settlement layer — L2 operator may need CFTC event contract DCM registration |
| European Union | MiCA (2024) | Utility token / e-money token (backed 1:1 equivalent via gateway) |
| United Kingdom | FCA | Unregulated utility token (not specified financial instrument) |
| Singapore | MAS | Digital payment token — exempt from securities regulation if used solely for payment |
| Japan | FSA | Prepaid payment instrument (fixed exchange rate, no speculation) |

### 16.3 Anti-Money Laundering (AML) Compliance

- **Wallet-level transaction history:** All transactions are publicly auditable via `GET /address/:address/transactions`.
- **Deposit gateway KYC integration point:** The two-step deposit flow (user request → dealer approval) provides a natural checkpoint for KYC/AML verification before any USDT enters the system.
- **Withdrawal gateway identity verification:** The dealer controls the USDT release step, enabling off-chain identity verification before external funds are sent.
- **Immutable audit trail:** Ed25519 signatures on every transaction provide cryptographic attribution — every movement of funds is signed by the initiator's private key.

### 16.4 Intellectual Property (Layer 3)

The L3 Creator Shield provides legally defensible copyright provenance:

- **PoH timestamping:** Every creation event is anchored against the L1's continuous SHA-256 clock, providing a cryptographic timestamp admissible in intellectual property disputes.
- **Merkle root anchoring:** L3 periodically submits Merkle roots to L1, creating an immutable record of all copyright registrations, license grants, and enforcement actions.
- **Cross-jurisdictional enforceability:** The on-chain record serves as technical evidence under the Berne Convention, DMCA (US), EU Copyright Directive, and equivalent international frameworks.

### 16.5 Gambling vs. Prediction Market Distinction

Prediction markets are legally distinct from gambling in several key jurisdictions:

- **CFTC-regulated event contracts** (United States): Prediction markets on economic or geopolitical events may qualify as regulated event contracts under CFTC authority, provided they do not involve gaming, terrorism, or assassination markets.
- **Skill-based information aggregation:** Academic research (Arrow et al., Hanson 2003) establishes prediction markets as information aggregation mechanisms, not games of chance. The L2 operator's regulatory burden depends on the specific event types offered.
- **The L1 is infrastructure.** Just as AWS is not a gambling operator because a customer runs a poker site on EC2, BlackBook's L1 is settlement infrastructure — not a prediction market operator.

---

## 17. Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | **Rust** | Memory-safe, zero-cost abstractions, no GC pauses |
| Async Runtime | **Tokio** | Multi-threaded async I/O |
| HTTP Framework | **Axum + Tower** | REST endpoints, CORS, compression |
| Parallel Execution | **Rayon** | Sealevel thread pool |
| Consensus Hash | **SHA-256** (sha2 crate) | PoH hash chain |
| Signatures | **Ed25519-dalek** | Transaction and governance signing |
| Concurrent Cache | **DashMap** | Lock-free hot caches |
| Persistence | **ReDB** | Embedded ACID key-value store |
| Merkle Trees | **rs_merkle** | Proof construction and verification |
| Erasure Coding | **reed-solomon-erasure** | Turbine FEC shreds |
| SVM Compatibility | **Solana SDK 2.1** | Pubkey, accounts, SPL token support |
| JSON-RPC | **jsonrpsee** | Solana-compatible RPC server |
| gRPC | **Tonic / Prost** | Settlement bridge protocol |
| Address Encoding | **bs58** | Base58 addresses (Solana-compatible) |
| Logging | **tracing** | Structured JSON logging |
| Container | **Docker** | Production deployment |

---

## 18. Roadmap

### ✅ Phase 1: Security & Core Stability — COMPLETE

All `.unwrap()` panics eliminated, atomic replay protection across all nonce sites, Sealevel deadlock prevention with bounded retry, Ed25519 enforcement verified on all endpoints.

### Phase 2: Financial Integrity — IN PROGRESS

- Replace `f64` with `u64` lamport math across all ledgers
- Database-before-cache persistence ordering
- Rate limiting and per-contract circuit breakers

### Phase 3: High-Throughput Networking

- UDP TPU optimization for 100K+ TPS
- Binary serialization (bincode) replacing JSON on the TPU path
- Stake-weighted QoS and dedicated RPC nodes

### Phase 4: Multi-Node Global Network

- Writer-to-Reader gRPC relay wiring
- Firewall lockdown (gRPC port whitelisting)
- Global Reader node deployment (US, Asia, EU)

### Phase 5: L2 Integration — IN PROGRESS

- ✅ Dealer SDK (`sdk/dealer.sdk.ts`) — complete
- L2 sequencer connection and live market testing
- End-to-end settlement cycle validation

### Phase 6+: L3 Creator Shield & Ecosystem

- L3 copyright anchoring endpoint
- Creator Coin AMM integration
- Cross-layer message passing
- P2P gossip mesh

---

## References

1. Yakovenko, A. (2017). *Solana: A new architecture for a high performance blockchain.* Solana Whitepaper.
2. Hanson, R. (2003). *Combinatorial Information Market Design.* Information Systems Frontiers, 5(1), 107-119.
3. Arrow, K. J. et al. (2008). *The Promise of Prediction Markets.* Science, 320(5878), 877-878.
4. EU Regulation 2023/1114. *Markets in Crypto-Assets Regulation (MiCA).*
5. U.S. Commodity Futures Trading Commission. *CFTC Guidance on Event Contracts.*
6. Reed, I. S. & Solomon, G. (1960). *Polynomial Codes Over Certain Finite Fields.* Journal of the Society for Industrial and Applied Mathematics.

---

*This document is the authoritative technical reference for the BlackBook protocol. For implementation details, see `root_manifesto.md`. For the production readiness checklist, see `security_step_by_step.md`. For the phased development plan, see `root_next_steps.md`.*
