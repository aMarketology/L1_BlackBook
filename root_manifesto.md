# BlackBook — Root Manifesto

> **The Ultimate Vessel for Fast Transactions, Prediction Markets, and Creator Copyright Protection.**

---

## The Vision

BlackBook is a purpose-built, three-layer blockchain stack designed to serve three converging global needs:

1. **Layer 1 — The Vessel.** A hyper-fast, stable base-layer blockchain for sub-second transaction finality, capital bridging, and cryptographic truth.
2. **Layer 2 — The Rollup.** A scalable execution environment built specifically for high-frequency prediction market trading, settling back to L1.
3. **Layer 3 — The Creator Shield.** A specialized app-chain for creators to mint, track, and enforce NFT copyrights across the open internet — stopping unauthorized reuse before it spreads.

The Layer 1 does not try to do everything. It **perfectly anchors everything**. It orders transactions blazingly fast, holds escrowed capital safely, and verifies L2/L3 cryptographic proofs without choking.

---

## Layer 1 — The Vessel

### Core Mission: Fast, Stable, Unbreakable Transactions

The L1 is a Solana-architecture-inspired chain written entirely in Rust, running Proof of History (PoH) + Tower BFT consensus with Sealevel parallel execution.

#### Consensus: PoH + Tower BFT

| Parameter | Value |
|-----------|-------|
| Slot time | **400 ms** |
| Hashes per tick | 12,500 (SHA-256) |
| Ticks per slot | 64 |
| Epoch length | 432,000 slots (~3 days) |
| Finality model | 32 consecutive confirmations → **ROOTED** (irreversible) |
| Supermajority | 2/3+ stake on a slot = CONFIRMED |
| Node model | 1 Writer (block producer) + up to 100 Readers (validators) |

- **PoH Clock** provides a deterministic, cryptographic timestamp for every transaction — no clock-skew debates, no mempool-ordering games.
- **Tower BFT** uses exponential lockout voting (`2^(depth+1)` slots per confirmation), making rollbacks exponentially expensive.
- **Gulf Stream** eliminates the global mempool entirely. Reader nodes forward transactions directly to the upcoming Writer node with an 8-slot lookahead, pre-filling its queue before the slot arrives. Cache: up to 300K pending transactions.

#### Execution: Sealevel Parallel Processing

- All non-conflicting transactions execute **simultaneously** across every available CPU core.
- `AccountLockManager` enforces per-account read/write exclusivity per batch.
- Dynamic batch tuning: optimal batch of 2,048 txs; shrinks automatically if conflict rate exceeds 25%.
- An NFT mint on L3 settling to L1 will **never** slow down a stablecoin transfer happening in the same slot.

#### Transaction Pipeline: 4-Stage Async Processing

```
FETCH → VERIFY → EXECUTE → COMMIT
```

1. **FETCH:** Receive transactions from network/RPC.
2. **VERIFY:** Validate Ed25519 signatures (16 parallel workers).
3. **EXECUTE:** Process via Sealevel (parallel account locking).
4. **COMMIT:** Batch finalize & broadcast (128 txs per batch).
- Buffer: 100K packets per stage. Pipeline latency: microsecond range.

#### Block Propagation: Turbine Shredding

- Shred size: 1,232 bytes (UDP MTU optimized).
- 32 data + 32 coding shreds per FEC set (50% Reed-Solomon erasure coding).
- Max fanout: 200 nodes per tree level — 2 hops reach 40,000 nodes.
- Lost packets recovered via erasure coding without re-requesting.

#### Localized Fee Markets

If the L2 prediction market goes viral during an election night or a major sporting event, the gas fees for regular L1 users **must remain unaffected**. Fees scale per-contract, not globally.

---

### L1 Smart Contracts

The L1 hosts six core contracts that serve as the financial spine of the entire stack:

| Contract | Purpose |
|----------|---------|
| **Global Escrow** | PDA vault holding ALL BB tokens for all open markets. Verifies deposits, stores Merkle roots, enables winner payouts. |
| **Deposit Gateway** | USDT → $BB at 1:10 ratio. Custody wallet monitoring on Solana + BSC. Watcher threads poll real balances. |
| **Withdrawal Gateway** | BB → USDT redemption. Dealer address derived from key. Double-spend protection via withdrawal claims set. |
| **Token Swap** | wUSDC ↔ BB atomic swaps at 10:1 ratio, executed through Sealevel. |
| **Layer2 Market** | BB market resolution. Per-market Merkle trees. Contest state tracking (Open → Settled → Expired). |
| **Creator Coin** | Launchpad for user-created tokens. Constant-product AMM pools. Per-ticker registry + balances. |

#### Guardian Invariants (Must NEVER Be Violated)

```
TIER 1 (VAULT):   vault_usdt × 10 == total_bb_supply         (ALWAYS)
CUSTODY:          L2 holds zero BB; all BB lives in L1 escrow PDA
IDENTITY:         L2 trusts L1's echoed depositor, ignores user claims
ZERO-SUM:         total_payout + house_rake == total_deposited
```

#### Storage

- **ReDB** — Single-writer ACID embedded database for accounts, blocks, disputes, deposits, withdrawals.
- **DashMap hot caches** — Zero-copy, lock-free concurrent reads for accounts, escrow, deposit/withdrawal requests, market roots, contest states, creator coins.

#### Safety Controls

- Network throttler & circuit breaker: 20% supply cap per single transfer.
- Nonce deduplication for replay attack prevention.
- No hardcoded test accounts — all accounts created at runtime via wallet creation.
- Faucet removed; users bridge capital via Deposit Gateway only.

---

## Layer 2 — The Prediction Market Rollup

### Core Mission: High-Frequency Prediction Market Execution at Scale

The L2 is a rollup execution environment purpose-built for prediction markets — where millions of bets need to be placed, odds need to update in real-time, and settlement must be trustless.

#### What the L1 Provides for L2

1. **Ultra-Cheap Data Availability.** The L1 provides an optimized lane for storing L2 state roots cheaply. Prediction markets require frequent state updates to reflect changing odds — the L1 must ingest these without congestion.

2. **Native ZK-Proof Verification.** If the L2 operates as a ZK-rollup, the L1 SVM needs hyper-optimized, low-gas pre-compiles to verify Zero-Knowledge Proofs and settle L2 bets instantly.

3. **Bulletproof Global Escrows.** The L1's `global_escrow` contract is a mathematically secure mechanism to lock stablecoins (collateral) on L1 while the liquidity is actively traded on L2. The L2 never holds BB directly — it only references L1's escrow.

4. **Settlement Bridge (L1 ↔ L2):**

```
User Deposit (Solana/BSC tx)
  → L2 verifies via L1 RPC (VerifyDeposit)
  → Event resolves on L2
  → L2 builds Merkle tree of outcomes
  → L2 signs & submits root to L1 (SubmitMerkleRoot)
  → L1 stores root
  → User claims winnings via Merkle proof (ClaimWinnings)
```

5. **L2 Sequencer Authentication.** The L1 maintains an Ed25519 public key allowlist for L2 sequencer signature verification. Only authorized sequencers can submit state roots.

---

## Layer 3 — The Creator Shield (NFT Copyright System)

### Core Mission: Protect Creators from Unauthorized Reuse Across the Internet

The L3 is a specialized app-chain / app-ecosystem where creators mint NFTs that carry enforceable copyright metadata. The system monitors the open internet for unauthorized reuse of creator content and takes cryptographic enforcement action.

#### What the L1 Provides for L3

1. **Lightweight State Anchoring.** As the L3 monitors the internet and enforces royalties, it generates billions of micro-verifications. The L1 allows L3 to anchor a cryptographic fingerprint (Merkle root) of this data periodically — proving chronological copyright without storing heavy data on L1.

2. **Programmable Interoperability (Arbitrary Message Passing).** If the L3 system catches unauthorized use of a creator's work, it can send a message down to L2 or L1 to penalize the bad actor — slashing staked tokens, intercepting transactions, or triggering automated royalty disbursement.

3. **Standardized Base Metadata.** The L1 natively understands "Creator/License" primitives in its base token standard. Bridging an NFT from L3 → L2 → L1 seamlessly carries its copyright rules, licensing terms, and royalty splits with it.

4. **Immutable Provenance Chain.** Every creation event, license grant, and enforcement action is timestamped via PoH and rooted on L1 — creating an immutable, legally defensible chain of provenance that holds up in any jurisdiction.

---

## Architecture Diagram

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
│   Market Resolution • ZK Proof Generation               │
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
│   Storage: ReDB (ACID) + DashMap (hot cache)            │
│   RPC: Solana JSON-RPC 2.0 (port 8899)                 │
│   Relay: gRPC (port 50051)                              │
│   HTTP: Axum (port 8080)                                │
└─────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | **Rust** | Memory-safe, zero-cost abstractions, no GC pauses |
| Async Runtime | **Tokio** | Multi-threaded async I/O |
| HTTP | **Axum + Tower** | REST endpoints, CORS, compression |
| Parallel Execution | **Rayon** | Thread pool for Sealevel batches |
| Consensus Hash | **SHA-256** | PoH hash chain |
| Signatures | **Ed25519-dalek** | Transaction and governance signing |
| Concurrent Cache | **DashMap** | Lock-free hot caches |
| Persistence | **ReDB** | Embedded ACID key-value store |
| Merkle Trees | **rs_merkle** | Proof construction and verification |
| SVM Compat | **Solana SDK 2.1** | Pubkey, accounts, SPL token support |
| RPC | **jsonrpsee** | Solana JSON-RPC 2.0 server |
| Relay | **Tonic / Prost** | gRPC protocol buffers |
| Encoding | **bs58** | Base58 addresses (Solana-compatible) |
| Logging | **Tracing** | Structured JSON logging |

---

## Network Configuration

| Parameter | Value |
|-----------|-------|
| Version | **5.0.0** (mainnet-beta) |
| Node Modes | `--mode writer` (block producer) / `--mode reader` (validator + RPC) |
| HTTP Port | 8080 |
| RPC Port | 8899 (Solana JSON-RPC 2.0) |
| Relay Port | 50051 (gRPC) |
| Target Network | Solana mainnet-beta integration |

---

## Production Readiness Status

### Green — Production-Ready

- ✅ PoH clock (continuous, stable 400ms slots)
- ✅ Tower BFT voting & finality (32-confirmation rooting)
- ✅ Gulf Stream (mempool-less transaction forwarding)
- ✅ Sealevel parallel execution (conflict detection, lock manager)
- ✅ Transaction pipeline (4-stage async processing)
- ✅ Merkle tree building & proof generation
- ✅ Deposit gateway (custody watcher on Solana + BSC)
- ✅ Withdrawal gateway (dealer address-based releases)
- ✅ ReDB persistence (ACID transactions)
- ✅ Turbine shredding (block propagation with FEC)
- ✅ Network throttler & circuit breaker
- ✅ Nonce deduplication (replay protection)

### Yellow — Planned / Partially Wired

- 🟡 P2P Gossip (Turbine propagation logic exists, not fully wired — Phase 5+)
- 🟡 PDA Derivation (struct exists, Layer 5+ feature)
- 🟡 Creator Coin AMM (Anchor program structure present, integration planned)
- 🟡 Circuit Breaker tuning for live production load

### Red — Blockers Before Global Deployment

- 🔴 **L2 Sequencer Pubkey Allowlist:** L1 contract requires manual allowlist registration for L2 sequencer keys. Not yet implemented in contract initialization.
- 🔴 **Writer-to-Reader gRPC Relay:** Skeleton exists in `relay/`, needs connection wiring.
- 🔴 **Contest Settlement E2E Testing:** Global escrow compiles, but full market resolution cycle not yet load-tested.
- 🔴 **L3 State Anchoring Interface:** Endpoint for L3 to submit copyright Merkle roots to L1 not yet built.
- 🔴 **Arbitrary Message Passing (L3 → L1):** Cross-layer enforcement messaging not yet implemented.
- 🔴 **Creator/License Base Metadata:** Native token standard does not yet carry copyright primitives.

---

## Principles

1. **The L1 is the court, not the marketplace.** All heavy computation happens on L2/L3. The L1 only stores truth and enforces rules.
2. **Collateral never leaves L1.** The L2 and L3 reference escrow balances — they never hold BB tokens directly.
3. **PoH is the universal clock.** Every event across all three layers is timestamped against the same cryptographic clock.
4. **Parallel by default.** Sealevel ensures that activity on one layer cannot bottleneck another.
5. **Creators own their work.** The L3 exists so that minting an NFT means something — it means the internet can't steal your art without cryptographic consequence.

---

*This document is the single source of truth for the BlackBook architecture. All development, auditing, and deployment decisions flow from this manifesto.*
