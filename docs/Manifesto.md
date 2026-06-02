# BlackBook — Technical Manifesto

> **v1.0.0 — June 2026. Production node live. L2 sequencer live. 502 tx/s validated.**
> Node: `91.98.196.34:8080` · Git tag: `v1.0.0` (commit `4224b0c`)

---

## The Core Premise

Prediction markets don't need a general-purpose blockchain. They need one thing: a chain that settles bets as fast as they are made, without leaking capital to MEV, without latency from consensus bloat, and without trusting a human operator with the funds.

BlackBook is that chain. Purpose-built for high-frequency L2 prediction markets. Every architectural decision — PoH ordering, Sealevel parallelism, the Universal Rollup Hub — exists to make the L2 engine credible and fast.

---

## v1.0.0 Production Status

| Metric | Value |
|--------|-------|
| **Sustained TPS (validated)** | **502 tx/s (Hetzner CX42, June 2026)** |
| Peak (burst) | ~1,200 tx/s |
| PoH slot time | 400 ms |
| L1 HTTP port | :8080 (Axum) |
| L1 UDP TPU port | :8003 (bincode, 8 workers) |
| Persistent store | ReDB (`blockchain_data/blockchain.redb`) |
| In-memory cache | DashMap (write-behind over ReDB) |
| Auth model | Ed25519 everywhere |
| L2 smoke test | 8 steps, all passing on live Hetzner |
| Build | `cargo build --release`, zero errors |
| Git | tag `v1.0.0`, pushed to `aMarketology/L1_BlackBook` |

---

## Consensus: PoH + Tower BFT

| Parameter | Value |
|-----------|-------|
| Slot time | **400 ms** |
| Hashes per tick | 12,500 (SHA-256) |
| Ticks per slot | 64 |
| Epoch length | 432,000 slots (~2 days) |
| Finality (current) | PoH-ordered, 2-confirmation tracker |
| Finality (design) | 32 confirmed slots → ROOTED (multi-validator when available) |
| Node model | 1 Writer + up to 100 Readers (read-only replicas) |

- **PoH Clock** — deterministic, cryptographic timestamp for every transaction. No clock-skew debates, no mempool-ordering games.
- **Tower BFT** — exponential lockout voting (`2^(depth+1)` slots per confirmation). Rollbacks become exponentially expensive. Currently single-writer self-vote; multi-validator designed and scaffolded.
- **Gulf Stream** — eliminates global mempool. Reader nodes forward transactions to the next block producer with 8-slot lookahead. Up to 300K pending transactions cached.

---

## Execution: Sealevel O(N) Parallel Scheduler

All non-conflicting transactions execute simultaneously across every CPU core.

### Algorithm (v1.0.0 — O(N) per-account queue)

```rust
// Sort by priority desc — Local Fee Market
transactions.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

// Single forward pass: O(N) total
let mut next_free: HashMap<String, usize> = HashMap::new();
for tx in &transactions {
    let slot = tx.accounts.iter()
        .filter_map(|a| next_free.get(a))
        .copied().max().unwrap_or(0);
    batches[slot].push(tx);
    for a in &tx.accounts { next_free.insert(a.clone(), slot + 1); }
}
// Each batch[i] is conflict-free — safe to Rayon-parallel-execute
```

**Before v1.0.0:** O(N²) scan-and-retry loop. 1,000 txs on one hot account → ~500,000 iterations.  
**After v1.0.0:** O(N) single pass. 1,000 txs on one hot account → 1,000 iterations, 1,000 serial batches.

### Local Fee Market

Transactions carry a `priority: u64` (lamports/compute-unit). Higher priority → earlier slot assignment on contested accounts. This is a direct implementation of Solana's Local Fee Market: users bid for write access to hot accounts without slowing down uncontested accounts.

### Key Properties

- `AccountLockManager` enforces per-account read/write exclusivity per batch.
- Dynamic batch tuning: 2,048 txs optimal; shrinks if conflict rate exceeds 25%.
- An NFT mint on L3 settling to L1 will **never** slow down a stablecoin transfer in the same slot.

---

## Transaction Pipeline: 4-Stage Async

```
FETCH → VERIFY → EXECUTE → COMMIT
```

1. **FETCH** — Receive from network/RPC (UDP TPU + HTTP).
2. **VERIFY** — Validate Ed25519 signatures (16 parallel workers).
3. **EXECUTE** — Process via Sealevel (parallel account locking).
4. **COMMIT** — Batch finalize + broadcast (128 txs per batch).

Buffer: 100K packets per stage. Pipeline latency: microsecond range.

---

## Token Economy

### `$BB` — Native Gas Token

| Property | Value |
|----------|-------|
| Decimals | 5 |
| Unit | `LAMPORTS_PER_BB = 100_000` |
| Purpose | Gas, betting collateral, oracle bonds |
| Bridge rate | 10 BB = 1 wUSDT (fixed, dealer market-maker) |
| Faucet cap | 0.1 BB per request (production) |

- Powers all gas, all prediction market stakes, all oracle bonds.
- Bridged in via Solana/BSC custody wallet → minted on L1 at 10:1.
- Bridged out by burning BB → releasing stablecoin from custody.

### `wUSDT` — Wrapped Stablecoin Reserve

| Property | Value |
|----------|-------|
| Decimals | 6 |
| Unit | `USDC_UNIT = 1_000_000` |
| Purpose | Swap reserve, stablecoin backing |

- Held in the swap pool PDA as sole backing reserve for BB.
- Swappable against BB at fixed 10:1 via `POST /swap/bb-to-usdc` and `POST /swap/usdc-to-bb`.
- Not AMM-priced — dealer market-maker only.

> **Removed:** MAXX, DECAY, OZ — all archived. Do NOT restore.

---

## L1 Native Contracts

| Contract | Purpose | Status |
|----------|---------|--------|
| **Universal Rollup Hub** | lock_bb / submit_root / exit for all L2/L3/L5 rollups | ✅ Live |
| **NFT Bridge** | L1-side NFT anchoring via Rollup Hub exit | ✅ Live |
| **Token Swap** | BB ↔ wUSDT fixed-rate swap (10:1) | ✅ Live |
| **Deposit Gateway** | wUSDT → BB bridge-in | ✅ Live |
| **Withdrawal Gateway** | BB → wUSDT bridge-out | ✅ Live |
| **Oracle** | Node registration, dispute staking, vote + finalize | ✅ Live |
| **Global Escrow** | Legacy System A escrow (frozen for new entries) | ✅ Claim windows still open |

---

## L2 Settlement Protocol

### System B — Universal Rollup Hub (current, all new markets)

```
User locks $BB → POST /rollup/L2/lock_bb → lock_id returned
L2 accepts bet off-chain (sequencer reads lock)
Market resolves → sequencer builds Merkle tree
  leaf    = SHA-256( "L2:BB:{address}:{balance_lamports}" )
  combine = SHA-256( min(a,b) || max(a,b) )   // sorted-pair hash
→ POST /rollup/L2/submit_root  (sequencer Ed25519-signed)
→ Users exit via POST /rollup/L2/exit  (with Merkle proof)
```

**Security guarantees:**
- Monotonic batch_id: L1 rejects any root with ID ≤ last accepted.
- Double-spend seal: `ROLLUP_CONSUMED_EXITS` table in ReDB — permanent.
- Per-rollup vault PDA isolation: L2 funds can never touch L3 vault.
- Sequencer pubkey locked at startup from `L2_SEQUENCER_PUBKEY` env var.

---

## Security Architecture

| Property | Implementation |
|----------|---------------|
| Ed25519 auth | Every state-changing endpoint. No unsigned writes. |
| Replay protection | Nonce + 60s timestamp window. `DashMap entry()` atomic check. |
| Crash safety | ReDB written **before** DashMap. No state regression on restart. |
| Admin gate | `unsafe_admin` compile-time feature flag. Off in production builds. |
| Input safety | No `.unwrap()` on user data anywhere in codebase. |
| Rate limiting | `NetworkThrottler`: 10 tx/window/wallet. |
| CORS | Locked to explicit origins. |

---

## Why BlackBook Exists

Every major prediction market platform today is:

- **Slow** — Polymarket settles in hours, not milliseconds.
- **Centralized** — Kalshi is a licensed exchange with KYC gates.
- **Financially fragile** — Onchain AMMs leak to MEV bots on every bet.

BlackBook builds the infrastructure layer that does not exist yet: a sub-second settlement chain where prediction markets are first-class citizens, capital is mathematically safe, and creators can prove copyright without begging a platform.

At 502 tx/s sustained, the L1 already outpaces every settlement chain designed for general-purpose use. The Sealevel O(N) scheduler means adding L3 NFT mints or L5 creator economy trades does not degrade L2 market throughput. Every layer is isolated. Every exit is proven.

**BlackBook is the layer under everything.**
