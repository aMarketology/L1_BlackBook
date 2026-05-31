# BlackBook — Manifesto

> **The Ultimate Vessel for Fast Transactions, Prediction Markets, and Creator Copyright Protection.**

---

## The Vision

BlackBook is a purpose-built, three-layer blockchain stack designed to serve three converging global needs:

1. **Layer 1 — The Vessel.** A hyper-fast, stable base-layer blockchain for sub-second transaction finality, capital bridging, and cryptographic truth.
2. **Layer 2 — The Rollup.** A scalable execution environment built specifically for high-frequency prediction market trading, settling back to L1.
3. **Layer 3 — The Creator Shield.** A specialized app-chain for creators to mint, track, and enforce NFT copyrights across the open internet.

The Layer 1 does not try to do everything. It **perfectly anchors everything**.

---

## Layer 1 — The Vessel

### Chain Specs

| Parameter | Value | Source of truth |
|-----------|-------|-----------------|
| Slot time | 400 ms | `main.rs::POH_SLOT_DURATION_MS` |
| Hashes per tick / ticks per slot | 12,500 / 64 | `main.rs::POH_HASHES_PER_TICK`, `POH_TICKS_PER_SLOT` |
| Block capacity | 240,000 txs/block | `poh_blockchain.rs::MAX_TXS_PER_BLOCK` |
| Theoretical TPS | 600,000 (240k ÷ 0.4s) | derived |
| Sustained TPS (tested) | ~230 (single-node REST path) | informal |
| Epoch length | 432,000 slots (~2 days at 400 ms) | `main.rs::POH_SLOTS_PER_EPOCH` |
| Finality (tx tracker) | 2 confirmations → Finalized | `runtime/poh_service.rs::CONFIRMATIONS_REQUIRED` |
| Finality (Tower rooting) | 32 consecutive confirmed slots → Rooted | `consensus.rs::MAX_TOWER_DEPTH` — multi-validator design, see status below |
| Signature scheme | Ed25519 (transactions/endpoints) | `svm/sigverify.rs`, `auth.rs` |
| Storage | ReDB (ACID) + DashMap (hot cache) | `storage/mod.rs` |
| Language | Rust — no VM overhead | — |

### Consensus: PoH + Tower BFT

- **Proof of History** provides a deterministic, cryptographic timestamp for every transaction — no clock-skew, no mempool games. **(Live.)**
- **Tower BFT** uses exponential lockout voting (`2^(depth+1)` slots per confirmation), making rollbacks exponentially expensive. **(Designed; see status below.)**
- **Gulf Stream** eliminates the global mempool. Readers forward transactions directly to the upcoming Writer with an 8-slot lookahead, pre-filling its queue before the slot arrives. **(Live for tx forwarding.)**

### Consensus — Current Implementation Status (read this)

The production chain runs as a **single writer node** with one or more read-only replica (Reader) nodes. To keep marketing and engineering aligned, the following is the honest state of the consensus stack as implemented in `runtime/consensus.rs`, `src/poh_blockchain.rs`, `src/relay/mod.rs`, and `src/reader/mod.rs`:

| Component | Designed | Live today |
|-----------|----------|-----------|
| PoH clock (400 ms slots) | ✅ | ✅ |
| Sealevel parallel execution | ✅ | ✅ |
| Gulf Stream tx forwarding | ✅ | ✅ |
| Writer → Reader block streaming (gRPC) | ✅ | ✅ |
| Tower BFT multi-validator voting | ✅ | ❌ — only the writer self-votes (stake 1000), so "supermajority" is always 100% |
| Ed25519-signed votes / P2P vote gossip | ✅ | ❌ — `Vote::signature` is a plain SHA-256 of public fields (no key), and votes are not gossiped |
| Leader signature on blocks | — | ❌ — `FinalizedBlock` carries a `leader` field but no signature |
| Reader independent state verification | — | ❌ — Readers verify the hash-chain + PoH linkage only, then **trust** the writer's state (`reader/mod.rs`: "Reader doesn't re-execute") |
| Turbine shred signatures | ✅ | ❌ — shred `signature` is a `format!("sig_{leader}_{index}")` placeholder |

**Bottom line:** today BlackBook is a high-performance, centrally-sequenced settlement chain (the writer is trusted). The Solana-style decentralization primitives are scaffolded but not yet load-bearing. Genuine BFT requires: leader block-signing, Ed25519-signed votes with P2P gossip, reader-side state verification, and ≥ 2 independent validators. These are the natural candidates for the planned **Layer 0** trust fabric.

### Execution: Sealevel Parallel Processing

All non-conflicting transactions execute **simultaneously** across every CPU core. `AccountLockManager` enforces per-account read/write exclusivity per batch. Dynamic batch tuning: 2,048 txs optimal; auto-shrinks if conflict rate exceeds 25%.

### Block Propagation: Turbine Shredding

Shred size: 1,232 bytes (UDP MTU). 32 data + 32 coding shreds per FEC set (50% Reed-Solomon erasure). Max fanout: 200 nodes per hop — 2 hops reach 40,000 nodes.

---

## The Token Economy

BlackBook runs a two-token settlement economy. MAXX, DECAY, and OZ have been removed and are archived in `archive/contracts/`.

### `$BB` — The Native Gas Token

- **1 BB = $0.10 USD.** Fixed. No oracle. No float. 10 BB = 1 wUSDT.
- 5 decimal places: 1 BB = 100,000 lamports. Minimum unit: $0.000001.
- Backed 10:1 by wUSDT reserves (enforced on-chain at every boot).
- Powers all gas, all prediction market stakes, all oracle bonds.
- Bridged in via Solana/BSC custody wallet → minted on L1 at 10:1.
- Bridged out by burning BB → releasing stablecoin from custody.

### `wUSDT` — Wrapped Stablecoin Reserve

- 6 decimal places. 1 wUSDT = 1,000,000 micro-units.
- Held in the swap pool PDA as the sole backing reserve for BB.
- Swappable against BB at the fixed 10:1 rate via `POST /swap/bb-to-usdc` and `POST /swap/usdc-to-bb`.
- Not AMM-priced — dealer market-maker only.

> **Removed:** MAXX (bonding-curve governance), DECAY (per-instance utility), OZ (premium access) — all archived. Do NOT restore.

---

## Smart Contracts (Layer 1 Native Modules)

| Contract | Purpose | Status |
|----------|---------|--------|
| **Global Escrow** | Legacy PDA vault for L2 prediction markets (System A). Deposits, Merkle roots, winner payouts. | ✅ Live — freeze new entries |
| **Universal Rollup Hub** | New settlement path for all L2/L3/L5 rollups. lock_bb / submit_root / exit. | ✅ Live |
| **NFT Bridge** | L1-side NFT anchoring. put_nft / get_nft via Rollup Hub exit. | ✅ Live |
| **Deposit Gateway** | wUSDT → BB 10:1 bridge-in. Custody wallet monitoring on Solana + BSC. | ✅ Live |
| **Withdrawal Gateway** | BB → wUSDT bridge-out. Burn BB, release stablecoin. | ✅ Live |
| **Token Swap** | BB ↔ wUSDT fixed-rate swap (10:1). Pool-backed, no private key. | ✅ Live |
| **Oracle** | Node registration, dispute staking ($BB), vote + finalize. | ✅ Live |

---

## L2 Settlement Protocol

Two settlement paths co-exist during migration. All new markets use System B.

### System B — Rollup Hub (current)
```
User locks $BB → POST /rollup/L2/lock_bb → lock_id returned
L2 accepts bet off-chain (sequencer reads lock)
Market resolves → sequencer builds Merkle tree
  leaf = SHA-256( "L2:BB:{address}:{balance_lamports}" )  // UTF-8 string
  combine = SHA-256( min(a,b) || max(a,b) )                // sorted-pair
→ POST /rollup/L2/submit_root  (sequencer signed)
→ Users exit via POST /rollup/L2/exit  (with Merkle proof)
```

### System A — Legacy Global Escrow (frozen, claim windows still open)
```
Dealer pre-funds escrow → POST /escrow/deposit
Market resolves → build Merkle tree
  leaf = SHA-256( bs58_decode(wallet)[32] || payout_spl_u64_le[8] )  // binary
→ POST /escrow/submit-state-root  (L2 sequencer binary-signed)
→ Users withdraw via POST /escrow/withdraw  (with Merkle proof)
```

**Security guarantees (both systems):**
- Monotonic batch/block ID: L1 rejects any root with ID ≤ last accepted
- Double-claim prevention: `ROLLUP_CONSUMED_EXITS` permanent seal in ReDB
- Claim window (System A only): 6,480,000 slots (~30 days) from settlement
- System B: per-rollup vault PDA — balances are ground truth, no zero-sum needed

---

## Security Architecture

- Ed25519 on every state-changing endpoint — no unsigned writes.
- Nonce + 60-second timestamp window — no replay attacks.
- ReDB written **before** DashMap — crash-safe, no state regression on restart.
- `unsafe_admin` feature flag — admin endpoints compile-time gated for production.
- No `.unwrap()` on user input anywhere in the codebase.
- Sealevel bounded retry with exponential backoff — no infinite spin-locks.

---

## Why BlackBook Exists

Every major prediction market platform today is either:
- Slow (Polymarket settles in hours, not seconds)
- Centralized (Kalshi is a licensed exchange with KYC gates)
- Financially fragile (onchain AMMs leak to MEV bots on every bet)

BlackBook builds the infrastructure layer that doesn't exist yet: a sub-second settlement chain where prediction markets are first-class citizens, capital is mathematically safe, and creators can prove copyright without begging a platform.

**BlackBook is the layer under everything.**
