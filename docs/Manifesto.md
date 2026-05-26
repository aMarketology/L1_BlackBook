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

| Parameter | Value |
|-----------|-------|
| Slot time | 400 ms |
| Block capacity | 50,000 txs/block |
| Theoretical TPS | 125,000 |
| Sustained TPS (tested) | 230 |
| Epoch length | 432,000 slots (~3 days) |
| Finality | 32 confirmations → ROOTED (irreversible) |
| Signature scheme | Ed25519 |
| Storage | ReDB (ACID) + DashMap (hot cache) |
| Language | Rust — no VM overhead |

### Consensus: PoH + Tower BFT

- **Proof of History** provides a deterministic, cryptographic timestamp for every transaction — no clock-skew, no mempool games.
- **Tower BFT** uses exponential lockout voting (`2^(depth+1)` slots per confirmation), making rollbacks exponentially expensive.
- **Gulf Stream** eliminates the global mempool. Readers forward transactions directly to the upcoming Writer with an 8-slot lookahead, pre-filling its queue before the slot arrives.

### Execution: Sealevel Parallel Processing

All non-conflicting transactions execute **simultaneously** across every CPU core. `AccountLockManager` enforces per-account read/write exclusivity per batch. Dynamic batch tuning: 2,048 txs optimal; auto-shrinks if conflict rate exceeds 25%.

### Block Propagation: Turbine Shredding

Shred size: 1,232 bytes (UDP MTU). 32 data + 32 coding shreds per FEC set (50% Reed-Solomon erasure). Max fanout: 200 nodes per hop — 2 hops reach 40,000 nodes.

---

## The Three-Token Economy

BlackBook runs a closed, self-reinforcing token economy with one stable foundation and two dynamic assets.

### `$BB` — The Native Gas Token

- **1 BB = $0.10 USD.** Fixed. No oracle. No float. 10 BB = 1 wUSDT.
- 5 decimal places: 1 BB = 100,000 lamports. Minimum unit: $0.000001.
- Backed 10:1 by wUSDT reserves (enforced on-chain at every boot).
- Powers all gas, all escrow deposits, all prediction market stakes.
- Bridged in via Solana/BSC custody wallet → minted on L1 at 10:1.
- Bridged out by burning BB → releasing stablecoin from custody.

### `wUSDT` — Wrapped Stablecoin Reserve

- 6 decimal places. 1 wUSDT = 1,000,000 micro-units.
- Held in the swap pool PDA as backing reserve for BB.
- Powers the MAXX bonding curve and $oz vault.
- Not user-tradeable directly — moves through the swap contract.

### `$XX / MAXX` — Bonding-Curve Governance Token

- 12 decimal places (picoMAXX). Linear bonding curve: `P(s) = 5×10⁻⁸ × s`
- Reserve held in wUSDT. Price rises as supply grows — no inflation surprise.
- Burned to recharge $oz tokens (value sink).

### `$oz` — Premium Access Token

- NFT-style per-instance object backed by wUSDT.
- Each `$oz` leaks 1% of its backing into the treasury per use (geometric decay: ~36.6% remains after 100 uses).
- After 100 uses: dead. Recharge by burning 5 MAXX + paying 2 wUSDT fee (1.5 wUSDT with a long-stake lock).
- Stake lock gives a 25% recharge discount.
- All 4 write endpoints fully Ed25519 authenticated.

---

## Smart Contracts (Layer 1 Native Modules)

| Contract | Purpose |
|----------|---------|
| **Global Escrow** | PDA vault for all open markets. Deposits, Merkle roots, winner payouts. |
| **Deposit Gateway** | wUSDT → BB 10:1 bridge-in. Custody wallet monitoring on Solana + BSC. |
| **Withdrawal Gateway** | BB → wUSDT bridge-out. Burn BB, release stablecoin. |
| **Token Swap** | BB ↔ wUSDT fixed-rate swap (10:1). Pool-backed, no private key. |
| **MAXX Bonding Curve** | Linear curve buy/sell for $XX governance token. |
| **$oz Contract** | Mint, use, recharge, stake. wUSDT-backed premium access token. |
| **Lightning Gateway** | BTC Lightning → BB at $0.10/BB rate. BTCPayServer webhook. |

---

## L2 Settlement Protocol

```
L2 bets
  → Dealer aggregates outcomes
  → settle_market_and_generate_root(winners)
  → SHA-256 sorted-pair Merkle tree → 32-byte root
  → POST /escrow/submit-state-root  (L2 sequencer signed)
  → Users withdraw via POST /escrow/withdraw  (with Merkle proof)
```

**Security guarantees:**
- Zero-sum invariant: `total_deposited == total_payout + house_rake`
- Monotonic block numbers: L1 rejects any state root with `l2_block_number ≤` last accepted
- Claim window: 6,480,000 slots (~30 days) from settlement
- Double-claim prevention: atomic nonce check in ReDB before DashMap

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
