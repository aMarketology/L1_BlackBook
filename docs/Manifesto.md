# BlackBook — Manifesto

> **The Ultimate Vessel for Fast Transactions, Prediction Markets, and Creator Copyright Protection.**

---

## The Vision

BlackBook is a **Consortium / Permissioned Layer 1** — a purpose-built, three-layer blockchain stack
modeled after the institutional infrastructure that powers global finance. Like Visa's settlement
backbone or Swift's interbank rails, BlackBook is not open to anonymous participation. It is a
vetted, exclusive network of institutional-grade validator nodes delivering sub-second finality
with the security guarantees of a private enterprise network and the auditability of a public chain.

1. **Layer 1 — The Vessel.** A hyper-fast, permissioned base-layer blockchain for sub-second transaction finality, capital bridging, and cryptographic truth. Only whitelisted validators produce and verify blocks.
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

### Consensus: PoH + Tower BFT (Permissioned Validator Set)

- **Proof of History** provides a deterministic, cryptographic timestamp for every transaction — no clock-skew, no mempool games.
- **Tower BFT** uses exponential lockout voting (`2^(depth+1)` slots per confirmation), making rollbacks exponentially expensive. Voting power is denominated in `u64` lamports — no floating-point arithmetic anywhere in the consensus path.
- **Gulf Stream** eliminates the global mempool. Readers forward transactions directly to the upcoming Writer with an 8-slot lookahead, pre-filling its queue before the slot arrives.
- **Validator Whitelist** (`APPROVED_VALIDATORS`): an on-chain-admin-controlled registry binding Ed25519 public key → static IP. UDP packets from unknown IPs are dropped at the socket layer before any signature verification — zero CPU cost for spam.

### Execution: Sealevel Parallel Processing

All non-conflicting transactions execute **simultaneously** across every CPU core. `AccountLockManager` enforces per-account read/write exclusivity per batch. Dynamic batch tuning: 2,048 txs optimal; auto-shrinks if conflict rate exceeds 25%.

### Block Propagation: Turbine Permissioned Gossip

Shred size: 1,232 bytes (UDP MTU). 32 data + 32 coding shreds per FEC set (50% Reed-Solomon erasure).

Topology: **VIP Mesh** — the Writer shreds a block and distributes shreds across the approved validator set. Each approved node, trusting the others by whitelist membership, immediately re-broadcasts its shred to the rest of the peer group. The Writer expends a fraction of the bandwidth; the block propagates globally across all consortium nodes in milliseconds. Nodes outside the whitelist never receive a single shred.

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

BlackBook builds the infrastructure layer that doesn't exist yet: a sub-second, permissioned settlement chain where prediction markets are first-class citizens, capital is mathematically safe, and creators can prove copyright without begging a platform. The consortium model means no MEV bots, no Sybil attacks, no anonymous validator pollution — only trusted institutions with skin in the game.

**BlackBook is the exclusive layer under everything.**
