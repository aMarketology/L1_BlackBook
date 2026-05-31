# BlackBook — Roadmap

> **L1 is live. L2 is running. The path from here to global scale.**
> Last updated: May 2026 — Universal Rollup Hub complete

---

## Architecture: 5-Layer Stack

```
┌───────────────────────────────────────────────────────────┐
│              BLACKBOOK L1  (Settlement Layer)             │
│  PoH · Tower BFT · Sealevel · Gulf Stream · Turbine       │
│  Global Escrow · Universal Rollup Hub · NFT Bridge        │
│  BB Settlement Economy (BB + wUSDT only)                 │
└──────┬──────────┬──────────┬───────────────────┘
       │          │          │          │
  ┌────▼────┐ ┌───▼───┐ ┌───▼───┐ ┌────▼────┐
  │   L2    │ │  L3   │ │  L4   │ │   L5    │
  │ Predict │ │  NFT  │ │ Yield │ │ Creator │
  │ Market  │ │Bridge │ │ Vault │ │omy     │
  └─────────┘ └───────┘ └───────┘ └─────────┘
```

Every L2–L5 layer settles to L1 via the Universal Rollup Hub:
1. Lock BB in per-rollup vault via `POST /rollup/:rollup_id/lock_bb`
2. Run autonomously (own DB, own execution)
3. Submit SHA-256 Merkle root via `POST /rollup/:rollup_id/submit_root`
4. L1 enforces: registered sequencer signature + monotonic batch_id
5. Users exit via `POST /rollup/:rollup_id/exit` with Merkle proof (BB or NFT)

---

## Phase 0 — Core Chain ✅ COMPLETE

| Component | Status |
|-----------|--------|
| PoH Clock (400ms, 64 ticks/slot, SHA-256) | ✅ |
| Tower BFT (exponential lockout, 2/3 supermajority) | ⚠️ Code present, **single-writer self-vote only** — not a real quorum (see note) |
| Gulf Stream (8-leader lookahead, 300K tx cache) | ✅ |
| Sealevel (Rayon parallel, batch 2,048, conflict serialization) | ✅ |
| Turbine (1,232-byte shreds, RS FEC 32+32) | ⚠️ Shredding/FEC works; shred Merkle proofs + signatures are placeholders, no network propagation yet |
| SVM (execute_transfer, blockhash queue, intra-block dedup) | ✅ |
| SvmAccountsDB (DashMap hot + ReDB durable) | ✅ |
| SPL Token engine (Mint, TokenAccount, ATA creation) | ✅ |
| JSON-RPC (28 Solana-compatible methods, port 8899) | ✅ |
| Writer/Reader relay (gRPC SubscribeBlocks, ForwardTx) | ✅ |
| Ed25519 transfers + replay protection | ✅ |
| Solana BSC watcher threads (custody balance monitoring) | ✅ |

> **Consensus reality note (⚠️ rows above):** the chain currently runs as a single trusted **writer** node with read-only **reader** replicas. Tower BFT voting, signed votes, leader block-signing, reader-side state verification, and a multi-validator set are designed/scaffolded but **not yet load-bearing**. See the "Consensus — Current Implementation Status" table in [Manifesto.md](Manifesto.md) and §3.2.1 of `root_whitepaper.md`. Making this real is the core of the planned **Layer 0** trust fabric.

---

## Phase 1 — BB Settlement Economy ✅ COMPLETE

| Token / Component | Status |
|-------------------|--------|
| `$BB` — $0.10 per BB (100,000 lamports/BB, 5 dec) | ✅ |
| `wUSDT` — wrapped reserve (1,000,000 micro/wUSDT, 6 dec) | ✅ |
| Token swap BB ↔ wUSDT (10:1 fixed-rate, pool-backed) | ✅ |
| Deposit gateway (wUSDT → BB 10:1, bridge-in) | ✅ |
| Withdrawal gateway (BB → wUSDT bridge-out) | ✅ |
| Oracle dispute staking in `$BB` lamports (100 BB min bond) | ✅ |
| 10:1 bootstrap invariant (BB == wUSDT × 10 on every boot) | ✅ |
| MAXX / DECAY / OZ — removed, archived in `archive/contracts/` | ✅ |

---

## Phase 2 — Security Hardening ✅ COMPLETE

| Item | Status |
|------|--------|
| Ed25519 on all write endpoints | ✅ |
| Nonce + 60s replay protection everywhere | ✅ |
| Atomic nonce entry (DashMap `entry()` — no TOCTOU) | ✅ |
| ReDB-first writes (disk before cache — crash safe) | ✅ |
| `unsafe_admin` compile-time gating (15 guards) | ✅ |
| No `.unwrap()` on user input | ✅ |
| Sealevel bounded retry (exponential backoff, no spin-lock) | ✅ |
| L2 monotonic block number enforcement | ✅ |
| Zero-sum escrow invariant checked on every settlement | ✅ |

---

## Phase 3 — L2 Prediction Market + Universal Rollup Hub ✅ COMPLETE

**Status:** Running at `:1234`. Rollup Hub live. New paths available alongside legacy escrow routes.

| Item | Status |
|------|--------|
| BB escrow deposit (`/escrow/deposit`) | ✅ |
| State root anchoring (`/escrow/submit-state-root`) | ✅ |
| Merkle proof withdrawal (`/escrow/withdraw`) | ✅ |
| Double-claim prevention (ReDB atomic) | ✅ |
| Contest state queries (`/escrow/contest/:id`) | ✅ |
| 30-day claim window (6,480,000 slots) | ✅ |
| L2 sequencer allowlist (multi-key) | ✅ |
| **Universal Rollup Hub `/rollup/:rollup_id/...`** | ✅ |
| **Per-rollup vault PDA isolation** | ✅ |
| **Multi-asset exit (BB + NFT)** | ✅ |
| **Permanent double-spend seal (ROLLUP_CONSUMED_EXITS)** | ✅ |
| **NFT bridge exit from L3** | ✅ |
| **Sequencer registry (authorized_sequencers DashMap)** | ✅ |
| End-to-end settlement test on Hetzner mainnet | ⚠️ Pending |
| L2 sequencer updated to use new `/rollup/L2/` paths | ⚠️ Pending |

---

## Phase 4 — Wallet & Frontend 🔄 IN PROGRESS

| Item | Status |
|------|--------|
| TypeScript wallet (zero compile errors) | ✅ |
| `tokens.ts` — `$BB` and `wUSDT` registered | ✅ |
| SwapModal — BB ↔ wUSDT only | ✅ |
| Price charts — BB ($0.10 fixed) | ✅ |
| MAXX / $oz UI removed from wallet | ⚠️ In progress |
| Balance push over WebSocket (real-time updates) | ✅ |
| Production Hetzner deployment (Docker + Nginx) | ⚠️ In progress |
| CORS locked to explicit origins | ❌ TODO |
| Shard B PIN fix (verify against stored hash) | ❌ TODO |

---

## Phase 5 — L3: NFT Bridge 🔄 L1 COMPLETE / L3 ENGINE PENDING

L1 side of the NFT bridge is fully implemented via the Universal Rollup Hub.
NFT exits from L3 mint `AnchoredNft` records directly on L1 via Merkle proof.

| Item | Status |
|------|--------|
| L1 NFT anchor (`nft_bridge::put_nft`) | ✅ |
| NFT exit handler (Merkle proof + mint) | ✅ |
| NFT leaf canonical format | ✅ |
| L3 execution engine (off-chain) | ❌ |
| L3 sequencer (builds NFT Merkle trees) | ❌ |
| L3 TypeScript SDK | ❌ |

---

## Phase 6 — L4: Yield Vaults 📋 PLANNED

Auto-compounding yield vaults. Users lock BB, vault allocates to L2/L3 strategies, profits settle back.

| Item | Status |
|------|--------|
| Vault deposit/withdraw contract | ❌ |
| Strategy executor (LMSR house-edge compounding) | ❌ |
| Yield accounting (per-epoch APY) | ❌ |

---

## Phase 7 — L5: Creator Economy Rollup 📋 PLANNED

Creator token launchpad. Creators lock $BB on L1 to seed their bonding curve on L5.
L1 bridge is fully wired (`rollup_id = "L5"`). Execution engine not built.

**L1 is ready. Required to start L5:**
- Creator locks $BB via `POST /rollup/L5/lock_bb`
- L5 engine credits rollup-$BB, runs bonding curve
- L5 sequencer posts Merkle roots of balances
- Holders exit back to L1 via `POST /rollup/L5/exit`

**Requirements to launch (proposed):**
- Creator must hold sufficient $BB to seed the vault
- Minimum $BB seed lock (e.g. 100 BB = 10,000,000 lamports)
- Bonding curve price formula: `P(s) = SLOPE × s` (linear, deterministic)
- Graduation threshold: exits to free trading once reserve hits a target

**Anti-rug mechanics:**
- Creator seed locked for minimum 30 days (enforced by L5 sequencer — batch_id window)
- All trades route through L5 bonding curve — no manual price control

| Item | Status |
|------|--------|
| L1 lock_bb bridge (`/rollup/L5/lock_bb`) | ✅ |
| L1 submit_root bridge | ✅ |
| L1 BB exit bridge | ✅ |
| Legacy L5 state root migration | ✅ |
| L5 bonding curve engine | ❌ |
| L5 sequencer | ❌ |
| L5 TypeScript SDK | ❌ |
|------|--------|
| Meme token factory contract (parameterized bonding curve) | ❌ |
| $oz ownership gate at launch | ❌ |
| wUSDT seed backing lock | ❌ |
| Graduation → free trading mechanism | ❌ |
| Creator fee distribution (1% of buys) | ❌ |
| L5 launchpad UI | ❌ |

---

## Phase 8 — Creator Shield (L3 NFT Copyright) 📋 PLANNED

Creators mint a cryptographic fingerprint of their work on-chain. Any downstream copy gets a deterministic provenance trail verifiable without a third-party registry.

| Item | Status |
|------|--------|
| Fingerprint mint (SHA-256 + creator Ed25519) | ❌ |
| Provenance chain (link derivative to original) | ❌ |
| Copyright enforcement hooks (L3 → L1 proof) | ❌ |
| Browser extension for automatic detection | ❌ |

---

## Infrastructure Priorities (Ongoing)

| Item | Priority |
|------|----------|
| CORS locked to explicit origins | P0 |
| `real_wallets/` out of Docker image | P0 |
| Shard B PIN stored hash fix | P0 |
| Multi-validator deployment (2nd Hetzner node) | P1 |
| Monitoring: Prometheus + Grafana on chain metrics | P1 |
| Load test: 10,000 concurrent escrow deposits | P1 |
| Chaos test: crash at mid-write, verify ReDB consistency | P2 |
