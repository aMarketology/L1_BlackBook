# BlackBook — Engineering Roadmap

> **Last updated: June 2026 — v1.0.0 production milestone tagged.**
> Production node: `91.98.196.34:8080` · Tag: `v1.0.0` (commit `4224b0c`)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    BLACKBOOK L1  (Settlement Layer)                 │
│   PoH · Tower BFT · Sealevel O(N) · Gulf Stream · Turbine          │
│   Universal Rollup Hub · NFT Bridge · SPL Token Engine             │
│   BB + wUSDT economy  ·  Ed25519 auth everywhere                   │
└────────┬──────────────┬──────────────┬──────────────┬──────────────┘
         │              │              │              │
    ┌────▼────┐    ┌────▼────┐    ┌───▼────┐    ┌───▼─────┐
    │   L2    │    │   L3    │    │   L4   │    │   L5    │
    │ Predict │    │  NFT    │    │ Yield  │    │ Creator │
    │ Markets │    │ Bridge  │    │ Vaults │    │ Economy │
    └─────────┘    └─────────┘    └────────┘    └─────────┘
```

Every rollup layer settles to L1 via the Universal Rollup Hub:
1. Users lock `$BB` → `POST /rollup/:rollup_id/lock_bb`
2. Rollup runs autonomously (own DB, own execution engine)
3. Sequencer anchors Merkle root → `POST /rollup/:rollup_id/submit_root` (signature-gated)
4. Users exit with Merkle proof → `POST /rollup/:rollup_id/exit`

---

## ✅ PHASE 0 — Core Chain (COMPLETE)

| Component | Status |
|-----------|--------|
| PoH Clock (400ms slots, SHA-256, 64 ticks/slot) | ✅ |
| Tower BFT (exponential lockout, 2/3 supermajority design) | ✅ Single-writer today |
| Gulf Stream (8-leader lookahead, 300K tx cache) | ✅ |
| Sealevel parallel execution (Rayon thread pool) | ✅ |
| **O(N) per-account queue scheduler** | ✅ v1.0.0 |
| **Local Fee Market (priority lanes on hot accounts)** | ✅ v1.0.0 |
| Turbine shredding (1,232-byte UDP shreds, RS FEC 32+32) | ✅ Shredding works; propagation scaffolded |
| SvmAccountsDB (DashMap hot + ReDB durable) | ✅ |
| SPL Token engine (Mint, TokenAccount, ATA) | ✅ |
| JSON-RPC (28 Solana-compatible methods, port 8899) | ✅ |
| Writer/Reader relay (gRPC SubscribeBlocks, ForwardTx) | ✅ |
| Ed25519 all write endpoints + replay protection | ✅ |
| UDP TPU (port 8003, bincode, 8 workers) | ✅ |

---

## ✅ PHASE 1 — BB Settlement Economy (COMPLETE)

| Component | Status |
|-----------|--------|
| `$BB` native gas token (5 decimals, 100K lamports/BB) | ✅ |
| `wUSDT` wrapped stablecoin (6 decimals) | ✅ |
| BB ↔ wUSDT fixed-rate swap (10:1) | ✅ |
| Deposit gateway (wUSDT → BB) | ✅ |
| Withdrawal gateway (BB → wUSDT) | ✅ |
| Oracle dispute staking in BB | ✅ |
| MAXX / DECAY / OZ removed, archived | ✅ |

---

## ✅ PHASE 2 — Security Hardening (COMPLETE)

| Item | Status |
|------|--------|
| Ed25519 on all state-changing endpoints | ✅ |
| Nonce + 60s timestamp replay protection | ✅ |
| Atomic nonce (`DashMap entry()` — no TOCTOU) | ✅ |
| ReDB-first writes (disk before cache) | ✅ |
| `unsafe_admin` compile-time feature gate | ✅ |
| No `.unwrap()` on user input | ✅ |
| Rate limiting (NetworkThrottler, 10 tx/window/wallet) | ✅ |
| CORS locked to explicit origins | ✅ |

---

## ✅ PHASE 3 — Universal Rollup Hub (COMPLETE)

| Item | Status |
|------|--------|
| Per-rollup vault PDA (`rollup_vault_address(rollup_id)`) | ✅ |
| `lock_bb` — user locks BB into vault | ✅ |
| `submit_root` — sequencer anchors Merkle root (sig-gated) | ✅ |
| `exit` — user exits BB with Merkle proof | ✅ |
| Multi-asset exit (BB + NFT) | ✅ |
| Permanent double-spend seal (`ROLLUP_CONSUMED_EXITS`) | ✅ |
| Monotonic batch_id enforcement | ✅ |
| L2 sequencer pubkey locked: `bc9359a9…` | ✅ |
| L3/L5 sequencer pubkeys registered | ✅ |

---

## ✅ PHASE 4 — L2 Sequencer v1 (COMPLETE — v1.0.0)

**502 tx/s validated on Hetzner CX42. 8-step smoke test passes on live mainnet.**

| Item | Status |
|------|--------|
| TypeScript npm workspace (shared, l2, l3, l5, bridge-watcher) | ✅ |
| PoH slot subscription (L1 WebSocket) | ✅ |
| lock_bb ingest + consume (L1 auth) | ✅ |
| Off-chain prediction market engine | ✅ |
| SHA-256 Merkle tree + state root generation | ✅ |
| Batch sealing every 25 slots | ✅ |
| `submit_root` with sequencer Ed25519 signature | ✅ |
| Merkle proof generation per user | ✅ |
| `exit` — user redeems on L1 with proof | ✅ |
| Double-spend guard (L1 403 on re-exit) | ✅ |
| Full 8-step smoke test on `91.98.196.34:8080` | ✅ |
| Stable compiled-JS run (no tsx watch) | ✅ |

---

## 🔄 PHASE 5 — Frontend Integration (CURRENT PRIORITY)

Wire the React wallet at `blackbook-wallet/` to the live L2 sequencer.

| Item | Status |
|------|--------|
| L1 balance fetch (`GET /balance/:addr`) | ✅ Already wired |
| L2 balance fetch (`GET {L2}/balances/:addr`) | ❌ |
| Lock BB into L2 (`POST /rollup/L2/lock_bb` via wallet) | ❌ |
| Create market (L2 POST `/markets`) | ❌ |
| Place bet (L2 POST `/markets/:id/bet`) | ❌ |
| Exit to L1 with Merkle proof | ❌ |
| Market list + live odds display | ❌ |
| Transaction history from L1 | ❌ |
| Environment config (`VITE_L2_URL`, `VITE_L1_URL`) | ❌ |

---

## 📋 PHASE 6 — Deploy L2 to Hetzner

Run the L2 sequencer in production alongside L1 on the same server.

| Item | Status |
|------|--------|
| Dockerfile for L2 sequencer | ❌ |
| `docker-compose.prod.yml` L2 service entry | ❌ |
| `L2_SEQUENCER_PRIVKEY` in Hetzner `.env` | ❌ |
| Nginx proxy for L2 (`:7072` internal → `/l2/`) | ❌ |
| Health check endpoint on L2 | ❌ |
| PM2 or systemd watchdog | ❌ |

---

## 📋 PHASE 7 — Performance: Kernel Bypass (XDP / io_uring)

Eliminate OS network stack overhead. Target: hardware wire-speed ingestion on :8003.

| Upgrade | Impact |
|---------|--------|
| **XDP (eXpress Data Path)** — intercept UDP at NIC before Linux kernel | Latency: ms → µs. Unlocks true 240K TPS ceiling |
| **eBPF packet filter** — drop malformed packets pre-Rust | DDoS resilience at zero CPU cost |
| **`io_uring`** — async disk I/O for ReDB flushes | Eliminates I/O blocking on CPU threads |
| **NUMA-aware thread pinning** — bind Rayon workers to physical cores | Eliminates cross-socket cache misses |

**Prerequisite:** Hetzner dedicated with NIC that supports XDP offload (CX42+ qualifies).

---

## 📋 PHASE 8 — Trustlessness: ZK Validity Proofs

Replace sequencer-authority trust with mathematical proof.

| Upgrade | Impact |
|---------|--------|
| **ZK-SNARK per batch** — L2 proves every bet/payout follows LMSR rules | L1 can't be fooled even if sequencer key is stolen |
| **ZK circuit for Merkle root** — proves state root is output of valid transitions | Eliminates the "honest sequencer assumption" |
| **Recursive proof aggregation** — 1,000 market resolutions → 1 proof | Amortizes proving cost across batch size |

**Stack candidates:** `risc0` (Rust-native RISC-V zkVM), `sp1` (Succinct), or `halo2`.  
**Estimated effort:** 4–8 weeks for a single-circuit MVP.

---

## 📋 PHASE 9 — Infinite Scale: Data Availability + State Pruning

Prevent state bloat from killing performance at high TPS.

| Upgrade | Impact |
|---------|--------|
| **Hot/Cold split** — ReDB holds last 48h; older blocks to cold storage | NVMe never fills; RAM lookups stay fast |
| **Snapshot system** — periodic full-state snapshots to S3/Arweave | New nodes sync in minutes, not days |
| **DA separation layer** — post block headers to Celestia/EigenDA | Historical auditability without local storage |
| **State pruning thread** — background task prunes finalized blocks beyond epoch | Automatic, no manual intervention |

---

## 📋 PHASE 10 — Resilience: HA Sequencer Failover

Eliminate the L2 sequencer as a single point of failure.

| Upgrade | Impact |
|---------|--------|
| **Active-Passive cluster** — secondary L2 streams WAL from primary | Failover in < 500ms on primary crash |
| **WAL replication** — SQLite WAL via Litestream or rsync-over-SSH | Zero data loss on failover |
| **Heartbeat monitor** — secondary auto-promotes on primary timeout | No manual intervention needed |
| **L1 multi-validator** — Tower BFT with real validator set | Eliminates single Hetzner node as L1 SPOF |

---

## Priority Summary

| Phase | Priority | Effort | Unlocks |
|-------|----------|--------|---------|
| 5 — Frontend | **NOW** | 1–2 weeks | Live users, revenue |
| 6 — L2 on Hetzner | **NOW** | 2 days | Production L2 |
| 7 — XDP | High | 2–3 weeks | 240K TPS ceiling |
| 8 — ZK Proofs | High | 4–8 weeks | Trustless L2 |
| 9 — DA + Pruning | Medium | 2–3 weeks | Infinite scale |
| 10 — HA Failover | Medium | 1–2 weeks | 99.99% uptime |
