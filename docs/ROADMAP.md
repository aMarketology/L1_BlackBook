# BlackBook — Engineering Roadmap

> **Last updated: June 2026 — v1.0.2. Rotating Leader Schedule live. Multi-validator consensus.**
> Production node: `91.98.196.34:8080` (migrating to Cherry bare-metal) · Last tag: `v1.0.2`
>
> **What the L1 is:** an **asset-custody ledger, state machine, and transaction execution environment**.
> Its only relationship with keys is to (1) store a balance against a public key, (2) receive an
> Ed25519-signed transaction, and (3) verify the signature before executing. It never generates,
> holds, or transmits user private keys or mnemonics — those are created and kept client-side only.
>
> **Network model: Consortium / Permissioned Layer 1 with Rotating Leaders.**
> Every validator runs `--mode validator`, consults the same deterministic `LeaderSchedule` from
> `config.toml`, and dynamically switches between Writer (produce blocks) and Reader (sync + verify)
> at slot boundaries. Leaders rotate in contiguous 4-slot tenures (1.6s each).
>
> **v1.0.2 — rotating leader consensus:**
> - 👑 **Rotating Leader Schedule** — `--mode validator`, multi-validator `LeaderSchedule` from
>   `config.toml` stakes, contiguous 4-slot tenures, dynamic role switching, `GET /validators`
> - 🧹 **Zero log spam** — leadership transitions logged once, not every slot
> - 📡 **Dynamic reader proxy** — non-leader POSTs forward to current leader automatically
> - 🌊 **Gulf Stream tx forwarding** — non-leader nodes forward txs to upcoming leaders
>
> **v1.0.1 — pure-L1 hardening:**
> - 🧹 **Removed off-mission fiat-onramp code** — the dead Bitcoin Lightning / BTCPayServer gateway (`contracts/lightning_gateway/`, orphaned, never compiled) and the dead Transak JWT webhook (`watcher/webhook.rs`). The L1 is settlement + execution, not a fiat payment aggregator. Build is now warning-clean.
> - 🔑 **No server-side key generation** — an experimental `POST /keypair/generate` endpoint was removed. Key generation must be client-side only: no custodial keys, no unauthenticated CPU-DoS surface against the PoH clock.
>
> **Post-v1.0.0 changes:**
> - 🔐 Sequencer keys rotated (compromised keys retired). Live L2 sequencer pubkey is now `fb78242e…` (was `bc9359a9…`).
> - 🛡️ **Rollup exit path hardened** against cross-batch double-exit — see Phase 3.5 below.
> - 🔧 L3 NFT sequencer transfer-ownership bug fixed; L3 mint/transfer SDK helpers added.
> - 📡 **Permissioned Turbine 7A/7B/7C live** — static `ValidatorRegistry`, UDP source-IP gate, Ed25519-signed tick-shreds, and the f64→u64 `LeaderSchedule` rewrite (Phase 7 below).
> - 🚚 **Cherry bare-metal migration in progress** — Hetzner flagged blockchain workloads; node moving to a Cherry host (Phase 7.5).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│           BLACKBOOK L1  (Consortium / Permissioned Settlement)      │
│   PoH · Tower BFT · Sealevel O(N) · Gulf Stream · Turbine          │
│   Universal Rollup Hub · NFT Bridge · SPL Token Engine             │
│   BB + wUSDT economy  ·  Ed25519 auth  ·  Whitelist Validator Mesh │
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
| Tower BFT (exponential lockout, 2/3 supermajority design) | ✅ Multi-validator from registry stakes |
| Gulf Stream (8-leader lookahead, 300K tx cache) | ✅ |
| Sealevel parallel execution (Rayon thread pool) | ✅ |
| **O(N) per-account queue scheduler** | ✅ v1.0.0 |
| **Local Fee Market (priority lanes on hot accounts)** | ✅ v1.0.0 |
| Turbine shredding (1,232-byte UDP shreds, RS FEC 32+32) | ✅ Shredding works; permissioned auth live (7A/7B/7C), full block-shred mesh = Phase 7D |
| SvmAccountsDB (DashMap hot + ReDB durable) | ✅ |
| SPL Token engine (Mint, TokenAccount, ATA) | ✅ |
| JSON-RPC (28 Solana-compatible methods, port 8899) | ✅ |
| Writer/Reader relay (gRPC SubscribeBlocks, ForwardTx) | ✅ |
| Ed25519 all write endpoints + replay protection | ✅ |
| UDP TPU (port 8003, bincode, 8 workers) | ✅ |
| **Rotating Leader Schedule** — `--mode validator`, multi-validator from `config.toml` | ✅ v1.0.2 |
| **Contiguous leader tenures** — 4 slots (1.6s) per leader, stake-proportional | ✅ v1.0.2 |
| **`GET /validators`** — full validator set with stakes + current leader | ✅ v1.0.2 |
| **Dynamic reader proxy** — non-leader POSTs forward to current leader | ✅ v1.0.2 |

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
| L2 sequencer pubkey (rotated): `fb78242e…` | ✅ |
| L3/L5 sequencer pubkeys registered | ✅ |

---

## ✅ PHASE 3.5 — Rollup Exit Security Hardening (COMPLETE — post-v1.0.0)

**Closed a CRITICAL money-loss bug: the same locked balance could be exited once
per historical Merkle root, draining the vault.**

| Item | Status |
|------|--------|
| Batch-agnostic BB exit key: `SHA256("{rollup}:BB:{addr}")` | ✅ |
| Cumulative-withdrawn accounting — exit releases `proven − already_withdrawn` | ✅ |
| Re-deposit increments handled (lock more → exit only the delta) | ✅ |
| `atomic_rollup_bb_exit()` — single ReDB txn (re-read cumulative, re-check vault solvency, debit+credit+seal, then mirror cache) | ✅ |
| Concurrent double-exit race → `exit_raced` 409 | ✅ |
| Vault solvency re-checked inside the write txn → `vault_insolvent` 409 | ✅ |
| NFT exit key batch-agnostic: `SHA256("{rollup}:NFT:{col}:{tok}")` + binary seal | ✅ |
| `cargo build --release` clean | ✅ |
| End-to-end exit replay test on live node | 🔲 Pending |

> **Still trusted-by-authority:** these fixes stop double-spend and insolvency, but a
> malicious sequencer can still post a false root. True trust-minimization needs the
> challenge window + ZK proofs (Phases 9 / future Phase 12). Tracked below.

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

## ✅ PHASE 5 — Frontend Integration (COMPLETE)

React wallet wired to live L2 sequencer at `https://layer2.blackbook.id/seq`.

| Item | Status |
|------|--------|
| L1 balance fetch (`GET /balance/:addr`) | ✅ |
| L2 sequencer deployed to Hetzner | ✅ June 2026 |
| `https://layer2.blackbook.id/seq/health` live | ✅ |

---

## ✅ PHASE 6 — Deploy L2 to Hetzner (COMPLETE — June 2026)

| Item | Status |
|------|--------|
| Multi-stage Dockerfile for L2 sequencer (Node 22-alpine) | ✅ |
| `docker-compose.prod.yml` `l2-sequencer` service | ✅ |
| `L2_SEQUENCER_PRIVKEY` alias in Hetzner `.env` | ✅ |
| Nginx `/seq/` → `:7072` with HTTPS (Certbot cert) | ✅ |
| `l2-sequencer` container healthy in `docker ps` | ✅ |
| PoH WebSocket subscription to L1 confirmed in logs | ✅ |

---

## 🔄 PHASE 7 — Permissioned P2P Gossip (Turbine Rewrite) — IN PROGRESS

Convert the star-topology Turbine from an unauthenticated 1-Writer→N-Reader broadcast
into an **authenticated, whitelist-gated** propagation layer among the consortium
validator set. Phases **7A / 7B / 7C are live**; the full block-shred mesh (round-robin
+ peer re-broadcast + FEC reassembly) is the remaining work.

### Design: The Three Laws of the Consortium Network
1. **IP Whitelist as First Defence** — UDP socket drops unknown-source packets in <1 µs, before any crypto.
2. **Shred & Share** — Writer splits block into 1,232-byte shreds, assigns each to a different approved node. Those nodes immediately re-broadcast to the full peer set.
3. **u64 Stake, no f64** — The `LeaderSchedule` f64 staking weights are ripped out and replaced with exact u64 lamport-denominated voting power.

### 7A — Static Permissioned Registry (✅ DONE)
| Item | Status |
|------|--------|
| `ValidatorRegistry` in AppState (`approved_validators: Arc<ValidatorRegistry>`) | ✅ `runtime/validator_registry.rs` |
| Load from `config.toml` `[[validators]]` or `APPROVED_VALIDATORS` env (env overrides) | ✅ |
| Fast `by_ip` + `by_pubkey` lookup maps; `empty()` dev fallback (never panics) | ✅ |
| `config.toml.example` template + `VALIDATOR_KEYPAIR_PATH` signing key | ✅ |
| `POST /turbine/register` + `/heartbeat` removed (hard cutover to static set) | ✅ |

### 7B — UDP Source-IP Gate (✅ DONE)
| Item | Status |
|------|--------|
| `recv_from` on `:8004` drops non-whitelisted source IPs before deserialization | ✅ `is_approved_ip()` |
| Silent drop (no per-packet logging) — parse-bomb / log-flood resistant | ✅ |

### 7C — Signed Tick-Shred Wire Format (✅ DONE)
| Item | Status |
|------|--------|
| `SignedTickShred { shred_bytes, signer, signature }` Ed25519 envelope | ✅ |
| Writer signs in async broadcaster thread — PoH OS thread stays crypto-free | ✅ |
| Receiver: signer-known check → Ed25519 verify → PoH SHA-256 chain replay | ✅ |
| `LeaderSchedule` f64 → u64 lamport rewrite (`set_stake`, deterministic schedule) | ✅ `runtime/consensus.rs` |

### 7D — Full Block-Shred VIP Mesh (🔲 REMAINING)
| Item | Status |
|------|--------|
| Writer → round-robin shred assignment (each shred to a different approved node) | 🔲 today: signed tick-shreds broadcast to all targets (star + auth) |
| Peer re-broadcast — each node blasts its shred to all other whitelisted peers | 🔲 |
| Block shred reassembly + Reed-Solomon FEC decode on receiver nodes | 🔲 today: per-tick PoH verify, no block reassembly |
| `GET /validators` endpoint — returns current approved set | ✅ v1.0.2 (Phase 1) |
| `POST /admin/validators/add` + `/remove` (feature-gated, hot registry) | 🔲 |

---

## ✅ PHASE 7.6 — Rotating Leader Schedule (COMPLETE — v1.0.2)

**Multi-validator consensus with dynamic role switching.** Every validator runs the same
binary, consults the deterministic `LeaderSchedule` from `config.toml`, and switches
between Writer and Reader at slot boundaries.

| Item | Status |
|------|--------|
| `--mode validator` CLI flag | ✅ |
| `stake_lamports` + `http_port` in `config.toml` `[[validators]]` | ✅ |
| `LeaderSchedule` populated from `ValidatorRegistry` (not hardcoded) | ✅ |
| `TowerBFT` multi-validator from registry stakes | ✅ |
| Contiguous leader tenures (`LEADER_TENURE_SLOTS = 4`, 1.6s per leader) | ✅ |
| `GET /validators` — pubkeys, stakes, current leader | ✅ |
| `GET /health` — `current_leader`, `is_leader`, `validators_registered` | ✅ |
| Zero log spam — leadership transitions logged once | ✅ |
| Dynamic reader proxy — non-leader POSTs forward to current leader | ✅ |
| Gulf Stream tx forwarding to upcoming leaders | ✅ |
| Leader handoff — Validator syncs as Reader when not leader | ✅ |
| Leader timeout detection foundation (tracking in block loop) | ✅ |

**Next:** Phase 6 — Leader timeout auto-skip (detect offline leader, advance schedule).

---

## 🚚 PHASE 7.5 — Cherry Bare-Metal Migration (IN PROGRESS — June 2026)

Hetzner flagged blockchain workloads, so the node is migrating to a **Cherry bare-metal**
host (no blockchain restrictions, NVMe, EU colocation). Phase 7A keypairs were generated
for the new Writer + Reader mesh on this host.

| Item | Status |
|------|--------|
| Cherry server provisioned (32-core / 64 GB / NVMe) | 🔄 |
| Firewall: TCP 8080/50051/8899 public · UDP 8003 public · UDP 8004 whitelist | 🔄 |
| Phase 7A keypairs generated (`keys/writer.key`, `keys/reader-local.key`) | ✅ |
| `config.toml` populated with Cherry Writer pubkey + addr | 🔲 |
| `docs/cherry.md` migration guide + `deployment/setup-cherry.sh` | ✅ |

---

## 📋 PHASE 8 — Performance: Kernel Bypass (XDP / io_uring)

Eliminate OS network stack overhead. Target: hardware wire-speed ingestion on :8003.
**Linux-only — implement on Hetzner node, not Windows dev box.**

| Upgrade | Impact |
|---------|--------|
| **XDP (eXpress Data Path)** — intercept UDP at NIC before Linux kernel | Latency: ms → µs. Unlocks true 240K TPS ceiling |
| **eBPF packet filter** — drop non-whitelisted IPs at NIC level | DDoS resilience at zero CPU cost |
| **`io_uring`** — async disk I/O for ReDB flushes | Eliminates I/O blocking on CPU threads |
| **NUMA-aware thread pinning** — bind Rayon workers to physical cores | Eliminates cross-socket cache misses |

**Prerequisite:** Hetzner dedicated with NIC that supports XDP offload (CX42+ qualifies).

---

## 📋 PHASE 9 — Trustlessness: ZK Validity Proofs

Replace sequencer-authority trust with mathematical proof.

| Upgrade | Impact |
|---------|--------|
| **ZK-SNARK per batch** — L2 proves every bet/payout follows LMSR rules | L1 can't be fooled even if sequencer key is stolen |
| **ZK circuit for Merkle root** — proves state root is output of valid transitions | Eliminates the "honest sequencer assumption" |
| **Recursive proof aggregation** — 1,000 market resolutions → 1 proof | Amortizes proving cost across batch size |

**Stack candidates:** `risc0` (Rust-native RISC-V zkVM), `sp1` (Succinct), or `halo2`.  
**Estimated effort:** 4–8 weeks for a single-circuit MVP.

---

## 📋 PHASE 10 — Infinite Scale: Data Availability + State Pruning

Prevent state bloat from killing performance at high TPS.

| Upgrade | Impact |
|---------|--------|
| **Hot/Cold split** — ReDB holds last 48h; older blocks to cold storage | NVMe never fills; RAM lookups stay fast |
| **Snapshot system** — periodic full-state snapshots to S3/Arweave | New nodes sync in minutes, not days |
| **DA separation layer** — post block headers to Celestia/EigenDA | Historical auditability without local storage |
| **State pruning thread** — background task prunes finalized blocks beyond epoch | Automatic, no manual intervention |

---

## 📋 PHASE 11 — Resilience: HA Sequencer Failover

Eliminate the L2 sequencer as a single point of failure.

| Upgrade | Impact |
|---------|--------|
| **Active-Passive cluster** — secondary L2 streams WAL from primary | Failover in < 500ms on primary crash |
| **WAL replication** — SQLite WAL via Litestream or rsync-over-SSH | Zero data loss on failover |
| **Heartbeat monitor** — secondary auto-promotes on primary timeout | No manual intervention needed |
| **L1 multi-validator** — Tower BFT with real validator set | Eliminates single Hetzner node as L1 SPOF |

---

## 📋 PHASE 12 — Rollup Trust-Minimization: Challenge Window + Escape Hatch

Phase 3.5 stopped double-spend/insolvency, but a sequencer that signs a *false* root
can still mis-credit exits. These items remove the "honest sequencer" assumption
without waiting for full ZK (Phase 9).

| Upgrade | Impact |
|---------|--------|
| **Challenge/dispute window** on `submit_root` (reuse `settlement/mod.rs` 2h `SubmitPendingRoot` pattern) | Roots are pending, not final — fraudulent roots can be contested before exits unlock |
| **Forced-inclusion / escape hatch** — user can exit against the last *finalized* root even if the sequencer censors them | Liveness: funds are never trapped by an offline/malicious sequencer |
| **Sequencer bond** — sequencer stakes $BB, slashed on a proven invalid root | Economic deterrent; aligns sequencer incentives |
| **Data-availability publication** — sequencer must publish the full balance set behind each root | Anyone can reconstruct proofs and detect fraud |

**Why before Phase 7/8:** this protects user funds at launch. P2P gossip and kernel
bypass are scaling/decentralization — important, but they don't guard the money path.

---

## Priority Summary

| Phase | Priority | Effort | Unlocks |
|-------|----------|--------|---------|
| 3.5 — Exit Security Hardening | ✅ Done | — | No cross-batch vault drain |
| 5 — Frontend | ✅ Done | — | — |
| 6 — L2 on Hetzner | ✅ Done | — | — |
| 7A/7B/7C — Registry + IP gate + signed shreds + u64 stake | ✅ Done | — | Authenticated, whitelist-gated propagation |
| **7.5 — Cherry bare-metal migration** | **NOW** | 2–3 days | Node off Hetzner, mesh on owned keys |
| 7D — Full block-shred mesh + `/validators` | **NEXT** | 1–2 weeks | True multi-node consortium, remove Writer SPOF |
| 12 — Challenge Window + Escape Hatch | High | 1–2 weeks | Trust-minimized exits, no trapped funds |
| 8 — XDP / io_uring | High | 2–3 weeks | 240K TPS ceiling (Linux node) |
| 9 — ZK Proofs | High | 4–8 weeks | Fully trustless L2 |
| 10 — DA + Pruning | Medium | 2–3 weeks | Infinite scale |
| 11 — HA Failover | Medium | 1–2 weeks | 99.99% uptime |
