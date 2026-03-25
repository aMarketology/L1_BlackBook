# NEXT-STEPS.md — BlackBook L1 Roadmap

> The microtransaction network for AI agents.
> Target: Hetzner launch, early March 2026.
> Last updated: 2026-03-22

---

## 1. What's Done

Everything below compiles, runs, and is wired end-to-end in `main.rs`:

| Component | What | Status |
|-----------|------|--------|
| **PoH Clock** | SHA-256 hash chain, 400 ms slots, 64 ticks/slot, 12,500 hashes/tick | ✅ Live |
| **Block Production** | `BlockProducer` → PoH-timestamped `FinalizedBlock` every 400 ms | ✅ Live |
| **SVM Execution** | `BlackBookSVM` — execute_transfer, blockhash queue (150 slots), intra-block dedup, atomic flush | ✅ Live |
| **SvmAccountsDB** | Two-layer: DashMap (hot) + ReDB (durable). Lock-free reads, dirty-set tracking, `flush_block()` | ✅ Live |
| **SPL Token** | Native Rust — 82-byte MintLayout, 165-byte TokenAccountLayout, USDC mint, Dealer as authority | ✅ Live |
| **JSON-RPC** | 28 Solana-compatible methods on port 8899 (jsonrpsee) | ✅ Live |
| **Tower BFT** | Exponential lockout, 2/3 supermajority, 32-deep root advancement | ✅ Live |
| **Turbine** | 1,232-byte shreds, Reed-Solomon FEC (32+32), fanout 200, Merkle proofs | ✅ Live |
| **Gulf Stream** | 8-leader lookahead, priority queues, dedup, background expiry | ✅ Live |
| **Sealevel** | Rayon parallel execution, batch 256, conflict serialization | ✅ Live |
| **1W/100R Relay** | gRPC `SubscribeBlocks`, `CatchupBlocks`, `ForwardTransaction`, `GetStatus` | ✅ Live |
| **CLI Modes** | `--mode writer|reader`, `--identity`, `--grpc-port`, `--http-port`, `--rpc-port` | ✅ Live |
| **Wallet SSS** | BIP-39 mnemonic, Shamir 2-of-3 (A=user, B=server, C=cold), Ed25519 keypairs | ✅ Live |
| **Faucet** | `/faucet` route, per-epoch rate limiting (0.1 BB cap), recorded in PoH blocks | ✅ Live |
| **Ed25519 Transfers** | `/transfer/simple` — sig verification, SVM execution, block recording | ✅ Live |
| **USDC Endpoints** | `/admin/usdc/mint`, `/usdc/transfer`, `/usdc/balance/{addr}`, `/usdc/supply` | ✅ Live |
| **Pure SVM Balance Path** | `SvmAccountsDB` is sole source of truth — no dual f64/legacy sync, no cloud deps | ✅ Live |
| **Unified Wallet (SSS)** | Shard B in ReDB on-chain; Shards A & C returned directly to client — zero cloud state | ✅ Live |
| **Replay Protection** | Nonce + 60s timestamp window on signed transfers, bounded nonce map with auto-prune | ✅ Live |
| **JavaScript SDK** | `@blackbook/sdk` v3.0 — createWallet, transfer, faucet, SSS verify | ✅ Published |

---

## 2. What Was Removed (Dead Code Cleanup — Done)

These modules were deleted to keep the runtime minimal for microtransaction speed:

| Removed | Lines | Why |
|---------|-------|-----|
| `src/main_v4.rs` | 1,593 | Legacy v4 binary — superseded by `main.rs` |
| `src/grpc/mod.rs` | 757 | L2 Settlement gRPC — orphaned, never imported. Rebuild as a program later. |
| `src/proof_of_reserves.rs` | 588 | PoR Merkle tree — orphaned. Wire when USDC backing matters. |
| `src/usdc/reserve.rs` | 390 | USDC reserve tracking — orphaned. Rebuild when on-ramp is live. |
| `src/svm/tx_adapter.rs` | 162 | TxRoute enum — all `#[allow(dead_code)]`, never called |
| `src/consensus/mod.rs` | 5 | Empty stub — consensus lives in `runtime/` |
| `proto/settlement.proto` | — | Only used by deleted `grpc/mod.rs` |
| **Total removed** | **~3,500** | Binary is leaner, compiles faster, less attack surface |

Unused dependencies also removed: `libp2p` (+ 9 sub-features), `memmap2`, `void`, `futures`.

---

## 3. What Must Happen Before Hetzner Launch

### 3.1 SECURITY — P0 (Do Not Deploy Without These)

| # | Fix | File(s) | Status | Effort |
|---|-----|---------|--------|--------|
| 1 | **Remove `real_wallets/` from Dockerfile** — private keys baked into container image | `Dockerfile` | ❌ TODO | 15 min |
| 2 | **Gate admin endpoints** behind `#[cfg(feature = "unsafe_admin")]` — `/admin/mint`, `/admin/burn`, `/admin/dealer/settle`, `/admin/wallet/migrate`, `/admin/accounts`, `/admin/usdc/mint` currently open to anyone | `src/main.rs` | ❌ TODO | 1 hour |
| 3 | **Lock down CORS** — currently `allow_origin(Any)`, any website can hit the node | `src/main.rs` | ❌ TODO | 30 min |
| 4 | **Authenticate Shard B retrieval** — PIN verified against itself (tautology), not against stored hash | `src/wallet_unified/handlers.rs` | ❌ TODO | 1 hour |

> `.gitignore` already has `real_wallets/` ✅. Replay protection already wired ✅. Faucet already capped at 0.1 BB ✅. No MD5 in codebase (SHA-256 throughout) ✅.

### 3.2 DATA INTEGRITY — P1

| # | Fix | File(s) | Status | Effort |
|---|-----|---------|--------|--------|
| 5 | **Wire graceful shutdown** — call `flush_final_block()` + `svm.end_of_block()` on SIGTERM so dirty accounts persist to ReDB | `src/main.rs` | ❌ TODO | 1 hour |
| 6 | **Per-account nonce in storage** — currently hardcoded `nonce: 0` with a TODO comment | `src/storage/mod.rs` | ❌ TODO | 30 min |

### 3.3 DEAD CODE CLEANUP — P2 (Remaining ~330 lines)

| # | What | File | Lines | Effort |
|---|------|------|-------|--------|
| 7 | Bridge/lock system (`BridgeLock`, `LockStatus`, `create_bridge_lock`, `release_bridge_lock`, `get_bridge_lock`) — never called | `src/storage/mod.rs` | ~220 | 30 min |
| 8 | Unreachable `TxData` variants + match arms (`Stake`, `Market`, `System`, `Social`, etc.) — only `Transfer` and `CreateWallet` are used | `protocol/blockchain.rs` | ~110 | 30 min |

### 3.4 LAUNCH INFRASTRUCTURE — P2

| # | Task | Effort |
|---|------|--------|
| 9 | **Dockerfile update** — remove baked secrets, add env var config, verify `cargo build --release` in container | 1 hour |
| 10 | **Hetzner deployment** — single Writer node, DNS, TLS (Caddy or nginx reverse proxy) | 2 hours |
| 11 | **Smoke test checklist** — wallet create → faucet → transfer → balance on live node | 1 hour |

---

## 4. Priority Order — Hetzner Launch Plan

```
 DAY 1 — SECURITY
 ├── 1. Remove real_wallets/ from Dockerfile
 ├── 2. Gate admin endpoints behind #[cfg(feature = "unsafe_admin")]
 ├── 3. Lock down CORS to explicit origins
 └── 4. Fix Shard B PIN authentication

 DAY 2 — DATA INTEGRITY + CLEANUP
 ├── 5. Wire graceful shutdown (flush_final_block on SIGTERM)
 ├── 6. Per-account nonce tracking in storage
 ├── 7. Remove dead bridge/lock code from storage
 └── 8. Remove unreachable TxData variants

 DAY 3 — DEPLOY
 ├── 9. Finalize Dockerfile
 ├── 10. Deploy Writer to Hetzner
 ├── 11. Smoke test on live node
 └── 🚀 LIVE
```

**Total estimated effort: ~8–10 hours of focused work.**

---

## 5. After Launch — Week 1-2

### AI-Agent Microtransaction Optimization & Scale

These architectural upgrades are designed to accommodate non-human actors continuously trading, hedging, and deploying capital via code.

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| A | **Event-Driven WebSockets** | 2–3 days | AI agents need instant <400ms feedback loops via `accountSubscribe`, not polling `/balance` APIs. |
| B | **Session Keys (Delegated Spend)** | 3–5 days | Allow human users to sign a 24-hr allowance for an AI Agent's specific pubkey without handing over full private keys. |
| C | **Localized Fee Markets (Anti-Spam)** | 1 week | Protect against runaway AI infinite-loop attacks. If a specific agent or contract spams, fees rise *only* for that local state. |
| D | **Archiver Nodes & Garbage Collection** | 2 weeks | 600,000 TPS generates massive data. We need to prune `SvmAccountsDB` and offload historical txs to cold-storage "Archiver" nodes. |
| E | **L2 Payment Channels (LLM Streaming)** | 2 weeks | For sub-cent continuous streams (e.g. paying per LLM token), agents need state channels that settle back to the L1 post-session. |
| F | **`simulateTransaction` RPC** | 2–4 hours | Pre-flight checks before an AI commits non-recoverable funds to a complex swap. |
| G | **Reader → Writer tx forwarding in RPC** | 2–3 hours | `sendTransaction` on Reader must forward to Writer. |

### Observability

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| E | **Health monitoring** — `/metrics` (Prometheus), `GET /status` | 2 hours | Production visibility |
| F | **WebSocket subscriptions** (`slotSubscribe`, `signatureSubscribe`) | 2 days | Real-time wallet UX |

### Infrastructure

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| G | **4 Reader nodes** (Oregon, Dallas, Sydney + 1 more) | 1–2 days | Geographic distribution |
| H | **CI/CD pipeline** (GitHub Actions: build → test → Docker push) | 4 hours | Automated quality gate |
| I | **Block Explorer** | 3–5 days | Users and investors see the chain is alive |

---

## 6. Medium Term — Month 2-3

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 14 | **QUIC ingestion endpoint** | 1–2 weeks | Eliminate TCP handshake overhead at scale |
| 15 | **rBPF VM activation** | 1–2 weeks | Custom on-chain programs |
| 16 | **Multi-Writer leader schedule** | 2–3 weeks | True decentralization |
| 17 | **USDC on-ramp** (fiat → USDC → BB) | 2–3 weeks | Real money on-chain |
| 18 | **Proof of Reserves endpoint** | 4 hours | Rebuild + wire when USDC backing is live |
| 19 | **L2 Settlement gRPC** | 1–2 days | Rebuild for casino/DeFi settlement |

---

## 7. Scoreboard — Current Health

| Area | Score | Notes |
|------|-------|-------|
| Core blockchain | 9/10 | PoH + SVM + storage all production-wired |
| Solana compatibility | 8/10 | 28 RPCs, real SPL tokens. Missing: `simulateTransaction`, WebSockets |
| Wallet system | 8/10 | Pure SSS 2-of-3. Shard B on-chain. PIN auth needs fix (tautology). |
| Security | 5/10 | Replay protection done. CORS open. Admin endpoints ungated. Shard B auth broken. |
| Multi-node | 7/10 | Writer/Reader gRPC relay complete. No P2P, no leader election |
| External integrations | 10/10 | Zero external deps — no Supabase, no Vault, no JWT. Pure L1. |
| AI-agent readiness | 4/10 | SVM path clean. Missing: WebSocket push, deterministic fees |
| Dead code | ~330 lines | Bridge/lock system + unreachable TxData variants. Down from ~3,500. |
| Test coverage | 3/10 | Needs investment after launch stabilizes |

---

*This document reflects the codebase as of 2026-03-22 (v5.0.0). Target: Hetzner launch — imminent.*

---

## 8. The Architecture Vision — Where We Are Going

These three pillars define what BlackBook will become beyond the initial launch. They are not hypothetical — the foundations already exist in the codebase today.

### 8.1 Zero-Knowledge Proofs (ZKPs)

**What it means:** A ZKP lets the network mathematically *prove* that a transaction is valid without requiring every node to re-execute it. Instead of 1,000 validators all burning electricity checking the same arithmetic, one node does the work and produces a small cryptographic proof. Every other node verifies the proof in microseconds.

**Why it matters for BlackBook:**
- Microtransactions between AI agents are extremely high-volume and repetitive in structure. ZKPs batch thousands of these into a single on-chain proof — collapsing the verification cost to near zero.
- It enables **light-client validation** — a mobile phone or IoT device can verify the chain is honest without downloading every block.
- Privacy extensions: ZKPs can optionally shield transaction amounts from public view while still proving they are valid, enabling private AI agent accounting.

**What we have today:** Our SVM execution path in `src/svm/runtime.rs` is the execution layer. ZKP integration sits one layer above: a proving system (e.g., **PLONK** or **Groth16** via `bellman` or `halo2` crates) would wrap the SVM's state transitions and produce succinct proofs per block.

**Roadmap step:** Introduce a `zkp/` module post-launch that wraps `flush_block()` output and generates a validity proof committed to the PoH hash chain.

---

### 8.2 PoH Speed — Without Hardware Centralization

**What it means:** Solana's PoH is a cryptographic clock — a continuous SHA-256 hash chain that stamps the *exact order* of events before consensus even runs. This eliminates the most expensive part of blockchain consensus: arguing about time.

**The problem with Solana's original design:** Running a Solana validator requires a $10,000+ server (high-core NVMe, 256 GB RAM, 10 Gbit NIC) because the state is enormous and transaction throughput is massive.

**How BlackBook solves this:**
- Our `SvmAccountsDB` uses a **two-layer architecture** — a hot `DashMap` in memory and a durable `ReDB` on disk. State is sharded and only *active* accounts are kept hot. Cold state is compressed to disk with zero overhead on the critical path.
- The **400 ms slot** time and **12,500 hashes/tick** PoH clock (in `runtime/poh_service.rs`) are tuned to be achievable on commodity hardware — not just $10,000 datacenter rigs.
- **Turbine shreds** (1,232 bytes, Reed-Solomon FEC 32+32, fanout 200) in `src/svm/` mean block propagation is O(log n), so even low-bandwidth nodes receive full blocks quickly.

**The goal:** A fully validating BlackBook node should run comfortably on a $30/month VPS or a modern laptop — keeping the network genuinely decentralized, not permissioned by hardware cost.

---

### 8.3 Self-Healing Architecture

**What it means:** The network should never halt. If the Writer node (block producer) goes down, the network automatically elects a new leader and resumes within seconds. No human intervention. No downtime for users.

**What we have today:**
- **Tower BFT** (`runtime/consensus.rs`) — exponential lockout, 2/3 supermajority, 32-deep root advancement. This is the Byzantine fault tolerance layer that lets the network agree on canonical blocks even if some nodes lie or go offline.
- **Turbine + Gulf Stream** — block shreds are propagated and transactions are pre-forwarded to upcoming leaders, so the pipeline never empties even during leader rotation.
- **1 Writer / N Readers** relay via gRPC — Readers continue serving RPC traffic even if the Writer is temporarily unreachable.

**What comes next (Month 2-3):**
- **Multi-Writer leader schedule** — rotate block production across multiple nodes on a deterministic schedule. If the current leader misses a slot, the next node automatically takes over.
- **Automatic Writer failover** — Readers detect a stalled Writer (no block within 2 slots) and trigger a leader-change vote via Tower BFT.

---

## 9. First 100 Users — Launch Checklist

This is the minimum viable set of work to go from "compiles and runs locally" to "live network with 100 real users transacting."

### 9.1 Pre-Launch Gate (Must Be Done First)
These block a live deployment entirely. See Section 3 for full details.

```
 ✅ PoH clock live
 ✅ SVM execution live
 ✅ SPL tokens live
 ✅ Replay protection live
 ✅ Faucet rate-limited
 ✅ JavaScript SDK published

 ❌ Remove real_wallets/ from Dockerfile            (15 min)
 ❌ Gate /admin/* endpoints behind unsafe_admin     (1 hour)
 ❌ Lock CORS to explicit origins                   (30 min)
 ❌ Fix Shard B PIN auth (tautology bug)            (1 hour)
 ❌ Wire SIGTERM → flush_final_block()              (1 hour)
 ❌ Per-account nonce in storage                   (30 min)
```

### 9.2 First 100 Users — Onboarding Requirements

| # | What | Why | Effort |
|---|------|-----|--------|
| 1 | **Public Writer node live** on writer.blackbook.io with TLS | Users can send real transactions | 2 hours |
| 2 | **Geo-load-balanced Reader nodes** (Virginia + Oregon minimum) | Fast RPC reads for all US users | 2 hours |
| 3 | **wallet.blackbook.io frontend** — create wallet, faucet, send | Non-technical users can onboard | 3–5 days |
| 4 | **Block Explorer** at explorer.blackbook.io | Users and investors can see the chain is alive | 3–5 days |
| 5 | **`accountSubscribe` WebSocket push** | Wallet UI shows live balance updates without polling | 2–3 days |
| 6 | **`simulateTransaction` RPC** | Phantom/Backpack wallet compatibility, pre-flight checks | 2–4 hours |
| 7 | **Reader → Writer tx forwarding** | `sendTransaction` on a Reader must forward to the Writer | 2–3 hours |
| 8 | **Deterministic flat fee** (0.0001 BB/tx, genesis-encoded) | Users and AI agents can pre-calculate exact costs | 4–8 hours |
| 9 | **Faucet UX** — one-click fund new wallet with 100 BB | No user should get stuck with zero balance on signup | 1 hour |
| 10 | **CI/CD pipeline** (GitHub Actions → Docker push) | Every merge deploys tested code automatically | 4 hours |

### 9.3 The 100-User Rollout Waves

| Wave | Users | Method | Goal |
|------|-------|--------|------|
| **Wave 1** | 5 | Internal team + friends. Manual onboarding via CLI. | Smoke test on live network. Catch anything broken. |
| **Wave 2** | 20 | Early beta invite list. Frontend live. | Validate wallet create → faucet → transfer UX is intuitive. |
| **Wave 3** | 75 | Discord/community invite. Block explorer live. | Observe chain live. Organic first transactions. Real excitement. |
| **Wave 4** | 100+ | Open signup via wallet.blackbook.io. | Sustained daily active users. Measure TPS under real load. |

### 9.4 Success Criteria for 100 Users

The launch is successful when all of the following are true simultaneously:
- [ ] 100 unique wallets created and funded on the live chain
- [ ] Block explorer shows a continuously growing block height
- [ ] Average transaction confirmation time < 800 ms end-to-end
- [ ] Zero unplanned chain halts in 72 hours of operation
- [ ] At least one AI agent sending microtransactions autonomously on-chain

---

*Last updated: 2026-03-22. Next milestone: Ship the Pre-Launch Gate items (Section 9.1) and go live.*
