# NEXT-STEPS.md — BlackBook L1 Roadmap

> The microtransaction network for AI agents.
> Target: Hetzner launch, early March 2026.
> Last updated: 2026-03-01

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

### AI-Agent Microtransaction Speed

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| A | **`accountSubscribe` WebSocket push** | 2–3 days | AI agents need instant push, not polling `/balance` |
| B | **Deterministic flat fee** (0.0001 BB per tx, encoded in genesis) | 4–8 hours | Agents pre-calculate cost of 10,000 hops before sending the first one |
| C | **`simulateTransaction` RPC** | 2–4 hours | Phantom/Backpack pre-flight checks |
| D | **Reader → Writer tx forwarding in RPC** | 2–3 hours | `sendTransaction` on Reader must forward to Writer |

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

*This document reflects the codebase as of 2026-03-01 (v5.0.0). Target: Hetzner launch March 3.*
