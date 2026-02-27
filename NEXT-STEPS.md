# NEXT-STEPS.md — BlackBook L1 Roadmap

> Where we've been, where we are, what happens next.
> Last updated: 2025-06-25

---

## 1. What's Done

Everything below compiles, runs, and is wired end-to-end in `main.rs`:

| Phase | What | Status |
|-------|------|--------|
| **PoH Clock** | SHA-256 hash chain, 600 ms slots, 64 ticks/slot, 12,500 hashes/tick | ✅ Live |
| **Block Production** | `BlockProducer` → PoH-timestamped `FinalizedBlock` every 600 ms | ✅ Live |
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
| **Faucet** | `/faucet` route, per-epoch rate limiting, recorded in PoH blocks | ✅ Live |
| **Ed25519 Transfers** | `/transfer/simple` — sig verification, SVM execution, block recording | ✅ Live |
| **USDC Endpoints** | `/admin/usdc/mint`, `/usdc/transfer`, `/usdc/balance/{addr}`, `/usdc/supply` | ✅ Live |
| **Supabase** | JWT validation, profile lookup, shard-B cloud storage | ✅ Wired |
| **HashiCorp Vault** | Shard-C emergency recovery storage via `vaultrs` | ✅ Wired |
| **JavaScript SDK** | `@blackbook/sdk` v3.0 — createWallet, transfer, faucet, SSS verify, WalletConnect scaffolding | ✅ Published |

---

## 2. What Exists But Isn't Connected

Code that compiles but is not imported or called at runtime:

| Module | Lines | What It Does | Decision Needed |
|--------|-------|-------------|-----------------|
| `src/grpc/mod.rs` | 757 | L2 Settlement gRPC service (SoftLock, SettleBet, BatchSettle) | Wire for L2 casino settlement? |
| `src/proof_of_reserves.rs` | 588 | Merkle-tree proof of reserves, USDC backing verification | Wire to `/reserves` endpoint |
| `src/social_mining.rs` | 397 | Social action rewards system with daily limits | Wire or defer to tokenomics phase |
| `src/svm/tx_adapter.rs` | ~120 | `TxRoute` enum to route system/SPL/BPF transactions | Wire into `produce_block()` or remove |
| `src/wallet_unified/opaque_impl.rs` | 171 | OPAQUE PAKE (password-authenticated key exchange) | Fix dep (`opaque_ke` missing) or remove |
| `src/main_v4.rs` | 1,651 | Legacy v4 main binary | Delete — superseded by `main.rs` |
| `src/consensus/mod.rs` | 5 | Empty stub (consensus moved to `runtime/`) | Delete |

---

## 3. What's Not Built Yet

### 3.1 Critical — Must Have Before 100 Users

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 1 | **Graceful shutdown** — call `flush_final_block()` on SIGTERM | 1 hour | Data loss on restart if dirty accounts aren't flushed |
| 2 | **`simulateTransaction` RPC** | 2–4 hours | Phantom/Backpack/Solflare pre-flight checks require it |
| 3 | **Reader → Writer tx forwarding (wired in RPC)** | 2–3 hours | `sendTransaction` on a Reader must forward to Writer via gRPC |
| 4 | **Health monitoring endpoints** | 2 hours | `/metrics` (Prometheus), Writer `GetStatus` exposed as REST |
| 5 | **Restore missing tests** | 1–2 days | 26+ tests documented as passing are not in the repo |
| 6 | **Clean dead code** | 2 hours | Remove `main_v4.rs`, empty `consensus/mod.rs`, broken `opaque_impl.rs` |
| 7 | **Prune unused deps** | 1 hour | `libp2p`, `memmap2`, `frost-ed25519` — add compile time for zero value |

### 3.2 High Value — Unlocks Real Users

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 8 | **WebSocket subscriptions** (`accountSubscribe`, `slotSubscribe`, `signatureSubscribe`) | 2–3 days | Real-time wallet UX without polling |
| 9 | **Block Explorer** (standalone Next.js or embedded) | 3–5 days | Users and investors need to see the chain is alive |
| 10 | **Proof of Reserves endpoint** | 4 hours | Wire the existing `proof_of_reserves.rs` to `/reserves` |
| 11 | **Priority fee model** (even if fees = 0.001 BB) | 1–2 days | Spam prevention, economic signal |
| 12 | **Deployment scripts** (Docker Compose / Terraform for 5-node cluster) | 1–2 days | Infra automation for the first-100-users plan |
| 13 | **CI/CD pipeline** (GitHub Actions: build, test, Docker push) | 4 hours | Automated quality gate |

### 3.3 Medium Term — Growth & Decentralization

| # | Feature | Effort | Why |
|---|---------|--------|-----|
| 14 | **L2 Settlement gRPC** — wire `grpc/mod.rs` | 1–2 days | Casino/DeFi L2s need on-chain settlement |
| 15 | **rBPF VM activation** | 1–2 weeks | Custom on-chain programs (DeFi, NFTs, governance) |
| 16 | **Multi-Writer leader schedule** | 2–3 weeks | True decentralization — Readers promote to Writers |
| 17 | **P2P gossip** (replace/supplement gRPC relay) | 2–4 weeks | Permissionless node discovery, >100 nodes |
| 18 | **USDC on-ramp** (fiat → USDC → BB swap) | 2–3 weeks | Real money on-chain |
| 19 | **Mobile wallet** (React Native + SDK) | 2–3 weeks | Consumer reach |

### 3.4 Deferred / Nice to Have

| # | Feature | Notes |
|---|---------|-------|
| 20 | GPU signature verification | Only matters at >10K TPS |
| 21 | Cloudbreak (memmap2 accounts) | Only matters with >10M accounts |
| 22 | Anchor program framework | After rBPF VM is live |
| 23 | Social mining rewards | Wire existing `social_mining.rs` when tokenomics are defined |

---

## 4. Priority Order

```
 NOW (before 5-node launch)
 ├── 1. Graceful shutdown
 ├── 2. simulateTransaction RPC
 ├── 3. Reader sendTransaction forwarding
 ├── 5. Restore test suite
 ├── 6. Clean dead code
 └── 7. Prune unused deps

 WEEK 1 (infrastructure)
 ├── 4. Health monitoring (/metrics)
 ├── 12. Deployment scripts (5-node Docker)
 └── 13. CI/CD pipeline

 WEEK 2-3 (user experience)
 ├── 8. WebSocket subscriptions
 ├── 9. Block Explorer
 ├── 10. Proof of Reserves endpoint
 └── 11. Priority fee model

 MONTH 2 (growth)
 ├── 14. L2 Settlement gRPC
 ├── 15. rBPF VM
 └── 18. USDC on-ramp

 MONTH 3+ (decentralization)
 ├── 16. Multi-Writer leader schedule
 ├── 17. P2P gossip
 └── 19. Mobile wallet
```

---

## 5. Scoreboard — Current Health

| Area | Score | Notes |
|------|-------|-------|
| Core blockchain | 9/10 | PoH + SVM + storage all production-wired |
| Solana compatibility | 8/10 | 28 RPCs, real SPL tokens. Missing: `simulateTransaction`, WebSockets |
| Wallet system | 8/10 | SSS works. OPAQUE broken (missing dep). Migration partially wired |
| Multi-node | 7/10 | Writer/Reader gRPC relay complete. No P2P, no leader election |
| External integrations | 7/10 | Supabase + Vault live. No Prometheus, no CI/CD |
| Test coverage | 3/10 | 1 integration test + 4 inline. 26+ missing from repo |
| Dead code | ~2,600 lines | `main_v4`, `grpc`, `proof_of_reserves`, `social_mining`, `opaque_impl`, `consensus` stub |
| Unused deps | 3–4 crates | `libp2p`, `memmap2`, `frost-ed25519` add compile time for zero runtime use |

---

## 6. Decision Log

Decisions to make before proceeding:

| # | Question | Options | Impact |
|---|----------|---------|--------|
| 1 | Keep or kill `proof_of_reserves.rs`? | Wire to endpoint vs. remove | 4 hours to wire, proves USDC backing |
| 2 | Keep or kill `social_mining.rs`? | Wire later vs. remove | Depends on tokenomics roadmap |
| 3 | Keep or kill `grpc/mod.rs` (L2 Settlement)? | Wire for L2 vs. remove | Critical if L2 casino settlement is planned |
| 4 | Wire `tx_adapter.rs` into produce_block()? | Cleaner routing vs. keep inline | Architecture cleanup, not functional change |
| 5 | Fix OPAQUE PAKE (`opaque_impl.rs`)? | Add `opaque_ke` dep vs. delete | Security feature, but SSS + Ed25519 is already strong |
| 6 | P2P gossip or stay with gRPC relay? | gRPC is working, P2P is weeks of work | gRPC sufficient for 100 nodes; P2P needed for permissionless |
| 7 | Restore 26 missing tests from scratch or skip? | Recreate vs. accept current coverage | 1–2 days investment, massive quality improvement |
