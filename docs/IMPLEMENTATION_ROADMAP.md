# BlackBook L1 — Implementation Roadmap

> Consolidated from NEXT-STEPS.md + NEXT-STEPS-INTEGRATION.md + production_ready.md
> Last updated: 2026-04-26

---

## Chain Specs at V5 Baseline

| Spec | Value |
|---|---|
| Slot Time | 400ms |
| Block Capacity | 50,000 txs/block |
| Theoretical TPS | 125,000 |
| Sustained TPS (tested) | 230 |
| Peak TPS (tested) | 1,765 (Sealevel) |
| Epoch Length | 432,000 slots (~3 days) |
| Signature Scheme | Ed25519 |
| Replay Protection | Nonce + 60s timestamp window |
| Storage | ReDB (ACID) + DashMap (hot cache) |
| Token Precision | 100,000 lamports / BB (5 dec) |

---

## V5 Baseline — What's Running

| Component | Status |
|---|---|
| PoH Clock (400ms, 64 ticks/slot, SHA-256) | ✅ |
| Tower BFT (exponential lockout, 2/3 supermajority) | ✅ |
| Gulf Stream (8-leader lookahead, priority queues, dedup) | ✅ |
| Sealevel (Rayon parallel, batch 256, conflict serialization) | ✅ |
| Turbine (1,232-byte shreds, RS FEC 32+32, Merkle proofs) | ✅ |
| SVM (execute_transfer, blockhash queue 150 slots, intra-block dedup) | ✅ |
| SvmAccountsDB (DashMap hot + ReDB durable, dirty-set flush) | ✅ |
| SPL Token (native Rust, 82-byte Mint, 165-byte TokenAccount) | ✅ |
| JSON-RPC (28 Solana-compatible methods, port 8899) | ✅ |
| Writer/Reader relay (gRPC SubscribeBlocks, CatchupBlocks, ForwardTx) | ✅ |
| Ed25519 transfers (`/transfer/simple`) | ✅ |
| Global Escrow (deposit → Merkle root → withdraw) | ✅ |
| MAXX bonding curve ($XX buy/sell) | ✅ |
| DECAY token (mint/use/recharge/stake) | ✅ |
| Token swap (BB ↔ wUSDT fixed-rate) | ✅ |
| Faucet (rate-limited 0.1 BB/epoch) | ✅ |
| SSS wallet (BIP-39, Shamir 2-of-3, Ed25519) | ✅ |
| Replay protection (nonce + 60s window) | ✅ |

---

## P0 — Security (Do Not Deploy Without These)

| # | Fix | File | Status |
|---|-----|------|--------|
| S1 | Remove `real_wallets/` from Dockerfile — private keys must not be in container image | `Dockerfile` | ❌ TODO |
| S2 | Verify all admin endpoints are behind `#[cfg(feature = "unsafe_admin")]` | `src/main.rs` | ⚠️ Partially done |
| S3 | Lock CORS to explicit origins — currently `allow_origin(Any)` | `src/main.rs` | ❌ TODO |
| S4 | Fix Shard B PIN check — currently verifies PIN against itself, not stored hash | `src/wallet_unified/handlers.rs` | ❌ TODO |

> Existing: `.gitignore` has `real_wallets/` ✅ · Replay protection wired ✅ · SHA-256 throughout ✅ · Faucet capped ✅

---

## P1 — Data Integrity

| # | Fix | File | Status |
|---|-----|------|--------|
| D1 | **Graceful shutdown** — call `flush_final_block()` + `svm.end_of_block()` on SIGTERM | `src/main.rs` | ❌ TODO |
| D2 | Per-account nonce in storage — currently hardcoded `nonce: 0` | `src/storage/mod.rs` | ❌ TODO |

---

## Integration Milestones

### Milestone 1 — Graceful Shutdown & Data Integrity
**Goal:** Zero data loss on Writer restart.

| Task | File | Detail |
|------|------|--------|
| Wire `flush_final_block()` in SIGTERM handler | `src/main.rs` | Call in `tokio::signal::ctrl_c()` handler before exit |
| Call `svm.end_of_block()` in shutdown path | `src/main.rs` | Flushes dirty DashMap entries to ReDB mid-slot |
| Verify `restore_chain_state()` on restart | `src/main.rs` | Already called at startup — verify slot + hash continuity |

**Acceptance:** Writer handles SIGTERM without data loss. Restart picks up at correct slot.

---

### Milestone 2 — `simulateTransaction` RPC
**Goal:** Phantom/Backpack can pre-flight check transactions.

| Task | File | Detail |
|------|------|--------|
| Add method to RPC trait | `src/solana_rpc/mod.rs` | `simulate_transaction(tx: String, config: Option<Value>)` |
| Implement simulation (read-only) | `src/solana_rpc/mod.rs` | Decode base64 tx → validate blockhash → check balance → return without mutating state |
| Solana-compatible response shape | `src/solana_rpc/mod.rs` | `{ context: { slot }, value: { err, logs, accounts, unitsConsumed } }` |
| Support `replaceRecentBlockhash` flag | `src/solana_rpc/mod.rs` | Skip blockhash validation if set (Phantom uses this) |

**Acceptance:** Phantom pre-flight passes. State NOT mutated.

---

### Milestone 3 — Reader `sendTransaction` Forwarding
**Goal:** Transactions to Reader nodes are forwarded to Writer and executed.

| Task | File | Detail |
|------|------|--------|
| Add `node_mode` to RPC server context | `src/solana_rpc/mod.rs` | Pass `NodeMode` and `writer_addr` |
| Branch `sendTransaction` by mode | `src/solana_rpc/mod.rs` | Writer: execute locally. Reader: gRPC `ForwardTransaction` |
| Reuse gRPC client (not per-request) | `src/solana_rpc/mod.rs` | `ValidatorRelayClient::connect(writer_addr)` at startup |
| Return tx signature from Writer response | `src/solana_rpc/mod.rs` | `ForwardTransactionResponse.tx_id` → RPC result |

**Acceptance:** Reader forwards to Writer within 1 slot. Clear error if Writer down.

---

### Milestone 4 — Dead Code Cleanup
**Goal:** Remove ~330 lines of remaining dead code.

| # | What | File | Lines |
|---|------|------|-------|
| 4.1 | Bridge/lock system (`BridgeLock`, etc.) | `src/storage/mod.rs` | ~220 |
| 4.2 | Unreachable `TxData` variants (`Stake`, `Market`, `System`, `Social`) | `protocol/blockchain.rs` | ~110 |

---

### Milestone 5 — Full Test Suite
**Goal:** Automated integration tests for core flows.

Tests needed:
- Wallet create → faucet → transfer → balance check
- MAXX buy/sell round-trip (integer math, no f64 loss)
- DECAY mint → use → recharge
- Escrow deposit → state root submit → withdraw (Merkle proof)
- Replay attack rejection (duplicate nonce)
- Graceful shutdown + restart slot continuity

---

### Milestone 6 — Metrics & Observability
**Goal:** Prometheus metrics endpoint for production monitoring.

| Metric | Detail |
|--------|--------|
| `bb_tps` | Transactions per second (EWMA) |
| `bb_slot` | Current PoH slot |
| `bb_escrow_balance` | Escrow PDA balance in lamports |
| `bb_redb_size_bytes` | On-disk ReDB size |
| `bb_active_markets` | Live L2 markets with state roots |
| `bb_pending_claims` | Withdrawal claims in-flight |

---

### Milestone 7 — WebSocket Subscriptions
**Goal:** Real-time balance and slot updates for wallets and L2 UIs.

| RPC Method | What |
|------------|------|
| `accountSubscribe` | Push notification on balance change |
| `slotSubscribe` | Push on every new slot |
| `signatureSubscribe` | Notify when a tx is finalized |

**Acceptance:** Frontend PredictPage receives balance update within 1 slot of escrow withdrawal.

---

### Milestone 8 — Proof of Reserves
**Goal:** Public verifiability that L1 escrow PDA ≥ sum of all pending claims.

| Task | File |
|------|------|
| Restore `src/proof_of_reserves.rs` (deleted in cleanup) | New file |
| Wire `GET /proof-of-reserves` to PoR Merkle tree | `src/main.rs` |
| Publish root hash in every PoH block | `runtime/poh_service.rs` |

---

### Milestone 9 — Deployment (Hetzner)

| Task | Effort |
|------|--------|
| Dockerfile: remove baked secrets, add env var config | 1h |
| Caddy/nginx TLS reverse proxy on :443 | 1h |
| Single Writer node + DNS | 2h |
| Smoke test: create wallet → faucet → transfer → balance | 1h |

---

### Milestone 10 — L2 Settlement End-to-End
**Goal:** Prediction market settlement fully verified on L1. See [ROLLUP_LAYERS_ROADMAP.md](ROLLUP_LAYERS_ROADMAP.md).

- L2 `settlement_bridge.rs` posts correct Merkle root to L1
- L2 proof endpoint returns valid Merkle proofs
- Frontend `handleClaim()` flow works end-to-end (deposit → play → claim)

---

### Milestone 11 — Fee Markets
**Goal:** Flat micro-fee per transaction. Prevents spam, funds validator rewards.

- `0.00001 BB` base fee per tx (~$0.0001 at $10/BB)
- Priority lane: 10x fee for sub-100ms Gulf Stream inclusion
- Fee accounts: agents pre-fund, chain auto-debits
- Sponsor model: platform pays fees for their users

---

### Milestone 12 — Session Keys (Agent SDK)
**Goal:** AI agents use short-lived delegated keys, not full wallet keys.

- `POST /session-key/create` — owner signs to create session key with spending cap
- Session key can transact up to X BB per hour, auto-expires
- `POST /session-key/revoke` — owner can revoke instantly
- SDK: `BBClient.withSessionKey(key)` for stateless agent signing

---

### Milestone 13 — Multi-Validator Network
**Goal:** Real Tower BFT consensus across 3+ validators.

- 3-validator minimum (2/3 supermajority)
- Stake-weighted leader rotation per epoch
- Gossip protocol for validator discovery
- Slashing for equivocation

---

### Milestone 14 — Horizontal TPS Scaling
**Goal:** Close gap between 230 TPS sustained and 125,000 TPS theoretical.

- Enable true multi-threaded Sealevel account-level locking
- Batch Ed25519 signature verification (8x speedup)
- SVM JIT compilation for hot paths
- HTTP/2 connection pooling for agent connections

---

## Post-Launch Product Roadmap

### AI Agent Native Features (Post-Milestone 12)
- **Batch submission** — 100+ microtxs in one HTTP call, settled atomically
- **Idempotency keys** — agents retry on network error; chain deduplicates
- **Rate-limit-aware SDK** — backpressure matching Gulf Stream capacity
- **Finality tiers** — `instant` (<10ms optimistic), `confirmed` (400ms), `finalized` (12.8s)

### Rollup Layers 3–5 (Post-Milestone 10)
See [ROLLUP_LAYERS_ROADMAP.md](ROLLUP_LAYERS_ROADMAP.md) for full architecture.
- **L3 DEX/Trading** — AMM layer using BB/wUSDT/XX, epoch settlement
- **L4 Yield Vaults** — continuous rolling settlement, partial claims
- **L5 Governance** — $XX weighted voting, DAO wrapper, multisig timelock

---

## Onramp Hardening Milestones

> **Goal:** Any user on any chain sends a stablecoin → BB appears in wallet within 60 seconds. No manual API call.

### Completed
| Milestone | What | Status |
|-----------|------|--------|
| 1.1 | `DepositRecord` integer refactor (`u64` micro-units, no `f64`) | ✅ Done |
| 1.2 | Atomic `reserve_bridge_tx` → `commit`/`cancel` (race fix) | ✅ Done |
| 1.5 | LI.FI widget + `DepositModal` (bridge / Solana direct / Lightning tabs) | ✅ Done |

### Pending

**Phase 1 — Solana (highest priority)**

| Milestone | Task | File | Detail |
|-----------|------|------|--------|
| 1.3 | Solana memo auto-detect | `src/watcher/mod.rs:scan_new_deposits` | Accept deposits where SPL `memo == BB_wallet_address` without requiring a prior `/deposit/request` call |
| 1.4 | Multi-ATA sum fix | `src/watcher/mod.rs:verify_transaction` | Sum ALL ATA transfers in a tx instead of returning on first match |
| 1.6 | Remove USDC references | `src/main.rs`, `src/svm/spl_token.rs` | Only wUSDT (native Solana USDT) is accepted; USDC paths create confusion |

**Phase 2 — BSC**

| Milestone | Task | File |
|-----------|------|------|
| 2.1 | Fix `decode_transfer` — guard `hex_data.len() >= 64` | `src/watcher/bsc_watcher.rs` |
| 2.2 | Remove USDC from BSC watcher | `src/watcher/bsc_watcher.rs` |
| 2.3 | Deploy BlackbookBridge contract to BSC mainnet | New Solidity |

**Phase 3 — Lightning / BTC**
- Deploy BTCPayServer instance
- Wire `LightningGateway` to live BTCPayServer webhook
- Invoice QR displayed in wallet Deposit modal

**Phase 4 — EVM Template**
- Generalize `BscWatcher` into a `ChainWatcher` trait
- 100-LOC config per new chain (ETH, Polygon, Base, Arbitrum, Optimism)

**Phase 5 — 5-Chain Rollout**
- Deploy bridge contracts + watchers for all 5 EVM chains
- One stablecoin per chain (USDT only) — halves the test matrix

### Stablecoin Policy (locked)
- **Accept:** native Solana USDT (`Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB`) + BSC Binance-Peg USDT
- **Reject:** Solana USDC, Wormhole-wrapped variants, all other SPL tokens
- **Internal credit:** L1 mints `wUSDT` 1:1, then `wUSDT → BB` at dealer rate (1 USDT = 10 BB)

---

## Priority Execution Order

```
Week 1 — Security & Production
  S1  Remove real_wallets/ from Dockerfile
  S2  Verify admin endpoints behind unsafe_admin feature flag
  S3  Lock CORS to explicit origins
  S4  Fix SSS PIN check
  M9  Deploy to Hetzner

Week 2 — Data & Stability
  D1  Graceful shutdown (SIGTERM flush)
  D2  Per-account nonce storage
  M1  Integration test: kill/restart slot continuity
  M10 L2 settlement E2E test

Week 3 — Wallet Compatibility
  M2  simulateTransaction RPC
  M3  Reader → Writer forwarding
  M7  WebSocket subscriptions (accountSubscribe, slotSubscribe)

Week 4 — Observability & Tests
  M4  Dead code removal
  M5  Full test suite
  M6  Prometheus metrics

Ongoing — Product
  M11 Fee markets
  M12 Session keys / agent SDK
  M8  Proof of reserves
  M13 Multi-validator network
  M14 TPS scaling
```
