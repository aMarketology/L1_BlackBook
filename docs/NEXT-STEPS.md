# BlackBook — Next Steps

> **What to do right now, in order.**
> Last updated: May 2026 — Universal Rollup Hub live (L2/L3/L5 bridges complete)

---

## Immediate: Test the BB-only Chain Locally

With the chain stripped to `$BB` + `wUSDT` only, run the smoke suite before re-deploying.

```powershell
# 1. Build and start (admin endpoints enabled for seeding)
cargo run --features unsafe_admin

# 2. In a second terminal — run the full smoke test
.\tests\l1_smoke.ps1
```

**Test coverage of `l1_smoke.ps1`:**

| Test | What it checks |
|------|----------------|
| 5.1 | `/escrow/status` — escrow vault reachable, L2 key configured |
| 5.2a | `/admin/mint` — mint 100 BB to test wallet |
| 5.2b | `/balance/:addr` — balance ≥ 100 after mint |
| 5.3 | `/escrow/contest/:id` — 404 for unknown contest |
| 5.5 | `/escrow/submit-state-root` — HTTP fallback path |

**Manual tests to run after smoke (require `node` or signing helper):**

```powershell
# a) Transfer BB between wallets
curl -X POST http://localhost:8080/transfer/simple \
  -H "Content-Type: application/json" \
  -d '{ "from": "<WALLET_A>", "to": "<WALLET_B>", "amount": 10, ... }'

# b) Swap BB → wUSDT (10 BB = 1 wUSDT)
curl -X POST http://localhost:8080/swap/bb-to-usdc ...

# c) Full escrow lifecycle (requires Ed25519 signed payloads)
#    deposit → submit-state-root → withdraw with merkle proof
node tests/full_flow_test.mjs
```

---

## Next: Deploy to Hetzner (Clean Genesis)

The BB token is $0.10 USD. The old ReDB data was minted at 10:1. Boot the chain clean.

```bash
# SSH into Hetzner
ssh root@<hetzner-ip>

# 1. Stop the node
docker compose -f deployment/docker-compose.prod.yml down

# 2. Wipe the old ReDB volume (10:1 era data)
docker volume rm blackbook-data

# 3. Pull updated code
git pull origin master

# 4. Rebuild and launch with clean genesis
docker compose -f deployment/docker-compose.prod.yml up -d --build

# 5. Verify
curl http://localhost:8080/health
curl http://localhost:8080/supply/audit  # expects backing_ratio: 1.0
```

---

## P0 — Security (Block on Deployment)

These must be done before opening to real users.

### 1. Lock CORS to explicit origins
**File:** `src/main.rs`
```rust
// Change:
.allow_origin(Any)
// To:
.allow_origin("https://blackbook.id".parse::<HeaderValue>().unwrap())
```

### 2. Remove `real_wallets/` from Docker image
**File:** `Dockerfile`
Verify `real_wallets/` is NOT copied in — it's in `.gitignore` but double-check the `COPY` statements in the Dockerfile don't inadvertently pull it in.

### 3. Fix Shard B PIN verification
**File:** `src/kms/` or wallet handler
PIN is currently verified against itself rather than a stored hash. Store `sha256(PIN)` at creation time and verify against that.

---

## P1 — L2 Settlement End-to-End

The escrow contract is fully built on L1. The L2 dealer needs to be confirmed working against the live Hetzner node.

**Checklist:**
- [ ] Dealer submits `POST /escrow/deposit` from L2 and receives `deposit_tx`
- [ ] Dealer calls `POST /escrow/submit-state-root` after market close
- [ ] Winner calls `POST /escrow/withdraw` with Merkle proof and receives BB
- [ ] Run `tests/escrow_e2e.rs` against `http://layer1.blackbook.id`
- [ ] Confirm monotonicity check rejects replayed state roots (HTTP 409)
- [ ] Confirm zero-sum check rejects invalid payout totals (HTTP 400)

**Key files:**
- `sdk/dealer.sdk.ts` — L2 dealer integration
- `sdk/escrow.sdk.ts` — user withdrawal SDK
- `tests/l2_settlement_integration.rs`

---

## P1 — Universal Rollup Hub: Sequencer Integration

The L1 bridge is complete. The sequencers need to update their integrations.

### L2 Sequencer (Prediction Markets)
The L2 dealer currently uses the old `/escrow/...` paths. These still work but should migrate
to the new Rollup Hub paths for consistency and future-proofing.

**Required changes in L2 dealer/sequencer:**
- [ ] Update `lock_bb` calls → `POST /rollup/L2/lock_bb` with signed message:
  `"ROLLUP_LOCK_BB:L2:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"`
- [ ] Update `submit_root` → `POST /rollup/L2/submit_root` with signed message:
  `"ROLLUP_SUBMIT_ROOT:L2:{batch_id}:{merkle_root_hex}:{ts}"`
- [ ] Update `exit` → `POST /rollup/L2/exit` with new **BB leaf format**:
  `SHA-256("L2:BB:{address}:{balance_lamports}")` (colon-separated, NOT old JSON format)
- [ ] Set `L2_SEQUENCER_PUBKEY` env var on Hetzner node
- [ ] Run end-to-end test: `lock_bb → play → submit_root → exit`

**Test in order:**
```bash
# 1. Lock $BB on L1 as if entering L2
curl -X POST http://localhost:8080/rollup/L2/lock_bb -d '{...signed...}'

# 2. (off-chain) L2 plays, sequencer builds Merkle tree with new leaf format
# Leaf = SHA-256("L2:BB:<address>:<balance_lamports>")

# 3. Sequencer submits root
curl -X POST http://localhost:8080/rollup/L2/submit_root -d '{...signed...}'

# 4. User exits
curl -X POST http://localhost:8080/rollup/L2/exit \
  -d '{"asset_type":"BB","address":"...","balance_lamports":500000,...}'
```

### L3 Sequencer (NFT Bridge) — NEW
L1 is ready. L3 execution engine needs to be built.

**Build order:**
- [ ] L3 execution engine (off-chain NFT trading environment)
- [ ] L3 sequencer: builds NFT Merkle tree using exact leaf format:
  `SHA-256("L3:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}")`
- [ ] Set `L3_SEQUENCER_PUBKEY` env var
- [ ] Test NFT exit: `lock_bb → trade → submit_root → exit(asset_type=NFT)`

### L5 Sequencer (Creator Economy) — NEW
L1 bridge fully wired. Execution engine needed.

- [ ] Build L5 bonding curve engine
- [ ] L5 sequencer: `SHA-256("L5:BB:{address}:{balance_lamports}")` leaf format
- [ ] Set `L5_SEQUENCER_PUBKEY` env var

---

## P1 — Wallet Production

- [ ] Strip MAXX / DECAY / $oz UI components from wallet (they reference removed endpoints)
- [ ] Update `tokens.ts` — register only `$BB` and `wUSDT`
- [ ] `SwapModal.tsx` — only show BB ↔ wUSDT swap
- [ ] Lock CORS to explicit origin (see P0 above)
- [ ] Confirm swap pool is seeded: 10 BB = 1 wUSDT ratio
- [ ] Run smoke test: `/supply/audit` shows `target_ratio: 10.0`

---

## P2 — Infrastructure

- [ ] **Multi-validator:** spin up a second Hetzner CX42 as a Reader node
  - Reader connects to Writer via gRPC `SubscribeBlocks` on port 50051
  - Validate block propagation latency < 100ms within same datacenter
- [ ] **Prometheus metrics endpoint** (`GET /metrics`) — slot height, TPS, escrow TVL
- [ ] **Nginx rate limiting** — 429 at load balancer before hitting Rust
- [ ] **Log rotation** — already set to `max-size: 100m` × 7 files in docker-compose

---

## P3 — Load Testing

Run after P0 security items are complete.

```bash
# Sealevel parallel execution load test
cargo run --example sealevel_load_test

# UDP TPU flood test
cargo run --example udp_tpu_load_test

# Full LMSR agent swarm (50 agents, 3 BB each)
MASTER_KEY=<64-hex> AGENT_COUNT=50 BB_PER_AGENT=5 node tests/lmsr_agent_swarm.mjs
```

**Target benchmarks:**
- Sustained TPS ≥ 1,000 (currently 230 tested)
- Escrow deposit → settlement → withdrawal < 5 seconds
- Zero state divergence after 10 simulated node crashes

---

## Ongoing: Code Health

| Item | File | Priority |
|------|------|----------|
| Replace `credit(f64)` with `credit_svm_lamports(u64)` at remaining call sites | `src/main.rs` (lines ~1176, 1256, 1480, 1797) | P1 |
| Remove remaining `f64` from `TransactionRecord` fields | `src/storage/mod.rs` | P2 |
| Add unit test for BB 10:1 invariant at startup | `tests/` | P2 |
| Add unit test for Rollup Hub exit (BB + NFT) | `tests/` | P2 |
| Replace deprecated `load_latest_l5_batch_id` with `latest_rollup_batch_id` | `src/storage/mod.rs` line 2238 | P3 |

---

## Token Economy Reference (BB-only, post-simplification)

| Token | Decimals | 1 Unit = | USD Value |
|-------|----------|----------|-----------|
| `$BB` | 5 | 100,000 lamports | **$0.10** |
| `wUSDT` | 6 | 1,000,000 micro | $1.00 |

**Swap rate:** 10 BB = 1 wUSDT (`BB_TO_USDC_RATE = 10`)
**Gas / collateral / escrow / oracle staking:** all denominated in `$BB` lamports
**MAXX, DECAY, OZ:** removed from L1 (archived in `archive/contracts/`)
