# BlackBook L2 Integration — Step-by-Step To Production

> **Date:** March 20, 2026  
> **Last updated:** March 20, 2026  
> **L1 version:** 5.0.0 (master)  
> **Purpose:** Ordered checklist from current state → first successful end-to-end settlement test.  
> **Current status:** Phase 1 (ops) ✅ complete. Phase 2 (persist data) ✅ complete. Ready for Phase 3 or Phase 5 (E2E test).

---

## Current State (as of March 20, 2026)

### L1 — Complete ✅

| Component | Status | Notes |
|-----------|--------|-------|
| `VerifyDeposit` gRPC handler | ✅ | Reads `deposit_requests` DashMap, returns SPL amount |
| `InitContestReserve` gRPC handler | ✅ | Debits dealer → escrow PDA, creates `ContestState::Open` |
| `SubmitMerkleRoot` gRPC handler | ✅ | Ed25519 verify, zero-sum check, stores root + `ContestState::Settled` |
| `GetContestStatus` gRPC handler | ✅ | Auto-expires to `EXPIRED` when `current_slot > claim_deadline_slot` |
| `SyncBridge` gRPC handler | ✅ | Returns `latest_slot` + `uptime_secs` |
| `POST /escrow/deposit` | ✅ | User locks tokens into escrow PDA |
| `POST /escrow/submit-state-root` | ✅ | HTTP fallback for `SubmitMerkleRoot`; returns `l1_tx_hash`, `l1_finalized_slot`, `claim_deadline_slot` |
| `POST /escrow/withdraw` | ✅ | Merkle proof verification, claim window enforced, double-claim blocked |
| `GET /escrow/status` | ✅ | PDA balance + settled market count |
| `GET /escrow/market/:id` | ✅ | Merkle root only |
| `GET /escrow/contest/:id` | ✅ | Full `ContestState` including deadline, total claimed, status (HTTP alt to gRPC) |
| `proto/settlement.proto` | ✅ | 5 RPCs, all wire types aligned |
| `ContestState` ReDB persistence | ✅ | `store_contest_state`, `load_contest_state`, startup recovery |
| Claim window enforcement | ✅ | `CLAIM_WINDOW_SLOTS = 6_480_000` (~30 days) |
| Zero-sum invariant | ✅ | Both gRPC and HTTP paths enforce it |
| Binary-packed signed message | ✅ | `contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]` |
| Leaf hash format | ✅ | `SHA-256(bs58_pubkey_raw_32 ++ amount_spl_u64_le8)` |
| Sorted-pair Merkle tree | ✅ | Matches L2 `svm_settlement.rs` |

### L2 — Implemented ✅

| Component | L2 File | When |
|-----------|---------|------|
| `VerifyDeposit` gRPC client call | `settlement_bridge.rs` | Prior |
| `InitContestReserve` gRPC client call | `settlement_bridge.rs` | Prior |
| `SubmitMerkleRoot` gRPC client call | `settlement_bridge.rs` | Prior |
| `GetContestStatus` gRPC client call | `settlement_bridge.rs` | Prior |
| Sorted-pair Merkle tree + proofs | `layer_2/svm_settlement.rs` | Session — rewrote from `rs_merkle` |
| SHA-256 leaf format | `layer_2/svm_settlement.rs` | Prior |
| `GET /proof/:market/:wallet` endpoint | `src/main_v3.rs` | Session |
| Zero-sum local check before submit | `src/main_v3.rs` | Prior |
| Ed25519 signing via `L2_SEQUENCER_KEY` | `settlement_bridge.rs` | Prior |
| Proto field tags aligned to L1 wire format | `generated/prism.settlement.v1.rs` | Session — re-tagged to match L1 |
| `l1_tx_hash` + `l1_finalized_slot` + `claim_deadline_slot` on `BbMarket` | `src/types.rs` | Session (Phase 2) |
| Settlement proofs + payouts persisted to redb `SETTLEMENTS_TABLE` | `layer_2/store.rs` | Session (Phase 2) |
| Proofs + payouts reloaded on startup | `src/main_v3.rs` (`startup_load`) | Session (Phase 2) |
| `claim_deadline_slot` in `/proof` response | `src/main_v3.rs` (`h_get_proof`) | Session (Phase 2) |
| Sequencer keypair generated | `.env` → `L2_SEQUENCER_KEY` | Session (Phase 1) |
| L1 env vars configured | L1 `.env` → `L2_SEQUENCER_PUBKEY` | Session (Phase 1) |
| L2 gRPC URL configured | `.env` → `L1_GRPC_URL=http://localhost:50052` | Session (Phase 1) |
| Connectivity verified | L1 `:8080` + `:50052` reachable, `l2_sequencer_configured: true` | Session (Phase 1) |

### L2 — Still Missing ❌

| # | Item | Risk | Priority |
|---|------|------|----------|
| 1 | `SyncBridge` heartbeat background task | No L1 health visibility | P3 |
| 2 | Claim-window expiry handling + `EXPIRED` status | Stale proofs served after deadline | P2 |
| 3 | HTTP fallback if gRPC `SubmitMerkleRoot` fails | Single transport = single point of failure | P3 |

### L2 — Completed This Session ✅ (was missing, now done)

| # | Item | How it was fixed |
|---|------|------------------|
| ~~2~~ | `claim_deadline_slot` stored per-market | Added `l1_tx_hash`, `l1_finalized_slot`, `claim_deadline_slot` fields to `BbMarket` struct in `types.rs`. Computed as `l1_finalized_slot + 6_480_000` after successful `SubmitMerkleRoot`. Included in `/proof` response. |
| ~~4~~ | `l1_tx_hash` + `l1_finalized_slot` persisted to redb | Stored on `BbMarket` in `resolve_bb()` after L1 confirms, saved via `store.save_market()`. Survives restart. |
| ~~6~~ | Settlement proofs/payouts persisted to disk | New `SETTLEMENTS_TABLE` in redb. `store.save_settlement()` writes proofs + payout after resolution. `store.load_all_settlements()` reloads into `settlement_proofs` + `settlement_payouts` HashMaps on startup. |

## Step-by-Step Plan to First Successful Test

---

### Phase 1 — Ops Configuration (no code changes) ✅ COMPLETE

#### Step 1.1 — Generate L2 Sequencer Keypair ✅

**Completed March 20, 2026.**

Generated a 32-byte Ed25519 private key, derived the public key using `src/bin/print_pubkey.rs`.

| Key | Value |
|-----|-------|
| Private (`L2_SEQUENCER_KEY`) | `47d8d39738edff6e48d727126da4ec1683142c95ad456d6424be31847e61ad7f` |
| Public (`L2_SEQUENCER_PUBKEY`) | `bc9359a98d3037e00ac9e7b90e814f89748fd9e1b997c20b06a9924412e8ac2a` |

The private key stays on L2 (`.env`). The public key was set on L1.

**How to regenerate if needed:**
```powershell
# Generate new private key
-join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
# Derive public key
$env:L2_SEQUENCER_KEY = "<64 hex chars>"
cargo run --bin print_pubkey
```

#### Step 1.2 — Set L1 Environment Variables ✅

**Completed March 20, 2026.** Set on L1:

```env
L2_SEQUENCER_PUBKEY=bc9359a98d3037e00ac9e7b90e814f89748fd9e1b997c20b06a9924412e8ac2a
DEALER_PRIVATE_KEY=e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae
```

Verified: `GET /escrow/status` returns `l2_sequencer_configured: true`.

#### Step 1.3 — Set L2 Environment Variables ✅

**Completed March 20, 2026.** Added to L2 `.env`:

```env
L2_SEQUENCER_KEY=47d8d39738edff6e48d727126da4ec1683142c95ad456d6424be31847e61ad7f
L1_GRPC_URL=http://localhost:50052
```

> **Note:** The L2 code reads `L1_GRPC_URL` (not `GRPC_URL`). See `main_v3.rs` line 2809.

#### Step 1.4 — Verify Connectivity ✅

**Completed March 20, 2026.** Both ports confirmed reachable from L2 host:

```
# HTTP — confirmed
GET http://localhost:8080/escrow/status
→ escrow_address: L1_BBE6E168DA6B976D2C017D8B8F86DE48C660824B
→ l2_sequencer_configured: true
→ escrow_balance_lamports: 0

# gRPC — confirmed
Test-NetConnection localhost:50052 → TcpTestSucceeded: True
```

---

### Phase 2 — L2 Code: Persist Critical Data (Priority 1) ✅ COMPLETE

**Completed March 20, 2026.** All changes compile and are on master.

#### Step 2.1 — Persist `l1_tx_hash`, `l1_finalized_slot`, `claim_deadline_slot` ✅

**Files changed:**
- `src/types.rs` — Added 3 new `Option` fields to `BbMarket` struct:
  ```rust
  pub l1_tx_hash: Option<String>,
  pub l1_finalized_slot: Option<u64>,
  pub claim_deadline_slot: Option<u64>,  // l1_finalized_slot + 6_480_000
  ```
- `src/main_v3.rs` — In `resolve_bb()`, after L1 confirms `SubmitMerkleRoot`:
  ```rust
  if l1r.success {
      m.l1_tx_hash = Some(l1r.l1_tx_hash.clone());
      m.l1_finalized_slot = Some(l1r.l1_slot);
      m.claim_deadline_slot = Some(l1r.l1_slot + 6_480_000);
  }
  self.store.save_market(m)?;
  ```
- `src/main_v3.rs` — `h_get_proof()` now includes `claim_deadline_slot` in the JSON response.

All three values are persisted to redb via the existing `MARKETS_TABLE` (serde serialization) and survive restarts.

#### Step 2.2 — Persist Settlement Proofs to Disk ✅

**Files changed:**
- `layer_2/store.rs` — New `SETTLEMENTS_TABLE` in redb:
  - `save_settlement(market_id, payout_spl, proofs)` — stores JSON `{ "payout_spl": u64, "proofs": { "wallet": ["hex",...] } }`
  - `load_all_settlements()` — returns `Vec<(market_id, payout_spl, HashMap<wallet, Vec<[u8;32]>>)>`
- `src/main_v3.rs` — In `resolve_bb()`, after caching proofs in memory:
  ```rust
  self.store.save_settlement(id, payout_spl, &proof_map)?;
  ```
- `src/main_v3.rs` — In `startup_load()`, after loading markets:
  ```rust
  for (market_id, payout_spl, proofs) in self.store.load_all_settlements()? {
      self.settlement_proofs.insert(market_id.clone(), proofs);
      self.settlement_payouts.insert(market_id, payout_spl);
  }
  ```

Proofs now survive L2 restarts. Winners can call `GET /proof` at any time after settlement.

---

### Phase 3 — L2 Code: Expiry & Health (Priority 2)

#### Step 3.1 — Store and Surface `claim_deadline_slot` (§14 item #2)

After completing Step 2.1, the deadline is in redb. Add it to the `GET /proof/:market/:wallet` response:

```json
{
  "proof": [...],
  "payout_spl": 5000000,
  "payout_bb": 5.0,
  "claim_deadline_slot": 7714567,
  "slots_remaining": 480000
}
```

Compute `slots_remaining = claim_deadline_slot - current_l1_slot`. Get `current_l1_slot` from the `SyncBridge` heartbeat (Step 3.3) or cache the last known slot locally.

#### Step 3.2 — Claim-Window Expiry Handling (§14 item #3)

Add a periodic job (every 5 minutes) that:
1. Queries all `SETTLED` markets from redb.
2. For each one, calls `GET http://<L1_HOST>:8080/escrow/contest/<contest_id>` (or the gRPC `GetContestStatus`).
3. If L1 returns `status: "EXPIRED"`, update the L2 market to `Expired`.
4. `GET /proof/:market/:wallet` must check: if market is `Expired`, return `410 Gone`:

```json
{ "error": "Claim window expired", "claim_deadline_slot": 7714567 }
```

#### Step 3.3 — `SyncBridge` Background Heartbeat (§14 item #1)

Add a background task that calls `SyncBridge({ node_id: "l2-dealer" })` every 30 seconds:

```typescript
// Pseudocode — runs as setInterval or tokio::spawn loop
async function syncBridgeLoop() {
  while (true) {
    try {
      const res = await settlementClient.syncBridge({ node_id: "l2-dealer" });
      dealer.l1_latest_slot = res.latest_slot;
      dealer.l1_healthy = true;
    } catch (e) {
      dealer.l1_healthy = false;
      warn("L1 SyncBridge failed:", e.message);
    }
    await sleep(30_000);
  }
}
```

Use `dealer.l1_latest_slot` for `slots_remaining` in Step 3.1.  
Optionally gate new entries when `!dealer.l1_healthy`.

---

### Phase 4 — L2 Code: Resilience (Priority 3)

#### Step 4.1 — HTTP Fallback for `SubmitMerkleRoot` (§14 item #5)

If the gRPC `submit_merkle_root` call fails with a connection error, retry once via HTTP:

```
POST http://<L1_HOST>:8080/escrow/submit-state-root
```

The same binary-packed signed message must be hex-encoded in the JSON body:

```json
{
  "market_id": "contest-123",
  "merkle_root": "<64 hex chars>",
  "l2_block_number": 9001,
  "total_deposited": 10000000,
  "total_payout": 9500000,
  "house_rake": 500000,
  "winner_count": 12,
  "signature": "<128 hex chars — same sig as gRPC sequencer_sig field>"
}
```

L1 response includes `l1_tx_hash`, `l1_finalized_slot`, `claim_deadline_slot` — same as gRPC.

---

### Phase 5 — End-to-End Integration Test

Run these steps in order, checking each response before proceeding.

#### Test 5.1 — Health Check

```bash
# L1 HTTP health
curl http://<L1_HOST>:8080/escrow/status
# Expected:
# { "escrow_address": "...", "l2_sequencer_configured": true,
#   "total_markets_settled": 0, "escrow_balance_lamports": 0 }

# gRPC health via SyncBridge
grpcurl -plaintext -d '{"node_id":"test"}' \
  <L1_HOST>:50052 settlement.SettlementService/SyncBridge
# Expected: { "nodeId": "test", "latestSlot": <N>, "uptimeSecs": <N> }
```

#### Test 5.2 — Deposit

```bash
# Mint some BB on L1 first (dev only)
curl -X POST http://<L1_HOST>:8080/admin/mint \
  -H "Content-Type: application/json" \
  -d '{"to":"<user_wallet>","amount":100}'

# User deposits into escrow
curl -X POST http://<L1_HOST>:8080/escrow/deposit \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_address": "<user_wallet>",
    "amount": 10.0,
    "signature": "<ed25519_sig_hex>",
    "public_key": "<ed25519_pubkey_hex>",
    "timestamp": <unix_ts>,
    "nonce": "<uuid>"
  }'
# Expected: { "success": true, "tx_hash": "...", "new_balance": <N> }
```

#### Test 5.3 — InitContestReserve (via L2 `fund_bb()`)

Trigger on L2. This calls the gRPC `InitContestReserve` RPC. On L1, verify:

```bash
curl http://<L1_HOST>:8080/escrow/contest/<contest_id>
# Expected: { "status": "OPEN", "total_deposited": <N>, "claim_deadline_slot": 0, ... }
```

#### Test 5.4 — VerifyDeposit (via L2 `enter_bb()`)

Trigger on L2. This calls `VerifyDeposit` with the deposit tx signature. On L1, the deposit record must exist in `deposit_requests` with `status: "approved"`.

If using the deposit gateway flow: deposit must be approved via `PATCH /deposit/:id` before `VerifyDeposit` will return `verified: true`.

#### Test 5.5 — SubmitMerkleRoot (via L2 `resolve_bb()`)

Trigger market resolution on L2. This:
1. Builds the sorted-pair Merkle tree over all winners.
2. Binary-packs the signed message: `contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ root[32]`.
3. Signs with `L2_SEQUENCER_KEY`.
4. Calls gRPC `SubmitMerkleRoot`.

Verify on L1:
```bash
curl http://<L1_HOST>:8080/escrow/contest/<contest_id>
# Expected:
# {
#   "status": "SETTLED",
#   "merkle_root": "<64 hex chars>",
#   "claim_deadline_slot": <current_slot + 6480000>,
#   "l1_tx_hash": "...",
#   "total_deposited": <N>,
#   "total_claimed": 0
# }
```

#### Test 5.6 — GetContestStatus Sync

```bash
grpcurl -plaintext \
  -d "{\"contest_id\":\"<contest_id>\"}" \
  <L1_HOST>:50052 settlement.SettlementService/GetContestStatus
# Expected: { "status": "SETTLED", "claimDeadlineSlot": <N>, ... }
```

#### Test 5.7 — Winner Claim (withdraw)

User calls `GET /proof/<contest_id>/<wallet>` on L2, gets the proof array, then:

```bash
curl -X POST http://<L1_HOST>:8080/escrow/withdraw \
  -H "Content-Type: application/json" \
  -d '{
    "market_id": "<contest_id>",
    "amount": 5.0,
    "wallet_address": "<winner_wallet>",
    "merkle_proof": ["<hex_sibling_1>", "<hex_sibling_2>"],
    "public_key": "<winner_pubkey_hex>",
    "signature": "<sig_over_ESCROW_WITHDRAW:...>",
    "timestamp": <unix_ts>,
    "nonce": "<uuid>"
  }'
# Expected: { "success": true, "tx_hash": "...", "amount_paid": 5.0 }
```

Verify `total_claimed` incremented on L1:
```bash
curl http://<L1_HOST>:8080/escrow/contest/<contest_id>
# Expected: "total_claimed": 5000000  (5.0 BB in SPL units)
```

#### Test 5.8 — Double-Claim Blocked

Repeat the same withdrawal request from Test 5.7.
Expected: `409 Conflict — already claimed`.

#### Test 5.9 — Full Tally

After all winners have claimed:
```bash
curl http://<L1_HOST>:8080/escrow/contest/<contest_id>
# total_claimed should equal (total_deposited - house_rake)
```

---

## Summary: Current Status

| Order | Where | Task | Status |
|-------|-------|------|--------|
| 1 | **Ops / L1** | Set `L2_SEQUENCER_PUBKEY` on L1 | ✅ Done — `bc9359a...e8ac2a` |
| 2 | **Ops / L2** | Set `L1_GRPC_URL=http://localhost:50052` | ✅ Done |
| 3 | **Ops / L1** | Set `DEALER_PRIVATE_KEY` | ✅ Done — `e5284b...3654ae` |
| 4 | **L2 code** | Persist `l1_tx_hash` + `l1_finalized_slot` + `claim_deadline_slot` to redb | ✅ Done — `types.rs` + `main_v3.rs` |
| 5 | **L2 code** | Persist Merkle proofs to redb | ✅ Done — `store.rs` `SETTLEMENTS_TABLE` |
| 6 | **L2 code** | Add `SyncBridge` background task every 30s | ❌ Not started |
| 7 | **L2 code** | Add expiry polling + `EXPIRED` status handling | ❌ Not started |
| 8 | **L2 code** | HTTP fallback for `SubmitMerkleRoot` | ❌ Not started |

**All blocking items (1–5) are complete.** The system is ready for a Phase 5 end-to-end integration test.

Items 6–8 are quality-of-life improvements for production but not required for the first test.

---

## What to Do Next

**Option A — Run Phase 5 end-to-end test now.** Everything needed is in place: keys configured, gRPC connected, proofs persisted. Walk through Tests 5.1–5.9 above.

**Option B — Implement Phase 3 first** (SyncBridge heartbeat + expiry handling) for a more production-ready setup before testing.

---

## Files Changed This Session

| File | Changes |
|------|---------|
| `grpc/settlement.proto` | Message names + field tags aligned to L1 wire format |
| `src/generated/prism.settlement.v1.rs` | Rust structs regenerated to match proto |
| `src/settlement_bridge.rs` | Imports + method signatures updated |
| `layer_2/svm_settlement.rs` | Rewrote Merkle tree: `rs_merkle` → custom sorted-pair SHA-256 |
| `src/types.rs` | Added `l1_tx_hash`, `l1_finalized_slot`, `claim_deadline_slot` to `BbMarket` |
| `layer_2/store.rs` | New `SETTLEMENTS_TABLE` + `save_settlement()` / `load_all_settlements()` |
| `src/main_v3.rs` | `/proof` endpoint, payout cache, proof persistence, startup reload, `IntoResponse` import |
| `Cargo.toml` | Removed dead `rs_merkle` dependency |
| `.env` | Added `L2_SEQUENCER_KEY` + `L1_GRPC_URL` |
| `src/bin/print_pubkey.rs` | Utility to derive Ed25519 pubkey from private key |
| `docs/L1_SMART_CONTRACT_SPEC.md` | Comprehensive L1 spec document |
| `L2_INTEGRATION_GUIDE.md` | §14 added: L2 implementation status + gap analysis |

---

*L1 codebase: fully implemented and compiling as of master on March 20, 2026.*  
*L2 codebase: fully compiling. Phases 1–2 complete. Ready for E2E test.*
