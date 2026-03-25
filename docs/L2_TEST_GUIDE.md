# BlackBook L2 — Integration Test Guide

> **Date:** March 21, 2026  
> **L1 version:** 5.0.0 (master)  
> **Audience:** L2 developer running the L2 game server against a live L1.  
> **Prerequisite:** L1 is running, Phase 1 ops complete, `l2_sequencer_configured: true` from `GET /escrow/status`.

---

## Overview

These tests must be triggered from the **L2 server**. Each test drives L2 business logic and the result is verified on L1. Tests must be run **in order** — each step creates state that the next step depends on.

| Test | L2 Action | L1 Verification |
|------|-----------|-----------------|
| T1 | `fund_bb(contest_id, reserve_spl)` | `GET /escrow/contest/:id` shows `OPEN` |
| T2 | `enter_bb(user, contest_id, tx_sig)` | `GET /deposit/:tx_sig` shows `approved` |
| T3 | `resolve_bb(contest_id, winners)` | `GET /escrow/contest/:id` shows `SETTLED` |
| T4 | `GET /proof/:market/:wallet` | Proof array + `claim_deadline_slot` returned |
| T5 | — | `POST /escrow/withdraw` on L1 with proof from T4 |
| T6 | — | Repeat T5 → expect `409` |
| T7 | — | `GET /escrow/contest/:id` — `total_claimed` tallies |

---

## Setup

### Environment variables required on L2

```env
L2_SEQUENCER_KEY=47d8d39738edff6e48d727126da4ec1683142c95ad456d6424be31847e61ad7f
L1_GRPC_URL=http://localhost:50052
L1_HTTP_URL=http://localhost:8080
```

### Start L1 first

```powershell
cd L1_BlackBook
cargo run --features unsafe_admin
```

Confirm: `GET http://localhost:8080/escrow/status` → `l2_sequencer_configured: true`

### Start L2

```bash
cd L2_BlackBook   # your L2 repo
cargo run         # or: npm start / node dist/main_v3.js
```

---

## Test T1 — `fund_bb()`: InitContestReserve

**What it does:** L2 calls gRPC `InitContestReserve`. L1 debits the dealer wallet and credits the escrow PDA. Creates a `ContestState` with `status: OPEN`.

**Precondition:** Dealer wallet on L1 must have enough BB.  
Mint it: `POST http://localhost:8080/admin/mint` with `{ "to": "<dealer_address>", "amount": 100.0 }`.  
Dealer address is logged at L1 startup: `🏦 Dealer address: ...`

**Trigger on L2:**
```
fund_bb(contest_id = "test-contest-001", bb_reserve = 10.0)
// bb_reserve is sent as SPL units: 10.0 BB = 10_000_000
```

**Verify on L1:**
```bash
curl http://localhost:8080/escrow/contest/test-contest-001
```
Expected response:
```json
{
  "contest_id": "test-contest-001",
  "status": "OPEN",
  "total_deposited": 10000000,
  "total_claimed": 0,
  "claim_deadline_slot": 0,
  "l1_tx_hash": "<uuid>"
}
```

**Pass criteria:** `status == "OPEN"`, `total_deposited == 10000000`, `claim_deadline_slot == 0`

---

## Test T2 — `enter_bb()`: User Deposit + VerifyDeposit

**What it does:** User deposits BB into L1 escrow. L2 calls gRPC `VerifyDeposit` to confirm the deposit is on-chain before allowing the user to enter the contest.

### Step T2a — Create a test user and deposit

Mint BB to a test user wallet and deposit into escrow:

```bash
# 1. Mint 50 BB to a test wallet
curl -X POST http://localhost:8080/admin/mint \
  -H "Content-Type: application/json" \
  -d '{ "to": "<test_user_wallet_bs58>", "amount": 50.0 }'

# 2. User deposits 10 BB into escrow
# Requires Ed25519 signature: "ESCROW_DEPOSIT:<wallet>:<amount>:<timestamp>:<nonce>"
# Generate using the L2 user keypair or a test script.
curl -X POST http://localhost:8080/escrow/deposit \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_address": "<test_user_wallet_bs58>",
    "amount": 10.0,
    "public_key":  "<user_pubkey_hex_32bytes>",
    "signature":   "<sig_hex_64bytes>",
    "timestamp":   <unix_ts>,
    "nonce":       "<uuid>"
  }'
```

Expected:
```json
{ "success": true, "deposited": 10.0, "escrow_balance": 10.0 }
```

> **Signature format:** `"ESCROW_DEPOSIT:{wallet}:{amount}:{timestamp}:{nonce}"`  
> Amount is the f64 as printed (e.g. `10` not `10.000000`).

### Step T2b — Approve the deposit on L1

The deposit gateway requires approval before `VerifyDeposit` returns `verified: true`:

```bash
# Get the deposit ID
curl http://localhost:8080/deposit/list

# Approve it
curl -X PATCH http://localhost:8080/deposit/<deposit_id>/approve
```

### Step T2c — Trigger L2 `enter_bb()`

```
enter_bb(user_id, contest_id = "test-contest-001", deposit_tx_sig = "<the_deposit_tx_hash>")
```

L2 calls gRPC `VerifyDeposit` with:
- `contest_id`: "test-contest-001"
- `deposit_tx_sig`: the `tx_hash` from the deposit response
- `expected_amount`: 10000000 (SPL units)

**Expected gRPC response:**
```json
{
  "verified": true,
  "depositor_wallet": "<test_user_wallet_bs58>",
  "actual_amount": 10000000,
  "deposit_slot": <N>,
  "error_code": ""
}
```

**Pass criteria:** `verified == true`, `actual_amount == 10000000`

**Common failure:** `error_code: "TX_NOT_FINAL"` — deposit not approved yet. Run Step T2b first.

---

## Test T3 — `resolve_bb()`: SubmitMerkleRoot

**What it does:** L2 resolves the contest. Builds a sorted-pair SHA-256 Merkle tree over all winners, signs the binary-packed message with `L2_SEQUENCER_KEY`, and calls gRPC `SubmitMerkleRoot`. L1 verifies the signature, enforces zero-sum, stores the root, and transitions the contest to `SETTLED`.

**Precondition:** T1 done (contest is `OPEN`).

**Trigger on L2:**
```
resolve_bb(
  contest_id = "test-contest-001",
  winners = [
    { wallet: "<test_user_wallet_bs58>", payout_bb: 9.5 }
  ],
  house_rake_bb = 0.5
)
```

L2 internally:
1. Computes leaves: `SHA-256(pubkey_raw_32 ++ amount_spl_le8)`
2. Builds sorted-pair Merkle tree
3. Binary-packs message: `contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ root[32]`
4. Signs with `L2_SEQUENCER_KEY`
5. Sends gRPC `SubmitMerkleRoot` with:
   - `merkle_root`: 32 raw bytes
   - `total_deposited`: 10000000
   - `total_payout`: 9500000
   - `house_rake`: 500000
   - `winner_count`: 1
   - `signed_message`: binary-packed bytes
   - `sequencer_pubkey`: 32 raw bytes of `L2_SEQUENCER_PUBKEY`
   - `sequencer_sig`: 64 raw bytes

**Expected gRPC response:**
```json
{
  "success": true,
  "l1_tx_hash": "<uuid>",
  "l1_finalized_slot": <N>,
  "error_message": ""
}
```

**Verify on L1:**
```bash
curl http://localhost:8080/escrow/contest/test-contest-001
```
Expected:
```json
{
  "status": "SETTLED",
  "merkle_root": "<64 hex chars>",
  "claim_deadline_slot": <current_slot + 6480000>,
  "total_deposited": 10000000,
  "total_claimed": 0,
  "l1_tx_hash": "<uuid>"
}
```

**Pass criteria:** `status == "SETTLED"`, `claim_deadline_slot > 0`, `merkle_root` is non-zero

**Common failures:**
| Error | Cause | Fix |
|-------|-------|-----|
| `503 L2_SEQUENCER_PUBKEY not configured` | L1 missing env var | Set `L2_SEQUENCER_PUBKEY` on L1, restart |
| `Sequencer signature verification failed` | Wrong key or wrong message format | Verify `signed_message = contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ root[32]` |
| `zero-sum violated` | `total_payout + house_rake != total_deposited` | Check accounting in `resolve_bb()` |
| `merkle_root must be exactly 32 bytes` | Sending hex string instead of raw bytes | Send raw bytes in proto field |

---

## Test T4 — Get Merkle Proof

**What it does:** L2 serves the winner's proof from the settled tree.

**Trigger on L2:**
```
GET /proof/test-contest-001/<test_user_wallet_bs58>
```

Expected L2 response:
```json
{
  "proof": [],
  "payout_spl": 9500000,
  "payout_bb": 9.5,
  "claim_deadline_slot": <N>,
  "slots_remaining": <N>
}
```

> **Note:** For a single-winner tree, the proof array is empty `[]` because the leaf IS the root.  
> For multi-winner trees, the proof contains hex-encoded sibling hashes.

**Pass criteria:** `payout_spl == 9500000`, `claim_deadline_slot > 0`, no `404`

**Common failure:** `404 Not Found` after L2 restart — means proofs weren't persisted. Step 2.2 from `L2_INTEGRATION_STEP_BY_STEP.md` must be implemented.

---

## Test T5 — Winner Claims on L1

**What it does:** User takes the proof from T4 and calls `POST /escrow/withdraw` directly on L1.

**How to generate the required signature:**

The user signs this exact string:
```
ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}
```

Example (Node.js with tweetnacl):
```javascript
const nacl = require('tweetnacl');
const ts = Math.floor(Date.now() / 1000);
const nonce = require('crypto').randomUUID();
const msg = `ESCROW_WITHDRAW:test-contest-001:${wallet}:9.5:${ts}:${nonce}`;
const sig = nacl.sign.detached(Buffer.from(msg), userKeypair.secretKey);
// hex-encode sig and pubkey for the HTTP body
```

**Call on L1:**
```bash
curl -X POST http://localhost:8080/escrow/withdraw \
  -H "Content-Type: application/json" \
  -d '{
    "market_id":      "test-contest-001",
    "amount":         9.5,
    "wallet_address": "<test_user_wallet_bs58>",
    "merkle_proof":   [],
    "public_key":     "<user_pubkey_hex>",
    "signature":      "<sig_hex>",
    "timestamp":      <unix_ts>,
    "nonce":          "<uuid>"
  }'
```

Expected:
```json
{ "success": true, "withdrawn": 9.5, "new_balance": <N> }
```

**Verify `total_claimed` updated on L1:**
```bash
curl http://localhost:8080/escrow/contest/test-contest-001
# "total_claimed": 9500000
```

**Pass criteria:** `success == true`, `total_claimed` incremented by 9500000

**Common failures:**
| HTTP status | Error | Cause |
|-------------|-------|-------|
| `401` | Signature verification failed | Wrong message format or key mismatch |
| `404` | No state root found | T3 not done yet |
| `409` | Already withdrawn | Double-claim (correct for T6) |
| `410` | Claim window expired | `claim_deadline_slot` passed |
| `400` | Merkle proof verification failed | Wrong proof, wrong payout amount, wrong wallet |

> **Critical:** `amount` in the withdraw body must match the leaf exactly.  
> Leaf is computed as `SHA-256(pubkey_raw_32 ++ amount_spl_u64_le8)` where `amount_spl = round(amount_bb * 1_000_000)`.  
> If the L2 stored the payout as `9.5` BB, pass `9.5` here — do not round differently.

---

## Test T6 — Double-Claim Blocked

**What it does:** Repeat the exact same withdraw request from T5.

Expected: HTTP `409 Conflict`
```json
{
  "error": "Already withdrawn for this market",
  "market_id": "test-contest-001",
  "wallet_address": "<test_user_wallet_bs58>"
}
```

> **Note:** The nonce replay protection also blocks reuse (`409 Nonce already used`).  
> To test double-claim specifically (not nonce replay), change the nonce but keep all other fields identical.  
> The `withdrawal_claims` DashMap keyed on `{market_id}:{wallet}` will reject it regardless.

**Pass criteria:** HTTP `409`, error message references market + wallet

---

## Test T7 — Full Tally

**What it does:** Confirms all claimed tokens account for the full payout pool.

```bash
curl http://localhost:8080/escrow/contest/test-contest-001
```

Expected:
```json
{
  "status": "SETTLED",
  "total_deposited": 10000000,
  "total_claimed":   9500000,
  "house_rake":        500000
}
```

Invariant to check:
```
total_claimed == total_deposited - house_rake
9500000      == 10000000          - 500000   ✓
```

**Pass criteria:** `total_claimed + house_rake == total_deposited`

---

## Test T8 — GetContestStatus gRPC Direct

**What it does:** Verify the gRPC path independently of HTTP.

Using `grpcurl` (install: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`):

```bash
grpcurl -plaintext \
  -d '{"contest_id":"test-contest-001"}' \
  localhost:50052 settlement.SettlementService/GetContestStatus
```

Expected:
```json
{
  "contestId": "test-contest-001",
  "status": "SETTLED",
  "totalDeposited": "10000000",
  "totalClaimed": "9500000",
  "merkleRoot": "<base64 32 bytes>",
  "claimDeadlineSlot": "<N>",
  "l1TxHash": "<uuid>"
}
```

---

## Test T9 — SyncBridge Heartbeat

```bash
grpcurl -plaintext \
  -d '{"node_id":"l2-test"}' \
  localhost:50052 settlement.SettlementService/SyncBridge
```

Expected:
```json
{
  "nodeId": "l2-test",
  "latestSlot": "<N>",
  "uptimeSecs": "<N>"
}
```

**Pass criteria:** `latestSlot > 0`, `uptimeSecs > 0`

---

## Test Pass/Fail Summary

| Test | Trigger | Verify on L1 | Pass Criteria |
|------|---------|-------------|---------------|
| T1 InitContestReserve | L2 `fund_bb()` | `GET /escrow/contest/:id` | `status: OPEN` |
| T2 VerifyDeposit | L2 `enter_bb()` | gRPC response | `verified: true` |
| T3 SubmitMerkleRoot | L2 `resolve_bb()` | `GET /escrow/contest/:id` | `status: SETTLED`, deadline set |
| T4 GetProof | L2 `GET /proof` | L2 response | proof array + `claim_deadline_slot` |
| T5 Withdraw | L1 HTTP direct | L1 response + `/contest/:id` | `success: true`, `total_claimed` incremented |
| T6 Double-claim | L1 HTTP direct | L1 response | `409 Conflict` |
| T7 Tally | L1 HTTP direct | `/escrow/contest/:id` | `total_claimed + house_rake == total_deposited` |
| T8 gRPC Status | grpcurl direct | gRPC response | `status: SETTLED` |
| T9 SyncBridge | grpcurl direct | gRPC response | `latestSlot > 0` |

---

## Crypto Reference (what L2 must match exactly)

### Leaf hash
```
leaf = SHA-256( bs58_decode(wallet_address)[0..32] ++ (amount_bb * 1_000_000).round().to_le_bytes() )
```

### Merkle tree
- Sort each pair: `if left <= right: hash(left ++ right)` else `hash(right ++ left)`
- Odd node: duplicate it — `hash(node ++ node)`

### SubmitMerkleRoot signed message
```
msg = contest_id.as_bytes() ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]
sig = ed25519_sign(L2_SEQUENCER_PRIVATE_KEY, msg)
```

### Withdraw signed message
```
msg = "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount_f64}:{timestamp_unix}:{nonce_uuid}"
sig = ed25519_sign(USER_PRIVATE_KEY, msg)
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| All gRPC calls fail to connect | `L1_GRPC_URL` points to 50051 (relay) not 50052 (settlement) |
| `503 L2_SEQUENCER_PUBKEY not configured` | Not set on L1 `.env`, or L1 not restarted after setting |
| `Sequencer signature verification failed` | Binary message format mismatch — check byte order |
| `merkle_root must be exactly 32 bytes` | Sending hex string in field, not raw bytes |
| Proofs return 404 after L2 restart | Persistence not implemented — see Phase 2 of `L2_INTEGRATION_STEP_BY_STEP.md` |
| `410 Gone` on withdraw | Claim window closed (`claim_deadline_slot` passed) |
| `400 Merkle proof verification failed` | Amount or wallet doesn't match the leaf that was committed |

---

*See [L2_INTEGRATION_GUIDE.md](L2_INTEGRATION_GUIDE.md) for full protocol specification.*  
*See [L2_INTEGRATION_STEP_BY_STEP.md](L2_INTEGRATION_STEP_BY_STEP.md) for current implementation status.*
