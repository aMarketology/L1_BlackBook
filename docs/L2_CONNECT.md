# BlackBook L1 — L2 Connection Guide

> **L1 Version:** 5.0.0  
> **Updated:** March 23, 2026  
> **Dealer address (live):** `WavLzgRxCPmPuiCCW1FA6aFRB6PwTRnNAoBmPWx2qwP`  
> **Dealer balance:** 6,561 BB

---

## Architecture

```
┌─────────────────────────────────────────┐
│           YOUR L2 GAME SERVER           │
│   (PostgreSQL · dealer logic · UI)      │
└────────┬─────────────────────────┬──────┘
         │  HTTP REST :8080        │  gRPC :50052
         ▼                         ▼
┌─────────────────────────────────────────┐
│         BlackBook L1 (this repo)        │
│                                         │
│  Axum HTTP           :8080              │
│  gRPC Settlement     :50052             │
│  gRPC Relay          :50051             │
│  Solana JSON-RPC     :8899              │
│                                         │
│  SVM AccountsDB · ReDB · PoH clock      │
└─────────────────────────────────────────┘
```

L1 is a **pure verifier and vault**:
- Verifies Ed25519 signatures — never trusts caller claims
- Holds BB balances in SVM AccountsDB (u64 lamports)
- Stores nothing about game logic, player metadata, or market descriptions
- All market metadata lives in your L2 PostgreSQL

---

## Ports & Transport

| Service | Protocol | Port | Notes |
|---------|----------|------|-------|
| REST API | HTTP/JSON | `8080` | Balances, escrow, admin payouts |
| Settlement | gRPC/tonic | `50052` | Contest lifecycle — preferred for L2 |
| Block relay | gRPC/tonic | `50051` | Block streaming |
| Solana JSON-RPC | JSON-RPC 2.0 | `8899` | Wallet reads |

---

## Environment Variables

### Set on your L2

```env
L1_API_URL=http://localhost:8080
L1_GRPC_HOST=localhost:50052
L1_DEALER_ADDRESS=WavLzgRxCPmPuiCCW1FA6aFRB6PwTRnNAoBmPWx2qwP
```

### Must be set on L1 for L2 to be trusted

```env
# Your L2 sequencer's Ed25519 pubkey (hex). L1 rejects all SubmitMerkleRoot calls without this.
L2_SEQUENCER_PUBKEY=<your_l2_sequencer_pubkey_hex_32_bytes>

# Dealer key — already set, controls payout authority
DEALER_PRIVATE_KEY=e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae

# Custody wallet where users send real USDC/USDT
CUSTODY_WALLET_ADDRESS=<solana_base58_wallet>
```

> L1 must be running with `--features unsafe_admin` for payout admin endpoints to be active.

---

## Token Units — Critical

**Mismatching units is the #1 integration bug.**

| Context | Unit | Example |
|--------|------|---------|
| HTTP REST amounts | `f64` BB | `10.5` |
| gRPC / Merkle / internal | `u64` SPL units | `10_500_000` |
| ReDB storage | `u64` lamports | same as gRPC |

```
// Conversion
spl_units = (bb_amount * 1_000_000.0).round() as u64
bb_amount = spl_units as f64 / 1_000_000.0

// 1 BB = 1,000,000 SPL units (6 decimal places)
```

---

## Option A — Simple Batch Payout (fastest, what's live now)

No Merkle tree needed. One HTTP call to pay all winners after an event resolves.

```http
POST http://localhost:8080/admin/dealer/settle
Content-Type: application/json

{
  "batch_receipt_id": "nfl_chiefs_ravens_2026_03_23",
  "payouts": [
    { "address": "<winner1_base58>", "amount": 50.0 },
    { "address": "<winner2_base58>", "amount": 45.0 },
    { "address": "<winner3_base58>", "amount": 10.0 }
  ]
}
```

Response:
```json
{
  "success": true,
  "batch_receipt_id": "nfl_chiefs_ravens_2026_03_23",
  "total_paid": 105.0,
  "payout_count": 3,
  "results": [
    { "address": "...", "amount": 50.0, "status": "paid", "new_balance": 50.0 },
    ...
  ]
}
```

- `batch_receipt_id` is your audit trail — use the event ID
- L1 credits each winner directly from chain supply
- Requires `unsafe_admin` feature flag on the running server

---

## Option B — Trustless Escrow + Merkle (full path)

Players bet by locking BB into escrow. Winnings are proven by Merkle proof — no dealer trust required.

### Full Contest Flow

```
1. Dealer → InitContestReserve (gRPC)     lock prize reserve
2. Player → POST /escrow/deposit           lock bet in escrow
3. L2     → VerifyDeposit (gRPC)           confirm deposit canonical identity
4. Event resolves on L2
5. L2 sequencer → SubmitMerkleRoot (gRPC)  finalize payout tree on L1
6. Player → POST /escrow/withdraw          self-claim with Merkle proof
```

---

### Step 1 — Lock Dealer Reserve (gRPC)

```protobuf
// service: SettlementService @ localhost:50052
// proto:   proto/settlement.proto

InitContestReserveRequest {
  contest_id:     "nfl_chiefs_ravens_2026_03_23"
  dealer_address: "WavLzgRxCPmPuiCCW1FA6aFRB6PwTRnNAoBmPWx2qwP"
  bb_reserve:     50_000_000   // 50 BB in SPL units
}
```

Response confirms L1 debited the dealer and created the escrow vault.

---

### Step 2 — Player Deposits (HTTP)

```http
POST http://localhost:8080/escrow/deposit
Content-Type: application/json

{
  "wallet_address": "<player_base58>",
  "amount": 10.0,
  "public_key": "<player_ed25519_pubkey_hex>",
  "signature": "<player_ed25519_sig_hex>",
  "timestamp": 1742476800,
  "nonce": "<uuid>"
}
```

**Player signs this exact UTF-8 string:**
```
ESCROW_DEPOSIT:<wallet_address>:<amount>:<timestamp>:<nonce>

// Example:
ESCROW_DEPOSIT:2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5:10:1742476800:abc-123
```

- `timestamp` must be within 60 seconds of L1 server time
- `nonce` is consumed on use — cannot be reused (replay protection)

---

### Step 3 — Verify Deposit on L2 (gRPC)

```protobuf
VerifyDepositRequest {
  contest_id:      "nfl_chiefs_ravens_2026_03_23"
  deposit_tx_sig:  "<l1_tx_id_from_deposit_response>"
  expected_amount: 10_000_000   // 10 BB in SPL units
}
```

**Always use `response.depositor_wallet` as the canonical player identity — never the self-reported wallet.**

Error codes:

| Code | Meaning |
|------|---------|
| `TX_NOT_FOUND` | Not on L1 yet — retry after 1–2 slots (800ms) |
| `WRONG_CONTEST` | Tx was for a different contest |
| `WRONG_AMOUNT` | Amount mismatch |
| `ALREADY_USED` | Tx already applied |
| `CONTEST_CLOSED` | Not accepting entries |
| `TX_NOT_FINAL` | < 32 confirmations |

---

### Step 4 — Submit Payout Tree After Event Resolves (gRPC)

```protobuf
MerkleRootSubmission {
  contest_id:       "nfl_chiefs_ravens_2026_03_23"
  merkle_root:      <32 raw bytes of SHA-256 Merkle root>
  winner_count:     3
  total_deposited:  100_000_000   // 100 BB in SPL units
  total_payout:     95_000_000    // 95 BB to winners
  house_rake:       5_000_000     // 5 BB to house
  winning_outcome:  "chiefs"
  resolved_at:      <unix_timestamp>
  receipt_hash:     SHA256("contest_id:outcome:ts:deposited:payout:rake")
  l2_block_number:  42            // monotonic — replay protection
  signed_message:   <see Cryptography section below>
  sequencer_pubkey: <32-byte L2 sequencer pubkey, raw bytes>
  sequencer_sig:    <64-byte Ed25519 sig over signed_message, raw bytes>
}
```

**L1 enforces:**
```
total_deposited == total_payout + house_rake   → 400 if violated
```

After success, contest status becomes `SETTLED` and a 30-day claim window opens.

---

### Step 4 (HTTP alternative) — Submit via REST

```http
POST http://localhost:8080/escrow/submit-state-root
Content-Type: application/json

{
  "market_id":       "nfl_chiefs_ravens_2026_03_23",
  "merkle_root":     "<64 hex chars = 32 bytes>",
  "signature":       "<64-byte Ed25519 sig, hex>",
  "l2_block_number": 42,
  "total_deposited": 100000000,
  "total_payout":    95000000,
  "house_rake":      5000000,
  "winner_count":    3
}
```

---

### Step 5 — Player Claims Winnings (HTTP)

```http
POST http://localhost:8080/escrow/withdraw
Content-Type: application/json

{
  "market_id":     "nfl_chiefs_ravens_2026_03_23",
  "amount":        50.0,
  "wallet_address": "<player_base58>",
  "merkle_proof":  ["<hex_sibling_1>", "<hex_sibling_2>"],
  "public_key":    "<player_ed25519_pubkey_hex>",
  "signature":     "<player_ed25519_sig_hex>",
  "timestamp":     1742476800,
  "nonce":         "<uuid>"
}
```

**Player signs this exact UTF-8 string:**
```
ESCROW_WITHDRAW:<market_id>:<wallet_address>:<amount>:<timestamp>:<nonce>
```

L1 checks before releasing funds:
1. Valid Ed25519 signature
2. Nonce not seen before + timestamp within 60s
3. Not already claimed for this `market_id + wallet_address`
4. Contest status is `SETTLED`
5. Current slot ≤ `claim_deadline_slot`
6. Merkle proof verifies against stored root
7. Escrow PDA has sufficient balance

---

## Cryptography

### Signed Message Binary Format (for SubmitMerkleRoot)

```
signed_message = contest_id_utf8_bytes ++ l2_block_number_le8 ++ merkle_root_32_bytes
```

**TypeScript:**
```typescript
function buildSignedMessage(
  contestId: string,
  l2BlockNumber: bigint,
  merkleRoot: Uint8Array   // must be 32 raw bytes, NOT hex string
): Uint8Array {
  const idBytes = new TextEncoder().encode(contestId);
  const blockBytes = new Uint8Array(8);
  new DataView(blockBytes.buffer).setBigUint64(0, l2BlockNumber, true); // little-endian
  const msg = new Uint8Array(idBytes.length + 8 + 32);
  msg.set(idBytes, 0);
  msg.set(blockBytes, idBytes.length);
  msg.set(merkleRoot, idBytes.length + 8);
  return msg;
}

// Then sign:
// const sig = ed25519.sign(signedMessage, sequencerPrivateKey);  // 64 bytes
```

---

### Merkle Leaf Format

```
leaf = SHA-256( pubkey_raw_32_bytes ++ payout_spl_u64_little_endian_8_bytes )
```

**TypeScript:**
```typescript
import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";

function buildLeaf(walletAddress: string, payoutBB: number): Uint8Array {
  const pubkeyBytes = bs58.decode(walletAddress);   // 32 bytes
  const spl = BigInt(Math.round(payoutBB * 1_000_000));
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, spl, true); // little-endian
  const input = new Uint8Array(40);
  input.set(pubkeyBytes, 0);
  input.set(amountBytes, 32);
  return sha256(input);
}
```

---

### Merkle Tree Construction (sorted pair hashing)

At every level, the **smaller** `[u8; 32]` goes first:

```typescript
function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  const cmp = Buffer.compare(left, right);
  return sha256(cmp <= 0 ? concat(left, right) : concat(right, left));
}

function buildTree(leaves: Uint8Array[]): { root: Uint8Array; proofs: Map<number, Uint8Array[]> } {
  // Sort leaves, build bottom-up, collect sibling paths
}
```

Build bottom-up from all winner leaves. The root = `merkle_root` in `SubmitMerkleRoot`. Each winner's proof = sibling path from leaf to root.

---

## Monitoring

```http
GET  /health                        → { status, total_supply, block_count, svm_accounts }
GET  /balance/<wallet_base58>       → { balance: f64, unit: "BB" }
GET  /escrow/status                 → { escrow_balance, total_markets_settled }
GET  /escrow/contest/<contest_id>   → { status, total_deposited, total_claimed, merkle_root }
```

gRPC heartbeat:
```protobuf
SyncBridgeRequest { node_id: "your-l2-node" }
// → SyncBridgeResponse { latest_slot, uptime_secs }
```

---

## Contest Lifecycle

```
InitContestReserve
       │
       ▼  status = OPEN
  Players deposit
       │
  Event resolves on L2
       │
       ▼
  SubmitMerkleRoot
       │  L1 enforces zero-sum invariant
       ▼  status = SETTLED
  Players claim (30-day window)
       │
  After ~6,480,000 slots (30 days @ 400ms/slot)
       │
       ▼  status = EXPIRED — no further claims
```

---

## Claim Window

```
Slot duration:          400ms
Claim window:           6,480,000 slots = 30 days exactly
claim_deadline_slot:    settlement_slot + 6,480,000
```

**Recommendation:** Surface a warning in your L2 UI at 7 days remaining (~1,512,000 slots before deadline). Disable the claim button at expiry.

---

## HTTP Error Reference

| Status | Meaning |
|--------|---------|
| `400` | Bad parameters or zero-sum invariant violated |
| `401` | Ed25519 signature invalid |
| `401` | Merkle proof invalid |
| `404` | No state root found for this market |
| `409` | Nonce already used (replay attack blocked) |
| `409` | Already claimed for this market + wallet |
| `410` | Claim window expired |
| `503` | `L2_SEQUENCER_PUBKEY` not configured on L1 |
| `500` | Internal L1 error |

---

## Pre-Launch Checklist

- [ ] Generate Ed25519 keypair for L2 sequencer; set `L2_SEQUENCER_PUBKEY` on L1
- [ ] Confirm `DEALER_PRIVATE_KEY` and `CUSTODY_WALLET_ADDRESS` set on L1
- [ ] `GET /health` → `200 { "status": "healthy" }`
- [ ] `SyncBridge { node_id: "test" }` → success on gRPC :50052
- [ ] Test `SubmitMerkleRoot` on a staging contest — verify `l1_tx_hash` returned
- [ ] Test `POST /admin/dealer/settle` with 1 payout entry — verify balance credited
- [ ] Confirm L1 running with `--features unsafe_admin` for payout endpoints

---

## Proto Import

```
proto/settlement.proto   → import as gRPC client
                           service SettlementService @ :50052
```

Generate TypeScript client:
```bash
npx grpc_tools_node_protoc \
  --js_out=import_style=commonjs:./src/proto \
  --grpc_out=grpc_js:./src/proto \
  --proto_path=../../proto \
  settlement.proto
```

Or with `@grpc/proto-loader` (runtime, no codegen):
```typescript
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const def = protoLoader.loadSync("../../proto/settlement.proto");
const proto = grpc.loadPackageDefinition(def) as any;
const client = new proto.settlement.SettlementService(
  "localhost:50052",
  grpc.credentials.createInsecure()
);
```
