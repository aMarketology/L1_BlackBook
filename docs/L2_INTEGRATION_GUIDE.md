# BlackBook L1 — L2 Integration Guide

> **Last updated:** March 20, 2026  
> **L1 version:** 5.0.0  
> **Status:** Fully implemented, compiling

This document is the single source of truth for connecting a BlackBook L2 game server to the L1 settlement chain. It covers every transport, every message format, every cryptographic invariant, and every error code your L2 must handle.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Ports & Transport](#2-ports--transport)
3. [Environment Variables (L1 side)](#3-environment-variables-l1-side)
4. [Token Units](#4-token-units)
5. [gRPC Settlement Service](#5-grpc-settlement-service)
   - [VerifyDeposit](#51-verifydeposit)
   - [InitContestReserve](#52-initcontestreserve)
   - [SubmitMerkleRoot](#53-submitmerkleroot)
   - [GetContestStatus](#54-getconteststatus)
   - [SyncBridge](#55-syncbridge)
6. [HTTP Escrow Contract](#6-http-escrow-contract)
   - [POST /escrow/deposit](#61-post-escrowdeposit)
   - [POST /escrow/submit-state-root](#62-post-escrowsubmit-state-root)
   - [POST /escrow/withdraw](#63-post-escrowwithdraw)
   - [GET /escrow/status](#64-get-escrowstatus)
7. [Cryptographic Specifications](#7-cryptographic-specifications)
   - [Signed Message Binary Format](#71-signed-message-binary-format)
   - [Merkle Leaf Hash Format](#72-merkle-leaf-hash-format)
   - [Merkle Tree Construction](#73-merkle-tree-construction)
8. [Contest Lifecycle](#8-contest-lifecycle)
9. [Zero-Sum Invariant](#9-zero-sum-invariant)
10. [Claim Window & Deadline Slots](#10-claim-window--deadline-slots)
11. [Error Codes & HTTP Status Reference](#11-error-codes--http-status-reference)
12. [L2 Integration Checklist](#12-l2-integration-checklist)
13. [Pseudocode Examples](#13-pseudocode-examples)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────┐
│           L2 Game Server            │
│  (PostgreSQL · dealer logic · UI)   │
└──────────┬──────────────────────────┘
           │  gRPC :50052 + HTTP :8080
           ▼
┌─────────────────────────────────────┐
│       BlackBook L1 (this repo)      │
│  Axum HTTP :8080                    │
│  tonic gRPC relay    :50051         │
│  tonic gRPC settlement :50052       │
│  JSON-RPC (Solana compat) :8899     │
│  ReDB storage · SVM · PoH clock     │
└─────────────────────────────────────┘
```

The L1 is a **pure verifier and vault**:
- It verifies Ed25519 signatures — it never trusts caller claims.
- It holds BB token balances in SVM AccountsDB (u64 lamports).
- It does not store game logic, player metadata, or market descriptions.
- All market metadata (names, outcomes, odds) lives in L2 PostgreSQL.

---

## 2. Ports & Transport

| Service | Protocol | Default Port | Env Override |
|---------|----------|-------------|--------------|
| HTTP API | REST/JSON | `8080` | `HTTP_PORT` |
| Relay (block streaming) | gRPC / tonic | `50051` | `GRPC_PORT` |
| **Settlement** | **gRPC / tonic** | **`50052`** | **`SETTLEMENT_GRPC_PORT`** |
| Solana JSON-RPC compat | JSON-RPC 2.0 | `8899` | `RPC_PORT` |

The settlement gRPC port defaults to `GRPC_PORT + 1 = 50052`. Override with:
```
SETTLEMENT_GRPC_PORT=50052
```

Proto file location: [`proto/settlement.proto`](../proto/settlement.proto)

---

## 3. Environment Variables (L1 side)

These **must** be set on the L1 server before it can interoperate with L2:

| Variable | Required | Description |
|----------|----------|-------------|
| `L2_SEQUENCER_PUBKEY` | **Yes** | Hex-encoded 32-byte Ed25519 public key of the L2 sequencer. All `SubmitMerkleRoot` calls are rejected without this. |
| `CUSTODY_WALLET_ADDRESS` | Yes | Base58 Solana wallet that users send USDC/USDT to. The watcher auto-mints BB on deposit. |
| `DEALER_PRIVATE_KEY` | Yes | Hex Ed25519 private key of the dealer. Used for InitContestReserve fund locking and withdrawal releases. |
| `SETTLEMENT_GRPC_PORT` | No | Default `50052`. |

---

## 4. Token Units

**CRITICAL — mismatching units is the #1 integration bug.**

| Context | Unit | Example |
|---------|------|---------|
| HTTP API amounts (user-facing) | `f64` BB | `1.5` = 1.5 BB |
| gRPC / internal / Merkle | `u64` SPL units | `1_500_000` = 1.5 BB |
| ReDB storage | `u64` SPL lamports | same as gRPC |
| `total_deposited`, `total_payout`, `house_rake` | `u64` SPL units | always |

**Conversion:**
```
spl_units = (bb_amount * 1_000_000.0).round() as u64
bb_amount = spl_units as f64 / 1_000_000.0
```

There are exactly **6 decimal places**. `1 BB = 1,000,000 SPL units`.

---

## 5. gRPC Settlement Service

Import the proto from [`proto/settlement.proto`](../proto/settlement.proto).

Connect to `L1_HOST:50052` (or `SETTLEMENT_GRPC_PORT`).

---

### 5.1 VerifyDeposit

Called by L2 on every user entry payment. Verifies the deposit transaction on L1 and returns the canonical depositor wallet. **L2 MUST use the returned `depositor_wallet` as the user's identity** — never trust the self-reported wallet.

**Request:**
```protobuf
message VerifyDepositRequest {
    string contest_id      = 1;
    string deposit_tx_sig  = 2;  // base58 Solana sig or hex string
    uint64 expected_amount = 3;  // SPL units — 0 = "any amount"
}
```

**Response:**
```protobuf
message VerifyDepositResponse {
    bool   verified         = 1;
    string depositor_wallet = 2;  // CANONICAL identity — use this
    uint64 actual_amount    = 3;  // SPL units
    uint64 deposit_slot     = 4;
    string error_code       = 5;
}
```

**Error codes:**

| `error_code` | Meaning |
|---|---|
| `TX_NOT_FOUND` | Tx not on L1 yet — retry after 1–2 slots |
| `WRONG_CONTEST` | Tx was for a different contest |
| `WRONG_AMOUNT` | Amount does not match `expected_amount` |
| `ALREADY_USED` | This tx was already applied |
| `CONTEST_CLOSED` | Contest no longer accepting entries |
| `TX_NOT_FINAL` | Tx not yet finalized (< 32 confirmations) |

---

### 5.2 InitContestReserve

Called by the dealer before opening a market. Locks BB from the dealer's wallet into the contest escrow reserve.

**Request:**
```protobuf
message InitContestReserveRequest {
    string contest_id     = 1;
    string dealer_address = 2;  // base58 dealer wallet
    uint64 bb_reserve     = 3;  // SPL units to lock
}
```

**Response:**
```protobuf
message InitContestReserveResponse {
    bool   confirmed     = 1;
    string l1_tx_hash    = 2;  // UUID of the L1 escrow transaction
    string error_message = 3;
}
```

---

### 5.3 SubmitMerkleRoot

Called by the L2 sequencer after a contest resolves. This is the **most critical RPC** — it permanently finalizes the payout tree on L1 and opens the 30-day claim window.

**Request:**
```protobuf
message MerkleRootSubmission {
    string contest_id      =  1;
    bytes  merkle_root     =  2;  // exactly 32 bytes
    uint32 winner_count    =  3;
    uint64 total_deposited =  4;  // SPL units
    uint64 total_payout    =  5;  // SPL units (net to winners)
    uint64 house_rake      =  6;  // SPL units
    string winning_outcome =  7;
    int64  resolved_at     =  8;  // Unix timestamp
    string receipt_hash    =  9;  // SHA-256 of "id:outcome:ts:dep:payout:rake"
    string oracle_proof    = 10;
    uint64 l2_block_number = 11;  // monotonic — replay protection
    bytes  signed_message  = 12;  // see §7.1 for exact binary format
    bytes  sequencer_pubkey = 13; // 32-byte Ed25519 verifying key
    bytes  sequencer_sig   = 14;  // 64-byte Ed25519 signature
}
```

**Invariant enforced by L1:**
```
total_deposited == total_payout + house_rake   (400 BAD REQUEST if violated)
```

**Response:**
```protobuf
message MerkleRootResponse {
    bool   success           = 1;
    string l1_tx_hash        = 2;
    uint64 l1_finalized_slot = 3;
    string error_message     = 4;
}
```

---

### 5.4 GetContestStatus

Poll from L2 at any time to check current contest state.

**Request:**
```protobuf
message ContestStatusRequest {
    string contest_id = 1;
}
```

**Response:**
```protobuf
message ContestStatusResponse {
    string contest_id          = 1;
    string status              = 2;  // "OPEN" | "SETTLED" | "EXPIRED"
    uint64 total_deposited     = 3;  // SPL units
    uint64 total_claimed       = 4;  // SPL units (live — increments on each claim)
    bytes  merkle_root         = 5;  // 32 bytes, zero if status == OPEN
    uint64 claim_deadline_slot = 6;
    string l1_tx_hash          = 7;
}
```

---

### 5.5 SyncBridge

Heartbeat / TPS monitoring. Call periodically to confirm L1 is alive and synced.

```protobuf
// Request
message SyncBridgeRequest  { string node_id = 1; }
// Response
message SyncBridgeResponse { string node_id = 1; uint64 latest_slot = 2; uint64 uptime_secs = 3; }
```

---

## 6. HTTP Escrow Contract

Base URL: `http://L1_HOST:8080`

All request/response bodies are `application/json`. All Ed25519 keys and signatures are **lowercase hex** strings.

---

### 6.1 POST /escrow/deposit

User locks BB tokens into the global escrow PDA before entering a market.

**Request body:**
```json
{
  "wallet_address": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
  "amount": 10.0,
  "public_key": "<32-byte Ed25519 pubkey, hex>",
  "signature": "<64-byte Ed25519 sig, hex>",
  "timestamp": 1742476800,
  "nonce": "uuid-or-random-string"
}
```

**Signed message (UTF-8 string, NOT binary):**
```
"ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

Example:
```
"ESCROW_DEPOSIT:2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5:10:1742476800:abc123"
```

**Success response `200`:**
```json
{
  "success": true,
  "deposited": 10.0,
  "wallet_address": "2Qmb...",
  "escrow_address": "bbescrow_...",
  "user_balance": 90.0,
  "escrow_balance": 10.0
}
```

**Replay protection:** `timestamp` must be within 60 seconds of L1 server time. The `nonce` is consumed and cannot be reused.

---

### 6.2 POST /escrow/submit-state-root

L2 sequencer submits the final payout Merkle root for a settled contest. This endpoint is the **HTTP equivalent** of the `SubmitMerkleRoot` gRPC call — use whichever transport your L2 sequencer prefers (gRPC is recommended for lower latency).

**Request body:**
```json
{
  "market_id": "contest_abc123",
  "merkle_root": "a1b2c3...64hexchars",
  "signature": "<64-byte Ed25519 sig of the binary packed message, hex>",
  "l2_block_number": 42,
  "total_deposited": 10000000,
  "total_payout": 9500000,
  "house_rake": 500000,
  "winner_count": 3
}
```

**Signed message — binary packed (see §7.1):**
```
bytes = contest_id.as_bytes() ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]
```

The `signature` field must sign this exact byte sequence. **The old `"STATE_ROOT:{id}:{root}:{block}"` string format is no longer accepted.**

**Success response `200`:**
```json
{
  "success": true,
  "market_id": "contest_abc123",
  "merkle_root": "a1b2c3...",
  "l2_block_number": 42,
  "slot": 1234567
}
```

---

### 6.3 POST /escrow/withdraw

User claims their winnings by providing a Merkle proof. Called directly by the user (or by L2 on the user's behalf with the user's signature).

**Request body:**
```json
{
  "market_id": "contest_abc123",
  "amount": 3.5,
  "wallet_address": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
  "merkle_proof": [
    "aabbcc...64hexchars",
    "ddeeff...64hexchars"
  ],
  "public_key": "<32-byte Ed25519 pubkey, hex>",
  "signature": "<64-byte Ed25519 sig, hex>",
  "timestamp": 1742476800,
  "nonce": "uuid-or-random-string"
}
```

**Signed message (UTF-8 string):**
```
"ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

**L1 enforces before releasing funds:**
1. Valid Ed25519 signature — proves caller owns the wallet
2. Nonce not seen before + timestamp within 60s
3. Not already claimed for this `market_id + wallet_address`
4. Contest status is `SETTLED` (not `OPEN` or `EXPIRED`)
5. `current_slot <= claim_deadline_slot` (30-day window)
6. Merkle proof verifies against the stored root (see §7.2)
7. Escrow PDA has sufficient balance

**Success response `200`:**
```json
{
  "success": true,
  "withdrawn": 3.5,
  "market_id": "contest_abc123",
  "wallet_address": "2Qmb...",
  "new_balance": 103.5
}
```

**Failure `410 Gone`** — claim window expired:
```json
{
  "error": "Claim window has expired for this contest",
  "current_slot": 8100000,
  "claim_deadline_slot": 7900000
}
```

---

### 6.4 GET /escrow/status

```
GET /escrow/status
```

```json
{
  "escrow_address": "bbescrow_...",
  "escrow_balance_lamports": 150.0,
  "total_markets_settled": 7,
  "l2_sequencer_configured": true
}
```

---

## 7. Cryptographic Specifications

### 7.1 Signed Message Binary Format

Used by **SubmitMerkleRoot** (both gRPC and HTTP).

```
signed_message = contest_id_bytes ++ l2_block_number_le8 ++ merkle_root_32
```

- `contest_id_bytes`: raw UTF-8 bytes of the contest ID string (no null terminator, no length prefix)
- `l2_block_number_le8`: `l2_block_number` encoded as 8 bytes little-endian (`u64::to_le_bytes()`)
- `merkle_root_32`: raw 32 bytes of the SHA-256 Merkle root (not the hex string — decode the hex first)

Total length: `len(contest_id) + 8 + 32` bytes.

**TypeScript example:**
```typescript
function buildSignedMessage(contestId: string, l2BlockNumber: bigint, merkleRoot: Uint8Array): Uint8Array {
  const idBytes = new TextEncoder().encode(contestId);
  const blockBytes = new Uint8Array(8);
  new DataView(blockBytes.buffer).setBigUint64(0, l2BlockNumber, true); // little-endian
  const msg = new Uint8Array(idBytes.length + 8 + 32);
  msg.set(idBytes, 0);
  msg.set(blockBytes, idBytes.length);
  msg.set(merkleRoot, idBytes.length + 8);  // must be raw 32 bytes, not hex
  return msg;
}
```

**Rust reference (from L1 source):**
```rust
let mut signed_message: Vec<u8> = Vec::with_capacity(contest_id.len() + 8 + 32);
signed_message.extend_from_slice(contest_id.as_bytes());
signed_message.extend_from_slice(&l2_block_number.to_le_bytes());
signed_message.extend_from_slice(&merkle_root_bytes); // [u8; 32]
```

The signature is `ed25519_sign(sequencer_private_key, signed_message)` using the standard Ed25519 algorithm (RFC 8032). For HTTP, encode the 64-byte signature as lowercase hex; for gRPC, send as raw bytes.

---

### 7.2 Merkle Leaf Hash Format

Each winner leaf is:
```
leaf = SHA-256(pubkey_raw_32 ++ amount_spl_u64_le8)
```

- `pubkey_raw_32`: the winner's wallet address decoded from base58 → raw 32 bytes. **NOT** the base58 string, **NOT** a hex string — the raw decoded bytes.
- `amount_spl_u64_le8`: the payout amount in SPL units (u64), encoded as 8 bytes little-endian.

**TypeScript example:**
```typescript
import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";

function buildLeaf(walletAddress: string, payoutBB: number): Uint8Array {
  const pubkeyBytes = bs58.decode(walletAddress);  // must be 32 bytes
  if (pubkeyBytes.length !== 32) throw new Error("Invalid pubkey");

  const spl = BigInt(Math.round(payoutBB * 1_000_000));
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, spl, true); // little-endian

  const input = new Uint8Array(40);
  input.set(pubkeyBytes, 0);
  input.set(amountBytes, 32);
  return sha256(input);  // 32-byte leaf hash
}
```

---

### 7.3 Merkle Tree Construction

The tree uses **sorted pair hashing** — at every level, the smaller `[u8; 32]` goes first:

```typescript
function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (compareBytes(left, right) <= 0) {
    return sha256(concat(left, right));
  } else {
    return sha256(concat(right, left));
  }
}
```

**Rust reference (from L1 withdraw handler):**
```rust
if current <= sibling {
    hasher.update(current);
    hasher.update(sibling);
} else {
    hasher.update(sibling);
    hasher.update(current);
}
```

Build the tree bottom-up from all winner leaves. The root is the `merkle_root` submitted to L1. Each user's proof is the sibling path from their leaf to the root.

---

## 8. Contest Lifecycle

```
                  InitContestReserve (gRPC)
                         │
                         ▼ status = OPEN
                  Users deposit via
                  POST /escrow/deposit
                         │
                  Contest resolves on L2
                         │
                         ▼
                  SubmitMerkleRoot (gRPC or HTTP)
                         │  zero-sum check enforced
                         ▼ status = SETTLED
                  Users claim via
                  POST /escrow/withdraw
                  (up to claim_deadline_slot)
                         │
                  After ~30 days (6,480,000 slots)
                         │
                         ▼ status = EXPIRED
                  No further claims accepted
```

**ContestState fields stored on L1:**

| Field | Type | Description |
|-------|------|-------------|
| `contest_id` | String | Unique market identifier |
| `status` | Enum | `OPEN` / `SETTLED` / `EXPIRED` |
| `merkle_root` | `[u8; 32]` | SHA-256 root, zero bytes when OPEN |
| `total_deposited` | `u64` | SPL units — sum of all entry fees |
| `total_claimed` | `u64` | SPL units — live counter, increments on each user claim |
| `winner_count` | `u32` | Number of entries in the payout Merkle tree |
| `house_rake` | `u64` | SPL units — platform cut |
| `claim_deadline_slot` | `u64` | Last slot at which `/escrow/withdraw` is accepted |
| `l1_tx_hash` | String | UUID of the SubmitMerkleRoot settlement transaction |
| `last_l2_block` | `u64` | Monotonic L2 block counter at settlement time |
| `created_at` | `u64` | Unix timestamp (seconds) |

---

## 9. Zero-Sum Invariant

L1 enforces at settlement time:

```
total_deposited == total_payout + house_rake
```

This guarantees every deposited token is accounted for. Submission fails with `400 Bad Request` if violated.

In SPL units:
```
10,000,000 == 9,500,000 + 500,000   ✓  (10 BB total: 9.5 BB to winners, 0.5 BB rake)
10,000,000 == 9,000,000 + 500,000   ✗  400: zero-sum invariant violated
```

`total_payout` is the **net amount given to all winners combined**. It is NOT the gross pot — it is the sum of all individual payouts in the Merkle tree.

---

## 10. Claim Window & Deadline Slots

L1 operates at **400ms per slot**.

```
CLAIM_WINDOW_SLOTS = 6,480,000
                   ≈ 30 days
                   = 6,480,000 × 0.4s
                   = 2,592,000s
                   = 30 days exactly
```

When `SubmitMerkleRoot` is accepted, L1 sets:
```
claim_deadline_slot = current_l1_slot + 6_480_000
```

After that slot, `/escrow/withdraw` returns `410 Gone`. L2 should surface this to users and stop serving the claim UI.

**L2 recommendation:** warn users at 7 days remaining (~1,512,000 slots before deadline), and disable the claim UI at deadline.

---

## 11. Error Codes & HTTP Status Reference

| Endpoint | Status | Condition |
|----------|--------|-----------|
| Any | `400` | Missing/invalid parameters |
| Any | `400` | Zero-sum invariant violated |
| Any | `401` | Ed25519 signature verification failed |
| Any | `401` | Merkle proof does not match stored root |
| Any | `409` | Nonce already used (replay attack) |
| Any | `409` | Already withdrawn for this market+wallet |
| Any | `404` | No state root found for market |
| Withdraw | `400` | Contest not yet settled (status != SETTLED) |
| Withdraw | `410` | Claim window expired |
| Submit-root | `503` | `L2_SEQUENCER_PUBKEY` not configured on L1 |
| Any | `500` | Internal L1 error (escrow debit/credit failure) |

---

## 12. L2 Integration Checklist

### Pre-launch (one-time)

- [ ] Generate Ed25519 keypair for L2 sequencer; set `L2_SEQUENCER_PUBKEY` (hex) as L1 env var
- [ ] Confirm `CUSTODY_WALLET_ADDRESS` and `DEALER_PRIVATE_KEY` are set on L1
- [ ] Confirm L1 responds: `GET /health` → 200
- [ ] Confirm Settlement gRPC responds: `SyncBridge({node_id: "test"})` → success
- [ ] In staging: call `SubmitMerkleRoot` with a dummy contest and verify the returned `l1_tx_hash`

### Per-contest

- [ ] Call `InitContestReserve` before opening the market
- [ ] On user entry: call `VerifyDeposit` to get canonical `depositor_wallet`; store gRPC result in L2 DB
- [ ] On market close: compute Merkle tree using **exact leaf format** (§7.2)
- [ ] Verify locally: `sum(all_payouts) + house_rake == total_deposited_spl`
- [ ] Build `signed_message` using **binary packing** (§7.1) and sign with sequencer key
- [ ] Call `SubmitMerkleRoot` (gRPC) or `POST /escrow/submit-state-root` (HTTP)
- [ ] Store `l1_tx_hash` and `claim_deadline_slot` in L2 DB
- [ ] Expose claim UI to winners with their proof path
- [ ] Set a reminder to mark contests `EXPIRED` in L2 DB after `claim_deadline_slot`

### Per withdrawal

- [ ] Supply user with their Merkle proof array (sibling hashes, hex-encoded)
- [ ] Client calls `POST /escrow/withdraw` with their Ed25519 signature 
- [ ] On `410 Gone`: display "Claim window has closed for this contest"
- [ ] On `409 Conflict`: display "Winnings already claimed"

---

## 13. Pseudocode Examples

### Build and submit a Merkle root (TypeScript)

```typescript
import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";
import * as nacl from "tweetnacl";

// ── 1. Build winner leaves ────────────────────────────────────────────────────
function buildLeaf(wallet: string, payoutBB: number): Uint8Array {
  const pubkey = bs58.decode(wallet);                          // 32 raw bytes
  const spl = BigInt(Math.round(payoutBB * 1_000_000));
  const spl8 = new Uint8Array(8);
  new DataView(spl8.buffer).setBigUint64(0, spl, true);        // little-endian u64
  const input = new Uint8Array(40);
  input.set(pubkey, 0);
  input.set(spl8, 32);
  return sha256(input);
}

// ── 2. Build Merkle tree (sorted pair hashing) ─────────────────────────────────
function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  const combined = new Uint8Array(64);
  if (compareUint8Arrays(a, b) <= 0) { combined.set(a, 0); combined.set(b, 32); }
  else                               { combined.set(b, 0); combined.set(a, 32); }
  return sha256(combined);
}

function buildTree(leaves: Uint8Array[]): { root: Uint8Array; proofs: Uint8Array[][] } {
  let layer = [...leaves];
  const levels: Uint8Array[][] = [layer];
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(hashPair(layer[i], right));
    }
    levels.unshift(next);
    layer = next;
  }
  // extract proofs for each leaf index (omitted for brevity)
  return { root: levels[0][0], proofs: [] };
}

// ── 3. Build signed message (binary packed) ────────────────────────────────────
function buildSignedMessage(
  contestId: string,
  l2BlockNumber: bigint,
  merkleRoot: Uint8Array   // raw 32 bytes
): Uint8Array {
  const idB = new TextEncoder().encode(contestId);
  const blockB = new Uint8Array(8);
  new DataView(blockB.buffer).setBigUint64(0, l2BlockNumber, true);  // LE
  const msg = new Uint8Array(idB.length + 8 + 32);
  msg.set(idB, 0);
  msg.set(blockB, idB.length);
  msg.set(merkleRoot, idB.length + 8);
  return msg;
}

// ── 4. Sign and submit ─────────────────────────────────────────────────────────
async function submitSettlement(
  sequencerKeypair: nacl.SignKeyPair,
  contestId: string,
  winners: Array<{ wallet: string; payoutBB: number }>,
  totalDepositedBB: number,
  houseRakeBB: number,
  l2BlockNumber: bigint
) {
  const leaves = winners.map(w => buildLeaf(w.wallet, w.payoutBB));
  const { root } = buildTree(leaves);

  const totalDeposited = BigInt(Math.round(totalDepositedBB * 1_000_000));
  const totalPayout    = BigInt(Math.round(winners.reduce((s, w) => s + w.payoutBB, 0) * 1_000_000));
  const houseRake      = BigInt(Math.round(houseRakeBB * 1_000_000));

  // Enforce zero-sum locally before sending
  if (totalDeposited !== totalPayout + houseRake) throw new Error("Zero-sum violated");

  const signedMessage = buildSignedMessage(contestId, l2BlockNumber, root);
  const sig = nacl.sign.detached(signedMessage, sequencerKeypair.secretKey);

  // gRPC (preferred)
  const response = await settlementClient.submitMerkleRoot({
    contestId,
    merkleRoot: root,
    winnerCount: winners.length,
    totalDeposited,
    totalPayout,
    houseRake,
    winningOutcome: "team_a",
    resolvedAt: BigInt(Math.floor(Date.now() / 1000)),
    receiptHash: "",
    oracleProof: "",
    l2BlockNumber,
    signedMessage,
    sequencerPubkey: sequencerKeypair.publicKey,
    sequencerSig: sig,
  });

  if (!response.success) throw new Error(response.errorMessage);
  return response.l1TxHash;
}
```

---

### User claims winnings (TypeScript)

```typescript
import * as nacl from "tweetnacl";

async function claimWinnings(
  userKeypair: nacl.SignKeyPair,
  walletAddress: string,     // base58
  marketId: string,
  amountBB: number,
  merkleProof: string[]      // hex-encoded siblings
) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const message = `ESCROW_WITHDRAW:${marketId}:${walletAddress}:${amountBB}:${timestamp}:${nonce}`;
  const sig = nacl.sign.detached(new TextEncoder().encode(message), userKeypair.secretKey);

  const res = await fetch("http://L1_HOST:8080/escrow/withdraw", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      market_id: marketId,
      amount: amountBB,
      wallet_address: walletAddress,
      merkle_proof: merkleProof,
      public_key: Buffer.from(userKeypair.publicKey).toString("hex"),
      signature: Buffer.from(sig).toString("hex"),
      timestamp,
      nonce,
    }),
  });

  if (res.status === 410) throw new Error("Claim window has expired");
  if (res.status === 409) throw new Error("Already claimed");
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
```

---

*This guide reflects the L1 implementation as of commit on master / March 20 2026. If L1 changes break compatibility, bump this document and the L1 version tag.*
