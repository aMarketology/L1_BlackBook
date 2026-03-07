# L1 Connection Reference — BlackBook Layer 2

This is the authoritative integration document for any L2 server connecting to the
BlackBook L1 node. All field names, signing conventions, hashing algorithms, and
error codes are derived directly from the live L1 source code.

---

## 1. Transport

| Protocol | Default Port | Purpose |
|---|---|---|
| HTTP/JSON | `8080` | All escrow + wallet + balance calls |
| gRPC | `50051` | Block streaming (Writer → Readers) |
| Solana JSON-RPC | `8899` | SVM-compatible RPC (Phase 2A) |

Configure via env vars: `HTTP_PORT`, `GRPC_PORT`.

---

## 2. Unit System

**1 BB token = 100,000 lamports**

All HTTP API amounts use `f64` BB units. The L1 internally converts to `u64`
lamports when writing to the SVM AccountsDB (`amount * 100_000.0 as u64`).

| Human | API | SVM |
|---|---|---|
| 1 BB | `1.0` | `100000` lamports |
| 0.5 BB | `0.5` | `50000` lamports |
| 500 BB | `500.0` | `50000000` lamports |

---

## 3. Ed25519 Signing Convention

All signatures are **Ed25519** (ed25519-dalek). The signed message is always a
plain UTF-8 string — no binary encoding, no hashing before signing. The L1
re-constructs the exact same string from the request fields and calls
`VerifyingKey::verify(message.as_bytes(), &signature)`.

**Encoding rules:**
- `public_key` — 32-byte compressed Ed25519 pubkey, hex-encoded (64 chars)
- `signature` — 64-byte Ed25519 signature, hex-encoded (128 chars)
- `nonce` — any unique string per wallet (UUID v4 recommended)
- `timestamp` — Unix seconds (`u64`)

---

## 4. Escrow Endpoints

### 4.1 `POST /escrow/deposit`

Called by the **user** (via L2 UI) to lock BB tokens into the global escrow PDA.

**Signed message (user's private key):**
```
ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}
```

**Request body:**
```json
{
  "wallet_address": "L1_abc123...",
  "amount": 500.0,
  "public_key": "32-byte-pubkey-hex-64chars",
  "signature": "64-byte-sig-hex-128chars",
  "timestamp": 1741293600,
  "nonce": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Success response `200`:**
```json
{
  "success": true,
  "deposited": 500.0,
  "wallet_address": "L1_abc123...",
  "escrow_address": "L1_ESCROW_PDA...",
  "user_balance": 9500.0,
  "escrow_balance": 50500.0
}
```

**L1 checks (in order):**
1. Nonce not previously used (60s replay window)
2. Request not older than 60 seconds
3. Ed25519 signature valid against `public_key`
4. `wallet_address` has sufficient balance
5. Atomic debit user → credit escrow PDA
6. Writes `EscrowDeposit` tx into PoH block

---

### 4.2 `POST /escrow/submit-state-root`

Called by the **L2 Sequencer server** after a market settles. Commits the final
Merkle root to L1 permanently.

**Signed message (L2 sequencer's private key):**
```
STATE_ROOT:{market_id}:{merkle_root}:{l2_block_number}
```

**Request body:**
```json
{
  "market_id": "super_bowl_2026",
  "merkle_root": "a3f1c8...64 hex chars (32 bytes)",
  "signature": "64-byte-sig-hex-128chars",
  "l2_block_number": 42
}
```

**Success response `200`:**
```json
{
  "success": true,
  "market_id": "super_bowl_2026",
  "merkle_root": "a3f1c8...",
  "l2_block_number": 42,
  "slot": 1083
}
```

**Critical rules:**
- `merkle_root` must be exactly 64 hex characters (32 bytes)
- `l2_block_number` must be **monotonically increasing** — use an atomic counter
  on the L2 side. Once the L1 stores a root for a `market_id`, it is **permanent**.
  Resubmitting the same `market_id` is a permanent rejection (double-settle guard).
- The L1 verifies `signature` against `L2_SEQUENCER_PUBKEY` (set on the L1 node
  via `L2_SEQUENCER_PUBKEY` env var — 32-byte hex Ed25519 public key).
- **The L1 does NOT sign anything here.** It is a pure verifier.
- The sequencer is the only authority allowed to call this endpoint.

**L2 counter contract:**
```
market settled at L2 block 41  →  l2_block_number: 41  ✅
market settled at L2 block 42  →  l2_block_number: 42  ✅
replay of block 41             →  REJECTED (same market_id already has root)
```

---

### 4.3 `POST /escrow/withdraw`

Called by the **user** to claim their winnings. The user must supply their Merkle
proof (provided by the L2 API — see Section 6).

**Signed message (user's private key):**
```
ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}
```

**Request body:**
```json
{
  "market_id": "super_bowl_2026",
  "wallet_address": "L1_abc123...",
  "amount": 500.0,
  "merkle_proof": [
    "sibling_hash_level_0_hex_64chars",
    "sibling_hash_level_1_hex_64chars",
    "sibling_hash_level_2_hex_64chars"
  ],
  "public_key": "32-byte-pubkey-hex-64chars",
  "signature": "64-byte-sig-hex-128chars",
  "timestamp": 1741293900,
  "nonce": "7a2b9c3d-..."
}
```

**`merkle_proof` rules:**
- Plain array of sibling hashes — **no `is_left` flag needed**
- Each entry is a 64-char hex string (32 bytes), optionally `0x`-prefixed
- Order: leaf-level sibling first, root-level sibling last
- The L1 uses **sorted hashing** (see Section 5) — the L2 must build its tree
  the same way or proofs will fail

**Success response `200`:**
```json
{
  "success": true,
  "withdrawn": 500.0,
  "market_id": "super_bowl_2026",
  "wallet_address": "L1_abc123...",
  "new_balance": 10500.0
}
```

**L1 checks (in order):**
1. Ed25519 signature valid (proves wallet ownership)
2. Nonce not previously used (60s replay window)
3. Not already withdrawn for this `{market_id}:{wallet_address}` pair
4. Market root exists in DashMap/ReDB
5. Merkle proof walks up to the stored `[u8; 32]` root
6. Atomic debit escrow PDA → credit user wallet
7. Claim persisted to ReDB (permanent double-withdrawal guard)
8. Writes `EscrowWithdraw` tx into PoH block

---

### 4.4 `GET /escrow/status`

Returns aggregate vault state only. **Does not list individual markets** (OOM
protection — the L2 PostgreSQL database owns the market list).

**Response:**
```json
{
  "escrow_address": "L1_ESCROW_PDA...",
  "escrow_balance_lamports": 50000000,
  "total_markets_settled": 412,
  "l2_sequencer_configured": true
}
```

---

### 4.5 `GET /escrow/market/:market_id`

Lookup the stored Merkle root for a single market.

**Response (found):**
```json
{
  "success": true,
  "market_id": "super_bowl_2026",
  "merkle_root": "a3f1c8..."
}
```

**Response (not found):**
```json
{
  "success": false,
  "error": "No settlement found for market 'super_bowl_2026'"
}
```

---

## 5. Sorted Hashing — Merkle Tree Convention

**This is the most important section for L2 implementation correctness.**

The L1 uses **sorted (lexicographic) hashing** throughout the entire Merkle tree —
building, proof generation, and proof verification all use the same function:

```
combine(a, b):
  if a <= b:  SHA256(a || b)
  else:        SHA256(b || a)
```

At every level of the tree, the smaller `[u8; 32]` always goes first. This means:

1. **No direction flag needed in proofs.** The proof array is just sibling hashes.
2. **Position-independent.** The root does not depend on leaf insertion order.
3. **Tamper-proof.** Any change to any leaf cascades to a completely different root.

### L2 must implement the identical algorithm in Python/JS/Go/etc.:

```python
import hashlib

def combine_hashes(a: bytes, b: bytes) -> bytes:
    if a <= b:
        return hashlib.sha256(a + b).digest()
    else:
        return hashlib.sha256(b + a).digest()

def build_merkle_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """Returns all levels for proof generation. Level 0 = leaves."""
    levels = [leaves[:]]
    current = leaves[:]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]  # duplicate odd
            next_level.append(combine_hashes(left, right))
        current = next_level
        levels.append(current)
    return levels

def get_root(leaves: list[bytes]) -> bytes:
    levels = build_merkle_tree(leaves)
    return levels[-1][0]

def get_proof(leaves: list[bytes], index: int) -> list[str]:
    """Returns hex-encoded sibling hashes from leaf to root."""
    levels = build_merkle_tree(leaves)
    proof = []
    idx = index
    for level in levels[:-1]:
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
        proof.append(sibling.hex())
        idx //= 2
    return proof
```

### Leaf construction (must match L1 exactly):

```python
import hashlib, struct

def make_leaf(wallet_address: str, amount_bb: float) -> bytes:
    # amount as little-endian f64 — matches Rust's f64.to_le_bytes()
    amount_bytes = struct.pack('<d', amount_bb)
    return hashlib.sha256(wallet_address.encode() + amount_bytes).digest()
```

---

## 6. What the L2 PostgreSQL Database Must Store

The L1 stores **only the 32-byte Merkle root and claim timestamps**. Everything
else lives in the L2 database.

| Data | Owner |
|---|---|
| 32-byte Merkle root per market | L1 ReDB (permanent) |
| Per-user payout amounts | L2 PostgreSQL |
| Full market metadata (name, dates, odds) | L2 PostgreSQL |
| Historical market list | L2 PostgreSQL |
| Per-user Merkle proof paths | L2 PostgreSQL (computed at settlement) |
| L2 block number counter | L2 (atomic, persisted) |
| User-facing balance history | L2 PostgreSQL |

**At settlement time the L2 must:**
1. Finalize all payout amounts for `market_id`
2. Sort accounts by wallet address (alphabetical) → deterministic leaf order
3. Build the Merkle tree using `make_leaf` + `combine_hashes`
4. Store every user's proof path in PostgreSQL
5. Submit root to `POST /escrow/submit-state-root` with the next `l2_block_number`
6. Store `{ market_id, merkle_root, l2_block_number, settled_at }` in PostgreSQL

**At withdrawal time the L2 must:**
1. Look up user's payout amount and proof path from PostgreSQL
2. Return to the frontend: `{ amount, merkle_proof: [hex, hex, ...] }`
3. Frontend constructs and signs `ESCROW_WITHDRAW:...` message
4. Frontend submits `POST /escrow/withdraw` directly to L1

---

## 7. gRPC Block Streaming

The L2 can subscribe to the live block feed to index confirmed escrow transactions.

**Proto service:** `validator_relay.ValidatorRelay`

```protobuf
rpc SubscribeBlocks(SubscribeRequest) returns (stream BlockData);
rpc CatchupBlocks(CatchupRequest)    returns (stream BlockData);
rpc ForwardTransaction(ForwardTransactionRequest) returns (ForwardTransactionResponse);
rpc GetStatus(StatusRequest) returns (StatusResponse);
```

Each `BlockData` message contains `repeated BlockTransaction transactions`.
Each `BlockTransaction.data_json` is a JSON-encoded `TxData` variant.

**Relevant `TxData` variants for escrow:**
```json
{ "EscrowDeposit":    { "amount": 50000000, "escrow_address": "L1_ESCROW_PDA..." } }
{ "EscrowStateRoot":  { "market_id": "super_bowl_2026", "merkle_root": "a3f1..." } }
{ "EscrowWithdraw":   { "market_id": "super_bowl_2026", "amount": 50000000, "escrow_address": "L1_ESCROW_PDA..." } }
```

`amount` in gRPC messages is always **lamports** (`u64`). Divide by `100_000` to
get BB tokens.

**Connect:**
```
grpc://<L1_HOST>:<GRPC_PORT>
proto: proto/validator_relay.proto
```

---

## 8. L1 Node Environment Variables

| Var | Required | Description |
|---|---|---|
| `L2_SEQUENCER_PUBKEY` | **Yes** | Hex Ed25519 pubkey (64 chars). Without this, `POST /escrow/submit-state-root` returns `503`. |
| `HTTP_PORT` | No | Default `8080` |
| `GRPC_PORT` | No | Default `50051` |
| `ADMIN_PUBKEY` | No | Hex Ed25519 pubkey authorised for `/admin/*` routes |

---

## 9. Common Error Responses

| HTTP | Meaning |
|---|---|
| `400 Bad Request` | Missing/invalid field, insufficient balance, stale timestamp |
| `401 Unauthorized` | Ed25519 signature verification failed |
| `404 Not Found` | Market not settled yet |
| `409 Conflict` | Nonce already used **or** already withdrawn for this market |
| `503 Service Unavailable` | `L2_SEQUENCER_PUBKEY` not configured on L1 node |

All errors return: `{ "error": "human readable message" }`
