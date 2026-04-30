# BlackBook L1 — Wallet Developer Changelog (2026-04-29)

> **For:** Frontend / wallet team
>
> **Summary:** Six previously broken API endpoints have been fixed, all deposit SDKs have been migrated to u64 integer math, and new route aliases have been added. This document tells you exactly what changed and what you need to update.

---

## ⚠️ BREAKING CHANGE: Deposit Gateway u64 Migration

The deposit gateway now uses **integer micro-units** (`u64`) instead of floating-point dollars (`f64`).

### What Changed

| Before (BROKEN) | After (CURRENT) |
|-----------------|-----------------|
| `amount_stablecoin: 5.0` (float) | `amount_micro_stablecoin: 5000000` (integer) |
| Signature: `...:{float_amount}:...` | Signature: `...:{integer_micro}:...` |

### Conversion Formula

```ts
// 1 USDC = 1,000,000 micro-units
const amount_micro_stablecoin = Math.round(usdcAmount * 1_000_000);

// Examples:
// 5.00 USDC  → 5000000
// 0.50 USDC  → 500000
// 100.00 USDC → 100000000
```

### Updated Signature Message Format

```
DEPOSIT_REQUEST:{wallet_address}:{external_tx_hash}:{amount_micro_stablecoin}:{asset}:{timestamp}:{nonce}
```

**Example:**
```
DEPOSIT_REQUEST:7kR2...xQ3p:4sG7...kL2m:5000000:USDC:1714400000:a1b2c3d4e5f6
```

> The `amount_micro_stablecoin` value in the signature MUST be the integer, not the float. If you sign with `5.0` but send `5000000`, the signature will fail.

### Updated Request Body

```json
// POST /deposit/request
{
  "wallet_address": "7kR2...xQ3p",
  "external_tx_hash": "4sG7...kL2m",
  "asset": "USDC",
  "amount_micro_stablecoin": 5000000,
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes",
  "timestamp": 1714400000,
  "nonce": "a1b2c3d4e5f6"
}
```

### SDK Files Already Updated

If you're using our SDKs, they've already been fixed:
- `sdk/deposit.sdk.ts` — ✅ Updated
- `deposit.sdk.ts` (root) — ✅ Updated
- `claim.mjs` — ✅ Updated

**If your frontend has its own deposit integration that doesn't use these SDKs, you MUST update it manually.**

---

## Fixed Endpoints

### 1. `POST /transfer` — NEW ALIAS

Previously only `/transfer/simple` was registered. Now both paths work:

```
POST /transfer          ← NEW (same handler)
POST /transfer/simple   ← Original (still works)
```

Both accept the same request body:

```json
{
  "from": "SenderBase58Address",
  "to": "RecipientBase58Address",
  "amount": 10.5,
  "timestamp": 1714400000,
  "nonce": "random_hex_string",
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes"
}
```

**Signature format:** `TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}`

---

### 2. `POST /swap/bb-to-usdc` — FIXED 422 ERRORS

**Problem:** Frontend sending `{ wallet, amount }` was rejected because the backend expected `{ wallet_address, bb_amount }`.

**Fix:** Both field names now work via serde aliases:

```json
// Either of these is now accepted:

// Original field names (preferred)
{ "wallet_address": "...", "bb_amount": 1000000 }

// Alias field names (also work)
{ "wallet": "...", "amount": 1000000 }
```

> `bb_amount` is in **lamports** (1 BB = 100,000 lamports).

**Signature format:** `SWAP_BB_USDC:{wallet_address}:{bb_amount}:{timestamp}:{nonce}`

**Response:**
```json
{
  "success": true,
  "bb_debited_lamports": 1000000,
  "wusdt_credited_micro": 100000,
  "pool_address": "SwapPool..."
}
```

---

### 3. `POST /swap/usdc-to-bb` — FIXED 422 ERRORS

Same alias fix as above:

```json
// Original field names (preferred)
{ "wallet_address": "...", "usdc_amount": 1000000 }

// Alias field names (also work)
{ "wallet": "...", "amount": 1000000 }
```

> `usdc_amount` is in **micro-units** (1 wUSDT = 1,000,000 micro).

**Signature format:** `SWAP_USDC_BB:{wallet_address}:{usdc_amount}:{timestamp}:{nonce}`

**Response:**
```json
{
  "success": true,
  "wusdt_debited_micro": 1000000,
  "bb_credited_lamports": 10000000,
  "pool_address": "SwapPool..."
}
```

---

### 4. `GET /deposit/status/:tx_hash` — NO LONGER RETURNS ERRORS

**Before:** When a deposit wasn't found, the endpoint returned an error JSON. This caused frontends polling for status to show error states.

**After:** Returns a graceful `"pending"` status:

```json
// When deposit is found:
{
  "found": true,
  "external_tx_hash": "...",
  "wallet_address": "...",
  "status": "pending",
  "amount_stablecoin": 5.0,
  "bb_to_mint": 50.0,
  "submitted_at": 1714400000
}

// When deposit is NOT found (safe for polling):
{
  "found": false,
  "status": "pending",
  "external_tx_hash": "...",
  "note": "No deposit request found yet — it may still be processing."
}
```

**Frontend recommendation:** Poll this endpoint every 3-5 seconds after submitting a deposit. Show a spinner until `status === "approved"` or `found === true`.

---

### 5. Block & Transaction Explorer Routes — NEW

Three new routes for the block explorer:

```
GET /blocks          → Returns the latest PoH block
GET /blocks/latest   → Same as above
GET /txs/:address    → Paginated tx history for a wallet (alias for /address/:address/transactions)
```

**`GET /blocks` response:**
```json
{
  "success": true,
  "block": {
    "slot": 98712,
    "timestamp": 1714400000,
    "hash": "abc123...",
    "previous_hash": "def456...",
    "tx_count": 5,
    "leader": "ValidatorId",
    "epoch": 12
  }
}
```

**`GET /txs/:address` response:**
```json
{
  "success": true,
  "address": "...",
  "page": 1,
  "limit": 50,
  "total": 142,
  "transactions": [
    {
      "tx_id": "uuid",
      "tx_type": "transfer",
      "from_address": "...",
      "to_address": "...",
      "amount": 10.5,
      "timestamp": 1714400000,
      "status": "completed",
      "block_height": 98712
    }
  ]
}
```

Query params: `?page=1&limit=50`

---

### 6. Wrapped Token Routes — NEW ALIASES

You can now use `/wusdt/*` or `/wusdc/*` instead of `/usdc/*`. They all hit the same SPL token handlers:

| Route | Alias 1 | Alias 2 |
|-------|---------|---------|
| `GET /usdc/balance/:address` | `GET /wusdt/balance/:address` | `GET /wusdc/balance/:address` |
| `GET /usdc/supply` | `GET /wusdt/supply` | `GET /wusdc/supply` |
| `GET /usdc/accounts/:address` | `GET /wusdt/accounts/:address` | `GET /wusdc/accounts/:address` |
| `POST /usdc/transfer` | `POST /wusdt/transfer` | `POST /wusdc/transfer` |

**Use whichever naming convention makes sense for your UI.** If your app calls the token "wUSDT", use the `/wusdt/*` routes.

---

## Integer Units Quick Reference

| Token | Field Unit | Conversion |
|-------|-----------|------------|
| $BB | lamports | 1 BB = 100,000 lamports |
| wUSDT / wUSDC | micro-units | 1 wUSDT = 1,000,000 micro |
| MAXX | picoMAXX | 12 decimal places |

---

## Authentication Pattern (All Write Endpoints)

Every `POST` endpoint requires Ed25519 signature verification:

1. **Construct** the canonical message string (format specified per endpoint above)
2. **Sign** with your Ed25519 private key
3. **Send** hex-encoded `public_key` (32 bytes) and `signature` (64 bytes)
4. **Include** `timestamp` (must be within 60 seconds of server time)
5. **Include** a random `nonce` (each nonce can only be used once)

```ts
// Example signing with @noble/ed25519
import * as ed from '@noble/ed25519';

const message = `TRANSFER:${from}:${to}:${amount}:${timestamp}:${nonce}`;
const messageBytes = new TextEncoder().encode(message);
const signature = await ed.signAsync(messageBytes, privateKeyBytes);
const signatureHex = Buffer.from(signature).toString('hex');
const publicKeyHex = Buffer.from(publicKeyBytes).toString('hex');
```

---

## Error Codes

| Status | Meaning |
|--------|---------|
| `400` | Bad request (missing fields, invalid format) |
| `401` | Signature verification failed |
| `404` | Route not found |
| `409` | Conflict (nonce already used, double-mint) |
| `422` | Request body deserialization failed |
| `429` | Rate limited (max 10 requests / 10s / wallet) |
| `503` | Service unavailable (insufficient pool liquidity) |

---

## Full API Reference

For the complete list of all endpoints (not just the fixed ones), see:
**[`docs/ENDPOINT_REFERENCE.md`](./ENDPOINT_REFERENCE.md)**
