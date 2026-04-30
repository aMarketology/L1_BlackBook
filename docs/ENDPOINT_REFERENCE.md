# BlackBook L1 — API Endpoint Reference

> **Last updated:** 2026-04-29
>
> Base URL: `https://l1.blackbook.bet` (production) or `http://127.0.0.1:8080` (local dev)

---

## Table of Contents

1. [Transfers](#1-transfers)
2. [Token Swaps (BB ↔ wUSDT)](#2-token-swaps-bb--wusdt)
3. [Deposit Gateway (Buy BB)](#3-deposit-gateway-buy-bb)
4. [Withdrawal Gateway](#4-withdrawal-gateway)
5. [Wrapped Token Balances (wUSDT / wUSDC)](#5-wrapped-token-balances-wusdt--wusdc)
6. [Blocks & Transaction Explorer](#6-blocks--transaction-explorer)
7. [Chain Status](#7-chain-status)

---

## 1. Transfers

### `POST /transfer` or `POST /transfer/simple`

Transfer $BB tokens between wallets. Both paths hit the same handler.

**Request Body:**
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

**Signature message format:**
```
TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}
```

**Response (200 OK):**
```json
{
  "success": true,
  "tx_id": "uuid",
  "from": "...",
  "to": "...",
  "amount": 10.5,
  "new_balance": 89.5
}
```

---

## 2. Token Swaps (BB ↔ wUSDT)

### `POST /swap/bb-to-usdc`

Swap $BB for wUSDT at a fixed rate of 10 BB = 1 wUSDT.

**Request Body:**
```json
{
  "wallet_address": "YourBase58Address",
  "bb_amount": 1000000,
  "timestamp": 1714400000,
  "nonce": "random_hex_string",
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes"
}
```

> **Note:** `bb_amount` is in **lamports** (1 BB = 100,000 lamports).
> The fields `wallet` and `amount` are accepted as aliases for `wallet_address` and `bb_amount`.

**Signature message format:**
```
SWAP_BB_USDC:{wallet_address}:{bb_amount}:{timestamp}:{nonce}
```

**Response (200 OK):**
```json
{
  "success": true,
  "bb_debited_lamports": 1000000,
  "wusdt_credited_micro": 100000,
  "pool_address": "SwapPool..."
}
```

### `POST /swap/usdc-to-bb`

Swap wUSDT for $BB at the same fixed rate.

**Request Body:**
```json
{
  "wallet_address": "YourBase58Address",
  "usdc_amount": 1000000,
  "timestamp": 1714400000,
  "nonce": "random_hex_string",
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes"
}
```

> **Note:** `usdc_amount` is in **micro-units** (1 wUSDT = 1,000,000 micro).
> The fields `wallet` and `amount` are accepted as aliases for `wallet_address` and `usdc_amount`.

**Signature message format:**
```
SWAP_USDC_BB:{wallet_address}:{usdc_amount}:{timestamp}:{nonce}
```

**Response (200 OK):**
```json
{
  "success": true,
  "wusdt_debited_micro": 1000000,
  "bb_credited_lamports": 10000000,
  "pool_address": "SwapPool..."
}
```

### `GET /swap/pool/balances`

Returns the current BB and wUSDT reserves in the swap pool.

---

## 3. Deposit Gateway (Buy BB)

### `POST /deposit/request`

Submit a deposit request after sending stablecoin to the custody wallet.

**Request Body:**
```json
{
  "wallet_address": "YourBBWalletBase58",
  "external_tx_hash": "solana_or_bsc_tx_hash",
  "asset": "USDC",
  "amount_micro_stablecoin": 5000000,
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes",
  "timestamp": 1714400000,
  "nonce": "random_hex_string"
}
```

> ⚠️ **BREAKING CHANGE (v5.0):** The field is now `amount_micro_stablecoin` (u64 integer, 6 decimal places).
> Previously it was `amount_stablecoin` (f64 float). Update your frontend!
>
> **Conversion:** `amount_micro_stablecoin = Math.round(usdcAmount * 1_000_000)`
>
> Example: 5.00 USDC → `5000000`

**Signature message format:**
```
DEPOSIT_REQUEST:{wallet_address}:{external_tx_hash}:{amount_micro_stablecoin}:{asset}:{timestamp}:{nonce}
```

**Response (200 OK — instant approval):**
```json
{
  "success": true,
  "status": "approved",
  "wallet_address": "...",
  "external_tx_hash": "...",
  "bb_minted": 50.0,
  "new_balance": 150.0
}
```

**Response (200 OK — pending dealer approval):**
```json
{
  "success": true,
  "status": "pending",
  "wallet_address": "...",
  "bb_to_mint": 50.0,
  "message": "Request received. The dealer will verify your deposit and mint BB shortly."
}
```

### `GET /deposit/status/:tx_hash`

Check the status of a deposit by its external transaction hash.

**Response (found):**
```json
{
  "found": true,
  "external_tx_hash": "...",
  "wallet_address": "...",
  "status": "pending",
  "amount_stablecoin": 5.0,
  "bb_to_mint": 50.0
}
```

**Response (not yet found — still processing):**
```json
{
  "found": false,
  "status": "pending",
  "external_tx_hash": "...",
  "note": "No deposit request found yet — it may still be processing."
}
```

> **Note:** This endpoint no longer returns an error when a deposit isn't found.
> It returns `status: "pending"` — safe for polling from a frontend.

### `POST /deposit/claim`

Claim an unattributed deposit (for users who sent directly to custody without calling `/deposit/request` first).

---

## 4. Withdrawal Gateway

### `POST /withdraw/request`

Request a withdrawal of wUSDT from BlackBook L1 back to an external chain.

**Request Body:**
```json
{
  "wallet_address": "YourBase58Address",
  "wusdt_amount_micro": 5000000,
  "destination_address": "ExternalChainAddress",
  "destination_chain": "solana",
  "timestamp": 1714400000,
  "nonce": "random_hex_string",
  "public_key": "hex_32_bytes",
  "signature": "hex_64_bytes"
}
```

> **Note:** `wusdt_amount_micro` is in **micro-units** (u64, 6 decimals).

### `GET /withdraw/status/:id`

Check withdrawal status by withdrawal ID.

---

## 5. Wrapped Token Balances (wUSDT / wUSDC)

All wrapped token routes are aliases for the same underlying SPL token engine.
You can use `/usdc/*`, `/wusdt/*`, or `/wusdc/*` — they all return the same data.

### `GET /wusdt/balance/:address` (or `/usdc/balance/:address` or `/wusdc/balance/:address`)

```json
{
  "address": "...",
  "usdc_balance": 100.5,
  "raw_balance": 100500000,
  "decimals": 6,
  "mint": "wUSDT_Mint_Base58"
}
```

### `GET /wusdt/supply` (or `/usdc/supply` or `/wusdc/supply`)

Total wrapped stablecoin supply on L1.

### `GET /wusdt/accounts/:address` (or `/usdc/accounts/:address` or `/wusdc/accounts/:address`)

All SPL token accounts (ATAs) owned by an address.

### `POST /wusdt/transfer` (or `/usdc/transfer` or `/wusdc/transfer`)

Transfer wrapped stablecoin between wallets.

```json
{
  "from": "SenderBase58",
  "to": "RecipientBase58",
  "amount": 10.5
}
```

---

## 6. Blocks & Transaction Explorer

### `GET /blocks` or `GET /blocks/latest`

Returns the most recently produced PoH block.

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

### `GET /poh/block/:slot`

Full block detail including all transactions at a specific slot.

### `GET /txs/:address` or `GET /address/:address/transactions`

Paginated transaction history for a wallet address.

**Query params:** `?page=1&limit=50`

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

### `GET /tx/:tx_id`

Full transaction detail by ID.

### `GET /ledger`

ASCII-art audit ledger (text/plain). Supports `?page=1&limit=50`.

---

## 7. Chain Status

### `GET /health`

Full node health including PoH, consensus, pipeline stats, and volume metrics.

### `GET /stats`

Execution pipeline, Gulf Stream, and blockchain counters.

### `GET /chain/volume`

Detailed on-chain volume breakdown by category (deposits, withdrawals, swaps, transfers, mints, escrow).

### `GET /supply/audit`

BB / wUSDT supply invariant check. Confirms the 10:1 backing ratio holds.

```json
{
  "bb_total_supply": 1000.0,
  "wusdt_total_supply": 100.0,
  "backing_ratio": 10.0,
  "invariant_ok": true
}
```

### `GET /poh/status`

Current PoH clock state (slot, hash count, running status).

### `GET /consensus/tower`

Tower BFT validator state.

---

## Common Patterns

### Authentication

All write endpoints require Ed25519 signature verification:

1. Construct the canonical message string (format specified per endpoint)
2. Sign with your Ed25519 private key
3. Send the hex-encoded `public_key` (32 bytes) and `signature` (64 bytes)
4. Include `timestamp` (must be within 60 seconds of server time)
5. Include a random `nonce` (replay protection — each nonce can only be used once)

### Error Responses

| Status | Meaning |
|--------|---------|
| 400 | Bad request (missing fields, invalid format) |
| 401 | Signature verification failed |
| 404 | Route not found |
| 409 | Conflict (nonce already used, double-mint) |
| 422 | Request body deserialization failed |
| 503 | Service unavailable (insufficient pool liquidity) |

### Integer Units

| Token | Unit | Conversion |
|-------|------|------------|
| $BB | lamports | 1 BB = 100,000 lamports |
| wUSDT/wUSDC | micro-units | 1 wUSDT = 1,000,000 micro |
