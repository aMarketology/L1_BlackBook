# BlackBook L1 — Hot Wallet Developer Guide

> Complete reference for building a frontend wallet against the BlackBook L1 chain.
> Production node: `http://layer1.blackbook.id`
> Last updated: May 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Setup & Dependencies](#2-setup--dependencies)
3. [Identity — Keypairs & Addresses](#3-identity--keypairs--addresses)
4. [Authentication — Ed25519 Signing](#4-authentication--ed25519-signing)
5. [Token Reference](#5-token-reference)
6. [Read Endpoints](#6-read-endpoints)
7. [Write Endpoints — $BB (Native Gas Token)](#7-write-endpoints--bb-native-gas-token)
8. [Write Endpoints — Swap (BB ↔ wUSDT)](#8-write-endpoints--swap-bb--wusdt)
9. [Write Endpoints — $XX / MAXX (Bonding Curve)](#9-write-endpoints--xx--maxx-bonding-curve)
10. [Write Endpoints — $oz (Decay NFT Token)](#10-write-endpoints--oz-decay-nft-token)
11. [Write Endpoints — Escrow (L2 Prediction Markets)](#11-write-endpoints--escrow-l2-prediction-markets)
12. [Write Endpoints — Bridge (Deposit & Withdraw)](#12-write-endpoints--bridge-deposit--withdraw)
13. [WebSocket — Real-Time Balance Push](#13-websocket--real-time-balance-push)
14. [Full TypeScript SDK (copy-paste ready)](#14-full-typescript-sdk-copy-paste-ready)
15. [Error Handling](#15-error-handling)
16. [Unit Conversion Reference](#16-unit-conversion-reference)

---

## 1. Overview

BlackBook L1 is a custom Rust blockchain — **not Solana, not Ethereum**. It uses Ed25519
keypairs in a Solana-style address format (base58 public keys), but its HTTP API, token
model, and economics are entirely its own.

The chain runs on port **8080** (direct) or **80/443** (via nginx on Hetzner).

Key facts for a wallet developer:

- Addresses are **base58-encoded 32-byte Ed25519 public keys**
- Every state-changing action requires an **Ed25519 signature** — the server holds no private keys
- All amounts are integers internally. `f64` only appears in display fields
- Slot time: 400 ms. A confirmed transaction is final within 1–2 slots
- Three user-facing tokens: `$BB`, `$XX`, `$oz`

---

## 2. Setup & Dependencies

```bash
npm install @noble/ed25519 @noble/hashes bs58
```

```ts
import * as ed        from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import bs58           from "bs58";
```

**Base URL constants:**

```ts
const PROD_URL  = "http://layer1.blackbook.id";
const LOCAL_URL = "http://localhost:8080";
```

---

## 3. Identity — Keypairs & Addresses

### Generate a new wallet

```ts
const privBytes = ed.utils.randomPrivateKey();          // 32 bytes — KEEP SECRET
const pubBytes  = await ed.getPublicKeyAsync(privBytes); // 32 bytes
const address   = bs58.encode(pubBytes);                // "7xKf..." — the wallet address
const privHex   = bytesToHex(privBytes);                // store in encrypted local storage
const pubHex    = bytesToHex(pubBytes);                 // include in every signed request
```

### Restore from saved private key

```ts
const privBytes = hexToBytes(savedPrivHex);
const pubBytes  = await ed.getPublicKeyAsync(privBytes);
const address   = bs58.encode(pubBytes);
```

### Storage guidance

- **Never** send `privateKeyHex` to the server
- Store it encrypted in `localStorage` or a password-derived vault (AES-GCM over pbkdf2)
- The `address` (public key base58) is safe to display and share

---

## 4. Authentication — Ed25519 Signing

Every write endpoint requires three fields added to the JSON body:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `string` | Hex-encoded 32-byte Ed25519 public key |
| `signature` | `string` | Hex-encoded 64-byte Ed25519 signature |
| `timestamp` | `number` | Unix seconds — must be within **60 seconds** of server time |
| `nonce` | `string` | Random hex string — used once, prevents replay |

### Canonical message format

Each action has its own signed message string:

```
"ACTION_NAME:{from}:{body_param1}:{body_param2}:...:{timestamp}:{nonce}"
```

The server reconstructs this exact string and verifies the signature.
**Any mismatch = 401 Unauthorized.**

### Signing helper (universal)

```ts
async function signAction(
  action: string,
  from: string,
  bodyFields: string[],
  privateKeyHex: string
): Promise<{ signature: string; timestamp: number; nonce: string }> {
  const timestamp = Math.floor(Date.now() / 1000);
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  const nonce = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");

  const message = [action, from, ...bodyFields, String(timestamp), nonce].join(":");
  const privBytes = hexToBytes(privateKeyHex);
  const sigBytes  = await ed.signAsync(new TextEncoder().encode(message), privBytes);

  return { signature: bytesToHex(sigBytes), timestamp, nonce };
}

// Example:
const auth = await signAction("DECAY_MINT", wallet.address, ["5000000"], wallet.privateKeyHex);
// auth = { signature: "abc...", timestamp: 1716123456, nonce: "a3f2..." }
```

---

## 5. Token Reference

| Token | Symbol | Decimals | Raw Unit | Fixed USD Value |
|-------|--------|----------|----------|-----------------|
| Native gas token | `$BB` | 5 | lamports (÷ 100,000) | **$0.10 fixed** |
| Wrapped stablecoin | `wUSDT` | 6 | microUSDT (÷ 1,000,000) | **$1.00 fixed** |
| Bonding curve governance | `$XX` / MAXX | 12 | picoMAXX (÷ 10^12) | **Bonding curve** |
| Decay utility NFT | `$oz` | n/a | unique object per-instance | **wUSDT-backed** |

### $BB Economics

- **1 BB = $0.10 USD.** Fixed forever. No oracle. No float.
- **10 BB = 1 wUSDT** (swap rate: `BB_TO_USDC_RATE = 10`)
- 1 BB = 100,000 lamports. Smallest unit = 0.00001 BB = $0.000001.
- Backed 10:1 by wUSDT reserves, enforced by the chain at every boot.

### $XX / MAXX Economics

- **Linear bonding curve:** `spot_price = 0.00000005 × total_supply_in_whole_XX` (wUSDT per 1 XX)
- Buy: send wUSDT → get $XX minted. Sell: send $XX → get wUSDT from reserve.
- Price at 1M XX = **$0.05 wUSDT/XX**. Price at 10M XX = **$0.50 wUSDT/XX**.
- The reserve vault always holds exactly enough wUSDT to buy back all supply.

### $oz Economics

- NFT-style. Each `$oz` is a unique on-chain object, not a fungible balance.
- Mint: lock N wUSDT as backing → get one `$oz` (min 1 wUSDT).
- Use: each use leaks **1% of current backing** to treasury (geometric decay).
- After 100 uses: token is **dead** (~63.4% of original backing has been recaptured).
- Recharge: burn **5 $XX** + pay **2 wUSDT** → reset to 0 uses (1.5 wUSDT if staked).
- Stake: lock token for N slots → recharge fee drops 25%.

---

## 6. Read Endpoints

All `GET` requests. No auth required.

### Chain health

```
GET /health
→ {
    status: string,           // "ok"
    version: string,          // "5.0.0"
    network: string,          // "mainnet"
    slot: number,             // current PoH slot
    total_supply: number,     // total $BB in whole units (f64)
    uptime_seconds: number
  }
```

### $BB balance

```
GET /balance/:address
→ { address: string, balance: number, unit: "BB" }
// balance is in whole BB (e.g. 12.5 means 12.5 BB = $1.25)
```

### wUSDT balance

```
GET /wusdt/balance/:address     (also: /usdc/balance/:address)
→ {
    address: string,
    usdc_balance: number,       // whole wUSDT (e.g. 5.25)
    raw_balance: number,        // microUSDT integer
    decimals: 6,
    mint: string                // mint authority address
  }
```

### $XX balance

```
GET /maxx/balance/:address
→ { address: string, balance_pico: number, balance_whole: number }
```

### $XX bonding curve state

```
GET /maxx/manifest
→ {
    ticker: "$XX",
    total_supply: number,       // picoMAXX (raw)
    vault_reserve: number,      // microUSDT (raw)
    spot_price: number,         // wUSDT per whole $XX (f64)
    last_update_height: number,
    reserve_currency: "wUSDT"
  }

GET /maxx/supply
→ { total_supply_pico: number, total_supply_whole: number }

GET /maxx/vault
→ { vault_reserve_micro: number, vault_reserve_usdt: number }
```

### $oz tokens for a wallet

```
GET /decay/owner/:address
→ [1, 4, 17, ...]               // array of token IDs owned by this address

GET /decay/token/:id
→ {
    id: number,
    owner: string,
    backing_value: number,      // microUSDT locked in vault
    uses_count: number,         // 0..100
    minted_slot: number,
    last_use_slot: number,
    lock_until_slot: number,    // 0 = unlocked
    recharge_count: number
  }

GET /decay/treasury
→ { balance_micro: number, balance_usdt: number }

GET /decay/supply
→ { total_tokens: number }
```

### Supply audit

```
GET /supply/audit
→ {
    bb_total_supply: number,    // whole BB
    wusdt_total_supply: number, // whole wUSDT
    backing_ratio: number,      // should be 10.0
    target_ratio: 10.0,
    delta_from_target: number,
    invariant_ok: boolean,
    wusdt_mint: string,
    note: string
  }
```

### Swap pool

```
GET /swap/pool/balances
→ {
    pool_address: string,
    bb: { lamports: number, balance: number },
    wusdt: { raw: number, balance: number },
    ratio: number,              // should be 10.0
    expected_ratio: 10.0,
    ratio_ok: boolean
  }
```

### Transaction history

```
GET /address/:address/transactions
→ [ { hash, from, to, amount, timestamp, type }, ... ]

GET /tx/:tx_id
→ { hash, from, to, amount, timestamp, status, type }
```

### Chain / PoH

```
GET /poh/status
→ { slot: number, hash: string, tick: number, epoch: number, leader: string }

GET /poh/block/latest
→ { slot, hash, parent_hash, timestamp, transactions: [...] }

GET /poh/block/:slot
→ same shape

GET /stats
→ { tps, total_transactions, slot, uptime, ... }
```

---

## 7. Write Endpoints — $BB (Native Gas Token)

### Transfer $BB to another wallet

> **Note:** Transfer uses a different signing format (chainId prefix byte).

**Sign:**
```
message = [0x01] + UTF8(JSON.stringify({to, amount})) + "\n" + timestamp + "\n" + nonce
```

```ts
const timestamp = Math.floor(Date.now() / 1000);
const nonce     = randomNonce();
const payload   = JSON.stringify({ to, amount });
const encoder   = new TextEncoder();
const message   = new Uint8Array([
  0x01,
  ...encoder.encode(payload),
  ...encoder.encode(`\n${timestamp}\n${nonce}`)
]);
const sigBytes = await ed.signAsync(message, hexToBytes(wallet.privateKeyHex));
```

**POST `/transfer/simple`**
```json
{
  "public_key":      "hex32bytes",
  "wallet_address":  "base58address",
  "payload":         "{\"to\":\"...\",\"amount\":5.0}",
  "timestamp":       1716123456,
  "nonce":           "a3f2b1c4...",
  "chain_id":        1,
  "signature":       "hex64bytes"
}
```

**Response:**
```json
{
  "success": true,
  "from": "...",
  "to": "...",
  "amount": 5.0,
  "from_balance": 45.0,
  "to_balance": 15.0
}
```

---

### Faucet (testnet — rate-limited)

Sign: `"FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"`
Amount uses default float format: `0.1` (NOT `0.100000`).

**POST `/faucet`**
```json
{
  "wallet_address": "base58address",
  "amount":         0.1,
  "public_key":     "hex32bytes",
  "signature":      "hex64bytes",
  "timestamp":      1716123456,
  "nonce":          "a3f2b1c4..."
}
```

**Response:**
```json
{ "success": true, "minted": 0.1, "wallet_address": "...", "new_balance": 0.1 }
```

---

## 8. Write Endpoints — Swap (BB ↔ wUSDT)

**Rate: 10 BB = 1 wUSDT.** Atomic — no slippage, no price impact.

### BB → wUSDT

Sign: `"SWAP_BB_USDC:{wallet_address}:{bb_amount}:{timestamp}:{nonce}"`

**POST `/swap/bb-to-usdc`**
```json
{
  "wallet_address": "base58address",
  "bb_amount":      10.0,
  "public_key":     "hex32bytes",
  "signature":      "hex64bytes",
  "timestamp":      1716123456,
  "nonce":          "a3f2b1c4..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Swapped 10 BB for 1 wUSDT",
  "bb_debited": 10.0,
  "usdc_credited": 1.0
}
```

### wUSDT → BB

Sign: `"SWAP_USDC_BB:{wallet_address}:{usdc_amount}:{timestamp}:{nonce}"`

**POST `/swap/usdc-to-bb`**
```json
{
  "wallet_address": "base58address",
  "usdc_amount":    1.0,
  "public_key":     "hex32bytes",
  "signature":      "hex64bytes",
  "timestamp":      1716123456,
  "nonce":          "a3f2b1c4..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Swapped 1 wUSDT for 10 BB",
  "usdc_debited": 1.0,
  "bb_credited": 10.0
}
```

---

## 9. Write Endpoints — $XX / MAXX (Bonding Curve)

All amounts are **integer raw units** — no floats in the body.

| Amount field | Raw unit | How to convert |
|---|---|---|
| `amount` on buy | microUSDT | `whole_usdt × 1_000_000` |
| `amount` on sell | picoMAXX | `whole_xx × 1_000_000_000_000` |

### Buy $XX

Sign: `"MAXX_BUY:{from}:{amount_microUsdt}:{timestamp}:{nonce}"`

**POST `/maxx/buy`**
```json
{
  "from":       "base58address",
  "amount":     5000000,
  "min_out":    null,
  "public_key": "hex32bytes",
  "signature":  "hex64bytes",
  "timestamp":  1716123456,
  "nonce":      "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Bought 200.0 $XX for 5 wUSDT",
  "state": {
    "ticker": "$XX",
    "total_supply": 1200000000000000,
    "vault_reserve": 36000000,
    "spot_price": 0.00006,
    "reserve_currency": "wUSDT"
  },
  "out_amount": 200000000000000,
  "user_maxx_balance": 200000000000000,
  "user_wusdt_balance": 0
}
```

### Sell $XX

Sign: `"MAXX_SELL:{from}:{amount_picoMaxx}:{timestamp}:{nonce}"`

**POST `/maxx/sell`**
```json
{
  "from":       "base58address",
  "amount":     200000000000000,
  "min_out":    null,
  "public_key": "hex32bytes",
  "signature":  "hex64bytes",
  "timestamp":  1716123456,
  "nonce":      "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Sold 200.0 $XX for 5 wUSDT",
  "state": { ... },
  "out_amount": 5000000,
  "user_maxx_balance": 0,
  "user_wusdt_balance": 5000000
}
```

### Display helpers

```ts
const PICO_MAXX  = 1_000_000_000_000n;
const MICRO_USDT = 1_000_000n;

// Convert whole units → raw
const rawMaxx  = BigInt(Math.floor(wholeXX  * 1e12));
const rawUsdt  = BigInt(Math.floor(wholeUsdt * 1e6));

// Display raw → whole
const wholeXX   = Number(rawPicoMaxx)  / 1e12;
const wholeUsdt = Number(rawMicroUsdt) / 1e6;

// Compute spot price from supply
const spotPrice = 0.00000005 * (Number(totalSupplyPico) / 1e12); // wUSDT per 1 XX
```

---

## 10. Write Endpoints — $oz (Decay NFT Token)

`$oz` tokens are unique NFT-style objects. Each one has an integer `id`.

### Mint a new $oz

Sign: `"DECAY_MINT:{from}:{backing_amount_microUsdt}:{timestamp}:{nonce}"`
Minimum backing: 1,000,000 microUSDT (= 1 wUSDT).

**POST `/decay/mint`**
```json
{
  "from":            "base58address",
  "backing_amount":  5000000,
  "public_key":      "hex32bytes",
  "signature":       "hex64bytes",
  "timestamp":       1716123456,
  "nonce":           "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Minted $oz #7 backed by 5.000000 wUSDT",
  "token": {
    "id": 7,
    "owner": "base58address",
    "backing_value": 5000000,
    "uses_count": 0,
    "minted_slot": 182400,
    "last_use_slot": 182400,
    "lock_until_slot": 0,
    "recharge_count": 0
  },
  "user_wusdt_balance": 0
}
```

### Use a $oz (spend 1 use, leak 1% backing)

Sign: `"DECAY_USE:{from}:{token_id}:{timestamp}:{nonce}"`

**POST `/decay/use`**
```json
{
  "from":       "base58address",
  "token_id":   7,
  "public_key": "hex32bytes",
  "signature":  "hex64bytes",
  "timestamp":  1716123456,
  "nonce":      "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Used $oz #7 — 0.050000 wUSDT recaptured to treasury (99 uses left)",
  "token": { "id": 7, "uses_count": 1, "backing_value": 4950000, ... },
  "leak_microusdt": 50000,
  "treasury_balance": 50000
}
```

### Recharge a dead $oz (burns 5 $XX + 2 wUSDT)

Token must be at 100 uses. If staked, fee drops to 1.5 wUSDT.

Sign: `"DECAY_RECHARGE:{from}:{token_id}:{timestamp}:{nonce}"`

**POST `/decay/recharge`**
```json
{
  "from":       "base58address",
  "token_id":   7,
  "public_key": "hex32bytes",
  "signature":  "hex64bytes",
  "timestamp":  1716123456,
  "nonce":      "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Recharged $oz #7 — fee 2.000000 wUSDT, burned 5.000000 $XX",
  "token": { "id": 7, "uses_count": 0, "recharge_count": 1, ... },
  "fee_paid_microusdt": 2000000,
  "maxx_burned": 5000000000000,
  "user_maxx_balance": 0,
  "user_wusdt_balance": 3000000,
  "treasury_balance": 2050000
}
```

### Stake a $oz (lock for N slots → cheaper recharges)

Sign: `"DECAY_STAKE:{from}:{token_id}:{timestamp}:{nonce}"`

**POST `/decay/stake`**
```json
{
  "from":        "base58address",
  "token_id":    7,
  "lock_slots":  432000,
  "public_key":  "hex32bytes",
  "signature":   "hex64bytes",
  "timestamp":   1716123456,
  "nonce":       "a3f2b1c4..."
}
```

**Response:**
```json
{
  "message": "Staked $oz #7 — locked until slot 614400",
  "token": { "id": 7, "lock_until_slot": 614400, ... }
}
```

### $oz UI state helpers

```ts
const LAMPORTS_PER_BB = 100_000;
const USDC_UNIT       = 1_000_000;
const MAX_USES        = 100;

function ozIsAlive(token: OzToken): boolean {
  return token.uses_count < MAX_USES;
}

function ozUsesLeft(token: OzToken): number {
  return MAX_USES - token.uses_count;
}

function ozBackingUsdt(token: OzToken): number {
  return token.backing_value / USDC_UNIT;
}

function ozIsStaked(token: OzToken, currentSlot: number): boolean {
  return token.lock_until_slot > currentSlot;
}

function ozRechargeFeeMicro(token: OzToken, currentSlot: number): number {
  return ozIsStaked(token, currentSlot) ? 1_500_000 : 2_000_000; // 1.5 or 2 wUSDT
}

function ozDecayProgress(token: OzToken): number {
  return token.uses_count / MAX_USES; // 0.0 → 1.0
}
```

---

## 11. Write Endpoints — Escrow (L2 Prediction Markets)

The escrow vault holds $BB locked for active prediction market positions.

### Deposit into escrow

Sign: `"ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"`

**POST `/escrow/deposit`**
```json
{
  "wallet_address": "base58address",
  "amount":         50,
  "public_key":     "hex32bytes",
  "signature":      "hex64bytes",
  "timestamp":      1716123456,
  "nonce":          "a3f2b1c4..."
}
```

**Response:**
```json
{
  "success": true,
  "deposited": 50,
  "wallet_address": "...",
  "escrow_address": "...",
  "user_balance": 50.0,
  "escrow_balance": 550.0
}
```

### Withdraw from escrow (with Merkle proof)

After L2 market settlement, users claim winnings by submitting a Merkle proof
obtained from the L2 sequencer / dealer SDK.

Sign: `"ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"`

**POST `/escrow/withdraw`**
```json
{
  "market_id":    "market_abc123",
  "amount":       75,
  "wallet_address": "base58address",
  "merkle_proof": ["a3f2...", "c1d4...", "e5b6..."],
  "public_key":   "hex32bytes",
  "signature":    "hex64bytes",
  "timestamp":    1716123456,
  "nonce":        "a3f2b1c4..."
}
```

**Response:**
```json
{
  "success": true,
  "withdrawn": 75,
  "wallet_address": "...",
  "new_balance": 125.0
}
```

### Read escrow state

```
GET /escrow/status
→ { escrow_address, escrow_balance, total_markets, l2_sequencer_configured }

GET /escrow/market/:market_id
→ { market_id, merkle_root, l2_block_number }

GET /escrow/contest/:contest_id
→ contest-specific state
```

---

## 12. Write Endpoints — Bridge (Deposit & Withdraw)

### Bridge in: real USDC on Solana → $BB on L1

```
POST /deposit/request
  → Triggers the deposit gateway to watch for the incoming USDC tx

GET /deposit/status/:tx_hash
  → { status: "pending" | "confirmed" | "minted", bb_minted, ... }

POST /deposit/claim
  → Once confirmed, claim the minted $BB
```

### Bridge out: $BB → real USDC on Solana

Sign: `"WITHDRAW_REQUEST:{wallet}:{solana_dest}:{amount}:{timestamp}:{nonce}"`

**POST `/withdraw/request`**
```json
{
  "wallet_address":      "base58address",
  "solana_destination":  "SolanaBase58Address",
  "wusdt_amount_micro":  5000000,
  "public_key":          "hex32bytes",
  "signature":           "hex64bytes",
  "timestamp":           1716123456,
  "nonce":               "a3f2b1c4..."
}
```

```
GET /withdraw/status/:id
→ { withdrawal_id, status: "pending" | "released", solana_tx_hash, ... }
```

---

## 13. WebSocket — Real-Time Balance Push

Connect to `ws://layer1.blackbook.id/ws` for live balance updates.

```ts
const ws = new WebSocket("ws://layer1.blackbook.id/ws");

ws.onopen = () => {
  // Subscribe to a specific wallet
  ws.send(JSON.stringify({
    type: "subscribe_balance",
    address: wallet.address
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);

  if (msg.type === "balance_update") {
    // { type: "balance_update", address: "...", balance: 12.5, unit: "BB" }
    setBalance(msg.balance);
  }
};
```

---

## 14. Full TypeScript SDK (copy-paste ready)

```ts
/**
 * BlackBook L1 — Minimal Hot Wallet SDK
 * deps: @noble/ed25519, @noble/hashes, bs58
 */

import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import bs58 from "bs58";

// ── Types ──────────────────────────────────────────────────────────────────

export interface BBKeypair {
  address: string;     // base58 — this IS the wallet address
  privateKeyHex: string;
  publicKeyHex: string;
}

export interface OzToken {
  id: number;
  owner: string;
  backing_value: number;    // microUSDT
  uses_count: number;       // 0..100
  minted_slot: number;
  last_use_slot: number;
  lock_until_slot: number;  // 0 = unlocked
  recharge_count: number;
}

export interface MaxxState {
  ticker: string;
  total_supply: number;
  vault_reserve: number;
  spot_price: number;
  reserve_currency: string;
}

// ── Constants ──────────────────────────────────────────────────────────────

export const LAMPORTS_PER_BB = 100_000;
export const USDC_UNIT       = 1_000_000;
export const PICO_MAXX       = 1_000_000_000_000;
export const BB_PER_USDT     = 10;           // 10 BB = 1 wUSDT
export const MAXX_SLOPE      = 0.00000005;   // bonding curve
export const MAX_OZ_USES     = 100;

// ── Keypair helpers ────────────────────────────────────────────────────────

export async function generateKeypair(): Promise<BBKeypair> {
  const priv = ed.utils.randomPrivateKey();
  const pub  = await ed.getPublicKeyAsync(priv);
  return { address: bs58.encode(pub), privateKeyHex: bytesToHex(priv), publicKeyHex: bytesToHex(pub) };
}

export async function keypairFromPrivateKey(privHex: string): Promise<BBKeypair> {
  const priv = hexToBytes(privHex);
  const pub  = await ed.getPublicKeyAsync(priv);
  return { address: bs58.encode(pub), privateKeyHex: privHex, publicKeyHex: bytesToHex(pub) };
}

// ── Auth helper ────────────────────────────────────────────────────────────

async function buildAuth(
  action: string, from: string, fields: string[], privHex: string
): Promise<{ signature: string; timestamp: number; nonce: string }> {
  const timestamp = Math.floor(Date.now() / 1000);
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  const nonce   = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
  const message = [action, from, ...fields, String(timestamp), nonce].join(":");
  const sig     = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(privHex));
  return { signature: bytesToHex(sig), timestamp, nonce };
}

// ── SDK class ──────────────────────────────────────────────────────────────

export class BlackBookSDK {
  constructor(
    private rpcUrl: string,
    private wallet?: BBKeypair
  ) {
    this.rpcUrl = rpcUrl.replace(/\/$/, "");
  }

  setWallet(kp: BBKeypair) { this.wallet = kp; }
  private kp(): BBKeypair {
    if (!this.wallet) throw new Error("No wallet loaded");
    return this.wallet;
  }

  private async get<T>(path: string): Promise<T> {
    const r = await fetch(`${this.rpcUrl}${path}`);
    const j = await r.json();
    if (!r.ok) throw new Error(`GET ${path}: ${j.error ?? JSON.stringify(j)}`);
    return j;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const r = await fetch(`${this.rpcUrl}${path}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const j = await r.json();
    if (!r.ok) throw new Error(`POST ${path}: ${j.error ?? JSON.stringify(j)}`);
    return j;
  }

  // ── Reads ────────────────────────────────────────────────────────────────

  health()                                  { return this.get<any>("/health"); }
  getBalance(addr?: string)                 { return this.get<any>(`/balance/${addr ?? this.kp().address}`); }
  getWusdtBalance(addr?: string)            { return this.get<any>(`/wusdt/balance/${addr ?? this.kp().address}`); }
  getMaxxBalance(addr?: string)             { return this.get<any>(`/maxx/balance/${addr ?? this.kp().address}`); }
  getMaxxState()                            { return this.get<any>("/maxx/manifest"); }
  getOzTokens(addr?: string)                { return this.get<number[]>(`/decay/owner/${addr ?? this.kp().address}`); }
  getOzToken(id: number)                    { return this.get<OzToken>(`/decay/token/${id}`); }
  getOzTreasury()                           { return this.get<any>("/decay/treasury"); }
  supplyAudit()                             { return this.get<any>("/supply/audit"); }
  swapPool()                                { return this.get<any>("/swap/pool/balances"); }
  pohStatus()                               { return this.get<any>("/poh/status"); }
  latestBlock()                             { return this.get<any>("/poh/block/latest"); }
  txStatus(id: string)                      { return this.get<any>(`/poh/tx/${id}/status`); }
  txHistory(addr?: string)                  { return this.get<any[]>(`/address/${addr ?? this.kp().address}/transactions`); }
  escrowStatus()                            { return this.get<any>("/escrow/status"); }

  // ── $BB ──────────────────────────────────────────────────────────────────

  async transfer(to: string, amount: number) {
    const kp = this.kp();
    const timestamp = Math.floor(Date.now() / 1000);
    const arr = new Uint8Array(12); crypto.getRandomValues(arr);
    const nonce   = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
    const payload = JSON.stringify({ to, amount });
    const enc     = new TextEncoder();
    const msg     = new Uint8Array([0x01, ...enc.encode(payload), ...enc.encode(`\n${timestamp}\n${nonce}`)]);
    const sig     = await ed.signAsync(msg, hexToBytes(kp.privateKeyHex));
    return this.post<any>("/transfer/simple", { public_key: kp.publicKeyHex, wallet_address: kp.address, payload, timestamp, nonce, chain_id: 1, signature: bytesToHex(sig) });
  }

  async faucet(amount = 0.1) {
    const kp = this.kp();
    const capped = Math.min(amount, 0.1);
    const auth = await buildAuth("FAUCET", kp.address, [String(capped)], kp.privateKeyHex);
    return this.post<any>("/faucet", { wallet_address: kp.address, amount: capped, public_key: kp.publicKeyHex, ...auth });
  }

  // ── Swap ─────────────────────────────────────────────────────────────────

  async swapBbToUsdt(bbAmount: number) {
    const kp = this.kp();
    const auth = await buildAuth("SWAP_BB_USDC", kp.address, [String(bbAmount)], kp.privateKeyHex);
    return this.post<any>("/swap/bb-to-usdc", { wallet_address: kp.address, bb_amount: bbAmount, public_key: kp.publicKeyHex, ...auth });
  }

  async swapUsdtToBb(usdtAmount: number) {
    const kp = this.kp();
    const auth = await buildAuth("SWAP_USDC_BB", kp.address, [String(usdtAmount)], kp.privateKeyHex);
    return this.post<any>("/swap/usdc-to-bb", { wallet_address: kp.address, usdc_amount: usdtAmount, public_key: kp.publicKeyHex, ...auth });
  }

  // ── $XX ──────────────────────────────────────────────────────────────────

  async buyMaxx(microUsdtAmount: number) {
    const kp = this.kp();
    const auth = await buildAuth("MAXX_BUY", kp.address, [String(microUsdtAmount)], kp.privateKeyHex);
    return this.post<any>("/maxx/buy", { from: kp.address, amount: microUsdtAmount, public_key: kp.publicKeyHex, ...auth });
  }

  async sellMaxx(picoMaxxAmount: number) {
    const kp = this.kp();
    const auth = await buildAuth("MAXX_SELL", kp.address, [String(picoMaxxAmount)], kp.privateKeyHex);
    return this.post<any>("/maxx/sell", { from: kp.address, amount: picoMaxxAmount, public_key: kp.publicKeyHex, ...auth });
  }

  // ── $oz ──────────────────────────────────────────────────────────────────

  async mintOz(backingMicroUsdt: number) {
    const kp = this.kp();
    const auth = await buildAuth("DECAY_MINT", kp.address, [String(backingMicroUsdt)], kp.privateKeyHex);
    return this.post<any>("/decay/mint", { from: kp.address, backing_amount: backingMicroUsdt, public_key: kp.publicKeyHex, ...auth });
  }

  async useOz(tokenId: number) {
    const kp = this.kp();
    const auth = await buildAuth("DECAY_USE", kp.address, [String(tokenId)], kp.privateKeyHex);
    return this.post<any>("/decay/use", { from: kp.address, token_id: tokenId, public_key: kp.publicKeyHex, ...auth });
  }

  async rechargeOz(tokenId: number) {
    const kp = this.kp();
    const auth = await buildAuth("DECAY_RECHARGE", kp.address, [String(tokenId)], kp.privateKeyHex);
    return this.post<any>("/decay/recharge", { from: kp.address, token_id: tokenId, public_key: kp.publicKeyHex, ...auth });
  }

  async stakeOz(tokenId: number, lockSlots: number) {
    const kp = this.kp();
    const auth = await buildAuth("DECAY_STAKE", kp.address, [String(tokenId)], kp.privateKeyHex);
    return this.post<any>("/decay/stake", { from: kp.address, token_id: tokenId, lock_slots: lockSlots, public_key: kp.publicKeyHex, ...auth });
  }

  // ── Escrow ───────────────────────────────────────────────────────────────

  async escrowDeposit(amount: number) {
    const kp = this.kp();
    const auth = await buildAuth("ESCROW_DEPOSIT", kp.address, [String(amount)], kp.privateKeyHex);
    return this.post<any>("/escrow/deposit", { wallet_address: kp.address, amount, public_key: kp.publicKeyHex, ...auth });
  }

  async escrowWithdraw(marketId: string, amount: number, merkleProof: string[]) {
    const kp = this.kp();
    const auth = await buildAuth("ESCROW_WITHDRAW", marketId, [kp.address, String(amount)], kp.privateKeyHex);
    return this.post<any>("/escrow/withdraw", { market_id: marketId, amount, wallet_address: kp.address, merkle_proof: merkleProof, public_key: kp.publicKeyHex, ...auth });
  }

  // ── WebSocket ────────────────────────────────────────────────────────────

  subscribeBalance(onUpdate: (balance: number) => void): WebSocket {
    const kp = this.kp();
    const ws = new WebSocket(this.rpcUrl.replace("http", "ws") + "/ws");
    ws.onopen = () => ws.send(JSON.stringify({ type: "subscribe_balance", address: kp.address }));
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "balance_update") onUpdate(msg.balance);
    };
    return ws;
  }
}
```

---

## 15. Error Handling

All errors return JSON with an `"error"` field:

```json
{ "error": "Signature verification failed" }
{ "error": "Token not found" }
{ "error": "Token is dead — recharge required" }
{ "error": "Backing too small to leak — recharge or mint a new token" }
{ "error": "Not the owner of this token" }
{ "error": "wUSDT transfer failed: InsufficientFunds" }
```

| HTTP Status | Meaning |
|-------------|---------|
| `200` | Success |
| `400` | Bad request (validation failed, wrong amounts, token dead) |
| `401` | Signature verification failed |
| `403` | Action not permitted (wrong owner, etc.) |
| `404` | Resource not found |
| `409` | Conflict (already claimed, token not dead yet) |
| `429` | Rate limited (10 txs per wallet per window) |
| `500` | Server error (ReDB or SVM internal failure) |

---

## 16. Unit Conversion Reference

```ts
// $BB
const bbToLamports   = (bb: number)       => Math.round(bb * 100_000);
const lamportsToBb   = (l: number)        => l / 100_000;
const bbToUsd        = (bb: number)       => bb * 0.10;

// wUSDT
const usdtToMicro    = (usdt: number)     => Math.round(usdt * 1_000_000);
const microToUsdt    = (m: number)        => m / 1_000_000;

// $XX
const xxToPico       = (xx: number)       => BigInt(Math.floor(xx * 1e12));
const picoToXx       = (p: bigint|number) => Number(p) / 1e12;
const maxxSpotPrice  = (supplyPico: number) => 0.00000005 * (supplyPico / 1e12); // wUSDT per XX

// Swap
const bbToUsdt       = (bb: number)       => bb / 10;
const usdtToBb       = (usdt: number)     => usdt * 10;

// $oz
const ozBackingUsdt  = (t: OzToken)       => t.backing_value / 1_000_000;
const ozUsesLeft     = (t: OzToken)       => 100 - t.uses_count;
const ozIsAlive      = (t: OzToken)       => t.uses_count < 100;
const ozIsStaked     = (t: OzToken, slot: number) => t.lock_until_slot > slot;
const ozRechargeFee  = (t: OzToken, slot: number) => ozIsStaked(t, slot) ? 1_500_000 : 2_000_000;
```

---

*Production node: `http://layer1.blackbook.id` — Chain ID 1 — BlackBook L1 v5.0.0*
