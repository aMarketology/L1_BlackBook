# BlackBook L1 — Faucet Endpoint Specification

> **Endpoint:** `POST /faucet`  
> **Auth:** DUAL — Ed25519 signature (microtx) **OR** session token (SSS wallet)  
> **Max mint:** `0.1 BB` per request (server clamps `amount` to this ceiling)  
> **Replay protection:** Unique nonce + 60-second timestamp window (Ed25519) / session-scoped (SSS)

---

## Request Body (JSON)

### Required Fields (both auth paths)

| Field       | Type     | Required | Description |
|-------------|----------|----------|-------------|
| `to`        | `string` | Yes | Wallet address — either **base58** (Solana-style, 32-byte pubkey) or **hex** (64 hex chars = 32 bytes) |
| `amount`    | `number` | Yes | Amount in BB. Server clamps to `min(amount, 0.1)`. Must be `> 0` |

### Auth Path 1: Ed25519 Signature (microtransaction wallets)

| Field       | Type     | Required | Description |
|-------------|----------|----------|-------------|
| `signature` | `string` | Yes* | Ed25519 signature over the message (see below). **128 hex chars** (64 bytes) |
| `timestamp` | `integer`| Yes* | Current Unix time in **seconds**. Must be within **60 seconds** of server time |
| `nonce`     | `string` | Yes* | Unique string (e.g. UUID). Each `(to, nonce)` pair can only be used **once** |

### Auth Path 2: Session Token (SSS 2-of-3 wallets)

| Field           | Type     | Required | Description |
|-----------------|----------|----------|-------------|
| `session_token` | `string` | Yes* | Session token from `POST /wallet/login`. Server verifies the cached seed matches `to`. |

> **\*** Provide EITHER `signature + timestamp + nonce` OR `session_token`. If neither is provided, the server returns a `400` explaining both auth paths.

---

## Signature Construction

### Step 1: Build the message string

The message is a **plain UTF-8 string** with this exact format:

```
FAUCET:{to}:{amount}:{timestamp}:{nonce}
```

**Example:**
```
FAUCET:2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5:0.1:1740000000:550e8400-e29b-41d4-a716-446655440000
```

> **CRITICAL:** The `{amount}` in the message must be the **exact value you send** in the JSON body (e.g. `0.1`, not `0.10` or `100000`). The server does `format!("FAUCET:{}:{}:{}:{}", req.to, req.amount, req.timestamp, req.nonce)` using Rust's default `f64` Display — so `0.1` stays `0.1`, `100` becomes `100`, `1.5` stays `1.5`.

### Step 2: Sign the message bytes with Ed25519

```
message_bytes = UTF-8 encode(message_string)
signature     = Ed25519_Sign(secret_key, message_bytes)
```

- The **secret key** is the 64-byte Ed25519 signing key (or 32-byte seed, depending on your library)
- The corresponding **public key** must decode to the same 32 bytes as the `to` address
- Output: 64 raw bytes → hex-encode to 128 characters

### Step 3: Hex-encode the signature

```
signature_hex = hex(signature_bytes)   // 128 lowercase hex chars
```

---

## Full Request Examples

### Ed25519 Signature (microtx wallet)

```json
{
  "to": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
  "amount": 0.1,
  "signature": "a1b2c3d4...64_bytes_hex_encoded...128_chars_total",
  "timestamp": 1740000000,
  "nonce": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Session Token (SSS wallet — login first)

```json
{
  "to": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
  "amount": 0.1,
  "session_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

> **Note:** The `session_token` is obtained from `POST /wallet/login`. The server
> verifies the cached seed matches the `to` address. You can only faucet to your own wallet.

---

## JavaScript Example (using `tweetnacl`)

```js
import nacl from 'tweetnacl';

// Your Ed25519 keypair (secretKey is 64 bytes: 32-byte seed + 32-byte pubkey)
const keypair = nacl.sign.keyPair();           // or from existing seed
const address = bs58.encode(keypair.publicKey); // base58 address

const amount    = 0.1;
const timestamp = Math.floor(Date.now() / 1000);
const nonce     = crypto.randomUUID();

// Step 1: Build message (must match server format exactly)
const message = `FAUCET:${address}:${amount}:${timestamp}:${nonce}`;

// Step 2: Sign
const msgBytes = new TextEncoder().encode(message);
const sigBytes = nacl.sign.detached(msgBytes, keypair.secretKey); // 64 bytes

// Step 3: Hex-encode signature
const signature = Array.from(sigBytes)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');

// Step 4: POST
const res = await fetch('http://localhost:8080/faucet', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ to: address, amount, signature, timestamp, nonce }),
});
const data = await res.json();
// { success: true, minted: 0.1, to: "2Qmb...", new_balance: 100.1 }
```

---

## Python Example (using `ed25519` / `PyNaCl`)

```python
import nacl.signing
import json, time, uuid, requests

# Your Ed25519 signing key (32-byte seed)
signing_key = nacl.signing.SigningKey(seed_bytes)  # 32 bytes
verify_key  = signing_key.verify_key
address     = base58_encode(bytes(verify_key))     # base58 of 32-byte pubkey

amount    = 0.1
timestamp = int(time.time())
nonce     = str(uuid.uuid4())

# Step 1: Build message
message = f"FAUCET:{address}:{amount}:{timestamp}:{nonce}"

# Step 2: Sign
signed    = signing_key.sign(message.encode('utf-8'))
sig_bytes = signed.signature  # 64 bytes

# Step 3: Hex-encode
signature = sig_bytes.hex()   # 128 hex chars

# Step 4: POST
resp = requests.post('http://localhost:8080/faucet', json={
    'to': address,
    'amount': amount,
    'signature': signature,
    'timestamp': timestamp,
    'nonce': nonce,
})
print(resp.json())
```

---

## cURL Example (with pre-computed signature)

```bash
curl -X POST http://localhost:8080/faucet \
  -H "Content-Type: application/json" \
  -d '{
    "to": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
    "amount": 0.1,
    "signature": "<128-char-hex-ed25519-signature>",
    "timestamp": 1740000000,
    "nonce": "unique-uuid-here"
  }'
```

---

## Server Validation Pipeline

The server checks these in order — first failure = rejection:

| Step | Check | HTTP Status | Error |
|------|-------|-------------|-------|
| 1 | `to` is non-empty | 400 | `Missing 'to' address` |
| 2 | `amount` is `> 0` after clamping to `0.1` max | 400 | `Amount must be between 0 and 0.1 BB` |
| 3 | `to` decodes to exactly 32 bytes (hex or base58) | 400 | `Invalid base58 public key (must be 32 bytes)` |
| 4 | `signature` is valid hex, decodes to exactly 64 bytes | 400 | `Invalid signature (must be 64 bytes hex)` |
| 5 | `to` is a valid Ed25519 public key | 400 | `Invalid Ed25519 public key` |
| 6 | **Signature verifies** against message `FAUCET:{to}:{amount}:{timestamp}:{nonce}` | **401** | `Signature verification failed` |
| 7 | Nonce `faucet:{to}:{nonce}` has not been used before | 409 | `Nonce already used — possible replay attack` |
| 8 | `timestamp` is within 60 seconds of server time | 400 | `Request too old (>60s)` |

---

## Success Response

```json
{
  "success": true,
  "minted": 0.1,
  "to": "2QmbGHwzYBgZKwM4iCPGw2g5rM1NUsV8VrYSUcyphsg5",
  "new_balance": 100.1
}
```

---

## Dual Auth Architecture — Who Uses What

BlackBook has two classes of clients. The faucet (and all token action endpoints) support **both**:

```
┌──────────────────────────────────────────────────────────────────┐
│  ALL HUMAN USERS — SSS 2-of-3 Wallets (session token)            │
│                                                                  │
│  The private key is SPLIT into 3 shards and DESTROYED.           │
│  The client NEVER has the signing key.                           │
│                                                                  │
│  Flow:                                                           │
│    1. POST /wallet/login  → session_token (seed cached 30 min)   │
│    2. POST /faucet        { to, amount, session_token }          │
│    3. Server verifies session → derives pubkey → confirms        │
│       it matches `to` → mints tokens ✓                           │
│                                                                  │
│  Also works for:                                                 │
│    POST /sealevel/submit    { from, to, amount, session_token }  │
│    POST /usdc/transfer      { from, to, amount, session_token }  │
│    POST /transfer/session   { from, to, amount, session_token }  │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  AI AGENTS — Raw Ed25519 Keypairs (signature)                    │
│                                                                  │
│  Agent holds the full Ed25519 keypair in memory.                 │
│  Signs each request client-side — no login, no session.          │
│                                                                  │
│  Flow:                                                           │
│    1. Build message: "FAUCET:{to}:{amount}:{timestamp}:{nonce}"  │
│    2. Ed25519 sign → hex encode → 128 chars                     │
│    3. POST /faucet  { to, amount, signature, timestamp, nonce }  │
│    4. Server verifies Ed25519 signature ✓                        │
│                                                                  │
│  Also works for:                                                 │
│    POST /sealevel/submit    + signature + timestamp + nonce      │
│    POST /usdc/transfer      + signature + timestamp + nonce      │
│    POST /transfer/simple    (existing Ed25519 signed transfer)   │
└──────────────────────────────────────────────────────────────────┘
```

### Why SSS Wallets Can't Sign Client-Side

When a BlackBook wallet is created, the Ed25519 private key is **split via Shamir's Secret Sharing (2-of-3)** into three shards:

| Shard | Location | Purpose |
|-------|----------|---------|
| **A** | Client (encrypted with user's password) | User's copy — stored in localStorage/Supabase |
| **B** | Server (encrypted with SERVER_MASTER_KEY in ReDB) | Server's copy — auto-fetched on login |
| **C** | Offline (raw hex — user stores in cold storage) | Recovery copy — emergency use only |

The **full private key is destroyed** after the split. No single party ever holds it. To sign anything, the server must:

1. Decrypt Shard A (user provides password)
2. Decrypt Shard B (server uses its master key)
3. **Reconstruct the 32-byte seed** via Lagrange interpolation
4. Derive the Ed25519 signing key from the seed
5. Sign the transaction
6. **Zeroize the seed immediately** — it only exists in RAM for milliseconds

This is why SSS wallets use **session tokens** instead of client-side signatures. After login, the reconstructed seed is cached server-side for 30 minutes (refreshed on each use). The session token proves ownership without re-doing the expensive shard reconstruction.

AI agents skip all of this — they hold the full keypair and sign directly.

---

## Common Pitfalls

1. **Amount clamping (not an error):** If you send `amount: 100`, the server clamps it to `0.1` (the max) and **succeeds** — it mints 0.1 BB. The server never rejects for "too much" — it just caps. Amounts ≤ 0 are rejected.

2. **Amount precision in Ed25519 signatures (AI agents only):** The signed message uses Rust's `f64` Display format. `0.1` stays `0.1`, `100` becomes `100` (not `100.0`). Your agent's message string must match exactly. **This does not affect session token auth** — no signature to format.

3. **Timestamp drift (Ed25519 only):** Client clock must be within 60 seconds of the server. Use `Date.now() / 1000 | 0` for Unix seconds. **Session tokens are not affected** by clock drift.

4. **Nonce reuse (Ed25519 only):** Each `(address, nonce)` pair is single-use. Always generate a fresh UUID. **Session tokens generate their own nonce server-side.**

5. **Signature encoding (Ed25519 only):** Must be **lowercase hex**, 128 characters. Not base64, not base58.

6. **Address format:** Both hex (64 hex chars) and base58 work, but the `to` value in your JSON body must match the format used in the signed message string (Ed25519) or the wallet's address on file (session).
