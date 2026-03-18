# BlackBook L1 — Wallet Keypairs & Address Generation

## Overview

On BlackBook L1, a wallet is nothing more than an **Ed25519 keypair**. No server call is required to "create" an account. The wallet exists the moment you generate the keypair locally. The first time you interact with the chain (e.g. via the Faucet), the L1 recognises that public key and opens an account for it automatically.

---

## Step 1 — Generate the Keypair (Client-Side Only)

### Option A — Random (fast, no recovery phrase)

Generate 32 cryptographically secure random bytes as a seed, then derive the Ed25519 keypair from it.

**TypeScript / JavaScript (browser or Node)**
```ts
import { randomBytes } from "@noble/curves/abstract/utils"; // or crypto.getRandomValues
import { ed25519 } from "@noble/curves/ed25519";

const privateKeyBytes = randomBytes(32);          // 32-byte CSPRNG seed
const publicKeyBytes  = ed25519.getPublicKey(privateKeyBytes); // 32 bytes
```

### Option B — BIP-39 Mnemonic (recommended, recoverable)

A human-readable 12- or 24-word phrase is hashed into a 64-byte BIP-39 seed. The first 32 bytes become the Ed25519 private key seed. This is **exactly what the Rust `export_keypair` example uses** and is compatible with Nightly / Phantom.

**TypeScript / JavaScript**
```ts
import * as bip39 from "bip39";
import { ed25519 } from "@noble/curves/ed25519";

// --- Create ---
const mnemonic    = bip39.generateMnemonic(256);       // 24-word phrase
const bip39Seed   = await bip39.mnemonicToSeed(mnemonic, ""); // 64 bytes, empty passphrase
const seed32      = bip39Seed.slice(0, 32);            // first 32 bytes only
const privateKey  = seed32;
const publicKey   = ed25519.getPublicKey(privateKey);   // 32 bytes

// --- Recover later ---
const bip39Seed2  = await bip39.mnemonicToSeed(existingMnemonic, "");
const privateKey2 = bip39Seed2.slice(0, 32);
```

> **WARNING — Store the mnemonic safely.** Anyone who has the mnemonic can regenerate the private key and drain the wallet. Never send it to any server.

---

## Step 2 — Derive the Wallet Address

The wallet address is **not** a hash of the public key. It is the **raw 32-byte Ed25519 public key encoded in Base58**. This is identical to how Solana addresses work.

```
Wallet Address = Base58Encode( Ed25519PublicKey[32 bytes] )
```

**TypeScript / JavaScript**
```ts
import bs58 from "bs58";

const walletAddress = bs58.encode(publicKey); // e.g. "Gk7aHj...3xPQ"
```

The server verifies this every time. When you call `/faucet` or `/transfer/simple`, the L1 re-derives the address from the provided public key and checks it matches the `wallet_address` you sent:

```rust
// From src/main.rs (server-side)
let derived_address = bs58::encode(verifying_key.to_bytes()).into_string();
if derived_address != req.wallet_address {
    return 401 Unauthorized
}
```

This means you cannot claim a wallet address that you do not hold the private key for.

---

## Step 3 — Signing Messages

All destructive actions on the chain require an **Ed25519 signature**. The chain never receives your private key — it only receives the signature and public key, then verifies them.

### Faucet (`POST /faucet`)

Construct the message string first, then sign it.

```
message = "FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

**TypeScript**
```ts
import { ed25519 } from "@noble/curves/ed25519";

const timestamp = Math.floor(Date.now() / 1000);
const nonce     = crypto.randomUUID();
const message   = `FAUCET:${walletAddress}:${amount}:${timestamp}:${nonce}`;
const msgBytes  = new TextEncoder().encode(message);
const signature = ed25519.sign(msgBytes, privateKey);   // Uint8Array(64)

const body = {
  wallet_address: walletAddress,
  amount:         100.0,
  public_key:     toHex(publicKey),   // hex string, 32 bytes → 64 hex chars
  signature:      toHex(signature),   // hex string, 64 bytes → 128 hex chars
  timestamp:      timestamp,
  nonce:          nonce,
};
```

### Transfer (`POST /transfer/simple`)

The transfer message is **binary**, not a plain string. It is constructed as:

```
[chain_id (1 byte)] + [payload JSON bytes] + ["\n"] + [timestamp string bytes] + ["\n"] + [nonce bytes]
```

where `payload` is the JSON string `{"to":"<address>","amount":<number>}`.

**TypeScript**
```ts
const chainId     = 1;
const payload     = JSON.stringify({ to: recipientAddress, amount: 50.0 });
const timestamp   = Math.floor(Date.now() / 1000);
const nonce       = crypto.randomUUID();

const enc         = new TextEncoder();
const messageBytes = new Uint8Array([
  chainId,
  ...enc.encode(payload),
  0x0a,                          // "\n"
  ...enc.encode(String(timestamp)),
  0x0a,                          // "\n"
  ...enc.encode(nonce),
]);

const signature = ed25519.sign(messageBytes, privateKey);

const body = {
  public_key:    toHex(publicKey),
  wallet_address: walletAddress,
  payload:       payload,        // the raw JSON string you signed
  timestamp:     timestamp,
  nonce:         nonce,
  chain_id:      chainId,
  signature:     toHex(signature),
};
```

### Escrow Deposit (`POST /escrow/deposit`)

```
message = "ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

### Escrow Withdraw (`POST /escrow/withdraw`)

```
message = "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

---

## Hex Encoding Helper

All `public_key` and `signature` fields are sent as **lowercase hex strings**, not Base58 and not Base64.

```ts
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
```

---

## Full Wallet Object (What to Store Client-Side)

```ts
interface BlackBookWallet {
  mnemonic:      string;      // 24 words — NEVER send to server
  privateKey:    Uint8Array;  // 32 bytes — NEVER send to server
  publicKey:     Uint8Array;  // 32 bytes — safe to share
  address:       string;      // Base58(publicKey) — your "account number"
}
```

---

## Security Rules

| Rule | Why |
|---|---|
| Generate keys with `crypto.getRandomValues()` (browser) or `OsRng` (Rust) | Predictable RNG = stolen funds |
| Never send `privateKey` or `mnemonic` over the network | Server does not need them |
| Always use a fresh `nonce` (UUID or random hex) per request | Protects against replay attacks |
| Always use the current Unix `timestamp` | Replay protection + ordering |
| `public_key` and `signature` are hex, `wallet_address` is Base58 | Field format mismatch causes 400/401 errors |

---

## Why Two Wallets Can Never Share an Address

The private key is a random draw from a $2^{256}$ space (approximately $1.16 \times 10^{77}$ possibilities — comparable to the number of atoms in the observable universe). The chain address is derived deterministically from the public key with no hash truncation, so the address space is equally large. A collision is not a practical concern for any system operating at human or even civilisation scale.
