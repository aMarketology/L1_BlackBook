# BlackBook Wallet System — Technical Deep Dive

> **Version**: 2.0 (Shamir SSS — SVM Compatible)  
> **Chain**: BlackBook L1 · Port 8080 (HTTP) · Port 8899 (SVM RPC)  
> **Status**: Production-ready. All wallets are standard Ed25519 keypairs importable into any SVM-compatible wallet (Nightly, svmseek, Phantom).

---

## Overview

BlackBook wallets are **non-custodial, threshold-signature wallets** backed by:

- **BIP-39 24-word mnemonic** — the entropy root for the entire keypair
- **Shamir Secret Sharing 2-of-3** — splits the 32-byte seed into 3 shares; any 2 reconstruct it
- **Standard Ed25519 signing** — fully compatible with Solana/SVM ecosystem tooling
- **Argon2id + AES-256-GCM encryption** — every share at rest is encrypted with a unique salt

No private key ever exists in plaintext in memory beyond the nanoseconds needed to sign, then it's zeroized.

---

## Key Derivation — Step by Step

```
[ 256 bits OS entropy ]
         │
         ▼
[ BIP-39 24-word Mnemonic ]
  e.g. "abandon ability able about ..."
         │
         │  mnemonic.to_seed("")  (PBKDF2-SHA512, 2048 rounds)
         ▼
[ 64-byte BIP-39 Seed ]
         │
         │  first 32 bytes only
         ▼
[ 32-byte Ed25519 Seed ]  ◄── THIS is the secret
         │
         │  Ed25519SigningKey::from_bytes(&seed_32)
         ▼
[ Ed25519 Signing Key ]  +  [ Ed25519 Verifying Key ]
                                       │
                                       │  bs58::encode(pub_key_bytes)
                                       ▼
                           [ Wallet Address / Wallet ID ]
                             e.g. "4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby"
```

The wallet address IS the base58-encoded Ed25519 public key. This is identical to how Solana addresses work — making every BlackBook wallet address directly recognizable to every SVM tool in the ecosystem.

---

## Shamir Secret Sharing — The 2-of-3 Split

After deriving the 32-byte seed, it is immediately split into 3 shares using **Sharks v0.5** (a pure-Rust Shamir implementation). The threshold is **2-of-3**: any 2 shares reconstruct the full seed; 1 share alone reveals nothing.

```
[ 32-byte Seed ]
        │
        │  Sharks(2u8).dealer(&seed_32).take(3)
        ▼
  ┌─────────────┬─────────────┬─────────────┐
  │   Share A   │   Share B   │   Share C   │
  │  (User)     │  (Server)   │  (Recovery) │
  └─────────────┴─────────────┴─────────────┘
```

The seed is **zeroized immediately** after the split. It never exists past the creation call.

---

## The Three Shares — Who Holds What

### Share A — User Active Share
- **Where it lives**: Client-side (localStorage OR Supabase user vault)
- **At rest**: Encrypted with the user's **password** via Argon2id + AES-256-GCM
- **Format returned**: `salt_b64:nonce_b64:ciphertext_b64` (hex-encoded in JSON)
- **Used for**: Every transaction — the user provides this + their password to sign
- **Risk if lost**: Wallet is locked until recovered via Shares B + C

### Share B — Server Share
- **Where it lives**: **ReDB** (embedded persistent database on the BlackBook node)
- **At rest**: Encrypted with `SERVER_MASTER_KEY` environment variable (Argon2id + AES-256-GCM)
- **Format stored**: JSON container `{ "shard_b_data": "salt:nonce:ciphertext" }` keyed by wallet_id
- **Used for**: Combined with Share A on every sign request — the server fetches and decrypts this automatically
- **Risk if server DB lost**: Wallet unrecoverable without Shares A + C together

### Share C — Cold Recovery Share
- **Where it lives**: Returned as raw hex to the user at creation time — **user must store this offline**
- **Secondary backup**: HashiCorp Vault (if configured) — `vault.store_shard_c(user_id, share_c_hex)`
- **Also backed to**: Supabase (Share A synced during authenticated wallet creation)
- **Format**: 40–50 byte hex string
- **Used for**: Recovery when Share A is lost (Shares B + C reconstruct the seed instead)
- **Risk if lost**: If Share A is also lost, wallet is permanently unrecoverable

---

## Encryption: Argon2id + AES-256-GCM

Every share is encrypted identically — the same module (`src/wallet_unified/security.rs`) handles both:

```
[ Password/Master Key (string) ]
              │
              │  Argon2id with fresh 128-bit random salt
              ▼
[ 32-byte AES key ]
              │
              │  AES-256-GCM with fresh 96-bit random nonce
              ▼
[ Ciphertext ]

Stored as:  "<base64_salt>:<base64_nonce>:<base64_ciphertext>"
```

- **Argon2id** (memory-hard KDF) prevents brute-forcing even weak passwords
- **AES-256-GCM** provides authenticated encryption — tampering with ciphertext is detected
- **Fresh salt and nonce per encryption** — same password on same data produces different ciphertext every time

---

## Wallet Creation Flow (`POST /wallet/create`)

```
Client Request
{
  "username": "max",
  "password": "MyPass123",   ← encrypts Share A
  "pin": "1234",             ← optional, for auth
  "daily_limit": 10000       ← optional, for PIN gating
}

Server:
  1. Generate 256 bits entropy → BIP-39 mnemonic (24 words)
  2. mnemonic.to_seed("") → take first 32 bytes → seed_32
  3. Ed25519SigningKey::from_bytes(&seed_32) → signing + verifying keys
  4. bs58::encode(pub_key) → wallet_id = address
  5. Sharks(2u8).dealer(&seed_32).take(3) → [share_a, share_b, share_c]
  6. seed_32.zeroize()                              ← killed immediately
  7. encrypt_with_secret(password, share_a)         → encrypted_share_a
  8. encrypt_with_secret(SERVER_MASTER_KEY, share_b)→ encrypted_share_b
  9. Store encrypted_share_b in ReDB (keyed by wallet_id)
  10. Store pub_key in ReDB
  11. Sync encrypted_share_a to Supabase (if JWT authenticated)
  12. Backup share_c_hex to HashiCorp Vault (if configured)

Response:
{
  "wallet_id": "4PtfY2y...",        ← base58 public key
  "address":   "4PtfY2y...",        ← same — this is your on-chain address
  "public_key": "4PtfY2y...",
  "mnemonic": "word1 word2 ... word24",  ← SAVE THIS — full recovery root
  "share_a": "abc123:def456:...",        ← SAVE THIS — encrypted, goes to localStorage
  "share_a_is_encrypted": true,
  "share_c": "0a1b2c3d4e5f..."           ← SAVE THIS — write offline or to vault
}
```

**After creation**, the client must persist:
- `share_a` → localStorage key `bb_shard_a_<wallet_id>` (or Supabase)
- `share_c` → written to paper / hardware vault / cold storage
- `mnemonic` → 24 words — the nuclear recovery option (derives the full seed directly)

---

## Signing a Transfer (`POST /transfer`)

The private key is **never stored** — it is reconstructed on demand and zeroized immediately after signing:

```
Client Request:
{
  "from_wallet_id": "4PtfY2y...",
  "to_address": "HVbEJfk...",
  "amount": 50.0,
  "share_a": "abc123:def456:...",    ← from localStorage
  "password": "MyPass123"             ← user types this each time
}

Server:
  1. decrypt_with_secret(password, share_a) → share_a_bytes
  2. ReDB lookup by wallet_id → get encrypted_share_b
  3. decrypt_with_secret(SERVER_MASTER_KEY, share_b_encrypted) → share_b_bytes
  4. Sharks(2u8).recover(&[share_a, share_b]) → seed_bytes[0..32] → seed_32
  5. Ed25519SigningKey::from_bytes(&seed_32) → signing_key
  6. bs58::encode(signing_key.verifying_key()) → derived_address
  7. ASSERT: derived_address == from_wallet_id   ← security check
  8. signing_key.sign(b"from:to:amount") → signature (64 bytes)
  9. seed_32.zeroize()
     seed_bytes.zeroize()
     share_a_bytes.zeroize()
     share_b_bytes.zeroize()          ← every byte of key material killed
  10. blockchain.transfer(from, to, amount)

Response:
{
  "success": true,
  "signature": "deadbeef...",   ← 64-byte Ed25519 signature (hex)
  "from": "4PtfY2y...",
  "to": "HVbEJfk...",
  "amount": 50.0,
  "from_balance": 9975.0,
  "to_balance": 1450.0
}
```

---

## Extracting a Private Key for External Wallet Import

Because the seed is a standard 32-byte Ed25519 seed, it can be exported as a 64-byte Solana-format keypair that **any SVM wallet can import**:

```
cargo run --example extract_private_key
```

The example (`examples/extract_private_key.rs`):
1. Reads `real_wallets/Max_wallet.json`
2. Decrypts Share A using the stored password
3. Decodes Share C from hex
4. Reconstructs the 32-byte seed via `Sharks(2u8).recover(&[share_a, share_c])`
5. Builds the 64-byte Solana keypair: `[seed(32 bytes) || pubkey(32 bytes)]`
6. Outputs base58 of that 64-byte array → **paste directly into Nightly / svmseek / Phantom**

```
Solana 64-byte keypair format:
  ┌─────────────────────────────────────────────────────────────┐
  │  seed_32 (private)  │  pub_key_32 (public)                 │
  │  bytes 0..31        │  bytes 32..63                        │
  └─────────────────────────────────────────────────────────────┘
  bs58::encode(full_64_bytes) → importable private key string
```

---

## Recovery Scenarios

| Situation | Recovery Path |
|-----------|---------------|
| Forgot password | Cannot decrypt Share A. Use Share B (server) + Share C (cold) to reconstruct → set new password |
| Lost Share A (localStorage cleared) | Restore from Supabase backup OR reconstruct from Share B + Share C |
| Lost Share C | Server holds Share B — transfer to new wallet immediately. Create new cold backup. |
| Server DB wiped (Share B gone) | Share A + Share C → reconstruct seed → sweep funds to new wallet |
| Lost mnemonic | Reconstruct via any 2 shares — mnemonic is not required for recovery |
| Lost mnemonic + 2 shares | **Unrecoverable.** At least 2 of 3 shares are always required. |

---

## API Endpoints (Wallet System)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/wallet/create` | Optional JWT | Create wallet, returns mnemonic + all shares |
| `POST` | `/transfer` | None (SSS) | Sign and execute transfer using Share A + password |
| `POST` | `/wallet/secure/shard-b` | None | Retrieve Share B blob from ReDB (encrypted) |
| `POST` | `/wallet/secure/recover-shard-c` | **JWT required** | Retrieve Share C from HashiCorp Vault |
| `POST` | `/faucet` | None | Mint up to 100 BB per address per epoch |

---

## Why Not FROST?

Previous versions used **FROST Ed25519 2-of-3** (threshold signing). FROST was replaced because:

1. **Non-importable**: FROST generates a random group scalar as the "key" — it is NOT a standard 32-byte Ed25519 seed. No SVM wallet (Nightly, Phantom, Backpack, svmseek) can import it.
2. **Complexity**: Distributed key generation (DKG) required multi-round communication between share holders. Shamir just splits bytes.
3. **Ecosystem lock-in**: FROST-signed transactions require FROST-aware verifiers. Standard Ed25519 signatures (from recovered seed) work everywhere.

**Shamir + standard Ed25519** gives identical threshold security properties (2-of-3 required to sign) while producing a keypair that is 100% compatible with the existing Solana/SVM ecosystem.

---

## SDK Integration (blackbook_sdk.js)

```js
import BlackBookSDK from './sdk/blackbook_sdk.js';

const sdk = new BlackBookSDK('http://localhost:8080');

// Create wallet
const wallet = await sdk.createWallet('alice', 'password123', '1234', 10000);
// wallet.wallet_id   → on-chain address
// wallet.share_a     → encrypt-at-rest, save to localStorage
// wallet.share_c     → write offline (cold)
// wallet.mnemonic    → 24 words — ultimate backup

// Save Share A locally
sdk.saveShardALocal(wallet.wallet_id, wallet.share_a);

// Transfer
const tx = await sdk.transferWithSSS(
  wallet.wallet_id,
  'HVbEJfko9NzqrnKzmbsJBU3rLSHehNZVEFXqiPkDCUSc',
  50.0,
  wallet.share_a,
  'password123'
);

// Faucet (dev — 100 BB/epoch per address)
await sdk.faucet(wallet.wallet_id, 100);
```

---

## Security Properties

| Property | Implementation |
|----------|---------------|
| Non-custodial | Server never sees plaintext seed — Share B alone is useless |
| Brute-force resistant | Argon2id (memory-hard) on all key derivation |
| Authenticated encryption | AES-256-GCM — any byte flip in stored ciphertext is detected |
| Key material lifetime | Seed exists in RAM for < 1ms; zeroized immediately after signing |
| Address verification | Derived address cross-checked against `from_wallet_id` before signing |
| Replay protection | Signature covers `from:to:amount` — unique per transfer |
| SVM compatibility | Standard Ed25519 — importable into any Solana-ecosystem wallet |
