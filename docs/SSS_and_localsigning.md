# BlackBook L1 — Two Auth Methods

There are two ways to authenticate and sign transactions on BlackBook. They are not competing — they serve different users and both will coexist.

---

## The Two Methods at a Glance

| | Method 1: SSS Session | Method 2: Local Signing |
|---|---|---|
| Who it's for | Casual users, web app | Power users, non-custodial |
| Where the private key lives | L1 server RAM (briefly) | User's browser memory only |
| What the user needs | Email + password | 24-word mnemonic or imported keypair |
| Server sees private key? | Yes (during login only) | Never |
| Survives server restart | No (re-login with password) | Yes |
| Browser extension needed | No | No |
| Implementation status | ✅ Done | ⏳ To be built |

---

## Method 1 — SSS Session (Password + Email)

### The Question You Asked: How Does It Work With Just a Password?

This is the key insight. **The password never protects the private key directly.** Instead it protects *one third* of the private key. Here is the full chain:

---

### Step 1: Wallet Creation — What Actually Happens

```
Server generates:
  256 bits of randomness (OsRng — cryptographically secure)
        ↓
  BIP-39 mnemonic (24 words) — derived from the randomness
        ↓
  Ed25519 seed (32 bytes) — derived from mnemonic via BIP-39 standard
        ↓
  Ed25519 keypair — public key = your wallet address (base58)
        ↓
  Shamir 2-of-3 split of the 32-byte seed:
        ↓
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │   Share A    │  │   Share B    │  │   Share C    │
  │  ~20 bytes   │  │  ~20 bytes   │  │  ~20 bytes   │
  └──────────────┘  └──────────────┘  └──────────────┘
  Any 2 of 3 reconstruct the full 32-byte seed
```

---

### Step 2: What Gets Stored Where

```
Share A:
  password → Argon2id(password, random_salt) → 32-byte AES key
  AES-256-GCM encrypt(Share A bytes, key, random_nonce)
  Output: "salt_b64:nonce_hex:ciphertext_hex"
  → Stored in YOUR database (Supabase, Postgres, etc.)
  → Without the password, this blob is computationally impossible to crack

Share B:
  SERVER_MASTER_KEY (env var on L1 server)
  AES-256-GCM encrypt(Share B bytes, master_key, random_nonce)
  → Stored in ReDB on the L1 server disk
  → Without the server master key, this is also impossible to crack

Share C:
  Raw hex bytes — no encryption
  → Returned to user once at creation
  → User stores offline (print it, write it down, hardware wallet)
  → Never stored on any server
```

---

### Step 3: The Password — Exactly What It Does

```
Your password "myPassword123" alone cannot do anything.
It is used ONLY as input to Argon2id:

  Argon2id(
    input:      "myPassword123",
    salt:       random 128-bit value (stored in the Share A blob),
    output:     32-byte AES key
  )

That 32-byte AES key decrypts the Share A blob → raw Share A bytes.
Share A bytes alone still cannot reconstruct the seed.
You need Share A + Share B together.
```

**This means:**
- Someone with your password but not the Share A blob → useless
- Someone with the Share A blob but not your password → computationally impossible to crack (Argon2id is designed to be slow: ~100ms per attempt intentionally)
- Someone with Share A blob + password but not Share B → still can't sign (only 1-of-3)
- Server with Share B but not Share A + password → can't sign either

---

### Step 4: Login Flow

```
POST /wallet/login {
  wallet_id:   "your_address",
  shard_1:     "salt:nonce:ciphertext",  ← Share A blob from your DB
  password:    "myPassword123",           ← user types this
  shard_2_is_server_encrypted: true,
  shard_2:     ""                         ← server fetches its own Share B
}

Server does:
  1. Argon2id(password, salt_from_blob) → 32-byte AES key
  2. AES-256-GCM decrypt(ciphertext, key, nonce) → raw Share A bytes
  3. Fetch Share B from ReDB → AES decrypt with SERVER_MASTER_KEY → raw Share B bytes
  4. Shamir.recover([Share_A, Share_B]) → 32-byte Ed25519 seed
  5. Ed25519(seed) → derive address → verify == wallet_id ✅
  6. Store seed in DashMap["uuid"] → return session_token
  7. Zeroize seed, both shares from server stack memory

Browser stores: session_token (a UUID, useless without server)
Server stores: seed in RAM only, keyed by session_token UUID
               wiped after 15 min idle, or on logout, or on restart
```

---

### Where Does Email Fit?

Email is **not part of the cryptographic system at all**. It is used only for:
- User account lookup (find the Share A blob in your DB)
- Password reset flows (if you build them)
- Supabase auth layer for identifying which row in DB to load Share A from

The actual security comes entirely from: **password + Argon2id + Share B on server**.

---

### What Happens If Someone Steals Your Database (Supabase)?

They get the Share A blobs for all users. Each blob is:
```
salt_b64:nonce_hex:AES-256-GCM-ciphertext
```

To crack one user's Share A they need to brute-force the password through Argon2id. Argon2id is designed to take ~100ms per attempt on modern hardware. At 10 attempts/second per GPU:
- 8-character password: ~months
- 12-character password: ~centuries

And even if they crack Share A, they still need Share B from the L1 server. Two separate breaches required.

---

## Method 2 — Local Signing (Phantom-Style)

### How It Works

The private key never leaves the user's device. The browser holds it in memory after the user unlocks it. Every transaction is signed locally before being sent to the server.

```
User imports keypair or derives from mnemonic:
  privateKey = Uint8Array(32 bytes) — in browser RAM only

To call /faucet:
  timestamp = current unix time (seconds)
  nonce = random UUID
  message = "FAUCET:{address}:{amount}:{timestamp}:{nonce}"
  signature = ed25519.sign(message_bytes, privateKey) → 64 bytes → hex

POST /faucet {
  to:         "address",
  amount:     0.1,
  public_key: "hex of 32-byte public key",
  signature:  "128 hex char signature",
  timestamp:  1234567890,
  nonce:      "uuid-v4"
}

Server does:
  1. Reconstruct message string
  2. Decode public_key hex → 32 bytes
  3. Verify public key base58 == `to` address
  4. ed25519.verify(message_bytes, signature_bytes, public_key) ✅
  5. Check timestamp is < 60 seconds old (anti-replay)
  6. Check nonce not seen before (anti-replay)
  7. Credit wallet
```

The server **never sees the private key**. It only sees the public key and signature, which are public by definition.

---

### How the Key Is Stored Locally

```
Option A — In-memory only (most secure, lost on page refresh):
  privateKey lives in a JS variable
  Browser tab closes → gone forever
  Best for: temporary sessions

Option B — Encrypted in localStorage:
  Argon2id(password) → AES-256-GCM encrypt(privateKey) → store in localStorage
  On unlock: user types password → decrypt → load into memory
  Browser wipe → gone (need mnemonic to restore)
  Best for: power users who manage their own keys

Option C — From mnemonic on demand:
  User types 24 words → derive seed → sign → forget
  Nothing stored anywhere
  Best for: maximum security, low frequency use
```

---

## How the Two Methods Coexist

```
User visits BlackBook app
         │
         ├── Has SSS wallet (created via /wallet/create)?
         │     └── Login with email + password → session_token
         │           └── All operations use session_token
         │
         └── Has raw keypair / mnemonic?
               └── Unlock locally in browser → hold privateKey in memory
                     └── All operations self-signed with Ed25519
                           no session_token needed
```

Both paths hit the same endpoints. The server accepts either:
- `{ session_token: "uuid" }` → looks up seed in DashMap
- `{ public_key: "hex", signature: "hex", timestamp: N, nonce: "uuid" }` → verifies locally signed message

---

## Implementation Plan

### Phase 1 — Already Done ✅
- SSS wallet creation (`/wallet/create`)
- SSS login (`/wallet/login`)
- SSS-based faucet, transfer, escrow (session_token path)
- Argon2id + AES-256-GCM encryption in `security.rs`
- Session store with 15-min TTL in `session_store.rs`

### Phase 2 — To Build ⏳
1. **Backend: Add Ed25519 signature branch to `/faucet`**
   - Accept `public_key + signature + timestamp + nonce` instead of `session_token`
   - Same anti-replay protection as `/escrow/deposit`

2. **Backend: Add Ed25519 branch to `/transfer/simple`**
   - Already partially done — verify the existing signed transfer handler

3. **Frontend: Local signing JS module**
   - `@noble/ed25519` library (~3KB)
   - `unlockFromMnemonic(words)` → load private key into memory
   - `sign(message)` → Ed25519 signature
   - `lock()` → zero out key from memory

4. **Frontend: Auth mode detection**
   - If `bb_session_token` in localStorage → use SSS path
   - If `bb_private_key_unlocked` in memory → use local signing path
   - If session expires → prompt: "re-enter password" (SSS) or "already unlocked locally"

---

## The Bottom Line on Security

| Attack | SSS Session | Local Signing |
|---|---|---|
| Someone steals your DB (Share A blobs) | Need password too — Argon2id protected | N/A (no server-side storage) |
| Someone compromises L1 server | Gets Share B only — needs Share A + password too | Gets nothing — key never there |
| Someone steals your browser localStorage | Gets encrypted blob — needs password to decrypt | Gets encrypted key — needs password to decrypt |
| Server restart | Session lost — re-login with password | No effect — key is local |
| You forget your password | Recovery via Share C + new password | Recovery via mnemonic only |
| You lose your mnemonic | OK — Share A (DB) + Share B (server) still works | Wallet permanently lost |
