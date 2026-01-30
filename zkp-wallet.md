# ZKP + SSS Non-Custodial Wallet Architecture

> **Project**: BlackBook L1 Blockchain  
> **Version**: 2.0.0-zkp  
> **Started**: January 29, 2026  
> **Status**: 🔄 In Progress  

---

## Executive Summary

BlackBook L1 is upgrading from a **storage-heavy custodial wallet model** to a **computationally secure non-custodial architecture** using:

| Component | Old System | New System |
|-----------|------------|------------|
| Key Derivation | PBKDF2-SHA256 (300k iterations) | **Argon2id** (64MB memory-hard) |
| Key Storage | Encrypted private key in DB | **No private key stored** |
| Authentication | Password → Decrypt key | **ZK-Proof** (password never transmitted) |
| Key Splitting | 2-of-3 SSS (all shares in DB) | **3-way distributed SSS** (User/L1/Supabase) |
| Recovery Share | Unencrypted in database | **Peppered encryption** (requires server secret) |

### Why This Matters

1. **Database breach = Game over** in old system (attacker gets encrypted keys + SSS shares)
2. **GPU brute-force** can crack PBKDF2 in weeks/months
3. **Insider threat** - admins could theoretically access user keys
4. **Single point of failure** - all shares stored together defeats SSS purpose

The new system ensures **no single party** (not even BlackBook validators) can access user funds.

---

## Overview

BlackBook L1 implements a **Zero-Knowledge Proof (ZKP) + Shamir's Secret Sharing (SSS)** wallet system that never stores private keys. Instead, the system stores:
- **ZK-Commitments**: Cryptographic proofs that a user knows their password
- **Distributed SSS Shares**: Secret split across 3 parties (User/L1/Supabase)

This architecture ensures that **no single party can access funds** - not even the L1 validators.

---

## Architecture Comparison

### ❌ OLD System (Storage-Heavy)
```
┌─────────────────────────────────────────────────┐
│                   SUPABASE                      │
│  ┌───────────────────────────────────────────┐  │
│  │ encrypted_private_key (AES-256-GCM)       │  │
│  │ salt, iv, authTag                         │  │
│  │ SSS shares (all 3 stored together!)       │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
         ↓ User enters password
         ↓ PBKDF2 derives key
         ↓ Decrypt private key
         ↓ Sign transaction
         
⚠️  PROBLEM: DB breach = encrypted keys stolen
⚠️  PROBLEM: Weak password = brute-forceable
⚠️  PROBLEM: SSS shares stored together (defeats purpose)
```

### ✅ NEW System (Computationally Secure)
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│    SUPABASE     │  │      L1         │  │      USER       │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │ Share C   │  │  │  │ Share B   │  │  │  │ Password  │  │
│  │ (pepper   │  │  │  │ (on-chain │  │  │  │    ↓      │  │
│  │ encrypted)│  │  │  │ storage)  │  │  │  │ Argon2id  │  │
│  │           │  │  │  │           │  │  │  │    ↓      │  │
│  │ ZK-commit │  │  │  │ Verify    │  │  │  │ Share A   │  │
│  │ salt      │  │  │  │ circuit   │  │  │  └───────────┘  │
│  └───────────┘  │  │  └───────────┘  │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                   │                    │
         └───────────────────┼────────────────────┘
                             ↓
                    2-of-3 SSS Reconstruction
                             ↓
                      Private Key (ephemeral)
                             ↓
                      Sign → Zeroize
```

---

## Cryptographic Primitives

### 1. Key Derivation Function: Argon2id
```javascript
// Memory-hard KDF resistant to GPU/ASIC attacks
const config = {
  type: 'argon2id',        // Hybrid of Argon2i + Argon2d
  memoryCost: 65536,       // 64 MB RAM required
  timeCost: 3,             // 3 iterations
  parallelism: 4,          // 4 threads
  hashLength: 32           // 256-bit output
};

// Share A = Argon2id(password, salt)
```

### 2. ZK-Commitment: Poseidon Hash
```javascript
// ZK-friendly hash function (efficient in ZK circuits)
// Commitment = Poseidon(username || password || salt)

// Properties:
// - User can prove they know password WITHOUT revealing it
// - Stored on Supabase for authentication
// - L1 verifies ZK-proof against this commitment
```

### 3. SSS: Shamir's Secret Sharing over GF(2^256)
```javascript
// Galois Field arithmetic for information-theoretic security
const GF_PRIME = 2n**256n - 189n;  // Safe prime for 256-bit field

// Split: secret → [Share A, Share B, Share C]
// Reconstruct: Any 2 shares → secret
// Threshold: k=2, n=3
```

### 4. Peppered Encryption for Share C
```javascript
// Encryption key = Argon2id(password + salt + PEPPER)
// PEPPER = Server-side secret (env var, never in DB)

// Even with DB breach:
// - Attacker has encrypted Share C
// - Attacker has salt
// - Attacker does NOT have PEPPER
// - Cannot decrypt Share C
```

---

## Data Flow

### Registration Flow
```
User Input: username, password
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 1. Generate random 256-bit secret (ephemeral private key)  │
│ 2. Generate random 256-bit salt                            │
│ 3. Derive public key from secret (Ed25519)                 │
│ 4. Generate L1 address: SHA256(pubkey)[0..20]              │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 5. SSS Split: secret → [shareA, shareB, shareC]            │
│    - Share A: Derived deterministically from password      │
│      shareA = Argon2id(password, salt)                     │
│    - Share B: Random, stored on L1                         │
│    - Share C: Random, encrypted with peppered key          │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 6. Generate ZK-Commitment                                  │
│    commitment = Poseidon(username || password || salt)     │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 7. Store:                                                  │
│    - Supabase: commitment, salt, encrypted_shareC, pubkey  │
│    - L1 Chain: shareB, verification_data, address          │
│    - User: Remembers password (derives Share A on login)   │
└────────────────────────────────────────────────────────────┘
                 ↓
              DONE (secret zeroized from memory)
```

### Login Flow
```
User Input: username, password
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 1. Fetch from Supabase: commitment, salt                   │
│ 2. Derive Share A: Argon2id(password, salt)                │
│ 3. Generate ZK-Proof: Prove(password, salt, commitment)    │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 4. Send ZK-Proof to L1                                     │
│ 5. L1 Verifies: Verify(proof, commitment) === true         │
│ 6. L1 Returns: Share B (encrypted with session key)        │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 7. Reconstruct: SSS_Reconstruct(shareA, shareB) → secret   │
│ 8. Create SecureSession with auto-lock timer               │
│ 9. Session holds ephemeral secret (zeroized on timeout)    │
└────────────────────────────────────────────────────────────┘
```

### Transaction Signing Flow
```
Session Active: secret in memory
                 ↓
┌────────────────────────────────────────────────────────────┐
│ 1. Build transaction payload                               │
│ 2. Hash payload: SHA256(canonical_json)                    │
│ 3. Sign with Ed25519: sign(hash, secret)                   │
│ 4. Submit signed transaction to L1                         │
└────────────────────────────────────────────────────────────┘
                 ↓
              L1 verifies signature against stored pubkey
```

### Recovery Flow (Lost Password)
```
User has: 2 SSS shares (any combination)
                 ↓
┌────────────────────────────────────────────────────────────┐
│ Option A: Share B (from L1) + Share C (from Supabase)      │
│   - Requires identity verification (KYC, email, etc.)      │
│   - L1 releases Share B after verification                 │
│   - Supabase releases encrypted Share C                    │
│   - User decrypts Share C with recovery key                │
│   - Reconstruct secret from B + C                          │
└────────────────────────────────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────────────┐
│ Option B: Share A (from old password) + Share B/C          │
│   - User remembers old password                            │
│   - Derives Share A from old password                      │
│   - Gets Share B from L1 or Share C from Supabase          │
│   - Reconstruct secret from A + B or A + C                 │
└────────────────────────────────────────────────────────────┘
                 ↓
              Set new password → Generate new shares
```

---

## Implementation Files

### SDK (JavaScript/TypeScript)
```
sdk/
├── zkp-wallet-sdk.js          # Main wallet SDK
│   ├── ZKPWallet class        # Wallet management
│   ├── SecureSession class    # Auto-locking session
│   ├── deriveShareA()         # Argon2id key derivation
│   ├── generateZKProof()      # Poseidon commitment proof
│   ├── sssplit()              # 2-of-3 secret splitting
│   ├── ssReconstruct()        # Lagrange interpolation
│   ├── encryptShareC()        # Peppered AES-256-GCM
│   └── signTransaction()      # Ed25519 signing
│
└── tests/
    └── test-zkp-wallet.js     # Comprehensive tests
```

### L1 Backend (Rust)
```
src/
├── integration/
│   └── unified_auth.rs        # ZK proof verification
│       ├── verify_zk_proof()  # Poseidon verification
│       ├── store_share_b()    # On-chain share storage
│       └── release_share_b()  # Conditional share release
│
├── routes_v2/
│   └── auth.rs                # ZKP auth endpoints
│       ├── POST /auth/zkp-register
│       ├── POST /auth/zkp-login
│       └── POST /auth/zkp-recover
│
└── storage/
    └── mod.rs                 # Share B storage table
```

---

## Security Analysis

### Attack Vectors Mitigated

| Attack | OLD System | NEW System |
|--------|------------|------------|
| Database Breach | ❌ Encrypted keys stolen | ✅ Only commitments + encrypted shares |
| Brute Force | ❌ PBKDF2 GPU-crackable | ✅ Argon2id memory-hard (64MB/attempt) |
| Insider Threat | ❌ Admin has encrypted keys | ✅ No single party has full key |
| Replay Attack | ⚠️ Nonce-based | ✅ ZK-proof + nonce |
| Man-in-Middle | ⚠️ TLS only | ✅ ZK-proof (password never transmitted) |
| Key Extraction | ❌ Key in memory long-term | ✅ Ephemeral session with auto-zeroize |

### Security Guarantees

1. **Information-Theoretic SSS**: Even with infinite compute, 1 share reveals nothing
2. **Memory-Hard KDF**: GPU farms cannot parallelize Argon2id effectively
3. **Zero-Knowledge**: Password never leaves client device
4. **Forward Secrecy**: Compromised session doesn't compromise future sessions
5. **Pepper Protection**: DB breach alone cannot decrypt Share C

---

## Migration Strategy

### Apollo Wallet Migration
```javascript
// Existing Apollo wallet data:
{
  "address": "L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC",
  "keyDerivation": "PBKDF2-SHA256-300k",  // OLD
  "sss": "2-of-3-secp256k1"               // OLD shares together
}

// Migration steps:
// 1. User authenticates with old password
// 2. Decrypt and recover original private key
// 3. Generate new ZK-commitment
// 4. Split key into new 3-way shares (A/B/C)
// 5. Store Share B on L1, Share C on Supabase
// 6. Update wallet metadata to new format
// 7. Zeroize old key material
```

### New Wallet Format
```javascript
{
  "version": "2.0-zkp",
  "address": "L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC",
  "pubkey": "f0c71914dd238f2f9b5443c21bbd5b0ff3d9364900c78d22e2f38603afea3eba",
  "zkCommitment": "0x...",           // Poseidon hash
  "salt": "5ad255046f...",
  "shareBLocation": "L1_CHAIN",      // Share B on-chain
  "shareCLocation": "SUPABASE",      // Share C encrypted in DB
  "keyDerivation": "Argon2id-64MB",
  "encryption": "AES-256-GCM-PEPPERED",
  "sss": "2-of-3-GF(2^256)",
  "created": "2026-01-29T...",
  "migrated": "2026-01-29T..."
}
```

---

## API Endpoints

### POST /auth/zkp-register
```json
// Request
{
  "username": "apollo",
  "zkCommitment": "0x...",
  "salt": "0x...",
  "pubkey": "0x...",
  "shareB": "0x...",              // Encrypted for L1 storage
  "shareCEncrypted": "0x..."     // For Supabase storage
}

// Response
{
  "success": true,
  "address": "L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC",
  "shareBStored": true,
  "message": "Wallet registered with ZKP authentication"
}
```

### POST /auth/zkp-login
```json
// Request
{
  "address": "L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC",
  "zkProof": {
    "commitment": "0x...",
    "proof": "0x...",
    "publicInputs": ["0x..."]
  },
  "sessionPubkey": "0x..."       // Ephemeral key for Share B encryption
}

// Response
{
  "success": true,
  "shareBEncrypted": "0x...",    // Share B encrypted to sessionPubkey
  "sessionToken": "jwt...",
  "expiresIn": 3600
}
```

### POST /auth/zkp-recover
```json
// Request
{
  "address": "L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC",
  "recoveryProof": {
    "type": "identity_verification",
    "verificationId": "kyc_123..."
  },
  "newZkCommitment": "0x...",
  "newShareB": "0x..."
}

// Response
{
  "success": true,
  "shareBReleased": "0x...",
  "shareCHint": "Contact support for Share C recovery",
  "message": "Recovery initiated"
}
```

---

## Testing Checklist

- [ ] Unit Tests
  - [ ] Argon2id derivation produces consistent Share A
  - [ ] SSS split/reconstruct is information-theoretically secure
  - [ ] Poseidon commitment matches expected value
  - [ ] Peppered encryption cannot be decrypted without pepper
  
- [ ] Integration Tests
  - [ ] Full registration flow stores all shares correctly
  - [ ] Login with valid ZK-proof retrieves Share B
  - [ ] Invalid ZK-proof is rejected
  - [ ] Session auto-locks after timeout
  - [ ] Transaction signing works with reconstructed key
  
- [ ] Security Tests
  - [ ] Brute force attack takes >1 year with Argon2id
  - [ ] Single share reveals no information about key
  - [ ] Pepper absence prevents Share C decryption
  - [ ] Memory is properly zeroized after use

---

## Dependencies

### JavaScript (package.json)
```json
{
  "dependencies": {
    "argon2": "^0.31.2",
    "tweetnacl": "^1.0.3",
    "circomlibjs": "^0.1.7",    // Poseidon hash
    "snarkjs": "^0.7.0",        // ZK-proof generation
    "@noble/hashes": "^1.3.0"
  }
}
```

### Rust (Cargo.toml)
```toml
[dependencies]
ed25519-dalek = "2.0"
sha2 = "0.10"
aes-gcm = "0.10"
argon2 = "0.5"
ark-ff = "0.4"                  # Finite field arithmetic
ark-bn254 = "0.4"               # BN254 curve for ZK
ark-groth16 = "0.4"             # Groth16 verifier
poseidon-ark = "0.0.1"          # Poseidon hash
zeroize = "1.7"
```

---

## Timeline

| Phase | Task | Status |
|-------|------|--------|
| 1 | Create implementation plan | ✅ Complete |
| 2 | Implement zkp-wallet-sdk.js | 🔄 In Progress |
| 3 | Add L1 ZKP verification | ⬜ Pending |
| 4 | Update auth endpoints | ⬜ Pending |
| 5 | Migrate Apollo wallet | ⬜ Pending |
| 6 | Comprehensive testing | ⬜ Pending |
| 7 | Security audit | ⬜ Pending |
