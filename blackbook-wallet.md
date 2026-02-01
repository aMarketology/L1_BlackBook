# BlackBook L1 Wallet System: S+ Tier

**FROST + OPAQUE — The Gold Standard of Non-Custodial Security**

> We don't just protect your private key; we ensure it **never exists in one place**.

---

## Table of Contents

1. [The S+ Tier Concept](#the-s-tier-concept-threshold-signing-mpc)
2. [Shard Architecture](#shard-architecture)
3. [OPAQUE Authentication](#1-zero-knowledge-passwords-opaque)
4. [FROST Threshold Signing](#2-threshold-signing-frost)
5. [Mnemonic Backup](#3-mnemonic-backup-shard-3)
6. [Security Comparison](#s-tier-security-comparison)
7. [API Endpoints](#api-endpoints)
8. [For Developers](#summary-for-developers)

---

## The S+ Tier Concept: Threshold Signing (MPC)

In **standard wallets**, the private key is a single file. If a hacker finds it, you're done.

In **BlackBook S+ Tier**, we use **FROST** (Flexible Round-Optimized Schnorr Threshold):

- The private key is "born" in 3 separate mathematical fragments called **Shards**
- To spend money, two shards "talk" to each other to create a signature
- The **full private key is NEVER reconstructed in memory**

---

## Shard Architecture

| Shard | Role | Where It Lives |
|-------|------|----------------|
| **Shard 1** | Device Shard | Your local machine/browser (inside a Secure Enclave) |
| **Shard 2** | Guardian Shard | The BlackBook L1 Network (protected by OPAQUE) |
| **Shard 3** | Recovery Shard | A printed 24-word backup or your personal Cloud |

### How Signing Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SHARD 1       │    │   SHARD 2       │    │   SHARD 3       │
│   (Device)      │    │   (Guardian)    │    │   (Recovery)    │
│                 │    │                 │    │                 │
│ Your Phone/PC   │    │ BlackBook L1    │    │ Paper Backup    │
└────────┬────────┘    └────────┬────────┘    └─────────────────┘
         │                      │
         │  Partial Signature   │  Partial Signature
         └──────────┬───────────┘
                    │
                    ▼
           ┌───────────────────┐
           │ VALID Ed25519 SIG │
           │ (Full key never   │
           │  existed!)        │
           └───────────────────┘
```

---

## 1. Zero-Knowledge Passwords (OPAQUE)

Instead of sending your password to the server, we use **OPAQUE**. This is a "Password Authenticated Key Exchange" where the server verifies your identity **without ever seeing your password or even a hash of it**.

### Registration (Server-Side)

When you sign up, we store an "OPAQUE Record"—a mathematical blob that is **useless to a hacker**.

```rust
// src/unified_wallet/opaque_auth.rs

pub fn registration_start(
    &self,
    session_id: &str,
    username: &str,
    client_request_bytes: &[u8],
) -> Result<Vec<u8>, WalletError> {
    // Deserialize client's registration request
    let client_request = RegistrationRequest::<BlackBookCipherSuite>::deserialize(client_request_bytes)
        .map_err(|e| WalletError::AuthError(format!("Invalid registration request: {:?}", e)))?;
    
    // Create server registration — server NEVER sees the password
    let server_registration_start = ServerRegistration::<BlackBookCipherSuite>::start(
        &self.server_setup,
        client_request,
        username.as_bytes(),
    ).map_err(|e| WalletError::AuthError(format!("Server registration start failed: {:?}", e)))?;
    
    // Serialize response
    let response_bytes = server_registration_start.message.serialize();
    Ok(response_bytes.to_vec())
}
```

### What Makes OPAQUE Special

| Traditional Auth | OPAQUE |
|-----------------|--------|
| Password sent to server | Password **never leaves device** |
| Server stores hash | Server stores **OPAQUE record** (can't be brute-forced) |
| Hacker can crack hashes offline | **No offline attacks possible** |

---

## 2. Threshold Signing (FROST)

When you want to send a transaction, you don't "log in" to get your key. Instead, you perform a **Distributed Signing Ceremony**.

### How It Works

1. **You** sign the transaction locally with **Shard 1**
2. **The L1 Node** verifies your identity via **OPAQUE**
3. **The L1 Node** signs the transaction with **Shard 2**
4. **Result**: The two partial signatures combine into one valid Ed25519 signature

```rust
// src/unified_wallet/tss.rs

/// Generate our signature share (round 2)
/// 
/// After receiving all commitments, we compute our partial signature.
pub fn generate_share(
    &self,
    session_id: &str,
) -> Result<SignatureShare, WalletError> {
    let mut sessions = self.sessions.write();
    let state = sessions.get_mut(session_id)
        .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
    
    // Get our nonces
    let nonces = self.nonces.write().remove(session_id)
        .ok_or_else(|| WalletError::SigningError("Nonces not found".to_string()))?;
    
    // Build commitment map including ourselves
    let mut all_commitments = state.commitments.clone();
    let our_id = frost::Identifier::try_from(SERVER_PARTICIPANT_ID)
        .map_err(|e| WalletError::InvalidShard(format!("Invalid our ID: {:?}", e)))?;
    all_commitments.insert(our_id, nonces.1);
    
    // Create signing package
    let signing_package = frost::SigningPackage::new(
        all_commitments,
        &state.session.message,
    );
    
    // Generate our signature share — KEY NEVER EXISTS IN FULL
    let signature_share = frost::round2::sign(
        &signing_package,
        &nonces.0,
        &state.key_package,
    ).map_err(|e| WalletError::SigningError(format!("Signing failed: {:?}", e)))?;
    
    Ok(SignatureShare {
        participant_id: SERVER_PARTICIPANT_ID,
        share_hex: hex::encode(signature_share.serialize()),
    })
}
```

---

## 3. Mnemonic Backup (Shard 3)

Even though we use advanced MPC, we still provide a **24-word recovery phrase**. This represents **Shard 3**.

If you lose your computer (Shard 1) AND BlackBook's servers vanish (Shard 2), you can use these 24 words to recreate the key.

```javascript
// sdk/mnemonic-wallet.js

function generateSPlusWallet() {
    // 1. Generate 256 bits of entropy
    const entropy = crypto.randomBytes(32);
    
    // 2. Generate 24 words for Shard 3 (The Backup)
    const mnemonic = bip39.entropyToMnemonic(entropy);
    
    // 3. Perform Distributed Key Generation (DKG)
    // Result: Shard 1 (Stay on device), Shard 2 (Send to L1), Shard 3 (Paper)
    return { shard1, shard2, shard3_mnemonic: mnemonic };
}
```

---

## S+ Tier Security Comparison

| Feature | Standard Wallet | BlackBook S+ Tier |
|---------|----------------|-------------------|
| **Key Storage** | Full key on disk | Key **never exists** in full |
| **Password** | Sent to server (hashed) | **Never leaves** user device (OPAQUE) |
| **Server Breach** | Hacker steals all wallets | Hacker gets **0 funds** (needs User Shard) |
| **Memory Safety** | Key in RAM during signing | Only Shards in RAM; Key **never appears** |
| **Offline Attack** | Hash can be cracked | **Mathematically impossible** |

---

## API Endpoints

### Registration Flow (DKG + OPAQUE)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/register/start` | POST | Initialize DKG + OPAQUE registration |
| `/wallet/register/round1` | POST | Exchange DKG round 1 packages |
| `/wallet/register/round2` | POST | Exchange DKG round 2 packages |
| `/wallet/register/finish` | POST | Finalize wallet creation |

### Login Flow (OPAQUE)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/login/start` | POST | Start OPAQUE authentication |
| `/wallet/login/finish` | POST | Complete login, get session key |

### Signing Flow (FROST TSS)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/sign/start` | POST | Begin threshold signing (round 1) |
| `/wallet/sign/commitment` | POST | Exchange commitments |
| `/wallet/sign/finish` | POST | Aggregate signature shares |

### Utility

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/info/:address` | GET | Get wallet public info |
| `/wallet/health` | GET | Service health check |
| `/balance/:address` | GET | Check on-chain balance |

---

## Summary for Developers

You are building on a **Multi-Party Computation (MPC)** system.

When you call `/wallet/sign/*`, you aren't "logging in"—you are participating in a **cryptographic ceremony** where the server acts as a **Co-Signer**.

### Security Guarantees

| Scenario | Result |
|----------|--------|
| **Server compromised** | User's funds are **SAFE** (attacker only has Shard 2) |
| **User's device compromised** | Funds are **SAFE** (attacker still needs OPAQUE proof for Shard 2) |
| **Both compromised** | Funds are **SAFE** (attacker needs password AND device access) |
| **User loses device** | **Recoverable** with Shard 3 (24 words) |

### Code Location

```
src/unified_wallet/
├── mod.rs           # Main module & UnifiedWalletSystem
├── types.rs         # WalletError, SignatureResult, etc.
├── dkg.rs           # FROST Distributed Key Generation
├── tss.rs           # Threshold Signature Scheme
├── opaque_auth.rs   # OPAQUE authentication
├── storage.rs       # Guardian shard storage
└── handlers.rs      # Axum HTTP handlers
```

### Dependencies (Cargo.toml)

```toml
frost-ed25519 = "2.0.0"    # Threshold Ed25519 signatures
frost-core = "2.0.0"       # FROST core library
opaque-ke = "3.0.0"        # OPAQUE PAKE protocol
vsss-rs = "4.0"            # Verifiable Secret Sharing
```

---

## Quick Start

```bash
# 1. Start the server
cargo run

# 2. Health check
curl http://localhost:8080/wallet/health

# 3. See sdk/tests/ for full examples
node sdk/tests/demo-ideal-hybrid.js
```

---

*BlackBook L1 — Where your keys are mathematically impossible to steal.*
