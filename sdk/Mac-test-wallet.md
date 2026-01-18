# Mac's BlackBook Wallet

**Created:** 2026-01-16T01:39:47.311Z
**Chain:** BlackBook L1
**Curve:** Ed25519

---

## 🔗 Public Blockchain Data

| Field | Value |
|-------|-------|
| **L1 Address** | `L1_94B3C863E068096596CE80F04C2233B72AE11790` |
| **Public Key** | `ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752` |

---

## 📧 Identity

| Field | Value |
|-------|-------|
| **Username** | mac_blackbook |
| **Email** | mac@blackbook.io |

---

## 🔐 Encrypted Vault (Safe to Store in Supabase)

This is what gets stored in your database. The private key can ONLY be derived 
when the user provides their password.

```json
{
  "salt": "579a5c28a02f8c3ecc2801545a216cec",
  "encrypted_blob": "U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad",
  "algorithm": "AES-256",
  "kdf": "PBKDF2",
  "kdf_iterations": 100000
}
```

---

## 🔑 How to Derive the Signing Key

When Mac logs in, the frontend does:

```javascript
// 1. User provides password
const password = userInput;

// 2. Derive encryption key using PBKDF2
const encryptionKey = PBKDF2(password, vault.salt, {
    iterations: 100000,
    keySize: 256
});

// 3. Decrypt the vault
const seed = AES.decrypt(vault.encrypted_blob, encryptionKey);

// 4. Derive Ed25519 keypair from seed
const keypair = nacl.sign.keyPair.fromSeed(seed);

// 5. Sign transactions with keypair.secretKey
const signature = nacl.sign.detached(message, keypair.secretKey);

// 6. Send to L1: { message, signature, public_key }
```

---

## ⚠️ Security Properties

1. **Private key is NEVER stored** - only encrypted seed in vault
2. **Private key is NEVER transmitted** - derived in-memory on client
3. **Password never leaves client** - only used to decrypt vault locally
4. **Salt is unique per wallet** - prevents rainbow table attacks
5. **PBKDF2 with 100k iterations** - makes brute force expensive

---

## 🧪 Test Credentials

> ⚠️ FOR TESTING ONLY - In production, user chooses their own password

| Field | Value |
|-------|-------|
| **Password** | `MacSecurePassword2026!` |

---

## 📋 Full Wallet Record (for Supabase)

```json
{
    "username": "mac_blackbook",
    "email": "mac@blackbook.io",
    "l1_address": "L1_94B3C863E068096596CE80F04C2233B72AE11790",
    "public_key": "ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752",
    "vault_salt": "579a5c28a02f8c3ecc2801545a216cec",
    "vault_encrypted_blob": "U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad",
    "vault_algorithm": "AES-256",
    "vault_kdf": "PBKDF2",
    "vault_kdf_iterations": 100000,
    "created_at": "2026-01-16T01:39:47.311Z"
}
```

---

## ✅ Verification

This wallet was tested and verified:
- ✓ Vault encrypts/decrypts correctly
- ✓ Keypair derives from seed correctly  
- ✓ Signatures are valid and verifiable
- ✓ Address matches public key derivation
