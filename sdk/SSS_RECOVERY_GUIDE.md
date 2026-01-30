# 🔐 Shamir's Secret Sharing (SSS) Recovery Guide
### Apollo Wallet - BlackBook L1 Blockchain

---

## Table of Contents
1. [What is Shamir's Secret Sharing?](#what-is-shamir-secret-sharing)
2. [Apollo Wallet Architecture](#apollo-wallet-architecture)
3. [The Paper Backup System](#the-paper-backup-system)
4. [Recovery Scenarios](#recovery-scenarios)
5. [Technical Implementation](#technical-implementation)
6. [Security Model](#security-model)

---

## What is Shamir's Secret Sharing?

**Shamir's Secret Sharing (SSS)** is a cryptographic technique that splits a secret (like your wallet's root key) into multiple "shares" such that:

- **ANY 2 shares** can reconstruct the original secret
- **1 share alone** reveals NOTHING about the secret
- You can have **3 shares total** (or more)

### Analogy: The Bank Vault
```
Traditional Setup:  One key = Full access (lose it, lose everything)

SSS Setup:         Three key fragments
                   Any 2 fragments = Open vault
                   1 fragment alone = Useless
```

### Why This Matters
- **No Single Point of Failure**: Lose one share? Still have access with the other two.
- **Distributed Backup**: Store shares in different physical locations.
- **Recovery Without Digital Access**: Paper-based, works even if all devices are lost.

---

## Apollo Wallet Architecture

Apollo uses a **Dual-Key Security Model**:

```
┌─────────────────────────────────────────────────────────────┐
│                    APOLLO WALLET                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  🔑 ROOT KEY (256-bit)                                       │
│     ├─ Long-term identity                                   │
│     ├─ Rarely used (only for recovery)                      │
│     ├─ Split into 3 SSS shares (2-of-3 threshold)           │
│     └─ Printed on paper, stored in safe locations           │
│                                                              │
│  🔧 OPERATIONAL KEY (256-bit)                                │
│     ├─ Daily transaction signing                            │
│     ├─ Encrypted with user password (PBKDF2 + AES-256-GCM)  │
│     ├─ Stored in Supabase Zero-Knowledge vault              │
│     └─ Can be rotated/regenerated from root key             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Hierarchy
```
Root Key (SSS Paper Backup)
    │
    ├──> Wallet Address (L1_...)
    │    └──> Proves ownership on blockchain
    │
    └──> Can Generate New Operational Keys
         └──> Encrypted with password → Supabase
```

---

## The Paper Backup System

When you create an Apollo wallet, you receive **3 paper backup shares**:

### Example Apollo Shares:
```
┌──────────────────────────────────────────────────────────────┐
│  APOLLO WALLET - PAPER BACKUP SHARE #1                       │
│  ════════════════════════════════════════════════════════════│
│                                                              │
│  Share Number: 1                                             │
│  Share Data:   7f425d5e4a4303db98c1cf8303b668453586...      │
│                                                              │
│  QR Code: [██████████]                                       │
│           APOLLO-SHARE-1-7f425d...                           │
│                                                              │
│  ⚠️  SECURITY WARNINGS:                                      │
│  • Keep this share in a SECURE location                      │
│  • Do NOT store with other shares                            │
│  • ANY 2 shares can restore full wallet access               │
│  • 1 share alone reveals NOTHING                             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Recommended Storage Strategy

| Share # | Storage Location | Access Level |
|---------|------------------|--------------|
| Share 1 | Home safe | Immediate |
| Share 2 | Bank safe deposit box | Secure, 1-2 days |
| Share 3 | Trusted family member | Emergency backup |

**Critical Rule**: NEVER store 2+ shares together!

---

## Recovery Scenarios

### Scenario 1: Lost Device + Have Password ✅
**What You Have:**
- ✅ Paper backup shares (any 2 of 3)
- ✅ Supabase account password
- ❌ Lost/broken phone with Apollo wallet

**Recovery Steps:**
1. Get new device
2. Use 2 SSS shares to recover **Root Key**
3. Derive wallet address from root key
4. Login to Supabase with existing password
5. Download encrypted operational key from vault
6. Decrypt operational key with password
7. ✅ **Full wallet access restored on new device**

**Time Required:** 5 minutes  
**Data Loss:** None  
**Blockchain State:** Unchanged (same address, same balance)

---

### Scenario 2: Lost Device + Forgot Password ⚠️
**What You Have:**
- ✅ Paper backup shares (any 2 of 3)
- ❌ Forgot Supabase password
- ❌ Lost/broken phone with Apollo wallet

**Recovery Steps:**

#### Step 1: Recover Root Key from Paper
```javascript
// Use any 2 shares from paper backup
const share1 = { x: 1, y: "7f425d5e4a4303db..." };
const share3 = { x: 3, y: "44e253910fd79ed0..." };

const recoveredRoot = recombineSecret([share1, share3]);
// Result: Original 256-bit root key recovered!
```

#### Step 2: Prove Wallet Ownership
```javascript
const rootKeyPair = nacl.sign.keyPair.fromSeed(recoveredRoot);
const walletAddress = deriveL1Address(rootKeyPair.publicKey);
// Result: L1_E150B878DC4BF1BAC31EEC0934F5373258F386DC

// This address exists on blockchain with balance = proof of ownership
```

#### Step 3: Reset Supabase Password
1. Go to Supabase login
2. Click "Forgot Password"
3. Receive email reset link
4. Create **NEW password**

#### Step 4: Generate New Operational Key
```javascript
// With recovered root key, generate NEW operational key
const newOpKey = crypto.randomBytes(32);
const newOpKeyPair = nacl.sign.keyPair.fromSeed(newOpKey);

// Sign a "vault reset" message with ROOT key to prove ownership
const resetSignature = nacl.sign.detached(
    "VAULT_RESET_REQUEST",
    rootKeyPair.secretKey
);
```

#### Step 5: Encrypt with NEW Password
```javascript
const newPassword = "apollo_new_password_2026";
const salt = crypto.randomBytes(32);
const encryptionKey = deriveEncryptionKey(newPassword, salt);
const encryptedNewOpKey = encryptKey(newOpKey, encryptionKey);
```

#### Step 6: Update Supabase Vault
```javascript
// Login to Supabase with NEW password
await supabase.auth.signInWithPassword({
    email: 'apollo@blackbook.io',
    password: 'apollo_new_password_2026'
});

// Update vault with new encrypted operational key
await supabase.from('user_vault').upsert({
    user_id: apolloUserId,
    encrypted_keys: encryptedNewOpKey,
    salt: salt,
    updated_at: new Date()
});
```

#### Result:
✅ **Full wallet access restored**
- Same wallet address
- Same blockchain balance
- **NEW operational key** (old one is abandoned)
- **NEW password** protecting the vault

**Time Required:** 10-15 minutes  
**Data Loss:** None (blockchain balance preserved)  
**Security:** Old operational key becomes useless, new one created

---

### Scenario 3: Lost 2 Shares ❌ 🚨
**What You Have:**
- ❌ Only 1 SSS share remaining
- ✅ Supabase password (doesn't matter)

**Recovery Status:** **IMPOSSIBLE**

**Why?**
- SSS requires 2-of-3 shares minimum
- 1 share reveals ZERO information about the secret
- Mathematical impossibility to recover (security by design)

**Prevention:**
- Store shares in 3 separate secure locations
- Never store 2+ shares together
- Verify share storage annually

---

### Scenario 4: Supabase Data Breach 🛡️
**What Happens:**
- ⚠️ Attacker steals Supabase database
- They have: Encrypted operational key, salt

**What Attacker CANNOT Do:**
1. **Cannot decrypt operational key** without your password
   - PBKDF2 with 300,000 iterations (very slow to brute force)
   - AES-256-GCM encryption
   
2. **Cannot access root key** (not stored in Supabase)
   - Root key only exists in SSS shares (paper)
   
3. **Cannot sign transactions** without decrypted keys

**What You Should Do:**
1. Detect breach notification
2. Use SSS shares to recover root key
3. Generate new operational key
4. Change Supabase password
5. Update vault with new encrypted key
6. ✅ Wallet remains secure (attacker got nothing)

**Time to Rotate Keys:** 10 minutes  
**Funds at Risk:** None (attacker has no usable keys)

---

## Technical Implementation

### SSS Share Generation

```javascript
// Split 256-bit root key into 3 shares (2-of-3 threshold)
const SSS_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

function splitSecret(secret, numShares = 3, threshold = 2) {
    const secretInt = BigInt('0x' + secret.toString('hex'));
    
    // Generate random coefficients for polynomial
    const coefficients = [secretInt];
    for (let i = 1; i < threshold; i++) {
        const coeff = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % SSS_PRIME;
        coefficients.push(coeff);
    }
    
    // Evaluate polynomial at x = 1, 2, 3
    const shares = [];
    for (let x = 1; x <= numShares; x++) {
        let y = BigInt(0);
        for (let i = 0; i < coefficients.length; i++) {
            const term = (coefficients[i] * (BigInt(x) ** BigInt(i))) % SSS_PRIME;
            y = (y + term) % SSS_PRIME;
        }
        shares.push({ x, y: y.toString(16).padStart(64, '0') });
    }
    
    return shares;
}
```

### SSS Share Recovery

```javascript
// Reconstruct secret from any 2 shares using Lagrange interpolation
function recombineSecret(shares) {
    if (shares.length < 2) throw new Error('Need at least 2 shares');
    
    let secret = BigInt(0);
    
    // Lagrange interpolation at x=0
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        
        let numerator = BigInt(1);
        let denominator = BigInt(1);
        
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                const xj = BigInt(shares[j].x);
                numerator = (numerator * (BigInt(0) - xj)) % SSS_PRIME;
                denominator = (denominator * (xi - xj)) % SSS_PRIME;
            }
        }
        
        const lagrange = (numerator * modInverse(denominator, SSS_PRIME)) % SSS_PRIME;
        secret = (secret + (yi * lagrange)) % SSS_PRIME;
    }
    
    secret = (secret % SSS_PRIME + SSS_PRIME) % SSS_PRIME;
    const hexStr = secret.toString(16).padStart(64, '0');
    return Buffer.from(hexStr, 'hex');
}
```

### Operational Key Encryption

```javascript
// Password-based encryption of operational key
function deriveEncryptionKey(userPassword, salt) {
    // PBKDF2 with 300,000 iterations (OWASP 2023 recommendation)
    return crypto.pbkdf2Sync(userPassword, Buffer.from(salt, 'hex'), 300000, 32, 'sha256');
}

function encryptKey(keyBytes, encryptionKey) {
    const iv = crypto.randomBytes(12); // GCM nonce
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    
    let encrypted = cipher.update(keyBytes);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}
```

---

## Security Model

### Defense in Depth

```
Layer 1: SSS Paper Backup (Root Key)
    └─> Physical security (safe, bank vault)
    └─> Distributed storage (no single point of failure)
    └─> Threshold cryptography (2-of-3 required)

Layer 2: Password Protection (Operational Key)
    └─> PBKDF2 300k iterations (slow brute force)
    └─> AES-256-GCM authenticated encryption
    └─> User-controlled password

Layer 3: Zero-Knowledge Storage (Supabase)
    └─> Server never sees decrypted keys
    └─> Row-Level Security (RLS) policies
    └─> Only encrypted data stored

Layer 4: Blockchain Signatures (Ed25519)
    └─> Every transaction requires signature
    └─> Private keys never leave device
    └─> Domain-separated signing (replay protection)
```

### Threat Model

| Attack Scenario | Apollo Defense | Outcome |
|----------------|----------------|---------|
| Supabase breach | Zero-Knowledge encryption | ✅ Funds safe |
| Stolen password | Still need paper shares to rotate keys | ✅ Funds safe |
| Lost 1 SSS share | 2 other shares sufficient | ✅ Full recovery |
| Lost device | SSS recovery + Supabase vault | ✅ Full recovery |
| Phishing attack | Hardware signatures, no key export | ✅ Funds safe |
| Lost 2 SSS shares | Wallet unrecoverable (by design) | ❌ Permanent loss |

### Recovery Time Objectives (RTO)

| Scenario | Recovery Time | Data Loss |
|----------|---------------|-----------|
| Lost device + have password | 5 minutes | None |
| Lost device + forgot password | 10-15 minutes | None |
| Supabase breach response | 10 minutes | None |
| Key rotation (proactive) | 5 minutes | None |

---

## Best Practices

### ✅ DO:
- Print all 3 SSS shares immediately after wallet creation
- Store shares in 3 physically separate locations
- Test recovery process annually
- Use strong, unique Supabase password
- Enable 2FA on Supabase account
- Keep share locations documented (separate from shares)

### ❌ DON'T:
- Store 2+ shares together
- Take digital photos of shares (compromises security)
- Share your Supabase password
- Store shares in cloud storage or email
- Assume "I'll remember where I put them"
- Delay printing paper backups

---

## Emergency Recovery Checklist

```
□ Locate 2 SSS paper backup shares
□ Install Apollo wallet software on new device
□ Run SSS recovery script with 2 shares
□ Verify recovered wallet address matches blockchain
□ Login to Supabase (or reset password if forgotten)
□ If password reset: Generate new operational key
□ Update Supabase vault with new encrypted key
□ Test transaction signing
□ Verify balance on blockchain
□ Print new shares if operational key was rotated
□ Document recovery date and any changes made
```

---

## Conclusion

Apollo's SSS-based recovery system provides:

✅ **Resilience**: Lose device, password, or 1 share → Still recoverable  
✅ **Security**: Attacker needs 2 shares + password to compromise  
✅ **Simplicity**: Paper-based backup, no complex hardware  
✅ **Zero-Knowledge**: Supabase breach → Funds remain safe  
✅ **Flexibility**: Rotate operational keys without changing root identity  

**The Bottom Line:** Your paper backup shares are the master key to your financial sovereignty. Protect them wisely, and you'll always have access to your funds—even in worst-case scenarios.

---

## Additional Resources

- [WALLET_SECURITY.md](./WALLET_SECURITY.md) - General security practices
- [test-apollo-advanced.js](./tests/apollo/test-apollo-advanced.js) - SSS recovery test
- [Shamir's Secret Sharing (Wikipedia)](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [OWASP Password Storage Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

**Document Version:** 1.0  
**Last Updated:** January 27, 2026  
**Status:** Production-Ready ✅
