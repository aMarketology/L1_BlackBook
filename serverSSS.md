# Server-Side SSS (Shamir's Secret Sharing) Wallet Recovery

## Overview

This document outlines the hybrid approach for user-friendly wallet recovery using **Shamir's Secret Sharing (SSS)** combined with cloud backup options. This system allows users to recover their wallet without remembering a seed phrase, while maintaining non-custodial security principles.

**NEW: Domain-Separated Unified Identity System**

Our wallet system now uses **domain separation** to prevent replay attacks between Layer 1 (Bank) and Layer 2 (Casino). One private key controls assets on both layers, but signatures are mathematically bound to their intended chain through a Chain ID prefix.

---

## Unified Identity Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ONE KEY → TWO PROTECTED DOMAINS                           │
└─────────────────────────────────────────────────────────────────────────────┘

User's Ed25519 Private Key (32 bytes)
         │
         ├──────────────────────────────────────────────────────────┐
         │                                                          │
         ▼                                                          ▼
┌────────────────────┐                                   ┌────────────────────┐
│  L1 TRANSACTIONS   │                                   │  L2 TRANSACTIONS   │
│  (Bank/Vault)      │                                   │  (Gaming/Casino)   │
├────────────────────┤                                   ├────────────────────┤
│ Chain ID: 0x01     │                                   │ Chain ID: 0x02     │
│ Signature format:  │                                   │ Signature format:  │
│ [0x01][message]    │                                   │ [0x02][message]    │
└────────────────────┘                                   └────────────────────┘
         │                                                          │
         │                                                          │
         └─────────── MATHEMATICALLY INCOMPATIBLE ─────────────────┘

If an attacker captures an L1 signature and replays it on L2:
❌ REJECTED - Signature was for [0x01][msg], not [0x02][msg]

If an attacker captures an L2 signature and replays it on L1:
❌ REJECTED - Signature was for [0x02][msg], not [0x01][msg]
```

---

## Wallet Address Format

### Deterministic Address Generation
```
Ed25519 Public Key (32 bytes)
         │
         ▼
    SHA256 Hash
         │
         ▼
   First 7 bytes (14 hex chars)
         │
         ▼
    L1: "L1" + 14 hex = "L148F582A1BC8976" (16 chars)
    L2: "L2" + 14 hex = "L248F582A1BC8976" (16 chars)
```

**Properties:**
- Same private key generates same address (deterministic)
- 56-bit address space (72 quadrillion unique addresses)
- Collision-resistant
- Human-readable with clear L1/L2 distinction

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WALLET CREATION FLOW                               │
└─────────────────────────────────────────────────────────────────────────────┘

User Signs Up
      │
      ▼
┌─────────────────┐
│ Generate Random │
│   32-byte Seed  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Create Ed25519  │────▶│ Encrypt Private │
│    Keypair      │     │ Key w/ Password │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │                       ▼
         │              ┌─────────────────┐
         │              │  Store in       │
         │              │  Supabase       │
         │              │  (wallets table)│
         │              └─────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│     SHAMIR'S SECRET SHARING (SSS)       │
│                                         │
│  Split seed into 3 shares               │
│  Threshold: 2 of 3 needed to recover    │
│                                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │ Share 1 │ │ Share 2 │ │ Share 3 │   │
│  └────┬────┘ └────┬────┘ └────┬────┘   │
└───────┼───────────┼───────────┼────────┘
        │           │           │
        ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ Supabase│ │  Cloud  │ │  Email  │
   │ Server  │ │ Backup  │ │ Backup  │
   │(encrypt)│ │(PIN enc)│ │(PIN enc)│
   └─────────┘ └─────────┘ └─────────┘
```

---

## Security Model

### What We Store

| Location | Data | Encryption | Who Has Access |
|----------|------|------------|----------------|
| Supabase `wallets` table | Encrypted private key | User's password (PBKDF2 + AES-256-GCM) | User only |
| Supabase `wallets` table | SSS Share 1 | Server key (AES-256-GCM) | Server + User (2FA required) |
| User's Google Drive/iCloud | SSS Share 2 | User's 6-digit PIN (PBKDF2 + AES-256-GCM) | User only |
| User's Email | SSS Share 3 | User's 6-digit PIN (PBKDF2 + AES-256-GCM) | User only |

### Why This Is Secure

1. **No single point of failure**: Server cannot recover wallet alone (only has 1 of 3 shares)
2. **User controls recovery**: Need PIN + backup = user consent required
3. **Brute-force resistant**: PIN-encrypted shares use 100,000 PBKDF2 iterations
4. **Non-custodial**: Server never has access to full private key

---

## Database Schema

### Wallets Table (Updated)

```sql
CREATE TABLE IF NOT EXISTS wallets (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id),
    email TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    address TEXT NOT NULL,
    
    -- Normal authentication
    encrypted_private_key TEXT NOT NULL,  -- AES-256-GCM encrypted with password
    
    -- SSS Recovery
    server_recovery_share TEXT,           -- Share 1: Encrypted with server key
    recovery_share_version INTEGER DEFAULT 1,
    
    -- Recovery state
    needs_recovery BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast lookups
CREATE INDEX idx_wallets_email ON wallets(email);
CREATE INDEX idx_wallets_user_id ON wallets(user_id);

-- RLS Policies
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own wallet" ON wallets
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own wallet" ON wallets
    FOR UPDATE USING (auth.uid() = user_id);
```

### Trigger for Password Reset Detection

```sql
-- Flag wallet for recovery when Supabase auth password changes
CREATE OR REPLACE FUNCTION flag_wallet_for_recovery()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE wallets 
    SET needs_recovery = TRUE,
        updated_at = NOW()
    WHERE user_id = NEW.id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_password_change ON auth.users;
CREATE TRIGGER on_password_change
    AFTER UPDATE OF encrypted_password ON auth.users
    FOR EACH ROW
    WHEN (OLD.encrypted_password IS DISTINCT FROM NEW.encrypted_password)
    EXECUTE FUNCTION flag_wallet_for_recovery();
```

---

## Environment Variables

```env
# Existing
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_JWT_SECRET=your-jwt-secret

# New - SSS Recovery
SERVER_ENCRYPTION_KEY=<64-char-hex-key>  # For encrypting server share
```

Generate server key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## Implementation Components

### 1. Wallet Recovery Module (`wallet-recovery.js`)

```javascript
// Dependencies
const crypto = require('crypto');
const secrets = require('secrets.js-grempe');  // SSS library

// Functions:
// - splitSeed(seedHex) → { serverShare, cloudShare, emailShare }
// - recoverSeed(share1, share2) → seedHex
// - encryptShareWithPIN(share, pin) → encryptedShare
// - decryptShareWithPIN(encryptedShare, pin) → share
```

### 2. SDK Methods (`unified-wallet-sdk.js`)

| Method | Purpose |
|--------|---------|
| `createWalletWithAutoBackup(email, password, pin)` | Create wallet with SSS shares |
| `recoverWalletWithBackup(email, pin, newPassword, backupShare)` | Recover using PIN + any backup |
| `changePassword(email, oldPassword, newPassword)` | Normal password change (re-encrypt) |
| `checkWalletStatus(email)` | Check if recovery is needed |
| `getServerShare(email)` | Retrieve server share (requires auth) |

### 3. NPM Dependencies

```json
{
  "dependencies": {
    "tweetnacl": "^1.0.3",
    "bip39": "^3.1.0",
    "secrets.js-grempe": "^2.0.0",
    "dotenv": "^16.0.0"
  }
}
```

---

## User Flows

### Flow 1: New Wallet Creation

```
┌─────────────────────────────────────────────────────────────┐
│                    WALLET CREATION                          │
└─────────────────────────────────────────────────────────────┘

1. User signs up with email + password
2. System generates random 32-byte seed
3. System creates Ed25519 keypair from seed
4. System encrypts private key with password → stores in Supabase
5. System splits seed into 3 SSS shares (threshold 2)
6. User prompted for 6-digit PIN

┌─────────────────────────────────────────────────────────────┐
│  🔐 Secure Your Wallet                                      │
│                                                             │
│  Create a 6-digit PIN for wallet recovery:                  │
│  [● ● ● ● ● ●]                                              │
│                                                             │
│  ⚠️  You'll need this PIN if you forget your password       │
└─────────────────────────────────────────────────────────────┘

7. Share 1 → Encrypted with server key → Stored in Supabase
8. Share 2 → Encrypted with PIN → Saved to Google Drive/iCloud
9. Share 3 → Encrypted with PIN → Emailed to user

┌─────────────────────────────────────────────────────────────┐
│  ✅ Wallet Created!                                         │
│                                                             │
│  Your wallet address: L1abc123...                           │
│                                                             │
│  Backup saved to:                                           │
│  ☑️ Our secure server                                       │
│  ☑️ Your Google Drive                                       │
│  ☑️ Your email                                              │
│                                                             │
│  Remember your 6-digit PIN for recovery!                    │
└─────────────────────────────────────────────────────────────┘
```

### Flow 2: Normal Login

```
┌─────────────────────────────────────────────────────────────┐
│                      NORMAL LOGIN                           │
└─────────────────────────────────────────────────────────────┘

1. User enters email + password
2. System fetches encrypted_private_key from Supabase
3. System decrypts with password
4. Wallet unlocked ✅

No PIN needed for normal login.
```

### Flow 3: Password Reset Recovery

```
┌─────────────────────────────────────────────────────────────┐
│                   PASSWORD RESET FLOW                       │
└─────────────────────────────────────────────────────────────┘

1. User clicks "Forgot Password"
2. Supabase sends password reset email
3. User sets new password via Supabase
4. Trigger fires → sets needs_recovery = TRUE

5. User logs in with new password
6. System detects needs_recovery = TRUE
7. System prompts for wallet recovery:

┌─────────────────────────────────────────────────────────────┐
│  🔐 Wallet Recovery Required                                │
│                                                             │
│  Your password was reset. To restore wallet access:         │
│                                                             │
│  Step 1: Enter your 6-digit PIN                             │
│  [● ● ● ● ● ●]                                              │
│                                                             │
│  Step 2: Provide your backup                                │
│  [☁️ From Google Drive]  [📧 Paste from email]              │
│                                                             │
│  [Recover Wallet]                                           │
└─────────────────────────────────────────────────────────────┘

8. System retrieves Share 1 from Supabase (user is authenticated)
9. User provides Share 2 (from cloud) OR Share 3 (from email)
10. User decrypts their share with PIN
11. System combines 2 shares → recovers seed
12. System verifies recovered public key matches stored public key
13. System re-encrypts private key with new password
14. System clears needs_recovery flag
15. Wallet restored ✅
```

### Flow 4: Change Password (Knows Old Password)

```
┌─────────────────────────────────────────────────────────────┐
│                   CHANGE PASSWORD FLOW                      │
└─────────────────────────────────────────────────────────────┘

1. User enters old password + new password
2. System decrypts private key with old password
3. System re-encrypts private key with new password
4. System updates Supabase
5. Done ✅

No PIN or SSS needed - user knows old password.
```

---

## Recovery Scenarios

| Scenario | User Has | Recovery Method | Outcome |
|----------|----------|-----------------|---------|
| Forgot password | PIN + Cloud backup | SSS recovery | ✅ Success |
| Forgot password | PIN + Email backup | SSS recovery | ✅ Success |
| Forgot password + PIN | Cloud + Email backup | Cannot decrypt shares | ❌ Lost |
| Forgot password + lost backups | PIN only | Only 1 share available | ❌ Lost |
| Lost everything | Nothing | No recovery possible | ❌ Lost |

### Key Insight
- User needs: **PIN** + **Any 1 backup** to recover
- Without PIN: Cannot decrypt cloud/email shares
- Without any backup: Cannot reach threshold of 2 shares

---

## Security Considerations

### Brute Force Protection

1. **PIN Encryption**: 100,000 PBKDF2 iterations
2. **Server Share**: Requires authenticated Supabase session to retrieve
3. **Rate Limiting**: Implement on recovery endpoint (recommended: 5 attempts/hour)

### Attack Vectors

| Attack | Mitigation |
|--------|------------|
| Server breach | Server only has 1 share (need 2) |
| Email compromise | Share encrypted with PIN |
| Cloud account hack | Share encrypted with PIN |
| PIN brute force | 100k iterations + rate limiting |
| Server + Email breach | Still need PIN to decrypt |

### What We Cannot Protect Against

- User forgets PIN + password (by design - non-custodial)
- User loses all backups + forgets password
- User shares PIN with attacker who has backup access

---

## API Endpoints (Rust Backend)

### Existing Routes to Modify

```rust
// src/routes_v2/wallet.rs

// POST /api/v2/wallet/create
// - Add SSS share generation
// - Store server share
// - Return cloud share for user to save

// POST /api/v2/wallet/recover
// - Accept PIN + encrypted backup share
// - Combine with server share
// - Re-encrypt with new password
```

### New Routes

```rust
// POST /api/v2/wallet/recovery-status
// - Check if wallet needs recovery
// - Returns { needs_recovery: bool }

// GET /api/v2/wallet/server-share
// - Requires authentication
// - Returns encrypted server share for recovery
```

---

## Testing Plan

### Unit Tests

1. SSS split and combine with exact threshold
2. SSS fails with fewer than threshold shares
3. PIN encryption/decryption
4. Server key encryption/decryption

### Integration Tests

1. Full wallet creation with SSS
2. Recovery with cloud backup + PIN
3. Recovery with email backup + PIN
4. Failure with wrong PIN
5. Failure with wrong backup
6. Password change flow
7. Trigger fires on password reset

### E2E Tests

1. User signup → wallet created → backups generated
2. User forgot password → Supabase reset → recovery flow
3. User changes password → wallet re-encrypted

---

## Migration Plan

### For Existing Users

1. Prompt existing users to "upgrade" wallet security
2. Require current password to generate SSS shares
3. Store server share, provide cloud/email backups
4. Set flag indicating SSS is enabled

### Database Migration

```sql
-- Add new columns for existing wallets
ALTER TABLE wallets 
ADD COLUMN IF NOT EXISTS server_recovery_share TEXT,
ADD COLUMN IF NOT EXISTS recovery_share_version INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS needs_recovery BOOLEAN DEFAULT FALSE;

-- Version 0 = legacy (no SSS)
-- Version 1 = SSS enabled
```

---

## File Structure

```
frontend-sdk/
├── unified-wallet-sdk.js      # Main SDK (updated)
├── wallet-recovery.js         # SSS utilities (new)
├── wallet-recovery-tests.js   # Tests (new)
└── README.md                  # Updated docs

src/
├── routes_v2/
│   └── wallet.rs              # Updated wallet routes
└── integration/
    └── wallet_recovery.rs     # Rust SSS utilities (new)
```

---

## Dependencies to Install

```bash
# Frontend SDK
cd frontend-sdk
npm install secrets.js-grempe bip39

# Generate server key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Add output to .env as SERVER_ENCRYPTION_KEY
```

---

## Summary

| Component | Status | Priority |
|-----------|--------|----------|
| `wallet-recovery.js` module | To implement | High |
| Update `unified-wallet-sdk.js` | To implement | High |
| Supabase schema changes | To implement | High |
| Server key generation | To implement | High |
| Password reset trigger | To implement | Medium |
| Frontend recovery UI | To implement | Medium |
| Rust backend routes | To implement | Medium |
| Migration for existing users | To implement | Low |
| Rate limiting | To implement | Low |

---

## Next Steps

1. ✅ Create this documentation
2. ⬜ Install `secrets.js-grempe` and `bip39`
3. ⬜ Create `wallet-recovery.js` module
4. ⬜ Update `unified-wallet-sdk.js` with SSS methods
5. ⬜ Run Supabase migrations
6. ⬜ Generate and store SERVER_ENCRYPTION_KEY
7. ⬜ Create test file
8. ⬜ Test full recovery flow
