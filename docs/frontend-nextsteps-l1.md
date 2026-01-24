# Frontend Integration Guide - BlackBook L1

## 🎯 Overview

This document outlines the complete frontend integration path for BlackBook L1 blockchain. The L1 is production-ready with full wallet management, token transfers, and L2 bridge operations.

---

## 📦 Available SDKs

### 1. **blackbook-frontend-sdk.js** (Primary SDK)
Location: `sdk/blackbook-frontend-sdk.js`

The main SDK for frontend applications. Handles:
- Wallet creation and management
- Transaction signing (Ed25519)
- Balance queries
- Token transfers
- L2 bridge operations

```javascript
import { BlackBookSDK } from './blackbook-frontend-sdk.js';

const sdk = new BlackBookSDK('http://localhost:8080');
```

### 2. **blackbook-wallet-sdk.js** (Wallet Operations)
Location: `sdk/blackbook-wallet-sdk.js`

Specialized wallet management:
- Seed generation (BIP39 mnemonic)
- Key derivation (Ed25519)
- Vault encryption (AES-256 + PBKDF2)
- Address derivation (SHA256 → L1_prefix)

### 3. **wallet-recovery-sdk.js** (SSS Recovery)
Location: `sdk/wallet-recovery-sdk.js`

Shamir's Secret Sharing implementation:
- 3 shares generated (need 2 to recover)
- Password-encrypted share
- Recovery codes share (9 codes)
- Email backup share
- Secure password changes without affecting keypair

### 4. **unified-balance-sdk.js** (Cross-Layer Balances)
Location: `sdk/unified-balance-sdk.js`

Unified balance management across L1 and L2:
- Available balance (L1)
- Locked balance (L2 escrow)
- Credit balance (L2 gaming)
- Total balance aggregation

### 5. **l2-credit-sdk.js** (L2 Gaming Operations)
Location: `sdk/l2-credit-sdk.js`

L2 gaming session management:
- Session initiation
- Credit tracking
- Settlement requests
- Win/loss handling

---

## 🔌 L1 API Endpoints

### Health & Status
```
GET  /health          - Server health check
GET  /ledger          - Visual transaction log (ASCII)
GET  /status          - Detailed blockchain stats
```

### Wallet Operations
```
GET  /balance/{address}           - Get wallet balance
GET  /transactions/{address}      - Transaction history
```

### Token Transfers
```
POST /transfer/simple             - Frontend-friendly transfer
POST /transfer                    - Full transfer (advanced)
```

### L2 Bridge Operations
```
POST /l2/lock                     - Lock tokens for L2 session
POST /l2/unlock                   - Release tokens from L2
POST /l2/settle                   - Settle L2 session
GET  /l2/session/{address}        - Get active L2 session
```

### Admin Operations
```
POST /admin/mint                  - Mint new tokens (USDC backing)
POST /admin/burn                  - Burn tokens
```

---

## 🔐 Wallet Integration

### Creating a New Wallet

```javascript
import nacl from 'tweetnacl';
import { sha256 } from '@noble/hashes/sha256';

// 1. Generate random seed (32 bytes)
const seed = crypto.getRandomValues(new Uint8Array(32));

// 2. Derive Ed25519 keypair
const keyPair = nacl.sign.keyPair.fromSeed(seed);

// 3. Derive L1 address from public key
const publicKeyHash = sha256(keyPair.publicKey);
const addressHex = Array.from(publicKeyHash.slice(0, 20))
  .map(b => b.toString(16).padStart(2, '0'))
  .join('')
  .toUpperCase();
const l1Address = `L1_${addressHex}`;

// 4. Store seed encrypted in vault (NEVER expose raw seed)
const vault = await encryptVault(seed, userPassword);
```

### Signing Transactions

The L1 uses a specific signature format for `/transfer/simple`:

```javascript
async function signTransfer(seed, toAddress, amount) {
  const keyPair = nacl.sign.keyPair.fromSeed(hexToBytes(seed));
  
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const payload = JSON.stringify({ to: toAddress, amount: amount });
  
  // Message format: chain_id_byte + payload + "\n" + timestamp + "\n" + nonce
  const chainIdByte = new Uint8Array([0x01]); // L1 chain ID
  const payloadBytes = new TextEncoder().encode(payload);
  const timestampBytes = new TextEncoder().encode(`\n${timestamp}\n`);
  const nonceBytes = new TextEncoder().encode(nonce);
  
  // Concatenate all parts
  const message = new Uint8Array(
    chainIdByte.length + payloadBytes.length + 
    timestampBytes.length + nonceBytes.length
  );
  let offset = 0;
  message.set(chainIdByte, offset); offset += chainIdByte.length;
  message.set(payloadBytes, offset); offset += payloadBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(nonceBytes, offset);
  
  // Sign with Ed25519
  const signature = nacl.sign.detached(message, keyPair.secretKey);
  
  return {
    public_key: bytesToHex(keyPair.publicKey),
    wallet_address: fromAddress,
    payload: payload,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    schema_version: 1,
    signature: bytesToHex(signature)
  };
}
```

### Making a Transfer

```javascript
async function transfer(fromSeed, fromAddress, toAddress, amount) {
  const request = await signTransfer(fromSeed, toAddress, amount);
  request.wallet_address = fromAddress;
  
  const response = await fetch('http://localhost:8080/transfer/simple', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  });
  
  return response.json();
}
```

---

## 🌉 L2 Bridge Integration

### Bridge Out (L1 → L2)

When a user wants to start a gaming session:

```javascript
async function bridgeOut(seed, address, amount) {
  // 1. Create signed lock request
  const request = await signTransfer(seed, 'L2_ESCROW_POOL', amount);
  request.wallet_address = address;
  request.session_type = 'gaming';
  
  // 2. Call bridge endpoint
  const response = await fetch('/l2/lock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  });
  
  return response.json();
  // Returns: { session_id, locked_amount, expires_at }
}
```

**What happens on L1:**
1. 🌉 **BRIDGE OUT** transaction recorded
2. └─🔒 **LOCK** tokens moved to L2_ESCROW_POOL

### Bridge In (L2 → L1)

When settling a gaming session:

```javascript
async function bridgeIn(seed, address, sessionId, finalAmount) {
  const request = {
    session_id: sessionId,
    wallet_address: address,
    final_amount: finalAmount, // After wins/losses
    signature: await signSettlement(seed, sessionId, finalAmount)
  };
  
  const response = await fetch('/l2/settle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  });
  
  return response.json();
}
```

**What happens on L1:**
1. 🌉 **BRIDGE IN** transaction recorded
2. └─🔓 **UNLOCK** tokens released from L2_ESCROW_POOL

---

## 💰 Balance Display

### Unified Balance Component

```javascript
async function getUnifiedBalance(address) {
  // L1 Available Balance
  const l1Response = await fetch(`/balance/${address}`);
  const l1Data = await l1Response.json();
  
  // L2 Session Balance (if active)
  const l2Response = await fetch(`/l2/session/${address}`);
  const l2Data = await l2Response.json();
  
  return {
    available: l1Data.balance,           // Can spend on L1
    locked: l2Data.locked_amount || 0,   // In L2 escrow
    credit: l2Data.credit_balance || 0,  // L2 gaming credit
    total: l1Data.balance + (l2Data.locked_amount || 0)
  };
}
```

### React Balance Component Example

```jsx
function WalletBalance({ address }) {
  const [balance, setBalance] = useState(null);
  
  useEffect(() => {
    getUnifiedBalance(address).then(setBalance);
  }, [address]);
  
  if (!balance) return <div>Loading...</div>;
  
  return (
    <div className="wallet-balance">
      <div className="available">
        <span>Available</span>
        <span>{balance.available.toFixed(2)} BB</span>
      </div>
      {balance.locked > 0 && (
        <div className="locked">
          <span>🔒 Locked (L2)</span>
          <span>{balance.locked.toFixed(2)} BB</span>
        </div>
      )}
      <div className="total">
        <span>Total</span>
        <span>{balance.total.toFixed(2)} BB</span>
      </div>
    </div>
  );
}
```

---

## 🔒 Security Best Practices

### 1. Never Expose Private Keys/Seeds
```javascript
// ❌ BAD - Never do this
const wallet = { seed: '18f2c2e3...', address: 'L1_...' };

// ✅ GOOD - Encrypt seed in vault
const vault = await encryptVault(seed, password);
localStorage.setItem('wallet_vault', vault.encrypted_blob);
```

### 2. Use Vault Encryption
```javascript
// PBKDF2 key derivation (100,000 iterations)
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
  passwordKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);
```

### 3. Password Changes Don't Affect Keys
The private key is derived from the **seed**, not the password. Password only encrypts the vault:
```
Seed (constant) → Private Key → Public Key → Address
     ↓
Password → Vault Encryption (can change)
```

### 4. Implement SSS Recovery
Create 3 shares during wallet creation:
- Share 1: Encrypted with password (stored in vault)
- Share 2: 9 recovery codes (give to user)
- Share 3: Email backup (optional)

User needs any 2 shares to recover wallet.

---

## 📊 Test Accounts (Development Only)

| Account | Address | Balance |
|---------|---------|---------|
| Alice | `L1_52882D768C0F3E7932AAD1813CF8B19058D507A8` | ~12,000 BB |
| Bob | `L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433` | ~17,000 BB |
| Mac | `L1_94B3C863E068096596CE80F04C2233B72AE11790` | ~8 BB |
| Dealer | `L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` | ~100,000 BB |

**Note:** These are testnet accounts. Never use these seeds in production.

---

## 🚀 Frontend Implementation Checklist

### Phase 1: Basic Wallet
- [ ] Wallet creation with seed generation
- [ ] Vault encryption for seed storage
- [ ] Address derivation and display
- [ ] Balance fetching and display
- [ ] Transaction history view

### Phase 2: Transfers
- [ ] Send tokens form
- [ ] Transaction signing
- [ ] Transfer confirmation UI
- [ ] Transaction status tracking

### Phase 3: L2 Bridge
- [ ] Bridge Out (start gaming session)
- [ ] Lock status display
- [ ] Bridge In (settle session)
- [ ] Unified balance (L1 + L2)

### Phase 4: Security
- [ ] SSS recovery code generation
- [ ] Password change flow
- [ ] Wallet backup/export
- [ ] Session timeout handling

### Phase 5: Advanced
- [ ] QR code for receiving
- [ ] Contact/address book
- [ ] Transaction notifications
- [ ] Multi-wallet support

---

## 📁 File Structure for Frontend

```
src/
├── lib/
│   ├── blackbook-sdk.js       # Main SDK wrapper
│   ├── wallet.js              # Wallet operations
│   ├── crypto.js              # Ed25519, SHA256, AES
│   └── api.js                 # HTTP client
├── components/
│   ├── WalletBalance.jsx
│   ├── SendTokens.jsx
│   ├── TransactionHistory.jsx
│   ├── BridgeOut.jsx
│   └── BridgeIn.jsx
├── hooks/
│   ├── useWallet.js
│   ├── useBalance.js
│   └── useTransactions.js
└── context/
    └── WalletContext.jsx
```

---

## 🔗 Useful Links

- **L1 Ledger View:** `http://localhost:8080/ledger`
- **Health Check:** `http://localhost:8080/health`
- **SDK Examples:** `sdk/` directory
- **Test Suite:** `tests/js/` directory

---

## ✅ Production Readiness

The L1 has passed comprehensive testing:
- ✅ Wallet generation and key derivation
- ✅ Ed25519 signature validation
- ✅ Token transfers with balance checks
- ✅ L2 bridge lock/unlock operations
- ✅ Double-spend prevention
- ✅ Replay attack protection
- ✅ Input validation (XSS, SQL injection, overflow)
- ✅ Concurrent request handling
- ✅ Fuzz testing (100+ random payloads)
- ✅ DOS resistance testing

**Total Supply:** 130,985 BB  
**Active Wallets:** 8  
**Transaction Count:** 93+

---

*Last Updated: January 23, 2026*
