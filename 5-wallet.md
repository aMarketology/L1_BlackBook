# 🔐 BlackBook L1 - 5 Test Wallet Accounts

**Generated:** 2026-02-03T00:01:31.696Z  
**Security Model:** Hybrid Custody (FROST Institutional + Mnemonic Consumer)  
**Status:** ⚠️ DEVELOPMENT/TESTING ONLY - Private keys exposed

---

## Quick Reference

| Account | Role | Track | Address |
|---------|------|-------|---------|
| **Alice** | Regular User / Bettor | 👤 Mnemonic | `bb_6b7665632e4d8284c9ff288b6cab2f94` |
| **Bob** | Regular User / Bettor | 👤 Mnemonic | `bb_d8ed1c2f27ed27081bf11e58bb6eb160` |
| **Mac** | Power User / Developer | 👤 Mnemonic | `bb_d80f7e335383c9677c26e0cb70cc82e2` |
| **Apollo** | Heavy Trader / Market Participant | 👤 Mnemonic | `bb_59a829316f3a9ecb32d768a155ec2e2c` |
| **Dealer** | Market Maker & Oracle Authority | 🏛️ FROST | `L1_C3655C7AA0E5DD9C21DCE65EFE805F902B1C4D01` |

---

## Address Derivation

```
Mnemonic (Consumer):     bb_ + SHA256(publicKey).slice(0,32).toLowerCase()
FROST (Institutional):   L1_ + SHA256(publicKey).slice(0,40).toUpperCase()
L2 Address:              L2_ + SHA256(publicKey).slice(0,40).toUpperCase()
```

---

## Alice 👤

**Role:** Regular User / Bettor  
**Security Track:** Mnemonic (Consumer)

### Addresses
| Network | Address |
|---------|---------|
| BB | `bb_6b7665632e4d8284c9ff288b6cab2f94` |
| L2 | `L2_6b7665632e4d8284c9ff288b6cab2f94` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | `3d6d1a0bc67f8fcf566fabe4e0d1fe500561becf1286c2a3f71086435917c3e1` |
| **Private Key** | `5dba98f70ad9139256ac216101ca3438332d8a42c6ad468677a857596d0e7f40` ⚠️ TEST ONLY |
| **24-Word Mnemonic** | `romance tape leaf devote cable spot evolve few voice spy sword material midnight genius cave pulp spin shoe milk shrimp spike poverty fork brown` |

### Security Parameters

**SSS Scheme:** 2-of-3 Shamir Secret Sharing over GF(256)

| Share | Description | Location |
|-------|-------------|----------|
| Share A | Password-bound share (client-side) | Client-side (password-derived) |
| Share B | L1 blockchain share (ZKP-gated) | L1 Blockchain |
| Share C | Vault-encrypted backup share | HashiCorp Vault |

| Parameter | Value |
|-----------|-------|
| Password | `AlicePassword123!` ⚠️ TEST ONLY |
| Password Salt | `38cc5e93a3783fafb881aeba53dfebe9` |
| Key Derivation | Argon2id-64MB (3 iterations, parallelism 4) |
| BIP-44 Path | `m/44'/501'/0'/0'` |

### Capabilities
- ✅ Place bets
- ✅ Transfer tokens
- ✅ View balance

---

## Bob 👤

**Role:** Regular User / Bettor  
**Security Track:** Mnemonic (Consumer)

### Addresses
| Network | Address |
|---------|---------|
| BB | `bb_d8ed1c2f27ed27081bf11e58bb6eb160` |
| L2 | `L2_d8ed1c2f27ed27081bf11e58bb6eb160` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | `d107ea1e684349bb2a67f026fd98ebc28ba12b273b94c498b85dbbd867f62d4a` |
| **Private Key** | `80c470406b817e178d85788062ef3bfc234dbb276afd2a243c7992c33b271973` ⚠️ TEST ONLY |
| **24-Word Mnemonic** | `valley drink voyage argue pulp truck dad transfer school leopard process van vanish boss climb barrel rude slab diary allow practice delay scout lunch` |

### Security Parameters

**SSS Scheme:** 2-of-3 Shamir Secret Sharing over GF(256)

| Share | Description | Location |
|-------|-------------|----------|
| Share A | Password-bound share (client-side) | Client-side (password-derived) |
| Share B | L1 blockchain share (ZKP-gated) | L1 Blockchain |
| Share C | Vault-encrypted backup share | HashiCorp Vault |

| Parameter | Value |
|-----------|-------|
| Password | `BobPassword123!` ⚠️ TEST ONLY |
| Password Salt | `766b233937c4da287c77c8a3b9363e4f` |
| Key Derivation | Argon2id-64MB (3 iterations, parallelism 4) |
| BIP-44 Path | `m/44'/501'/0'/0'` |

### Capabilities
- ✅ Place bets
- ✅ Transfer tokens
- ✅ View balance

---

## Mac 👤

**Role:** Power User / Developer  
**Security Track:** Mnemonic (Consumer)

### Addresses
| Network | Address |
|---------|---------|
| BB | `bb_d80f7e335383c9677c26e0cb70cc82e2` |
| L2 | `L2_d80f7e335383c9677c26e0cb70cc82e2` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | `6f71fa7114d9d79f4681d6a0193ed6b9f22dfd8eace08b9106e41642a33698f7` |
| **Private Key** | `0088c6e8d7ae88f86033975e1cb6ccf61d06bc9666953a5947126ee30113d636` ⚠️ TEST ONLY |
| **24-Word Mnemonic** | `little yard valid yard core silly shaft rule monster noise combine arena lecture dizzy job kind pulse bonus better black crystal nephew again very` |

### Security Parameters

**SSS Scheme:** 2-of-3 Shamir Secret Sharing over GF(256)

| Share | Description | Location |
|-------|-------------|----------|
| Share A | Password-bound share (client-side) | Client-side (password-derived) |
| Share B | L1 blockchain share (ZKP-gated) | L1 Blockchain |
| Share C | Vault-encrypted backup share | HashiCorp Vault |

| Parameter | Value |
|-----------|-------|
| Password | `MacSecurePassword2026!` ⚠️ TEST ONLY |
| Password Salt | `19570dfa8fd6a10ca5b840895c864b77` |
| Key Derivation | Argon2id-64MB (3 iterations, parallelism 4) |
| BIP-44 Path | `m/44'/501'/0'/0'` |

### Capabilities
- ✅ Full SDK testing
- ✅ Advanced transaction signing
- ✅ Cross-chain bridge operations

---

## Apollo 👤

**Role:** Heavy Trader / Market Participant  
**Security Track:** Mnemonic (Consumer)

### Addresses
| Network | Address |
|---------|---------|
| BB | `bb_59a829316f3a9ecb32d768a155ec2e2c` |
| L2 | `L2_59a829316f3a9ecb32d768a155ec2e2c` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | `c2786b9bcce4298eae07b5d9fb5f97901ad5ab7269d57211e3ab15878cc954d1` |
| **Private Key** | `9a175706e189911a0470e75d6d3c61530880d7d219df8d5ced367e1134d9fb64` ⚠️ TEST ONLY |
| **24-Word Mnemonic** | `able mosquito intact tone organ sunset autumn hybrid tragic insect bundle image fetch maximum crazy blouse cupboard cry open airport goddess nerve near tag` |

### Security Parameters

**SSS Scheme:** 2-of-3 Shamir Secret Sharing over GF(256)

| Share | Description | Location |
|-------|-------------|----------|
| Share A | Password-bound share (client-side) | Client-side (password-derived) |
| Share B | L1 blockchain share (ZKP-gated) | L1 Blockchain |
| Share C | Vault-encrypted backup share | HashiCorp Vault |

| Parameter | Value |
|-----------|-------|
| Password | `apollo_secure_password_2026` ⚠️ TEST ONLY |
| Password Salt | `8d672c7c77e4179dd689e0745908fc59` |
| Key Derivation | Argon2id-64MB (3 iterations, parallelism 4) |
| BIP-44 Path | `m/44'/501'/0'/0'` |

### Capabilities
- ✅ High-frequency trading
- ✅ Large volume transactions
- ✅ Prediction market participation

---

## Dealer 🏛️

**Role:** Market Maker & Oracle Authority  
**Security Track:** FROST (Institutional)

### Addresses
| Network | Address |
|---------|---------|
| L1 | `L1_C3655C7AA0E5DD9C21DCE65EFE805F902B1C4D01` |
| L2 | `L2_C3655C7AA0E5DD9C21DCE65EFE805F902B1C4D01` |

### Cryptographic Material

| Field | Value |
|-------|-------|
| **Public Key** | `6a2944608156ffc470bdaea36018a3e9bef58db318dc4f8ce86cd9f3e9e690a7` |
| **Private Key** | `bf7c054ef5ae03ea4daba1e099bb0953b4640e946ed2b442a690e57759abfa96` ⚠️ TEST ONLY |

### Security Parameters

**FROST Protocol:** FROST-Ed25519

| Shard | Description | Location |
|-------|-------------|----------|
| Shard 1 | Device Shard | Local machine / Secure Enclave |
| Shard 2 | Guardian Shard | BlackBook L1 Network (OPAQUE-protected) |
| Shard 3 | Recovery Shard | Paper backup / Cold storage |

| Parameter | Value |
|-----------|-------|

### Capabilities
- ✅ Create/approve/reject markets
- ✅ Resolve markets with winning outcome
- ✅ Fund markets with liquidity
- ✅ Sign bridge operations

---

## Transaction Signing Guide

### Canonical Payload Format (V2 SDK)

For **transfers**:
```
canonical = "{from}|{to}|{amount}|{timestamp}|{nonce}"
payload_hash = SHA256(canonical).hex()
domain_prefix = "BLACKBOOK_L1/transfer"
message = "{domain_prefix}\n{payload_hash}\n{timestamp}\n{nonce}"
signature = Ed25519.sign(private_key, message)
```

For **burns**:
```
canonical = "{from}|{amount}|{timestamp}|{nonce}"
payload_hash = SHA256(canonical).hex()
domain_prefix = "BLACKBOOK_L1/admin/burn"
message = "{domain_prefix}\n{payload_hash}\n{timestamp}\n{nonce}"
signature = Ed25519.sign(private_key, message)
```

### Example: Alice sends 100 BB to Bob

```javascript
const crypto = require('crypto');
const nacl = require('tweetnacl');

// Alice's credentials
const alicePrivateKey = Buffer.from('5dba98f70ad9139256ac216101ca3438332d8a42c6ad468677a857596d0e7f40', 'hex');
const aliceAddress = 'bb_6b7665632e4d8284c9ff288b6cab2f94';
const bobAddress = 'bb_d8ed1c2f27ed27081bf11e58bb6eb160';

const timestamp = Math.floor(Date.now() / 1000);
const nonce = crypto.randomUUID();
const amount = 100.0;

// Step 1: Create canonical payload
const canonical = `${aliceAddress}|${bobAddress}|${amount}|${timestamp}|${nonce}`;
const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');

// Step 2: Create signing message
const domainPrefix = 'BLACKBOOK_L1/transfer';
const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;

// Step 3: Sign with Ed25519
const signature = nacl.sign.detached(
    Buffer.from(message),
    nacl.sign.keyPair.fromSeed(alicePrivateKey).secretKey
);

// Step 4: Build request
const request = {
    public_key: '3d6d1a0bc67f8fcf566fabe4e0d1fe500561becf1286c2a3f71086435917c3e1',
    payload_hash: payloadHash,
    payload_fields: {
        from: aliceAddress,
        to: bobAddress,
        amount: amount,
        timestamp: timestamp,
        nonce: nonce
    },
    operation_type: 'transfer',
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    request_path: '/transfer',
    signature: Buffer.from(signature).toString('hex')
};
```

---

## Test Scenarios

### 1. Fund All Accounts (Mint)
```bash
# Mint 10,000 BB to each account
curl -X POST http://localhost:8080/admin/mint \
  -H "Content-Type: application/json" \
  -d '{"to": "bb_6b7665632e4d8284c9ff288b6cab2f94", "amount": 10000}'
```

### 2. Transfer: Alice → Bob
```bash
# See signing example above
curl -X POST http://localhost:8080/transfer \
  -H "Content-Type: application/json" \
  -d '{...signed_request...}'
```

### 3. Burn Tokens (Requires Signature)
```bash
# Burns must be signed by the token owner
curl -X POST http://localhost:8080/admin/burn \
  -H "Content-Type: application/json" \
  -d '{...signed_burn_request...}'
```

---

## Security Warnings

⚠️ **NEVER use these wallets in production!**
- Private keys and mnemonics are exposed
- Passwords are documented in plaintext
- These are for development/testing ONLY

For production wallets:
- Use `POST /mnemonic/create` (mnemonics never returned)
- Use `POST /wallet/register/*` for FROST wallets
- Never log or store private keys

---

*Generated by BlackBook L1 Wallet Generator*
