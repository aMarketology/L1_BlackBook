# Domain-Separated Unified Identity System

## Overview

BlackBook Layer1 implements a **Hierarchical Deterministic (HD) Identity System** with **Domain Separation** to prevent replay attacks between Layer 1 (Bank) and Layer 2 (Gaming). This allows users to have **one private key** that controls assets on both layers while mathematically guaranteeing that a transaction signed for L1 cannot be replayed on L2, and vice versa.

---

## Architecture

### The Problem

Without domain separation, an attacker who intercepts a signed transaction could:
1. Capture a signature for "Withdraw 100 BB" on L1
2. Replay the same signature on L2 to steal gaming funds
3. Or vice versa - replay L2 betting signatures to drain L1 bank accounts

### The Solution: Mathematical Isolation

We prepend a **Chain ID** to every message before signing:
- **L1 Chain ID:** `0x01` (Bank/Vault)
- **L2 Chain ID:** `0x02` (Gaming/Casino)

```
Message to sign:
┌──────────┬────────────────────────────┐
│ Chain ID │ Actual Message             │
├──────────┼────────────────────────────┤
│  0x01    │ {"action":"withdraw",...}  │  ← L1 Signature
└──────────┴────────────────────────────┘

┌──────────┬────────────────────────────┐
│ Chain ID │ Actual Message             │
├──────────┼────────────────────────────┤
│  0x02    │ {"action":"bet",...}       │  ← L2 Signature
└──────────┴────────────────────────────┘

These produce COMPLETELY DIFFERENT signatures!
```

---

## Unified Address Format

Users have **one wallet address** derived from their public key, but it's prefixed differently for L1 and L2:

```rust
Ed25519 Public Key (32 bytes)
         │
         ▼
    SHA-256 Hash
         │
         ▼
   First 7 bytes
         │
         ▼
   14 Hex Characters
         │
         ├────────────────┬────────────────┐
         ▼                ▼                ▼
    L1 Address       L2 Address       Core ID
    L148F582A1BC8976 L248F582A1BC8976 48F582A1BC8976
```

**Example:**
- **Core Public Key:** `4013e5a935e9873a57879c471d5da838a0c9c762eea3937eb3cd34d35c97dd57`
- **L1 Address:** `L148F582A1BC8976` (Bank/Vault)
- **L2 Address:** `L248F582A1BC8976` (Gaming/Casino)

---

## Implementation

### 1. Client-Side Signing (SDK)

```rust
use layer1::integration::unified_auth::{
    sign_with_domain_separation,
    create_signed_request,
    CHAIN_ID_L1,
    CHAIN_ID_L2,
};

// Sign for L1 (Bank)
let l1_signature = sign_with_domain_separation(
    private_key,
    message,
    CHAIN_ID_L1  // 0x01
)?;

// Sign for L2 (Gaming)
let l2_signature = sign_with_domain_separation(
    private_key,
    message,
    CHAIN_ID_L2  // 0x02
)?;

// These signatures are DIFFERENT even with same key + message!
```

### 2. Server-Side Verification (L1 Validator)

```rust
// L1 Node: HARDCODED to expect 0x01
impl SignedRequest {
    pub fn verify(&self) -> Result<String, String> {
        // 1. Validate chain_id
        if self.chain_id != CHAIN_ID_L1 {
            return Err("Wrong chain".into());
        }
        
        // 2. Reconstruct message with chain_id
        let mut message = Vec::new();
        message.push(CHAIN_ID_L1);  // <--- CRITICAL
        message.extend_from_slice(payload.as_bytes());
        
        // 3. Verify signature
        verifying_key.verify(&message, &signature)?;
        
        Ok(address)
    }
}
```

### 3. Server-Side Verification (L2 Engine)

```rust
// L2 Node: HARDCODED to expect 0x02
impl SignedRequest {
    pub fn verify(&self) -> Result<String, String> {
        // 1. Validate chain_id
        if self.chain_id != CHAIN_ID_L2 {
            return Err("Wrong chain".into());
        }
        
        // 2. Reconstruct message with chain_id
        let mut message = Vec::new();
        message.push(CHAIN_ID_L2);  // <--- CRITICAL
        message.extend_from_slice(payload.as_bytes());
        
        // 3. Verify signature
        verifying_key.verify(&message, &signature)?;
        
        Ok(address)
    }
}
```

---

## Attack Scenarios & Prevention

### Scenario 1: L1 → L2 Replay Attack

**Attack:**
1. Hacker intercepts L1 transaction: "Withdraw 1000 BB"
2. Hacker captures signature `Sig_A` (signed with `[0x01][withdraw 1000]`)
3. Hacker sends same signature to L2 node to drain gaming funds

**Prevention:**
```
L2 Node receives: chain_id=0x02, signature=Sig_A
L2 Node reconstructs: [0x02][withdraw 1000]
L2 Node verifies: Sig_A against [0x02][...]

Result: ❌ REJECTED
Reason: Sig_A was for [0x01][...], not [0x02][...]
```

### Scenario 2: L2 → L1 Replay Attack

**Attack:**
1. User places bet on L2: "Bet 500 BB on BTC"
2. Hacker captures signature `Sig_B` (signed with `[0x02][bet 500]`)
3. Hacker sends same signature to L1 node to withdraw from bank

**Prevention:**
```
L1 Node receives: chain_id=0x01, signature=Sig_B
L1 Node reconstructs: [0x01][bet 500]
L1 Node verifies: Sig_B against [0x01][...]

Result: ❌ REJECTED
Reason: Sig_B was for [0x02][...], not [0x01][...]
```

---

## Complete Transaction Lifecycle

### Example: User Bets 100 BB on L2

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User Action (Frontend)                                  │
└─────────────────────────────────────────────────────────────────┘
User clicks "Bet 100 BB on BTC > $100K"

┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: SDK Signs for L2                                        │
└─────────────────────────────────────────────────────────────────┘
Payload: {"action":"bet","amount":100,"market":"BTC_100K"}
Message: [0x02] + payload + timestamp + nonce
Signature: sign(private_key, message) → Sig_L2

┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Send to L2 Node                                         │
└─────────────────────────────────────────────────────────────────┘
POST /api/v2/markets/bet
{
  "public_key": "4013e5...",
  "payload": "{...}",
  "timestamp": 1735000000,
  "nonce": "uuid-v4",
  "chain_id": 2,  ← L2
  "signature": "Sig_L2"
}

┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: L2 Node Verifies                                        │
└─────────────────────────────────────────────────────────────────┘
1. Check chain_id == 0x02 ✓
2. Reconstruct: [0x02] + payload + timestamp + nonce
3. Verify: signature matches ✓
4. Execute bet ✓

┌─────────────────────────────────────────────────────────────────┐
│ ATTACK ATTEMPT: Hacker Tries to Replay on L1                    │
└─────────────────────────────────────────────────────────────────┘
POST /api/v2/wallet/transfer (L1 endpoint)
{
  "public_key": "4013e5...",
  "payload": "{...}",  ← Same payload!
  "timestamp": 1735000000,
  "nonce": "uuid-v4",
  "chain_id": 1,  ← Changed to L1!
  "signature": "Sig_L2"  ← Reusing L2 signature!
}

┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: L1 Node REJECTS                                         │
└─────────────────────────────────────────────────────────────────┘
1. Check chain_id == 0x01 ✓
2. Reconstruct: [0x01] + payload + timestamp + nonce  ← Different!
3. Verify: signature matches? ✗
   Expected: Sig for [0x01][...]
   Got: Sig_L2 (for [0x02][...])
4. REJECT ❌

Result: Hacker gets nothing, user's L1 funds are safe.
```

---

## Code Locations

| Component | File | Purpose |
|-----------|------|---------|
| Constants | `src/integration/unified_auth.rs` | `CHAIN_ID_L1`, `CHAIN_ID_L2` |
| Signing | `src/integration/unified_auth.rs` | `sign_with_domain_separation()` |
| Request Creation | `src/integration/unified_auth.rs` | `create_signed_request()` |
| Verification | `src/integration/unified_auth.rs` | `SignedRequest::verify()` |
| Settlement Protocol | `proto/settlement.proto` | `chain_id` field in messages |
| Tests | `tests/domain_separation_tests.rs` | Replay attack prevention tests |

---

## Migration Guide

### For Existing Clients

1. **Update SDK:** Install latest version with domain separation support
2. **Add chain_id:** Include `chain_id: 1` (L1) or `chain_id: 2` (L2) in requests
3. **Update Signing:** Use `create_signed_request()` instead of manual signing
4. **Backward Compatibility:** Old requests without `chain_id` default to L1

### For Existing Servers

1. **Update Dependencies:** Rebuild with latest `layer1` crate
2. **No Breaking Changes:** `SignedRequest` defaults `chain_id = 0x01` for backward compatibility
3. **Gradual Rollout:** Old signatures (no domain separation) still work temporarily
4. **Deprecation:** After 30 days, enforce `chain_id` validation

---

## Security Properties

✅ **Mathematically Guaranteed:**
- L1 signatures cannot be verified on L2
- L2 signatures cannot be verified on L1
- Same key + same message = different signatures per chain

✅ **No Trusted Third Party:**
- Domain separation enforced by cryptography
- No centralized authority needed
- Works even if all nodes are malicious

✅ **Industry Standard:**
- Used by Ethereum (EIP-155), Cosmos, Polkadot, etc.
- Proven secure in production for years
- Audited by multiple security firms

---

## Testing

Run domain separation tests:
```bash
cargo test --test domain_separation_tests
```

**Test Coverage:**
- ✅ L1 → L2 replay attack prevention
- ✅ L2 → L1 replay attack prevention
- ✅ Same key generates different signatures per chain
- ✅ Invalid chain IDs rejected
- ✅ Legitimate multi-chain usage works
- ✅ Chain ID cryptographically embedded in signatures

---

## FAQ

**Q: Can I use the same private key for L1 and L2?**
A: Yes! That's the whole point. One key controls both layers securely.

**Q: What if I accidentally sign with the wrong chain_id?**
A: The transaction will be rejected. E.g., if you sign for L1 but send to L2, verification fails.

**Q: Can I change the chain_id after signing?**
A: No. The chain_id is cryptographically bound to the signature. Changing it invalidates the signature.

**Q: What about cross-chain operations (e.g., bridging)?**
A: Bridge operations are L1 operations (they lock L1 funds), so use `CHAIN_ID_L1`.

**Q: Is this vulnerable to any attacks?**
A: Not known attacks. This is the same method used by billion-dollar blockchains like Ethereum.

---

## References

- **EIP-155:** Ethereum's Simple Replay Attack Protection
- **Cosmos SDK:** IBC Channel Identifiers
- **Polkadot:** Parachain Domain Separation
- **Ed25519:** RFC 8032 - Edwards-Curve Digital Signature Algorithm
- **Domain Separation:** NIST SP 800-185 - SHA-3 Derived Functions
