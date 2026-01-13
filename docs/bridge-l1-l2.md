# Bridge L1 → L2: Dealer Lock Transaction

## Transaction Summary

**Date:** January 11, 2026  
**Action:** Lock 5,000 $BC on L1 → Credit 5,000 $BB on L2  
**Status:** L1 Lock ✅ Complete | L2 Credit ⏳ Pending Verification

---

## What Happened on L1

### 1. Signed Request Sent to L1
```
POST http://localhost:8080/bridge/initiate
```

**Payload:**
```json
{
  "public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
  "wallet_address": "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
  "payload": "{\"amount\":5000,\"target_layer\":\"L2\"}",
  "timestamp": 1768194156,
  "nonce": "f61025a2-637c-4bb3-b908-72a42271b352",
  "chain_id": 1,
  "signature": "af36d4e1714ce6bf9983199c555be491af8436aaa191d4fe46d6ae1e91de032700fd1c1af540d65a205d7daa23bb52338835c5133d10f699865c1731dd7ede00"
}
```

### 2. L1 Response
```json
{
  "amount": 5000.0,
  "l2_balance": null,
  "l2_credited": false,
  "latency_ms": 310,
  "lock_id": "lock_1768194156_7_L1_A75E1",
  "message": "Tokens locked on L1. L2 credit pending."
}
```

### 3. L1 Balance Change (Verified)
| Account | Before | After | Change |
|---------|--------|-------|--------|
| Dealer L1 | 100,000 $BC | 95,000 $BC | -5,000 (LOCKED) |

---

## What L2 Should Have Received

### HTTP POST from L1 to L2
L1 should have sent this to L2:
```
POST http://localhost:1234/bridge/credit
```

**Expected Payload:**
```json
{
  "user_address": "L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
  "amount": 5000.0,
  "lock_id": "lock_1768194156_7_L1_A75E1",
  "l1_public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
  "l1_signature": "<signature_of_bridge_lock_message>",
  "l1_tx_hash": "lock_1768194156_7_L1_A75E1",
  "timestamp": 1768194156,
  "source": "L1_bridge"
}
```

### L2 Verification Requirements
L2 must verify before crediting:
1. ✅ `l1_signature` is valid for message: `BRIDGE_LOCK:L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D:5000:lock_1768194156_7_L1_A75E1`
2. ✅ `l1_public_key` matches known L1 node key
3. ✅ `lock_id` has not been processed before (prevent double-credit)
4. ✅ `amount` is positive

### Expected L2 State After Credit
| Account | L2 Balance ($BB) |
|---------|------------------|
| L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D | 5,000 $BB |

---

## L2 Endpoints to Check

### 1. Check Dealer L2 Balance
```bash
curl http://localhost:1234/balance/L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D
```
**Expected:** `{"balance": 5000.0, ...}`

### 2. Check Bridge Credit Logs
```bash
curl http://localhost:1234/bridge/credits
# or
curl http://localhost:1234/bridge/status/lock_1768194156_7_L1_A75E1
```

### 3. Check L2 Pending Credits
```bash
curl http://localhost:1234/bridge/pending
```

---

## L2 Implementation Requirements

### Required Endpoint: POST /bridge/credit
L2 must implement:
```javascript
// Pseudo-code for L2 /bridge/credit handler
app.post('/bridge/credit', async (req, res) => {
  const { user_address, amount, lock_id, l1_signature, l1_public_key, timestamp } = req.body;
  
  // 1. Verify L1 signature
  const message = `BRIDGE_LOCK:${user_address}:${amount}:${lock_id}`;
  if (!verifyEd25519(l1_public_key, message, l1_signature)) {
    return res.status(401).json({ error: "Invalid L1 signature" });
  }
  
  // 2. Check L1 public key is trusted
  const TRUSTED_L1_PUBKEY = "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a";
  if (l1_public_key !== TRUSTED_L1_PUBKEY) {
    return res.status(401).json({ error: "Unknown L1 node" });
  }
  
  // 3. Prevent double-credit
  if (await isLockIdProcessed(lock_id)) {
    return res.status(409).json({ error: "Lock already credited" });
  }
  
  // 4. Credit the user
  await creditBalance(user_address, amount);
  await markLockIdProcessed(lock_id);
  
  return res.json({
    success: true,
    user_address,
    amount,
    lock_id,
    new_balance: await getBalance(user_address)
  });
});
```

---

## Cryptographic Details

### Dealer Account
| Field | Value |
|-------|-------|
| L1 Address | `L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` |
| L2 Address | `L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` |
| Public Key | `07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a` |
| Private Key | 🔒 In `.env` (DEALER_PRIVATE_KEY) |

### Signature Format (L1 → L2 Proof)
```
Message: BRIDGE_LOCK:{l2_address}:{amount}:{lock_id}
Example: BRIDGE_LOCK:L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D:5000:lock_1768194156_7_L1_A75E1

Signature: Ed25519(DEALER_PRIVATE_KEY, message)
```

---

## Zero-Sum Invariant

**LAW OF THE BLOCKCHAIN:**
```
L1_available + L1_locked = TOTAL_SUPPLY
L1_locked = L2_total_supply (always)

Before Bridge:
  L1_available = 100,000 $BC
  L1_locked    = 0 $BC
  L2_supply    = 0 $BB

After Bridge (5000 $BC → $BB):
  L1_available = 95,000 $BC
  L1_locked    = 5,000 $BC  ← LOCKED, cannot be spent
  L2_supply    = 5,000 $BB  ← 1:1 backed by locked $BC

Invariant: L1_locked === L2_supply (ALWAYS)
```

---

## Next Steps

1. **Verify L2 received the credit** - Check `/balance/L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D`
2. **If L2 balance is 0**, check:
   - L2 logs for `/bridge/credit` request
   - L2 signature verification logic
   - L2 trusted public key configuration
3. **Test reverse bridge** (L2 → L1) after confirming credit works

---

## Files Involved

### L1 (This Repository)
- `src/routes_v2/bridge.rs` - Bridge initiate, lock logic, L2 HTTP call
- `src/storage/persistent.rs` - Lock storage in Sled

### L2 (External)
- `/bridge/credit` endpoint - Must verify L1 signature and credit user
- Trusted L1 public key config - Must match `07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a`
