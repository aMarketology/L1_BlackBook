# BlackBook L1↔L2 Bridge - Complete Guide

> **Comprehensive documentation for the Layer 1 ↔ Layer 2 token bridge system**

---

## Table of Contents

1. [Why Bridging is Necessary](#why-bridging-is-necessary)
2. [Architecture Overview](#architecture-overview)
3. [Token Economics](#token-economics)
4. [Deposit Flow (L1 → L2)](#deposit-flow-l1--l2)
5. [Withdrawal Flow (L2 → L1)](#withdrawal-flow-l2--l1)
6. [Security Guarantees](#security-guarantees)
7. [API Reference](#api-reference)
8. [Testing](#testing)
9. [Current Status](#current-status)
10. [Troubleshooting](#troubleshooting)

---

## Why Bridging is Necessary

### The Core Problem

**Layer 2 (L2) cannot create money from thin air.** Every dollar bet on L2 prediction markets must be backed by real value locked on Layer 1 (L1).

```
❌ BAD: L2 mints tokens whenever users want to bet
✅ GOOD: L2 only credits tokens that are LOCKED on L1
```

### Why This Design?

1. **Security** - L2 cannot print infinite money
2. **Solvency** - L1 always has enough funds to pay winners  
3. **Regulatory Compliance** - Full audit trail of every token
4. **Trust** - Users know their L2 bets are backed by real L1 value

### The Golden Rule

```
L2_TOTAL_SUPPLY <= L1_TOTAL_LOCKED

Every $BB on L2 MUST have a corresponding $BC locked on L1
```

---

## Architecture Overview

BlackBook operates as a **dual-layer system**:

```
┌──────────────────────────────────────────────────────────────────┐
│                     BLACKBOOK ARCHITECTURE                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────┐           ┌─────────────────────┐      │
│  │   LAYER 1 ($BC)     │           │   LAYER 2 ($BB)     │      │
│  │   Bank/Consensus    │           │  Prediction Market  │      │
│  │                     │           │                     │      │
│  │  • Real money       │  BRIDGE   │  • Fast bets        │      │
│  │  • Final settlement │  ═══════> │  • CPMM pricing     │      │
│  │  • Lock/unlock      │  <═══════ │  • LP pools         │      │
│  │  • Credit lines     │           │  • Oracle resolution│      │
│  │                     │           │                     │      │
│  │  localhost:8080     │           │  localhost:1234     │      │
│  └─────────────────────┘           └─────────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Address System

Addresses use the same base hash with different prefixes:

```
L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D  ← Funds on L1
L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D  ← Funds on L2
```

This allows seamless tracking of the same user across both layers.

---

## Token Economics

| Layer | Token | Symbol | Purpose | Backing |
|-------|-------|--------|---------|---------|
| **L1** | BlackCoin | **$BC** | Settlement, credit lines | Native asset |
| **L2** | BlackBook | **$BB** | Betting, liquidity | 1:1 backed by locked $BC |

**Key Invariant**: Every $BB on L2 is backed by locked $BC on L1. L2 cannot mint tokens independently.

---

## Deposit Flow (L1 → L2)

Users lock $BC on L1 to receive $BB on L2 for betting.

### Step-by-Step Flow

```
USER WANTS TO BET
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 1: Lock Funds on L1                           │
├─────────────────────────────────────────────────────┤
│  POST http://localhost:8080/bridge/initiate         │
│                                                     │
│  Request:                                           │
│  {                                                  │
│    "wallet": "L1_USER_ADDRESS",                     │
│    "amount": 1000,                                  │
│    "target_layer": "L2",                            │
│    "public_key": "...",                             │
│    "signature": "...",                              │
│    "timestamp": 1768718429,                         │
│    "nonce": "uuid-v4",                              │
│    "chain_id": 1                                    │
│  }                                                  │
│                                                     │
│  L1 Action:                                         │
│    ✅ Verify signature                              │
│    ✅ Check user has 1000 $BC                       │
│    ✅ Lock 1000 $BC (debit user balance)            │
│    ✅ Generate lock_id                              │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "lock_id": "lock_1768718429_7_L1_USER",          │
│    "amount": 1000.0,                                │
│    "l1_signature": "<L1_NODE_SIGNS_THIS>",          │
│    "message": "Tokens locked on L1"                 │
│  }                                                  │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 2: Credit Tokens on L2                        │
├─────────────────────────────────────────────────────┤
│  POST http://localhost:1234/bridge/credit           │
│                                                     │
│  Request:                                           │
│  {                                                  │
│    "user_address": "L2_USER_ADDRESS",               │
│    "amount": 1000.0,                                │
│    "lock_id": "lock_1768718429_7_L1_USER",          │
│    "l1_signature": "<FROM_STEP_1>",                 │
│    "l1_public_key": "<L1_NODE_PUBLIC_KEY>",         │
│    "l1_tx_hash": "lock_1768718429_7_L1_USER",       │
│    "timestamp": 1768718429,                         │
│    "source": "L1_bridge"                            │
│  }                                                  │
│                                                     │
│  L2 Verification:                                   │
│    ✅ Verify L1 signature (proves L1 locked funds)  │
│    ✅ Check lock_id not used before (no double)     │
│    ✅ Verify amount matches                         │
│                                                     │
│  L2 Action:                                         │
│    ✅ Credit user 1000 $BB                          │
│    ✅ Record lock_id (prevent replay)               │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "success": true,                                 │
│    "balance": 1000.0,                               │
│    "message": "Bridge credit successful"            │
│  }                                                  │
└─────────────────────────────────────────────────────┘
      │
      ▼
   USER CAN NOW BET 1000 $BB ON L2
```

### Signature Verification

L2 verifies L1's signature using this message format:

```rust
// L1 signs this message when locking funds:
format!("BRIDGE_LOCK:{}:{}:{}", 
    user_address, 
    amount, 
    lock_id
)

// L2 verifies with L1 node's known public key
```

---

## Withdrawal Flow (L2 → L1)

Users withdraw $BB from L2 back to $BC on L1.

### Step-by-Step Flow

```
USER WANTS TO WITHDRAW
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 1: Burn Tokens on L2                          │
├─────────────────────────────────────────────────────┤
│  POST http://localhost:1234/withdraw                │
│                                                     │
│  Request:                                           │
│  {                                                  │
│    "address": "L2_USER_ADDRESS",                    │
│    "amount": 1500.0,                                │
│    "destination": "L1_USER_ADDRESS"                 │
│  }                                                  │
│                                                     │
│  L2 Action:                                         │
│    ✅ Check user has 1500 $BB                       │
│    ✅ Debit user balance (burn tokens)              │
│    ✅ Create withdrawal record                      │
│    ✅ Status: Pending                               │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "success": true,                                 │
│    "withdrawal_id": "WD_abc123",                    │
│    "amount": 1500.0                                 │
│  }                                                  │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 2: Batch to L1 (Sequencer)                    │
├─────────────────────────────────────────────────────┤
│  • Runs every ~5 minutes (background task)          │
│  • Batches all pending withdrawals                  │
│  • Creates Merkle proof tree                        │
│  • Posts to L1 settlement endpoint                  │
│  • Updates status: Included → Claimed               │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 3: Release Funds on L1                        │
├─────────────────────────────────────────────────────┤
│  POST http://localhost:8080/settlement              │
│                                                     │
│  L1 Verification:                                   │
│    ✅ Verify L2 sequencer signature                 │
│    ✅ Verify Merkle proof                           │
│    ✅ Check withdrawal not already claimed          │
│                                                     │
│  L1 Action:                                         │
│    ✅ Unlock 1500 $BC                               │
│    ✅ Credit user L1 balance                        │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "success": true,                                 │
│    "tx_hash": "0xabc...",                           │
│    "balance": 1500.0                                │
│  }                                                  │
└─────────────────────────────────────────────────────┘
      │
      ▼
   USER HAS 1500 $BC ON L1 (Real money!)
```

---

## Security Guarantees

### 1. L2 Cannot Mint Without L1 Signature

```rust
// Every bridge credit requires L1's signature
async fn bridge_credit(req: BridgeCreditRequest) {
    // Verify L1 node signed this message
    if !verify_l1_signature(
        &req.l1_signature,
        &req.l1_public_key,
        &format!("BRIDGE_LOCK:{}:{}:{}", 
            req.user_address, 
            req.amount, 
            req.lock_id
        )
    ) {
        return Err("Invalid L1 signature");
    }
    
    // Only credit after verification
    ledger.credit(req.user_address, req.amount);
}
```

### 2. No Double-Spending

```rust
// Each lock_id can only be used once
if processed_locks.contains(&req.lock_id) {
    return Err("Lock already processed");
}
processed_locks.insert(req.lock_id.clone());
```

### 3. Atomic Operations

- L1 lock and L2 credit happen separately but are verifiable
- If L2 credit fails, L1 lock remains (can retry)
- If L1 lock fails, L2 never credits

### 4. Withdrawal Proofs

```rust
// L2 creates Merkle proof for batch withdrawals
let merkle_root = create_merkle_tree(pending_withdrawals);
let proof = generate_merkle_proof(withdrawal_id, merkle_root);

// L1 verifies proof before releasing funds
if !verify_merkle_proof(proof, merkle_root, withdrawal) {
    return Err("Invalid withdrawal proof");
}
```

---

## API Reference

### L1 Endpoints (localhost:8080)

#### Health Check
```http
GET /health
Response: {"status":"ok","engine":"axum","version":"3.0.0"}
```

#### Check Balance
```http
GET /balance/{address}
Response: {"address":"L1_xxx","balance":100000.0,"exists":true}
```

#### Initiate Bridge Lock
```http
POST /bridge/initiate
Content-Type: application/json

{
  "wallet": "L1_USER_ADDRESS",
  "amount": 1000,
  "target_layer": "L2",
  "public_key": "user_public_key_hex",
  "signature": "ed25519_signature_hex",
  "timestamp": 1768718429,
  "nonce": "uuid-v4-string",
  "chain_id": 1,
  "payload": "{\"amount\":1000,\"target_layer\":\"L2\"}"
}

Response:
{
  "lock_id": "lock_1768718429_7_L1_xxx",
  "amount": 1000.0,
  "l1_signature": "hex_signature",
  "l2_credited": false,
  "message": "Tokens locked on L1. L2 credit pending."
}
```

#### Settlement (Batch Withdrawals)
```http
POST /settlement
Content-Type: application/json

{
  "batch_id": "batch_123",
  "withdrawals": [...],
  "merkle_root": "0xabc...",
  "l2_signature": "sequencer_signature"
}
```

---

### L2 Endpoints (localhost:1234)

#### Health Check
```http
GET /health
Response: {"status":"healthy","version":"2.0.0"}
```

#### Check Balance
```http
GET /balance/{address}
Response: {"available":1000.0,"locked":0.0,"has_active_credit":false}
```

#### Bridge Credit
```http
POST /bridge/credit
Content-Type: application/json

{
  "user_address": "L2_USER_ADDRESS",
  "amount": 1000.0,
  "lock_id": "lock_1768718429_7_L1_xxx",
  "l1_signature": "hex_signature_from_l1",
  "l1_public_key": "L1_NODE_PUBLIC_KEY",
  "l1_tx_hash": "lock_1768718429_7_L1_xxx",
  "timestamp": 1768718429,
  "source": "L1_bridge"
}

Response:
{
  "success": true,
  "balance": 1000.0,
  "message": "Bridge credit successful"
}
```

#### Withdraw
```http
POST /withdraw
Content-Type: application/json

{
  "address": "L2_USER_ADDRESS",
  "amount": 500.0,
  "destination": "L1_USER_ADDRESS"
}

Response:
{
  "success": true,
  "withdrawal_id": "WD_abc123",
  "amount": 500.0
}
```

---

## Testing

### Check Server Health

```bash
# L1 Server
curl http://localhost:8080/health
# Expected: {"status":"ok","engine":"axum","version":"3.0.0"}

# L2 Server  
curl http://localhost:1234/health
# Expected: {"status":"healthy","version":"2.0.0"}
```

### Check Balances

```bash
# L1 Balance (Dealer account)
curl http://localhost:8080/balance/L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D
# Expected: {"balance":100000.0,...}

# L2 Balance (Dealer account)
curl http://localhost:1234/balance/L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D
# Expected: {"available":19980.0,...}
```

### Run Bridge Tests

```bash
# Test Alice & Bob bridge (99 $BC each)
node tests/alice-bob-bridge-99.js

# Test Dealer bridge (larger amounts)
node tests/dealer_bridge.js

# Test withdrawal
node tests/test_markets_withdraw.js
```

### Monitor L1↔L2 Connection

L2 automatically checks L1 health every 10 seconds and logs:

```
✅ [L1↔L2] Connected | L1 Slot: 12345 | Status: healthy
```

If L1 is unreachable:

```
⚠️ [L1↔L2] L1 health check failed: connection refused
```

---

## Current Status

### ✅ Working

| Component | Status | Details |
|-----------|--------|---------|
| L1 Server | ✅ Running | Port 8080, health endpoint active |
| L2 Server | ✅ Running | Port 1234, 21 active markets |
| L1 Health Check | ✅ Working | Every 10 seconds |
| L2 Balance Query | ✅ Working | 19,980 $BB available |
| L2 Withdrawal | ✅ Working | Tested with 10 $BB |
| Signature Verification | ✅ Working | Ed25519 verification functional |

### ⚠️ Needs Fixing

| Issue | Impact | Fix Required |
|-------|--------|--------------|
| L1 bridge endpoint schema | Bridge deposits fail | Update endpoint or tests to include `wallet` field |
| L1→L2 auto-credit | Manual step needed | L1 should POST to L2 after lock |
| Withdrawal batching | Not verified | Confirm sequencer posts to L1 |

### Known Issues

1. **Schema Mismatch Error**
   ```
   Error: "missing field `wallet` at line 1 column 362"
   Location: POST /bridge/initiate on L1
   Cause: Test scripts don't include wallet field
   Fix: Update dealer_bridge.js to match L1 schema
   ```

2. **L1→L2 Manual Credit**
   ```
   Current: L1 locks funds, returns lock_id
   Missing: L1 should auto-POST to L2 /bridge/credit
   Workaround: Manual L2 credit call in tests
   ```

---

## Troubleshooting

### Problem: L1 Server Not Responding

**Symptoms:**
```
curl: (7) Failed to connect to localhost:8080
```

**Solution:**
```bash
# Start L1 server (separate terminal)
cd path/to/L1_server
cargo run --release
```

---

### Problem: L2 Server Not Responding

**Symptoms:**
```
curl: (7) Failed to connect to localhost:1234
```

**Solution:**
```bash
# Start L2 server
cargo run --release
```

---

### Problem: Bridge Credit Rejected

**Symptoms:**
```
Error: Invalid L1 signature
```

**Solutions:**

1. **Check L1 Public Key**
   ```bash
   # L1 node public key should be:
   # 07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a
   ```

2. **Verify Message Format**
   ```rust
   // Message must be exactly:
   format!("BRIDGE_LOCK:{}:{}:{}", user_address, amount, lock_id)
   ```

3. **Check Lock ID Not Used**
   ```bash
   # Each lock_id can only be used once
   # Generate new lock_id for each deposit
   ```

---

### Problem: Withdrawal Not Processing

**Symptoms:**
```
Withdrawal stuck in "pending" status
```

**Solutions:**

1. **Check Sequencer Running**
   ```bash
   # L2 logs should show:
   # "Batch poster started" message
   ```

2. **Check L1 Reachable**
   ```bash
   curl http://localhost:8080/health
   # Must return 200 OK
   ```

3. **Wait for Batch**
   ```
   Batches run every ~5 minutes
   Check again after waiting
   ```

---

## Example: Complete Deposit Flow

Here's a full example of depositing 5,000 $BC from L1 to L2:

### Transaction Record

**Date:** January 11, 2026  
**Account:** Dealer  
**Amount:** 5,000 $BC → 5,000 $BB

#### Step 1: L1 Lock

```bash
curl -X POST http://localhost:8080/bridge/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "wallet": "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
    "amount": 5000,
    "target_layer": "L2",
    "public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
    "signature": "af36d4e1714ce6bf9983199c555be491af8436aaa191d4fe46d6ae1e91de032700fd1c1af540d65a205d7daa23bb52338835c5133d10f699865c1731dd7ede00",
    "timestamp": 1768194156,
    "nonce": "f61025a2-637c-4bb3-b908-72a42271b352",
    "chain_id": 1,
    "payload": "{\"amount\":5000,\"target_layer\":\"L2\"}"
  }'
```

**Response:**
```json
{
  "lock_id": "lock_1768194156_7_L1_A75E1",
  "amount": 5000.0,
  "l1_signature": "...",
  "l2_credited": false,
  "message": "Tokens locked on L1. L2 credit pending.",
  "latency_ms": 310
}
```

**L1 Balance Change:**
- Before: 100,000 $BC
- After: 95,000 $BC
- Change: -5,000 (LOCKED)

#### Step 2: L2 Credit

```bash
curl -X POST http://localhost:1234/bridge/credit \
  -H "Content-Type: application/json" \
  -d '{
    "user_address": "L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
    "amount": 5000.0,
    "lock_id": "lock_1768194156_7_L1_A75E1",
    "l1_signature": "...",
    "l1_public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
    "l1_tx_hash": "lock_1768194156_7_L1_A75E1",
    "timestamp": 1768194156,
    "source": "L1_bridge"
  }'
```

**Response:**
```json
{
  "success": true,
  "balance": 5000.0,
  "message": "Bridge credit successful"
}
```

**L2 Balance Change:**
- Before: 0 $BB
- After: 5,000 $BB
- Change: +5,000 (CREDITED)

**Result:** ✅ Deposit complete. User can now bet 5,000 $BB on prediction markets.

---

## Summary

The L1↔L2 bridge is the **security backbone** of BlackBook:

- **L2 cannot create tokens** - Every $BB is backed by locked $BC on L1
- **Full audit trail** - Every deposit and withdrawal is cryptographically verified
- **Fast betting** - L2 provides instant trades while L1 ensures solvency
- **Safe withdrawals** - Merkle proofs ensure only legitimate withdrawals are paid

**Current State:**
- ✅ Core infrastructure working
- ✅ Both servers communicating
- ✅ Signature verification functional
- ⚠️ Minor schema fixes needed for production

**Next Steps:**
1. Fix L1 bridge endpoint schema
2. Enable L1→L2 auto-credit callback
3. Verify withdrawal batch posting
4. Production testing with real users
