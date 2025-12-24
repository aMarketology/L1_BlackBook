# L1 Functionality Testing Guide

## Prerequisites

1. **Start the L1 server:**
   ```powershell
   cd "C:\Users\Allied Gaming\Documents\GitHub\L1_BlackBook"
   cargo run
   ```

2. **Install SDK dependencies** (if not already done):
   ```powershell
   cd sdk
   npm install
   ```

## Running the Tests

### Option 1: NPM Script (Recommended)
```powershell
cd sdk
npm run test:l1
```

### Option 2: Direct Execution
```powershell
cd sdk
node test-l1-functionality.js
```

### Option 3: Custom L1 URL
```powershell
$env:L1_URL="http://localhost:8080"
npm run test:l1
```

## What Gets Tested

The test suite validates all core L1 functionality:

### ✅ **Test 1: Server Health**
- Checks if L1 is running and healthy
- Verifies API accessibility

### ✅ **Test 2: Test Account Retrieval**
- Fetches Alice and Bob test accounts
- Validates account structure (keys, addresses, balances)

### ✅ **Test 3: Balance Queries**
- Tests public balance endpoint (no auth)
- Tests authenticated balance endpoint (with signature)
- Validates L1/L2 balance separation

### ✅ **Test 4: Signature Verification**
- Tests Ed25519 signature verification
- Validates domain separation (chain_id)
- Tests path binding (request_path)
- Confirms invalid signatures are rejected

### ✅ **Test 5: Transfer Alice → Bob**
- Creates signed transfer request
- Executes transfer on L1
- Validates balance changes
- Confirms transaction ID generation

### ✅ **Test 6: Credit Line Flow**
- Approves credit line (L2 integration)
- Validates signature-based approval
- Checks credit status endpoint
- Confirms L2-ready architecture

### ✅ **Test 7: Keypair Generation**
- Tests keypair generation endpoint
- Validates Ed25519 key format
- Checks address derivation

### ✅ **Test 8: Profile Endpoint**
- Tests authenticated profile retrieval
- Validates wallet info
- Checks transaction history

### ✅ **Test 9: Blockchain Stats**
- Queries blockchain statistics
- Checks PoH (Proof of History) status
- Validates continuous clock operation

## Expected Output

```
╔═══════════════════════════════════════════════════════════════╗
║      BLACKBOOK L1 FUNCTIONALITY TEST SUITE                    ║
║      Testing wallet, transfers, and L2 integration readiness  ║
╚═══════════════════════════════════════════════════════════════╝

📡 Target: http://localhost:8080

═══════════════════════════════════════════════════════════════
   TEST 1: Server Health Check
═══════════════════════════════════════════════════════════════

✅ PASS: Health endpoint returns 200
✅ PASS: Server reports healthy status
ℹ️  INFO: Server uptime: N/A

═══════════════════════════════════════════════════════════════
   TEST 2: Test Account Retrieval (Alice & Bob)
═══════════════════════════════════════════════════════════════

✅ PASS: Test accounts endpoint returns success
✅ PASS: Alice has public_key
✅ PASS: Alice has private_key
✅ PASS: Alice has address
✅ PASS: Bob has public_key
✅ PASS: Bob has private_key
✅ PASS: Bob has address
ℹ️  INFO: Alice address: L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD
ℹ️  INFO: Bob address: L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9
ℹ️  INFO: Alice L1 balance: 10000 BB
ℹ️  INFO: Bob L1 balance: 5000 BB

═══════════════════════════════════════════════════════════════
   TEST 5: Transfer from Alice to Bob
═══════════════════════════════════════════════════════════════

ℹ️  INFO: Before transfer:
ℹ️  INFO:   Alice: 10000 BB
ℹ️  INFO:   Bob: 5000 BB
✅ PASS: Transfer of 10 BB succeeds
ℹ️  INFO: After transfer:
ℹ️  INFO:   Alice: 9990 BB (-10)
ℹ️  INFO:   Bob: 5010 BB (+10)
✅ PASS: Alice balance decreased
✅ PASS: Bob balance increased
✅ PASS: Bob received correct amount

═══════════════════════════════════════════════════════════════
   TEST SUMMARY
═══════════════════════════════════════════════════════════════

Passed: 28
Failed: 0
Total:  28

🎉 ALL TESTS PASSED! L1 is ready for L2 integration.
```

## Troubleshooting

### Error: "Server not reachable"
**Solution:** Make sure L1 is running:
```powershell
cargo run
```

### Error: "fetch is not defined"
**Solution:** Update Node.js to v18+ or install node-fetch:
```powershell
npm install node-fetch
```

### Error: "Cannot find module 'tweetnacl'"
**Solution:** Install dependencies:
```powershell
npm install
```

### Port Already in Use
**Solution:** Change the port in cargo run or set L1_URL:
```powershell
$env:L1_URL="http://localhost:8081"
npm run test:l1
```

## Manual Testing (curl)

If you prefer quick manual checks:

```powershell
# Health check
curl http://localhost:8080/health

# Get test accounts
curl http://localhost:8080/auth/test-accounts

# Check Alice's balance
curl http://localhost:8080/balance/L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD

# Blockchain stats
curl http://localhost:8080/stats

# PoH status
curl http://localhost:8080/poh/status
```

## Security Features Tested

✅ **Ed25519 Signatures**: All authenticated requests use Ed25519 signatures  
✅ **Domain Separation**: Chain ID prevents L1/L2 replay attacks  
✅ **Path Binding**: Request path prevents cross-endpoint replay  
✅ **Nonce Deduplication**: Time-bucketed cache prevents replay attacks  
✅ **Timestamp Validation**: 5-minute expiry window for all requests

## L2 Integration Readiness

After all tests pass, the following are confirmed working:

- ✅ **Credit Line Approval**: L2 can request signed credit approvals
- ✅ **Signed Draws**: L2 forwards signed draw requests to L1
- ✅ **Signed Settlements**: L2 forwards signed settlements to L1
- ✅ **Signature Validation**: L1 validates all signatures (L2 does NOT)
- ✅ **Wallet Security**: All token movements require user signatures

## Next Steps

Once tests pass:

1. **Deploy L2 Server** (prediction market backbone)
2. **Integrate Credit Line SDK** (`CreditLineWallet` class)
3. **Test L1↔L2 Flow** (approve → draw → bet → settle)
4. **Deploy Frontend** (connect to both L1 and L2)

---

**Questions?** Check the main README or open an issue.
