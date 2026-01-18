# BlackBook L1 ↔ L2 Integration Tests

Comprehensive test suite validating L1 and L2 server functionality with isolated, focused test scenarios.

## Test Overview

Each test file focuses on a specific feature area for clear diagnostics:

1. **test-01-l1-health.js** - L1 server health, stats, and PoH status
2. **test-02-l1-balances.js** - L1 balance queries for known/unknown accounts
3. **test-03-l2-health.js** - L2 server health, market count, L1 connection
4. **test-04-l2-balances.js** - L2 balance queries across test accounts
5. **test-05-l1-transfer.js** - L1 transfer validation (requires Ed25519 signatures)
6. **test-06-bridge-initiate.js** - L1→L2 bridge lock initiation and status tracking
7. **test-07-l2-markets.js** - L2 market listing, details, prices, CPMM pool state
8. **test-08-credit-line.js** - Credit session endpoints and validation

## Prerequisites

- **L1 Server**: Running on `http://localhost:8080`
- **L2 Server**: Running on `http://localhost:1234`
- **Node.js**: v18+ with ES modules support

## Running Tests

### Individual Tests (Recommended)

Run one test at a time for detailed output:

```powershell
cd sdk/tests

node test-01-l1-health.js
node test-02-l1-balances.js
node test-03-l2-health.js
node test-04-l2-balances.js
node test-05-l1-transfer.js
node test-06-bridge-initiate.js
node test-07-l2-markets.js
node test-08-credit-line.js
```

### All Tests (PowerShell)

```powershell
cd sdk/tests
.\run-all.ps1
```

### Quick Check

```powershell
# Check if servers are running
Invoke-WebRequest -Uri "http://localhost:8080/health"  # L1
Invoke-WebRequest -Uri "http://localhost:1234/health"  # L2
```

## Test Accounts

The tests use these predefined accounts:

- **Alice**: `L1_52882D768C0F3E7932AAD1813CF8B19058D507A8` / `L2_52882D768C0F3E7932AAD1813CF8B19058D507A8`
- **Bob**: `L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433` / `L2_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433`
- **Dealer**: `L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` / `L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D`

## Expected Results

All tests should pass when both L1 and L2 servers are running correctly:

```
📊 TEST 01 SUMMARY
   ✅ Passed: 3
   ❌ Failed: 0

📊 TEST 02 SUMMARY
   ✅ Passed: 4
   ❌ Failed: 0

... (and so on for all 8 tests)
```

## Test Details

### Test 01: L1 Health (3 subtests)
- Health endpoint returns `{status: "ok", engine: "axum", storage: "redb"}`
- Stats endpoint returns block height and account count
- PoH status shows current slot and tick count

### Test 02: L1 Balances (4 subtests)
- Alice, Bob, Dealer balance queries
- Unknown address returns 0 balance

### Test 03: L2 Health (4 subtests)
- Health endpoint returns market count and L2 supply
- L1 connection status (configured: true)
- Markets endpoint lists active markets
- Balances endpoint returns account list

### Test 04: L2 Balances (4 subtests)
- Alice, Bob, Dealer L2 balance queries
- Balance format: `{available, locked, total}`

### Test 05: L1 Transfer (5 subtests)
- Initial balance retrieval
- Transfer endpoint validation (requires Ed25519 signature)
- Balance integrity after invalid transfer
- Debug endpoint security check
- Schema validation for malformed requests

### Test 06: Bridge Initiate (6 subtests)
- Bridge stats (total locks, pending amount)
- Pending bridges for Alice
- Initiate bridge lock (creates lock_id)
- Lock status tracking
- Pending count increment
- L2 balance check post-bridge

### Test 07: L2 Markets (5 subtests)
- List all active markets
- Get market details (`/market/{id}`)
- CPMM prices endpoint (`/cpmm/prices/{id}`)
- Market status breakdown (active/frozen/resolved)
- CPMM pool state (reserves, k constant, liquidity)

### Test 08: Credit Line (5 subtests)
- Credit balance endpoint validation
- Credit status for wallet
- Credit open endpoint schema validation
- Credit settle endpoint validation
- List credit sessions endpoint

## Troubleshooting

### Test Failures

**L1 connection refused**
```
Check if L1 server is running: cargo run
```

**L2 connection refused**
```
Check if L2 server is running on port 1234
```

**Signature verification failures**
```
Expected for Test 05 and Test 08 - L1 requires real Ed25519 signatures
These tests validate that endpoints correctly reject unsigned requests
```

### Common Issues

1. **Servers not running**: Start both L1 and L2 before running tests
2. **Port conflicts**: Ensure 8080 (L1) and 1234 (L2) are available
3. **Test account balances**: Some tests assume Alice/Bob/Dealer exist with non-zero balances

## Integration with SDK

These tests validate the endpoints used by:
- `unified-dealer-sdk.js`
- `credit-prediction-actions-sdk.js`
- `blackbook-wallet-sdk.js`

If a test fails, the corresponding SDK method may also fail.

## Next Steps

After all tests pass:
1. Test signed transfers using the SDK with real keypairs
2. Test full bridge flow (L1 lock → L2 credit)
3. Test market creation and betting with credit sessions
4. Implement rate limiting and nonce enforcement
