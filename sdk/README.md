# BlackBook L1 Testing SDK

Comprehensive testing SDK for the BlackBook L1 blockchain. Tests both REST and gRPC endpoints using real test accounts.

## Test Accounts

All test accounts are pre-funded and ready to use:

| Account | Address | Initial Balance | Purpose |
|---------|---------|-----------------|---------|
| Alice | `L1_ALICE000000001` | 10,000 BB | Test bettor |
| Bob | `L1_BOB0000000001` | 5,000 BB | Test bettor |
| Dealer | `L1_DEALER00000001` | 100,000 BB | House bankroll |

## Installation

```bash
cd sdk
npm install
```

## Usage

### Run Full Test Suite (REST + gRPC)

```bash
npm test
```

This runs 8 comprehensive tests:
1. ✅ Health check (REST)
2. ✅ Account balances (REST)
3. ✅ Balance checks (gRPC)
4. ✅ Simple transfer Alice→Bob (gRPC)
5. ✅ Batch settlement (gRPC)
6. ✅ Dealer model simulation (gRPC)
7. ✅ Stress test: 100 rapid transfers (gRPC)
8. ✅ Final balance report

### Prerequisites

**L1 Server must be running:**
```bash
cargo run
```

The server should show:
- 🌐 REST API on http://0.0.0.0:8080
- 🌐 gRPC server on 0.0.0.0:50051

## Test Coverage

### REST Endpoints Tested
- `GET /health` - Health check
- `GET /stats` - Blockchain statistics
- `GET /balance/:address` - Query balance

### gRPC Methods Tested
- `CheckBalance(address)` - Query account balance
- `ExecuteSettlement(from, to, amount)` - Single transfer
- `BatchSettlement(settlements[])` - Bulk transfers

## Example: Using the SDK in Your Code

```javascript
const { ALICE, BOB, DEALER, grpcExecuteSettlement, grpcCheckBalance } = require('./comprehensive-test-suite');

// Check Alice's balance
const balance = await grpcCheckBalance(ALICE.address);
console.log(`Alice has ${balance.available_balance} BB available`);

// Transfer 100 BB from Alice to Bob
const result = await grpcExecuteSettlement(
    ALICE.address,
    BOB.address,
    100,
    'my_market_001'
);
console.log(`Transfer complete! TX: ${result.transaction_id}`);
```

## Test Scenarios

### Simple Transfer
Alice sends 100 BB to Bob via gRPC settlement.

### Batch Settlement
Executes 3 simultaneous transfers in one block:
1. Alice → Dealer: 50 BB
2. Bob → Dealer: 30 BB
3. Dealer → Alice: 20 BB

### Dealer Model (Betting)
Simulates a betting round:
1. Alice bets 100 BB (loses)
2. Bob bets 50 BB (wins 100 BB)
3. Net: Alice -100, Bob +50, Dealer +50

### Stress Test
Executes 100 transfers as fast as possible to measure throughput (TPS).

## Expected Output

```
🚀 BLACKBOOK L1 COMPREHENSIVE TEST SUITE
   Testing REST + gRPC endpoints with real accounts

✅ gRPC client connected to localhost:50051

════════════════════════════════════════════════════════════════════════════════
  TEST 1: Health Check
════════════════════════════════════════════════════════════════════════════════
✅ REST /health: {"status":"ok","timestamp":1703087123}
✅ REST /stats: 42 blocks, 156 txs

════════════════════════════════════════════════════════════════════════════════
  TEST 8: Final Balance Report
════════════════════════════════════════════════════════════════════════════════

📊 FINAL BALANCES:
┌─────────────────────┬──────────────┬──────────────┬──────────────┐
│ Account             │ Total        │ Available    │ Locked       │
├─────────────────────┼──────────────┼──────────────┼──────────────┤
│ Alice (L1_ALICE...) │ 9850         │ 9850         │ 0            │
│ Bob (L1_BOB...)     │ 5050         │ 5050         │ 0            │
│ Dealer (L1_DEALER)  │ 100100       │ 100100       │ 0            │
└─────────────────────┴──────────────┴──────────────┴──────────────┘

════════════════════════════════════════════════════════════════════════════════
  TEST SUMMARY
════════════════════════════════════════════════════════════════════════════════

  Total tests: 8
  ✅ Passed: 8
  ❌ Failed: 0
  Success rate: 100.0%

🎉 ALL TESTS PASSED! The L1 blockchain is fully functional.
```

## Troubleshooting

### "Failed to initialize gRPC client"
- Make sure L1 server is running: `cargo run`
- Check that gRPC is on port 50051: Look for "🌐 [L1 gRPC] Starting on 0.0.0.0:50051"

### "Connection refused on port 8080"
- L1 REST server not running
- Check firewall settings

### "Insufficient balance" errors
- Server may have restarted and lost state
- Re-mint tokens: `curl -X POST http://localhost:8080/admin/mint -d '{"address":"L1_ALICE000000001","amount":10000}'`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  SDK Test Suite (Node.js)                                   │
│  comprehensive-test-suite.js                                │
└───────────────────┬─────────────────────┬───────────────────┘
                    │                     │
         REST (JSON/HTTP)          gRPC (Protocol Buffers)
                    │                     │
         Port 8080  │                     │  Port 50051
                    ▼                     ▼
         ┌──────────────────────────────────────────┐
         │  L1 Blockchain (Rust)                    │
         │  - Warp (REST)                           │
         │  - Tonic (gRPC)                          │
         │  - EnhancedBlockchain                    │
         └──────────────────────────────────────────┘
```

## License

MIT
