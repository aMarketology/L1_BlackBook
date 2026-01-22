# BlackBook L1 - Production Test Suite

## Overview

Comprehensive test suite for the BlackBook Layer 1 blockchain. These tests ensure production readiness by covering:

- ✅ Core wallet operations
- ✅ Token transfers
- ✅ Balance accuracy  
- ✅ Transaction history
- ✅ L2 bridge (lock/settlement)
- ✅ Signature validation
- ✅ Security (DAO-style attack prevention)
- ✅ Fuzz testing
- ✅ Rate limiting & DoS prevention
- ✅ Consensus validation

## Quick Start

```bash
cd tests/js
npm install
npm test
```

## Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| `wallet` | 01-02 | Wallet generation, login, vault decryption |
| `transfer` | 03-04 | Send/receive tokens |
| `balance` | 05 | Balance accuracy & total supply |
| `ledger` | 06 | Transaction history |
| `bridge` | 07-08 | L2 session lock & settlement |
| `security` | 09-13, 16, 20 | Signatures, double-spend, reentrancy, invariants, overflow, keys |
| `system` | 14-15 | Health checks, persistence |
| `fuzz` | 17 | Random/malformed input testing |
| `performance` | 18 | Rate limiting, DoS prevention |
| `consensus` | 19 | Block validation, ordering |

## Test Files

### Core Functionality (Tests 01-08)

| File | Description |
|------|-------------|
| `01-wallet-generate.test.js` | Ed25519 keypair generation, address derivation |
| `02-wallet-login.test.js` | Seed import, encrypted vault decryption |
| `03-send-tokens.test.js` | V2 signed transfers |
| `04-receive-tokens.test.js` | New account creation, receive verification |
| `05-balance-accuracy.test.js` | Balance consistency, total supply tracking |
| `06-transaction-history.test.js` | History endpoint, pagination |
| `07-l2-session-lock.test.js` | Token locking for L2 sessions |
| `08-l2-settlement.test.js` | Win/loss/break-even settlement scenarios |

### Security (Tests 09-13, 16, 20)

| File | Description |
|------|-------------|
| `09-signature-validation.test.js` | Tampered payload detection, wrong key rejection |
| `10-double-spend-prevention.test.js` | Concurrent attack prevention |
| `11-invalid-inputs.test.js` | SQL injection, XSS, malformed data |
| `12-reentrancy-prevention.test.js` | **DAO-style attack prevention** |
| `13-balance-invariants.test.js` | **Total supply = sum of balances** |
| `16-overflow-underflow.test.js` | Numeric overflow/underflow attacks |
| `20-wallet-key-security.test.js` | Key derivation, wallet isolation |

### System & Performance (Tests 14-15, 17-19)

| File | Description |
|------|-------------|
| `14-server-health.test.js` | Health endpoint checks |
| `15-persistence.test.js` | Data durability after restart |
| `17-fuzz-testing.test.js` | Random/malformed data stress test |
| `18-rate-limiting-dos.test.js` | DoS attack prevention |
| `19-consensus-validation.test.js` | Block ordering, finality |

## Running Specific Tests

```bash
# Run all tests
npm test

# Quick smoke tests (critical only)
npm run test:quick

# By category
npm run test:security
npm run test:wallet
npm run test:bridge
npm run test:fuzz

# Individual tests
npm run test:12  # Reentrancy prevention
npm run test:13  # Balance invariants
npm run test:17  # Fuzz testing
```

## Test Accounts

| Account | Address | Purpose |
|---------|---------|---------|
| Alice | `L1_52882D768C0F3E7932AAD1813CF8B19058D507A8` | Primary test sender |
| Bob | `L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433` | Primary test receiver |
| Mac | `L1_94B3C863E068096596CE80F04C2233B72AE11790` | Vault-encrypted wallet |
| Dealer | `L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` | L2 game dealer |

## Security Tests Explained

### DAO Attack Prevention (Test 12)

The DAO hack exploited reentrancy - calling back into a contract before state was updated.

Our tests verify:
1. **Rapid-fire withdrawals** - Multiple concurrent withdrawal attempts
2. **Interleaved transactions** - Race conditions between accounts
3. **State consistency** - Partial failure doesn't corrupt state
4. **L2 lock reentrancy** - Session lock can't be exploited

### Balance Invariants (Test 13)

Core accounting equation: **Total Supply = Sum of All Balances**

Tests verify:
1. Total supply is never negative
2. No individual balance is negative
3. Known accounts sum ≤ total supply
4. Transfer is zero-sum (sender - receiver = 0)
5. L2 lock is zero-sum (locked + available = total)
6. Settlement preserves total supply
7. Invariants hold under stress (20 rapid transfers)

### Overflow/Underflow (Test 16)

Tests for numeric attacks:
- `MAX_SAFE_INTEGER` transfers
- `Infinity` / `-Infinity`
- `NaN` values
- Underflow (balance - more than balance)
- Scientific notation (`1e308`)
- Floating point precision

### Fuzz Testing (Test 17)

Throws random/malformed data at the system:
- 100 random transfer payloads
- 50 random balance queries
- Malformed JSON (incomplete, prototype pollution)
- Path traversal attempts
- Unicode/encoding attacks
- Binary data in JSON fields

## Environment Variables

```bash
L1_URL=http://localhost:3000  # L1 server URL
VERBOSE=true                  # Extra logging
```

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Run L1 Tests
  run: |
    cd tests/js
    npm install
    npm test
```

## Adding New Tests

1. Create `XX-test-name.test.js`
2. Export `run()` function returning `TestResults`
3. Add to `TEST_FILES` in `test-runner.js`
4. Add npm script in `package.json`

```javascript
import { TestResults, TEST_ACCOUNTS, httpGet, httpPost } from './test-runner.js';

export async function run() {
  const results = new TestResults();
  
  // Your tests here
  results.pass('Test name');
  // results.fail('Test name', error);
  // results.skip('Test name', 'reason');
  
  return results;
}
```

## Known Limitations

- Tests require running L1 server at `L1_URL`
- Some tests modify real balances (use test accounts only)
- Fuzz tests may be slow (~30 seconds)
- Rate limiting tests require server support
