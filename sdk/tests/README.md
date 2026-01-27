# BlackBook L1 - Wallet & Security Test Suite

## Overview

This test suite validates the complete wallet creation, security, and SSS (Shamir's Secret Sharing) recovery system for BlackBook L1.

## Prerequisites

1. **L1 Server Running**: Start the server before running tests:
   ```bash
   cargo run
   ```

2. **Dependencies**: Install npm packages:
   ```bash
   npm install tweetnacl node-fetch
   ```

## Running Tests

### Run All Tests
```bash
# Node.js
node run-all-tests.js

# PowerShell
./run-all.ps1
```

### Quick Mode (Skip Lifecycle Test)
```bash
node run-all-tests.js quick
```

### Run Specific Test
```bash
node run-all-tests.js test-04
# or
node test-04-secure-transfer.js
```

## Test Suite

| # | Test | Description |
|---|------|-------------|
| 01 | Server Health | Validates L1 server health, stats, PoH status |
| 02 | Wallet Creation | Ed25519 keypair generation, SSS share creation |
| 03 | Wallet Funding | Admin mint, balance verification |
| 04 | Secure Transfer | V2 signed transfers, signature validation |
| 05 | Secure Burn | Signed burns, unauthorized burn prevention |
| 06 | SSS Recovery | 2-of-3 share recovery, all combinations |
| 07 | Wallet Security | PBKDF2, AES-256-GCM, auto-lock, key zeroing |
| 08 | Full Lifecycle | End-to-end user journey with password recovery |

## Security Features Tested

### Cryptographic Primitives
- **Ed25519**: Digital signatures for transactions
- **PBKDF2**: Password-based key derivation (100k iterations, SHA-512)
- **AES-256-GCM**: Authenticated encryption for seed storage
- **SSS (2-of-3)**: Shamir's Secret Sharing for recovery

### V2 Signing Protocol
- Domain separation: `BLACKBOOK_L{chain_id}{path}`
- Payload hash verification
- Timestamp and nonce for replay prevention
- Ed25519 signature validation

### Session Security
- Auto-lock timeout (10 min desktop, 60s mobile)
- Key zeroing on lock (memory cleared)
- Activity-based timeout refresh

## Test Output Example

```
╔═══════════════════════════════════════════════════════════════════════╗
║   BLACKBOOK L1 - WALLET & SECURITY TEST SUITE                         ║
╚═══════════════════════════════════════════════════════════════════════╝

✓ Server is running

═══════════════════════════════════════════════════════════════
  RUNNING: Wallet Creation & SSS Shares
═══════════════════════════════════════════════════════════════

  ✓ Wallet created
  ✓ SSS Shares generated (2-of-3)
  ✓ Seed recovered from shares 1 & 2
  ✓ Seed recovered from shares 2 & 3
  ✓ Single share cannot recover seed (security verified)

═══════════════════════════════════════════════════════════════
  TEST SUMMARY
═══════════════════════════════════════════════════════════════
  Passed: 8  |  Failed: 0  |  Time: 12.5s

╔═══════════════════════════════════════════════════════════════════════╗
║   ✨  ALL TESTS PASSED!  ✨                                           ║
╚═══════════════════════════════════════════════════════════════════════╝
```

## SSS Recovery Guide

The wallet uses 2-of-3 Shamir's Secret Sharing:

| Share | Storage | Usage |
|-------|---------|-------|
| 1 | Encrypted with password (Supabase) | Primary access |
| 2 | Recovery codes (user writes down) | Backup |
| 3 | Email backup (encrypted) | Emergency |

### Recovery Scenarios:
- **Forgot password?** → Use Recovery Codes + Email
- **Lost recovery codes?** → Use Password + Email
- **Lost email access?** → Use Password + Recovery Codes
- **Lost 2+ methods?** → ❌ Cannot recover (by design)

## Files

```
sdk/tests/
├── run-all-tests.js       # Main test runner
├── run-all.ps1            # PowerShell runner
├── test-01-server-health.js
├── test-02-wallet-creation.js
├── test-03-wallet-funding.js
├── test-04-secure-transfer.js
├── test-05-secure-burn.js
├── test-06-sss-recovery.js
├── test-07-wallet-security.js
├── test-08-full-lifecycle.js
└── README.md              # This file
```

## Troubleshooting

### Server Not Running
```
✗ Server not reachable at http://localhost:8080
  Start the server with: cargo run
```
**Solution**: Run `cargo run` in the project root.

### Missing Dependencies
```
Error: Cannot find module 'tweetnacl'
```
**Solution**: `npm install tweetnacl node-fetch`

### Test Failures
Run the specific failing test for detailed output:
```bash
node test-04-secure-transfer.js
```
