# 🔴 BLACKBOOK L1 ATTACK SIMULATION SUITE

This folder contains malicious attack scripts designed to test the security of the BlackBook L1 blockchain against known exploits.

## ⚠️ WARNING
These scripts simulate **REAL ATTACKS** including:
- The 2016 Ethereum DAO hack (reentrancy)
- Replay attacks
- Double-spend attacks
- Race condition exploits

**DO NOT RUN AGAINST PRODUCTION SYSTEMS**

## Attack Vectors Tested

### 1. DAO Reentrancy Attack (`dao-reentrancy-attack.js`)
Simulates the $60M Ethereum DAO hack where an attacker exploited reentrancy to drain funds.

**Attack Pattern:**
```
1. Attacker calls withdraw()
2. Before balance update, attacker's callback re-enters withdraw()
3. Repeat step 2 multiple times
4. Drain all funds before balance is set to zero
```

### 2. Replay Attack (`replay-attack.js`)
Attempts to reuse a valid signed transaction multiple times to steal funds.

**Attack Pattern:**
```
1. Create legitimate signed transfer
2. Submit transaction (succeeds)
3. Re-submit EXACT same transaction (should fail)
4. Try variations (different timestamp, nonce tampering)
```

### 3. Race Condition Attack (`race-condition-attack.js`)
Exploits concurrent transaction processing to double-spend or create inconsistent state.

**Attack Pattern:**
```
1. Send multiple identical transactions concurrently
2. Attempt to spend same funds twice
3. Check if blockchain maintains consistency
```

### 4. Signature Tampering Attack (`signature-tampering-attack.js`)
Tries to manipulate signed transactions to redirect funds or increase amounts.

**Attack Pattern:**
```
1. Capture valid signed transaction
2. Tamper with amount/recipient while keeping signature
3. Attempt to submit tampered transaction
```

## Expected Results (Secure Blockchain)

All attacks should **FAIL** with the L1 blockchain rejecting malicious attempts:

- ✅ Reentrancy: Prevented by atomic ReDB transactions
- ✅ Replay: Prevented by nonce tracking
- ✅ Race conditions: Prevented by transaction sequencing
- ✅ Signature tampering: Prevented by cryptographic verification

## Running Attack Tests

```bash
# Run individual attacks
node dao-reentrancy-attack.js
node replay-attack.js
node race-condition-attack.js
node signature-tampering-attack.js

# Run all attacks
node run-all-attacks.js
```

## Success Criteria

Each attack script should:
1. ✅ Report "BLOCKCHAIN SECURE" if attack is prevented
2. ❌ Report "VULNERABILITY FOUND" if attack succeeds
3. 📊 Provide detailed attack attempt logs
4. 🔍 Verify no state inconsistencies after attack

## Historical Context: The DAO Hack

**Date:** June 17, 2016  
**Loss:** ~$60 million USD (3.6M ETH)  
**Cause:** Reentrancy vulnerability in Solidity smart contract

The attacker exploited the recursive calling pattern:
```solidity
function withdraw(uint amount) {
    if (balances[msg.sender] >= amount) {
        msg.sender.call.value(amount)();  // ← VULNERABLE
        balances[msg.sender] -= amount;   // ← Too late!
    }
}
```

Our L1 uses **Checks-Effects-Interactions** pattern with atomic ReDB transactions to prevent this.
