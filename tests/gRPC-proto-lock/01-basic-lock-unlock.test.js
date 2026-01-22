/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 01: Basic Lock/Unlock Token Flow
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This test validates the basic happy path for token locking/unlocking:
 * 1. Check initial L1 balance
 * 2. Lock tokens for L2 session (via gRPC/HTTP)
 * 3. Verify tokens are locked (unavailable for transfers)
 * 4. Settle session with PNL
 * 5. Verify tokens are released and balance updated correctly
 * 
 * PROTOCOL: REST HTTP (simulating gRPC protocol buffer messages)
 */

import {
  TestResults,
  TEST_ACCOUNTS,
  getBalance,
  lockTokens,
  settleSession,
  generateSessionId,
} from './test-helpers.js';

console.log('\n╔═══════════════════════════════════════════════════════════════╗');
console.log('║  TEST 01: BASIC LOCK/UNLOCK TOKEN FLOW                       ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

async function run() {
  const results = new TestResults();
  const ALICE = TEST_ACCOUNTS.ALICE;
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 1: Check initial balance (available + locked)
  // ═══════════════════════════════════════════════════════════════════════
  let initialBalance;
  try {
    initialBalance = await getBalance(ALICE.address);
    console.log(`   Initial Balance:`);
    console.log(`   • Available: ${initialBalance.available.toFixed(2)} BB`);
    console.log(`   • Locked:    ${initialBalance.locked.toFixed(2)} BB`);
    console.log(`   • Total:     ${initialBalance.total.toFixed(2)} BB\n`);
    
    if (initialBalance.available > 0) {
      results.pass('Query L1 balance via HTTP');
    } else {
      results.skip('Query L1 balance', 'Insufficient balance');
      return results;
    }
  } catch (err) {
    results.fail('Query L1 balance', err);
    return results;
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 2: Lock tokens for L2 session
  // ═══════════════════════════════════════════════════════════════════════
  const lockAmount = Math.min(10, initialBalance.available);
  const sessionId = generateSessionId();
  
  console.log(`🔒 Locking ${lockAmount} BB for L2 session...`);
  console.log(`   Session ID: ${sessionId}\n`);
  
  let lockResult;
  try {
    lockResult = await lockTokens(ALICE.address, lockAmount, sessionId);
    
    if (lockResult.success) {
      results.pass(`Lock ${lockAmount} BB for L2 session`);
    } else {
      results.fail('Lock tokens', `Lock failed: ${JSON.stringify(lockResult.response)}`);
      return results;
    }
  } catch (err) {
    results.fail('Lock tokens', err);
    return results;
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 3: Verify tokens are locked (available balance decreased)
  // ═══════════════════════════════════════════════════════════════════════
  try {
    const balanceAfterLock = await getBalance(ALICE.address);
    
    console.log(`   Balance After Lock:`);
    console.log(`   • Available: ${balanceAfterLock.available.toFixed(2)} BB`);
    console.log(`   • Locked:    ${balanceAfterLock.locked.toFixed(2)} BB\n`);
    
    const expectedAvailable = initialBalance.available - lockAmount;
    
    if (Math.abs(balanceAfterLock.available - expectedAvailable) < 0.01) {
      results.pass('Available balance decreased by locked amount');
    } else {
      results.fail(
        'Available balance check',
        `Expected ${expectedAvailable.toFixed(2)}, got ${balanceAfterLock.available.toFixed(2)}`
      );
    }
  } catch (err) {
    results.fail('Verify locked balance', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 4: Settle session with positive PNL (win)
  // ═══════════════════════════════════════════════════════════════════════
  const pnl = 5.0; // Player won 5 BB
  
  console.log(`💰 Settling session with PNL: +${pnl} BB\n`);
  
  try {
    const settleResult = await settleSession(sessionId, pnl);
    
    if (settleResult.success) {
      results.pass(`Settle session with PNL +${pnl} BB`);
    } else {
      results.fail('Settle session', `Settlement failed: ${JSON.stringify(settleResult.response)}`);
      return results;
    }
  } catch (err) {
    results.fail('Settle session', err);
    return results;
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 5: Verify tokens released and PNL applied
  // ═══════════════════════════════════════════════════════════════════════
  try {
    const finalBalance = await getBalance(ALICE.address);
    
    console.log(`   Final Balance:`);
    console.log(`   • Available: ${finalBalance.available.toFixed(2)} BB`);
    console.log(`   • Locked:    ${finalBalance.locked.toFixed(2)} BB`);
    console.log(`   • Total:     ${finalBalance.total.toFixed(2)} BB\n`);
    
    // Expected: initial - lockAmount + lockAmount + pnl = initial + pnl
    const expectedFinal = initialBalance.available + pnl;
    
    if (Math.abs(finalBalance.available - expectedFinal) < 0.01) {
      results.pass('Final balance reflects settlement PNL');
    } else {
      results.fail(
        'Final balance check',
        `Expected ${expectedFinal.toFixed(2)}, got ${finalBalance.available.toFixed(2)}`
      );
    }
    
    // Locked should be back to 0 (or original locked amount)
    if (Math.abs(finalBalance.locked - initialBalance.locked) < 0.01) {
      results.pass('Locked balance restored after settlement');
    } else {
      results.fail(
        'Locked balance check',
        `Expected ${initialBalance.locked.toFixed(2)}, got ${finalBalance.locked.toFixed(2)}`
      );
    }
  } catch (err) {
    results.fail('Verify final balance', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 6: Verify conservation of supply
  // ═══════════════════════════════════════════════════════════════════════
  try {
    const finalBalance = await getBalance(ALICE.address);
    const netChange = finalBalance.total - initialBalance.total;
    
    if (Math.abs(netChange - pnl) < 0.01) {
      results.pass('Total supply conserved (net change equals PNL)');
    } else {
      results.fail(
        'Supply conservation',
        `Net change ${netChange.toFixed(2)} does not match PNL ${pnl.toFixed(2)}`
      );
    }
  } catch (err) {
    results.fail('Supply conservation check', err);
  }
  
  return results;
}

run()
  .then(results => {
    const success = results.summary();
    process.exit(success ? 0 : 1);
  })
  .catch(err => {
    console.error('\n💥 Test error:', err);
    process.exit(1);
  });
