/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 02: Concurrent Lock Attempts
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This test validates that the L1 blockchain correctly handles concurrent
 * lock attempts and prevents double-locking vulnerabilities.
 * 
 * CRITICAL SECURITY TEST:
 * - Only ONE active session per wallet should be allowed
 * - Concurrent lock requests must be serialized
 * - Second lock attempt should fail with "active session exists"
 * 
 * ATTACK VECTOR: Race condition where attacker tries to lock same wallet
 * multiple times simultaneously before first lock completes.
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
console.log('║  TEST 02: CONCURRENT LOCK ATTEMPTS                           ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

async function run() {
  const results = new TestResults();
  const ALICE = TEST_ACCOUNTS.ALICE;
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 1: Check initial balance
  // ═══════════════════════════════════════════════════════════════════════
  let initialBalance;
  try {
    initialBalance = await getBalance(ALICE.address);
    console.log(`   Initial: ${initialBalance.available.toFixed(2)} BB available\n`);
    
    if (initialBalance.available < 20) {
      results.skip('Concurrent lock test', 'Insufficient balance');
      return results;
    }
    results.pass('Initial balance check');
  } catch (err) {
    results.fail('Initial balance check', err);
    return results;
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 2: Attempt to open 5 concurrent sessions
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🔒 Attempting 5 simultaneous lock requests...\n');
  
  const lockAmount = 5.0;
  const concurrentAttempts = 5;
  const lockPromises = [];
  
  for (let i = 0; i < concurrentAttempts; i++) {
    const sessionId = generateSessionId();
    lockPromises.push(
      lockTokens(ALICE.address, lockAmount, sessionId)
        .then(result => ({ ...result, attemptNumber: i + 1 }))
        .catch(err => ({ success: false, error: err.message, attemptNumber: i + 1 }))
    );
  }
  
  let lockResults;
  try {
    lockResults = await Promise.all(lockPromises);
    
    const successfulLocks = lockResults.filter(r => r.success).length;
    const failedLocks = lockResults.filter(r => !r.success).length;
    
    console.log(`   Results:`);
    console.log(`   ✓ Successful: ${successfulLocks}/${concurrentAttempts}`);
    console.log(`   ✗ Rejected:   ${failedLocks}/${concurrentAttempts}\n`);
    
    if (successfulLocks === 1) {
      results.pass('Only ONE concurrent lock succeeded (correct)');
    } else if (successfulLocks === 0) {
      results.fail('Concurrent locks', 'All locks failed (unexpected)');
    } else {
      results.fail('Concurrent locks', `${successfulLocks} locks succeeded - DOUBLE LOCKING VULNERABILITY!`);
    }
  } catch (err) {
    results.fail('Concurrent lock attempt', err);
    return results;
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 3: Verify balance reflects only ONE lock
  // ═══════════════════════════════════════════════════════════════════════
  try {
    const balanceAfterLocks = await getBalance(ALICE.address);
    const totalLocked = initialBalance.available - balanceAfterLocks.available;
    
    console.log(`   Balance After Lock Attempts:`);
    console.log(`   • Available: ${balanceAfterLocks.available.toFixed(2)} BB`);
    console.log(`   • Locked:    ${totalLocked.toFixed(2)} BB\n`);
    
    if (Math.abs(totalLocked - lockAmount) < 0.01) {
      results.pass('Balance reflects single lock only');
    } else if (totalLocked === 0) {
      results.fail('Balance check', 'No tokens locked (all attempts failed)');
    } else {
      results.fail(
        'Balance check',
        `Expected ${lockAmount} locked, got ${totalLocked.toFixed(2)} - CRITICAL BUG!`
      );
    }
  } catch (err) {
    results.fail('Balance verification', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 4: Attempt second lock while first is active
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🔒 Attempting second lock with active session...\n');
  
  try {
    const secondSessionId = generateSessionId();
    const secondLock = await lockTokens(ALICE.address, 3.0, secondSessionId);
    
    if (!secondLock.success) {
      results.pass('Second lock rejected (correct behavior)');
    } else {
      results.fail('Second lock prevention', 'Second lock succeeded - VULNERABILITY!');
    }
  } catch (err) {
    // Exception is acceptable if lock is rejected
    results.pass('Second lock rejected with error');
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // TEST 5: Settle active session
  // ═══════════════════════════════════════════════════════════════════════
  const successfulSession = lockResults.find(r => r.success);
  
  if (successfulSession) {
    console.log('💰 Settling active session...\n');
    
    try {
      const settleResult = await settleSession(successfulSession.session_id, 0);
      
      if (settleResult.success) {
        results.pass('Settle active session');
      } else {
        results.fail('Settlement', 'Failed to settle');
      }
    } catch (err) {
      results.fail('Settlement', err);
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // TEST 6: After settlement, new lock should succeed
    // ═══════════════════════════════════════════════════════════════════
    console.log('🔒 Attempting lock after settlement...\n');
    
    try {
      const newSessionId = generateSessionId();
      const newLock = await lockTokens(ALICE.address, 2.0, newSessionId);
      
      if (newLock.success) {
        results.pass('New lock succeeds after settlement');
        
        // Clean up
        await settleSession(newSessionId, 0);
      } else {
        results.fail('Post-settlement lock', 'Lock failed after settlement');
      }
    } catch (err) {
      results.fail('Post-settlement lock', err);
    }
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
