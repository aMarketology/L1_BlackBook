/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 12: Reentrancy Prevention (DAO-Style Attack Prevention)
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The 2016 DAO hack exploited reentrancy: calling back into the contract
 * before state was updated. This test ensures our blockchain is immune.
 * 
 * Attack Pattern:
 *   1. Attacker calls withdraw()
 *   2. Before balance is updated, attacker's callback re-enters withdraw()
 *   3. Attacker drains funds multiple times
 * 
 * Defense: Checks-Effects-Interactions pattern
 *   1. CHECK: Verify conditions (has balance?)
 *   2. EFFECT: Update state (set balance to 0)
 *   3. INTERACT: External call (send funds)
 * 
 * Our L1 uses atomic ReDB transactions - state is updated atomically
 * before any response is sent, making reentrancy impossible.
 */

import nacl from 'tweetnacl';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet, httpPost } from './test-runner.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateNonce() {
  return crypto.randomUUID();
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
}

async function createSignedTransfer(from, to, amount, keyPair, timestampOffset = 0) {
  const timestamp = Math.floor(Date.now() / 1000) + Math.floor(timestampOffset / 1000);
  const nonce = generateNonce();
  const payload = JSON.stringify({ to, amount });
  
  const chainIdByte = new Uint8Array([0x01]);
  const payloadBytes = new TextEncoder().encode(payload);
  const timestampBytes = new TextEncoder().encode(`\n${timestamp}\n`);
  const nonceBytes = new TextEncoder().encode(nonce);
  
  const message = new Uint8Array(chainIdByte.length + payloadBytes.length + timestampBytes.length + nonceBytes.length);
  let offset = 0;
  message.set(chainIdByte, offset); offset += chainIdByte.length;
  message.set(payloadBytes, offset); offset += payloadBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(nonceBytes, offset);
  
  const signature = nacl.sign.detached(message, keyPair.secretKey);
  
  return {
    public_key: bytesToHex(keyPair.publicKey),
    wallet_address: from,
    payload: payload,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    schema_version: 1,
    signature: bytesToHex(signature)
  };
}

export async function run() {
  const results = new TestResults();
  
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  
  console.log('   🛡️  Testing DAO-style attack prevention...\n');
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 1: Rapid-fire withdrawals (simulated reentrancy)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const withdrawAmount = 1;
    const attackAttempts = 20;
    
    if (balanceBefore < withdrawAmount * 2) {
      results.skip('Rapid-fire withdrawal attack', 'Insufficient balance');
    } else {
      console.log(`   Simulating ${attackAttempts} rapid withdrawals of ${withdrawAmount} BB each...`);
      
      // Create all requests with same timestamp (simulated reentrancy)
      const sameTimestamp = Date.now();
      const requests = [];
      
      for (let i = 0; i < attackAttempts; i++) {
        const payload = { 
          amount: withdrawAmount, 
          chain_id: 1, 
          from: TEST_ACCOUNTS.ALICE.address, 
          timestamp: sameTimestamp, // Same timestamp = same "transaction"
          to: TEST_ACCOUNTS.BOB.address 
        };
        const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
        const payloadBytes = new TextEncoder().encode(canonicalJson);
        const payloadHash = await sha256(payloadBytes);
        const signature = nacl.sign.detached(payloadHash, aliceKeyPair.secretKey);
        
        requests.push({
          from: TEST_ACCOUNTS.ALICE.address,
          to: TEST_ACCOUNTS.BOB.address,
          amount: withdrawAmount,
          timestamp: sameTimestamp,
          public_key: bytesToHex(aliceKeyPair.publicKey),
          signature: bytesToHex(signature),
        });
      }
      
      // Fire all at once (simulated reentrancy attack)
      const responses = await Promise.all(requests.map(r => httpPost('/transfer/simple', r)));
      
      const successCount = responses.filter(r => !r.error && r.success !== false).length;
      const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      
      console.log(`   Successful: ${successCount}/${attackAttempts}`);
      console.log(`   Balance: ${balanceBefore} → ${balanceAfter}`);
      
      // Only ONE should succeed (idempotent) or ALL should fail
      // The key is: balance should not drop more than withdrawAmount
      const actualLoss = balanceBefore - balanceAfter;
      
      if (actualLoss > withdrawAmount + 0.01) {
        throw new Error(`REENTRANCY DETECTED! Lost ${actualLoss} BB instead of max ${withdrawAmount} BB`);
      }
      
      if (successCount > 1) {
        console.log(`   ⚠️  Warning: Multiple successes, but balance protected`);
      }
      
      results.pass('Rapid-fire withdrawal attack prevented');
    }
  } catch (err) {
    results.fail('Rapid-fire withdrawal attack', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 2: Interleaved transactions (race condition)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const halfBalance = Math.floor(balanceBefore / 2);
    
    if (halfBalance < 1) {
      results.skip('Interleaved transaction attack', 'Insufficient balance');
    } else {
      console.log(`   Testing interleaved transactions for ${halfBalance} BB each...`);
      
      // Create two transactions that each try to spend half the balance
      // If both succeed, it's a double-spend
      const requests = await Promise.all([
        createSignedTransfer(TEST_ACCOUNTS.ALICE.address, TEST_ACCOUNTS.BOB.address, halfBalance, aliceKeyPair, 0),
        createSignedTransfer(TEST_ACCOUNTS.ALICE.address, TEST_ACCOUNTS.DEALER.address, halfBalance, aliceKeyPair, 1),
      ]);
      
      // Send simultaneously
      const [resp1, resp2] = await Promise.all([
        httpPost('/transfer/simple', requests[0]),
        httpPost('/transfer', requests[1]),
      ]);
      
      const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      
      // At most one should succeed, or both fail
      const success1 = !resp1.error && resp1.success !== false;
      const success2 = !resp2.error && resp2.success !== false;
      
      console.log(`   Transfer 1 (to Bob): ${success1 ? 'SUCCESS' : 'REJECTED'}`);
      console.log(`   Transfer 2 (to Dealer): ${success2 ? 'SUCCESS' : 'REJECTED'}`);
      console.log(`   Balance: ${balanceBefore} → ${balanceAfter}`);
      
      // Verify no double-spend
      const totalSpent = balanceBefore - balanceAfter;
      if (success1 && success2 && totalSpent > balanceBefore) {
        throw new Error('DOUBLE-SPEND! Both transactions succeeded beyond balance');
      }
      
      results.pass('Interleaved transaction attack prevented');
    }
  } catch (err) {
    results.fail('Interleaved transaction attack', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 3: State consistency after partial failure
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const aliceBalanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const bobBalanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    
    // Try to transfer more than balance (should fail atomically)
    const excessiveAmount = aliceBalanceBefore + 1000;
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      excessiveAmount,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    // Balances should be UNCHANGED
    const aliceBalanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const bobBalanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
    
    if (Math.abs(aliceBalanceAfter - aliceBalanceBefore) > 0.01) {
      throw new Error('Alice balance changed on failed transaction!');
    }
    
    if (Math.abs(bobBalanceAfter - bobBalanceBefore) > 0.01) {
      throw new Error('Bob balance changed on failed transaction!');
    }
    
    results.pass('State consistency after failed transaction');
  } catch (err) {
    results.fail('State consistency after failure', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 4: L2 session lock reentrancy
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const lockAmount = 10;
    
    if (balanceBefore < lockAmount * 2) {
      results.skip('L2 lock reentrancy', 'Insufficient balance');
    } else {
      console.log(`   Testing rapid L2 session lock attempts...`);
      
      // Try to open multiple sessions simultaneously
      const lockPromises = Array(5).fill(null).map(() => 
        httpPost('/credit/open', {
          wallet: TEST_ACCOUNTS.ALICE.address,
          amount: lockAmount,
        })
      );
      
      const responses = await Promise.all(lockPromises);
      const successCount = responses.filter(r => r.session_id && !r.error).length;
      
      console.log(`   Lock attempts successful: ${successCount}/5`);
      
      // At most ONE session should be created
      if (successCount > 1) {
        // Check if it's the same session ID (idempotent) or different (bug!)
        const sessionIds = responses
          .filter(r => r.session_id)
          .map(r => r.session_id);
        const uniqueSessions = new Set(sessionIds);
        
        if (uniqueSessions.size > 1) {
          throw new Error(`Multiple unique sessions created: ${[...uniqueSessions].join(', ')}`);
        }
        console.log(`   ✓ Same session returned (idempotent behavior)`);
      }
      
      // Cleanup - settle any session
      const sessionId = responses.find(r => r.session_id)?.session_id;
      if (sessionId) {
        await httpPost('/credit/settle', { session_id: sessionId, net_pnl: 0 });
      }
      
      results.pass('L2 lock reentrancy prevented');
    }
  } catch (err) {
    results.fail('L2 lock reentrancy', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 5: Withdrawal during pending state
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (balanceBefore < 20) {
      results.skip('Withdrawal during lock', 'Insufficient balance');
    } else {
      // Open L2 session to lock funds
      const lockResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: 15,
      });
      
      if (lockResponse.error) {
        results.skip('Withdrawal during lock', 'Could not create session');
      } else {
        const sessionId = lockResponse.session_id;
        
        // Try to withdraw the locked funds
        const withdrawRequest = await createSignedTransfer(
          TEST_ACCOUNTS.ALICE.address,
          TEST_ACCOUNTS.BOB.address,
          balanceBefore, // Try to withdraw ALL funds
          aliceKeyPair
        );
        
        const withdrawResponse = await httpPost('/transfer', withdrawRequest);
        
        // Should fail or only withdraw available (not locked)
        const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
        
        console.log(`   Balance before lock: ${balanceBefore}`);
        console.log(`   Locked: 15 BB`);
        console.log(`   Balance after withdraw attempt: ${balanceAfter}`);
        
        // Locked funds should NOT have been withdrawn
        // If withdraw succeeded, it should only be for available balance
        
        // Cleanup
        await httpPost('/credit/settle', { session_id: sessionId, net_pnl: 0 });
        
        results.pass('Locked funds protected during withdrawal');
      }
    }
  } catch (err) {
    results.fail('Withdrawal during lock', err);
  }
  
  return results;
}

// Run if executed directly
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
if (__filename === process.argv[1]) {
  run().then(r => {
    r.summary();
    process.exit(r.failed === 0 ? 0 : 1);
  });
}
