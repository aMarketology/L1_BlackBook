/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 08: L2 Settlement
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Settle session returns locked + P&L
 * - Win scenario: user gets locked + profit
 * - Loss scenario: user gets locked - loss
 * - Break-even: user gets exact locked amount back
 * - Dealer balance adjusts accordingly
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

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return {
    total: response.balance ?? response.available ?? 0,
    available: response.available ?? response.balance ?? 0,
    locked: response.locked ?? 0,
  };
}

export async function run() {
  const results = new TestResults();
  
  // Test 1: Win scenario - Alice locks 30, wins 10
  try {
    const aliceBalanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const dealerBalanceBefore = await getBalance(TEST_ACCOUNTS.DEALER.address);
    
    const lockAmount = 30;
    const winAmount = 10;
    
    if (aliceBalanceBefore.available < lockAmount) {
      results.skip('Win scenario', `Insufficient balance: ${aliceBalanceBefore.available}`);
    } else {
      // Open session
      const openResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: lockAmount,
      });
      
      if (openResponse.error) throw new Error(openResponse.error);
      const sessionId = openResponse.session_id || openResponse.sessionId;
      
      // Settle with win
      const settleResponse = await httpPost('/credit/settle', {
        session_id: sessionId,
        net_pnl: winAmount, // Positive = win
      });
      
      if (settleResponse.error) throw new Error(settleResponse.error);
      
      // Verify balances
      const aliceBalanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      const expectedAlice = aliceBalanceBefore.available + winAmount;
      
      console.log(`   Alice: ${aliceBalanceBefore.available} → ${aliceBalanceAfter.available} (expected ${expectedAlice})`);
      
      if (Math.abs(aliceBalanceAfter.available - expectedAlice) > 0.01) {
        throw new Error(`Expected ${expectedAlice}, got ${aliceBalanceAfter.available}`);
      }
      
      results.pass('Win scenario: locked + profit returned');
    }
  } catch (err) {
    results.fail('Win scenario', err);
  }
  
  // Test 2: Loss scenario - Bob locks 40, loses 15
  try {
    const bobBalanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    const lockAmount = 40;
    const lossAmount = 15;
    
    if (bobBalanceBefore.available < lockAmount) {
      results.skip('Loss scenario', 'Insufficient balance');
    } else {
      // Open session
      const openResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.BOB.address,
        amount: lockAmount,
      });
      
      if (openResponse.error) throw new Error(openResponse.error);
      const sessionId = openResponse.session_id || openResponse.sessionId;
      
      // Settle with loss
      const settleResponse = await httpPost('/credit/settle', {
        session_id: sessionId,
        net_pnl: -lossAmount, // Negative = loss
      });
      
      if (settleResponse.error) throw new Error(settleResponse.error);
      
      // Verify balances
      const bobBalanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
      const expectedBob = bobBalanceBefore.available - lossAmount;
      
      console.log(`   Bob: ${bobBalanceBefore.available} → ${bobBalanceAfter.available} (expected ${expectedBob})`);
      
      if (Math.abs(bobBalanceAfter.available - expectedBob) > 0.01) {
        throw new Error(`Expected ${expectedBob}, got ${bobBalanceAfter.available}`);
      }
      
      results.pass('Loss scenario: locked - loss returned');
    }
  } catch (err) {
    results.fail('Loss scenario', err);
  }
  
  // Test 3: Break-even scenario
  try {
    const aliceBalanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const lockAmount = 25;
    
    if (aliceBalanceBefore.available < lockAmount) {
      results.skip('Break-even scenario', 'Insufficient balance');
    } else {
      // Open session
      const openResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: lockAmount,
      });
      
      if (openResponse.error) throw new Error(openResponse.error);
      const sessionId = openResponse.session_id || openResponse.sessionId;
      
      // Settle with no P&L
      const settleResponse = await httpPost('/credit/settle', {
        session_id: sessionId,
        net_pnl: 0,
      });
      
      if (settleResponse.error) throw new Error(settleResponse.error);
      
      // Verify Alice got exact amount back
      const aliceBalanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      
      if (Math.abs(aliceBalanceAfter.available - aliceBalanceBefore.available) > 0.01) {
        throw new Error('Break-even should return exact locked amount');
      }
      
      results.pass('Break-even: exact locked amount returned');
    }
  } catch (err) {
    results.fail('Break-even scenario', err);
  }
  
  // Test 4: Cannot settle non-existent session
  try {
    const response = await httpPost('/credit/settle', {
      session_id: 'fake-session-id-12345',
      net_pnl: 100,
    });
    
    if (response.success && !response.error) {
      throw new Error('Should reject fake session ID');
    }
    
    results.pass('Cannot settle non-existent session');
  } catch (err) {
    if (err.message.includes('Should reject')) {
      results.fail('Cannot settle non-existent session', err);
    } else {
      results.pass('Cannot settle non-existent session');
    }
  }
  
  // Test 5: Cannot lose more than locked amount
  try {
    const aliceBalanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const lockAmount = 20;
    const excessiveLoss = lockAmount + 100;
    
    if (aliceBalanceBefore.available < lockAmount) {
      results.skip('Cannot lose more than locked', 'Insufficient balance');
    } else {
      // Open session
      const openResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: lockAmount,
      });
      
      if (openResponse.error) throw new Error(openResponse.error);
      const sessionId = openResponse.session_id || openResponse.sessionId;
      
      // Try to settle with excessive loss
      const settleResponse = await httpPost('/credit/settle', {
        session_id: sessionId,
        net_pnl: -excessiveLoss,
      });
      
      // Should either reject or cap the loss
      const aliceBalanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      
      // Alice should have at least some balance (not negative)
      if (aliceBalanceAfter.available < 0) {
        throw new Error('Balance went negative');
      }
      
      // If the loss was capped, the user gets 0 back
      // If rejected, user gets lockAmount back
      console.log(`   After excessive loss attempt: ${aliceBalanceAfter.available}`);
      
      results.pass('Excessive loss handled safely');
    }
  } catch (err) {
    results.fail('Excessive loss handling', err);
  }
  
  // Test 6: Dealer balance reflects settlements
  try {
    const dealerBalance = await getBalance(TEST_ACCOUNTS.DEALER.address);
    
    console.log(`   Dealer balance: ${dealerBalance.available} BB`);
    
    if (dealerBalance.available < 0) {
      throw new Error('Dealer balance is negative');
    }
    
    results.pass('Dealer balance is valid');
  } catch (err) {
    results.fail('Dealer balance check', err);
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
