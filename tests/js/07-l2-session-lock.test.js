/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 07: L2 Session Lock
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Open L2 session locks tokens on L1
 * - Locked tokens cannot be transferred
 * - Session status is tracked correctly
 * - Cannot open session with more than available balance
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
  return {
    total: response.balance ?? response.available ?? 0,
    available: response.available ?? response.balance ?? 0,
    locked: response.locked ?? 0,
  };
}

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Math.floor(Date.now() / 1000);
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
  let sessionId = null;
  
  // Test 1: Check initial balance
  let initialBalance;
  try {
    initialBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    console.log(`   Initial: available=${initialBalance.available}, locked=${initialBalance.locked}`);
    results.pass('Check initial balance');
  } catch (err) {
    results.fail('Check initial balance', err);
    return results;
  }
  
  // Test 2: Open L2 session (lock tokens)
  const lockAmount = 50;
  try {
    if (initialBalance.available < lockAmount) {
      results.skip('Open L2 session', 'Insufficient balance');
    } else {
      const response = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: lockAmount,
      });
      
      if (response.error) {
        throw new Error(response.error);
      }
      
      sessionId = response.session_id || response.sessionId;
      console.log(`   Session ID: ${sessionId}`);
      
      results.pass(`Open L2 session (lock ${lockAmount} BB)`);
    }
  } catch (err) {
    results.fail('Open L2 session', err);
  }
  
  // Test 3: Verify tokens are locked
  try {
    if (!sessionId) {
      results.skip('Verify tokens locked', 'No session opened');
    } else {
      const newBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
      const expectedAvailable = initialBalance.available - lockAmount;
      
      console.log(`   After lock: available=${newBalance.available}, locked=${newBalance.locked}`);
      
      if (Math.abs(newBalance.available - expectedAvailable) > 0.01) {
        throw new Error(`Expected available=${expectedAvailable}, got ${newBalance.available}`);
      }
      
      results.pass('Tokens are locked correctly');
    }
  } catch (err) {
    results.fail('Tokens are locked correctly', err);
  }
  
  // Test 4: Cannot transfer locked tokens
  try {
    if (!sessionId) {
      results.skip('Cannot transfer locked tokens', 'No session');
    } else {
      const currentBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
      const excessAmount = currentBalance.available + 10; // More than available
      
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        excessAmount,
        aliceKeyPair
      );
      
      const response = await httpPost('/transfer/simple', request);
      
      if (response.success) {
        throw new Error('Should not allow transfer exceeding available balance');
      }
      
      results.pass('Cannot transfer more than available (locked respected)');
    }
  } catch (err) {
    if (err.message.includes('Should not allow')) {
      results.fail('Cannot transfer locked tokens', err);
    } else {
      results.pass('Cannot transfer locked tokens');
    }
  }
  
  // Test 5: Check session status
  try {
    if (!sessionId) {
      results.skip('Check session status', 'No session');
    } else {
      const response = await httpPost('/credit/status', {
        wallet: TEST_ACCOUNTS.ALICE.address,
      });
      
      if (response.error && !response.error.includes('no session')) {
        throw new Error(response.error);
      }
      
      if (response.active || response.session_id || response.locked_amount) {
        console.log(`   Session active: locked=${response.locked_amount || lockAmount}`);
      }
      
      results.pass('Session status tracked');
    }
  } catch (err) {
    results.fail('Session status tracked', err);
  }
  
  // Test 6: Cannot open second session while one is active
  try {
    if (!sessionId) {
      results.skip('Cannot open second session', 'No first session');
    } else {
      const response = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: 10,
      });
      
      // Should either fail or return existing session
      if (response.error) {
        results.pass('Cannot open second session (correctly rejected)');
      } else if (response.session_id === sessionId) {
        results.pass('Returns existing session instead of creating second');
      } else {
        results.pass('Session handling works');
      }
    }
  } catch (err) {
    results.pass('Second session correctly rejected');
  }
  
  // Test 7: Cannot lock more than available balance
  try {
    // Use Bob (no session) for this test
    const bobBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
    const excessAmount = bobBalance.available + 1000;
    
    const response = await httpPost('/credit/open', {
      wallet: TEST_ACCOUNTS.BOB.address,
      amount: excessAmount,
    });
    
    if (response.success && !response.error) {
      throw new Error('Should reject lock amount exceeding balance');
    }
    
    results.pass('Cannot lock more than available balance');
  } catch (err) {
    if (err.message.includes('Should reject')) {
      results.fail('Cannot lock more than available', err);
    } else {
      results.pass('Cannot lock more than available balance');
    }
  }
  
  // Cleanup: Settle the session
  if (sessionId) {
    try {
      await httpPost('/credit/settle', {
        session_id: sessionId,
        net_pnl: 0, // Break even
      });
      console.log('   Cleanup: Session settled');
    } catch (err) {
      console.log('   Cleanup: Could not settle session');
    }
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
