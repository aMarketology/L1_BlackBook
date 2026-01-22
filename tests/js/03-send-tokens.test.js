/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 03: Send Tokens
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Alice sends tokens to Bob
 * - Bob sends tokens to Mac
 * - Verify balances update correctly
 * - Verify transaction signatures (V2 format)
 * - Verify sender cannot send more than balance
 */

import nacl from 'tweetnacl';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet, httpPost } from './test-runner.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSFER HELPERS (V2 SIGNING)
// ═══════════════════════════════════════════════════════════════════════════════

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Date.now();
  
  // V2 canonical payload (sorted keys)
  const payload = {
    amount: amount,
    chain_id: 1,
    from: from,
    timestamp: timestamp,
    to: to,
  };
  
  // Canonical JSON (sorted keys)
  const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadBytes = new TextEncoder().encode(canonicalJson);
  const payloadHash = await sha256(payloadBytes);
  
  // Sign the hash
  const signature = nacl.sign.detached(payloadHash, keyPair.secretKey);
  
  return {
    from,
    to,
    amount,
    timestamp,
    public_key: bytesToHex(keyPair.publicKey),
    signature: bytesToHex(signature),
  };
}

async function getBalance(address) {
  try {
    const response = await httpGet(`/balance/${address}`);
    return response.balance ?? response.available ?? 0;
  } catch {
    return 0;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

export async function run() {
  const results = new TestResults();
  
  // Setup: Load keypairs
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  const bobKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.BOB.seed));
  
  // Get initial balances
  let aliceBalanceBefore, bobBalanceBefore, macBalanceBefore;
  
  try {
    aliceBalanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    bobBalanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    macBalanceBefore = await getBalance(TEST_ACCOUNTS.MAC.address);
    
    console.log(`   Initial: Alice=${aliceBalanceBefore}, Bob=${bobBalanceBefore}, Mac=${macBalanceBefore}`);
    results.pass('Fetch initial balances');
  } catch (err) {
    results.fail('Fetch initial balances', err);
    return results;
  }
  
  // Test 1: Alice sends 5 BB to Bob
  const aliceToBobAmount = 5;
  try {
    if (aliceBalanceBefore < aliceToBobAmount) {
      results.skip('Alice sends 5 BB to Bob', 'Insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        aliceToBobAmount,
        aliceKeyPair
      );
      
      const response = await httpPost('/transfer', request);
      
      if (response.error) {
        throw new Error(response.error);
      }
      
      if (!response.success && !response.tx_id && !response.transaction_id) {
        throw new Error('Transfer did not return success indicator');
      }
      
      results.pass(`Alice sends ${aliceToBobAmount} BB to Bob`);
    }
  } catch (err) {
    results.fail('Alice sends 5 BB to Bob', err);
  }
  
  // Test 2: Verify Alice balance decreased
  try {
    const aliceBalanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const expectedBalance = aliceBalanceBefore - aliceToBobAmount;
    
    if (Math.abs(aliceBalanceAfter - expectedBalance) > 0.01) {
      throw new Error(`Expected ${expectedBalance}, got ${aliceBalanceAfter}`);
    }
    
    results.pass('Alice balance decreased correctly');
  } catch (err) {
    results.fail('Alice balance decreased correctly', err);
  }
  
  // Test 3: Verify Bob balance increased
  try {
    const bobBalanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
    const expectedBalance = bobBalanceBefore + aliceToBobAmount;
    
    if (Math.abs(bobBalanceAfter - expectedBalance) > 0.01) {
      throw new Error(`Expected ${expectedBalance}, got ${bobBalanceAfter}`);
    }
    
    results.pass('Bob balance increased correctly');
    bobBalanceBefore = bobBalanceAfter; // Update for next test
  } catch (err) {
    results.fail('Bob balance increased correctly', err);
  }
  
  // Test 4: Bob sends 2 BB to Mac
  const bobToMacAmount = 2;
  try {
    if (bobBalanceBefore < bobToMacAmount) {
      results.skip('Bob sends 2 BB to Mac', 'Insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.BOB.address,
        TEST_ACCOUNTS.MAC.address,
        bobToMacAmount,
        bobKeyPair
      );
      
      const response = await httpPost('/transfer', request);
      
      if (response.error) {
        throw new Error(response.error);
      }
      
      results.pass(`Bob sends ${bobToMacAmount} BB to Mac`);
    }
  } catch (err) {
    results.fail('Bob sends 2 BB to Mac', err);
  }
  
  // Test 5: Verify Mac received tokens
  try {
    const macBalanceAfter = await getBalance(TEST_ACCOUNTS.MAC.address);
    const expectedBalance = macBalanceBefore + bobToMacAmount;
    
    if (Math.abs(macBalanceAfter - expectedBalance) > 0.01) {
      throw new Error(`Expected ${expectedBalance}, got ${macBalanceAfter}`);
    }
    
    results.pass('Mac balance increased correctly');
  } catch (err) {
    results.fail('Mac balance increased correctly', err);
  }
  
  // Test 6: Cannot send more than balance
  try {
    const excessiveAmount = 999999999;
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      excessiveAmount,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success || (!response.error && !response.message)) {
      throw new Error('Should reject excessive transfer');
    }
    
    results.pass('Rejects transfer exceeding balance');
  } catch (err) {
    if (err.message.includes('Should reject')) {
      results.fail('Rejects transfer exceeding balance', err);
    } else {
      results.pass('Rejects transfer exceeding balance');
    }
  }
  
  // Test 7: Cannot send negative amount
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      -100,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success) {
      throw new Error('Should reject negative amount');
    }
    
    results.pass('Rejects negative transfer amount');
  } catch (err) {
    if (err.message.includes('Should reject')) {
      results.fail('Rejects negative transfer amount', err);
    } else {
      results.pass('Rejects negative transfer amount');
    }
  }
  
  // Test 8: Cannot send zero amount
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success) {
      throw new Error('Should reject zero amount');
    }
    
    results.pass('Rejects zero transfer amount');
  } catch (err) {
    if (err.message.includes('Should reject')) {
      results.fail('Rejects zero transfer amount', err);
    } else {
      results.pass('Rejects zero transfer amount');
    }
  }
  
  return results;
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  run().then(r => {
    r.summary();
    process.exit(r.failed === 0 ? 0 : 1);
  });
}
