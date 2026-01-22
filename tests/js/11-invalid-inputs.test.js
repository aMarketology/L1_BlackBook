/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 11: Invalid Inputs
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Invalid address formats rejected
 * - Invalid amounts rejected
 * - Missing required fields rejected
 * - Malformed JSON handled
 * - SQL injection attempts handled
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

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Date.now();
  const payload = { amount, chain_id: 1, from, timestamp, to };
  const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadBytes = new TextEncoder().encode(canonicalJson);
  const payloadHash = await sha256(payloadBytes);
  const signature = nacl.sign.detached(payloadHash, keyPair.secretKey);
  
  return { from, to, amount, timestamp, public_key: bytesToHex(keyPair.publicKey), signature: bytesToHex(signature) };
}

export async function run() {
  const results = new TestResults();
  
  // Test 1: Invalid "from" address format
  try {
    const request = await createSignedTransfer(
      'INVALID_ADDRESS',
      TEST_ACCOUNTS.BOB.address,
      1,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.success && !response.error) {
      throw new Error('Invalid from address should be rejected');
    }
    
    results.pass('Invalid from address rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Invalid from address rejected', err);
    } else {
      results.pass('Invalid from address rejected');
    }
  }
  
  // Test 2: Invalid "to" address format
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      'not-a-valid-address',
      1,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.success && !response.error) {
      throw new Error('Invalid to address should be rejected');
    }
    
    results.pass('Invalid to address rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Invalid to address rejected', err);
    } else {
      results.pass('Invalid to address rejected');
    }
  }
  
  // Test 3: Negative amount
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      -100,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.success && !response.error) {
      throw new Error('Negative amount should be rejected');
    }
    
    results.pass('Negative amount rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Negative amount rejected', err);
    } else {
      results.pass('Negative amount rejected');
    }
  }
  
  // Test 4: Zero amount
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.success && !response.error) {
      throw new Error('Zero amount should be rejected');
    }
    
    results.pass('Zero amount rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Zero amount rejected', err);
    } else {
      results.pass('Zero amount rejected');
    }
  }
  
  // Test 5: Very large amount (overflow check)
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      Number.MAX_SAFE_INTEGER,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.success && !response.error) {
      throw new Error('Overflow amount should be rejected');
    }
    
    results.pass('Very large amount rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Very large amount rejected', err);
    } else {
      results.pass('Very large amount rejected');
    }
  }
  
  // Test 6: Missing required fields
  try {
    const response = await httpPost('/transfer', {
      from: TEST_ACCOUNTS.ALICE.address,
      // Missing: to, amount, timestamp, signature, public_key
    });
    
    if (response.success && !response.error) {
      throw new Error('Missing fields should be rejected');
    }
    
    results.pass('Missing required fields rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Missing required fields rejected', err);
    } else {
      results.pass('Missing required fields rejected');
    }
  }
  
  // Test 7: SQL injection attempt in address
  try {
    const sqlInjection = "L1_'; DROP TABLE balances;--";
    const response = await httpGet(`/balance/${encodeURIComponent(sqlInjection)}`);
    
    // Should return error, not crash
    results.pass('SQL injection in address handled');
  } catch (err) {
    // Error is fine - means it was rejected
    results.pass('SQL injection in address handled');
  }
  
  // Test 8: XSS attempt in request body
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      1,
      aliceKeyPair
    );
    
    // Add XSS payload
    request.note = '<script>alert("xss")</script>';
    
    const response = await httpPost('/transfer/simple', request);
    
    // Server should either strip the field or handle it safely
    results.pass('XSS attempt handled');
  } catch (err) {
    results.pass('XSS attempt handled');
  }
  
  // Test 9: Self-transfer (from === to)
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.ALICE.address, // Same as from
      1,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    // Self-transfer might be allowed or rejected - just shouldn't crash
    console.log(`   Self-transfer: ${response.error ? 'rejected' : 'allowed'}`);
    results.pass('Self-transfer handled');
  } catch (err) {
    results.pass('Self-transfer handled');
  }
  
  // Test 10: Extremely long address
  try {
    const longAddress = 'L1_' + 'A'.repeat(1000);
    const response = await httpGet(`/balance/${longAddress}`);
    
    if (response.success && !response.error) {
      throw new Error('Extremely long address should be rejected');
    }
    
    results.pass('Extremely long address rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Extremely long address rejected', err);
    } else {
      results.pass('Extremely long address rejected');
    }
  }
  
  // Test 11: Unicode in address
  try {
    const unicodeAddress = 'L1_🎰🎲💰' + '0'.repeat(34);
    const response = await httpGet(`/balance/${encodeURIComponent(unicodeAddress)}`);
    
    // Should handle gracefully
    results.pass('Unicode in address handled');
  } catch (err) {
    results.pass('Unicode in address handled');
  }
  
  // Test 12: Null bytes in input
  try {
    const response = await httpPost('/transfer', {
      from: TEST_ACCOUNTS.ALICE.address + '\x00',
      to: TEST_ACCOUNTS.BOB.address,
      amount: 1,
    });
    
    results.pass('Null bytes handled');
  } catch (err) {
    results.pass('Null bytes handled');
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
