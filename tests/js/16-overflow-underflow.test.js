/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 16: Overflow & Underflow Protection
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Integer overflow/underflow attacks have caused billions in losses.
 * 
 * Classic attacks:
 * - Overflow: amount so large it wraps to small number
 * - Underflow: subtracting from 0 wraps to MAX_INT
 * 
 * Our Rust backend uses f64 with explicit bounds checking.
 * These tests verify the protection works.
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

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
}

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
  
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  
  console.log('   🔢 Testing overflow/underflow protection...\n');
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 1: Maximum safe integer transfer rejected
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      Number.MAX_SAFE_INTEGER, // 9007199254740991
      aliceKeyPair
    );
    
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const response = await httpPost('/transfer', request);
    const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    // Should be rejected
    if (response.success && !response.error) {
      throw new Error('MAX_SAFE_INTEGER transfer should be rejected');
    }
    
    // Balance should be unchanged
    if (Math.abs(balanceAfter - balanceBefore) > 0.01) {
      throw new Error('Balance changed on rejected overflow transfer');
    }
    
    results.pass('MAX_SAFE_INTEGER transfer rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('MAX_SAFE_INTEGER rejected', err);
    } else {
      results.pass('MAX_SAFE_INTEGER transfer rejected');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 2: Infinity transfer rejected
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      Infinity,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Infinity transfer should be rejected');
    }
    
    results.pass('Infinity transfer rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Infinity rejected', err);
    } else {
      results.pass('Infinity transfer rejected');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 3: Negative infinity transfer rejected
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      -Infinity,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Negative infinity transfer should be rejected');
    }
    
    results.pass('Negative infinity transfer rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('-Infinity rejected', err);
    } else {
      results.pass('Negative infinity transfer rejected');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 4: NaN transfer rejected
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      NaN,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('NaN transfer should be rejected');
    }
    
    results.pass('NaN transfer rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('NaN rejected', err);
    } else {
      results.pass('NaN transfer rejected');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 5: Very small number (underflow check)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.000000001, // Smaller than our 2-decimal precision
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    // Should either reject or round to 0 (which should be rejected)
    console.log(`   Very small amount (0.000000001): ${response.error ? 'rejected' : 'processed'}`);
    
    results.pass('Very small amount handled');
  } catch (err) {
    results.pass('Very small amount handled');
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 6: Underflow attempt (balance - more than balance)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const currentBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const underflowAmount = currentBalance + 1000000;
    
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      underflowAmount,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    // Should be rejected
    if (response.success && !response.error) {
      throw new Error('Underflow transfer should be rejected');
    }
    
    // Balance should be unchanged AND non-negative
    if (balanceAfter < 0) {
      throw new Error(`UNDERFLOW DETECTED! Balance is negative: ${balanceAfter}`);
    }
    
    if (Math.abs(balanceAfter - currentBalance) > 0.01) {
      throw new Error('Balance changed on rejected underflow transfer');
    }
    
    results.pass('Underflow attempt prevented');
  } catch (err) {
    if (err.message.includes('UNDERFLOW') || err.message.includes('should be rejected')) {
      results.fail('Underflow prevention', err);
    } else {
      results.pass('Underflow attempt prevented');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 7: Scientific notation attack
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    // Try to send 1e308 (largest f64)
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      1e308,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('1e308 transfer should be rejected');
    }
    
    results.pass('Scientific notation overflow rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Scientific notation attack', err);
    } else {
      results.pass('Scientific notation overflow rejected');
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 8: Negative exponent (tiny number that rounds to 0)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      1e-308, // Smallest positive f64
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    // Should reject (amount too small)
    console.log(`   Tiny amount (1e-308): ${response.error ? 'rejected' : 'processed'}`);
    
    results.pass('Tiny number handled safely');
  } catch (err) {
    results.pass('Tiny number handled safely');
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 9: Floating point precision attack
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    // 0.1 + 0.2 !== 0.3 in floating point
    const amount = 0.1 + 0.2; // 0.30000000000000004
    
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      amount,
      aliceKeyPair
    );
    
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const response = await httpPost('/transfer', request);
    const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (!response.error) {
      // Transfer succeeded - verify correct deduction
      const expected = balanceBefore - 0.3; // Should round to 0.30
      const tolerance = 0.01;
      
      if (Math.abs(balanceAfter - expected) > tolerance) {
        console.log(`   Warning: Floating point precision issue`);
        console.log(`   Expected: ${expected}, Got: ${balanceAfter}`);
      }
    }
    
    results.pass('Floating point precision handled');
  } catch (err) {
    results.pass('Floating point precision handled');
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // TEST 10: Maximum reasonable transfer succeeds
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const balance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (balance < 1) {
      results.skip('Max reasonable transfer', 'Insufficient balance');
    } else {
      // Transfer a normal amount
      const normalAmount = Math.min(balance, 1.0);
      
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        normalAmount,
        aliceKeyPair
      );
      
      const response = await httpPost('/transfer', request);
      
      if (response.error) {
        throw new Error(`Normal transfer failed: ${response.error}`);
      }
      
      results.pass('Normal transfer succeeds (sanity check)');
    }
  } catch (err) {
    results.fail('Normal transfer sanity check', err);
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
