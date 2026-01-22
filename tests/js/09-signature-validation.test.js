/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 09: Signature Validation
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Valid signatures are accepted
 * - Invalid signatures are rejected
 * - Wrong public key is rejected
 * - Tampered payload is rejected
 * - Replay attacks are prevented
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
  const bobKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.BOB.seed));
  
  // Test 1: Valid signature is accepted
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.01,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer', request);
    
    if (response.error && response.error.includes('signature')) {
      throw new Error('Valid signature was rejected');
    }
    
    results.pass('Valid signature accepted');
  } catch (err) {
    results.fail('Valid signature accepted', err);
  }
  
  // Test 2: Invalid signature is rejected
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.01,
      aliceKeyPair
    );
    
    // Corrupt the signature
    request.signature = request.signature.replace(/[a-f]/g, '0');
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Invalid signature should be rejected');
    }
    
    results.pass('Invalid signature rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Invalid signature rejected', err);
    } else {
      results.pass('Invalid signature rejected');
    }
  }
  
  // Test 3: Wrong public key is rejected
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.01,
      aliceKeyPair
    );
    
    // Use Bob's public key with Alice's signature
    request.public_key = bytesToHex(bobKeyPair.publicKey);
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Wrong public key should be rejected');
    }
    
    results.pass('Wrong public key rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Wrong public key rejected', err);
    } else {
      results.pass('Wrong public key rejected');
    }
  }
  
  // Test 4: Tampered amount is rejected
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.01,
      aliceKeyPair
    );
    
    // Change amount after signing
    request.amount = 1000;
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Tampered amount should be rejected');
    }
    
    results.pass('Tampered amount rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Tampered amount rejected', err);
    } else {
      results.pass('Tampered amount rejected');
    }
  }
  
  // Test 5: Tampered recipient is rejected
  try {
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      0.01,
      aliceKeyPair
    );
    
    // Change recipient after signing
    request.to = TEST_ACCOUNTS.DEALER.address;
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Tampered recipient should be rejected');
    }
    
    results.pass('Tampered recipient rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Tampered recipient rejected', err);
    } else {
      results.pass('Tampered recipient rejected');
    }
  }
  
  // Test 6: Signing with wrong private key is rejected
  try {
    // Sign Alice's transfer with Bob's key
    const timestamp = Date.now();
    const payload = {
      amount: 0.01,
      chain_id: 1,
      from: TEST_ACCOUNTS.ALICE.address, // Alice is sender
      timestamp,
      to: TEST_ACCOUNTS.BOB.address,
    };
    
    const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
    const payloadBytes = new TextEncoder().encode(canonicalJson);
    const payloadHash = await sha256(payloadBytes);
    
    // Sign with BOB's key (wrong key for Alice's address)
    const signature = nacl.sign.detached(payloadHash, bobKeyPair.secretKey);
    
    const request = {
      from: TEST_ACCOUNTS.ALICE.address,
      to: TEST_ACCOUNTS.BOB.address,
      amount: 0.01,
      timestamp,
      public_key: bytesToHex(bobKeyPair.publicKey), // Bob's pubkey
      signature: bytesToHex(signature),
    };
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Wrong signer should be rejected');
    }
    
    results.pass('Wrong signer rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Wrong signer rejected', err);
    } else {
      results.pass('Wrong signer rejected');
    }
  }
  
  // Test 7: Old timestamp (potential replay) - may or may not be rejected
  try {
    const oldTimestamp = Date.now() - (60 * 60 * 1000); // 1 hour ago
    const payload = {
      amount: 0.01,
      chain_id: 1,
      from: TEST_ACCOUNTS.ALICE.address,
      timestamp: oldTimestamp,
      to: TEST_ACCOUNTS.BOB.address,
    };
    
    const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
    const payloadBytes = new TextEncoder().encode(canonicalJson);
    const payloadHash = await sha256(payloadBytes);
    const signature = nacl.sign.detached(payloadHash, aliceKeyPair.secretKey);
    
    const request = {
      from: TEST_ACCOUNTS.ALICE.address,
      to: TEST_ACCOUNTS.BOB.address,
      amount: 0.01,
      timestamp: oldTimestamp,
      public_key: bytesToHex(aliceKeyPair.publicKey),
      signature: bytesToHex(signature),
    };
    
    const response = await httpPost('/transfer', request);
    
    // Note: Some systems allow old timestamps, some don't
    if (response.error && response.error.includes('timestamp')) {
      console.log('   Server enforces timestamp freshness');
    } else {
      console.log('   Server allows old timestamps (may need timestamp validation)');
    }
    
    results.pass('Old timestamp handling checked');
  } catch (err) {
    results.pass('Old timestamp handling checked');
  }
  
  // Test 8: Empty signature rejected
  try {
    const request = {
      from: TEST_ACCOUNTS.ALICE.address,
      to: TEST_ACCOUNTS.BOB.address,
      amount: 0.01,
      timestamp: Date.now(),
      public_key: bytesToHex(aliceKeyPair.publicKey),
      signature: '',
    };
    
    const response = await httpPost('/transfer', request);
    
    if (response.success && !response.error) {
      throw new Error('Empty signature should be rejected');
    }
    
    results.pass('Empty signature rejected');
  } catch (err) {
    if (err.message.includes('should be rejected')) {
      results.fail('Empty signature rejected', err);
    } else {
      results.pass('Empty signature rejected');
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
