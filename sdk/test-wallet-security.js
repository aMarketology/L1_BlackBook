/**
 * TEST: WALLET SECURITY & SSS RECOVERY
 * =====================================
 * Tests:
 * 1. Ed25519 keypair generation from seed
 * 2. Address derivation (L1/L2 match with same hash)
 * 3. Shamir's Secret Sharing (SSS) split/recover
 * 4. PIN-based encryption/decryption
 * 5. Cross-layer address consistency (L1 ↔ L2)
 */

import nacl from 'tweetnacl';
import { createHash } from 'crypto';
import secrets from 'secrets.js-grempe';
import CryptoJS from 'crypto-js';

// ============================================================================
// TEST ACCOUNTS (From working alice-to-bob.js)
// ============================================================================
const TEST_ACCOUNTS = {
  ALICE: {
    name: 'Alice',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    expectedL1: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    expectedL2: 'L2_52882D768C0F3E7932AAD1813CF8B19058D507A8',
  },
  BOB: {
    name: 'Bob',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    expectedL1: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    expectedL2: 'L2_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
  },
  DEALER: {
    name: 'Dealer',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    expectedL1: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    expectedL2: 'L2_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
  }
};

// SSS Constants
const SSS_SHARE_COUNT = 3;
const SSS_THRESHOLD = 2;
const PIN_PBKDF2_ITERATIONS = 100000;

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

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

function deriveKeypair(seedHex) {
  const seed = hexToBytes(seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  return {
    publicKey: bytesToHex(keypair.publicKey),
    secretKey: keypair.secretKey
  };
}

function deriveAddress(publicKeyHex, layer = 'L1') {
  const pubKeyBytes = hexToBytes(publicKeyHex);
  const hash = createHash('sha256').update(pubKeyBytes).digest();
  const prefix = layer === 'L2' ? 'L2_' : 'L1_';
  return prefix + hash.slice(0, 20).toString('hex').toUpperCase();
}

// ============================================================================
// SSS FUNCTIONS
// ============================================================================

function splitSeed(seedHex, shares = SSS_SHARE_COUNT, threshold = SSS_THRESHOLD) {
  return secrets.share(seedHex, shares, threshold);
}

function recoverSeed(shares) {
  return secrets.combine(shares);
}

function derivePinKey(pin, salt) {
  const key = CryptoJS.PBKDF2(pin, salt, {
    keySize: 256 / 32,
    iterations: PIN_PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA256
  });
  return key.toString(CryptoJS.enc.Hex);
}

function encryptWithPIN(data, pin) {
  const salt = CryptoJS.lib.WordArray.random(32).toString();
  const key = derivePinKey(pin, salt);
  const encrypted = CryptoJS.AES.encrypt(data, key).toString();
  return { encrypted, salt };
}

function decryptWithPIN(encrypted, salt, pin) {
  const key = derivePinKey(pin, salt);
  const decrypted = CryptoJS.AES.decrypt(encrypted, key);
  return decrypted.toString(CryptoJS.enc.Utf8);
}

// ============================================================================
// TEST RESULTS TRACKING
// ============================================================================

let passed = 0;
let failed = 0;
const results = [];

function test(name, fn) {
  try {
    const result = fn();
    if (result === true) {
      passed++;
      results.push({ name, status: '✅ PASS' });
      console.log(`✅ ${name}`);
    } else {
      failed++;
      results.push({ name, status: '❌ FAIL', error: result });
      console.log(`❌ ${name}: ${result}`);
    }
  } catch (err) {
    failed++;
    results.push({ name, status: '❌ FAIL', error: err.message });
    console.log(`❌ ${name}: ${err.message}`);
  }
}

// ============================================================================
// TESTS
// ============================================================================

console.log('');
console.log('╔═══════════════════════════════════════════════════════════════════════╗');
console.log('║  WALLET SECURITY & SSS RECOVERY TEST                                  ║');
console.log('║  Tests Ed25519, Address Derivation, SSS Split/Recover, L1↔L2 Match    ║');
console.log('╚═══════════════════════════════════════════════════════════════════════╝');
console.log('');

// ============================================================================
// TEST 1: ED25519 KEYPAIR GENERATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 1: ED25519 KEYPAIR GENERATION');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('1.1 Alice keypair derives correctly', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  return publicKey.length === 64 || `Expected 64 hex chars, got ${publicKey.length}`;
});

test('1.2 Bob keypair derives correctly', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.BOB.seed);
  return publicKey.length === 64 || `Expected 64 hex chars, got ${publicKey.length}`;
});

test('1.3 Dealer keypair derives correctly', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.DEALER.seed);
  return publicKey.length === 64 || `Expected 64 hex chars, got ${publicKey.length}`;
});

test('1.4 Same seed always produces same keypair', () => {
  const kp1 = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const kp2 = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  return kp1.publicKey === kp2.publicKey || 'Keypairs should match';
});

test('1.5 Different seeds produce different keypairs', () => {
  const kp1 = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const kp2 = deriveKeypair(TEST_ACCOUNTS.BOB.seed);
  return kp1.publicKey !== kp2.publicKey || 'Keypairs should differ';
});

console.log('');

// ============================================================================
// TEST 2: L1/L2 ADDRESS DERIVATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 2: L1/L2 ADDRESS DERIVATION & CROSS-LAYER CONSISTENCY');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('2.1 Alice L1 address matches expected', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  return l1Addr === TEST_ACCOUNTS.ALICE.expectedL1 || 
    `Expected ${TEST_ACCOUNTS.ALICE.expectedL1}, got ${l1Addr}`;
});

test('2.2 Alice L2 address matches expected', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const l2Addr = deriveAddress(publicKey, 'L2');
  return l2Addr === TEST_ACCOUNTS.ALICE.expectedL2 || 
    `Expected ${TEST_ACCOUNTS.ALICE.expectedL2}, got ${l2Addr}`;
});

test('2.3 Alice L1 and L2 addresses share same hash (only prefix differs)', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  const l2Addr = deriveAddress(publicKey, 'L2');
  const l1Hash = l1Addr.substring(3);
  const l2Hash = l2Addr.substring(3);
  return l1Hash === l2Hash || `L1 hash: ${l1Hash}, L2 hash: ${l2Hash}`;
});

test('2.4 Bob L1/L2 addresses share same hash', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.BOB.seed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  const l2Addr = deriveAddress(publicKey, 'L2');
  return l1Addr.substring(3) === l2Addr.substring(3) || 'Hashes should match';
});

test('2.5 Dealer L1/L2 addresses share same hash', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.DEALER.seed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  const l2Addr = deriveAddress(publicKey, 'L2');
  return l1Addr.substring(3) === l2Addr.substring(3) || 'Hashes should match';
});

test('2.6 Address format is correct (L1_ + 40 hex chars = 43 total)', () => {
  const { publicKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  return l1Addr.length === 43 && l1Addr.startsWith('L1_') || 
    `Expected 43 chars starting with L1_, got ${l1Addr.length} chars`;
});

console.log('');

// ============================================================================
// TEST 3: SHAMIR'S SECRET SHARING (SSS)
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 3: SHAMIR\'S SECRET SHARING (SSS) - SPLIT & RECOVER');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const aliceSeed = TEST_ACCOUNTS.ALICE.seed;
let shares = [];

test('3.1 Split seed into 3 shares', () => {
  shares = splitSeed(aliceSeed, 3, 2);
  return shares.length === 3 || `Expected 3 shares, got ${shares.length}`;
});

test('3.2 Each share is different', () => {
  return shares[0] !== shares[1] && shares[1] !== shares[2] && shares[0] !== shares[2] ||
    'All shares should be unique';
});

test('3.3 Recover with shares 1+2 (threshold met)', () => {
  const recovered = recoverSeed([shares[0], shares[1]]);
  return recovered === aliceSeed || `Expected ${aliceSeed}, got ${recovered}`;
});

test('3.4 Recover with shares 1+3 (threshold met)', () => {
  const recovered = recoverSeed([shares[0], shares[2]]);
  return recovered === aliceSeed || `Expected ${aliceSeed}, got ${recovered}`;
});

test('3.5 Recover with shares 2+3 (threshold met)', () => {
  const recovered = recoverSeed([shares[1], shares[2]]);
  return recovered === aliceSeed || `Expected ${aliceSeed}, got ${recovered}`;
});

test('3.6 Recover with all 3 shares', () => {
  const recovered = recoverSeed([shares[0], shares[1], shares[2]]);
  return recovered === aliceSeed || `Expected ${aliceSeed}, got ${recovered}`;
});

test('3.7 Single share alone cannot recover seed', () => {
  try {
    const recovered = recoverSeed([shares[0]]);
    // If we get here without error, check if it's wrong
    return recovered !== aliceSeed || 'Single share should not recover correct seed';
  } catch (e) {
    return true; // Expected to fail
  }
});

console.log('');

// ============================================================================
// TEST 4: PIN-BASED ENCRYPTION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 4: PIN-BASED ENCRYPTION (PBKDF2 + AES)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const testPIN = '123456';
const wrongPIN = '654321';
let encryptedShare = null;
let encryptionSalt = null;

test('4.1 Encrypt share with PIN', () => {
  const result = encryptWithPIN(shares[0], testPIN);
  encryptedShare = result.encrypted;
  encryptionSalt = result.salt;
  return encryptedShare && encryptionSalt || 'Encryption should produce encrypted + salt';
});

test('4.2 Encrypted share differs from original', () => {
  return encryptedShare !== shares[0] || 'Encrypted should differ from original';
});

test('4.3 Decrypt with correct PIN', () => {
  const decrypted = decryptWithPIN(encryptedShare, encryptionSalt, testPIN);
  return decrypted === shares[0] || `Expected ${shares[0]}, got ${decrypted}`;
});

test('4.4 Decrypt with wrong PIN fails', () => {
  const decrypted = decryptWithPIN(encryptedShare, encryptionSalt, wrongPIN);
  return decrypted !== shares[0] || 'Wrong PIN should not decrypt correctly';
});

test('4.5 PBKDF2 produces consistent keys', () => {
  const key1 = derivePinKey(testPIN, encryptionSalt);
  const key2 = derivePinKey(testPIN, encryptionSalt);
  return key1 === key2 || 'Same PIN + salt should produce same key';
});

test('4.6 Different salts produce different keys', () => {
  const salt2 = CryptoJS.lib.WordArray.random(32).toString();
  const key1 = derivePinKey(testPIN, encryptionSalt);
  const key2 = derivePinKey(testPIN, salt2);
  return key1 !== key2 || 'Different salts should produce different keys';
});

console.log('');

// ============================================================================
// TEST 5: FULL RECOVERY FLOW
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 5: FULL RECOVERY FLOW (SSS + PIN Encryption)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('5.1 Full flow: Split → Encrypt → Decrypt → Recover → Derive Address', () => {
  const originalSeed = TEST_ACCOUNTS.BOB.seed;
  const pin = '987654';
  
  // Step 1: Split
  const newShares = splitSeed(originalSeed, 3, 2);
  
  // Step 2: Encrypt share 2 with PIN (simulating cloud backup)
  const encrypted = encryptWithPIN(newShares[1], pin);
  
  // Step 3: Decrypt share 2 with PIN
  const decryptedShare = decryptWithPIN(encrypted.encrypted, encrypted.salt, pin);
  
  // Step 4: Recover seed with share 1 + decrypted share 2
  const recoveredSeed = recoverSeed([newShares[0], decryptedShare]);
  
  // Step 5: Verify we get back original seed
  if (recoveredSeed !== originalSeed) {
    return `Seed mismatch: expected ${originalSeed}, got ${recoveredSeed}`;
  }
  
  // Step 6: Derive address and verify it matches
  const { publicKey } = deriveKeypair(recoveredSeed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  
  return l1Addr === TEST_ACCOUNTS.BOB.expectedL1 || 
    `Address mismatch: expected ${TEST_ACCOUNTS.BOB.expectedL1}, got ${l1Addr}`;
});

test('5.2 Recovered wallet can derive both L1 and L2 addresses', () => {
  const originalSeed = TEST_ACCOUNTS.DEALER.seed;
  
  // Split and recover
  const newShares = splitSeed(originalSeed, 3, 2);
  const recoveredSeed = recoverSeed([newShares[0], newShares[2]]);
  
  // Derive both addresses
  const { publicKey } = deriveKeypair(recoveredSeed);
  const l1Addr = deriveAddress(publicKey, 'L1');
  const l2Addr = deriveAddress(publicKey, 'L2');
  
  return l1Addr === TEST_ACCOUNTS.DEALER.expectedL1 && 
         l2Addr === TEST_ACCOUNTS.DEALER.expectedL2 ||
    `L1: ${l1Addr}, L2: ${l2Addr}`;
});

console.log('');

// ============================================================================
// TEST 6: SIGNATURE SECURITY
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 6: ED25519 SIGNATURE SECURITY');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('6.1 Sign message with secret key', () => {
  const { secretKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const message = new TextEncoder().encode('Test message');
  const signature = nacl.sign.detached(message, secretKey);
  return signature.length === 64 || `Expected 64 byte signature, got ${signature.length}`;
});

test('6.2 Verify signature with public key', () => {
  const { publicKey, secretKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const message = new TextEncoder().encode('Test message');
  const signature = nacl.sign.detached(message, secretKey);
  const pubKeyBytes = hexToBytes(publicKey);
  return nacl.sign.detached.verify(message, signature, pubKeyBytes) || 'Signature should verify';
});

test('6.3 Wrong public key fails verification', () => {
  const alice = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const bob = deriveKeypair(TEST_ACCOUNTS.BOB.seed);
  const message = new TextEncoder().encode('Test message');
  const signature = nacl.sign.detached(message, alice.secretKey);
  const bobPubKeyBytes = hexToBytes(bob.publicKey);
  return !nacl.sign.detached.verify(message, signature, bobPubKeyBytes) || 
    'Wrong pubkey should fail verification';
});

test('6.4 Tampered message fails verification', () => {
  const { publicKey, secretKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const message = new TextEncoder().encode('Test message');
  const tamperedMessage = new TextEncoder().encode('Tampered message');
  const signature = nacl.sign.detached(message, secretKey);
  const pubKeyBytes = hexToBytes(publicKey);
  return !nacl.sign.detached.verify(tamperedMessage, signature, pubKeyBytes) || 
    'Tampered message should fail verification';
});

test('6.5 Domain separation: L1 signature differs from L2', () => {
  const { secretKey } = deriveKeypair(TEST_ACCOUNTS.ALICE.seed);
  const payload = 'transfer:100:bob';
  
  // L1 signature (chain_id = 1)
  const l1Message = new Uint8Array([0x01, ...new TextEncoder().encode(payload)]);
  const l1Sig = nacl.sign.detached(l1Message, secretKey);
  
  // L2 signature (chain_id = 2)  
  const l2Message = new Uint8Array([0x02, ...new TextEncoder().encode(payload)]);
  const l2Sig = nacl.sign.detached(l2Message, secretKey);
  
  return bytesToHex(l1Sig) !== bytesToHex(l2Sig) || 'L1 and L2 signatures should differ';
});

console.log('');

// ============================================================================
// SUMMARY
// ============================================================================
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('                           TEST SUMMARY                                ');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');

console.log('┌────────────────────────────────────────────────────────┬──────────┐');
console.log('│ Test                                                   │ Status   │');
console.log('├────────────────────────────────────────────────────────┼──────────┤');
for (const r of results) {
  console.log(`│ ${r.name.padEnd(56)} │ ${r.status.padEnd(8)} │`);
}
console.log('└────────────────────────────────────────────────────────┴──────────┘');
console.log('');

console.log(`✅ Passed: ${passed}`);
console.log(`❌ Failed: ${failed}`);
console.log('');

// Account Address Summary
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('                     L1 ↔ L2 ADDRESS MAPPING                           ');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');
console.log('┌─────────┬──────────────────────────────────────────────┬──────────────────────────────────────────────┐');
console.log('│ Account │ L1 Address                                   │ L2 Address                                   │');
console.log('├─────────┼──────────────────────────────────────────────┼──────────────────────────────────────────────┤');
for (const [key, acct] of Object.entries(TEST_ACCOUNTS)) {
  const { publicKey } = deriveKeypair(acct.seed);
  const l1 = deriveAddress(publicKey, 'L1');
  const l2 = deriveAddress(publicKey, 'L2');
  console.log(`│ ${acct.name.padEnd(7)} │ ${l1} │ ${l2} │`);
}
console.log('└─────────┴──────────────────────────────────────────────┴──────────────────────────────────────────────┘');
console.log('');

// Exit with appropriate code
process.exit(failed > 0 ? 1 : 0);
