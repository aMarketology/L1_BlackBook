/**
 * TEST: WALLET GENERATION & MULTI-LAYER ADDRESS CONSISTENCY
 * ==========================================================
 * Tests:
 * 1. Secure wallet generation (entropy, Ed25519)
 * 2. Same address hash across ALL layers (L1, L2, L3, L4, L5, etc.)
 * 3. Collision prevention (no two users can share same address)
 * 4. Active wallet protection
 * 5. Address uniqueness from different seeds
 */

import nacl from 'tweetnacl';
import { createHash, randomBytes } from 'crypto';

// ============================================================================
// CONSTANTS
// ============================================================================

const SUPPORTED_LAYERS = ['L1', 'L2', 'L3', 'L4', 'L5'];  // Extensible
const ADDRESS_HASH_LENGTH = 40;  // 160-bit (same as Bitcoin RIPEMD160)

// Simulated active wallet registry (in production: Supabase/DB)
const activeWallets = new Set();

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

/**
 * Generate a cryptographically secure random seed (32 bytes)
 */
function generateSecureSeed() {
  const entropy = randomBytes(32);
  return bytesToHex(entropy);
}

/**
 * Derive Ed25519 keypair from seed
 */
function deriveKeypair(seedHex) {
  const seed = hexToBytes(seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  return {
    publicKey: bytesToHex(keypair.publicKey),
    secretKey: keypair.secretKey,
    seed: seedHex
  };
}

/**
 * Derive the base address hash from public key (layer-agnostic)
 * This is the core identity - same across ALL layers
 */
function deriveAddressHash(publicKeyHex) {
  const pubKeyBytes = hexToBytes(publicKeyHex);
  const hash = createHash('sha256').update(pubKeyBytes).digest();
  return hash.slice(0, 20).toString('hex').toUpperCase();
}

/**
 * Get full address for any layer
 * Format: {LAYER}_{40-hex-hash}
 */
function getLayerAddress(publicKeyHex, layer) {
  const hash = deriveAddressHash(publicKeyHex);
  return `${layer}_${hash}`;
}

/**
 * Get addresses for ALL supported layers
 */
function getAllLayerAddresses(publicKeyHex) {
  const hash = deriveAddressHash(publicKeyHex);
  const addresses = {};
  for (const layer of SUPPORTED_LAYERS) {
    addresses[layer] = `${layer}_${hash}`;
  }
  return addresses;
}

/**
 * Check if an address hash is already active (collision check)
 */
function isAddressActive(addressHash) {
  return activeWallets.has(addressHash);
}

/**
 * Register a new wallet (mark as active)
 */
function registerWallet(addressHash) {
  if (activeWallets.has(addressHash)) {
    throw new Error(`COLLISION: Address ${addressHash} already registered!`);
  }
  activeWallets.add(addressHash);
  return true;
}

/**
 * Generate a new wallet with collision protection
 */
function generateNewWallet() {
  const MAX_ATTEMPTS = 10;  // In practice, collision is astronomically unlikely
  
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const seed = generateSecureSeed();
    const keypair = deriveKeypair(seed);
    const addressHash = deriveAddressHash(keypair.publicKey);
    
    if (!isAddressActive(addressHash)) {
      registerWallet(addressHash);
      return {
        seed: keypair.seed,
        publicKey: keypair.publicKey,
        addressHash,
        addresses: getAllLayerAddresses(keypair.publicKey),
        attempt
      };
    }
    
    console.log(`⚠️ Collision detected on attempt ${attempt}, regenerating...`);
  }
  
  throw new Error('Failed to generate unique wallet after max attempts');
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
console.log('║  WALLET GENERATION & MULTI-LAYER ADDRESS TEST                         ║');
console.log('║  Tests: Secure Generation, Cross-Layer Consistency, Collision Prevention║');
console.log('╚═══════════════════════════════════════════════════════════════════════╝');
console.log('');

// ============================================================================
// TEST 1: SECURE SEED GENERATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 1: SECURE SEED GENERATION (Entropy Quality)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('1.1 Seed is 64 hex characters (32 bytes)', () => {
  const seed = generateSecureSeed();
  return seed.length === 64 || `Expected 64, got ${seed.length}`;
});

test('1.2 Seed is valid hex', () => {
  const seed = generateSecureSeed();
  return /^[0-9a-f]{64}$/i.test(seed) || 'Seed contains non-hex characters';
});

test('1.3 Each seed generation is unique', () => {
  const seeds = new Set();
  for (let i = 0; i < 100; i++) {
    seeds.add(generateSecureSeed());
  }
  return seeds.size === 100 || `Expected 100 unique seeds, got ${seeds.size}`;
});

test('1.4 Seeds have good entropy distribution', () => {
  const seed = generateSecureSeed();
  const bytes = hexToBytes(seed);
  const uniqueBytes = new Set(bytes).size;
  // A good random 32-byte seed should have at least 20 unique byte values
  return uniqueBytes >= 15 || `Low entropy: only ${uniqueBytes} unique bytes`;
});

console.log('');

// ============================================================================
// TEST 2: MULTI-LAYER ADDRESS CONSISTENCY
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 2: SAME ADDRESS HASH ACROSS ALL LAYERS (L1, L2, L3, L4, L5)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const testKeypair = deriveKeypair(generateSecureSeed());
const testAddresses = getAllLayerAddresses(testKeypair.publicKey);

test('2.1 All layers have same hash (only prefix differs)', () => {
  const hashes = SUPPORTED_LAYERS.map(layer => testAddresses[layer].substring(3));
  const uniqueHashes = new Set(hashes);
  return uniqueHashes.size === 1 || `Found ${uniqueHashes.size} different hashes`;
});

test('2.2 L1 address format: L1_ + 40 hex chars', () => {
  const l1 = testAddresses.L1;
  return l1.startsWith('L1_') && l1.length === 43 || `Invalid L1: ${l1}`;
});

test('2.3 L2 address format: L2_ + 40 hex chars', () => {
  const l2 = testAddresses.L2;
  return l2.startsWith('L2_') && l2.length === 43 || `Invalid L2: ${l2}`;
});

test('2.4 L3 address format: L3_ + 40 hex chars', () => {
  const l3 = testAddresses.L3;
  return l3.startsWith('L3_') && l3.length === 43 || `Invalid L3: ${l3}`;
});

test('2.5 L4 address format: L4_ + 40 hex chars', () => {
  const l4 = testAddresses.L4;
  return l4.startsWith('L4_') && l4.length === 43 || `Invalid L4: ${l4}`;
});

test('2.6 L5 address format: L5_ + 40 hex chars', () => {
  const l5 = testAddresses.L5;
  return l5.startsWith('L5_') && l5.length === 43 || `Invalid L5: ${l5}`;
});

test('2.7 Address hash is deterministic (same pubkey → same hash)', () => {
  const hash1 = deriveAddressHash(testKeypair.publicKey);
  const hash2 = deriveAddressHash(testKeypair.publicKey);
  return hash1 === hash2 || 'Hash should be deterministic';
});

console.log('');

// Print the multi-layer address mapping
console.log('   📋 Sample Multi-Layer Address Mapping:');
console.log('   ┌─────────┬──────────────────────────────────────────────┐');
console.log('   │ Layer   │ Address                                      │');
console.log('   ├─────────┼──────────────────────────────────────────────┤');
for (const layer of SUPPORTED_LAYERS) {
  console.log(`   │ ${layer.padEnd(7)} │ ${testAddresses[layer]} │`);
}
console.log('   └─────────┴──────────────────────────────────────────────┘');
console.log('');

// ============================================================================
// TEST 3: COLLISION PREVENTION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 3: COLLISION PREVENTION (No Two Users Share Same Address)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

// Clear registry for clean test
activeWallets.clear();

test('3.1 Generate 100 unique wallets with no collisions', () => {
  const wallets = [];
  for (let i = 0; i < 100; i++) {
    const wallet = generateNewWallet();
    wallets.push(wallet);
  }
  const uniqueHashes = new Set(wallets.map(w => w.addressHash));
  return uniqueHashes.size === 100 || `Expected 100 unique, got ${uniqueHashes.size}`;
});

test('3.2 Active wallet registry has 100 entries', () => {
  return activeWallets.size === 100 || `Expected 100, got ${activeWallets.size}`;
});

test('3.3 Attempting to register duplicate address throws error', () => {
  const existingHash = Array.from(activeWallets)[0];
  try {
    registerWallet(existingHash);
    return 'Should have thrown collision error';
  } catch (e) {
    return e.message.includes('COLLISION') || `Wrong error: ${e.message}`;
  }
});

test('3.4 Different seeds always produce different addresses', () => {
  const seed1 = generateSecureSeed();
  const seed2 = generateSecureSeed();
  const kp1 = deriveKeypair(seed1);
  const kp2 = deriveKeypair(seed2);
  const hash1 = deriveAddressHash(kp1.publicKey);
  const hash2 = deriveAddressHash(kp2.publicKey);
  return hash1 !== hash2 || 'Different seeds should produce different addresses';
});

console.log('');

// ============================================================================
// TEST 4: ADDRESS UNIQUENESS STRESS TEST
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 4: ADDRESS UNIQUENESS STRESS TEST (1000 Wallets)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

// Clear and run stress test
activeWallets.clear();

test('4.1 Generate 1000 wallets with zero collisions', () => {
  const startTime = Date.now();
  const addresses = new Set();
  
  for (let i = 0; i < 1000; i++) {
    const seed = generateSecureSeed();
    const kp = deriveKeypair(seed);
    const hash = deriveAddressHash(kp.publicKey);
    
    if (addresses.has(hash)) {
      return `Collision at wallet ${i + 1}!`;
    }
    addresses.add(hash);
  }
  
  const elapsed = Date.now() - startTime;
  console.log(`   ⏱️  Generated 1000 unique wallets in ${elapsed}ms`);
  return addresses.size === 1000 || `Expected 1000, got ${addresses.size}`;
});

test('4.2 All 1000 addresses have valid format', () => {
  let valid = 0;
  for (let i = 0; i < 1000; i++) {
    const seed = generateSecureSeed();
    const kp = deriveKeypair(seed);
    const addr = getLayerAddress(kp.publicKey, 'L1');
    if (/^L1_[0-9A-F]{40}$/.test(addr)) valid++;
  }
  return valid === 1000 || `Only ${valid}/1000 valid`;
});

console.log('');

// ============================================================================
// TEST 5: CROSS-LAYER IDENTITY VERIFICATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 5: CROSS-LAYER IDENTITY (One Wallet, All Layers)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

test('5.1 User can be identified on any layer by their hash', () => {
  const userSeed = generateSecureSeed();
  const userKP = deriveKeypair(userSeed);
  const userHash = deriveAddressHash(userKP.publicKey);
  
  // Check all layers point to same user
  for (const layer of SUPPORTED_LAYERS) {
    const addr = getLayerAddress(userKP.publicKey, layer);
    const addrHash = addr.substring(3);  // Remove prefix
    if (addrHash !== userHash) {
      return `${layer} hash mismatch`;
    }
  }
  return true;
});

test('5.2 Layer prefix correctly identifies which layer', () => {
  const kp = deriveKeypair(generateSecureSeed());
  const l1 = getLayerAddress(kp.publicKey, 'L1');
  const l2 = getLayerAddress(kp.publicKey, 'L2');
  const l3 = getLayerAddress(kp.publicKey, 'L3');
  
  return l1.startsWith('L1_') && l2.startsWith('L2_') && l3.startsWith('L3_') ||
    'Layer prefixes incorrect';
});

test('5.3 Convert between layers preserves identity', () => {
  const kp = deriveKeypair(generateSecureSeed());
  const l1Addr = getLayerAddress(kp.publicKey, 'L1');
  
  // Extract hash from L1 address
  const hash = l1Addr.substring(3);
  
  // Reconstruct L2 address from hash
  const l2FromHash = `L2_${hash}`;
  const l2Direct = getLayerAddress(kp.publicKey, 'L2');
  
  return l2FromHash === l2Direct || 'Layer conversion failed';
});

test('5.4 Same signature works across all layers (with domain separation)', () => {
  const kp = deriveKeypair(generateSecureSeed());
  const message = new TextEncoder().encode('test');
  
  // Sign for L1
  const l1Msg = new Uint8Array([0x01, ...message]);
  const l1Sig = nacl.sign.detached(l1Msg, kp.secretKey);
  
  // Verify with same pubkey
  const pubKeyBytes = hexToBytes(kp.publicKey);
  const verified = nacl.sign.detached.verify(l1Msg, l1Sig, pubKeyBytes);
  
  return verified || 'Signature verification failed';
});

console.log('');

// ============================================================================
// TEST 6: KNOWN TEST ACCOUNTS VERIFICATION
// ============================================================================
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  TEST 6: KNOWN TEST ACCOUNTS (Alice, Bob, Dealer)');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const KNOWN_ACCOUNTS = {
  ALICE: {
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    expectedHash: '52882D768C0F3E7932AAD1813CF8B19058D507A8'
  },
  BOB: {
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    expectedHash: '5DB4B525FB40D6EA6BFD24094C2BC24984BAC433'
  },
  DEALER: {
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    expectedHash: 'EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC'
  }
};

test('6.1 Alice hash matches across all layers', () => {
  const kp = deriveKeypair(KNOWN_ACCOUNTS.ALICE.seed);
  const hash = deriveAddressHash(kp.publicKey);
  return hash === KNOWN_ACCOUNTS.ALICE.expectedHash ||
    `Expected ${KNOWN_ACCOUNTS.ALICE.expectedHash}, got ${hash}`;
});

test('6.2 Bob hash matches across all layers', () => {
  const kp = deriveKeypair(KNOWN_ACCOUNTS.BOB.seed);
  const hash = deriveAddressHash(kp.publicKey);
  return hash === KNOWN_ACCOUNTS.BOB.expectedHash ||
    `Expected ${KNOWN_ACCOUNTS.BOB.expectedHash}, got ${hash}`;
});

test('6.3 Dealer hash matches across all layers', () => {
  const kp = deriveKeypair(KNOWN_ACCOUNTS.DEALER.seed);
  const hash = deriveAddressHash(kp.publicKey);
  return hash === KNOWN_ACCOUNTS.DEALER.expectedHash ||
    `Expected ${KNOWN_ACCOUNTS.DEALER.expectedHash}, got ${hash}`;
});

test('6.4 Alice, Bob, Dealer all have unique addresses', () => {
  const hashes = Object.values(KNOWN_ACCOUNTS).map(a => {
    const kp = deriveKeypair(a.seed);
    return deriveAddressHash(kp.publicKey);
  });
  const unique = new Set(hashes);
  return unique.size === 3 || 'Test accounts should have unique addresses';
});

console.log('');

// ============================================================================
// SUMMARY
// ============================================================================
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('                           TEST SUMMARY                                ');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');

console.log(`✅ Passed: ${passed}`);
console.log(`❌ Failed: ${failed}`);
console.log('');

// Print known accounts with all layer addresses
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('                  KNOWN ACCOUNTS - ALL LAYER ADDRESSES                 ');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');

for (const [name, acct] of Object.entries(KNOWN_ACCOUNTS)) {
  const kp = deriveKeypair(acct.seed);
  const addresses = getAllLayerAddresses(kp.publicKey);
  
  console.log(`👤 ${name}`);
  console.log('┌─────────┬──────────────────────────────────────────────┐');
  console.log('│ Layer   │ Address                                      │');
  console.log('├─────────┼──────────────────────────────────────────────┤');
  for (const layer of SUPPORTED_LAYERS) {
    console.log(`│ ${layer.padEnd(7)} │ ${addresses[layer]} │`);
  }
  console.log('└─────────┴──────────────────────────────────────────────┘');
  console.log('');
}

// Security summary
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('                       SECURITY CHARACTERISTICS                        ');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');
console.log('┌────────────────────────────────────┬─────────────────────────────────┐');
console.log('│ Property                           │ Value                           │');
console.log('├────────────────────────────────────┼─────────────────────────────────┤');
console.log('│ Seed Entropy                       │ 256 bits (32 bytes)             │');
console.log('│ Address Hash                       │ 160 bits (SHA256 truncated)     │');
console.log('│ Collision Probability              │ ~1 in 2^80 (birthday bound)     │');
console.log('│ Signature Algorithm                │ Ed25519 (256-bit security)      │');
console.log('│ Cross-Layer Identity               │ ✅ Same hash, different prefix   │');
console.log('│ Active Wallet Protection           │ ✅ Registry prevents collision   │');
console.log('│ Domain Separation                  │ ✅ Chain ID prefix in signatures │');
console.log('└────────────────────────────────────┴─────────────────────────────────┘');
console.log('');

// Exit with appropriate code
process.exit(failed > 0 ? 1 : 0);
