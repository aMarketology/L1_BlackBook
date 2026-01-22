/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 01: Wallet Generation
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Generate new wallet with mnemonic
 * - Verify address format (L1_ prefix, 40 hex chars)
 * - Verify keypair is valid Ed25519
 * - Verify deterministic derivation (same seed = same keys)
 */

import nacl from 'tweetnacl';
import { TestResults, CONFIG } from './test-runner.js';

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

async function deriveAddress(publicKey) {
  const hash = await sha256(publicKey);
  const addressBytes = hash.slice(0, 20);
  return 'L1_' + bytesToHex(addressBytes).toUpperCase();
}

// BIP39 wordlist (first 100 words for testing)
const WORDLIST = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
  'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
  'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
  'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
  'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
  'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
  'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
  'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
  'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
  'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
  'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april',
  'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor',
  'army', 'around', 'arrange', 'arrest'
];

function generateMnemonic(wordCount = 12) {
  const entropy = crypto.getRandomValues(new Uint8Array(wordCount * 4 / 3));
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    const idx = entropy[i] % WORDLIST.length;
    words.push(WORDLIST[idx]);
  }
  return words.join(' ');
}

async function mnemonicToSeed(mnemonic) {
  const encoder = new TextEncoder();
  const mnemonicBytes = encoder.encode(mnemonic);
  const salt = encoder.encode('mnemonic');
  
  // Simple PBKDF2-like derivation for testing
  const hash = await sha256(new Uint8Array([...mnemonicBytes, ...salt]));
  return hash;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

export async function run() {
  process.stdout.write('\n╔════════════════════════════════════════════════════════════════╗\n');
  process.stdout.write('║  TEST 01: WALLET GENERATION                                    ║\n');
  process.stdout.write('╚════════════════════════════════════════════════════════════════╝\n\n');
  
  const results = new TestResults();
  
  // Test 1: Generate random keypair
  try {
    const keyPair = nacl.sign.keyPair();
    if (keyPair.publicKey.length !== 32) throw new Error('Invalid public key length');
    if (keyPair.secretKey.length !== 64) throw new Error('Invalid secret key length');
    results.pass('Generate random Ed25519 keypair');
  } catch (err) {
    results.fail('Generate random Ed25519 keypair', err);
  }
  
  // Test 2: Derive address from public key
  try {
    const keyPair = nacl.sign.keyPair();
    const address = await deriveAddress(keyPair.publicKey);
    
    if (!address.startsWith('L1_')) throw new Error('Address must start with L1_');
    if (address.length !== 43) throw new Error(`Address must be 43 chars, got ${address.length}`);
    if (!/^L1_[0-9A-F]{40}$/.test(address)) throw new Error('Invalid address format');
    
    results.pass('Derive L1 address from public key');
  } catch (err) {
    results.fail('Derive L1 address from public key', err);
  }
  
  // Test 3: Generate mnemonic
  try {
    const mnemonic = generateMnemonic(12);
    const words = mnemonic.split(' ');
    
    if (words.length !== 12) throw new Error('Mnemonic must be 12 words');
    words.forEach(word => {
      if (typeof word !== 'string' || word.length < 3) {
        throw new Error(`Invalid word: ${word}`);
      }
    });
    
    results.pass('Generate 12-word mnemonic');
  } catch (err) {
    results.fail('Generate 12-word mnemonic', err);
  }
  
  // Test 4: Deterministic key derivation (same seed = same keys)
  try {
    const testSeed = hexToBytes('18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24');
    
    const keyPair1 = nacl.sign.keyPair.fromSeed(testSeed);
    const keyPair2 = nacl.sign.keyPair.fromSeed(testSeed);
    
    const pub1 = bytesToHex(keyPair1.publicKey);
    const pub2 = bytesToHex(keyPair2.publicKey);
    
    if (pub1 !== pub2) throw new Error('Same seed should produce same keys');
    
    results.pass('Deterministic key derivation');
  } catch (err) {
    results.fail('Deterministic key derivation', err);
  }
  
  // Test 5: Verify known Alice keypair
  try {
    const aliceSeed = hexToBytes('18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24');
    const keyPair = nacl.sign.keyPair.fromSeed(aliceSeed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    
    const expectedPubKey = 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705';
    if (publicKeyHex !== expectedPubKey) {
      throw new Error(`Expected ${expectedPubKey}, got ${publicKeyHex}`);
    }
    
    const address = await deriveAddress(keyPair.publicKey);
    const expectedAddress = 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8';
    if (address !== expectedAddress) {
      throw new Error(`Expected ${expectedAddress}, got ${address}`);
    }
    
    results.pass('Verify Alice test account derivation');
  } catch (err) {
    results.fail('Verify Alice test account derivation', err);
  }
  
  // Test 6: Verify known Bob keypair
  try {
    const bobSeed = hexToBytes('e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b');
    const keyPair = nacl.sign.keyPair.fromSeed(bobSeed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    
    const expectedPubKey = '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a';
    if (publicKeyHex !== expectedPubKey) {
      throw new Error(`Expected ${expectedPubKey}, got ${publicKeyHex}`);
    }
    
    const address = await deriveAddress(keyPair.publicKey);
    const expectedAddress = 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433';
    if (address !== expectedAddress) {
      throw new Error(`Expected ${expectedAddress}, got ${address}`);
    }
    
    results.pass('Verify Bob test account derivation');
  } catch (err) {
    results.fail('Verify Bob test account derivation', err);
  }
  
  // Test 7: Unique addresses for different seeds
  try {
    const addresses = new Set();
    
    for (let i = 0; i < 10; i++) {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const keyPair = nacl.sign.keyPair.fromSeed(seed);
      const address = await deriveAddress(keyPair.publicKey);
      
      if (addresses.has(address)) {
        throw new Error('Collision detected!');
      }
      addresses.add(address);
    }
    
    results.pass('Unique addresses for different seeds (10 iterations)');
  } catch (err) {
    results.fail('Unique addresses for different seeds', err);
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
