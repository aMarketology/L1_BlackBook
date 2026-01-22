/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 02: Wallet Login (Import/Recovery)
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Import wallet from seed (hex)
 * - Import wallet from secret key
 * - Vault-based login (encrypted storage like Mac's wallet)
 * - Verify imported wallet can sign transactions
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet } from './test-runner.js';

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

// Vault decryption (AES-256-CBC with PBKDF2)
function decryptVault(encryptedBlob, password, salt) {
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 100000,
    hasher: CryptoJS.algo.SHA256
  });
  
  const decrypted = CryptoJS.AES.decrypt(encryptedBlob, key.toString());
  return decrypted.toString(CryptoJS.enc.Utf8);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

export async function run() {
  const results = new TestResults();
  
  // Test 1: Import Alice from seed
  try {
    const seed = hexToBytes(TEST_ACCOUNTS.ALICE.seed);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    
    if (publicKeyHex !== TEST_ACCOUNTS.ALICE.publicKey) {
      throw new Error('Public key mismatch');
    }
    
    results.pass('Import Alice from seed');
  } catch (err) {
    results.fail('Import Alice from seed', err);
  }
  
  // Test 2: Import Bob from seed
  try {
    const seed = hexToBytes(TEST_ACCOUNTS.BOB.seed);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    
    if (publicKeyHex !== TEST_ACCOUNTS.BOB.publicKey) {
      throw new Error('Public key mismatch');
    }
    
    results.pass('Import Bob from seed');
  } catch (err) {
    results.fail('Import Bob from seed', err);
  }
  
  // Test 3: Mac's vault-based login (encrypted seed)
  try {
    const { vault, password, publicKey } = TEST_ACCOUNTS.MAC;
    
    // Decrypt the vault
    const decryptedSeed = decryptVault(vault.encrypted_blob, password, vault.salt);
    
    if (!decryptedSeed || decryptedSeed.length !== 64) {
      throw new Error('Vault decryption failed');
    }
    
    // Derive keypair from decrypted seed
    const seed = hexToBytes(decryptedSeed);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const derivedPubKey = bytesToHex(keyPair.publicKey);
    
    if (derivedPubKey !== publicKey) {
      throw new Error(`Public key mismatch: expected ${publicKey}, got ${derivedPubKey}`);
    }
    
    results.pass('Mac vault-based login (password unlock)');
  } catch (err) {
    results.fail('Mac vault-based login', err);
  }
  
  // Test 4: Wrong password fails vault unlock
  try {
    const { vault } = TEST_ACCOUNTS.MAC;
    const wrongPassword = 'WrongPassword123!';
    
    const decrypted = decryptVault(vault.encrypted_blob, wrongPassword, vault.salt);
    
    // Wrong password should produce garbage or empty string
    if (decrypted && decrypted.length === 64 && /^[a-f0-9]+$/i.test(decrypted)) {
      throw new Error('Wrong password should not decrypt correctly');
    }
    
    results.pass('Wrong password fails vault unlock');
  } catch (err) {
    if (err.message.includes('should not decrypt')) {
      results.fail('Wrong password fails vault unlock', err);
    } else {
      // Expected - decryption failed or produced garbage
      results.pass('Wrong password fails vault unlock');
    }
  }
  
  // Test 5: Imported wallet can sign messages
  try {
    const seed = hexToBytes(TEST_ACCOUNTS.ALICE.seed);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    const message = new TextEncoder().encode('Test message for signing');
    const signature = nacl.sign.detached(message, keyPair.secretKey);
    
    if (signature.length !== 64) {
      throw new Error('Invalid signature length');
    }
    
    // Verify signature
    const valid = nacl.sign.detached.verify(message, signature, keyPair.publicKey);
    if (!valid) {
      throw new Error('Signature verification failed');
    }
    
    results.pass('Imported wallet can sign and verify');
  } catch (err) {
    results.fail('Imported wallet can sign and verify', err);
  }
  
  // Test 6: Verify account exists on chain (Alice)
  try {
    const response = await httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    if (typeof response.balance !== 'number' && typeof response.available !== 'number') {
      throw new Error('Balance not returned');
    }
    
    results.pass('Alice account exists on chain');
  } catch (err) {
    results.fail('Alice account exists on chain', err);
  }
  
  // Test 7: Verify account exists on chain (Bob)
  try {
    const response = await httpGet(`/balance/${TEST_ACCOUNTS.BOB.address}`);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    results.pass('Bob account exists on chain');
  } catch (err) {
    results.fail('Bob account exists on chain', err);
  }
  
  // Test 8: Verify Mac account exists on chain
  try {
    const response = await httpGet(`/balance/${TEST_ACCOUNTS.MAC.address}`);
    
    // Mac might be a new account with 0 balance
    if (response.error && !response.error.includes('not found')) {
      throw new Error(response.error);
    }
    
    results.pass('Mac account lookup works');
  } catch (err) {
    results.fail('Mac account lookup works', err);
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
