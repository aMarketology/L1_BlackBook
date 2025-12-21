/**
 * wallet-recovery.js - Shamir's Secret Sharing (SSS) Recovery System
 * 
 * Implements server-side SSS for user-friendly wallet recovery.
 * Users can recover their wallet with: PIN + Any 1 Backup (Cloud or Email)
 * 
 * Architecture:
 *   32-byte Seed → Split into 3 shares (threshold: 2 needed)
 *   Share 1: Server (encrypted with server key)
 *   Share 2: Cloud backup (encrypted with PIN)
 *   Share 3: Email backup (encrypted with PIN)
 * 
 * Security:
 *   - Server only has 1 share (cannot recover alone)
 *   - User needs PIN to decrypt their backups
 *   - 100k PBKDF2 iterations for PIN encryption
 *   - Non-custodial: server never has full private key
 */

import secrets from 'secrets.js-grempe';
import CryptoJS from 'crypto-js';

// ============================================================================
// CONSTANTS
// ============================================================================

/** Number of SSS shares to create */
const SHARE_COUNT = 3;

/** Number of shares needed to recover (threshold) */
const THRESHOLD = 2;

/** PBKDF2 iterations for PIN-based encryption (brute-force resistant) */
const PIN_PBKDF2_ITERATIONS = 100000;

/** Server encryption key length (must match backend) */
const SERVER_KEY_LENGTH = 32; // 256 bits

// ============================================================================
// SHAMIR'S SECRET SHARING (SSS) - Core Split/Combine
// ============================================================================

/**
 * Split a seed into multiple shares using Shamir's Secret Sharing
 * 
 * @param {string} seedHex - 64-character hex seed (32 bytes)
 * @param {number} [shares=SHARE_COUNT] - Number of shares to create
 * @param {number} [threshold=THRESHOLD] - Minimum shares needed to recover
 * @returns {Array<string>} Array of hex-encoded shares
 */
export function splitSeed(seedHex, shares = SHARE_COUNT, threshold = THRESHOLD) {
  if (!seedHex || seedHex.length !== 64) {
    throw new Error('Seed must be 64 hex characters (32 bytes)');
  }
  
  if (threshold > shares) {
    throw new Error(`Threshold (${threshold}) cannot exceed share count (${shares})`);
  }
  
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2 for security');
  }
  
  // secrets.js expects hex input, returns array of hex shares
  const shareArray = secrets.share(seedHex, shares, threshold);
  
  return shareArray;
}

/**
 * Recover seed from shares using Shamir's Secret Sharing
 * 
 * @param {Array<string>} shares - Array of hex-encoded shares (need THRESHOLD)
 * @returns {string} 64-character hex seed (32 bytes)
 */
export function recoverSeed(shares) {
  if (!shares || shares.length < THRESHOLD) {
    throw new Error(`Need at least ${THRESHOLD} shares to recover seed`);
  }
  
  try {
    // secrets.js combine via Lagrange interpolation
    const recovered = secrets.combine(shares);
    
    if (!recovered || recovered.length !== 64) {
      throw new Error('Recovery failed: invalid seed length');
    }
    
    return recovered;
  } catch (error) {
    throw new Error(`SSS recovery failed: ${error.message}`);
  }
}

// ============================================================================
// PIN-BASED ENCRYPTION (For User Backups - Shares 2 & 3)
// ============================================================================

/**
 * Derive encryption key from 6-digit PIN using PBKDF2
 * 
 * @param {string} pin - 6-digit PIN
 * @param {string} salt - Hex salt
 * @returns {string} 64-character hex key
 */
function derivePinKey(pin, salt) {
  if (!pin || pin.length !== 6 || !/^\d{6}$/.test(pin)) {
    throw new Error('PIN must be exactly 6 digits');
  }
  
  const key = CryptoJS.PBKDF2(pin, salt, {
    keySize: 256 / 32,
    iterations: PIN_PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA256
  });
  
  return key.toString(CryptoJS.enc.Hex);
}

/**
 * Encrypt an SSS share with a PIN using AES-256-GCM
 * 
 * Used for Share 2 (Cloud) and Share 3 (Email)
 * 
 * @param {string} shareHex - Hex-encoded SSS share
 * @param {string} pin - 6-digit PIN
 * @returns {Object} { encrypted, salt, nonce }
 */
export async function encryptShareWithPIN(shareHex, pin) {
  if (!shareHex) {
    throw new Error('Share cannot be empty');
  }
  
  // Generate random salt for PIN key derivation
  const saltBytes = new Uint8Array(32);
  crypto.getRandomValues(saltBytes);
  const salt = Array.from(saltBytes, b => b.toString(16).padStart(2, '0')).join('');
  
  // Derive key from PIN
  const pinKey = derivePinKey(pin, salt);
  
  // Generate random nonce (12 bytes for GCM)
  const nonceBytes = new Uint8Array(12);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes, b => b.toString(16).padStart(2, '0')).join('');
  
  // Convert share to bytes
  const shareBytes = new TextEncoder().encode(shareHex);
  
  // Import key for AES-GCM
  const keyBytes = new Uint8Array(pinKey.match(/.{2}/g).map(byte => parseInt(byte, 16)));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
    cryptoKey,
    shareBytes
  );
  
  // Base64 encode ciphertext
  const encrypted = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  
  return {
    encrypted,
    salt,
    nonce,
    version: 1,
    iterations: PIN_PBKDF2_ITERATIONS
  };
}

/**
 * Decrypt a PIN-encrypted SSS share
 * 
 * @param {string} encrypted - Base64 encrypted share
 * @param {string} salt - Hex salt
 * @param {string} nonce - Hex nonce
 * @param {string} pin - 6-digit PIN
 * @returns {Promise<string>} Decrypted hex share
 */
export async function decryptShareWithPIN(encrypted, salt, nonce, pin) {
  try {
    // Derive key from PIN
    const pinKey = derivePinKey(pin, salt);
    
    // Decode ciphertext from base64
    const ciphertext = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    
    // Convert nonce from hex to bytes
    const nonceBytes = new Uint8Array(nonce.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    
    // Import key for AES-GCM
    const keyBytes = new Uint8Array(pinKey.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Decrypt with AES-GCM
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
      cryptoKey,
      ciphertext
    );
    
    const decoded = new TextDecoder().decode(plaintext);
    return decoded;
  } catch (error) {
    throw new Error('Decryption failed - wrong PIN or corrupted share');
  }
}

// ============================================================================
// SERVER-SIDE ENCRYPTION (For Share 1 - Stored in Supabase)
// ============================================================================

/**
 * Encrypt an SSS share with server key using AES-256-GCM
 * 
 * Used for Share 1 (Server storage)
 * Server key must be stored in environment variable
 * 
 * @param {string} shareHex - Hex-encoded SSS share
 * @param {string} serverKeyHex - 64-character hex server key (from env)
 * @returns {Promise<Object>} { encrypted, nonce }
 */
export async function encryptServerShare(shareHex, serverKeyHex) {
  if (!shareHex) {
    throw new Error('Share cannot be empty');
  }
  
  if (!serverKeyHex || serverKeyHex.length !== 64) {
    throw new Error('Server key must be 64 hex characters (32 bytes)');
  }
  
  // Generate random nonce (12 bytes for GCM)
  const nonceBytes = new Uint8Array(12);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes, b => b.toString(16).padStart(2, '0')).join('');
  
  // Convert share to bytes
  const shareBytes = new TextEncoder().encode(shareHex);
  
  // Import server key for AES-GCM
  const keyBytes = new Uint8Array(serverKeyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
    cryptoKey,
    shareBytes
  );
  
  // Base64 encode ciphertext
  const encrypted = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  
  return {
    encrypted,
    nonce,
    version: 1
  };
}

/**
 * Decrypt a server-encrypted SSS share
 * 
 * @param {string} encrypted - Base64 encrypted share
 * @param {string} nonce - Hex nonce
 * @param {string} serverKeyHex - 64-character hex server key
 * @returns {Promise<string>} Decrypted hex share
 */
export async function decryptServerShare(encrypted, nonce, serverKeyHex) {
  try {
    // Decode ciphertext from base64
    const ciphertext = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    
    // Convert nonce from hex to bytes
    const nonceBytes = new Uint8Array(nonce.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    
    // Import server key for AES-GCM
    const keyBytes = new Uint8Array(serverKeyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Decrypt with AES-GCM
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
      cryptoKey,
      ciphertext
    );
    
    const decoded = new TextDecoder().decode(plaintext);
    return decoded;
  } catch (error) {
    throw new Error('Server share decryption failed - wrong key or corrupted data');
  }
}

// ============================================================================
// HIGH-LEVEL RECOVERY FUNCTIONS
// ============================================================================

/**
 * Create all 3 encrypted recovery shares from a seed
 * 
 * @param {string} seedHex - 64-character hex seed
 * @param {string} pin - 6-digit PIN for user backups
 * @param {string} serverKeyHex - Server encryption key
 * @returns {Promise<Object>} { serverShare, cloudShare, emailShare }
 */
export async function createRecoveryShares(seedHex, pin, serverKeyHex) {
  // 1. Split seed into 3 shares (threshold 2)
  const shares = splitSeed(seedHex, SHARE_COUNT, THRESHOLD);
  
  if (shares.length !== 3) {
    throw new Error(`Expected 3 shares, got ${shares.length}`);
  }
  
  // 2. Encrypt Share 1 with server key (for Supabase)
  const serverShare = await encryptServerShare(shares[0], serverKeyHex);
  
  // 3. Encrypt Share 2 with PIN (for Google Drive/iCloud)
  const cloudShare = await encryptShareWithPIN(shares[1], pin);
  
  // 4. Encrypt Share 3 with PIN (for Email)
  const emailShare = await encryptShareWithPIN(shares[2], pin);
  
  return {
    serverShare: {
      encrypted: serverShare.encrypted,
      nonce: serverShare.nonce,
      version: serverShare.version,
      location: 'server'
    },
    cloudShare: {
      encrypted: cloudShare.encrypted,
      salt: cloudShare.salt,
      nonce: cloudShare.nonce,
      version: cloudShare.version,
      iterations: cloudShare.iterations,
      location: 'cloud'
    },
    emailShare: {
      encrypted: emailShare.encrypted,
      salt: emailShare.salt,
      nonce: emailShare.nonce,
      version: emailShare.version,
      iterations: emailShare.iterations,
      location: 'email'
    }
  };
}

/**
 * Recover seed from server share + one user backup
 * 
 * @param {Object} serverShare - Encrypted server share
 * @param {Object} userShare - Encrypted user share (cloud or email)
 * @param {string} pin - 6-digit PIN
 * @param {string} serverKeyHex - Server encryption key
 * @returns {Promise<string>} Recovered 64-character hex seed
 */
export async function recoverSeedFromShares(serverShare, userShare, pin, serverKeyHex) {
  // 1. Decrypt server share
  const decryptedServerShare = await decryptServerShare(
    serverShare.encrypted,
    serverShare.nonce,
    serverKeyHex
  );
  
  // 2. Decrypt user share with PIN
  const decryptedUserShare = await decryptShareWithPIN(
    userShare.encrypted,
    userShare.salt,
    userShare.nonce,
    pin
  );
  
  // 3. Combine 2 shares to recover seed
  const recoveredSeed = recoverSeed([decryptedServerShare, decryptedUserShare]);
  
  return recoveredSeed;
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/**
 * Validate a 6-digit PIN
 * @param {string} pin
 * @returns {boolean}
 */
export function isValidPIN(pin) {
  return /^\d{6}$/.test(pin);
}

/**
 * Validate hex seed format
 * @param {string} seedHex
 * @returns {boolean}
 */
export function isValidSeed(seedHex) {
  return /^[0-9a-fA-F]{64}$/.test(seedHex);
}

/**
 * Test the full SSS recovery flow
 * @returns {Promise<boolean>} true if test passes
 */
export async function testRecoveryFlow() {
  console.log('🧪 Testing SSS Recovery Flow...\n');
  
  try {
    // 1. Generate test seed
    const testSeed = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const testPIN = '123456';
    const serverKey = '0000000000000000000000000000000000000000000000000000000000000000';
    
    console.log('1️⃣  Creating recovery shares...');
    const shares = await createRecoveryShares(testSeed, testPIN, serverKey);
    console.log('   ✅ Created 3 encrypted shares\n');
    
    console.log('2️⃣  Recovering seed from server + cloud shares...');
    const recovered = await recoverSeedFromShares(
      shares.serverShare,
      shares.cloudShare,
      testPIN,
      serverKey
    );
    console.log(`   Original: ${testSeed}`);
    console.log(`   Recovered: ${recovered}`);
    
    if (recovered === testSeed) {
      console.log('   ✅ Recovery successful!\n');
      
      console.log('3️⃣  Testing recovery with server + email shares...');
      const recovered2 = await recoverSeedFromShares(
        shares.serverShare,
        shares.emailShare,
        testPIN,
        serverKey
      );
      
      if (recovered2 === testSeed) {
        console.log('   ✅ Alternative recovery successful!\n');
        console.log('✅ ALL TESTS PASSED');
        return true;
      }
    }
    
    throw new Error('Recovery failed - seeds do not match');
  } catch (error) {
    console.error('❌ TEST FAILED:', error.message);
    return false;
  }
}

// Run test if executed directly
if (typeof process !== 'undefined' && process.argv[1] === new URL(import.meta.url).pathname) {
  testRecoveryFlow().then(passed => {
    process.exit(passed ? 0 : 1);
  });
}
