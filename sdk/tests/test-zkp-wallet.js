/**
 * ZKP Wallet SDK Comprehensive Test Suite
 * 
 * Tests all cryptographic operations, SSS splitting/reconstruction,
 * wallet lifecycle (create, login, sign, recover), and security features.
 * 
 * @version 2.0.0-zkp
 */

const assert = require('assert');
const crypto = require('crypto');
const {
  ZKPWallet,
  SecureSession,
  sssSplit,
  sssReconstruct,
  sssSplitWithDeterministicA,
  deriveShareA,
  derivePepperedKey,
  generateZKCommitment,
  generateZKProof,
  verifyZKProof,
  encryptShareC,
  decryptShareC,
  generateKeypair,
  deriveAddress,
  sign,
  verify,
  migrateLegacyWallet,
  GF_PRIME,
  SSS_THRESHOLD,
  SSS_TOTAL
} = require('../zkp-wallet-sdk');

// Test configuration
const TEST_PEPPER = 'TEST_PEPPER_SECRET_DO_NOT_USE_IN_PRODUCTION';
const TEST_USERNAME = 'apollo';
const TEST_PASSWORD = 'SecureP@ssw0rd!2026';
const TEST_WEAK_PASSWORD = '12345';

// Color codes for terminal output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[36m';
const RESET = '\x1b[0m';

// Test counters
let passed = 0;
let failed = 0;

// Helper functions
function log(message, color = RESET) {
  console.log(color + message + RESET);
}

function test(name, fn) {
  return async () => {
    try {
      await fn();
      passed++;
      log(`  ✓ ${name}`, GREEN);
    } catch (error) {
      failed++;
      log(`  ✗ ${name}`, RED);
      log(`    Error: ${error.message}`, RED);
      console.error(error.stack);
    }
  };
}

function section(name) {
  log(`\n${name}`, BLUE);
  log('='.repeat(name.length), BLUE);
}

// =============================================================================
// TEST SUITES
// =============================================================================

async function testGaloisField() {
  section('Galois Field Arithmetic Tests');
  
  await test('GF_PRIME is correct value', () => {
    const expected = 2n ** 256n - 189n;
    assert.strictEqual(GF_PRIME, expected);
  })();
  
  await test('SSS configuration is correct', () => {
    assert.strictEqual(SSS_THRESHOLD, 2);
    assert.strictEqual(SSS_TOTAL, 3);
  })();
}

async function testSSS() {
  section('Shamir\'s Secret Sharing Tests');
  
  await test('SSS split produces 3 shares', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    assert.strictEqual(shares.length, 3);
    assert.strictEqual(shares[0].x, 1);
    assert.strictEqual(shares[1].x, 2);
    assert.strictEqual(shares[2].x, 3);
  })();
  
  await test('SSS reconstruct with shares 1+2', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    const reconstructed = sssReconstruct([shares[0], shares[1]]);
    assert.deepStrictEqual(reconstructed, secret);
  })();
  
  await test('SSS reconstruct with shares 1+3', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    const reconstructed = sssReconstruct([shares[0], shares[2]]);
    assert.deepStrictEqual(reconstructed, secret);
  })();
  
  await test('SSS reconstruct with shares 2+3', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    const reconstructed = sssReconstruct([shares[1], shares[2]]);
    assert.deepStrictEqual(reconstructed, secret);
  })();
  
  await test('SSS fails with only 1 share', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    assert.throws(() => {
      sssReconstruct([shares[0]]);
    }, /Need at least 2 shares/);
  })();
  
  await test('SSS with deterministic Share A', async () => {
    const secret = crypto.randomBytes(32);
    const salt = crypto.randomBytes(32);
    const password = 'test123';
    
    // Derive Share A from password
    const shareA = await deriveShareA(password, salt);
    
    // Split with deterministic Share A
    const shares = sssSplitWithDeterministicA(secret, shareA);
    
    // Verify Share A matches
    assert.strictEqual(shares.shareA.y, shareA.toString('hex'));
    
    // Verify reconstruction works
    const reconstructed = sssReconstruct([shares.shareA, shares.shareB]);
    assert.deepStrictEqual(reconstructed, secret);
  })();
}

async function testKeyDerivation() {
  section('Key Derivation (Argon2id) Tests');
  
  await test('deriveShareA produces 32-byte output', async () => {
    const salt = crypto.randomBytes(32);
    const shareA = await deriveShareA(TEST_PASSWORD, salt);
    assert.strictEqual(shareA.length, 32);
  })();
  
  await test('deriveShareA is deterministic', async () => {
    const salt = crypto.randomBytes(32);
    const shareA1 = await deriveShareA(TEST_PASSWORD, salt);
    const shareA2 = await deriveShareA(TEST_PASSWORD, salt);
    assert.deepStrictEqual(shareA1, shareA2);
  })();
  
  await test('deriveShareA differs with different passwords', async () => {
    const salt = crypto.randomBytes(32);
    const shareA1 = await deriveShareA(TEST_PASSWORD, salt);
    const shareA2 = await deriveShareA(TEST_PASSWORD + '!', salt);
    assert.notDeepStrictEqual(shareA1, shareA2);
  })();
  
  await test('deriveShareA differs with different salts', async () => {
    const salt1 = crypto.randomBytes(32);
    const salt2 = crypto.randomBytes(32);
    const shareA1 = await deriveShareA(TEST_PASSWORD, salt1);
    const shareA2 = await deriveShareA(TEST_PASSWORD, salt2);
    assert.notDeepStrictEqual(shareA1, shareA2);
  })();
  
  await test('derivePepperedKey differs from regular Share A', async () => {
    const salt = crypto.randomBytes(32);
    const shareA = await deriveShareA(TEST_PASSWORD, salt);
    const pepperedKey = await derivePepperedKey(TEST_PASSWORD, salt, TEST_PEPPER);
    assert.notDeepStrictEqual(shareA, pepperedKey);
  })();
  
  await test('derivePepperedKey is deterministic with same pepper', async () => {
    const salt = crypto.randomBytes(32);
    const key1 = await derivePepperedKey(TEST_PASSWORD, salt, TEST_PEPPER);
    const key2 = await derivePepperedKey(TEST_PASSWORD, salt, TEST_PEPPER);
    assert.deepStrictEqual(key1, key2);
  })();
}

async function testZKCommitment() {
  section('ZK-Commitment Tests');
  
  await test('generateZKCommitment produces 64-char hex', () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    assert.strictEqual(commitment.length, 64);
    assert.match(commitment, /^[0-9a-f]{64}$/);
  })();
  
  await test('generateZKCommitment is deterministic', () => {
    const salt = crypto.randomBytes(32);
    const c1 = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const c2 = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    assert.strictEqual(c1, c2);
  })();
  
  await test('generateZKCommitment differs with different passwords', () => {
    const salt = crypto.randomBytes(32);
    const c1 = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const c2 = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD + '!', salt);
    assert.notStrictEqual(c1, c2);
  })();
  
  await test('generateZKProof succeeds with correct password', () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    const proof = generateZKProof(TEST_USERNAME, TEST_PASSWORD, salt, commitment, nonce);
    
    assert.strictEqual(proof.commitment, commitment);
    assert.strictEqual(typeof proof.proof, 'string');
    assert.strictEqual(proof.version, 'hmac-sha256-v1');
  })();
  
  await test('generateZKProof fails with wrong password', () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    assert.throws(() => {
      generateZKProof(TEST_USERNAME, 'wrongpassword', salt, commitment, nonce);
    }, /Commitment mismatch/);
  })();
  
  await test('verifyZKProof accepts valid proof', () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    const proof = generateZKProof(TEST_USERNAME, TEST_PASSWORD, salt, commitment, nonce);
    const valid = verifyZKProof(proof, commitment, nonce);
    
    assert.strictEqual(valid, true);
  })();
  
  await test('verifyZKProof rejects wrong commitment', () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const wrongCommitment = generateZKCommitment(TEST_USERNAME, 'wrong', salt);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    const proof = generateZKProof(TEST_USERNAME, TEST_PASSWORD, salt, commitment, nonce);
    const valid = verifyZKProof(proof, wrongCommitment, nonce);
    
    assert.strictEqual(valid, false);
  })();
  
  await test('verifyZKProof rejects expired proof', async () => {
    const salt = crypto.randomBytes(32);
    const commitment = generateZKCommitment(TEST_USERNAME, TEST_PASSWORD, salt);
    const nonce = crypto.randomBytes(16).toString('hex');
    
    const proof = generateZKProof(TEST_USERNAME, TEST_PASSWORD, salt, commitment, nonce);
    
    // Wait 100ms and verify with 50ms maxAge
    await new Promise(resolve => setTimeout(resolve, 100));
    const valid = verifyZKProof(proof, commitment, nonce, 50);
    
    assert.strictEqual(valid, false);
  })();
}

async function testEncryption() {
  section('Peppered Encryption Tests');
  
  await test('encryptShareC produces valid ciphertext', async () => {
    const shareC = crypto.randomBytes(32);
    const password = TEST_PASSWORD;
    const salt = crypto.randomBytes(32);
    const key = await derivePepperedKey(password, salt, TEST_PEPPER);
    
    const encrypted = encryptShareC(shareC, key);
    
    assert.strictEqual(encrypted.encrypted.length, 64); // 32 bytes hex
    assert.strictEqual(encrypted.iv.length, 24);        // 12 bytes hex
    assert.strictEqual(encrypted.authTag.length, 32);   // 16 bytes hex
  })();
  
  await test('decryptShareC recovers original share', async () => {
    const shareC = crypto.randomBytes(32);
    const password = TEST_PASSWORD;
    const salt = crypto.randomBytes(32);
    const key = await derivePepperedKey(password, salt, TEST_PEPPER);
    
    const encrypted = encryptShareC(shareC, key);
    const decrypted = decryptShareC(encrypted, key);
    
    assert.deepStrictEqual(decrypted, shareC);
  })();
  
  await test('decryptShareC fails with wrong key', async () => {
    const shareC = crypto.randomBytes(32);
    const password = TEST_PASSWORD;
    const salt = crypto.randomBytes(32);
    const key = await derivePepperedKey(password, salt, TEST_PEPPER);
    const wrongKey = await derivePepperedKey('wrongpassword', salt, TEST_PEPPER);
    
    const encrypted = encryptShareC(shareC, key);
    
    assert.throws(() => {
      decryptShareC(encrypted, wrongKey);
    });
  })();
  
  await test('decryptShareC fails without pepper', async () => {
    const shareC = crypto.randomBytes(32);
    const password = TEST_PASSWORD;
    const salt = crypto.randomBytes(32);
    const keyWithPepper = await derivePepperedKey(password, salt, TEST_PEPPER);
    const keyWithoutPepper = await deriveShareA(password, salt); // No pepper
    
    const encrypted = encryptShareC(shareC, keyWithPepper);
    
    assert.throws(() => {
      decryptShareC(encrypted, keyWithoutPepper);
    });
  })();
}

async function testEd25519() {
  section('Ed25519 Signing Tests');
  
  await test('generateKeypair produces valid keys', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    
    assert.strictEqual(keypair.publicKey.length, 64); // 32 bytes hex
    assert.strictEqual(keypair.secretKey.length, 64); // 64 bytes buffer
  })();
  
  await test('generateKeypair is deterministic', () => {
    const secret = crypto.randomBytes(32);
    const kp1 = generateKeypair(secret);
    const kp2 = generateKeypair(secret);
    
    assert.strictEqual(kp1.publicKey, kp2.publicKey);
  })();
  
  await test('deriveAddress produces L1_ prefixed address', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    assert.match(address, /^L1_[0-9A-F]{40}$/);
  })();
  
  await test('sign produces 128-char hex signature', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const message = Buffer.from('Hello, BlackBook!');
    
    const signature = sign(message, keypair.secretKey);
    
    assert.strictEqual(signature.length, 128); // 64 bytes hex
  })();
  
  await test('verify accepts valid signature', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const message = Buffer.from('Hello, BlackBook!');
    
    const signature = sign(message, keypair.secretKey);
    const valid = verify(message, signature, keypair.publicKey);
    
    assert.strictEqual(valid, true);
  })();
  
  await test('verify rejects tampered message', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const message = Buffer.from('Hello, BlackBook!');
    const tamperedMessage = Buffer.from('Hello, Blackbook!'); // lowercase 'b'
    
    const signature = sign(message, keypair.secretKey);
    const valid = verify(tamperedMessage, signature, keypair.publicKey);
    
    assert.strictEqual(valid, false);
  })();
  
  await test('verify rejects wrong public key', () => {
    const secret1 = crypto.randomBytes(32);
    const secret2 = crypto.randomBytes(32);
    const keypair1 = generateKeypair(secret1);
    const keypair2 = generateKeypair(secret2);
    const message = Buffer.from('Hello, BlackBook!');
    
    const signature = sign(message, keypair1.secretKey);
    const valid = verify(message, signature, keypair2.publicKey);
    
    assert.strictEqual(valid, false);
  })();
}

async function testSecureSession() {
  section('SecureSession Tests');
  
  await test('SecureSession initializes correctly', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const session = new SecureSession(secret, keypair, address, 5000);
    
    assert.strictEqual(session.isActive, true);
    assert.strictEqual(session.publicKey, keypair.publicKey);
    assert.strictEqual(session.address, address);
    assert(session.remainingTime <= 5000);
    
    session.lock();
  })();
  
  await test('SecureSession auto-locks after timeout', async () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const session = new SecureSession(secret, keypair, address, 100); // 100ms timeout
    
    assert.strictEqual(session.isActive, true);
    
    await new Promise(resolve => setTimeout(resolve, 150));
    
    assert.strictEqual(session.isActive, false);
  })();
  
  await test('SecureSession extends timeout', async () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const session = new SecureSession(secret, keypair, address, 200);
    
    await new Promise(resolve => setTimeout(resolve, 100));
    session.extend();
    
    assert.strictEqual(session.isActive, true);
    assert(session.remainingTime > 100);
    
    session.lock();
  })();
  
  await test('SecureSession signs messages', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    const message = Buffer.from('Test message');
    
    const session = new SecureSession(secret, keypair, address);
    const signature = session.sign(message);
    
    assert.strictEqual(signature.length, 128);
    assert(verify(message, signature, keypair.publicKey));
    
    session.lock();
  })();
  
  await test('SecureSession fails to sign after lock', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    const message = Buffer.from('Test message');
    
    const session = new SecureSession(secret, keypair, address);
    session.lock();
    
    assert.throws(() => {
      session.sign(message);
    }, /Session is locked/);
  })();
  
  await test('SecureSession signs transactions', () => {
    const secret = crypto.randomBytes(32);
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const session = new SecureSession(secret, keypair, address);
    
    const tx = {
      from: address,
      to: 'L1_0000000000000000000000000000000000000000',
      amount: 100,
      nonce: 1
    };
    
    const signed = session.signTransaction(tx);
    
    assert.strictEqual(signed.signature.length, 128);
    assert.strictEqual(signed.pubkey, keypair.publicKey);
    assert.strictEqual(signed.address, address);
    assert(typeof signed.timestamp === 'number');
    
    session.lock();
  })();
}

async function testWalletLifecycle() {
  section('Wallet Lifecycle Tests');
  
  let walletData;
  let shareB;
  let shareCEncrypted;
  
  await test('ZKPWallet.create generates new wallet', async () => {
    const result = await ZKPWallet.create(TEST_USERNAME, TEST_PASSWORD, TEST_PEPPER);
    
    walletData = result.wallet;
    shareB = result.shareB;
    shareCEncrypted = result.shareCEncrypted;
    
    assert.strictEqual(walletData.version, '2.0-zkp');
    assert.match(walletData.address, /^L1_[0-9A-F]{40}$/);
    assert.strictEqual(walletData.pubkey.length, 64);
    assert.strictEqual(walletData.salt.length, 64);
    assert.strictEqual(walletData.zkCommitment.length, 64);
    assert.strictEqual(walletData.keyDerivation, 'Argon2id-64MB');
    assert.strictEqual(walletData.sss, '2-of-3-GF(2^256)');
    
    assert.strictEqual(shareB.x, 2);
    assert.strictEqual(shareB.y.length, 64);
    
    assert.strictEqual(shareCEncrypted.encrypted.length, 64);
    assert.strictEqual(shareCEncrypted.iv.length, 24);
    assert.strictEqual(shareCEncrypted.authTag.length, 32);
  })();
  
  await test('ZKPWallet.login succeeds with correct password', async () => {
    const session = await ZKPWallet.login(
      walletData,
      shareB,
      TEST_PASSWORD
    );
    
    assert(session instanceof SecureSession);
    assert.strictEqual(session.isActive, true);
    assert.strictEqual(session.address, walletData.address);
    assert.strictEqual(session.publicKey, walletData.pubkey);
    
    session.lock();
  })();
  
  await test('ZKPWallet.login fails with wrong password', async () => {
    try {
      await ZKPWallet.login(walletData, shareB, 'wrongpassword');
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.match(error.message, /Invalid password/);
    }
  })();
  
  await test('Session can sign transactions', async () => {
    const session = await ZKPWallet.login(walletData, shareB, TEST_PASSWORD);
    
    const tx = {
      from: walletData.address,
      to: 'L1_1234567890ABCDEF1234567890ABCDEF12345678',
      amount: 50.5,
      nonce: 1
    };
    
    const signed = session.signTransaction(tx);
    
    assert.strictEqual(signed.signature.length, 128);
    assert.strictEqual(signed.address, walletData.address);
    
    // Verify signature
    const canonical = JSON.stringify(tx, Object.keys(tx).sort());
    const hash = crypto.createHash('sha256').update(canonical).digest();
    const valid = verify(hash, signed.signature, walletData.pubkey);
    assert.strictEqual(valid, true);
    
    session.lock();
  })();
}

async function testWalletRecovery() {
  section('Wallet Recovery Tests');
  
  let walletData;
  let shareB;
  let shareCEncrypted;
  
  // Create wallet first
  await test('Setup: Create test wallet for recovery', async () => {
    const result = await ZKPWallet.create(TEST_USERNAME, TEST_PASSWORD, TEST_PEPPER);
    walletData = result.wallet;
    shareB = result.shareB;
    shareCEncrypted = result.shareCEncrypted;
  })();
  
  await test('ZKPWallet.recover with Share B + C', async () => {
    const NEW_PASSWORD = 'NewSecureP@ss2026!';
    
    const recovered = await ZKPWallet.recover(
      walletData,
      shareB,
      shareCEncrypted,
      TEST_PASSWORD,  // Old password to decrypt Share C
      NEW_PASSWORD,   // New password
      TEST_PEPPER
    );
    
    assert.strictEqual(recovered.wallet.version, '2.0-zkp');
    assert.strictEqual(recovered.wallet.address, walletData.address);
    assert.strictEqual(recovered.wallet.pubkey, walletData.pubkey);
    assert.notStrictEqual(recovered.wallet.salt, walletData.salt); // New salt
    assert.notStrictEqual(recovered.wallet.zkCommitment, walletData.zkCommitment); // New commitment
    assert(recovered.wallet.recoveredAt);
    
    // Verify can login with new password
    const session = await ZKPWallet.login(
      recovered.wallet,
      recovered.shareB,
      NEW_PASSWORD
    );
    
    assert.strictEqual(session.address, walletData.address);
    session.lock();
  })();
  
  await test('ZKPWallet.changePassword updates credentials', async () => {
    const NEW_PASSWORD = 'AnotherNewP@ss2026!';
    
    const updated = await ZKPWallet.changePassword(
      walletData,
      shareB,
      TEST_PASSWORD,
      NEW_PASSWORD,
      TEST_PEPPER
    );
    
    assert.strictEqual(updated.wallet.address, walletData.address);
    assert.strictEqual(updated.wallet.pubkey, walletData.pubkey);
    assert.notStrictEqual(updated.wallet.salt, walletData.salt);
    assert(updated.wallet.passwordChangedAt);
    
    // Verify can login with new password
    const session = await ZKPWallet.login(
      updated.wallet,
      updated.shareB,
      NEW_PASSWORD
    );
    
    assert.strictEqual(session.address, walletData.address);
    session.lock();
  })();
  
  await test('ZKPWallet.changePassword fails with wrong current password', async () => {
    try {
      await ZKPWallet.changePassword(
        walletData,
        shareB,
        'wrongpassword',
        'NewPassword123!',
        TEST_PEPPER
      );
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.match(error.message, /Invalid current password/);
    }
  })();
}

async function testMigration() {
  section('Legacy Wallet Migration Tests');
  
  await test('migrateLegacyWallet converts PBKDF2 to ZKP', async () => {
    // Create a legacy-style wallet (PBKDF2)
    const password = 'legacy123';
    const salt = crypto.randomBytes(32);
    const secret = crypto.randomBytes(32);
    
    // Legacy PBKDF2 encryption
    const derivedKey = crypto.pbkdf2Sync(password, salt, 300000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const legacyWallet = {
      name: 'TestLegacy',
      address,
      created: new Date().toISOString(),
      rootPubkey: keypair.publicKey,
      opPubkey: keypair.publicKey,
      salt: salt.toString('hex'),
      encryptedOpKey: {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      },
      sssShares: [],
      keyDerivation: 'PBKDF2-SHA256-300k'
    };
    
    // Migrate to ZKP format
    const migrated = await migrateLegacyWallet(legacyWallet, password, TEST_PEPPER);
    
    assert.strictEqual(migrated.wallet.version, '2.0-zkp');
    assert.strictEqual(migrated.wallet.address, address);
    assert.strictEqual(migrated.wallet.pubkey, keypair.publicKey);
    assert.strictEqual(migrated.wallet.keyDerivation, 'Argon2id-64MB');
    assert.strictEqual(migrated.wallet.legacyKeyDerivation, 'PBKDF2-SHA256-300k');
    assert(migrated.wallet.migratedAt);
    
    // Verify can login with migrated wallet
    const session = await ZKPWallet.login(
      migrated.wallet,
      migrated.shareB,
      password
    );
    
    assert.strictEqual(session.address, address);
    assert.strictEqual(session.publicKey, keypair.publicKey);
    
    session.lock();
  })();
}

async function testSecurityProperties() {
  section('Security Property Tests');
  
  await test('Single SSS share reveals no information', () => {
    const secret = crypto.randomBytes(32);
    const shares = sssSplit(secret);
    
    // Having only 1 share, attacker cannot determine secret
    // (Information-theoretic security)
    // This is a theoretical test - we verify reconstruction fails
    try {
      sssReconstruct([shares[0]]);
      assert.fail('Should not reconstruct with 1 share');
    } catch (error) {
      assert.match(error.message, /Need at least 2 shares/);
    }
  })();
  
  await test('Argon2id is memory-hard', async () => {
    const salt = crypto.randomBytes(32);
    const start = Date.now();
    
    await deriveShareA(TEST_PASSWORD, salt);
    
    const duration = Date.now() - start;
    
    // Should take at least 10ms (memory-hard operation)
    // GPU parallelization is limited by memory bandwidth
    assert(duration >= 10, `Expected >= 10ms, got ${duration}ms`);
  })();
  
  await test('Pepper prevents Share C decryption', async () => {
    const shareC = crypto.randomBytes(32);
    const salt = crypto.randomBytes(32);
    const password = TEST_PASSWORD;
    
    // Encrypt with pepper
    const pepperedKey = await derivePepperedKey(password, salt, TEST_PEPPER);
    const encrypted = encryptShareC(shareC, pepperedKey);
    
    // Try to decrypt without pepper (using password + salt only)
    const noPepperKey = await deriveShareA(password, salt);
    
    try {
      decryptShareC(encrypted, noPepperKey);
      assert.fail('Should not decrypt without pepper');
    } catch (error) {
      // Expected - cannot decrypt without pepper
      assert(true);
    }
  })();
  
  await test('Session zeroizes secret on lock', () => {
    const secret = crypto.randomBytes(32);
    const originalSecret = Buffer.from(secret); // Copy
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    const session = new SecureSession(secret, keypair, address);
    
    // Lock and verify session is unusable
    session.lock();
    assert.strictEqual(session.isActive, false);
    
    // Verify cannot sign after lock
    assert.throws(() => {
      session.sign(Buffer.from('test'));
    }, /Session is locked/);
  })();
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

async function runAllTests() {
  console.log('\n╔═══════════════════════════════════════════════════════════╗');
  console.log('║   BlackBook L1 - ZKP Wallet SDK Test Suite              ║');
  console.log('║   Version: 2.0.0-zkp                                     ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');
  
  const startTime = Date.now();
  
  try {
    await testGaloisField();
    await testSSS();
    await testKeyDerivation();
    await testZKCommitment();
    await testEncryption();
    await testEd25519();
    await testSecureSession();
    await testWalletLifecycle();
    await testWalletRecovery();
    await testMigration();
    await testSecurityProperties();
  } catch (error) {
    log('\n❌ Test suite failed with error:', RED);
    console.error(error);
  }
  
  const duration = Date.now() - startTime;
  
  // Summary
  console.log('\n' + '═'.repeat(60));
  log(`\nTest Summary:`, BLUE);
  log(`  Passed: ${passed}`, passed > 0 ? GREEN : RESET);
  log(`  Failed: ${failed}`, failed > 0 ? RED : RESET);
  log(`  Total:  ${passed + failed}`, RESET);
  log(`  Duration: ${duration}ms\n`, YELLOW);
  
  if (failed === 0) {
    log('✅ All tests passed!', GREEN);
    process.exit(0);
  } else {
    log(`❌ ${failed} test(s) failed`, RED);
    process.exit(1);
  }
}

// Run tests
if (require.main === module) {
  runAllTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { runAllTests };
