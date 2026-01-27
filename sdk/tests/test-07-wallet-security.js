/**
 * TEST 07: Wallet Security Hardening
 * 
 * Tests:
 * - Password-based key derivation (PBKDF2/Argon2)
 * - Key encryption/decryption
 * - Auto-lock timeout simulation
 * - Key zeroing after lock
 * - Session signing security
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');

const L1_URL = 'http://localhost:8080';
const CHAIN_ID = 1;

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function section(title) {
    console.log(`\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}`);
    console.log(`${BLUE}  ${title}${RESET}`);
    console.log(`${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n`);
}

function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); return true; }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); return false; }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }

// ═══════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// PBKDF2 key derivation
async function deriveEncryptionKey(password, salt) {
    return new Promise((resolve, reject) => {
        const saltBuffer = Buffer.from(salt, 'hex');
        crypto.pbkdf2(password, saltBuffer, 100000, 32, 'sha512', (err, key) => {
            if (err) reject(err);
            else resolve(key);
        });
    });
}

// AES-256-GCM encryption
function encryptKey(keyBytes, encryptionKey) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(keyBytes), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return {
        iv: iv.toString('hex'),
        ciphertext: encrypted.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

// AES-256-GCM decryption
function decryptKey(encryptedData, encryptionKey) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Secure Session Class
class SecureSession {
    constructor(keyPair, timeoutMs = 600000) { // 10 min default
        this._keyPair = keyPair;
        this._isLocked = false;
        this._timeoutMs = timeoutMs;
        this._lastActivity = Date.now();
        
        // Auto-lock timer
        this._timer = setTimeout(() => this.lock(), timeoutMs);
    }
    
    get isLocked() {
        return this._isLocked;
    }
    
    get publicKey() {
        return this._keyPair ? Buffer.from(this._keyPair.publicKey).toString('hex') : null;
    }
    
    _refreshTimeout() {
        this._lastActivity = Date.now();
        clearTimeout(this._timer);
        this._timer = setTimeout(() => this.lock(), this._timeoutMs);
    }
    
    sign(message) {
        if (this._isLocked) throw new Error('Session locked');
        this._refreshTimeout();
        
        const msgBuffer = typeof message === 'string' ? Buffer.from(message) : message;
        return nacl.sign.detached(msgBuffer, this._keyPair.secretKey);
    }
    
    lock() {
        if (this._keyPair && this._keyPair.secretKey) {
            // Zero out secret key bytes
            this._keyPair.secretKey.fill(0);
        }
        this._keyPair = null;
        this._isLocked = true;
        clearTimeout(this._timer);
    }
}

async function runTests() {
    console.log(`\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${CYAN}║  TEST 07: WALLET SECURITY HARDENING                          ║${RESET}`);
    console.log(`${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}`);

    let passed = 0;
    let failed = 0;

    // Test 7.1: Key Derivation (PBKDF2)
    section('7.1 Password-Based Key Derivation');
    let derivedKey = null;
    try {
        const password = 'MySecureP@ssw0rd!';
        const salt = crypto.randomBytes(32).toString('hex');
        
        info(`Password: ${password}`);
        info(`Salt: ${salt.slice(0, 32)}...`);
        
        const startTime = Date.now();
        derivedKey = await deriveEncryptionKey(password, salt);
        const elapsedMs = Date.now() - startTime;
        
        pass(`Key derived in ${elapsedMs}ms`);
        info(`Derived Key: ${derivedKey.toString('hex').slice(0, 32)}...`);
        info('Using PBKDF2 with 100,000 iterations (SHA-512)');
        
        // Verify same password + salt = same key
        const derivedKey2 = await deriveEncryptionKey(password, salt);
        if (Buffer.compare(derivedKey, derivedKey2) === 0) {
            pass('Deterministic: Same password + salt = same key');
            passed++;
        } else {
            fail('Key derivation not deterministic!');
            failed++;
        }
        passed++;
    } catch (e) {
        fail(`Key derivation error: ${e.message}`);
        failed++;
    }

    // Test 7.2: Key Encryption/Decryption
    section('7.2 AES-256-GCM Key Encryption');
    try {
        const secretSeed = crypto.randomBytes(32);
        const encryptionKey = crypto.randomBytes(32);
        
        info(`Original Seed: ${secretSeed.toString('hex').slice(0, 32)}...`);
        
        const encrypted = encryptKey(secretSeed, encryptionKey);
        info(`Encrypted: ${encrypted.ciphertext.slice(0, 32)}...`);
        info(`IV: ${encrypted.iv}`);
        info(`AuthTag: ${encrypted.authTag}`);
        
        const decrypted = decryptKey(encrypted, encryptionKey);
        
        if (Buffer.compare(secretSeed, decrypted) === 0) {
            pass('Encryption/Decryption successful');
            passed++;
        } else {
            fail('Decrypted data does not match original');
            failed++;
        }
    } catch (e) {
        fail(`Encryption error: ${e.message}`);
        failed++;
    }

    // Test 7.3: Wrong Password Fails Decryption
    section('7.3 Wrong Password Rejection');
    try {
        const password1 = 'CorrectPassword123';
        const password2 = 'WrongPassword456';
        const salt = crypto.randomBytes(32).toString('hex');
        const secretSeed = crypto.randomBytes(32);
        
        const key1 = await deriveEncryptionKey(password1, salt);
        const encrypted = encryptKey(secretSeed, key1);
        
        const key2 = await deriveEncryptionKey(password2, salt);
        
        try {
            decryptKey(encrypted, key2);
            fail('SECURITY: Wrong password decrypted the key!');
            failed++;
        } catch (e) {
            pass('Wrong password correctly rejected');
            info(`Error: ${e.message}`);
            passed++;
        }
    } catch (e) {
        fail(`Wrong password test error: ${e.message}`);
        failed++;
    }

    // Test 7.4: Session Auto-Lock
    section('7.4 Session Auto-Lock');
    try {
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        
        // Create session with 100ms timeout for testing
        const session = new SecureSession(keyPair, 100);
        
        // Should work before timeout
        const sig1 = session.sign('test message');
        pass('Signing works before timeout');
        info(`Signature: ${Buffer.from(sig1).toString('hex').slice(0, 32)}...`);
        
        // Wait for timeout
        await new Promise(r => setTimeout(r, 150));
        
        // Should fail after timeout
        try {
            session.sign('another message');
            fail('SECURITY: Session signed after timeout!');
            failed++;
        } catch (e) {
            pass('Session auto-locked after timeout');
            info(`Error: ${e.message}`);
            passed++;
        }
        passed++;
    } catch (e) {
        fail(`Auto-lock test error: ${e.message}`);
        failed++;
    }

    // Test 7.5: Key Zeroing on Lock
    section('7.5 Key Zeroing on Lock');
    try {
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        const originalKey = Buffer.from(keyPair.secretKey);
        
        info(`Original secret (first 16 bytes): ${originalKey.slice(0, 16).toString('hex')}`);
        
        const session = new SecureSession(keyPair, 60000);
        session.lock();
        
        // Check if key was zeroed
        const allZero = keyPair.secretKey.every(b => b === 0);
        
        if (allZero) {
            pass('Secret key bytes zeroed after lock');
            info(`After lock (first 16 bytes): ${Buffer.from(keyPair.secretKey).slice(0, 16).toString('hex')}`);
            passed++;
        } else {
            fail('Secret key NOT zeroed after lock');
            failed++;
        }
    } catch (e) {
        fail(`Key zeroing test error: ${e.message}`);
        failed++;
    }

    // Test 7.6: Activity Refreshes Timeout
    section('7.6 Activity Refreshes Timeout');
    try {
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        
        // Create session with 200ms timeout
        const session = new SecureSession(keyPair, 200);
        
        // Activity at 100ms
        await new Promise(r => setTimeout(r, 100));
        session.sign('activity 1');
        
        // Activity at 200ms (would have locked without refresh)
        await new Promise(r => setTimeout(r, 100));
        session.sign('activity 2');
        
        // Activity at 300ms
        await new Promise(r => setTimeout(r, 100));
        const sig3 = session.sign('activity 3');
        
        pass('Activity refreshes timeout');
        info('Session still active at 300ms (original timeout was 200ms)');
        passed++;
    } catch (e) {
        fail(`Timeout refresh test error: ${e.message}`);
        failed++;
    }

    // Test 7.7: Signature Verification
    section('7.7 Signature Verification');
    try {
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        const session = new SecureSession(keyPair, 60000);
        
        const message = 'Important transaction data';
        const signature = session.sign(message);
        
        // Verify signature
        const isValid = nacl.sign.detached.verify(
            Buffer.from(message),
            signature,
            keyPair.publicKey
        );
        
        if (isValid) {
            pass('Signature verified with public key');
            passed++;
        } else {
            fail('Signature verification failed');
            failed++;
        }
        
        // Verify wrong message fails
        const isWrongValid = nacl.sign.detached.verify(
            Buffer.from('tampered message'),
            signature,
            keyPair.publicKey
        );
        
        if (!isWrongValid) {
            pass('Tampered message correctly rejected');
            passed++;
        } else {
            fail('SECURITY: Tampered message accepted!');
            failed++;
        }
    } catch (e) {
        fail(`Signature verification error: ${e.message}`);
        failed++;
    }

    // Test 7.8: Full Wallet Security Flow
    section('7.8 Full Security Flow (End-to-End)');
    try {
        // 1. User creates wallet
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        const publicKey = Buffer.from(keyPair.publicKey).toString('hex');
        const address = 'L1_' + crypto.createHash('sha256')
            .update(keyPair.publicKey).digest().slice(0, 20).toString('hex').toUpperCase();
        
        info(`1. Wallet created: ${address}`);
        
        // 2. User sets password, we derive encryption key
        const password = 'UserSecurePassword123!';
        const salt = crypto.randomBytes(32).toString('hex');
        const encKey = await deriveEncryptionKey(password, salt);
        
        info(`2. Password set, key derived`);
        
        // 3. Encrypt seed for storage
        const encryptedSeed = encryptKey(seed, encKey);
        
        info(`3. Seed encrypted for storage`);
        
        // 4. Simulate "login" - decrypt seed
        const decryptedSeed = decryptKey(encryptedSeed, encKey);
        const restoredKeyPair = nacl.sign.keyPair.fromSeed(decryptedSeed);
        
        info(`4. Login: seed decrypted`);
        
        // 5. Create secure session
        const session = new SecureSession(restoredKeyPair, 600000);
        
        info(`5. Secure session created`);
        
        // 6. Fund and transact
        await fetch(`${L1_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: address, amount: 100.0 })
        });
        
        info(`6. Wallet funded with 100 BB`);
        
        // 7. Create signed transaction
        const destSeed = crypto.randomBytes(32);
        const destKeyPair = nacl.sign.keyPair.fromSeed(destSeed);
        const destAddress = 'L1_' + crypto.createHash('sha256')
            .update(destKeyPair.publicKey).digest().slice(0, 20).toString('hex').toUpperCase();
        
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(8).toString('hex');
        const canonical = `${address}|${destAddress}|10|${timestamp}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        const domainPrefix = `BLACKBOOK_L${CHAIN_ID}/transfer`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        const signature = session.sign(message);
        
        info(`7. Transaction signed`);
        
        // 8. Verify the signature
        const isValid = nacl.sign.detached.verify(
            Buffer.from(message),
            signature,
            keyPair.publicKey
        );
        
        if (isValid) {
            pass('Full security flow completed successfully!');
            console.log(`
    ${GREEN}Security Flow Summary:${RESET}
    ✓ Seed generated securely
    ✓ Password-derived encryption key
    ✓ Seed encrypted with AES-256-GCM
    ✓ Login decrypts seed
    ✓ Session with auto-lock created
    ✓ Transaction signed with session
    ✓ Signature verified
`);
            passed++;
        } else {
            fail('Security flow signature verification failed');
            failed++;
        }
    } catch (e) {
        fail(`Full security flow error: ${e.message}`);
        failed++;
    }

    // Summary
    section('TEST SUMMARY');
    console.log(`  ${GREEN}Passed: ${passed}${RESET}`);
    console.log(`  ${failed > 0 ? RED : GREEN}Failed: ${failed}${RESET}`);
    
    if (failed === 0) {
        console.log(`\n  ${GREEN}✨ ALL SECURITY TESTS PASSED!${RESET}\n`);
    } else {
        console.log(`\n  ${RED}❌ SOME TESTS FAILED${RESET}\n`);
        process.exit(1);
    }
    
    return { passed, failed };
}

runTests().catch(console.error);

module.exports = { runTests, deriveEncryptionKey, encryptKey, decryptKey, SecureSession };
