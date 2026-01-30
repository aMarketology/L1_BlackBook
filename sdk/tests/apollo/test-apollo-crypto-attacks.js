/**
 * APOLLO WALLET - ADVANCED CRYPTOGRAPHIC ATTACK TESTS
 * Tests for sophisticated cryptographic vulnerabilities
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load wallet data
const walletDataPath = path.join(__dirname, 'apollo-wallet-data.json');
const walletData = JSON.parse(fs.readFileSync(walletDataPath, 'utf8'));

const APOLLO_ADDRESS = walletData.address;
const APOLLO_PASSWORD = 'ApolloMissionControl2026!';

// Colors
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

let testResults = { total: 0, passed: 0, failed: 0, warnings: 0 };

function section(title) {
    console.log(`\n${colors.cyan}${'='.repeat(70)}\n${title}\n${'='.repeat(70)}${colors.reset}\n`);
}

function success(msg) {
    console.log(`${colors.green}✓ ${msg}${colors.reset}`);
    testResults.passed++;
    testResults.total++;
}

function fail(msg) {
    console.log(`${colors.red}✗ ${msg}${colors.reset}`);
    testResults.failed++;
    testResults.total++;
}

function warning(msg) {
    console.log(`${colors.yellow}⚠ ${msg}${colors.reset}`);
    testResults.warnings++;
}

function info(msg) {
    console.log(`${colors.blue}ℹ ${msg}${colors.reset}`);
}

// =============================================================================
// CRYPTO ATTACK 1: AES-GCM IV Reuse Detection
// =============================================================================
function testIVReuse() {
    section('CRYPTO ATTACK 1: AES-GCM IV Reuse Detection');
    
    info('Checking for IV reuse vulnerabilities...');
    
    const iv = walletData.encryptedOpKey.iv;
    const ivBuffer = Buffer.from(iv, 'hex');
    
    // IV should be 12 bytes for AES-GCM
    if (ivBuffer.length === 12) {
        success('IV length is correct (12 bytes for AES-GCM)');
    } else {
        fail(`IV length is incorrect: ${ivBuffer.length} bytes (should be 12)`);
    }
    
    // Check for all-zero IV (critical vulnerability)
    const allZeros = ivBuffer.every(byte => byte === 0);
    if (allZeros) {
        fail('CRITICAL: IV is all zeros - catastrophic security failure!');
    } else {
        success('IV is not all zeros');
    }
    
    // Check for low entropy IV
    const uniqueBytes = new Set(ivBuffer).size;
    if (uniqueBytes < 8) {
        warning(`IV has low entropy: only ${uniqueBytes} unique bytes`);
    } else {
        success('IV appears to have good entropy');
    }
    
    // In production, we should check if IV is ever reused across multiple encryptions
    // For now, we'll just verify it looks random
    info(`IV: ${iv}`);
}

// =============================================================================
// CRYPTO ATTACK 2: Authentication Tag Verification
// =============================================================================
function testAuthTagIntegrity() {
    section('CRYPTO ATTACK 2: Authentication Tag Verification');
    
    info('Testing GCM authentication tag integrity...');
    
    const authTag = walletData.encryptedOpKey.authTag;
    const authTagBuffer = Buffer.from(authTag, 'hex');
    
    // Auth tag should be 16 bytes for GCM
    if (authTagBuffer.length === 16) {
        success('Auth tag length is correct (16 bytes)');
    } else {
        fail(`Auth tag length is incorrect: ${authTagBuffer.length} bytes`);
    }
    
    // Try to decrypt with tampered ciphertext (should fail)
    const encrypted = Buffer.from(walletData.encryptedOpKey.encrypted, 'hex');
    const tamperedCiphertext = Buffer.from(encrypted);
    tamperedCiphertext[0] ^= 0xFF; // Flip all bits in first byte
    
    info('Testing tamper detection...');
    
    try {
        // Derive key from password (simplified - actual implementation should match SDK)
        const salt = Buffer.from(walletData.salt, 'hex');
        const key = crypto.pbkdf2Sync(APOLLO_PASSWORD, salt, 300000, 32, 'sha256');
        const iv = Buffer.from(walletData.encryptedOpKey.iv, 'hex');
        
        // Try to decrypt tampered data
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTagBuffer);
        
        let decrypted = decipher.update(tamperedCiphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        // If we get here, tamper detection failed
        fail('CRITICAL: Tampered ciphertext was accepted - auth tag not verified!');
        
    } catch (error) {
        if (error.message.includes('Unsupported state') || 
            error.message.includes('authentication') ||
            error.message.includes('tag')) {
            success('Tamper detection working - tampered data rejected');
        } else {
            warning(`Unexpected error during tamper test: ${error.message}`);
        }
    }
}

// =============================================================================
// CRYPTO ATTACK 3: Weak Key Derivation Detection
// =============================================================================
function testKeyDerivationStrength() {
    section('CRYPTO ATTACK 3: Key Derivation Strength');
    
    info('Analyzing key derivation parameters...');
    
    const expectedIterations = 300000;
    const expectedAlgorithm = 'PBKDF2-SHA256-300k';
    
    if (walletData.keyDerivation === expectedAlgorithm) {
        success(`Key derivation uses strong parameters: ${expectedAlgorithm}`);
    } else {
        fail(`Weak key derivation: ${walletData.keyDerivation}`);
    }
    
    // Test actual derivation speed
    info('Benchmarking key derivation speed...');
    
    const testPassword = 'TestPassword123!';
    const testSalt = crypto.randomBytes(32);
    
    const start = Date.now();
    crypto.pbkdf2Sync(testPassword, testSalt, expectedIterations, 32, 'sha256');
    const elapsed = Date.now() - start;
    
    info(`Key derivation took ${elapsed}ms for ${expectedIterations} iterations`);
    
    if (elapsed < 50) {
        warning('Key derivation is very fast - may be vulnerable to brute force');
    } else if (elapsed < 200) {
        info('Key derivation speed is acceptable but could be stronger');
    } else {
        success('Key derivation is sufficiently slow to resist brute force');
    }
    
    // Check salt quality
    const salt = Buffer.from(walletData.salt, 'hex');
    if (salt.length === 32) {
        success('Salt is proper length (32 bytes)');
    } else {
        fail(`Salt length is incorrect: ${salt.length} bytes`);
    }
}

// =============================================================================
// CRYPTO ATTACK 4: Shamir Secret Sharing Integrity
// =============================================================================
function testShamirSecretSharing() {
    section('CRYPTO ATTACK 4: Shamir Secret Sharing Security');
    
    info('Testing SSS implementation security...');
    
    const shares = walletData.sssShares;
    
    // Verify we have exactly 3 shares
    if (shares.length === 3) {
        success('Correct number of shares (3) for 2-of-3 scheme');
    } else {
        fail(`Incorrect number of shares: ${shares.length}`);
    }
    
    // Verify x coordinates are correct
    const xCoords = shares.map(s => s.x);
    const expectedX = [1, 2, 3];
    
    if (JSON.stringify(xCoords) === JSON.stringify(expectedX)) {
        success('X coordinates are correct [1, 2, 3]');
    } else {
        fail(`X coordinates are incorrect: [${xCoords}]`);
    }
    
    // Check that shares are not equal
    const share1 = shares[0].y;
    const share2 = shares[1].y;
    const share3 = shares[2].y;
    
    if (share1 !== share2 && share2 !== share3 && share1 !== share3) {
        success('All shares are unique');
    } else {
        fail('CRITICAL: Shares are not unique - SSS is broken!');
    }
    
    // Verify share length (should be 32 bytes = 64 hex chars)
    const shareLengths = shares.map(s => s.y.length);
    if (shareLengths.every(len => len === 64)) {
        success('All shares are correct length (32 bytes)');
    } else {
        fail(`Share lengths are incorrect: ${shareLengths}`);
    }
    
    // Check if any share matches the root key (should not!)
    if (walletData._testOnly_rootKeyBytes) {
        const rootKey = walletData._testOnly_rootKeyBytes;
        const shareMatchesRoot = shares.some(s => s.y === rootKey);
        
        if (shareMatchesRoot) {
            fail('CRITICAL: A share matches the root key directly!');
        } else {
            success('No share matches the root key directly');
        }
    }
    
    // Verify QR codes are properly formatted
    const qrFormats = shares.every(s => 
        s.qrCode.startsWith('APOLLO-SHARE-') && 
        s.qrCode.includes(s.shareNumber.toString())
    );
    
    if (qrFormats) {
        success('QR codes are properly formatted');
    } else {
        warning('QR code format may not be optimal');
    }
}

// =============================================================================
// CRYPTO ATTACK 5: Public Key Correlation
// =============================================================================
function testPublicKeyCorrelation() {
    section('CRYPTO ATTACK 5: Public Key Correlation Analysis');
    
    info('Checking for correlation between public keys...');
    
    const rootPubkey = walletData.rootPubkey;
    const opPubkey = walletData.opPubkey;
    
    // Keys should be different
    if (rootPubkey !== opPubkey) {
        success('Root and operational public keys are different');
    } else {
        fail('CRITICAL: Root and operational keys are identical!');
    }
    
    // Check key lengths (should be 32 bytes = 64 hex chars for secp256k1)
    if (rootPubkey.length === 64 && opPubkey.length === 64) {
        success('Public keys are correct length (32 bytes)');
    } else {
        fail(`Public key lengths incorrect: root=${rootPubkey.length}, op=${opPubkey.length}`);
    }
    
    // Calculate Hamming distance between keys
    const rootBuffer = Buffer.from(rootPubkey, 'hex');
    const opBuffer = Buffer.from(opPubkey, 'hex');
    
    let hammingDistance = 0;
    for (let i = 0; i < rootBuffer.length; i++) {
        hammingDistance += (rootBuffer[i] ^ opBuffer[i]).toString(2).split('1').length - 1;
    }
    
    const totalBits = rootBuffer.length * 8;
    const similarity = 1 - (hammingDistance / totalBits);
    
    info(`Hamming distance: ${hammingDistance} bits out of ${totalBits}`);
    info(`Key similarity: ${(similarity * 100).toFixed(2)}%`);
    
    // Keys should have ~50% similarity if truly random
    if (similarity < 0.3 || similarity > 0.7) {
        warning('Public keys may have unusual correlation');
    } else {
        success('Public keys appear to be independently generated');
    }
    
    // Check for weak key patterns (all same byte, sequential, etc.)
    const hasWeakPattern = (key) => {
        const buffer = Buffer.from(key, 'hex');
        
        // Check for all same byte
        if (buffer.every(b => b === buffer[0])) return true;
        
        // Check for sequential bytes
        let sequential = true;
        for (let i = 1; i < buffer.length; i++) {
            if (buffer[i] !== (buffer[i-1] + 1) % 256) {
                sequential = false;
                break;
            }
        }
        return sequential;
    };
    
    if (hasWeakPattern(rootPubkey) || hasWeakPattern(opPubkey)) {
        fail('CRITICAL: Weak key pattern detected!');
    } else {
        success('No weak key patterns detected');
    }
}

// =============================================================================
// CRYPTO ATTACK 6: Address Generation Collision Risk
// =============================================================================
function testAddressCollisionRisk() {
    section('CRYPTO ATTACK 6: Address Generation Collision Risk');
    
    info('Analyzing address generation for collision vulnerabilities...');
    
    const address = walletData.address;
    
    // Check address format
    if (address.startsWith('L1_')) {
        success('Address has correct prefix (L1_)');
    } else {
        fail('Address has incorrect prefix');
    }
    
    // Extract hex portion
    const addressHex = address.substring(3);
    
    // Should be 40 hex characters (20 bytes)
    if (addressHex.length === 40) {
        success('Address is correct length (20 bytes)');
    } else {
        fail(`Address length incorrect: ${addressHex.length} hex chars`);
    }
    
    // Calculate address entropy
    const addressBuffer = Buffer.from(addressHex, 'hex');
    const uniqueBytes = new Set(addressBuffer).size;
    const entropy = uniqueBytes / addressBuffer.length;
    
    info(`Address entropy: ${uniqueBytes}/20 unique bytes (${(entropy * 100).toFixed(1)}%)`);
    
    if (entropy > 0.7) {
        success('Address has good entropy');
    } else if (entropy > 0.5) {
        warning('Address entropy is moderate');
    } else {
        fail('Address entropy is low - collision risk!');
    }
    
    // Estimate collision probability
    const addressSpace = Math.pow(2, addressBuffer.length * 8);
    const collisionProb = 1 / addressSpace;
    
    info(`Address space: 2^${addressBuffer.length * 8} (${addressBuffer.length * 8} bits)`);
    info(`Collision probability: ~1 in ${addressSpace.toExponential(2)}`);
    
    if (addressBuffer.length * 8 >= 160) {
        success('Address space is large enough (>=160 bits)');
    } else {
        warning('Address space may be too small for long-term security');
    }
}

// =============================================================================
// CRYPTO ATTACK 7: Side-Channel Analysis Preparation
// =============================================================================
function testSideChannelResistance() {
    section('CRYPTO ATTACK 7: Side-Channel Resistance Indicators');
    
    info('Checking for side-channel attack resistance...');
    
    // Check if constant-time operations are likely used
    info('Testing for timing-safe comparisons...');
    
    // Test if password validation takes similar time for different passwords
    const passwords = [
        APOLLO_PASSWORD,
        'WrongPassword1',
        'WrongPassword2',
        'WrongPassword3'
    ];
    
    const timings = [];
    
    for (const password of passwords) {
        const salt = Buffer.from(walletData.salt, 'hex');
        
        const start = process.hrtime.bigint();
        crypto.pbkdf2Sync(password, salt, 300000, 32, 'sha256');
        const end = process.hrtime.bigint();
        
        timings.push(Number(end - start) / 1000000); // Convert to ms
    }
    
    const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
    const maxDeviation = Math.max(...timings.map(t => Math.abs(t - avgTiming)));
    const deviationPercent = (maxDeviation / avgTiming * 100).toFixed(2);
    
    info(`Average derivation time: ${avgTiming.toFixed(2)}ms`);
    info(`Max deviation: ${maxDeviation.toFixed(2)}ms (${deviationPercent}%)`);
    
    if (deviationPercent < 5) {
        success('Key derivation timing is consistent - good side-channel resistance');
    } else if (deviationPercent < 15) {
        warning('Moderate timing variation detected');
    } else {
        fail(`High timing variation (${deviationPercent}%) - side-channel risk!`);
    }
    
    // Check for key material wiping indicators
    info('Verifying secure memory handling patterns...');
    
    // In production, we would check if keys are zeroed after use
    // For now, we verify sensitive data is properly encrypted
    
    const hasEncryptedKeys = walletData.encryptedOpKey && 
                            walletData.encryptedOpKey.encrypted &&
                            !walletData.rootPrivateKey &&
                            !walletData.opPrivateKey;
    
    if (hasEncryptedKeys) {
        success('Private keys are not stored in plaintext');
    } else {
        fail('Private keys may be exposed in memory');
    }
}

// =============================================================================
// CRYPTO ATTACK 8: Nonce Prediction Attack
// =============================================================================
function testNoncePrediction() {
    section('CRYPTO ATTACK 8: Nonce/IV Predictability Analysis');
    
    info('Testing for predictable nonce/IV generation...');
    
    // Analyze the IV used in encryption
    const iv = Buffer.from(walletData.encryptedOpKey.iv, 'hex');
    
    // Check for patterns that might indicate sequential or predictable IVs
    let hasPattern = false;
    
    // Check for sequential bytes
    let sequential = 0;
    for (let i = 1; i < iv.length; i++) {
        if (iv[i] === iv[i-1] + 1) {
            sequential++;
        }
    }
    
    if (sequential >= iv.length - 2) {
        fail('CRITICAL: IV appears to be sequential - predictable!');
        hasPattern = true;
    }
    
    // Check for timestamp-based IV (common vulnerability)
    const possibleTimestamp = iv.readUInt32BE(0);
    const currentTime = Date.now();
    const timeDiff = Math.abs(possibleTimestamp - currentTime);
    
    if (timeDiff < 1000 * 60 * 60 * 24 * 365) { // Within a year
        warning('IV may be timestamp-based - could be predictable');
    }
    
    // Check for counter-based IV
    const possibleCounter = iv.readUInt32BE(0);
    if (possibleCounter < 1000000) {
        warning('IV may be counter-based - could be predictable if counter is reset');
    }
    
    if (!hasPattern) {
        success('IV does not show obvious predictable patterns');
    }
    
    // Entropy check
    const uniqueBytes = new Set(iv).size;
    const entropy = uniqueBytes / iv.length;
    
    info(`IV entropy: ${(entropy * 100).toFixed(1)}%`);
    
    if (entropy > 0.8) {
        success('IV has high entropy');
    } else if (entropy > 0.6) {
        warning('IV has moderate entropy');
    } else {
        fail('IV has low entropy - may be predictable!');
    }
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================
async function runCryptoAttackTests() {
    console.log(`${colors.magenta}`);
    console.log('╔══════════════════════════════════════════════════════════════════════╗');
    console.log('║         APOLLO WALLET - ADVANCED CRYPTOGRAPHIC ATTACK TESTS          ║');
    console.log('║              Sophisticated Cryptographic Vulnerability Testing       ║');
    console.log('╚══════════════════════════════════════════════════════════════════════╝');
    console.log(`${colors.reset}`);
    
    info(`Testing wallet: ${APOLLO_ADDRESS}`);
    info(`Test started: ${new Date().toISOString()}\n`);
    
    try {
        testIVReuse();
        testAuthTagIntegrity();
        testKeyDerivationStrength();
        testShamirSecretSharing();
        testPublicKeyCorrelation();
        testAddressCollisionRisk();
        testSideChannelResistance();
        testNoncePrediction();
        
    } catch (error) {
        console.error(`${colors.red}Test suite error: ${error.message}${colors.reset}`);
        console.error(error.stack);
    }
    
    // Print summary
    section('CRYPTOGRAPHIC ATTACK TEST RESULTS');
    
    console.log(`${colors.white}Total Tests:    ${testResults.total}${colors.reset}`);
    console.log(`${colors.green}Passed:         ${testResults.passed}${colors.reset}`);
    console.log(`${colors.red}Failed:         ${testResults.failed}${colors.reset}`);
    console.log(`${colors.yellow}Warnings:       ${testResults.warnings}${colors.reset}`);
    
    const passRate = (testResults.passed / testResults.total * 100).toFixed(1);
    console.log(`\n${colors.white}Pass Rate:      ${passRate}%${colors.reset}`);
    
    if (testResults.failed === 0) {
        console.log(`\n${colors.green}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✓ ALL CRYPTOGRAPHIC TESTS PASSED - STRONG CRYPTO IMPLEMENTATION`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    } else {
        console.log(`\n${colors.red}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✗ ${testResults.failed} CRYPTO VULNERABILITIES - CRITICAL FIXES NEEDED`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    }
    
    if (testResults.warnings > 0) {
        console.log(`${colors.yellow}⚠  ${testResults.warnings} warnings require review${colors.reset}\n`);
    }
    
    info(`Test completed: ${new Date().toISOString()}`);
}

runCryptoAttackTests().catch(error => {
    console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
    process.exit(1);
});
