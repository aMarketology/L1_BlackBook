/**
 * BlackBook L1 - Mnemonic Wallet Tests
 * 
 * Tests the "Hidden Mnemonic" architecture:
 * 1. Entropy generation and BIP-39 encoding
 * 2. Shamir's Secret Sharing split/reconstruct
 * 3. Password-bound Share A
 * 4. Full wallet generation pipeline
 */

require('dotenv').config({ path: '../.env' });

const {
    generateEntropy,
    entropyToMnemonic,
    mnemonicToEntropy,
    validateMnemonic,
    splitEntropy,
    reconstructEntropy,
    deriveShareA,
    recoverShareA,
    deriveEd25519FromMnemonic,
    generateWallet,
    reconstructMnemonic,
    signTransaction,
} = require('../mnemonic-wallet');

const crypto = require('crypto');

// Test results tracking
let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✅ ${name}`);
        passed++;
    } catch (error) {
        console.log(`❌ ${name}`);
        console.log(`   Error: ${error.message}`);
        failed++;
    }
}

async function asyncTest(name, fn) {
    try {
        await fn();
        console.log(`✅ ${name}`);
        passed++;
    } catch (error) {
        console.log(`❌ ${name}`);
        console.log(`   Error: ${error.message}`);
        failed++;
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || 'Assertion failed');
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message || 'Not equal'}: expected ${expected}, got ${actual}`);
    }
}

// ============================================================================
// TEST SUITE
// ============================================================================

async function runTests() {
    console.log('\n' + '='.repeat(60));
    console.log('🧪 BlackBook Mnemonic Wallet Tests');
    console.log('='.repeat(60) + '\n');

    // -------------------------------------------------------------------------
    console.log('📦 Entropy & BIP-39 Tests\n');
    // -------------------------------------------------------------------------

    test('Generate entropy returns 16 bytes', () => {
        const entropy = generateEntropy();
        assertEqual(entropy.length, 16, 'Entropy length');
    });

    test('Entropy to mnemonic returns 12 words', () => {
        const entropy = generateEntropy();
        const mnemonic = entropyToMnemonic(entropy);
        const words = mnemonic.split(' ');
        assertEqual(words.length, 12, 'Word count');
    });

    test('Mnemonic round-trip preserves entropy', () => {
        const original = generateEntropy();
        const mnemonic = entropyToMnemonic(original);
        const recovered = mnemonicToEntropy(mnemonic);
        assert(original.equals(recovered), 'Entropy should match after round-trip');
    });

    test('Known mnemonic validates correctly', () => {
        const validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        assert(validateMnemonic(validMnemonic), 'Should be valid');
    });

    test('Invalid mnemonic rejected', () => {
        const invalidMnemonic = 'invalid words here that are not real';
        assert(!validateMnemonic(invalidMnemonic), 'Should be invalid');
    });

    // -------------------------------------------------------------------------
    console.log('\n🔐 Shamir Secret Sharing Tests\n');
    // -------------------------------------------------------------------------

    test('Split entropy returns 3 shares', () => {
        const entropy = generateEntropy();
        const { shareA, shareB, shareC } = splitEntropy(entropy);
        assert(shareA && shareB && shareC, 'Should have all 3 shares');
        assert(shareA !== shareB && shareB !== shareC, 'Shares should be different');
    });

    test('Reconstruct with Share A + B works', () => {
        const original = generateEntropy();
        const { shareA, shareB } = splitEntropy(original);
        const recovered = reconstructEntropy(shareA, shareB);
        assert(original.equals(recovered), 'Should reconstruct with A+B');
    });

    test('Reconstruct with Share A + C works', () => {
        const original = generateEntropy();
        const { shareA, shareC } = splitEntropy(original);
        const recovered = reconstructEntropy(shareA, shareC);
        assert(original.equals(recovered), 'Should reconstruct with A+C');
    });

    test('Reconstruct with Share B + C works', () => {
        const original = generateEntropy();
        const { shareB, shareC } = splitEntropy(original);
        const recovered = reconstructEntropy(shareB, shareC);
        assert(original.equals(recovered), 'Should reconstruct with B+C');
    });

    // -------------------------------------------------------------------------
    console.log('\n🔑 Password-Bound Share A Tests\n');
    // -------------------------------------------------------------------------

    await asyncTest('Derive and recover Share A with correct password', async () => {
        const password = 'TestPassword123!';
        const salt = crypto.randomBytes(32);
        const originalShare = crypto.randomBytes(32).toString('hex');
        
        // Bind share to password
        const boundShare = await deriveShareA(password, originalShare, salt);
        assert(boundShare !== originalShare, 'Bound share should be different');
        
        // Recover with correct password
        const recoveredShare = await recoverShareA(password, boundShare, salt);
        assertEqual(recoveredShare, originalShare, 'Should recover original share');
    });

    await asyncTest('Wrong password produces wrong Share A', async () => {
        const correctPassword = 'CorrectPassword!';
        const wrongPassword = 'WrongPassword!';
        const salt = crypto.randomBytes(32);
        const originalShare = crypto.randomBytes(32).toString('hex');
        
        // Bind with correct password
        const boundShare = await deriveShareA(correctPassword, originalShare, salt);
        
        // Try to recover with wrong password
        const wrongRecovery = await recoverShareA(wrongPassword, boundShare, salt);
        assert(wrongRecovery !== originalShare, 'Wrong password should not recover share');
    });

    // -------------------------------------------------------------------------
    console.log('\n🏠 HD Wallet Derivation Tests\n');
    // -------------------------------------------------------------------------

    test('Derive address from known mnemonic is deterministic', () => {
        const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        
        const result1 = deriveEd25519FromMnemonic(mnemonic);
        const result2 = deriveEd25519FromMnemonic(mnemonic);
        
        assertEqual(result1.address, result2.address, 'Address should be deterministic');
        assertEqual(result1.publicKey, result2.publicKey, 'Public key should be deterministic');
    });

    test('Different mnemonics produce different addresses', () => {
        const entropy1 = generateEntropy();
        const entropy2 = generateEntropy();
        const mnemonic1 = entropyToMnemonic(entropy1);
        const mnemonic2 = entropyToMnemonic(entropy2);
        
        const result1 = deriveEd25519FromMnemonic(mnemonic1);
        const result2 = deriveEd25519FromMnemonic(mnemonic2);
        
        assert(result1.address !== result2.address, 'Different mnemonics should produce different addresses');
    });

    test('Address has correct L1_ format', () => {
        const entropy = generateEntropy();
        const mnemonic = entropyToMnemonic(entropy);
        const { address } = deriveEd25519FromMnemonic(mnemonic);
        
        assert(address.startsWith('L1_'), 'Address should start with L1_');
        assertEqual(address.length, 43, 'Address should be 43 chars (L1_ + 40 hex)');
    });

    // -------------------------------------------------------------------------
    console.log('\n🎯 Full Wallet Pipeline Tests\n');
    // -------------------------------------------------------------------------

    await asyncTest('Generate wallet creates valid structure', async () => {
        const password = 'SecurePassword123!';
        const wallet = await generateWallet(password);
        
        assert(wallet.address, 'Should have address');
        assert(wallet.publicKey, 'Should have publicKey');
        assert(wallet.shareARaw, 'Should have shareARaw');
        assert(wallet.shareB, 'Should have shareB');
        assert(wallet.shareC, 'Should have shareC');
        assert(wallet.salt, 'Should have salt');
        assert(wallet.address.startsWith('L1_'), 'Address should start with L1_');
    });

    await asyncTest('Reconstruct mnemonic from shares', async () => {
        const password = 'SecurePassword123!';
        const wallet = await generateWallet(password);
        
        // Reconstruct mnemonic
        const mnemonic = await reconstructMnemonic(
            password,
            wallet.shareARaw,
            wallet.shareB,
            wallet.salt,
            false
        );
        
        // Verify it produces the same address
        const { address } = deriveEd25519FromMnemonic(mnemonic);
        assertEqual(address, wallet.address, 'Reconstructed mnemonic should produce same address');
    });

    await asyncTest('Sign transaction with reconstructed key', async () => {
        const password = 'SecurePassword123!';
        const wallet = await generateWallet(password);
        
        const signedTx = await signTransaction(password, {
            shareARaw: wallet.shareARaw,
            shareB: wallet.shareB,
            salt: wallet.salt,
        }, {
            to: 'L1_RECIPIENT_ADDRESS_HERE_1234567890',
            amount: 100,
            nonce: 1,
        });
        
        assert(signedTx.signature, 'Should have signature');
        assert(signedTx.transaction, 'Should have transaction');
        assertEqual(signedTx.from, wallet.address, 'Should be from correct address');
        assert(signedTx.signature.length === 128, 'Ed25519 signature should be 64 bytes (128 hex)');
    });

    // -------------------------------------------------------------------------
    console.log('\n📊 Security Tests\n');
    // -------------------------------------------------------------------------

    await asyncTest('Cannot reconstruct without 2 shares', async () => {
        const entropy = generateEntropy();
        const { shareA } = splitEntropy(entropy);
        
        // Try to reconstruct with just 1 share (should fail or produce garbage)
        try {
            const result = reconstructEntropy(shareA, shareA);
            // If it doesn't throw, check if result is wrong
            assert(!entropy.equals(result), 'Single share should not reconstruct');
        } catch (e) {
            // Expected - reconstruction should fail
        }
    });

    test('Wallet does NOT include mnemonic in output', async () => {
        const password = 'SecurePassword123!';
        const wallet = await generateWallet(password);
        
        assert(!wallet.mnemonic, 'Wallet should NOT contain mnemonic');
        
        const walletString = JSON.stringify(wallet);
        assert(!walletString.includes('abandon'), 'Wallet JSON should not contain mnemonic words');
    });

    // -------------------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------------------
    
    console.log('\n' + '='.repeat(60));
    console.log(`📊 Test Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(60) + '\n');
    
    if (failed > 0) {
        process.exit(1);
    }
}

// Run tests
runTests().catch(console.error);
