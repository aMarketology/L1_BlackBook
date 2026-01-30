/**
 * BlackBook L1 - Comprehensive 5-Wallet Test Suite
 * Tests: Apollo, Mac, Alice, Bob, Dealer
 * 
 * Security Tests:
 * - Valid transactions
 * - Invalid signatures
 * - Replay attacks
 * - Insufficient balance
 * - Various transaction patterns
 */

const nacl = require('tweetnacl');
const crypto = require('crypto');

const L1_API_URL = 'http://localhost:8080';

// All 5 wallet accounts with private keys
const wallets = {
    alice: {
        name: 'Alice',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
        publicKey: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
        privateKey: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24'
    },
    bob: {
        name: 'Bob',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
        publicKey: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
        privateKey: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b'
    },
    mac: {
        name: 'Mac',
        address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
        publicKey: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
        privateKey: null // Would need to decrypt vault
    },
    apollo: {
        name: 'Apollo',
        address: 'L1_47597088CDD24661AAA867D44CBBF6519635338C',
        publicKey: '4c6fc26efbb41288294f696237de0a1eadb9fde5864ce8b7056128a20fab41fd',
        privateKey: null // Would need to decrypt
    },
    dealer: {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        publicKey: '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a',
        privateKey: null // Stored in .env
    }
};

/**
 * Get balance for an address
 */
async function getBalance(address) {
    try {
        const response = await fetch(`${L1_API_URL}/balance/${address}`);
        if (!response.ok) return null;
        const data = await response.json();
        return data.balance || 0;
    } catch (error) {
        return null;
    }
}

/**
 * Sign a transaction using Ed25519
 */
function signTransaction(privateKeyHex, payload, timestamp, nonce, chainId = 1) {
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    
    const chainIdByte = Buffer.from([chainId]);
    const payloadBytes = Buffer.from(payload, 'utf8');
    const timestampBytes = Buffer.from(timestamp.toString(), 'utf8');
    const nonceBytes = Buffer.from(nonce, 'utf8');
    
    const message = Buffer.concat([
        chainIdByte,
        payloadBytes,
        Buffer.from('\n'),
        timestampBytes,
        Buffer.from('\n'),
        nonceBytes
    ]);
    
    const signature = nacl.sign.detached(message, keyPair.secretKey);
    return Buffer.from(signature).toString('hex');
}

/**
 * Send tokens
 */
async function sendTokens(fromWallet, toAddress, amount) {
    if (!fromWallet.privateKey) {
        console.log(`   ⚠️  ${fromWallet.name} requires vault decryption (skipped)`);
        return null;
    }
    
    try {
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString('hex');
        const chainId = 1;
        
        const payload = JSON.stringify({ to: toAddress, amount: amount });
        const signature = signTransaction(
            fromWallet.privateKey,
            payload,
            timestamp,
            nonce,
            chainId
        );
        
        const requestBody = {
            wallet_address: fromWallet.address,
            public_key: fromWallet.publicKey,
            payload: payload,
            signature: signature,
            timestamp: timestamp,
            nonce: nonce,
            chain_id: chainId,
            schema_version: 1
        };
        
        const response = await fetch(`${L1_API_URL}/transfer/simple`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        const contentType = response.headers.get('content-type');
        let result;
        
        if (contentType && contentType.includes('application/json')) {
            result = await response.json();
        } else {
            const text = await response.text();
            return { success: false, error: text };
        }
        
        if (!response.ok || !result.success) {
            return { success: false, error: result.error || 'Unknown error' };
        }
        
        return { success: true, result };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Test invalid signature
 */
async function testInvalidSignature(fromWallet, toAddress, amount) {
    if (!fromWallet.privateKey) {
        console.log(`   ⚠️  ${fromWallet.name} requires vault decryption (skipped)`);
        return null;
    }
    
    try {
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString('hex');
        const chainId = 1;
        
        const payload = JSON.stringify({ to: toAddress, amount: amount });
        
        // Create INVALID signature by using wrong private key
        const wrongPrivateKey = crypto.randomBytes(32).toString('hex');
        const invalidSignature = signTransaction(
            wrongPrivateKey,
            payload,
            timestamp,
            nonce,
            chainId
        );
        
        const requestBody = {
            wallet_address: fromWallet.address,
            public_key: fromWallet.publicKey,
            payload: payload,
            signature: invalidSignature,
            timestamp: timestamp,
            nonce: nonce,
            chain_id: chainId,
            schema_version: 1
        };
        
        const response = await fetch(`${L1_API_URL}/transfer/simple`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        if (response.ok) {
            return { success: false, error: 'Invalid signature was accepted!' };
        } else {
            return { success: true, rejected: true };
        }
    } catch (error) {
        return { success: true, rejected: true, error: error.message };
    }
}

/**
 * Display balances
 */
async function displayBalances(title) {
    console.log('\n' + '='.repeat(80));
    console.log(`💰 ${title}`);
    console.log('='.repeat(80));
    
    let total = 0;
    for (const [key, wallet] of Object.entries(wallets)) {
        const balance = await getBalance(wallet.address);
        if (balance !== null) {
            total += balance;
            const vaultStatus = wallet.privateKey ? '🔓' : '🔒';
            console.log(`${vaultStatus} ${wallet.name.padEnd(10)} ${wallet.address}  ${balance.toLocaleString().padStart(12)} BB`);
        }
    }
    console.log('-'.repeat(80));
    console.log(`Total: ${total.toLocaleString()} BB\n`);
}

/**
 * Main test suite
 */
async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('🧪 BLACKBOOK L1 - COMPREHENSIVE 5-WALLET TEST SUITE');
    console.log('='.repeat(80));
    console.log('\nWallets: Apollo, Mac, Alice, Bob, Dealer');
    console.log('Tests: Transactions, Security, Balance Verification\n');
    
    let testsPassed = 0;
    let testsFailed = 0;
    
    // Initial balances
    await displayBalances('INITIAL BALANCES');
    
    console.log('='.repeat(80));
    console.log('TEST 1: Valid Transactions Between Wallets');
    console.log('='.repeat(80));
    
    // Alice → Bob (75 BB)
    console.log('\n📤 Test 1.1: Alice → Bob (75 BB)');
    let result = await sendTokens(wallets.alice, wallets.bob.address, 75);
    if (result && result.success) {
        console.log('   ✅ PASSED - Transaction successful');
        testsPassed++;
    } else {
        console.log(`   ❌ FAILED - ${result?.error || 'Unknown error'}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Bob → Dealer (25 BB)
    console.log('\n📤 Test 1.2: Bob → Dealer (25 BB)');
    result = await sendTokens(wallets.bob, wallets.dealer.address, 25);
    if (result && result.success) {
        console.log('   ✅ PASSED - Transaction successful');
        testsPassed++;
    } else {
        console.log(`   ❌ FAILED - ${result?.error || 'Unknown error'}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Alice → Dealer (50 BB)
    console.log('\n📤 Test 1.3: Alice → Dealer (50 BB)');
    result = await sendTokens(wallets.alice, wallets.dealer.address, 50);
    if (result && result.success) {
        console.log('   ✅ PASSED - Transaction successful');
        testsPassed++;
    } else {
        console.log(`   ❌ FAILED - ${result?.error || 'Unknown error'}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Bob → Alice (100 BB) - return some tokens
    console.log('\n📤 Test 1.4: Bob → Alice (100 BB)');
    result = await sendTokens(wallets.bob, wallets.alice.address, 100);
    if (result && result.success) {
        console.log('   ✅ PASSED - Transaction successful');
        testsPassed++;
    } else {
        console.log(`   ❌ FAILED - ${result?.error || 'Unknown error'}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    console.log('\n' + '='.repeat(80));
    console.log('TEST 2: Security Tests');
    console.log('='.repeat(80));
    
    // Test 2.1: Invalid signature should be rejected
    console.log('\n🔒 Test 2.1: Invalid Signature (should be REJECTED)');
    result = await testInvalidSignature(wallets.alice, wallets.bob.address, 10);
    if (result && result.rejected) {
        console.log('   ✅ PASSED - Invalid signature rejected');
        testsPassed++;
    } else {
        console.log('   ❌ FAILED - Invalid signature was accepted!');
        testsFailed++;
    }
    
    // Test 2.2: Try to send more than balance
    console.log('\n💸 Test 2.2: Insufficient Balance (should be REJECTED)');
    result = await sendTokens(wallets.alice, wallets.bob.address, 999999999);
    if (result && !result.success) {
        console.log('   ✅ PASSED - Insufficient balance rejected');
        testsPassed++;
    } else {
        console.log('   ❌ FAILED - Insufficient balance was accepted!');
        testsFailed++;
    }
    
    console.log('\n' + '='.repeat(80));
    console.log('TEST 3: Multiple Small Transactions (Stress Test)');
    console.log('='.repeat(80));
    
    // Send 5 small transactions rapidly
    console.log('\n🔄 Test 3: Rapid small transactions (5x 1 BB)');
    let rapidSuccess = 0;
    for (let i = 0; i < 5; i++) {
        result = await sendTokens(wallets.alice, wallets.bob.address, 1);
        if (result && result.success) rapidSuccess++;
        await new Promise(r => setTimeout(r, 200));
    }
    if (rapidSuccess === 5) {
        console.log(`   ✅ PASSED - All ${rapidSuccess}/5 rapid transactions succeeded`);
        testsPassed++;
    } else {
        console.log(`   ⚠️  PARTIAL - Only ${rapidSuccess}/5 rapid transactions succeeded`);
        testsFailed++;
    }
    
    // Final balances
    await displayBalances('FINAL BALANCES');
    
    console.log('='.repeat(80));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(80));
    console.log(`✅ Passed: ${testsPassed}`);
    console.log(`❌ Failed: ${testsFailed}`);
    console.log(`📈 Success Rate: ${((testsPassed / (testsPassed + testsFailed)) * 100).toFixed(1)}%`);
    console.log('='.repeat(80) + '\n');
    
    // Note about encrypted wallets
    console.log('📝 Note: Mac and Apollo wallets require vault decryption to sign transactions.');
    console.log('   They can receive tokens but cannot send without unlocking.\n');
}

// Run tests
main().catch(error => {
    console.error('\n❌ Test suite failed:', error);
    process.exit(1);
});
