/**
 * TEST 2: Valid Transactions Between Wallets
 * Tests legitimate token transfers using proper signatures
 */

const nacl = require('tweetnacl');
const crypto = require('crypto');

const L1_API_URL = 'http://localhost:8080';

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
    dealer: {
        name: 'Dealer',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
        publicKey: '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a',
        privateKey: null
    }
};

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

async function sendTokens(fromWallet, toAddress, amount) {
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
    
    console.log(`   Response Status: ${response.status} ${response.statusText}`);
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
        const result = await response.json();
        console.log(`   Response Body:`, JSON.stringify(result, null, 2));
        return result;
    } else {
        const text = await response.text();
        console.log(`   Response Text:`, text.substring(0, 200));
        return { success: false, error: text };
    }
}

async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 2: VALID TRANSACTIONS');
    console.log('='.repeat(80));
    console.log('Testing legitimate token transfers with proper signatures\n');
    
    let testsPassed = 0;
    let testsFailed = 0;
    
    // Test 2.1: Alice → Bob (75 BB)
    console.log('📤 Test 2.1: Alice → Bob (75 BB)');
    try {
        let result = await sendTokens(wallets.alice, wallets.bob.address, 75);
        if (result.success) {
            console.log('   ✅ PASSED - Transaction successful');
            testsPassed++;
        } else {
            console.log(`   ❌ FAILED - ${result.error}`);
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Test 2.2: Bob → Dealer (25 BB)
    console.log('\n📤 Test 2.2: Bob → Dealer (25 BB)');
    try {
        let result = await sendTokens(wallets.bob, wallets.dealer.address, 25);
        if (result.success) {
            console.log('   ✅ PASSED - Transaction successful');
            testsPassed++;
        } else {
            console.log(`   ❌ FAILED - ${result.error}`);
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Test 2.3: Alice → Dealer (50 BB)
    console.log('\n📤 Test 2.3: Alice → Dealer (50 BB)');
    try {
        let result = await sendTokens(wallets.alice, wallets.dealer.address, 50);
        if (result.success) {
            console.log('   ✅ PASSED - Transaction successful');
            testsPassed++;
        } else {
            console.log(`   ❌ FAILED - ${result.error}`);
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    await new Promise(r => setTimeout(r, 500));
    
    // Test 2.4: Bob → Alice (100 BB)
    console.log('\n📤 Test 2.4: Bob → Alice (100 BB)');
    try {
        let result = await sendTokens(wallets.bob, wallets.alice.address, 100);
        if (result.success) {
            console.log('   ✅ PASSED - Transaction successful');
            testsPassed++;
        } else {
            console.log(`   ❌ FAILED - ${result.error}`);
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    
    console.log('\n' + '='.repeat(80));
    console.log('📊 TEST 2 SUMMARY');
    console.log('='.repeat(80));
    console.log(`✅ Passed: ${testsPassed}`);
    console.log(`❌ Failed: ${testsFailed}`);
    console.log(`📈 Success Rate: ${((testsPassed / (testsPassed + testsFailed)) * 100).toFixed(1)}%`);
    console.log('='.repeat(80) + '\n');
}

main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
