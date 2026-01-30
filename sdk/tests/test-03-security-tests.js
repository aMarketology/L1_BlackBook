/**
 * TEST 3: Security Tests
 * Tests invalid signatures, insufficient balance, and other security features
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

async function testInvalidSignature(fromWallet, toAddress, amount) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    const chainId = 1;
    
    const payload = JSON.stringify({ to: toAddress, amount: amount });
    
    // Create INVALID signature by using random private key
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
    
    return !response.ok; // Should be rejected
}

async function testInsufficientBalance(fromWallet, toAddress, amount) {
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
    
    return !response.ok; // Should be rejected
}

async function testReplayAttack(fromWallet, toAddress, amount) {
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
    
    // Send first transaction
    const response1 = await fetch(`${L1_API_URL}/transfer/simple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });
    
    if (!response1.ok) {
        return { firstFailed: true };
    }
    
    await new Promise(r => setTimeout(r, 500));
    
    // Try to replay same transaction
    const response2 = await fetch(`${L1_API_URL}/transfer/simple`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });
    
    return { firstSucceeded: true, replayRejected: !response2.ok };
}

async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 3: SECURITY TESTS');
    console.log('='.repeat(80));
    console.log('Testing invalid signatures, insufficient balance, and replay protection\n');
    
    let testsPassed = 0;
    let testsFailed = 0;
    
    // Test 3.1: Invalid Signature
    console.log('🔒 Test 3.1: Invalid Signature (should be REJECTED)');
    try {
        const rejected = await testInvalidSignature(wallets.alice, wallets.bob.address, 10);
        if (rejected) {
            console.log('   ✅ PASSED - Invalid signature rejected');
            testsPassed++;
        } else {
            console.log('   ❌ FAILED - Invalid signature was accepted!');
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    
    // Test 3.2: Insufficient Balance
    console.log('\n💸 Test 3.2: Insufficient Balance (should be REJECTED)');
    try {
        const rejected = await testInsufficientBalance(wallets.alice, wallets.bob.address, 999999999);
        if (rejected) {
            console.log('   ✅ PASSED - Insufficient balance rejected');
            testsPassed++;
        } else {
            console.log('   ❌ FAILED - Insufficient balance was accepted!');
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    
    // Test 3.3: Replay Attack
    console.log('\n🔄 Test 3.3: Replay Attack (2nd transaction should be REJECTED)');
    try {
        const result = await testReplayAttack(wallets.alice, wallets.bob.address, 5);
        if (result.firstSucceeded && result.replayRejected) {
            console.log('   ✅ PASSED - First transaction accepted, replay rejected');
            testsPassed++;
        } else if (result.firstFailed) {
            console.log('   ⚠️  WARNING - First transaction failed');
            testsFailed++;
        } else {
            console.log('   ❌ FAILED - Replay attack was successful!');
            testsFailed++;
        }
    } catch (error) {
        console.log(`   ❌ FAILED - ${error.message}`);
        testsFailed++;
    }
    
    console.log('\n' + '='.repeat(80));
    console.log('📊 TEST 3 SUMMARY');
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
