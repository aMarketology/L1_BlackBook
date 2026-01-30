/**
 * TEST 4: Stress Test - Rapid Small Transactions
 * Tests system performance under rapid transaction load
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
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
        return await response.json();
    } else {
        const text = await response.text();
        return { success: false, error: text };
    }
}

async function main() {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 4: STRESS TEST - RAPID SMALL TRANSACTIONS');
    console.log('='.repeat(80));
    console.log('Testing system performance under rapid transaction load\n');
    
    const testConfigs = [
        { count: 5, amount: 1, delay: 200, desc: '5 transactions @ 1 BB each (200ms delay)' },
        { count: 10, amount: 0.5, delay: 100, desc: '10 transactions @ 0.5 BB each (100ms delay)' },
    ];
    
    let totalTests = 0;
    let totalPassed = 0;
    let totalFailed = 0;
    
    for (const config of testConfigs) {
        console.log(`\n🔄 Test 4.${totalTests + 1}: ${config.desc}`);
        console.log(`   Sending ${config.count} rapid transactions from Alice → Bob...`);
        
        const startTime = Date.now();
        let succeeded = 0;
        let failed = 0;
        
        for (let i = 0; i < config.count; i++) {
            try {
                const result = await sendTokens(wallets.alice, wallets.bob.address, config.amount);
                if (result.success) {
                    process.stdout.write('   ✓');
                    succeeded++;
                } else {
                    process.stdout.write('   ✗');
                    failed++;
                }
            } catch (error) {
                process.stdout.write('   ✗');
                failed++;
            }
            await new Promise(r => setTimeout(r, config.delay));
        }
        
        const endTime = Date.now();
        const duration = endTime - startTime;
        const avgTime = duration / config.count;
        
        console.log(`\n   Results: ${succeeded}/${config.count} succeeded, ${failed}/${config.count} failed`);
        console.log(`   Duration: ${duration}ms total, ${avgTime.toFixed(0)}ms average per tx`);
        
        totalTests++;
        if (succeeded === config.count) {
            console.log(`   ✅ PASSED - All transactions succeeded`);
            totalPassed++;
        } else if (succeeded > 0) {
            console.log(`   ⚠️  PARTIAL - ${succeeded}/${config.count} succeeded`);
            totalFailed++;
        } else {
            console.log(`   ❌ FAILED - No transactions succeeded`);
            totalFailed++;
        }
    }
    
    console.log('\n' + '='.repeat(80));
    console.log('📊 TEST 4 SUMMARY');
    console.log('='.repeat(80));
    console.log(`✅ Passed: ${totalPassed}/${totalTests}`);
    console.log(`❌ Failed: ${totalFailed}/${totalTests}`);
    console.log(`📈 Success Rate: ${((totalPassed / totalTests) * 100).toFixed(1)}%`);
    console.log('='.repeat(80) + '\n');
}

main().catch(error => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
});
