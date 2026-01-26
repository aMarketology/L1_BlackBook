/**
 * 🔐 PRODUCTION BRIDGE TEST - Full Signature Validation
 * 
 * Tests the L1→L2 bridge endpoint with proper Ed25519 signatures.
 * This demonstrates how the frontend should integrate with the bridge.
 * 
 * NO TEST MODE BYPASSES - All transactions require real signatures.
 */

import crypto from 'crypto';
import * as ed25519 from '@noble/ed25519';

const L1_URL = 'http://localhost:8080';

// Mac's Wallet Credentials (from migration)
const MAC_PRIVATE_KEY = 'dca84e83c94b855a56b0cd4b7154b579f8ebc6aaf9c9f8d9ba7b293749c5ba56';
const MAC_PUBLIC_KEY = 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752';
const MAC_ADDRESS = 'L1_94B3C863E068096596CE80F04C2233B72AE11790';

/**
 * Sign a message using Ed25519
 */
async function signMessage(privateKeyHex, message) {
    const messageBytes = Buffer.from(message, 'utf-8');
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    const signatureBytes = await ed25519.signAsync(messageBytes, privateKeyBytes);
    return Buffer.from(signatureBytes).toString('hex');
}

/**
 * Make authenticated request to L1
 */
async function makeSignedRequest(endpoint, payload, privateKey, publicKey) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    
    // Payload as JSON string
    const payloadStr = JSON.stringify(payload);
    
    // Message format: EXACTLY AS THE SDK DOES IT
    // Backend expects: chain_id_byte(0x01) + "{payload}\n{timestamp}\n{nonce}"
    const message = `${payloadStr}\n${timestamp}\n${nonce}`;
    const chainIdByte = Buffer.from([1]); // Chain ID 1 as byte
    const messageBytes = Buffer.concat([chainIdByte, Buffer.from(message, 'utf-8')]);
    
    console.log(`\n📝 Signing message (${messageBytes.length} bytes):`);
    console.log(`   Message format: [0x01] + "${payloadStr}\\n${timestamp}\\n${nonce.substring(0, 16)}..."`);
    
    // Sign with Ed25519
    const privateKeyBytes = Buffer.from(privateKey, 'hex');
    const signatureBytes = await ed25519.signAsync(messageBytes, privateKeyBytes);
    const signatureHex = Buffer.from(signatureBytes).toString('hex');
    
    console.log(`✍️  Signature (${signatureHex.length} chars): ${signatureHex.substring(0, 32)}...`);
    
    // Build SignedRequest
    const signedRequest = {
        payload: payloadStr,
        public_key: publicKey,
        signature: signatureHex,
        nonce: nonce,
        timestamp: timestamp,
        chain_id: 1
    };
    
    // Send to L1
    const response = await fetch(`${L1_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest)
    });
    
    const result = await response.json();
    
    return {
        status: response.status,
        ok: response.ok,
        data: result
    };
}

/**
 * Test 1: Valid Bridge Request with Signature
 */
async function testValidBridge() {
    console.log('\n' + '='.repeat(70));
    console.log('🧪 TEST 1: Valid Bridge Request (1000 BB)');
    console.log('='.repeat(70));
    
    try {
        // Check balance first
        const balanceRes = await fetch(`${L1_URL}/balance/${MAC_ADDRESS}`);
        const balance = await balanceRes.json();
        console.log(`\n💰 Current Balance: ${balance.available} BB available, ${balance.locked} BB locked`);
        
        if (balance.available < 1000) {
            console.log(`❌ Insufficient balance for test (need 1000 BB)`);
            return false;
        }
        
        // Initiate bridge with signature
        const payload = {
            amount: 1000,
            target_layer: "L2"
        };
        
        const result = await makeSignedRequest(
            '/bridge/initiate',
            payload,
            MAC_PRIVATE_KEY,
            MAC_PUBLIC_KEY
        );
        
        console.log(`\n📡 Response Status: ${result.status}`);
        console.log(`📦 Response Data:`, JSON.stringify(result.data, null, 2));
        
        if (result.ok && result.data.success) {
            console.log(`\n✅ TEST PASSED: Bridge initiated successfully`);
            console.log(`   Lock ID: ${result.data.lock_id}`);
            console.log(`   Amount: ${result.data.amount} BB`);
            console.log(`   Status: ${result.data.status}`);
            return result.data.lock_id;
        } else {
            console.log(`\n❌ TEST FAILED: ${result.data.error || 'Unknown error'}`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ TEST FAILED: ${error.message}`);
        return false;
    }
}

/**
 * Test 2: Bridge Request with EMPTY Signature (Should Fail)
 */
async function testEmptySignature() {
    console.log('\n' + '='.repeat(70));
    console.log('🧪 TEST 2: Empty Signature (Should Fail - Production Security)');
    console.log('='.repeat(70));
    
    try {
        const payload = {
            amount: 100,
            target_layer: "L2"
        };
        
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        // Send request with EMPTY signature
        const signedRequest = {
            payload: JSON.stringify(payload),
            public_key: "",
            signature: "",
            nonce: nonce,
            timestamp: timestamp,
            chain_id: 1
        };
        
        const response = await fetch(`${L1_URL}/bridge/initiate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        
        const result = await response.json();
        
        console.log(`\n📡 Response Status: ${response.status}`);
        console.log(`📦 Response Data:`, JSON.stringify(result, null, 2));
        
        if (response.status === 401 || !result.success) {
            console.log(`\n✅ TEST PASSED: Empty signature correctly rejected`);
            return true;
        } else {
            console.log(`\n❌ TEST FAILED: Empty signature was accepted (SECURITY BREACH!)`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ TEST FAILED: ${error.message}`);
        return false;
    }
}

/**
 * Test 3: Bridge Request with INVALID Signature (Should Fail)
 */
async function testInvalidSignature() {
    console.log('\n' + '='.repeat(70));
    console.log('🧪 TEST 3: Invalid Signature (Should Fail)');
    console.log('='.repeat(70));
    
    try {
        const payload = {
            amount: 100,
            target_layer: "L2"
        };
        
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        // Send request with FAKE signature
        const signedRequest = {
            payload: JSON.stringify(payload),
            public_key: MAC_PUBLIC_KEY,
            signature: "deadbeef".repeat(16), // Invalid signature
            nonce: nonce,
            timestamp: timestamp,
            chain_id: 1
        };
        
        const response = await fetch(`${L1_URL}/bridge/initiate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        
        const result = await response.json();
        
        console.log(`\n📡 Response Status: ${response.status}`);
        console.log(`📦 Response Data:`, JSON.stringify(result, null, 2));
        
        if (response.status === 401 || !result.success) {
            console.log(`\n✅ TEST PASSED: Invalid signature correctly rejected`);
            return true;
        } else {
            console.log(`\n❌ TEST FAILED: Invalid signature was accepted (SECURITY BREACH!)`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ TEST FAILED: ${error.message}`);
        return false;
    }
}

/**
 * Test 4: Check Bridge Status
 */
async function testBridgeStatus(lockId) {
    console.log('\n' + '='.repeat(70));
    console.log('🧪 TEST 4: Check Bridge Lock Status');
    console.log('='.repeat(70));
    
    if (!lockId) {
        console.log('⚠️  Skipping - no lock_id from previous test');
        return false;
    }
    
    try {
        const response = await fetch(`${L1_URL}/bridge/status/${lockId}`);
        const result = await response.json();
        
        console.log(`\n📦 Lock Status:`, JSON.stringify(result, null, 2));
        
        if (response.ok) {
            console.log(`\n✅ TEST PASSED: Lock status retrieved`);
            return true;
        } else {
            console.log(`\n❌ TEST FAILED: Could not retrieve lock status`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ TEST FAILED: ${error.message}`);
        return false;
    }
}

/**
 * Test 5: Check Pending Bridges for Wallet
 */
async function testPendingBridges() {
    console.log('\n' + '='.repeat(70));
    console.log('🧪 TEST 5: Check Pending Bridges');
    console.log('='.repeat(70));
    
    try {
        const response = await fetch(`${L1_URL}/bridge/pending/${MAC_ADDRESS}`);
        const result = await response.json();
        
        console.log(`\n📦 Pending Bridges:`, JSON.stringify(result, null, 2));
        
        if (response.ok) {
            console.log(`\n✅ TEST PASSED: Retrieved ${result.pending_count || 0} pending bridges`);
            return true;
        } else {
            console.log(`\n❌ TEST FAILED: Could not retrieve pending bridges`);
            return false;
        }
        
    } catch (error) {
        console.log(`\n❌ TEST FAILED: ${error.message}`);
        return false;
    }
}

/**
 * Run all tests
 */
async function runAllTests() {
    console.log('\n' + '═'.repeat(70));
    console.log('🔐 PRODUCTION BRIDGE SECURITY TEST SUITE');
    console.log('   Testing L1→L2 Bridge with Full Ed25519 Signature Validation');
    console.log('═'.repeat(70));
    
    const results = {
        passed: 0,
        failed: 0,
        tests: []
    };
    
    // Test 1: Valid bridge request
    const lockId = await testValidBridge();
    results.tests.push({ name: 'Valid Bridge', passed: !!lockId });
    if (lockId) results.passed++; else results.failed++;
    
    // Small delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Test 2: Empty signature (should fail)
    const test2 = await testEmptySignature();
    results.tests.push({ name: 'Reject Empty Signature', passed: test2 });
    if (test2) results.passed++; else results.failed++;
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Test 3: Invalid signature (should fail)
    const test3 = await testInvalidSignature();
    results.tests.push({ name: 'Reject Invalid Signature', passed: test3 });
    if (test3) results.passed++; else results.failed++;
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Test 4: Bridge status
    const test4 = await testBridgeStatus(lockId);
    results.tests.push({ name: 'Bridge Status', passed: test4 });
    if (test4) results.passed++; else results.failed++;
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Test 5: Pending bridges
    const test5 = await testPendingBridges();
    results.tests.push({ name: 'Pending Bridges', passed: test5 });
    if (test5) results.passed++; else results.failed++;
    
    // Summary
    console.log('\n' + '═'.repeat(70));
    console.log('📊 TEST SUMMARY');
    console.log('═'.repeat(70));
    
    results.tests.forEach((test, i) => {
        const icon = test.passed ? '✅' : '❌';
        console.log(`${icon} Test ${i + 1}: ${test.name}`);
    });
    
    console.log(`\n📈 Results: ${results.passed}/${results.tests.length} tests passed`);
    
    if (results.failed === 0) {
        console.log('\n🎉 ALL TESTS PASSED - Bridge is production ready!');
        console.log('✅ Signature validation working');
        console.log('✅ Empty signatures rejected');
        console.log('✅ Invalid signatures rejected');
        console.log('✅ Bridge flow operational');
    } else {
        console.log(`\n⚠️  ${results.failed} test(s) failed - review security`);
    }
    
    console.log('═'.repeat(70) + '\n');
}

// Run tests
runAllTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
