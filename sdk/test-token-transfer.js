/**
 * TEST 1.1: TOKEN TRANSFERS (L1 Internal)
 * ========================================
 * Tests: POST /transfer
 * 
 * WHAT IT TESTS:
 * - Can Alice send BB tokens to Bob on L1?
 * - Are balances correctly debited/credited?
 * - Does signature verification work for transfers?
 * - Are nonces preventing replay attacks?
 * 
 * TEST ACCOUNTS (REAL):
 * - Alice: 10,000 BB ($100 USD at $0.01/BB)
 * - Bob: 5,000 BB ($50 USD)
 */

const nacl = require('tweetnacl');

const L1_URL = 'http://localhost:8080';
const CHAIN_ID_L1 = 0x01;

// ============================================================================
// REAL TEST ACCOUNTS (from TEST_ACCOUNTS.txt)
// ============================================================================
const ALICE = {
    name: 'Alice',
    wallet_address: 'L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD',
    public_key: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
    private_key: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24'
};

const BOB = {
    name: 'Bob',
    wallet_address: 'L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9',
    public_key: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
    private_key: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b'
};

// ============================================================================
// SIGNING UTILITIES
// ============================================================================

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function createSignedRequest(account, payload) {
    const timestamp = Date.now();
    const nonce = Math.floor(Math.random() * 1000000000);
    
    // Create message to sign: {payload}\n{timestamp}\n{nonce}
    const payloadJson = JSON.stringify(payload);
    const message = `${payloadJson}\n${timestamp}\n${nonce}`;
    
    // Prepend chain_id byte for domain separation
    const chainIdByte = new Uint8Array([CHAIN_ID_L1]);
    const messageBytes = new TextEncoder().encode(message);
    const fullMessage = new Uint8Array(chainIdByte.length + messageBytes.length);
    fullMessage.set(chainIdByte);
    fullMessage.set(messageBytes, chainIdByte.length);
    
    // Sign with Ed25519
    const privateKeyBytes = hexToBytes(account.private_key);
    const publicKeyBytes = hexToBytes(account.public_key);
    const secretKey = new Uint8Array(64);
    secretKey.set(privateKeyBytes);
    secretKey.set(publicKeyBytes, 32);
    
    const signature = nacl.sign.detached(fullMessage, secretKey);
    
    return {
        public_key: account.public_key,
        wallet_address: account.wallet_address,
        payload: payload,
        timestamp: timestamp,
        nonce: nonce,
        chain_id: 'L1',
        schema_version: 2,
        signature: bytesToHex(signature)
    };
}

// ============================================================================
// API HELPERS
// ============================================================================

async function getBalance(address) {
    const res = await fetch(`${L1_URL}/balance/${address}`);
    return await res.json();
}

async function transfer(fromAccount, toAddress, amount) {
    const payload = {
        action: 'transfer',
        to: toAddress,
        amount: amount  // BB tokens (not microtokens for this endpoint)
    };
    
    const signedRequest = createSignedRequest(fromAccount, payload);
    
    const res = await fetch(`${L1_URL}/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest)
    });
    
    return {
        status: res.status,
        data: await res.json()
    };
}

async function healthCheck() {
    const res = await fetch(`${L1_URL}/health`);
    return await res.json();
}

// ============================================================================
// TEST EXECUTION
// ============================================================================

async function runTest() {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════════╗');
    console.log('║  TEST 1.1: TOKEN TRANSFERS (L1 Internal)                      ║');
    console.log('║  Alice sends 100 BB ($1.00 USD) to Bob                        ║');
    console.log('╚═══════════════════════════════════════════════════════════════╝');
    console.log('');
    
    let passed = 0;
    let failed = 0;
    const issues = [];
    
    // -----------------------------------------------------------------
    // STEP 0: Health Check
    // -----------------------------------------------------------------
    console.log('📡 Step 0: Health check...');
    try {
        const health = await healthCheck();
        console.log(`   ✓ L1 Server: ${health.status}`);
        console.log(`   ✓ Block Height: ${health.block_height}`);
    } catch (err) {
        console.log(`   ✗ L1 Server not responding: ${err.message}`);
        issues.push({ step: 'Health Check', error: err.message });
        failed++;
        return { passed, failed, issues };
    }
    
    // -----------------------------------------------------------------
    // STEP 1: Get initial balances
    // -----------------------------------------------------------------
    console.log('');
    console.log('💰 Step 1: Get initial balances...');
    
    let aliceInitial, bobInitial;
    try {
        aliceInitial = await getBalance(ALICE.wallet_address);
        bobInitial = await getBalance(BOB.wallet_address);
        
        console.log(`   Alice: ${aliceInitial.balance} BB ($${(aliceInitial.balance * 0.01).toFixed(2)} USD)`);
        console.log(`   Bob:   ${bobInitial.balance} BB ($${(bobInitial.balance * 0.01).toFixed(2)} USD)`);
        passed++;
    } catch (err) {
        console.log(`   ✗ Failed to get balances: ${err.message}`);
        issues.push({ step: 'Get Initial Balances', error: err.message });
        failed++;
    }
    
    // -----------------------------------------------------------------
    // STEP 2: Alice sends 100 BB to Bob
    // -----------------------------------------------------------------
    console.log('');
    console.log('📤 Step 2: Alice sends 100 BB to Bob...');
    
    const TRANSFER_AMOUNT = 100; // 100 BB = $1.00 USD
    
    try {
        const result = await transfer(ALICE, BOB.wallet_address, TRANSFER_AMOUNT);
        
        if (result.status === 200 && result.data.success) {
            console.log(`   ✓ Transfer successful!`);
            console.log(`   ✓ TX Hash: ${result.data.tx_hash || result.data.signature || 'N/A'}`);
            passed++;
        } else {
            console.log(`   ✗ Transfer failed!`);
            console.log(`   ✗ Status: ${result.status}`);
            console.log(`   ✗ Response: ${JSON.stringify(result.data, null, 2)}`);
            issues.push({ 
                step: 'Transfer 100 BB', 
                error: result.data.error || result.data.message || JSON.stringify(result.data)
            });
            failed++;
        }
    } catch (err) {
        console.log(`   ✗ Transfer error: ${err.message}`);
        issues.push({ step: 'Transfer 100 BB', error: err.message });
        failed++;
    }
    
    // -----------------------------------------------------------------
    // STEP 3: Verify final balances
    // -----------------------------------------------------------------
    console.log('');
    console.log('🔍 Step 3: Verify final balances...');
    
    try {
        const aliceFinal = await getBalance(ALICE.wallet_address);
        const bobFinal = await getBalance(BOB.wallet_address);
        
        console.log(`   Alice: ${aliceFinal.balance} BB (was ${aliceInitial.balance})`);
        console.log(`   Bob:   ${bobFinal.balance} BB (was ${bobInitial.balance})`);
        
        const aliceDiff = aliceFinal.balance - aliceInitial.balance;
        const bobDiff = bobFinal.balance - bobInitial.balance;
        
        console.log(`   Alice change: ${aliceDiff >= 0 ? '+' : ''}${aliceDiff} BB`);
        console.log(`   Bob change:   ${bobDiff >= 0 ? '+' : ''}${bobDiff} BB`);
        
        // Verify Alice decreased by ~100 BB (maybe minus fees)
        if (aliceDiff <= -TRANSFER_AMOUNT + 1 && aliceDiff >= -TRANSFER_AMOUNT - 10) {
            console.log(`   ✓ Alice balance decreased correctly`);
            passed++;
        } else if (aliceDiff === 0) {
            console.log(`   ✗ Alice balance unchanged (transfer may have failed)`);
            issues.push({ step: 'Verify Alice Balance', error: `Expected -${TRANSFER_AMOUNT}, got ${aliceDiff}` });
            failed++;
        } else {
            console.log(`   ⚠ Alice balance change unexpected: ${aliceDiff}`);
            issues.push({ step: 'Verify Alice Balance', error: `Expected ~-${TRANSFER_AMOUNT}, got ${aliceDiff}` });
            failed++;
        }
        
        // Verify Bob increased by exactly 100 BB
        if (bobDiff === TRANSFER_AMOUNT) {
            console.log(`   ✓ Bob balance increased correctly (+${TRANSFER_AMOUNT} BB)`);
            passed++;
        } else if (bobDiff === 0) {
            console.log(`   ✗ Bob balance unchanged (transfer may have failed)`);
            issues.push({ step: 'Verify Bob Balance', error: `Expected +${TRANSFER_AMOUNT}, got ${bobDiff}` });
            failed++;
        } else {
            console.log(`   ⚠ Bob balance change unexpected: ${bobDiff}`);
            issues.push({ step: 'Verify Bob Balance', error: `Expected +${TRANSFER_AMOUNT}, got ${bobDiff}` });
            failed++;
        }
    } catch (err) {
        console.log(`   ✗ Failed to verify balances: ${err.message}`);
        issues.push({ step: 'Verify Final Balances', error: err.message });
        failed++;
    }
    
    // -----------------------------------------------------------------
    // STEP 4: Test replay attack protection (use same signature again)
    // -----------------------------------------------------------------
    console.log('');
    console.log('🛡️  Step 4: Test replay attack protection...');
    
    try {
        // Create a signed request
        const payload = {
            action: 'transfer',
            to: BOB.wallet_address,
            amount: 50
        };
        const signedRequest = createSignedRequest(ALICE, payload);
        
        // Send it once
        const res1 = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        const data1 = await res1.json();
        console.log(`   First request: ${data1.success ? 'SUCCESS' : 'FAILED'} (expected: SUCCESS)`);
        
        // Try to replay the EXACT same signed request
        const res2 = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)  // Same signature!
        });
        const data2 = await res2.json();
        console.log(`   Replay attempt: ${data2.success ? 'SUCCESS' : 'REJECTED'} (expected: REJECTED)`);
        
        if (!data2.success) {
            console.log(`   ✓ Replay attack properly rejected!`);
            console.log(`   ✓ Reason: ${data2.error || data2.message || 'nonce/signature already used'}`);
            passed++;
        } else {
            console.log(`   ✗ SECURITY ISSUE: Replay attack succeeded!`);
            issues.push({ step: 'Replay Protection', error: 'Replay attack was not blocked!' });
            failed++;
        }
    } catch (err) {
        console.log(`   ✗ Replay test error: ${err.message}`);
        issues.push({ step: 'Replay Protection', error: err.message });
        failed++;
    }
    
    // -----------------------------------------------------------------
    // STEP 5: Test insufficient balance rejection
    // -----------------------------------------------------------------
    console.log('');
    console.log('💸 Step 5: Test insufficient balance rejection...');
    
    try {
        // Alice tries to send more than she has
        const result = await transfer(ALICE, BOB.wallet_address, 999999);
        
        if (!result.data.success) {
            console.log(`   ✓ Insufficient balance properly rejected!`);
            console.log(`   ✓ Reason: ${result.data.error || result.data.message}`);
            passed++;
        } else {
            console.log(`   ✗ CRITICAL: Sent 999,999 BB with insufficient funds!`);
            issues.push({ step: 'Insufficient Balance Check', error: 'Over-transfer was allowed!' });
            failed++;
        }
    } catch (err) {
        console.log(`   ✗ Insufficient balance test error: ${err.message}`);
        issues.push({ step: 'Insufficient Balance Check', error: err.message });
        failed++;
    }
    
    return { passed, failed, issues };
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    try {
        const result = await runTest();
        
        console.log('');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log('                    TEST 1.1 RESULTS                           ');
        console.log('═══════════════════════════════════════════════════════════════');
        console.log(`   ✓ Passed: ${result.passed}`);
        console.log(`   ✗ Failed: ${result.failed}`);
        console.log(`   Status: ${result.failed === 0 ? '✅ ALL PASSED' : '❌ ISSUES FOUND'}`);
        
        if (result.issues.length > 0) {
            console.log('');
            console.log('   📋 Issues to investigate:');
            result.issues.forEach((issue, i) => {
                console.log(`      ${i + 1}. [${issue.step}] ${issue.error}`);
            });
        }
        
        console.log('═══════════════════════════════════════════════════════════════');
        
        // Return exit code based on results
        process.exit(result.failed === 0 ? 0 : 1);
        
    } catch (err) {
        console.error('Fatal error:', err);
        process.exit(1);
    }
}

main();
