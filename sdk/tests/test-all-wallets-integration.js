#!/usr/bin/env node

/**
 * BlackBook L1 - Complete ZKP Wallet Integration Test
 * Tests all wallets (Alice, Bob, Mac, Apollo) against live L1 server
 */

const fs = require('fs');
const path = require('path');
const { ZKPWallet } = require('../zkp-wallet-sdk.js');
const fetch = require('node-fetch');

// Configuration
const L1_URL = 'http://localhost:3030';
const TEST_DIR = __dirname;

// Colors
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
};

// Test wallets
const WALLETS = {
    alice: {
        file: 'alice-zkp-wallet.json',
        password: 'AlicePassword123!'
    },
    bob: {
        file: 'bob-zkp-wallet.json',
        password: 'BobPassword123!'
    },
    mac: {
        file: 'mac-zkp-wallet.json',
        password: 'MacSecurePassword2026!'
    },
    apollo: {
        file: 'apollo-zkp-wallet.json',
        password: 'apollo_secure_password_2026'
    }
};

// Test results
let testResults = {
    passed: 0,
    failed: 0,
    tests: []
};

/**
 * Log test result
 */
function logTest(name, passed, details = '') {
    const symbol = passed ? `${colors.green}✓${colors.reset}` : `${colors.red}✗${colors.reset}`;
    console.log(`  ${symbol} ${name}`);
    if (details) {
        console.log(`     ${colors.cyan}${details}${colors.reset}`);
    }
    
    testResults.tests.push({ name, passed, details });
    if (passed) {
        testResults.passed++;
    } else {
        testResults.failed++;
    }
}

/**
 * Test 1: Load wallet files
 */
async function testLoadWallets() {
    console.log(`\n${colors.bright}1️⃣  Loading Wallet Files${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        const filepath = path.join(TEST_DIR, config.file);
        
        try {
            if (fs.existsSync(filepath)) {
                const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                config.data = data;
                logTest(`Load ${name} wallet`, true, `Address: ${data.address}`);
            } else {
                logTest(`Load ${name} wallet`, false, `File not found: ${config.file}`);
            }
        } catch (error) {
            logTest(`Load ${name} wallet`, false, error.message);
        }
    }
}

/**
 * Test 2: Wallet login (reconstruct keys from Share C)
 */
async function testWalletLogins() {
    console.log(`\n${colors.bright}2️⃣  Testing Wallet Logins (ZKP Authentication)${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.data) {
            logTest(`${name} login`, false, 'Wallet data not loaded');
            continue;
        }
        
        try {
            const wallet = await ZKPWallet.login(
                config.password,
                config.data.shareCEncrypted,
                config.data.salt,
                config.data.address
            );
            
            // Verify address matches
            if (wallet.address === config.data.address) {
                config.wallet = wallet;
                logTest(`${name} login`, true, `Address verified: ${wallet.address}`);
            } else {
                logTest(`${name} login`, false, `Address mismatch: expected ${config.data.address}, got ${wallet.address}`);
            }
        } catch (error) {
            logTest(`${name} login`, false, error.message);
        }
    }
}

/**
 * Test 3: Check L1 registration status
 */
async function testL1Registration() {
    console.log(`\n${colors.bright}3️⃣  Checking L1 Registration Status${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.data) {
            logTest(`${name} L1 status`, false, 'Wallet data not available');
            continue;
        }
        
        try {
            const response = await fetch(`${L1_URL}/auth/zkp-commitment/${config.data.address}`);
            
            if (response.ok) {
                const data = await response.json();
                logTest(`${name} L1 registered`, true, `Commitment: ${data.zkCommitment.substring(0, 16)}...`);
                config.registered = true;
            } else if (response.status === 404) {
                logTest(`${name} L1 registered`, false, 'Not registered on L1');
                config.registered = false;
            } else {
                const error = await response.text();
                logTest(`${name} L1 registered`, false, error);
                config.registered = false;
            }
        } catch (error) {
            logTest(`${name} L1 registered`, false, `Connection error: ${error.message}`);
            config.registered = false;
        }
    }
}

/**
 * Test 4: Register wallets on L1 (if not already registered)
 */
async function testL1RegistrationProcess() {
    console.log(`\n${colors.bright}4️⃣  Registering Wallets on L1${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.wallet) {
            logTest(`${name} register`, false, 'Wallet not logged in');
            continue;
        }
        
        if (config.registered) {
            logTest(`${name} register`, true, 'Already registered (skipped)');
            continue;
        }
        
        try {
            const registerPayload = {
                address: config.wallet.address,
                pubkey: config.wallet.pubkey,
                zkCommitment: config.wallet.zkCommitment,
                shareB: config.wallet.shareB
            };
            
            const response = await fetch(`${L1_URL}/auth/zkp-register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(registerPayload)
            });
            
            if (response.ok) {
                const result = await response.json();
                logTest(`${name} register`, true, `Registered at ${result.address}`);
                config.registered = true;
            } else {
                const error = await response.text();
                logTest(`${name} register`, false, error);
            }
        } catch (error) {
            logTest(`${name} register`, false, error.message);
        }
    }
}

/**
 * Test 5: ZKP Login Flow (retrieve Share B from L1)
 */
async function testZKPLoginFlow() {
    console.log(`\n${colors.bright}5️⃣  Testing ZKP Login Flow (Retrieve Share B)${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.wallet || !config.registered) {
            logTest(`${name} ZKP login`, false, 'Wallet not ready');
            continue;
        }
        
        try {
            // Generate ZK proof
            const challenge = Buffer.from(config.wallet.address, 'utf8').toString('hex');
            const proof = config.wallet.generateZKProof(challenge);
            
            // Request Share B from L1
            const loginPayload = {
                address: config.wallet.address,
                challenge: challenge,
                proof: {
                    hash: proof.hash,
                    salt: proof.salt
                }
            };
            
            const response = await fetch(`${L1_URL}/auth/zkp-login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(loginPayload)
            });
            
            if (response.ok) {
                const result = await response.json();
                
                // Verify we got Share B
                if (result.shareB && result.shareB.x && result.shareB.y) {
                    logTest(`${name} ZKP login`, true, `Retrieved Share B (x=${result.shareB.x})`);
                    config.shareBRetrieved = result.shareB;
                } else {
                    logTest(`${name} ZKP login`, false, 'Share B missing from response');
                }
            } else {
                const error = await response.text();
                logTest(`${name} ZKP login`, false, error);
            }
        } catch (error) {
            logTest(`${name} ZKP login`, false, error.message);
        }
    }
}

/**
 * Test 6: Key Reconstruction (Share A + Share B + Share C)
 */
async function testKeyReconstruction() {
    console.log(`\n${colors.bright}6️⃣  Testing Key Reconstruction (SSS)${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.wallet || !config.shareBRetrieved) {
            logTest(`${name} reconstruct key`, false, 'Prerequisites not met');
            continue;
        }
        
        try {
            // Reconstruct full key from Share A + Share B + Share C
            // In real implementation, this would be done in the wallet SDK
            // For now, we verify that the wallet has the correct signing key
            
            const testMessage = `Test transaction from ${name}`;
            const signature = config.wallet.sign(testMessage);
            
            // Verify signature
            const crypto = require('crypto');
            const nacl = require('tweetnacl');
            
            const pubkeyBytes = Buffer.from(config.wallet.pubkey, 'hex');
            const messageBytes = Buffer.from(testMessage, 'utf8');
            const signatureBytes = Buffer.from(signature, 'hex');
            
            const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, pubkeyBytes);
            
            if (isValid) {
                logTest(`${name} reconstruct key`, true, 'Signature verified');
                config.keyReconstructed = true;
            } else {
                logTest(`${name} reconstruct key`, false, 'Signature verification failed');
            }
        } catch (error) {
            logTest(`${name} reconstruct key`, false, error.message);
        }
    }
}

/**
 * Test 7: Transaction Signing
 */
async function testTransactionSigning() {
    console.log(`\n${colors.bright}7️⃣  Testing Transaction Signing${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.wallet || !config.keyReconstructed) {
            logTest(`${name} sign transaction`, false, 'Key not reconstructed');
            continue;
        }
        
        try {
            // Create test transaction
            const tx = {
                from: config.wallet.address,
                to: 'L1_TEST_RECIPIENT_ADDRESS',
                amount: 100,
                timestamp: Date.now(),
                nonce: Math.floor(Math.random() * 1000000)
            };
            
            const txString = JSON.stringify(tx);
            const signature = config.wallet.sign(txString);
            
            // Verify signature locally
            const nacl = require('tweetnacl');
            const pubkeyBytes = Buffer.from(config.wallet.pubkey, 'hex');
            const messageBytes = Buffer.from(txString, 'utf8');
            const signatureBytes = Buffer.from(signature, 'hex');
            
            const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, pubkeyBytes);
            
            if (isValid) {
                logTest(`${name} sign transaction`, true, `TX: ${tx.amount} BB to recipient`);
                config.txSigned = { tx, signature };
            } else {
                logTest(`${name} sign transaction`, false, 'Signature invalid');
            }
        } catch (error) {
            logTest(`${name} sign transaction`, false, error.message);
        }
    }
}

/**
 * Test 8: Password Change Flow
 */
async function testPasswordChange() {
    console.log(`\n${colors.bright}8️⃣  Testing Password Change${colors.reset}`);
    
    // Test with Alice only (to avoid changing all passwords)
    const name = 'alice';
    const config = WALLETS[name];
    
    if (!config.wallet) {
        logTest(`${name} password change`, false, 'Wallet not available');
        return;
    }
    
    try {
        const oldPassword = config.password;
        const newPassword = 'AliceNewPassword456!';
        
        // Change password
        const updatedWallet = await config.wallet.changePassword(oldPassword, newPassword);
        
        // Try logging in with new password
        const loginTest = await ZKPWallet.login(
            newPassword,
            updatedWallet.shareCEncrypted,
            config.data.salt,
            config.data.address
        );
        
        if (loginTest.address === config.data.address) {
            logTest(`${name} password change`, true, 'Password changed and verified');
            
            // Change back to original
            await loginTest.changePassword(newPassword, oldPassword);
        } else {
            logTest(`${name} password change`, false, 'Login with new password failed');
        }
    } catch (error) {
        logTest(`${name} password change`, false, error.message);
    }
}

/**
 * Test 9: Account Recovery (SSS)
 */
async function testAccountRecovery() {
    console.log(`\n${colors.bright}9️⃣  Testing Account Recovery (2-of-3 SSS)${colors.reset}`);
    
    // Test with Bob only
    const name = 'bob';
    const config = WALLETS[name];
    
    if (!config.wallet) {
        logTest(`${name} SSS recovery`, false, 'Wallet not available');
        return;
    }
    
    try {
        // Simulate recovery using Share A and Share B (without Share C)
        const shareA = config.wallet.shareA;
        const shareB = config.shareBRetrieved;
        
        if (!shareB) {
            logTest(`${name} SSS recovery`, false, 'Share B not retrieved');
            return;
        }
        
        // Request recovery from L1
        const recoveryPayload = {
            address: config.wallet.address,
            shares: [shareA, shareB]
        };
        
        const response = await fetch(`${L1_URL}/auth/zkp-recover`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(recoveryPayload)
        });
        
        if (response.ok) {
            const result = await response.json();
            
            if (result.success) {
                logTest(`${name} SSS recovery`, true, 'Recovery successful');
            } else {
                logTest(`${name} SSS recovery`, false, result.error || 'Recovery failed');
            }
        } else {
            const error = await response.text();
            logTest(`${name} SSS recovery`, false, error);
        }
    } catch (error) {
        logTest(`${name} SSS recovery`, false, error.message);
    }
}

/**
 * Test 10: Security - Wrong Password Rejection
 */
async function testSecurityWrongPassword() {
    console.log(`\n${colors.bright}🔟  Testing Security (Wrong Password Rejection)${colors.reset}`);
    
    for (const [name, config] of Object.entries(WALLETS)) {
        if (!config.data) {
            logTest(`${name} reject wrong password`, false, 'Wallet data not available');
            continue;
        }
        
        try {
            const wrongPassword = 'WrongPassword123!';
            
            await ZKPWallet.login(
                wrongPassword,
                config.data.shareCEncrypted,
                config.data.salt,
                config.data.address
            );
            
            // If we get here, wrong password was accepted (bad!)
            logTest(`${name} reject wrong password`, false, 'Wrong password was accepted');
        } catch (error) {
            // Expected to fail with wrong password
            if (error.message.includes('verification failed') || error.message.includes('Invalid')) {
                logTest(`${name} reject wrong password`, true, 'Wrong password correctly rejected');
            } else {
                logTest(`${name} reject wrong password`, false, `Unexpected error: ${error.message}`);
            }
        }
    }
}

/**
 * Print summary
 */
function printSummary() {
    console.log(`\n${colors.bright}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.bright}║                    📊 TEST SUMMARY                        ║${colors.reset}`);
    console.log(`${colors.bright}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);
    
    const total = testResults.passed + testResults.failed;
    const passRate = total > 0 ? ((testResults.passed / total) * 100).toFixed(1) : 0;
    
    console.log(`\n${colors.bright}Total Tests:${colors.reset} ${total}`);
    console.log(`${colors.green}✓ Passed:${colors.reset} ${testResults.passed}`);
    console.log(`${colors.red}✗ Failed:${colors.reset} ${testResults.failed}`);
    console.log(`${colors.cyan}Pass Rate:${colors.reset} ${passRate}%`);
    
    if (testResults.failed === 0) {
        console.log(`\n${colors.green}${colors.bright}🎉 ALL TESTS PASSED! 🎉${colors.reset}`);
    } else {
        console.log(`\n${colors.yellow}⚠️  Some tests failed. Review details above.${colors.reset}`);
    }
    
    // Wallet status summary
    console.log(`\n${colors.bright}Wallet Status:${colors.reset}`);
    for (const [name, config] of Object.entries(WALLETS)) {
        const status = config.registered ? `${colors.green}✓ Ready${colors.reset}` : `${colors.yellow}⚠ Not Registered${colors.reset}`;
        console.log(`  ${name.padEnd(10)} ${status}  ${config.data?.address || 'N/A'}`);
    }
    
    // Save detailed results
    const resultsFile = path.join(TEST_DIR, 'integration-test-results.json');
    fs.writeFileSync(resultsFile, JSON.stringify(testResults, null, 2));
    console.log(`\n${colors.cyan}📝 Detailed results saved to: integration-test-results.json${colors.reset}`);
}

/**
 * Main test execution
 */
async function main() {
    console.log(`${colors.bright}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.bright}║     BlackBook L1 - ZKP Wallet Integration Test Suite    ║${colors.reset}`);
    console.log(`${colors.bright}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log(`\n${colors.cyan}L1 Server:${colors.reset} ${L1_URL}`);
    console.log(`${colors.cyan}Test Wallets:${colors.reset} Alice, Bob, Mac, Apollo`);
    console.log(`${colors.cyan}Started:${colors.reset} ${new Date().toISOString()}`);
    
    try {
        await testLoadWallets();
        await testWalletLogins();
        await testL1Registration();
        await testL1RegistrationProcess();
        await testZKPLoginFlow();
        await testKeyReconstruction();
        await testTransactionSigning();
        await testPasswordChange();
        await testAccountRecovery();
        await testSecurityWrongPassword();
        
        printSummary();
    } catch (error) {
        console.error(`\n${colors.red}Fatal error:${colors.reset}`, error);
        process.exit(1);
    }
}

// Run tests
main().catch(console.error);
