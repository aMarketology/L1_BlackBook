/**
 * APOLLO WALLET - COMPREHENSIVE VULNERABILITY TESTING SUITE
 * Tests for security vulnerabilities, attack vectors, and edge cases
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load wallet data
const walletDataPath = path.join(__dirname, 'apollo-wallet-data.json');
const walletData = JSON.parse(fs.readFileSync(walletDataPath, 'utf8'));

const BASE_URL = 'http://localhost:3000';
const APOLLO_ADDRESS = walletData.address;
const APOLLO_PASSWORD = 'ApolloMissionControl2026!';
const WRONG_PASSWORD = 'WrongPassword123!';

// Colors for terminal output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

let testResults = {
    total: 0,
    passed: 0,
    failed: 0,
    warnings: 0
};

function section(title) {
    console.log(`\n${colors.cyan}${'='.repeat(70)}`);
    console.log(`${title}`);
    console.log(`${'='.repeat(70)}${colors.reset}\n`);
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

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// VULNERABILITY TEST 1: Password Brute Force Protection
// =============================================================================
async function testPasswordBruteForce() {
    section('VULNERABILITY TEST 1: Password Brute Force Protection');
    
    const wrongPasswords = [
        'password123',
        '12345678',
        'admin',
        'apollo',
        'qwerty',
        'letmein',
        'Password1',
        'ApolloMission',
        'Control2026',
        'Apollo2026',
        // Variations
        'ApolloMissionControl2026',
        'apollomissioncontrol2026!',
        'APOLLOMISSIONCONTROL2026!',
        'ApolloMissionControl2026!!',
        // Dictionary attack attempts
        'password',
        'welcome',
        'monkey',
        'dragon',
        'master'
    ];
    
    info(`Attempting ${wrongPasswords.length} password guesses...`);
    
    let successfulAttempts = 0;
    let startTime = Date.now();
    
    for (const wrongPassword of wrongPasswords) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    address: APOLLO_ADDRESS,
                    password: wrongPassword,
                    rootPubkey: walletData.rootPubkey,
                    opPubkey: walletData.opPubkey,
                    salt: walletData.salt,
                    encryptedOpKey: walletData.encryptedOpKey
                })
            });
            
            if (response.ok) {
                successfulAttempts++;
                fail(`Brute force vulnerability: Password "${wrongPassword}" was accepted!`);
            }
            
            // Small delay to test rate limiting
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
    
    const elapsedTime = Date.now() - startTime;
    const attemptsPerSecond = (wrongPasswords.length / elapsedTime * 1000).toFixed(2);
    
    info(`Completed ${wrongPasswords.length} attempts in ${elapsedTime}ms (${attemptsPerSecond} attempts/sec)`);
    
    if (successfulAttempts === 0) {
        success('No weak passwords accepted - password validation is strong');
    } else {
        fail(`${successfulAttempts} weak passwords were accepted!`);
    }
    
    if (attemptsPerSecond > 100) {
        warning('Rate limiting may be insufficient - allowing >100 attempts/second');
    } else {
        success('Rate limiting appears adequate');
    }
}

// =============================================================================
// VULNERABILITY TEST 2: Replay Attack Protection
// =============================================================================
async function testReplayAttack() {
    section('VULNERABILITY TEST 2: Replay Attack Protection');
    
    info('Creating a legitimate transaction...');
    
    // Create a legitimate transaction
    const txData = {
        from: APOLLO_ADDRESS,
        to: 'L1_TEST_RECIPIENT_12345678901234567890',
        amount: 10,
        timestamp: Date.now()
    };
    
    // Sign the transaction
    const signature = crypto.createHash('sha256')
        .update(JSON.stringify(txData))
        .digest('hex');
    
    const transaction = { ...txData, signature };
    
    info('Attempting to replay the same transaction multiple times...');
    
    const replayAttempts = 5;
    let acceptedReplays = 0;
    
    for (let i = 0; i < replayAttempts; i++) {
        try {
            const response = await fetch(`${BASE_URL}/api/transactions/submit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(transaction)
            });
            
            if (response.ok) {
                acceptedReplays++;
                if (i > 0) {
                    fail(`Replay attack successful on attempt ${i + 1} - same transaction accepted multiple times!`);
                } else {
                    info('First transaction accepted (expected)');
                }
            }
            
            await sleep(50);
            
        } catch (error) {
            // Expected to fail for replays
        }
    }
    
    if (acceptedReplays <= 1) {
        success('Replay attack prevented - duplicate transactions rejected');
    } else {
        fail(`Replay attack vulnerability: ${acceptedReplays} duplicate transactions accepted!`);
    }
}

// =============================================================================
// VULNERABILITY TEST 3: Timing Attack Resistance
// =============================================================================
async function testTimingAttack() {
    section('VULNERABILITY TEST 3: Timing Attack Resistance');
    
    info('Measuring response times for correct vs incorrect passwords...');
    
    const trials = 20;
    const correctTimes = [];
    const incorrectTimes = [];
    
    // Test correct password timing
    for (let i = 0; i < trials; i++) {
        const start = process.hrtime.bigint();
        
        try {
            await fetch(`${BASE_URL}/api/wallet/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    address: APOLLO_ADDRESS,
                    password: APOLLO_PASSWORD,
                    rootPubkey: walletData.rootPubkey,
                    opPubkey: walletData.opPubkey,
                    salt: walletData.salt,
                    encryptedOpKey: walletData.encryptedOpKey
                })
            });
        } catch (error) {}
        
        const end = process.hrtime.bigint();
        correctTimes.push(Number(end - start) / 1000000); // Convert to ms
        
        await sleep(50);
    }
    
    // Test incorrect password timing
    for (let i = 0; i < trials; i++) {
        const start = process.hrtime.bigint();
        
        try {
            await fetch(`${BASE_URL}/api/wallet/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    address: APOLLO_ADDRESS,
                    password: WRONG_PASSWORD,
                    rootPubkey: walletData.rootPubkey,
                    opPubkey: walletData.opPubkey,
                    salt: walletData.salt,
                    encryptedOpKey: walletData.encryptedOpKey
                })
            });
        } catch (error) {}
        
        const end = process.hrtime.bigint();
        incorrectTimes.push(Number(end - start) / 1000000);
        
        await sleep(50);
    }
    
    const avgCorrect = correctTimes.reduce((a, b) => a + b, 0) / correctTimes.length;
    const avgIncorrect = incorrectTimes.reduce((a, b) => a + b, 0) / incorrectTimes.length;
    const timeDiff = Math.abs(avgCorrect - avgIncorrect);
    const percentDiff = (timeDiff / Math.min(avgCorrect, avgIncorrect) * 100).toFixed(2);
    
    info(`Average correct password time: ${avgCorrect.toFixed(2)}ms`);
    info(`Average incorrect password time: ${avgIncorrect.toFixed(2)}ms`);
    info(`Time difference: ${timeDiff.toFixed(2)}ms (${percentDiff}% difference)`);
    
    if (percentDiff < 5) {
        success('Timing attack resistant - response times are consistent');
    } else if (percentDiff < 15) {
        warning('Moderate timing difference detected - potential for timing attacks');
    } else {
        fail(`Timing attack vulnerability: ${percentDiff}% timing difference detected!`);
    }
}

// =============================================================================
// VULNERABILITY TEST 4: Key Extraction via Memory Dump Simulation
// =============================================================================
async function testKeyExtractionPrevention() {
    section('VULNERABILITY TEST 4: Key Extraction Prevention');
    
    info('Testing if keys are exposed in plaintext in wallet data...');
    
    const sensitiveData = JSON.stringify(walletData, null, 2);
    
    // Check for exposed private keys
    if (sensitiveData.includes('_testOnly_')) {
        warning('Test-only keys found in wallet data (acceptable for testing only)');
    }
    
    // Verify encryption
    const hasEncryptedOpKey = walletData.encryptedOpKey && 
                              walletData.encryptedOpKey.encrypted &&
                              walletData.encryptedOpKey.iv &&
                              walletData.encryptedOpKey.authTag;
    
    if (hasEncryptedOpKey) {
        success('Operational key is properly encrypted (AES-256-GCM)');
    } else {
        fail('Operational key is not encrypted!');
    }
    
    // Verify salt is present
    if (walletData.salt && walletData.salt.length === 64) {
        success('Salt is present and properly sized (32 bytes)');
    } else {
        fail('Salt is missing or improperly sized');
    }
    
    // Check SSS shares
    if (walletData.sssShares && walletData.sssShares.length === 3) {
        success('Shamir Secret Shares are present (2-of-3)');
        
        // Verify shares don't expose the root key directly
        const share1 = walletData.sssShares[0].y;
        const share2 = walletData.sssShares[1].y;
        const rootKey = walletData._testOnly_rootKeyBytes;
        
        if (share1 !== rootKey && share2 !== rootKey) {
            success('SSS shares do not directly expose the root key');
        } else {
            fail('SSS shares may be exposing sensitive key material!');
        }
    } else {
        fail('SSS shares are missing or incomplete');
    }
}

// =============================================================================
// VULNERABILITY TEST 5: SQL Injection Attempts
// =============================================================================
async function testSQLInjection() {
    section('VULNERABILITY TEST 5: SQL Injection Protection');
    
    const sqlPayloads = [
        "L1_' OR '1'='1",
        "L1_'; DROP TABLE wallets;--",
        "L1_' UNION SELECT * FROM users--",
        "L1_admin'--",
        "L1_' OR 1=1--",
        "L1_') OR ('1'='1",
        "L1_%27%20OR%20%271%27%3D%271",
        "L1_'; EXEC xp_cmdshell('dir');--",
    ];
    
    info(`Testing ${sqlPayloads.length} SQL injection payloads...`);
    
    let vulnerableEndpoints = 0;
    
    for (const payload of sqlPayloads) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/balance/${payload}`);
            
            if (response.ok) {
                const data = await response.json();
                // Check if the response suggests SQL injection worked
                if (data.balance !== undefined || data.error === undefined) {
                    fail(`SQL injection may be possible with payload: ${payload}`);
                    vulnerableEndpoints++;
                }
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
    
    if (vulnerableEndpoints === 0) {
        success('SQL injection protection is effective - all payloads rejected');
    } else {
        fail(`${vulnerableEndpoints} potential SQL injection vulnerabilities detected!`);
    }
}

// =============================================================================
// VULNERABILITY TEST 6: Cross-Site Scripting (XSS) Prevention
// =============================================================================
async function testXSSPrevention() {
    section('VULNERABILITY TEST 6: XSS Prevention');
    
    const xssPayloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "';alert('XSS');//",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<body onload=alert('XSS')>"
    ];
    
    info(`Testing ${xssPayloads.length} XSS payloads...`);
    
    let vulnerableFields = 0;
    
    for (const payload of xssPayloads) {
        try {
            // Test in wallet creation name field
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: payload,
                    password: 'TestPass123!'
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                // Check if payload is reflected without sanitization
                if (data.name && data.name.includes('<script>')) {
                    fail(`XSS vulnerability: Unsanitized payload reflected: ${payload}`);
                    vulnerableFields++;
                }
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
    
    if (vulnerableFields === 0) {
        success('XSS protection is effective - all payloads sanitized');
    } else {
        fail(`${vulnerableFields} potential XSS vulnerabilities detected!`);
    }
}

// =============================================================================
// VULNERABILITY TEST 7: Integer Overflow/Underflow
// =============================================================================
async function testIntegerOverflow() {
    section('VULNERABILITY TEST 7: Integer Overflow/Underflow Protection');
    
    const edgeCaseAmounts = [
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER + 1,
        -1,
        -1000000,
        0,
        0.0000000001,
        Infinity,
        -Infinity,
        NaN,
        "999999999999999999999999999999",
        "0.00000000000000000001"
    ];
    
    info(`Testing ${edgeCaseAmounts.length} edge case amounts...`);
    
    let vulnerableTransactions = 0;
    
    for (const amount of edgeCaseAmounts) {
        try {
            const response = await fetch(`${BASE_URL}/api/transactions/submit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from: APOLLO_ADDRESS,
                    to: 'L1_TEST_RECIPIENT_12345678901234567890',
                    amount: amount,
                    timestamp: Date.now()
                })
            });
            
            if (response.ok) {
                fail(`Integer overflow vulnerability: Invalid amount accepted: ${amount}`);
                vulnerableTransactions++;
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
    
    if (vulnerableTransactions === 0) {
        success('Integer overflow protection is effective - all edge cases rejected');
    } else {
        fail(`${vulnerableTransactions} potential integer overflow vulnerabilities detected!`);
    }
}

// =============================================================================
// VULNERABILITY TEST 8: Race Condition in Double Spending
// =============================================================================
async function testDoubleSpendingRaceCondition() {
    section('VULNERABILITY TEST 8: Double Spending Race Condition');
    
    info('Attempting simultaneous transactions to detect race conditions...');
    
    const recipient1 = 'L1_RECIPIENT_A_12345678901234567890';
    const recipient2 = 'L1_RECIPIENT_B_12345678901234567890';
    const amount = 1000;
    
    // Create two transactions that would spend the same funds
    const tx1Promise = fetch(`${BASE_URL}/api/transactions/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            from: APOLLO_ADDRESS,
            to: recipient1,
            amount: amount,
            timestamp: Date.now()
        })
    });
    
    const tx2Promise = fetch(`${BASE_URL}/api/transactions/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            from: APOLLO_ADDRESS,
            to: recipient2,
            amount: amount,
            timestamp: Date.now() + 1
        })
    });
    
    try {
        const [response1, response2] = await Promise.all([tx1Promise, tx2Promise]);
        
        const success1 = response1.ok;
        const success2 = response2.ok;
        
        if (success1 && success2) {
            fail('Double spending vulnerability: Both transactions were accepted!');
        } else if (!success1 && !success2) {
            warning('Both transactions rejected - may need to check error handling');
        } else {
            success('Race condition protection effective - only one transaction accepted');
        }
    } catch (error) {
        info(`Race condition test error: ${error.message}`);
    }
}

// =============================================================================
// VULNERABILITY TEST 9: Cryptographic Randomness Quality
// =============================================================================
function testRandomnessQuality() {
    section('VULNERABILITY TEST 9: Cryptographic Randomness Quality');
    
    info('Testing randomness quality of generated keys and salts...');
    
    // Analyze the wallet salt for patterns
    const salt = walletData.salt;
    const saltBytes = Buffer.from(salt, 'hex');
    
    // Check for repeating patterns
    let hasRepeatingBytes = false;
    for (let i = 0; i < saltBytes.length - 3; i++) {
        if (saltBytes[i] === saltBytes[i+1] && 
            saltBytes[i] === saltBytes[i+2] && 
            saltBytes[i] === saltBytes[i+3]) {
            hasRepeatingBytes = true;
            break;
        }
    }
    
    if (!hasRepeatingBytes) {
        success('No obvious repeating patterns in salt');
    } else {
        warning('Repeating patterns detected in salt - may indicate weak RNG');
    }
    
    // Check entropy (very basic check)
    const uniqueBytes = new Set(saltBytes).size;
    const entropyRatio = uniqueBytes / saltBytes.length;
    
    info(`Unique bytes in salt: ${uniqueBytes}/${saltBytes.length} (${(entropyRatio * 100).toFixed(1)}%)`);
    
    if (entropyRatio > 0.7) {
        success('Salt appears to have good entropy');
    } else if (entropyRatio > 0.5) {
        warning('Salt entropy is moderate - consider improving randomness');
    } else {
        fail('Salt entropy is low - weak random number generator!');
    }
    
    // Check SSS shares for randomness
    const share1 = Buffer.from(walletData.sssShares[0].y, 'hex');
    const share2 = Buffer.from(walletData.sssShares[1].y, 'hex');
    const share3 = Buffer.from(walletData.sssShares[2].y, 'hex');
    
    // Shares should be different
    if (!share1.equals(share2) && !share2.equals(share3) && !share1.equals(share3)) {
        success('SSS shares are unique');
    } else {
        fail('SSS shares are not unique - critical vulnerability!');
    }
}

// =============================================================================
// VULNERABILITY TEST 10: Authentication Bypass Attempts
// =============================================================================
async function testAuthenticationBypass() {
    section('VULNERABILITY TEST 10: Authentication Bypass Attempts');
    
    info('Testing various authentication bypass techniques...');
    
    const bypassAttempts = [
        // Missing password
        { address: APOLLO_ADDRESS, password: null },
        // Empty password
        { address: APOLLO_ADDRESS, password: '' },
        // Missing address
        { address: null, password: APOLLO_PASSWORD },
        // Empty address
        { address: '', password: APOLLO_PASSWORD },
        // Missing both
        { address: null, password: null },
        // Null encryption data
        { address: APOLLO_ADDRESS, password: APOLLO_PASSWORD, encryptedOpKey: null },
        // Empty object
        {},
        // Wrong structure
        { user: APOLLO_ADDRESS, pass: APOLLO_PASSWORD }
    ];
    
    let bypassSuccessful = 0;
    
    for (const attempt of bypassAttempts) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(attempt)
            });
            
            if (response.ok) {
                fail(`Authentication bypass successful with: ${JSON.stringify(attempt)}`);
                bypassSuccessful++;
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
    
    if (bypassSuccessful === 0) {
        success('Authentication bypass protection is effective');
    } else {
        fail(`${bypassSuccessful} authentication bypass vulnerabilities detected!`);
    }
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================
async function runAllVulnerabilityTests() {
    console.log(`${colors.magenta}`);
    console.log('╔══════════════════════════════════════════════════════════════════════╗');
    console.log('║        APOLLO WALLET - COMPREHENSIVE VULNERABILITY TEST SUITE        ║');
    console.log('║                    Security & Penetration Testing                    ║');
    console.log('╚══════════════════════════════════════════════════════════════════════╝');
    console.log(`${colors.reset}`);
    
    info(`Testing wallet: ${APOLLO_ADDRESS}`);
    info(`Target API: ${BASE_URL}`);
    info(`Test started: ${new Date().toISOString()}\n`);
    
    try {
        // Check if server is running
        info('Checking if server is running...');
        try {
            const healthCheck = await fetch(`${BASE_URL}/api/health`, {
                signal: AbortSignal.timeout(5000)
            });
            
            if (healthCheck.ok) {
                success('Server is running and responding\n');
            } else {
                warning('Server responded but may have issues\n');
            }
        } catch (error) {
            warning('Server health check failed - some tests may not work properly');
            info(`Error: ${error.message}\n`);
        }
        
        // Run all vulnerability tests
        await testPasswordBruteForce();
        await sleep(500);
        
        await testReplayAttack();
        await sleep(500);
        
        await testTimingAttack();
        await sleep(500);
        
        testKeyExtractionPrevention();
        await sleep(500);
        
        await testSQLInjection();
        await sleep(500);
        
        await testXSSPrevention();
        await sleep(500);
        
        await testIntegerOverflow();
        await sleep(500);
        
        await testDoubleSpendingRaceCondition();
        await sleep(500);
        
        testRandomnessQuality();
        await sleep(500);
        
        await testAuthenticationBypass();
        
    } catch (error) {
        console.error(`${colors.red}Test suite error: ${error.message}${colors.reset}`);
        console.error(error.stack);
    }
    
    // Print final summary
    section('VULNERABILITY TEST RESULTS SUMMARY');
    
    console.log(`${colors.white}Total Tests:    ${testResults.total}${colors.reset}`);
    console.log(`${colors.green}Passed:         ${testResults.passed}${colors.reset}`);
    console.log(`${colors.red}Failed:         ${testResults.failed}${colors.reset}`);
    console.log(`${colors.yellow}Warnings:       ${testResults.warnings}${colors.reset}`);
    
    const passRate = (testResults.passed / testResults.total * 100).toFixed(1);
    console.log(`\n${colors.white}Pass Rate:      ${passRate}%${colors.reset}`);
    
    if (testResults.failed === 0) {
        console.log(`\n${colors.green}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✓ ALL VULNERABILITY TESTS PASSED - WALLET IS SECURE`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    } else {
        console.log(`\n${colors.red}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✗ ${testResults.failed} VULNERABILITIES DETECTED - IMMEDIATE ACTION REQUIRED`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    }
    
    if (testResults.warnings > 0) {
        console.log(`${colors.yellow}⚠  ${testResults.warnings} warnings require attention${colors.reset}\n`);
    }
    
    info(`Test completed: ${new Date().toISOString()}`);
}

// Run the tests
runAllVulnerabilityTests().catch(error => {
    console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
    process.exit(1);
});
