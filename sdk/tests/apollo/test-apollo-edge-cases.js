/**
 * APOLLO WALLET - EDGE CASE & DENIAL OF SERVICE ATTACK TESTS
 * Tests for edge cases, DoS vulnerabilities, and resource exhaustion
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const walletDataPath = path.join(__dirname, 'apollo-wallet-data.json');
const walletData = JSON.parse(fs.readFileSync(walletDataPath, 'utf8'));

const BASE_URL = 'http://localhost:3000';
const APOLLO_ADDRESS = walletData.address;

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

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// EDGE CASE 1: Malformed JSON Attacks
// =============================================================================
async function testMalformedJSON() {
    section('EDGE CASE 1: Malformed JSON Attack Resistance');
    
    info('Testing server resilience to malformed JSON...');
    
    const malformedPayloads = [
        '{invalid json}',
        '{"unclosed": "quote}',
        '{"trailing": "comma",}',
        '{unterminated',
        'null',
        'undefined',
        '{"address": undefined}',
        '{"amount": NaN}',
        '{"nested": {"very": {"deeply": {"nested": {"object": {"that": {"goes": {"on": {"forever": {}}}}}}}}}',
        '[]',
        'true',
        '12345',
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
    ];
    
    let crashedServer = 0;
    let acceptedMalformed = 0;
    
    for (const payload of malformedPayloads) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload
            });
            
            if (response.status === 500 || response.status === 502 || response.status === 503) {
                crashedServer++;
                fail(`Server may have crashed or errored on: ${payload.substring(0, 50)}...`);
            } else if (response.ok) {
                acceptedMalformed++;
                warning(`Malformed payload was accepted: ${payload.substring(0, 50)}...`);
            }
            
            await sleep(10);
            
        } catch (error) {
            // Network errors are acceptable for malformed JSON
        }
    }
    
    if (crashedServer === 0) {
        success('Server did not crash on malformed JSON');
    } else {
        fail(`Server crashed/errored ${crashedServer} times on malformed JSON`);
    }
    
    if (acceptedMalformed === 0) {
        success('No malformed JSON was accepted');
    } else {
        warning(`${acceptedMalformed} malformed payloads were accepted`);
    }
}

// =============================================================================
// EDGE CASE 2: Unicode and Special Character Handling
// =============================================================================
async function testUnicodeHandling() {
    section('EDGE CASE 2: Unicode & Special Character Handling');
    
    info('Testing Unicode and special character handling...');
    
    const specialNames = [
        '💎🚀🌙',  // Emojis
        '测试钱包',  // Chinese
        'Тест',  // Cyrillic
        '🔐Apollo🔐',  // Mixed emojis and text
        '\'";DROP TABLE wallets;--',  // SQL injection attempt
        '<script>alert("xss")</script>',  // XSS attempt
        '../../../etc/passwd',  // Path traversal
        '\x00null byte\x00',  // Null byte injection
        '\n\r\t\b\f',  // Control characters
        'A'.repeat(10000),  // Very long string
        '',  // Empty string
        ' ',  // Space
        '\u202E' + 'Apollo',  // Right-to-left override
        'Apollo\u0000Hidden',  // Null byte
    ];
    
    let handledProperly = 0;
    let vulnerabilities = 0;
    
    for (const name of specialNames) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name,
                    password: 'TestPassword123!'
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Check if dangerous content was sanitized
                if (data.name && (
                    data.name.includes('<script>') ||
                    data.name.includes('DROP TABLE') ||
                    data.name.includes('../')
                )) {
                    vulnerabilities++;
                    fail(`Dangerous content not sanitized: ${name.substring(0, 30)}...`);
                } else {
                    handledProperly++;
                }
            } else if (response.status === 400) {
                handledProperly++;
                // Proper rejection is acceptable
            }
            
            await sleep(10);
            
        } catch (error) {
            // Some extreme cases may cause network errors
        }
    }
    
    info(`Properly handled: ${handledProperly}/${specialNames.length}`);
    
    if (vulnerabilities === 0) {
        success('All special characters handled safely');
    } else {
        fail(`${vulnerabilities} Unicode/special character vulnerabilities detected`);
    }
}

// =============================================================================
// EDGE CASE 3: Extremely Large Payload Attack
// =============================================================================
async function testLargePayloadAttack() {
    section('EDGE CASE 3: Large Payload DoS Protection');
    
    info('Testing server resilience to extremely large payloads...');
    
    const sizes = [
        { size: 1024 * 100, name: '100KB' },  // 100KB
        { size: 1024 * 1024, name: '1MB' },  // 1MB
        { size: 1024 * 1024 * 10, name: '10MB' },  // 10MB
    ];
    
    for (const { size, name } of sizes) {
        try {
            const largeString = 'A'.repeat(size);
            const payload = JSON.stringify({
                name: largeString,
                password: 'Test123!'
            });
            
            info(`Sending ${name} payload...`);
            
            const start = Date.now();
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload,
                signal: AbortSignal.timeout(10000)
            });
            const elapsed = Date.now() - start;
            
            if (response.status === 413) {
                success(`${name} payload rejected (payload too large)`);
            } else if (response.status === 400) {
                success(`${name} payload rejected (bad request)`);
            } else if (response.ok) {
                warning(`${name} payload was accepted (took ${elapsed}ms) - potential DoS risk`);
            } else {
                info(`${name} payload resulted in status ${response.status}`);
            }
            
        } catch (error) {
            if (error.name === 'TimeoutError') {
                fail(`Server timed out on ${name} payload - DoS vulnerability!`);
            } else {
                // Other errors are acceptable
                info(`${name} test error: ${error.message}`);
            }
        }
        
        await sleep(100);
    }
}

// =============================================================================
// EDGE CASE 4: Concurrent Request Flooding
// =============================================================================
async function testConcurrentRequestFlooding() {
    section('EDGE CASE 4: Concurrent Request Flooding (DoS)');
    
    info('Testing server resilience to request flooding...');
    
    const concurrentRequests = 100;
    const requests = [];
    
    info(`Sending ${concurrentRequests} concurrent requests...`);
    
    const start = Date.now();
    
    for (let i = 0; i < concurrentRequests; i++) {
        requests.push(
            fetch(`${BASE_URL}/api/wallet/balance/${APOLLO_ADDRESS}`, {
                signal: AbortSignal.timeout(5000)
            }).catch(error => ({ error: true, message: error.message }))
        );
    }
    
    try {
        const results = await Promise.all(requests);
        const elapsed = Date.now() - start;
        
        const successful = results.filter(r => r.ok || (r.status && r.status !== 500)).length;
        const errors = results.filter(r => r.error).length;
        const serverErrors = results.filter(r => r.status === 500 || r.status === 503).length;
        
        info(`Completed in ${elapsed}ms`);
        info(`Successful: ${successful}, Errors: ${errors}, Server errors: ${serverErrors}`);
        
        if (serverErrors > concurrentRequests * 0.1) {
            fail(`High server error rate (${serverErrors}/${concurrentRequests}) - DoS vulnerability!`);
        } else if (serverErrors > 0) {
            warning(`Some server errors detected (${serverErrors}/${concurrentRequests})`);
        } else {
            success('Server handled concurrent requests without errors');
        }
        
        // Check response time
        const avgResponseTime = elapsed / concurrentRequests;
        info(`Average response time: ${avgResponseTime.toFixed(2)}ms`);
        
        if (avgResponseTime > 1000) {
            warning('Slow response time under load - potential DoS risk');
        } else {
            success('Response times are acceptable under load');
        }
        
    } catch (error) {
        fail(`Flooding test failed: ${error.message}`);
    }
}

// =============================================================================
// EDGE CASE 5: Resource Exhaustion - Memory
// =============================================================================
async function testMemoryExhaustion() {
    section('EDGE CASE 5: Memory Exhaustion Protection');
    
    info('Testing for memory exhaustion vulnerabilities...');
    
    // Create deeply nested objects
    const createDeepObject = (depth) => {
        let obj = { value: 'end' };
        for (let i = 0; i < depth; i++) {
            obj = { nested: obj };
        }
        return obj;
    };
    
    const depths = [10, 100, 1000, 5000];
    
    for (const depth of depths) {
        try {
            const deepObject = createDeepObject(depth);
            const payload = JSON.stringify({
                address: APOLLO_ADDRESS,
                metadata: deepObject
            });
            
            info(`Testing with nesting depth ${depth}...`);
            
            const response = await fetch(`${BASE_URL}/api/wallet/metadata`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: payload,
                signal: AbortSignal.timeout(5000)
            });
            
            if (response.status === 400 || response.status === 413) {
                success(`Depth ${depth} rejected - good protection`);
            } else if (response.ok) {
                warning(`Depth ${depth} accepted - potential memory exhaustion risk`);
            }
            
        } catch (error) {
            if (error.name === 'TimeoutError') {
                fail(`Depth ${depth} caused timeout - memory exhaustion vulnerability!`);
            } else {
                // Some errors are acceptable
                info(`Depth ${depth} error: ${error.message}`);
            }
        }
        
        await sleep(50);
    }
}

// =============================================================================
// EDGE CASE 6: Null/Undefined/Special Value Injection
// =============================================================================
async function testSpecialValueInjection() {
    section('EDGE CASE 6: Null/Undefined/Special Value Injection');
    
    info('Testing handling of special JavaScript values...');
    
    const specialValues = [
        { name: 'null', value: null },
        { name: 'empty string', value: '' },
        { name: 'zero', value: 0 },
        { name: 'false', value: false },
        { name: 'negative zero', value: -0 },
        { name: 'empty array', value: [] },
        { name: 'empty object', value: {} },
    ];
    
    for (const { name, value } of specialValues) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: value,
                    password: value
                })
            });
            
            if (response.status === 400) {
                success(`Special value "${name}" properly rejected`);
            } else if (response.ok) {
                fail(`Special value "${name}" was accepted - validation bypass!`);
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
}

// =============================================================================
// EDGE CASE 7: Boundary Value Testing
// =============================================================================
async function testBoundaryValues() {
    section('EDGE CASE 7: Boundary Value Testing');
    
    info('Testing extreme boundary values...');
    
    const boundaryTests = [
        { name: 'Max safe integer', amount: Number.MAX_SAFE_INTEGER },
        { name: 'Max safe integer + 1', amount: Number.MAX_SAFE_INTEGER + 1 },
        { name: 'Min safe integer', amount: Number.MIN_SAFE_INTEGER },
        { name: 'Smallest positive', amount: Number.MIN_VALUE },
        { name: 'Epsilon', amount: Number.EPSILON },
        { name: 'Negative one', amount: -1 },
        { name: 'Very small decimal', amount: 0.0000000001 },
        { name: 'Very large decimal', amount: 999999999999.999999999 },
    ];
    
    for (const { name, amount } of boundaryTests) {
        try {
            const response = await fetch(`${BASE_URL}/api/transactions/submit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from: APOLLO_ADDRESS,
                    to: 'L1_TEST_12345678901234567890',
                    amount: amount,
                    timestamp: Date.now()
                })
            });
            
            if (response.status === 400) {
                success(`Boundary "${name}" (${amount}) properly rejected`);
            } else if (response.ok) {
                warning(`Boundary "${name}" (${amount}) was accepted - verify if intended`);
            }
            
            await sleep(10);
            
        } catch (error) {
            // Expected to fail
        }
    }
}

// =============================================================================
// EDGE CASE 8: HTTP Method Confusion
// =============================================================================
async function testHTTPMethodConfusion() {
    section('EDGE CASE 8: HTTP Method Confusion');
    
    info('Testing for HTTP method confusion vulnerabilities...');
    
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];
    
    let properlyRestricted = 0;
    
    for (const method of methods) {
        try {
            const response = await fetch(`${BASE_URL}/api/wallet/create`, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: method !== 'GET' && method !== 'HEAD' ? JSON.stringify({
                    name: 'Test',
                    password: 'Test123!'
                }) : undefined
            });
            
            if (method === 'POST' && response.ok) {
                info(`POST method works as expected`);
            } else if (method === 'OPTIONS' && (response.ok || response.status === 204)) {
                info(`OPTIONS method allowed (CORS preflight)`);
            } else if (response.status === 405 || response.status === 404) {
                properlyRestricted++;
            } else if (response.ok) {
                fail(`${method} method incorrectly allowed - method confusion vulnerability!`);
            }
            
            await sleep(10);
            
        } catch (error) {
            // Network errors are fine
        }
    }
    
    if (properlyRestricted >= methods.length - 2) { // Allow POST and OPTIONS
        success('HTTP methods properly restricted');
    } else {
        warning('Some HTTP methods may not be properly restricted');
    }
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================
async function runEdgeCaseTests() {
    console.log(`${colors.magenta}`);
    console.log('╔══════════════════════════════════════════════════════════════════════╗');
    console.log('║       APOLLO WALLET - EDGE CASE & DoS ATTACK TESTS                  ║');
    console.log('║            Resource Exhaustion & Edge Case Testing                  ║');
    console.log('╚══════════════════════════════════════════════════════════════════════╝');
    console.log(`${colors.reset}`);
    
    info(`Testing wallet: ${APOLLO_ADDRESS}`);
    info(`Target API: ${BASE_URL}`);
    info(`Test started: ${new Date().toISOString()}\n`);
    
    try {
        // Check server
        try {
            await fetch(`${BASE_URL}/api/health`, { signal: AbortSignal.timeout(5000) });
            success('Server is responding\n');
        } catch (error) {
            warning('Server may not be running - some tests will fail\n');
        }
        
        await testMalformedJSON();
        await sleep(500);
        
        await testUnicodeHandling();
        await sleep(500);
        
        await testLargePayloadAttack();
        await sleep(500);
        
        await testConcurrentRequestFlooding();
        await sleep(500);
        
        await testMemoryExhaustion();
        await sleep(500);
        
        await testSpecialValueInjection();
        await sleep(500);
        
        await testBoundaryValues();
        await sleep(500);
        
        await testHTTPMethodConfusion();
        
    } catch (error) {
        console.error(`${colors.red}Test suite error: ${error.message}${colors.reset}`);
    }
    
    // Summary
    section('EDGE CASE TEST RESULTS');
    
    console.log(`${colors.white}Total Tests:    ${testResults.total}${colors.reset}`);
    console.log(`${colors.green}Passed:         ${testResults.passed}${colors.reset}`);
    console.log(`${colors.red}Failed:         ${testResults.failed}${colors.reset}`);
    console.log(`${colors.yellow}Warnings:       ${testResults.warnings}${colors.reset}`);
    
    const passRate = (testResults.passed / testResults.total * 100).toFixed(1);
    console.log(`\n${colors.white}Pass Rate:      ${passRate}%${colors.reset}`);
    
    if (testResults.failed === 0) {
        console.log(`\n${colors.green}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✓ ALL EDGE CASE TESTS PASSED - ROBUST ERROR HANDLING`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    } else {
        console.log(`\n${colors.red}════════════════════════════════════════════════════════════════════════`);
        console.log(`  ✗ ${testResults.failed} EDGE CASE VULNERABILITIES DETECTED`);
        console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    }
    
    if (testResults.warnings > 0) {
        console.log(`${colors.yellow}⚠  ${testResults.warnings} warnings require attention${colors.reset}\n`);
    }
    
    info(`Test completed: ${new Date().toISOString()}`);
}

runEdgeCaseTests().catch(error => {
    console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
    process.exit(1);
});
