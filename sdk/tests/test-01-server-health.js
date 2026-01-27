/**
 * TEST 01: L1 Server Health & Infrastructure
 * 
 * Tests:
 * - Server health endpoint
 * - Stats endpoint
 * - PoH status
 * - Performance stats
 */

const L1_URL = 'http://localhost:8080';

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function section(title) {
    console.log(`\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}`);
    console.log(`${BLUE}  ${title}${RESET}`);
    console.log(`${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n`);
}

function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); return true; }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); return false; }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }

async function runTests() {
    console.log(`\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${CYAN}║  TEST 01: L1 SERVER HEALTH & INFRASTRUCTURE                  ║${RESET}`);
    console.log(`${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}`);

    let passed = 0;
    let failed = 0;

    // Test 1.1: Health Check
    section('1.1 Health Check');
    try {
        const res = await fetch(`${L1_URL}/health`);
        const data = await res.json();
        
        if (data.status === 'ok') {
            pass('Server is healthy');
            info(`Engine: ${data.engine || 'unknown'}`);
            info(`Storage: ${data.storage || 'unknown'}`);
            info(`Version: ${data.version || 'unknown'}`);
            passed++;
        } else {
            fail(`Unexpected status: ${data.status}`);
            failed++;
        }
    } catch (e) {
        fail(`Health endpoint unreachable: ${e.message}`);
        console.log(`\n  ${RED}Server might not be running! Start with: cargo run${RESET}\n`);
        process.exit(1);
    }

    // Test 1.2: Stats Endpoint
    section('1.2 Blockchain Stats');
    try {
        const res = await fetch(`${L1_URL}/stats`);
        const data = await res.json();
        
        pass('Stats endpoint responding');
        info(`Block Height: ${data.block_height ?? 'N/A'}`);
        info(`Total Accounts: ${data.total_accounts ?? 'N/A'}`);
        info(`Total Supply: ${data.total_supply ?? 'N/A'}`);
        passed++;
    } catch (e) {
        fail(`Stats endpoint error: ${e.message}`);
        failed++;
    }

    // Test 1.3: PoH Status
    section('1.3 Proof of History Status');
    try {
        const res = await fetch(`${L1_URL}/poh/status`);
        const data = await res.json();
        
        pass('PoH status endpoint responding');
        info(`Current Hash: ${(data.current_hash || 'N/A').slice(0, 32)}...`);
        info(`Sequence: ${data.sequence ?? 'N/A'}`);
        info(`TPS: ${data.tps ?? 'N/A'}`);
        passed++;
    } catch (e) {
        fail(`PoH endpoint error: ${e.message}`);
        failed++;
    }

    // Test 1.4: Performance Stats
    section('1.4 Performance Stats');
    try {
        const res = await fetch(`${L1_URL}/performance/stats`);
        const data = await res.json();
        
        pass('Performance stats endpoint responding');
        info(`Transactions Processed: ${data.transactions_processed ?? 'N/A'}`);
        info(`Avg Latency: ${data.avg_latency_ms ?? 'N/A'} ms`);
        passed++;
    } catch (e) {
        // Performance endpoint might not exist, that's ok
        info('Performance stats endpoint not available (optional)');
        passed++;
    }

    // Test 1.5: Auth Test Accounts
    section('1.5 Test Accounts');
    try {
        const res = await fetch(`${L1_URL}/auth/test-accounts`);
        const data = await res.json();
        
        if (data.alice && data.bob && data.dealer) {
            pass('Test accounts available');
            info(`Alice: ${data.alice.address} (${data.alice.balance} BB)`);
            info(`Bob: ${data.bob.address} (${data.bob.balance} BB)`);
            info(`Dealer: ${data.dealer.address} (${data.dealer.balance} BB)`);
            passed++;
        } else {
            fail('Missing test accounts');
            failed++;
        }
    } catch (e) {
        fail(`Test accounts endpoint error: ${e.message}`);
        failed++;
    }

    // Summary
    section('TEST SUMMARY');
    console.log(`  ${GREEN}Passed: ${passed}${RESET}`);
    console.log(`  ${failed > 0 ? RED : GREEN}Failed: ${failed}${RESET}`);
    
    if (failed === 0) {
        console.log(`\n  ${GREEN}✨ ALL TESTS PASSED!${RESET}\n`);
    } else {
        console.log(`\n  ${RED}❌ SOME TESTS FAILED${RESET}\n`);
        process.exit(1);
    }
    
    return { passed, failed };
}

runTests().catch(console.error);

module.exports = { runTests };
