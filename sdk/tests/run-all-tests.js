/**
 * BLACKBOOK L1 TEST SUITE RUNNER
 * 
 * Runs all wallet creation, security, and SSS tests
 * 
 * Usage:
 *   node run-all-tests.js          # Run all tests
 *   node run-all-tests.js quick    # Run fast tests only (no lifecycle)
 *   node run-all-tests.js test-03  # Run specific test
 */

const { spawn } = require('child_process');
const path = require('path');

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

const TESTS = [
    { file: 'test-01-server-health.js', name: 'Server Health & Infrastructure', quick: true },
    { file: 'test-02-wallet-creation.js', name: 'Wallet Creation & SSS Shares', quick: true },
    { file: 'test-03-wallet-funding.js', name: 'Wallet Funding (Admin Mint)', quick: true },
    { file: 'test-04-secure-transfer.js', name: 'Secure Transfer (V2 Signing)', quick: true },
    { file: 'test-05-secure-burn.js', name: 'Secure Burn (Signature Required)', quick: true },
    { file: 'test-06-sss-recovery.js', name: 'SSS Recovery (2-of-3 Shares)', quick: true },
    { file: 'test-07-wallet-security.js', name: 'Wallet Security Hardening', quick: true },
    { file: 'test-08-full-lifecycle.js', name: 'Full Wallet Lifecycle', quick: false },
];

async function runTest(testFile) {
    return new Promise((resolve) => {
        const testPath = path.join(__dirname, testFile);
        const child = spawn('node', [testPath], {
            stdio: 'inherit',
            cwd: __dirname
        });

        child.on('close', (code) => {
            resolve(code === 0);
        });

        child.on('error', (err) => {
            console.error(`Failed to start test: ${err.message}`);
            resolve(false);
        });
    });
}

async function main() {
    const args = process.argv.slice(2);
    const quickMode = args.includes('quick');
    const specificTest = args.find(a => a.startsWith('test-'));

    console.log(`
${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${RESET}
${CYAN}║                                                                       ║${RESET}
${CYAN}║   ${BOLD}BLACKBOOK L1 - WALLET & SECURITY TEST SUITE${RESET}${CYAN}                       ║${RESET}
${CYAN}║                                                                       ║${RESET}
${CYAN}║   Testing: Wallet Creation, SSS Recovery, Transfers, Burns, Security ║${RESET}
${CYAN}║                                                                       ║${RESET}
${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${RESET}
`);

    // Filter tests
    let testsToRun = TESTS;
    
    if (specificTest) {
        testsToRun = TESTS.filter(t => t.file.includes(specificTest));
        if (testsToRun.length === 0) {
            console.log(`${RED}No test found matching: ${specificTest}${RESET}`);
            console.log('Available tests:');
            TESTS.forEach(t => console.log(`  - ${t.file}`));
            process.exit(1);
        }
    } else if (quickMode) {
        testsToRun = TESTS.filter(t => t.quick);
        console.log(`${YELLOW}Running QUICK mode (skipping lifecycle test)${RESET}\n`);
    }

    console.log(`${BLUE}Tests to run:${RESET}`);
    testsToRun.forEach((t, i) => {
        console.log(`  ${i + 1}. ${t.name}`);
    });
    console.log();

    // Check server health first
    console.log(`${YELLOW}Checking L1 server...${RESET}`);
    try {
        const res = await fetch('http://localhost:8080/health');
        const data = await res.json();
        if (data.status === 'ok') {
            console.log(`${GREEN}✓ Server is running${RESET}\n`);
        } else {
            throw new Error('Server not healthy');
        }
    } catch (e) {
        console.log(`${RED}✗ Server not reachable at http://localhost:8080${RESET}`);
        console.log(`${YELLOW}  Start the server with: cargo run${RESET}\n`);
        process.exit(1);
    }

    // Run tests
    const results = [];
    const startTime = Date.now();

    for (const test of testsToRun) {
        console.log(`\n${MAGENTA}${'═'.repeat(70)}${RESET}`);
        console.log(`${MAGENTA}  RUNNING: ${test.name}${RESET}`);
        console.log(`${MAGENTA}${'═'.repeat(70)}${RESET}\n`);

        const passed = await runTest(test.file);
        results.push({ name: test.name, file: test.file, passed });

        if (!passed && !specificTest) {
            console.log(`\n${RED}Test failed. Stopping test suite.${RESET}`);
            console.log(`${YELLOW}Run individual test for details: node ${test.file}${RESET}\n`);
            break;
        }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    // Summary
    console.log(`\n${'═'.repeat(70)}`);
    console.log(`${BOLD}  TEST SUITE SUMMARY${RESET}`);
    console.log('═'.repeat(70));

    const passedCount = results.filter(r => r.passed).length;
    const failedCount = results.filter(r => !r.passed).length;

    results.forEach(r => {
        const icon = r.passed ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
        console.log(`  ${icon} ${r.name}`);
    });

    console.log('═'.repeat(70));
    console.log(`  ${GREEN}Passed: ${passedCount}${RESET}  |  ${failedCount > 0 ? RED : GREEN}Failed: ${failedCount}${RESET}  |  Time: ${elapsed}s`);
    console.log('═'.repeat(70));

    if (failedCount === 0) {
        console.log(`
${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${RESET}
${GREEN}║                                                                       ║${RESET}
${GREEN}║   ✨  ALL TESTS PASSED!  ✨                                           ║${RESET}
${GREEN}║                                                                       ║${RESET}
${GREEN}║   Your BlackBook L1 wallet system is working correctly:              ║${RESET}
${GREEN}║   • Wallet creation with Ed25519 keys                                ║${RESET}
${GREEN}║   • SSS 2-of-3 recovery shares                                       ║${RESET}
${GREEN}║   • Secure transfers with V2 signing                                 ║${RESET}
${GREEN}║   • Secure burns with signature requirement                          ║${RESET}
${GREEN}║   • Password-based encryption (PBKDF2 + AES-256-GCM)                ║${RESET}
${GREEN}║   • Auto-lock sessions with key zeroing                              ║${RESET}
${GREEN}║                                                                       ║${RESET}
${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${RESET}
`);
    } else {
        console.log(`
${RED}╔═══════════════════════════════════════════════════════════════════════╗${RESET}
${RED}║   ❌  SOME TESTS FAILED                                               ║${RESET}
${RED}║                                                                       ║${RESET}
${RED}║   Review the output above for details.                                ║${RESET}
${RED}║   Run individual tests: node test-XX-name.js                          ║${RESET}
${RED}╚═══════════════════════════════════════════════════════════════════════╝${RESET}
`);
        process.exit(1);
    }
}

main().catch(console.error);
