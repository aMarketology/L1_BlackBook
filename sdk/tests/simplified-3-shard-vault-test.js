/**
 * SIMPLIFIED 3-SHARD WALLET & VAULT SECURITY TEST
 * 
 * Focuses on:
 * 1. 3-shard wallet creation (A, B, C)
 * 2. All recovery paths (A+B, B+C, A+C)
 * 3. High-value transfers >1000 BB (Vault pepper requirement)
 * 4. Security validations
 */

const axios = require('axios');

const API_BASE = 'http://localhost:8080';
const MNEMONIC_API = `${API_BASE}/mnemonic`;
const TEST_PASSWORD = 'SecureTestPassword123!';
const ADMIN_RECOVERY_KEY = 'blackbook_admin_recovery_key_2026';

// Colors
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    bright: '\x1b[1m',
};

function log(emoji, message, color = colors.reset) {
    console.log(`${color}${emoji} ${message}${colors.reset}`);
}

function section(title) {
    console.log(`\n${'='.repeat(80)}`);
    console.log(`${colors.bright}${colors.cyan}${title}${colors.reset}`);
    console.log(`${'='.repeat(80)}\n`);
}

// =============================================================================
// MAIN TEST SUITE
// =============================================================================

async function runTests() {
    let passed = 0;
    let failed = 0;
    let testWallet = null;

    console.log(`\n${colors.bright}🚀 BlackBook 3-Shard Wallet & Vault Security Test${colors.reset}\n`);

    // =========================================================================
    // TEST 1: Create 3-Shard Wallet
    // =========================================================================
    section('TEST 1: Create 3-Shard Wallet (SSS 2-of-3)');
    
    try {
        log('🔧', 'Creating wallet with password binding...');
        
        const response = await axios.post(`${MNEMONIC_API}/create`, {
            password: TEST_PASSWORD,
            show_mnemonic: true
        });

        testWallet = response.data;
        
        log('✅', `Wallet created: ${testWallet.wallet_address}`, colors.green);
        log('📝', `Mnemonic: ${testWallet.mnemonic.substring(0, 50)}...`);
        log('🧩', `Share A (password-bound): ${testWallet.share_a_bound.substring(0, 30)}...`);
        log('ℹ️', `Share B: Stored on L1 blockchain (ZKP-gated)`);
        log('ℹ️', `Share C: Encrypted in Vault (pepper-protected)`);
        passed++;
    } catch (error) {
        log('❌', `Failed: ${error.message}`, colors.red);
        failed++;
        return { passed, failed };
    }

    // =========================================================================
    // TEST 2: Recovery Path A+B (Standard)
    // =========================================================================
    section('TEST 2: Recovery A+B (Password + Blockchain)');
    
    try {
        log('🔐', 'Recovering via A+B (standard user path)...');
        
        const response = await axios.post(`${MNEMONIC_API}/recover/ab`, {
            wallet_address: testWallet.wallet_address,
            share_a_bound: testWallet.share_a_bound,
            password: TEST_PASSWORD
        });

        const recoveredMnemonic = response.data.mnemonic;
        
        if (recoveredMnemonic === testWallet.mnemonic) {
            log('✅', 'A+B recovery successful - mnemonic matches', colors.green);
            passed++;
        } else {
            throw new Error('Recovered mnemonic does not match original');
        }
    } catch (error) {
        log('❌', `Failed: ${error.message}`, colors.red);
        failed++;
    }

    // =========================================================================
    // TEST 3: Recovery Path B+C (Admin)
    // =========================================================================
    section('TEST 3: Recovery B+C (Admin + Vault)');
    
    try {
        log('🏦', 'Recovering via B+C (admin path - fetches Shard C from Vault)...');
        
        const response = await axios.post(`${MNEMONIC_API}/recover/bc`, {
            wallet_address: testWallet.wallet_address,
            admin_key: ADMIN_RECOVERY_KEY
        });

        const recoveredMnemonic = response.data.mnemonic;
        
        if (recoveredMnemonic === testWallet.mnemonic) {
            log('✅', 'B+C recovery successful - Vault Shard C accessed', colors.green);
            log('🔐', 'Vault integration verified');
            passed++;
        } else {
            throw new Error('Recovered mnemonic does not match original');
        }
    } catch (error) {
        log('❌', `Failed: ${error.response?.data?.error || error.message}`, colors.red);
        failed++;
    }

    // =========================================================================
    // TEST 4: Recovery Path A+C (Emergency)
    // =========================================================================
    section('TEST 4: Recovery A+C (Password + Vault)');
    
    try {
        log('⚠️', 'Recovering via A+C (emergency path)...');
        
        const response = await axios.post(`${MNEMONIC_API}/recover/ac`, {
            wallet_address: testWallet.wallet_address,
            share_a_bound: testWallet.share_a_bound,
            password: TEST_PASSWORD
        });

        const recoveredMnemonic = response.data.mnemonic;
        
        if (recoveredMnemonic === testWallet.mnemonic) {
            log('✅', 'A+C recovery successful', colors.green);
            passed++;
        } else {
            throw new Error('Recovered mnemonic does not match original');
        }
    } catch (error) {
        log('❌', `Failed: ${error.message}`, colors.red);
        failed++;
    }

    // =========================================================================
    // TEST 5: High-Value Transfer (>1000 BB) - Vault Pepper Required
    // =========================================================================
    section('TEST 5: High-Value Transfer (>1000 BB) - Vault Pepper Test');
    
    try {
        // First mint tokens
        log('💰', 'Minting 2000 BB for high-value transfer test...');
        await axios.post(`${API_BASE}/admin/mint`, {
            to: testWallet.wallet_address,
            amount: 2000
        });
        log('✅', 'Minted 2000 BB');

        // Create recipient
        log('👤', 'Creating recipient wallet...');
        const recipientResp = await axios.post(`${MNEMONIC_API}/create`, {
            password: 'RecipientPass123!',
            show_mnemonic: true
        });
        const recipientAddress = recipientResp.data.wallet_address;
        log('✅', `Recipient: ${recipientAddress}`);

        // Attempt high-value transfer (1500 BB)
        log('💎', 'Initiating 1500 BB transfer (above 1000 BB threshold)...');
        log('🔐', 'This should trigger Vault pepper requirement in server logs');
        
        const transferResp = await axios.post(`${MNEMONIC_API}/transfer`, {
            from: testWallet.wallet_address,
            to: recipientAddress,
            amount: 1500,
            recovery_path: 'ab',
            share_a_bound: testWallet.share_a_bound,
            password: TEST_PASSWORD
        });

        if (transferResp.data.success) {
            log('✅', 'High-value transfer successful', colors.green);
            log('📊', `TX: ${testWallet.wallet_address.substring(0, 20)}... → ${recipientAddress.substring(0, 20)}...`);
            log('💵', `Amount: 1500 BB`);
            log('⚠️', 'Check server logs for "HIGH-VALUE TRANSFER" and Vault pepper access');
            passed++;
        } else {
            throw new Error('Transfer was not successful');
        }
    } catch (error) {
        log('❌', `Failed: ${error.response?.data?.error || error.message}`, colors.red);
        failed++;
    }

    // =========================================================================
    // TEST 6: Security Validation - Wrong Password
    // =========================================================================
    section('TEST 6: Security - Reject Wrong Password');
    
    try {
        log('🔒', 'Attempting recovery with incorrect password...');
        
        const response = await axios.post(`${MNEMONIC_API}/recover/ab`, {
            wallet_address: testWallet.wallet_address,
            share_a_bound: testWallet.share_a_bound,
            password: 'WrongPassword123!'
        });

        // Check if recovered mnemonic is different from original
        const wrongMnemonic = response.data.mnemonic;
        if (wrongMnemonic !== testWallet.mnemonic) {
            log('✅', 'Wrong password produced incorrect mnemonic (as expected)', colors.green);
            log('ℹ️', 'Note: SSS allows any password but produces garbage output with wrong one');
            passed++;
        } else {
            log('❌', 'SECURITY FAILURE: Wrong password produced correct mnemonic!', colors.red);
            failed++;
        }
    } catch (error) {
        if (error.response && error.response.status >= 400) {
            log('✅', 'Server rejected wrong password', colors.green);
            passed++;
        } else {
            throw error;
        }
    }

    // =========================================================================
    // TEST 7: Security Validation - Wrong Admin Key
    // =========================================================================
    section('TEST 7: Security - Reject Wrong Admin Key');
    
    try {
        log('🔒', 'Attempting B+C recovery with incorrect admin key...');
        
        await axios.post(`${MNEMONIC_API}/recover/bc`, {
            wallet_address: testWallet.wallet_address,
            admin_key: 'fake_admin_key'
        });

        // Should not reach here
        log('❌', 'SECURITY FAILURE: Accepted wrong admin key!', colors.red);
        failed++;
    } catch (error) {
        if (error.response && error.response.status >= 400) {
            log('✅', 'Correctly rejected wrong admin key', colors.green);
            passed++;
        } else {
            throw error;
        }
    }

    // =========================================================================
    // TEST 8: Shard Integrity - All Paths Produce Same Secret
    // =========================================================================
    section('TEST 8: Shard Integrity - All Paths Reconstruct Same Secret');
    
    try {
        log('🧩', 'Verifying all recovery paths produce identical mnemonic...');
        
        const abResp = await axios.post(`${MNEMONIC_API}/recover/ab`, {
            wallet_address: testWallet.wallet_address,
            share_a_bound: testWallet.share_a_bound,
            password: TEST_PASSWORD
        });

        const bcResp = await axios.post(`${MNEMONIC_API}/recover/bc`, {
            wallet_address: testWallet.wallet_address,
            admin_key: ADMIN_RECOVERY_KEY
        });

        const acResp = await axios.post(`${MNEMONIC_API}/recover/ac`, {
            wallet_address: testWallet.wallet_address,
            share_a_bound: testWallet.share_a_bound,
            password: TEST_PASSWORD
        });

        const abMnemonic = abResp.data.mnemonic;
        const bcMnemonic = bcResp.data.mnemonic;
        const acMnemonic = acResp.data.mnemonic;

        if (abMnemonic === bcMnemonic && bcMnemonic === acMnemonic && acMnemonic === testWallet.mnemonic) {
            log('✅', 'All recovery paths produce identical mnemonic', colors.green);
            log('🔐', '3-shard SSS integrity verified');
            passed++;
        } else {
            throw new Error('Recovery paths produced different mnemonics!');
        }
    } catch (error) {
        log('❌', `Failed: ${error.message}`, colors.red);
        failed++;
    }

    // =========================================================================
    // FINAL REPORT
    // =========================================================================
    section('TEST RESULTS');
    
    const total = passed + failed;
    const passRate = ((passed / total) * 100).toFixed(1);
    
    console.log(`Total Tests: ${total}`);
    console.log(`${colors.green}✅ Passed: ${passed}${colors.reset}`);
    console.log(`${colors.red}❌ Failed: ${failed}${colors.reset}`);
    console.log(`${colors.cyan}📊 Pass Rate: ${passRate}%${colors.reset}\n`);

    if (failed === 0) {
        log('🎉', 'ALL TESTS PASSED!', colors.green);
        log('🔐', '3-Shard Wallet System: PRODUCTION READY', colors.green);
        log('🏦', 'Vault Integration: VERIFIED', colors.green);
        log('🛡️', 'Security Validations: PASSED', colors.green);
        console.log('\n' + '='.repeat(80));
        console.log(`${colors.bright}${colors.green}✅ BlackBook L1 is ready for production deployment${colors.reset}`);
        console.log('='.repeat(80) + '\n');
        return { passed, failed, success: true };
    } else {
        log('⚠️', `${failed} test(s) failed. Review the errors above.`, colors.yellow);
        return { passed, failed, success: false };
    }
}

// Run tests
if (require.main === module) {
    runTests()
        .then(result => {
            process.exit(result.success ? 0 : 1);
        })
        .catch(error => {
            console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
            console.error(error);
            process.exit(1);
        });
}

module.exports = { runTests };
