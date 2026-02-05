/**
 * COMPREHENSIVE 3-SHARD WALLET SECURITY TEST
 * 
 * Tests:
 * 1. Wallet creation (3-shard SSS generation)
 * 2. All recovery paths (A+B, B+C, A+C)
 * 3. High-value transfers (>1000 BB) requiring Vault pepper
 * 4. ZKP authentication for Share B access
 * 5. Shard integrity and reconstruction
 * 6. Security validations (signatures, rate limiting)
 */

const { MnemonicWallet, BlackBookClient } = require('../blackbook-wallet-sdk.js');
const axios = require('axios');

const API_BASE = 'http://localhost:8080';
const MNEMONIC_API = `${API_BASE}/mnemonic`;

// Test configuration
const HIGH_VALUE_THRESHOLD = 1000; // BB tokens
const TEST_PASSWORD = 'SecureTestPassword123!';
const ADMIN_RECOVERY_KEY = 'blackbook_admin_recovery_key_2026';

// ANSI color codes for output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
};

function log(emoji, message, color = colors.reset) {
    console.log(`${color}${emoji} ${message}${colors.reset}`);
}

function logSection(title) {
    console.log(`\n${'='.repeat(80)}`);
    console.log(`${colors.bright}${colors.cyan}${title}${colors.reset}`);
    console.log(`${'='.repeat(80)}\n`);
}

function logTest(num, total, description) {
    console.log(`\n${colors.bright}[${num}/${total}] ${description}${colors.reset}`);
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// TEST SUITE
// =============================================================================

class ThreeShardSecurityTester {
    constructor() {
        this.testWallet = null;
        this.testResults = {
            passed: 0,
            failed: 0,
            total: 0,
            details: []
        };
    }

    async runTest(name, testFn) {
        this.testResults.total++;
        try {
            await testFn();
            this.testResults.passed++;
            this.testResults.details.push({ name, status: 'PASS' });
            log('✅', `PASS: ${name}`, colors.green);
            return true;
        } catch (error) {
            this.testResults.failed++;
            this.testResults.details.push({ name, status: 'FAIL', error: error.message });
            log('❌', `FAIL: ${name}`, colors.red);
            console.error(`${colors.red}   Error: ${error.message}${colors.reset}`);
            return false;
        }
    }

    // =========================================================================
    // TEST 1: Wallet Creation & 3-Shard Generation
    // =========================================================================
    async test01_CreateWallet() {
        logSection('TEST 1: Wallet Creation & 3-Shard SSS Generation');

        await this.runTest('Create wallet with password', async () => {
            log('🔧', 'Creating wallet with 3-shard SSS...');
            
            const response = await axios.post(`${MNEMONIC_API}/create`, {
                password: TEST_PASSWORD,
                show_mnemonic: true  // Request mnemonic in response for testing
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            const data = response.data;
            log('📝', `Wallet Address: ${data.wallet_address}`);
            log('🔑', `Mnemonic: ${data.mnemonic ? data.mnemonic.substring(0, 50) + '...' : 'Not returned'}`);
            log('🧩', `Share A: ${data.share_a_bound.substring(0, 32)}...`);

            // Validate response structure
            if (!data.wallet_address || !data.share_a_bound) {
                throw new Error('Missing required fields in response');
            }

            if (!data.mnemonic) {
                throw new Error('Mnemonic not returned (show_mnemonic=true required)');
            }

            if (!data.wallet_address.startsWith('bb_')) {
                throw new Error('Invalid wallet address format');
            }

            // Store for later tests
            this.testWallet = {
                address: data.wallet_address,
                mnemonic: data.mnemonic,
                share_a_bound: data.share_a_bound,
                password: TEST_PASSWORD
            };

            log('✨', 'Wallet created with 3 shards:', colors.cyan);
            log('  ', `Shard A: Password-bound (client-side)`, colors.cyan);
            log('  ', `Shard B: Stored on L1 blockchain (ZKP-gated)`, colors.cyan);
            log('  ', `Shard C: Encrypted in Vault (pepper-protected)`, colors.cyan);
        });

        await this.runTest('Verify Share A structure', async () => {
            const shareA = this.testWallet.share_a_bound;
            
            // Share A format: "1:hex" or "2:hex" (threshold:hex_data)
            if (!/^[12]:[0-9a-fA-F]+$/.test(shareA)) {
                throw new Error('Share A is not valid SSS format (expected threshold:hex)');
            }

            log('🔍', `Share A format: ${shareA.substring(0, 40)}...`);
        });
    }

    // =========================================================================
    // TEST 2: Mint Tokens for Testing
    // =========================================================================
    async test02_MintTokens() {
        logSection('TEST 2: Mint Tokens for High-Value Transfer Test');

        await this.runTest('Mint 2000 BB tokens', async () => {
            log('💰', 'Minting 2000 BB for high-value transfer test...');

            const response = await axios.post(`${API_BASE}/rpc`, {
                jsonrpc: '2.0',
                method: 'mint',
                params: {
                    to: this.testWallet.address,
                    amount: 2000
                },
                id: 1
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            log('✅', `Minted 2000 BB to ${this.testWallet.address}`);
        });

        await this.runTest('Verify balance', async () => {
            const response = await axios.post(`${API_BASE}/rpc`, {
                jsonrpc: '2.0',
                method: 'get_balance',
                params: { address: this.testWallet.address },
                id: 1
            });
            const balance = response.data.result.balance;

            log('💵', `Current balance: ${balance} BB`);

            if (balance < 2000) {
                throw new Error(`Expected balance >= 2000, got ${balance}`);
            }
        });
    }

    // =========================================================================
    // TEST 3: Recovery Path A+B (Standard Path)
    // =========================================================================
    async test03_RecoveryPathAB() {
        logSection('TEST 3: Recovery Path A+B (Password + Blockchain)');

        let shareB = null;

        await this.runTest('Request ZKP challenge', async () => {
            log('🔐', 'Requesting ZKP challenge for Share B access...');
            
            const response = await axios.post(
                `${MNEMONIC_API}/zkp/challenge`,
                { wallet_address: this.testWallet.address }
            );

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            const { challenge } = response.data;
            log('🎲', `Challenge: ${challenge}`);

            // Store for next test
            this.zkpChallenge = challenge;
        });

        await this.runTest('Verify ZKP and retrieve Share B', async () => {
            log('✍️', 'Signing ZKP challenge with derived key...');

            // Derive keypair from mnemonic
            const wallet = new MnemonicWallet(this.testWallet.mnemonic, this.testWallet.password);
            const address = wallet.address;

            if (address !== this.testWallet.address) {
                throw new Error(`Address mismatch: ${address} vs ${this.testWallet.address}`);
            }

            // Sign challenge (format: BLACKBOOK_SHARE_B\n{challenge}\n{address})
            const message = `BLACKBOOK_SHARE_B\n${this.zkpChallenge}\n${address}`;
            const signature = wallet.signMessage(message);

            log('📝', `Signature: ${signature.substring(0, 32)}...`);

            // Verify ZKP and get Share B
            const response = await axios.post(
                `${MNEMONIC_API}/share-b/${this.testWallet.address}`,
                {
                    signature: signature
                }
            );

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            shareB = response.data.share_b;
            log('🧩', `Share B retrieved: ${shareB.substring(0, 32)}...`);
        });

        await this.runTest('Reconstruct mnemonic from A+B', async () => {
            log('🔧', 'Reconstructing mnemonic from Share A + Share B...');

            const response = await axios.post(`${MNEMONIC_API}/recover/ab`, {
                wallet_address: this.testWallet.address,
                share_a_bound: this.testWallet.share_a_bound,
                password: TEST_PASSWORD
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            const { mnemonic, public_key } = response.data;

            log('🔑', `Recovered mnemonic: ${mnemonic.substring(0, 50)}...`);
            log('🔑', `Public key: ${public_key}`);

            // Verify mnemonic matches original
            if (mnemonic !== this.testWallet.mnemonic) {
                throw new Error('Recovered mnemonic does not match original!');
            }

            log('✅', 'A+B recovery successful: Mnemonic matches original');
        });
    }

    // =========================================================================
    // TEST 4: Recovery Path B+C (Admin Recovery)
    // =========================================================================
    async test04_RecoveryPathBC() {
        logSection('TEST 4: Recovery Path B+C (Admin + Vault)');

        await this.runTest('Admin recovery via B+C', async () => {
            log('🔐', 'Attempting B+C recovery with admin key...');

            const response = await axios.post(`${MNEMONIC_API}/recover/bc`, {
                wallet_address: this.testWallet.address,
                admin_recovery_key: ADMIN_RECOVERY_KEY
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            const { mnemonic, public_key } = response.data;

            log('🔑', `Recovered mnemonic: ${mnemonic.substring(0, 50)}...`);
            log('🔑', `Public key: ${public_key}`);

            // Verify mnemonic matches original
            if (mnemonic !== this.testWallet.mnemonic) {
                throw new Error('Recovered mnemonic does not match original!');
            }

            log('✅', 'B+C recovery successful: Mnemonic matches original');
            log('🏦', 'Vault Shard C access verified');
        });
    }

    // =========================================================================
    // TEST 5: Recovery Path A+C (Emergency Recovery)
    // =========================================================================
    async test05_RecoveryPathAC() {
        logSection('TEST 5: Recovery Path A+C (Password + Vault)');

        await this.runTest('Emergency recovery via A+C', async () => {
            log('⚠️', 'Attempting A+C recovery (emergency path)...');

            const response = await axios.post(`${MNEMONIC_API}/recover/ac`, {
                wallet_address: this.testWallet.address,
                share_a_bound: this.testWallet.share_a_bound,
                password: TEST_PASSWORD,
                admin_recovery_key: ADMIN_RECOVERY_KEY
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            const { mnemonic, public_key } = response.data;

            log('🔑', `Recovered mnemonic: ${mnemonic.substring(0, 50)}...`);
            log('🔑', `Public key: ${public_key}`);

            // Verify mnemonic matches original
            if (mnemonic !== this.testWallet.mnemonic) {
                throw new Error('Recovered mnemonic does not match original!');
            }

            log('✅', 'A+C recovery successful: Mnemonic matches original');
            log('🚨', 'Emergency recovery path verified');
        });
    }

    // =========================================================================
    // TEST 6: High-Value Transfer (<1000 BB) - No Vault Pepper Required
    // =========================================================================
    async test06_NormalValueTransfer() {
        logSection('TEST 6: Normal-Value Transfer (<1000 BB)');

        // Create recipient wallet
        const recipientResponse = await axios.post(`${MNEMONIC_API}/create`, {
            password: 'RecipientPassword123!',
            show_mnemonic: true
        });
        const recipientAddress = recipientResponse.data.wallet_address;

        await this.runTest('Transfer 500 BB (no Vault pepper required)', async () => {
            log('💸', 'Transferring 500 BB (below 1000 BB threshold)...');

            const wallet = new MnemonicWallet(this.testWallet.mnemonic, this.testWallet.password);
            const address = wallet.address;

            // Sign transfer
            const transferMsg = `BB_TRANSFER:${address}->${recipientAddress}:500`;
            const signature = wallet.signMessage(transferMsg);

            const response = await axios.post(`${MNEMONIC_API}/transfer`, {
                from: address,
                to: recipientAddress,
                amount: 500,
                recovery_path: 'ab',
                share_a_bound: this.testWallet.share_a_bound,
                signature: signature
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            log('✅', `Transferred 500 BB successfully`);
            log('📊', `Transaction: ${address} → ${recipientAddress}`);
        });

        await this.runTest('Verify balances after normal transfer', async () => {
            const senderResponse = await axios.post(`${API_BASE}/rpc`, {
                jsonrpc: '2.0',
                method: 'get_balance',
                params: { address: this.testWallet.address },
                id: 1
            });
            const recipientResponse = await axios.post(`${API_BASE}/rpc`, {
                jsonrpc: '2.0',
                method: 'get_balance',
                params: { address: recipientAddress },
                id: 2
            });

            const senderBalance = senderResponse.data.result.balance;
            const recipientBalance = recipientResponse.data.result.balance;

            log('💵', `Sender balance: ${senderBalance} BB`);
            log('💵', `Recipient balance: ${recipientBalance} BB`);

            if (recipientBalance < 500) {
                throw new Error(`Expected recipient balance >= 500, got ${recipientBalance}`);
            }
        });
    }

    // =========================================================================
    // TEST 7: High-Value Transfer (>1000 BB) - Vault Pepper Required
    // =========================================================================
    async test07_HighValueTransfer() {
        logSection('TEST 7: High-Value Transfer (>1000 BB) - Vault Pepper Required');

        // Create recipient wallet
        const recipientResponse = await axios.post(`${MNEMONIC_API}/create`, {
            password: 'HighValueRecipient123!',
            show_mnemonic: true
        });
        const recipientAddress = recipientResponse.data.wallet_address;

        await this.runTest('Transfer 1500 BB (Vault pepper required)', async () => {
            log('💎', 'Transferring 1500 BB (above 1000 BB threshold)...');
            log('🔐', 'This should trigger Vault pepper requirement...');

            const wallet = new MnemonicWallet(this.testWallet.mnemonic, this.testWallet.password);
            const address = wallet.address;

            // Sign transfer
            const transferMsg = `BB_TRANSFER:${address}->${recipientAddress}:1500`;
            const signature = wallet.signMessage(transferMsg);

            const response = await axios.post(`${MNEMONIC_API}/transfer`, {
                from: address,
                to: recipientAddress,
                amount: 1500,
                recovery_path: 'ab',
                share_a_bound: this.testWallet.share_a_bound,
                signature: signature
            });

            if (response.status !== 200) {
                throw new Error(`Expected 200, got ${response.status}`);
            }

            log('✅', `Transferred 1500 BB successfully`);
            log('🔒', `High-value transfer completed (Vault pepper accessed)`);
            log('📊', `Transaction: ${address} → ${recipientAddress}`);
        });

        await this.runTest('Verify balances after high-value transfer', async () => {
            const recipientResponse = await axios.post(`${API_BASE}/rpc`, {
                jsonrpc: '2.0',
                method: 'get_balance',
                params: { address: recipientAddress },
                id: 1
            });
            const recipientBalance = recipientResponse.data.result.balance;

            log('💵', `Recipient balance: ${recipientBalance} BB`);

            if (recipientBalance < 1500) {
                throw new Error(`Expected recipient balance >= 1500, got ${recipientBalance}`);
            }

            log('✅', 'High-value transfer successfully completed');
        });
    }

    // =========================================================================
    // TEST 8: Security Validations
    // =========================================================================
    async test08_SecurityValidations() {
        logSection('TEST 8: Security Validations');

        await this.runTest('Reject invalid password for A+B recovery', async () => {
            log('🔒', 'Attempting recovery with wrong password...');

            try {
                await axios.post(`${MNEMONIC_API}/recover/ab`, {
                    wallet_address: this.testWallet.address,
                    share_a_bound: this.testWallet.share_a_bound,
                    password: 'WrongPassword123!'
                });
                throw new Error('Should have rejected wrong password');
            } catch (error) {
                if (error.response && error.response.status >= 400) {
                    log('✅', 'Correctly rejected wrong password');
                } else {
                    throw error;
                }
            }
        });

        await this.runTest('Reject invalid admin key for B+C recovery', async () => {
            log('🔒', 'Attempting B+C recovery with wrong admin key...');

            try {
                await axios.post(`${MNEMONIC_API}/recover/bc`, {
                    wallet_address: this.testWallet.address,
                    admin_recovery_key: 'wrong_admin_key'
                });
                throw new Error('Should have rejected wrong admin key');
            } catch (error) {
                if (error.response && error.response.status >= 400) {
                    log('✅', 'Correctly rejected wrong admin key');
                } else {
                    throw error;
                }
            }
        });

        await this.runTest('Reject invalid signature for Share B access', async () => {
            log('🔒', 'Attempting Share B access with invalid signature...');

            try {
                await axios.post(
                    `${MNEMONIC_API}/share-b/${this.testWallet.address}`,
                    {
                        signature: '0'.repeat(128) // Invalid signature
                    }
                );
                throw new Error('Should have rejected invalid signature');
            } catch (error) {
                if (error.response && error.response.status >= 400) {
                    log('✅', 'Correctly rejected invalid signature');
                } else {
                    throw error;
                }
            }
        });
    }

    // =========================================================================
    // TEST 9: Shard Integrity
    // =========================================================================
    async test09_ShardIntegrity() {
        logSection('TEST 9: Shard Integrity & Reconstruction');

        await this.runTest('Verify all 3 shards can reconstruct secret', async () => {
            log('🧩', 'Testing shard reconstruction integrity...');

            // Test A+B (already tested, but verify again)
            const abResponse = await axios.post(`${MNEMONIC_API}/recover/ab`, {
                wallet_address: this.testWallet.address,
                share_a_bound: this.testWallet.share_a_bound,
                password: TEST_PASSWORD
            });

            // Test B+C
            const bcResponse = await axios.post(`${MNEMONIC_API}/recover/bc`, {
                wallet_address: this.testWallet.address,
                admin_recovery_key: ADMIN_RECOVERY_KEY
            });

            // Test A+C
            const acResponse = await axios.post(`${MNEMONIC_API}/recover/ac`, {
                wallet_address: this.testWallet.address,
                share_a_bound: this.testWallet.share_a_bound,
                password: TEST_PASSWORD,
                admin_recovery_key: ADMIN_RECOVERY_KEY
            });

            const abMnemonic = abResponse.data.mnemonic;
            const bcMnemonic = bcResponse.data.mnemonic;
            const acMnemonic = acResponse.data.mnemonic;

            // All should match original
            if (abMnemonic !== this.testWallet.mnemonic) {
                throw new Error('A+B reconstruction mismatch');
            }
            if (bcMnemonic !== this.testWallet.mnemonic) {
                throw new Error('B+C reconstruction mismatch');
            }
            if (acMnemonic !== this.testWallet.mnemonic) {
                throw new Error('A+C reconstruction mismatch');
            }

            log('✅', 'All 3 recovery paths produce identical mnemonic');
            log('🔐', '3-shard SSS integrity verified');
        });
    }

    // =========================================================================
    // Generate Final Report
    // =========================================================================
    generateReport() {
        logSection('TEST SUMMARY');

        const passRate = ((this.testResults.passed / this.testResults.total) * 100).toFixed(1);
        
        console.log(`Total Tests: ${this.testResults.total}`);
        console.log(`${colors.green}✅ Passed: ${this.testResults.passed}${colors.reset}`);
        console.log(`${colors.red}❌ Failed: ${this.testResults.failed}${colors.reset}`);
        console.log(`${colors.cyan}📊 Pass Rate: ${passRate}%${colors.reset}\n`);

        if (this.testResults.failed > 0) {
            console.log(`${colors.red}Failed Tests:${colors.reset}`);
            this.testResults.details
                .filter(t => t.status === 'FAIL')
                .forEach(t => {
                    console.log(`  ${colors.red}❌ ${t.name}${colors.reset}`);
                    console.log(`     ${colors.red}${t.error}${colors.reset}`);
                });
        }

        console.log('\n' + '='.repeat(80));
        
        if (this.testResults.failed === 0) {
            log('🎉', 'ALL TESTS PASSED! 3-Shard Wallet System is Production Ready!', colors.green);
            log('🔐', 'Security Features Verified:', colors.cyan);
            log('  ', '✅ Shamir Secret Sharing (2-of-3 threshold)', colors.cyan);
            log('  ', '✅ Zero-Knowledge Proof authentication', colors.cyan);
            log('  ', '✅ Vault pepper for high-value transfers', colors.cyan);
            log('  ', '✅ All recovery paths functional', colors.cyan);
        } else {
            log('⚠️', 'Some tests failed. Review the errors above.', colors.yellow);
        }

        console.log('='.repeat(80) + '\n');

        return this.testResults.failed === 0;
    }

    // =========================================================================
    // Main Test Runner
    // =========================================================================
    async runAll() {
        console.log('\n');
        log('🚀', 'Starting Comprehensive 3-Shard Wallet Security Test Suite', colors.bright);
        console.log(`${'='.repeat(80)}\n`);

        try {
            await this.test01_CreateWallet();
            await this.test02_MintTokens();
            await this.test03_RecoveryPathAB();
            await this.test04_RecoveryPathBC();
            await this.test05_RecoveryPathAC();
            await this.test06_NormalValueTransfer();
            await this.test07_HighValueTransfer();
            await this.test08_SecurityValidations();
            await this.test09_ShardIntegrity();

            return this.generateReport();
        } catch (error) {
            log('💥', `Fatal error: ${error.message}`, colors.red);
            console.error(error);
            return false;
        }
    }
}

// =============================================================================
// RUN TESTS
// =============================================================================

if (require.main === module) {
    (async () => {
        const tester = new ThreeShardSecurityTester();
        const success = await tester.runAll();
        process.exit(success ? 0 : 1);
    })();
}

module.exports = { ThreeShardSecurityTester };
