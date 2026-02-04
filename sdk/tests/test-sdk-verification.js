/**
 * SDK Verification Test
 * Tests the updated SDK against the running server
 */

const bip39 = require('bip39');
const nacl = require('tweetnacl');
const { BlackBookWallet, BlackBookClient } = require('../blackbook-wallet-sdk.js');

const L1_URL = 'http://localhost:8080';

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function success(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }

async function main() {
    console.log(`\n${CYAN}╔${'═'.repeat(78)}╗${RESET}`);
    console.log(`${CYAN}║${RESET} ${BOLD}BLACKBOOK WALLET SDK VERIFICATION TEST${' '.repeat(38)}${RESET} ${CYAN}║${RESET}`);
    console.log(`${CYAN}╚${'═'.repeat(78)}╝${RESET}\n`);

    const stats = { passed: 0, failed: 0 };

    try {
        // Test 1: Create new wallet
        console.log(`\n━━━ 1. CREATE NEW WALLET ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const wallet = await BlackBookWallet.createNew(bip39, nacl);
        info(`Address: ${wallet.address}`);
        info(`Mnemonic: ${wallet.mnemonic.split(' ').slice(0, 4).join(' ')}...`);
        success('Wallet created successfully');
        stats.passed++;

        // Test 2: Get balance
        console.log(`\n━━━ 2. GET BALANCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const balance = await wallet.getBalance();
        info(`Balance: ${balance} BB`);
        success('Balance retrieved successfully');
        stats.passed++;

        // Test 3: Create signed transfer (don't send)
        console.log(`\n━━━ 3. CREATE SIGNED TRANSFER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const signedTransfer = await wallet.createSignedTransfer(
            'bb_d8ed1c2f27ed27081bf11e58bb6eb160',
            100,
            nacl
        );
        info(`Public Key: ${signedTransfer.public_key.substring(0, 16)}...`);
        info(`Signature: ${signedTransfer.signature.substring(0, 16)}...`);
        info(`Payload Hash: ${signedTransfer.payload_hash.substring(0, 16)}...`);
        info(`Nonce: ${signedTransfer.nonce}`);
        
        // Verify structure
        if (!signedTransfer.public_key) throw new Error('Missing public_key');
        if (!signedTransfer.signature) throw new Error('Missing signature');
        if (!signedTransfer.payload_hash) throw new Error('Missing payload_hash');
        if (!signedTransfer.payload_fields) throw new Error('Missing payload_fields');
        if (!signedTransfer.payload_fields.timestamp) throw new Error('Missing timestamp in payload_fields');
        if (!signedTransfer.payload_fields.nonce) throw new Error('Missing nonce in payload_fields');
        
        success('Transfer signature created successfully');
        stats.passed++;

        // Test 4: Create signed burn (don't send)
        console.log(`\n━━━ 4. CREATE SIGNED BURN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const signedBurn = await wallet.createSignedBurn(50, nacl);
        info(`Public Key: ${signedBurn.public_key.substring(0, 16)}...`);
        info(`Signature: ${signedBurn.signature.substring(0, 16)}...`);
        info(`Operation: ${signedBurn.operation_type}`);
        
        // Verify structure
        if (signedBurn.operation_type !== 'burn') throw new Error('Wrong operation type');
        if (!signedBurn.payload_fields.from) throw new Error('Missing from address');
        
        success('Burn signature created successfully');
        stats.passed++;

        // Test 5: Restore from mnemonic
        console.log(`\n━━━ 5. RESTORE FROM MNEMONIC ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const restoredWallet = await BlackBookWallet.fromMnemonic(wallet.mnemonic, bip39, nacl);
        
        if (restoredWallet.address !== wallet.address) {
            throw new Error('Address mismatch after restoration');
        }
        
        info(`Original: ${wallet.address}`);
        info(`Restored: ${restoredWallet.address}`);
        success('Wallet restored successfully');
        stats.passed++;

        // Test 6: Client health check
        console.log(`\n━━━ 6. CLIENT HEALTH CHECK ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const client = new BlackBookClient(L1_URL);
        const health = await client.health();
        
        info(`Status: ${health.status || 'unknown'}`);
        if (health.sealevel) {
            info(`TPS: ${health.sealevel.tps || 0}`);
        }
        success('Health check successful');
        stats.passed++;

        // Test 7: Get wallet info
        console.log(`\n━━━ 7. GET WALLET INFO ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const info_data = wallet.getInfo();
        info(`Track: ${info_data.track}`);
        info(`Address: ${info_data.address}`);
        info(`L2 Address: ${info_data.l2Address}`);
        info(`Has Mnemonic: ${info_data.hasMnemonic}`);
        success('Wallet info retrieved successfully');
        stats.passed++;

    } catch (err) {
        fail(err.message);
        stats.failed++;
        console.error('\n', err);
    }

    // Final results
    console.log(`\n${CYAN}╔${'═'.repeat(78)}╗${RESET}`);
    console.log(`${CYAN}║${RESET} ${BOLD}TEST RESULTS${' '.repeat(64)}${RESET} ${CYAN}║${RESET}`);
    console.log(`${CYAN}╚${'═'.repeat(78)}╝${RESET}\n`);

    console.log(`  Passed: ${stats.passed}`);
    console.log(`  Failed: ${stats.failed}`);
    console.log(`  Total:  ${stats.passed + stats.failed}\n`);

    if (stats.failed === 0) {
        console.log(`  ${GREEN}✓ ALL TESTS PASSED!${RESET}`);
        console.log(`  ${GREEN}SDK is ready for frontend integration.${RESET}\n`);
        process.exit(0);
    } else {
        console.log(`  ${RED}✗ SOME TESTS FAILED${RESET}\n`);
        process.exit(1);
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
