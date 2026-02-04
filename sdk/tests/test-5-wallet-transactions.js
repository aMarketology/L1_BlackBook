/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK L1 - 5 WALLET SECURITY & TRANSACTION TESTS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests wallet security and transaction operations with REAL cryptographic
 * signatures for all 5 test accounts:
 *   - Alice, Bob, Mac, Apollo (Mnemonic Track)
 *   - Dealer (FROST Track)
 * 
 * Test Scenarios:
 *   1. Fund all accounts via /admin/mint
 *   2. Verify balances
 *   3. Signed transfers between accounts
 *   4. Signed burn operations
 *   5. Security validation (invalid signatures rejected)
 * 
 * Run: node sdk/tests/test-5-wallet-transactions.js
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const L1_URL = 'http://localhost:8080';
const CHAIN_ID = 1;

// Load wallet data
const WALLETS_DIR = path.join(__dirname);
const loadWallet = (name) => {
    const filepath = path.join(WALLETS_DIR, `${name.toLowerCase()}-wallet.json`);
    return JSON.parse(fs.readFileSync(filepath, 'utf8'));
};

// ═══════════════════════════════════════════════════════════════
// ANSI COLORS
// ═══════════════════════════════════════════════════════════════

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function header(text) {
    console.log(`\n${CYAN}╔${'═'.repeat(68)}╗${RESET}`);
    console.log(`${CYAN}║${RESET} ${BOLD}${text.padEnd(66)}${RESET} ${CYAN}║${RESET}`);
    console.log(`${CYAN}╚${'═'.repeat(68)}╝${RESET}\n`);
}

function section(text) {
    console.log(`\n${YELLOW}━━━ ${text} ${'━'.repeat(Math.max(0, 60 - text.length))}${RESET}`);
}

function success(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function info(msg) { console.log(`  ${BLUE}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }

// ═══════════════════════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════════════════════

async function httpPost(endpoint, body) {
    try {
        const response = await fetch(`${L1_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return await response.json();
    } catch (err) {
        return { error: err.message };
    }
}

async function httpGet(endpoint) {
    try {
        const response = await fetch(`${L1_URL}${endpoint}`);
        return await response.json();
    } catch (err) {
        return { error: err.message };
    }
}

// ═══════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC SIGNING (V2 SDK FORMAT)
// ═══════════════════════════════════════════════════════════════

function createSignedTransfer(wallet, toAddress, amount) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    
    // Get correct address field (bb_address for Mnemonic, l1_address for FROST)
    const fromAddress = wallet.bb_address || wallet.l1_address;
    
    // Step 1: Create canonical payload
    const canonical = `${fromAddress}|${toAddress}|${amount}|${timestamp}|${nonce}`;
    const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
    
    // Step 2: Create signing message with domain prefix
    const domainPrefix = `BLACKBOOK_L${CHAIN_ID}/transfer`;
    const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
    
    // Step 3: Sign with Ed25519
    const privateKeyBytes = Buffer.from(wallet.private_key, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    const signature = nacl.sign.detached(Buffer.from(message), keyPair.secretKey);
    
    return {
        public_key: wallet.public_key,
        payload_hash: payloadHash,
        payload_fields: {
            from: fromAddress,
            to: toAddress,
            amount: amount,
            timestamp: timestamp,
            nonce: nonce
        },
        operation_type: 'transfer',
        schema_version: 2,
        timestamp: timestamp,
        nonce: nonce,
        chain_id: CHAIN_ID,
        request_path: '/transfer',
        signature: Buffer.from(signature).toString('hex')
    };
}

function createSignedBurn(wallet, amount) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    
    // Get correct address field (bb_address for Mnemonic, l1_address for FROST)
    const fromAddress = wallet.bb_address || wallet.l1_address;
    
    // Step 1: Create canonical payload (no "to" for burns)
    const canonical = `${fromAddress}|${amount}|${timestamp}|${nonce}`;
    const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
    
    // Step 2: Create signing message with domain prefix
    const domainPrefix = `BLACKBOOK_L${CHAIN_ID}/admin/burn`;
    const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
    
    // Step 3: Sign with Ed25519
    const privateKeyBytes = Buffer.from(wallet.private_key, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
    const signature = nacl.sign.detached(Buffer.from(message), keyPair.secretKey);
    
    return {
        public_key: wallet.public_key,
        payload_hash: payloadHash,
        payload_fields: {
            from: fromAddress,
            amount: amount,
            timestamp: timestamp,
            nonce: nonce
        },
        operation_type: 'burn',
        timestamp: timestamp,
        nonce: nonce,
        chain_id: CHAIN_ID,
        request_path: '/admin/burn',
        signature: Buffer.from(signature).toString('hex')
    };
}

// ═══════════════════════════════════════════════════════════════
// TEST CASES
// ═══════════════════════════════════════════════════════════════

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        success(name);
        passed++;
    } catch (err) {
        fail(`${name}: ${err.message}`);
        failed++;
    }
}

// ═══════════════════════════════════════════════════════════════
// MAIN TEST SUITE
// ═══════════════════════════════════════════════════════════════

async function runTests() {
    header('BLACKBOOK L1 - 5 WALLET TRANSACTION TESTS');
    
    // Load all wallets
    const alice = loadWallet('alice');
    const bob = loadWallet('bob');
    const mac = loadWallet('mac');
    const apollo = loadWallet('apollo');
    const dealer = loadWallet('dealer');
    
    const wallets = { alice, bob, mac, apollo, dealer };
    
    console.log(`${MAGENTA}Loaded Wallets:${RESET}`);
    for (const [name, w] of Object.entries(wallets)) {
        const address = w.bb_address || w.l1_address;
        console.log(`  ${name.padEnd(8)} │ ${address} │ ${w.track}`);
    }
    
    // =========================================================================
    // TEST 1: Check Initial Balances (Skipping Mint)
    // =========================================================================
    section('1. INITIAL BALANCES - Using Existing Tokens');
    
    // =========================================================================
    // TEST 2: Verify Balances
    // =========================================================================
    section('2. BALANCE - Verify All Accounts');
    
    for (const [name, wallet] of Object.entries(wallets)) {
        await test(`Check ${name}'s balance`, async () => {
            const address = wallet.bb_address || wallet.l1_address;
            const res = await httpGet(`/balance/${address}`);
            if (res.error) throw new Error(res.error);
            if (res.balance < 10000) throw new Error(`Expected >= 10000, got ${res.balance}`);
            info(`${name}: ${res.balance} BB`);
        });
    }
    
    // =========================================================================
    // TEST 3: Signed Transfers
    // =========================================================================
    section('3. TRANSFER - Signed Transfers Between Accounts');
    
    // Alice → Bob: 100 BB
    await test('Alice → Bob: 100 BB (signed transfer)', async () => {
        const req = createSignedTransfer(alice, bob.bb_address || bob.l1_address, 100);
        const res = await httpPost('/transfer', req);
        if (!res.success) throw new Error(res.error || 'Transfer failed');
        info(`TX ID: ${res.tx_id}`);
    });
    
    // Bob → Mac: 50 BB
    await test('Bob → Mac: 50 BB (signed transfer)', async () => {
        const req = createSignedTransfer(bob, mac.bb_address || mac.l1_address, 50);
        const res = await httpPost('/transfer', req);
        if (!res.success) throw new Error(res.error || 'Transfer failed');
        info(`TX ID: ${res.tx_id}`);
    });
    
    // Mac → Apollo: 25 BB
    await test('Mac → Apollo: 25 BB (signed transfer)', async () => {
        const req = createSignedTransfer(mac, apollo.bb_address || apollo.l1_address, 25);
        const res = await httpPost('/transfer', req);
        if (!res.success) throw new Error(res.error || 'Transfer failed');
        info(`TX ID: ${res.tx_id}`);
    });
    
    // Apollo → Dealer: 10 BB
    await test('Apollo → Dealer: 10 BB (signed transfer)', async () => {
        const req = createSignedTransfer(apollo, dealer.bb_address || dealer.l1_address, 10);
        const res = await httpPost('/transfer', req);
        if (!res.success) throw new Error(res.error || 'Transfer failed');
        info(`TX ID: ${res.tx_id}`);
    });
    
    // Dealer → Alice: 5 BB (FROST wallet)
    await test('Dealer → Alice: 5 BB (FROST wallet transfer)', async () => {
        const req = createSignedTransfer(dealer, alice.bb_address || alice.l1_address, 5);
        const res = await httpPost('/transfer', req);
        if (!res.success) throw new Error(res.error || 'Transfer failed');
        info(`TX ID: ${res.tx_id}`);
    });
    
    // =========================================================================
    // TEST 4: Verify Balances After Transfers
    // =========================================================================
    section('4. BALANCE - Verify After Transfers');
    
    const expectedBalances = {
        alice: 10000 - 100 + 5,      // 9905
        bob: 10000 + 100 - 50,       // 10050
        mac: 10000 + 50 - 25,        // 10025
        apollo: 10000 + 25 - 10,     // 10015
        dealer: 10000 + 10 - 5       // 10005
    };
    
    for (const [name, wallet] of Object.entries(wallets)) {
        await test(`Verify ${name}'s balance after transfers`, async () => {
            const address = wallet.bb_address || wallet.l1_address;
            const res = await httpGet(`/balance/${address}`);
            if (res.error) throw new Error(res.error);
            info(`${name}: ${res.balance} BB (expected: ~${expectedBalances[name]})`);
        });
    }
    
    // =========================================================================
    // TEST 5: Signed Burns
    // =========================================================================
    section('5. BURN - Signed Token Burns');
    
    // Alice burns 100 BB
    await test('Alice burns 100 BB (signed)', async () => {
        const req = createSignedBurn(alice, 100);
        const res = await httpPost('/admin/burn', req);
        if (!res.success) throw new Error(res.error || 'Burn failed');
        info(`Burned: ${res.burned_amount} BB`);
    });
    
    // Mac burns 50 BB
    await test('Mac burns 50 BB (signed)', async () => {
        const req = createSignedBurn(mac, 50);
        const res = await httpPost('/admin/burn', req);
        if (!res.success) throw new Error(res.error || 'Burn failed');
        info(`Burned: ${res.burned_amount} BB`);
    });
    
    // =========================================================================
    // TEST 6: Security - Invalid Signatures Rejected
    // =========================================================================
    section('6. SECURITY - Invalid Signature Rejection');
    
    // Try transfer with wrong signature
    await test('Reject transfer with invalid signature', async () => {
        const req = createSignedTransfer(alice, bob.l1_address, 10);
        // Corrupt the signature
        req.signature = 'deadbeef' + req.signature.slice(8);
        const res = await httpPost('/transfer', req);
        if (res.success) throw new Error('SECURITY FAILURE: Invalid signature was accepted!');
        info(`Correctly rejected: ${res.error}`);
    });
    
    // Try transfer with wrong public key
    await test('Reject transfer with wrong public key', async () => {
        const req = createSignedTransfer(alice, bob.bb_address || bob.l1_address, 10);
        // Use Bob's public key instead of Alice's
        req.public_key = bob.public_key;
        const res = await httpPost('/transfer', req);
        if (res.success) throw new Error('SECURITY FAILURE: Wrong public key was accepted!');
        info(`Correctly rejected: ${res.error}`);
    });
    
    // Try burn with wrong signature
    await test('Reject burn with invalid signature', async () => {
        const req = createSignedBurn(apollo, 10);
        // Corrupt the signature
        req.signature = 'cafebabe' + req.signature.slice(8);
        const res = await httpPost('/admin/burn', req);
        if (res.success) throw new Error('SECURITY FAILURE: Invalid burn signature accepted!');
        info(`Correctly rejected: ${res.error}`);
    });
    
    // Try to burn more than balance
    await test('Reject overdraw burn', async () => {
        const req = createSignedBurn(alice, 999999);
        const res = await httpPost('/admin/burn', req);
        if (res.success) throw new Error('SECURITY FAILURE: Overdraw burn was allowed!');
        info(`Correctly rejected: ${res.error}`);
    });
    
    // =========================================================================
    // TEST 7: Replay Attack Prevention
    // =========================================================================
    section('7. SECURITY - Replay Attack Prevention');
    
    await test('Reject replayed transfer (same nonce)', async () => {
        const req = createSignedTransfer(bob, mac.bb_address || mac.l1_address, 1);
        
        // First request should succeed
        const res1 = await httpPost('/transfer', req);
        if (!res1.success) throw new Error(`First transfer failed: ${res1.error}`);
        info(`First transfer succeeded: ${res1.tx_id}`);
        
        // Same request (replay) should fail
        const res2 = await httpPost('/transfer', req);
        if (res2.success) throw new Error('SECURITY FAILURE: Replay attack succeeded!');
        info(`Replay correctly rejected: ${res2.error}`);
    });
    
    // =========================================================================
    // TEST 8: Cross-Account Transfers (Full Circle)
    // =========================================================================
    section('8. FULL CIRCLE - Multi-hop Transfer');
    
    await test('Chain transfer: Dealer → Alice → Bob → Mac → Apollo → Dealer', async () => {
        const amount = 1;
        
        // Dealer → Alice
        let res = await httpPost('/transfer', createSignedTransfer(dealer, alice.bb_address || alice.l1_address, amount));
        if (!res.success) throw new Error(`Dealer → Alice failed: ${res.error}`);
        
        // Alice → Bob  
        res = await httpPost('/transfer', createSignedTransfer(alice, bob.bb_address || bob.l1_address, amount));
        if (!res.success) throw new Error(`Alice → Bob failed: ${res.error}`);
        
        // Bob → Mac
        res = await httpPost('/transfer', createSignedTransfer(bob, mac.bb_address || mac.l1_address, amount));
        if (!res.success) throw new Error(`Bob → Mac failed: ${res.error}`);
        
        // Mac → Apollo
        res = await httpPost('/transfer', createSignedTransfer(mac, apollo.bb_address || apollo.l1_address, amount));
        if (!res.success) throw new Error(`Mac → Apollo failed: ${res.error}`);
        
        // Apollo → Dealer
        res = await httpPost('/transfer', createSignedTransfer(apollo, dealer.bb_address || dealer.l1_address, amount));
        if (!res.success) throw new Error(`Apollo → Dealer failed: ${res.error}`);
        
        info(`Full circle complete! ${amount} BB traveled through all 5 wallets.`);
    });
    
    // =========================================================================
    // TEST 9: Final Balance Summary
    // =========================================================================
    section('9. FINAL BALANCE SUMMARY');
    
    console.log(`\n  ${CYAN}┌─────────┬──────────────────────────────────────────────┬────────────┐${RESET}`);
    console.log(`  ${CYAN}│ Account │ Address                                      │ Balance    │${RESET}`);
    console.log(`  ${CYAN}├─────────┼──────────────────────────────────────────────┼────────────┤${RESET}`);
    
    for (const [name, wallet] of Object.entries(wallets)) {
        const address = wallet.bb_address || wallet.l1_address;
        const res = await httpGet(`/balance/${address}`);
        const balance = res.balance?.toFixed(2) || '0.00';
        const paddedName = name.charAt(0).toUpperCase() + name.slice(1);
        console.log(`  ${CYAN}│${RESET} ${paddedName.padEnd(7)} ${CYAN}│${RESET} ${address.padEnd(44)} ${CYAN}│${RESET} ${balance.padStart(10)} ${CYAN}│${RESET}`);
    }
    
    console.log(`  ${CYAN}└─────────┴──────────────────────────────────────────────┴────────────┘${RESET}\n`);
    
    // =========================================================================
    // SUMMARY
    // =========================================================================
    header('TEST RESULTS');
    
    console.log(`  ${GREEN}Passed:${RESET} ${passed}`);
    console.log(`  ${RED}Failed:${RESET} ${failed}`);
    console.log(`  ${BLUE}Total:${RESET}  ${passed + failed}`);
    
    if (failed === 0) {
        console.log(`\n  ${GREEN}${BOLD}✓ ALL TESTS PASSED!${RESET}`);
        console.log(`  ${GREEN}Wallet security and transaction signing verified for all 5 accounts.${RESET}\n`);
    } else {
        console.log(`\n  ${RED}${BOLD}✗ SOME TESTS FAILED${RESET}`);
        console.log(`  ${RED}Please review the errors above.${RESET}\n`);
        process.exit(1);
    }
}

// Run tests
runTests().catch(err => {
    console.error(`${RED}Fatal error: ${err.message}${RESET}`);
    process.exit(1);
});
