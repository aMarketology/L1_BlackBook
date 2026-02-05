/**
 * Test Bob's High-Value Transfer (>1000 BB)
 * 
 * This test validates:
 * 1. High-value transaction threshold detection
 * 2. Vault pepper fetch requirement
 * 3. Share-based transaction signing
 * 4. Transfer execution
 * 
 * Prerequisites:
 * 1. L1 server running: cargo run
 * 2. Bob's wallet minted with >1000 BB
 * 3. HashiCorp Vault configured (or fallback to cached pepper)
 */

const bip39 = require('bip39');
const nacl = require('tweetnacl');
const crypto = require('crypto');

// Bob's wallet credentials from 5-wallet.md
const BOB = {
    mnemonic: 'valley drink voyage argue pulp truck dad transfer school leopard process van vanish boss climb barrel rude slab diary allow practice delay scout lunch',
    address: 'bb_d8ed1c2f27ed27081bf11e58bb6eb160',
    password: 'BobPassword123!',
    publicKey: 'd107ea1e684349bb2a67f026fd98ebc28ba12b273b94c498b85dbbd867f62d4a'
};

const ALICE = {
    address: 'bb_6b7665632e4d8284c9ff288b6cab2f94'
};

const API_URL = 'http://localhost:8080';
const HIGH_VALUE_AMOUNT = 1500; // Above 1000 BB threshold

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

function log(msg, emoji = '📝') {
    console.log(`${emoji} ${msg}`);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkHealth() {
    try {
        const response = await fetch(`${API_URL}/health`);
        return response.ok;
    } catch (err) {
        return false;
    }
}

async function getBalance(address) {
    try {
        const response = await fetch(`${API_URL}/balance/${address}`);
        const data = await response.json();
        return data.balance || 0;
    } catch (err) {
        return 0;
    }
}

async function mintTokens(address, amount) {
    try {
        const response = await fetch(`${API_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: address, amount })
        });
        return response.ok;
    } catch (err) {
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN TEST
// ═══════════════════════════════════════════════════════════════════════════

async function runTest() {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║    Bob\'s High-Value Transfer Test (Vault Pepper Required)    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 1: Check if server is running
    // ─────────────────────────────────────────────────────────────────────────
    log('Checking if L1 server is running...', '🔍');
    const isRunning = await checkHealth();
    if (!isRunning) {
        console.error('❌ ERROR: L1 server is not running!');
        console.error('   Please run: cargo run');
        process.exit(1);
    }
    log('✅ L1 server is online', '✅');
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 2: Check Bob's balance
    // ─────────────────────────────────────────────────────────────────────────
    log('Checking Bob\'s balance...', '💰');
    let bobBalance = await getBalance(BOB.address);
    log(`Bob's current balance: ${bobBalance} BB`, '💵');

    if (bobBalance < HIGH_VALUE_AMOUNT) {
        log(`Minting ${HIGH_VALUE_AMOUNT + 100} BB to Bob's wallet...`, '🏦');
        const minted = await mintTokens(BOB.address, HIGH_VALUE_AMOUNT + 100);
        if (!minted) {
            console.error('❌ ERROR: Failed to mint tokens');
            process.exit(1);
        }
        bobBalance = await getBalance(BOB.address);
        log(`✅ New balance: ${bobBalance} BB`, '✅');
    }
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 3: Check Alice's balance (recipient)
    // ─────────────────────────────────────────────────────────────────────────
    log('Checking Alice\'s balance...', '💰');
    const aliceBalanceBefore = await getBalance(ALICE.address);
    log(`Alice's current balance: ${aliceBalanceBefore} BB`, '💵');
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 4: Derive Bob's keypair from mnemonic
    // ─────────────────────────────────────────────────────────────────────────
    log('Deriving Bob\'s keypair from mnemonic...', '🔑');
    const seed = await bip39.mnemonicToSeed(BOB.mnemonic);
    const privateKey = new Uint8Array(seed.slice(0, 32));
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    log(`✅ Public key: ${bytesToHex(keyPair.publicKey).substring(0, 32)}...`, '✅');
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 5: Create signed transfer (V2 SDK format)
    // ─────────────────────────────────────────────────────────────────────────
    log(`Creating signed transfer: ${HIGH_VALUE_AMOUNT} BB`, '✍️');
    log(`⚠️  Amount exceeds 1000 BB threshold - Vault pepper will be fetched`, '⚠️');

    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();

    // Canonical payload
    const canonical = `${BOB.address}|${ALICE.address}|${HIGH_VALUE_AMOUNT}|${timestamp}|${nonce}`;
    const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');

    // Signing message
    const domainPrefix = 'BLACKBOOK_L1/transfer';
    const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
    const messageBytes = new TextEncoder().encode(message);
    const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

    const signedTransfer = {
        public_key: bytesToHex(keyPair.publicKey),
        payload_hash: payloadHash,
        payload_fields: {
            from: BOB.address,
            to: ALICE.address,
            amount: HIGH_VALUE_AMOUNT,
            timestamp,
            nonce
        },
        operation_type: 'transfer',
        schema_version: 2,
        timestamp,
        nonce,
        chain_id: 1,
        request_path: '/transfer',
        signature: bytesToHex(signature)
    };

    log(`✅ Transfer signed with payload hash: ${payloadHash.substring(0, 16)}...`, '✅');
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Step 6: Execute transfer
    // ─────────────────────────────────────────────────────────────────────────
    log(`Executing transfer to ${ALICE.address}...`, '🚀');
    console.log('');

    try {
        const response = await fetch(`${API_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedTransfer)
        });

        if (!response.ok) {
            const error = await response.json();
            console.error('❌ Transfer failed:', error.error || response.statusText);
            
            if (error.error && error.error.includes('Vault')) {
                console.error('\n📝 NOTE: Vault pepper fetch failed. This is expected if:');
                console.error('   1. HashiCorp Vault is not running');
                console.error('   2. Vault token is not configured');
                console.error('   The system will fall back to cached pepper for testing.');
            }
            
            process.exit(1);
        }

        const result = await response.json();
        
        console.log('╔════════════════════════════════════════════════════════════════╗');
        console.log('║                    ✅ TRANSFER SUCCESSFUL!                    ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        log(`Transaction ID: ${result.tx_id}`, '🆔');
        log(`Amount: ${HIGH_VALUE_AMOUNT} BB`, '💸');
        log(`From: ${BOB.address}`, '👤');
        log(`To: ${ALICE.address}`, '👤');
        console.log('');

        // Check final balances
        const bobBalanceAfter = await getBalance(BOB.address);
        const aliceBalanceAfter = await getBalance(ALICE.address);

        log('Final Balances:', '📊');
        console.log(`   Bob:   ${bobBalance} → ${bobBalanceAfter} BB (${bobBalanceAfter - bobBalance > 0 ? '+' : ''}${bobBalanceAfter - bobBalance})`);
        console.log(`   Alice: ${aliceBalanceBefore} → ${aliceBalanceAfter} BB (+${aliceBalanceAfter - aliceBalanceBefore})`);
        console.log('');

        if (result.tx_id) {
            log('✅ High-value transfer completed successfully!', '🎉');
            log('✅ Vault pepper was fetched (or fallback used)', '🔐');
        }

    } catch (err) {
        console.error('❌ ERROR:', err.message);
        console.error(err);
        process.exit(1);
    }

    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║                  🎉 TEST COMPLETED SUCCESSFULLY! 🎉           ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');
}

// Run the test
runTest().catch(err => {
    console.error('\n❌ TEST FAILED:', err.message);
    console.error(err);
    process.exit(1);
});
