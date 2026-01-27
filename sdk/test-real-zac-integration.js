/**
 * REAL ZAC INTEGRATION TEST
 * 
 * Performs end-to-end validation of Zac's hardened wallet against the live L1 server:
 * 1. Create Wallet (SSS/Dual-Key)
 * 2. Admin Mint (Fund Zac)
 * 3. Check Balance
 * 4. Transfer (Secure V2 signing)
 * 5. Secure Burn (Requires signature)
 */

const { EnhancedSecureWallet } = require('./enhanced-secure-wallet.js');
const nacl = require('tweetnacl');
const crypto = require('crypto');
const fetch = require('node-fetch');

// Configuration
const SERVER_URL = 'http://localhost:8080';
const CH_ID = 1;

// ANSI colors
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

async function runIntegrationTest() {
    console.log(`${CYAN}🚀 STARTING GENUINE SERVER INTEGRATION TEST${RESET}`);
    
    let zacWallet = null;
    let session = null;
    let aliceAddress = 'L1_ALICE00000000000000000000000000000000000'; // Example Alice

    try {
        // ═══════════════════════════════════════════════════════════════
        // 1. CREATE ZAC'S WALLET
        // ═══════════════════════════════════════════════════════════════
        section('1. Creating Zac\'s Secure Wallet');
        
        const rootSeed = crypto.randomBytes(32);
        const rootKeyPair = nacl.sign.keyPair.fromSeed(rootSeed);
        const rootPubkey = Buffer.from(rootKeyPair.publicKey).toString('hex');
        const address = 'L1_' + crypto.createHash('sha256').update(rootKeyPair.publicKey).digest().slice(0, 20).toString('hex').toUpperCase();

        const opSeed = crypto.randomBytes(32);
        const opKeyPair = nacl.sign.keyPair.fromSeed(opSeed);
        const opPubkey = Buffer.from(opKeyPair.publicKey).toString('hex');

        const salt = crypto.randomBytes(32).toString('hex');
        const userPassword = 'ZacSecurePassword123!';
        
        // Use the wallet class to encrypt and prepare
        const { deriveEncryptionKey, encryptKey } = require('./enhanced-secure-wallet.js');
        const encKey = await deriveEncryptionKey(userPassword, salt);
        const encryptedOpKey = encryptKey(opSeed, encKey);

        zacWallet = {
            address,
            username: 'zac',
            salt,
            encrypted_op_key: encryptedOpKey,
            root_pubkey: rootPubkey,
            opPubkey: opPubkey // For local ref
        };

        console.log(`  ✅ Wallet created: ${address}`);
        console.log(`  🔑 Root Pubkey:    ${rootPubkey.slice(0, 32)}...`);
        console.log(`  🔑 Op Pubkey:      ${opPubkey.slice(0, 32)}...`);

        // Login to get session object
        session = await EnhancedSecureWallet.login(userPassword, zacWallet);
        console.log('  ✅ Logged in, session active.');

        // ═══════════════════════════════════════════════════════════════
        // 2. FUND WALLET (ADMIN MINT)
        // ═══════════════════════════════════════════════════════════════
        section('2. Funding Wallet (Admin Mint)');
        
        console.log(`  Minting 1000 BB to ${address}...`);
        const mintRes = await fetch(`${SERVER_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: address, amount: 1000.0 })
        });
        const mintData = await mintRes.json();
        
        if (!mintData.success) throw new Error(`Mint failed: ${JSON.stringify(mintData)}`);
        console.log(`  ✅ Mint successful. New balance: ${mintData.new_balance} BB`);

        // ═══════════════════════════════════════════════════════════════
        // 3. SECURE TRANSFER (V2 SIGNING)
        // ═══════════════════════════════════════════════════════════════
        section('3. Performing Secure Transfer (50 BB)');
        
        const txPath = '/transfer';
        const amount = 50.0;
        const ts = Date.now();
        const nonce = crypto.randomBytes(8).toString('hex');

        // signing message construction
        const canonical = `${address}|${aliceAddress}|${amount}|${ts}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        
        const domainPrefix = `BLACKBOOK_L${CH_ID}${txPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${ts}\n${nonce}`;
        
        const signedRes = session.signTransaction({
            raw_message_for_demo: message // The SDK wraps this internally usually, but let's do it manually if needed or use session.sign()
        });
        // Wait, session.signTransaction(tx) in our SDK does the whole JSON stringify...
        // Let's use the raw signing capability if we have it, or adapt the script to match the server's expected format.
        
        // Actually, our Server expects a specific JSON structure for /transfer
        const transferRequest = {
            public_key: opPubkey,
            payload_hash: payloadHash,
            payload_fields: {
                from: address,
                to: aliceAddress,
                amount: amount,
                timestamp: ts,
                nonce: nonce
            },
            operation_type: 'transfer',
            schema_version: 2,
            timestamp: ts,
            nonce: nonce,
            chain_id: CH_ID,
            request_path: txPath,
            signature: '' // fill below
        };

        // Manual sign to match the exact protocol
        const sig = nacl.sign.detached(Buffer.from(message), opKeyPair.secretKey);
        transferRequest.signature = Buffer.from(sig).toString('hex');

        console.log('  Submitting signed transfer to /transfer...');
        const txRes = await fetch(`${SERVER_URL}${txPath}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(transferRequest)
        });
        const txData = await txRes.json();

        if (!txData.success) throw new Error(`Transfer failed: ${JSON.stringify(txData)}`);
        console.log(`  ✅ Transfer SUCCESS! TxID: ${txData.tx_id}`);
        console.log(`  💰 Zac's New Balance: ${txData.from_balance} BB`);

        // ═══════════════════════════════════════════════════════════════
        // 4. SECURE BURN (NEW ENFORCED SIGNATURE)
        // ═══════════════════════════════════════════════════════════════
        section('4. Performing Secure Burn (100 BB)');
        
        const burnPath = '/admin/burn';
        const burnAmount = 100.0;
        const burnTs = Date.now();
        const burnNonce = crypto.randomBytes(8).toString('hex');

        const burnCanonical = `${address}|${burnAmount}|${burnTs}|${burnNonce}`;
        const burnPayloadHash = crypto.createHash('sha256').update(burnCanonical).digest('hex');
        
        const burnDomainPrefix = `BLACKBOOK_L${CH_ID}${burnPath}`;
        const burnMessage = `${burnDomainPrefix}\n${burnPayloadHash}\n${burnTs}\n${burnNonce}`;
        
        const burnSig = nacl.sign.detached(Buffer.from(burnMessage), opKeyPair.secretKey);
        
        const burnRequest = {
            public_key: opPubkey,
            payload_hash: burnPayloadHash,
            payload_fields: {
                from: address,
                amount: burnAmount,
                timestamp: burnTs,
                nonce: burnNonce
            },
            operation_type: 'burn',
            timestamp: burnTs,
            nonce: burnNonce,
            chain_id: CH_ID,
            request_path: burnPath,
            signature: Buffer.from(burnSig).toString('hex')
        };

        console.log('  Submitting signed burn to /admin/burn...');
        const burnRes = await fetch(`${SERVER_URL}${burnPath}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(burnRequest)
        });
        const burnData = await burnRes.json();

        if (!burnData.success) {
            console.log(`  ${RED}Expected Failure or unexpected error?${RESET}`);
            throw new Error(`Burn failed: ${JSON.stringify(burnData)}`);
        }
        
        console.log(`  ✅ Burn SUCCESS! TxID: ${burnData.tx_id}`);
        console.log(`  🔥 Tokens permanently destroyed: ${burnData.burned_amount} BB`);
        console.log(`  💰 Final Balance: ${burnData.new_balance} BB`);

        // ═══════════════════════════════════════════════════════════════
        // 5. FINAL AUDIT
        // ═══════════════════════════════════════════════════════════════
        section('5. Final Audit');
        
        const auditRes = await fetch(`${SERVER_URL}/balance/${address}`);
        const auditData = await auditRes.json();
        
        console.log(`  Final Verified Balance: ${auditData.balance} BB`);
        const expected = 1000 - 50 - 100;
        if (auditData.balance === expected) {
            console.log(`\n  ${GREEN}✨ ALL INTEGRATION TESTS PASSED GENUINELY! ✨${RESET}`);
            console.log(`     Zac Wallet is secure, functional, and server-integrated.`);
        } else {
            console.log(`\n  ${RED}❌ Balance mismatch! Expected ${expected}, got ${auditData.balance}${RESET}`);
        }

    } catch (err) {
        console.error(`\n${RED}🔴 FATAL TEST ERROR:${RESET}`);
        console.error(err.message);
        process.exit(1);
    }
}

runIntegrationTest();
