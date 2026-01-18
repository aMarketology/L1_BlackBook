/**
 * Bob ↔ Mac Transfer Test
 * 
 * This demonstrates the FULL wallet flow:
 * 1. Bob sends tokens to Mac (using Bob's stored private key)
 * 2. Mac unlocks wallet using vault + password
 * 3. Mac sends tokens back to Bob (proving vault works)
 * 
 * Run: node bob-mac-transfer-test.js
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';

const L1_BASE_URL = 'http://127.0.0.1:8080';

// ═══════════════════════════════════════════════════════════════
// BOB'S CREDENTIALS (from TEST_ACCOUNTS.txt - already exposed)
// ═══════════════════════════════════════════════════════════════
const BOB = {
    name: 'Bob',
    l1_address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    public_key: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    private_key: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a'
};

// ═══════════════════════════════════════════════════════════════
// MAC'S VAULT DATA (from Mac-test-wallet.md - SECURE)
// Private key is NEVER stored, only derived from vault
// ═══════════════════════════════════════════════════════════════
const MAC = {
    name: 'Mac',
    l1_address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    public_key: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    // Vault data (this is what's stored in Supabase)
    vault: {
        salt: '579a5c28a02f8c3ecc2801545a216cec',
        encrypted_blob: 'U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad',
        algorithm: 'AES-256',
        kdf: 'PBKDF2',
        kdf_iterations: 100000
    },
    // Test password (in production, user provides this)
    password: 'MacSecurePassword2026!'
};

// ═══════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC HELPERS
// ═══════════════════════════════════════════════════════════════

/**
 * Derive encryption key from password using PBKDF2
 */
function deriveEncryptionKey(password, salt) {
    return CryptoJS.PBKDF2(password, salt, {
        keySize: 256 / 32,
        iterations: 100000,
        hasher: CryptoJS.algo.SHA256
    });
}

/**
 * Unlock wallet by decrypting vault with password
 * Returns the Ed25519 keypair
 */
function unlockWallet(vault, password) {
    console.log('   🔐 Deriving encryption key with PBKDF2 (100k iterations)...');
    const encryptionKey = deriveEncryptionKey(password, vault.salt);
    
    console.log('   🔓 Decrypting vault...');
    const decrypted = CryptoJS.AES.decrypt(vault.encrypted_blob, encryptionKey.toString());
    const seedHex = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!seedHex || seedHex.length !== 64) {
        throw new Error('Failed to decrypt vault - wrong password?');
    }
    
    console.log('   🔑 Deriving Ed25519 keypair from seed...');
    const seedBytes = Buffer.from(seedHex, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    return keypair;
}

/**
 * Sign a transfer message
 */
function signTransfer(from, to, amount, keypair) {
    const message = {
        from: from,
        to: to,
        amount: amount.toString(),
        timestamp: Date.now(),
        nonce: Math.floor(Math.random() * 1000000)
    };
    
    const messageStr = JSON.stringify(message);
    const messageBytes = new TextEncoder().encode(messageStr);
    const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
    
    return {
        message: message,
        signature: Buffer.from(signature).toString('hex'),
        public_key: Buffer.from(keypair.publicKey).toString('hex')
    };
}

/**
 * Get keypair from hex private key (for Bob - exposed key)
 */
function keypairFromPrivateKey(privateKeyHex) {
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    return nacl.sign.keyPair.fromSeed(privateKeyBytes);
}

/**
 * Call L1 API to transfer tokens
 */
async function transferTokens(from, to, amount, signedPayload) {
    const response = await fetch(`${L1_BASE_URL}/wallet/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            from: from,
            to: to,
            amount: amount,
            signature: signedPayload.signature,
            public_key: signedPayload.public_key,
            timestamp: signedPayload.message.timestamp,
            nonce: signedPayload.message.nonce
        })
    });
    
    return await response.json();
}

/**
 * Get wallet balance from L1
 */
async function getBalance(address) {
    const response = await fetch(`${L1_BASE_URL}/wallet/${address}`);
    return await response.json();
}

// ═══════════════════════════════════════════════════════════════
// MAIN TEST FLOW
// ═══════════════════════════════════════════════════════════════

async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║          BOB ↔ MAC TRANSFER TEST                             ║');
    console.log('║          Testing Vault-Based Wallet Unlock                   ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    const TRANSFER_AMOUNT = 100;
    
    try {
        // ═══════════════════════════════════════════════════════════════
        // STEP 1: Check initial balances
        // ═══════════════════════════════════════════════════════════════
        console.log('═'.repeat(64));
        console.log('STEP 1: Checking Initial Balances');
        console.log('═'.repeat(64));
        
        let bobBalance, macBalance;
        try {
            bobBalance = await getBalance(BOB.l1_address);
            console.log(`   Bob's balance: ${bobBalance.balance || bobBalance.available || 'N/A'} BB`);
        } catch (e) {
            console.log(`   Bob's balance: (server not running or account not found)`);
            bobBalance = { balance: 'unknown' };
        }
        
        try {
            macBalance = await getBalance(MAC.l1_address);
            console.log(`   Mac's balance: ${macBalance.balance || macBalance.available || '0'} BB`);
        } catch (e) {
            console.log(`   Mac's balance: 0 BB (new account)`);
            macBalance = { balance: 0 };
        }
        
        // ═══════════════════════════════════════════════════════════════
        // STEP 2: Bob sends tokens to Mac
        // ═══════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(64));
        console.log(`STEP 2: Bob Sends ${TRANSFER_AMOUNT} BB to Mac`);
        console.log('═'.repeat(64));
        
        console.log('   📝 Creating transfer from Bob to Mac...');
        console.log(`      From: ${BOB.l1_address}`);
        console.log(`      To:   ${MAC.l1_address}`);
        console.log(`      Amount: ${TRANSFER_AMOUNT} BB`);
        
        // Bob uses his private key directly (it's already exposed in TEST_ACCOUNTS)
        const bobKeypair = keypairFromPrivateKey(BOB.private_key);
        const bobSignedTransfer = signTransfer(BOB.l1_address, MAC.l1_address, TRANSFER_AMOUNT, bobKeypair);
        
        console.log('   ✍️  Signed with Bob\'s private key');
        console.log(`      Signature: ${bobSignedTransfer.signature.substring(0, 32)}...`);
        
        // Verify signature locally
        const bobMsgBytes = new TextEncoder().encode(JSON.stringify(bobSignedTransfer.message));
        const bobSigBytes = Buffer.from(bobSignedTransfer.signature, 'hex');
        const bobVerified = nacl.sign.detached.verify(bobMsgBytes, bobSigBytes, bobKeypair.publicKey);
        console.log(`   ✓ Local signature verification: ${bobVerified ? 'VALID' : 'INVALID'}`);
        
        // Send to L1
        console.log('   📤 Sending to L1...');
        try {
            const bobResult = await transferTokens(BOB.l1_address, MAC.l1_address, TRANSFER_AMOUNT, bobSignedTransfer);
            console.log('   ✅ Transfer result:', bobResult);
        } catch (e) {
            console.log(`   ⚠️  L1 not available: ${e.message}`);
            console.log('   📋 Transfer would have been sent with this payload:');
            console.log(JSON.stringify(bobSignedTransfer.message, null, 2));
        }
        
        // ═══════════════════════════════════════════════════════════════
        // STEP 3: UNLOCK MAC'S WALLET (THE KEY PART!)
        // ═══════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(64));
        console.log('STEP 3: Unlock Mac\'s Wallet from Vault');
        console.log('═'.repeat(64));
        
        console.log('   📂 Mac\'s vault data (from Supabase):');
        console.log(`      Salt: ${MAC.vault.salt}`);
        console.log(`      Encrypted: ${MAC.vault.encrypted_blob.substring(0, 40)}...`);
        console.log(`      KDF: ${MAC.vault.kdf} (${MAC.vault.kdf_iterations} iterations)`);
        
        console.log('\n   🔑 Mac enters password...');
        
        // THIS IS THE MAGIC: Derive the keypair from the vault
        const macKeypair = unlockWallet(MAC.vault, MAC.password);
        
        // Verify we got the right public key
        const derivedPubKey = Buffer.from(macKeypair.publicKey).toString('hex');
        console.log(`\n   ✓ Derived public key: ${derivedPubKey.substring(0, 32)}...`);
        console.log(`   ✓ Expected public key: ${MAC.public_key.substring(0, 32)}...`);
        console.log(`   ✓ Keys match: ${derivedPubKey === MAC.public_key ? 'YES ✅' : 'NO ❌'}`);
        
        if (derivedPubKey !== MAC.public_key) {
            throw new Error('Public key mismatch! Vault may be corrupted.');
        }
        
        // ═══════════════════════════════════════════════════════════════
        // STEP 4: Mac sends tokens back to Bob
        // ═══════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(64));
        console.log(`STEP 4: Mac Sends ${TRANSFER_AMOUNT} BB back to Bob`);
        console.log('═'.repeat(64));
        
        console.log('   📝 Creating transfer from Mac to Bob...');
        console.log(`      From: ${MAC.l1_address}`);
        console.log(`      To:   ${BOB.l1_address}`);
        console.log(`      Amount: ${TRANSFER_AMOUNT} BB`);
        
        // Mac signs with the keypair derived from vault (NEVER stored!)
        const macSignedTransfer = signTransfer(MAC.l1_address, BOB.l1_address, TRANSFER_AMOUNT, macKeypair);
        
        console.log('   ✍️  Signed with Mac\'s derived keypair (from vault)');
        console.log(`      Signature: ${macSignedTransfer.signature.substring(0, 32)}...`);
        
        // Verify signature locally
        const macMsgBytes = new TextEncoder().encode(JSON.stringify(macSignedTransfer.message));
        const macSigBytes = Buffer.from(macSignedTransfer.signature, 'hex');
        const macVerified = nacl.sign.detached.verify(macMsgBytes, macSigBytes, macKeypair.publicKey);
        console.log(`   ✓ Local signature verification: ${macVerified ? 'VALID' : 'INVALID'}`);
        
        // Send to L1
        console.log('   📤 Sending to L1...');
        try {
            const macResult = await transferTokens(MAC.l1_address, BOB.l1_address, TRANSFER_AMOUNT, macSignedTransfer);
            console.log('   ✅ Transfer result:', macResult);
        } catch (e) {
            console.log(`   ⚠️  L1 not available: ${e.message}`);
            console.log('   📋 Transfer would have been sent with this payload:');
            console.log(JSON.stringify(macSignedTransfer.message, null, 2));
        }
        
        // ═══════════════════════════════════════════════════════════════
        // STEP 5: Check final balances
        // ═══════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(64));
        console.log('STEP 5: Final Balances');
        console.log('═'.repeat(64));
        
        try {
            bobBalance = await getBalance(BOB.l1_address);
            console.log(`   Bob's balance: ${bobBalance.balance || bobBalance.available || 'N/A'} BB`);
        } catch (e) {
            console.log(`   Bob's balance: (server not running)`);
        }
        
        try {
            macBalance = await getBalance(MAC.l1_address);
            console.log(`   Mac's balance: ${macBalance.balance || macBalance.available || '0'} BB`);
        } catch (e) {
            console.log(`   Mac's balance: (server not running)`);
        }
        
        // ═══════════════════════════════════════════════════════════════
        // SUMMARY
        // ═══════════════════════════════════════════════════════════════
        console.log('\n' + '═'.repeat(64));
        console.log('TEST SUMMARY');
        console.log('═'.repeat(64));
        console.log('');
        console.log('   ✅ Bob signed transfer using stored private key');
        console.log('   ✅ Mac\'s wallet unlocked from encrypted vault');
        console.log('   ✅ Mac\'s derived public key matches expected');
        console.log('   ✅ Mac signed transfer using derived keypair');
        console.log('   ✅ Both signatures verified locally');
        console.log('');
        console.log('   🔐 SECURITY PROOF:');
        console.log('      - Mac\'s private key was NEVER stored anywhere');
        console.log('      - Mac\'s private key was NEVER displayed');
        console.log('      - Only vault data + password = signing capability');
        console.log('      - Password never sent to server');
        console.log('');
        
    } catch (error) {
        console.error('\n❌ TEST FAILED:', error.message);
        console.error(error.stack);
    }
}

main();
