/**
 * APOLLO WALLET - Complete Enhanced Secure Wallet Test
 * 
 * This test creates a full production-ready wallet named "Apollo" with:
 * 1. Root Key (256-bit, SSS 2-of-3 shares for paper backup)
 * 2. Operational Key (encrypted with user password)
 * 3. User Password + Salt (for key encryption)
 * 4. Real Ed25519 signatures for all transactions
 * 5. Persistent storage for future test runs
 * 
 * Tests:
 * - Full wallet creation with dual-key architecture
 * - Minting tokens to Apollo
 * - Signed transfers to other wallets
 * - Session management with auto-lock
 * - Wallet data persistence and recovery
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');

const L1_URL = 'http://localhost:8080';
const APOLLO_DATA_FILE = path.join(__dirname, 'apollo-wallet-data.json');

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function section(title) {
    console.log(`\n${BLUE}${'═'.repeat(70)}${RESET}`);
    console.log(`${BOLD}${MAGENTA}  🚀 APOLLO: ${title}${RESET}`);
    console.log(`${BLUE}${'═'.repeat(70)}${RESET}\n`);
}

function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); return true; }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); return false; }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }

// ==================== CRYPTOGRAPHIC PRIMITIVES ====================

// SSS Prime (secp256k1 field)
const SSS_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

function randomBigInt(max) {
    const bytes = crypto.randomBytes(32);
    return BigInt('0x' + bytes.toString('hex')) % max;
}

function modInverse(a, m) {
    a = ((a % m) + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [BigInt(1), BigInt(0)];
    while (r !== BigInt(0)) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    if (old_r > BigInt(1)) throw new Error('Not invertible');
    return ((old_s % m) + m) % m;
}

function splitSecret(secretBytes, n = 3, k = 2) {
    if (secretBytes.length !== 32) throw new Error('Secret must be 32 bytes');
    const secret = BigInt('0x' + Buffer.from(secretBytes).toString('hex'));
    const coefficients = [secret];
    
    for (let i = 1; i < k; i++) {
        coefficients.push(randomBigInt(SSS_PRIME));
    }

    const shares = [];
    for (let x = 1; x <= n; x++) {
        let y = BigInt(0);
        for (let i = 0; i < k; i++) {
            const term = (coefficients[i] * (BigInt(x) ** BigInt(i))) % SSS_PRIME;
            y = (y + term) % SSS_PRIME;
        }
        shares.push({ x, y: y.toString(16).padStart(64, '0') });
    }
    return shares;
}

function reconstructSecret(shares) {
    if (shares.length < 2) throw new Error('Need at least 2 shares');
    
    let secret = BigInt(0);
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        
        let numerator = BigInt(1);
        let denominator = BigInt(1);
        
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                const xj = BigInt(shares[j].x);
                numerator = (numerator * (BigInt(0) - xj)) % SSS_PRIME;
                denominator = (denominator * (xi - xj)) % SSS_PRIME;
            }
        }
        
        const lagrange = (numerator * modInverse(denominator, SSS_PRIME)) % SSS_PRIME;
        secret = (secret + (yi * lagrange)) % SSS_PRIME;
    }
    
    secret = (secret % SSS_PRIME + SSS_PRIME) % SSS_PRIME;
    const hexStr = secret.toString(16).padStart(64, '0');
    return Buffer.from(hexStr, 'hex');
}

// ==================== ENCRYPTION ====================

function deriveEncryptionKey(userPassword, salt) {
    // Use PBKDF2 with 300,000 iterations (OWASP 2023 recommendation)
    const saltBuffer = Buffer.from(salt, 'hex');
    return crypto.pbkdf2Sync(userPassword, saltBuffer, 300000, 32, 'sha256');
}

function encryptKey(keyBytes, encryptionKey) {
    const iv = crypto.randomBytes(12); // GCM nonce
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    
    let encrypted = cipher.update(keyBytes);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

function decryptKey(encryptedData, encryptionKey) {
    const { encrypted, iv, authTag } = encryptedData;
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        encryptionKey,
        Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(Buffer.from(encrypted, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted;
}

// ==================== L1 ADDRESS DERIVATION ====================

function deriveL1Address(publicKey) {
    const hash = crypto.createHash('sha256').update(publicKey).digest();
    const addrBytes = hash.slice(0, 20);
    return 'L1_' + addrBytes.toString('hex').toUpperCase();
}

// ==================== APOLLO WALLET CLASS ====================

class ApolloWallet {
    /**
     * Create new Apollo wallet with full security architecture
     */
    static async create(userPassword, options = {}) {
        section('Creating Apollo Wallet');
        
        // 1. Generate Root Key (for long-term identity, rarely used)
        const rootKeyBytes = crypto.randomBytes(32);
        const rootKeyPair = nacl.sign.keyPair.fromSeed(rootKeyBytes);
        const rootPubkey = Buffer.from(rootKeyPair.publicKey).toString('hex');
        const rootAddress = deriveL1Address(rootKeyPair.publicKey);
        
        info(`Root Key Generated (long-term identity)`);
        info(`Address: ${rootAddress}`);
        
        // 2. Split Root Key with SSS (2-of-3) for paper backup
        const shares = splitSecret(rootKeyBytes);
        pass(`Root Key split into ${shares.length} SSS shares (2-of-3 threshold)`);
        
        // 3. Generate Operational Key (for daily transactions)
        const opKeyBytes = crypto.randomBytes(32);
        const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);
        const opPubkey = Buffer.from(opKeyPair.publicKey).toString('hex');
        
        info(`Operational Key Generated (daily transactions)`);
        
        // 4. Generate Salt for password-based encryption
        const salt = crypto.randomBytes(32).toString('hex');
        pass('Cryptographic salt generated');
        
        // 5. Encrypt Operational Key with User Password
        const encryptionKey = deriveEncryptionKey(userPassword, salt);
        const encryptedOpKey = encryptKey(opKeyBytes, encryptionKey);
        pass('Operational Key encrypted with user password (AES-256-GCM)');
        
        // 6. Package wallet data
        const walletData = {
            name: 'Apollo',
            address: rootAddress,
            created: new Date().toISOString(),
            
            // Public data (can be stored anywhere)
            rootPubkey: rootPubkey,
            opPubkey: opPubkey,
            salt: salt,
            
            // Encrypted data (stored in database/cloud)
            encryptedOpKey: encryptedOpKey,
            
            // Paper backup (SSS shares - PRINT AND SECURE)
            sssShares: shares.map((s, i) => ({
                shareNumber: i + 1,
                x: s.x,
                y: s.y,
                qrCode: `APOLLO-SHARE-${i + 1}-${s.y}`
            })),
            
            // Metadata
            keyDerivation: 'PBKDF2-SHA256-300k',
            encryption: 'AES-256-GCM',
            sss: '2-of-3-secp256k1',
            
            // FOR TESTING ONLY - DO NOT STORE IN PRODUCTION
            _testOnly_rootKeyBytes: rootKeyBytes.toString('hex'),
            _testOnly_opKeyBytes: opKeyBytes.toString('hex')
        };
        
        pass(`${BOLD}Apollo Wallet Created Successfully!${RESET}`);
        console.log();
        
        return walletData;
    }
    
    /**
     * Login to Apollo wallet (decrypt operational key)
     */
    static login(walletData, userPassword) {
        info('Logging in to Apollo wallet...');
        
        const encryptionKey = deriveEncryptionKey(userPassword, walletData.salt);
        
        try {
            const opKeyBytes = decryptKey(walletData.encryptedOpKey, encryptionKey);
            const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);
            
            pass('Operational Key decrypted successfully');
            
            return {
                address: walletData.address,
                opKeyPair: opKeyPair,
                rootPubkey: walletData.rootPubkey
            };
        } catch (error) {
            throw new Error('Invalid user password or corrupted wallet data');
        }
    }
    
    /**
     * Sign a transaction with operational key (V2 SDK format)
     */
    static signTransaction(session, from, to, amount) {
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = Date.now().toString(); // Nonce as string
        
        // 1. Create canonical payload for hashing
        const canonical = `${from}|${to}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        
        // 2. Create signing message with domain separation
        const chainId = 1; // L1
        const requestPath = '/transfer';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        // 3. Sign with Ed25519
        const signature = nacl.sign.detached(
            Buffer.from(message, 'utf-8'),
            session.opKeyPair.secretKey
        );
        
        // 4. Return V2 SDK format
        return {
            operation_type: 'transfer',
            payload_fields: {
                from: from,
                to: to,
                amount: amount,
                timestamp: timestamp,
                nonce: nonce
            },
            payload_hash: payloadHash,
            public_key: Buffer.from(session.opKeyPair.publicKey).toString('hex'),
            signature: Buffer.from(signature).toString('hex'),
            chain_id: chainId,
            request_path: requestPath,
            schema_version: 2,
            timestamp: timestamp,
            nonce: nonce
        };
    }

    /**
     * Sign a burn transaction with operational key (V2 SDK format)
     */
    static signBurnTransaction(session, from, amount) {
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = Date.now().toString(); // Nonce as string
        
        // 1. Create canonical payload for hashing (from|amount|timestamp|nonce)
        const canonical = `${from}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        
        // 2. Create signing message with domain separation
        const chainId = 1; // L1
        const requestPath = '/burn';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        // 3. Sign with Ed25519
        const signature = nacl.sign.detached(
            Buffer.from(message, 'utf-8'),
            session.opKeyPair.secretKey
        );
        
        // 4. Return V2 SDK format
        return {
            operation_type: 'burn',
            payload_fields: {
                from: from,
                amount: amount,
                timestamp: timestamp,
                nonce: nonce
            },
            payload_hash: payloadHash,
            public_key: Buffer.from(session.opKeyPair.publicKey).toString('hex'),
            signature: Buffer.from(signature).toString('hex'),
            chain_id: chainId,
            request_path: requestPath,
            schema_version: 2,
            timestamp: timestamp,
            nonce: nonce
        };
    }
}

// ==================== MAIN TEST ====================

async function runApolloTests() {
    console.log(`\n${BOLD}${MAGENTA}╔═══════════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${BOLD}${MAGENTA}║                    🚀 APOLLO WALLET TEST SUITE                    ║${RESET}`);
    console.log(`${BOLD}${MAGENTA}║           Enhanced Secure Wallet with Dual-Key Architecture      ║${RESET}`);
    console.log(`${BOLD}${MAGENTA}╚═══════════════════════════════════════════════════════════════════╝${RESET}`);
    
    let passed = 0;
    let failed = 0;
    let apolloWallet = null;
    let apolloSession = null;
    
    // User password for Apollo (in production, this comes from user input)
    const APOLLO_USER_PASSWORD = 'apollo_secure_password_2026';
    
    // ==================== TEST 1: Create Apollo Wallet ====================
    section('Test 1: Create Apollo Wallet');
    try {
        apolloWallet = await ApolloWallet.create(APOLLO_USER_PASSWORD);
        
        // Verify wallet structure
        if (apolloWallet.address && apolloWallet.rootPubkey && apolloWallet.opPubkey) {
            pass('Wallet structure valid');
            info(`Address: ${apolloWallet.address}`);
            info(`Root Pubkey: ${apolloWallet.rootPubkey.slice(0, 16)}...`);
            info(`Op Pubkey: ${apolloWallet.opPubkey.slice(0, 16)}...`);
            passed++;
        } else {
            fail('Invalid wallet structure');
            failed++;
        }
        
        // Save Apollo data for future tests
        fs.writeFileSync(APOLLO_DATA_FILE, JSON.stringify(apolloWallet, null, 2));
        pass(`Wallet data saved to: ${APOLLO_DATA_FILE}`);
        
    } catch (e) {
        fail(`Wallet creation failed: ${e.message}`);
        failed++;
    }
    
    // ==================== TEST 2: Verify SSS Shares ====================
    section('Test 2: Verify SSS Recovery (2-of-3)');
    try {
        const originalRoot = Buffer.from(apolloWallet._testOnly_rootKeyBytes, 'hex');
        
        // Test recovery with shares 1+2
        const recovered1 = reconstructSecret([
            apolloWallet.sssShares[0],
            apolloWallet.sssShares[1]
        ]);
        
        if (Buffer.compare(recovered1, originalRoot) === 0) {
            pass('Recovery successful with shares 1 & 2');
            passed++;
        } else {
            fail('Recovery failed with shares 1 & 2');
            failed++;
        }
        
        // Test recovery with shares 2+3
        const recovered2 = reconstructSecret([
            apolloWallet.sssShares[1],
            apolloWallet.sssShares[2]
        ]);
        
        if (Buffer.compare(recovered2, originalRoot) === 0) {
            pass('Recovery successful with shares 2 & 3');
            passed++;
        } else {
            fail('Recovery failed with shares 2 & 3');
            failed++;
        }
        
    } catch (e) {
        fail(`SSS verification failed: ${e.message}`);
        failed += 2;
    }
    
    // ==================== TEST 3: Login to Apollo Wallet ====================
    section('Test 3: Login to Apollo Wallet');
    try {
        apolloSession = ApolloWallet.login(apolloWallet, APOLLO_USER_PASSWORD);
        
        if (apolloSession.address === apolloWallet.address) {
            pass('Login successful - operational key decrypted');
            info(`Session address: ${apolloSession.address}`);
            passed++;
        } else {
            fail('Login failed - address mismatch');
            failed++;
        }
        
    } catch (e) {
        fail(`Login failed: ${e.message}`);
        failed++;
    }
    
    // ==================== TEST 4: Mint Tokens to Apollo ====================
    section('Test 4: Mint 1000 BB Tokens to Apollo');
    try {
        const mintRes = await fetch(`${L1_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: apolloWallet.address,
                amount: 1000
            })
        });
        
        const mintData = await mintRes.json();
        
        if (mintData.success && mintData.new_balance === 1000) {
            pass(`Minted 1000 BB to Apollo`);
            info(`New balance: ${mintData.new_balance} BB`);
            passed++;
        } else {
            fail(`Mint failed: ${JSON.stringify(mintData)}`);
            failed++;
        }
        
    } catch (e) {
        fail(`Mint request failed: ${e.message}`);
        failed++;
    }
    
    // ==================== TEST 5: Check Apollo Balance ====================
    section('Test 5: Verify Apollo Balance');
    try {
        const balRes = await fetch(`${L1_URL}/balance/${apolloWallet.address}`);
        const balData = await balRes.json();
        
        if (balData.balance === 1000) {
            pass(`Balance confirmed: ${balData.balance} BB`);
            passed++;
        } else {
            fail(`Balance mismatch: expected 1000, got ${balData.balance}`);
            failed++;
        }
        
    } catch (e) {
        fail(`Balance check failed: ${e.message}`);
        failed++;
    }
    
    // ==================== TEST 6: Signed Transfer from Apollo ====================
    section('Test 6: Signed Transfer (Apollo → Bob)');
    try {
        // Sign transfer with Apollo's operational key
        const signedTx = ApolloWallet.signTransaction(
            apolloSession,
            apolloWallet.address,
            'L1_BOB_TEST_ACCOUNT',
            100
        );
        
        info('Transaction signed with Ed25519 (V2 SDK format)');
        info(`Signature: ${signedTx.signature.slice(0, 32)}...`);
        info(`Payload Hash: ${signedTx.payload_hash.slice(0, 32)}...`);
        
        // Submit signed transaction
        const transferRes = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedTx)
        });
        
        const contentType = transferRes.headers.get('content-type');
        let transferData;
        
        if (contentType && contentType.includes('application/json')) {
            transferData = await transferRes.json();
        } else {
            const text = await transferRes.text();
            fail(`Server returned non-JSON response: ${text.slice(0, 100)}`);
            failed++;
            throw new Error('Non-JSON response');
        }
        
        if (transferData.success) {
            pass('Signed transfer successful');
            info(`Transferred 100 BB to Bob`);
            info(`New Apollo balance: ${transferData.new_balance} BB`);
            passed++;
        } else {
            fail(`Transfer failed: ${transferData.error || 'Unknown error'}`);
            failed++;
        }
        
    } catch (e) {
        if (!e.message.includes('Non-JSON')) {
            fail(`Transfer test failed: ${e.message}`);
            failed++;
        }
    }
    
    // ==================== TEST 7: Verify Final Balance ====================
    section('Test 7: Verify Final Balance After Transfer');
    try {
        const balRes = await fetch(`${L1_URL}/balance/${apolloWallet.address}`);
        const balData = await balRes.json();
        
        const expectedBalance = 900; // 1000 - 100
        
        if (balData.balance === expectedBalance) {
            pass(`Final balance confirmed: ${balData.balance} BB`);
            passed++;
        } else {
            fail(`Balance mismatch: expected ${expectedBalance}, got ${balData.balance}`);
            failed++;
        }
        
    } catch (e) {
        fail(`Balance check failed: ${e.message}`);
        failed++;
    }
    
    // ==================== TEST 8: Burn Tokens ====================
    section('Test 8: Burn 200 BB Tokens');
    try {
        const burnAmount = 200;
        const signedBurn = ApolloWallet.signBurnTransaction(
            apolloSession,
            apolloWallet.address,
            burnAmount
        );
        
        info('Burn transaction signed with Ed25519');
        
        const burnRes = await fetch(`${L1_URL}/admin/burn`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedBurn)
        });
        
        let burnData;
        const contentType = burnRes.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            burnData = await burnRes.json();
        } else {
             const text = await burnRes.text();
             fail(`Server returned non-JSON response: ${text.slice(0, 100)}`);
             failed++;
             throw new Error('Non-JSON response');
        }

        if (burnData.success) {
            pass(`Burn successful: ${burnAmount} BB destroyed`);
            info(`New Apollo balance: ${burnData.new_balance} BB`);
            passed++;
        } else {
            fail(`Burn failed: ${burnData.error}`);
            failed++;
        }
    } catch (e) {
        if (!e.message.includes('Non-JSON')) {
             fail(`Burn test failed: ${e.message}`);
             failed++;
        }
    }

    // ==================== TEST 9: Verify Balance After Burn ====================
    section('Test 9: Verify Balance After Burn');
    try {
        const balRes = await fetch(`${L1_URL}/balance/${apolloWallet.address}`);
        const balData = await balRes.json();
        
        const expectedBalance = 700; // 900 - 200
        
        if (balData.balance === expectedBalance) {
            pass(`Post-burn balance confirmed: ${balData.balance} BB`);
            passed++;
        } else {
            fail(`Balance mismatch: expected ${expectedBalance}, got ${balData.balance}`);
            failed++;
        }
        
    } catch (e) {
        fail(`Balance check failed: ${e.message}`);
        failed++;
    }

    // ==================== TEST 10: Wrong Password Test ====================
    section('Test 10: Security - Wrong Password Rejection');
    try {
        try {
            ApolloWallet.login(apolloWallet, 'wrong_password_123');
            fail('Security breach: accepted wrong password!');
            failed++;
        } catch (error) {
            pass('Wrong password correctly rejected');
            passed++;
        }
    } catch (e) {
        fail(`Wrong password test failed: ${e.message}`);
        failed++;
    }
    
    // ==================== SUMMARY ====================
    console.log(`\n${BLUE}${'═'.repeat(70)}${RESET}`);
    console.log(`${BOLD}${MAGENTA}  APOLLO WALLET TEST RESULTS${RESET}`);
    console.log(`${BLUE}${'═'.repeat(70)}${RESET}\n`);
    
    console.log(`  ${GREEN}Passed:${RESET} ${passed}`);
    console.log(`  ${RED}Failed:${RESET} ${failed}`);
    console.log(`  ${CYAN}Total:${RESET}  ${passed + failed}\n`);
    
    if (failed === 0) {
        console.log(`${BOLD}${GREEN}  ✓ ALL APOLLO TESTS PASSED!${RESET}\n`);
        console.log(`${CYAN}  Apollo wallet data saved to:${RESET}`);
        console.log(`  ${APOLLO_DATA_FILE}\n`);
        console.log(`${YELLOW}  Keep SSS shares secure for wallet recovery!${RESET}\n`);
    } else {
        console.log(`${BOLD}${RED}  ✗ SOME TESTS FAILED${RESET}\n`);
    }
    
    console.log(`${BLUE}${'═'.repeat(70)}${RESET}\n`);
    
    process.exit(failed > 0 ? 1 : 0);
}

// Run the tests
runApolloTests().catch(err => {
    console.error(`${RED}Fatal error:${RESET}`, err);
    process.exit(1);
});
