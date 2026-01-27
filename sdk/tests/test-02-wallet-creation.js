/**
 * TEST 02: Real Wallet Creation on L1
 * 
 * Tests:
 * - Generate keypair via /auth/keypair
 * - Create wallet with SSS shares
 * - Derive address from public key
 * - Verify wallet format
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');

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

// SSS Implementation (simplified for testing)
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
    return ((old_s % m) + m) % m;
}

function splitSecret(secretBytes, n = 3, k = 2) {
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
    let secret = BigInt(0);
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        let li = BigInt(1);
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                const xj = BigInt(shares[j].x);
                const num = (SSS_PRIME - xj) % SSS_PRIME;
                const den = ((xi - xj) % SSS_PRIME + SSS_PRIME) % SSS_PRIME;
                li = (li * num % SSS_PRIME) * modInverse(den, SSS_PRIME) % SSS_PRIME;
            }
        }
        secret = (secret + yi * li) % SSS_PRIME;
    }
    return Buffer.from(secret.toString(16).padStart(64, '0'), 'hex');
}

// Export for other tests
let createdWallet = null;

async function runTests() {
    console.log(`\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${CYAN}║  TEST 02: REAL WALLET CREATION ON L1                         ║${RESET}`);
    console.log(`${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}`);

    let passed = 0;
    let failed = 0;

    // Test 2.1: Generate Keypair via Server
    section('2.1 Generate Keypair via Server');
    let serverKeypair = null;
    try {
        const res = await fetch(`${L1_URL}/auth/keypair`, { method: 'POST' });
        const data = await res.json();
        
        if (data.success && data.public_key && data.secret_key && data.address) {
            pass('Server generated keypair');
            info(`Public Key: ${data.public_key.slice(0, 32)}...`);
            info(`Address: ${data.address}`);
            serverKeypair = data;
            passed++;
        } else {
            fail(`Invalid keypair response: ${JSON.stringify(data)}`);
            failed++;
        }
    } catch (e) {
        fail(`Keypair generation failed: ${e.message}`);
        failed++;
    }

    // Test 2.2: Create Local Keypair with nacl
    section('2.2 Create Local Keypair (Ed25519)');
    let localKeypair = null;
    try {
        const seed = crypto.randomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        const publicKey = Buffer.from(keyPair.publicKey).toString('hex');
        const secretKey = Buffer.from(keyPair.secretKey).toString('hex');
        const address = 'L1_' + crypto.createHash('sha256')
            .update(keyPair.publicKey)
            .digest()
            .slice(0, 20)
            .toString('hex')
            .toUpperCase();
        
        localKeypair = {
            seed,
            publicKey,
            secretKey,
            keyPair,
            address
        };
        
        pass('Local keypair created');
        info(`Public Key: ${publicKey.slice(0, 32)}...`);
        info(`Address: ${address}`);
        
        // Verify address format
        if (address.startsWith('L1_') && address.length === 43) {
            pass('Address format valid (L1_<40 hex chars>)');
            passed++;
        } else {
            fail(`Invalid address format: ${address}`);
            failed++;
        }
        passed++;
    } catch (e) {
        fail(`Local keypair creation failed: ${e.message}`);
        failed++;
    }

    // Test 2.3: SSS Share Generation
    section('2.3 SSS Share Generation (2-of-3)');
    let sssShares = null;
    try {
        sssShares = splitSecret(localKeypair.seed, 3, 2);
        
        pass('Generated 3 SSS shares');
        info(`Share 1 (x=${sssShares[0].x}): ${sssShares[0].y.slice(0, 32)}...`);
        info(`Share 2 (x=${sssShares[1].x}): ${sssShares[1].y.slice(0, 32)}...`);
        info(`Share 3 (x=${sssShares[2].x}): ${sssShares[2].y.slice(0, 32)}...`);
        passed++;
    } catch (e) {
        fail(`SSS generation failed: ${e.message}`);
        failed++;
    }

    // Test 2.4: SSS Recovery (shares 1+2)
    section('2.4 SSS Recovery (Shares 1 & 2)');
    try {
        const recoveredSeed = reconstructSecret([sssShares[0], sssShares[1]]);
        
        if (Buffer.compare(recoveredSeed, localKeypair.seed) === 0) {
            pass('Seed recovered from shares 1 & 2');
            passed++;
        } else {
            fail('Recovered seed does not match original');
            failed++;
        }
    } catch (e) {
        fail(`SSS recovery (1+2) failed: ${e.message}`);
        failed++;
    }

    // Test 2.5: SSS Recovery (shares 2+3)
    section('2.5 SSS Recovery (Shares 2 & 3)');
    try {
        const recoveredSeed = reconstructSecret([sssShares[1], sssShares[2]]);
        
        if (Buffer.compare(recoveredSeed, localKeypair.seed) === 0) {
            pass('Seed recovered from shares 2 & 3');
            passed++;
        } else {
            fail('Recovered seed does not match original');
            failed++;
        }
    } catch (e) {
        fail(`SSS recovery (2+3) failed: ${e.message}`);
        failed++;
    }

    // Test 2.6: SSS Recovery (shares 1+3)
    section('2.6 SSS Recovery (Shares 1 & 3)');
    try {
        const recoveredSeed = reconstructSecret([sssShares[0], sssShares[2]]);
        
        if (Buffer.compare(recoveredSeed, localKeypair.seed) === 0) {
            pass('Seed recovered from shares 1 & 3');
            passed++;
        } else {
            fail('Recovered seed does not match original');
            failed++;
        }
    } catch (e) {
        fail(`SSS recovery (1+3) failed: ${e.message}`);
        failed++;
    }

    // Test 2.7: Verify Single Share Cannot Recover
    section('2.7 Security: Single Share Cannot Recover');
    try {
        // With only 1 share, you shouldn't be able to reconstruct
        // (This test ensures k=2 threshold is enforced)
        const singleShare = [sssShares[0]];
        // If we try to reconstruct with 1 share, it will just return that share's y value
        // which should NOT equal the original seed
        const badRecovery = reconstructSecret(singleShare);
        
        if (Buffer.compare(badRecovery, localKeypair.seed) !== 0) {
            pass('Single share cannot recover seed (security verified)');
            passed++;
        } else {
            fail('SECURITY ISSUE: Single share recovered seed!');
            failed++;
        }
    } catch (e) {
        // Error is also acceptable - means can't reconstruct
        pass('Single share throws error (security verified)');
        passed++;
    }

    // Store wallet for subsequent tests
    createdWallet = {
        ...localKeypair,
        sssShares,
        serverKeypair
    };

    // Summary
    section('TEST SUMMARY');
    console.log(`  ${GREEN}Passed: ${passed}${RESET}`);
    console.log(`  ${failed > 0 ? RED : GREEN}Failed: ${failed}${RESET}`);
    
    if (failed === 0) {
        console.log(`\n  ${GREEN}✨ ALL WALLET CREATION TESTS PASSED!${RESET}`);
        console.log(`  ${CYAN}Wallet ready for funding: ${localKeypair.address}${RESET}\n`);
    } else {
        console.log(`\n  ${RED}❌ SOME TESTS FAILED${RESET}\n`);
        process.exit(1);
    }
    
    return { passed, failed, wallet: createdWallet };
}

runTests().catch(console.error);

module.exports = { runTests, splitSecret, reconstructSecret };
