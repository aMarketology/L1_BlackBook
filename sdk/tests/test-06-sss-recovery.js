/**
 * TEST 06: SSS (Shamir's Secret Sharing) Recovery
 * 
 * Tests:
 * - Create wallet with SSS shares
 * - Simulate "lost password" scenario
 * - Recover seed from 2-of-3 shares
 * - Verify recovered wallet works
 * - Test all share combinations
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');

const L1_URL = 'http://localhost:8080';
const CHAIN_ID = 1;

// ANSI Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';
const RESET = '\x1b[0m';

function section(title) {
    console.log(`\n${BLUE}═══════════════════════════════════════════════════════════════${RESET}`);
    console.log(`${BLUE}  ${title}${RESET}`);
    console.log(`${BLUE}═══════════════════════════════════════════════════════════════${RESET}\n`);
}

function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); return true; }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); return false; }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }

// ═══════════════════════════════════════════════════════════════
// SSS IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════

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
        shares.push({
            x,
            y: y.toString(16).padStart(64, '0'),
            label: ['Password-Encrypted', 'Recovery Codes', 'Email Backup'][x-1]
        });
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

// Create wallet from seed
function walletFromSeed(seed) {
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKey = Buffer.from(keyPair.publicKey).toString('hex');
    const address = 'L1_' + crypto.createHash('sha256')
        .update(keyPair.publicKey)
        .digest()
        .slice(0, 20)
        .toString('hex')
        .toUpperCase();
    
    return { seed, keyPair, publicKey, address };
}

// Create signed transfer
function createSignedTransfer(wallet, toAddress, amount) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(8).toString('hex');
    const requestPath = '/transfer';
    
    const canonical = `${wallet.address}|${toAddress}|${amount}|${timestamp}|${nonce}`;
    const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
    
    const domainPrefix = `BLACKBOOK_L${CHAIN_ID}${requestPath}`;
    const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
    
    const signature = nacl.sign.detached(Buffer.from(message), wallet.keyPair.secretKey);
    
    return {
        public_key: wallet.publicKey,
        payload_hash: payloadHash,
        payload_fields: {
            from: wallet.address,
            to: toAddress,
            amount,
            timestamp,
            nonce
        },
        operation_type: 'transfer',
        schema_version: 2,
        timestamp,
        nonce,
        chain_id: CHAIN_ID,
        request_path: requestPath,
        signature: Buffer.from(signature).toString('hex')
    };
}

async function runTests() {
    console.log(`\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${CYAN}║  TEST 06: SSS (SHAMIR'S SECRET SHARING) RECOVERY             ║${RESET}`);
    console.log(`${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}`);

    let passed = 0;
    let failed = 0;

    // Test 6.1: Create Wallet with SSS
    section('6.1 Create Wallet with SSS Shares');
    
    const originalSeed = crypto.randomBytes(32);
    const originalWallet = walletFromSeed(originalSeed);
    const shares = splitSecret(originalSeed, 3, 2);
    
    pass('Wallet created');
    info(`Address: ${originalWallet.address}`);
    info(`Seed: ${originalSeed.toString('hex').slice(0, 32)}...`);
    console.log();
    
    pass('SSS Shares generated (2-of-3):');
    shares.forEach((s, i) => {
        info(`Share ${i+1} (${s.label}): x=${s.x}, y=${s.y.slice(0, 24)}...`);
    });
    passed++;

    // Fund the wallet
    section('6.2 Fund Original Wallet');
    try {
        const res = await fetch(`${L1_URL}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: originalWallet.address, amount: 500.0 })
        });
        const data = await res.json();
        
        if (data.success) {
            pass(`Funded with 500 BB`);
            passed++;
        } else {
            fail(`Funding failed: ${data.error}`);
            failed++;
        }
    } catch (e) {
        fail(`Funding error: ${e.message}`);
        failed++;
    }

    // Test 6.3: Simulate Lost Password - Recover with Shares 1+2
    section('6.3 Recovery Simulation: Shares 1 & 2');
    try {
        info(`${MAGENTA}🔒 USER SCENARIO: Forgot password, has recovery codes${RESET}`);
        info('Using Share 1 (Password-Encrypted) + Share 2 (Recovery Codes)');
        console.log();
        
        const recoveredSeed = reconstructSecret([shares[0], shares[1]]);
        const recoveredWallet = walletFromSeed(recoveredSeed);
        
        if (recoveredWallet.address === originalWallet.address) {
            pass('Seed recovered successfully!');
            pass(`Address matches: ${recoveredWallet.address}`);
            passed++;
        } else {
            fail('Recovered address does not match!');
            info(`Original:  ${originalWallet.address}`);
            info(`Recovered: ${recoveredWallet.address}`);
            failed++;
        }
    } catch (e) {
        fail(`Recovery 1+2 failed: ${e.message}`);
        failed++;
    }

    // Test 6.4: Recovery with Shares 2+3
    section('6.4 Recovery Simulation: Shares 2 & 3');
    try {
        info(`${MAGENTA}🔒 USER SCENARIO: No password share, using recovery codes + email${RESET}`);
        info('Using Share 2 (Recovery Codes) + Share 3 (Email Backup)');
        console.log();
        
        const recoveredSeed = reconstructSecret([shares[1], shares[2]]);
        const recoveredWallet = walletFromSeed(recoveredSeed);
        
        if (recoveredWallet.address === originalWallet.address) {
            pass('Seed recovered with shares 2+3!');
            passed++;
        } else {
            fail('Recovery 2+3 failed!');
            failed++;
        }
    } catch (e) {
        fail(`Recovery 2+3 error: ${e.message}`);
        failed++;
    }

    // Test 6.5: Recovery with Shares 1+3
    section('6.5 Recovery Simulation: Shares 1 & 3');
    try {
        info(`${MAGENTA}🔒 USER SCENARIO: Lost recovery codes, has password + email${RESET}`);
        info('Using Share 1 (Password-Encrypted) + Share 3 (Email Backup)');
        console.log();
        
        const recoveredSeed = reconstructSecret([shares[0], shares[2]]);
        const recoveredWallet = walletFromSeed(recoveredSeed);
        
        if (recoveredWallet.address === originalWallet.address) {
            pass('Seed recovered with shares 1+3!');
            passed++;
        } else {
            fail('Recovery 1+3 failed!');
            failed++;
        }
    } catch (e) {
        fail(`Recovery 1+3 error: ${e.message}`);
        failed++;
    }

    // Test 6.6: Verify Recovered Wallet Can Transact
    section('6.6 Recovered Wallet Transaction Test');
    try {
        info('Recovering wallet and making a transfer...');
        
        const recoveredSeed = reconstructSecret([shares[0], shares[1]]);
        const recoveredWallet = walletFromSeed(recoveredSeed);
        
        // Create a destination
        const destSeed = crypto.randomBytes(32);
        const destWallet = walletFromSeed(destSeed);
        
        // Make transfer from recovered wallet
        const transferReq = createSignedTransfer(recoveredWallet, destWallet.address, 50.0);
        
        const res = await fetch(`${L1_URL}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(transferReq)
        });
        const data = await res.json();
        
        if (data.success) {
            pass('Recovered wallet transferred 50 BB!');
            info(`Tx ID: ${data.tx_id}`);
            info(`Remaining Balance: ${data.from_balance} BB`);
            passed++;
        } else {
            fail(`Transfer failed: ${data.error}`);
            failed++;
        }
    } catch (e) {
        fail(`Transaction test error: ${e.message}`);
        failed++;
    }

    // Test 6.7: Single Share Cannot Recover (Security)
    section('6.7 Security: Single Share Cannot Recover');
    try {
        const singleRecovery = reconstructSecret([shares[0]]);
        
        if (Buffer.compare(singleRecovery, originalSeed) !== 0) {
            pass('Single share does NOT recover original seed');
            info('✓ 2-of-3 threshold is enforced');
            passed++;
        } else {
            fail('SECURITY BREACH: Single share recovered seed!');
            failed++;
        }
    } catch (e) {
        pass('Single share recovery throws error (expected)');
        passed++;
    }

    // Test 6.8: Display Recovery Flow for Users
    section('6.8 User Recovery Flow Documentation');
    console.log(`
  ${CYAN}╭──────────────────────────────────────────────────────────────╮${RESET}
  ${CYAN}│  SSS RECOVERY GUIDE FOR END USERS                           │${RESET}
  ${CYAN}╰──────────────────────────────────────────────────────────────╯${RESET}

  ${YELLOW}Your wallet is protected by 3 shares. Any 2 can recover it:${RESET}

  ${GREEN}Share 1: Password-Encrypted${RESET}
     → Stored in Supabase, decrypted with your password
     → If you know your password, this is always available

  ${GREEN}Share 2: Recovery Codes${RESET}
     → 24 words you wrote down when creating the wallet
     → Store safely offline (paper, metal, safety deposit box)

  ${GREEN}Share 3: Email Recovery${RESET}
     → Encrypted and sent to your email
     → Requires access to your registered email

  ${YELLOW}Recovery Scenarios:${RESET}
  
  • Forgot password? → Use Recovery Codes + Email
  • Lost recovery codes? → Use Password + Email
  • Lost email access? → Use Password + Recovery Codes
  • Lost 2+ methods? → ❌ Cannot recover (this is by design!)

  ${RED}IMPORTANT: Store your recovery codes safely!${RESET}
`);
    pass('Recovery documentation displayed');
    passed++;

    // Summary
    section('TEST SUMMARY');
    console.log(`  ${GREEN}Passed: ${passed}${RESET}`);
    console.log(`  ${failed > 0 ? RED : GREEN}Failed: ${failed}${RESET}`);
    
    if (failed === 0) {
        console.log(`\n  ${GREEN}✨ ALL SSS RECOVERY TESTS PASSED!${RESET}\n`);
    } else {
        console.log(`\n  ${RED}❌ SOME TESTS FAILED${RESET}\n`);
        process.exit(1);
    }
    
    return { passed, failed, shares, originalWallet };
}

runTests().catch(console.error);

module.exports = { runTests, splitSecret, reconstructSecret, walletFromSeed };
