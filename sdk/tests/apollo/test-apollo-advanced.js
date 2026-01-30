/**
 * APOLLO ADVANCED TESTS
 * 
 * Tests:
 * 1. Burn tokens from Apollo's wallet
 * 2. Session management with auto-lock
 * 3. SSS recovery using paper backup shares
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const fs = require('fs');
const path = require('path');

const L1_URL = 'http://localhost:8080';
const APOLLO_DATA_FILE = path.join(__dirname, 'apollo-wallet-data.json');

// Colors
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
    console.log(`${BOLD}${MAGENTA}  🚀 ${title}${RESET}`);
    console.log(`${BLUE}${'═'.repeat(70)}${RESET}\n`);
}

function pass(msg) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function info(msg) { console.log(`  ${CYAN}ℹ${RESET} ${msg}`); }
function warn(msg) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }

// ==================== SSS (SHAMIR'S SECRET SHARING) ====================

const SSS_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

function modInverse(a, m) {
    a = ((a % m) + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [BigInt(1), BigInt(0)];
    
    while (r !== BigInt(0)) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    
    return ((old_s % m) + m) % m;
}

function recombineSecret(shares) {
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
    const saltBuffer = Buffer.from(salt, 'hex');
    return crypto.pbkdf2Sync(userPassword, saltBuffer, 300000, 32, 'sha256');
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

// ==================== APOLLO WALLET CLASS ====================

class ApolloWallet {
    static unlock(userPassword, sessionDurationMs = 300000) {
        if (!fs.existsSync(APOLLO_DATA_FILE)) {
            throw new Error('Apollo wallet not found');
        }

        const data = JSON.parse(fs.readFileSync(APOLLO_DATA_FILE, 'utf8'));
        const encryptionKey = deriveEncryptionKey(userPassword, data.salt);
        const opKeyBytes = decryptKey(data.encryptedOpKey, encryptionKey);
        const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);

        return {
            address: data.address,
            opKeyPair: opKeyPair,
            opPubkey: data.opPubkey,
            unlockTime: Date.now(),
            sessionDurationMs: sessionDurationMs,
            isLocked: function() {
                return Date.now() - this.unlockTime > this.sessionDurationMs;
            },
            remainingTime: function() {
                const elapsed = Date.now() - this.unlockTime;
                const remaining = Math.max(0, this.sessionDurationMs - elapsed);
                return Math.floor(remaining / 1000);
            }
        };
    }

    static signBurnTransaction(session, from, amount) {
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = Date.now().toString();
        
        const canonical = `${from}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = crypto.createHash('sha256').update(canonical).digest('hex');
        
        const chainId = 1;
        const requestPath = '/admin/burn';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        const signature = nacl.sign.detached(
            Buffer.from(message, 'utf-8'),
            session.opKeyPair.secretKey
        );
        
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

    static recoverFromShares(share1, share2) {
        info('Attempting SSS recovery with 2 shares...');
        const recoveredRoot = recombineSecret([share1, share2]);
        const rootKeyPair = nacl.sign.keyPair.fromSeed(recoveredRoot);
        
        return {
            rootKeyBytes: recoveredRoot,
            rootKeyPair: rootKeyPair,
            publicKey: Buffer.from(rootKeyPair.publicKey).toString('hex')
        };
    }
}

// ==================== TESTS ====================

async function testBurn() {
    section('TEST 1: Burn Tokens from Apollo');
    
    try {
        // 1. Unlock wallet
        info('Unlocking Apollo wallet...');
        const session = ApolloWallet.unlock('apollo_secure_password_2026');
        pass('Apollo unlocked');

        // 2. Check initial balance
        const initialRes = await fetch(`${L1_URL}/balance/${session.address}`);
        const initialData = await initialRes.json();
        info(`Initial balance: ${initialData.balance.toLocaleString()} BB`);

        // 3. Burn 1,000 BB
        const burnAmount = 1000;
        info(`Burning ${burnAmount} BB...`);
        
        const burnTx = ApolloWallet.signBurnTransaction(session, session.address, burnAmount);
        const burnRes = await fetch(`${L1_URL}/admin/burn`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(burnTx)
        });
        
        const burnResult = await burnRes.json();
        
        if (burnResult.success) {
            pass(`Burned ${burnAmount} BB successfully`);
            info(`New balance: ${burnResult.new_balance.toLocaleString()} BB`);
            return true;
        } else {
            fail(`Burn failed: ${burnResult.error}`);
            return false;
        }
    } catch (error) {
        fail(`Test failed: ${error.message}`);
        return false;
    }
}

async function testSessionManagement() {
    section('TEST 2: Session Management & Auto-Lock');
    
    try {
        // 1. Create session with 5-second timeout
        info('Creating session with 5-second auto-lock...');
        const session = ApolloWallet.unlock('apollo_secure_password_2026', 5000);
        pass(`Session created for ${session.address}`);
        info(`Session duration: 5 seconds`);

        // 2. Check immediately
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (!session.isLocked()) {
            pass(`Session active (${session.remainingTime()}s remaining)`);
        } else {
            fail('Session locked prematurely');
            return false;
        }

        // 3. Wait for auto-lock
        await new Promise(resolve => setTimeout(resolve, 2000));
        info(`Waiting... (${session.remainingTime()}s remaining)`);
        
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // 4. Check if locked
        if (session.isLocked()) {
            pass('Session auto-locked after timeout ✓');
            warn('Attempting to use locked session would require re-authentication');
            return true;
        } else {
            fail('Session should be locked but is still active');
            return false;
        }
    } catch (error) {
        fail(`Test failed: ${error.message}`);
        return false;
    }
}

async function testSSSRecovery() {
    section('TEST 3: SSS Recovery from Paper Backup');
    
    try {
        // 1. Load Apollo's data
        const data = JSON.parse(fs.readFileSync(APOLLO_DATA_FILE, 'utf8'));
        info('Loaded Apollo wallet data');
        info(`Original root pubkey: ${data.rootPubkey.slice(0, 32)}...`);

        // 2. Simulate paper backup scenario (using shares 1 and 3)
        warn('Simulating recovery scenario: User has paper backup shares 1 & 3');
        const share1 = data.sssShares[0];
        const share3 = data.sssShares[2];
        
        info(`Share 1: ${share1.qrCode}`);
        info(`Share 3: ${share3.qrCode}`);

        // 3. Recover root key
        const recovered = ApolloWallet.recoverFromShares(share1, share3);
        pass('Root key recovered from 2-of-3 shares');
        info(`Recovered pubkey: ${recovered.publicKey.slice(0, 32)}...`);

        // 4. Verify recovery
        if (recovered.publicKey === data.rootPubkey) {
            pass('✓ Recovery successful: Public keys match!');
            pass('✓ User can now restore full wallet access');
            
            // Show what user could do with recovered root
            info('With recovered root key, user can:');
            info('  • Generate new operational keys');
            info('  • Update password encryption');
            info('  • Restore full wallet control');
            
            return true;
        } else {
            fail('Recovery failed: Public key mismatch');
            warn(`Expected: ${data.rootPubkey}`);
            warn(`Got:      ${recovered.publicKey}`);
            return false;
        }
    } catch (error) {
        fail(`Test failed: ${error.message}`);
        return false;
    }
}

// ==================== MAIN ====================

async function main() {
    console.log(`\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}`);
    console.log(`${BOLD}${CYAN}║         APOLLO ADVANCED WALLET TESTS                           ║${RESET}`);
    console.log(`${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}`);

    const results = {
        burn: false,
        session: false,
        recovery: false
    };

    // Run all tests
    results.burn = await testBurn();
    results.session = await testSessionManagement();
    results.recovery = await testSSSRecovery();

    // Summary
    section('TEST SUMMARY');
    console.log(`  ${results.burn ? GREEN + '✓' : RED + '✗'}${RESET} Burn Tokens: ${results.burn ? 'PASSED' : 'FAILED'}`);
    console.log(`  ${results.session ? GREEN + '✓' : RED + '✗'}${RESET} Session Management: ${results.session ? 'PASSED' : 'FAILED'}`);
    console.log(`  ${results.recovery ? GREEN + '✓' : RED + '✗'}${RESET} SSS Recovery: ${results.recovery ? 'PASSED' : 'FAILED'}`);

    const allPassed = Object.values(results).every(r => r);
    if (allPassed) {
        console.log(`\n${GREEN}${BOLD}  ✓ ALL TESTS PASSED${RESET}`);
        console.log(`${GREEN}  Apollo wallet is production-ready!${RESET}\n`);
    } else {
        console.log(`\n${RED}${BOLD}  ✗ SOME TESTS FAILED${RESET}\n`);
    }
}

main();
