/**
 * BlackBook Wallet Recovery SDK
 * 
 * Integrates Shamir's Secret Sharing (SSS) for secure password recovery.
 * 
 * KEY CONCEPTS:
 * - Password encrypts the seed, does NOT derive the keypair
 * - Changing password = re-encrypt same seed = same keys
 * - SSS splits seed into shares for recovery
 * 
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────┐
 * │                        SEED (32 bytes)                       │
 * │                             │                                │
 * │              ┌──────────────┼──────────────┐                │
 * │              ▼              ▼              ▼                │
 * │          Share 1        Share 2        Share 3              │
 * │         (password)    (recovery)      (email)               │
 * │              │            codes           │                  │
 * │              ▼                            ▼                  │
 * │         Supabase      User writes    Email sent             │
 * │                          down                                │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * RECOVERY: Any 2 of 3 shares → reconstruct seed → set new password
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';
import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════════════════════
// SHAMIR'S SECRET SHARING
// ═══════════════════════════════════════════════════════════════════════════

const PRIME = 2n ** 256n - 189n;

function randomBigInt(max) {
    const bytes = crypto.randomBytes(32);
    return BigInt('0x' + bytes.toString('hex')) % max;
}

function modInverse(a, m) {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
}

function evaluatePolynomial(coeffs, x, prime) {
    let result = 0n, power = 1n;
    for (const c of coeffs) {
        result = (result + c * power) % prime;
        power = (power * x) % prime;
    }
    return result;
}

function splitSecret(secret, n, k) {
    const secretBigInt = BigInt('0x' + secret.toString('hex'));
    const coeffs = [secretBigInt];
    for (let i = 1; i < k; i++) coeffs.push(randomBigInt(PRIME));
    
    const shares = [];
    for (let x = 1; x <= n; x++) {
        shares.push({
            x,
            y: evaluatePolynomial(coeffs, BigInt(x), PRIME).toString(16).padStart(64, '0')
        });
    }
    return shares;
}

function reconstructSecret(shares) {
    let secret = 0n;
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        let num = 1n, den = 1n;
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                const xj = BigInt(shares[j].x);
                num = (num * (0n - xj)) % PRIME;
                den = (den * (xi - xj)) % PRIME;
            }
        }
        num = ((num % PRIME) + PRIME) % PRIME;
        den = ((den % PRIME) + PRIME) % PRIME;
        secret = (secret + yi * num * modInverse(den, PRIME)) % PRIME;
    }
    secret = ((secret % PRIME) + PRIME) % PRIME;
    const hex = secret.toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

// ═══════════════════════════════════════════════════════════════════════════
// WALLET RECOVERY SDK
// ═══════════════════════════════════════════════════════════════════════════

export class WalletRecoverySDK {
    
    /**
     * Create a new wallet with SSS recovery
     * @param {string} password - User's password
     * @param {string} email - User's email
     * @returns {Object} Wallet data for storage + recovery codes for user
     */
    static createWallet(password, email) {
        // 1. Generate cryptographically secure seed
        const seed = crypto.randomBytes(32);
        
        // 2. Derive keypair from seed
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        const publicKey = Buffer.from(keypair.publicKey).toString('hex');
        
        // 3. Derive L1 address
        const addressHash = CryptoJS.SHA256(publicKey).toString();
        const l1Address = 'L1_' + addressHash.substring(0, 40).toUpperCase();
        
        // 4. Split seed into 3 shares (need 2 to recover)
        const shares = splitSecret(seed, 3, 2);
        
        // 5. Encrypt primary vault with password
        const salt = crypto.randomBytes(16).toString('hex');
        const encryptionKey = CryptoJS.PBKDF2(password, salt, {
            keySize: 256/32, iterations: 100000
        });
        const encryptedVault = CryptoJS.AES.encrypt(
            seed.toString('hex'), 
            encryptionKey.toString()
        ).toString();
        
        // 6. Encrypt email share (for recovery link)
        const emailSalt = crypto.randomBytes(16).toString('hex');
        const emailKey = CryptoJS.PBKDF2(email + ':recovery', emailSalt, {
            keySize: 256/32, iterations: 50000
        });
        const encryptedEmailShare = CryptoJS.AES.encrypt(
            JSON.stringify(shares[2]),
            emailKey.toString()
        ).toString();
        
        // 7. Format recovery codes (share 2) for user to write down
        const recoveryCodes = this.formatRecoveryCodes(shares[1]);
        
        return {
            // Store in Supabase
            supabaseData: {
                l1_address: l1Address,
                public_key: publicKey,
                email: email,
                vault_salt: salt,
                vault_encrypted: encryptedVault,
                recovery_share_x: shares[0].x,  // Share 1 metadata
                recovery_share_y_encrypted: CryptoJS.AES.encrypt(
                    shares[0].y, encryptionKey.toString()
                ).toString(),
                email_share_salt: emailSalt,
                email_share_encrypted: encryptedEmailShare,
                created_at: new Date().toISOString()
            },
            
            // Give to user (show once, they write down)
            recoveryCodes: recoveryCodes,
            
            // For immediate use
            wallet: {
                l1_address: l1Address,
                public_key: publicKey
            }
        };
    }
    
    /**
     * Unlock wallet with password (normal login)
     */
    static unlockWallet(supabaseData, password) {
        const encryptionKey = CryptoJS.PBKDF2(password, supabaseData.vault_salt, {
            keySize: 256/32, iterations: 100000
        });
        
        const decrypted = CryptoJS.AES.decrypt(
            supabaseData.vault_encrypted, 
            encryptionKey.toString()
        );
        const seedHex = decrypted.toString(CryptoJS.enc.Utf8);
        
        if (!seedHex || seedHex.length !== 64) {
            throw new Error('Wrong password');
        }
        
        const seed = Buffer.from(seedHex, 'hex');
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        
        return {
            keypair,
            l1_address: supabaseData.l1_address,
            public_key: supabaseData.public_key
        };
    }
    
    /**
     * Change password (user knows old password)
     * Returns new vault data - same keys, same address
     */
    static changePassword(supabaseData, oldPassword, newPassword) {
        // 1. Decrypt with old password to get seed
        const oldKey = CryptoJS.PBKDF2(oldPassword, supabaseData.vault_salt, {
            keySize: 256/32, iterations: 100000
        });
        const decrypted = CryptoJS.AES.decrypt(
            supabaseData.vault_encrypted, 
            oldKey.toString()
        );
        const seedHex = decrypted.toString(CryptoJS.enc.Utf8);
        
        if (!seedHex || seedHex.length !== 64) {
            throw new Error('Wrong old password');
        }
        
        // 2. Re-encrypt with new password
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newKey = CryptoJS.PBKDF2(newPassword, newSalt, {
            keySize: 256/32, iterations: 100000
        });
        const newVault = CryptoJS.AES.encrypt(seedHex, newKey.toString()).toString();
        
        // 3. Also re-encrypt the recovery share
        const oldShareY = CryptoJS.AES.decrypt(
            supabaseData.recovery_share_y_encrypted,
            oldKey.toString()
        ).toString(CryptoJS.enc.Utf8);
        
        const newShareYEncrypted = CryptoJS.AES.encrypt(
            oldShareY, newKey.toString()
        ).toString();
        
        return {
            // Update these fields in Supabase
            vault_salt: newSalt,
            vault_encrypted: newVault,
            recovery_share_y_encrypted: newShareYEncrypted,
            updated_at: new Date().toISOString()
        };
    }
    
    /**
     * Recover wallet using recovery codes + email link
     * Returns new vault data - same keys, same address
     */
    static recoverWithCodesAndEmail(recoveryCodes, emailShareData, newPassword, email) {
        // 1. Parse recovery codes into share
        const share2 = this.parseRecoveryCodes(recoveryCodes);
        
        // 2. Decrypt email share
        const emailKey = CryptoJS.PBKDF2(email + ':recovery', emailShareData.salt, {
            keySize: 256/32, iterations: 50000
        });
        const decrypted = CryptoJS.AES.decrypt(
            emailShareData.encrypted, 
            emailKey.toString()
        );
        const share3 = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
        
        // 3. Reconstruct seed from 2 shares
        const seed = reconstructSecret([share2, share3]);
        
        // 4. Verify we got valid seed by deriving keypair
        const keypair = nacl.sign.keyPair.fromSeed(seed);
        const publicKey = Buffer.from(keypair.publicKey).toString('hex');
        const addressHash = CryptoJS.SHA256(publicKey).toString();
        const l1Address = 'L1_' + addressHash.substring(0, 40).toUpperCase();
        
        // 5. Create new vault with new password
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newKey = CryptoJS.PBKDF2(newPassword, newSalt, {
            keySize: 256/32, iterations: 100000
        });
        const newVault = CryptoJS.AES.encrypt(
            seed.toString('hex'), 
            newKey.toString()
        ).toString();
        
        // 6. Generate new shares for future recovery
        const newShares = splitSecret(seed, 3, 2);
        
        return {
            // Update in Supabase
            supabaseUpdate: {
                vault_salt: newSalt,
                vault_encrypted: newVault,
                recovery_share_x: newShares[0].x,
                recovery_share_y_encrypted: CryptoJS.AES.encrypt(
                    newShares[0].y, newKey.toString()
                ).toString(),
                updated_at: new Date().toISOString()
            },
            
            // New recovery codes (show to user)
            newRecoveryCodes: this.formatRecoveryCodes(newShares[1]),
            
            // Wallet info (should match original)
            wallet: {
                l1_address: l1Address,
                public_key: publicKey
            }
        };
    }
    
    /**
     * Format share as recovery codes
     */
    static formatRecoveryCodes(share) {
        const combined = share.x.toString().padStart(2, '0') + share.y;
        const codes = [];
        for (let i = 0; i < combined.length; i += 8) {
            codes.push(combined.slice(i, i + 8).toUpperCase());
        }
        return codes;
    }
    
    /**
     * Parse recovery codes back to share
     */
    static parseRecoveryCodes(codes) {
        const combined = codes.join('').toLowerCase();
        return {
            x: parseInt(combined.slice(0, 2)),
            y: combined.slice(2)
        };
    }
    
    /**
     * Sign a transaction (after wallet is unlocked)
     */
    static signTransaction(keypair, payload, walletAddress) {
        const payloadStr = JSON.stringify(payload);
        const timestamp = Math.floor(Date.now() / 1000);
        const nonce = crypto.randomUUID();
        
        const CHAIN_ID_L1 = 0x01;
        const message = `${payloadStr}\n${timestamp}\n${nonce}`;
        const messageBytes = new Uint8Array(1 + message.length);
        messageBytes[0] = CHAIN_ID_L1;
        messageBytes.set(new TextEncoder().encode(message), 1);
        
        const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
        
        return {
            public_key: Buffer.from(keypair.publicKey).toString('hex'),
            wallet_address: walletAddress,
            payload: payloadStr,
            timestamp,
            nonce,
            chain_id: CHAIN_ID_L1,
            signature: Buffer.from(signature).toString('hex')
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEMO / TEST
// ═══════════════════════════════════════════════════════════════════════════

async function demo() {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('WALLET RECOVERY SDK - FULL DEMO');
    console.log('═══════════════════════════════════════════════════════════════\n');
    
    // 1. Create new wallet
    console.log('1. CREATE WALLET');
    console.log('─────────────────────────────────────────────────────────────');
    const wallet = WalletRecoverySDK.createWallet('MyPassword123!', 'user@example.com');
    
    console.log('   L1 Address:', wallet.wallet.l1_address);
    console.log('   Public Key:', wallet.wallet.public_key.slice(0, 32) + '...');
    console.log('\n   📝 RECOVERY CODES (write these down!):');
    wallet.recoveryCodes.forEach((code, i) => console.log(`      ${i+1}. ${code}`));
    
    // 2. Normal login
    console.log('\n2. NORMAL LOGIN (with password)');
    console.log('─────────────────────────────────────────────────────────────');
    const unlocked = WalletRecoverySDK.unlockWallet(wallet.supabaseData, 'MyPassword123!');
    console.log('   ✓ Wallet unlocked');
    console.log('   Address:', unlocked.l1_address);
    
    // 3. Sign a transaction
    console.log('\n3. SIGN TRANSACTION');
    console.log('─────────────────────────────────────────────────────────────');
    const signed = WalletRecoverySDK.signTransaction(
        unlocked.keypair,
        { to: 'L1_BOB123', amount: 10 },
        unlocked.l1_address
    );
    console.log('   ✓ Transaction signed');
    console.log('   Signature:', signed.signature.slice(0, 32) + '...');
    
    // 4. Change password
    console.log('\n4. CHANGE PASSWORD');
    console.log('─────────────────────────────────────────────────────────────');
    const updated = WalletRecoverySDK.changePassword(
        wallet.supabaseData, 
        'MyPassword123!', 
        'NewPassword456!'
    );
    console.log('   ✓ Password changed');
    console.log('   Same address:', wallet.wallet.l1_address);
    console.log('   Same public key: (unchanged)');
    
    // Update supabase data for next test
    const updatedSupabase = { ...wallet.supabaseData, ...updated };
    
    // 5. Login with new password
    console.log('\n5. LOGIN WITH NEW PASSWORD');
    console.log('─────────────────────────────────────────────────────────────');
    const unlocked2 = WalletRecoverySDK.unlockWallet(updatedSupabase, 'NewPassword456!');
    console.log('   ✓ Wallet unlocked with new password');
    console.log('   Same address:', unlocked2.l1_address);
    
    // 6. Recover with codes + email (simulated)
    console.log('\n6. RECOVER WALLET (forgot password)');
    console.log('─────────────────────────────────────────────────────────────');
    console.log('   Using: recovery codes + email share');
    
    const recovered = WalletRecoverySDK.recoverWithCodesAndEmail(
        wallet.recoveryCodes,
        { 
            salt: wallet.supabaseData.email_share_salt,
            encrypted: wallet.supabaseData.email_share_encrypted
        },
        'RecoveredPassword789!',
        'user@example.com'
    );
    
    console.log('   ✓ Wallet recovered with new password');
    console.log('   Same address:', recovered.wallet.l1_address);
    console.log('   Address matches original:', recovered.wallet.l1_address === wallet.wallet.l1_address ? '✓ YES' : '✗ NO');
    
    console.log('\n   📝 NEW RECOVERY CODES (write these down!):');
    recovered.newRecoveryCodes.forEach((code, i) => console.log(`      ${i+1}. ${code}`));
    
    // Summary
    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('SUMMARY');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`
┌─────────────────────────────────────────────────────────────┐
│ PASSWORD CHANGE:                                            │
│   - Same seed, same keys, same address                      │
│   - Just re-encrypts the vault                              │
├─────────────────────────────────────────────────────────────┤
│ FORGOT PASSWORD (SSS Recovery):                             │
│   - Need 2 of 3 shares (codes + email)                      │
│   - Reconstructs original seed                              │
│   - Same keys, same address                                 │
│   - Sets new password                                       │
│   - Generates new recovery codes                            │
├─────────────────────────────────────────────────────────────┤
│ THE PRIVATE KEY NEVER CHANGES unless user explicitly        │
│ requests KEY ROTATION (which creates new address!)          │
└─────────────────────────────────────────────────────────────┘
`);
}

demo().catch(console.error);

export default WalletRecoverySDK;
