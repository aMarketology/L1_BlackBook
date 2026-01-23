/**
 * Shamir's Secret Sharing (SSS) for BlackBook Wallet Recovery
 * 
 * Problem: Password encrypts vault. If user changes password or forgets it,
 *          they lose access to their wallet forever.
 * 
 * Solution: Split the seed into shares using SSS
 *           - 3 shares total, need 2 to recover
 *           - Share 1: Encrypted with password (stored in Supabase)
 *           - Share 2: Recovery codes (user writes down)
 *           - Share 3: Email recovery (sent to user's email, encrypted)
 * 
 * Password Change Flow:
 *   1. User provides old password
 *   2. Decrypt vault with old password → get seed
 *   3. Re-encrypt seed with new password → new vault
 *   4. Update Supabase with new vault
 * 
 * Forgot Password Flow:
 *   1. User provides 2 of 3 shares (recovery codes + email link)
 *   2. Reconstruct seed from shares
 *   3. User sets new password
 *   4. Re-encrypt seed with new password → new vault
 */

import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════════════════════
// SHAMIR'S SECRET SHARING IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

const PRIME = 2n ** 256n - 189n;  // Large prime for finite field

/**
 * Generate random BigInt in range [0, max)
 */
function randomBigInt(max) {
    const bytes = crypto.randomBytes(32);
    const num = BigInt('0x' + bytes.toString('hex'));
    return num % max;
}

/**
 * Modular multiplicative inverse using extended Euclidean algorithm
 */
function modInverse(a, m) {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    
    while (r !== 0n) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
    }
    
    return ((old_s % m) + m) % m;
}

/**
 * Evaluate polynomial at x
 */
function evaluatePolynomial(coefficients, x, prime) {
    let result = 0n;
    let power = 1n;
    
    for (const coef of coefficients) {
        result = (result + coef * power) % prime;
        power = (power * x) % prime;
    }
    
    return result;
}

/**
 * Split secret into n shares, requiring k to reconstruct
 * @param {Buffer} secret - 32-byte seed
 * @param {number} n - Total shares
 * @param {number} k - Threshold to reconstruct
 * @returns {Array} Array of {x, y} share objects
 */
function splitSecret(secret, n, k) {
    // Convert secret to BigInt
    const secretBigInt = BigInt('0x' + secret.toString('hex'));
    
    // Generate random coefficients for polynomial
    // f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    const coefficients = [secretBigInt];
    for (let i = 1; i < k; i++) {
        coefficients.push(randomBigInt(PRIME));
    }
    
    // Generate shares by evaluating polynomial at x = 1, 2, ..., n
    const shares = [];
    for (let x = 1; x <= n; x++) {
        const y = evaluatePolynomial(coefficients, BigInt(x), PRIME);
        shares.push({
            x: x,
            y: y.toString(16).padStart(64, '0')
        });
    }
    
    return shares;
}

/**
 * Reconstruct secret from k shares using Lagrange interpolation
 * @param {Array} shares - Array of {x, y} share objects
 * @returns {Buffer} Reconstructed 32-byte secret
 */
function reconstructSecret(shares) {
    let secret = 0n;
    
    for (let i = 0; i < shares.length; i++) {
        const xi = BigInt(shares[i].x);
        const yi = BigInt('0x' + shares[i].y);
        
        // Calculate Lagrange basis polynomial
        let numerator = 1n;
        let denominator = 1n;
        
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                const xj = BigInt(shares[j].x);
                numerator = (numerator * (0n - xj)) % PRIME;
                denominator = (denominator * (xi - xj)) % PRIME;
            }
        }
        
        // Ensure positive modulo
        numerator = ((numerator % PRIME) + PRIME) % PRIME;
        denominator = ((denominator % PRIME) + PRIME) % PRIME;
        
        // Calculate Lagrange coefficient
        const lagrange = (numerator * modInverse(denominator, PRIME)) % PRIME;
        
        // Add contribution
        secret = (secret + yi * lagrange) % PRIME;
    }
    
    secret = ((secret % PRIME) + PRIME) % PRIME;
    
    // Convert back to buffer
    const hex = secret.toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

// ═══════════════════════════════════════════════════════════════════════════
// WALLET RECOVERY SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create wallet with SSS recovery
 */
function createWalletWithRecovery(seed, password) {
    console.log('Creating wallet with SSS recovery...\n');
    
    // Split seed into 3 shares (need 2 to recover)
    const shares = splitSecret(seed, 3, 2);
    
    console.log('Generated 3 shares (need any 2 to recover):');
    console.log('  Share 1: For password-encrypted vault');
    console.log('  Share 2: Recovery codes (user writes down)');
    console.log('  Share 3: Email recovery backup\n');
    
    return {
        // Share 1: Encrypted with user's password (stored in Supabase)
        passwordShare: shares[0],
        
        // Share 2: Recovery codes (user writes down, 4 groups of 8 chars)
        recoveryCodes: formatRecoveryCodes(shares[1]),
        
        // Share 3: Email recovery (sent encrypted to user's email)
        emailShare: shares[2]
    };
}

/**
 * Format share as recovery codes (human-readable)
 */
function formatRecoveryCodes(share) {
    const combined = share.x.toString().padStart(2, '0') + share.y;
    // Split into 8-character groups
    const codes = [];
    for (let i = 0; i < combined.length; i += 8) {
        codes.push(combined.slice(i, i + 8).toUpperCase());
    }
    return codes;
}

/**
 * Parse recovery codes back to share
 */
function parseRecoveryCodes(codes) {
    const combined = codes.join('').toLowerCase();
    return {
        x: parseInt(combined.slice(0, 2)),
        y: combined.slice(2)
    };
}

/**
 * Change password (requires old password)
 */
function changePassword(vault, oldPassword, newPassword) {
    console.log('CHANGING PASSWORD\n');
    console.log('Step 1: Decrypt vault with old password');
    // In real implementation: decrypt vault with old password
    console.log('Step 2: Get seed from decrypted vault');
    console.log('Step 3: Re-encrypt seed with new password');
    console.log('Step 4: Update vault in Supabase');
    console.log('\n✓ Password changed successfully');
    console.log('  - Wallet still works');
    console.log('  - Same L1 address');
    console.log('  - Same public key');
}

/**
 * Recover wallet (forgot password)
 */
function recoverWallet(share1, share2, newPassword) {
    console.log('RECOVERING WALLET\n');
    console.log('Step 1: Combine 2 shares using SSS');
    
    const seed = reconstructSecret([share1, share2]);
    
    console.log('Step 2: Seed reconstructed');
    console.log('Step 3: Encrypt seed with new password');
    console.log('Step 4: Save new vault to Supabase');
    console.log('\n✓ Wallet recovered with new password');
    
    return seed;
}

// ═══════════════════════════════════════════════════════════════════════════
// DEMO
// ═══════════════════════════════════════════════════════════════════════════

console.log('═══════════════════════════════════════════════════════════════');
console.log('SHAMIR\'S SECRET SHARING FOR WALLET RECOVERY');
console.log('═══════════════════════════════════════════════════════════════\n');

// Create a test seed
const testSeed = crypto.randomBytes(32);
console.log('Original seed (32 bytes): ' + testSeed.toString('hex').slice(0, 32) + '...\n');

// Create wallet with recovery
const recovery = createWalletWithRecovery(testSeed, 'UserPassword123!');

console.log('─────────────────────────────────────────────────────────────');
console.log('WHAT GETS STORED WHERE:');
console.log('─────────────────────────────────────────────────────────────\n');

console.log('📦 SUPABASE (vault table):');
console.log('   - encrypted_vault (seed encrypted with password)');
console.log('   - password_share: x=' + recovery.passwordShare.x);
console.log('   - email_share_encrypted (encrypted with email-specific key)\n');

console.log('📧 USER\'S EMAIL (one-time):');
console.log('   - Email recovery link with encrypted share\n');

console.log('📝 USER WRITES DOWN:');
console.log('   Recovery Codes:');
recovery.recoveryCodes.forEach((code, i) => {
    console.log('   ' + (i + 1) + '. ' + code);
});

console.log('\n─────────────────────────────────────────────────────────────');
console.log('RECOVERY SCENARIOS:');
console.log('─────────────────────────────────────────────────────────────\n');

console.log('SCENARIO 1: Change Password (know old password)');
console.log('  → Decrypt with old, re-encrypt with new');
console.log('  → No shares needed\n');

console.log('SCENARIO 2: Forgot Password (have recovery codes + email)');
console.log('  → Combine share from codes + share from email');
console.log('  → Reconstruct seed, encrypt with new password\n');

console.log('SCENARIO 3: Forgot Password (have recovery codes only)');
console.log('  → Need password_share from Supabase');
console.log('  → But can\'t decrypt it without password!');
console.log('  → ❌ Cannot recover with only 1 share\n');

// Test reconstruction
console.log('─────────────────────────────────────────────────────────────');
console.log('TESTING SSS RECONSTRUCTION:');
console.log('─────────────────────────────────────────────────────────────\n');

// Reconstruct from shares 1 and 2
const reconstructed = reconstructSecret([
    recovery.passwordShare,  // Share 1
    parseRecoveryCodes(recovery.recoveryCodes)  // Share 2
]);

console.log('Original:     ' + testSeed.toString('hex').slice(0, 32) + '...');
console.log('Reconstructed: ' + reconstructed.toString('hex').slice(0, 32) + '...');
console.log('Match: ' + (testSeed.toString('hex') === reconstructed.toString('hex') ? '✓ YES' : '✗ NO'));

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('SUMMARY: Password Change & Recovery');
console.log('═══════════════════════════════════════════════════════════════\n');

console.log('┌─────────────────────────────────────────────────────────────┐');
console.log('│ CHANGE PASSWORD (know old password):                        │');
console.log('│   old_password → decrypt vault → seed → new_password → save │');
console.log('├─────────────────────────────────────────────────────────────┤');
console.log('│ FORGOT PASSWORD (have 2 of 3 shares):                       │');
console.log('│   recovery_codes + email_share → SSS → seed → new_password  │');
console.log('├─────────────────────────────────────────────────────────────┤');
console.log('│ LOST EVERYTHING:                                            │');
console.log('│   ❌ Wallet is gone forever (this is by design)             │');
console.log('└─────────────────────────────────────────────────────────────┘');
