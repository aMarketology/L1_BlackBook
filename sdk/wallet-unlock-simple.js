/**
 * WALLET UNLOCK - Simple Explanation
 * 
 * This shows exactly what's needed to unlock Mac's wallet and sign a transaction.
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';

// ═══════════════════════════════════════════════════════════════
// WHAT'S STORED IN SUPABASE (safe to store publicly)
// ═══════════════════════════════════════════════════════════════
const STORED_IN_DATABASE = {
    l1_address: 'L1_94B3C863E068096596CE80F04C2233B72AE11790',
    public_key: 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752',
    vault_salt: '579a5c28a02f8c3ecc2801545a216cec',
    vault_blob: 'U2FsdGVkX19443Y8LJ1PaUV6/aG4Ctod88tWo7AVDftZlcgWurkSGAhVEAScVQ91+Ew9iP0d588HfIUYlXQPGEmIMDhjj3M6cDPbDtnTZFh848l0Z71CjV0CpB41Avad'
};

// ═══════════════════════════════════════════════════════════════
// WHAT USER PROVIDES (only they know this)
// ═══════════════════════════════════════════════════════════════
const PASSWORD = 'MacSecurePassword2026!';

// ═══════════════════════════════════════════════════════════════
// UNLOCK WALLET - 3 Steps
// ═══════════════════════════════════════════════════════════════

console.log('UNLOCKING MAC\'S WALLET\n');

// STEP 1: Derive encryption key from password + salt
console.log('STEP 1: password + salt → encryption_key');
console.log('        PBKDF2(password, salt, 100000 iterations)');
const encryptionKey = CryptoJS.PBKDF2(PASSWORD, STORED_IN_DATABASE.vault_salt, {
    keySize: 256 / 32,
    iterations: 100000
});
console.log('        ✓ encryption_key derived\n');

// STEP 2: Decrypt vault to get seed
console.log('STEP 2: encryption_key + vault_blob → seed');
console.log('        AES.decrypt(vault_blob, encryption_key)');
const decrypted = CryptoJS.AES.decrypt(STORED_IN_DATABASE.vault_blob, encryptionKey.toString());
const seed = decrypted.toString(CryptoJS.enc.Utf8);
console.log('        ✓ seed recovered (32 bytes, never shown)\n');

// STEP 3: Derive keypair from seed
console.log('STEP 3: seed → keypair');
console.log('        nacl.sign.keyPair.fromSeed(seed)');
const keypair = nacl.sign.keyPair.fromSeed(Buffer.from(seed, 'hex'));
console.log('        ✓ keypair.publicKey (can share)');
console.log('        ✓ keypair.secretKey (NEVER share)\n');

// VERIFY: Public key matches what's stored
const derivedPubKey = Buffer.from(keypair.publicKey).toString('hex');
console.log('VERIFY: derived public_key === stored public_key?');
console.log('        ' + (derivedPubKey === STORED_IN_DATABASE.public_key ? '✓ YES - wallet unlocked!' : '✗ NO - wrong password'));

// ═══════════════════════════════════════════════════════════════
// NOW YOU CAN SIGN
// ═══════════════════════════════════════════════════════════════
console.log('\n─────────────────────────────────────────────────────────────');
console.log('SIGNING A TRANSACTION\n');

const message = 'Send 1 BB to Bob';
const messageBytes = new TextEncoder().encode(message);
const signature = nacl.sign.detached(messageBytes, keypair.secretKey);

console.log('message:   "' + message + '"');
console.log('signature: ' + Buffer.from(signature).toString('hex').substring(0, 32) + '...');
console.log('\nSend to L1: { message, signature, public_key }');
console.log('L1 verifies signature using public_key');

// ═══════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════
console.log('\n═══════════════════════════════════════════════════════════════');
console.log('SUMMARY');
console.log('═══════════════════════════════════════════════════════════════');
console.log('');
console.log('Stored in DB:  salt, encrypted_blob, public_key, address');
console.log('User provides: password');
console.log('');
console.log('Unlock flow:');
console.log('  password + salt → encryption_key (PBKDF2)');
console.log('  encryption_key + blob → seed (AES decrypt)');
console.log('  seed → keypair (Ed25519)');
console.log('');
console.log('Private key exists ONLY in memory during signing.');
console.log('');
