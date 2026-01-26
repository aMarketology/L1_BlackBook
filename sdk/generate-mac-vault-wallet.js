/**
 * Generate Fork Architecture V2 Wallet for Mac
 * 
 * Creates proper encrypted vault with:
 * - auth_salt & vault_salt (domain separation)
 * - AES-GCM encrypted private key
 * - Nonce for GCM mode
 * - NO private key exposure
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';
import fs from 'fs';

const PASSWORD = 'MacSecurePassword2026!';

console.log('\n🔑 Generating Fork Architecture V2 Wallet for Mac...\n');

// Step 1: Generate fresh Ed25519 keypair
const keypair = nacl.sign.keyPair();
const seedHex = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');
const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');

// Step 2: Derive L1 address
const addressHash = crypto.createHash('sha256').update(keypair.publicKey).digest();
const l1Address = 'L1_' + addressHash.slice(0, 20).toString('hex').toUpperCase();
const l2Address = 'L2_' + addressHash.slice(0, 20).toString('hex').toUpperCase();

// Step 3: Generate salts
const auth_salt = crypto.randomBytes(32).toString('hex');
const vault_salt = crypto.randomBytes(32).toString('hex');

// Step 4: Derive keys from password
// AUTH KEY: SHA256(AUTH_DOMAIN + auth_salt + password)
const AUTH_DOMAIN = 'BLACKBOOK_AUTH_V2';
const auth_key = crypto.createHash('sha256')
    .update(AUTH_DOMAIN + auth_salt + PASSWORD)
    .digest('hex');

// VAULT KEY: SHA256(VAULT_DOMAIN + vault_salt + password)  
const VAULT_DOMAIN = 'BLACKBOOK_VAULT_V2';
const vault_key = crypto.createHash('sha256')
    .update(VAULT_DOMAIN + vault_salt + PASSWORD)
    .digest();

// Step 5: Encrypt seed with AES-256-GCM
const nonce = crypto.randomBytes(12); // 96-bit nonce for GCM
const cipher = crypto.createCipheriv('aes-256-gcm', vault_key, nonce);
cipher.setAAD(Buffer.from(vault_salt, 'utf-8')); // Additional auth data

let ciphertext = cipher.update(seedHex, 'utf-8');
ciphertext = Buffer.concat([ciphertext, cipher.final()]);
const authTag = cipher.getAuthTag();
const ciphertextWithTag = Buffer.concat([ciphertext, authTag]);

// Step 6: Create wallet object
const macWallet = {
    username: 'mac_blackbook',
    email: 'mac@blackbook.io',
    l1_address: l1Address,
    l2_address: l2Address,
    public_key: publicKeyHex,
    auth_salt: auth_salt,
    auth_key: auth_key,  // Include for testing - server would store bcrypt(auth_key)
    vault_salt: vault_salt,
    vault: {
        version: 2,
        algorithm: 'AES-256-GCM',
        kdf: 'SHA-256',
        ciphertext: ciphertextWithTag.toString('base64'),
        nonce: nonce.toString('hex')
    },
    test_password: PASSWORD,
    created_at: new Date().toISOString(),
    note: 'Fork Architecture V2 - Vault encrypted, no private key stored'
};

// Save full wallet (for testing)
fs.writeFileSync(
    'mac-wallet-fresh.json',
    JSON.stringify(macWallet, null, 2)
);

// Save public version (what goes in database)
const macWalletPublic = {
    username: macWallet.username,
    email: macWallet.email,
    l1_address: macWallet.l1_address,
    l2_address: macWallet.l2_address,
    public_key: macWallet.public_key,
    auth_salt: macWallet.auth_salt,
    vault_salt: macWallet.vault_salt,
    vault_ciphertext: macWallet.vault.ciphertext,
    vault_nonce: macWallet.vault.nonce,
    vault_version: macWallet.vault.version,
    created_at: macWallet.created_at
};

fs.writeFileSync(
    'mac-wallet-fresh-public.json',
    JSON.stringify(macWalletPublic, null, 2)
);

console.log('✅ Fork Architecture V2 Wallet Generated!\n');
console.log('═'.repeat(70));
console.log('📋 WALLET DETAILS');
console.log('═'.repeat(70));
console.log(`Username:       ${macWallet.username}`);
console.log(`Email:          ${macWallet.email}`);
console.log(`L1 Address:     ${macWallet.l1_address}`);
console.log(`Public Key:     ${macWallet.public_key}`);
console.log(`Auth Salt:      ${macWallet.auth_salt.substring(0, 16)}...`);
console.log(`Vault Salt:     ${macWallet.vault_salt.substring(0, 16)}...`);
console.log(`Vault Nonce:    ${macWallet.vault.nonce}`);
console.log(`Test Password:  ${PASSWORD}`);
console.log(`\n💾 Full wallet:   mac-wallet-fresh.json`);
console.log(`💾 Public data:   mac-wallet-fresh-public.json`);
console.log('═'.repeat(70));

// Step 7: Test decryption to verify it works
console.log('\n🧪 Testing vault decryption...');
const test_vault_key = crypto.createHash('sha256')
    .update(VAULT_DOMAIN + vault_salt + PASSWORD)
    .digest();

const test_nonce = Buffer.from(macWallet.vault.nonce, 'hex');
const test_ciphertext = Buffer.from(macWallet.vault.ciphertext, 'base64');
const test_authTag = test_ciphertext.slice(-16);
const test_data = test_ciphertext.slice(0, -16);

const decipher = crypto.createDecipheriv('aes-256-gcm', test_vault_key, test_nonce);
decipher.setAAD(Buffer.from(vault_salt, 'utf-8'));
decipher.setAuthTag(test_authTag);

let decrypted = decipher.update(test_data, null, 'utf-8');
decrypted += decipher.final('utf-8');

if (decrypted === seedHex) {
    console.log('✅ Vault decryption successful!');
    console.log(`   Seed: ${decrypted.substring(0, 16)}...`);
    
    // Verify keypair derivation
    const testSeed = Buffer.from(decrypted, 'hex');
    const testKeypair = nacl.sign.keyPair.fromSeed(testSeed);
    const testPublicKey = Buffer.from(testKeypair.publicKey).toString('hex');
    
    if (testPublicKey === publicKeyHex) {
        console.log('✅ Public key derivation matches!');
    } else {
        console.log('❌ Public key mismatch!');
    }
} else {
    console.log('❌ Vault decryption failed!');
}

console.log('\n🎉 Ready for bridge testing!\n');
