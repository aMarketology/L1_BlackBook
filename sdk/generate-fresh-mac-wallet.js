/**
 * Generate Fresh Mac Wallet
 * 
 * Creates a new Ed25519 keypair for Mac and saves credentials
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';
import fs from 'fs';

console.log('\n🔑 Generating Fresh Mac Wallet...\n');

// Generate new Ed25519 keypair
const keypair = nacl.sign.keyPair();

// Derive L1 address from public key
const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
const addressHash = crypto.createHash('sha256').update(keypair.publicKey).digest();
const l1Address = 'L1_' + addressHash.slice(0, 20).toString('hex').toUpperCase();
const l2Address = 'L2_' + addressHash.slice(0, 20).toString('hex').toUpperCase();

// Private key (first 32 bytes of secretKey)
const privateKeyHex = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');

const macWallet = {
    username: 'mac_blackbook',
    email: 'mac@blackbook.io',
    l1_address: l1Address,
    l2_address: l2Address,
    public_key: publicKeyHex,
    private_key: privateKeyHex,  // ⚠️ ONLY FOR TESTING - Never store in production
    created_at: new Date().toISOString(),
    note: 'Fresh wallet for testing - private key included for development only'
};

// Save to file
fs.writeFileSync(
    'mac-wallet-fresh.json',
    JSON.stringify(macWallet, null, 2)
);

console.log('✅ Fresh Mac Wallet Generated!\n');
console.log('═'.repeat(70));
console.log('📋 WALLET DETAILS');
console.log('═'.repeat(70));
console.log(`Username:     ${macWallet.username}`);
console.log(`Email:        ${macWallet.email}`);
console.log(`L1 Address:   ${macWallet.l1_address}`);
console.log(`L2 Address:   ${macWallet.l2_address}`);
console.log(`Public Key:   ${macWallet.public_key}`);
console.log(`Private Key:  ${macWallet.private_key}`);
console.log(`\n💾 Saved to: mac-wallet-fresh.json`);
console.log('═'.repeat(70));
console.log('\n⚠️  IMPORTANT: Private key is included for TESTING ONLY');
console.log('   In production, private keys are encrypted in vaults\n');

// Also create a version without private key (for "database" storage)
const macWalletPublic = {
    username: macWallet.username,
    email: macWallet.email,
    l1_address: macWallet.l1_address,
    l2_address: macWallet.l2_address,
    public_key: macWallet.public_key,
    created_at: macWallet.created_at
};

fs.writeFileSync(
    'mac-wallet-fresh-public.json',
    JSON.stringify(macWalletPublic, null, 2)
);

console.log('✅ Public version saved to: mac-wallet-fresh-public.json\n');
