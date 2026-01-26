/**
 * Verify Mac's address derivation matches server
 */

import crypto from 'crypto';
import fs from 'fs';

const macWallet = JSON.parse(fs.readFileSync('mac-wallet-fresh.json', 'utf-8'));

console.log('\n🔍 Verifying Address Derivation\n');
console.log('Public Key:', macWallet.public_key);

// Our derivation
const publicKeyBytes = Buffer.from(macWallet.public_key, 'hex');
const hash = crypto.createHash('sha256').update(publicKeyBytes).digest();
const ourAddress = 'L1_' + hash.slice(0, 20).toString('hex').toUpperCase();

console.log('Our Address:    ', ourAddress);
console.log('Wallet Address: ', macWallet.l1_address);
console.log('Match:', ourAddress === macWallet.l1_address ? '✅' : '❌');

// Check what the server would derive
console.log('\n📡 Checking what server derives...');
const response = await fetch('http://localhost:8080/auth/test-accounts');
const accounts = await response.json();

console.log('\nTest Accounts:');
accounts.accounts.forEach(acc => {
    console.log(`  ${acc.name}: ${acc.address}`);
});

console.log(`\n💡 Our Mac address: ${macWallet.l1_address}`);
console.log(`   This is ${ourAddress === macWallet.l1_address ? '' : 'NOT '}correctly derived\n`);
