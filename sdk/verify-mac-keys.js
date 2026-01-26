/**
 * Verify Mac's key pair is correct
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

// Mac's keys from wallet
const MAC_PRIVATE_KEY = 'dca84e83c94b855a56b0cd4b7154b579f8ebc6aaf9c9f8d9ba7b293749c5ba56';
const MAC_PUBLIC_KEY_EXPECTED = 'ec6941c71740e192bbf5933d5f9cc18ea161329ce864da900d8de73d45c28752';
const MAC_ADDRESS_EXPECTED = 'L1_94B3C863E068096596CE80F04C2233B72AE11790';

console.log('\n🔍 Verifying Mac Wallet Keys');
console.log('='.repeat(70));

// Derive public key from private key using tweetnacl
const privateKeyBytes = Buffer.from(MAC_PRIVATE_KEY, 'hex');
const keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');

console.log(`\n📌 Private Key: ${MAC_PRIVATE_KEY}`);
console.log(`📌 Derived Public Key:  ${publicKeyHex}`);
console.log(`📌 Expected Public Key: ${MAC_PUBLIC_KEY_EXPECTED}`);

if (publicKeyHex === MAC_PUBLIC_KEY_EXPECTED) {
    console.log(`✅ Public key matches!`);
} else {
    console.log(`❌ Public key MISMATCH!`);
    console.log(`   This means the private key doesn't match the expected public key`);
}

// Derive L1 address from public key (SHA-256 hash, first 20 bytes)
const addressHash = crypto.createHash('sha256').update(Buffer.from(keyPair.publicKey)).digest();
const address = 'L1_' + addressHash.slice(0, 20).toString('hex').toUpperCase();

console.log(`\n📌 Derived Address:  ${address}`);
console.log(`📌 Expected Address: ${MAC_ADDRESS_EXPECTED}`);

if (address === MAC_ADDRESS_EXPECTED) {
    console.log(`✅ Address matches!`);
} else {
    console.log(`❌ Address MISMATCH!`);
}

// Test signing
console.log(`\n🔐 Testing Signature:`);
const testMessage = Buffer.from('test message');
const signedMessage = nacl.sign(testMessage, keyPair.secretKey);
const signature = signedMessage.slice(0, 64); // First 64 bytes is the signature
console.log(`   Signature: ${Buffer.from(signature).toString('hex').substring(0, 32)}...`);

// Verify
const isValid = nacl.sign.detached.verify(testMessage, signature, keyPair.publicKey);
console.log(`   Verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);

console.log('\n' + '='.repeat(70) + '\n');
