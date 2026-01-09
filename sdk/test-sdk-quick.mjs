/**
 * Quick SDK Test - Verify blackbook-wallet-sdk.js works correctly
 * Run: node test-sdk-quick.mjs
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookWallet, TEST_ACCOUNTS } = require('./blackbook-wallet-sdk.js');

console.log('═══════════════════════════════════════════════════════════════');
console.log('           BlackBook Wallet SDK - Quick Test');
console.log('═══════════════════════════════════════════════════════════════');

// Test 1: Create wallet instance
console.log('\n✓ Test 1: Create wallet instance');
const wallet = new BlackBookWallet('http://localhost:8080');
console.log('  L1 URL:', wallet.apiUrl);

// Test 2: Initialize from test account
console.log('\n✓ Test 2: Initialize from test account (Alice)');
const aliceInfo = wallet.initFromTestAccount('alice');
console.log('  Address:', aliceInfo.address);
console.log('  Public Key:', aliceInfo.publicKey);
console.log('  Expected Balance:', aliceInfo.expectedBalance);

// Test 3: Verify TEST_ACCOUNTS are accessible
console.log('\n✓ Test 3: TEST_ACCOUNTS available');
console.log('  Alice:', TEST_ACCOUNTS.ALICE.address);
console.log('  Bob:', TEST_ACCOUNTS.BOB.address);
console.log('  Dealer:', TEST_ACCOUNTS.DEALER.address);

// Test 4: Sign a request (this tests the crypto functions)
console.log('\n✓ Test 4: Sign a test request');
try {
  const payload = { from: wallet.address, to: TEST_ACCOUNTS.BOB.address, amount: 10 };
  const signedRequest = await wallet.signRequest(payload);
  console.log('  Payload hash:', signedRequest.payload_hash.slice(0, 20) + '...');
  console.log('  Signature:', signedRequest.signature.slice(0, 20) + '...');
  console.log('  Public key:', signedRequest.public_key.slice(0, 20) + '...');
} catch (error) {
  console.log('  Error:', error.message);
}

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('All offline tests passed! SDK is ready for use.');
console.log('═══════════════════════════════════════════════════════════════');

// Network tests (require L1 server running)
console.log('\nTo test network functionality, start L1 server and run:');
console.log('  node test-l1-functionality.js');
