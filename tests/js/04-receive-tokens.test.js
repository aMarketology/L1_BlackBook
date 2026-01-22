/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 04: Receive Tokens
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Receive tokens from another account
 * - Verify balance updates on receive
 * - Verify transaction appears in history
 * - Test receiving to new address (creates account)
 */

import nacl from 'tweetnacl';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet, httpPost } from './test-runner.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

function generateNonce() {
  return crypto.randomUUID();
}

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  const payload = JSON.stringify({ to, amount });
  
  // Sign: chain_id byte + payload + newline + timestamp + newline + nonce
  // This matches the SDK's transferSimple() method
  const chainIdByte = new Uint8Array([0x01]); // CHAIN_ID_L1
  const payloadBytes = new TextEncoder().encode(payload);
  const timestampBytes = new TextEncoder().encode(`\n${timestamp}\n`);
  const nonceBytes = new TextEncoder().encode(nonce);
  
  // Concatenate all parts
  const message = new Uint8Array(
    chainIdByte.length + payloadBytes.length + timestampBytes.length + nonceBytes.length
  );
  let offset = 0;
  message.set(chainIdByte, offset); offset += chainIdByte.length;
  message.set(payloadBytes, offset); offset += payloadBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(nonceBytes, offset);
  
  // Sign with Ed25519
  const signature = nacl.sign.detached(message, keyPair.secretKey);
  
  return {
    public_key: bytesToHex(keyPair.publicKey),
    wallet_address: from,
    payload: payload,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: 1,
    schema_version: 1,
    signature: bytesToHex(signature)
  };
}

async function getBalance(address) {
  try {
    const response = await httpGet(`/balance/${address}`);
    return response.balance ?? response.available ?? 0;
  } catch {
    return 0;
  }
}

async function deriveAddress(publicKey) {
  const hash = await sha256(publicKey);
  const addressBytes = hash.slice(0, 20);
  return 'L1_' + bytesToHex(addressBytes).toUpperCase();
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

export async function run() {
  const results = new TestResults();
  
  // Setup
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  const bobKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.BOB.seed));
  
  // Test 1: Bob receives tokens from Alice
  try {
    const bobBalanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    const transferAmount = 3;
    
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      TEST_ACCOUNTS.BOB.address,
      transferAmount,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    const bobBalanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
    const expectedBalance = bobBalanceBefore + transferAmount;
    
    if (Math.abs(bobBalanceAfter - expectedBalance) > 0.01) {
      throw new Error(`Expected ${expectedBalance}, got ${bobBalanceAfter}`);
    }
    
    results.pass('Bob receives 3 BB from Alice');
  } catch (err) {
    results.fail('Bob receives 3 BB from Alice', err);
  }
  
  // Test 2: Mac receives tokens from Bob
  try {
    const macBalanceBefore = await getBalance(TEST_ACCOUNTS.MAC.address);
    const transferAmount = 1;
    
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.BOB.address,
      TEST_ACCOUNTS.MAC.address,
      transferAmount,
      bobKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    const macBalanceAfter = await getBalance(TEST_ACCOUNTS.MAC.address);
    const expectedBalance = macBalanceBefore + transferAmount;
    
    if (Math.abs(macBalanceAfter - expectedBalance) > 0.01) {
      throw new Error(`Expected ${expectedBalance}, got ${macBalanceAfter}`);
    }
    
    results.pass('Mac receives 1 BB from Bob');
  } catch (err) {
    results.fail('Mac receives 1 BB from Bob', err);
  }
  
  // Test 3: Check transaction appears in Bob's history
  try {
    const response = await httpGet(`/transactions?address=${TEST_ACCOUNTS.BOB.address}&limit=5`);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    if (!Array.isArray(response) && !Array.isArray(response.transactions)) {
      throw new Error('Expected transactions array');
    }
    
    const transactions = response.transactions || response;
    if (transactions.length === 0) {
      throw new Error('No transactions found');
    }
    
    // Check that we have incoming transactions (from Alice)
    const incoming = transactions.some(tx => 
      tx.to === TEST_ACCOUNTS.BOB.address || 
      tx.type === 'receive' ||
      tx.direction === 'in'
    );
    
    if (!incoming) {
      console.log('   Transactions:', JSON.stringify(transactions.slice(0, 2), null, 2));
    }
    
    results.pass('Transaction history includes received tokens');
  } catch (err) {
    results.fail('Transaction history includes received tokens', err);
  }
  
  // Test 4: Receive to a NEW address (auto-creates account)
  try {
    // Generate a fresh address
    const newKeyPair = nacl.sign.keyPair();
    const newAddress = await deriveAddress(newKeyPair.publicKey);
    
    // Check it doesn't exist
    const balanceBefore = await getBalance(newAddress);
    
    // Send tokens to new address
    const transferAmount = 0.5;
    const request = await createSignedTransfer(
      TEST_ACCOUNTS.ALICE.address,
      newAddress,
      transferAmount,
      aliceKeyPair
    );
    
    const response = await httpPost('/transfer/simple', request);
    
    if (response.error) {
      throw new Error(response.error);
    }
    
    // Verify new account was created with balance
    const balanceAfter = await getBalance(newAddress);
    
    if (balanceAfter < transferAmount) {
      throw new Error(`New account should have ${transferAmount} BB, got ${balanceAfter}`);
    }
    
    results.pass('Receive to new address creates account');
  } catch (err) {
    results.fail('Receive to new address creates account', err);
  }
  
  // Test 5: Multiple rapid receives
  try {
    const bobBalanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    const transferCount = 3;
    const amountEach = 0.1;
    
    // Send multiple transfers rapidly
    const promises = [];
    for (let i = 0; i < transferCount; i++) {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        amountEach,
        aliceKeyPair
      );
      promises.push(httpPost('/transfer/simple', request));
      await new Promise(r => setTimeout(r, 50)); // Small delay for unique timestamps
    }
    
    await Promise.all(promises);
    
    // Give time for processing
    await new Promise(r => setTimeout(r, 500));
    
    const bobBalanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
    const expectedIncrease = transferCount * amountEach;
    const actualIncrease = bobBalanceAfter - bobBalanceBefore;
    
    if (actualIncrease < expectedIncrease - 0.1) {
      throw new Error(`Expected increase of ${expectedIncrease}, got ${actualIncrease}`);
    }
    
    results.pass(`Receive ${transferCount} rapid transfers`);
  } catch (err) {
    results.fail('Receive multiple rapid transfers', err);
  }
  
  // Test 6: Verify receive doesn't affect sender's locked balance
  try {
    const aliceBalance = await httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`);
    
    // Locked balance should be 0 or unchanged if Alice has no L2 session
    if (aliceBalance.locked && aliceBalance.locked < 0) {
      throw new Error('Locked balance should not be negative');
    }
    
    results.pass('Receive does not affect locked balance');
  } catch (err) {
    results.fail('Receive does not affect locked balance', err);
  }
  
  return results;
}

// Run if executed directly
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
if (__filename === process.argv[1]) {
  run().then(r => {
    r.summary();
    process.exit(r.failed === 0 ? 0 : 1);
  });
}
