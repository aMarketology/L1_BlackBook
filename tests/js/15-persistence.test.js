/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 15: Persistence
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Balances persist across requests
 * - Transaction history persists
 * - Account creation persists
 * - Total supply remains consistent
 */

import nacl from 'tweetnacl';
import { TestResults, TEST_ACCOUNTS, CONFIG, httpGet, httpPost } from './test-runner.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(data) {
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buffer);
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
}

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Date.now();
  const payload = { amount, chain_id: 1, from, timestamp, to };
  const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadBytes = new TextEncoder().encode(canonicalJson);
  const payloadHash = await sha256(payloadBytes);
  const signature = nacl.sign.detached(payloadHash, keyPair.secretKey);
  
  return { from, to, amount, timestamp, public_key: bytesToHex(keyPair.publicKey), signature: bytesToHex(signature) };
}

export async function run() {
  const results = new TestResults();
  
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  
  // Test 1: Balance persists across multiple reads
  try {
    const balance1 = await getBalance(TEST_ACCOUNTS.ALICE.address);
    await new Promise(r => setTimeout(r, 500)); // Wait
    const balance2 = await getBalance(TEST_ACCOUNTS.ALICE.address);
    await new Promise(r => setTimeout(r, 500)); // Wait
    const balance3 = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (balance1 !== balance2 || balance2 !== balance3) {
      throw new Error('Balance changed without any transaction');
    }
    
    console.log(`   Balance consistent: ${balance1} BB`);
    results.pass('Balance persists across reads');
  } catch (err) {
    results.fail('Balance persists across reads', err);
  }
  
  // Test 2: Transfer persists (sender)
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const transferAmount = 0.1;
    
    if (balanceBefore < transferAmount) {
      results.skip('Transfer persists (sender)', 'Insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        transferAmount,
        aliceKeyPair
      );
      
      await httpPost('/transfer/simple', request);
      await new Promise(r => setTimeout(r, 1000)); // Wait for persistence
      
      const balanceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
      const expectedBalance = balanceBefore - transferAmount;
      
      if (Math.abs(balanceAfter - expectedBalance) > 0.01) {
        throw new Error(`Balance not persisted: expected ${expectedBalance}, got ${balanceAfter}`);
      }
      
      results.pass('Transfer persists (sender balance)');
    }
  } catch (err) {
    results.fail('Transfer persists (sender)', err);
  }
  
  // Test 3: Transfer persists (receiver)
  try {
    const balanceBefore = await getBalance(TEST_ACCOUNTS.BOB.address);
    const transferAmount = 0.1;
    
    const aliceBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    if (aliceBalance < transferAmount) {
      results.skip('Transfer persists (receiver)', 'Alice insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        transferAmount,
        aliceKeyPair
      );
      
      await httpPost('/transfer/simple', request);
      await new Promise(r => setTimeout(r, 1000)); // Wait
      
      const balanceAfter = await getBalance(TEST_ACCOUNTS.BOB.address);
      const expectedBalance = balanceBefore + transferAmount;
      
      if (Math.abs(balanceAfter - expectedBalance) > 0.01) {
        throw new Error(`Balance not persisted: expected ${expectedBalance}, got ${balanceAfter}`);
      }
      
      results.pass('Transfer persists (receiver balance)');
    }
  } catch (err) {
    results.fail('Transfer persists (receiver)', err);
  }
  
  // Test 4: Transaction appears in history
  try {
    const response = await httpGet(`/transactions?address=${TEST_ACCOUNTS.ALICE.address}&limit=5`);
    const transactions = response.transactions || response;
    
    if (!Array.isArray(transactions)) {
      throw new Error('No transaction history returned');
    }
    
    if (transactions.length === 0) {
      results.skip('Transaction in history', 'No transactions found');
    } else {
      // Check recent transaction exists
      const recentTx = transactions[0];
      if (!recentTx) {
        throw new Error('Transaction not persisted to history');
      }
      
      console.log(`   Found ${transactions.length} transactions in history`);
      results.pass('Transaction persists in history');
    }
  } catch (err) {
    results.fail('Transaction persists in history', err);
  }
  
  // Test 5: Total supply remains consistent
  try {
    const health1 = await httpGet('/health');
    await new Promise(r => setTimeout(r, 500));
    const health2 = await httpGet('/health');
    await new Promise(r => setTimeout(r, 500));
    const health3 = await httpGet('/health');
    
    const supply1 = health1.total_supply;
    const supply2 = health2.total_supply;
    const supply3 = health3.total_supply;
    
    if (supply1 !== supply2 || supply2 !== supply3) {
      throw new Error('Total supply inconsistent');
    }
    
    console.log(`   Total supply consistent: ${supply1} BB`);
    results.pass('Total supply consistent');
  } catch (err) {
    results.fail('Total supply consistent', err);
  }
  
  // Test 6: New account persists
  try {
    // Generate a new address
    const newKeyPair = nacl.sign.keyPair();
    const pubKeyHash = await sha256(newKeyPair.publicKey);
    const addressBytes = pubKeyHash.slice(0, 20);
    const newAddress = 'L1_' + bytesToHex(addressBytes).toUpperCase();
    
    // Send tokens to new address
    const aliceBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    if (aliceBalance < 0.5) {
      results.skip('New account persists', 'Insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        newAddress,
        0.5,
        aliceKeyPair
      );
      
      await httpPost('/transfer/simple', request);
      await new Promise(r => setTimeout(r, 1000));
      
      // Check new account exists
      const newBalance = await getBalance(newAddress);
      
      if (newBalance < 0.5) {
        throw new Error('New account balance not persisted');
      }
      
      console.log(`   New account ${newAddress.substring(0, 15)}... has ${newBalance} BB`);
      results.pass('New account persists');
    }
  } catch (err) {
    results.fail('New account persists', err);
  }
  
  // Test 7: Account count increases
  try {
    const health = await httpGet('/health');
    const accountCount = health.total_accounts || health.accounts;
    
    if (accountCount === undefined) {
      results.skip('Account count tracking', 'Not tracked');
    } else if (accountCount < 3) {
      throw new Error(`Account count too low: ${accountCount}`);
    } else {
      console.log(`   Account count: ${accountCount}`);
      results.pass('Account count persists');
    }
  } catch (err) {
    results.fail('Account count tracking', err);
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
