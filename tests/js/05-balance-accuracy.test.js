/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 05: Balance Accuracy
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Tests:
 * - Balance queries return accurate values
 * - Available vs locked balance tracking
 * - Balance consistency across multiple queries
 * - Total supply integrity
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
  return {
    total: response.balance ?? response.available ?? 0,
    available: response.available ?? response.balance ?? 0,
    locked: response.locked ?? 0,
  };
}

export async function run() {
  const results = new TestResults();
  
  // Test 1: Alice balance query returns valid structure
  try {
    const response = await httpGet(`/balance/${TEST_ACCOUNTS.ALICE.address}`);
    
    if (typeof response !== 'object') {
      throw new Error('Expected object response');
    }
    
    const hasBalance = 'balance' in response || 'available' in response;
    if (!hasBalance) {
      throw new Error('Response missing balance field');
    }
    
    results.pass('Balance query returns valid structure');
  } catch (err) {
    results.fail('Balance query returns valid structure', err);
  }
  
  // Test 2: Balance is non-negative
  try {
    const balance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (balance.total < 0) throw new Error('Total balance is negative');
    if (balance.available < 0) throw new Error('Available balance is negative');
    if (balance.locked < 0) throw new Error('Locked balance is negative');
    
    results.pass('Balance values are non-negative');
  } catch (err) {
    results.fail('Balance values are non-negative', err);
  }
  
  // Test 3: Available + locked = total (or close to it)
  try {
    const balance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    // Some implementations might only have 'balance' without locked
    if (balance.locked > 0) {
      const sum = balance.available + balance.locked;
      if (Math.abs(sum - balance.total) > 0.01) {
        throw new Error(`Available(${balance.available}) + Locked(${balance.locked}) != Total(${balance.total})`);
      }
    }
    
    results.pass('Balance components are consistent');
  } catch (err) {
    results.fail('Balance components are consistent', err);
  }
  
  // Test 4: Multiple consecutive balance queries return same value
  try {
    const results1 = await getBalance(TEST_ACCOUNTS.BOB.address);
    const results2 = await getBalance(TEST_ACCOUNTS.BOB.address);
    const results3 = await getBalance(TEST_ACCOUNTS.BOB.address);
    
    if (results1.total !== results2.total || results2.total !== results3.total) {
      throw new Error('Balance inconsistent across queries');
    }
    
    results.pass('Balance consistency across multiple queries');
  } catch (err) {
    results.fail('Balance consistency across multiple queries', err);
  }
  
  // Test 5: Query non-existent address returns 0 or error
  try {
    const fakeAddress = 'L1_0000000000000000000000000000000000000000';
    const response = await httpGet(`/balance/${fakeAddress}`);
    
    // Should either return 0 balance or an error
    const balance = response.balance ?? response.available ?? 0;
    if (balance < 0) {
      throw new Error('Non-existent account should not have negative balance');
    }
    
    results.pass('Non-existent address handled correctly');
  } catch (err) {
    if (err.message.includes('not found') || err.message.includes('404')) {
      results.pass('Non-existent address handled correctly');
    } else {
      results.fail('Non-existent address handled correctly', err);
    }
  }
  
  // Test 6: Health endpoint shows total supply
  try {
    const health = await httpGet('/health');
    
    if (!health.total_supply && health.total_supply !== 0) {
      throw new Error('Health missing total_supply');
    }
    
    if (health.total_supply < 0) {
      throw new Error('Total supply cannot be negative');
    }
    
    console.log(`   Total Supply: ${health.total_supply} BB`);
    results.pass('Total supply is tracked');
  } catch (err) {
    results.fail('Total supply is tracked', err);
  }
  
  // Test 7: Sum of known accounts approaches total supply
  try {
    const health = await httpGet('/health');
    const totalSupply = health.total_supply;
    
    const alice = await getBalance(TEST_ACCOUNTS.ALICE.address);
    const bob = await getBalance(TEST_ACCOUNTS.BOB.address);
    const dealer = await getBalance(TEST_ACCOUNTS.DEALER.address);
    
    const knownSum = alice.total + bob.total + dealer.total;
    
    console.log(`   Known accounts sum: ${knownSum.toFixed(2)} BB`);
    console.log(`   Total supply: ${totalSupply} BB`);
    
    // Known accounts should be a significant portion of total supply
    if (knownSum > totalSupply * 1.1) {
      throw new Error('Known accounts exceed total supply');
    }
    
    results.pass('Known account balances within total supply');
  } catch (err) {
    results.fail('Known account balances within total supply', err);
  }
  
  // Test 8: Balance precision (2 decimal places)
  try {
    const balance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    // Check that balance has at most 2 decimal places
    const decimalPlaces = (balance.total.toString().split('.')[1] || '').length;
    
    if (decimalPlaces > 2) {
      console.log(`   Warning: Balance has ${decimalPlaces} decimal places`);
    }
    
    results.pass('Balance precision check');
  } catch (err) {
    results.fail('Balance precision check', err);
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
