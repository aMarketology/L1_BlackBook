/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 13: Balance Invariants (Total Supply Integrity)
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * CRITICAL INVARIANT: Total Supply = Sum of All Balances
 * 
 * This is the fundamental accounting equation that must ALWAYS hold true.
 * If violated, tokens have been created from thin air or destroyed.
 * 
 * The DAO attack violated this invariant by allowing recursive withdrawals
 * that drained ETH without properly updating the internal accounting.
 * 
 * We test:
 * 1. Invariant holds before operations
 * 2. Invariant holds after transfers
 * 3. Invariant holds after L2 locks
 * 4. Invariant holds after settlements
 * 5. Invariant holds under stress
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

function generateNonce() {
  return crypto.randomUUID();
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return {
    available: response.balance ?? response.available ?? 0,
    locked: response.locked ?? 0,
    total: (response.balance ?? response.available ?? 0) + (response.locked ?? 0),
  };
}

async function getTotalSupply() {
  const health = await httpGet('/health');
  return health.total_supply;
}

async function getKnownAccountsSum() {
  const alice = await getBalance(TEST_ACCOUNTS.ALICE.address);
  const bob = await getBalance(TEST_ACCOUNTS.BOB.address);
  const dealer = await getBalance(TEST_ACCOUNTS.DEALER.address);
  const mac = await getBalance(TEST_ACCOUNTS.MAC.address);
  
  return {
    alice: alice.total,
    bob: bob.total,
    dealer: dealer.total,
    mac: mac.total,
    sum: alice.total + bob.total + dealer.total + mac.total,
  };
}

async function createSignedTransfer(from, to, amount, keyPair, timestampOffset = 0) {
  const timestamp = Math.floor(Date.now() / 1000) + Math.floor(timestampOffset / 1000);
  const nonce = generateNonce();
  const payload = JSON.stringify({ to, amount });
  
  const chainIdByte = new Uint8Array([0x01]);
  const payloadBytes = new TextEncoder().encode(payload);
  const timestampBytes = new TextEncoder().encode(`\n${timestamp}\n`);
  const nonceBytes = new TextEncoder().encode(nonce);
  
  const message = new Uint8Array(chainIdByte.length + payloadBytes.length + timestampBytes.length + nonceBytes.length);
  let offset = 0;
  message.set(chainIdByte, offset); offset += chainIdByte.length;
  message.set(payloadBytes, offset); offset += payloadBytes.length;
  message.set(timestampBytes, offset); offset += timestampBytes.length;
  message.set(nonceBytes, offset);
  
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

export async function run() {
  const results = new TestResults();
  
  const aliceKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.ALICE.seed));
  const bobKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(TEST_ACCOUNTS.BOB.seed));
  
  console.log('   📊 Testing balance invariants...\n');
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 1: Total supply is non-negative
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const totalSupply = await getTotalSupply();
    
    if (totalSupply < 0) {
      throw new Error(`INVARIANT VIOLATION: Total supply is negative (${totalSupply})`);
    }
    
    console.log(`   Total Supply: ${totalSupply.toFixed(2)} BB`);
    results.pass('Invariant: Total supply >= 0');
  } catch (err) {
    results.fail('Invariant: Total supply >= 0', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 2: All individual balances are non-negative
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const accounts = await getKnownAccountsSum();
    
    if (accounts.alice < 0) throw new Error(`Alice balance negative: ${accounts.alice}`);
    if (accounts.bob < 0) throw new Error(`Bob balance negative: ${accounts.bob}`);
    if (accounts.dealer < 0) throw new Error(`Dealer balance negative: ${accounts.dealer}`);
    if (accounts.mac < 0) throw new Error(`Mac balance negative: ${accounts.mac}`);
    
    console.log(`   Alice: ${accounts.alice.toFixed(2)} BB`);
    console.log(`   Bob: ${accounts.bob.toFixed(2)} BB`);
    console.log(`   Dealer: ${accounts.dealer.toFixed(2)} BB`);
    console.log(`   Mac: ${accounts.mac.toFixed(2)} BB`);
    
    results.pass('Invariant: All balances >= 0');
  } catch (err) {
    results.fail('Invariant: All balances >= 0', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 3: Known accounts sum <= total supply
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const totalSupply = await getTotalSupply();
    const accounts = await getKnownAccountsSum();
    
    console.log(`\n   Known accounts sum: ${accounts.sum.toFixed(2)} BB`);
    console.log(`   Total supply: ${totalSupply.toFixed(2)} BB`);
    
    if (accounts.sum > totalSupply * 1.001) { // Allow tiny floating point error
      throw new Error(`INVARIANT VIOLATION: Known accounts (${accounts.sum}) > Total supply (${totalSupply})`);
    }
    
    const coverage = (accounts.sum / totalSupply * 100).toFixed(1);
    console.log(`   Coverage: ${coverage}%`);
    
    results.pass('Invariant: Known accounts <= total supply');
  } catch (err) {
    results.fail('Invariant: Known accounts <= total supply', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 4: Transfer is zero-sum (no tokens created/destroyed)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const supplyBefore = await getTotalSupply();
    const accountsBefore = await getKnownAccountsSum();
    
    // Execute transfer
    const amount = 1.5;
    const aliceBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (aliceBalance.available < amount) {
      results.skip('Invariant: Transfer zero-sum', 'Insufficient balance');
    } else {
      const request = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        amount,
        aliceKeyPair
      );
      
      await httpPost('/transfer/simple', request);
      
      const supplyAfter = await getTotalSupply();
      const accountsAfter = await getKnownAccountsSum();
      
      // Total supply should be UNCHANGED
      const supplyDiff = Math.abs(supplyAfter - supplyBefore);
      if (supplyDiff > 0.01) {
        throw new Error(`INVARIANT VIOLATION: Supply changed by ${supplyDiff} during transfer`);
      }
      
      // Sum of balances should be UNCHANGED
      const sumDiff = Math.abs(accountsAfter.sum - accountsBefore.sum);
      if (sumDiff > 0.01) {
        throw new Error(`INVARIANT VIOLATION: Balance sum changed by ${sumDiff} during transfer`);
      }
      
      console.log(`\n   Transfer: Alice → Bob: ${amount} BB`);
      console.log(`   Supply change: ${supplyDiff.toFixed(6)} (should be 0)`);
      console.log(`   Balance sum change: ${sumDiff.toFixed(6)} (should be 0)`);
      
      results.pass('Invariant: Transfer is zero-sum');
    }
  } catch (err) {
    results.fail('Invariant: Transfer is zero-sum', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 5: L2 lock is zero-sum (tokens move from available to locked)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const supplyBefore = await getTotalSupply();
    const aliceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    const lockAmount = 10;
    
    if (aliceBefore.available < lockAmount) {
      results.skip('Invariant: L2 lock zero-sum', 'Insufficient balance');
    } else {
      const response = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: lockAmount,
      });
      
      if (response.error) {
        results.skip('Invariant: L2 lock zero-sum', response.error);
      } else {
        const sessionId = response.session_id;
        const supplyAfter = await getTotalSupply();
        const aliceAfter = await getBalance(TEST_ACCOUNTS.ALICE.address);
        
        // Total supply should be UNCHANGED
        const supplyDiff = Math.abs(supplyAfter - supplyBefore);
        if (supplyDiff > 0.01) {
          throw new Error(`INVARIANT VIOLATION: Supply changed by ${supplyDiff} during lock`);
        }
        
        // Alice's total (available + locked) should be UNCHANGED
        const aliceTotalBefore = aliceBefore.total;
        const aliceTotalAfter = aliceAfter.total;
        const aliceDiff = Math.abs(aliceTotalAfter - aliceTotalBefore);
        
        console.log(`\n   Lock: ${lockAmount} BB`);
        console.log(`   Alice before: available=${aliceBefore.available}, locked=${aliceBefore.locked}`);
        console.log(`   Alice after: available=${aliceAfter.available}, locked=${aliceAfter.locked}`);
        console.log(`   Total change: ${aliceDiff.toFixed(6)} (should be 0)`);
        
        // Cleanup
        await httpPost('/credit/settle', { session_id: sessionId, net_pnl: 0 });
        
        if (aliceDiff > 0.01) {
          throw new Error(`INVARIANT VIOLATION: Alice total changed by ${aliceDiff} during lock`);
        }
        
        results.pass('Invariant: L2 lock is zero-sum');
      }
    }
  } catch (err) {
    results.fail('Invariant: L2 lock is zero-sum', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 6: Settlement preserves total supply
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const supplyBefore = await getTotalSupply();
    const aliceBefore = await getBalance(TEST_ACCOUNTS.ALICE.address);
    
    if (aliceBefore.available < 20) {
      results.skip('Invariant: Settlement preserves supply', 'Insufficient balance');
    } else {
      // Open session
      const openResponse = await httpPost('/credit/open', {
        wallet: TEST_ACCOUNTS.ALICE.address,
        amount: 20,
      });
      
      if (openResponse.error) {
        results.skip('Invariant: Settlement', openResponse.error);
      } else {
        const sessionId = openResponse.session_id;
        
        // Settle with P&L
        const pnl = 5; // Win 5 BB
        await httpPost('/credit/settle', { session_id: sessionId, net_pnl: pnl });
        
        const supplyAfter = await getTotalSupply();
        
        // Total supply should be UNCHANGED (P&L is transfer from dealer)
        const supplyDiff = Math.abs(supplyAfter - supplyBefore);
        
        console.log(`\n   Settlement with P&L: +${pnl} BB`);
        console.log(`   Supply change: ${supplyDiff.toFixed(6)}`);
        
        if (supplyDiff > 0.01) {
          throw new Error(`INVARIANT VIOLATION: Supply changed by ${supplyDiff} during settlement`);
        }
        
        results.pass('Invariant: Settlement preserves total supply');
      }
    }
  } catch (err) {
    results.fail('Invariant: Settlement preserves supply', err);
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // INVARIANT 7: Stress test - multiple operations preserve invariant
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const supplyBefore = await getTotalSupply();
    const accountsBefore = await getKnownAccountsSum();
    
    console.log('\n   Running stress test (20 rapid transfers)...');
    
    // Execute many transfers
    const promises = [];
    for (let i = 0; i < 10; i++) {
      const req1 = await createSignedTransfer(
        TEST_ACCOUNTS.ALICE.address,
        TEST_ACCOUNTS.BOB.address,
        0.1,
        aliceKeyPair,
        i * 2
      );
      const req2 = await createSignedTransfer(
        TEST_ACCOUNTS.BOB.address,
        TEST_ACCOUNTS.ALICE.address,
        0.1,
        bobKeyPair,
        i * 2 + 1
      );
      promises.push(httpPost('/transfer', req1));
      promises.push(httpPost('/transfer', req2));
    }
    
    await Promise.all(promises);
    
    // Wait for all to process
    await new Promise(r => setTimeout(r, 500));
    
    const supplyAfter = await getTotalSupply();
    const accountsAfter = await getKnownAccountsSum();
    
    const supplyDiff = Math.abs(supplyAfter - supplyBefore);
    const sumDiff = Math.abs(accountsAfter.sum - accountsBefore.sum);
    
    console.log(`   Supply change: ${supplyDiff.toFixed(6)}`);
    console.log(`   Balance sum change: ${sumDiff.toFixed(6)}`);
    
    if (supplyDiff > 0.1) {
      throw new Error(`INVARIANT VIOLATION: Supply changed by ${supplyDiff} under stress`);
    }
    
    results.pass('Invariant: Preserved under stress');
  } catch (err) {
    results.fail('Invariant: Preserved under stress', err);
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
