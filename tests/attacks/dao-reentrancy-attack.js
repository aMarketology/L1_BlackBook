/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * 🔴 DAO REENTRANCY ATTACK SIMULATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This script simulates the 2016 Ethereum DAO hack that exploited reentrancy
 * to drain ~$60M USD. We test if BlackBook L1 is vulnerable to the same attack.
 * 
 * ATTACK PATTERN (The DAO Hack):
 * ────────────────────────────────
 * 1. Attacker deposits funds into contract
 * 2. Attacker calls withdraw() function
 * 3. Contract sends ETH to attacker (msg.sender.call.value())
 * 4. Before contract updates balance, attacker's fallback function re-enters
 * 5. Attacker calls withdraw() AGAIN with same old balance
 * 6. Repeat steps 3-5 recursively, draining all funds
 * 7. Finally, balance is set to zero (too late!)
 * 
 * WHY IT WORKED:
 * ──────────────
 * Solidity's "Checks-Effects-Interactions" pattern was violated:
 *   BAD:  Check balance → Send funds → Update balance
 *   GOOD: Check balance → Update balance → Send funds
 * 
 * OUR DEFENSE:
 * ────────────
 * BlackBook L1 uses atomic ReDB transactions. State updates are committed
 * atomically BEFORE any response is sent, making reentrancy impossible.
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

const L1_URL = 'http://localhost:8080';

// Test accounts
const ATTACKER = {
  seed: 'a'.repeat(64), // Malicious actor
  address: null, // Will be derived
};

const VICTIM = {
  seed: '5DB4B525FB40D6EA6BFD24094C2BC24984BAC433FFC5F31CABE597BE18AA8F83',
  address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
};

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

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

async function createSignedTransfer(from, to, amount, keyPair) {
  const timestamp = Math.floor(Date.now() / 1000);
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

async function httpPost(endpoint, body) {
  const response = await fetch(`${L1_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return await response.json();
}

async function httpGet(endpoint) {
  const response = await fetch(`${L1_URL}${endpoint}`);
  return await response.json();
}

async function getBalance(address) {
  const response = await httpGet(`/balance/${address}`);
  return response.balance ?? response.available ?? 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK SIMULATION
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n🔴 ═════════════════════════════════════════════════════════════');
console.log('   DAO REENTRANCY ATTACK SIMULATION');
console.log('   Replicating the $60M Ethereum DAO hack');
console.log('═════════════════════════════════════════════════════════════\n');

async function runAttack() {
  // Setup attacker wallet
  const attackerKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(ATTACKER.seed));
  const attackerPubKey = bytesToHex(attackerKeyPair.publicKey);
  ATTACKER.address = `L1_${attackerPubKey.substring(0, 40).toUpperCase()}`;
  
  console.log(`👤 Attacker: ${ATTACKER.address}`);
  console.log(`👤 Victim:   ${VICTIM.address}\n`);
  
  const victimKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(VICTIM.seed));
  
  // Check initial balances
  const victimInitial = await getBalance(VICTIM.address);
  const attackerInitial = await getBalance(ATTACKER.address);
  
  console.log(`💰 Initial Balances:`);
  console.log(`   Victim:   ${victimInitial.toFixed(2)} BB`);
  console.log(`   Attacker: ${attackerInitial.toFixed(2)} BB\n`);
  
  if (victimInitial < 10) {
    console.log('⚠️  Victim has insufficient balance for attack simulation');
    console.log('   Attempting attack anyway...\n');
  }
  
  // ═══════════════════════════════════════════════════════════════════════
  // ATTACK 1: Rapid-fire recursive withdrawals (simulated reentrancy)
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🚨 ATTACK 1: Rapid-fire Recursive Withdrawals');
  console.log('   Simulating reentrancy by sending many requests with same timestamp...\n');
  
  const withdrawAmount = 1.0;
  const recursionDepth = 50; // Number of "recursive" calls
  const sameTimestamp = Math.floor(Date.now() / 1000);
  
  let successfulWithdrawals = 0;
  let totalDrained = 0;
  
  // Create all requests with SAME timestamp (simulates recursive callback)
  const promises = [];
  for (let i = 0; i < recursionDepth; i++) {
    const nonce = generateNonce();
    const payload = JSON.stringify({ to: ATTACKER.address, amount: withdrawAmount });
    
    const chainIdByte = new Uint8Array([0x01]);
    const payloadBytes = new TextEncoder().encode(payload);
    const timestampBytes = new TextEncoder().encode(`\n${sameTimestamp}\n`);
    const nonceBytes = new TextEncoder().encode(nonce);
    
    const message = new Uint8Array(chainIdByte.length + payloadBytes.length + timestampBytes.length + nonceBytes.length);
    let offset = 0;
    message.set(chainIdByte, offset); offset += chainIdByte.length;
    message.set(payloadBytes, offset); offset += payloadBytes.length;
    message.set(timestampBytes, offset); offset += timestampBytes.length;
    message.set(nonceBytes, offset);
    
    const signature = nacl.sign.detached(message, victimKeyPair.secretKey);
    
    const request = {
      public_key: bytesToHex(victimKeyPair.publicKey),
      wallet_address: VICTIM.address,
      payload: payload,
      timestamp: sameTimestamp,
      nonce: nonce,
      chain_id: 1,
      schema_version: 1,
      signature: bytesToHex(signature)
    };
    
    // Fire all requests simultaneously (simulate recursive calls)
    promises.push(
      httpPost('/transfer/simple', request)
        .then(res => {
          if (res.status === 'success' || res.success) {
            successfulWithdrawals++;
            totalDrained += withdrawAmount;
          }
          return res;
        })
        .catch(err => ({ error: err.message }))
    );
  }
  
  console.log(`   Firing ${recursionDepth} simultaneous withdrawal requests...`);
  const results = await Promise.all(promises);
  
  console.log(`\n   Results:`);
  console.log(`   ✓ Successful: ${successfulWithdrawals}/${recursionDepth}`);
  console.log(`   ✗ Rejected:   ${recursionDepth - successfulWithdrawals}/${recursionDepth}`);
  console.log(`   💸 Drained:   ${totalDrained.toFixed(2)} BB\n`);
  
  // Check final balances
  const victimFinal = await getBalance(VICTIM.address);
  const attackerFinal = await getBalance(ATTACKER.address);
  
  console.log(`💰 Final Balances:`);
  console.log(`   Victim:   ${victimFinal.toFixed(2)} BB (change: ${(victimFinal - victimInitial).toFixed(2)})`);
  console.log(`   Attacker: ${attackerFinal.toFixed(2)} BB (change: ${(attackerFinal - attackerInitial).toFixed(2)})\n`);
  
  // ═══════════════════════════════════════════════════════════════════════
  // ATTACK 2: Interleaved transactions (state race condition)
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🚨 ATTACK 2: Interleaved State Race Condition');
  console.log('   Attempting to exploit transaction ordering...\n');
  
  const interleavedAmount = Math.min(victimFinal / 2, 5);
  const interleavedPromises = [];
  
  for (let i = 0; i < 10; i++) {
    interleavedPromises.push(
      createSignedTransfer(VICTIM.address, ATTACKER.address, interleavedAmount, victimKeyPair)
        .then(req => httpPost('/transfer/simple', req))
        .catch(err => ({ error: err.message }))
    );
  }
  
  console.log(`   Firing 10 interleaved ${interleavedAmount} BB transfers...`);
  const interleavedResults = await Promise.all(interleavedPromises);
  const interleavedSuccess = interleavedResults.filter(r => r.status === 'success' || r.success).length;
  
  console.log(`   ✓ Successful: ${interleavedSuccess}/10`);
  console.log(`   ✗ Rejected:   ${10 - interleavedSuccess}/10\n`);
  
  const victimAfterInterleaved = await getBalance(VICTIM.address);
  const attackerAfterInterleaved = await getBalance(ATTACKER.address);
  
  // ═══════════════════════════════════════════════════════════════════════
  // VERDICT
  // ═══════════════════════════════════════════════════════════════════════
  console.log('═════════════════════════════════════════════════════════════');
  console.log('📊 ATTACK ANALYSIS');
  console.log('═════════════════════════════════════════════════════════════\n');
  
  const totalExpectedDeductions = (successfulWithdrawals * withdrawAmount) + (interleavedSuccess * interleavedAmount);
  const actualDeductions = victimInitial - victimAfterInterleaved;
  
  console.log(`Expected victim balance reduction: ${totalExpectedDeductions.toFixed(2)} BB`);
  console.log(`Actual victim balance reduction:   ${actualDeductions.toFixed(2)} BB`);
  console.log(`Discrepancy: ${Math.abs(totalExpectedDeductions - actualDeductions).toFixed(2)} BB\n`);
  
  // Vulnerability detection
  const vulnerabilities = [];
  
  if (successfulWithdrawals > 1) {
    vulnerabilities.push('Multiple simultaneous withdrawals succeeded (reentrancy)');
  }
  
  if (interleavedSuccess > 1) {
    vulnerabilities.push('Multiple interleaved transactions succeeded (race condition)');
  }
  
  if (Math.abs(totalExpectedDeductions - actualDeductions) > 0.01) {
    vulnerabilities.push('Balance inconsistency detected (state corruption)');
  }
  
  if (attackerAfterInterleaved - attackerInitial > totalExpectedDeductions + 0.01) {
    vulnerabilities.push('Attacker gained more funds than expected (critical bug)');
  }
  
  if (vulnerabilities.length > 0) {
    console.log('❌ VULNERABILITY FOUND ❌\n');
    console.log('🚨 CRITICAL: Blockchain is vulnerable to DAO-style attack!\n');
    console.log('Issues detected:');
    vulnerabilities.forEach((v, i) => console.log(`   ${i + 1}. ${v}`));
    console.log('\n⚠️  DO NOT DEPLOY TO PRODUCTION');
    process.exit(1);
  } else {
    console.log('✅ BLOCKCHAIN SECURE ✅\n');
    console.log('🛡️  DAO reentrancy attack successfully prevented!');
    console.log('   • Atomic transactions enforced');
    console.log('   • State consistency maintained');
    console.log('   • No fund drainage detected');
    console.log('\n✨ BlackBook L1 is immune to The DAO hack');
    process.exit(0);
  }
}

runAttack().catch(err => {
  console.error('\n💥 Attack script error:', err);
  process.exit(1);
});
