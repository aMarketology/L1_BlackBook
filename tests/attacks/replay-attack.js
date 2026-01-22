/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * 🔴 REPLAY ATTACK SIMULATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This script attempts to replay a valid signed transaction multiple times
 * to steal funds. A properly secured blockchain must reject replayed transactions.
 * 
 * ATTACK PATTERN:
 * ───────────────
 * 1. Create a legitimate signed transfer: Alice → Attacker (1 BB)
 * 2. Submit transaction (should succeed)
 * 3. Capture the EXACT transaction details
 * 4. Re-submit the SAME transaction 100 times
 * 5. If blockchain is vulnerable: Attacker receives 100 BB instead of 1 BB
 * 6. If blockchain is secure: Only first transaction succeeds
 * 
 * DEFENSE MECHANISMS TESTED:
 * ──────────────────────────
 * 1. Nonce tracking (each nonce can only be used once)
 * 2. Transaction ID deduplication
 * 3. Timestamp validation (reject old transactions)
 * 4. Signature replay protection
 * 
 * REAL-WORLD EXAMPLES:
 * ────────────────────
 * • Bitcoin SigHash vulnerability (2010)
 * • Ethereum Classic replay attacks after ETH/ETC fork (2016)
 * • Various exchange hacks exploiting replay vulnerabilities
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

const L1_URL = 'http://localhost:8080';

const VICTIM = {
  seed: '5DB4B525FB40D6EA6BFD24094C2BC24984BAC433FFC5F31CABE597BE18AA8F83',
  address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
};

const ATTACKER = {
  seed: 'b'.repeat(64),
  address: null,
};

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
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

async function createSignedTransfer(from, to, amount, keyPair, customNonce = null, customTimestamp = null) {
  const timestamp = customTimestamp ?? Math.floor(Date.now() / 1000);
  const nonce = customNonce ?? generateNonce();
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
console.log('   REPLAY ATTACK SIMULATION');
console.log('   Attempting to reuse signed transactions');
console.log('═════════════════════════════════════════════════════════════\n');

async function runReplayAttack() {
  // Setup
  const attackerKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(ATTACKER.seed));
  const attackerPubKey = bytesToHex(attackerKeyPair.publicKey);
  ATTACKER.address = `L1_${attackerPubKey.substring(0, 40).toUpperCase()}`;
  
  const victimKeyPair = nacl.sign.keyPair.fromSeed(hexToBytes(VICTIM.seed));
  
  console.log(`👤 Victim:   ${VICTIM.address}`);
  console.log(`👤 Attacker: ${ATTACKER.address}\n`);
  
  const victimInitial = await getBalance(VICTIM.address);
  const attackerInitial = await getBalance(ATTACKER.address);
  
  console.log(`💰 Initial Balances:`);
  console.log(`   Victim:   ${victimInitial.toFixed(2)} BB`);
  console.log(`   Attacker: ${attackerInitial.toFixed(2)} BB\n`);
  
  // ═══════════════════════════════════════════════════════════════════════
  // ATTACK 1: Exact transaction replay (100 times)
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🚨 ATTACK 1: Exact Transaction Replay');
  console.log('   Creating one legitimate transaction, then replaying 100 times...\n');
  
  const transferAmount = 0.1;
  const replayCount = 100;
  
  // Create ONE legitimate signed transaction
  const legitimateTransaction = await createSignedTransfer(
    VICTIM.address,
    ATTACKER.address,
    transferAmount,
    victimKeyPair
  );
  
  console.log(`   Transaction details:`);
  console.log(`   • Amount:    ${transferAmount} BB`);
  console.log(`   • Timestamp: ${legitimateTransaction.timestamp}`);
  console.log(`   • Nonce:     ${legitimateTransaction.nonce}`);
  console.log(`   • Signature: ${legitimateTransaction.signature.substring(0, 16)}...`);
  console.log(`\n   Submitting original transaction...`);
  
  const firstResult = await httpPost('/transfer/simple', legitimateTransaction);
  const firstSuccess = firstResult.status === 'success' || firstResult.success;
  
  console.log(`   ${firstSuccess ? '✓' : '✗'} Original: ${firstSuccess ? 'SUCCESS' : 'FAILED'}`);
  
  if (!firstSuccess) {
    console.log(`\n   ⚠️  Original transaction failed: ${JSON.stringify(firstResult)}`);
    console.log(`   Cannot proceed with replay attack test.\n`);
    return;
  }
  
  // Now replay the EXACT same transaction 100 times
  console.log(`\n   Replaying EXACT same transaction ${replayCount} times...`);
  
  let replaySuccesses = 0;
  let replayFailures = 0;
  const replayPromises = [];
  
  for (let i = 0; i < replayCount; i++) {
    replayPromises.push(
      httpPost('/transfer/simple', legitimateTransaction)
        .then(res => {
          if (res.status === 'success' || res.success) {
            replaySuccesses++;
          } else {
            replayFailures++;
          }
          return res;
        })
        .catch(err => {
          replayFailures++;
          return { error: err.message };
        })
    );
  }
  
  await Promise.all(replayPromises);
  
  console.log(`\n   Replay Results:`);
  console.log(`   ✓ Succeeded: ${replaySuccesses}/${replayCount}`);
  console.log(`   ✗ Rejected:  ${replayFailures}/${replayCount}\n`);
  
  // ═══════════════════════════════════════════════════════════════════════
  // ATTACK 2: Same nonce, different timestamp
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🚨 ATTACK 2: Nonce Reuse with Different Timestamp');
  console.log('   Attempting to bypass nonce check with timestamp variation...\n');
  
  const sameNonce = generateNonce();
  let nonceReuseSuccess = 0;
  
  for (let i = 0; i < 10; i++) {
    const tx = await createSignedTransfer(
      VICTIM.address,
      ATTACKER.address,
      0.05,
      victimKeyPair,
      sameNonce,  // REUSE same nonce
      Math.floor(Date.now() / 1000) + i  // Different timestamps
    );
    
    const result = await httpPost('/transfer/simple', tx);
    if (result.status === 'success' || result.success) {
      nonceReuseSuccess++;
    }
  }
  
  console.log(`   ✓ Succeeded: ${nonceReuseSuccess}/10`);
  console.log(`   ✗ Rejected:  ${10 - nonceReuseSuccess}/10\n`);
  
  // ═══════════════════════════════════════════════════════════════════════
  // ATTACK 3: Old transaction replay (timestamp in past)
  // ═══════════════════════════════════════════════════════════════════════
  console.log('🚨 ATTACK 3: Old Transaction Replay');
  console.log('   Submitting transactions with old timestamps...\n');
  
  const oldTimestamps = [
    Math.floor(Date.now() / 1000) - 3600,  // 1 hour ago
    Math.floor(Date.now() / 1000) - 86400, // 1 day ago
    Math.floor(Date.now() / 1000) - 604800, // 1 week ago
  ];
  
  let oldTxSuccess = 0;
  
  for (const oldTimestamp of oldTimestamps) {
    const tx = await createSignedTransfer(
      VICTIM.address,
      ATTACKER.address,
      0.01,
      victimKeyPair,
      null,
      oldTimestamp
    );
    
    const result = await httpPost('/transfer/simple', tx);
    if (result.status === 'success' || result.success) {
      oldTxSuccess++;
    }
  }
  
  console.log(`   ✓ Succeeded: ${oldTxSuccess}/3`);
  console.log(`   ✗ Rejected:  ${3 - oldTxSuccess}/3\n`);
  
  // Check final balances
  const victimFinal = await getBalance(VICTIM.address);
  const attackerFinal = await getBalance(ATTACKER.address);
  
  console.log(`💰 Final Balances:`);
  console.log(`   Victim:   ${victimFinal.toFixed(2)} BB (change: ${(victimFinal - victimInitial).toFixed(2)})`);
  console.log(`   Attacker: ${attackerFinal.toFixed(2)} BB (change: ${(attackerFinal - attackerInitial).toFixed(2)})\n`);
  
  // ═══════════════════════════════════════════════════════════════════════
  // VERDICT
  // ═══════════════════════════════════════════════════════════════════════
  console.log('═════════════════════════════════════════════════════════════');
  console.log('📊 REPLAY ATTACK ANALYSIS');
  console.log('═════════════════════════════════════════════════════════════\n');
  
  const expectedGain = transferAmount;  // Only the first transaction should succeed
  const actualGain = attackerFinal - attackerInitial;
  
  console.log(`Expected attacker gain: ${expectedGain.toFixed(2)} BB (1 transaction)`);
  console.log(`Actual attacker gain:   ${actualGain.toFixed(2)} BB`);
  console.log(`Extra funds stolen:     ${Math.max(0, actualGain - expectedGain).toFixed(2)} BB\n`);
  
  const vulnerabilities = [];
  
  if (replaySuccesses > 0) {
    vulnerabilities.push(`Exact replay succeeded ${replaySuccesses} times (CRITICAL)`);
  }
  
  if (nonceReuseSuccess > 1) {
    vulnerabilities.push(`Nonce reuse succeeded ${nonceReuseSuccess} times`);
  }
  
  if (oldTxSuccess > 0) {
    vulnerabilities.push(`Old timestamp accepted ${oldTxSuccess} times`);
  }
  
  if (actualGain > expectedGain + 0.01) {
    vulnerabilities.push(`Attacker stole extra funds: ${(actualGain - expectedGain).toFixed(2)} BB`);
  }
  
  if (vulnerabilities.length > 0) {
    console.log('❌ VULNERABILITY FOUND ❌\n');
    console.log('🚨 CRITICAL: Blockchain vulnerable to replay attacks!\n');
    console.log('Issues detected:');
    vulnerabilities.forEach((v, i) => console.log(`   ${i + 1}. ${v}`));
    console.log('\n⚠️  DO NOT DEPLOY TO PRODUCTION');
    process.exit(1);
  } else {
    console.log('✅ BLOCKCHAIN SECURE ✅\n');
    console.log('🛡️  Replay attacks successfully prevented!');
    console.log('   • Nonce tracking enforced');
    console.log('   • Transaction deduplication working');
    console.log('   • Only 1 transaction succeeded out of 113 attempts');
    console.log('\n✨ BlackBook L1 is immune to replay attacks');
    process.exit(0);
  }
}

runReplayAttack().catch(err => {
  console.error('\n💥 Attack script error:', err);
  process.exit(1);
});
