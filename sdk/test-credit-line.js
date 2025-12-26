#!/usr/bin/env node
// ============================================================================
// CREDIT LINE FLOW TEST
// ============================================================================
// Tests the new Credit Approve → Draw → Settle flow
// ============================================================================

import nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

const L1_URL = process.env.L1_URL || 'http://localhost:8080';
const CHAIN_ID_L1 = 0x01;

// ============================================================================
// HELPERS
// ============================================================================

function signMessage(privateKeyHex, message, chainId = CHAIN_ID_L1) {
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey, 0);
  secretKey.set(keypair.publicKey, 32);
  
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  const signature = nacl.sign.detached(domainSeparated, secretKey);
  return Buffer.from(signature).toString('hex');
}

// ============================================================================
// MAIN TEST
// ============================================================================

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║      CREDIT LINE FLOW TEST                               ║');
  console.log('║      Approve → Draw → Settle                            ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');
  
  // Get Alice's test account
  const accountsRes = await fetch(`${L1_URL}/auth/test-accounts`);
  const accounts = await accountsRes.json();
  const alice = accounts.alice;
  
  console.log('📋 Test Account:');
  console.log(`   Address: ${alice.address}`);
  console.log(`   L1 Balance: ${alice.l1_available} BB\n`);
  
  // ====================================================================
  // STEP 1: Approve Credit Line
  // ====================================================================
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  STEP 1: Approve Credit Line (1000 BB)');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  const creditLimit = 1000;
  const nonce1 = Date.now();
  const approveMessage = `APPROVE_CREDIT:${alice.address}:${creditLimit}:${nonce1}`;
  const approveSignature = signMessage(alice.private_key, approveMessage);
  
  const approveRes = await fetch(`${L1_URL}/credit/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: alice.address,
      public_key: alice.public_key,
      credit_limit: creditLimit,
      signature: approveSignature,
      nonce: nonce1
    })
  });
  
  const approveData = await approveRes.json();
  console.log('📝 Approve Response:', JSON.stringify(approveData, null, 2));
  
  if (!approveData.success) {
    console.log('\n❌ Credit approval failed!');
    console.log('   Error:', approveData.error);
    return;
  }
  
  console.log('✅ Credit line approved!');
  console.log(`   Approval ID: ${approveData.approval_id}`);
  console.log(`   Session ID: ${approveData.session_id}`);
  console.log(`   Available Credit: ${approveData.available_credit} BB`);
  console.log(`   Lock ID: ${approveData.lock_id}\n`);
  
  const approvalId = approveData.approval_id;
  const sessionId = approveData.session_id;
  
  // ====================================================================
  // STEP 2: Draw from Credit Line
  // ====================================================================
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  STEP 2: Draw 250 BB from Credit Line');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  const drawAmount = 250;
  const nonce2 = Date.now() + 1;
  const drawMessage = `CREDIT_DRAW:${alice.address}:${drawAmount}:Market betting:${nonce2}`;
  const drawSignature = signMessage(alice.private_key, drawMessage);
  
  const drawRes = await fetch(`${L1_URL}/credit/draw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: alice.address,
      public_key: alice.public_key,
      amount: drawAmount,
      reason: 'Market betting',
      signature: drawSignature,
      nonce: nonce2
    })
  });
  
  const drawData = await drawRes.json();
  console.log('📝 Draw Response:', JSON.stringify(drawData, null, 2));
  
  if (!drawData.success) {
    console.log('\n❌ Credit draw failed!');
    console.log('   Error:', drawData.error);
    return;
  }
  
  console.log('✅ Credit drawn successfully!');
  console.log(`   Amount Drawn: ${drawData.amount_drawn} BB`);
  console.log(`   Remaining Credit: ${drawData.remaining_credit} BB`);
  console.log(`   L2 Balance: ${drawData.l2_balance} BB\n`);
  
  // ====================================================================
  // STEP 3: Settle Credit Line
  // ====================================================================
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  STEP 3: Settle Credit Line (Won 50 BB)');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  const finalL2Balance = drawAmount + 50; // Won 50 BB
  const lockedInBets = 0;
  const nonce3 = Date.now() + 2;
  const settleMessage = `CREDIT_SETTLE:${alice.address}:${sessionId}:${finalL2Balance}:${lockedInBets}:${nonce3}`;
  const settleSignature = signMessage(alice.private_key, settleMessage);
  
  const settleRes = await fetch(`${L1_URL}/credit/settle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      wallet_address: alice.address,
      public_key: alice.public_key,
      session_id: sessionId,
      final_l2_balance: finalL2Balance,
      locked_in_bets: lockedInBets,
      signature: settleSignature,
      nonce: nonce3
    })
  });
  
  const settleData = await settleRes.json();
  console.log('📝 Settle Response:', JSON.stringify(settleData, null, 2));
  
  if (!settleData.success) {
    console.log('\n❌ Credit settlement failed!');
    console.log('   Error:', settleData.error);
    return;
  }
  
  console.log('✅ Credit line settled!');
  console.log(`   Total Drawn: ${settleData.total_drawn} BB`);
  console.log(`   Final L2 Balance: ${settleData.final_l2_balance} BB`);
  console.log(`   Profit/Loss: ${settleData.profit_loss > 0 ? '+' : ''}${settleData.profit_loss} BB`);
  console.log(`   Returned to User: ${settleData.returned_to_user} BB`);
  console.log(`   Dealer Payment: ${settleData.dealer_payment} BB\n`);
  
  // ====================================================================
  // VERIFICATION
  // ====================================================================
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  VERIFICATION: Final Balances');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  const finalBalanceRes = await fetch(`${L1_URL}/balance/${alice.address}`);
  const finalBalance = await finalBalanceRes.json();
  
  console.log(`   Alice Final L1 Balance: ${finalBalance.balance} BB`);
  console.log(`   Expected: ${alice.l1_available + settleData.profit_loss} BB\n`);
  
  console.log('🎉 Credit Line Flow Test Complete!\n');
}

main().catch(console.error);
