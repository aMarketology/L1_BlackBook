/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TEST 11: End-to-End Game Session Flow
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * This test simulates a complete game session lifecycle:
 * 
 * 1. Player checks L1 balance
 * 2. Player initiates game (L2 requests lock from L1 via gRPC)
 * 3. L1 locks tokens and confirms to L2
 * 4. L2 processes game (off-chain, fast)
 * 5. Game ends with win/loss/draw
 * 6. L2 sends settlement to L1 via gRPC
 * 7. L1 releases tokens with PNL adjustment
 * 8. Player sees updated balance
 * 
 * INTEGRATION TEST: Validates full L1 ↔ L2 communication flow
 */

import {
  TestResults,
  TEST_ACCOUNTS,
  getBalance,
  lockTokens,
  settleSession,
  generateSessionId,
} from './test-helpers.js';

console.log('\n╔═══════════════════════════════════════════════════════════════╗');
console.log('║  TEST 11: END-TO-END GAME SESSION                            ║');
console.log('╚═══════════════════════════════════════════════════════════════╝\n');

async function simulateGameSession(player, betAmount, outcome) {
  console.log(`\n🎮 ═══════ GAME SESSION START ═══════`);
  console.log(`   Player: ${player.address.substring(0, 20)}...`);
  console.log(`   Bet:    ${betAmount} BB`);
  console.log(`   Game:   BlackJack`);
  console.log('');
  
  const sessionId = generateSessionId();
  const results = new TestResults();
  
  // Step 1: Check L1 balance
  console.log('📊 Step 1: Query L1 balance...');
  const initialBalance = await getBalance(player.address);
  console.log(`   Available: ${initialBalance.available.toFixed(2)} BB`);
  console.log(`   Locked:    ${initialBalance.locked.toFixed(2)} BB\n`);
  
  if (initialBalance.available < betAmount) {
    results.fail('Balance check', 'Insufficient balance');
    return results;
  }
  results.pass('Query L1 balance');
  
  // Step 2: L2 requests lock via gRPC
  console.log(`🔒 Step 2: L2 → L1 gRPC: LockTokensRequest`);
  console.log(`   SessionID: ${sessionId}`);
  console.log(`   Amount:    ${betAmount} BB\n`);
  
  const lockResult = await lockTokens(player.address, betAmount, sessionId);
  if (!lockResult.success) {
    results.fail('Lock tokens', 'Lock request failed');
    return results;
  }
  results.pass('L1 locks tokens via gRPC');
  
  // Step 3: Verify lock in L1
  console.log('✅ Step 3: L1 → L2 gRPC: LockTokensResponse (success)');
  const lockedBalance = await getBalance(player.address);
  console.log(`   New Available: ${lockedBalance.available.toFixed(2)} BB\n`);
  
  if (Math.abs(lockedBalance.available - (initialBalance.available - betAmount)) < 0.01) {
    results.pass('Tokens locked on L1');
  } else {
    results.fail('Token lock verification', 'Balance mismatch');
  }
  
  // Step 4: L2 game processing (simulated)
  console.log('🎲 Step 4: L2 game processing (off-chain)...');
  console.log('   Player: Hit → 19');
  console.log('   Dealer: Stand → 17');
  console.log(`   Result: ${outcome.toUpperCase()}\n`);
  
  // Calculate PNL
  let pnl;
  switch (outcome) {
    case 'win':
      pnl = betAmount; // Win returns bet + profit
      break;
    case 'loss':
      pnl = -betAmount; // Lose the bet
      break;
    case 'push':
      pnl = 0; // Break even
      break;
    default:
      pnl = 0;
  }
  
  // Step 5: L2 sends settlement to L1
  console.log(`💰 Step 5: L2 → L1 gRPC: SettleSessionRequest`);
  console.log(`   SessionID: ${sessionId}`);
  console.log(`   PNL:       ${pnl >= 0 ? '+' : ''}${pnl} BB\n`);
  
  const settleResult = await settleSession(sessionId, pnl);
  if (!settleResult.success) {
    results.fail('Settlement', 'Settlement request failed');
    return results;
  }
  results.pass('L2 settles session via gRPC');
  
  // Step 6: Verify final balance
  console.log('✅ Step 6: L1 → L2 gRPC: SettleSessionResponse (success)');
  const finalBalance = await getBalance(player.address);
  console.log(`   Final Available: ${finalBalance.available.toFixed(2)} BB`);
  console.log(`   Net Change:      ${(finalBalance.available - initialBalance.available).toFixed(2)} BB\n`);
  
  const expectedFinal = initialBalance.available + pnl;
  if (Math.abs(finalBalance.available - expectedFinal) < 0.01) {
    results.pass('Final balance correct');
  } else {
    results.fail('Final balance', `Expected ${expectedFinal}, got ${finalBalance.available}`);
  }
  
  console.log(`🎮 ═══════ GAME SESSION END ═══════\n`);
  
  return results;
}

async function run() {
  const mainResults = new TestResults();
  
  console.log('Testing three complete game sessions:\n');
  
  // Session 1: WIN
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const winResults = await simulateGameSession(TEST_ACCOUNTS.ALICE, 5.0, 'win');
  if (winResults.failed === 0) {
    mainResults.pass('Win scenario (full session)');
  } else {
    mainResults.fail('Win scenario', `${winResults.failed} failures`);
  }
  
  // Small delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Session 2: LOSS
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const lossResults = await simulateGameSession(TEST_ACCOUNTS.ALICE, 3.0, 'loss');
  if (lossResults.failed === 0) {
    mainResults.pass('Loss scenario (full session)');
  } else {
    mainResults.fail('Loss scenario', `${lossResults.failed} failures`);
  }
  
  // Small delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Session 3: PUSH (break even)
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  const pushResults = await simulateGameSession(TEST_ACCOUNTS.ALICE, 2.0, 'push');
  if (pushResults.failed === 0) {
    mainResults.pass('Push scenario (full session)');
  } else {
    mainResults.fail('Push scenario', `${pushResults.failed} failures`);
  }
  
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  return mainResults;
}

run()
  .then(results => {
    const success = results.summary();
    process.exit(success ? 0 : 1);
  })
  .catch(err => {
    console.error('\n💥 Test error:', err);
    process.exit(1);
  });
