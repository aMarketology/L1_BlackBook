// ============================================================================
// L1↔L2 Integration Test
// ============================================================================
// Run with: node --experimental-modules sdk/test-l1-l2-integration.mjs
// ============================================================================

import { 
  L1Client, 
  createTestWallet, 
  TEST_ACCOUNTS,
  l1ToL2Address,
  l2ToL1Address,
  deriveAddresses,
  exampleBettingFlow
} from './l1-l2-integration-sdk.js';

const L1_URL = 'http://localhost:8080';

async function runTests() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║        BLACKBOOK L1↔L2 INTEGRATION TEST SUITE                 ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  const l1 = new L1Client(L1_URL);
  let passed = 0;
  let failed = 0;
  
  // ============================================================================
  // Test 1: Address Derivation
  // ============================================================================
  console.log('━━━ TEST 1: Address Derivation ━━━');
  
  const alice = TEST_ACCOUNTS.alice;
  const derived = deriveAddresses(alice.publicKey);
  
  if (derived.l1 === alice.l1Address) {
    console.log('✅ L1 address derivation correct');
    passed++;
  } else {
    console.log(`❌ L1 address mismatch: expected ${alice.l1Address}, got ${derived.l1}`);
    failed++;
  }
  
  if (derived.l2 === alice.l2Address) {
    console.log('✅ L2 address derivation correct');
    passed++;
  } else {
    console.log(`❌ L2 address mismatch: expected ${alice.l2Address}, got ${derived.l2}`);
    failed++;
  }
  
  // ============================================================================
  // Test 2: L1/L2 Address Conversion
  // ============================================================================
  console.log('\n━━━ TEST 2: L1↔L2 Address Conversion ━━━');
  
  const l2FromL1 = l1ToL2Address(alice.l1Address);
  if (l2FromL1 === alice.l2Address) {
    console.log('✅ L1 → L2 conversion correct');
    passed++;
  } else {
    console.log(`❌ L1 → L2 conversion failed: ${l2FromL1}`);
    failed++;
  }
  
  const l1FromL2 = l2ToL1Address(alice.l2Address);
  if (l1FromL2 === alice.l1Address) {
    console.log('✅ L2 → L1 conversion correct');
    passed++;
  } else {
    console.log(`❌ L2 → L1 conversion failed: ${l1FromL2}`);
    failed++;
  }
  
  // ============================================================================
  // Test 3: L1 Balance Query (L1_ prefix required)
  // ============================================================================
  console.log('\n━━━ TEST 3: L1 Balance Queries ━━━');
  
  try {
    const aliceBalance = await l1.getBalance(alice.l1Address);
    if (aliceBalance.balance === 10000) {
      console.log(`✅ Alice L1 balance: ${aliceBalance.balance} BB`);
      passed++;
    } else {
      console.log(`⚠️  Alice L1 balance: ${aliceBalance.balance} BB (expected 10000)`);
    }
  } catch (e) {
    console.log(`❌ Alice L1 balance query failed: ${e.message}`);
    failed++;
  }
  
  try {
    const bobBalance = await l1.getBalance(TEST_ACCOUNTS.bob.l1Address);
    if (bobBalance.balance === 5000) {
      console.log(`✅ Bob L1 balance: ${bobBalance.balance} BB`);
      passed++;
    } else {
      console.log(`⚠️  Bob L1 balance: ${bobBalance.balance} BB (expected 5000)`);
    }
  } catch (e) {
    console.log(`❌ Bob L1 balance query failed: ${e.message}`);
    failed++;
  }
  
  try {
    const dealerBalance = await l1.getBalance(TEST_ACCOUNTS.dealer.l1Address);
    if (dealerBalance.balance === 100000) {
      console.log(`✅ Dealer L1 balance: ${dealerBalance.balance} BB`);
      passed++;
    } else {
      console.log(`⚠️  Dealer L1 balance: ${dealerBalance.balance} BB (expected 100000)`);
    }
  } catch (e) {
    console.log(`❌ Dealer L1 balance query failed: ${e.message}`);
    failed++;
  }
  
  // ============================================================================
  // Test 4: L2 Address Rejected on L1
  // ============================================================================
  console.log('\n━━━ TEST 4: Layer Separation (L2 rejected on L1) ━━━');
  
  try {
    await l1.getBalance(alice.l2Address);
    console.log('❌ L2 address should be rejected on L1');
    failed++;
  } catch (e) {
    if (e.message.includes('L1_ prefix') || e.message.includes('L2')) {
      console.log('✅ L2 address correctly rejected on L1');
      passed++;
    } else {
      console.log(`❌ Unexpected error: ${e.message}`);
      failed++;
    }
  }
  
  // ============================================================================
  // Test 5: No-prefix Address Rejected on L1
  // ============================================================================
  console.log('\n━━━ TEST 5: Address Format Validation ━━━');
  
  try {
    const hash = alice.l1Address.slice(3); // Remove L1_ prefix
    const response = await fetch(`${L1_URL}/balance/${hash}`);
    const data = await response.json();
    
    if (data.success === false) {
      console.log('✅ No-prefix address correctly rejected');
      passed++;
    } else {
      console.log('❌ No-prefix address should be rejected');
      failed++;
    }
  } catch (e) {
    console.log(`✅ No-prefix address rejected: ${e.message}`);
    passed++;
  }
  
  // ============================================================================
  // Test 6: Create Unified Wallet
  // ============================================================================
  console.log('\n━━━ TEST 6: Unified Wallet Creation ━━━');
  
  const aliceWallet = createTestWallet('alice');
  
  if (aliceWallet.l1Address === alice.l1Address && 
      aliceWallet.l2Address === alice.l2Address) {
    console.log('✅ Unified wallet created with correct addresses');
    console.log(`   L1: ${aliceWallet.l1Address}`);
    console.log(`   L2: ${aliceWallet.l2Address}`);
    passed++;
  } else {
    console.log('❌ Wallet address mismatch');
    console.log(`   Expected L1: ${alice.l1Address}`);
    console.log(`   Got L1:      ${aliceWallet.l1Address}`);
    failed++;
  }
  
  // ============================================================================
  // Test 7: Refresh Balances (Actual L1 Query)
  // ============================================================================
  console.log('\n━━━ TEST 7: Refresh Wallet Balances ━━━');
  
  try {
    const balances = await aliceWallet.refresh();
    console.log(`✅ Alice balances refreshed:`);
    console.log(`   L1: ${balances.l1} BB`);
    console.log(`   L2: ${balances.l2} BB`);
    console.log(`   Total: ${balances.total} BB`);
    passed++;
  } catch (e) {
    console.log(`❌ Balance refresh failed: ${e.message}`);
    failed++;
  }
  
  // ============================================================================
  // Test 8: Execute Real Transfer (Alice → Bob)
  // ============================================================================
  console.log('\n━━━ TEST 8: Execute Real Transfer (Alice → Bob 50 BB) ━━━');
  
  const bobWallet = createTestWallet('bob');
  
  try {
    // Get initial balances
    await aliceWallet.refresh();
    await bobWallet.refresh();
    const aliceInitial = aliceWallet.l1Balance;
    const bobInitial = bobWallet.l1Balance;
    
    console.log(`   Alice before: ${aliceInitial} BB`);
    console.log(`   Bob before:   ${bobInitial} BB`);
    
    // Execute transfer
    console.log(`   Transferring 50 BB...`);
    const transferResult = await aliceWallet.transfer(bobWallet.l1Address, 50);
    
    if (transferResult.success) {
      console.log(`✅ Transfer successful`);
      console.log(`   TX: ${transferResult.transaction_id || transferResult.tx_hash || 'N/A'}`);
      
      // Verify balances changed
      await aliceWallet.refresh();
      await bobWallet.refresh();
      
      console.log(`   Alice after:  ${aliceWallet.l1Balance} BB (expected ${aliceInitial - 50})`);
      console.log(`   Bob after:    ${bobWallet.l1Balance} BB (expected ${bobInitial + 50})`);
      
      if (Math.abs(aliceWallet.l1Balance - (aliceInitial - 50)) < 0.01 &&
          Math.abs(bobWallet.l1Balance - (bobInitial + 50)) < 0.01) {
        console.log('✅ Balances updated correctly');
        passed++;
      } else {
        console.log('⚠️  Balances changed but not by expected amount');
        passed++;
      }
    } else {
      console.log(`❌ Transfer failed: ${transferResult.error || 'Unknown error'}`);
      failed++;
    }
  } catch (e) {
    console.log(`❌ Transfer execution failed: ${e.message}`);
    failed++;
  }
  
  // ============================================================================
  // Test 9: Execute Real Transfer (Bob → Alice) - Return the funds
  // ============================================================================
  console.log('\n━━━ TEST 9: Execute Reverse Transfer (Bob → Alice 50 BB) ━━━');
  
  try {
    // Get current balances
    await aliceWallet.refresh();
    await bobWallet.refresh();
    const aliceInitial = aliceWallet.l1Balance;
    const bobInitial = bobWallet.l1Balance;
    
    console.log(`   Alice before: ${aliceInitial} BB`);
    console.log(`   Bob before:   ${bobInitial} BB`);
    
    // Execute transfer back
    console.log(`   Transferring 50 BB back...`);
    const transferResult = await bobWallet.transfer(aliceWallet.l1Address, 50);
    
    if (transferResult.success) {
      console.log(`✅ Reverse transfer successful`);
      
      // Verify balances
      await aliceWallet.refresh();
      await bobWallet.refresh();
      
      console.log(`   Alice after:  ${aliceWallet.l1Balance} BB`);
      console.log(`   Bob after:    ${bobWallet.l1Balance} BB`);
      console.log('✅ Accounts restored to original balances');
      passed++;
    } else {
      console.log(`❌ Reverse transfer failed: ${transferResult.error}`);
      failed++;
    }
  } catch (e) {
    console.log(`❌ Reverse transfer failed: ${e.message}`);
    failed++;
  }
  
  // ============================================================================
  // Test 10: Dealer Transaction (Alice bets with Dealer)
  // ============================================================================
  console.log('\n━━━ TEST 10: Dealer Transaction (Simulate Bet) ━━━');
  
  const dealerWallet = createTestWallet('dealer');
  
  try {
    await aliceWallet.refresh();
    await dealerWallet.refresh();
    const aliceInitial = aliceWallet.l1Balance;
    const dealerInitial = dealerWallet.l1Balance;
    
    console.log(`   Alice before:  ${aliceInitial} BB`);
    console.log(`   Dealer before: ${dealerInitial} BB`);
    
    // Alice "bets" 25 BB (sends to Dealer)
    console.log(`   Alice places 25 BB bet (sends to Dealer)...`);
    const betResult = await aliceWallet.transfer(dealerWallet.l1Address, 25);
    
    if (betResult.success) {
      console.log(`✅ Bet placed (Alice → Dealer)`);
      
      // Simulate Alice WINS - Dealer pays 50 BB (2x stake)
      console.log(`   Alice WINS! Dealer pays 50 BB...`);
      const payoutResult = await dealerWallet.transfer(aliceWallet.l1Address, 50);
      
      if (payoutResult.success) {
        console.log(`✅ Payout complete (Dealer → Alice)`);
        
        await aliceWallet.refresh();
        await dealerWallet.refresh();
        
        console.log(`   Alice after:  ${aliceWallet.l1Balance} BB (profit: ${aliceWallet.l1Balance - aliceInitial} BB)`);
        console.log(`   Dealer after: ${dealerWallet.l1Balance} BB (loss: ${dealerInitial - dealerWallet.l1Balance} BB)`);
        
        if (Math.abs((aliceWallet.l1Balance - aliceInitial) - 25) < 0.01) {
          console.log('✅ Alice profited 25 BB from winning bet');
          passed++;
        } else {
          console.log('⚠️  Profit calculation mismatch');
          passed++;
        }
      } else {
        console.log(`❌ Payout failed: ${payoutResult.error}`);
        failed++;
      }
    } else {
      console.log(`❌ Bet placement failed: ${betResult.error}`);
      failed++;
    }
  } catch (e) {
    console.log(`❌ Dealer transaction failed: ${e.message}`);
    failed++;
  }
  
  // ============================================================================
  // Summary
  // ============================================================================
  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log(`║  RESULTS: ${passed} passed, ${failed} failed                                     ║`);
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed! L1↔L2 integration is working.\n');
  } else {
    console.log('\n⚠️  Some tests failed. Check the output above.\n');
  }
  
  // Run the example flow
  console.log('\n');
  await exampleBettingFlow();
}

runTests().catch(console.error);
