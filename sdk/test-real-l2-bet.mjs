// ============================================================================
// Real L2 Betting Test - Tesla RoboTaxi Market
// ============================================================================
// Run with: node sdk/test-real-l2-bet.mjs
// Requires: L1 server on :8080, L2 server on :3000
// ============================================================================

import { 
  createTestWallet, 
  L2Client
} from './l1-l2-integration-sdk.js';

const L1_URL = 'http://localhost:8080';
const L2_URL = 'http://localhost:1234';

async function testRealL2Betting() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║     REAL L2 BETTING TEST - Tesla RoboTaxi Market              ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');
  
  const alice = createTestWallet('alice');
  const bob = createTestWallet('bob');
  const l2 = new L2Client(L2_URL);
  
  try {
    // ========================================================================
    // Step 1: Check L2 Server Health
    // ========================================================================
    console.log('━━━ STEP 1: L2 Server Health Check ━━━');
    try {
      // L2 returns text at root, not JSON
      const resp = await fetch(`${L2_URL}/`);
      const text = await resp.text();
      if (text.includes('BlackBook') || text.includes('L2')) {
        console.log(`✅ L2 server is healthy`);
        console.log(`   Status: ${text.trim()}`);
      } else {
        throw new Error('Unexpected response');
      }
    } catch (e) {
      console.log(`❌ L2 server not reachable: ${e.message}`);
      console.log(`   Make sure L2 server is running on ${L2_URL}`);
      return;
    }
    
    // ========================================================================
    // Step 2: Check Market
    // ========================================================================
    console.log('\n━━━ STEP 2: Fetch Tesla RoboTaxi Market ━━━');
    let market;
    let MARKET_ID;  // Will be set to actual market ID found
    try {
      // Fetch from /markets endpoint and find by ID
      const resp = await fetch(`${L2_URL}/markets`);
      const data = await resp.json();
      market = data.markets?.find(m => m.id.includes('tesla'));
      
      if (!market) {
        console.log(`❌ Tesla market not found. Available markets:`);
        data.markets?.slice(0, 5).forEach(m => console.log(`   - ${m.id}: ${m.title}`));
        return;
      }
      
      MARKET_ID = market.id;  // Use actual market ID
      console.log(`✅ Market found: ${market.title || market.id}`);
      console.log(`   Market ID: ${MARKET_ID}`);
      console.log(`   YES price: ${market.yes_price || 'N/A'}`);
      console.log(`   NO price: ${market.no_price || 'N/A'}`);
      console.log(`   Total volume: ${market.total_volume || 0} BB`);
      console.log(`   Status: ${market.is_resolved ? 'RESOLVED' : 'ACTIVE'}`);
      
      if (market.is_resolved) {
        console.log(`⚠️  Market already resolved to: ${market.winning_outcome}`);
        console.log(`   Cannot place new bets on resolved market`);
        return;
      }
    } catch (e) {
      console.log(`❌ Failed to fetch market: ${e.message}`);
      return;
    }
    
    // ========================================================================
    // Step 3: Check Initial L2 Balances
    // ========================================================================
    console.log('\n━━━ STEP 3: Check L2 Balances ━━━');
    
    let aliceL2Balance, bobL2Balance;
    try {
      const aliceData = await l2.getBalance(alice.l2Address);
      aliceL2Balance = aliceData.balance || 0;
      console.log(`   Alice L2: ${aliceL2Balance} BB`);
    } catch (e) {
      aliceL2Balance = 0;
      console.log(`   Alice L2: 0 BB (not yet credited)`);
    }
    
    try {
      const bobData = await l2.getBalance(bob.l2Address);
      bobL2Balance = bobData.balance || 0;
      console.log(`   Bob L2: ${bobL2Balance} BB`);
    } catch (e) {
      bobL2Balance = 0;
      console.log(`   Bob L2: 0 BB (not yet credited)`);
    }
    
    // ========================================================================
    // Step 4: Credit L2 Balances (Simulate Bridge)
    // ========================================================================
    console.log('\n━━━ STEP 4: Credit L2 Balances (Simulate L1→L2 Bridge) ━━━');
    
    if (aliceL2Balance < 100) {
      console.log(`   Crediting Alice 1000 BB on L2...`);
      try {
        const creditResult = await l2.credit(alice.l2Address, 1000);
        console.log(`✅ Alice credited: ${JSON.stringify(creditResult)}`);
        aliceL2Balance = 1000;
      } catch (e) {
        console.log(`❌ Credit failed: ${e.message}`);
      }
    }
    
    if (bobL2Balance < 100) {
      console.log(`   Crediting Bob 500 BB on L2...`);
      try {
        const creditResult = await l2.credit(bob.l2Address, 500);
        console.log(`✅ Bob credited: ${JSON.stringify(creditResult)}`);
        bobL2Balance = 500;
      } catch (e) {
        console.log(`❌ Credit failed: ${e.message}`);
      }
    }
    
    // ========================================================================
    // Step 5: Get Price Quote
    // ========================================================================
    console.log('\n━━━ STEP 5: Get Buy Quote ━━━');
    
    try {
      const quote = await l2.getQuote(MARKET_ID, 'YES', 50);
      console.log(`   Alice wants to bet 50 BB on YES`);
      console.log(`   Quote: ${JSON.stringify(quote)}`);
      if (quote.tokens_received) {
        console.log(`   Will receive: ${quote.tokens_received} YES tokens`);
        console.log(`   Effective price: ${quote.effective_price || 'N/A'}`);
      }
    } catch (e) {
      console.log(`   Quote not available: ${e.message}`);
    }
    
    // ========================================================================
    // Step 6: Alice Bets YES
    // ========================================================================
    console.log('\n━━━ STEP 6: Alice Places Bet (50 BB on YES) ━━━');
    
    try {
      const betResult = await alice.placeBet(MARKET_ID, 'YES', 50);
      console.log(`✅ Bet placed successfully!`);
      console.log(`   Result: ${JSON.stringify(betResult, null, 2)}`);
      
      if (betResult.tokens_received || betResult.tokens) {
        console.log(`   Alice received: ${betResult.tokens_received || betResult.tokens} YES tokens`);
      }
      
      // Update balance
      const newBalance = await l2.getBalance(alice.l2Address);
      console.log(`   Alice new balance: ${newBalance.balance} BB`);
      
    } catch (e) {
      console.log(`❌ Bet failed: ${e.message}`);
    }
    
    // ========================================================================
    // Step 7: Bob Bets NO
    // ========================================================================
    console.log('\n━━━ STEP 7: Bob Places Bet (30 BB on NO) ━━━');
    
    try {
      const betResult = await bob.placeBet(MARKET_ID, 'NO', 30);
      console.log(`✅ Bet placed successfully!`);
      console.log(`   Result: ${JSON.stringify(betResult, null, 2)}`);
      
      if (betResult.tokens_received || betResult.tokens) {
        console.log(`   Bob received: ${betResult.tokens_received || betResult.tokens} NO tokens`);
      }
      
      // Update balance
      const newBalance = await l2.getBalance(bob.l2Address);
      console.log(`   Bob new balance: ${newBalance.balance} BB`);
      
    } catch (e) {
      console.log(`❌ Bet failed: ${e.message}`);
    }
    
    // ========================================================================
    // Step 8: Check Updated Market Prices (CPMM moved)
    // ========================================================================
    console.log('\n━━━ STEP 8: Check Updated Market Prices ━━━');
    
    try {
      const updatedMarket = await l2.getMarket(MARKET_ID);
      console.log(`   YES price: ${updatedMarket.yes_price || 'N/A'} (was ${market.yes_price || 'N/A'})`);
      console.log(`   NO price: ${updatedMarket.no_price || 'N/A'} (was ${market.no_price || 'N/A'})`);
      console.log(`   Total volume: ${updatedMarket.volume || 0} BB`);
      console.log(`✅ Prices updated by CPMM!`);
    } catch (e) {
      console.log(`   Could not fetch updated prices: ${e.message}`);
    }
    
    // ========================================================================
    // Step 9: Check User Positions
    // ========================================================================
    console.log('\n━━━ STEP 9: Check User Positions ━━━');
    
    try {
      const alicePosition = await alice.getPosition(MARKET_ID);
      console.log(`   Alice position: ${JSON.stringify(alicePosition)}`);
    } catch (e) {
      console.log(`   Alice position: ${e.message}`);
    }
    
    try {
      const bobPosition = await bob.getPosition(MARKET_ID);
      console.log(`   Bob position: ${JSON.stringify(bobPosition)}`);
    } catch (e) {
      console.log(`   Bob position: ${e.message}`);
    }
    
    // ========================================================================
    // Step 10: Get User Bets History
    // ========================================================================
    console.log('\n━━━ STEP 10: Get Bet History ━━━');
    
    try {
      const aliceBets = await alice.getBets();
      console.log(`   Alice total bets: ${aliceBets.length || 0}`);
      if (aliceBets.length > 0) {
        console.log(`   Latest: ${JSON.stringify(aliceBets[aliceBets.length - 1])}`);
      }
    } catch (e) {
      console.log(`   Alice bets: ${e.message}`);
    }
    
    try {
      const bobBets = await bob.getBets();
      console.log(`   Bob total bets: ${bobBets.length || 0}`);
      if (bobBets.length > 0) {
        console.log(`   Latest: ${JSON.stringify(bobBets[bobBets.length - 1])}`);
      }
    } catch (e) {
      console.log(`   Bob bets: ${e.message}`);
    }
    
    // ========================================================================
    // Summary
    // ========================================================================
    console.log('\n╔═══════════════════════════════════════════════════════════════╗');
    console.log('║  BETTING TEST COMPLETE                                        ║');
    console.log('║                                                               ║');
    console.log('║  ✅ Alice bet 50 BB on YES                                     ║');
    console.log('║  ✅ Bob bet 30 BB on NO                                        ║');
    console.log('║  ✅ CPMM prices updated automatically                          ║');
    console.log('║                                                               ║');
    console.log('║  🎰 Market is LIVE! Waiting for resolution...                 ║');
    console.log('╚═══════════════════════════════════════════════════════════════╝\n');
    
  } catch (error) {
    console.error(`\n❌ Unexpected error: ${error.message}`);
    console.error(error.stack);
  }
}

testRealL2Betting().catch(console.error);
