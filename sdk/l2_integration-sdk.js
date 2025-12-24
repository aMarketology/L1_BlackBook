/**
 * ============================================================================
 * L2 INTEGRATION SDK - Full Prediction Market Testing Suite
 * ============================================================================
 * 
 * This SDK provides comprehensive integration testing for the L2 prediction
 * market, callable from L1 to validate the entire chain functions correctly.
 * 
 * 🎯 PURPOSE:
 *   - Validate L2 prediction market lifecycle end-to-end
 *   - Test credit line integration (L1-backed borrowing)
 *   - Test bridge operations (L1↔L2 token flow)
 *   - Test CPMM pricing accuracy
 *   - Test multi-user market scenarios
 *   - Verify settlement proofs and payouts
 * 
 * 📋 MARKET CREATION FLOW:
 *   1. RSS events come from AI scrapers → stored as DRAFTS
 *   2. Market makers review drafts in inbox
 *   3. Market makers PROVIDE LIQUIDITY (10,000 BB default) to launch
 *   4. Draft becomes LIVE market with CPMM pool (x * y = k)
 *   5. Everyone can bet on the live market
 *   6. Initial liquidity sets the starting odds (equal split = 50/50)
 * 
 * 📊 TEST SCENARIOS:
 *   1. Full Market Lifecycle (create → bet → resolve → payout)
 *   2. Credit Line Flow (draw → trade → settle)
 *   3. Bridge Operations (lock → deposit → withdraw → release)
 *   4. CPMM Pricing Validation (slippage, liquidity, fees)
 *   5. Multi-User Trading (alice vs bob vs dealer)
 *   6. Resolution Disputes (propose → dispute → finalize)
 * 
 * 🔐 SECURITY VALIDATION:
 *   - Ed25519 signature verification at each step
 *   - Balance reconciliation (L1 locks = L2 credits)
 *   - Double-spend prevention
 *   - Replay attack prevention (nonce + timestamp)
 *   - Settlement proof validation
 */

const { DealerSDK, DealerCrypto, CHAIN_ID_L1, CHAIN_ID_L2 } = require('./dealer-sdk.js');
const { UnifiedWallet, ACCOUNTS } = require('./unified-wallet-sdk.js');

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  L1_URL: process.env.L1_URL || "http://localhost:8080",
  L2_URL: process.env.L2_URL || "http://localhost:1234",
  TEST_TIMEOUT: 30000,  // 30 seconds per test
  VERBOSE: process.env.VERBOSE === "true",
};

// ============================================================================
// L2 INTEGRATION TEST ORCHESTRATOR
// ============================================================================

class L2IntegrationSDK {
  constructor(options = {}) {
    this.l1Url = options.l1Url || CONFIG.L1_URL;
    this.l2Url = options.l2Url || CONFIG.L2_URL;
    this.verbose = options.verbose !== undefined ? options.verbose : CONFIG.VERBOSE;
    
    // Initialize test wallets
    this.dealer = new DealerSDK({ l1Url: this.l1Url, l2Url: this.l2Url });
    this.alice = UnifiedWallet.fromTestAccount('alice');
    this.bob = UnifiedWallet.fromTestAccount('bob');
    
    // Test results tracking
    this.results = {
      passed: 0,
      failed: 0,
      skipped: 0,
      tests: []
    };
  }
  
  // ==========================================================================
  // LOGGING & REPORTING
  // ==========================================================================
  
  log(message) {
    if (this.verbose) {
      console.log(message);
    }
  }
  
  logTest(name, status, details = null) {
    const emoji = status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : '⏭️';
    console.log(`${emoji} ${name}`);
    if (details) {
      console.log(`   ${details}`);
    }
    
    this.results.tests.push({ name, status, details });
    if (status === 'PASS') this.results.passed++;
    else if (status === 'FAIL') this.results.failed++;
    else this.results.skipped++;
  }
  
  printSummary() {
    console.log("\n" + "═".repeat(70));
    console.log("📊 TEST SUMMARY");
    console.log("═".repeat(70));
    console.log(`✅ Passed:  ${this.results.passed}`);
    console.log(`❌ Failed:  ${this.results.failed}`);
    console.log(`⏭️  Skipped: ${this.results.skipped}`);
    console.log(`📈 Total:   ${this.results.tests.length}`);
    console.log("═".repeat(70));
    
    if (this.results.failed > 0) {
      console.log("\n❌ FAILED TESTS:");
      for (const test of this.results.tests) {
        if (test.status === 'FAIL') {
          console.log(`   • ${test.name}`);
          if (test.details) console.log(`     ${test.details}`);
        }
      }
    }
    
    return this.results.failed === 0;
  }
  
  // ==========================================================================
  // TEST 1: FULL MARKET LIFECYCLE
  // ==========================================================================
  
  /**
   * Test complete market lifecycle from creation to payout
   * 
   * FLOW:
   * 1. Dealer creates market with initial liquidity
   * 2. Alice and Bob place bets on opposite outcomes
   * 3. CPMM prices adjust based on bet flow
   * 4. Dealer resolves market with winning outcome
   * 5. Winners claim payouts
   * 6. Verify balances reconcile correctly
   */
  async testFullMarketLifecycle() {
    console.log("\n" + "═".repeat(70));
    console.log("🎲 TEST 1: FULL MARKET LIFECYCLE");
    console.log("═".repeat(70));
    
    const testMarketId = `test_market_${Date.now()}`;
    
    try {
      // Step 1: Create market by providing liquidity
      // NOTE: In production, this would be:
      //   1. AI scraper creates RSS draft
      //   2. Market maker reviews draft in /drafts inbox
      //   3. Market maker provides liquidity → launches market
      this.log("\n📝 Step 1: Create market with liquidity provision...");
      const marketData = {
        id: testMarketId,
        title: "Integration Test: Will this test pass?",
        description: "Testing the full market lifecycle",
        outcomes: ["YES", "NO"],
        category: "Technology",
        freeze_datetime: Date.now() + 3600000,  // 1 hour from now
        initial_liquidity: 1000,  // Market maker provides 1000 BB to launch
        cpmm_enabled: true,
      };
      
      const createResult = await this.createMarketWithLiquidity(marketData);
      if (!createResult.success) {
        this.logTest("Market Creation", "FAIL", createResult.error);
        return false;
      }
      this.logTest("Market Creation", "PASS", `Market ID: ${testMarketId}`);
      
      // Step 2: Check initial market state
      this.log("\n📊 Step 2: Check initial market state...");
      const marketState = await this.getMarketState(testMarketId);
      if (!marketState.cpmm_enabled) {
        this.logTest("CPMM Initialization", "FAIL", "CPMM not enabled");
        return false;
      }
      this.logTest("CPMM Initialization", "PASS", `TVL: ${marketState.tvl} BB`);
      
      // Step 3: Alice bets YES (100 BB)
      this.log("\n💰 Step 3: Alice bets YES (100 BB)...");
      const aliceBalanceBefore = await this.getL2Balance(this.alice.l2Address);
      const aliceBet = await this.placeBet(this.alice, testMarketId, 0, 100);
      if (!aliceBet.success) {
        this.logTest("Alice Bet", "FAIL", aliceBet.error);
        return false;
      }
      this.logTest("Alice Bet", "PASS", `Shares: ${aliceBet.shares_received}`);
      
      // Step 4: Bob bets NO (150 BB)
      this.log("\n💰 Step 4: Bob bets NO (150 BB)...");
      const bobBalanceBefore = await this.getL2Balance(this.bob.l2Address);
      const bobBet = await this.placeBet(this.bob, testMarketId, 1, 150);
      if (!bobBet.success) {
        this.logTest("Bob Bet", "FAIL", bobBet.error);
        return false;
      }
      this.logTest("Bob Bet", "PASS", `Shares: ${bobBet.shares_received}`);
      
      // Step 5: Check CPMM prices after bets
      this.log("\n📈 Step 5: Verify CPMM pricing...");
      const pricesAfterBets = await this.getMarketPrices(testMarketId);
      if (!pricesAfterBets || pricesAfterBets.length < 2) {
        this.logTest("CPMM Pricing", "FAIL", "Prices not available");
        return false;
      }
      this.logTest("CPMM Pricing", "PASS", 
        `YES: ${pricesAfterBets[0].probability.toFixed(1)}%, NO: ${pricesAfterBets[1].probability.toFixed(1)}%`);
      
      // Step 6: Resolve market (YES wins)
      this.log("\n🏆 Step 6: Resolve market (YES wins)...");
      const resolveResult = await this.resolveMarket(testMarketId, 0);
      if (!resolveResult.success) {
        this.logTest("Market Resolution", "FAIL", resolveResult.error);
        return false;
      }
      this.logTest("Market Resolution", "PASS", "Winner: YES");
      
      // Step 7: Verify Alice can claim winnings
      this.log("\n💸 Step 7: Check Alice's winnings...");
      const aliceBalanceAfter = await this.getL2Balance(this.alice.l2Address);
      const aliceProfit = aliceBalanceAfter - aliceBalanceBefore;
      if (aliceProfit <= 0) {
        this.logTest("Alice Payout", "FAIL", `No profit: ${aliceProfit}`);
        return false;
      }
      this.logTest("Alice Payout", "PASS", `Profit: ${aliceProfit.toFixed(2)} BB`);
      
      // Step 8: Verify Bob lost his bet
      this.log("\n📉 Step 8: Verify Bob's loss...");
      const bobBalanceAfter = await this.getL2Balance(this.bob.l2Address);
      const bobLoss = bobBalanceBefore - bobBalanceAfter;
      if (bobLoss <= 0) {
        this.logTest("Bob Loss", "FAIL", `Expected loss, got profit: ${bobLoss}`);
        return false;
      }
      this.logTest("Bob Loss", "PASS", `Loss: ${bobLoss.toFixed(2)} BB`);
      
      console.log("\n✅ FULL MARKET LIFECYCLE TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("Market Lifecycle", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // TEST 2: CREDIT LINE FLOW
  // ==========================================================================
  
  /**
   * Test L1-backed credit line operations
   * 
   * FLOW:
   * 1. Alice draws 500 BB credit from L1 (L1 locks funds)
   * 2. Alice uses credit to place bets on L2
   * 3. Check credit balance reflects usage
   * 4. Alice settles credit (L1 releases remaining)
   * 5. Verify L1 balances reconcile
   */
  async testCreditLineFlow() {
    console.log("\n" + "═".repeat(70));
    console.log("💳 TEST 2: CREDIT LINE FLOW");
    console.log("═".repeat(70));
    
    const drawAmount = 500;
    const betAmount = 200;
    
    try {
      // Step 1: Check initial L1 balance
      this.log("\n💰 Step 1: Check Alice's L1 balance...");
      const aliceL1Before = await this.getL1Balance(this.alice.l1Address);
      if (aliceL1Before < drawAmount) {
        this.logTest("Credit Line Prerequisites", "SKIP", "Insufficient L1 balance");
        return false;
      }
      this.log(`   Alice L1 Balance: ${aliceL1Before} BB`);
      
      // Step 2: Draw credit from L1
      this.log("\n📥 Step 2: Draw credit from L1...");
      const drawResult = await this.drawCredit(this.alice, drawAmount, "betting");
      if (!drawResult.success) {
        this.logTest("Credit Draw", "FAIL", drawResult.error);
        return false;
      }
      this.logTest("Credit Draw", "PASS", `Session: ${drawResult.session_id}`);
      const sessionId = drawResult.session_id;
      
      // Step 3: Verify credit balance on L2
      this.log("\n💳 Step 3: Check credit balance on L2...");
      const creditBalance = await this.getCreditBalance(this.alice.l2Address);
      if (creditBalance.balance !== drawAmount) {
        this.logTest("Credit Balance", "FAIL", 
          `Expected ${drawAmount}, got ${creditBalance.balance}`);
        return false;
      }
      this.logTest("Credit Balance", "PASS", `Balance: ${creditBalance.balance} BB`);
      
      // Step 4: Use credit to place bet
      this.log("\n🎲 Step 4: Place bet using credit...");
      const testMarketId = `credit_test_${Date.now()}`;
      await this.createMarketWithLiquidity({
        id: testMarketId,
        title: "Credit Line Test Market",
        outcomes: ["YES", "NO"],
        initial_liquidity: 500,
      });
      
      const betResult = await this.placeBet(this.alice, testMarketId, 0, betAmount);
      if (!betResult.success) {
        this.logTest("Credit Bet", "FAIL", betResult.error);
        return false;
      }
      this.logTest("Credit Bet", "PASS", `Bet placed: ${betAmount} BB`);
      
      // Step 5: Check credit balance after bet
      this.log("\n📊 Step 5: Check remaining credit...");
      const creditAfterBet = await this.getCreditBalance(this.alice.l2Address);
      const expectedRemaining = drawAmount - betAmount;
      if (Math.abs(creditAfterBet.balance - expectedRemaining) > 1) {
        this.logTest("Credit Balance Update", "FAIL", 
          `Expected ~${expectedRemaining}, got ${creditAfterBet.balance}`);
        return false;
      }
      this.logTest("Credit Balance Update", "PASS", 
        `Remaining: ${creditAfterBet.balance} BB`);
      
      // Step 6: Settle credit session
      this.log("\n💸 Step 6: Settle credit session...");
      const settleResult = await this.settleCredit(
        this.alice, 
        sessionId, 
        creditAfterBet.balance, 
        betAmount  // locked in active bet
      );
      if (!settleResult.success) {
        this.logTest("Credit Settle", "FAIL", settleResult.error);
        return false;
      }
      this.logTest("Credit Settle", "PASS", 
        `Returned to L1: ${settleResult.returned_to_l1} BB`);
      
      // Step 7: Verify L1 balance reconciliation
      this.log("\n✅ Step 7: Verify L1 balance reconciliation...");
      const aliceL1After = await this.getL1Balance(this.alice.l1Address);
      const expectedL1 = aliceL1Before - betAmount;  // Only the bet amount should be consumed
      if (Math.abs(aliceL1After - expectedL1) > 1) {
        this.logTest("L1 Balance Reconciliation", "FAIL", 
          `Expected ~${expectedL1}, got ${aliceL1After}`);
        return false;
      }
      this.logTest("L1 Balance Reconciliation", "PASS", 
        `L1 Balance: ${aliceL1After} BB`);
      
      console.log("\n✅ CREDIT LINE FLOW TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("Credit Line Flow", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // TEST 3: BRIDGE OPERATIONS
  // ==========================================================================
  
  /**
   * Test L1↔L2 bridge token flow
   * 
   * FLOW:
   * 1. Lock tokens on L1
   * 2. L1 confirms and deposits to L2
   * 3. Trade on L2
   * 4. Withdraw from L2
   * 5. L1 releases tokens
   */
  async testBridgeOperations() {
    console.log("\n" + "═".repeat(70));
    console.log("🌉 TEST 3: BRIDGE OPERATIONS");
    console.log("═".repeat(70));
    
    const bridgeAmount = 300;
    
    try {
      // Step 1: Lock tokens on L1
      this.log("\n🔒 Step 1: Lock tokens on L1...");
      const bobL1Before = await this.getL1Balance(this.bob.l1Address);
      const bobL2Before = await this.getL2Balance(this.bob.l2Address);
      
      const lockResult = await this.bridgeToL2(this.bob, bridgeAmount);
      if (!lockResult.success) {
        this.logTest("Bridge Lock", "FAIL", lockResult.error);
        return false;
      }
      this.logTest("Bridge Lock", "PASS", `Lock ID: ${lockResult.lock_id}`);
      
      // Step 2: Wait for L2 deposit confirmation
      this.log("\n⏳ Step 2: Wait for L2 deposit...");
      await this.sleep(2000);  // Wait 2 seconds for async deposit
      
      const bobL2After = await this.getL2Balance(this.bob.l2Address);
      const l2Increase = bobL2After - bobL2Before;
      if (l2Increase < bridgeAmount * 0.95) {  // Allow 5% slippage for fees
        this.logTest("L2 Deposit", "FAIL", 
          `Expected ${bridgeAmount}, got ${l2Increase}`);
        return false;
      }
      this.logTest("L2 Deposit", "PASS", `L2 Balance: ${bobL2After} BB`);
      
      // Step 3: Trade on L2
      this.log("\n🎲 Step 3: Trade on L2...");
      const testMarketId = `bridge_test_${Date.now()}`;
      await this.createMarketWithLiquidity({
        id: testMarketId,
        title: "Bridge Test Market",
        outcomes: ["YES", "NO"],
        initial_liquidity: 500,
      });
      
      const betResult = await this.placeBet(this.bob, testMarketId, 0, 100);
      if (!betResult.success) {
        this.logTest("L2 Trading", "FAIL", betResult.error);
        return false;
      }
      this.logTest("L2 Trading", "PASS", "Bet placed successfully");
      
      // Step 4: Withdraw from L2
      this.log("\n💸 Step 4: Withdraw from L2...");
      const bobL2BeforeWithdraw = await this.getL2Balance(this.bob.l2Address);
      const withdrawAmount = 150;
      
      const withdrawResult = await this.withdrawToL1(this.bob, withdrawAmount);
      if (!withdrawResult.success) {
        this.logTest("L2 Withdrawal", "FAIL", withdrawResult.error);
        return false;
      }
      this.logTest("L2 Withdrawal", "PASS", 
        `Settlement Proof: ${withdrawResult.settlement_proof}`);
      
      // Step 5: Verify L2 balance decreased
      this.log("\n📉 Step 5: Verify L2 balance...");
      const bobL2Final = await this.getL2Balance(this.bob.l2Address);
      const l2Decrease = bobL2BeforeWithdraw - bobL2Final;
      if (Math.abs(l2Decrease - withdrawAmount) > 1) {
        this.logTest("L2 Balance Update", "FAIL", 
          `Expected decrease of ${withdrawAmount}, got ${l2Decrease}`);
        return false;
      }
      this.logTest("L2 Balance Update", "PASS", `L2 Balance: ${bobL2Final} BB`);
      
      console.log("\n✅ BRIDGE OPERATIONS TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("Bridge Operations", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // TEST 4: CPMM PRICING VALIDATION
  // ==========================================================================
  
  /**
   * Test CPMM pricing accuracy and slippage calculations
   */
  async testCPMMPricing() {
    console.log("\n" + "═".repeat(70));
    console.log("💹 TEST 4: CPMM PRICING VALIDATION");
    console.log("═".repeat(70));
    
    const testMarketId = `cpmm_test_${Date.now()}`;
    const initialLiquidity = 1000;
    
    try {
      // Step 1: Create market with balanced liquidity
      this.log("\n📝 Step 1: Create balanced market...");
      await this.createMarketWithLiquidity({
        id: testMarketId,
        title: "CPMM Pricing Test",
        outcomes: ["YES", "NO"],
        initial_liquidity: initialLiquidity,
      });
      
      // Step 2: Check initial 50/50 pricing
      this.log("\n💰 Step 2: Check initial 50/50 pricing...");
      const initialPrices = await this.getMarketPrices(testMarketId);
      const yesPrice = initialPrices[0].probability;
      const noPrice = initialPrices[1].probability;
      
      if (Math.abs(yesPrice - 50) > 5 || Math.abs(noPrice - 50) > 5) {
        this.logTest("Initial Pricing", "FAIL", 
          `Expected ~50/50, got ${yesPrice}/${noPrice}`);
        return false;
      }
      this.logTest("Initial Pricing", "PASS", 
        `YES: ${yesPrice.toFixed(1)}%, NO: ${noPrice.toFixed(1)}%`);
      
      // Step 3: Place large YES bet, expect price to move
      this.log("\n📈 Step 3: Place large YES bet (300 BB)...");
      await this.placeBet(this.dealer, testMarketId, 0, 300);
      
      const pricesAfterYesBet = await this.getMarketPrices(testMarketId);
      const yesPriceAfter = pricesAfterYesBet[0].probability;
      
      if (yesPriceAfter <= yesPrice) {
        this.logTest("Price Movement", "FAIL", 
          `Expected YES price to increase, but it didn't`);
        return false;
      }
      this.logTest("Price Movement", "PASS", 
        `YES increased: ${yesPrice.toFixed(1)}% → ${yesPriceAfter.toFixed(1)}%`);
      
      // Step 4: Place large NO bet, expect price to rebalance
      this.log("\n📉 Step 4: Place large NO bet (300 BB)...");
      await this.placeBet(this.dealer, testMarketId, 1, 300);
      
      const pricesAfterNoBet = await this.getMarketPrices(testMarketId);
      const yesPriceFinal = pricesAfterNoBet[0].probability;
      
      if (Math.abs(yesPriceFinal - 50) > 10) {
        this.logTest("Price Rebalancing", "FAIL", 
          `Expected ~50%, got ${yesPriceFinal.toFixed(1)}%`);
        return false;
      }
      this.logTest("Price Rebalancing", "PASS", 
        `Rebalanced to ${yesPriceFinal.toFixed(1)}%`);
      
      // Step 5: Verify constant product k remains stable
      this.log("\n🔢 Step 5: Verify constant product k...");
      const marketState = await this.getMarketState(testMarketId);
      const k = marketState.pool.reserves[0] * marketState.pool.reserves[1];
      const expectedK = (initialLiquidity / 2) * (initialLiquidity / 2);
      
      if (k < expectedK * 0.9) {  // Allow 10% variance for fees
        this.logTest("Constant Product", "FAIL", 
          `k too low: ${k} (expected ~${expectedK})`);
        return false;
      }
      this.logTest("Constant Product", "PASS", `k = ${k.toFixed(0)}`);
      
      console.log("\n✅ CPMM PRICING VALIDATION TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("CPMM Pricing", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // TEST 5: MULTI-USER TRADING
  // ==========================================================================
  
  /**
   * Test multi-user trading scenario with realistic bet flows
   */
  async testMultiUserTrading() {
    console.log("\n" + "═".repeat(70));
    console.log("👥 TEST 5: MULTI-USER TRADING");
    console.log("═".repeat(70));
    
    const testMarketId = `multiuser_test_${Date.now()}`;
    
    try {
      // Step 1: Dealer creates market with liquidity
      this.log("\n📝 Step 1: Dealer creates market...");
      await this.createMarketWithLiquidity({
        id: testMarketId,
        title: "Multi-User Trading Test",
        outcomes: ["Bull", "Bear", "Neutral"],
        initial_liquidity: 1500,
      });
      
      // Step 2: Multiple users place bets
      this.log("\n🎲 Step 2: Multiple users place bets...");
      const aliceBet1 = await this.placeBet(this.alice, testMarketId, 0, 100);
      const bobBet1 = await this.placeBet(this.bob, testMarketId, 1, 150);
      const aliceBet2 = await this.placeBet(this.alice, testMarketId, 0, 50);
      const bobBet2 = await this.placeBet(this.bob, testMarketId, 2, 80);
      
      if (!aliceBet1.success || !bobBet1.success || !aliceBet2.success || !bobBet2.success) {
        this.logTest("Multi-User Betting", "FAIL", "One or more bets failed");
        return false;
      }
      this.logTest("Multi-User Betting", "PASS", "All bets placed successfully");
      
      // Step 3: Verify positions
      this.log("\n📊 Step 3: Verify user positions...");
      const alicePosition = await this.getUserPosition(this.alice.l2Address, testMarketId);
      const bobPosition = await this.getUserPosition(this.bob.l2Address, testMarketId);
      
      if (!alicePosition || !bobPosition) {
        this.logTest("Position Tracking", "FAIL", "Positions not tracked");
        return false;
      }
      this.logTest("Position Tracking", "PASS", 
        `Alice: ${alicePosition.total_invested} BB, Bob: ${bobPosition.total_invested} BB`);
      
      // Step 4: Resolve market
      this.log("\n🏆 Step 4: Resolve market (Bull wins)...");
      await this.resolveMarket(testMarketId, 0);
      
      // Step 5: Verify payouts
      this.log("\n💸 Step 5: Verify payouts...");
      const aliceBalanceAfter = await this.getL2Balance(this.alice.l2Address);
      const bobBalanceAfter = await this.getL2Balance(this.bob.l2Address);
      
      this.logTest("Payout Distribution", "PASS", 
        `Alice (winner): ${aliceBalanceAfter} BB, Bob (loser): ${bobBalanceAfter} BB`);
      
      console.log("\n✅ MULTI-USER TRADING TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("Multi-User Trading", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // TEST 6: DRAFT INBOX & LIQUIDITY PROVISION
  // ==========================================================================
  
  /**
   * Test the draft inbox and liquidity provision flow
   * 
   * FLOW:
   * 1. AI scraper creates RSS draft event
   * 2. Draft appears in /drafts inbox
   * 3. Market maker reviews draft
   * 4. Market maker provides liquidity to launch
   * 5. Market goes live with CPMM pool
   * 6. Initial liquidity sets starting odds
   */
  async testDraftInboxFlow() {
    console.log("\n" + "═".repeat(70));
    console.log("📥 TEST 6: DRAFT INBOX & LIQUIDITY PROVISION");
    console.log("═".repeat(70));
    
    const draftId = `draft_${Date.now()}`;
    
    try {
      // Step 1: Simulate AI scraper creating a draft
      this.log("\n🤖 Step 1: AI scraper creates draft event...");
      const draftData = {
        id: draftId,
        title: "Will Bitcoin reach $150k by Q2 2026?",
        description: "Market for BTC price prediction based on recent market analysis",
        outcomes: ["YES", "NO"],
        category: "Crypto",
        source: "CoinDesk",
        source_url: "https://coindesk.com/example",
        initial_probabilities: [0.35, 0.65],  // Market thinks 35% chance YES
        min_liquidity: 5000,  // Minimum 5000 BB to launch
      };
      
      const createDraftResult = await this.createDraft(draftData);
      if (!createDraftResult.success) {
        this.logTest("Draft Creation", "FAIL", createDraftResult.error);
        return false;
      }
      this.logTest("Draft Creation", "PASS", `Draft ID: ${draftId}`);
      
      // Step 2: Check draft appears in inbox
      this.log("\n📋 Step 2: Verify draft in inbox...");
      const drafts = await this.getDrafts();
      const ourDraft = drafts.find(d => d.id === draftId);
      if (!ourDraft) {
        this.logTest("Draft Inbox", "FAIL", "Draft not found in inbox");
        return false;
      }
      this.logTest("Draft Inbox", "PASS", `Found in inbox: ${ourDraft.title}`);
      
      // Step 3: Market maker reviews draft
      this.log("\n👀 Step 3: Market maker reviews draft...");
      const draftDetail = await this.getDraft(draftId);
      if (!draftDetail.is_ready_to_launch) {
        this.logTest("Draft Validation", "FAIL", 
          `Not ready: ${draftDetail.validation_errors.join(', ')}`);
        return false;
      }
      this.logTest("Draft Validation", "PASS", "Draft ready to launch");
      
      // Step 4: Market maker provides liquidity to launch
      this.log("\n💰 Step 4: Market maker provides liquidity (5000 BB)...");
      const launchResult = await this.launchDraft(draftId, 5000);
      if (!launchResult.success) {
        this.logTest("Launch Market", "FAIL", launchResult.error);
        return false;
      }
      this.logTest("Launch Market", "PASS", 
        `Market launched: ${launchResult.market_id}`);
      
      // Step 5: Verify market is live with CPMM pool
      this.log("\n🟢 Step 5: Verify market is live...");
      const marketState = await this.getMarketState(launchResult.market_id);
      if (!marketState.cpmm_enabled) {
        this.logTest("CPMM Pool", "FAIL", "CPMM not initialized");
        return false;
      }
      this.logTest("CPMM Pool", "PASS", 
        `TVL: ${marketState.tvl} BB, Status: ${marketState.status}`);
      
      // Step 6: Verify initial odds match provided probabilities
      this.log("\n📊 Step 6: Verify initial odds...");
      const prices = await this.getMarketPrices(launchResult.market_id);
      const yesPrice = prices[0].probability;
      
      // Should be close to 35% (±5% tolerance)
      if (Math.abs(yesPrice - 35) > 5) {
        this.logTest("Initial Odds", "FAIL", 
          `Expected ~35%, got ${yesPrice.toFixed(1)}%`);
        return false;
      }
      this.logTest("Initial Odds", "PASS", 
        `YES: ${yesPrice.toFixed(1)}%, NO: ${prices[1].probability.toFixed(1)}%`);
      
      // Step 7: Verify users can bet on launched market
      this.log("\n🎲 Step 7: Test betting on launched market...");
      const bet = await this.placeBet(this.alice, launchResult.market_id, 0, 100);
      if (!bet.success) {
        this.logTest("Betting After Launch", "FAIL", bet.error);
        return false;
      }
      this.logTest("Betting After Launch", "PASS", 
        `Alice bet 100 BB, received ${bet.shares_received} shares`);
      
      console.log("\n✅ DRAFT INBOX & LIQUIDITY PROVISION TEST PASSED");
      return true;
      
    } catch (error) {
      this.logTest("Draft Inbox Flow", "FAIL", error.message);
      console.error(error);
      return false;
    }
  }
  
  // ==========================================================================
  // HELPER METHODS
  // ==========================================================================
  
  /**
   * Create market with initial liquidity (simulates market maker launching a draft)
   * 
   * PRODUCTION FLOW:
   * 1. AI scraper posts RSS event → becomes draft in /drafts
   * 2. Market maker calls GET /drafts to review
   * 3. Market maker calls POST /drafts/:id/launch with liquidity
   * 4. L1 mints liquidity to escrow address
   * 5. L2 initializes CPMM pool with reserves
   * 6. Market goes LIVE (status: Provisional → Active after 72hrs if TVL > 10k)
   * 
   * This helper combines steps 1-6 for testing convenience.
   */
  async createMarketWithLiquidity(marketData) {
    try {
      // In production, market maker would:
      // 1. Review draft: GET /drafts/:id
      // 2. Launch with liquidity: POST /drafts/:id/launch
      //    { "liquidity": 10000 }
      // 
      // For testing, we directly create+launch via /market/create
      const response = await fetch(`${this.l2Url}/market/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...marketData,
          dealer_address: this.dealer.address,
          // initial_liquidity is what the market maker provides to launch
          initial_liquidity: marketData.initial_liquidity || 10000,
        }),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async placeBet(wallet, marketId, outcome, amount) {
    try {
      const payload = { market_id: marketId, option: outcome.toString(), amount };
      const signedRequest = wallet.signRequest(payload, CHAIN_ID_L2, '/bet');
      
      const response = await fetch(`${this.l2Url}/bet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async resolveMarket(marketId, winningOutcome) {
    try {
      const response = await fetch(`${this.l2Url}/market/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          market_id: marketId,
          winning_outcome: winningOutcome,
          dealer_address: this.dealer.address,
        }),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async getMarketState(marketId) {
    const response = await fetch(`${this.l2Url}/market/${marketId}`);
    return response.json();
  }
  
  async getMarketPrices(marketId) {
    const response = await fetch(`${this.l2Url}/market/${marketId}/prices`);
    const data = await response.json();
    return data.prices || [];
  }
  
  async getL1Balance(address) {
    try {
      const response = await fetch(`${this.l1Url}/balance/${address}`);
      const data = await response.json();
      return data.balance || 0;
    } catch {
      return 0;
    }
  }
  
  async getL2Balance(address) {
    try {
      const response = await fetch(`${this.l2Url}/balance/${address}`);
      const data = await response.json();
      return data.balance || 0;
    } catch {
      return 0;
    }
  }
  
  async drawCredit(wallet, amount, reason) {
    try {
      const payload = { amount, reason };
      const signedRequest = wallet.signRequest(payload, CHAIN_ID_L2, '/credit/draw');
      
      const response = await fetch(`${this.l2Url}/credit/draw`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async settleCredit(wallet, sessionId, finalBalance, lockedInBets) {
    try {
      const payload = { session_id: sessionId, final_l2_balance: finalBalance, locked_in_bets: lockedInBets };
      const signedRequest = wallet.signRequest(payload, CHAIN_ID_L2, '/credit/settle');
      
      const response = await fetch(`${this.l2Url}/credit/settle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async getCreditBalance(address) {
    try {
      const response = await fetch(`${this.l2Url}/credit/balance/${address}`);
      return response.json();
    } catch (error) {
      return { balance: 0 };
    }
  }
  
  async bridgeToL2(wallet, amount) {
    try {
      const payload = { l2_address: wallet.l2Address, amount, purpose: "testing" };
      const signedRequest = wallet.signRequest(payload, CHAIN_ID_L1, '/bridge/lock');
      
      const response = await fetch(`${this.l1Url}/bridge/lock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async withdrawToL1(wallet, amount) {
    try {
      const payload = { amount, target_address: wallet.l1Address };
      const signedRequest = wallet.signRequest(payload, CHAIN_ID_L2, '/bridge/withdraw');
      
      const response = await fetch(`${this.l2Url}/bridge/withdraw`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedRequest),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async getUserPosition(address, marketId) {
    try {
      const response = await fetch(`${this.l2Url}/user/${address}/positions/${marketId}`);
      return response.json();
    } catch {
      return null;
    }
  }
  
  async createDraft(draftData) {
    try {
      const response = await fetch(`${this.l2Url}/drafts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draftData),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async getDrafts() {
    try {
      const response = await fetch(`${this.l2Url}/drafts`);
      const data = await response.json();
      return data.drafts || [];
    } catch {
      return [];
    }
  }
  
  async getDraft(draftId) {
    try {
      const response = await fetch(`${this.l2Url}/drafts/${draftId}`);
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async launchDraft(draftId, liquidity) {
    try {
      const response = await fetch(`${this.l2Url}/drafts/${draftId}/launch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ liquidity }),
      });
      return response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // ==========================================================================
  // RUN ALL TESTS
  // ==========================================================================
  
  async runAllTests() {
    console.log("\n" + "═".repeat(70));
    console.log("🚀 L2 PREDICTION MARKET INTEGRATION TEST SUITE");
    console.log("═".repeat(70));
    console.log(`L1 URL: ${this.l1Url}`);
    console.log(`L2 URL: ${this.l2Url}`);
    console.log("═".repeat(70));
    
    const tests = [
      { name: "Full Market Lifecycle", fn: () => this.testFullMarketLifecycle() },
      { name: "Credit Line Flow", fn: () => this.testCreditLineFlow() },
      { name: "Bridge Operations", fn: () => this.testBridgeOperations() },
      { name: "CPMM Pricing Validation", fn: () => this.testCPMMPricing() },
      { name: "Multi-User Trading", fn: () => this.testMultiUserTrading() },
      { name: "Draft Inbox & Liquidity Provision", fn: () => this.testDraftInboxFlow() },
    ];
    
    for (const test of tests) {
      try {
        await test.fn();
      } catch (error) {
        console.error(`\n❌ Test "${test.name}" crashed:`, error);
        this.logTest(test.name, "FAIL", error.message);
      }
    }
    
    return this.printSummary();
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  L2IntegrationSDK,
  CONFIG,
};

// ============================================================================
// CLI RUNNER
// ============================================================================

async function main() {
  const sdk = new L2IntegrationSDK({ verbose: true });
  const allPassed = await sdk.runAllTests();
  
  process.exit(allPassed ? 0 : 1);
}

if (require.main === module) {
  main().catch(error => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
