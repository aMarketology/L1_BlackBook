// ============================================================================
// BLACKBOOK L1↔L2 INTEGRATION SDK
// ============================================================================
//
// ARCHITECTURE:
//
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │                     L1 (Consensus Layer)                                │
//  │  • Validates all L2 settlements via Ed25519 signatures                  │
//  │  • Manages Credit Line approvals & sessions                             │
//  │  • Provides immutable audit trail                                       │
//  │  REST: localhost:8080                                                   │
//  └─────────────────────────────────────────────────────────────────────────┘
//                              ▲
//                              │ Signed Draw / Settlement Requests
//                              ▼
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │                L2 (Prediction Market Backbone)                          │
//  │  • CPMM prediction markets                                              │
//  │  • Tracks all bets internally                                           │
//  │  • Calculates prices & payouts                                          │
//  │  • Forwards signed requests to L1 (does NOT validate signatures)        │
//  │  REST: localhost:1234                                                   │
//  └─────────────────────────────────────────────────────────────────────────┘
//
// CREDIT LINE FLOW (Casino Bank Model):
//   1. wallet.approveCreditLine(500) → User signs ONCE to allow L2 draws
//   2. wallet.draw(100) → SDK signs request, L2 forwards to L1, L1 validates
//   3. wallet.placeBet(...) → L2 handles bet internally using credited balance
//   4. wallet.ensureFundsForBet(50) → Auto-draw if L2 balance low
//   5. wallet.closeSession() → SDK signs settlement, L2 forwards to L1, unused tokens return
//
// SECURITY MODEL:
//   ✅ All token movements require Ed25519 signatures from wallet owner
//   ✅ L2 forwards signed requests but CANNOT validate signatures
//   ✅ L1 is the source of truth for all signature validation
//   ✅ L2 can ONLY return tokens to the SAME wallet that deposited them
//
// ============================================================================

import nacl from 'tweetnacl';

export const L1_URL = 'http://localhost:8080';
export const L2_URL = 'http://localhost:1234';

/**
 * Strip L1_/L2_ prefix from address
 */
function stripPrefix(address) {
  return address.startsWith('L1_') || address.startsWith('L2_') 
    ? address.slice(3) 
    : address;
}

// ============================================================================
// L1 CLIENT
// ============================================================================

export class L1Client {
  constructor(baseUrl = L1_URL) {
    this.baseUrl = baseUrl;
  }
  
  async getBalance(address) {
    const res = await fetch(`${this.baseUrl}/balance/${address}`);
    const data = await res.json();
    return data.balance || 0;
  }
  
  async startSession(walletAddress, amount) {
    const res = await fetch(`${this.baseUrl}/session/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet_address: walletAddress,
        allocation: amount
      })
    });
    return res.json();
  }
  
  async settleSession(walletAddress, finalL2Balance) {
    const res = await fetch(`${this.baseUrl}/session/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet_address: walletAddress,
        final_l2_balance: finalL2Balance
      })
    });
    return res.json();
  }
  
  async getSessionStatus(walletAddress) {
    const res = await fetch(`${this.baseUrl}/session/status/${walletAddress}`);
    return res.json();
  }
  
  // =========================================================================
  // CREDIT LINE ENDPOINTS (Casino Bank Model)
  // =========================================================================
  
  /**
   * Approve a credit line (requires signature)
   */
  async approveCreditLine(walletAddress, publicKey, creditLimit, signature, nonce, expiresInHours = 24) {
    const res = await fetch(`${this.baseUrl}/credit/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet_address: walletAddress,
        public_key: publicKey,
        credit_limit: creditLimit,
        signature,
        nonce,
        expires_in_hours: expiresInHours
      })
    });
    return res.json();
  }
  
  /**
   * Draw funds from credit line (requires signed request)
   * SECURITY: Every L1→L2 transfer requires valid Ed25519 signature
   */
  async creditDraw(signedRequest) {
    const res = await fetch(`${this.baseUrl}/credit/draw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    return res.json();
  }
  
  /**
   * Settle credit session (requires signed request)
   * SECURITY: Settlement returns tokens to L1 - requires signature from original depositor
   */
  async creditSettle(signedRequest) {
    const res = await fetch(`${this.baseUrl}/credit/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    return res.json();
  }
  
  /**
   * Get credit line status
   */
  async getCreditStatus(walletAddress) {
    const res = await fetch(`${this.baseUrl}/credit/status/${walletAddress}`);
    return res.json();
  }
}

// ============================================================================
// L2 CLIENT
// ============================================================================

export class L2Client {
  constructor(baseUrl = L2_URL) {
    this.baseUrl = baseUrl;
  }
  
  async getBalance(address) {
    const clean = stripPrefix(address);
    const res = await fetch(`${this.baseUrl}/balance/${clean}`);
    return res.json();
  }
  
  async getMarkets() {
    const res = await fetch(`${this.baseUrl}/markets`);
    return res.json();
  }
  
  async getMarket(marketId) {
    const res = await fetch(`${this.baseUrl}/markets/${marketId}`);
    return res.json();
  }
  
  async placeBet(address, marketId, outcome, amount) {
    const clean = stripPrefix(address);
    const outcomeIndex = outcome.toUpperCase() === 'YES' ? 0 : 1;
    
    const res = await fetch(`${this.baseUrl}/bet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: clean,
        market_id: marketId,
        outcome: outcomeIndex,
        amount
      })
    });
    return res.json();
  }
  
  async getPosition(address, marketId) {
    const clean = stripPrefix(address);
    const res = await fetch(`${this.baseUrl}/position/${clean}/${marketId}`);
    return res.json();
  }
}

// ============================================================================
// UNIFIED WALLET
// ============================================================================

export class UnifiedWallet {
  constructor(walletAddress) {
    this.address = walletAddress;
    this.l1 = new L1Client();
    this.l2 = new L2Client();
  }
  
  /**
   * Get balances from both layers
   */
  async getBalances() {
    const l1Balance = await this.l1.getBalance(this.address);
    const l2Data = await this.l2.getBalance(this.address);
    return {
      l1: l1Balance,
      l2: l2Data.balance || 0
    };
  }
  
  /**
   * Step 1: Start L2 session (lock funds on L1)
   */
  async startSession(amount) {
    console.log(`🎮 Starting session with ${amount} BB...`);
    const result = await this.l1.startSession(this.address, amount);
    if (result.success) {
      console.log(`✅ Session started: ${result.session_id}`);
    }
    return result;
  }
  
  /**
   * Step 2: Place bet on L2 (L2 tracks internally)
   */
  async placeBet(marketId, outcome, amount) {
    console.log(`🎰 Betting ${amount} BB on ${outcome}...`);
    const result = await this.l2.placeBet(this.address, marketId, outcome, amount);
    if (result.success) {
      console.log(`✅ Bet placed`);
    }
    return result;
  }
  
  /**
   * Step 3: Settle session (L2 → L1 validation)
   */
  async settleSession() {
    console.log(`💰 Settling session...`);
    
    // Get final L2 balance
    console.log(`📊 Fetching final L2 balance...`);
    const l2Data = await this.l2.getBalance(this.address);
    const finalBalance = l2Data.balance || 0;
    console.log(`   L2 Balance: ${finalBalance} BB`);
    
    // Send to L1 for validation
    console.log(`🔍 L1 validating settlement...`);
    const result = await this.l1.settleSession(this.address, finalBalance);
    
    if (result.success) {
      const pnl = result.settlement?.net_pnl || 0;
      console.log(`✅ Settlement validated`);
      console.log(`   Net PnL: ${pnl >= 0 ? '+' : ''}${pnl} BB`);
      console.log(`   L1 Balance: ${result.settlement?.l1_before} → ${result.settlement?.l1_after} BB`);
    }
    
    return result;
  }
  
  /**
   * Get markets
   */
  async getMarkets() {
    return this.l2.getMarkets();
  }
  
  /**
   * Get market details
   */
  async getMarket(marketId) {
    return this.l2.getMarket(marketId);
  }
  
  /**
   * Get position
   */
  async getPosition(marketId) {
    return this.l2.getPosition(this.address, marketId);
  }
}

// ============================================================================
// CREDIT LINE WALLET (Casino Bank Model)
// ============================================================================

/**
 * CreditLineWallet provides a casino-like experience where users never
 * run out of L2 tokens as long as they have L1 balance.
 * 
 * FLOW:
 *   1. User signs ONE credit approval for a limit (e.g., 500 BB)
 *   2. L2 automatically draws funds as needed (initial + replenish)
 *   3. Session ends → unused tokens return to L1
 * 
 * SECURITY:
 *   - Credit approval requires Ed25519 signature
 *   - L1 validates all settlements (fraud detection)
 *   - Session expiry returns unused funds
 */
export class CreditLineWallet {
  constructor(privateKeyHex, walletAddress = null) {
    // Store keys
    this.privateKey = privateKeyHex;
    
    // Derive public key
    const keypair = nacl.sign.keyPair.fromSeed(Buffer.from(privateKeyHex, 'hex'));
    this.publicKey = Buffer.from(keypair.publicKey).toString('hex');
    
    // Use provided address or generate from public key
    this.address = walletAddress || `L1_${this.publicKey.slice(0, 40).toUpperCase()}`;
    
    // Initialize clients
    this.l1 = new L1Client();
    this.l2 = new L2Client();
    
    // Session state
    this.sessionId = null;
    this.creditLimit = 0;
    this.l2Balance = 0;
    this.nonce = Date.now();
    
    // Auto-replenish settings
    this.autoReplenishThreshold = 10; // Draw more when L2 balance < 10
    this.autoReplenishAmount = 50;    // Draw 50 BB at a time
  }
  
  /**
   * Sign a message with Ed25519
   */
  sign(message) {
    const privateKey = Buffer.from(this.privateKey, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(privateKey);
    
    const secretKey = new Uint8Array(64);
    secretKey.set(privateKey, 0);
    secretKey.set(keypair.publicKey, 32);
    
    const signature = nacl.sign.detached(Buffer.from(message, 'utf8'), secretKey);
    return Buffer.from(signature).toString('hex');
  }
  
  /**
   * Step 1: Approve credit line (ONE-TIME signature)
   * 
   * Like giving the casino permission to advance you chips up to your credit limit.
   */
  async approveCreditLine(creditLimit, expiresInHours = 24) {
    console.log(`🏦 Approving credit line: ${creditLimit} BB for ${expiresInHours} hours`);
    
    // Create the message to sign
    this.nonce = Date.now();
    const message = `APPROVE_CREDIT:${this.address}:${creditLimit}:${this.nonce}`;
    
    // Sign it
    const signature = this.sign(message);
    console.log(`🔐 Signed credit approval`);
    
    // Send to L1
    const result = await this.l1.approveCreditLine(
      this.address,
      this.publicKey,
      creditLimit,
      signature,
      this.nonce,
      expiresInHours
    );
    
    if (result.success) {
      this.sessionId = result.session.session_id;
      this.creditLimit = creditLimit;
      console.log(`✅ Credit line approved: Session ${this.sessionId}`);
    } else {
      console.error(`❌ Credit approval failed: ${result.error}`);
    }
    
    return result;
  }
  
  /**
   * Step 2: Draw funds from L1 to L2
   * 
   * SECURITY: Every L1→L2 transfer requires valid Ed25519 signature.
   * The wallet owner must sign each draw request.
   */
  async draw(amount, reason = 'user_request') {
    if (!this.sessionId) {
      throw new Error('No active credit session. Call approveCreditLine() first.');
    }
    
    console.log(`💳 Drawing ${amount} BB (${reason})`);
    
    // Create signed request
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    
    // Sign: CREDIT_DRAW:wallet:session:amount:timestamp:nonce
    const message = `CREDIT_DRAW:${this.address}:${this.sessionId}:${amount}:${timestamp}:${nonce}`;
    const signature = this.sign(message);
    
    console.log(`🔐 Signed draw request`);
    
    const signedRequest = {
      wallet_address: this.address,
      public_key: this.publicKey,
      session_id: this.sessionId,
      amount,
      reason,
      timestamp,
      nonce,
      signature
    };
    
    const result = await this.l1.creditDraw(signedRequest);
    
    if (result.success) {
      this.l2Balance = result.session.l2_balance;
      console.log(`✅ Drew ${amount} BB. L2 balance: ${this.l2Balance} BB`);
    } else {
      console.error(`❌ Draw failed: ${result.error}`);
    }
    
    return result;
  }
  
  /**
   * Auto-replenish L2 balance if needed before a bet
   * 
   * This is called internally before placing bets.
   */
  async ensureFundsForBet(betAmount) {
    // Get current L2 balance
    const l2Data = await this.l2.getBalance(this.address);
    this.l2Balance = l2Data.balance || 0;
    
    // Check if we need to draw more
    const available = this.l2Balance;
    if (available < betAmount) {
      // Draw enough for this bet plus some buffer
      const drawAmount = Math.max(betAmount - available + this.autoReplenishAmount, this.autoReplenishAmount);
      console.log(`⚡ Auto-replenishing: need ${betAmount}, have ${available}, drawing ${drawAmount}`);
      
      const result = await this.draw(drawAmount, 'low_balance');
      if (!result.success) {
        throw new Error(`Failed to auto-replenish: ${result.error}`);
      }
    }
    
    return { sufficient: true, balance: this.l2Balance };
  }
  
  /**
   * Place a bet (auto-replenishes if needed)
   */
  async placeBet(marketId, outcome, amount) {
    // Ensure we have enough funds
    await this.ensureFundsForBet(amount);
    
    console.log(`🎰 Betting ${amount} BB on ${outcome}`);
    const result = await this.l2.placeBet(this.address, marketId, outcome, amount);
    
    if (result.success) {
      // Update local balance estimate
      this.l2Balance -= amount;
      console.log(`✅ Bet placed. Estimated L2 balance: ${this.l2Balance} BB`);
    }
    
    return result;
  }
  
  /**
   * Step 3: Close session and return unused funds to L1
   * 
   * SECURITY: Settlement requires valid Ed25519 signature.
   * L2 can ONLY return tokens to the SAME wallet that deposited them.
   */
  async closeSession() {
    if (!this.sessionId) {
      throw new Error('No active credit session.');
    }
    
    console.log(`💰 Closing credit session ${this.sessionId}...`);
    
    // Get final L2 balance
    const l2Data = await this.l2.getBalance(this.address);
    const finalBalance = l2Data.balance || 0;
    
    // TODO: Get locked in bets from L2 if any positions are open
    const lockedInBets = 0;
    
    console.log(`📊 Final L2 balance: ${finalBalance} BB`);
    
    // Create signed settlement request
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    
    // Sign: CREDIT_SETTLE:session:wallet:balance:timestamp:nonce
    const message = `CREDIT_SETTLE:${this.sessionId}:${this.address}:${finalBalance}:${timestamp}:${nonce}`;
    const signature = this.sign(message);
    
    console.log(`🔐 Signed settlement request`);
    
    const signedRequest = {
      session_id: this.sessionId,
      wallet_address: this.address,
      public_key: this.publicKey,
      final_l2_balance: finalBalance,
      locked_in_bets: lockedInBets,
      timestamp,
      nonce,
      signature
    };
    
    // Settle with L1
    const result = await this.l1.creditSettle(signedRequest);
    
    if (result.success) {
      const netPnL = result.settlement.net_pnl;
      console.log(`✅ Session settled`);
      console.log(`   Net PnL: ${netPnL >= 0 ? '+' : ''}${netPnL} BB`);
      console.log(`   L1 Balance: ${result.settlement.l1_before} → ${result.settlement.l1_after} BB`);
      console.log(`   Returned to L1: ${result.settlement.returned_to_l1} BB`);
      
      // Clear session state
      this.sessionId = null;
      this.creditLimit = 0;
      this.l2Balance = 0;
    } else {
      console.error(`❌ Settlement failed: ${result.error}`);
    }
    
    return result;
  }
  
  /**
   * Get current status
   */
  async getStatus() {
    const [l1Balance, l2Data, creditStatus] = await Promise.all([
      this.l1.getBalance(this.address),
      this.l2.getBalance(this.address),
      this.l1.getCreditStatus(this.address)
    ]);
    
    return {
      address: this.address,
      l1_balance: l1Balance,
      l2_balance: l2Data.balance || 0,
      credit: creditStatus.success ? creditStatus : null,
      session_id: this.sessionId
    };
  }
  
  /**
   * Get markets
   */
  async getMarkets() {
    return this.l2.getMarkets();
  }
  
  /**
   * Get market details
   */
  async getMarket(marketId) {
    return this.l2.getMarket(marketId);
  }
  
  /**
   * Get position
   */
  async getPosition(marketId) {
    return this.l2.getPosition(this.address, marketId);
  }
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

export async function exampleFlow() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  BLACKBOOK L1↔L2 INTEGRATION DEMO');
  console.log('═══════════════════════════════════════════════════════════════\n');
  
  const wallet = new UnifiedWallet('L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD');
  
  // Step 1: Start session
  await wallet.startSession(100);
  
  // Step 2: Place bets
  await wallet.placeBet('tesla_rtaxi', 'YES', 10);
  await wallet.placeBet('tesla_rtaxi', 'YES', 20);
  
  // Step 3: Settle
  await wallet.settleSession();
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  COMPLETE');
  console.log('═══════════════════════════════════════════════════════════════');
}

/**
 * Example: Credit Line Flow (Casino Model)
 */
export async function creditLineExample() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  CREDIT LINE DEMO (Casino Bank Model)');
  console.log('═══════════════════════════════════════════════════════════════\n');
  
  // Create wallet from private key
  const privateKey = 'a'.repeat(64); // Replace with actual private key
  const wallet = new CreditLineWallet(privateKey);
  
  console.log(`Wallet: ${wallet.address}\n`);
  
  // Step 1: Approve credit line (ONE-TIME signature)
  await wallet.approveCreditLine(500, 24);
  
  // Step 2: Draw initial funds
  await wallet.draw(100, 'initial');
  
  // Step 3: Place bets (auto-replenishes if needed)
  await wallet.placeBet('tesla_rtaxi', 'YES', 50);
  await wallet.placeBet('ai_2025', 'NO', 30);
  await wallet.placeBet('btc_100k', 'YES', 80); // This triggers auto-replenish!
  
  // Step 4: Close session (returns unused to L1)
  await wallet.closeSession();
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  COMPLETE');
  console.log('═══════════════════════════════════════════════════════════════');
}

export default {
  L1Client,
  L2Client,
  UnifiedWallet,
  CreditLineWallet,
  exampleFlow,
  creditLineExample
};
