/**
 * ═══════════════════════════════════════════════════════════════════════════
 * DEALER/ORACLE SDK - BlackBook Prediction Market Operations
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * The Dealer (also called ORACLE) is the privileged account that:
 * 
 * 1. CREATES MARKETS - Seeds markets with initial liquidity
 * 2. RESOLVES MARKETS - Acts as oracle to determine winning outcomes
 * 3. PAYS WINNERS - Resolution automatically credits winners
 * 4. COLLECTS FEES - 1% house fee on all resolved markets
 * 5. MANAGES LIQUIDITY - Funds the prediction market pools
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * DEBIT/CREDIT FLOW:
 * 
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  USER PLACES BET                                                    │
 *   │  ─────────────────                                                  │
 *   │  1. User calls POST /buy with amount                                │
 *   │  2. Ledger.debit(user, amount) - REMOVES from user balance          │
 *   │  3. Amount goes into market pool (reserves)                         │
 *   │  4. User receives "shares" representing their position              │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  MARKET RESOLVES (Oracle determines winner)                         │
 *   │  ───────────────────────────────────────────────────────────────────│
 *   │  1. Dealer calls POST /resolve with winning_outcome                 │
 *   │  2. Total pool = sum of ALL bets                                    │
 *   │  3. House fee = 1% of pool → CREDIT to ORACLE account               │
 *   │  4. Remaining 99% → CREDIT to winners proportional to shares        │
 *   │  5. Losers get nothing (their bet was already debited)              │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  EXAMPLE: BTC > $100K Market                                        │
 *   │  ─────────────────────────────                                      │
 *   │  Alice bets $100 on YES → Gets 120 shares (better odds)             │
 *   │  Bob bets $100 on NO   → Gets 80 shares                             │
 *   │  Pool = $200                                                        │
 *   │                                                                     │
 *   │  Outcome: YES wins (BTC hits $100K)                                 │
 *   │  ─────────────────────────────────                                  │
 *   │  Fee: $200 × 1% = $2 → ORACLE                                       │
 *   │  Payout: $198 → Alice (she had 100% of winning shares)              │
 *   │  Bob: $0 (lost his bet)                                             │
 *   │                                                                     │
 *   │  Net: Alice +$98, Bob -$100, House +$2                              │
 *   └─────────────────────────────────────────────────────────────────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Usage:
 *   const dealer = new DealerSDK({
 *     l2Url: 'http://localhost:1234',
 *     privateKey: process.env.DEALER_PRIVATE_KEY
 *   });
 *   
 *   // Create a market
 *   await dealer.createMarket({
 *     title: 'Will BTC hit $100K?',
 *     outcomes: ['Yes', 'No'],
 *     initialLiquidity: 1000,
 *     closesAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 1 week
 *   });
 *   
 *   // Resolve market (pay winners)
 *   const payouts = await dealer.resolveMarket('market_123', 0); // Yes wins
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

import nacl from 'tweetnacl';
import { Buffer } from 'buffer';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  l2Url: 'http://localhost:1234',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
};

// Dealer/Oracle address (derived from dealer mnemonic)
const ORACLE_ADDRESS = 'L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D';

// ═══════════════════════════════════════════════════════════════════════════
// DEALER SDK
// ═══════════════════════════════════════════════════════════════════════════

export class DealerSDK {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.l2Url = this.config.l2Url;
    
    // Load private key for signing
    if (config.privateKey) {
      this.privateKey = Buffer.from(config.privateKey, 'hex');
      const keypair = nacl.sign.keyPair.fromSeed(this.privateKey.slice(0, 32));
      this.publicKey = Buffer.from(keypair.publicKey).toString('hex');
    } else {
      console.warn('⚠️  No private key provided - oracle operations will fail');
      this.privateKey = null;
      this.publicKey = null;
    }
    
    // Dealer address
    this.address = config.address || ORACLE_ADDRESS;
    
    console.log('🎰 Dealer SDK initialized');
    console.log(`   L2 URL: ${this.l2Url}`);
    console.log(`   Dealer: ${this.address.substring(0, 20)}...`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNATURE HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  sign(message) {
    if (!this.privateKey) throw new Error('Private key not configured');
    
    const messageBytes = Buffer.from(message, 'utf8');
    let secretKey = this.privateKey;
    if (secretKey.length === 32) {
      const keypair = nacl.sign.keyPair.fromSeed(secretKey);
      secretKey = keypair.secretKey;
    }
    
    const signature = nacl.sign.detached(messageBytes, secretKey);
    return Buffer.from(signature).toString('hex');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  async request(method, path, body = null) {
    const url = `${this.l2Url}${path}`;
    const options = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    
    if (body) options.body = JSON.stringify(body);
    
    let lastError;
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const response = await fetch(url, options);
        const text = await response.text();
        
        try {
          const data = JSON.parse(text);
          if (!response.ok && !data.success) {
            throw new Error(data.error || `HTTP ${response.status}`);
          }
          return data;
        } catch {
          throw new Error(`HTTP ${response.status}: ${text.substring(0, 200)}`);
        }
      } catch (error) {
        lastError = error;
        if (attempt < this.config.retryAttempts) {
          await this.sleep(this.config.retryDelay * attempt);
        }
      }
    }
    throw lastError;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET CREATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new prediction market
   * 
   * @param {Object} params
   * @param {string} params.title - Market title/question
   * @param {string} params.description - Detailed description
   * @param {string[]} params.outcomes - Array of outcome names (e.g., ['Yes', 'No'])
   * @param {number} params.initialLiquidity - Initial liquidity in $BB
   * @param {number|Date} params.closesAt - When betting closes (timestamp or Date)
   * @param {string} params.resolutionCriteria - How the market will be resolved
   * @param {string} params.category - Category (e.g., 'crypto', 'sports', 'politics')
   * @returns {Object} Created market details
   * 
   * @example
   * const market = await dealer.createMarket({
   *   title: 'Will BTC hit $100K by Feb 2026?',
   *   description: 'Bitcoin price on any major exchange',
   *   outcomes: ['Yes', 'No'],
   *   initialLiquidity: 1000,
   *   closesAt: new Date('2026-02-01'),
   *   resolutionCriteria: 'BTC/USD price on Coinbase',
   *   category: 'crypto'
   * });
   */
  async createMarket({
    title,
    description = '',
    outcomes = ['Yes', 'No'],
    initialLiquidity,
    closesAt,
    resolutionCriteria = '',
    category = 'general',
    parentMarketId = null
  }) {
    console.log(`\n🏗️ Creating market: "${title}"`);
    console.log(`   Outcomes: ${outcomes.join(', ')}`);
    console.log(`   Liquidity: ${initialLiquidity} $BB`);
    
    // Convert Date to timestamp if needed
    const closesAtTs = closesAt instanceof Date 
      ? Math.floor(closesAt.getTime() / 1000) 
      : closesAt;
    
    const result = await this.request('POST', '/markets', {
      title,
      description,
      outcomes,
      initial_liquidity: initialLiquidity,
      closes_at: closesAtTs,
      resolution_criteria: resolutionCriteria,
      category,
      parent_market_id: parentMarketId,
      creator: this.address
    });
    
    console.log(`   ✅ Market created: ${result.market_id || result.id}`);
    return result;
  }

  /**
   * Create a prop bet under a parent market
   */
  async createProp(parentMarketId, {
    title,
    description = '',
    outcomes = ['Yes', 'No'],
    initialLiquidity,
    closesAt,
    resolutionCriteria = ''
  }) {
    return this.createMarket({
      title,
      description,
      outcomes,
      initialLiquidity,
      closesAt,
      resolutionCriteria,
      parentMarketId
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET RESOLUTION (ORACLE FUNCTIONS)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Resolve a market and pay winners
   * 
   * This is the core oracle function that:
   * 1. Marks the market as resolved
   * 2. Calculates the payout pool (total bets - 1% fee)
   * 3. Credits winners proportionally by their shares
   * 4. Credits house fee to ORACLE account
   * 
   * @param {string} marketId - Market ID to resolve
   * @param {number} winningOutcome - Index of winning outcome (0, 1, etc.)
   * @returns {Object} Resolution result with payouts
   * 
   * @example
   * // Market has outcomes: ['Yes', 'No']
   * // To resolve as 'Yes' wins:
   * const result = await dealer.resolveMarket('market_123', 0);
   * console.log(result.payouts); // [['L2_Alice...', 198.50], ['L2_Bob...', 50.25]]
   */
  async resolveMarket(marketId, winningOutcome) {
    console.log(`\n⚖️ Resolving market: ${marketId}`);
    console.log(`   Winning outcome: ${winningOutcome}`);
    
    const result = await this.request('POST', '/resolve', {
      market_id: marketId,
      winning_outcome: winningOutcome,
      caller: this.address
    });
    
    if (result.success) {
      console.log(`   ✅ Market resolved!`);
      console.log(`   Total payouts: ${result.payouts?.length || 0} winners`);
      
      if (result.payouts && result.payouts.length > 0) {
        console.log(`   Payouts:`);
        for (const [address, amount] of result.payouts) {
          console.log(`     ${address.substring(0, 20)}... → ${amount.toFixed(2)} $BB`);
        }
      }
    }
    
    return result;
  }

  /**
   * Get market info before resolving
   */
  async getMarket(marketId) {
    return this.request('GET', `/markets/${marketId}`);
  }

  /**
   * Get all markets
   */
  async getMarkets() {
    return this.request('GET', '/markets');
  }

  /**
   * Get markets ready for resolution (frozen, not resolved)
   */
  async getMarketsAwaitingResolution() {
    const markets = await this.getMarkets();
    const now = Math.floor(Date.now() / 1000);
    
    return (markets.markets || []).filter(m => 
      !m.is_resolved && 
      m.closes_at && 
      m.closes_at < now
    );
  }

  /**
   * Get all bets for a market (to verify before resolution)
   */
  async getMarketBets(marketId) {
    return this.request('GET', `/markets/${marketId}/bets`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Freeze a market (stop accepting bets)
   */
  async freezeMarket(marketId) {
    console.log(`\n❄️ Freezing market: ${marketId}`);
    
    const result = await this.request('POST', `/markets/${marketId}/freeze`, {
      caller: this.address
    });
    
    console.log(`   ✅ Market frozen`);
    return result;
  }

  /**
   * Reopen a frozen market
   */
  async reopenMarket(marketId) {
    console.log(`\n🔓 Reopening market: ${marketId}`);
    
    const result = await this.request('POST', `/markets/${marketId}/reopen`, {
      caller: this.address
    });
    
    console.log(`   ✅ Market reopened`);
    return result;
  }

  /**
   * Void a market (cancel and refund all bettors)
   */
  async voidMarket(marketId, reason = 'Market voided by oracle') {
    console.log(`\n🚫 Voiding market: ${marketId}`);
    console.log(`   Reason: ${reason}`);
    
    const result = await this.request('POST', `/markets/${marketId}/void`, {
      caller: this.address,
      reason
    });
    
    console.log(`   ✅ Market voided - all bets refunded`);
    return result;
  }

  /**
   * Delete a market (only if no bets)
   */
  async deleteMarket(marketId) {
    console.log(`\n🗑️ Deleting market: ${marketId}`);
    
    const result = await this.request('DELETE', `/markets/${marketId}`, {
      caller: this.address
    });
    
    console.log(`   ✅ Market deleted`);
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LIQUIDITY MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Add liquidity to a market
   */
  async addLiquidity(marketId, amount) {
    console.log(`\n💧 Adding liquidity to ${marketId}: ${amount} $BB`);
    
    const result = await this.request('POST', `/markets/${marketId}/liquidity`, {
      amount,
      address: this.address,
      action: 'add'
    });
    
    console.log(`   ✅ Liquidity added`);
    return result;
  }

  /**
   * Remove liquidity from a market (LP withdrawal)
   */
  async removeLiquidity(marketId, shares) {
    console.log(`\n💧 Removing liquidity from ${marketId}: ${shares} shares`);
    
    const result = await this.request('POST', `/markets/${marketId}/liquidity`, {
      shares,
      address: this.address,
      action: 'remove'
    });
    
    console.log(`   ✅ Liquidity removed`);
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEALER BALANCE & ACCOUNTING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get dealer's L2 balance
   */
  async getBalance() {
    const result = await this.request('GET', `/balance/${this.address}`);
    console.log(`\n💰 Dealer Balance:`);
    console.log(`   Available: ${result.available} $BB`);
    console.log(`   Locked: ${result.locked} $BB`);
    return result;
  }

  /**
   * Get all balances on L2
   */
  async getAllBalances() {
    return this.request('GET', '/balances');
  }

  /**
   * Get dealer's collected fees (from house take)
   * The dealer receives 1% of every resolved market pool
   */
  async getCollectedFees() {
    // This would need a dedicated endpoint, for now estimate from activity
    const balance = await this.getBalance();
    return {
      balance: balance.available,
      note: 'Dealer balance includes 1% fee from all resolved markets'
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CREDIT LINE OPERATIONS (Dealer can open credit for users)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Open a credit line for a user (after verifying L1 lock)
   * Normally called by the user, but dealer can facilitate
   */
  async openCreditForUser({ lockId, walletAddress, creditAmount }) {
    console.log(`\n🔓 Opening credit line for user: ${walletAddress.substring(0, 20)}...`);
    
    const message = `CREDIT_OPEN:${walletAddress}:${creditAmount}:${lockId}`;
    const signature = this.sign(message);
    
    const result = await this.request('POST', '/credit/open', {
      lock_id: lockId,
      wallet_address: walletAddress,
      credit_amount: creditAmount,
      l2_public_key: this.publicKey,
      signature
    });
    
    console.log(`   ✅ Credit opened: ${creditAmount} $BB`);
    return result;
  }

  /**
   * Get credit status for any user
   */
  async getCreditStatus(walletAddress) {
    return this.request('GET', `/credit/status/${walletAddress}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // WITHDRAWAL & SETTLEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Withdraw dealer funds from L2 to L1
   */
  async withdraw(amount, destinationL1) {
    console.log(`\n🏧 Withdrawing ${amount} $BB to L1`);
    
    const result = await this.request('POST', '/withdraw', {
      address: this.address,
      amount,
      destination: destinationL1 || this.address.replace('L2_', 'L1_')
    });
    
    console.log(`   ✅ Withdrawal initiated: ${result.withdrawal_id}`);
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ANALYTICS & REPORTING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get summary statistics
   */
  async getStats() {
    const [markets, balance] = await Promise.all([
      this.getMarkets(),
      this.getBalance()
    ]);
    
    const marketList = markets.markets || [];
    const totalVolume = marketList.reduce((sum, m) => sum + (m.total_volume || 0), 0);
    const activeMarkets = marketList.filter(m => !m.is_resolved && m.status === 'active').length;
    const resolvedMarkets = marketList.filter(m => m.is_resolved).length;
    
    return {
      totalMarkets: marketList.length,
      activeMarkets,
      resolvedMarkets,
      pendingResolution: marketList.filter(m => !m.is_resolved && m.status === 'frozen').length,
      totalVolume,
      dealerBalance: balance.available,
      estimatedFees: totalVolume * 0.01 // 1% of volume
    };
  }

  /**
   * Get recent activity log
   */
  async getActivityLog() {
    return this.request('GET', '/activity');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HEALTH & STATUS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check L2 server health
   */
  async health() {
    return this.request('GET', '/health');
  }

  /**
   * Get current state root
   */
  async getStateRoot() {
    return this.request('GET', '/state_root');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVENIENCE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export default DealerSDK;

/**
 * Create dealer SDK with environment variables
 */
export function createDealerSDK(options = {}) {
  return new DealerSDK({
    l2Url: process.env.L2_URL || 'http://localhost:1234',
    privateKey: process.env.DEALER_PRIVATE_KEY || process.env.PRIVATE_KEY,
    address: process.env.DEALER_ADDRESS || ORACLE_ADDRESS,
    ...options
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// RESOLUTION HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Helper to calculate expected payouts before resolution
 * 
 * @param {Object[]} bets - Array of bets [{user, outcome, amount, shares}]
 * @param {number} winningOutcome - Which outcome wins
 * @returns {Object} Payout calculation
 */
export function calculatePayouts(bets, winningOutcome) {
  const totalPool = bets.reduce((sum, b) => sum + b.amount, 0);
  const fee = totalPool * 0.01;
  const poolAfterFee = totalPool - fee;
  
  const winningBets = bets.filter(b => b.outcome === winningOutcome);
  const totalWinningShares = winningBets.reduce((sum, b) => sum + b.shares, 0);
  
  const payouts = winningBets.map(bet => ({
    user: bet.user,
    shares: bet.shares,
    payout: totalWinningShares > 0 
      ? (bet.shares / totalWinningShares) * poolAfterFee 
      : 0
  }));
  
  return {
    totalPool,
    fee,
    poolAfterFee,
    winningBets: winningBets.length,
    losingBets: bets.length - winningBets.length,
    totalWinningShares,
    payouts
  };
}
