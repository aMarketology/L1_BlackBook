/**
 * ============================================================================
 * DEALER SDK - Market Maker & Oracle Authority
 * ============================================================================
 * 
 * This SDK provides all dealer functionality for the frontend:
 * 
 * 🎰 MARKET MAKING:
 *   - Fund markets with liquidity (add to CPMM pools)
 *   - Place bets on any outcome
 *   - Balance positions across outcomes
 *   - View positions and P&L
 * 
 * 🔮 ORACLE AUTHORITY:
 *   - Create new markets
 *   - Resolve markets with winning outcome
 *   - Cancel/refund markets
 * 
 * 💰 LIQUIDITY MANAGEMENT:
 *   - Add liquidity to pools
 *   - Withdraw liquidity (LP tokens)
 *   - View LP positions
 * 
 * 📊 CPMM PRICING:
 *   - Real-time price feeds
 *   - Price impact calculations
 *   - Historical price tracking
 *   - Slippage estimation
 * 
 * 📈 ANALYTICS:
 *   - Portfolio overview
 *   - P&L tracking
 *   - Market exposure
 * 
 * 🔐 SECURITY MODEL (Unified Wallet Architecture):
 *   - Ed25519 signatures with domain separation (CHAIN_ID_L1 / CHAIN_ID_L2)
 *   - Path binding prevents cross-endpoint replay attacks
 *   - SDK signs requests → L2 forwards to L1 for validation
 *   - L2 NEVER validates signatures (only L1 validates)
 *   - All balances backed by L1 locks (L2 cannot mint tokens)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

// ============================================================================
// CONFIGURATION
// ============================================================================

// Load .env file
const envPath = path.resolve(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split('\n').forEach(line => {
    const [key, ...valueParts] = line.split('=');
    if (key && valueParts.length > 0) {
      const value = valueParts.join('=').trim();
      if (!process.env[key.trim()]) {
        process.env[key.trim()] = value;
      }
    }
  });
}

// Chain ID constants for domain separation (matches unified-wallet-sdk.js)
const CHAIN_ID_L1 = 0x01;  // Layer 1 (Bank/Vault) - Real money
const CHAIN_ID_L2 = 0x02;  // Layer 2 (Gaming) - Fast bets

const CONFIG = {
  L1_URL: process.env.L1_URL || "http://localhost:8080",
  L2_URL: process.env.L2_URL || "http://localhost:1234",
  // Dealer/Oracle - derived from DEALER_PRIVATE_KEY mnemonic
  DEALER_ADDRESS: "L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D",
  DEALER_PUBLIC_KEY: "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
  DEALER_PRIVATE_KEY: process.env.DEALER_PRIVATE_KEY || process.env.dealer_private_key,
};

// ============================================================================
// ED25519 CRYPTOGRAPHY (Unified Wallet Compatible)
// ============================================================================

class DealerCrypto {
  /**
   * Sign a message using Ed25519 with domain separation
   * Matches unified-wallet-sdk.js signature format
   * 
   * @param {string} privateKeyHex - 64 hex char private key
   * @param {string} message - Message to sign
   * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2 for domain separation
   * @returns {string} - Signature (128 hex chars)
   */
  static sign(privateKeyHex, message, chainId = CHAIN_ID_L2) {
    if (!privateKeyHex) {
      throw new Error("Private key not provided");
    }
    
    // Domain separation: prepend chain ID to prevent L1/L2 replay attacks
    const domainSeparated = Buffer.concat([
      Buffer.from([chainId]),
      Buffer.from(message, 'utf8')
    ]);
    
    // Sign with tweetnacl (matches unified-wallet-sdk.js)
    const privateKey = Buffer.from(privateKeyHex, 'hex');
    const secretKey = new Uint8Array(64);
    secretKey.set(privateKey, 0);
    
    // Derive public key from private key
    const keypair = nacl.sign.keyPair.fromSeed(privateKey);
    secretKey.set(keypair.publicKey, 32);
    
    const signature = nacl.sign.detached(domainSeparated, secretKey);
    return Buffer.from(signature).toString('hex');
  }
  
  /**
   * Verify an Ed25519 signature
   * 
   * @param {string} publicKeyHex - 64 hex char public key
   * @param {string} message - Original message
   * @param {string} signatureHex - Signature (128 hex chars)
   * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
   * @returns {boolean} - True if signature is valid
   */
  static verify(publicKeyHex, message, signatureHex, chainId = CHAIN_ID_L2) {
    const domainSeparated = Buffer.concat([
      Buffer.from([chainId]),
      Buffer.from(message, 'utf8')
    ]);
    
    const publicKey = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
    const signature = new Uint8Array(Buffer.from(signatureHex, 'hex'));
    
    return nacl.sign.detached.verify(domainSeparated, signature, publicKey);
  }
  
  /**
   * Generate a unique nonce
   */
  static generateNonce() {
    return Date.now() * 1000 + Math.floor(Math.random() * 1000);
  }
}

// ============================================================================
// DEALER SDK CLASS
// ============================================================================

class DealerSDK {
  constructor(options = {}) {
    this.l1Url = options.l1Url || CONFIG.L1_URL;
    this.l2Url = options.l2Url || CONFIG.L2_URL;
    this.address = options.address || CONFIG.DEALER_ADDRESS;
    this.publicKey = options.publicKey || CONFIG.DEALER_PUBLIC_KEY;
    this.privateKey = options.privateKey || CONFIG.DEALER_PRIVATE_KEY;
    this.nonceCounter = Date.now();
  }
  
  // ==========================================================================
  // AUTHENTICATION & SIGNING
  // ==========================================================================
  
  /**
   * Create a signed bet request (unified wallet format)
   * Includes domain separation (chain_id) and path binding (request_path)
   * 
   * @param {string} marketId - Market ID
   * @param {number} outcome - Outcome index
   * @param {number} amount - Bet amount
   * @param {string} requestPath - API endpoint path (e.g., "/bet")
   * @returns {Object} - Signed request
   */
  createSignedBetRequest(marketId, outcome, amount, requestPath = "/bet") {
    const timestamp = Date.now();
    const nonce = ++this.nonceCounter;
    
    // Build payload
    const payload = {
      market_id: marketId,
      option: outcome.toString(),
      amount: amount,
    };
    
    const payloadStr = JSON.stringify(payload);
    
    // Build message with path binding (prevents cross-endpoint replay)
    // Format: path\npayload\ntimestamp\nnonce
    const message = `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`;
    
    // Sign with L2 chain ID (bets are on L2)
    const signature = DealerCrypto.sign(this.privateKey, message, CHAIN_ID_L2);
    
    return {
      wallet_address: this.address,
      public_key: this.publicKey,
      nonce: nonce.toString(),
      timestamp: timestamp,
      chain_id: CHAIN_ID_L2,
      request_path: requestPath,
      payload: payloadStr,
      signature: signature,
    };
  }
  
  /**
   * Create a signed generic request (unified wallet format)
   * 
   * @param {Object} payload - Request payload
   * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
   * @param {string} requestPath - API endpoint path
   * @returns {Object} - Signed request
   */
  createSignedRequest(payload, chainId = CHAIN_ID_L2, requestPath = null) {
    const timestamp = Date.now();
    const nonce = ++this.nonceCounter;
    
    const payloadStr = JSON.stringify(payload);
    
    // Build message with path binding (if provided)
    let message;
    if (requestPath) {
      message = `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`;
    } else {
      // Backward compatibility: no path
      message = `${payloadStr}\n${timestamp}\n${nonce}`;
    }
    
    const signature = DealerCrypto.sign(this.privateKey, message, chainId);
    
    const result = {
      wallet_address: this.address,
      public_key: this.publicKey,
      nonce: nonce.toString(),
      timestamp: timestamp,
      chain_id: chainId,
      payload: payloadStr,
      signature: signature,
    };
    
    // Include request_path if provided (recommended for security)
    if (requestPath) {
      result.request_path = requestPath;
    }
    
    return result;
  }
  
  // ==========================================================================
  // BALANCE & ACCOUNT
  // ==========================================================================
  
  /**
   * Get dealer's L1 balance (main chain)
   */
  async getL1Balance() {
    const response = await fetch(`${this.l1Url}/balance/${this.address}`);
    if (!response.ok) throw new Error(`L1 balance failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get dealer's L2 balance (prediction market chain)
   */
  async getL2Balance() {
    const response = await fetch(`${this.l2Url}/balance/${this.address}`);
    if (!response.ok) throw new Error(`L2 balance failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get detailed balance breakdown (available, locked, total)
   */
  async getBalanceDetails() {
    const response = await fetch(`${this.l2Url}/balance/${this.address}/details`);
    if (!response.ok) throw new Error(`Balance details failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Connect wallet (creates L2 account with 0 balance - needs bridge)
   * IMPORTANT: L2 cannot mint tokens. Balance only comes from L1 bridge.
   */
  async connectWallet() {
    const response = await fetch(`${this.l2Url}/auth/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key: this.publicKey,
        wallet_address: this.address,
      }),
    });
    if (!response.ok) throw new Error(`Connect wallet failed: ${response.status}`);
    return response.json();
  }
  
  // ==========================================================================
  // L1→L2 BRIDGE (DEPOSIT TO L2)
  // ==========================================================================
  
  /**
   * Bridge tokens from L1 to L2
   * FLOW: 
   * 1. Lock tokens on L1 (this call)
   * 2. L1 notifies L2 of lock (automatic)
   * 3. L1 confirms deposit to L2 (automatic after confirmations)
   * 4. L2 credits balance
   * 
   * @param {number} amount - Amount to bridge
   * @param {string} purpose - "bridge" | "session" | "liquidity"
   * @returns {Object} Lock details with lock_id for tracking
   */
  async bridgeFromL1(amount, purpose = "bridge") {
    // Create bridge lock payload
    const payload = {
      l2_address: this.address,  // Same address on L2
      amount: amount,
      purpose: purpose,
    };
    
    // Sign with L1 chain ID (locking on L1)
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L1, '/bridge/lock');
    
    // Call L1 bridge/lock endpoint
    const response = await fetch(`${this.l1Url}/bridge/lock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`Bridge lock failed: ${error.error || response.status}`);
    }
    
    return response.json();
  }
  
  /**
   * Check status of a bridge lock
   * @param {string} lockId - Lock ID from bridgeFromL1
   * @returns {Object} Lock status (pending/deposited/released)
   */
  async getLockStatus(lockId) {
    const response = await fetch(`${this.l2Url}/bridge/lock/${lockId}`);
    if (!response.ok) throw new Error(`Lock status failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get all L1 locks backing this wallet's L2 balance
   * @returns {Object} All locks for this address
   */
  async getL1Locks() {
    const response = await fetch(`${this.l2Url}/bridge/locks/${this.address}`);
    if (!response.ok) throw new Error(`Get locks failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Simulate L1→L2 bridge deposit (for testing when L1 not available)
   * This bypasses L1 and directly credits L2 balance.
   * ONLY USE IN TESTS - production should use bridgeFromL1()
   * 
   * @param {number} amount - Amount to deposit
   * @returns {Object} Deposit result
   */
  async simulateBridgeDeposit(amount) {
    const bridgeId = `test_bridge_${Date.now()}`;
    const lockId = `test_lock_${Date.now()}`;
    
    const request = {
      bridge_id: bridgeId,
      lock_id: lockId,
      from_address: this.address,
      to_address: this.address,
      amount: amount,
      l1_tx_hash: `test_tx_${Date.now()}`,
      l1_slot: Date.now(),
    };
    
    const response = await fetch(`${this.l2Url}/bridge/deposit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`Bridge deposit failed: ${error.error || response.status}`);
    }
    
    return response.json();
  }
  
  // ==========================================================================
  // L2→L1 BRIDGE (WITHDRAW FROM L2)
  // ==========================================================================
  
  /**
   * Withdraw tokens from L2 back to L1
   * Returns settlement proof for L1 to release tokens
   * 
   * @param {number} amount - Amount to withdraw
   * @param {string} targetAddress - L1 address to receive tokens
   * @returns {Object} Settlement proof for L1
   */
  async withdrawToL1(amount, targetAddress = null) {
    const target = targetAddress || this.address;
    
    // Create withdraw payload
    const payload = {
      amount: amount,
      target_address: target,
    };
    
    // Sign with L2 chain ID (withdrawing from L2)
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/bridge/withdraw');
    
    const response = await fetch(`${this.l2Url}/bridge/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`Withdraw failed: ${error.error || response.status}`);
    }
    
    return response.json();
  }
  
  /**
   * Get pending bridge status (both directions)
   * @param {string} bridgeId - Bridge transaction ID
   * @returns {Object} Bridge status
   */
  async getBridgeStatus(bridgeId) {
    const response = await fetch(`${this.l2Url}/bridge/status/${bridgeId}`);
    if (!response.ok) throw new Error(`Bridge status failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get full bridge overview (all pending deposits/withdrawals)
   * @returns {Object} Bridge overview for this wallet
   */
  async getBridgeOverview() {
    const [l2Balance, l1Balance] = await Promise.all([
      this.getL2Balance().catch(() => ({ balance: 0 })),
      this.getL1Balance().catch(() => ({ balance: 0 })),
    ]);
    
    let locks = [];
    try {
      const locksResp = await this.getL1Locks();
      locks = locksResp.locks || [];
    } catch (e) {
      // No locks endpoint or no locks
    }
    
    return {
      l1_balance: l1Balance.balance || l1Balance.available || 0,
      l2_balance: l2Balance.balance || 0,
      l1_locks: locks,
      total_locked: locks.reduce((sum, l) => sum + (l.amount || 0), 0),
      needs_bridge: l2Balance.balance === 0 && (l1Balance.balance || l1Balance.available || 0) > 0,
    };
  }
  
  // ==========================================================================
  // CREDIT LINE - L1-BACKED BORROWING
  // ==========================================================================
  
  /**
   * Draw credit from L1 to L2 (opens a credit line session)
   * SDK signs request → L2 forwards to L1 for validation → L2 tracks balance
   * 
   * SECURITY: L2 NEVER authorizes draws - only L1 can validate and approve
   * 
   * @param {number} amount - Amount to draw from L1
   * @param {string} reason - Purpose: "liquidity" | "betting" | "market_making"
   * @returns {Object} Draw result with session_id
   */
  async drawCredit(amount, reason = "betting") {
    const payload = {
      amount: amount,
      reason: reason,
    };
    
    // Sign with L2 chain ID (credit is tracked on L2, but validated by L1)
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/credit/draw');
    
    const response = await fetch(`${this.l2Url}/credit/draw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`Credit draw failed: ${error.error || response.status}`);
    }
    
    return response.json();
  }
  
  /**
   * Settle credit line session (close session and return to L1)
   * L2 verifies final balance → forwards to L1 → L1 releases remaining locked funds
   * 
   * @param {string} sessionId - Session ID from drawCredit
   * @param {number} finalL2Balance - Final L2 balance after betting/trading
   * @param {number} lockedInBets - Amount still locked in active bets
   * @returns {Object} Settlement result
   */
  async settleCredit(sessionId, finalL2Balance, lockedInBets = 0) {
    const payload = {
      session_id: sessionId,
      final_l2_balance: finalL2Balance,
      locked_in_bets: lockedInBets,
    };
    
    // Sign with L2 chain ID
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/credit/settle');
    
    const response = await fetch(`${this.l2Url}/credit/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(`Credit settle failed: ${error.error || response.status}`);
    }
    
    return response.json();
  }
  
  /**
   * Get current credit balance for this wallet
   * @returns {Object} Credit balance and session info
   */
  async getCreditBalance() {
    const response = await fetch(`${this.l2Url}/credit/balance/${this.address}`);
    
    if (!response.ok) {
      throw new Error(`Get credit balance failed: ${response.status}`);
    }
    
    return response.json();
  }
  
  /**
   * List all credit sessions (admin/debugging)
   * @returns {Object} All active credit sessions
   */
  async listCreditSessions() {
    const response = await fetch(`${this.l2Url}/credit/sessions`);
    
    if (!response.ok) {
      throw new Error(`List credit sessions failed: ${response.status}`);
    }
    
    return response.json();
  }
  
  // ==========================================================================
  // MARKET MAKING - BETTING
  // ==========================================================================
  
  /**
   * Place a bet on a market outcome
   * @param {string} marketId - Market ID
   * @param {number|string} outcome - Outcome index (0, 1, 2...) or "YES"/"NO"
   * @param {number} amount - Amount in BB to bet
   */
  async placeBet(marketId, outcome, amount) {
    const request = this.createSignedBetRequest(marketId, outcome, amount);
    
    const response = await fetch(`${this.l2Url}/bet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || 'Bet failed');
    }
    return data;
  }
  
  /**
   * Place bets on multiple outcomes to provide liquidity
   * @param {string} marketId - Market ID
   * @param {Object} amounts - { outcome: amount } e.g. { 0: 100, 1: 100 }
   */
  async placeLiquidityBets(marketId, amounts) {
    const results = [];
    for (const [outcome, amount] of Object.entries(amounts)) {
      if (amount > 0) {
        try {
          const result = await this.placeBet(marketId, parseInt(outcome), amount);
          results.push({ outcome, amount, success: true, result });
        } catch (e) {
          results.push({ outcome, amount, success: false, error: e.message });
        }
      }
    }
    return results;
  }
  
  /**
   * Balance a market by betting on the underpriced side
   * @param {string} marketId - Market ID
   * @param {number} amount - Total amount to use for balancing
   * @param {number} targetSpread - Target price difference (default 0.05 = 5%)
   */
  async balanceMarket(marketId, amount, targetSpread = 0.05) {
    const prices = await this.getMarketPrices(marketId);
    
    if (!prices.cpmm_enabled) {
      throw new Error('Market does not have CPMM enabled');
    }
    
    // Find the cheapest outcome
    const outcomes = prices.prices.sort((a, b) => a.price - b.price);
    const cheapest = outcomes[0];
    const mostExpensive = outcomes[outcomes.length - 1];
    
    const spread = mostExpensive.price - cheapest.price;
    
    if (spread < targetSpread) {
      return { 
        action: 'none', 
        reason: `Spread ${(spread * 100).toFixed(1)}% is within target ${(targetSpread * 100).toFixed(1)}%` 
      };
    }
    
    // Bet on the cheapest outcome to push price up
    const result = await this.placeBet(marketId, cheapest.index, amount);
    
    return {
      action: 'balanced',
      outcome: cheapest.label,
      amount: amount,
      oldPrice: cheapest.price,
      newPrice: result.new_price,
      result,
    };
  }
  
  // ==========================================================================
  // MARKET INFORMATION
  // ==========================================================================
  
  /**
   * Get all markets
   */
  async getMarkets() {
    const response = await fetch(`${this.l2Url}/markets`);
    if (!response.ok) throw new Error(`Get markets failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get a specific market
   */
  async getMarket(marketId) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}`);
    if (!response.ok) throw new Error(`Get market failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get market CPMM prices and pool info
   */
  async getMarketPrices(marketId) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/prices`);
    if (!response.ok) throw new Error(`Get prices failed: ${response.status}`);
    return response.json();
  }
  
  // ==========================================================================
  // CPMM - CONSTANT PRODUCT MARKET MAKER
  // ==========================================================================
  
  /**
   * Get real-time prices for all outcomes in a market
   * @param {string} marketId - Market ID
   * @returns {Object} Current prices with probability percentages
   */
  async getPrices(marketId) {
    const data = await this.getMarketPrices(marketId);
    return {
      marketId,
      cpmmEnabled: data.cpmm_enabled,
      prices: data.prices.map(p => ({
        outcome: p.index,
        label: p.label,
        price: p.price,                    // 0.0 to 1.0
        probability: p.probability_percent, // 0% to 100%
        reserve: p.reserve,                // Tokens in pool
        volume: p.total_volume_bb,         // Total traded
        betCount: p.bet_count,
      })),
      pool: data.pool ? {
        tvl: data.pool.tvl,                // Total Value Locked
        reserves: data.pool.reserves,      // Token balances
        k: data.pool.k,                    // Constant product
        feesCollected: data.pool.fees_collected,
        lpSupply: data.pool.lp_token_supply,
      } : null,
      feeRate: data.fee_rate,              // 0.02 = 2%
      totalVolume: data.total_market_volume,
      totalBets: data.total_bets,
    };
  }
  
  /**
   * Calculate expected shares and price impact BEFORE placing a bet
   * @param {string} marketId - Market ID
   * @param {number} outcome - Outcome index
   * @param {number} amount - BB amount to bet
   * @returns {Object} Preview of trade results
   */
  async previewTrade(marketId, outcome, amount) {
    const data = await this.getMarketPrices(marketId);
    
    if (!data.cpmm_enabled || !data.pool) {
      throw new Error('Market does not have CPMM enabled');
    }
    
    const currentPrice = data.prices.find(p => p.index === outcome)?.price || 0.5;
    const feeRate = data.fee_rate || 0.02;
    const fee = amount * feeRate;
    const amountAfterFee = amount - fee;
    
    // Constant product formula: x * y = k
    // Buying outcome 0: removes from reserve[0], adds to reserve[1]
    const reserves = data.pool.reserves;
    const k = data.pool.k;
    
    let sharesOut, newPrice, priceImpact, effectivePrice;
    
    if (reserves.length === 2) {
      // Binary market
      const x = reserves[outcome];           // Reserve we're buying from
      const y = reserves[1 - outcome];       // Other reserve
      
      // New reserve after adding liquidity to the other side
      const newY = y + amountAfterFee;
      const newX = k / newY;
      sharesOut = x - newX;
      
      // Calculate new price after trade
      const newTotal = newX + newY;
      newPrice = newY / newTotal;  // Price of outcome we bought
      
      effectivePrice = amount / sharesOut;
      priceImpact = effectivePrice - currentPrice;
    } else {
      // Multi-outcome market (simplified)
      sharesOut = amountAfterFee / currentPrice;
      newPrice = currentPrice;
      effectivePrice = currentPrice;
      priceImpact = 0;
    }
    
    return {
      marketId,
      outcome,
      amountIn: amount,
      fee,
      amountAfterFee,
      currentPrice,
      sharesOut: sharesOut.toFixed(4),
      effectivePrice: effectivePrice.toFixed(4),
      newPrice: newPrice.toFixed(4),
      priceImpact: priceImpact.toFixed(4),
      priceImpactPercent: (priceImpact * 100).toFixed(2) + '%',
      slippage: ((effectivePrice - currentPrice) / currentPrice * 100).toFixed(2) + '%',
    };
  }
  
  /**
   * Get price impacts for various bet sizes
   * @param {string} marketId - Market ID
   * @returns {Array} Price impacts for sample amounts
   */
  async getPriceImpacts(marketId) {
    const data = await this.getMarketPrices(marketId);
    return data.price_impacts || [];
  }
  
  /**
   * Subscribe to real-time price updates (polling)
   * @param {string} marketId - Market ID
   * @param {function} callback - Called with new prices
   * @param {number} intervalMs - Polling interval (default 2000ms)
   * @returns {function} Unsubscribe function
   */
  subscribeToPrices(marketId, callback, intervalMs = 2000) {
    let lastPrices = null;
    
    const poll = async () => {
      try {
        const prices = await this.getPrices(marketId);
        
        // Only callback if prices changed
        const priceKey = prices.prices.map(p => p.price.toFixed(4)).join(',');
        if (priceKey !== lastPrices) {
          lastPrices = priceKey;
          callback(prices);
        }
      } catch (e) {
        console.error('Price poll error:', e.message);
      }
    };
    
    // Initial fetch
    poll();
    
    // Start polling
    const interval = setInterval(poll, intervalMs);
    
    // Return unsubscribe function
    return () => clearInterval(interval);
  }
  
  /**
   * Get all markets with their current CPMM prices
   * @returns {Array} Markets with live pricing data
   */
  async getAllMarketPrices() {
    const markets = await this.getMarkets();
    const marketList = markets.markets || [];
    
    const results = await Promise.all(
      marketList.map(async (m) => {
        try {
          const prices = await this.getPrices(m.id);
          return {
            id: m.id,
            title: m.title,
            category: m.category,
            isResolved: m.is_resolved,
            cpmmEnabled: prices.cpmmEnabled,
            prices: prices.prices,
            tvl: prices.pool?.tvl || 0,
            totalVolume: prices.totalVolume,
          };
        } catch (e) {
          return {
            id: m.id,
            title: m.title,
            error: e.message,
          };
        }
      })
    );
    
    return results;
  }
  
  /**
   * Calculate how much BB needed to move price to target
   * @param {string} marketId - Market ID
   * @param {number} outcome - Outcome index
   * @param {number} targetPrice - Target price (0.0 to 1.0)
   * @returns {Object} Amount needed and expected results
   */
  async calculateAmountForTargetPrice(marketId, outcome, targetPrice) {
    const data = await this.getMarketPrices(marketId);
    
    if (!data.cpmm_enabled || !data.pool) {
      throw new Error('Market does not have CPMM enabled');
    }
    
    const currentPrice = data.prices.find(p => p.index === outcome)?.price || 0.5;
    const reserves = data.pool.reserves;
    const k = data.pool.k;
    const feeRate = data.fee_rate || 0.02;
    
    if (targetPrice <= currentPrice) {
      return {
        error: 'Target price must be higher than current price (buying increases price)',
        currentPrice,
        targetPrice,
      };
    }
    
    if (reserves.length !== 2) {
      return { error: 'Only binary markets supported' };
    }
    
    // For binary: price = y / (x + y)
    // Target: targetPrice = newY / (newX + newY)
    // With k = x * y = newX * newY
    // Solve for newY, then calculate amount needed
    
    // targetPrice = newY / (k/newY + newY)
    // targetPrice * (k/newY + newY) = newY
    // targetPrice * k/newY + targetPrice * newY = newY
    // targetPrice * k = newY^2 - targetPrice * newY^2
    // targetPrice * k = newY^2 * (1 - targetPrice)
    // newY = sqrt(targetPrice * k / (1 - targetPrice))
    
    const newY = Math.sqrt(targetPrice * k / (1 - targetPrice));
    const currentY = reserves[1 - outcome];
    const amountAfterFee = newY - currentY;
    const amountNeeded = amountAfterFee / (1 - feeRate);
    
    return {
      currentPrice: currentPrice.toFixed(4),
      targetPrice: targetPrice.toFixed(4),
      amountNeeded: amountNeeded.toFixed(2),
      fee: (amountNeeded * feeRate).toFixed(2),
      priceMove: ((targetPrice - currentPrice) * 100).toFixed(2) + '%',
    };
  }
  
  // ==========================================================================
  // DEALER POSITIONS & P&L
  // ==========================================================================
  
  /**
   * Get all dealer positions across markets
   */
  async getPositions() {
    const response = await fetch(`${this.l2Url}/dealer/positions/${this.address}`);
    if (!response.ok) throw new Error(`Get positions failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Calculate current P&L for all positions
   */
  async calculatePnL() {
    const positions = await this.getPositions();
    
    let totalInvested = 0;
    let totalCurrentValue = 0;
    const marketPnL = [];
    
    for (const position of positions.positions || []) {
      const prices = await this.getMarketPrices(position.market_id);
      
      let marketValue = 0;
      let marketInvested = 0;
      
      for (const pos of position.outcomes || []) {
        const price = prices.prices?.find(p => p.index === pos.outcome)?.price || 0.5;
        const value = pos.shares * price;
        marketValue += value;
        marketInvested += pos.total_invested || pos.shares * 0.5; // Estimate if not tracked
      }
      
      totalInvested += marketInvested;
      totalCurrentValue += marketValue;
      
      marketPnL.push({
        market_id: position.market_id,
        title: position.title,
        invested: marketInvested,
        current_value: marketValue,
        pnl: marketValue - marketInvested,
        pnl_percent: ((marketValue - marketInvested) / marketInvested * 100) || 0,
      });
    }
    
    return {
      total_invested: totalInvested,
      total_current_value: totalCurrentValue,
      total_pnl: totalCurrentValue - totalInvested,
      total_pnl_percent: ((totalCurrentValue - totalInvested) / totalInvested * 100) || 0,
      markets: marketPnL,
    };
  }
  
  // ==========================================================================
  // LIQUIDITY MANAGEMENT
  // ==========================================================================
  
  /**
   * Fund all markets with equal liquidity
   * @param {number} amountPerMarket - BB amount per market (0 = auto-calculate)
   */
  async fundAllMarkets(amountPerMarket = 0) {
    const response = await fetch(`${this.l2Url}/dealer/fund-all-markets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_address: this.address,
        amount_per_market: amountPerMarket,
      }),
    });
    
    if (!response.ok) throw new Error(`Fund markets failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Add liquidity to a specific market's CPMM pool
   * @param {string} marketId - Market ID
   * @param {number} amount - BB amount to add
   */
  async addLiquidity(marketId, amount) {
    // For now, liquidity is added by placing equal bets on all outcomes
    const prices = await this.getMarketPrices(marketId);
    const numOutcomes = prices.prices?.length || 2;
    const amountPerOutcome = amount / numOutcomes;
    
    const amounts = {};
    for (let i = 0; i < numOutcomes; i++) {
      amounts[i] = amountPerOutcome;
    }
    
    return this.placeLiquidityBets(marketId, amounts);
  }
  
  // ==========================================================================
  // ORACLE AUTHORITY - MARKET MANAGEMENT
  // ==========================================================================
  
  /**
   * Create a new market
   */
  async createMarket(options) {
    const { title, description, outcomes, category, source } = options;
    
    const response = await fetch(`${this.l2Url}/markets/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        description,
        outcomes: outcomes || ['Yes', 'No'],
        category: category || 'general',
        source: source,
        creator: this.address,
      }),
    });
    
    if (!response.ok) throw new Error(`Create market failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Resolve a market with winning outcome
   * @param {string} marketId - Market ID
   * @param {number} winningOutcome - Index of winning outcome
   */
  async resolveMarket(marketId, winningOutcome) {
    const request = this.createSignedRequest('resolve', {
      market_id: marketId,
      winning_outcome: winningOutcome,
    });
    
    const response = await fetch(`${this.l2Url}/markets/${marketId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    
    if (!response.ok) throw new Error(`Resolve market failed: ${response.status}`);
    return response.json();
  }
  
  // ==========================================================================
  // ANALYTICS & REPORTING
  // ==========================================================================
  
  /**
   * Get comprehensive portfolio overview
   */
  async getPortfolioOverview() {
    const [l1Balance, l2Balance, positions, pnl] = await Promise.all([
      this.getL1Balance().catch(() => ({ balance: 0 })),
      this.getL2Balance().catch(() => ({ balance: 0 })),
      this.getPositions().catch(() => ({ positions: [] })),
      this.calculatePnL().catch(() => ({ total_pnl: 0 })),
    ]);
    
    return {
      balances: {
        l1: l1Balance.balance || 0,
        l2: l2Balance.balance || 0,
        total: (l1Balance.balance || 0) + (l2Balance.balance || 0),
      },
      positions: positions.positions?.length || 0,
      total_invested: pnl.total_invested || 0,
      total_value: pnl.total_current_value || 0,
      pnl: pnl.total_pnl || 0,
      pnl_percent: pnl.total_pnl_percent || 0,
    };
  }
  
  /**
   * Get market exposure (how much is at risk per outcome)
   */
  async getMarketExposure(marketId) {
    const [prices, positions] = await Promise.all([
      this.getMarketPrices(marketId),
      this.getPositions(),
    ]);
    
    const marketPosition = positions.positions?.find(p => p.market_id === marketId);
    
    if (!marketPosition) {
      return { market_id: marketId, exposure: [], total_exposure: 0 };
    }
    
    const exposure = prices.prices.map(p => {
      const position = marketPosition.outcomes?.find(o => o.outcome === p.index);
      const shares = position?.shares || 0;
      
      // If this outcome wins, we get shares * 1.0
      // If this outcome loses, we get 0
      return {
        outcome: p.index,
        label: p.label,
        shares: shares,
        current_price: p.price,
        win_payout: shares, // Full payout if wins
        loss: shares * p.price, // What we paid
        expected_value: shares * p.price, // EV = shares * probability
      };
    });
    
    return {
      market_id: marketId,
      exposure,
      total_shares: exposure.reduce((sum, e) => sum + e.shares, 0),
      total_exposure: exposure.reduce((sum, e) => sum + e.loss, 0),
    };
  }
  
  // ==========================================================================
  // LEDGER & TRANSACTION FEED
  // ==========================================================================
  
  /**
   * Get L2 ledger activity (all transactions)
   * @param {Object} options - Filter options
   * @returns {Array} Transaction list
   */
  async getLedger(options = {}) {
    const params = new URLSearchParams();
    if (options.limit) params.set('limit', options.limit);
    if (options.type) params.set('type', options.type);
    if (options.account) params.set('account', options.account);
    
    const url = `${this.l2Url}/ledger${params.toString() ? '?' + params : ''}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Get ledger failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get all transactions with filtering
   * @param {Object} filters - Optional filters
   */
  async getTransactions(filters = {}) {
    const params = new URLSearchParams();
    if (filters.type) params.set('type', filters.type);
    if (filters.account) params.set('account', filters.account);
    if (filters.market_id) params.set('market_id', filters.market_id);
    if (filters.limit) params.set('limit', filters.limit);
    
    const url = `${this.l2Url}/ledger/transactions${params.toString() ? '?' + params : ''}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Get transactions failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get all oracle-related transactions (payouts, resolutions, fees)
   * @returns {Array} Oracle transactions
   */
  async getOracleTransactions() {
    const ledger = await this.getLedger({ limit: 1000 });
    const transactions = ledger.transactions || ledger.activity || [];
    
    return transactions.filter(tx => 
      tx.tx_type === 'OraclePayout' ||
      tx.tx_type === 'OracleResolution' ||
      tx.tx_type === 'FeeCollection' ||
      tx.from === this.address ||
      tx.to === this.address
    );
  }
  
  /**
   * Subscribe to ledger updates (polling)
   * @param {function} callback - Called with new transactions
   * @param {number} intervalMs - Polling interval (default 3000ms)
   * @returns {function} Unsubscribe function
   */
  subscribeToLedger(callback, intervalMs = 3000) {
    let lastTxId = null;
    
    const poll = async () => {
      try {
        const ledger = await this.getLedger({ limit: 50 });
        const transactions = ledger.transactions || ledger.activity || [];
        
        if (transactions.length > 0) {
          const latestId = transactions[0]?.id;
          if (latestId !== lastTxId) {
            lastTxId = latestId;
            callback(transactions);
          }
        }
      } catch (e) {
        console.error('Ledger poll error:', e.message);
      }
    };
    
    poll();
    const interval = setInterval(poll, intervalMs);
    return () => clearInterval(interval);
  }

  // ==========================================================================
  // DRAFT EVENT MANAGEMENT (Oracle Inbox)
  // ==========================================================================
  // Events come in as DRAFTS and require validation before going LIVE
  // DEALER must verify: outcomes, freeze dates, resolution rules, liquidity
  
  /**
   * Get all draft events in the inbox
   * @returns {Object} { drafts, ready_to_launch, needs_completion }
   */
  async getDrafts() {
    const response = await fetch(`${this.l2Url}/drafts`);
    if (!response.ok) throw new Error(`Get drafts failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Get a specific draft by ID
   * @param {string} draftId - Draft ID
   */
  async getDraft(draftId) {
    const response = await fetch(`${this.l2Url}/drafts/${draftId}`);
    if (!response.ok) throw new Error(`Get draft failed: ${response.status}`);
    return response.json();
  }
  
  /**
   * Create a new draft event manually
   * @param {Object} draft - Draft event data
   */
  async createDraft(draft) {
    const response = await fetch(`${this.l2Url}/drafts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(draft),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Create draft failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Update a draft event (add missing fields, fix validation errors)
   * @param {string} draftId - Draft ID
   * @param {Object} updates - Fields to update
   */
  async updateDraft(draftId, updates) {
    const response = await fetch(`${this.l2Url}/drafts/${draftId}/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Update draft failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Launch a draft as a live market (must pass all validations)
   * @param {string} draftId - Draft ID
   */
  async launchDraft(draftId) {
    const response = await fetch(`${this.l2Url}/drafts/${draftId}/launch`, {
      method: 'POST',
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Launch draft failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Delete/reject a draft
   * @param {string} draftId - Draft ID
   */
  async deleteDraft(draftId) {
    const response = await fetch(`${this.l2Url}/drafts/${draftId}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Delete draft failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Complete a draft with all required fields and launch it
   * Convenience method that updates then launches
   * @param {string} draftId - Draft ID
   * @param {Object} completionData - Required fields to add
   */
  async completeDraftAndLaunch(draftId, completionData) {
    // First, update with completion data
    const updateResult = await this.updateDraft(draftId, completionData);
    
    if (!updateResult.can_launch) {
      return {
        success: false,
        error: 'Draft still has validation errors after update',
        validation_errors: updateResult.validation_errors,
      };
    }
    
    // Now launch it
    return this.launchDraft(draftId);
  }
  
  /**
   * Get draft inbox summary for dashboard
   */
  async getDraftSummary() {
    const drafts = await this.getDrafts();
    
    return {
      total: drafts.total_drafts || 0,
      readyToLaunch: drafts.ready_to_launch || 0,
      needsWork: drafts.needs_completion || 0,
      drafts: (drafts.drafts || []).map(d => ({
        id: d.id,
        title: d.title,
        category: d.category,
        status: d.is_valid ? '✅ Ready' : '⚠️ Incomplete',
        errors: d.validation_errors || [],
        source: d.source,
        createdAt: new Date(d.created_at * 1000).toISOString(),
      })),
    };
  }
  
  /**
   * Subscribe to draft inbox (polling for new RSS imports)
   * @param {function} callback - Called when drafts change
   * @param {number} intervalMs - Poll interval (default 10s)
   * @returns {function} Unsubscribe function
   */
  subscribeToDrafts(callback, intervalMs = 10000) {
    let lastCount = null;
    
    const poll = async () => {
      try {
        const summary = await this.getDraftSummary();
        if (lastCount === null || summary.total !== lastCount) {
          lastCount = summary.total;
          callback(summary);
        }
      } catch (e) {
        console.error('Draft poll error:', e.message);
      }
    };
    
    poll();
    const interval = setInterval(poll, intervalMs);
    return () => clearInterval(interval);
  }
  
  // ==========================================================================
  // MARKET LIFECYCLE MANAGEMENT
  // ==========================================================================
  
  /**
   * Get full market lifecycle status
   * Draft → Active → Frozen → Resolved
   * @param {string} marketId - Market ID
   */
  async getMarketLifecycle(marketId) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}`);
    if (!response.ok) throw new Error(`Get market failed: ${response.status}`);
    const data = await response.json();
    const market = data.market || data;
    
    // Determine lifecycle stage
    let stage = 'Unknown';
    let canBet = false;
    let canResolve = false;
    
    const now = Math.floor(Date.now() / 1000);
    const freezeDate = market.betting_closes_at;
    
    if (market.is_resolved) {
      stage = 'Resolved';
      canBet = false;
      canResolve = false;
    } else if (freezeDate && now >= freezeDate) {
      stage = 'Frozen';
      canBet = false;
      canResolve = true;
    } else {
      stage = 'Active';
      canBet = true;
      canResolve = false;
    }
    
    return {
      id: market.id,
      title: market.title,
      stage,
      canBet,
      canResolve,
      freezeDate: freezeDate ? new Date(freezeDate * 1000).toISOString() : null,
      freezesIn: freezeDate ? Math.max(0, freezeDate - now) : null,
      isResolved: market.is_resolved,
      winningOutcome: market.winning_option,
      outcomes: market.options || market.outcomes,
      volume: market.total_volume,
      cpmmEnabled: !!market.cpmm_pool,
    };
  }
  
  /**
   * Get all markets organized by lifecycle stage
   */
  async getMarketsByStage() {
    const response = await fetch(`${this.l2Url}/markets`);
    if (!response.ok) throw new Error(`Get markets failed: ${response.status}`);
    const data = await response.json();
    const markets = data.markets || [];
    
    const now = Math.floor(Date.now() / 1000);
    
    const result = {
      active: [],     // Can bet
      frozen: [],     // Betting closed, awaiting resolution
      resolved: [],   // Completed
    };
    
    for (const m of markets) {
      const freezeDate = m.betting_closes_at;
      
      if (m.is_resolved) {
        result.resolved.push(m);
      } else if (freezeDate && now >= freezeDate) {
        result.frozen.push(m);
      } else {
        result.active.push(m);
      }
    }
    
    return {
      ...result,
      summary: {
        active: result.active.length,
        frozen: result.frozen.length,
        resolved: result.resolved.length,
        total: markets.length,
      }
    };
  }
  
  /**
   * Resolve a market (Oracle authority required)
   * @param {string} marketId - Market ID
   * @param {number|string} outcome - Winning outcome index or name
   */
  async resolveMarket(marketId, outcome) {
    // Try the admin resolve endpoint
    const response = await fetch(`${this.l2Url}/resolve/${marketId}/${outcome}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet_address: this.address,
        public_key: this.publicKey,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || `Resolve market failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Get markets ready for resolution (frozen but not resolved)
   */
  async getMarketsAwaitingResolution() {
    const byStage = await this.getMarketsByStage();
    return byStage.frozen.map(m => ({
      id: m.id,
      title: m.title,
      frozenAt: m.betting_closes_at ? new Date(m.betting_closes_at * 1000).toISOString() : null,
      outcomes: m.options || m.outcomes,
      volume: m.total_volume,
      resolutionRules: m.resolution_rules?.conditions || {},
    }));
  }

  // ==========================================================================
  // DEALER CONTROL & TESTING ENDPOINTS
  // ==========================================================================
  // These endpoints allow the DEALER to manage markets for testing and operations
  
  /**
   * Initialize all markets with CPMM pools and freeze dates
   * @param {number} liquidity - Initial liquidity per market (default 10000 BB)
   * @returns {Object} Summary of initialized markets
   */
  async initAllMarkets(liquidity = 10000) {
    const response = await fetch(`${this.l2Url}/dealer/markets/init-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_key: this.address,
        initial_liquidity: liquidity,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Init all markets failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Get detailed market status (DEALER dashboard view)
   * @param {string} marketId - Market ID
   * @returns {Object} Comprehensive market status with bets, resolution info
   */
  async getMarketStatus(marketId) {
    const response = await fetch(`${this.l2Url}/dealer/markets/${marketId}/status`);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Get market status failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Close a market (stop all betting)
   * @param {string} marketId - Market ID
   * @param {string} reason - Optional reason for closing
   */
  async closeMarket(marketId, reason = 'DEALER closed market') {
    const response = await fetch(`${this.l2Url}/dealer/markets/${marketId}/close`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_key: this.address,
        reason: reason,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Close market failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Reopen a closed market (resume betting)
   * @param {string} marketId - Market ID
   */
  async reopenMarket(marketId) {
    const response = await fetch(`${this.l2Url}/dealer/markets/${marketId}/reopen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_key: this.address,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Reopen market failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Set freeze date for a market (when betting stops)
   * @param {string} marketId - Market ID
   * @param {number|Date} freezeDate - Unix timestamp or Date object
   */
  async setFreezeDate(marketId, freezeDate) {
    const timestamp = freezeDate instanceof Date 
      ? Math.floor(freezeDate.getTime() / 1000)
      : freezeDate;
    
    const response = await fetch(`${this.l2Url}/dealer/markets/${marketId}/set-freeze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_key: this.address,
        freeze_timestamp: timestamp,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Set freeze date failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Instantly resolve a market (TESTING MODE - skips 24hr dispute window)
   * Use this for testing payouts. In production, use proposeResolution()
   * @param {string} marketId - Market ID
   * @param {number} winningOutcome - Index of winning outcome
   * @param {string} reason - Resolution reason
   * @returns {Object} Payout summary with winners and amounts
   */
  async instantResolve(marketId, winningOutcome, reason = 'DEALER instant resolution') {
    const response = await fetch(`${this.l2Url}/dealer/markets/${marketId}/instant-resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dealer_key: this.address,
        winning_outcome: winningOutcome,
        reason: reason,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Instant resolve failed: ${response.status}`);
    }
    return response.json();
  }

  // ==========================================================================
  // RESOLUTION SYSTEM (Polymarket-style with 24hr dispute window)
  // ==========================================================================
  // Flow: proposeResolution() → 24hr window → finalizeResolution()
  //       OR: proposeResolution() → disputeResolution() → resolveDispute()
  
  /**
   * Propose a resolution (starts 24hr dispute window)
   * Anyone with a position can dispute during this window
   * @param {string} marketId - Market ID
   * @param {number} outcome - Proposed winning outcome index
   * @param {string} evidence - URL to evidence supporting resolution
   * @returns {Object} Resolution proposal with dispute deadline
   */
  async proposeResolution(marketId, outcome, evidence = null) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/propose-resolution`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proposer: this.address,
        proposed_outcome: outcome,
        evidence_url: evidence,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Propose resolution failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Dispute a pending resolution (requires 100 BB stake)
   * Must have a position in the market to dispute
   * @param {string} marketId - Market ID
   * @param {string} reason - Reason for disputing
   * @param {number} proposedOutcome - Your proposed correct outcome (optional)
   * @param {string} evidence - URL to counter-evidence (optional)
   */
  async disputeResolution(marketId, reason, proposedOutcome = null, evidence = null) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/dispute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        disputer: this.address,
        reason: reason,
        proposed_outcome: proposedOutcome,
        evidence_url: evidence,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Dispute resolution failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Finalize a resolution after dispute window passes (24hrs)
   * Can only be called if no disputes or disputes were rejected
   * @param {string} marketId - Market ID
   */
  async finalizeResolution(marketId) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/finalize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        caller: this.address,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Finalize resolution failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * VOID a market (cancel and refund all bettors)
   * Use when market cannot be resolved fairly (ambiguous outcome, external issues)
   * @param {string} marketId - Market ID
   * @param {string} reason - Reason for voiding
   */
  async voidMarket(marketId, reason) {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/void`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        oracle: this.address,
        reason: reason,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Void market failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Resolve a dispute (DEALER/Oracle authority only)
   * Reviews dispute and decides final outcome
   * @param {string} marketId - Market ID
   * @param {string} disputeId - Dispute ID to resolve
   * @param {string} decision - 'accept' or 'reject'
   * @param {number} finalOutcome - Final winning outcome if accepting dispute
   * @param {string} reason - Explanation for decision
   */
  async resolveDispute(marketId, disputeId, decision, finalOutcome = null, reason = '') {
    const response = await fetch(`${this.l2Url}/markets/${marketId}/resolve-dispute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        oracle: this.address,
        dispute_id: disputeId,
        decision: decision,
        final_outcome: finalOutcome,
        reason: reason,
      }),
    });
    
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Resolve dispute failed: ${response.status}`);
    }
    return response.json();
  }

  // ==========================================================================
  // USER BETTING LEDGER & P&L
  // ==========================================================================
  
  /**
   * Get a user's complete betting history with wins/losses
   * @param {string} address - User wallet address (defaults to dealer)
   * @returns {Object} Full betting history with P&L calculations
   */
  async getUserBettingHistory(address = null) {
    const wallet = address || this.address;
    const response = await fetch(`${this.l2Url}/user/${wallet}/betting-history`);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Get betting history failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Get quick P&L summary for a user
   * @param {string} address - User wallet address (defaults to dealer)
   * @returns {Object} P&L summary with win rate
   */
  async getUserPnL(address = null) {
    const wallet = address || this.address;
    const response = await fetch(`${this.l2Url}/user/${wallet}/pnl`);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Get user P&L failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Get simple list of user bets
   * @param {string} address - User wallet address (defaults to dealer)
   */
  async getUserBets(address = null) {
    const wallet = address || this.address;
    const response = await fetch(`${this.l2Url}/user/${wallet}/bets`);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Get user bets failed: ${response.status}`);
    }
    return response.json();
  }

  // ==========================================================================
  // ANALYTICS & DASHBOARD
  // ==========================================================================
  
  /**
   * Get markets in RESOLVING state (proposed but not finalized)
   * @returns {Array} Markets awaiting finalization or in dispute
   */
  async getResolutionQueue() {
    const markets = await this.getMarkets();
    const marketList = markets.markets || [];
    
    const resolving = [];
    for (const m of marketList) {
      if (m.proposed_outcome !== undefined && m.proposed_outcome !== null && !m.is_resolved) {
        const status = await this.getMarketStatus(m.id).catch(() => null);
        resolving.push({
          id: m.id,
          title: m.title,
          proposedOutcome: m.proposed_outcome,
          proposedBy: status?.market?.resolution?.proposed_by,
          proposedAt: status?.market?.resolution?.proposed_at,
          disputeDeadline: status?.market?.resolution?.dispute_deadline,
          disputeCount: status?.market?.resolution?.disputes_count || 0,
          volume: m.total_volume,
        });
      }
    }
    
    return resolving;
  }
  
  /**
   * Get all markets with active disputes
   * @returns {Array} Markets in DISPUTED state
   */
  async getDisputedMarkets() {
    const markets = await this.getMarkets();
    const marketList = markets.markets || [];
    
    const disputed = [];
    for (const m of marketList) {
      const status = await this.getMarketStatus(m.id).catch(() => null);
      if (status?.market?.resolution?.disputes_count > 0) {
        disputed.push({
          id: m.id,
          title: m.title,
          disputeCount: status.market.resolution.disputes_count,
          proposedOutcome: status.market.resolution.proposed_outcome,
          status: status.market.status,
          volume: m.total_volume,
        });
      }
    }
    
    return disputed;
  }
  
  /**
   * Get recent payouts (from ledger transactions)
   * @param {number} limit - Max payouts to return
   */
  async getPayoutHistory(limit = 50) {
    const response = await fetch(`${this.l2Url}/ledger/transactions?type=payout&limit=${limit}`);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Get payout history failed: ${response.status}`);
    }
    return response.json();
  }
  
  /**
   * Bulk set freeze dates for multiple markets
   * @param {Array<string>} marketIds - Array of market IDs
   * @param {number|Date} freezeDate - Freeze timestamp
   * @returns {Array} Results for each market
   */
  async bulkSetFreezeDate(marketIds, freezeDate) {
    const results = [];
    for (const marketId of marketIds) {
      try {
        const result = await this.setFreezeDate(marketId, freezeDate);
        results.push({ marketId, success: true, result });
      } catch (e) {
        results.push({ marketId, success: false, error: e.message });
      }
    }
    return results;
  }
  
  /**
   * Bulk close multiple markets
   * @param {Array<string>} marketIds - Array of market IDs
   * @param {string} reason - Reason for closing
   * @returns {Array} Results for each market
   */
  async bulkCloseMarkets(marketIds, reason = 'Bulk close by DEALER') {
    const results = [];
    for (const marketId of marketIds) {
      try {
        const result = await this.closeMarket(marketId, reason);
        results.push({ marketId, success: true, result });
      } catch (e) {
        results.push({ marketId, success: false, error: e.message });
      }
    }
    return results;
  }
  
  /**
   * Get complete DEALER dashboard summary
   * @returns {Object} Full overview of all markets, positions, P&L
   */
  async getDashboard() {
    const [
      portfolio,
      marketsByStage,
      draftSummary,
      pnl,
    ] = await Promise.all([
      this.getPortfolioOverview().catch(() => ({})),
      this.getMarketsByStage().catch(() => ({ summary: {} })),
      this.getDraftSummary().catch(() => ({ total: 0 })),
      this.getUserPnL().catch(() => ({ realized_pnl: 0 })),
    ]);
    
    return {
      timestamp: new Date().toISOString(),
      balances: portfolio.balances || {},
      markets: {
        active: marketsByStage.summary?.active || 0,
        frozen: marketsByStage.summary?.frozen || 0,
        resolved: marketsByStage.summary?.resolved || 0,
        total: marketsByStage.summary?.total || 0,
      },
      drafts: {
        total: draftSummary.total || 0,
        ready: draftSummary.readyToLaunch || 0,
        needsWork: draftSummary.needsWork || 0,
      },
      performance: {
        totalInvested: portfolio.total_invested || 0,
        totalValue: portfolio.total_value || 0,
        realizedPnL: pnl.realized_pnl || 0,
        unrealizedExposure: pnl.unrealized_exposure || 0,
      },
    };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  DealerSDK,
  DealerCrypto,
  CONFIG,
  CHAIN_ID_L1,
  CHAIN_ID_L2,
};

// ============================================================================
// CLI DEMO
// ============================================================================

async function demo() {
  console.log("═".repeat(70));
  console.log("🎰 DEALER SDK DEMO - FULL MARKET LIFECYCLE");
  console.log("═".repeat(70));
  
  const dealer = new DealerSDK();
  
  try {
    // Connect wallet
    console.log("\n📡 Connecting wallet...");
    const connect = await dealer.connectWallet();
    console.log("   ✅ Connected:", dealer.address);
    
    // Get portfolio overview
    console.log("\n📊 Portfolio Overview:");
    const portfolio = await dealer.getPortfolioOverview();
    console.log("   L1 Balance:", portfolio.balances.l1, "BB");
    console.log("   L2 Balance:", portfolio.balances.l2, "BB");
    console.log("   Positions:", portfolio.positions, "markets");
    
    // ═══════════════════════════════════════════════════════════════════════
    // DRAFT INBOX
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("📋 DRAFT INBOX (Events awaiting approval):");
    console.log("─".repeat(70));
    
    const draftSummary = await dealer.getDraftSummary();
    console.log(`   Total Drafts: ${draftSummary.total}`);
    console.log(`   ✅ Ready to Launch: ${draftSummary.readyToLaunch}`);
    console.log(`   ⚠️  Needs Completion: ${draftSummary.needsWork}`);
    
    if (draftSummary.drafts.length > 0) {
      console.log("\n   Recent Drafts:");
      for (const d of draftSummary.drafts.slice(0, 5)) {
        console.log(`   • ${d.status} ${d.title.slice(0, 45)}...`);
        if (d.errors.length > 0) {
          console.log(`     └─ Missing: ${d.errors.join(', ')}`);
        }
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // MARKET LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("📈 MARKET LIFECYCLE STATUS:");
    console.log("─".repeat(70));
    
    const lifecycle = await dealer.getMarketsByStage();
    console.log(`   🟢 Active (betting open):    ${lifecycle.summary.active}`);
    console.log(`   🔵 Frozen (awaiting oracle): ${lifecycle.summary.frozen}`);
    console.log(`   ⚪ Resolved (completed):     ${lifecycle.summary.resolved}`);
    
    // Show markets awaiting resolution
    if (lifecycle.frozen.length > 0) {
      console.log("\n   ⏳ Markets Awaiting Resolution:");
      const awaiting = await dealer.getMarketsAwaitingResolution();
      for (const m of awaiting.slice(0, 3)) {
        console.log(`   • ${m.title.slice(0, 45)}...`);
        console.log(`     Outcomes: ${m.outcomes?.join(' / ')}`);
        console.log(`     Volume: ${m.volume} BB`);
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // LIVE PRICES
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("💹 LIVE CPMM PRICES:");
    console.log("─".repeat(70));
    
    const allPrices = await dealer.getAllMarketPrices();
    const activePrices = allPrices.filter(m => m.cpmmEnabled && !m.isResolved).slice(0, 5);
    
    for (const m of activePrices) {
      console.log(`\n   📌 ${m.title.slice(0, 50)}...`);
      console.log(`      TVL: ${m.tvl?.toFixed(2) || 0} BB`);
      for (const p of m.prices || []) {
        const bar = '█'.repeat(Math.floor(p.probability / 5)) + '░'.repeat(20 - Math.floor(p.probability / 5));
        console.log(`      ${p.label}: ${p.probability.toFixed(1)}% ${bar}`);
      }
    }
    
    // Preview a trade
    if (activePrices.length > 0) {
      const testMarket = activePrices[0];
      console.log("\n   💹 Trade Preview (100 BB on YES):");
      try {
        const preview = await dealer.previewTrade(testMarket.id, 0, 100);
        console.log(`      Shares Out: ${preview.sharesOut}`);
        console.log(`      Effective Price: ${preview.effectivePrice}`);
        console.log(`      Price Impact: ${preview.priceImpactPercent}`);
      } catch (e) {
        console.log(`      ⚠️ Could not preview: ${e.message}`);
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // DEALER DASHBOARD
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("🎛️  DEALER DASHBOARD:");
    console.log("─".repeat(70));
    
    try {
      const dashboard = await dealer.getDashboard();
      console.log(`   💰 L2 Balance: ${dashboard.balances?.l2 || 0} BB`);
      console.log(`   📊 Markets: ${dashboard.markets?.active || 0} active, ${dashboard.markets?.frozen || 0} frozen, ${dashboard.markets?.resolved || 0} resolved`);
      console.log(`   📝 Drafts: ${dashboard.drafts?.total || 0} total (${dashboard.drafts?.ready || 0} ready)`);
      console.log(`   📈 P&L: ${dashboard.performance?.realizedPnL?.toFixed(2) || 0} BB realized`);
    } catch (e) {
      console.log(`   ⚠️ Dashboard unavailable: ${e.message}`);
    }
    
    console.log("\n" + "═".repeat(70));
    console.log("✅ Demo complete! Full market lifecycle SDK ready.");
    console.log("═".repeat(70));
    
    console.log("\n📖 CREDIT LINE (L1-Backed Borrowing):");
    console.log("   dealer.drawCredit(amount, reason)     - Draw credit from L1 (SDK signs → L2 forwards → L1 validates)");
    console.log("   dealer.settleCredit(sessionId, bal)   - Close session & return to L1");
    console.log("   dealer.getCreditBalance()             - Check current credit balance");
    console.log("   dealer.listCreditSessions()           - List all active sessions");
    
    console.log("\n📖 DEALER CONTROL (Testing):");
    console.log("   dealer.initAllMarkets(liquidity)      - Initialize all markets with CPMM");
    console.log("   dealer.getMarketStatus(id)            - Detailed market status");
    console.log("   dealer.closeMarket(id, reason)        - Stop betting");
    console.log("   dealer.reopenMarket(id)               - Resume betting");
    console.log("   dealer.setFreezeDate(id, timestamp)   - Set freeze date");
    console.log("   dealer.instantResolve(id, outcome)    - Test payouts (skip dispute)");
    
    console.log("\n📖 RESOLUTION SYSTEM (Polymarket-style):");
    console.log("   dealer.proposeResolution(id, outcome) - Start 24hr dispute window");
    console.log("   dealer.disputeResolution(id, reason)  - Dispute (requires 100 BB stake)");
    console.log("   dealer.finalizeResolution(id)         - Complete after 24hrs");
    console.log("   dealer.voidMarket(id, reason)         - Cancel & refund all");
    console.log("   dealer.resolveDispute(id, disputeId)  - DEALER decides dispute");
    
    console.log("\n📖 USER P&L TRACKING:");
    console.log("   dealer.getUserBettingHistory(addr)    - Full betting history");
    console.log("   dealer.getUserPnL(addr)               - Quick P&L summary");
    console.log("   dealer.getUserBets(addr)              - Simple bet list");
    
    console.log("\n📖 ANALYTICS:");
    console.log("   dealer.getResolutionQueue()           - Markets in RESOLVING state");
    console.log("   dealer.getDisputedMarkets()           - Markets with active disputes");
    console.log("   dealer.getPayoutHistory(limit)        - Recent payouts");
    console.log("   dealer.getDashboard()                 - Complete overview");
    
    console.log("\n📖 DRAFT MANAGEMENT:");
    console.log("   dealer.getDrafts()                    - List all drafts");
    console.log("   dealer.createDraft(data)              - Create new draft");
    console.log("   dealer.launchDraft(id)                - Launch as live market");
    console.log("   dealer.subscribeToDrafts(callback)    - Watch for new RSS imports");
    
    console.log("\n📖 MARKET LIFECYCLE:");
    console.log("   dealer.getMarketLifecycle(id)         - Get stage & status");
    console.log("   dealer.getMarketsByStage()            - Active/Frozen/Resolved");
    console.log("   dealer.getMarketsAwaitingResolution() - Ready for oracle");
    
  } catch (e) {
    console.error("❌ Error:", e.message);
  }
}

// Run demo if executed directly
if (require.main === module) {
  demo().catch(console.error);
}
