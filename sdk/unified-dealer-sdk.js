/**
 * ═══════════════════════════════════════════════════════════════════════════
 * UNIFIED DEALER SDK - Layer 1 + Layer 2 Operations
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Complete SDK for BlackBook prediction markets with full L1↔L2 bridge support.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * ARCHITECTURE:
 * 
 *   Layer 1 (Bank/Vault)           Layer 2 (Gaming/Markets)
 *   ─────────────────────          ──────────────────────────
 *   • Real money storage           • Fast prediction markets
 *   • Token locks                  • CPMM pricing (AMM)
 *   • Settlement authority         • Betting & positions
 *   • Credit validation            • Oracle resolution
 *   • Bridge source                • Bridge destination
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * SECURITY MODEL:
 * 
 *   • Ed25519 signatures with domain separation (L1=0x01, L2=0x02)
 *   • Path binding prevents cross-endpoint replay attacks
 *   • L2 NEVER validates signatures - only L1 validates
 *   • All L2 balances are backed by L1 locks (L2 cannot mint)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
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
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

import nacl from 'tweetnacl';
import { Buffer } from 'buffer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// Chain ID constants for domain separation
export const CHAIN_ID_L1 = 0x01;  // Layer 1 (Bank/Vault) - Real money
export const CHAIN_ID_L2 = 0x02;  // Layer 2 (Gaming) - Fast bets

// Default Dealer/Oracle address
const ORACLE_ADDRESS = 'L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D';
const ORACLE_PUBLIC_KEY = '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a';

const DEFAULT_CONFIG = {
  l1Url: process.env.L1_URL || 'http://localhost:8080',
  l2Url: process.env.L2_URL || 'http://localhost:1234',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
};

// ═══════════════════════════════════════════════════════════════════════════
// ED25519 CRYPTOGRAPHY
// ═══════════════════════════════════════════════════════════════════════════

export class DealerCrypto {
  /**
   * Sign a message using Ed25519 with domain separation
   * @param {string} privateKeyHex - 64 hex char private key (32 bytes)
   * @param {string} message - Message to sign
   * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
   * @returns {string} - Hex signature (128 chars)
   */
  static sign(privateKeyHex, message, chainId = CHAIN_ID_L2) {
    if (!privateKeyHex) throw new Error("Private key not provided");
    
    // Domain separation: prepend chain ID
    const domainSeparated = Buffer.concat([
      Buffer.from([chainId]),
      Buffer.from(message, 'utf8')
    ]);
    
    const privateKey = Buffer.from(privateKeyHex, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(privateKey.slice(0, 32));
    const signature = nacl.sign.detached(domainSeparated, keypair.secretKey);
    
    return Buffer.from(signature).toString('hex');
  }
  
  /**
   * Verify an Ed25519 signature
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

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED DEALER SDK
// ═══════════════════════════════════════════════════════════════════════════

export class UnifiedDealerSDK {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.l1Url = this.config.l1Url;
    this.l2Url = this.config.l2Url;
    
    // Load private key
    const privateKeyHex = config.privateKey || process.env.DEALER_PRIVATE_KEY || process.env.dealer_private_key;
    if (privateKeyHex) {
      this.privateKey = privateKeyHex;
      const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');
      const keypair = nacl.sign.keyPair.fromSeed(privateKeyBuffer.slice(0, 32));
      this.publicKey = Buffer.from(keypair.publicKey).toString('hex');
    } else {
      console.warn('⚠️  No private key provided - signed operations will fail');
      this.privateKey = null;
      this.publicKey = config.publicKey || ORACLE_PUBLIC_KEY;
    }
    
    this.address = config.address || ORACLE_ADDRESS;
    this.nonceCounter = Date.now();
    
    console.log('═'.repeat(60));
    console.log('🎰 UNIFIED DEALER SDK INITIALIZED');
    console.log('═'.repeat(60));
    console.log(`   L1 URL: ${this.l1Url}`);
    console.log(`   L2 URL: ${this.l2Url}`);
    console.log(`   Address: ${this.address}`);
    console.log('═'.repeat(60));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNATURE HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Sign a message with domain separation
   */
  sign(message, chainId = CHAIN_ID_L2) {
    if (!this.privateKey) throw new Error('Private key not configured');
    return DealerCrypto.sign(this.privateKey, message, chainId);
  }

  /**
   * Create a signed bet request
   */
  createSignedBetRequest(marketId, outcome, amount, requestPath = "/bet") {
    const timestamp = Date.now();
    const nonce = ++this.nonceCounter;
    
    const payload = {
      market_id: marketId,
      option: outcome.toString(),
      amount: amount,
    };
    
    const payloadStr = JSON.stringify(payload);
    const message = `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`;
    const signature = this.sign(message, CHAIN_ID_L2);
    
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
   * Create a signed generic request
   */
  createSignedRequest(payload, chainId = CHAIN_ID_L2, requestPath = null) {
    const timestamp = Date.now();
    const nonce = ++this.nonceCounter;
    
    const payloadStr = JSON.stringify(payload);
    let message = requestPath 
      ? `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`
      : `${payloadStr}\n${timestamp}\n${nonce}`;
    
    const signature = this.sign(message, chainId);
    
    const result = {
      wallet_address: this.address,
      public_key: this.publicKey,
      nonce: nonce.toString(),
      timestamp: timestamp,
      chain_id: chainId,
      payload: payloadStr,
      signature: signature,
    };
    
    if (requestPath) result.request_path = requestPath;
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  async request(method, url, body = null) {
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
          if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.substring(0, 200)}`);
          return text;
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
  // LAYER 1 OPERATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get L1 balance
   */
  async getL1Balance(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l1Url}/balance/${wallet}`);
  }

  /**
   * Transfer tokens on L1
   */
  async l1Transfer(to, amount) {
    console.log(`\n💸 L1 Transfer: ${amount} $BC → ${to.substring(0, 20)}...`);
    
    return this.request('POST', `${this.l1Url}/transfer/simple`, {
      wallet: this.address,
      to: to,
      amount: amount,
    });
  }

  /**
   * Get L1 pending transactions
   */
  async getL1Pending() {
    return this.request('GET', `${this.l1Url}/bridge/pending/${this.address}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LAYER 2 OPERATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get L2 balance
   */
  async getL2Balance(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/balance/${wallet}`);
  }

  /**
   * Get detailed L2 balance breakdown
   */
  async getL2BalanceDetails(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/balance/${wallet}/details`);
  }

  /**
   * Connect wallet to L2 (creates account with 0 balance)
   */
  async connectWallet() {
    console.log('\n📡 Connecting wallet to L2...');
    
    const result = await this.request('POST', `${this.l2Url}/auth/connect`, {
      public_key: this.publicKey,
      wallet_address: this.address,
    });
    
    console.log(`   ✅ Connected: ${this.address}`);
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // L1 → L2 BRIDGE (DEPOSIT)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Bridge tokens from L1 to L2
   * @param {number} amount - Amount to bridge
   * @param {string} purpose - "bridge" | "session" | "liquidity"
   */
  async bridgeToL2(amount, purpose = "bridge") {
    console.log(`\n🌉 Bridging ${amount} $BC from L1 → L2`);
    
    // Step 1: Lock on L1
    const lockResult = await this.request('POST', `${this.l1Url}/bridge/initiate`, {
      wallet: this.address,
      amount: amount,
    });
    
    console.log(`   ✅ Locked on L1: ${lockResult.lock_id}`);
    
    // Step 2: Credit on L2 (in production, this happens automatically)
    try {
      const creditResult = await this.request('POST', `${this.l2Url}/bridge/credit`, {
        lock_id: lockResult.lock_id,
        wallet: this.address,
        amount: amount,
      });
      console.log(`   ✅ Credited on L2`);
      return { lock: lockResult, credit: creditResult };
    } catch (e) {
      console.log(`   ⚠️ L2 credit pending: ${e.message}`);
      return { lock: lockResult, credit: null };
    }
  }

  /**
   * Check status of a bridge lock
   */
  async getBridgeStatus(lockId) {
    return this.request('GET', `${this.l1Url}/bridge/status/${lockId}`);
  }

  /**
   * Get all L1 locks for this wallet
   */
  async getL1Locks() {
    return this.request('GET', `${this.l2Url}/bridge/locks/${this.address}`);
  }

  /**
   * Get bridge statistics
   */
  async getBridgeStats() {
    return this.request('GET', `${this.l1Url}/bridge/stats`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // L2 → L1 BRIDGE (WITHDRAW)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Withdraw tokens from L2 back to L1
   */
  async withdrawToL1(amount, targetAddress = null) {
    console.log(`\n🏧 Withdrawing ${amount} $BB from L2 → L1`);
    
    const payload = {
      amount: amount,
      target_address: targetAddress || this.address,
    };
    
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/bridge/withdraw');
    
    return this.request('POST', `${this.l2Url}/bridge/withdraw`, signedRequest);
  }

  /**
   * Get full bridge overview
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
      // No locks
    }
    
    return {
      l1_balance: l1Balance.balance || l1Balance.available || 0,
      l2_balance: l2Balance.balance || 0,
      l1_locks: locks,
      total_locked: locks.reduce((sum, l) => sum + (l.amount || 0), 0),
      needs_bridge: l2Balance.balance === 0 && (l1Balance.balance || l1Balance.available || 0) > 0,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CREDIT LINE - L1-BACKED BORROWING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Draw credit from L1 to L2 (opens credit session)
   */
  async drawCredit(amount, reason = "betting") {
    console.log(`\n🔓 Drawing ${amount} $BB credit for: ${reason}`);
    
    const payload = { amount, reason };
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/credit/draw');
    
    return this.request('POST', `${this.l2Url}/credit/draw`, signedRequest);
  }

  /**
   * Settle credit line session
   */
  async settleCredit(sessionId, finalL2Balance, lockedInBets = 0) {
    console.log(`\n🔒 Settling credit session: ${sessionId}`);
    
    const payload = {
      session_id: sessionId,
      final_l2_balance: finalL2Balance,
      locked_in_bets: lockedInBets,
    };
    
    const signedRequest = this.createSignedRequest(payload, CHAIN_ID_L2, '/credit/settle');
    
    return this.request('POST', `${this.l2Url}/credit/settle`, signedRequest);
  }

  /**
   * Get current credit balance
   */
  async getCreditBalance(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/credit/balance/${wallet}`);
  }

  /**
   * List all credit sessions
   */
  async listCreditSessions() {
    return this.request('GET', `${this.l2Url}/credit/sessions`);
  }

  /**
   * Open credit line for a user (dealer function)
   */
  async openCreditForUser({ lockId, walletAddress, creditAmount }) {
    console.log(`\n🔓 Opening credit for: ${walletAddress.substring(0, 20)}...`);
    
    const message = `CREDIT_OPEN:${walletAddress}:${creditAmount}:${lockId}`;
    const signature = this.sign(message, CHAIN_ID_L2);
    
    return this.request('POST', `${this.l2Url}/credit/open`, {
      lock_id: lockId,
      wallet_address: walletAddress,
      credit_amount: creditAmount,
      l2_public_key: this.publicKey,
      signature,
    });
  }

  /**
   * Get credit status for any user
   */
  async getCreditStatus(walletAddress) {
    return this.request('GET', `${this.l2Url}/credit/status/${walletAddress}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET CREATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new prediction market
   */
  async createMarket({
    title,
    description = '',
    outcomes = ['Yes', 'No'],
    initialLiquidity = 1000,
    closesAt,
    resolutionCriteria = '',
    category = 'general',
    parentMarketId = null,
    source = null,
  }) {
    console.log(`\n🏗️ Creating market: "${title}"`);
    console.log(`   Outcomes: ${outcomes.join(', ')}`);
    console.log(`   Liquidity: ${initialLiquidity} $BB`);
    
    const closesAtTs = closesAt instanceof Date 
      ? Math.floor(closesAt.getTime() / 1000) 
      : closesAt;
    
    const result = await this.request('POST', `${this.l2Url}/markets`, {
      title,
      description,
      outcomes,
      initial_liquidity: initialLiquidity,
      closes_at: closesAtTs,
      resolution_criteria: resolutionCriteria,
      category,
      parent_market_id: parentMarketId,
      source,
      creator: this.address,
    });
    
    console.log(`   ✅ Market created: ${result.market_id || result.id}`);
    return result;
  }

  /**
   * Create a prop bet under a parent market
   */
  async createProp(parentMarketId, options) {
    return this.createMarket({ ...options, parentMarketId });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET INFORMATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get all markets
   */
  async getMarkets() {
    return this.request('GET', `${this.l2Url}/markets`);
  }

  /**
   * Get a specific market
   */
  async getMarket(marketId) {
    return this.request('GET', `${this.l2Url}/markets/${marketId}`);
  }

  /**
   * Get market CPMM prices and pool info
   */
  async getMarketPrices(marketId) {
    return this.request('GET', `${this.l2Url}/markets/${marketId}/prices`);
  }

  /**
   * Get all bets for a market
   */
  async getMarketBets(marketId) {
    return this.request('GET', `${this.l2Url}/markets/${marketId}/bets`);
  }

  /**
   * Get markets organized by lifecycle stage
   */
  async getMarketsByStage() {
    const data = await this.getMarkets();
    const markets = data.markets || [];
    const now = Math.floor(Date.now() / 1000);
    
    const result = {
      active: [],
      frozen: [],
      resolved: [],
    };
    
    for (const m of markets) {
      const freezeDate = m.betting_closes_at || m.closes_at;
      
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
      },
    };
  }

  /**
   * Get markets ready for resolution (frozen, not resolved)
   */
  async getMarketsAwaitingResolution() {
    const byStage = await this.getMarketsByStage();
    return byStage.frozen.map(m => ({
      id: m.id,
      title: m.title,
      frozenAt: m.betting_closes_at || m.closes_at,
      outcomes: m.options || m.outcomes,
      volume: m.total_volume,
    }));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BETTING & MARKET MAKING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Place a bet on a market outcome
   */
  async placeBet(marketId, outcome, amount) {
    console.log(`\n🎲 Betting ${amount} $BB on outcome ${outcome} in ${marketId}`);
    
    const request = this.createSignedBetRequest(marketId, outcome, amount);
    const result = await this.request('POST', `${this.l2Url}/bet`, request);
    
    if (!result.success) throw new Error(result.error || 'Bet failed');
    console.log(`   ✅ Bet placed`);
    return result;
  }

  /**
   * Place bets on multiple outcomes to provide liquidity
   */
  async placeLiquidityBets(marketId, amounts) {
    console.log(`\n💧 Placing liquidity bets on ${marketId}`);
    
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
   */
  async balanceMarket(marketId, amount, targetSpread = 0.05) {
    const prices = await this.getMarketPrices(marketId);
    
    if (!prices.cpmm_enabled) {
      throw new Error('Market does not have CPMM enabled');
    }
    
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
    
    const result = await this.placeBet(marketId, cheapest.index, amount);
    
    return {
      action: 'balanced',
      outcome: cheapest.label,
      amount,
      oldPrice: cheapest.price,
      newPrice: result.new_price,
      result,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CPMM PRICING & ANALYTICS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get real-time prices for all outcomes
   */
  async getPrices(marketId) {
    const data = await this.getMarketPrices(marketId);
    return {
      marketId,
      cpmmEnabled: data.cpmm_enabled,
      prices: data.prices?.map(p => ({
        outcome: p.index,
        label: p.label,
        price: p.price,
        probability: p.probability_percent,
        reserve: p.reserve,
        volume: p.total_volume_bb,
        betCount: p.bet_count,
      })) || [],
      pool: data.pool ? {
        tvl: data.pool.tvl,
        reserves: data.pool.reserves,
        k: data.pool.k,
        feesCollected: data.pool.fees_collected,
        lpSupply: data.pool.lp_token_supply,
      } : null,
      feeRate: data.fee_rate,
      totalVolume: data.total_market_volume,
      totalBets: data.total_bets,
    };
  }

  /**
   * Preview a trade before placing
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
    
    const reserves = data.pool.reserves;
    const k = data.pool.k;
    
    let sharesOut, newPrice, priceImpact, effectivePrice;
    
    if (reserves.length === 2) {
      const x = reserves[outcome];
      const y = reserves[1 - outcome];
      const newY = y + amountAfterFee;
      const newX = k / newY;
      sharesOut = x - newX;
      const newTotal = newX + newY;
      newPrice = newY / newTotal;
      effectivePrice = amount / sharesOut;
      priceImpact = effectivePrice - currentPrice;
    } else {
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
      sharesOut: sharesOut?.toFixed(4),
      effectivePrice: effectivePrice?.toFixed(4),
      newPrice: newPrice?.toFixed(4),
      priceImpact: priceImpact?.toFixed(4),
      priceImpactPercent: ((priceImpact || 0) * 100).toFixed(2) + '%',
      slippage: (((effectivePrice || 0) - currentPrice) / currentPrice * 100).toFixed(2) + '%',
    };
  }

  /**
   * Subscribe to real-time price updates (polling)
   */
  subscribeToPrices(marketId, callback, intervalMs = 2000) {
    let lastPrices = null;
    
    const poll = async () => {
      try {
        const prices = await this.getPrices(marketId);
        const priceKey = prices.prices.map(p => p.price?.toFixed(4)).join(',');
        if (priceKey !== lastPrices) {
          lastPrices = priceKey;
          callback(prices);
        }
      } catch (e) {
        console.error('Price poll error:', e.message);
      }
    };
    
    poll();
    const interval = setInterval(poll, intervalMs);
    return () => clearInterval(interval);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ORACLE RESOLUTION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Resolve a market and pay winners
   */
  async resolveMarket(marketId, winningOutcome) {
    console.log(`\n⚖️ Resolving market: ${marketId}`);
    console.log(`   Winning outcome: ${winningOutcome}`);
    
    const result = await this.request('POST', `${this.l2Url}/resolve`, {
      market_id: marketId,
      winning_outcome: winningOutcome,
      caller: this.address,
    });
    
    if (result.success) {
      console.log(`   ✅ Market resolved!`);
      console.log(`   Total payouts: ${result.payouts?.length || 0} winners`);
      
      if (result.payouts?.length > 0) {
        console.log(`   Payouts:`);
        for (const [address, amount] of result.payouts) {
          console.log(`     ${address.substring(0, 20)}... → ${amount.toFixed(2)} $BB`);
        }
      }
    }
    
    return result;
  }

  /**
   * Instantly resolve a market (TESTING - skips dispute window)
   */
  async instantResolve(marketId, winningOutcome, reason = 'Instant resolution') {
    console.log(`\n⚡ Instant resolve: ${marketId}`);
    
    return this.request('POST', `${this.l2Url}/dealer/markets/${marketId}/instant-resolve`, {
      dealer_key: this.address,
      winning_outcome: winningOutcome,
      reason,
    });
  }

  /**
   * Propose a resolution (starts 24hr dispute window)
   */
  async proposeResolution(marketId, outcome, evidence = null) {
    console.log(`\n📋 Proposing resolution for: ${marketId}`);
    
    return this.request('POST', `${this.l2Url}/markets/${marketId}/propose-resolution`, {
      proposer: this.address,
      proposed_outcome: outcome,
      evidence_url: evidence,
    });
  }

  /**
   * Dispute a pending resolution
   */
  async disputeResolution(marketId, reason, proposedOutcome = null, evidence = null) {
    return this.request('POST', `${this.l2Url}/markets/${marketId}/dispute`, {
      disputer: this.address,
      reason,
      proposed_outcome: proposedOutcome,
      evidence_url: evidence,
    });
  }

  /**
   * Finalize resolution after dispute window
   */
  async finalizeResolution(marketId) {
    return this.request('POST', `${this.l2Url}/markets/${marketId}/finalize`, {
      caller: this.address,
    });
  }

  /**
   * Void a market (cancel and refund all)
   */
  async voidMarket(marketId, reason) {
    console.log(`\n🚫 Voiding market: ${marketId}`);
    console.log(`   Reason: ${reason}`);
    
    const result = await this.request('POST', `${this.l2Url}/markets/${marketId}/void`, {
      caller: this.address,
      reason,
    });
    
    console.log(`   ✅ Market voided`);
    return result;
  }

  /**
   * Resolve a dispute (Oracle authority)
   */
  async resolveDispute(marketId, disputeId, decision, finalOutcome = null, reason = '') {
    return this.request('POST', `${this.l2Url}/markets/${marketId}/resolve-dispute`, {
      oracle: this.address,
      dispute_id: disputeId,
      decision,
      final_outcome: finalOutcome,
      reason,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Freeze a market (stop accepting bets)
   */
  async freezeMarket(marketId) {
    console.log(`\n❄️ Freezing market: ${marketId}`);
    
    const result = await this.request('POST', `${this.l2Url}/markets/${marketId}/freeze`, {
      caller: this.address,
    });
    
    console.log(`   ✅ Market frozen`);
    return result;
  }

  /**
   * Reopen a frozen market
   */
  async reopenMarket(marketId) {
    console.log(`\n🔓 Reopening market: ${marketId}`);
    
    const result = await this.request('POST', `${this.l2Url}/markets/${marketId}/reopen`, {
      caller: this.address,
    });
    
    console.log(`   ✅ Market reopened`);
    return result;
  }

  /**
   * Close a market (dealer function)
   */
  async closeMarket(marketId, reason = 'Closed by dealer') {
    return this.request('POST', `${this.l2Url}/dealer/markets/${marketId}/close`, {
      dealer_key: this.address,
      reason,
    });
  }

  /**
   * Set freeze date for a market
   */
  async setFreezeDate(marketId, freezeDate) {
    const timestamp = freezeDate instanceof Date 
      ? Math.floor(freezeDate.getTime() / 1000)
      : freezeDate;
    
    return this.request('POST', `${this.l2Url}/dealer/markets/${marketId}/set-freeze`, {
      dealer_key: this.address,
      freeze_timestamp: timestamp,
    });
  }

  /**
   * Delete a market (only if no bets)
   */
  async deleteMarket(marketId) {
    console.log(`\n🗑️ Deleting market: ${marketId}`);
    
    const result = await this.request('DELETE', `${this.l2Url}/markets/${marketId}`, {
      caller: this.address,
    });
    
    console.log(`   ✅ Market deleted`);
    return result;
  }

  /**
   * Initialize all markets with CPMM pools
   */
  async initAllMarkets(liquidity = 10000) {
    return this.request('POST', `${this.l2Url}/dealer/markets/init-all`, {
      dealer_key: this.address,
      initial_liquidity: liquidity,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LIQUIDITY MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Add liquidity to a market
   */
  async addLiquidity(marketId, amount) {
    console.log(`\n💧 Adding liquidity to ${marketId}: ${amount} $BB`);
    
    const result = await this.request('POST', `${this.l2Url}/markets/${marketId}/liquidity`, {
      amount,
      address: this.address,
      action: 'add',
    });
    
    console.log(`   ✅ Liquidity added`);
    return result;
  }

  /**
   * Remove liquidity from a market
   */
  async removeLiquidity(marketId, shares) {
    console.log(`\n💧 Removing liquidity from ${marketId}: ${shares} shares`);
    
    const result = await this.request('POST', `${this.l2Url}/markets/${marketId}/liquidity`, {
      shares,
      address: this.address,
      action: 'remove',
    });
    
    console.log(`   ✅ Liquidity removed`);
    return result;
  }

  /**
   * Fund all markets with equal liquidity
   */
  async fundAllMarkets(amountPerMarket = 0) {
    return this.request('POST', `${this.l2Url}/dealer/fund-all-markets`, {
      dealer_address: this.address,
      amount_per_market: amountPerMarket,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DRAFT EVENT MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get all draft events
   */
  async getDrafts() {
    return this.request('GET', `${this.l2Url}/drafts`);
  }

  /**
   * Get a specific draft
   */
  async getDraft(draftId) {
    return this.request('GET', `${this.l2Url}/drafts/${draftId}`);
  }

  /**
   * Create a new draft
   */
  async createDraft(draft) {
    return this.request('POST', `${this.l2Url}/drafts`, draft);
  }

  /**
   * Update a draft
   */
  async updateDraft(draftId, updates) {
    return this.request('POST', `${this.l2Url}/drafts/${draftId}/update`, updates);
  }

  /**
   * Launch a draft as a live market
   */
  async launchDraft(draftId) {
    return this.request('POST', `${this.l2Url}/drafts/${draftId}/launch`);
  }

  /**
   * Delete a draft
   */
  async deleteDraft(draftId) {
    return this.request('DELETE', `${this.l2Url}/drafts/${draftId}`);
  }

  /**
   * Complete and launch a draft
   */
  async completeDraftAndLaunch(draftId, completionData) {
    const updateResult = await this.updateDraft(draftId, completionData);
    
    if (!updateResult.can_launch) {
      return {
        success: false,
        error: 'Draft still has validation errors',
        validation_errors: updateResult.validation_errors,
      };
    }
    
    return this.launchDraft(draftId);
  }

  /**
   * Get draft inbox summary
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
        createdAt: d.created_at ? new Date(d.created_at * 1000).toISOString() : null,
      })),
    };
  }

  /**
   * Subscribe to draft inbox changes
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

  // ═══════════════════════════════════════════════════════════════════════════
  // USER POSITIONS & P&L
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get all dealer positions
   */
  async getPositions(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/dealer/positions/${wallet}`);
  }

  /**
   * Get user betting history
   */
  async getUserBettingHistory(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/user/${wallet}/betting-history`);
  }

  /**
   * Get user P&L summary
   */
  async getUserPnL(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/user/${wallet}/pnl`);
  }

  /**
   * Get user bets
   */
  async getUserBets(address = null) {
    const wallet = address || this.address;
    return this.request('GET', `${this.l2Url}/user/${wallet}/bets`);
  }

  /**
   * Calculate P&L for all positions
   */
  async calculatePnL() {
    const positions = await this.getPositions();
    
    let totalInvested = 0;
    let totalCurrentValue = 0;
    const marketPnL = [];
    
    for (const position of positions.positions || []) {
      const prices = await this.getMarketPrices(position.market_id).catch(() => ({ prices: [] }));
      
      let marketValue = 0;
      let marketInvested = 0;
      
      for (const pos of position.outcomes || []) {
        const price = prices.prices?.find(p => p.index === pos.outcome)?.price || 0.5;
        const value = pos.shares * price;
        marketValue += value;
        marketInvested += pos.total_invested || pos.shares * 0.5;
      }
      
      totalInvested += marketInvested;
      totalCurrentValue += marketValue;
      
      marketPnL.push({
        market_id: position.market_id,
        title: position.title,
        invested: marketInvested,
        current_value: marketValue,
        pnl: marketValue - marketInvested,
        pnl_percent: marketInvested > 0 ? ((marketValue - marketInvested) / marketInvested * 100) : 0,
      });
    }
    
    return {
      total_invested: totalInvested,
      total_current_value: totalCurrentValue,
      total_pnl: totalCurrentValue - totalInvested,
      total_pnl_percent: totalInvested > 0 ? ((totalCurrentValue - totalInvested) / totalInvested * 100) : 0,
      markets: marketPnL,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ANALYTICS & DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════════

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
        l1: l1Balance.balance || l1Balance.available || 0,
        l2: l2Balance.balance || 0,
        total: (l1Balance.balance || l1Balance.available || 0) + (l2Balance.balance || 0),
      },
      positions: positions.positions?.length || 0,
      total_invested: pnl.total_invested || 0,
      total_value: pnl.total_current_value || 0,
      pnl: pnl.total_pnl || 0,
      pnl_percent: pnl.total_pnl_percent || 0,
    };
  }

  /**
   * Get dealer balance
   */
  async getBalance() {
    const result = await this.getL2BalanceDetails();
    console.log(`\n💰 Dealer Balance:`);
    console.log(`   Available: ${result.available || result.balance} $BB`);
    console.log(`   Locked: ${result.locked || 0} $BB`);
    return result;
  }

  /**
   * Get all L2 balances
   */
  async getAllBalances() {
    return this.request('GET', `${this.l2Url}/balances`);
  }

  /**
   * Get summary statistics
   */
  async getStats() {
    const [markets, balance] = await Promise.all([
      this.getMarkets(),
      this.getBalance().catch(() => ({ available: 0 })),
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
      dealerBalance: balance.available || balance.balance || 0,
      estimatedFees: totalVolume * 0.01,
    };
  }

  /**
   * Get ledger activity
   */
  async getLedger(options = {}) {
    const params = new URLSearchParams();
    if (options.limit) params.set('limit', options.limit);
    if (options.type) params.set('type', options.type);
    if (options.account) params.set('account', options.account);
    
    const url = `${this.l2Url}/ledger${params.toString() ? '?' + params : ''}`;
    return this.request('GET', url);
  }

  /**
   * Get payout history
   */
  async getPayoutHistory(limit = 50) {
    return this.request('GET', `${this.l2Url}/ledger/transactions?type=payout&limit=${limit}`);
  }

  /**
   * Get complete dashboard summary
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

  /**
   * Check L2 server health
   */
  async health() {
    return this.request('GET', `${this.l2Url}/health`);
  }

  /**
   * Get current state root
   */
  async getStateRoot() {
    return this.request('GET', `${this.l2Url}/state_root`);
  }

  /**
   * Withdraw dealer funds from L2 to L1
   */
  async withdraw(amount, destinationL1 = null) {
    console.log(`\n🏧 Withdrawing ${amount} $BB to L1`);
    
    return this.request('POST', `${this.l2Url}/withdraw`, {
      address: this.address,
      amount,
      destination: destinationL1 || this.address.replace('L2_', 'L1_'),
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Calculate expected payouts before resolution
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
      : 0,
  }));
  
  return {
    totalPool,
    fee,
    poolAfterFee,
    winningBets: winningBets.length,
    losingBets: bets.length - winningBets.length,
    totalWinningShares,
    payouts,
  };
}

/**
 * Create dealer SDK with environment variables
 */
export function createDealerSDK(options = {}) {
  return new UnifiedDealerSDK({
    l1Url: process.env.L1_URL || 'http://localhost:8080',
    l2Url: process.env.L2_URL || 'http://localhost:1234',
    privateKey: process.env.DEALER_PRIVATE_KEY || process.env.dealer_private_key,
    address: process.env.DEALER_ADDRESS || ORACLE_ADDRESS,
    ...options,
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export default UnifiedDealerSDK;

// ═══════════════════════════════════════════════════════════════════════════
// CLI DEMO
// ═══════════════════════════════════════════════════════════════════════════

async function demo() {
  console.log("═".repeat(70));
  console.log("🎰 UNIFIED DEALER SDK DEMO - L1 + L2 OPERATIONS");
  console.log("═".repeat(70));
  
  const dealer = createDealerSDK();
  
  try {
    // ═══════════════════════════════════════════════════════════════════════
    // BRIDGE OVERVIEW
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("🌉 BRIDGE OVERVIEW:");
    console.log("─".repeat(70));
    
    const bridge = await dealer.getBridgeOverview();
    console.log(`   L1 Balance: ${bridge.l1_balance} $BC`);
    console.log(`   L2 Balance: ${bridge.l2_balance} $BB`);
    console.log(`   Total Locked: ${bridge.total_locked} $BC`);
    console.log(`   Needs Bridge: ${bridge.needs_bridge ? 'YES' : 'NO'}`);
    
    // ═══════════════════════════════════════════════════════════════════════
    // MARKET LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("📈 MARKET LIFECYCLE:");
    console.log("─".repeat(70));
    
    const lifecycle = await dealer.getMarketsByStage();
    console.log(`   🟢 Active: ${lifecycle.summary.active}`);
    console.log(`   🔵 Frozen: ${lifecycle.summary.frozen}`);
    console.log(`   ⚪ Resolved: ${lifecycle.summary.resolved}`);
    
    // ═══════════════════════════════════════════════════════════════════════
    // DASHBOARD
    // ═══════════════════════════════════════════════════════════════════════
    console.log("\n" + "─".repeat(70));
    console.log("🎛️ DEALER DASHBOARD:");
    console.log("─".repeat(70));
    
    const dashboard = await dealer.getDashboard();
    console.log(`   L1: ${dashboard.balances?.l1 || 0} $BC`);
    console.log(`   L2: ${dashboard.balances?.l2 || 0} $BB`);
    console.log(`   Markets: ${dashboard.markets?.total || 0} total`);
    console.log(`   Drafts: ${dashboard.drafts?.total || 0}`);
    
    console.log("\n" + "═".repeat(70));
    console.log("✅ Unified SDK ready for L1 + L2 operations!");
    console.log("═".repeat(70));
    
    // Print help
    console.log("\n📖 LAYER 1 OPERATIONS:");
    console.log("   dealer.getL1Balance()              - Get L1 balance");
    console.log("   dealer.l1Transfer(to, amount)      - Transfer on L1");
    console.log("   dealer.bridgeToL2(amount)          - Bridge L1 → L2");
    
    console.log("\n📖 LAYER 2 OPERATIONS:");
    console.log("   dealer.getL2Balance()              - Get L2 balance");
    console.log("   dealer.connectWallet()             - Connect to L2");
    console.log("   dealer.withdrawToL1(amount)        - Withdraw L2 → L1");
    
    console.log("\n📖 MARKET OPERATIONS:");
    console.log("   dealer.createMarket({...})         - Create market");
    console.log("   dealer.placeBet(id, outcome, amt)  - Place bet");
    console.log("   dealer.resolveMarket(id, winner)   - Resolve market");
    console.log("   dealer.voidMarket(id, reason)      - Void market");
    
    console.log("\n📖 CREDIT LINE:");
    console.log("   dealer.drawCredit(amount, reason)  - Draw from L1");
    console.log("   dealer.settleCredit(session, bal)  - Settle session");
    
    console.log("\n📖 ANALYTICS:");
    console.log("   dealer.getDashboard()              - Full dashboard");
    console.log("   dealer.getPortfolioOverview()      - Portfolio summary");
    console.log("   dealer.calculatePnL()              - P&L calculation");
    
  } catch (e) {
    console.error("❌ Error:", e.message);
  }
}

// Run demo if executed directly
const isMain = process.argv[1] && (
  process.argv[1].endsWith('unified-dealer-sdk.js') ||
  process.argv[1].includes('unified-dealer-sdk')
);

if (isMain) {
  demo().catch(console.error);
}
