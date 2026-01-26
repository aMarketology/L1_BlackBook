/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CREDIT PREDICTION ACTIONS SDK - v3 PRODUCTION
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Frontend SDK for BlackBook L2 - Real L1 Integration & Prediction Markets
 * 
 * ⚠️  PRODUCTION MODE - L1 gRPC Required:
 *    - L1 server must be running at localhost:50051
 *    - All deposits verify REAL L1 balances via gRPC
 *    - No simulated deposits - production L1 verification only
 * 
 * SETTLEMENT ROADMAP (January 2026):
 * ══════════════════════════════════════════════════════════════════════════
 * 
 * PHASE 1: DEALER DEPOSITS (✅ IMPLEMENTED - v3)
 *   Endpoint: POST /deposit
 *   Requirements: Dealer signature + L1 balance verification via gRPC
 *   
 * PHASE 2: CPMM TRADING (✅ IMPLEMENTED)
 *   Endpoints: POST /buy, POST /sell
 *   Features: Real-time pricing, Ed25519 signatures
 *   
 * PHASE 3: ORACLE RESOLUTION (✅ IMPLEMENTED)  
 *   Endpoint: POST /resolve
 *   Requirements: Dealer signature + oracle authentication
 *   Auto-features: Payout calculation, balance distribution
 *   
 * PHASE 4: WITHDRAWALS (✅ IMPLEMENTED)
 *   Flow: POST /withdraw → POST /withdraw/complete
 *   Requirements: Dual dealer signatures for security
 * 
 * PHASE 5: CREDIT LINES (⚠️ NOT IMPLEMENTED)
 *   Status: Planned for future release
 *   Credit line endpoints (/credit/*) are deprecated in v3
 * 
 * ⚠️  CRITICAL: Dealer operations require Ed25519 signatures with replay protection
 * 
 * Usage:
 *   const sdk = new CreditPredictionSDK({
 *     l2Url: 'http://localhost:1234',
 *     supabaseUrl: 'https://xxx.supabase.co',
 *     supabaseKey: 'your-anon-key',
 *     address: 'L2_YOUR_ADDRESS',
 *     publicKey: 'your-ed25519-public-key-hex',
 *     signer: async (msg) => wallet.sign(msg)
 *   });
 * 
 *   // User flow
 *   await sdk.openCredit(1000);
 *   await sdk.bet('market-id', 0, 100);
 *   await sdk.settleCredit();
 * 
 *   // Dealer flow (requires dealer private key)
 *   const dealerSdk = new CreditPredictionSDK({ ...config, isDealerMode: true });
 *   await dealerSdk.confirmDeposit({ ... });
 *   await dealerSdk.resolveMarket('market-id', 0);
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { createClient } from '@supabase/supabase-js';

// ═══════════════════════════════════════════════════════════════════════════
// MAIN SDK CLASS
// ═══════════════════════════════════════════════════════════════════════════

export class CreditPredictionSDK {
  constructor(config) {
    this.l2Url = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
    this.l1Url = (config.l1Url || 'http://localhost:8080').replace(/\/$/, '');
    this.address = config.address;
    this.publicKey = config.publicKey;  // Ed25519 public key for signing
    this.signer = config.signer;
    this.listeners = [];
    
    // Dealer mode - enables clearinghouse confirmations and resolution
    this.isDealerMode = config.isDealerMode || false;
    
    // Supabase for markets
    if (config.supabaseUrl && config.supabaseKey) {
      this.supabase = createClient(config.supabaseUrl, config.supabaseKey);
    }
    
    // Active credit session tracking
    this.activeSession = null;
    
    // Nonce counter for replay protection
    this._nonceCounter = Date.now();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNING & REPLAY PROTECTION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Generate a unique nonce for replay protection
   */
  generateNonce() {
    return `${Date.now()}_${++this._nonceCounter}_${Math.random().toString(36).slice(2, 10)}`;
  }

  async signTransaction(tx) {
    const message = JSON.stringify(tx);
    const signature = await this.signer(message);
    return { tx, signature, signer: this.address };
  }

  /**
   * Sign a message with dealer authentication format (for protected endpoints)
   * Required for: /clearinghouse/deposit, /clearinghouse/withdraw/complete, /resolve
   * @param {object} payload - The payload to sign
   * @returns {object} Signed payload with dealer auth fields
   */
  async signDealerMessage(payload) {
    if (!this.publicKey) {
      throw new Error('publicKey required for dealer operations');
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = this.generateNonce();
    
    const message = JSON.stringify({
      action: payload.action || 'dealer_operation',
      timestamp,
      nonce,
      payload
    });
    
    const signature = await this.signer(message);
    
    return {
      ...payload,
      dealer_public_key: this.publicKey,
      dealer_signature: signature,
      timestamp,
      nonce
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BRIDGE: L1 ($BC) → L2 ($BB)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get L1 ($BC) balance for connected wallet
   * @returns {Promise<{available: number, locked: number}>}
   */
  async getL1Balance() {
    // Convert L2 address to L1 format if needed
    const l1Address = this.address.startsWith('L2_') 
      ? this.address.replace('L2_', 'L1_') 
      : this.address.startsWith('L1_') 
        ? this.address 
        : `L1_${this.address}`;
    
    try {
      const res = await this.l1Get(`/balance/${l1Address}`);
      return {
        available: res.available ?? res.balance ?? 0,
        locked: res.locked ?? 0
      };
    } catch (error) {
      throw new Error(`Failed to get L1 balance: ${error.message}. Is L1 server running?`);
    }
  }

  /**
   * Lock $BC on L1 (Step 1 of bridge)
   * @param {number} amount - Amount of $BC to lock
   * @returns {Promise<{lockId: string, l1TxHash: string, amount: number}>}
   */
  async bridgeLockOnL1(amount) {
    if (!this.publicKey) {
      throw new Error('publicKey required in SDK config for L1 bridge operations');
    }

    const nonce = crypto.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const timestamp = Math.floor(Date.now() / 1000);

    // L1 payload structure
    const payload = {
      amount: amount,
      target_layer: "L2"
    };
    const payloadStr = JSON.stringify(payload);

    // Sign for L1 (chain_id=1 for L1)
    const messageToSign = `1${payloadStr}\n${timestamp}\n${nonce}`;
    const signature = await this.signer(messageToSign);

    const res = await this.l1Post('/bridge/initiate', {
      payload: payloadStr,
      public_key: this.publicKey,
      signature: signature,
      nonce: nonce,
      timestamp: timestamp,
      chain_id: 1
    });

    if (res.error) {
      throw new Error(`L1 bridge lock failed: ${res.error}`);
    }

    return {
      lockId: res.lock_id || res.lockId,
      l1TxHash: res.tx_hash || res.l1_tx_hash || `tx_${res.lock_id}`,
      amount: res.amount || amount
    };
  }

  /**
   * Claim $BB on L2 after locking on L1 (Step 2 of bridge)
   * @param {string} lockId - Lock ID from L1 bridge/initiate
   * @param {number} amount - Amount locked on L1
   * @param {string} l1TxHash - L1 transaction hash
   * @returns {Promise<{success: boolean, newBalance: number}>}
   */
  async bridgeClaimOnL2(lockId, amount, l1TxHash) {
    if (!this.publicKey) {
      throw new Error('publicKey required in SDK config for L2 bridge claims');
    }

    // Sign for L2 claim
    const claimPayload = { lock_id: lockId, amount: amount, l1_tx_hash: l1TxHash };
    const signature = await this.signer(JSON.stringify(claimPayload));

    const res = await this.l2Post('/bridge/credit', {
      lock_id: lockId,
      address: this.address,
      amount: amount,
      l1_tx_hash: l1TxHash,
      signature: signature,
      l1_pubkey: this.publicKey
    });

    if (res.error) {
      throw new Error(`L2 bridge claim failed: ${res.error}`);
    }

    this.emit({ type: 'bridge_completed', lockId, amount });

    return {
      success: true,
      newBalance: res.new_balance || res.balance || amount
    };
  }

  /**
   * Full bridge flow: Lock $BC on L1 → Credit $BB on L2
   * @param {number} amount - Amount to bridge
   * @returns {Promise<{success: boolean, lockId: string, newL2Balance: number}>}
   */
  async bridge(amount) {
    // Step 1: Check L1 balance
    const l1Balance = await this.getL1Balance();
    if (l1Balance.available < amount) {
      throw new Error(`Insufficient L1 balance: ${l1Balance.available} < ${amount}. Deposit $BC on L1 first.`);
    }

    // Step 2: Lock on L1
    this.emit({ type: 'bridge_started', amount });
    const lock = await this.bridgeLockOnL1(amount);

    // Step 3: Claim on L2
    const claim = await this.bridgeClaimOnL2(lock.lockId, amount, lock.l1TxHash);

    return {
      success: true,
      lockId: lock.lockId,
      newL2Balance: claim.newBalance
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BALANCE & USER STATUS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get L2 balance for connected wallet
   */
  async getBalance() {
    const res = await this.l2Get(`/balance/${this.address}`);
    return {
      available: res.l2_available || 0,
      locked: res.l2_locked || 0,
      hasActiveCredit: res.has_active_credit || false
    };
  }

  /**
   * Get unified L1/L2 balance view
   */
  async getUnifiedBalance() {
    const res = await this.l2Get(`/unified/balance/${this.address}`);
    return {
      l1Available: res.l1_available || 0,
      l1Locked: res.l1_locked || 0,
      l2Available: res.l2_available || 0,
      l2Locked: res.l2_locked || 0,
      totalAvailable: res.total_available || 0,
      hasActiveCredit: res.has_active_credit || false
    };
  }

  /**
   * Get comprehensive user status (balance + positions + bets + credit)
   */
  async getUserStatus() {
    const res = await this.l2Get(`/user/status/${this.address}`);
    return res;
  }

  /**
   * Get all positions for connected wallet
   */
  async getPositions() {
    const res = await this.l2Get(`/unified/positions/${this.address}`);
    return res.positions || [];
  }

  /**
   * Get full portfolio (balance + positions + P&L)
   */
  async getPortfolio() {
    const [balance, positions] = await Promise.all([
      this.getBalance(),
      this.getPositions()
    ]);
    
    const totalValue = balance.available + positions.reduce((sum, p) => sum + (p.currentValue || 0), 0);
    const totalPnl = positions.reduce((sum, p) => sum + (p.unrealizedPnl || 0), 0);
    
    return { balance, positions, totalValue, totalPnl };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CLEARINGHOUSE (Dealer-Controlled Deposits & Withdrawals)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Confirm a deposit (DEALER ONLY - requires dealer signature)
   * Called after L1 lock is verified
   * @param {object} params - { userAddress, amount, l1TxHash, lockId }
   */
  async confirmDeposit(params) {
    if (!this.isDealerMode) {
      throw new Error('confirmDeposit requires dealer mode (isDealerMode: true)');
    }

    const payload = {
      action: 'deposit_confirm',
      user_address: params.userAddress,
      amount: params.amount,
      l1_tx_hash: params.l1TxHash,
      lock_id: params.lockId
    };

    const signedPayload = await this.signDealerMessage(payload);
    const res = await this.l2Post('/deposit', signedPayload);

    if (res.success) {
      this.emit({ type: 'deposit_confirmed', userAddress: params.userAddress, amount: params.amount });
    }

    return {
      success: res.success !== false,
      newBalance: res.new_balance,
      message: res.message || 'Deposit confirmed'
    };
  }

  /**
   * Request a withdrawal (user-initiated)
   * @param {number} amount - Amount to withdraw
   */
  async requestWithdrawal(amount) {
    const tx = {
      action: 'withdraw_request',
      wallet: this.address,
      amount,
      timestamp: Date.now()
    };

    const signed = await this.signTransaction(tx);
    const res = await this.l2Post('/withdraw', {
      ...signed,
      address: this.address,
      amount
    });

    if (res.success) {
      this.emit({ type: 'withdrawal_requested', amount, requestId: res.request_id });
    }

    return {
      success: res.success !== false,
      requestId: res.request_id,
      status: res.status || 'pending',
      message: res.message || 'Withdrawal requested'
    };
  }

  /**
   * Complete a withdrawal (DEALER ONLY - requires dealer signature)
   * @param {object} params - { requestId, userAddress, amount, l1TxHash }
   */
  async completeWithdrawal(params) {
    if (!this.isDealerMode) {
      throw new Error('completeWithdrawal requires dealer mode (isDealerMode: true)');
    }

    const payload = {
      action: 'withdraw_complete',
      request_id: params.requestId,
      user_address: params.userAddress,
      amount: params.amount,
      l1_tx_hash: params.l1TxHash
    };

    const signedPayload = await this.signDealerMessage(payload);
    const res = await this.l2Post('/withdraw/complete', signedPayload);

    if (res.success) {
      this.emit({ type: 'withdrawal_completed', userAddress: params.userAddress, amount: params.amount });
    }

    return {
      success: res.success !== false,
      message: res.message || 'Withdrawal completed'
    };
  }

  /**
   * Get pending withdrawals (for dealer dashboard)
   */
  async getPendingWithdrawals() {
    const res = await this.l2Get('/withdrawals/pending');
    return res.pending || [];
  }

  /**
   * Get clearinghouse statistics
   */
  async getClearinghouseStats() {
    const res = await this.l2Get('/clearinghouse/stats');
    return {
      totalDeposits: res.total_deposits || 0,
      totalWithdrawals: res.total_withdrawals || 0,
      pendingWithdrawals: res.pending_withdrawals || 0,
      netBalance: res.net_balance || 0,
      userCount: res.user_count || 0
    };
  }

  /**
   * Get user's deposit history
   */
  async getMyDeposits() {
    const res = await this.l2Get(`/clearinghouse/deposits/${this.address}`);
    return res.deposits || [];
  }

  /**
   * Get user's withdrawal history
   */
  async getMyWithdrawals() {
    const res = await this.l2Get(`/clearinghouse/withdrawals/${this.address}`);
    return res.withdrawals || [];
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CREDIT LINE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check if user has an active credit session
   * @deprecated Credit line endpoints not implemented in v3 production
   */
  async getCreditSession() {
    console.warn('⚠️ DEPRECATED: Credit line endpoints (/credit/*) not implemented in v3');
    throw new Error('Credit line feature not available in v3 production. Use deposits instead.');
    /*
    try {
      const res = await this.l2Get(`/credit/session/${this.address}`);
      this.activeSession = res.session || null;
      return this.activeSession;
    } catch {
      this.activeSession = null;
      return null;
    }
    */
  }

  /**
   * Open a credit line session
   * @param {number} amount - Amount of credit to request
   * @deprecated Credit line endpoints not implemented in v3 production
   */
  async openCredit(amount) {
    console.warn('⚠️ DEPRECATED: Credit line endpoints (/credit/*) not implemented in v3');
    throw new Error('Credit line feature not available in v3 production. Use confirmDeposit() for dealer deposits.');
    /*
    const tx = {
      action: 'credit_open',
      wallet: this.address,
      amount,
      timestamp: Date.now()
    };
    
    const signed = await this.signTransaction(tx);
    const res = await this.l2Post('/credit/open', signed);
    
    if (res.success !== false) {
      this.activeSession = {
        sessionId: res.session_id,
        creditAmount: res.credit_amount || amount,
        virtualBalance: res.virtual_balance || amount,
        openedAt: Date.now()
      };
      
      this.emit({ type: 'credit_opened', session: this.activeSession });
    }
    
    return {
      success: res.success !== false,
      sessionId: res.session_id,
      creditAmount: res.credit_amount || amount,
      virtualBalance: res.virtual_balance || amount,
      message: res.message || 'Credit opened'
    };
    */
  }

  /**
   * Settle and close the credit session
   * @deprecated Credit line endpoints not implemented in v3 production
   */
  async settleCredit() {
    console.warn('⚠️ DEPRECATED: Credit line endpoints (/credit/*) not implemented in v3');
    throw new Error('Credit line feature not available in v3 production.');
    /*
    const tx = {
      action: 'credit_settle',
      wallet: this.address,
      timestamp: Date.now()
    };
    
    const signed = await this.signTransaction(tx);
    const res = await this.l2Post('/credit/settle', signed);
    
    const pnl = res.pnl || 0;
    
    if (res.success !== false) {
      this.activeSession = null;
      this.emit({ type: 'credit_settled', pnl });
    }
    
    return {
      success: res.success !== false,
      sessionId: res.session_id || '',
      pnl,
      message: res.message || 'Credit settled'
    };
    */
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRADING (CPMM)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get a quote before placing a bet
   * @param {string} marketId - Market ID
   * @param {number} outcomeIndex - Which outcome (0, 1, etc.)
   * @param {number} amount - Amount to spend
   */
  async getQuote(marketId, outcomeIndex, amount) {
    const res = await this.l2Get(`/quote/${marketId}/${outcomeIndex}/${amount}`);
    return {
      shares: res.shares || 0,
      avgPrice: res.avg_price || res.avgPrice || 0,
      priceImpact: res.price_impact || res.priceImpact || 0,
      fee: res.fee || 0,
      total: res.total || amount
    };
  }

  /**
   * Place a bet (buy outcome shares)
   * @param {string} marketId - Market ID
   * @param {number} outcomeIndex - Which outcome (0, 1, etc.)
   * @param {number} amount - Amount to spend
   */
  async bet(marketId, outcomeIndex, amount) {
    const tx = {
      action: 'buy',
      wallet: this.address,
      market_id: marketId,
      outcome_index: outcomeIndex,
      amount,
      timestamp: Date.now()
    };
    
    const signed = await this.signTransaction(tx);
    const res = await this.l2Post('/cpmm/buy', signed);
    
    const result = {
      success: res.success !== false,
      shares: res.shares || 0,
      avgPrice: res.avg_price || 0,
      newPrices: res.new_prices || res.prices || [],
      txHash: res.tx_hash
    };
    
    if (result.success) {
      this.emit({ type: 'bet_placed', result, marketId, outcomeIndex, amount });
    }
    
    return result;
  }

  /**
   * Sell outcome shares
   * @param {string} marketId - Market ID
   * @param {number} outcomeIndex - Which outcome
   * @param {number} shares - Number of shares to sell
   */
  async sell(marketId, outcomeIndex, shares) {
    const tx = {
      action: 'sell',
      wallet: this.address,
      market_id: marketId,
      outcome_index: outcomeIndex,
      shares,
      timestamp: Date.now()
    };
    
    const signed = await this.signTransaction(tx);
    const res = await this.l2Post('/cpmm/sell', signed);
    
    return {
      success: res.success !== false,
      shares: res.shares || 0,
      avgPrice: res.avg_price || 0,
      newPrices: res.new_prices || res.prices || [],
      txHash: res.tx_hash
    };
  }

  /**
   * Get current prices for a market
   * @param {string} marketId - Market ID
   */
  async getPrices(marketId) {
    const res = await this.l2Get(`/cpmm/prices/${marketId}`);
    return res.prices || [];
  }

  /**
   * Get pool state (reserves, liquidity)
   * @param {string} marketId - Market ID
   */
  async getPool(marketId) {
    const res = await this.l2Get(`/cpmm/pool/${marketId}`);
    return {
      reserves: res.reserves || [],
      k: res.k || 0,
      liquidity: res.liquidity || 0
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKETS (from Supabase with L2 fallback)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get all active markets
   */
  async getMarkets() {
    if (!this.supabase) {
      // L2 fallback - returns server-filtered active markets
      const res = await this.l2Get('/markets');
      return res.markets || [];
    }
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('market_type', 'main')
      .eq('status', 'active')
      .order('is_featured', { ascending: false })
      .order('created_at', { ascending: false });
    
    if (error) throw new Error(`Failed to fetch markets: ${error.message}`);
    return data || [];
  }

  /**
   * Get pending markets (L2 only - markets awaiting liquidity)
   */
  async getPendingMarkets() {
    const res = await this.l2Get('/markets/pending');
    return res.markets || [];
  }

  /**
   * Get frozen markets (L2 only - past closes_at, awaiting resolution)
   */
  async getFrozenMarkets() {
    const res = await this.l2Get('/markets/frozen');
    return res.markets || [];
  }

  /**
   * Get resolved markets (L2 only - completed markets)
   * @param {object} options - { sort: 'closes_at'|'created_at', order: 'asc'|'desc' }
   */
  async getResolvedMarkets(options = {}) {
    const params = new URLSearchParams();
    if (options.sort) params.append('sort', options.sort);
    if (options.order) params.append('order', options.order);
    const query = params.toString();
    const res = await this.l2Get(`/markets/resolved${query ? '?' + query : ''}`);
    return res.markets || [];
  }

  /**
   * Get featured markets
   */
  async getFeaturedMarkets() {
    if (!this.supabase) return [];
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('status', 'active')
      .eq('is_featured', true)
      .order('created_at', { ascending: false });
    
    if (error) throw new Error(`Failed to fetch featured: ${error.message}`);
    return data || [];
  }

  /**
   * Get markets by category
   * @param {string} category - Category name
   */
  async getMarketsByCategory(category) {
    if (!this.supabase) return [];
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('category', category)
      .eq('status', 'active')
      .order('created_at', { ascending: false });
    
    if (error) throw new Error(`Failed to fetch: ${error.message}`);
    return data || [];
  }

  /**
   * Search markets
   * @param {string} query - Search query
   */
  async searchMarkets(query) {
    if (!this.supabase) return [];
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('status', 'active')
      .or(`title.ilike.%${query}%,description.ilike.%${query}%`)
      .limit(50);
    
    if (error) throw new Error(`Search failed: ${error.message}`);
    return data || [];
  }

  /**
   * Get single market by ID (with L2 prices and props)
   * @param {string|number} marketId - Market ID
   */
  async getMarket(marketId) {
    // Always fetch from L2 to get live prices and props
    const l2Data = await this.l2Get(`/market/${marketId}`);
    
    if (!this.supabase) {
      return l2Data;
    }
    
    // Optionally enrich with Supabase metadata
    const { data: sbData } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('market_id', marketId)
      .single();
    
    return {
      ...sbData,
      ...l2Data,  // L2 data takes precedence (live prices, props)
    };
  }

  /**
   * Get market with all its prop bets (L2 endpoint)
   * @param {string|number} marketId - Parent market ID
   */
  async getMarketWithProps(marketId) {
    // L2 /market/:id now includes props automatically
    return this.getMarket(marketId);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET LIFECYCLE (Draft → Pending → Active → Frozen → Resolved)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get draft markets awaiting dealer approval
   */
  async getDraftMarkets() {
    const res = await this.l2Get('/markets/drafts');
    return res.markets || [];
  }

  /**
   * Get full lifecycle status for a market
   * @param {string} marketId - Market ID
   * @returns {Promise<{current_status, is_draft, is_active, is_frozen, is_resolved, transitions}>}
   */
  async getMarketLifecycle(marketId) {
    const res = await this.l2Get(`/market/${marketId}/lifecycle`);
    return res;
  }

  /**
   * Create a DRAFT market (dealer must approve before trading)
   * @param {object} marketData - { id, title, description, outcomes, closesAt, resolutionCriteria, category, sourceUrl }
   */
  async createDraft(marketData) {
    const res = await this.l2Post('/market/draft', {
      id: marketData.id,
      title: marketData.title,
      description: marketData.description || '',
      outcomes: marketData.outcomes || ['Yes', 'No'],
      closes_at: typeof marketData.closesAt === 'number' 
        ? marketData.closesAt 
        : Math.floor(new Date(marketData.closesAt).getTime() / 1000),
      resolution_criteria: marketData.resolutionCriteria,
      category: marketData.category || 'general',
      source_url: marketData.sourceUrl || '',
    });

    if (res.success) {
      this.emit({ type: 'draft_created', marketId: res.market_id });
    }

    return {
      success: res.success !== false,
      marketId: res.market_id,
      status: res.status || 'draft',
      message: res.message || 'Draft created'
    };
  }

  /**
   * Approve a draft market (DEALER ONLY - requires dealer signature)
   * @param {string} marketId - Market ID to approve
   * @param {number} initialLiquidity - Amount of $BB to add as liquidity
   */
  async approveMarket(marketId, initialLiquidity) {
    if (!this.isDealerMode) {
      throw new Error('approveMarket requires dealer mode (isDealerMode: true)');
    }

    const payload = {
      action: 'market_approve',
      market_id: marketId,
      initial_liquidity: initialLiquidity
    };

    const signedPayload = await this.signDealerMessage(payload);
    const res = await this.l2Post('/market/approve', signedPayload);

    if (res.success) {
      this.emit({ type: 'market_approved', marketId, liquidity: initialLiquidity });
    }

    return {
      success: res.success !== false,
      marketId: res.market_id,
      status: res.status || 'active',
      liquidity: res.liquidity,
      message: res.message || 'Market approved'
    };
  }

  /**
   * Reject a draft market (DEALER ONLY - requires dealer signature)
   * @param {string} marketId - Market ID to reject
   * @param {string} reason - Reason for rejection
   */
  async rejectMarket(marketId, reason) {
    if (!this.isDealerMode) {
      throw new Error('rejectMarket requires dealer mode (isDealerMode: true)');
    }

    const payload = {
      action: 'market_reject',
      market_id: marketId,
      reason: reason
    };

    const signedPayload = await this.signDealerMessage(payload);
    const res = await this.l2Post('/market/reject', signedPayload);

    if (res.success) {
      this.emit({ type: 'market_rejected', marketId, reason });
    }

    return {
      success: res.success !== false,
      marketId: res.market_id,
      status: 'rejected',
      reason: res.reason || reason,
      message: res.message || 'Market rejected'
    };
  }

  /**
   * Resolve a market (DEALER/ORACLE ONLY - requires dealer signature)
   * Automatically calculates and distributes payouts to winners
   * @param {string} marketId - Market ID to resolve
   * @param {number} winningOutcome - Index of winning outcome (0, 1, etc.)
   */
  async resolveMarket(marketId, winningOutcome) {
    if (!this.isDealerMode) {
      throw new Error('resolveMarket requires dealer mode (isDealerMode: true)');
    }

    const payload = {
      action: 'resolve',
      market_id: marketId,
      winning_outcome: winningOutcome
    };

    const signedPayload = await this.signDealerMessage(payload);
    const res = await this.l2Post('/resolve', signedPayload);

    if (res.success) {
      this.emit({ type: 'market_resolved', marketId, winningOutcome, payouts: res.payouts });
    }

    return {
      success: res.success !== false,
      marketId: res.market_id || marketId,
      winningOutcome: res.winning_outcome,
      totalPool: res.total_pool,
      fee: res.fee,
      payouts: res.payouts || [],
      message: res.message || 'Market resolved'
    };
  }

  /**
   * Create a prop bet on a market (L2)
   * Requires 100 $BC minimum liquidity
   * @param {string|number} parentMarketId - Parent market ID
   * @param {object} propData - { title, description, outcomes, initialLiquidity, closesAt, resolutionCriteria }
   */
  async createProp(parentMarketId, propData) {
    const tx = {
      action: 'create_prop',
      wallet: this.address,
      parent_market_id: parentMarketId,
      title: propData.title,
      description: propData.description || '',
      outcomes: propData.outcomes || ['Yes', 'No'],
      initial_liquidity: propData.initialLiquidity || 100,
      closes_at: propData.closesAt,
      resolution_criteria: propData.resolutionCriteria || '',
      timestamp: Date.now()
    };
    
    const signed = await this.signTransaction(tx);
    const res = await this.l2Post(`/market/${parentMarketId}/prop/create`, signed);
    
    const result = {
      success: res.success !== false,
      propId: res.prop_id || res.market_id,
      message: res.message || 'Prop created'
    };
    
    if (result.success) {
      this.emit({ type: 'prop_created', result, parentMarketId });
    }
    
    return result;
  }
    
  /**
   * Get all categories with counts
   */
  async getCategories() {
    if (!this.supabase) return [];
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('category')
      .eq('market_type', 'main')
      .eq('status', 'active');
    
    if (error) return [];
    
    const counts = (data || []).reduce((acc, row) => {
      acc[row.category] = (acc[row.category] || 0) + 1;
      return acc;
    }, {});
    
    return Object.entries(counts)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // USER PROP BETS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Propose a new user prop bet (uses L2 createProp)
   * Requires 100 $BC minimum liquidity
   * @param {object} proposal - Prop bet details
   */
  async proposeProp(proposal) {
    return this.createProp(proposal.parentMarketId, {
      title: proposal.title,
      description: proposal.description,
      outcomes: proposal.outcomes,
      initialLiquidity: proposal.minLiquidity || 100,
      closesAt: proposal.closesAt,
      resolutionCriteria: proposal.resolutionCriteria || ''
    });
  }

  /**
   * Get user's proposed props
   */
  async getMyProps() {
    if (!this.supabase) return [];
    
    const { data, error } = await this.supabase
      .from('pmarket')
      .select('*')
      .eq('creator_address', this.address)
      .order('created_at', { ascending: false });
    
    if (error) return [];
    return data || [];
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REALTIME SUBSCRIPTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Subscribe to market updates
   * @param {number} marketId - Market to watch
   * @param {function} callback - Called on updates
   * @returns {function} Unsubscribe function
   */
  subscribeToMarket(marketId, callback) {
    if (!this.supabase) return () => {};
    
    const subscription = this.supabase
      .channel(`market-${marketId}`)
      .on('postgres_changes', {
        event: '*',
        schema: 'public',
        table: 'pmarket',
        filter: `market_id=eq.${marketId}`
      }, (payload) => {
        if (payload.new) callback(payload.new);
      })
      .subscribe();
    
    return () => subscription.unsubscribe();
  }

  /**
   * Subscribe to all market updates
   * @param {function} callback - Called on updates (market, eventType)
   * @returns {function} Unsubscribe function
   */
  subscribeToAllMarkets(callback) {
    if (!this.supabase) return () => {};
    
    const subscription = this.supabase
      .channel('all-markets')
      .on('postgres_changes', {
        event: '*',
        schema: 'public',
        table: 'pmarket'
      }, (payload) => {
        const market = payload.new || payload.old;
        if (market) callback(market, payload.eventType);
      })
      .subscribe();
    
    return () => subscription.unsubscribe();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EVENTS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Subscribe to SDK events
   * @param {function} callback - Event handler
   * @returns {function} Unsubscribe function
   */
  on(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(l => l !== callback);
    };
  }

  emit(event) {
    this.listeners.forEach(l => l(event));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HEALTH & STATE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check L2 server health
   */
  async health() {
    try {
      const res = await this.l2Get('/health');
      return { 
        healthy: true, 
        blockHeight: res.block_height,
        stateRoot: res.state_root,
        marketCount: res.market_count,
        userCount: res.user_count
      };
    } catch {
      return { healthy: false };
    }
  }

  /**
   * Get current state root (for L1 verification)
   */
  async getStateRoot() {
    const res = await this.l2Get('/state_root');
    return {
      stateRoot: res.state_root,
      blockHeight: res.block_height || res.tx_count,
      timestamp: res.timestamp
    };
  }

  /**
   * Get reserve proof for a user's balance
   * @param {string} address - User address to prove
   */
  async getReserveProof(address) {
    const res = await this.l2Post('/clearinghouse/reserves', {
      address: address || this.address
    });
    return {
      balance: res.balance,
      proof: res.proof,
      stateRoot: res.state_root,
      verified: res.verified
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  async l1Get(path) {
    const res = await fetch(`${this.l1Url}${path}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`L1 GET failed: ${await res.text()}`);
    return res.json();
  }

  async l1Post(path, body) {
    const res = await fetch(`${this.l1Url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`L1 POST failed: ${await res.text()}`);
    return res.json();
  }

  async l2Get(path) {
    const res = await fetch(`${this.l2Url}${path}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error(`L2 GET failed: ${await res.text()}`);
    return res.json();
  }

  async l2Post(path, body) {
    const res = await fetch(`${this.l2Url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`L2 POST failed: ${await res.text()}`);
    return res.json();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FACTORY & DEFAULT EXPORT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a user SDK instance
 */
export function createCreditPredictionSDK(config) {
  return new CreditPredictionSDK(config);
}

/**
 * Create a dealer SDK instance (for clearinghouse operations)
 * Requires dealer private key for signing
 * 
 * @param {object} config - SDK configuration
 * @param {string} config.l2Url - L2 server URL
 * @param {string} config.publicKey - Dealer Ed25519 public key (hex)
 * @param {function} config.signer - Signing function
 */
export function createDealerSDK(config) {
  return new CreditPredictionSDK({
    ...config,
    isDealerMode: true,
    address: config.address || `L2_DEALER` // Dealer doesn't need user address
  });
}

/**
 * Dealer address constant (from .env)
 */
export const DEALER_ADDRESS = 'L2_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D';
export const ORACLE_ADDRESS = DEALER_ADDRESS; // Same entity

export default CreditPredictionSDK;
