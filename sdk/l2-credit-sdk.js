/**
 * ═══════════════════════════════════════════════════════════════════════════
 * L2 CREDIT LINE SDK - Layer 2 Integration with L1 BlackBook
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This SDK provides L2 sequencers with the ability to:
 * - Open credit lines against L1 balances
 * - Track virtual balances during gaming sessions
 * - Settle sessions by reporting P&L to L1
 * 
 * IMPORTANT: L1 is the ONLY source of truth for real token balances.
 * L2 operates on credit lines - virtual balances backed by L1 reserves.
 * 
 * Usage:
 *   const sdk = new L2CreditSDK({
 *     l1Url: 'http://localhost:8080',
 *     l2PrivateKey: process.env.L2_PRIVATE_KEY
 *   });
 *   
 *   // Open credit for user
 *   const session = await sdk.openCredit('L1_ABC123...', 5000);
 *   
 *   // Track virtual balance during gameplay
 *   session.placeBet(100);
 *   session.recordWin(250);
 *   
 *   // Settle when done
 *   await sdk.settleCredit(session);
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

import nacl from 'tweetnacl';
import { Buffer } from 'buffer';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  l1Url: 'http://localhost:8080',
  timeout: 30000, // 30 seconds
  retryAttempts: 3,
  retryDelay: 1000, // 1 second
};

// L2 Sequencer keys (from dealer mnemonic)
const L2_PUBLIC_KEY = '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a';

// ═══════════════════════════════════════════════════════════════════════════
// CREDIT SESSION CLASS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Represents an active credit session for a user
 */
export class CreditSession {
  constructor(sessionId, walletAddress, creditAmount, l1BalanceAtOpen) {
    this.sessionId = sessionId;
    this.walletAddress = walletAddress;
    this.creditAmount = creditAmount;
    this.l1BalanceAtOpen = l1BalanceAtOpen;
    this.virtualBalance = creditAmount;
    this.openedAt = Date.now();
    this.bets = [];
    this.isActive = true;
  }

  /**
   * Record a bet placement (deducts from virtual balance)
   */
  placeBet(amount, eventId = null, odds = null) {
    if (!this.isActive) {
      throw new Error('Session is not active');
    }
    if (amount > this.virtualBalance) {
      throw new Error(`Insufficient virtual balance: ${this.virtualBalance} < ${amount}`);
    }
    
    const bet = {
      id: `bet_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      amount,
      eventId,
      odds,
      placedAt: Date.now(),
      settled: false,
      payout: 0
    };
    
    this.virtualBalance -= amount;
    this.bets.push(bet);
    
    console.log(`📉 Bet placed: ${amount} $BB | Virtual balance: ${this.virtualBalance}`);
    return bet;
  }

  /**
   * Record a win (adds to virtual balance)
   */
  recordWin(betId, payout) {
    const bet = this.bets.find(b => b.id === betId);
    if (bet) {
      bet.settled = true;
      bet.payout = payout;
    }
    
    this.virtualBalance += payout;
    console.log(`📈 Win recorded: +${payout} $BB | Virtual balance: ${this.virtualBalance}`);
  }

  /**
   * Record a loss (bet was already deducted, just mark as settled)
   */
  recordLoss(betId) {
    const bet = this.bets.find(b => b.id === betId);
    if (bet) {
      bet.settled = true;
      bet.payout = 0;
    }
    console.log(`📉 Loss recorded | Virtual balance: ${this.virtualBalance}`);
  }

  /**
   * Add funds directly (e.g., bonus, refund)
   */
  addFunds(amount, reason = 'adjustment') {
    this.virtualBalance += amount;
    console.log(`💰 Funds added: +${amount} $BB (${reason}) | Virtual balance: ${this.virtualBalance}`);
  }

  /**
   * Calculate current P&L
   */
  getPnL() {
    return this.virtualBalance - this.creditAmount;
  }

  /**
   * Get session summary
   */
  getSummary() {
    const pnl = this.getPnL();
    return {
      sessionId: this.sessionId,
      walletAddress: this.walletAddress,
      creditAmount: this.creditAmount,
      virtualBalance: this.virtualBalance,
      pnl,
      pnlPercent: ((pnl / this.creditAmount) * 100).toFixed(2) + '%',
      totalBets: this.bets.length,
      settledBets: this.bets.filter(b => b.settled).length,
      openedAt: this.openedAt,
      durationMs: Date.now() - this.openedAt,
      isActive: this.isActive
    };
  }

  /**
   * Close session (called internally by SDK during settlement)
   */
  _close() {
    this.isActive = false;
    this.closedAt = Date.now();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// L2 CREDIT SDK
// ═══════════════════════════════════════════════════════════════════════════

export class L2CreditSDK {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.l1Url = this.config.l1Url;
    
    // Load L2 private key
    if (config.l2PrivateKey) {
      this.privateKey = Buffer.from(config.l2PrivateKey, 'hex');
      this.publicKey = L2_PUBLIC_KEY;
    } else {
      console.warn('⚠️  No L2 private key provided - signatures will fail');
      this.privateKey = null;
      this.publicKey = L2_PUBLIC_KEY;
    }
    
    // Track active sessions
    this.activeSessions = new Map(); // walletAddress -> CreditSession
    
    console.log('🔗 L2 Credit SDK initialized');
    console.log(`   L1 URL: ${this.l1Url}`);
    console.log(`   L2 Public Key: ${this.publicKey.substring(0, 16)}...`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNATURE HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Sign a message with L2 private key
   */
  sign(message) {
    if (!this.privateKey) {
      throw new Error('L2 private key not configured');
    }
    
    const messageBytes = Buffer.from(message, 'utf8');
    
    // nacl.sign.detached requires 64-byte secret key
    // If we have 32-byte seed, derive the full keypair
    let secretKey = this.privateKey;
    if (secretKey.length === 32) {
      const keypair = nacl.sign.keyPair.fromSeed(secretKey);
      secretKey = keypair.secretKey;
    }
    
    const signature = nacl.sign.detached(messageBytes, secretKey);
    return Buffer.from(signature).toString('hex');
  }

  /**
   * Get current timestamp
   */
  timestamp() {
    return Math.floor(Date.now() / 1000);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  async request(method, path, body = null) {
    const url = `${this.l1Url}${path}`;
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };
    
    if (body) {
      options.body = JSON.stringify(body);
    }
    
    let lastError;
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const response = await fetch(url, options);
        const text = await response.text();
        
        // Try to parse as JSON
        try {
          const data = JSON.parse(text);
          if (!response.ok && !data.success) {
            throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
          }
          return data;
        } catch (parseError) {
          // If JSON parse fails, throw the raw text
          throw new Error(`Server response (${response.status}): ${text.substring(0, 200)}`);
        }
      } catch (error) {
        lastError = error;
        console.warn(`⚠️  Request failed (attempt ${attempt}/${this.config.retryAttempts}): ${error.message}`);
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
  // CREDIT LINE OPERATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check user's L1 balance
   */
  async getL1Balance(walletAddress) {
    console.log(`\n💰 Checking L1 balance for ${walletAddress.substring(0, 20)}...`);
    
    const result = await this.request('GET', `/credit/balance/${walletAddress}`);
    
    console.log(`   Balance: ${result.l1_balance} ${result.symbol}`);
    return result.l1_balance;
  }

  /**
   * Check if user has active credit session
   */
  async getCreditStatus(walletAddress) {
    console.log(`\n📋 Checking credit status for ${walletAddress.substring(0, 20)}...`);
    
    const result = await this.request('GET', `/credit/status/${walletAddress}`);
    
    if (result.has_active_credit) {
      console.log(`   ✅ Active session: ${result.session_id}`);
      console.log(`   Credit amount: ${result.credit_amount} $BC`);
      console.log(`   Available balance: ${result.available_balance} $BC`);
    } else {
      console.log(`   ❌ No active credit line`);
      console.log(`   L1 Balance: ${result.l1_balance} $BC`);
    }
    
    return result;
  }

  /**
   * Open a credit line for a user
   * 
   * @param {string} walletAddress - User's L1 address (L1_...)
   * @param {number} amount - Amount to reserve from L1
   * @returns {CreditSession} - Session object for tracking virtual balance
   */
  async openCredit(walletAddress, amount) {
    console.log(`\n════════════════════════════════════════════════════════`);
    console.log(`📋 OPENING CREDIT LINE`);
    console.log(`════════════════════════════════════════════════════════`);
    console.log(`   Wallet: ${walletAddress}`);
    console.log(`   Amount: ${amount} $BC`);
    
    // Check for existing session
    if (this.activeSessions.has(walletAddress)) {
      const existing = this.activeSessions.get(walletAddress);
      if (existing.isActive) {
        console.log(`   ⚠️  User already has active session: ${existing.sessionId}`);
        return existing;
      }
    }
    
    // Build signed request
    const ts = this.timestamp();
    const message = `CREDIT_OPEN:${walletAddress}:${amount}:${ts}`;
    const signature = this.sign(message);
    
    const result = await this.request('POST', '/credit/open', {
      wallet_address: walletAddress,
      amount,
      l2_public_key: this.publicKey,
      signature,
      timestamp: ts
    });
    
    if (!result.success) {
      console.log(`   ❌ Failed: ${result.error}`);
      throw new Error(result.error);
    }
    
    // Create session object
    const session = new CreditSession(
      result.session_id,
      walletAddress,
      result.credit_amount,
      result.l1_balance
    );
    
    // Track session
    this.activeSessions.set(walletAddress, session);
    
    console.log(`   ✅ Credit line opened!`);
    console.log(`   Session ID: ${result.session_id}`);
    console.log(`   Credit: ${result.credit_amount} $BC`);
    console.log(`   L1 Balance: ${result.l1_balance} $BC`);
    console.log(`   Available after credit: ${result.available_after_credit} $BC`);
    
    return session;
  }

  /**
   * Settle a credit session
   * 
   * @param {CreditSession|string} sessionOrWallet - Session object or wallet address
   * @returns {object} - Settlement result with new L1 balance
   */
  async settleCredit(sessionOrWallet) {
    // Get session
    let session;
    if (typeof sessionOrWallet === 'string') {
      session = this.activeSessions.get(sessionOrWallet);
      if (!session) {
        throw new Error(`No active session for wallet: ${sessionOrWallet}`);
      }
    } else {
      session = sessionOrWallet;
    }
    
    const pnl = session.getPnL();
    
    console.log(`\n════════════════════════════════════════════════════════`);
    console.log(`💰 SETTLING CREDIT LINE`);
    console.log(`════════════════════════════════════════════════════════`);
    console.log(`   Session: ${session.sessionId}`);
    console.log(`   Wallet: ${session.walletAddress}`);
    console.log(`   Credit Amount: ${session.creditAmount} $BC`);
    console.log(`   Final Balance: ${session.virtualBalance} $BC`);
    console.log(`   P&L: ${pnl >= 0 ? '+' : ''}${pnl} $BC`);
    
    // Build signed request
    const ts = this.timestamp();
    const message = `CREDIT_SETTLE:${session.sessionId}:${session.walletAddress}:${pnl}:${ts}`;
    const signature = this.sign(message);
    
    const result = await this.request('POST', '/credit/settle', {
      session_id: session.sessionId,
      wallet_address: session.walletAddress,
      final_balance: session.virtualBalance,
      pnl,
      l2_public_key: this.publicKey,
      signature,
      timestamp: ts
    });
    
    if (!result.success) {
      console.log(`   ❌ Settlement failed: ${result.error}`);
      throw new Error(result.error);
    }
    
    // Close session
    session._close();
    this.activeSessions.delete(session.walletAddress);
    
    console.log(`   ✅ Settlement complete!`);
    console.log(`   L1 Before: ${result.l1_balance_before} $BC`);
    console.log(`   L1 After: ${result.l1_balance_after} $BC`);
    console.log(`   P&L Applied: ${result.pnl_applied >= 0 ? '+' : ''}${result.pnl_applied} $BC`);
    
    return {
      ...result,
      session: session.getSummary()
    };
  }

  /**
   * Get active session for a wallet
   */
  getSession(walletAddress) {
    return this.activeSessions.get(walletAddress);
  }

  /**
   * Get all active sessions
   */
  getAllSessions() {
    return Array.from(this.activeSessions.values()).map(s => s.getSummary());
  }

  /**
   * Force settle all sessions (for shutdown)
   */
  async settleAllSessions() {
    console.log(`\n🔄 Settling all active sessions...`);
    
    const results = [];
    for (const [wallet, session] of this.activeSessions) {
      try {
        const result = await this.settleCredit(session);
        results.push({ wallet, success: true, result });
      } catch (error) {
        results.push({ wallet, success: false, error: error.message });
      }
    }
    
    console.log(`✅ Settled ${results.filter(r => r.success).length}/${results.length} sessions`);
    return results;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BRIDGE OPERATIONS (Real Token Transfer L1↔L2)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Initiate bridge from L1 to L2 (locks tokens on L1)
   * This is for REAL token transfer, not credit lines.
   * 
   * @param {string} walletAddress - User's L1 address
   * @param {number} amount - Amount to bridge
   * @returns {object} - Bridge initiation result with lock_id
   */
  async bridgeToL2(walletAddress, amount) {
    console.log(`\n🌉 BRIDGING TO L2`);
    console.log(`   From: ${walletAddress}`);
    console.log(`   Amount: ${amount} $BC`);
    
    const ts = this.timestamp();
    const message = `BRIDGE_L1_TO_L2:${walletAddress}:${amount}:${ts}`;
    const signature = this.sign(message);
    
    const result = await this.request('POST', '/bridge/initiate', {
      wallet_address: walletAddress,
      amount,
      target_layer: 'L2',
      l2_public_key: this.publicKey,
      signature,
      timestamp: ts
    });
    
    console.log(`   ✅ Bridge initiated: ${result.lock_id || result.bridge_id}`);
    console.log(`   Status: ${result.status}`);
    
    return result;
  }

  /**
   * Get bridge status
   * 
   * @param {string} lockId - Bridge lock ID
   * @returns {object} - Bridge status
   */
  async getBridgeStatus(lockId) {
    console.log(`\n📊 Checking bridge status: ${lockId}`);
    
    const result = await this.request('GET', `/bridge/status/${lockId}`);
    
    console.log(`   Status: ${result.status}`);
    console.log(`   Amount: ${result.amount} $BC`);
    
    return result;
  }

  /**
   * Get all pending bridges
   * 
   * @param {string} walletAddress - Optional: Filter by wallet address
   * @returns {array} - List of pending bridges
   */
  async getPendingBridges(walletAddress = null) {
    console.log(`\n📋 Fetching pending bridges...`);
    
    const path = walletAddress 
      ? `/bridge/pending/${walletAddress}`
      : '/bridge/pending/all'; // Fallback
    
    const result = await this.request('GET', path);
    
    console.log(`   Found ${result.pending?.length || 0} pending bridges`);
    
    return result;
  }

  /**
   * Get bridge statistics
   * 
   * @returns {object} - Bridge stats
   */
  async getBridgeStats() {
    const result = await this.request('GET', '/bridge/stats');
    return result;
  }

  /**
   * Release locked tokens after L2 settlement
   * Requires BOTH wallet signature (from user) and L2 signature (from sequencer)
   * 
   * @param {string} lockId - Lock ID from bridge/credit approval
   * @param {string} walletAddress - User's L1 address
   * @param {string} walletPrivateKey - User's private key (hex) for signing
   * @param {object} settlementData - Settlement details { final_balance, pnl, session_id, l2_block_height }
   * @returns {object} - Release result
   */
  async releaseBridge(lockId, walletAddress, walletPrivateKey, settlementData) {
    console.log(`\n🔓 RELEASING BRIDGE TOKENS`);
    console.log(`   Lock ID: ${lockId.substring(0, 16)}...`);
    console.log(`   Wallet: ${walletAddress}`);
    console.log(`   P&L: ${settlementData.pnl >= 0 ? '+' : ''}${settlementData.pnl} $BC`);
    
    // 1. Wallet signs the release (user approval)
    const walletMessage = `BRIDGE_RELEASE:${lockId}:${settlementData.session_id}:${settlementData.pnl}`;
    const walletKeyBuffer = Buffer.from(walletPrivateKey, 'hex');
    let walletSecretKey = walletKeyBuffer;
    if (walletKeyBuffer.length === 32) {
      const keypair = nacl.sign.keyPair.fromSeed(walletKeyBuffer);
      walletSecretKey = keypair.secretKey;
    }
    const walletSig = nacl.sign.detached(Buffer.from(walletMessage, 'utf8'), walletSecretKey);
    const walletSignature = Buffer.from(walletSig).toString('hex');
    
    // Extract wallet public key from address (remove L1_ prefix)
    const walletPublicKey = walletAddress.replace('L1_', '');
    
    console.log(`   ✅ Wallet signed release`);
    
    // 2. L2 signs the release (sequencer confirmation)
    const l2Message = `BRIDGE_RELEASE:${lockId}:${walletAddress}:${settlementData.final_balance}:${settlementData.session_id}`;
    const l2Signature = this.sign(l2Message);
    
    console.log(`   ✅ L2 signed release`);
    
    // 3. Send release request with both signatures
    const result = await this.request('POST', '/bridge/release', {
      lock_id: lockId,
      l2_signature: l2Signature,
      l2_public_key: this.publicKey,
      wallet_signature: walletSignature,
      wallet_public_key: walletPublicKey,
      settlement_data: {
        wallet_address: walletAddress,
        final_balance: settlementData.final_balance,
        pnl: settlementData.pnl,
        session_id: settlementData.session_id,
        l2_block_height: settlementData.l2_block_height || 0
      }
    });
    
    if (result.success) {
      console.log(`   ✅ Tokens released!`);
      console.log(`   Recipient: ${result.released.recipient}`);
      console.log(`   Amount: ${result.released.amount} $BC`);
    } else {
      console.log(`   ❌ Release failed: ${result.error}`);
    }
    
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // L2 STATE ROOT OPERATIONS (Optimistic Rollup)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Post L2 state root to L1 (for optimistic rollup security)
   * 
   * @param {string} stateRoot - Merkle root of L2 state
   * @param {number} l2Slot - L2 slot number
   * @param {object} metadata - Additional metadata (txCount, etc.)
   * @returns {object} - State root submission result
   */
  async postStateRoot(stateRoot, l2Slot, metadata = {}) {
    console.log(`\n🌳 POSTING L2 STATE ROOT TO L1`);
    console.log(`   State Root: ${stateRoot.substring(0, 16)}...`);
    console.log(`   L2 Slot: ${l2Slot}`);
    
    const ts = this.timestamp();
    const message = `L2_STATE_ROOT:${stateRoot}:${l2Slot}:${ts}`;
    const signature = this.sign(message);
    
    const result = await this.request('POST', '/l2/state-root', {
      state_root: stateRoot,
      l2_slot: l2Slot,
      l2_public_key: this.publicKey,
      signature,
      timestamp: ts,
      metadata
    });
    
    console.log(`   ✅ State root anchored on L1`);
    console.log(`   L1 Slot: ${result.l1_slot || 'pending'}`);
    
    return result;
  }

  /**
   * Get latest L2 state root from L1
   * 
   * @returns {object} - Latest state root info
   */
  async getLatestStateRoot() {
    const result = await this.request('GET', '/l2/latest-state');
    return result;
  }

  /**
   * Get all L2 state roots from L1
   * 
   * @param {number} limit - Maximum number to return
   * @returns {array} - List of state roots
   */
  async getAllStateRoots(limit = 100) {
    const result = await this.request('GET', `/l2/all-states?limit=${limit}`);
    return result;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// QUICK TEST
// ═══════════════════════════════════════════════════════════════════════════

async function quickTest() {
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('🧪 L2 CREDIT SDK - COMPREHENSIVE TEST');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  // Load private key from environment
  const L2_PRIVATE_KEY = process.env.L2_PRIVATE_KEY || 
    'e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae';
  
  const sdk = new L2CreditSDK({
    l1Url: 'http://localhost:8080',
    l2PrivateKey: L2_PRIVATE_KEY
  });
  
  const ALICE = 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8';
  
  try {
    console.log('═══════════════════════════════════════════════════════════');
    console.log('PART 1: CREDIT LINE SYSTEM (Token Locking)');
    console.log('═══════════════════════════════════════════════════════════');
    
    // 1. Check L1 balance
    const balance = await sdk.getL1Balance(ALICE);
    console.log(`\n📊 Alice L1 Balance: ${balance} $BC`);
    
    // 2. Check current status
    const status = await sdk.getCreditStatus(ALICE);
    
    if (status.has_active_credit) {
      console.log('\n⚠️  Alice already has active credit - settling first...');
      const existingSession = new CreditSession(
        status.session_id,
        ALICE,
        status.credit_amount,
        status.l1_balance
      );
      sdk.activeSessions.set(ALICE, existingSession);
      await sdk.settleCredit(ALICE);
    }
    
    // 3. Open credit line (locks tokens on L1)
    const session = await sdk.openCredit(ALICE, 1000);
    
    // 4. Simulate some gameplay
    console.log('\n🎮 Simulating gameplay...');
    
    // Place some bets
    const bet1 = session.placeBet(100, 'event_123', 2.5);
    const bet2 = session.placeBet(200, 'event_456', 1.8);
    const bet3 = session.placeBet(150, 'event_789', 3.0);
    
    // Simulate outcomes
    session.recordWin(bet1.id, 250);  // Won 2.5x
    session.recordLoss(bet2.id);       // Lost
    session.recordWin(bet3.id, 450);  // Won 3x
    
    // Show session summary
    console.log('\n📋 Session Summary:');
    const summary = session.getSummary();
    console.log(`   Credit: ${summary.creditAmount} $BC`);
    console.log(`   Virtual Balance: ${summary.virtualBalance} $BC`);
    console.log(`   P&L: ${summary.pnl >= 0 ? '+' : ''}${summary.pnl} $BC (${summary.pnlPercent})`);
    console.log(`   Bets: ${summary.settledBets}/${summary.totalBets} settled`);
    
    // 5. Settle the session (applies P&L, unlocks tokens)
    const result = await sdk.settleCredit(session);
    
    // 6. Verify final L1 balance
    const finalBalance = await sdk.getL1Balance(ALICE);
    console.log(`\n✅ Final L1 Balance: ${finalBalance} $BC`);
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('PART 2: BRIDGE OPERATIONS (Real Token Transfer)');
    console.log('═══════════════════════════════════════════════════════════');
    
    // Get bridge stats
    const bridgeStats = await sdk.getBridgeStats();
    console.log('\n📊 Bridge Statistics:');
    console.log(`   Active Sessions: ${bridgeStats.active_sessions}`);
    console.log(`   Total Sessions: ${bridgeStats.total_sessions}`);
    
    // Check pending bridges
    const pending = await sdk.getPendingBridges(ALICE);
    console.log(`\n📋 Pending Bridges: ${pending.pending?.length || 0}`);
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('PART 3: L2 STATE ROOT ANCHORING');
    console.log('═══════════════════════════════════════════════════════════');
    
    // Get latest state root
    try {
      const latestState = await sdk.getLatestStateRoot();
      if (latestState.state_root) {
        console.log('\n🌳 Latest L2 State Root:');
        console.log(`   Root: ${latestState.state_root.substring(0, 16)}...`);
        console.log(`   L2 Slot: ${latestState.l2_slot}`);
      } else {
        console.log('\n📋 No state roots posted yet');
      }
    } catch (error) {
      console.log('\n📋 State root endpoint not yet fully implemented');
    }
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('✅ L2 CREDIT SDK COMPREHENSIVE TEST COMPLETE');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('\n📚 SDK now includes:');
    console.log('   ✅ Credit line operations (token locking)');
    console.log('   ✅ Bridge operations (real token transfer)');
    console.log('   ✅ L2 state root anchoring (rollup security)');
    console.log('   ✅ Session management');
    console.log('   ✅ P&L tracking and settlement\n');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error(error.stack);
  }
}

// Run if executed directly
const isMainModule = process.argv[1]?.includes('l2-credit-sdk');
if (isMainModule) {
  quickTest();
}

export default L2CreditSDK;
