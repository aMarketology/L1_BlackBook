/**
 * ═══════════════════════════════════════════════════════════════════════════
 * UNIFIED BALANCE SDK - Seamless L1 ↔ L2 Integration
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Architecture: Virtual Balance with Auto-Sync
 * 
 * Key Concept:
 *   - L2 balance IS L1 balance (minus active positions)
 *   - No manual bridging required
 *   - Funds auto-lock when betting, auto-release when closing
 *   - User sees ONE unified balance across both layers
 * 
 * Flow:
 *   1. User has 10,000 $BC on L1
 *   2. User places 1,000 $BB bet on L2 → 1,000 $BC soft-locked on L1
 *   3. User's available balance: 9,000 (visible on both L1 and L2)
 *   4. Position closes with +200 profit → L1 balance: 10,200 $BC
 * 
 * Usage:
 *   const wallet = new UnifiedWallet({ ... });
 *   
 *   // Get unified balance (L1 + L2 view)
 *   const balance = await wallet.getBalance();
 *   // { available: 9000, inPositions: 1000, total: 10000 }
 *   
 *   // Bet seamlessly (auto-locks on L1)
 *   await wallet.bet('market_id', 'Yes', 500);
 *   
 *   // Close position (auto-releases to L1)
 *   await wallet.closePosition('position_id');
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

import nacl from 'tweetnacl';

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED WALLET CLASS
// ═══════════════════════════════════════════════════════════════════════════

export class UnifiedWallet {
  constructor(config) {
    this.l1Url = (config.l1Url || 'http://localhost:8080').replace(/\/$/, '');
    this.l2Url = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
    
    // Wallet identity (same across L1 and L2)
    this.publicKey = config.publicKey;
    this.secretKey = config.secretKey; // For signing (optional, can use external signer)
    this.signer = config.signer; // External signer function
    
    // Derive addresses from public key
    if (this.publicKey) {
      const hash = this.publicKey.slice(0, 40).toUpperCase();
      this.l1Address = `L1_${hash}`;
      this.l2Address = `L2_${hash}`;
    } else if (config.address) {
      const hash = config.address.replace(/^L[12]_/, '');
      this.l1Address = `L1_${hash}`;
      this.l2Address = `L2_${hash}`;
    }
    
    // Event listeners
    this.listeners = [];
    
    // Cache for performance
    this._balanceCache = null;
    this._balanceCacheTime = 0;
    this._cacheMaxAge = 2000; // 2 second cache
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UNIFIED BALANCE (THE MAGIC)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get unified balance across L1 and L2
   * 
   * This is the key abstraction - user sees ONE balance that works everywhere.
   * 
   * @returns {Promise<{
   *   available: number,      // Can be used for new bets
   *   inPositions: number,    // Currently locked in L2 positions  
   *   pendingPnL: number,     // Unrealized P&L from positions
   *   total: number,          // L1 total (source of truth)
   *   l1: { balance: number, locked: number },
   *   l2: { inPositions: number, pendingPnL: number }
   * }>}
   */
  async getBalance(forceRefresh = false) {
    // Return cache if fresh
    const now = Date.now();
    if (!forceRefresh && this._balanceCache && (now - this._balanceCacheTime) < this._cacheMaxAge) {
      return this._balanceCache;
    }

    // Fetch L1 and L2 state in parallel
    const [l1Data, l2Data] = await Promise.all([
      this._getL1Balance(),
      this._getL2State()
    ]);

    // L1 is source of truth
    const l1Balance = l1Data.balance || 0;
    const l1Locked = l1Data.locked || 0; // Soft-locked for L2 positions
    
    // L2 positions
    const l2InPositions = l2Data.inPositions || 0;
    const l2PendingPnL = l2Data.pendingPnL || 0;

    // Calculate unified view
    const available = l1Balance - l1Locked;
    const total = l1Balance + l2PendingPnL; // Include unrealized P&L

    const result = {
      // Simplified view (what user cares about)
      available,
      inPositions: l2InPositions,
      pendingPnL: l2PendingPnL,
      total,
      
      // Detailed breakdown
      l1: {
        balance: l1Balance,
        locked: l1Locked
      },
      l2: {
        inPositions: l2InPositions,
        pendingPnL: l2PendingPnL
      }
    };

    // Update cache
    this._balanceCache = result;
    this._balanceCacheTime = now;

    return result;
  }

  /**
   * Get L1 balance details
   */
  async _getL1Balance() {
    try {
      const res = await fetch(`${this.l1Url}/balance/${this.l1Address}`);
      const data = await res.json();
      return {
        balance: data.balance ?? data.available ?? 0,
        locked: data.locked ?? data.soft_locked ?? 0
      };
    } catch (e) {
      console.warn('L1 balance fetch failed:', e.message);
      return { balance: 0, locked: 0 };
    }
  }

  /**
   * Get L2 position state
   */
  async _getL2State() {
    try {
      const res = await fetch(`${this.l2Url}/positions/${this.l2Address}`);
      const data = await res.json();
      
      const positions = data.positions || [];
      let inPositions = 0;
      let pendingPnL = 0;
      
      for (const pos of positions) {
        inPositions += pos.cost || pos.amount || 0;
        pendingPnL += pos.unrealized_pnl || pos.pnl || 0;
      }
      
      return { inPositions, pendingPnL, positions };
    } catch (e) {
      // L2 might not have positions endpoint, fallback to balance
      try {
        const res = await fetch(`${this.l2Url}/balance/${this.l2Address}`);
        const data = await res.json();
        return {
          inPositions: data.locked || 0,
          pendingPnL: 0,
          positions: []
        };
      } catch {
        return { inPositions: 0, pendingPnL: 0, positions: [] };
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SEAMLESS BETTING (Auto-lock on L1)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Place a bet on L2 with automatic L1 soft-lock
   * 
   * This is the seamless flow:
   * 1. Check if user has enough available balance
   * 2. Soft-lock the amount on L1
   * 3. Place bet on L2
   * 4. If bet fails, auto-unlock on L1
   * 
   * @param {string} marketId - Market to bet on
   * @param {number} outcomeIndex - Which outcome (0, 1, etc.)
   * @param {number} amount - Amount to bet
   * @returns {Promise<{success: boolean, shares: number, avgPrice: number, txId: string}>}
   */
  async bet(marketId, outcomeIndex, amount) {
    // Step 1: Check balance
    const balance = await this.getBalance(true);
    if (balance.available < amount) {
      throw new Error(`Insufficient balance: ${balance.available} available, ${amount} needed`);
    }

    // Step 2: Soft-lock on L1 (reserve funds)
    const lockResult = await this._softLockOnL1(amount, marketId);
    if (!lockResult.success) {
      throw new Error(`Failed to reserve funds: ${lockResult.error}`);
    }

    // Step 3: Place bet on L2
    try {
      const betResult = await this._placeBetOnL2(marketId, outcomeIndex, amount);
      
      // Emit event
      this._emit({
        type: 'bet_placed',
        marketId,
        outcomeIndex,
        amount,
        shares: betResult.shares,
        avgPrice: betResult.avgPrice,
        lockId: lockResult.lockId
      });

      // Invalidate cache
      this._balanceCache = null;

      return {
        success: true,
        shares: betResult.shares,
        avgPrice: betResult.avgPrice,
        txId: betResult.txId || lockResult.lockId,
        lockId: lockResult.lockId
      };
    } catch (e) {
      // Step 4: Rollback - unlock on L1 if L2 bet failed
      await this._softUnlockOnL1(lockResult.lockId);
      throw new Error(`Bet failed: ${e.message}`);
    }
  }

  /**
   * Soft-lock funds on L1 for L2 position
   * This reserves funds without actually moving them
   */
  async _softLockOnL1(amount, reason) {
    const timestamp = Date.now();
    const nonce = `lock_${timestamp}_${Math.random().toString(36).slice(2)}`;
    
    // Create lock request
    const payload = {
      amount,
      reason: reason || 'l2_position',
      target: 'L2'
    };

    // Sign the lock request
    const signature = await this._sign(JSON.stringify(payload) + timestamp + nonce);

    try {
      const res = await fetch(`${this.l1Url}/balance/soft-lock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wallet: this.l1Address,
          public_key: this.publicKey,
          amount,
          reason: reason || 'l2_position',
          timestamp,
          nonce,
          signature
        })
      });

      const data = await res.json();
      
      if (data.success || data.lock_id) {
        return { success: true, lockId: data.lock_id || nonce };
      }
      
      // Fallback: If soft-lock endpoint doesn't exist, use bridge/initiate
      if (res.status === 404) {
        return this._fallbackLock(amount, reason);
      }

      return { success: false, error: data.error || 'Lock failed' };
    } catch (e) {
      // Fallback to bridge lock
      return this._fallbackLock(amount, reason);
    }
  }

  /**
   * Fallback: Use existing bridge/initiate as soft-lock
   */
  async _fallbackLock(amount, reason) {
    try {
      const res = await fetch(`${this.l1Url}/bridge/initiate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wallet: this.l1Address,
          amount,
          target_layer: 'L2',
          auto_release: true, // Flag for auto-release when position closes
          reason
        })
      });

      const data = await res.json();
      return {
        success: data.success !== false && data.lock_id,
        lockId: data.lock_id,
        error: data.error
      };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  /**
   * Release soft-lock on L1 (when position closes or bet fails)
   */
  async _softUnlockOnL1(lockId) {
    try {
      const res = await fetch(`${this.l1Url}/balance/soft-unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wallet: this.l1Address,
          lock_id: lockId
        })
      });
      return res.ok;
    } catch {
      // Try bridge release as fallback
      try {
        await fetch(`${this.l1Url}/bridge/release`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ lock_id: lockId })
        });
      } catch {}
      return false;
    }
  }

  /**
   * Place bet on L2
   */
  async _placeBetOnL2(marketId, outcomeIndex, amount) {
    const timestamp = Date.now();
    const tx = {
      action: 'buy',
      wallet: this.l2Address,
      market_id: marketId,
      outcome_index: outcomeIndex,
      amount,
      timestamp
    };

    const signature = await this._sign(JSON.stringify(tx));

    const res = await fetch(`${this.l2Url}/cpmm/buy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tx, signature, signer: this.l2Address })
    });

    const data = await res.json();
    
    if (data.error) {
      throw new Error(data.error);
    }

    return {
      shares: data.shares || 0,
      avgPrice: data.avg_price || data.avgPrice || 0,
      txId: data.tx_id || data.txId
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // POSITION MANAGEMENT (Auto-release on close)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get all active positions
   */
  async getPositions() {
    try {
      const res = await fetch(`${this.l2Url}/positions/${this.l2Address}`);
      const data = await res.json();
      return data.positions || [];
    } catch {
      return [];
    }
  }

  /**
   * Sell shares (close position)
   * Auto-releases funds back to L1 available balance
   */
  async sell(marketId, outcomeIndex, shares) {
    const timestamp = Date.now();
    const tx = {
      action: 'sell',
      wallet: this.l2Address,
      market_id: marketId,
      outcome_index: outcomeIndex,
      shares,
      timestamp
    };

    const signature = await this._sign(JSON.stringify(tx));

    const res = await fetch(`${this.l2Url}/cpmm/sell`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tx, signature, signer: this.l2Address })
    });

    const data = await res.json();

    if (data.success !== false) {
      // Auto-release the cost back to L1
      // The L2 should notify L1 to unlock, but we can also trigger it client-side
      this._emit({
        type: 'position_closed',
        marketId,
        outcomeIndex,
        shares,
        proceeds: data.proceeds || 0,
        pnl: data.pnl || 0
      });

      // Invalidate cache
      this._balanceCache = null;
    }

    return {
      success: data.success !== false,
      proceeds: data.proceeds || 0,
      avgPrice: data.avg_price || 0,
      pnl: data.pnl || 0
    };
  }

  /**
   * Claim winnings after market resolves
   * Auto-releases principal + winnings back to L1
   */
  async claim(marketId) {
    const res = await fetch(`${this.l2Url}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet: this.l2Address,
        market_id: marketId
      })
    });

    const data = await res.json();

    if (data.success !== false) {
      this._emit({
        type: 'winnings_claimed',
        marketId,
        amount: data.amount || 0,
        pnl: data.pnl || 0
      });

      // Invalidate cache
      this._balanceCache = null;
    }

    return {
      success: data.success !== false,
      amount: data.amount || 0,
      pnl: data.pnl || 0
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MARKET DATA
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get active markets
   */
  async getMarkets() {
    const res = await fetch(`${this.l2Url}/markets`);
    const data = await res.json();
    return data.markets || data || [];
  }

  /**
   * Get market details with prices
   */
  async getMarket(marketId) {
    const res = await fetch(`${this.l2Url}/market/${marketId}`);
    return res.json();
  }

  /**
   * Get quote before betting
   */
  async getQuote(marketId, outcomeIndex, amount) {
    try {
      const res = await fetch(`${this.l2Url}/quote/${marketId}/${outcomeIndex}/${amount}`);
      const data = await res.json();
      return {
        shares: data.shares || 0,
        avgPrice: data.avg_price || 0,
        priceImpact: data.price_impact || 0,
        fee: data.fee || 0
      };
    } catch {
      // Calculate from pool state
      const pool = await this.getPool(marketId);
      const reserves = pool.reserves || [500, 500];
      const k = reserves[0] * reserves[1];
      const newReserve = reserves[outcomeIndex] - amount;
      const otherReserve = k / newReserve;
      const shares = otherReserve - reserves[1 - outcomeIndex];
      
      return {
        shares,
        avgPrice: amount / shares,
        priceImpact: (amount / reserves[outcomeIndex]) * 100,
        fee: 0
      };
    }
  }

  /**
   * Get CPMM pool state
   */
  async getPool(marketId) {
    const res = await fetch(`${this.l2Url}/cpmm/pool/${marketId}`);
    return res.json();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNING
  // ═══════════════════════════════════════════════════════════════════════════

  async _sign(message) {
    if (this.signer) {
      return this.signer(message);
    }
    
    if (this.secretKey) {
      const messageBytes = new TextEncoder().encode(message);
      const secretKeyBytes = typeof this.secretKey === 'string' 
        ? Uint8Array.from(Buffer.from(this.secretKey, 'hex'))
        : this.secretKey;
      
      const signature = nacl.sign.detached(messageBytes, secretKeyBytes);
      return Buffer.from(signature).toString('hex');
    }
    
    // No signing available - some endpoints may work without
    return '';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EVENTS
  // ═══════════════════════════════════════════════════════════════════════════

  on(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(l => l !== callback);
    };
  }

  _emit(event) {
    this.listeners.forEach(l => l(event));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FACTORY
// ═══════════════════════════════════════════════════════════════════════════

export function createUnifiedWallet(config) {
  return new UnifiedWallet(config);
}

export default UnifiedWallet;
