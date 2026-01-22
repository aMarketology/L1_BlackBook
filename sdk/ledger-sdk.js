/**
 * ═══════════════════════════════════════════════════════════════════════════
 * LEDGER SDK - Unified L1 + L2 Transaction History
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive transaction tracking across both Layer 1 (Bank) and Layer 2 (CPMM).
 * Provides unified view of all operations: deposits, withdrawals, bridges, trades, etc.
 * 
 * LAYER 1 (Bank Server - localhost:8080):
 *   - Deposits (external → L1)
 *   - Withdrawals (L1 → external)
 *   - Bridge Out (L1 → L2 soft-lock)
 *   - Bridge In (L2 → L1 release)
 *   - Transfers (P2P on L1)
 *   - Settlements (final L2 position → L1)
 * 
 * LAYER 2 (CPMM Server - localhost:1234):
 *   - Trades (buy/sell shares)
 *   - Market Creation
 *   - Market Resolution
 *   - Clearinghouse Deposits (L1 bridge confirmation)
 *   - Clearinghouse Withdrawals (L2 → L1 initiation)
 *   - Liquidity Operations
 * 
 * Usage:
 * 
 *   const ledger = new LedgerSDK({
 *     l1Url: 'http://localhost:8080',
 *     l2Url: 'http://localhost:1234'
 *   });
 * 
 *   // Get all transactions
 *   const all = await ledger.getAll();
 * 
 *   // Get user transactions
 *   const userTx = await ledger.getUserTransactions('L1_ABC...');
 * 
 *   // Filter by type
 *   const deposits = await ledger.getByType('deposit');
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ═══════════════════════════════════════════════════════════════════════════
// TRANSACTION TYPES
// ═══════════════════════════════════════════════════════════════════════════

export const TxType = {
  // L1 Operations
  DEPOSIT: 'deposit',
  WITHDRAW: 'withdraw',
  BRIDGE_OUT: 'bridge_out',
  BRIDGE_IN: 'bridge_in',
  TRANSFER: 'transfer',
  SETTLEMENT: 'settlement',
  
  // L2 Operations
  TRADE_BUY: 'trade_buy',
  TRADE_SELL: 'trade_sell',
  MARKET_CREATE: 'market_create',
  MARKET_RESOLVE: 'market_resolve',
  CLEARINGHOUSE_DEPOSIT: 'clearinghouse_deposit',
  CLEARINGHOUSE_WITHDRAW: 'clearinghouse_withdraw',
  LIQUIDITY_ADD: 'liquidity_add',
  LIQUIDITY_REMOVE: 'liquidity_remove',
};

export const TxStatus = {
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
};

// ═══════════════════════════════════════════════════════════════════════════
// LEDGER SDK
// ═══════════════════════════════════════════════════════════════════════════

export class LedgerSDK {
  constructor(config = {}) {
    this.l1Url = (config.l1Url || 'http://localhost:8080').replace(/\/$/, '');
    this.l2Url = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CORE FETCHING METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Fetch L1 transactions from bank server
   * @param {Object} filters - { address, type, limit, offset }
   * @returns {Array} L1 transactions
   */
  async fetchL1Transactions(filters = {}) {
    try {
      const params = new URLSearchParams();
      if (filters.address) params.append('address', filters.address);
      if (filters.limit) params.append('limit', filters.limit);
      if (filters.offset) params.append('offset', filters.offset);

      const url = `${this.l1Url}/transactions?${params.toString()}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        if (response.status === 404) {
          console.warn('L1 transactions endpoint not available');
          return [];
        }
        throw new Error(`L1 server error: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Filter by type if specified (L1 server doesn't support type filtering yet)
      let transactions = data.transactions || [];
      if (filters.type) {
        transactions = transactions.filter(tx => tx.tx_type === filters.type);
      }
      
      return this._normalizeL1Transactions(transactions);
    } catch (error) {
      console.error('Failed to fetch L1 transactions:', error);
      return [];
    }
  }

  /**
   * Fetch L2 transactions from CPMM server
   * @param {Object} filters - { address, market_id, type, limit, offset }
   * @returns {Array} L2 transactions
   */
  async fetchL2Transactions(filters = {}) {
    try {
      const params = new URLSearchParams();
      if (filters.address) params.append('address', filters.address);
      if (filters.market_id) params.append('market_id', filters.market_id);
      if (filters.type) params.append('type', filters.type);
      if (filters.limit) params.append('limit', filters.limit);
      if (filters.offset) params.append('offset', filters.offset);

      const url = `${this.l2Url}/transactions?${params.toString()}`;
      const response = await fetch(url);
      
      if (!response.ok) {
        if (response.status === 404) {
          console.warn('L2 transactions endpoint not available');
          return [];
        }
        throw new Error(`L2 server error: ${response.statusText}`);
      }

      const data = await response.json();
      return this._normalizeL2Transactions(data.transactions || []);
    } catch (error) {
      console.error('Failed to fetch L2 transactions:', error);
      return [];
    }
  }

  /**
   * Get all transactions from both layers
   * @param {Object} options - { limit, offset, sortBy }
   * @returns {Array} Merged and sorted transactions
   */
  async getAll(options = {}) {
    const limit = options.limit || 100;
    const offset = options.offset || 0;

    const [l1Txs, l2Txs] = await Promise.all([
      this.fetchL1Transactions({ limit: Math.ceil(limit / 2) }),
      this.fetchL2Transactions({ limit: Math.ceil(limit / 2) }),
    ]);

    const merged = [...l1Txs, ...l2Txs];
    return this._sortAndPaginate(merged, offset, limit);
  }

  /**
   * Get all transactions for a specific user
   * @param {string} address - L1 or L2 address
   * @param {Object} options - { limit, offset, layer }
   * @returns {Array} User transactions
   */
  async getUserTransactions(address, options = {}) {
    const limit = options.limit || 100;
    const offset = options.offset || 0;
    const layer = options.layer; // 'l1', 'l2', or undefined (both)

    let transactions = [];

    if (!layer || layer === 'l1') {
      const l1Txs = await this.fetchL1Transactions({ address, limit });
      transactions.push(...l1Txs);
    }

    if (!layer || layer === 'l2') {
      const l2Txs = await this.fetchL2Transactions({ address, limit });
      transactions.push(...l2Txs);
    }

    return this._sortAndPaginate(transactions, offset, limit);
  }

  /**
   * Get transactions by type
   * @param {string} type - Transaction type from TxType
   * @param {Object} options - { limit, offset }
   * @returns {Array} Filtered transactions
   */
  async getByType(type, options = {}) {
    const limit = options.limit || 100;
    const offset = options.offset || 0;

    // Determine which layer(s) to query
    const isL1Type = [
      TxType.DEPOSIT, TxType.WITHDRAW, TxType.BRIDGE_OUT, 
      TxType.BRIDGE_IN, TxType.TRANSFER, TxType.SETTLEMENT
    ].includes(type);

    const isL2Type = [
      TxType.TRADE_BUY, TxType.TRADE_SELL, TxType.MARKET_CREATE,
      TxType.MARKET_RESOLVE, TxType.CLEARINGHOUSE_DEPOSIT,
      TxType.CLEARINGHOUSE_WITHDRAW, TxType.LIQUIDITY_ADD, TxType.LIQUIDITY_REMOVE
    ].includes(type);

    let transactions = [];

    if (isL1Type) {
      const l1Txs = await this.fetchL1Transactions({ type, limit });
      transactions.push(...l1Txs);
    }

    if (isL2Type) {
      const l2Txs = await this.fetchL2Transactions({ type, limit });
      transactions.push(...l2Txs);
    }

    return this._sortAndPaginate(transactions, offset, limit);
  }

  /**
   * Get transactions for a specific market
   * @param {string} marketId - Market ID
   * @param {Object} options - { limit, offset }
   * @returns {Array} Market transactions
   */
  async getMarketTransactions(marketId, options = {}) {
    const limit = options.limit || 100;
    const offset = options.offset || 0;

    const l2Txs = await this.fetchL2Transactions({ market_id: marketId, limit });
    return this._sortAndPaginate(l2Txs, offset, limit);
  }

  /**
   * Get bridge transactions (L1 ↔ L2)
   * @param {Object} options - { address, direction, limit, offset }
   * @returns {Array} Bridge transactions
   */
  async getBridgeTransactions(options = {}) {
    const limit = options.limit || 100;
    const offset = options.offset || 0;
    const { address, direction } = options;

    let transactions = [];

    // L1 bridge transactions
    if (!direction || direction === 'out' || direction === 'both') {
      const bridgeOut = await this.fetchL1Transactions({ 
        type: TxType.BRIDGE_OUT, 
        address, 
        limit 
      });
      transactions.push(...bridgeOut);
    }

    if (!direction || direction === 'in' || direction === 'both') {
      const bridgeIn = await this.fetchL1Transactions({ 
        type: TxType.BRIDGE_IN, 
        address, 
        limit 
      });
      transactions.push(...bridgeIn);
    }

    // L2 clearinghouse operations (related to bridges)
    const clearinghouse = await this.fetchL2Transactions({ 
      address, 
      limit 
    });
    const chDeposits = clearinghouse.filter(tx => tx.type === TxType.CLEARINGHOUSE_DEPOSIT);
    const chWithdraws = clearinghouse.filter(tx => tx.type === TxType.CLEARINGHOUSE_WITHDRAW);
    
    transactions.push(...chDeposits, ...chWithdraws);

    return this._sortAndPaginate(transactions, offset, limit);
  }

  /**
   * Get pending transactions
   * @param {Object} options - { address, layer, limit, offset }
   * @returns {Array} Pending transactions
   */
  async getPendingTransactions(options = {}) {
    const transactions = await this.getAll(options);
    return transactions.filter(tx => tx.status === TxStatus.PENDING);
  }

  /**
   * Get transaction statistics
   * @param {string} address - Optional address filter
   * @returns {Object} Statistics
   */
  async getStatistics(address) {
    const transactions = address 
      ? await this.getUserTransactions(address, { limit: 1000 })
      : await this.getAll({ limit: 1000 });

    const stats = {
      total: transactions.length,
      by_type: {},
      by_status: {},
      by_layer: { l1: 0, l2: 0 },
      total_volume: 0,
      pending_count: 0,
    };

    transactions.forEach(tx => {
      // Count by type
      stats.by_type[tx.type] = (stats.by_type[tx.type] || 0) + 1;
      
      // Count by status
      stats.by_status[tx.status] = (stats.by_status[tx.status] || 0) + 1;
      
      // Count by layer
      stats.by_layer[tx.layer] = (stats.by_layer[tx.layer] || 0) + 1;
      
      // Sum volume
      stats.total_volume += tx.amount || 0;
      
      // Count pending
      if (tx.status === TxStatus.PENDING) {
        stats.pending_count++;
      }
    });

    return stats;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // NORMALIZATION & HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Normalize L1 transactions to standard format
   * @private
   */
  _normalizeL1Transactions(transactions) {
    return transactions.map(tx => ({
      id: tx.tx_id || tx.id,
      layer: 'l1',
      type: tx.tx_type || tx.type,
      from_address: tx.from_address || tx.from,
      to_address: tx.to_address || tx.to,
      amount: parseFloat(tx.amount || 0),
      timestamp: this._normalizeTimestamp(tx.timestamp),
      status: tx.status || TxStatus.COMPLETED,
      tx_hash: tx.signature || tx.tx_hash,
      signature: tx.signature,
      metadata: tx.metadata || {},
      description: this._generateL1Description(tx),
    }));
  }

  /**
   * Normalize L2 transactions to standard format
   * @private
   */
  _normalizeL2Transactions(transactions) {
    return transactions.map(tx => ({
      id: tx.id || tx.tx_id,
      layer: 'l2',
      type: tx.type || this._inferL2Type(tx),
      from_address: tx.address || tx.user_address,
      to_address: tx.to_address || tx.market_id,
      amount: parseFloat(tx.amount || tx.cost || 0),
      timestamp: tx.timestamp || tx.created_at || new Date().toISOString(),
      status: tx.status || TxStatus.COMPLETED,
      market_id: tx.market_id,
      outcome: tx.outcome,
      shares: tx.shares,
      price: tx.price,
      l1_tx_id: tx.l1_tx_id,
      request_id: tx.request_id,
      description: tx.description || this._generateL2Description(tx),
      metadata: tx.metadata || {},
    }));
  }

  /**
   * Generate description for L1 transaction
   * @private
   */
  _generateL1Description(tx) {
    const amount = tx.amount?.toFixed(2) || '0.00';
    const txType = tx.tx_type || tx.type;
    switch (txType) {
      case TxType.DEPOSIT:
        return `Deposited ${amount} credits to L1`;
      case TxType.WITHDRAW:
        return `Withdrew ${amount} credits from L1`;
      case TxType.BRIDGE_OUT:
        return `Bridged ${amount} credits to L2`;
      case TxType.BRIDGE_IN:
        return `Bridged ${amount} credits from L2`;
      case TxType.TRANSFER:
        return `Transferred ${amount} credits`;
      case TxType.SETTLEMENT:
        return `Settled L2 position for ${amount} credits`;
      default:
        return `L1 transaction: ${amount} credits`;
    }
  }

  /**
   * Normalize timestamp to ISO string
   * @private
   */
  _normalizeTimestamp(timestamp) {
    if (!timestamp) return new Date().toISOString();
    
    // If it's already an ISO string, return it
    if (typeof timestamp === 'string' && timestamp.includes('T')) {
      return timestamp;
    }
    
    // If it's a Unix timestamp (seconds), convert to milliseconds
    if (typeof timestamp === 'number') {
      return new Date(timestamp * 1000).toISOString();
    }
    
    return new Date().toISOString();
  }

  /**
   * Generate description for L2 transaction
   * @private
   */
  _generateL2Description(tx) {
    const amount = tx.amount?.toFixed(2) || '0.00';
    const shares = tx.shares?.toFixed(2) || '0.00';
    
    switch (tx.type) {
      case TxType.TRADE_BUY:
        return `Bought ${shares} shares for ${amount} credits`;
      case TxType.TRADE_SELL:
        return `Sold ${shares} shares for ${amount} credits`;
      case TxType.MARKET_CREATE:
        return `Created market with ${amount} credits liquidity`;
      case TxType.MARKET_RESOLVE:
        return `Resolved market`;
      case TxType.CLEARINGHOUSE_DEPOSIT:
        return `Clearinghouse deposit: ${amount} credits`;
      case TxType.CLEARINGHOUSE_WITHDRAW:
        return `Clearinghouse withdrawal: ${amount} credits`;
      case TxType.LIQUIDITY_ADD:
        return `Added ${amount} credits liquidity`;
      case TxType.LIQUIDITY_REMOVE:
        return `Removed ${amount} credits liquidity`;
      default:
        return `L2 transaction: ${amount} credits`;
    }
  }

  /**
   * Infer L2 transaction type from data
   * @private
   */
  _inferL2Type(tx) {
    if (tx.action) {
      const actionMap = {
        'buy': TxType.TRADE_BUY,
        'sell': TxType.TRADE_SELL,
        'create_market': TxType.MARKET_CREATE,
        'resolve': TxType.MARKET_RESOLVE,
        'deposit': TxType.CLEARINGHOUSE_DEPOSIT,
        'withdraw': TxType.CLEARINGHOUSE_WITHDRAW,
        'add_liquidity': TxType.LIQUIDITY_ADD,
        'remove_liquidity': TxType.LIQUIDITY_REMOVE,
      };
      return actionMap[tx.action] || tx.action;
    }
    
    // Fallback inference
    if (tx.shares > 0 && tx.cost) return TxType.TRADE_BUY;
    if (tx.market_id && tx.outcome !== undefined) return TxType.TRADE_SELL;
    
    return 'unknown';
  }

  /**
   * Sort transactions by timestamp and paginate
   * @private
   */
  _sortAndPaginate(transactions, offset = 0, limit = 100) {
    // Sort by timestamp (newest first)
    const sorted = transactions.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return timeB - timeA;
    });

    // Paginate
    return sorted.slice(offset, offset + limit);
  }
}

export default LedgerSDK;
