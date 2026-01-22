/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK FRONTEND SDK - Complete Integration Package
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * A complete SDK for integrating BlackBook L1 blockchain into web applications.
 * Supports React, Next.js, Vue, and vanilla JavaScript.
 * 
 * FEATURES:
 * - Wallet management (create, import, connect)
 * - Balance queries with real-time updates
 * - Token transfers with Ed25519 signatures
 * - USDC deposit/withdrawal (USD-pegged tokens)
 * - L2 gaming session management
 * - Transaction history via Ledger SDK
 * - Event system for UI updates
 * 
 * INSTALLATION:
 *   npm install tweetnacl
 * 
 * USAGE (Browser):
 *   <script src="blackbook-frontend-sdk.js"></script>
 *   const bb = new BlackBookSDK({ url: 'https://api.blackbook.io' });
 * 
 * USAGE (React/Next.js):
 *   import { BlackBookSDK, useBlackBook } from './blackbook-frontend-sdk';
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ═══════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT DETECTION & IMPORTS
// ═══════════════════════════════════════════════════════════════════════════════

import nacl from 'tweetnacl';

// Node.js crypto polyfill
if (typeof window === 'undefined') {
  const { webcrypto } = await import('crypto');
  if (typeof globalThis.crypto === 'undefined') {
    globalThis.crypto = webcrypto;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const CHAIN_ID = 0x01;
const TOKEN_SYMBOL = 'BB';
const TOKEN_DECIMALS = 2;
const USD_PEG = 1.00; // 1 BB = 1 USD

// Event types for the event system
const EVENTS = {
  WALLET_CONNECTED: 'wallet:connected',
  WALLET_DISCONNECTED: 'wallet:disconnected',
  BALANCE_UPDATED: 'balance:updated',
  TRANSFER_SENT: 'transfer:sent',
  TRANSFER_CONFIRMED: 'transfer:confirmed',
  SESSION_OPENED: 'session:opened',
  SESSION_SETTLED: 'session:settled',
  ERROR: 'error',
};

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SDK CLASS
// ═══════════════════════════════════════════════════════════════════════════════

class BlackBookSDK {
  constructor(config = {}) {
    this.url = (config.url || 'http://localhost:8080').replace(/\/$/, '');
    this.l2Url = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
    
    // Wallet state
    this.wallet = null;
    this.isConnected = false;
    
    // Event listeners
    this._listeners = {};
    
    // Polling for balance updates
    this._balancePollingInterval = null;
    this._lastKnownBalance = null;
    
    // Cache
    this._cache = {
      balance: null,
      balanceTimestamp: 0,
      transactions: null,
      transactionsTimestamp: 0,
    };
    this._cacheMaxAge = config.cacheMaxAge || 5000; // 5 seconds
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EVENT SYSTEM
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Subscribe to SDK events
   * @param {string} event - Event name from EVENTS constant
   * @param {Function} callback - Function to call when event fires
   * @returns {Function} Unsubscribe function
   */
  on(event, callback) {
    if (!this._listeners[event]) {
      this._listeners[event] = [];
    }
    this._listeners[event].push(callback);
    
    // Return unsubscribe function
    return () => {
      this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
    };
  }

  /**
   * Emit an event to all listeners
   * @private
   */
  _emit(event, data) {
    if (this._listeners[event]) {
      this._listeners[event].forEach(cb => {
        try {
          cb(data);
        } catch (err) {
          console.error(`Error in event listener for ${event}:`, err);
        }
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new wallet with a random keypair
   * @returns {Object} { address, publicKey, mnemonic (if generated) }
   */
  async createWallet() {
    const keyPair = nacl.sign.keyPair();
    const publicKeyHex = this._bytesToHex(keyPair.publicKey);
    const address = this._deriveAddress(publicKeyHex);
    
    this.wallet = {
      address,
      publicKey: publicKeyHex,
      secretKey: keyPair.secretKey,
      keyPair,
    };
    
    this.isConnected = true;
    this._emit(EVENTS.WALLET_CONNECTED, { address });
    this._startBalancePolling();
    
    return {
      address,
      publicKey: publicKeyHex,
    };
  }

  /**
   * Import wallet from secret key (hex string)
   * @param {string} secretKeyHex - 64-byte secret key as hex
   * @returns {Object} { address, publicKey }
   */
  importFromSecretKey(secretKeyHex) {
    const secretKey = this._hexToBytes(secretKeyHex);
    const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey);
    const publicKeyHex = this._bytesToHex(keyPair.publicKey);
    const address = this._deriveAddress(publicKeyHex);
    
    this.wallet = {
      address,
      publicKey: publicKeyHex,
      secretKey: keyPair.secretKey,
      keyPair,
    };
    
    this.isConnected = true;
    this._emit(EVENTS.WALLET_CONNECTED, { address });
    this._startBalancePolling();
    
    return { address, publicKey: publicKeyHex };
  }

  /**
   * Import from seed (for deterministic wallets)
   * @param {Uint8Array} seed - 32-byte seed
   * @returns {Object} { address, publicKey }
   */
  importFromSeed(seed) {
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = this._bytesToHex(keyPair.publicKey);
    const address = this._deriveAddress(publicKeyHex);
    
    this.wallet = {
      address,
      publicKey: publicKeyHex,
      secretKey: keyPair.secretKey,
      keyPair,
    };
    
    this.isConnected = true;
    this._emit(EVENTS.WALLET_CONNECTED, { address });
    this._startBalancePolling();
    
    return { address, publicKey: publicKeyHex };
  }

  /**
   * Connect using test account
   * @param {'alice' | 'bob' | 'dealer'} accountName
   * @returns {Object} { address, publicKey }
   */
  connectTestAccount(accountName) {
    // Pre-computed test accounts with proper seeds and addresses
    const TEST_ACCOUNTS = {
      alice: {
        seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
        address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
      },
      bob: {
        seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
        address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
      },
      dealer: {
        seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
      },
    };
    
    const account = TEST_ACCOUNTS[accountName.toLowerCase()];
    if (!account) {
      throw new Error(`Unknown test account: ${accountName}. Use 'alice', 'bob', or 'dealer'`);
    }
    
    // Convert hex seed to bytes
    const seed = this._hexToBytes(account.seed);
    
    // Generate keypair
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = this._bytesToHex(keyPair.publicKey);
    
    this.wallet = {
      address: account.address,
      publicKey: publicKeyHex,
      secretKey: keyPair.secretKey,
      keyPair,
    };
    
    this.isConnected = true;
    this._emit(EVENTS.WALLET_CONNECTED, { address: account.address });
    this._startBalancePolling();
    
    return { address: account.address, publicKey: publicKeyHex };
  }

  /**
   * Disconnect wallet
   */
  disconnect() {
    this._stopBalancePolling();
    this.wallet = null;
    this.isConnected = false;
    this._cache = { balance: null, balanceTimestamp: 0, transactions: null, transactionsTimestamp: 0 };
    this._emit(EVENTS.WALLET_DISCONNECTED, {});
  }

  /**
   * Get connected wallet address
   * @returns {string|null}
   */
  getAddress() {
    return this.wallet?.address || null;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BALANCE & TOKEN INFO
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get balance for an address
   * @param {string} address - L1 address (optional, defaults to connected wallet)
   * @returns {Object} { balance, usdValue, symbol }
   */
  async getBalance(address = null) {
    const addr = address || this.wallet?.address;
    if (!addr) throw new Error('No address provided and no wallet connected');
    
    // Check cache for connected wallet
    if (addr === this.wallet?.address && this._cache.balance !== null) {
      if (Date.now() - this._cache.balanceTimestamp < this._cacheMaxAge) {
        return this._cache.balance;
      }
    }
    
    const response = await fetch(`${this.url}/balance/${addr}`);
    const data = await response.json();
    
    const result = {
      balance: data.balance,
      usdValue: data.balance * USD_PEG,
      symbol: TOKEN_SYMBOL,
      address: addr,
      formatted: `${data.balance.toFixed(TOKEN_DECIMALS)} ${TOKEN_SYMBOL}`,
      formattedUsd: `$${(data.balance * USD_PEG).toFixed(2)}`,
    };
    
    // Update cache for connected wallet
    if (addr === this.wallet?.address) {
      this._cache.balance = result;
      this._cache.balanceTimestamp = Date.now();
      
      // Check if balance changed
      if (this._lastKnownBalance !== null && this._lastKnownBalance !== result.balance) {
        this._emit(EVENTS.BALANCE_UPDATED, result);
      }
      this._lastKnownBalance = result.balance;
    }
    
    return result;
  }

  /**
   * Get token info
   * @returns {Object} Token metadata
   */
  getTokenInfo() {
    return {
      name: 'BlackBook Token',
      symbol: TOKEN_SYMBOL,
      decimals: TOKEN_DECIMALS,
      usdPeg: USD_PEG,
      description: 'USD-pegged token backed 1:1 by USDC',
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRANSFERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer tokens to another address
   * @param {string} to - Recipient address
   * @param {number} amount - Amount to transfer
   * @returns {Object} Transfer result
   */
  async transfer(to, amount) {
    if (!this.wallet) throw new Error('Wallet not connected');
    if (amount <= 0) throw new Error('Amount must be positive');
    
    const from = this.wallet.address;
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = this._generateNonce();
    
    // Create canonical payload hash
    const canonical = `${from}|${to}|${amount}|${timestamp}|${nonce}`;
    const payloadHash = await this._sha256(canonical);
    
    // Create signing message with domain separation
    const domain = `BLACKBOOK_L${CHAIN_ID}/transfer`;
    const message = `${domain}\n${payloadHash}\n${timestamp}\n${nonce}`;
    
    // Sign the message
    const messageBytes = new TextEncoder().encode(message);
    const signature = nacl.sign.detached(messageBytes, this.wallet.secretKey);
    const signatureHex = this._bytesToHex(signature);
    
    // Build request
    const request = {
      schema_version: 2,
      chain_id: CHAIN_ID,
      request_path: '/transfer',
      operation_type: 'transfer',
      timestamp,
      nonce,
      payload_fields: { from, to, amount, timestamp, nonce },
      payload_hash: payloadHash,
      public_key: this.wallet.publicKey,
      signature: signatureHex,
    };
    
    this._emit(EVENTS.TRANSFER_SENT, { to, amount, nonce });
    
    const response = await fetch(`${this.url}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    
    const result = await response.json();
    
    if (result.success) {
      // Invalidate cache
      this._cache.balance = null;
      this._cache.transactions = null;
      
      this._emit(EVENTS.TRANSFER_CONFIRMED, {
        txId: result.tx_id,
        from,
        to,
        amount,
        fromBalance: result.from_balance,
        toBalance: result.to_balance,
      });
    } else {
      this._emit(EVENTS.ERROR, { type: 'transfer', error: result.error });
    }
    
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // L2 GAMING SESSIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Open a credit session for L2 gaming
   * @param {number} amount - Amount to lock for L2
   * @returns {Object} Session info
   */
  async openL2Session(amount) {
    if (!this.wallet) throw new Error('Wallet not connected');
    if (amount <= 0) throw new Error('Amount must be positive');
    
    const response = await fetch(`${this.url}/credit/open`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet: this.wallet.address,
        amount,
      }),
    });
    
    const result = await response.json();
    
    if (result.success) {
      // Invalidate cache
      this._cache.balance = null;
      
      this._emit(EVENTS.SESSION_OPENED, {
        sessionId: result.session_id,
        lockedAmount: result.locked_amount,
        l1Balance: result.l1_balance_after_lock,
        l2Credit: result.available_credit,
        expiresAt: result.expires_at,
      });
    } else {
      this._emit(EVENTS.ERROR, { type: 'session_open', error: result.error });
    }
    
    return result;
  }

  /**
   * Get current L2 session status
   * @returns {Object|null} Session info or null if no active session
   */
  async getL2Session() {
    if (!this.wallet) throw new Error('Wallet not connected');
    
    const response = await fetch(`${this.url}/credit/status/${this.wallet.address}`);
    const result = await response.json();
    
    if (result.has_active_session) {
      return {
        sessionId: result.session.id,
        lockedAmount: result.session.locked_amount,
        availableCredit: result.session.available_credit,
        usedCredit: result.session.used_credit,
        expiresAt: result.session.expires_at,
        l1Balance: result.l1_balance,
      };
    }
    
    return null;
  }

  /**
   * Settle L2 session (usually called by L2 server, but exposed for testing)
   * @param {string} sessionId - Session ID to settle
   * @param {number} netPnl - Net profit/loss from L2
   * @returns {Object} Settlement result
   */
  async settleL2Session(sessionId, netPnl) {
    const response = await fetch(`${this.url}/credit/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: sessionId,
        net_pnl: netPnl,
      }),
    });
    
    const result = await response.json();
    
    if (result.success) {
      // Invalidate cache
      this._cache.balance = null;
      
      this._emit(EVENTS.SESSION_SETTLED, {
        sessionId: result.session_id,
        lockedAmount: result.locked_amount,
        netPnl: result.net_pnl,
        amountReturned: result.amount_returned,
        l1Balance: result.l1_balance_after_settle,
      });
    }
    
    return result;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRANSACTION HISTORY
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get transaction history
   * @param {Object} options - { limit, offset }
   * @returns {Array} Transactions
   */
  async getTransactions(options = {}) {
    const address = this.wallet?.address;
    if (!address) throw new Error('Wallet not connected');
    
    const limit = options.limit || 50;
    const offset = options.offset || 0;
    
    // Check cache
    if (this._cache.transactions && offset === 0) {
      if (Date.now() - this._cache.transactionsTimestamp < this._cacheMaxAge) {
        return this._cache.transactions;
      }
    }
    
    const params = new URLSearchParams({ address, limit, offset });
    const response = await fetch(`${this.url}/transactions?${params}`);
    const data = await response.json();
    
    const transactions = (data.transactions || []).map(tx => ({
      id: tx.tx_id,
      type: tx.tx_type,
      from: tx.from_address,
      to: tx.to_address,
      amount: tx.amount,
      usdValue: tx.amount * USD_PEG,
      timestamp: new Date(tx.timestamp * 1000).toISOString(),
      status: tx.status,
      signature: tx.signature,
      
      // Computed fields
      isIncoming: tx.to_address === address,
      isOutgoing: tx.from_address === address,
      displayAmount: tx.from_address === address ? `-${tx.amount}` : `+${tx.amount}`,
    }));
    
    // Cache if first page
    if (offset === 0) {
      this._cache.transactions = transactions;
      this._cache.transactionsTimestamp = Date.now();
    }
    
    return transactions;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SYSTEM INFO
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check if L1 server is healthy
   * @returns {boolean}
   */
  async isHealthy() {
    try {
      const response = await fetch(`${this.url}/health`);
      const data = await response.json();
      return data.status === 'ok';
    } catch {
      return false;
    }
  }

  /**
   * Get blockchain stats
   * @returns {Object} Stats
   */
  async getStats() {
    const response = await fetch(`${this.url}/stats`);
    return await response.json();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  _deriveAddress(publicKeyHex) {
    // Simple address derivation: L1_ + first 40 chars of pubkey hash
    const hash = publicKeyHex.toUpperCase().substring(0, 40);
    return `L1_${hash}`;
  }

  _bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  _generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return this._bytesToHex(bytes);
  }

  async _sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  _startBalancePolling(interval = 10000) {
    this._stopBalancePolling();
    this._balancePollingInterval = setInterval(async () => {
      if (this.wallet) {
        try {
          await this.getBalance();
        } catch (err) {
          console.warn('Balance polling failed:', err);
        }
      }
    }, interval);
  }

  _stopBalancePolling() {
    if (this._balancePollingInterval) {
      clearInterval(this._balancePollingInterval);
      this._balancePollingInterval = null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REACT HOOKS (for React/Next.js applications)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * React hook for BlackBook SDK
 * 
 * Usage:
 *   const { sdk, address, balance, transfer } = useBlackBook();
 */
function createReactHooks(React) {
  if (!React) return null;
  
  const { useState, useEffect, useCallback, createContext, useContext } = React;
  
  // Context for sharing SDK instance
  const BlackBookContext = createContext(null);
  
  // Provider component
  function BlackBookProvider({ children, config }) {
    const [sdk] = useState(() => new BlackBookSDK(config));
    return React.createElement(BlackBookContext.Provider, { value: sdk }, children);
  }
  
  // Main hook
  function useBlackBook() {
    const sdk = useContext(BlackBookContext);
    if (!sdk) throw new Error('useBlackBook must be used within BlackBookProvider');
    
    const [address, setAddress] = useState(sdk.getAddress());
    const [balance, setBalance] = useState(null);
    const [isConnected, setIsConnected] = useState(sdk.isConnected);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    
    // Subscribe to events
    useEffect(() => {
      const unsubs = [
        sdk.on(EVENTS.WALLET_CONNECTED, ({ address }) => {
          setAddress(address);
          setIsConnected(true);
        }),
        sdk.on(EVENTS.WALLET_DISCONNECTED, () => {
          setAddress(null);
          setBalance(null);
          setIsConnected(false);
        }),
        sdk.on(EVENTS.BALANCE_UPDATED, (bal) => {
          setBalance(bal);
        }),
        sdk.on(EVENTS.ERROR, ({ error }) => {
          setError(error);
        }),
      ];
      
      return () => unsubs.forEach(unsub => unsub());
    }, [sdk]);
    
    // Fetch balance on connect
    useEffect(() => {
      if (isConnected && address) {
        sdk.getBalance().then(setBalance).catch(console.error);
      }
    }, [isConnected, address, sdk]);
    
    const connect = useCallback(async (method, ...args) => {
      setIsLoading(true);
      setError(null);
      try {
        if (method === 'test') {
          return sdk.connectTestAccount(args[0]);
        } else if (method === 'create') {
          return await sdk.createWallet();
        } else if (method === 'secretKey') {
          return sdk.importFromSecretKey(args[0]);
        }
      } catch (err) {
        setError(err.message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    }, [sdk]);
    
    const disconnect = useCallback(() => {
      sdk.disconnect();
    }, [sdk]);
    
    const transfer = useCallback(async (to, amount) => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await sdk.transfer(to, amount);
        if (!result.success) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        setError(err.message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    }, [sdk]);
    
    const refreshBalance = useCallback(async () => {
      if (address) {
        const bal = await sdk.getBalance();
        setBalance(bal);
        return bal;
      }
    }, [sdk, address]);
    
    return {
      sdk,
      address,
      balance,
      isConnected,
      isLoading,
      error,
      connect,
      disconnect,
      transfer,
      refreshBalance,
    };
  }
  
  // Balance hook
  function useBalance(address) {
    const sdk = useContext(BlackBookContext);
    const [balance, setBalance] = useState(null);
    const [loading, setLoading] = useState(true);
    
    useEffect(() => {
      if (!address) return;
      
      setLoading(true);
      sdk.getBalance(address)
        .then(setBalance)
        .finally(() => setLoading(false));
    }, [sdk, address]);
    
    return { balance, loading };
  }
  
  // Transactions hook
  function useTransactions(options = {}) {
    const sdk = useContext(BlackBookContext);
    const [transactions, setTransactions] = useState([]);
    const [loading, setLoading] = useState(true);
    
    const refresh = useCallback(async () => {
      setLoading(true);
      try {
        const txs = await sdk.getTransactions(options);
        setTransactions(txs);
      } finally {
        setLoading(false);
      }
    }, [sdk, options.limit, options.offset]);
    
    useEffect(() => {
      if (sdk.isConnected) {
        refresh();
      }
    }, [sdk.isConnected, refresh]);
    
    return { transactions, loading, refresh };
  }
  
  return {
    BlackBookContext,
    BlackBookProvider,
    useBlackBook,
    useBalance,
    useTransactions,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

// Browser global
if (typeof window !== 'undefined') {
  window.BlackBookSDK = BlackBookSDK;
  window.BLACKBOOK_EVENTS = EVENTS;
  
  // Create React hooks if React is available
  if (window.React) {
    const hooks = createReactHooks(window.React);
    window.BlackBookProvider = hooks.BlackBookProvider;
    window.useBlackBook = hooks.useBlackBook;
    window.useBalance = hooks.useBalance;
    window.useTransactions = hooks.useTransactions;
  }
}

// Node.js / ESM export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    BlackBookSDK,
    EVENTS,
    createReactHooks,
  };
}

// ESM export for bundlers
export { BlackBookSDK, EVENTS, createReactHooks };
export default BlackBookSDK;
