/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * BLACKBOOK REACT COMPONENTS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Ready-to-use React components for BlackBook integration.
 * 
 * USAGE:
 *   1. Copy this file to your React/Next.js project
 *   2. Import and wrap your app with BlackBookProvider
 *   3. Use the components anywhere in your app
 * 
 * EXAMPLE:
 *   import { BlackBookProvider, WalletButton, BalanceDisplay } from './blackbook-react';
 * 
 *   function App() {
 *     return (
 *       <BlackBookProvider config={{ url: 'https://api.blackbook.io' }}>
 *         <WalletButton />
 *         <BalanceDisplay />
 *       </BlackBookProvider>
 *     );
 *   }
 */

import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';

// ═══════════════════════════════════════════════════════════════════════════════
// SDK IMPORT (adjust path as needed)
// ═══════════════════════════════════════════════════════════════════════════════

// For npm package: import { BlackBookSDK, EVENTS } from 'blackbook-sdk';
// For local file:
import { BlackBookSDK, EVENTS } from './blackbook-frontend-sdk.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT & PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════

const BlackBookContext = createContext(null);

export function BlackBookProvider({ children, config = {} }) {
  const [sdk] = useState(() => new BlackBookSDK(config));
  const [state, setState] = useState({
    address: null,
    balance: null,
    isConnected: false,
    isLoading: false,
    error: null,
    session: null,
  });

  // Subscribe to SDK events
  useEffect(() => {
    const unsubs = [
      sdk.on(EVENTS.WALLET_CONNECTED, async ({ address }) => {
        const balance = await sdk.getBalance();
        setState(s => ({ ...s, address, isConnected: true, balance }));
      }),
      sdk.on(EVENTS.WALLET_DISCONNECTED, () => {
        setState(s => ({ ...s, address: null, balance: null, isConnected: false, session: null }));
      }),
      sdk.on(EVENTS.BALANCE_UPDATED, (balance) => {
        setState(s => ({ ...s, balance }));
      }),
      sdk.on(EVENTS.SESSION_OPENED, (session) => {
        setState(s => ({ ...s, session }));
      }),
      sdk.on(EVENTS.SESSION_SETTLED, () => {
        setState(s => ({ ...s, session: null }));
      }),
      sdk.on(EVENTS.ERROR, ({ error }) => {
        setState(s => ({ ...s, error }));
      }),
    ];

    return () => unsubs.forEach(unsub => unsub());
  }, [sdk]);

  const value = {
    sdk,
    ...state,
    setState,
  };

  return (
    <BlackBookContext.Provider value={value}>
      {children}
    </BlackBookContext.Provider>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

export function useBlackBook() {
  const context = useContext(BlackBookContext);
  if (!context) {
    throw new Error('useBlackBook must be used within BlackBookProvider');
  }
  return context;
}

export function useWallet() {
  const { sdk, address, isConnected, isLoading, setState } = useBlackBook();

  const connect = useCallback(async (method, ...args) => {
    setState(s => ({ ...s, isLoading: true, error: null }));
    try {
      if (method === 'test') {
        return sdk.connectTestAccount(args[0]);
      } else if (method === 'create') {
        return await sdk.createWallet();
      } else if (method === 'secretKey') {
        return sdk.importFromSecretKey(args[0]);
      }
    } catch (err) {
      setState(s => ({ ...s, error: err.message }));
      throw err;
    } finally {
      setState(s => ({ ...s, isLoading: false }));
    }
  }, [sdk, setState]);

  const disconnect = useCallback(() => {
    sdk.disconnect();
  }, [sdk]);

  return { address, isConnected, isLoading, connect, disconnect };
}

export function useBalance(targetAddress = null) {
  const { sdk, address, balance } = useBlackBook();
  const [externalBalance, setExternalBalance] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (targetAddress && targetAddress !== address) {
      setLoading(true);
      sdk.getBalance(targetAddress)
        .then(setExternalBalance)
        .finally(() => setLoading(false));
    }
  }, [sdk, targetAddress, address]);

  if (targetAddress && targetAddress !== address) {
    return { balance: externalBalance, loading };
  }

  return { balance, loading: false };
}

export function useTransfer() {
  const { sdk, setState } = useBlackBook();
  const [isTransferring, setIsTransferring] = useState(false);

  const transfer = useCallback(async (to, amount) => {
    setIsTransferring(true);
    setState(s => ({ ...s, error: null }));
    try {
      const result = await sdk.transfer(to, amount);
      if (!result.success) {
        setState(s => ({ ...s, error: result.error }));
      }
      return result;
    } catch (err) {
      setState(s => ({ ...s, error: err.message }));
      throw err;
    } finally {
      setIsTransferring(false);
    }
  }, [sdk, setState]);

  return { transfer, isTransferring };
}

export function useL2Session() {
  const { sdk, session, setState } = useBlackBook();
  const [isLoading, setIsLoading] = useState(false);

  const openSession = useCallback(async (amount) => {
    setIsLoading(true);
    try {
      const result = await sdk.openL2Session(amount);
      return result;
    } finally {
      setIsLoading(false);
    }
  }, [sdk]);

  const settleSession = useCallback(async (sessionId, netPnl) => {
    setIsLoading(true);
    try {
      const result = await sdk.settleL2Session(sessionId, netPnl);
      return result;
    } finally {
      setIsLoading(false);
    }
  }, [sdk]);

  const refreshSession = useCallback(async () => {
    const s = await sdk.getL2Session();
    setState(prev => ({ ...prev, session: s }));
    return s;
  }, [sdk, setState]);

  return { session, openSession, settleSession, refreshSession, isLoading };
}

export function useTransactions(options = {}) {
  const { sdk, isConnected } = useBlackBook();
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!isConnected) return;
    setLoading(true);
    try {
      const txs = await sdk.getTransactions(options);
      setTransactions(txs);
    } finally {
      setLoading(false);
    }
  }, [sdk, isConnected, options.limit, options.offset]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { transactions, loading, refresh };
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wallet Connect/Disconnect Button
 */
export function WalletButton({ className = '', testAccount = null }) {
  const { address, isConnected, isLoading, connect, disconnect } = useWallet();
  const [showMenu, setShowMenu] = useState(false);

  if (isConnected) {
    return (
      <div className={`bb-wallet-connected ${className}`}>
        <button 
          onClick={() => setShowMenu(!showMenu)}
          className="bb-wallet-btn"
        >
          {address.substring(0, 8)}...{address.substring(address.length - 6)}
        </button>
        {showMenu && (
          <div className="bb-wallet-menu">
            <button onClick={disconnect}>Disconnect</button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={`bb-wallet-disconnected ${className}`}>
      {testAccount ? (
        <button 
          onClick={() => connect('test', testAccount)}
          disabled={isLoading}
          className="bb-connect-btn"
        >
          {isLoading ? 'Connecting...' : `Connect ${testAccount}`}
        </button>
      ) : (
        <button 
          onClick={() => connect('create')}
          disabled={isLoading}
          className="bb-connect-btn"
        >
          {isLoading ? 'Creating...' : 'Create Wallet'}
        </button>
      )}
    </div>
  );
}

/**
 * Balance Display Component
 */
export function BalanceDisplay({ className = '', showUsd = true }) {
  const { balance, isConnected } = useBlackBook();

  if (!isConnected || !balance) {
    return (
      <div className={`bb-balance-disconnected ${className}`}>
        <span>--</span>
      </div>
    );
  }

  return (
    <div className={`bb-balance ${className}`}>
      <span className="bb-balance-amount">{balance.formatted}</span>
      {showUsd && (
        <span className="bb-balance-usd">{balance.formattedUsd}</span>
      )}
    </div>
  );
}

/**
 * Transfer Form Component
 */
export function TransferForm({ className = '', onSuccess, onError }) {
  const { isConnected } = useBlackBook();
  const { transfer, isTransferring } = useTransfer();
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [result, setResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResult(null);
    
    try {
      const res = await transfer(to, parseFloat(amount));
      setResult(res);
      if (res.success) {
        setTo('');
        setAmount('');
        onSuccess?.(res);
      } else {
        onError?.(res.error);
      }
    } catch (err) {
      onError?.(err.message);
    }
  };

  if (!isConnected) {
    return <div className={className}>Connect wallet to transfer</div>;
  }

  return (
    <form onSubmit={handleSubmit} className={`bb-transfer-form ${className}`}>
      <div className="bb-form-group">
        <label>Recipient Address</label>
        <input
          type="text"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="L1_..."
          required
        />
      </div>
      <div className="bb-form-group">
        <label>Amount (BB)</label>
        <input
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0.00"
          min="0.01"
          step="0.01"
          required
        />
      </div>
      <button type="submit" disabled={isTransferring}>
        {isTransferring ? 'Sending...' : 'Send'}
      </button>
      {result && (
        <div className={`bb-result ${result.success ? 'success' : 'error'}`}>
          {result.success ? '✅ Transfer successful!' : `❌ ${result.error}`}
        </div>
      )}
    </form>
  );
}

/**
 * Transaction History Component
 */
export function TransactionList({ className = '', limit = 10 }) {
  const { transactions, loading, refresh } = useTransactions({ limit });

  return (
    <div className={`bb-transaction-list ${className}`}>
      <div className="bb-list-header">
        <h3>Recent Transactions</h3>
        <button onClick={refresh} disabled={loading}>
          {loading ? '...' : '↻'}
        </button>
      </div>
      {transactions.length === 0 ? (
        <div className="bb-empty">No transactions yet</div>
      ) : (
        <ul>
          {transactions.map((tx) => (
            <li key={tx.id} className={`bb-tx ${tx.isIncoming ? 'incoming' : 'outgoing'}`}>
              <span className="bb-tx-icon">{tx.isIncoming ? '⬇️' : '⬆️'}</span>
              <span className="bb-tx-amount">{tx.displayAmount} BB</span>
              <span className="bb-tx-type">{tx.type}</span>
              <span className="bb-tx-date">
                {new Date(tx.timestamp).toLocaleDateString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * L2 Gaming Session Component
 */
export function L2SessionPanel({ className = '' }) {
  const { isConnected } = useBlackBook();
  const { session, openSession, settleSession, refreshSession, isLoading } = useL2Session();
  const [amount, setAmount] = useState('100');

  useEffect(() => {
    if (isConnected) {
      refreshSession();
    }
  }, [isConnected, refreshSession]);

  if (!isConnected) {
    return <div className={className}>Connect wallet to play</div>;
  }

  if (session) {
    return (
      <div className={`bb-session-active ${className}`}>
        <h3>🎮 Active L2 Session</h3>
        <div className="bb-session-info">
          <p>Locked: <strong>{session.lockedAmount} BB</strong></p>
          <p>Available Credit: <strong>{session.availableCredit} BB</strong></p>
          <p>Used: <strong>{session.usedCredit} BB</strong></p>
        </div>
        <p className="bb-session-note">
          Session is managed by the L2 gaming server.
          Your tokens are safely locked on L1.
        </p>
      </div>
    );
  }

  return (
    <div className={`bb-session-create ${className}`}>
      <h3>🎮 Start Playing</h3>
      <p>Lock tokens to play on Layer 2</p>
      <div className="bb-form-group">
        <label>Amount to Lock (BB)</label>
        <input
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          min="1"
          step="1"
        />
      </div>
      <button 
        onClick={() => openSession(parseFloat(amount))}
        disabled={isLoading}
      >
        {isLoading ? 'Opening...' : `Lock ${amount} BB & Play`}
      </button>
    </div>
  );
}

/**
 * Error Display Component
 */
export function ErrorDisplay({ className = '' }) {
  const { error, setState } = useBlackBook();

  if (!error) return null;

  return (
    <div className={`bb-error ${className}`}>
      <span>⚠️ {error}</span>
      <button onClick={() => setState(s => ({ ...s, error: null }))}>×</button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CSS STYLES (inject or import separately)
// ═══════════════════════════════════════════════════════════════════════════════

export const defaultStyles = `
  .bb-wallet-btn, .bb-connect-btn {
    padding: 10px 20px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-weight: bold;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    transition: all 0.2s;
  }
  .bb-wallet-btn:hover, .bb-connect-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
  }
  .bb-balance {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
  }
  .bb-balance-amount {
    font-size: 1.5rem;
    font-weight: bold;
  }
  .bb-balance-usd {
    color: #888;
    font-size: 0.9rem;
  }
  .bb-transfer-form {
    display: flex;
    flex-direction: column;
    gap: 15px;
    max-width: 400px;
  }
  .bb-form-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .bb-form-group input {
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 1rem;
  }
  .bb-result.success { color: green; }
  .bb-result.error { color: red; }
  .bb-transaction-list ul {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .bb-tx {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px;
    border-bottom: 1px solid #eee;
  }
  .bb-tx.incoming .bb-tx-amount { color: green; }
  .bb-tx.outgoing .bb-tx-amount { color: red; }
  .bb-error {
    background: #fee;
    border: 1px solid #f00;
    color: #900;
    padding: 10px 15px;
    border-radius: 6px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .bb-error button {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.2rem;
  }
`;

// Export all
export default {
  BlackBookProvider,
  useBlackBook,
  useWallet,
  useBalance,
  useTransfer,
  useL2Session,
  useTransactions,
  WalletButton,
  BalanceDisplay,
  TransferForm,
  TransactionList,
  L2SessionPanel,
  ErrorDisplay,
  defaultStyles,
};
