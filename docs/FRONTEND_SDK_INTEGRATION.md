# BlackBook Frontend SDK Integration Guide

Complete guide for integrating BlackBook L1 blockchain into web applications.

## 📦 Installation

```bash
npm install tweetnacl
# Copy SDK files to your project
```

## 🚀 Quick Start

### Vanilla JavaScript
```html
<script type="module">
  import { BlackBookSDK } from './blackbook-frontend-sdk.js';
  
  const bb = new BlackBookSDK({ 
    url: 'https://your-l1-server.com' 
  });
  
  // Create a new wallet
  const { address, mnemonic } = await bb.createWallet();
  console.log('Save this mnemonic:', mnemonic);
  
  // Check balance
  const balance = await bb.getBalance();
  console.log(balance.formatted); // "1000.00 BB"
</script>
```

### React / Next.js
```jsx
import { BlackBookSDK, EVENTS } from './blackbook-frontend-sdk.js';
import { useState, useEffect } from 'react';

function WalletApp() {
  const [sdk] = useState(() => new BlackBookSDK({ url: 'https://api.blackbook.io' }));
  const [balance, setBalance] = useState(null);
  
  useEffect(() => {
    sdk.on(EVENTS.BALANCE_UPDATED, setBalance);
    return () => sdk.disconnect();
  }, [sdk]);
  
  async function connect() {
    await sdk.createWallet();
  }
  
  return (
    <div>
      <button onClick={connect}>Create Wallet</button>
      {balance && <span>{balance.formatted}</span>}
    </div>
  );
}
```

### Using Pre-built React Components
```jsx
import { 
  BlackBookProvider, 
  WalletButton, 
  BalanceDisplay, 
  TransferForm,
  TransactionList,
  L2SessionPanel
} from './blackbook-react.jsx';

function App() {
  return (
    <BlackBookProvider config={{ url: 'https://api.blackbook.io' }}>
      <WalletButton />
      <BalanceDisplay showUsd />
      <TransferForm />
      <TransactionList limit={10} />
      <L2SessionPanel />
    </BlackBookProvider>
  );
}
```

---

## 📚 API Reference

### BlackBookSDK Class

#### Constructor
```javascript
const sdk = new BlackBookSDK({
  url: 'https://api.blackbook.io',  // L1 server URL
  pollInterval: 30000,               // Balance poll interval (ms)
});
```

#### Wallet Management

| Method | Description | Returns |
|--------|-------------|---------|
| `createWallet()` | Generate new wallet with mnemonic | `{ address, mnemonic, publicKey }` |
| `importFromMnemonic(words)` | Import from 24-word phrase | `{ address, publicKey }` |
| `importFromSecretKey(hexKey)` | Import from secret key | `{ address, publicKey }` |
| `connectTestAccount(name)` | Connect test account (alice/bob/dealer) | `{ address, publicKey }` |
| `disconnect()` | Disconnect wallet | `void` |
| `getAddress()` | Get current address | `string \| null` |
| `isConnected` | Connection status | `boolean` |

#### Balance & Transfers

| Method | Description | Returns |
|--------|-------------|---------|
| `getBalance(address?)` | Get BB balance | `{ balance, formatted, usdValue, formattedUsd, symbol }` |
| `transfer(to, amount)` | Send BB tokens | `{ success, txId, fromBalance, toBalance }` |
| `refreshBalance()` | Force balance refresh | `BalanceResult` |

#### L2 Gaming Sessions

| Method | Description | Returns |
|--------|-------------|---------|
| `openL2Session(amount)` | Lock tokens for L2 play | `{ success, sessionId, lockedAmount, l1Balance, l2Credits }` |
| `getL2Session()` | Get active session status | `{ sessionId, lockedAmount, availableCredit, usedCredit }` |
| `settleL2Session(sessionId, netPnl)` | Settle and return tokens | `{ success, l1Balance, returned }` |

#### Transaction History

| Method | Description | Returns |
|--------|-------------|---------|
| `getTransactions({ limit, offset })` | Get transaction history | `Transaction[]` |

#### Server Info

| Method | Description | Returns |
|--------|-------------|---------|
| `getHealth()` | Check server status | `{ healthy, totalAccounts, totalSupply }` |
| `getTokenInfo()` | Get token metadata | `{ name, symbol, decimals, usdPeg }` |

---

## 🎯 Events

Subscribe to SDK events for real-time UI updates:

```javascript
import { EVENTS } from './blackbook-frontend-sdk.js';

// Available events
EVENTS.WALLET_CONNECTED      // { address }
EVENTS.WALLET_DISCONNECTED   // {}
EVENTS.BALANCE_UPDATED       // { balance, formatted, usdValue }
EVENTS.TRANSFER_SENT         // { to, amount, txId }
EVENTS.TRANSFER_CONFIRMED    // { txId, fromBalance, toBalance }
EVENTS.SESSION_OPENED        // { sessionId, lockedAmount }
EVENTS.SESSION_SETTLED       // { returned, l1Balance }
EVENTS.ERROR                 // { error, code }

// Subscribe
const unsubscribe = sdk.on(EVENTS.BALANCE_UPDATED, (balance) => {
  console.log('New balance:', balance.formatted);
});

// Unsubscribe when done
unsubscribe();
```

---

## 💰 Token Information

| Property | Value |
|----------|-------|
| **Name** | BlackBook Token |
| **Symbol** | BB |
| **Decimals** | 2 |
| **USD Peg** | 1 BB = $1.00 USD |
| **Backing** | 1:1 USDC reserves |

---

## 🎮 L2 Gaming Flow

### Step 1: Open Session (Lock Tokens)
```javascript
// Lock 100 BB for gaming
const session = await sdk.openL2Session(100);
console.log('Session ID:', session.sessionId);
console.log('L2 Credits:', session.l2Credits);
```

### Step 2: Play on L2
The L2 gaming server manages credits during gameplay:
- User's L1 tokens are LOCKED (cannot spend)
- L2 credits are created 1:1
- All games use L2 credits

### Step 3: Settle Session
```javascript
// Settlement is handled by L2 server when player cashes out
// Example: Player won +50 BB net
const result = await sdk.settleL2Session(session.sessionId, 50);
console.log('Returned to L1:', result.returned); // 150 BB (100 locked + 50 won)
```

### Token Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                        L1 BLOCKCHAIN                             │
│                                                                  │
│   [User Wallet]          [Escrow Lock]           [Dealer]       │
│   1000 BB                 ───────►                 50000 BB     │
│                           100 BB                                │
│        │                    │                        │          │
│        │ LOCK 100           │                        │          │
│        ▼                    ▼                        ▼          │
│   900 BB locked         100 BB held             (unchanged)     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ 1:1 Credit
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        L2 GAMING                                 │
│                                                                  │
│   [User Credits]         [Game Table]                           │
│   100 credits            BET 10 → WIN 20                        │
│        │                    │                                   │
│        │ Play               │                                   │
│        ▼                    ▼                                   │
│   130 credits            Net P&L: +30                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Settlement
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        L1 SETTLEMENT                             │
│                                                                  │
│   User receives: 100 (locked) + 30 (P&L) = 130 BB              │
│   Dealer pays: 30 BB (from house bankroll)                      │
│   Final: User 1030 BB, Dealer 49970 BB                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧪 Test Accounts

For development/testing, use pre-configured accounts:

```javascript
// Alice (primary test account)
sdk.connectTestAccount('alice');
// Address: L1_52882D768C0F3E7932AAD1813CF8B19058D507A8

// Bob (secondary test account)
sdk.connectTestAccount('bob');
// Address: L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433

// Dealer (house bankroll)
sdk.connectTestAccount('dealer');
// Address: L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D
```

---

## 🔐 Security Notes

### Production Checklist
- [ ] Never expose mnemonic/secret keys in frontend code
- [ ] Use HTTPS for all API calls
- [ ] Implement proper session timeout
- [ ] Add rate limiting on sensitive operations
- [ ] Validate all user inputs
- [ ] Use Content Security Policy headers

### Key Storage
```javascript
// NEVER do this in production:
localStorage.setItem('secretKey', key); // ❌ Bad!

// Instead, use secure storage or require re-authentication:
// - Hardware wallets (Ledger, Trezor)
// - Browser extensions (MetaMask-style)
// - Biometric authentication
// - Server-side session management
```

---

## 📁 File Structure

```
sdk/
├── blackbook-frontend-sdk.js   # Core SDK (use this)
├── blackbook-react.jsx         # React components
├── test-frontend-sdk.js        # Test suite
├── ledger-sdk.js               # Transaction history
└── blackbook-wallet-sdk.js     # Full wallet SDK
```

---

## 🛠️ Troubleshooting

### "nacl is not defined"
```bash
npm install tweetnacl
```

### "Network request failed"
Check your server URL and CORS settings:
```javascript
// Server should allow:
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

### "Invalid signature"
Ensure you're using the V2 signing format with canonical JSON:
```javascript
// SDK handles this automatically
// If implementing manually, sort keys alphabetically
```

---

## 📊 Live Example

See the full test at: `sdk/test-frontend-sdk.js`

```bash
cd sdk
node test-frontend-sdk.js
```

Expected output:
```
✅ Health Check: Online
✅ Wallet Connected: L1_52882D768C0F3E79...
✅ Balance: 15841.00 BB ($15841.00)
✅ Transfer: 10 BB sent to Bob
✅ L2 Session: 100 BB locked
✅ Settlement: +25 BB P&L, 125 BB returned
✅ History: 5 transactions found
```

---

## 🚀 Ready for Production

The BlackBook Frontend SDK provides everything needed for:
- **Wallets**: Creation, import, signing
- **Transfers**: P2P token transfers
- **Gaming**: L2 session management
- **History**: Full transaction ledger
- **Real-time**: Event-driven updates

Happy building! 🎰
