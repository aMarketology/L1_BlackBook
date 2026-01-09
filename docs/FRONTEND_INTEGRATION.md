# 🌐 BlackBook L1 Frontend Integration Guide

> **For Next.js / React / Web Applications**  
> **Last Updated**: January 8, 2026

---

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLACKBOOK FRONTEND ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐         ┌──────────────┐         ┌──────────────┐       │
│   │   Next.js    │         │    L1 Node   │         │   L2 Node    │       │
│   │   Frontend   │         │   (Rust)     │         │   (Gaming)   │       │
│   └──────┬───────┘         └──────┬───────┘         └──────┬───────┘       │
│          │                        │                        │                │
│          │  HTTP REST             │  gRPC (internal)       │                │
│          │  :8080                 │  :50051                │                │
│          │                        │                        │                │
│   ┌──────▼───────┐         ┌──────▼───────┐         ┌──────▼───────┐       │
│   │  Wallet SDK  │◄───────►│  REST API    │◄───────►│  gRPC Client │       │
│   │  (browser)   │         │  (public)    │         │  (L2→L1)     │       │
│   └──────────────┘         └──────────────┘         └──────────────┘       │
│                                                                              │
│   IMPORTANT: Browsers CANNOT use gRPC directly!                              │
│   Frontend uses HTTP REST → L1 handles gRPC internally                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚫 Why NOT gRPC for Frontend?

**Browsers cannot use native gRPC** because:
1. gRPC uses HTTP/2 with binary protobuf (not browser-compatible)
2. CORS issues with gRPC-Web
3. Complex setup with Envoy proxy

**Our Solution**: 
- **Frontend → REST API (HTTP)** on port `:8080`
- **L2 → L1 uses gRPC** on port `:50051` (server-to-server only)

---

## 🔗 Connection Methods

### Method 1: REST API (Recommended for Frontend)

```javascript
// Next.js / React - use HTTP REST API
const L1_URL = 'http://localhost:8080';  // Dev
// const L1_URL = 'https://api.blackbook.io';  // Production

// Simple balance check
const response = await fetch(`${L1_URL}/balance/${walletAddress}`);
const data = await response.json();
console.log('Balance:', data.balance);
```

### Method 2: gRPC (Server-to-Server Only)

```javascript
// Node.js backend / L2 server - NOT for browser!
import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';

const client = new SettlementNode('localhost:50051', grpc.credentials.createInsecure());
client.GetBalance({ address: 'L1_...' }, (err, res) => { ... });
```

---

## 🔐 Wallet System Explained

### The Fork Architecture (V2)

```
                    PASSWORD FORK ARCHITECTURE
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                       User's Password                           │
│                            │                                    │
│                    ┌───────┴───────┐                           │
│                    │  forkPassword │                           │
│                    └───────┬───────┘                           │
│                            │                                    │
│              ┌─────────────┴─────────────┐                     │
│              │                           │                      │
│              ▼                           ▼                      │
│    ┌─────────────────┐         ┌─────────────────┐            │
│    │    auth_key     │         │    vault_key    │            │
│    │   (SHA-256)     │         │   (Argon2id)    │            │
│    └────────┬────────┘         └────────┬────────┘            │
│             │                           │                      │
│             │ Sent to server            │ NEVER leaves browser │
│             │ for authentication        │ Decrypts mnemonic    │
│             ▼                           ▼                      │
│    ┌─────────────────┐         ┌─────────────────┐            │
│    │  bcrypt hash    │         │ Decrypt Vault   │            │
│    │  stored in DB   │         │ → Get Mnemonic  │            │
│    └─────────────────┘         │ → Derive Keys   │            │
│                                └─────────────────┘            │
│                                                                 │
│    SERVER CAN'T DECRYPT VAULT - Host-Proof Security!           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Derivation Flow

```
Mnemonic (24 words)
       │
       ▼
   SHA-256 seed (32 bytes)
       │
       ▼
   Ed25519 KeyPair
       │
       ├─► Public Key (32 bytes) → Wallet Address
       │
       └─► Private Key (64 bytes) → Signs transactions
```

### Address Format

```
L1_52882D768C0F3E7932AAD1813CF8B19058D507A8
│  └──────────────────────────────────────────┘
│                    │
│                    └── SHA-256(publicKey) truncated to 40 hex chars
│
└── Layer prefix: L1_ for Layer 1, L2_ for Layer 2
```

---

## 📦 SDK Installation (Next.js)

### 1. Copy SDK to your project

```bash
# From BlackBook L1 repo
cp sdk/blackbook-wallet-sdk.js your-nextjs-app/lib/
```

### 2. Install dependencies

```bash
npm install tweetnacl argon2-browser
```

### 3. Create a wallet context

```typescript
// lib/wallet-context.tsx
'use client';

import { createContext, useContext, useState, ReactNode } from 'react';

interface WalletState {
  address: string | null;
  publicKey: string | null;
  isConnected: boolean;
}

interface WalletContextType extends WalletState {
  connect: (username: string, password: string) => Promise<void>;
  disconnect: () => void;
  transfer: (to: string, amount: number) => Promise<any>;
  getBalance: () => Promise<number>;
}

const WalletContext = createContext<WalletContextType | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [wallet, setWallet] = useState<WalletState>({
    address: null,
    publicKey: null,
    isConnected: false,
  });
  
  // Private key stored in memory only (never persisted)
  const [privateKey, setPrivateKey] = useState<Uint8Array | null>(null);

  const connect = async (username: string, password: string) => {
    const sdk = await import('./blackbook-wallet-sdk');
    const walletInstance = new sdk.BlackBookWallet('http://localhost:8080');
    
    const result = await walletInstance.login(username, password);
    
    setWallet({
      address: walletInstance.address,
      publicKey: sdk.bytesToHex(walletInstance.publicKey),
      isConnected: true,
    });
    setPrivateKey(walletInstance.privateKey);
  };

  const disconnect = () => {
    setWallet({ address: null, publicKey: null, isConnected: false });
    setPrivateKey(null);
  };

  const transfer = async (to: string, amount: number) => {
    if (!privateKey || !wallet.address) throw new Error('Not connected');
    
    const sdk = await import('./blackbook-wallet-sdk');
    const signedRequest = await sdk.signRequest(
      privateKey,
      'transfer',
      { from: wallet.address, to, amount },
      '/transfer',
      0x01  // CHAIN_ID_L1
    );
    
    const response = await fetch('http://localhost:8080/transfer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest),
    });
    
    return response.json();
  };

  const getBalance = async () => {
    if (!wallet.address) throw new Error('Not connected');
    
    const response = await fetch(`http://localhost:8080/balance/${wallet.address}`);
    const data = await response.json();
    return data.balance;
  };

  return (
    <WalletContext.Provider value={{ ...wallet, connect, disconnect, transfer, getBalance }}>
      {children}
    </WalletContext.Provider>
  );
}

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) throw new Error('useWallet must be used within WalletProvider');
  return context;
};
```

---

## 🔑 Core Operations

### 1. Register New Wallet

```typescript
// pages/register.tsx
'use client';

import { useState } from 'react';

export default function Register() {
  const [mnemonic, setMnemonic] = useState<string | null>(null);

  const handleRegister = async (username: string, password: string) => {
    const sdk = await import('@/lib/blackbook-wallet-sdk');
    const wallet = new sdk.BlackBookWallet('http://localhost:8080');
    
    const result = await wallet.register(username, password);
    
    if (result.success) {
      // CRITICAL: Show mnemonic to user ONCE
      setMnemonic(wallet.mnemonic);
      alert('SAVE YOUR MNEMONIC! It will never be shown again.');
    }
  };

  return (
    <div>
      {/* Registration form */}
      {mnemonic && (
        <div className="bg-yellow-100 p-4 rounded">
          <h3>🔐 Your Recovery Phrase (SAVE THIS!):</h3>
          <code className="block mt-2">{mnemonic}</code>
        </div>
      )}
    </div>
  );
}
```

### 2. Login

```typescript
// pages/login.tsx
'use client';

import { useWallet } from '@/lib/wallet-context';

export default function Login() {
  const { connect, isConnected, address } = useWallet();

  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    await connect(
      form.get('username') as string,
      form.get('password') as string
    );
  };

  if (isConnected) {
    return <div>Connected: {address}</div>;
  }

  return (
    <form onSubmit={handleLogin}>
      <input name="username" placeholder="Username" required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>
  );
}
```

### 3. Check Balance

```typescript
// components/Balance.tsx
'use client';

import { useWallet } from '@/lib/wallet-context';
import { useEffect, useState } from 'react';

export default function Balance() {
  const { address, isConnected, getBalance } = useWallet();
  const [balance, setBalance] = useState<number | null>(null);

  useEffect(() => {
    if (isConnected) {
      getBalance().then(setBalance);
    }
  }, [isConnected]);

  if (!isConnected) return null;

  return (
    <div className="p-4 bg-gray-100 rounded">
      <p>Address: {address}</p>
      <p>Balance: {balance?.toFixed(2)} $BC</p>
    </div>
  );
}
```

### 4. Transfer Tokens

```typescript
// components/Transfer.tsx
'use client';

import { useWallet } from '@/lib/wallet-context';
import { useState } from 'react';

export default function Transfer() {
  const { transfer, isConnected } = useWallet();
  const [status, setStatus] = useState<string>('');

  const handleTransfer = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setStatus('Processing...');
    
    const form = new FormData(e.currentTarget);
    const to = form.get('to') as string;
    const amount = parseFloat(form.get('amount') as string);
    
    try {
      const result = await transfer(to, amount);
      if (result.success) {
        setStatus(`✅ Sent! TX: ${result.tx_id}`);
      } else {
        setStatus(`❌ Failed: ${result.error}`);
      }
    } catch (err: any) {
      setStatus(`❌ Error: ${err.message}`);
    }
  };

  if (!isConnected) return <p>Please connect wallet first</p>;

  return (
    <form onSubmit={handleTransfer} className="space-y-4">
      <input 
        name="to" 
        placeholder="Recipient Address (L1_...)" 
        className="w-full p-2 border rounded"
        required 
      />
      <input 
        name="amount" 
        type="number" 
        step="0.01"
        placeholder="Amount ($BC)" 
        className="w-full p-2 border rounded"
        required 
      />
      <button 
        type="submit"
        className="w-full bg-blue-500 text-white p-2 rounded"
      >
        Send
      </button>
      {status && <p>{status}</p>}
    </form>
  );
}
```

---

## 🌉 Bridge Operations (L1 ↔ L2)

### Bridge to L2 (Lock tokens for gaming)

```typescript
async function bridgeToL2(amount: number) {
  const signedRequest = await signRequest(
    privateKey,
    'bridge_deposit',
    { from: address, amount },
    '/bridge/initiate',
    0x01
  );
  
  const response = await fetch('http://localhost:8080/bridge/initiate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...signedRequest,
      target_layer: 'L2',
    }),
  });
  
  const data = await response.json();
  // Returns: { lock_id, amount_locked, l1_signature }
  // L2 will verify l1_signature to credit user on L2
  return data;
}
```

### Request Credit Line (for instant betting)

```typescript
async function requestCreditLine(creditLimit: number) {
  const signedRequest = await signRequest(
    privateKey,
    'credit_line',
    { wallet_address: address, credit_limit: creditLimit },
    '/bridge/credit/approve',
    0x01
  );
  
  const response = await fetch('http://localhost:8080/bridge/credit/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(signedRequest),
  });
  
  return response.json();
}
```

---

## 📡 API Reference

### Public Endpoints (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/balance/{address}` | Get balance |
| GET | `/explorer/block/{slot}` | Get block data |
| GET | `/explorer/tx/{id}` | Get transaction |
| GET | `/explorer/richlist` | Top accounts |
| GET | `/headers/latest` | Latest block header |
| POST | `/rpc` | JSON-RPC endpoint |

### Authenticated Endpoints (Signature Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/transfer` | Send tokens |
| POST | `/bridge/initiate` | Lock for L2 |
| POST | `/bridge/credit/approve` | Request credit line |
| POST | `/bridge/credit/draw` | Draw from credit |
| POST | `/bridge/credit/settle` | Settle session |

### Signed Request Format

```typescript
interface SignedRequest {
  public_key: string;      // 64 hex chars
  payload_hash: string;    // SHA-256 of payload
  payload_fields: {
    from: string;
    to: string;
    amount: number;
    timestamp: number;
    nonce: string;
  };
  operation_type: string;  // 'transfer', 'bridge_deposit', etc.
  schema_version: number;  // 2
  timestamp: number;       // Unix ms
  nonce: string;           // UUID
  chain_id: number;        // 0x01 for L1
  request_path: string;    // '/transfer'
  signature: string;       // 128 hex chars (Ed25519)
}
```

---

## 🔄 Real-time Updates (WebSocket)

```typescript
// Coming soon - WebSocket for live balance updates
// For now, poll the balance endpoint

useEffect(() => {
  const interval = setInterval(async () => {
    if (isConnected) {
      const balance = await getBalance();
      setBalance(balance);
    }
  }, 5000); // Poll every 5 seconds
  
  return () => clearInterval(interval);
}, [isConnected]);
```

---

## 🧪 Test Accounts (Development Only)

```javascript
const TEST_ACCOUNTS = {
  alice: {
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    balance: 10000, // $BC
  },
  bob: {
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    balance: 5000,
  },
  dealer: {
    address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    balance: 100000,
  },
};
```

---

## 🚨 Security Checklist

```
FRONTEND SECURITY CHECKLIST
═══════════════════════════════════════════════════════════════

[x] Private key NEVER sent to server
[x] Private key stored in memory only (not localStorage)
[x] Mnemonic shown ONCE at registration
[x] All transactions signed client-side
[x] Domain separation (chain_id in signatures)
[x] Nonce prevents replay attacks
[x] HTTPS in production

NEVER DO:
❌ Store private key in localStorage
❌ Send private key to any server
❌ Log private key or mnemonic
❌ Store mnemonic in plaintext
```

---

## 🐛 Troubleshooting

### "Wallet not initialized"
- User needs to login first
- Check if privateKey is set in context

### "Invalid signature"
- Ensure chain_id matches (0x01 for L1)
- Check timestamp is recent (not expired)
- Verify nonce is unique

### "CORS error"
- Add your frontend origin to L1 CORS whitelist
- Or run L1 with CORS disabled for development

### "Connection refused"
- Ensure L1 server is running: `cargo run`
- Check port 8080 is not blocked

---

## 📚 Additional Resources

- [Wallet SDK Source](../sdk/blackbook-wallet-sdk.js)
- [gRPC Proto Definition](../proto/settlement.proto)
- [Test Examples](../sdk/test-credit-line-grpc.js)
- [Mainnet Checklist](../mainnet.md)
