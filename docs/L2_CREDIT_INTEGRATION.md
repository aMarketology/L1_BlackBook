# L2 Credit Line Integration Guide

## Overview

Layer 1 (L1) is the **sole source of truth** for all real token balances. Layer 2 (L2) operates on **credit lines** - virtual balances backed by L1 reserves. No tokens are ever "moved" between layers; instead:

1. L2 requests credit against a user's L1 balance
2. L1 reserves the requested amount
3. User plays on L2 with virtual balance
4. L2 settles the session by reporting P&L to L1
5. L1 transfers tokens between user and dealer based on P&L

```
┌─────────────────────────────────────────────────────────────────┐
│                      CREDIT LINE FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   USER L1 BALANCE: 10,000 $BC                                   │
│         │                                                       │
│         ▼                                                       │
│   ┌─────────────────┐    POST /credit/open     ┌──────────────┐│
│   │   L1 Reserve    │ ◄──────────────────────── │     L2      ││
│   │   5,000 $BC     │    (amount: 5000)         │  Sequencer  ││
│   └────────┬────────┘                           └──────┬───────┘│
│            │                                           │        │
│            │  User plays, wins 2,500                   │        │
│            │                                           │        │
│            ▼                                           ▼        │
│   ┌─────────────────┐    POST /credit/settle   ┌──────────────┐│
│   │  Apply P&L      │ ◄──────────────────────── │  L2 reports ││
│   │  +2,500 to user │    (pnl: 2500)            │  final P&L  ││
│   └────────┬────────┘                           └─────────────┘│
│            │                                                    │
│            ▼                                                    │
│   USER L1 BALANCE: 12,500 $BC  (10,000 + 2,500 winnings)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## L1 Endpoints

### Base URL
```
Production: https://l1.blackbook.bet
Development: http://localhost:8080
```

### Authentication
All credit endpoints require L2 node signature verification:
- **L2 Public Key**: `07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a`
- **Signature Format**: Ed25519 signature over message string

---

## Endpoint Reference

### 1. Query L1 Balance (Before Opening Credit)

```http
GET /credit/balance/{wallet_address}
```

**Purpose**: Check user's L1 balance before requesting credit.

**Example Request**:
```bash
curl http://localhost:8080/credit/balance/L1_52882D768C0F3E7932AAD1813CF8B19058D507A8
```

**Response**:
```json
{
  "wallet_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "l1_balance": 15273.79,
  "symbol": "$BC"
}
```

---

### 2. Open Credit Line

```http
POST /credit/open
Content-Type: application/json
```

**Purpose**: Reserve funds from user's L1 balance for L2 gaming session.

**Request Body**:
```json
{
  "wallet_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "amount": 5000.0,
  "l2_public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
  "signature": "<ed25519_signature>",
  "timestamp": 1736700000
}
```

**Signature Message Format**:
```
CREDIT_OPEN:{wallet_address}:{amount}:{timestamp}
```

**Example**:
```
CREDIT_OPEN:L1_52882D768C0F3E7932AAD1813CF8B19058D507A8:5000:1736700000
```

**Success Response**:
```json
{
  "success": true,
  "session_id": "session_1736700000123456789",
  "credit_amount": 5000.0,
  "l1_balance": 15273.79,
  "available_after_credit": 10273.79,
  "message": "Credit line opened. L2 can now track virtual balance."
}
```

**Error Responses**:
```json
// Insufficient balance
{
  "success": false,
  "error": "Insufficient balance: 1000 < 5000",
  "l1_balance": 1000.0,
  "requested": 5000.0
}

// Already has active session
{
  "success": false,
  "error": "User already has active credit session"
}

// Invalid signature
{
  "success": false,
  "error": "Invalid L2 signature"
}
```

---

### 3. Check Credit Status

```http
GET /credit/status/{wallet_address}
```

**Purpose**: Check if user has an active credit session.

**Example Request**:
```bash
curl http://localhost:8080/credit/status/L1_52882D768C0F3E7932AAD1813CF8B19058D507A8
```

**Response (Active Session)**:
```json
{
  "wallet_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "l1_balance": 15273.79,
  "has_active_credit": true,
  "session_id": "session_1736700000123456789",
  "credit_amount": 5000.0,
  "available_balance": 10273.79,
  "opened_at": 1736700000
}
```

**Response (No Active Session)**:
```json
{
  "wallet_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "l1_balance": 15273.79,
  "has_active_credit": false,
  "available_balance": 15273.79,
  "message": "No active credit line"
}
```

---

### 4. Settle Credit Line

```http
POST /credit/settle
Content-Type: application/json
```

**Purpose**: Close credit session and apply P&L to L1 balances.

**Request Body**:
```json
{
  "session_id": "session_1736700000123456789",
  "wallet_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "final_balance": 7500.0,
  "pnl": 2500.0,
  "l2_public_key": "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
  "signature": "<ed25519_signature>",
  "timestamp": 1736703600
}
```

**P&L Explanation**:
- `pnl > 0`: User won → Dealer pays user
- `pnl < 0`: User lost → User pays dealer
- `pnl = 0`: Break even → No transfer

**Signature Message Format**:
```
CREDIT_SETTLE:{session_id}:{wallet_address}:{pnl}:{timestamp}
```

**Example**:
```
CREDIT_SETTLE:session_1736700000123456789:L1_52882D768C0F3E7932AAD1813CF8B19058D507A8:2500:1736703600
```

**Success Response**:
```json
{
  "success": true,
  "session_id": "session_1736700000123456789",
  "l1_balance_before": 15273.79,
  "l1_balance_after": 17773.79,
  "pnl_applied": 2500.0,
  "message": "Settlement complete. L1 balance updated."
}
```

**Error Responses**:
```json
// Session not found
{
  "success": false,
  "error": "Session not found"
}

// Session already settled
{
  "success": false,
  "error": "Session already settled"
}

// Dealer insufficient balance (rare - means dealer is undercapitalized)
{
  "success": false,
  "error": "Dealer insufficient balance"
}
```

---

## L2 Implementation Requirements

### 1. Session Management

L2 must track:
```typescript
interface L2Session {
  sessionId: string;          // From /credit/open response
  walletAddress: string;      // L1_... address
  creditAmount: number;       // Initial credit from L1
  virtualBalance: number;     // Current balance (starts at creditAmount)
  openedAt: number;           // Unix timestamp
  bets: Bet[];                // All bets in session
}
```

### 2. Virtual Balance Tracking

When user places bets on L2:
```typescript
// User bets 100 on an event
session.virtualBalance -= 100;

// User wins 250 (including stake)
session.virtualBalance += 250;

// Calculate P&L for settlement
const pnl = session.virtualBalance - session.creditAmount;
// If started with 5000, now has 7500: pnl = 2500 (profit)
// If started with 5000, now has 3000: pnl = -2000 (loss)
```

### 3. Settlement Triggers

L2 should settle sessions:
- **On user request** (cash out)
- **Session timeout** (e.g., 24 hours)
- **Risk threshold** (e.g., user down 80% of credit)
- **Market close** (for prediction markets)

### 4. Signature Generation

```typescript
import nacl from 'tweetnacl';
import { Buffer } from 'buffer';

const L2_PRIVATE_KEY = process.env.L2_PRIVATE_KEY; // 64 hex chars

function signMessage(message: string): string {
  const privateKey = Buffer.from(L2_PRIVATE_KEY, 'hex');
  const messageBytes = Buffer.from(message, 'utf8');
  const signature = nacl.sign.detached(messageBytes, privateKey);
  return Buffer.from(signature).toString('hex');
}

// Open credit
const openMessage = `CREDIT_OPEN:${walletAddress}:${amount}:${timestamp}`;
const openSignature = signMessage(openMessage);

// Settle credit
const settleMessage = `CREDIT_SETTLE:${sessionId}:${walletAddress}:${pnl}:${timestamp}`;
const settleSignature = signMessage(settleMessage);
```

---

## Key Addresses

| Account | L1 Address | Role |
|---------|------------|------|
| **Dealer** | `L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D` | House/counterparty for all bets |
| **L2 Sequencer** | Uses public key `07943256...` | Signs credit requests |

---

## Example L2 Flow (TypeScript)

```typescript
import axios from 'axios';

const L1_URL = 'http://localhost:8080';
const L2_PUBLIC_KEY = '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a';

class CreditLineManager {
  async openCredit(walletAddress: string, amount: number): Promise<string> {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `CREDIT_OPEN:${walletAddress}:${amount}:${timestamp}`;
    const signature = this.sign(message);

    const response = await axios.post(`${L1_URL}/credit/open`, {
      wallet_address: walletAddress,
      amount,
      l2_public_key: L2_PUBLIC_KEY,
      signature,
      timestamp
    });

    if (!response.data.success) {
      throw new Error(response.data.error);
    }

    return response.data.session_id;
  }

  async settleCredit(sessionId: string, walletAddress: string, pnl: number): Promise<void> {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `CREDIT_SETTLE:${sessionId}:${walletAddress}:${pnl}:${timestamp}`;
    const signature = this.sign(message);

    const response = await axios.post(`${L1_URL}/credit/settle`, {
      session_id: sessionId,
      wallet_address: walletAddress,
      final_balance: 0, // L2 tracks this internally
      pnl,
      l2_public_key: L2_PUBLIC_KEY,
      signature,
      timestamp
    });

    if (!response.data.success) {
      throw new Error(response.data.error);
    }

    console.log(`Settlement complete: L1 balance now ${response.data.l1_balance_after}`);
  }

  async checkBalance(walletAddress: string): Promise<number> {
    const response = await axios.get(`${L1_URL}/credit/balance/${walletAddress}`);
    return response.data.l1_balance;
  }

  private sign(message: string): string {
    // Implement Ed25519 signing with L2 private key
    // See "Signature Generation" section above
    return '...';
  }
}
```

---

## Zero-Sum Invariant

**CRITICAL**: The system maintains a zero-sum invariant:

```
Total L1 Supply = Treasury + Sum(All User Balances) + Dealer Balance
```

- When user wins: Dealer balance decreases, user balance increases
- When user loses: User balance decreases, dealer balance increases
- **No tokens are created or destroyed** during settlement

---

## Error Handling

| Error | Cause | L2 Action |
|-------|-------|-----------|
| `Insufficient balance` | User doesn't have enough L1 tokens | Reject credit request, prompt deposit |
| `User already has active credit session` | User has open session | Use existing session or settle first |
| `Session not found` | Invalid session_id | Check session tracking |
| `Dealer insufficient balance` | Dealer undercapitalized | Alert admin, pause new sessions |

---

## Testing

Use test accounts:
```
Alice: L1_52882D768C0F3E7932AAD1813CF8B19058D507A8
Bob:   L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433
```

Test flow:
1. Check Alice's balance: `GET /credit/balance/L1_52882D...`
2. Open credit: `POST /credit/open` with amount 1000
3. Check status: `GET /credit/status/L1_52882D...`
4. Settle with profit: `POST /credit/settle` with pnl: 500
5. Verify L1 balance increased by 500
