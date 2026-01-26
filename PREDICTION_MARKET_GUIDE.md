# BlackBook Prediction Market - Token Lock Guide

> **Documentation for BB token locking for prediction market trading**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Token Economics](#token-economics)
3. [Lock Flow (For Market Sessions)](#lock-flow-for-market-sessions)
4. [Settlement Flow (Market Resolution)](#settlement-flow-market-resolution)
5. [Security Guarantees](#security-guarantees)
6. [API Reference](#api-reference)
7. [Testing](#testing)

---

## Architecture Overview

### Simplified Single-Token Architecture

BlackBook uses a **single token (BB)** for all operations. There is no separate L2 token.

```
┌──────────────────────────────────────────────────────────────────┐
│                   BLACKBOOK ARCHITECTURE                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      L1 BLOCKCHAIN                          ││
│  │                                                             ││
│  │  • BB Token (USDC-backed)                                   ││
│  │  • Token Locking for Markets                                ││
│  │  • Settlement & P&L                                         ││
│  │  • Full Audit Trail                                         ││
│  │                                                             ││
│  │  localhost:8080                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                     Token Lock/Unlock                            │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   PREDICTION MARKETS                        ││
│  │                                                             ││
│  │  • Uses locked BB tokens directly                           ││
│  │  • CPMM pricing                                             ││
│  │  • LP pools                                                 ││
│  │  • Oracle resolution                                        ││
│  │                                                             ││
│  │  localhost:1234                                             ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Principle: Single Token, No Bridge

- **Before**: Users had to "bridge" tokens from L1 to L2
- **Now**: Users lock their L1 $BB tokens directly for market sessions
- No token conversion, no bridging complexity

---

## Token Economics

| Token | Symbol | Purpose | Backing |
|-------|--------|---------|---------|
| BlackBook | **$BB** | All operations (transfers, betting, liquidity) | 1:1 USDC backed |

**Key Points**:
- Single token for everything
- 1:1 USDC backing means every BB is worth exactly $1
- Locking reserves tokens for market trading (prevents double-spending)
- Settlement releases tokens back with P&L applied

---

## Lock Flow (For Market Sessions)

When users want to trade on prediction markets, they lock BB tokens.

### Step-by-Step Flow

```
USER WANTS TO TRADE
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 1: Lock BB Tokens                              │
├─────────────────────────────────────────────────────┤
│  POST http://localhost:8080/credit/open             │
│                                                     │
│  Request:                                           │
│  {                                                  │
│    "wallet": "L1_USER_ADDRESS",                     │
│    "amount": 1000                                   │
│  }                                                  │
│                                                     │
│  L1 Action:                                         │
│    ✅ Check user has 1000 BB                        │
│    ✅ Debit 1000 BB (move to escrow)               │
│    ✅ Create market session                         │
│    ✅ Generate session_id                           │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "success": true,                                 │
│    "session_id": "uuid-session-id",                 │
│    "locked_amount": 1000.0,                         │
│    "available_balance": 1000.0,                     │
│    "l1_balance_after_lock": 9000.0,                 │
│    "expires_at": "2026-01-26T00:00:00Z"             │
│  }                                                  │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 2: Trade on Prediction Markets                │
├─────────────────────────────────────────────────────┤
│  User places bets using their locked balance        │
│                                                     │
│  • Buy outcome shares                               │
│  • Sell outcome shares                              │
│  • Provide liquidity                                │
│                                                     │
│  All tracked against locked_amount                  │
└─────────────────────────────────────────────────────┘
```

---

## Settlement Flow (Market Resolution)

When markets resolve or user wants to exit, tokens are settled.

```
MARKET RESOLVES / USER EXITS
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ POST http://localhost:8080/credit/settle            │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Request:                                           │
│  {                                                  │
│    "session_id": "uuid-session-id",                 │
│    "net_pnl": 250.0  // User won $250              │
│  }                                                  │
│                                                     │
│  L1 Action:                                         │
│    ✅ Find session by ID                            │
│    ✅ Calculate: final = locked_amount + net_pnl    │
│    ✅ Credit final amount to user                   │
│    ✅ Close session                                 │
│                                                     │
│  Response:                                          │
│  {                                                  │
│    "success": true,                                 │
│    "session_id": "uuid-session-id",                 │
│    "locked_amount": 1000.0,                         │
│    "net_pnl": 250.0,                                │
│    "amount_returned": 1250.0,                       │
│    "l1_balance_after_settle": 10250.0               │
│  }                                                  │
└─────────────────────────────────────────────────────┘
```

### P&L Scenarios

| Scenario | Locked | Net P&L | Returned | Final Balance |
|----------|--------|---------|----------|---------------|
| Won $250 | 1000 | +250 | 1250 | 10,250 |
| Lost $300 | 1000 | -300 | 700 | 9,700 |
| Break even | 1000 | 0 | 1000 | 10,000 |
| Lost all | 1000 | -1000 | 0 | 9,000 |

---

## Security Guarantees

### 1. No Double Spending
Locked tokens are debited from user's balance immediately. They cannot spend the same tokens twice.

### 2. Solvency
Total locked tokens are always backed by actual BB in escrow.

### 3. Audit Trail
Every lock and settlement is recorded as a transaction with metadata.

### 4. Session Isolation
Each user has at most one active session at a time.

---

## API Reference

### Lock Tokens (Open Session)

```http
POST /credit/open
Content-Type: application/json

{
  "wallet": "L1_ADDRESS",
  "amount": 1000.0
}
```

**Response:**
```json
{
  "success": true,
  "session_id": "uuid",
  "wallet": "L1_ADDRESS",
  "locked_amount": 1000.0,
  "available_balance": 1000.0,
  "l1_balance_after_lock": 9000.0,
  "expires_at": "2026-01-26T00:00:00Z"
}
```

### Check Session Status

```http
GET /credit/status/{wallet_address}
```

**Response:**
```json
{
  "wallet": "L1_ADDRESS",
  "l1_balance": 9000.0,
  "has_active_session": true,
  "session": {
    "id": "uuid",
    "locked_amount": 1000.0,
    "available_balance": 1000.0,
    "expires_at": "2026-01-26T00:00:00Z"
  }
}
```

### Settle Session

```http
POST /credit/settle
Content-Type: application/json

{
  "session_id": "uuid",
  "net_pnl": 250.0
}
```

**Response:**
```json
{
  "success": true,
  "session_id": "uuid",
  "locked_amount": 1000.0,
  "net_pnl": 250.0,
  "amount_returned": 1250.0,
  "l1_balance_after_settle": 10250.0,
  "settled_at": "2026-01-25T12:00:00Z"
}
```

---

## Testing

### Quick Test

```bash
# 1. Check balance
curl http://localhost:8080/balance/L1_TEST_ADDRESS

# 2. Lock tokens for trading
curl -X POST http://localhost:8080/credit/open \
  -H "Content-Type: application/json" \
  -d '{"wallet": "L1_TEST_ADDRESS", "amount": 100}'

# 3. Check session status
curl http://localhost:8080/credit/status/L1_TEST_ADDRESS

# 4. Settle with profit
curl -X POST http://localhost:8080/credit/settle \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID", "net_pnl": 25}'

# 5. Verify final balance
curl http://localhost:8080/balance/L1_TEST_ADDRESS
```

---

## Migration from Old Bridge System

If you're migrating from the old L1↔L2 bridge system:

1. **Remove L2 address handling** - Only L1 addresses needed
2. **Replace bridge calls with lock/settle** - Use `/credit/open` and `/credit/settle`
3. **Remove token conversion logic** - BB is the only token
4. **Update SDKs** - Use new `MarketSession` types instead of `CreditSession`

### Backwards Compatibility

The old endpoints and type aliases are maintained for backwards compatibility:
- `CreditSession` → `MarketSession` (alias)
- `BridgeLock` → `TokenLock` (alias)
- `open_credit_session()` → `open_market_session()` (calls through)
- `settle_credit_session()` → `settle_market_session()` (calls through)
