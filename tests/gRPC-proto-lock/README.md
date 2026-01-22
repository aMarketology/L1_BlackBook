# 🔗 BLACKBOOK L1-L2 gRPC/PROTO LOCK TESTS

This test suite validates the **Layer 1 ↔ Layer 2 token locking integration** using gRPC and Protocol Buffers.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     LAYER 1 (L1)                            │
│  - Rust-based blockchain (Axum + ReDB)                     │
│  - Holds actual token balances                              │
│  - Exposes gRPC server for L2 communication                 │
│  - Locks tokens when L2 session opens                       │
│  - Releases tokens when L2 session settles                  │
└─────────────────┬───────────────────────────┬───────────────┘
                  │                           │
                  │ gRPC + Protobuf           │
                  │ (settlement.proto)        │
                  │                           │
┌─────────────────▼───────────────────────────▼───────────────┐
│                     LAYER 2 (L2)                            │
│  - Credit-based gaming layer                                │
│  - Fast, off-chain transactions                             │
│  - Queries L1 for available balance via gRPC                │
│  - Notifies L1 of session results                           │
└─────────────────────────────────────────────────────────────┘
```

## Token Locking Flow

### 1. Session Open (Lock)
```
L2 → gRPC → L1: LockTokensRequest(wallet, amount, session_id)
L1: Verify balance
L1: Deduct from available balance
L1: Store locked_amount in session table
L1 → gRPC → L2: LockTokensResponse(success, new_balance)
```

### 2. Session Settle (Unlock)
```
L2 → gRPC → L1: SettleSessionRequest(session_id, pnl)
L1: Retrieve locked_amount
L1: Calculate return = locked_amount + pnl
L1: Credit wallet with return amount
L1: Mark session as settled
L1 → gRPC → L2: SettleSessionResponse(success, final_balance)
```

## Protocol Buffers (settlement.proto)

### Key Messages:
- `LockTokensRequest` - Request to lock tokens for L2 session
- `LockTokensResponse` - Confirmation with updated balance
- `SettleSessionRequest` - Request to settle and unlock tokens
- `SettleSessionResponse` - Final balance after settlement
- `QueryBalanceRequest` - L2 queries available L1 balance
- `QueryBalanceResponse` - Returns available + locked amounts

## Test Coverage

### ✅ Basic Lock/Unlock Tests
- `01-basic-lock-unlock.test.js` - Happy path token locking
- `02-concurrent-locks.test.js` - Multiple simultaneous lock attempts
- `03-lock-exceed-balance.test.js` - Insufficient balance scenarios

### ✅ Settlement Tests
- `04-positive-pnl-settlement.test.js` - Win scenarios (+credits)
- `05-negative-pnl-settlement.test.js` - Loss scenarios (-credits)
- `06-zero-pnl-settlement.test.js` - Break-even scenarios

### ✅ Edge Cases & Security
- `07-double-lock-prevention.test.js` - Prevent locking twice
- `08-settle-non-existent-session.test.js` - Invalid session IDs
- `09-grpc-timeout-handling.test.js` - Network failures
- `10-proto-message-validation.test.js` - Malformed messages

### ✅ Integration Tests
- `11-end-to-end-game-session.test.js` - Full game flow
- `12-session-expiry.test.js` - Timeout handling
- `13-balance-consistency.test.js` - State consistency checks

## Running Tests

```bash
# Install dependencies
npm install

# Run all gRPC/proto tests
npm test

# Run specific test
node 01-basic-lock-unlock.test.js

# Run with verbose gRPC logging
GRPC_TRACE=all node 01-basic-lock-unlock.test.js
```

## Prerequisites

1. **L1 Server Running**: Start the L1 blockchain server
   ```bash
   cargo run --features unsafe_admin
   ```

2. **gRPC Server Enabled**: Ensure L1 is listening on gRPC port (default: 50051)

3. **Proto Definitions**: Compiled from `proto/settlement.proto`

## Expected Behavior

### ✅ Secure System:
- Only one active session per wallet
- Locked tokens cannot be transferred
- Settlements must match locked amounts
- All state changes are atomic
- gRPC errors are handled gracefully

### ❌ Vulnerable System:
- Multiple concurrent locks succeed
- Locked tokens can be withdrawn
- Settlements create/destroy tokens
- Race conditions cause inconsistency

## Protocol Buffer Schema

From `proto/settlement.proto`:

```protobuf
service L1Settlement {
  rpc LockTokens(LockTokensRequest) returns (LockTokensResponse);
  rpc SettleSession(SettleSessionRequest) returns (SettleSessionResponse);
  rpc QueryBalance(QueryBalanceRequest) returns (QueryBalanceResponse);
}

message LockTokensRequest {
  string wallet_address = 1;
  double amount = 2;
  string session_id = 3;
}

message SettleSessionRequest {
  string session_id = 1;
  double pnl = 2;  // Profit/Loss from L2 session
}
```

## Critical Invariants

These must ALWAYS hold true:

1. **Conservation of Supply**: `total_supply = Σ(available) + Σ(locked)`
2. **Session Uniqueness**: One active session per wallet maximum
3. **Atomic Locking**: Lock operation is all-or-nothing
4. **PNL Bounds**: `-locked_amount ≤ pnl ≤ +∞`
5. **Balance Non-Negative**: `available_balance ≥ 0` always

## Troubleshooting

### gRPC Connection Failed
- Check L1 server is running on correct port
- Verify firewall settings
- Check proto definitions match server implementation

### Lock Fails Despite Balance
- Check for existing active session
- Verify wallet address format
- Check session ID uniqueness

### Settlement Fails
- Verify session exists and is active
- Check PNL calculation (loss cannot exceed locked amount)
- Ensure session hasn't already been settled

## Security Considerations

⚠️ **CRITICAL**: These tests verify that:
- Tokens cannot be double-locked
- Locked tokens are truly unavailable for transfers
- Settlements cannot create tokens from thin air
- gRPC authentication/authorization is enforced
- Malformed proto messages are rejected
