# Unified Wallet Integration: Next Steps

---

## Preamble: How Wallets Work on This Chain

Before diving into the L1/L2 architecture, it's essential to understand how wallets are **created**, **initialized**, and **connected** on this blockchain. This is fundamentally different from traditional Web3 wallets.

### No MetaMask. No Seed Phrases. No External Wallets.

This chain uses a **password-derived deterministic wallet** system:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WALLET CREATION FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   USER ENTERS:                                                               │
│   ┌─────────────────┐                                                        │
│   │  Email/Username │                                                        │
│   │  Password       │                                                        │
│   └────────┬────────┘                                                        │
│            │                                                                 │
│            ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  SALT (random 32 bytes, stored in Supabase per user)            │       │
│   └────────┬────────────────────────────────────────────────────────┘       │
│            │                                                                 │
│            ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  ARGON2 KEY DERIVATION                                          │       │
│   │  password + salt → 32-byte encryption key                       │       │
│   └────────┬────────────────────────────────────────────────────────┘       │
│            │                                                                 │
│            ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  ED25519 KEYPAIR GENERATION                                     │       │
│   │  encryption_key → private_key → public_key                      │       │
│   └────────┬────────────────────────────────────────────────────────┘       │
│            │                                                                 │
│            ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  WALLET ADDRESS = first 14 chars of SHA256(public_key)          │       │
│   │  Example: ABC123DEF456GH                                         │       │
│   └────────┬────────────────────────────────────────────────────────┘       │
│            │                                                                 │
│            ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │  ENCRYPTED BLOB (AES-256-GCM)                                   │       │
│   │  Contains: { private_key, public_key, wallet_address }          │       │
│   │  Encrypted with: encryption_key (derived from password)         │       │
│   │  Stored in: Supabase (user never sees raw private key)          │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Insight: Same Password = Same Wallet

Because the wallet is **deterministically derived** from `password + salt`:

- User can "recover" wallet by entering same password (salt retrieved from Supabase)
- No seed phrase to lose
- No private key export (it's always derived on-demand)
- Password change = new salt = new wallet (migration required)

### What Gets Stored Where

| Component | Stored In | Encrypted? |
|-----------|-----------|------------|
| Salt | Supabase (public per user) | No |
| Encrypted Blob | Supabase | Yes (AES-256-GCM) |
| Public Key | Supabase + Blockchain | No |
| Private Key | **NOWHERE** - derived on demand | N/A |
| Wallet Address | Supabase + Blockchain | No |

### Authentication: Signature-Based (No JWT!)

Every API request is authenticated via **Ed25519 signature**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    EVERY API REQUEST                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CLIENT SIDE:                                                               │
│   1. User enters password                                                    │
│   2. Fetch salt from Supabase                                                │
│   3. Derive encryption_key = Argon2(password, salt)                          │
│   4. Decrypt blob → get private_key                                          │
│   5. Create payload: { action, data, timestamp, nonce }                      │
│   6. Sign payload with private_key                                           │
│   7. Send: { payload, signature, public_key }                                │
│                                                                              │
│   SERVER SIDE (Layer1):                                                      │
│   1. Verify signature matches public_key                                     │
│   2. Check timestamp within 5 minutes (replay protection)                    │
│   3. Check nonce not reused (LRU cache)                                      │
│   4. Derive wallet_address from public_key                                   │
│   5. Execute action with wallet_address as authenticated identity            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Wallet Initialization: First-Time Setup

When a new user creates an account:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NEW USER SIGNUP                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. USER: Enters email + password                                           │
│                                                                              │
│   2. FRONTEND:                                                               │
│      - Generate random salt (32 bytes)                                       │
│      - Derive keys from password + salt                                      │
│      - Generate Ed25519 keypair                                              │
│      - Create encrypted blob                                                 │
│      - Compute wallet address                                                │
│                                                                              │
│   3. SUPABASE:                                                               │
│      - Store: { email, salt, encrypted_blob, public_key, wallet_address }   │
│                                                                              │
│   4. LAYER1 (via signed request):                                            │
│      - Register wallet_address on blockchain                                 │
│      - Initialize L1 account (balance = 0)                                   │
│      - Initialize L2 account (locked = 0)                                    │
│                                                                              │
│   5. DEALER (optional):                                                      │
│      - If welcome bonus enabled:                                             │
│      - dealer_initialize_wallet(wallet_id, 10.0) // 10 BB welcome bonus     │
│      - Funds come from Dealer's L2 liquidity pool                            │
│      - Credited directly to user's L1.available                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Wallet Connection: Returning User Login

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RETURNING USER LOGIN                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. USER: Enters email + password                                           │
│                                                                              │
│   2. FRONTEND:                                                               │
│      - Fetch salt + encrypted_blob from Supabase (by email)                 │
│      - Derive encryption_key = Argon2(password, salt)                        │
│      - Decrypt blob → get private_key, public_key, wallet_address           │
│      - Store in memory (never persisted unencrypted)                         │
│                                                                              │
│   3. READY TO TRANSACT:                                                      │
│      - User can now sign requests with derived private_key                   │
│      - Wallet is "connected" (keys in memory)                                │
│      - No blockchain transaction needed for login                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Wallet Address Format

```
Base Address:     ABC123DEF456GH     (14 alphanumeric characters)
                  └──────┬─────┘
                         │
            SHA256(public_key)[0..14].toUpperCase()

With Layer Prefix:
├── L1_ABC123DEF456GH    →  Bank/Vault (source of truth)
└── L2_ABC123DEF456GH    →  Gaming Layer (active bets only)

Special Addresses:
├── L1_ALICE000000001    →  Test account Alice
├── L1_BOB0000000001     →  Test account Bob  
└── L2DEALER00000001     →  Dealer/Oracle (16 chars, L2-native)
```

### Why This Design?

| Traditional Wallet | Our Wallet |
|--------------------|------------|
| User manages seed phrase | Password-based, no seed phrase |
| Private key in browser extension | Private key derived on-demand, never stored |
| Connect wallet = sign message | Enter password = derive keys |
| Lose seed = lose funds forever | Forget password = request reset (with identity verification) |
| Multiple wallets per user | One deterministic wallet per user account |
| Gas fees for every action | Signature-based auth, no gas for reads |

### Security Model Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Layer 1: Password Strength                                                 │
│   └── Argon2 makes brute-force expensive                                    │
│                                                                              │
│   Layer 2: Salt Uniqueness                                                   │
│   └── Each user has unique salt (rainbow tables useless)                    │
│                                                                              │
│   Layer 3: Encrypted Blob                                                    │
│   └── AES-256-GCM encryption at rest                                        │
│                                                                              │
│   Layer 4: Ed25519 Signatures                                                │
│   └── Every request cryptographically signed                                │
│                                                                              │
│   Layer 5: Timestamp + Nonce                                                 │
│   └── 5-minute window, no replay attacks                                    │
│                                                                              │
│   Layer 6: Supabase RLS                                                      │
│   └── Users can only access their own data                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Connecting Wallet to Unified Storage

When the unified wallet system receives a request:

```rust
// 1. Extract wallet address from verified signature
let wallet_address = request.wallet_address; // e.g., "ABC123DEF456GH"

// 2. Parse into WalletId (byte-type for performance)
let wallet_id = WalletId::from_str(&wallet_address)?; // [u8; 14]

// 3. Access dual balance storage
let storage = wallet_storage.read().unwrap();
let balance = storage.get_dual_balance(&wallet_id);

// 4. Return both L1 and L2 views
// L1: Available funds (can bet, withdraw, transfer)
// L2: Locked funds (in active bets)
```

---

## Overview

This document outlines how L1 (Bank/Vault) and L2 (Ledger/Prediction Market) wallets integrate, and the remaining work to complete the unified wallet architecture.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         UNIFIED WALLET SYSTEM                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    L1 (Port 8080)                    L2 (Port 1234)                         │
│    ═══════════════                   ═══════════════                         │
│                                                                              │
│    ┌──────────────┐                  ┌──────────────┐                       │
│    │  BANK/VAULT  │                  │ PRED MARKET  │                       │
│    │              │   JIT Bridge     │              │                       │
│    │ L1_xxx       │ ───────────────► │ L2_xxx       │                       │
│    │ .available   │                  │ .locked      │                       │
│    │              │ ◄─────────────── │              │                       │
│    │              │  Batch Settle    │              │                       │
│    └──────────────┘                  └──────────────┘                       │
│                                             │                                │
│                                             │                                │
│                                      ┌──────▼──────┐                        │
│                                      │   DEALER    │                        │
│                                      │   (Oracle)  │                        │
│                                      │             │                        │
│                                      │ L2-NATIVE   │                        │
│                                      │ .available  │ ◄── House Liquidity    │
│                                      │ .locked     │                        │
│                                      └─────────────┘                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## What's Implemented ✅

### 1. Core Data Structures (`src/unified_wallet/`)

| File | Purpose | Status |
|------|---------|--------|
| `accounts.rs` | `WalletId` (byte-type), `L1Account`, `L2Account` | ✅ Complete |
| `dealer.rs` | `DealerAccount` with L2-native privileges | ✅ Complete |
| `jit_bridge.rs` | Atomic `L1.available → L2.locked` transfer | ✅ Complete |
| `settlement.rs` | Batch queue with flush triggers | ✅ Complete |
| `storage.rs` | `DualBalanceStorage` with dealer integration | ✅ Complete |

### 2. Key Features

- **Byte-Type Pattern**: `WalletId` stores `[u8; 14]` not `String`
- **L2 Invariant**: `L2Account` has no `available` field (structurally enforced)
- **Dealer Exception**: `DealerAccount` CAN hold `available` on L2
- **JIT Bridging**: Atomic per-bet locking
- **Settlement Batching**: Aggregates settlements before L1 sync

---

## What Needs Integration 🔧

### Phase 1: Wire Module into Main

```rust
// In src/lib.rs - add:
pub mod unified_wallet;

// In src/main_v2.rs - add:
use layer1::unified_wallet::{DualBalanceStorage, create_shared_storage};

// Create shared storage at startup:
let wallet_storage = create_shared_storage();
```

### Phase 2: Add API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/balance/dual/:address` | GET | Return L1 + L2 balances |
| `/wallet/place-bet` | POST | JIT bridge + lock |
| `/wallet/resolve-bet` | POST | Dealer settles bet |
| `/dealer/stats` | GET | Dealer P&L, liquidity |
| `/internal/batch-settle` | POST | L2 → L1 batch sync |

### Phase 3: Replace Old Balance System

The current `protocol/blockchain.rs` uses a single `balances: HashMap<String, f64>`.

**Migration Path:**
1. Keep old system running alongside new
2. Route new bets through `DualBalanceStorage`
3. Sync balances periodically
4. Deprecate old system once validated

---

## Integration Flow: Place Bet

```
┌──────────────────────────────────────────────────────────────────────────┐
│ USER clicks "Bet 100 BB on YES"                                          │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. VALIDATE                                                              │
│    storage.validate_bet(&wallet_id, 100.0)?                              │
│    └── Checks L1.available >= 100 BB                                     │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. JIT BRIDGE (Atomic)                                                   │
│    storage.place_bet(&wallet_id, 100.0, "btc_100k", "bet_001", "YES", 0.45)?│
│    └── L1.available -= 100                                               │
│    └── L2.locked += 100                                                  │
│    └── Returns lock_id                                                   │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. RECORD BET                                                            │
│    ActiveBet stored with lock_id as key                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Integration Flow: Resolve Bet (Dealer)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ MARKET RESOLVES: "BTC > 100K" = YES                                      │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. DEALER RESOLVES ALL BETS                                              │
│    storage.dealer_resolve_market("btc_100k", "YES")                      │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
┌─────────────────────────────┐   ┌─────────────────────────────┐
│ USER BET ON YES (WIN)       │   │ USER BET ON NO (LOSS)       │
├─────────────────────────────┤   ├─────────────────────────────┤
│ • L2.locked → 0 (released)  │   │ • L2.locked → 0 (forfeited) │
│ • Dealer.available -= payout│   │ • Dealer.available += stake │
│ • L1.available += payout    │   │ • L1.available unchanged    │
│ • Queue settlement (WIN)    │   │ • Queue settlement (LOSS)   │
└─────────────────────────────┘   └─────────────────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. BATCH FLUSH (on timer or threshold)                                   │
│    storage.flush_settlements()                                           │
│    └── Aggregates by wallet                                              │
│    └── POST /l1/internal/batch-settle                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Internal RPC: L2 → L1 Communication

L2 calls L1 via internal RPC on localhost:8090 (not exposed externally).

```rust
// L1 must expose these internal endpoints:

POST /internal/batch-settle
{
  "batch_id": "batch_123",
  "settlements": [
    { "wallet": "ABC123DEF456GH", "net_delta": 180000000 }, // +180 BB
    { "wallet": "XYZ789ABC123DE", "net_delta": -50000000 }  // -50 BB (rare)
  ],
  "timestamp": 1702915200
}

POST /internal/lock-tokens
{
  "wallet": "ABC123DEF456GH",
  "amount": 100000000,  // 100 BB in microtokens
  "purpose": "jit_bridge",
  "lock_id": 12345
}

POST /internal/get-balance
{
  "wallet": "ABC123DEF456GH"
}
// Returns: { "available": 500000000, "locked": 0, "total": 500000000 }
```

---

## Dealer Initialization

At system startup, initialize dealer with liquidity:

```rust
// In main_v2.rs
let wallet_storage = DualBalanceStorage::with_dealer_liquidity(1_000_000.0); // 1M BB

// Or add liquidity later:
wallet_storage.write().unwrap().dealer_add_liquidity(500_000.0);
```

---

## Security Checklist

| Check | Status |
|-------|--------|
| Dealer private key NEVER in code | ✅ Env var only |
| Dealer operations require signature verification | 🔧 TODO |
| L2 invariant structurally enforced | ✅ No `available` field |
| JIT bridge is atomic | ✅ Single function |
| Settlement batching prevents L1 overload | ✅ Queue + flush |
| Nonce replay protection | ✅ Existing system |

---

## File Structure After Integration

```
src/
├── unified_wallet/
│   ├── mod.rs              # Module exports
│   ├── accounts.rs         # WalletId, L1Account, L2Account
│   ├── dealer.rs           # DealerAccount (L2-native oracle)
│   ├── jit_bridge.rs       # Atomic L1→L2 transfer
│   ├── settlement.rs       # Batch queue + flush
│   └── storage.rs          # DualBalanceStorage
├── routes_v2/
│   ├── wallet.rs           # User wallet endpoints (update)
│   ├── markets.rs          # Market + betting endpoints (update)
│   └── internal.rs         # NEW: Internal L2→L1 RPC
└── main_v2.rs              # Wire up storage
```

---

## Testing Plan

### Unit Tests (Already in place)
- `accounts.rs`: WalletId parsing, L2 invariant
- `jit_bridge.rs`: Atomic transfer, insufficient balance
- `settlement.rs`: Queue, aggregation, flush triggers
- `storage.rs`: Full flow, dealer operations

### Integration Tests (TODO)
```rust
#[test]
fn test_full_bet_lifecycle() {
    // 1. Create storage with dealer liquidity
    // 2. Initialize user wallet via dealer
    // 3. User places bet (JIT bridge)
    // 4. Market resolves (dealer settles)
    // 5. Verify balances
    // 6. Flush settlements
}
```

---

## Estimated Work Remaining

| Task | Effort | Priority |
|------|--------|----------|
| Wire module into lib.rs/main_v2.rs | 1 hour | HIGH |
| Add /balance/dual endpoint | 2 hours | HIGH |
| Update /markets/place-bet to use JIT | 4 hours | HIGH |
| Add dealer signature verification | 2 hours | HIGH |
| Add internal RPC endpoints | 4 hours | MEDIUM |
| Migration script for old balances | 4 hours | MEDIUM |
| Integration tests | 4 hours | MEDIUM |
| Documentation + API spec | 2 hours | LOW |

**Total: ~23 hours**

---

## Quick Start: Test the Module

```rust
use layer1::unified_wallet::*;

fn main() {
    // Create storage with 1M dealer liquidity
    let mut storage = DualBalanceStorage::with_dealer_liquidity(1_000_000.0);
    
    // Initialize new user wallet with 100 BB welcome bonus
    let wallet = WalletId::from_str("ABC123DEF456GH").unwrap();
    storage.dealer_initialize_wallet(&wallet, 100.0).unwrap();
    
    // User places bet
    let bet = storage.place_bet(
        &wallet,
        50.0,
        "btc_100k",
        "bet_001",
        "YES",
        0.45,
    ).unwrap();
    
    println!("Bet placed! Lock ID: {}", bet.lock_id);
    
    // Check balances
    let balance = storage.get_dual_balance(&wallet);
    println!("L1 available: {} BB", balance.l1_available_bb());
    println!("L2 locked: {} BB", balance.l2_locked_bb());
    
    // Resolve market (user wins)
    let (result, dealer_settlement) = storage.dealer_resolve_bet(
        bet.lock_id,
        "YES",
    ).unwrap();
    
    println!("Won: {} | Payout: {} BB", result.won, result.amount_credited as f64 / 1_000_000.0);
    
    // Final balances
    let final_balance = storage.get_dual_balance(&wallet);
    println!("Final L1 available: {} BB", final_balance.l1_available_bb());
    
    // Dealer stats
    let stats = storage.stats();
    println!("Dealer P&L: {} BB", stats.dealer_profit_loss_bb());
}
```

---

## Summary

The unified wallet architecture provides:

1. **Clear Separation**: L1 (real money) vs L2 (active bets)
2. **L2 Invariant**: Users never have "trapped" funds
3. **Dealer Exception**: House can operate instantly on L2
4. **JIT Bridging**: Funds move only when needed, exact amounts
5. **Batch Settlement**: Protects L1 from overload
6. **Byte-Type Storage**: Performance optimization

Next immediate step: Wire the module into `lib.rs` and add the `/balance/dual` endpoint.
