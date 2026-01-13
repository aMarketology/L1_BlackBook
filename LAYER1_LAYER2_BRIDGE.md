# Layer 1 ↔ Layer 2 Bridge Architecture

> **BlackBook Prediction Market - Token Bridge & Oracle System**

## Overview

The BlackBook prediction market operates as a **Layer 2 (L2)** gaming chain that settles to a **Layer 1 (L1)** bank/consensus chain. This architecture provides:

- **Fast betting** on L2 (instant trades, no gas fees)
- **Secure settlement** on L1 (funds backed by L1 locks)
- **Oracle authority** (DEALER/ORACLE account with special privileges)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BLACKBOOK ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐                    ┌─────────────────────┐        │
│  │    LAYER 1 ($BC)    │                    │    LAYER 2 ($BB)    │        │
│  │   Bank/Consensus    │                    │   Prediction Market │        │
│  │                     │                    │                     │        │
│  │  • Real money       │  ═══ BRIDGE ═══>   │  • Fast bets        │        │
│  │  • Final settlement │  <═══════════════  │  • CPMM pricing     │        │
│  │  • Lock/unlock      │                    │  • LP pools         │        │
│  │  • Credit lines     │                    │  • Oracle resolution│        │
│  │                     │                    │                     │        │
│  │  Port: 8080         │                    │  Port: 1234         │        │
│  └─────────────────────┘                    └─────────────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Token Economics

| Layer | Token | Purpose | Backing |
|-------|-------|---------|---------|
| **L1** | **$BC** (BlackCoin) | Settlement, credit lines | Native asset |
| **L2** | **$BB** (BlackBook) | Betting, liquidity | 1:1 backed by locked $BC |

**Key Invariant**: Every $BB on L2 is backed by locked $BC on L1. L2 cannot mint tokens.

---

## Address System

Addresses use the same base hash with different prefixes to indicate fund location:

```
L1_542AB3537F3ACB2D6E4597DAF41615F148B9F8410A390EF73970806FEC6ED26F  ← Funds on L1
L2_542AB3537F3ACB2D6E4597DAF41615F148B9F8410A390EF73970806FEC6ED26F  ← Funds on L2
```

This allows seamless tracking of the same user across both layers.

---

## Deposit Flow: L1 → L2

Users lock $BC on L1 to receive $BB on L2 for betting.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           L1 → L2 DEPOSIT FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USER                        L1 BANK                       L2 MARKET        │
│    │                           │                              │             │
│    │  1. InitiateBridgeLock()  │                              │             │
│    │  ─────────────────────>   │                              │             │
│    │     amount: 1000 $BC      │                              │             │
│    │                           │                              │             │
│    │  2. {lock_id, status}     │                              │             │
│    │  <─────────────────────   │                              │             │
│    │     L1 debits user        │                              │             │
│    │                           │                              │             │
│    │                           │  3. POST /bridge/credit      │             │
│    │                           │  ─────────────────────────>  │             │
│    │                           │     signed by L1 node        │             │
│    │                           │                              │             │
│    │                           │  4. L2 verifies signature    │             │
│    │                           │     credits user 1000 $BB    │             │
│    │                           │  <─────────────────────────  │             │
│    │                           │                              │             │
│    │  5. User can now bet on L2 with 1000 $BB                 │             │
│    │                                                          │             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Bridge Credit Verification

L2 verifies that L1 actually locked the funds by checking L1's signature:

```rust
// Message format L1 signs:
"BRIDGE_LOCK:{user_address}:{amount}:{lock_id}"

// L2 verifies with L1's public key before crediting
```

**Testing Note:** L2 bridge credit endpoint can be tested independently without L1 server running. The Ed25519 signature verification is fully functional, allowing L2-only testing of the credit mechanism. Full L1↔L2 flow requires L1 server for token locking.

### Endpoints

| Endpoint | Layer | Purpose |
|----------|-------|---------|
| `POST /bridge/lock` | L1 | Lock $BC, get lock_id |
| `POST /bridge/credit` | L2 | Credit $BB after L1 lock verified |
| `GET /bridge/lock/:id` | L2 | Check lock status |

---

## Withdrawal Flow: L2 → L1

Users withdraw $BB from L2 back to $BC on L1.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          L2 → L1 WITHDRAWAL FLOW                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USER                       L2 MARKET                       L1 BANK         │
│    │                           │                              │             │
│    │  1. POST /withdraw        │                              │             │
│    │  ─────────────────────>   │                              │             │
│    │     amount: 500 $BB       │                              │             │
│    │     dest: L1_xxx          │                              │             │
│    │                           │                              │             │
│    │  2. L2 debits balance     │                              │             │
│    │     creates Withdrawal    │                              │             │
│    │     status: Pending       │                              │             │
│    │  <─────────────────────   │                              │             │
│    │                           │                              │             │
│    │                           │  3. Sequencer batches        │             │
│    │                           │     (every ~5 min)           │             │
│    │                           │     status: Included         │             │
│    │                           │                              │             │
│    │                           │  4. POST settlement proof    │             │
│    │                           │  ─────────────────────────>  │             │
│    │                           │     merkle proof included    │             │
│    │                           │                              │             │
│    │                           │  5. L1 verifies proof        │             │
│    │                           │     releases 500 $BC         │             │
│    │  <────────────────────────────────────────────────────   │             │
│    │     status: Claimed                                      │             │
│    │                                                          │             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Withdrawal Status

```rust
enum WithdrawalStatus {
    Pending,   // User requested, not yet batched
    Included,  // In sequencer batch, has merkle proof
    Claimed,   // Funds released on L1
}
```

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /withdraw` | Signature-authenticated withdrawal |
| `POST /withdraw/session` | Session-authenticated withdrawal |
| `GET /withdrawal/:id` | Check withdrawal status |
| `GET /withdrawals/:user` | List user's withdrawals |

---

## JIT (Just-In-Time) Bridging

For a seamless UX, users can bet **directly from L1 funds** without a separate bridge transaction:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JIT BRIDGING (AUTO-BRIDGE)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Traditional Flow:                                                          │
│    1. User bridges L1 → L2  (separate transaction)                          │
│    2. User places bet       (separate transaction)                          │
│                                                                             │
│  JIT Flow:                                                                  │
│    1. User signs bet request with L1 funds                                  │
│    2. L2 atomically: bridges L1→L2 + places bet (single transaction!)       │
│                                                                             │
│  Balance Changes:                                                           │
│    Before:  L1.available = 1000,  L2.locked = 0                             │
│    After:   L1.available = 900,   L2.locked = 100 (in bet)                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Rule**: Regular users' `L2.available` is always 0. All betting flows through `L1.available → L2.locked`.

---

## 🔮 ORACLE/DEALER Account

The **ORACLE** (also called **DEALER**) is a special account with elevated privileges for operating the prediction market.

### ORACLE Identity

```rust
// layer_2/ledger_v2.rs
const ORACLE: &str = "L2_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC";
const ORACLE_FEE: f64 = 0.01;  // 1% fee on winning payouts
```

The ORACLE address is derived from the ORACLE private key (stored in `.env` as `ORACLE_PRIVATE_KEY`).

### ORACLE Special Privileges

| Privilege | Description | Regular Users |
|-----------|-------------|---------------|
| **Market Resolution** | Can resolve ANY market | Only markets they proposed |
| **Skip JIT Bridge** | Uses direct L2 balance | Must use L1→L2 JIT bridge |
| **Fee Collection** | Receives 1% of all payouts | N/A |
| **Dispute Panel** | Initial member with 1.0 reputation | Must earn reputation |
| **Multi-Sig Pool** | Initial member for high-value markets | Must be promoted |
| **Credit Lines** | Can request L1 credit for liquidity | N/A |

### Resolution Authority Check

```rust
// Who can resolve a market?
let is_oracle = user == ORACLE;                                    // ✅ Always
let is_proposer = market.proposer == Some(user);                   // ✅ If they created it
let is_authorized = market.authorized_resolvers.contains(&user);   // ✅ If explicitly added

if !is_oracle && !is_proposer && !is_authorized {
    return Err("Not authorized to resolve this market");
}
```

### ORACLE Balance Behavior

Unlike regular users, ORACLE:
- Does **NOT** use JIT bridging (already has L2 funds)
- Payouts stay on L2 (no settlement queue entry)
- Can directly fund markets from L2 balance

```rust
// Regular user payout → Settlement queue (eventual L1 withdrawal)
// ORACLE payout → Direct L2 credit (stays on L2 for more market making)
```

---

## Oracle Registry & Reputation

The system tracks oracle reputation for trust scoring:

```rust
struct OracleRegistry {
    oracles: HashMap<String, OracleInfo>,
    whitelist: HashSet<String>,        // Active oracles
    multi_sig_pool: Vec<String>,       // High-trust oracles for multi-sig
}

struct OracleInfo {
    address: String,
    reputation: f64,         // 0.0 to 1.0 (ORACLE starts at 1.0)
    resolutions: u64,        // Total markets resolved
    disputes_against: u64,   // Times disputed
    disputes_lost: u64,      // Disputes where oracle was wrong
    is_admin: bool,          // ORACLE = true
}
```

### Reputation Rules

| Event | Reputation Impact |
|-------|-------------------|
| Successful resolution | +0.01 (up to 1.0) |
| Dispute lost | -0.1 |
| >95% accuracy after 20 resolutions | Promoted to multi-sig pool |
| >10% dispute rate | Demoted from whitelist |

---

## Multi-Sig Resolution

High-value markets require multiple oracles to agree:

```rust
struct MultiSigConfig {
    threshold: u64,           // Number of signatures required (default: 3)
    high_value_threshold: f64, // 100,000 BB triggers multi-sig
    multi_sig_pool: Vec<String>,
    pending_signatures: HashMap<String, Vec<SignatureRecord>>,
}
```

### Flow for High-Value Markets

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MULTI-SIG RESOLUTION (TVL > 100k BB)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Market TVL: 150,000 BB (requires 3 signatures)                             │
│                                                                             │
│  Oracle A: Signs "outcome: YES"  ──────────────────> 1/3 signatures         │
│  Oracle B: Signs "outcome: YES"  ──────────────────> 2/3 signatures         │
│  Oracle C: Signs "outcome: YES"  ──────────────────> 3/3 ✅ RESOLVED        │
│                                                                             │
│  If Oracle C signs "outcome: NO":                                           │
│    → Dispute triggered, panel votes                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Insurance Fund

Protects users against oracle misbehavior and voided markets:

```rust
struct InsuranceFund {
    balance: f64,              // Current fund balance
    protocol_fee_rate: f64,    // 0.5% of all volume goes to fund
    claims: Vec<InsuranceClaim>,
}
```

### Funding Sources
- 0.5% protocol fee on all trades
- ORACLE deposits (market maker profits)
- Slashed stake from bad oracles

### Claim Triggers
- Market voided after bets placed
- Oracle proven to resolve incorrectly
- Dispute panel rules against resolution

---

## Test Accounts

The following test accounts are used for bridge testing:

| Account | L2 Address | Current L2 Balance | L1 Balance |
|---------|-----------|-------------------|------------|
| **Alice** | `L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD` | 9065.30 $BB | 20000 $BC |
| **Bob** | `L2_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9` | 8625.42 $BB | 10000 $BC |

*Note: L2 balances include test bridge transactions. L1 balances remain unchanged as L1 server is currently offline.*

---

## Protocol Constants

```rust
// Bridge
BRIDGE_TIMEOUT_SECS: u64 = 300;        // 5 minutes
MIN_BRIDGE_AMOUNT: f64 = 0.01;
MAX_BRIDGE_AMOUNT: f64 = 1_000_000.0;

// Market Liquidity Tiers
FRIEND_BET_MIN: f64 = 10.0;            // Private (2-5 people)
COMMUNITY_MIN: f64 = 100.0;            // Community events
GLOBAL_MIN: f64 = 1000.0;              // Public markets
VIABILITY_THRESHOLD: f64 = 10000.0;    // Pass probation
HIGH_VALUE_THRESHOLD: f64 = 100000.0;  // Requires multi-sig

// Fees
ORACLE_FEE: f64 = 0.01;                // 1% on payouts → ORACLE
PROTOCOL_FEE_RATE: f64 = 0.005;        // 0.5% → Insurance fund
DISPUTE_STAKE: f64 = 100.0;            // BB to file dispute
```

---

## Implementation Status

### ✅ Implemented

| Component | Location | Status |
|-----------|----------|--------|
| Bridge credit endpoint | `layer_2/ledger_v2.rs` | ✅ **Tested & Verified** |
| Ed25519 signature verification | `layer_2/ledger_v2.rs` | ✅ **Tested & Verified** |
| Withdrawal flow | `layer_2/ledger_v2.rs` | ✅ Working |
| JIT bridging | `layer_2/handlers.rs` | ✅ Working |
| ORACLE resolution | `layer_2/handlers.rs` | ✅ Working |
| Oracle registry | `layer_2/models.rs` | ✅ Defined |
| Multi-sig config | `layer_2/models.rs` | ✅ Defined |
| Insurance fund | `layer_2/models.rs` | ✅ Defined |
| Session auth | `layer_2/auth.rs` | ✅ Working |
| Market creation | `layer_2/ledger_v2.rs` | ✅ Working |
| CPMM pricing | `layer_2/market_resolve/cpmm.rs` | ✅ Working |

### ⚠️ Needs Implementation

| Component | Issue | Priority |
|-----------|-------|----------|
| L1 server | Not running (port 8080) - L2 bridge credit working independently | Low |
| L1 lock verification | L2 credits work, but L1 lock side not active | Medium |
| Settlement batch processor | Batches created but not submitted to L1 | High |
| Multi-sig enforcement | Config exists but not enforced in resolve | Medium |
| Dispute endpoints | Panel exists but no API endpoints | Medium |
| Automatic bridge timeout refund | Timeout detected but no refund | Low |
| L1 callback for deposits | L2 stores locks but doesn't get L1 confirmation | High |

### 🔄 Next Steps

1. **Implement L1 server** or mock for local testing
2. **Add settlement batch submission** to L1
3. **Wire multi-sig checks** into resolution flow
4. **Add dispute API endpoints** (`/dispute/file`, `/dispute/vote`)
5. **Create admin dashboard** for ORACLE operations

---

## Testing the Bridge

### Verified Test Results (January 2026)

**Bridge Test: Alice & Bob - 99 $BC → 99 $BB**

✅ **Alice Bridge Transaction**
- Amount: 99 $BC → 99 $BB (1:1 ratio)
- Before: 8966.30 $BB | After: 9065.30 $BB
- Lock ID: `lock_1768165617_alice`
- Signature: Verified ✓
- Status: Success

✅ **Bob Bridge Transaction**
- Amount: 99 $BC → 99 $BB (1:1 ratio)
- Before: 8526.42 $BB | After: 8625.42 $BB
- Lock ID: `lock_1768165617_bob`
- Signature: Verified ✓
- Status: Success

**Key Findings:**
- Ed25519 signature verification working correctly
- Message format verified: `BRIDGE_LOCK:{address}:{amount}:{lock_id}`
- 1:1 token ratio maintained ($BC to $BB)
- Idempotency working (unique lock_ids prevent double-spend)
- L2 credits exact amounts with no slippage

### 1. Credit a user (simulates L1→L2 deposit)
```bash
curl -X POST http://localhost:1234/bridge/credit \
  -H "Content-Type: application/json" \
  -d '{
    "user_address": "L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
    "amount": 99.0,
    "lock_id": "lock_1768165617_alice",
    "l1_signature": "be5bdac9925cd420308cc0a95807694d918efb55...",
    "l1_public_key": "18f2c2e3bcb7a4b5329cfed4bd79bf17...",
    "l1_tx_hash": "test_hash"
  }'
```

### 2. Check balance
```bash
curl http://localhost:1234/balance/L2_YOUR_ADDRESS
```

### 3. Withdraw to L1
```bash
curl -X POST http://localhost:1234/withdraw/session \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: YOUR_TOKEN" \
  -d '{
    "destination": "L1_YOUR_ADDRESS",
    "amount": 500.0
  }'
```

---

## SDK Integration

### For Regular Users
```javascript
const { Layer2SDK } = require('./integration/layer-2-sdk.js');
const sdk = new Layer2SDK({ privateKey, address });
await sdk.authenticate();
await sdk.placeBet(marketId, outcome, amount);  // Uses JIT bridge automatically
```

### For ORACLE/DEALER
```javascript
const { ORACLESDK } = require('./integration/oracle-sdk.js');
const oracle = new ORACLESDK();  // Uses ORACLE credentials from .env
await oracle.createMarket({ title, outcomes });
await oracle.addLiquidity(marketId, 10000);
await oracle.resolveMarket(marketId, winningOutcome);
```

---

## File References

| File | Purpose |
|------|---------|
| [`layer_2/ledger_v2.rs`](../layer_2/ledger_v2.rs) | Main L2 ledger, bridge endpoints, ORACLE constant |
| [`layer_2/handlers.rs`](../layer_2/handlers.rs) | HTTP handlers, JIT bridging, resolution |
| [`layer_2/models.rs`](../layer_2/models.rs) | OracleRegistry, MultiSigConfig, InsuranceFund |
| [`layer_2/auth.rs`](../layer_2/auth.rs) | Session authentication |
| [`rpc/bridge.rs`](../rpc/bridge.rs) | Bridge manager, L1Lock records |
| [`proto/settlement.proto`](../proto/settlement.proto) | gRPC definitions for L1 communication |
| [`integration/oracle-sdk.js`](../integration/oracle-sdk.js) | ORACLE SDK for frontend |
| [`integration/layer-2-sdk.js`](../integration/layer-2-sdk.js) | User SDK with JIT bridging |
