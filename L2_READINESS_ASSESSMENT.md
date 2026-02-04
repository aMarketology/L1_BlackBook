# Layer 2 Zero-Sum AMM Readiness Assessment

**Date:** February 2, 2026  
**Assessment:** Is L1 ready for L2 prediction market integration?

---

## Executive Summary

**Status:** 🟡 **PARTIALLY READY** (60% complete)

Your L1 has strong collateral locking infrastructure but is **missing critical AMM-specific components** needed for a zero-sum prediction market. The bridge works for simple lock/unlock, but L2 needs additional L1 features to support:
- Market escrow with multiple winners
- Batch settlement with Merkle proofs
- Oracle-based resolution verification
- Liquidity pool management

---

## ✅ What You Have (Working Infrastructure)

### 1. **Collateral Locking System** ✅
- **Location:** `src/storage/mod.rs`, `src/main_v3.rs`
- **Endpoints:** 
  - `POST /bridge/initiate` - Lock tokens on L1
  - `POST /bridge/soft-lock` - Reserve tokens for L2 positions
  - `POST /bridge/release` - Release locked tokens with P&L
- **Features:**
  - Lock records with unique IDs
  - Multiple lock purposes (`BridgeToL2`, `MarketEscrow`, `SettlementPending`)
  - Per-user locked balance tracking
  - Balance segregation (available vs locked)
- **Tests:** 33 passing tests in `tests/bridge_escrow_tests.rs`

**Verdict:** ✅ **PRODUCTION READY**

---

### 2. **Single Settlement Flow** ✅
- **Location:** `src/grpc/mod.rs` (gRPC service)
- **Methods:**
  - `SoftLock` - Lock collateral when user opens position
  - `ReleaseLock` - Release on close/cancel
  - `SettleBet` - Settle single bet with winner/loser
- **Signature Verification:** Ed25519 L2 signature validation
- **Credit System:** Soft-lock without immediate transfer

**Verdict:** ✅ **WORKS for 1v1 betting** (user vs dealer)

---

### 3. **Wallet System** ✅
- **Status:** 98% passing (49/50 tests)
- **Features:**
  - Mnemonic wallet creation/restoration
  - Ed25519 signatures
  - Transfer/burn operations
  - SDK for frontend integration
- **Documentation:** Complete (SDK_UPDATE_SUMMARY.md, WALLET_FRONTEND_READINESS.md)

**Verdict:** ✅ **READY for L2 integration**

---

### 4. **High-Speed Infrastructure** ✅
- **Parallel Processing:** Sealevel-inspired batch execution
- **Proof of History:** Temporal ordering for transactions
- **ReDB Storage:** MVCC for concurrent reads
- **Current TPS:** Unknown (needs benchmarking)
- **Claimed TPS:** 65,000+ (unverified)

**Verdict:** ✅ **Architecture supports high throughput**

---

## ❌ What You're Missing (Critical Gaps)

### 1. **Batch Settlement with Merkle Proofs** ❌

**Why You Need It:**
Zero-sum markets often have 100+ winners per resolution. Submitting individual transactions to L1 is:
- **Slow:** 100 winners = 100 separate L1 transactions
- **Expensive:** Each transaction costs gas/fees
- **Unreliable:** If 1 of 100 fails, entire settlement is incomplete

**What L2 AMM Needs:**
```rust
// L2 creates batch settlement
struct BatchSettlement {
    market_id: String,
    total_winners: u32,
    payouts: Vec<(Address, Amount)>,  // All winners
    merkle_root: Hash,                // Proof of batch integrity
    l2_signature: Signature,          // L2 sequencer signs entire batch
}

// L1 endpoint (MISSING)
POST /settlement/batch
{
    "batch_id": "market_abc_resolution_123",
    "market_id": "market_abc",
    "merkle_root": "0xabcdef...",
    "withdrawals": [
        {"address": "bb_user1", "amount": 1500, "merkle_proof": ["0x1a2b...", "0x3c4d..."]},
        {"address": "bb_user2", "amount": 800, "merkle_proof": ["0x5e6f...", "0x7g8h..."]}
        // ... 98 more winners
    ],
    "l2_signature": "ed25519_sig_of_merkle_root",
    "timestamp": 1738454400
}
```

**Current Status:** 
- ❌ No Merkle tree implementation in L1
- ❌ No batch settlement endpoint
- ❌ No batch withdrawal verification
- ⚠️ `MerkleTree` exists in `poh_blockchain.rs` but only for PoH, not for settlements

**Files to Create:**
1. `src/settlement/merkle.rs` - Merkle proof generation/verification
2. `src/settlement/batch.rs` - Batch settlement logic
3. `POST /settlement/batch` endpoint in `main_v3.rs`

---

### 2. **Market-Specific Escrow** ❌

**Why You Need It:**
Your current locks are user-centric (`user -> amount -> lock_id`). For prediction markets, you need:
- **Market-scoped locks:** All liquidity for a specific market
- **Multi-beneficiary releases:** One market → 50 winners get payouts
- **Oracle resolution proof:** Market resolves based on external data

**What's Missing:**
```rust
// Current: One lock = one user
pub struct TokenLock {
    lock_id: String,
    owner: String,        // Single user
    amount: f64,
    beneficiary: Option<String>,  // Single beneficiary
}

// Needed: Market escrow = many users
pub struct MarketEscrow {
    market_id: String,
    total_collateral: f64,          // Sum of all positions
    participants: HashMap<Address, Position>,  // All users in market
    resolution_data: Option<OracleProof>,
    status: EscrowStatus,           // Open, Resolved, Distributed
}

pub enum Position {
    LiquidityProvider { shares: f64, initial_value: f64 },
    YesPosition { shares: f64, avg_price: f64 },
    NoPosition { shares: f64, avg_price: f64 },
}
```

**Current Gap:**
- ✅ You can lock funds per user
- ❌ No way to group locks by market
- ❌ No way to distribute one market's collateral to multiple winners
- ❌ No oracle resolution verification

**Files to Create:**
1. `src/market_escrow/mod.rs` - Market-scoped collateral management
2. `src/market_escrow/settlement.rs` - Multi-beneficiary distribution
3. `POST /market/create-escrow` - L2 creates market escrow
4. `POST /market/resolve` - Oracle resolves market + distributes

---

### 3. **Oracle Integration** ❌

**Why You Need It:**
Prediction markets resolve based on real-world events:
- "Will it rain tomorrow?" → Weather API oracle
- "Will BTC hit $100k?" → Price feed oracle
- "Who wins the Super Bowl?" → Sports data oracle

**What L2 Needs from L1:**
```rust
// Oracle resolution proof
pub struct OracleResolution {
    market_id: String,
    outcome: String,           // "YES", "NO", or outcome index
    oracle_timestamp: u64,
    oracle_signature: Vec<u8>, // Oracle signs (market_id + outcome + timestamp)
    data_source: String,       // "chainlink", "pyth", "manual_dealer"
}

// L1 endpoint (MISSING)
POST /market/resolve
{
    "market_id": "market_btc_100k",
    "outcome": "NO",
    "oracle_pubkey": "oracle_ed25519_pubkey",
    "oracle_signature": "ed25519_sig",
    "oracle_data": {"price": 98500, "timestamp": 1738454400},
    "l2_signature": "l2_sequencer_sig"
}
```

**Current Status:**
- ✅ You have `usdc/oracle.rs` (for USDC bridge)
- ❌ No prediction market oracle integration
- ❌ No oracle signature verification for market resolution
- ❌ No oracle allowlist/registry

**What to Build:**
1. `src/oracle/registry.rs` - Register trusted oracle pubkeys
2. `src/oracle/verification.rs` - Verify oracle signatures on resolution
3. Update `SettlementProof` to include `OracleResolution`

---

### 4. **Liquidity Pool Support** ❌

**Why You Need It:**
Zero-sum AMMs need liquidity providers (LPs) to:
- Provide initial market liquidity
- Take the opposite side of trades
- Earn fees from trading activity

**What L1 Needs to Track:**
```rust
pub struct LiquidityPosition {
    market_id: String,
    lp_address: String,
    shares: f64,              // LP tokens (represents % of pool)
    initial_value: f64,       // Collateral when deposited
    fees_earned: f64,         // Trading fees accumulated
    impermanent_loss: f64,    // Loss from price movement
}

// When market resolves:
// - Regular traders get their winnings (zero-sum)
// - LPs get remaining pool value + fees
```

**Current Gap:**
- ❌ No LP position tracking on L1
- ❌ No way to lock collateral as "liquidity provider"
- ❌ No fee distribution mechanism
- ❌ No impermanent loss calculation

**Not Critical for MVP:** L2 can track LP positions internally and only settle net LP P&L to L1. But for transparency, L1 should know who provided liquidity.

---

### 5. **Multi-Outcome Market Support** ❌

**Why You Need It:**
Binary markets (YES/NO) are simple. Multi-outcome markets are common:
- "Who wins the election?" → 5 candidates
- "What's the final score?" → 0-5 goals
- "Pick 3 winners in order" → Combinatorial outcomes

**What Changes:**
```rust
// Current: Binary (YES/NO)
pub enum Outcome {
    Yes,
    No,
}

// Needed: Multi-outcome
pub struct Market {
    market_id: String,
    outcomes: Vec<String>,     // ["Candidate A", "Candidate B", "Candidate C"]
    positions: HashMap<(Address, OutcomeIndex), Shares>,
}

// Settlement becomes complex:
// - Only outcome X winners get paid
// - Losers' collateral distributed proportionally
```

**Current Status:**
- ⚠️ Your `SettlementProof` has `outcome: String` (flexible)
- ❌ No multi-outcome position tracking
- ❌ No multi-outcome payout logic

---

### 6. **Fee Management for AMM** ❌

**Why You Need It:**
Zero-sum markets often charge:
- **Trading fees:** 0.5-2% per trade (goes to LPs)
- **Protocol fees:** 0.1-0.5% to platform
- **Settlement fees:** Gas costs for L1 finalization

**What's Missing:**
```rust
pub struct MarketFees {
    trading_fee_bps: u16,      // Basis points (50 = 0.5%)
    protocol_fee_bps: u16,
    lp_fee_share: f64,         // % of trading fees to LPs
}

// Fee accumulation
pub struct FeeAccounts {
    lp_fees: HashMap<Address, f64>,
    protocol_fees: f64,
    treasury_address: String,
}
```

**Current Status:**
- ✅ You have `LocalizedFeeMarket` for spam prevention
- ❌ No AMM trading fees tracked
- ❌ No fee distribution to LPs
- ❌ No protocol fee treasury

---

### 7. **Zero-Sum Invariant Enforcement** ❌

**Critical Requirement:**
L1 must verify that L2 settlements are truly zero-sum:
```
Total Payouts = Total Collateral Locked (minus fees)
```

**What L1 Should Check:**
```rust
// Before releasing funds from market escrow
fn verify_zero_sum(market: &MarketEscrow, payouts: &[Payout]) -> Result<(), String> {
    let total_locked = market.total_collateral;
    let total_payout: f64 = payouts.iter().map(|p| p.amount).sum();
    let expected_fees = market.total_collateral * market.fee_rate;
    
    let expected_payout = total_locked - expected_fees;
    
    if (total_payout - expected_payout).abs() > 0.01 {
        return Err(format!(
            "Zero-sum violation: {} locked, {} paid out (expected {})",
            total_locked, total_payout, expected_payout
        ));
    }
    
    Ok(())
}
```

**Current Status:**
- ❌ No zero-sum verification
- ⚠️ L1 trusts L2 settlement amounts without validation

---

## 🟡 What Needs Improvement

### 1. **Settlement Proof Structure** 🟡

**Current:**
```rust
pub struct SettlementProof {
    market_id: String,
    outcome: String,
    l2_block_height: u64,
    l2_signature: String,
    verified_at: u64,
}
```

**Needed for AMM:**
```rust
pub struct AMMSettlementProof {
    market_id: String,
    outcome: String,              // Winning outcome
    l2_block_height: u64,
    l2_signature: String,
    
    // NEW: Zero-sum verification
    total_collateral: f64,        // Sum of all locked funds
    total_payouts: f64,           // Sum of all winner payouts
    fees_collected: f64,          // Trading + protocol fees
    
    // NEW: Oracle verification
    oracle_resolution: OracleResolution,
    
    // NEW: Batch settlement
    merkle_root: Option<String>,  // For batch withdrawals
    payout_count: u32,            // Number of winners
}
```

---

### 2. **gRPC vs REST for L2 Communication** 🟡

**Current:** You have both:
- REST endpoints (`/bridge/*`, `/credit/*`)
- gRPC service (`L1Settlement`)

**For high-frequency AMM:** gRPC is better (lower latency, typed schemas)

**Recommendation:** Migrate all L2→L1 calls to gRPC:
- `CreateMarketEscrow()`
- `LockCollateral()`
- `BatchSettle()`
- `GetMarketState()`

Your proto file (`settlement.proto`) already defines the service structure — just needs implementation.

---

### 3. **Performance Validation** 🟡

**Claimed:** 65,000+ TPS  
**Tested:** Unknown

**For L2 AMM:** You need:
- **Quote latency:** <10ms for price quotes
- **Settlement throughput:** 1,000+ settlements/second
- **Lock/unlock latency:** <50ms

**Action Items:**
1. Benchmark `/bridge/soft-lock` endpoint under load
2. Simulate 100-winner batch settlement
3. Measure gRPC `SoftLock` → `SettleBet` round-trip time

---

## 📋 Implementation Checklist

### Phase 1: Batch Settlement (Highest Priority)
- [ ] **Merkle Tree Library** (`src/settlement/merkle.rs`)
  - Implement `create_merkle_tree(leaves: Vec<Hash>)` → root
  - Implement `generate_proof(leaf: Hash, tree: &Tree)` → proof path
  - Implement `verify_proof(leaf: Hash, proof: Vec<Hash>, root: Hash)` → bool
- [ ] **Batch Settlement Endpoint** (`POST /settlement/batch`)
  - Parse batch request with merkle_root + withdrawals
  - Verify L2 signature on merkle_root
  - Verify each withdrawal's merkle proof
  - Mark withdrawals as claimed (prevent double-spend)
  - Credit all winners in single transaction batch
- [ ] **Tests** (`tests/batch_settlement_tests.rs`)
  - Test 100-winner settlement
  - Test invalid merkle proof rejection
  - Test double-claim prevention

---

### Phase 2: Market Escrow System
- [ ] **Market Escrow Module** (`src/market_escrow/mod.rs`)
  - `create_market_escrow(market_id, participants)`
  - `add_collateral(market_id, user, amount)`
  - `resolve_market(market_id, outcome, oracle_proof)`
  - `distribute_payouts(market_id, winners: Vec<(Address, Amount)>)`
- [ ] **Escrow Endpoints**
  - `POST /market/escrow/create` - L2 creates market escrow on L1
  - `GET /market/escrow/:market_id` - Query market state
  - `POST /market/escrow/resolve` - Resolve with oracle proof
- [ ] **Multi-Beneficiary Release Logic**
  - Replace single `beneficiary: Option<String>` with `Vec<(Address, Share)>`

---

### Phase 3: Oracle Integration
- [ ] **Oracle Registry** (`src/oracle/registry.rs`)
  - Allowlist of trusted oracle public keys
  - Add/remove oracles (dealer-only)
  - Verify oracle signatures
- [ ] **Resolution Verification**
  - `verify_oracle_resolution(market_id, outcome, oracle_sig)`
  - Store oracle resolution proofs on-chain
  - Link oracle proof to settlement

---

### Phase 4: Liquidity Pool Support
- [ ] **LP Position Tracking** (`src/market_escrow/liquidity.rs`)
  - Track LP deposits per market
  - Calculate LP share percentages
  - Distribute fees to LPs on settlement
- [ ] **Fee Management**
  - Separate trading fees from collateral
  - Protocol fee treasury
  - LP fee distribution logic

---

### Phase 5: Zero-Sum Validation
- [ ] **Settlement Invariant Checks**
  - `verify_zero_sum(market)` before distribution
  - Reject settlements where `payouts != collateral - fees`
  - Emit audit logs for all settlements

---

### Phase 6: Performance Validation
- [ ] **Benchmarking Suite**
  - Soft-lock throughput test
  - Batch settlement load test (1000 winners)
  - gRPC vs REST latency comparison
- [ ] **TPS Verification**
  - Actual TPS measurement under load
  - Bottleneck identification (ReDB? Signature verification?)

---

## 🎯 Recommended Implementation Order

### MVP (Week 1-2): Basic AMM Support
1. ✅ Keep existing wallet + transfer system
2. 🔨 Implement Merkle tree library
3. 🔨 Add `POST /settlement/batch` endpoint
4. 🔨 Test 100-winner settlement

**Outcome:** L2 can resolve markets with batch payouts to L1

---

### Phase 2 (Week 3-4): Market Escrow
1. 🔨 Create `MarketEscrow` module
2. 🔨 Add market-scoped collateral tracking
3. 🔨 Implement multi-beneficiary release
4. 🔨 Add zero-sum verification

**Outcome:** L1 tracks per-market collateral, enforces zero-sum

---

### Phase 3 (Week 5-6): Oracle + LP
1. 🔨 Oracle registry + signature verification
2. 🔨 LP position tracking
3. 🔨 Fee distribution logic

**Outcome:** Full prediction market support with oracles and liquidity

---

## 🚨 Blockers & Risks

### 1. **No L2 Implementation Yet**
- You have L1 ready, but no L2 Rust service?
- Need to build the actual AMM pricing engine
- Need Supabase schema for L2 state

### 2. **Oracle Dependency**
- Manual oracle (dealer) is centralized
- Need decentralized oracle (Chainlink, Pyth) for mainnet
- Oracle latency affects settlement time

### 3. **Regulatory Compliance**
- Prediction markets face legal scrutiny in many jurisdictions
- Need KYC/AML for real money markets
- May need gambling license depending on market types

---

## 📊 Readiness Matrix

| Component | Status | Priority | Blocker? |
|-----------|--------|----------|----------|
| Wallet System | ✅ 98% Ready | High | No |
| Collateral Locking | ✅ Production Ready | High | No |
| Single Settlement | ✅ Works | Medium | No |
| **Batch Settlement** | ❌ Missing | **CRITICAL** | **YES** |
| **Market Escrow** | ❌ Missing | **CRITICAL** | **YES** |
| Oracle Integration | ❌ Missing | High | No (manual workaround) |
| LP Support | ❌ Missing | Medium | No (L2 can track) |
| Zero-Sum Validation | ❌ Missing | High | No (trust L2) |
| Merkle Proofs | ❌ Missing | **CRITICAL** | **YES** |
| Multi-Outcome Markets | ⚠️ Partial | Medium | No |
| Performance Benchmarks | ❌ Missing | Medium | No |

---

## 🎬 Final Verdict

### Can You Build L2 AMM Today?

**YES, but with limitations:**

✅ **You CAN build:**
- Simple 1v1 betting (user vs dealer)
- Binary markets with single winner
- Credit-based trading (soft-lock system works)

❌ **You CANNOT build without additions:**
- Markets with 50+ winners (no batch settlement)
- Complex multi-outcome markets (escrow system limited)
- LP-based liquidity (no LP tracking)
- Automated oracle resolution (no oracle integration)

---

## 🛠️ Next Steps

### Option A: Quick MVP (2 weeks)
**Goal:** Get a minimal AMM working for binary markets

1. Implement Merkle batch settlement
2. Test with 10-winner market
3. Use dealer as manual oracle
4. Track LPs on L2 only (settle net to L1)

**Result:** Working binary prediction market with small user base

---

### Option B: Production System (6 weeks)
**Goal:** Full zero-sum AMM with all features

1. Week 1-2: Batch settlement + Merkle proofs
2. Week 3-4: Market escrow + multi-beneficiary
3. Week 5: Oracle integration (Chainlink/manual hybrid)
4. Week 6: LP support + fee management

**Result:** Enterprise-grade prediction market platform

---

## 📞 Questions to Clarify

1. **L2 Implementation:** Do you have the Rust L2 service built? Or just planning?
2. **Oracle Strategy:** Manual dealer oracle or decentralized (Chainlink)?
3. **Market Types:** Binary only or multi-outcome from day 1?
4. **Liquidity:** Dealer provides initial liquidity or community LPs?
5. **Timeline:** MVP in 2 weeks or full system in 6 weeks?

---

## 📚 Resources for Implementation

### Merkle Tree (Rust)
```bash
cargo add merkletree
# or
cargo add rs_merkle
```

### Oracle Integration
- **Chainlink:** `cargo add chainlink`
- **Pyth Network:** `cargo add pyth-sdk`

### AMM Math
- **LMSR:** Hanson's logarithmic market scoring rule
- **pm-AMM:** Constant-product for prediction markets
- Reference: https://github.com/gnosis/conditional-tokens-contracts

---

**Assessment Complete.** You have a solid L1 foundation, but need 3 critical additions: **Batch Settlement**, **Market Escrow**, and **Merkle Proofs**. These are not trivial but very achievable in 2-4 weeks.
