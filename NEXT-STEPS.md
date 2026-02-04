# BlackBook L1 - Next Steps

## 🎯 Priority #1: Layer 2 Prediction Market Integration

**Current Status:** L1 Wallet System 98% Ready, Bridge Infrastructure Operational

**Goal:** Enable L2 zero-sum AMM with batch settlements, market escrow, and oracle resolution.

---

## 🚨 CRITICAL BLOCKERS (Must Complete for L2 Launch)

### ❌ Blocker #1: Batch Settlement with Merkle Proofs

**Why Critical:** Zero-sum markets have 50-100+ winners per resolution. Current single-settlement system cannot scale.

**Implementation Tasks:**
- [ ] Merkle tree library (`src/settlement/merkle.rs`)
- [ ] Batch settlement endpoint (`POST /settlement/batch`)
- [ ] Double-claim prevention (withdrawal tracking)
- [ ] Merkle proof verification
- [ ] Tests for 100+ winner settlements

**Files to Create:**
```
src/settlement/
├── mod.rs           - Settlement module
├── merkle.rs        - Merkle tree creation/verification
├── batch.rs         - Batch settlement logic
└── claims.rs        - Claim tracking (prevent double-spend)
```

---

### ❌ Blocker #2: Market-Specific Escrow

**Why Critical:** Current locks are user-centric. Need market-scoped collateral for multi-winner distribution.

**Implementation Tasks:**
- [ ] Market escrow module (`src/market_escrow/mod.rs`)
- [ ] Market creation endpoint (`POST /market/create`)
- [ ] Multi-beneficiary payout distribution
- [ ] Market status tracking (Open, Locked, Resolved, Distributed)
- [ ] Link oracle resolution to market settlement

**Data Structure Needed:**
```rust
pub struct MarketEscrow {
    market_id: String,
    total_collateral: f64,
    participants: HashMap<Address, Position>,
    oracle_resolution: Option<OracleProof>,
    status: EscrowStatus,
}
```

---

### ❌ Blocker #3: Zero-Sum Invariant Enforcement

**Why Critical:** L1 must verify L2 isn't creating money from thin air.

**Implementation Tasks:**
- [ ] Pre-settlement validation function
- [ ] Verify: `Total Payouts = Total Collateral - Fees`
- [ ] Reject invalid settlements
- [ ] Audit logging for all settlements

---

## 🟡 IMPORTANT (Not Blocking MVP)

### Oracle Integration
- [ ] Oracle registry (`src/oracle/registry.rs`)
- [ ] Oracle signature verification
- [ ] Chainlink/Pyth integration (future)
- **MVP Workaround:** Dealer acts as manual oracle

### LP Position Tracking
- [ ] LP share tracking on L1
- [ ] Fee distribution logic
- **MVP Workaround:** L2 tracks LPs, settles net P&L to L1

### Multi-Outcome Markets
- [ ] Extend beyond binary (YES/NO)
- [ ] Support 3+ outcomes
- **MVP:** Start with binary markets only

---

## 📅 EXECUTION TIMELINE

### Week 1-2: Batch Settlement System ⚡ CURRENT FOCUS

**Goal:** L2 can resolve markets and pay 100+ winners in single L1 transaction

| Day | Task | Deliverable |
|-----|------|-------------|
| 1-2 | Merkle tree library | `merkle.rs` with tests |
| 3-4 | Batch endpoint + validation | `POST /settlement/batch` working |
| 5-6 | Claim tracking | Double-spend prevention |
| 7-8 | Integration tests | 100-winner settlement test passing |

**Pass Criteria:**
- ✅ Merkle proof verification works
- ✅ Batch of 100 winners settles in <5s
- ✅ Cannot claim same payout twice
- ✅ Invalid merkle proofs rejected

---

### Week 3-4: Market Escrow System

**Goal:** L1 tracks per-market collateral and distributes to multiple winners

| Day | Task | Deliverable |
|-----|------|-------------|
| 1-2 | Market escrow data structures | `market_escrow/mod.rs` |
| 3-4 | Market creation endpoint | `POST /market/create` |
| 5-6 | Multi-beneficiary distribution | Settlement logic |
| 7-8 | Zero-sum validation | Invariant enforcement |

**Pass Criteria:**
- ✅ Can create market with N participants
- ✅ Can lock collateral per participant
- ✅ Can distribute to M winners (M < N)
- ✅ Zero-sum check passes: `Σ payouts = collateral - fees`

---

### Week 5: Oracle + Polish

**Goal:** Oracle-based resolution with fallback to manual dealer

| Day | Task | Deliverable |
|-----|------|-------------|
| 1-2 | Oracle registry | Trusted oracle pubkeys |
| 3-4 | Oracle signature verification | Resolution proof validation |
| 5 | Dealer manual override | Emergency resolution |

---

### Week 6: Performance + Production Hardening

**Goal:** Verify 65k TPS claim, optimize bottlenecks

| Day | Task | Deliverable |
|-----|------|-------------|
| 1-2 | Batch settlement benchmarks | Measure throughput |
| 3-4 | gRPC optimization | Reduce latency |
| 5-6 | Load testing | 1000 concurrent markets |

---

## 🛠️ IMMEDIATE NEXT ACTIONS (Starting Now)

### Step 1: Create Settlement Module Structure
```bash
mkdir -p src/settlement
touch src/settlement/mod.rs
touch src/settlement/merkle.rs
touch src/settlement/batch.rs
touch src/settlement/claims.rs
```

### Step 2: Add Dependencies to Cargo.toml
```toml
# Merkle tree support
rs_merkle = "1.4"
sha2 = "0.10"
hex = "0.4"
```

### Step 3: Implement Merkle Tree Core
- Create merkle tree from list of (address, amount) pairs
- Generate proof for specific withdrawal
- Verify proof against root

### Step 4: Build Batch Settlement Endpoint
- Accept array of withdrawals with merkle proofs
- Verify L2 signature on merkle root
- Validate each proof
- Credit all winners atomically

---

## 🎯 SUCCESS METRICS

### MVP Launch Criteria (End of Week 2)
- ✅ 100-winner batch settlement in <5 seconds
- ✅ Merkle proof verification 100% accurate
- ✅ No double-claim vulnerabilities
- ✅ L2 can trigger batch settlement via gRPC

### Production Launch Criteria (End of Week 6)
- ✅ 1000+ settlements per second
- ✅ Zero-sum invariant enforced on all markets
- ✅ Oracle integration working
- ✅ 10,000 concurrent users supported
- ✅ Full audit trail of all settlements

---

## 📊 DEPRIORITIZED (Post-Launch)

### S+ Tier Wallet System (FROST + OPAQUE)

**Status:** Module structure exists, postponed for post-L2 launch

**Goal:** 100% operational MPC wallet where the private key **NEVER EXISTS**.

**Milestones:** (Deferred to Phase 2 - Post-L2 Launch)
- OPAQUE Handshake (password-less auth)
- FROST DKG (distributed key generation)
- Threshold Signing (multi-party signatures)
- Production polish

**Reason for Deferral:** Current mnemonic wallet system (98% passing tests) is sufficient for L2 launch. FROST+OPAQUE provides enhanced security but is not blocking L2 market functionality.

---

## 🔧 Code Structure (Current + Planned)

### ✅ Existing (Production Ready)
```
src/
├── main_v3.rs                    ✅ Main server (wallet + bridge working)
├── storage/mod.rs                ✅ Blockchain state + locks
├── grpc/mod.rs                   ✅ L1Settlement gRPC service
├── wallet_mnemonic/              ✅ BIP-39 wallet system (98% passing)
└── poh_blockchain.rs             ✅ PoH + parallel execution

sdk/
├── blackbook-wallet-sdk.js       ✅ Wallet SDK (13/13 tests passing)
└── tests/                        ✅ Comprehensive test suite

tests/
├── wallet_tests.rs               ✅ 23/23 passing
├── bridge_escrow_tests.rs        ✅ 33/33 passing
└── wallet_production_tests.rs    ✅ 13/14 passing
```

### 🔨 To Build (Week 1-6)
```
src/settlement/
├── mod.rs           ⬜ Settlement coordination
├── merkle.rs        ⬜ Merkle tree creation/verification
├── batch.rs         ⬜ Batch settlement logic
└── claims.rs        ⬜ Withdrawal claim tracking

src/market_escrow/
├── mod.rs           ⬜ Market-scoped collateral
├── escrow.rs        ⬜ Multi-participant escrow
├── distribution.rs  ⬜ Multi-winner payouts
└── validation.rs    ⬜ Zero-sum invariant checks

src/oracle/
├── mod.rs           ⬜ Oracle coordination
├── registry.rs      ⬜ Trusted oracle registry
└── verification.rs  ⬜ Oracle signature verification

tests/
├── batch_settlement_tests.rs  ⬜ 100-winner tests
└── market_escrow_tests.rs     ⬜ Zero-sum validation tests
```

---

## 📦 Dependencies to Add

```toml
[dependencies]
# Existing (already in Cargo.toml)
axum = "0.7"
tokio = { version = "1", features = ["full"] }
redb = "2.1"
ed25519-dalek = "2.1"
# ... (rest already present)

# NEW - For Merkle Trees
rs_merkle = "1.4"

# NEW - For SHA-256 hashing
sha2 = "0.10"

# FUTURE (Phase 2) - For FROST+OPAQUE
# frost-ed25519 = "2.0.0"
# frost-core = "2.0.0"
# opaque-ke = "3.0.0"
# vsss-rs = "4.0"
```

---

*Last Updated: February 2, 2026*  
*Next Review: After Week 2 (Batch Settlement Complete)*
