# BlackBook L1 - Microtransaction & TPS Optimization Roadmap

## Executive Summary

This document outlines the implementation plan for achieving:
- **Effective Zero Gas Fees** for microtransactions (< $0.10)
- **Dime-Pegged Stablecoin** as native gas token
- **Fee Sponsorship Model** for true zero-fee UX
- **100,000+ TPS** to compete with Solana

Target: Sub-$0.00001 fees, invisible to users, paid in stable value.

---

## Table of Contents

1. [Current State Analysis](#1-current-state-analysis)
2. [Phase 1: Ultra-Low Base Fee Implementation](#2-phase-1-ultra-low-base-fee)
3. [Phase 2: Dime-Pegged Gas Token](#3-phase-2-dime-pegged-gas-token)
4. [Phase 3: Fee Sponsorship/Paymaster Model](#4-phase-3-fee-sponsorship-paymaster)
5. [Phase 4: TPS Optimization (100K+ Target)](#5-phase-4-tps-optimization)
6. [Phase 5: True Zero-Fee for Sponsored Transactions](#6-phase-5-true-zero-fee)
7. [Economic Model & Sustainability](#7-economic-model)
8. [Implementation Timeline](#8-timeline)
9. [Technical Specifications](#9-technical-specifications)

---

## 0. CRITICAL: Simplification Strategy

### The Hard Truth

**To achieve 100K+ TPS with sub-$0.00001 fees, we must strip the codebase to absolute essentials.**

Current BlackBook L1 has accumulated significant complexity that creates:
- Execution overhead (more code = more cycles)
- Lock contention (more features = more shared state)
- Cognitive load (harder to optimize what you don't understand)
- Attack surface (more code = more bugs)

### The Solana Lesson

Solana achieves 65K TPS because the core runtime is **ruthlessly minimal**:
```
Solana Core = Accounts + Instructions + Signatures + PoH
That's it.
```

Everything else (tokens, NFTs, DeFi) lives in **programs** (smart contracts), not the runtime.

---

### 🗑️ FLUFF TO REMOVE (Non-Essential Complexity)

#### 1. Social Mining System (`social_mining.rs`)
**Current**: Complex engagement scoring, streak tracking, multipliers
**Problem**: Adds state reads/writes to every transaction path
**Action**: 
- [ ] Move to separate Layer 2 or off-chain service
- [ ] Remove from transaction critical path
- [ ] Engagement can be calculated from on-chain events externally

#### 2. Unified Wallet DKG (`unified_wallet/dkg.rs`)
**Current**: Full FROST Distributed Key Generation in runtime
**Problem**: Heavy cryptographic operations, complex state machine
**Action**:
- [ ] Move DKG to client-side (SDK handles key generation)
- [ ] L1 only verifies signatures, doesn't generate keys
- [ ] Keep threshold verification, remove threshold generation

#### 3. OPAQUE PAKE Authentication (`unified_wallet/opaque_auth.rs`)
**Current**: Server-side password-authenticated key exchange
**Problem**: Adds 2 extra round trips, heavy computation
**Action**:
- [ ] Remove from core runtime
- [ ] Use simple Ed25519 signatures (user holds key)
- [ ] OPAQUE can be optional client-side enhancement

#### 4. Complex Account Types (`runtime/core.rs` - AccountType enum)
**Current**: 12+ account types with custom validation
```rust
pub enum AccountType {
    UserWallet, UserProfile, StakePool, EscrowVault,
    Treasury, MarketPosition, LiquidityProvider,
    SystemConfig, BridgeEscrow, OracleConfig,
    ValidatorIdentity, DataAccount,
}
```
**Problem**: Type checking on every account access
**Action**:
- [ ] Reduce to 3 types: `User`, `Program`, `System`
- [ ] Move complex types to program layer
- [ ] Remove runtime type validation overhead

#### 5. Settlement System (`settlement/`)
**Current**: Full batch settlement with Merkle proofs, claim registry
**Problem**: Complex state machine, heavy on storage
**Action**:
- [ ] Move to program (smart contract)
- [ ] Runtime only processes simple transfers
- [ ] Settlement is application-layer concern

#### 6. Bridge/L2 Integration (`usdc/`, L2 references)
**Current**: USDC reserve, bridge escrow, cross-chain messaging
**Problem**: Adds complexity to every balance check
**Action**:
- [ ] Isolate to separate bridge program
- [ ] Core runtime doesn't know about L2
- [ ] Bridge is just another program

#### 7. Multiple Signature Schemes
**Current**: Ed25519 + Secp256k1 + FROST threshold
**Problem**: Multiple verification paths, can't optimize one
**Action**:
- [ ] Standardize on Ed25519 only (fastest)
- [ ] Remove secp256k1 support
- [ ] FROST verification can be program-level

#### 8. Security Infrastructure Overhead
**Current in every request**:
```rust
throttler.check()?;          // Rate limit check
circuit_breaker.check()?;    // Circuit breaker
fee_market.get_fee()?;       // Localized fee calc
account_validator.check()?;  // Type validation
nonce_tracker.check()?;      // Replay check
```
**Problem**: 5 checks before any work
**Action**:
- [ ] Batch these into single validation phase
- [ ] Move rate limiting to network layer (before runtime)
- [ ] Pre-compute fee at transaction submission

#### 9. Verbose Audit Logging
**Current**: Structured JSON audit events on every operation
**Problem**: Serialization overhead, storage writes
**Action**:
- [ ] Log only failures and high-value events
- [ ] Use binary format, not JSON
- [ ] Async logging (don't block tx)

#### 10. Multi-Recovery Paths (A+B, A+C, B+C)
**Current**: Three Shamir share reconstruction paths
**Problem**: Complex state for share storage
**Action**:
- [ ] Keep only A+B (user password + blockchain)
- [ ] Move B+C (admin recovery) to separate service
- [ ] Simplify share storage to single path

---

### ✅ CORE ESSENTIALS TO KEEP & OPTIMIZE

#### 1. PoH Clock (KEEP - This is our competitive edge)
```rust
// This is the heart - optimize heavily
pub struct PoHService {
    current_hash: [u8; 32],
    num_hashes: u64,
    // Nothing else needed
}
```
**Optimization**:
- [ ] Use SIMD SHA-256 (AVX-512 on modern CPUs)
- [ ] Pre-allocate hash buffer (no allocation per hash)
- [ ] Batch hash computation

#### 2. Simple Account Model (KEEP - Minimal)
```rust
// This is ALL an account needs
pub struct Account {
    pub lamports: u64,      // Balance
    pub owner: [u8; 32],    // Owner pubkey
    pub data: Vec<u8>,      // Optional data (for programs)
}
```
**Optimization**:
- [ ] Fixed-size accounts where possible
- [ ] Memory-mapped account storage
- [ ] Zero-copy reads

#### 3. Ed25519 Signature Verification (KEEP - Parallel)
```rust
// Single instruction type for core runtime
pub struct Transfer {
    from: [u8; 32],
    to: [u8; 32],
    lamports: u64,
    signature: [u8; 64],
}
```
**Optimization**:
- [ ] Batch verification (ed25519-dalek supports this)
- [ ] GPU offload for 100K+ sigs/sec
- [ ] SIMD vectorization

#### 4. Transaction Pipeline (KEEP - But Simplify)
```rust
// 4 stages is good, but each stage must be FAST
Fetch → Verify → Execute → Commit
```
**Optimization**:
- [ ] Lock-free queues between stages
- [ ] Zero-copy message passing
- [ ] Pre-allocated buffers

#### 5. Turbine Propagation (KEEP - Network efficiency)
**Optimization**:
- [ ] Larger shreds (maximize UDP payload)
- [ ] Parallel encoding threads
- [ ] Direct memory access for shred construction

#### 6. Gulf Stream (KEEP - Mempool-less is key)
**Optimization**:
- [ ] Sticky connections to leader
- [ ] Transaction deduplication at network edge
- [ ] Pre-validated transaction cache

---

### 🎯 MINIMAL RUNTIME SPECIFICATION

After simplification, the core runtime should be:

```
┌────────────────────────────────────────────────────┐
│              BLACKBOOK L1 MINIMAL RUNTIME          │
├────────────────────────────────────────────────────┤
│                                                    │
│  ACCOUNTS (3 types only)                           │
│  ├── User: { balance, pubkey }                     │
│  ├── Program: { executable, data }                 │
│  └── System: { config }                            │
│                                                    │
│  INSTRUCTIONS (5 core only)                        │
│  ├── Transfer(from, to, amount)                    │
│  ├── CreateAccount(pubkey, balance)                │
│  ├── CloseAccount(pubkey)                          │
│  ├── Invoke(program, data)                         │
│  └── SetData(account, data)                        │
│                                                    │
│  CONSENSUS                                         │
│  ├── PoH Clock (SHA-256 chain)                     │
│  ├── Tower BFT (vote + lockout)                    │
│  └── Leader Schedule (stake-weighted)              │
│                                                    │
│  NETWORK                                           │
│  ├── Gulf Stream (tx forwarding)                   │
│  └── Turbine (block propagation)                   │
│                                                    │
│  EXECUTION                                         │
│  ├── Sealevel (parallel by account)                │
│  └── Programs (BPF bytecode)                       │
│                                                    │
└────────────────────────────────────────────────────┘

Lines of Code Target: < 10,000 (currently ~30,000+)
```

---

### 📊 Complexity Budget

| Component | Current LOC | Target LOC | Reduction |
|-----------|-------------|------------|-----------|
| Account Model | ~2,000 | ~300 | 85% |
| Transaction | ~1,500 | ~200 | 87% |
| PoH Service | ~500 | ~300 | 40% |
| Consensus | ~1,500 | ~800 | 47% |
| Wallet (runtime) | ~3,000 | ~0* | 100% |
| Settlement | ~1,000 | ~0* | 100% |
| Social Mining | ~800 | ~0* | 100% |
| **Total Runtime** | ~15,000 | ~3,000 | **80%** |

*Moved to program layer or external service

---

### 🚀 Migration Path

#### Step 1: Extract Non-Core to Programs (Week 1-2)
```
Before: Runtime handles everything
After:  Runtime handles accounts + execution
        Programs handle: tokens, settlement, social, bridge
```

#### Step 2: Simplify Account Model (Week 3)
```rust
// Before: 12 account types with validation
// After:
pub struct Account {
    lamports: u64,
    owner: Pubkey,
    data: Box<[u8]>,  // Fixed allocation
    executable: bool,
}
```

#### Step 3: Single Signature Scheme (Week 4)
```rust
// Before: Ed25519 + Secp256k1 + FROST
// After: Ed25519 only (with batch verify)
pub fn verify_signatures(txs: &[Transaction]) -> Vec<bool> {
    ed25519_dalek::verify_batch(/* ... */)
}
```

#### Step 4: Optimize Hot Paths (Week 5-6)
- Profile actual bottlenecks
- SIMD for hash computation
- Lock-free data structures
- Zero-copy where possible

#### Step 5: Benchmark & Iterate (Week 7-8)
- Target: 100K TPS on single node
- Identify remaining bottlenecks
- Micro-optimize critical sections

---

### ⚠️ What We LOSE (And Why It's OK)

| Removed Feature | Why It's OK |
|-----------------|-------------|
| Social Mining | Can run as L2/off-chain indexer |
| FROST DKG | Users generate keys client-side |
| OPAQUE Auth | Ed25519 sigs are sufficient |
| Complex PDAs | Programs derive their own |
| Settlement | Program can handle |
| Bridge Logic | Separate bridge program |
| Multi-sig Admin | Program-level feature |

**Philosophy**: If it's not needed for `Transfer A → B`, it doesn't belong in runtime.

---

### 📈 Expected Gains from Simplification

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Tx Processing | 50μs | 10μs | 5x |
| Signature Verify | 100μs | 20μs | 5x |
| State Access | 30μs | 5μs | 6x |
| Block Build | 10ms | 2ms | 5x |
| **Effective TPS** | 20K | **100K+** | **5x** |

---

## 1. Current State Analysis

### What We Have ✅
```
✅ PoH Clock (600ms slots)
✅ Tower BFT Consensus
✅ Gulf Stream Transaction Forwarding
✅ Turbine Shred Propagation
✅ Sealevel Parallel Execution
✅ Transaction Pipeline (4-stage)
✅ 16,667 TPS theoretical (10K txs/block @ 600ms)
```

### What We Need 🎯
```
❌ Fixed ultra-low base fee (currently variable)
❌ Dime-pegged gas token
❌ Fee delegation / paymaster field
❌ Sponsored transaction support
❌ Parallel signature verification at scale
❌ 100K+ TPS sustained
```

### Current Fee Structure (Needs Replacement)
```rust
// Current: Variable fee based on compute
pub const BASE_FEE_LAMPORTS: u64 = 5000;  // ~$0.0005 at $0.10/token
pub const PRIORITY_FEE_PER_CU: u64 = 1;   // Variable
```

### Target Fee Structure
```rust
// Target: Fixed micro-fee in dime-stable
pub const BASE_FEE_DIMES: u64 = 1;        // 0.00001 dime = $0.000001
pub const DIME_DECIMALS: u8 = 6;          // 1 dime = 1_000_000 micro-dimes
pub const MAX_PRIORITY_DIMES: u64 = 100;  // 0.0001 dime max priority
```

---

## 2. Phase 1: Ultra-Low Base Fee

### Milestone 1.1: Fixed Base Fee System
**Goal**: Replace variable compute-based fees with fixed micro-fee

**Files to Modify**:
- `runtime/core.rs` - Fee calculation
- `src/storage/mod.rs` - Fee deduction
- `protocol/mod.rs` - Transaction structure

**Implementation**:

```rust
// New: runtime/fees.rs

/// Fee configuration for microtransactions
#[derive(Debug, Clone)]
pub struct FeeConfig {
    /// Base fee in micro-dimes (1 dime = 1_000_000 micro-dimes)
    /// Default: 1 micro-dime = $0.0000001
    pub base_fee_micro_dimes: u64,
    
    /// Maximum priority fee (for congestion)
    pub max_priority_micro_dimes: u64,
    
    /// Fee burn percentage (0-100)
    pub burn_percentage: u8,
    
    /// Validator reward percentage (remainder after burn)
    pub validator_percentage: u8,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            base_fee_micro_dimes: 10,      // $0.000001 (10 micro-dimes)
            max_priority_micro_dimes: 1000, // $0.0001 max priority
            burn_percentage: 50,            // 50% burned (deflationary)
            validator_percentage: 50,       // 50% to validator
        }
    }
}

/// Calculate fee for a transaction
pub fn calculate_fee(
    config: &FeeConfig,
    priority: u64,
    is_sponsored: bool,
) -> u64 {
    if is_sponsored {
        return 0; // Sponsor pays
    }
    
    let priority_capped = priority.min(config.max_priority_micro_dimes);
    config.base_fee_micro_dimes + priority_capped
}
```

### Milestone 1.2: Fee Burn Mechanism
**Goal**: 50% of fees burned for deflationary pressure

```rust
/// Process fee: burn + validator reward
pub fn process_fee(
    blockchain: &mut ConcurrentBlockchain,
    fee_payer: &str,
    validator: &str,
    fee_micro_dimes: u64,
    config: &FeeConfig,
) -> Result<(), FeeError> {
    // Calculate split
    let burn_amount = (fee_micro_dimes * config.burn_percentage as u64) / 100;
    let validator_amount = fee_micro_dimes - burn_amount;
    
    // Deduct from payer
    blockchain.subtract_balance(fee_payer, fee_micro_dimes)?;
    
    // Burn portion (reduce total supply)
    blockchain.burn_supply(burn_amount)?;
    
    // Reward validator
    blockchain.add_balance(validator, validator_amount)?;
    
    Ok(())
}
```

### Milestone 1.3: Priority Fee Market (Localized)
**Goal**: Optional priority fees that only affect the payer, not global rates

```rust
/// Localized fee market - no global fee spikes
pub struct LocalizedFeeMarket {
    /// Per-account congestion tracking
    account_load: DashMap<String, AccountLoad>,
    
    /// Base fee (fixed)
    base_fee: u64,
    
    /// Priority multiplier per account (1.0 = normal)
    priority_multipliers: DashMap<String, f64>,
}

impl LocalizedFeeMarket {
    /// Get fee for specific account (localized, not global)
    pub fn get_fee_for_account(&self, account: &str, priority: u64) -> u64 {
        let multiplier = self.priority_multipliers
            .get(account)
            .map(|m| *m)
            .unwrap_or(1.0);
        
        // Only this account's fee is affected by their own spam
        let adjusted_priority = (priority as f64 * multiplier) as u64;
        self.base_fee + adjusted_priority.min(1000)
    }
}
```

---

## 3. Phase 2: Dime-Pegged Gas Token

### Milestone 2.1: Dime Token Specification
**Goal**: Native gas token pegged to $0.10 USD

```rust
/// Dime token configuration
pub struct DimeToken {
    /// Symbol
    pub symbol: String,  // "DIME"
    
    /// Decimals (6 = micro-dimes)
    pub decimals: u8,
    
    /// Peg target in USD cents
    pub peg_target_cents: u64,  // 10 = $0.10
    
    /// Total supply (minted on deposit)
    pub total_supply: AtomicU64,
    
    /// Treasury reserve (USD-backed)
    pub treasury_reserve_cents: AtomicU64,
}

impl DimeToken {
    pub fn new() -> Self {
        Self {
            symbol: "DIME".to_string(),
            decimals: 6,
            peg_target_cents: 10,
            total_supply: AtomicU64::new(0),
            treasury_reserve_cents: AtomicU64::new(0),
        }
    }
    
    /// Mint dimes on USD deposit
    /// 1 USD = 10 DIME
    pub fn mint_from_usd(&self, usd_cents: u64) -> u64 {
        let dimes_to_mint = usd_cents / self.peg_target_cents;
        self.total_supply.fetch_add(dimes_to_mint * 1_000_000, Ordering::SeqCst);
        self.treasury_reserve_cents.fetch_add(usd_cents, Ordering::SeqCst);
        dimes_to_mint * 1_000_000 // Return micro-dimes
    }
    
    /// Burn dimes on redemption
    pub fn burn_for_usd(&self, micro_dimes: u64) -> u64 {
        let dimes = micro_dimes / 1_000_000;
        let usd_cents = dimes * self.peg_target_cents;
        self.total_supply.fetch_sub(micro_dimes, Ordering::SeqCst);
        self.treasury_reserve_cents.fetch_sub(usd_cents, Ordering::SeqCst);
        usd_cents
    }
}
```

### Milestone 2.2: Gas Payment in Dime
**Goal**: All fees paid in DIME token, not volatile native token

```rust
/// Transaction with dime-denominated fee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimeTransaction {
    /// Standard transaction fields
    pub from: String,
    pub to: String,
    pub amount: u64,  // In micro-dimes
    
    /// Fee in micro-dimes (fixed + priority)
    pub fee_micro_dimes: u64,
    
    /// Priority level (0 = base only)
    pub priority: u8,
    
    /// Optional: fee payer (for sponsorship)
    pub fee_payer: Option<String>,
    
    /// Signature
    pub signature: String,
    
    /// Nonce for replay protection
    pub nonce: String,
}

impl DimeTransaction {
    /// Get effective fee payer
    pub fn effective_fee_payer(&self) -> &str {
        self.fee_payer.as_ref().unwrap_or(&self.from)
    }
    
    /// Check if sponsored
    pub fn is_sponsored(&self) -> bool {
        self.fee_payer.is_some() && self.fee_payer.as_ref() != Some(&self.from)
    }
}
```

### Milestone 2.3: Peg Stability Mechanism
**Goal**: Maintain $0.10 peg with mint/burn arbitrage

```rust
/// Peg stability controller
pub struct PegStabilityModule {
    /// Oracle price feed (DIME/USD)
    pub oracle_price_cents: AtomicU64,
    
    /// Allowed deviation before intervention
    pub max_deviation_bps: u64,  // 50 = 0.5%
    
    /// Treasury for stability operations
    pub stability_treasury: AtomicU64,
}

impl PegStabilityModule {
    /// Check if price is within peg bounds
    pub fn is_pegged(&self) -> bool {
        let price = self.oracle_price_cents.load(Ordering::Relaxed);
        let target = 10u64; // $0.10
        let deviation = if price > target { price - target } else { target - price };
        let deviation_bps = (deviation * 10000) / target;
        deviation_bps <= self.max_deviation_bps
    }
    
    /// Arbitrage incentive: if DIME < $0.10, buying is profitable
    pub fn get_arbitrage_incentive(&self) -> ArbitrageDirection {
        let price = self.oracle_price_cents.load(Ordering::Relaxed);
        if price < 10 {
            ArbitrageDirection::Buy  // Buy DIME, redeem for $0.10
        } else if price > 10 {
            ArbitrageDirection::Sell // Mint DIME at $0.10, sell higher
        } else {
            ArbitrageDirection::None
        }
    }
}
```

---

## 4. Phase 3: Fee Sponsorship/Paymaster Model

### Milestone 3.1: Fee Payer Field in Transactions
**Goal**: Allow third party to pay transaction fees

```rust
/// Versioned transaction supporting fee delegation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedTransaction {
    /// Version (0 = legacy, 1 = fee delegation)
    pub version: u8,
    
    /// Primary signer (action performer)
    pub signer: String,
    
    /// Fee payer (can be different from signer)
    pub fee_payer: String,
    
    /// Instructions
    pub instructions: Vec<Instruction>,
    
    /// Signatures: [signer_sig, fee_payer_sig (if different)]
    pub signatures: Vec<String>,
    
    /// Recent blockhash for expiry
    pub recent_blockhash: String,
}

impl VersionedTransaction {
    /// Create sponsored transaction
    pub fn create_sponsored(
        signer: &str,
        fee_payer: &str,
        instructions: Vec<Instruction>,
        signer_signature: &str,
    ) -> Self {
        Self {
            version: 1,
            signer: signer.to_string(),
            fee_payer: fee_payer.to_string(),
            instructions,
            signatures: vec![signer_signature.to_string()], // Fee payer signs later
            recent_blockhash: String::new(),
        }
    }
    
    /// Add fee payer signature (relayer completes the tx)
    pub fn add_fee_payer_signature(&mut self, signature: &str) {
        if self.signer != self.fee_payer {
            self.signatures.push(signature.to_string());
        }
    }
    
    /// Validate all required signatures present
    pub fn is_complete(&self) -> bool {
        if self.signer == self.fee_payer {
            self.signatures.len() >= 1
        } else {
            self.signatures.len() >= 2
        }
    }
}
```

### Milestone 3.2: Paymaster Contract
**Goal**: Protocol/dApp treasury sponsors fees

```rust
/// Paymaster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymasterConfig {
    /// Treasury address funding the paymaster
    pub treasury: String,
    
    /// Maximum fee per sponsored tx
    pub max_fee_per_tx: u64,
    
    /// Daily budget in micro-dimes
    pub daily_budget: u64,
    
    /// Remaining budget today
    pub remaining_budget: AtomicU64,
    
    /// Eligible transaction types
    pub eligible_types: Vec<TxType>,
    
    /// Maximum tx value for sponsorship
    pub max_tx_value_for_sponsor: u64,  // e.g., 5_000_000 = 5 DIME = $0.50
}

/// Paymaster service
pub struct Paymaster {
    /// Configuration
    pub config: PaymasterConfig,
    
    /// Sponsored tx count per user today
    pub user_sponsored_count: DashMap<String, u64>,
    
    /// Max sponsored txs per user per day
    pub max_per_user_daily: u64,
}

impl Paymaster {
    /// Check if transaction qualifies for sponsorship
    pub fn can_sponsor(&self, tx: &DimeTransaction) -> bool {
        // Check budget
        let remaining = self.config.remaining_budget.load(Ordering::Relaxed);
        if remaining < tx.fee_micro_dimes {
            return false;
        }
        
        // Check user daily limit
        let user_count = self.user_sponsored_count
            .get(&tx.from)
            .map(|c| *c)
            .unwrap_or(0);
        if user_count >= self.max_per_user_daily {
            return false;
        }
        
        // Check tx value (only sponsor small txs)
        if tx.amount > self.config.max_tx_value_for_sponsor {
            return false;
        }
        
        true
    }
    
    /// Sponsor a transaction (modify fee_payer)
    pub fn sponsor(&self, tx: &mut DimeTransaction) -> Result<(), PaymasterError> {
        if !self.can_sponsor(tx) {
            return Err(PaymasterError::NotEligible);
        }
        
        // Deduct from budget
        self.config.remaining_budget.fetch_sub(tx.fee_micro_dimes, Ordering::SeqCst);
        
        // Increment user count
        self.user_sponsored_count
            .entry(tx.from.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        // Set treasury as fee payer
        tx.fee_payer = Some(self.config.treasury.clone());
        
        Ok(())
    }
}
```

### Milestone 3.3: Sponsorship Rules Engine
**Goal**: Configurable rules for what gets sponsored

```rust
/// Sponsorship rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorshipRules {
    /// Sponsor first N txs per user per day
    pub free_txs_per_day: u64,
    
    /// Sponsor txs below this value
    pub max_value_for_free: u64,  // 5_000_000 = $0.50
    
    /// Specific tx types always sponsored
    pub always_sponsored: Vec<String>,  // ["transfer", "swap"]
    
    /// Whitelist: these addresses always get sponsorship
    pub whitelist: HashSet<String>,
    
    /// Blacklist: these addresses never get sponsorship
    pub blacklist: HashSet<String>,
}

impl SponsorshipRules {
    /// Default: 3 free txs/day for transfers under $0.50
    pub fn default_microtx() -> Self {
        Self {
            free_txs_per_day: 3,
            max_value_for_free: 5_000_000,  // $0.50 in micro-dimes
            always_sponsored: vec!["transfer".to_string()],
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
        }
    }
}
```

---

## 5. Phase 4: TPS Optimization (100K+ Target)

### Current Bottlenecks
```
1. Slot duration: 600ms (need 400ms or less)
2. Txs per block: 10,000 (need 50,000+)
3. Signature verification: Sequential (need parallel)
4. State access: Lock contention (need better sharding)
5. Network propagation: Tree depth (need wider fanout)
```

### Milestone 4.1: Reduce Slot Duration (600ms → 400ms)
**Goal**: Match Solana's slot timing

```rust
// runtime/consensus.rs - Update PoH config

impl PoHConfig {
    /// High-performance configuration (Solana-competitive)
    pub fn high_performance() -> Self {
        Self {
            slot_duration_ms: 400,    // ← Reduced from 600ms
            hashes_per_tick: 12500,
            ticks_per_slot: 64,
            slots_per_epoch: 432000,
        }
    }
}

// Impact: 2.5 blocks/sec → 16,667 TPS becomes 25,000 TPS base
```

### Milestone 4.2: Increase Block Capacity (10K → 50K txs)
**Goal**: 5x more transactions per block

```rust
// src/poh_blockchain.rs - Update constants

/// Maximum transactions per block
/// UPGRADED: 50,000 txs/block at 400ms = 125,000 TPS theoretical
pub const MAX_TXS_PER_BLOCK: usize = 50_000;

/// Block production interval
pub const BLOCK_INTERVAL_MS: u64 = 400;

/// Shred size optimized for jumbo blocks
pub const SHRED_SIZE: usize = 1280;  // Max UDP payload

/// More data shreds per FEC set (better recovery)
pub const DATA_SHREDS_PER_FEC_SET: usize = 64;
```

### Milestone 4.3: Parallel Signature Verification
**Goal**: GPU-accelerated Ed25519 verification

```rust
/// Parallel signature verifier using Rayon
pub struct ParallelSigVerifier {
    /// Number of worker threads
    pub threads: usize,
    
    /// Batch size for parallel processing
    pub batch_size: usize,
}

impl ParallelSigVerifier {
    pub fn new() -> Self {
        Self {
            threads: num_cpus::get(),
            batch_size: 1000,
        }
    }
    
    /// Verify batch of signatures in parallel
    pub fn verify_batch(&self, txs: &[DimeTransaction]) -> Vec<bool> {
        use rayon::prelude::*;
        
        txs.par_chunks(self.batch_size)
            .flat_map(|chunk| {
                chunk.iter().map(|tx| {
                    // Ed25519 verification
                    verify_ed25519_signature(
                        &tx.signature,
                        &tx.from,
                        &tx.to_signing_message()
                    )
                }).collect::<Vec<_>>()
            })
            .collect()
    }
}

// Expected: 100K sig verifications in <100ms on modern CPU
// With GPU (CUDA): 500K+ verifications in <100ms
```

### Milestone 4.4: Account State Sharding
**Goal**: Reduce lock contention via horizontal sharding

```rust
/// Sharded account state for parallel access
pub struct ShardedAccountState {
    /// Number of shards (power of 2)
    pub num_shards: usize,
    
    /// Shard stores: each shard has independent locks
    shards: Vec<RwLock<HashMap<String, Account>>>,
}

impl ShardedAccountState {
    pub fn new(num_shards: usize) -> Self {
        let shards = (0..num_shards)
            .map(|_| RwLock::new(HashMap::new()))
            .collect();
        
        Self { num_shards, shards }
    }
    
    /// Get shard index for an address
    fn shard_index(&self, address: &str) -> usize {
        let hash = blake3::hash(address.as_bytes());
        let bytes = hash.as_bytes();
        let idx = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        (idx as usize) % self.num_shards
    }
    
    /// Access account with minimal lock contention
    pub fn get_account(&self, address: &str) -> Option<Account> {
        let shard_idx = self.shard_index(address);
        let shard = self.shards[shard_idx].read();
        shard.get(address).cloned()
    }
    
    /// Update account (only locks one shard)
    pub fn update_account(&self, address: &str, account: Account) {
        let shard_idx = self.shard_index(address);
        let mut shard = self.shards[shard_idx].write();
        shard.insert(address.to_string(), account);
    }
}

// With 256 shards: 256x reduction in lock contention
// Enables true parallel execution of non-conflicting txs
```

### Milestone 4.5: Turbine Optimization (Wider Fanout)
**Goal**: Faster block propagation to validators

```rust
// src/poh_blockchain.rs - Turbine optimization

/// Maximum fanout per propagation level
/// UPGRADED: 400 nodes = 160,000 nodes in 2 hops
pub const TURBINE_FANOUT: usize = 400;

/// Enable parallel shred transmission
pub const PARALLEL_SHRED_SEND: bool = true;

/// Shred retransmission threads
pub const SHRED_SENDER_THREADS: usize = 4;

impl TurbinePropagator {
    /// Optimized propagation with parallel UDP sends
    pub async fn propagate_parallel(&self, shreds: Vec<Shred>) {
        use tokio::task::JoinSet;
        
        let mut tasks = JoinSet::new();
        
        for chunk in shreds.chunks(100) {
            let chunk = chunk.to_vec();
            let peers = self.get_next_layer_peers();
            
            tasks.spawn(async move {
                for shred in chunk {
                    for peer in &peers {
                        // Non-blocking UDP send
                        let _ = send_shred_udp(&shred, peer).await;
                    }
                }
            });
        }
        
        // Wait for all sends to complete
        while tasks.join_next().await.is_some() {}
    }
}
```

### Milestone 4.6: Gulf Stream Enhancement
**Goal**: Pre-forward transactions to next 16 leaders (not just 8)

```rust
// runtime/consensus.rs - Gulf Stream optimization

/// Number of upcoming leaders to forward transactions to
/// UPGRADED: 16 leaders = ~6.4 seconds lookahead at 400ms
const GULF_STREAM_LOOKAHEAD: usize = 16;

/// Maximum transactions to cache per leader
/// UPGRADED: 100K for burst handling
const MAX_CACHED_TXS_PER_LEADER: usize = 100_000;

/// Enable speculative execution (execute before confirmation)
const SPECULATIVE_EXECUTION: bool = true;
```

### TPS Projection After Optimizations

| Optimization | TPS Impact |
|-------------|------------|
| Baseline (current) | 16,667 |
| 400ms slots | +50% → 25,000 |
| 50K txs/block | +5x → 125,000 |
| Parallel sig verify | -bottleneck |
| State sharding | -bottleneck |
| **Total Theoretical** | **125,000 TPS** |
| **Realistic Sustained** | **80,000-100,000 TPS** |

---

## 6. Phase 5: True Zero-Fee for Sponsored Transactions

### Milestone 5.1: Protocol Treasury Funding
**Goal**: Sustainable fee sponsorship from protocol revenue

```rust
/// Protocol treasury for fee sponsorship
pub struct ProtocolTreasury {
    /// Treasury balance in micro-dimes
    pub balance: AtomicU64,
    
    /// Revenue sources
    pub revenue_sources: Vec<RevenueSource>,
    
    /// Daily sponsorship allocation
    pub daily_sponsorship_budget: u64,
}

#[derive(Debug, Clone)]
pub enum RevenueSource {
    /// Small spread on DIME mint/burn (0.01%)
    MintBurnSpread { rate_bps: u64 },
    
    /// Validator inflation allocation
    InflationAllocation { percentage: u64 },
    
    /// Priority fee overflow (above cap)
    PriorityFeeOverflow,
    
    /// Partner integrations
    PartnerFees { partner: String, amount: u64 },
}

impl ProtocolTreasury {
    /// Calculate sustainable daily sponsorship
    pub fn calculate_daily_budget(&self) -> u64 {
        // Budget = 80% of average daily revenue
        let daily_revenue = self.estimate_daily_revenue();
        (daily_revenue * 80) / 100
    }
    
    fn estimate_daily_revenue(&self) -> u64 {
        // Based on network activity
        // At 50K TPS, 0.1% txs pay priority = 50 TPS paying
        // Average priority = 100 micro-dimes
        // Daily = 50 * 86400 * 100 = 432M micro-dimes = $43,200/day
        432_000_000
    }
}
```

### Milestone 5.2: Invisible Fee UX
**Goal**: Users never see or approve fees

```rust
/// SDK integration for invisible fees
impl MnemonicWallet {
    /// Transfer with automatic fee handling
    /// Fee is either sponsored or deducted invisibly
    pub async fn transfer_invisible_fee(
        &self,
        to: &str,
        amount: u64,
    ) -> Result<TransferResult, WalletError> {
        let mut tx = DimeTransaction {
            from: self.address.clone(),
            to: to.to_string(),
            amount,
            fee_micro_dimes: 10, // Base fee
            priority: 0,
            fee_payer: None,
            signature: String::new(),
            nonce: generate_nonce(),
        };
        
        // Try sponsorship first
        let sponsor_result = self.try_get_sponsorship(&mut tx).await;
        
        if sponsor_result.is_ok() {
            // Fee is sponsored - user pays nothing
            tx.fee_payer = Some("PROTOCOL_TREASURY".to_string());
        } else {
            // Auto-deduct from user balance (invisible)
            // Fee is so small ($0.000001) user won't notice
        }
        
        // Sign and submit
        tx.signature = self.sign(&tx)?;
        self.submit_transaction(tx).await
    }
}
```

### Milestone 5.3: Free Tier Implementation
**Goal**: First 3 transactions per day are completely free

```rust
/// Free tier tracking
pub struct FreeTierManager {
    /// User free tx count today
    user_free_count: DashMap<String, u64>,
    
    /// Free txs per user per day
    free_per_day: u64,
    
    /// Reset hour (UTC)
    reset_hour: u8,
    
    /// Last reset timestamp
    last_reset: AtomicU64,
}

impl FreeTierManager {
    pub fn new() -> Self {
        Self {
            user_free_count: DashMap::new(),
            free_per_day: 3,
            reset_hour: 0, // Midnight UTC
            last_reset: AtomicU64::new(0),
        }
    }
    
    /// Check and consume free tx
    pub fn try_use_free(&self, user: &str) -> bool {
        self.maybe_reset();
        
        let count = self.user_free_count
            .entry(user.to_string())
            .or_insert(0);
        
        if *count < self.free_per_day {
            *count += 1;
            true
        } else {
            false
        }
    }
    
    /// Get remaining free txs for user
    pub fn remaining_free(&self, user: &str) -> u64 {
        let used = self.user_free_count
            .get(user)
            .map(|c| *c)
            .unwrap_or(0);
        
        self.free_per_day.saturating_sub(used)
    }
}
```

---

## 7. Economic Model & Sustainability

### Fee Economics Summary

| Component | Value | USD Equivalent |
|-----------|-------|----------------|
| Base fee | 10 micro-dimes | $0.000001 |
| Max priority | 1000 micro-dimes | $0.0001 |
| Burn rate | 50% of fees | Deflationary |
| Validator reward | 50% of fees | Sustainable |
| Free tier | 3 txs/day | $0.000003 cost |

### Revenue Projections at Scale

```
At 50,000 TPS sustained:
- Total daily txs: 4.32 billion
- 0.1% pay priority (congestion): 4.32 million
- Average priority: 100 micro-dimes ($0.00001)
- Daily priority revenue: $43,200

At 100,000 TPS sustained:
- Daily priority revenue: $86,400

Mint/burn spread (0.01%):
- $10M daily volume: $1,000/day
- $100M daily volume: $10,000/day

Total sustainable: $50,000-$100,000/day at scale
```

### Inflation Model

```rust
/// Inflation schedule (annual %)
pub struct InflationSchedule {
    /// Initial inflation rate
    pub initial_rate: f64,  // 5%
    
    /// Terminal inflation rate
    pub terminal_rate: f64,  // 1.5%
    
    /// Years to reach terminal
    pub taper_years: u64,  // 10
}

impl InflationSchedule {
    /// Get inflation rate for a given year
    pub fn rate_for_year(&self, year: u64) -> f64 {
        if year >= self.taper_years {
            return self.terminal_rate;
        }
        
        // Linear taper
        let progress = year as f64 / self.taper_years as f64;
        self.initial_rate - (self.initial_rate - self.terminal_rate) * progress
    }
}

// Year 0: 5.0%
// Year 5: 3.25%
// Year 10+: 1.5%
```

---

## 8. Implementation Timeline

### Phase 1: Ultra-Low Base Fee (2 weeks)
```
Week 1:
- [ ] Implement FeeConfig struct
- [ ] Add fixed base fee calculation
- [ ] Implement fee burn mechanism
- [ ] Update transaction processing

Week 2:
- [ ] Implement localized fee market
- [ ] Add priority fee caps
- [ ] Unit tests for fee system
- [ ] Integration tests
```

### Phase 2: Dime Token (3 weeks)
```
Week 3:
- [ ] Implement DimeToken struct
- [ ] Add mint/burn mechanics
- [ ] Create treasury management

Week 4:
- [ ] Implement peg stability module
- [ ] Add oracle price feed integration
- [ ] Arbitrage incentive system

Week 5:
- [ ] Gas payment in DIME
- [ ] Update all fee deductions
- [ ] Integration testing
```

### Phase 3: Fee Sponsorship (2 weeks)
```
Week 6:
- [ ] Implement VersionedTransaction
- [ ] Add fee_payer field support
- [ ] Create Paymaster contract

Week 7:
- [ ] Implement sponsorship rules engine
- [ ] Add free tier manager
- [ ] SDK integration for invisible fees
```

### Phase 4: TPS Optimization (4 weeks)
```
Week 8:
- [ ] Reduce slot duration to 400ms
- [ ] Increase block capacity to 50K
- [ ] Benchmark and stress test

Week 9:
- [ ] Implement parallel sig verification
- [ ] Add state sharding (256 shards)
- [ ] Benchmark parallel execution

Week 10:
- [ ] Optimize Turbine (fanout 400)
- [ ] Enhance Gulf Stream (16 leaders)
- [ ] Parallel shred transmission

Week 11:
- [ ] Full system integration
- [ ] Load testing at 100K TPS
- [ ] Performance tuning
```

### Phase 5: Production Hardening (2 weeks)
```
Week 12:
- [ ] Protocol treasury setup
- [ ] Sponsorship budget allocation
- [ ] Monitoring and alerts

Week 13:
- [ ] Security audit
- [ ] Documentation
- [ ] Mainnet deployment prep
```

**Total: 13 weeks (3 months)**

---

## 9. Technical Specifications

### Transaction Format (v2)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TransactionV2 {
    /// Version (2 = dime fees + sponsorship)
    pub version: u8,
    
    /// Signer (action performer)
    pub signer: String,
    
    /// Fee payer (sponsor if different)
    pub fee_payer: String,
    
    /// Fee in micro-dimes
    pub fee_micro_dimes: u64,
    
    /// Priority (0-255)
    pub priority: u8,
    
    /// Instructions
    pub instructions: Vec<Instruction>,
    
    /// Signatures: [signer, fee_payer?]
    pub signatures: Vec<[u8; 64]>,
    
    /// Recent blockhash
    pub recent_blockhash: [u8; 32],
    
    /// Nonce (UUID)
    pub nonce: [u8; 16],
}
```

### API Endpoints (New)

```
POST /v2/transaction/submit
  - Accepts TransactionV2 format
  - Auto-detects sponsorship eligibility

POST /v2/sponsor/request
  - Request fee sponsorship for a transaction
  - Returns signed fee_payer if eligible

GET /v2/fees/estimate
  - Returns current base fee + recommended priority

GET /v2/user/{address}/free-tier
  - Returns remaining free txs today

GET /v2/treasury/status
  - Returns sponsorship budget status
```

### Configuration File

```toml
# config/fees.toml

[base_fee]
micro_dimes = 10          # $0.000001
burn_percentage = 50
validator_percentage = 50

[priority]
max_micro_dimes = 1000    # $0.0001
localized = true          # Per-account, not global

[sponsorship]
enabled = true
free_per_day = 3
max_tx_value = 5000000    # $0.50 in micro-dimes
daily_budget = 1000000000 # $100/day in micro-dimes

[dime_token]
decimals = 6
peg_target_cents = 10
max_deviation_bps = 50    # 0.5%

[tps]
slot_duration_ms = 400
max_txs_per_block = 50000
parallel_sig_verify = true
state_shards = 256
turbine_fanout = 400
gulf_stream_lookahead = 16
```

---

## Success Metrics

### Fee Metrics
- [ ] Average fee < $0.00001
- [ ] 95% of txs are sponsored (free)
- [ ] Zero fee complaints from users
- [ ] Stable DIME peg (±0.5%)

### TPS Metrics
- [ ] Sustained 80,000 TPS in testnet
- [ ] Peak 100,000+ TPS achieved
- [ ] < 500ms finality
- [ ] < 1% failed transactions under load

### Economic Metrics
- [ ] Treasury self-sustaining (revenue > sponsorship)
- [ ] Positive burn rate (deflationary)
- [ ] Validator APY > 5%

---

## Appendix A: Comparison with Solana

| Feature | Solana | BlackBook L1 Target |
|---------|--------|---------------------|
| Slot duration | 400ms | 400ms |
| Base fee | ~$0.0005 | ~$0.000001 |
| Fee token | SOL (volatile) | DIME (stable) |
| Sponsorship | Manual (fee payer) | Automatic |
| Free tier | No | 3 txs/day |
| TPS | 65,000 | 100,000+ |
| Finality | 400ms | 400ms |

---

## Appendix B: Risk Assessment

### Technical Risks
| Risk | Mitigation |
|------|------------|
| 400ms slots unstable | Keep 500ms fallback |
| State sharding bugs | Extensive testing, gradual rollout |
| Sig verify bottleneck | GPU acceleration option |

### Economic Risks
| Risk | Mitigation |
|------|------------|
| DIME depeg | Fully backed treasury, arbitrage |
| Treasury depletion | Revenue diversification |
| Validator exodus | Competitive staking rewards |

### Security Risks
| Risk | Mitigation |
|------|------------|
| Sponsorship abuse | Rate limits, blacklists |
| Free tier spam | Account age requirements |
| Fee market manipulation | Localized fees, caps |

---

*Document Version: 1.0*
*Last Updated: February 2026*
*Author: BlackBook L1 Team*
