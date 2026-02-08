# 🔥 BlackBook L1 - Hot Upgrade System Guide

**Document Version:** 1.0  
**Target:** Production Network (100 Validators)  
**Upgrade Model:** Rolling Blue-Green Deployment  
**Downtime Target:** Zero (Service continues during upgrade)  
**First Upgrade:** FROST Institutional Wallets (Phase 2)

---

## Table of Contents

1. [What is a Hot Upgrade?](#what-is-a-hot-upgrade)
2. [Why Hot Upgrades Matter](#why-hot-upgrades-matter)
3. [Our First Hot Upgrade: FROST Wallets](#our-first-hot-upgrade-frost-wallets)
4. [Hot Upgrade Architecture](#hot-upgrade-architecture)
5. [Upgrade Process (Step-by-Step)](#upgrade-process-step-by-step)
6. [Implementation Requirements](#implementation-requirements)
7. [Safety Mechanisms](#safety-mechanisms)
8. [Testing Strategy](#testing-strategy)
9. [`Rollback Procedures](#rollback-procedures)
10. [FROST Wallet Integration Details](#frost-wallet-integration-details)

---

## 1. What is a Hot Upgrade?

A **hot upgrade** is a software update that happens while the system is running in production, with **zero downtime** for users.

### Traditional Upgrade (❌ Downtime)

```
1. ANNOUNCE: "Maintenance window 2AM-6AM"
2. STOP: Shut down all validators
3. UPGRADE: Deploy new software
4. TEST: Verify functionality
5. START: Bring network back online
Result: 4 hours of downtime
```

### Hot Upgrade (✅ Zero Downtime)

```
1. PREPARE: New version deployed alongside old version
2. TEST: New version verified on staging network
3. MIGRATE: 10 validators at a time switch to new version
4. VERIFY: Check consensus still works (67+ validators online)
5. CONTINUE: Repeat until all 100 validators upgraded
Result: 0 seconds of downtime
```

---

## 2. Why Hot Upgrades Matter

### For Users
- ✅ **No service interruption**: Deposits, withdrawals, and bets continue
- ✅ **No transaction delays**: Finality stays at 19.2 seconds
- ✅ **No schedule coordination**: Upgrades happen transparently

### For BlackBook
- ✅ **Faster iteration**: Ship new features weekly instead of monthly
- ✅ **Competitive advantage**: Add FROST wallets while competitors plan maintenance windows
- ✅ **Lower risk**: Can rollback instantly if issues detected

### For Validators
- ✅ **No coordination burden**: Automated upgrade orchestration
- ✅ **Gradual rollout**: Issues detected before affecting entire network
- ✅ **Rollback safety**: Can revert to old version instantly

---

## 3. Our First Hot Upgrade: FROST Wallets

**Timeline:** 4-6 weeks after mainnet launch  
**Upgrade Type:** Additive feature (backward compatible)

### What Ships at Launch (v1.0.0)

```
┌─────────────────────────────────────────────────────┐
│           L1 MVP (Consumer Wallets Only)            │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ✅ Mnemonic SSS Wallets (BIP-39 + Shamir 2-of-3)  │
│  ✅ USDT ↔ $BB Settlement (Tier 1 Gateway)         │
│  ✅ Bridge to L2 (bb_locked_on_l2 tracking)        │
│  ✅ 65,000+ TPS (Sealevel parallel execution)      │
│  ✅ 19.2 sec finality (Tower BFT consensus)        │
│                                                     │
│  ❌ FROST Institutional Wallets (Phase 2)          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### What Gets Added via Hot Upgrade (v1.1.0)

```
┌─────────────────────────────────────────────────────┐
│         L1 Post-Upgrade (Hybrid Wallets)            │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ✅ Mnemonic SSS Wallets (unchanged)               │
│  ✅ FROST Institutional Wallets (NEW!)              │
│     • DKG (Distributed Key Generation)             │
│     • Threshold signatures (2-of-3)                │
│     • OPAQUE authentication                        │
│     • No recovery phrase (guardian-based)          │
│  ✅ All existing functionality preserved            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Why FROST First?

1. **Market Demand**: DAOs and treasuries need institutional-grade security
2. **Revenue Driver**: Premium feature for high-value accounts
3. **Backward Compatible**: Doesn't affect existing mnemonic wallets
4. **Low Risk**: New code path, doesn't touch critical settlement logic

---

## 4. Hot Upgrade Architecture

### Network Topology During Upgrade

```
┌─────────────────────────────────────────────────────────────────┐
│                     100-NODE NETWORK                            │
│                    (Mid-Upgrade State)                          │
└─────────────────────────────────────────────────────────────────┘

  OLD VERSION (v1.0.0)                NEW VERSION (v1.1.0)
  ───────────────────                 ───────────────────
  60 Validators                       40 Validators
  ✅ Mnemonic Wallets                 ✅ Mnemonic Wallets
  ❌ FROST Wallets                    ✅ FROST Wallets (NEW!)

  Both versions:
  • Speak same consensus protocol (Tower BFT)
  • Validate same transaction types
  • Agree on block finality (67+ votes needed)

  Upgrade Flow:
  1. Start: 100 nodes on v1.0.0
  2. Batch 1: 10 nodes → v1.1.0 (90 old + 10 new)
  3. Batch 2: 10 nodes → v1.1.0 (80 old + 20 new)
  4. ...continue...
  5. Batch 10: Last 10 nodes → v1.1.0 (100 new)
  6. Complete: All nodes on v1.1.0
```

### Version Compatibility Matrix

| Component | v1.0.0 | v1.1.0 | Compatible? |
|-----------|--------|--------|-------------|
| **PoH Block Format** | Same | Same | ✅ Yes |
| **Tower BFT Voting** | Same | Same | ✅ Yes |
| **Transaction Types** | 6 variants | 7 variants | ✅ Yes (additive) |
| **Consensus Rules** | Same | Same | ✅ Yes |
| **P2P Protocol** | v1 | v1 | ✅ Yes |
| **ReDB Schema** | v1 | v1 | ✅ Yes |

**Key Insight:** Old validators can validate new transactions (FROST wallets) because they see them as standard Ed25519 signatures. The FROST ceremony happens client-side.

---

## 5. Upgrade Process (Step-by-Step)

### Phase 1: Preparation (48 hours before)

```bash
# 1. Deploy new binary to all validators (but don't run it yet)
for validator in {001..100}; do
    scp layer1-v1.1.0 validator${validator}:/opt/blackbook/bin/
done

# 2. Verify checksums (ensure no corruption)
sha256sum /opt/blackbook/bin/layer1-v1.1.0
# Expected: a3f7b2c9... (published checksum)

# 3. Test on staging network (10 nodes)
./scripts/test-upgrade-staging.sh --version v1.1.0

# 4. Announce upgrade to community
curl -X POST https://api.blackbook.network/announcements \
  -d '{"message": "FROST wallets upgrade scheduled for 2025-03-15 00:00 UTC"}'
```

### Phase 2: Rolling Upgrade (2-3 hours)

```bash
# Automated upgrade script (runs on orchestration server)
./scripts/rolling-upgrade.sh \
  --version v1.1.0 \
  --batch-size 10 \
  --wait-time 10m \
  --max-concurrent 1

# What it does:
# 1. SELECT: Pick 10 validators (non-leaders, spread across regions)
# 2. STOP: Gracefully shut down old binary
# 3. START: Launch new binary (v1.1.0)
# 4. VERIFY: Check if validator joins consensus (casts votes)
# 5. WAIT: 10 minutes to observe stability
# 6. REPEAT: Move to next batch

# Progress monitoring:
watch -n 5 'curl -s https://api.blackbook.network/upgrade-status | jq'
```

### Phase 3: Verification (30 minutes after)

```bash
# Check all validators are on new version
./scripts/check-versions.sh
# Expected output:
# v1.0.0: 0 validators
# v1.1.0: 100 validators ✅

# Test FROST wallet registration
curl -X POST https://validator001.blackbook.network/wallet/frost/register \
  -d '{"participant_id": 1, "threshold": 2, "total": 3}'

# Verify consensus still works
./scripts/run-tps-test.sh --duration 5m
# Expected: 65,000+ TPS maintained
```

### Phase 4: Celebrate 🎉

```
Upgrade complete! FROST wallets now available.
- Total downtime: 0 seconds
- Failed validators: 0
- Consensus interruptions: 0
- User-facing issues: 0
```

---

## 6. Implementation Requirements

### File: `src/network/upgrades.rs` (NEW)

```rust
/// Hot upgrade orchestration system
pub struct UpgradeManager {
    /// Current network version
    current_version: Arc<AtomicU64>,
    
    /// Validators by version (address -> version)
    validator_versions: Arc<DashMap<String, Version>>,
    
    /// Upgrade schedule
    upgrade_plan: Option<UpgradePlan>,
    
    /// Gossip service for version discovery
    gossip: Arc<GossipService>,
}

pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub git_hash: String,
}

pub struct UpgradePlan {
    pub target_version: Version,
    pub batch_size: usize,           // 10 validators per batch
    pub wait_time: Duration,         // 10 minutes between batches
    pub rollback_threshold: f64,     // 0.05 (5% failure triggers rollback)
    pub start_time: SystemTime,
}

impl UpgradeManager {
    /// Propose upgrade to network
    pub async fn propose_upgrade(
        &self,
        target_version: Version,
        plan: UpgradePlan,
    ) -> Result<(), UpgradeError> {
        // 1. Broadcast upgrade proposal to all validators
        let proposal = UpgradeProposal {
            version: target_version,
            plan: plan.clone(),
            proposer: self.local_address.clone(),
            timestamp: SystemTime::now(),
        };
        
        self.gossip.broadcast(GossipMessage::UpgradeProposal(proposal)).await?;
        
        // 2. Wait for 50%+ approval
        let votes = self.collect_votes(Duration::from_secs(3600)).await?;
        if votes.approvals < self.total_validators / 2 {
            return Err(UpgradeError::InsufficientVotes);
        }
        
        // 3. Schedule upgrade
        self.upgrade_plan = Some(plan);
        Ok(())
    }
    
    /// Execute upgrade for a batch of validators
    pub async fn execute_batch(
        &self,
        batch: Vec<String>,
    ) -> Result<BatchResult, UpgradeError> {
        let mut results = Vec::new();
        
        for validator in batch {
            // Signal validator to upgrade
            self.gossip.send_to(
                &validator,
                GossipMessage::UpgradeSignal {
                    version: self.upgrade_plan.as_ref().unwrap().target_version.clone(),
                }
            ).await?;
            
            // Wait for validator to rejoin with new version
            let rejoined = self.wait_for_rejoin(&validator, Duration::from_secs(300)).await?;
            results.push((validator.clone(), rejoined));
        }
        
        Ok(BatchResult { results })
    }
    
    /// Check if upgrade is safe to continue
    pub fn is_upgrade_safe(&self) -> bool {
        // 1. Check consensus (67+ validators voting)
        let voting_validators = self.count_voting_validators();
        if voting_validators < 67 {
            return false;
        }
        
        // 2. Check failure rate
        let failed = self.count_failed_upgrades();
        let total = self.count_attempted_upgrades();
        let failure_rate = failed as f64 / total as f64;
        
        failure_rate < 0.05 // 5% threshold
    }
    
    /// Rollback to previous version
    pub async fn rollback(&self) -> Result<(), UpgradeError> {
        warn!("🚨 ROLLBACK INITIATED: Upgrade failed safety checks");
        
        // Signal all upgraded validators to revert
        for validator in self.validator_versions.iter() {
            if validator.value() == &self.upgrade_plan.as_ref().unwrap().target_version {
                self.gossip.send_to(
                    validator.key(),
                    GossipMessage::RollbackSignal {
                        revert_to: self.current_version.load(Ordering::Relaxed),
                    }
                ).await?;
            }
        }
        
        Ok(())
    }
}
```

### File: `src/network/gossip.rs` (UPDATE)

```rust
pub enum GossipMessage {
    // Existing messages...
    PeerAdvertisement(PeerInfo),
    BlockShred(Shred),
    ValidatorVote(Vote),
    
    // NEW: Upgrade messages
    UpgradeProposal(UpgradeProposal),
    UpgradeVote { version: Version, approve: bool },
    UpgradeSignal { version: Version },
    RollbackSignal { revert_to: u64 },
    VersionAnnouncement { version: Version, validator: String },
}

pub struct UpgradeProposal {
    pub version: Version,
    pub plan: UpgradePlan,
    pub proposer: String,
    pub timestamp: SystemTime,
    pub signature: [u8; 64],
}
```

### File: `src/main_v4.rs` (UPDATE)

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ... existing initialization ...
    
    // NEW: Initialize upgrade manager
    let upgrade_manager = Arc::new(UpgradeManager::new(
        config.version.clone(),
        total_validators,
        gossip_service.clone(),
    ));
    
    // NEW: Version announcement loop
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            upgrade_manager.announce_version().await;
        }
    });
    
    // ... rest of initialization ...
}
```

---

## 7. Safety Mechanisms

### 1. Version Handshake (Consensus Protocol)

```rust
/// Every block includes producer's version
pub struct POHBlock {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub producer_version: Version,  // NEW: Track who produced this block
}

/// Validators check version compatibility
impl TowerBFT {
    fn can_vote_on_block(&self, block: &POHBlock) -> bool {
        // Allow voting if version difference is <= 1 minor version
        let my_version = self.my_version();
        let producer_version = &block.producer_version;
        
        (my_version.major == producer_version.major) &&
        (my_version.minor.abs_diff(producer_version.minor) <= 1)
    }
}
```

### 2. Quorum Enforcement

```
Upgrade Rule: Never upgrade if it would drop quorum below 67 validators

Example:
- Current: 80 validators online
- Batch size: 10
- After upgrade: 70 online (worst case: 10 stuck in upgrade)
- Quorum: 67 required
- Status: ✅ SAFE (70 > 67)

Example (unsafe):
- Current: 70 validators online
- Batch size: 10
- After upgrade: 60 online (worst case)
- Quorum: 67 required
- Status: ❌ UNSAFE (60 < 67)
- Action: SKIP this batch, wait for more validators to come online
```

### 3. Canary Deployment

```
Phase 1: Test on 3 validators (3% of network)
  ↓
Wait 30 minutes, check for:
  • Consensus participation
  • Transaction processing
  • Error logs
  ↓
Phase 2: If healthy, upgrade 10 validators (10% of network)
  ↓
Wait 10 minutes, check again
  ↓
Phase 3: If still healthy, upgrade remaining 87 validators
  ↓
Done!
```

### 4. Automatic Rollback Triggers

```rust
pub enum RollbackTrigger {
    /// Quorum dropped below 67
    QuorumLoss,
    
    /// >5% of upgraded validators failed to rejoin
    HighFailureRate,
    
    /// No blocks finalized in 60 seconds
    ConsensusStall,
    
    /// Upgraded validators producing invalid blocks
    InvalidBlocks,
    
    /// Manual operator intervention
    ManualTrigger,
}
```

---

## 8. Testing Strategy

### 8.1 Staging Network (10 Nodes)

```bash
# Deploy staging network with 10 validators
./scripts/deploy-staging.sh

# Run upgrade simulation
./scripts/test-upgrade.sh \
  --from-version v1.0.0 \
  --to-version v1.1.0 \
  --batch-size 3 \
  --chaos-monkey enabled

# Chaos monkey injects:
# - Random validator crashes (20% probability)
# - Network partitions (10% probability)
# - Disk full errors (5% probability)
```

### 8.2 Shadow Upgrade (Production Data, Staging Nodes)

```bash
# Replay production traffic on staging network
./scripts/shadow-upgrade.sh \
  --replay-from mainnet \
  --start-time "2025-03-14 00:00" \
  --duration 24h

# This tests:
# - Real transaction patterns
# - Real account states
# - Real consensus behavior
```

### 8.3 Canary Validators (Production Network)

```
Step 1: Upgrade 3 validators (validator098, validator099, validator100)
Step 2: Wait 30 minutes, monitor metrics:
  - Votes cast: Should match expected rate (1/600ms)
  - Blocks produced: Should match leader schedule
  - Error rate: Should be <0.1%
Step 3: If healthy, proceed to full upgrade
```

---

## 9. Rollback Procedures

### Scenario 1: Detected Before Completion

```bash
# Operator notices consensus stall
./scripts/check-consensus.sh
# Output: ⚠️ No blocks finalized in last 90 seconds

# Trigger rollback
./scripts/rollback-upgrade.sh --immediate

# What happens:
# 1. All validators on v1.1.0 receive "ROLLBACK" signal
# 2. They stop current binary, restart v1.0.0 binary
# 3. Consensus resumes within 30 seconds
# 4. Users experience: 1-2 missed slots (1.2 sec delay)
```

### Scenario 2: Detected After Completion

```bash
# Upgrade completed, but FROST wallets have a bug
# Bug: DKG ceremony fails for 50% of participants

# Immediate rollback:
./scripts/rollback-upgrade.sh --all-validators

# What happens:
# 1. All 100 validators revert to v1.0.0
# 2. FROST wallet endpoints return 503 (unavailable)
# 3. Mnemonic wallets continue working (unaffected)
# 4. Users experience: FROST unavailable until fixed

# Fix & re-deploy:
# 1. Fix bug in v1.1.1
# 2. Test on staging
# 3. Deploy v1.1.1 via hot upgrade
```

---

## 10. FROST Wallet Integration Details

### What Gets Added in v1.1.0

#### New Files

```
src/
  wallet_frost/              # NEW DIRECTORY
    mod.rs                   # Module entry point
    dkg.rs                   # Distributed Key Generation
    signing.rs               # Threshold signing ceremony
    opaque.rs                # OPAQUE authentication
    frost_signer.rs          # FrostSigner implementation
    handlers.rs              # HTTP API endpoints
```

#### New Dependencies (Cargo.toml)

```toml
[dependencies]
# FROST threshold signatures
frost-ed25519 = "2.0.0"
frost-core = "2.0.0"

# OPAQUE password authentication
opaque-ke = "3.0.0"

# Verifiable Secret Sharing for DKG
vsss-rs = "4.0"

# Encryption for shard storage
chacha20poly1305 = "0.10"
```

#### Updated Files

##### `src/wallet_mnemonic/mod.rs`

```rust
/// Wallet security mode enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletSecurityMode {
    /// Consumer track: BIP-39 mnemonic + Shamir SSS
    Deterministic(MnemonicConfig),
    
    /// Institutional track: FROST threshold signatures (v1.1.0+)
    Threshold(ThresholdConfig),  // ADDED
}

/// FROST wallet configuration (v1.1.0+)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub threshold: u16,          // e.g., 2 of 3
    pub participants: u16,       // Total shard holders
    pub guardian_shard_id: String,
    pub has_recovery_guardian: bool,
}
```

##### `src/wallet_mnemonic/signer.rs`

```rust
/// Signer factory (updated)
pub fn create_signer_for_wallet(
    metadata: &WalletMetadata,
    password: Option<&str>,
    shares: Option<&[SecureShare]>,
) -> Result<Box<dyn WalletSigner>, SignerError> {
    match &metadata.security_mode {
        WalletSecurityMode::Deterministic(_) => {
            // Existing mnemonic signer logic
            Ok(Box::new(MnemonicSigner::new(...)))
        }
        
        // NEW: FROST wallet support
        WalletSecurityMode::Threshold(_) => {
            Ok(Box::new(FrostSigner::new(...)))
        }
    }
}
```

##### `src/main_v4.rs`

```rust
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ... existing initialization ...
    
    // NEW: Initialize FROST wallet handlers (v1.1.0+)
    let frost_handlers = if version >= Version::new(1, 1, 0) {
        Some(Arc::new(FrostHandlers::new(
            storage.clone(),
            consensus.clone(),
        )))
    } else {
        None
    };
    
    // ... rest of initialization ...
}
```

#### New API Endpoints (v1.1.0)

```rust
// FROST wallet registration (DKG ceremony)
POST /wallet/frost/register
  Body: {
    "participant_id": 1,
    "threshold": 2,
    "total_participants": 3
  }
  Response: {
    "session_id": "dkg_session_abc123",
    "round_1_commitments": [...],
    "timeout": 300  // 5 minutes
  }

// FROST signing ceremony
POST /wallet/frost/sign
  Body: {
    "wallet_address": "bb_ABC123...",
    "message": "0x1234...",
    "participant_id": 1,
    "session_id": "sign_xyz789"
  }
  Response: {
    "partial_signature": "0xabcd...",
    "aggregated": false,
    "waiting_for": [2, 3]
  }

// FROST wallet info
GET /wallet/frost/{address}
  Response: {
    "address": "bb_ABC123...",
    "public_key": "0x...",
    "security_mode": "Threshold",
    "threshold": 2,
    "participants": 3,
    "created_at": 1678886400
  }
```

### Backward Compatibility

```rust
// Old validators (v1.0.0) see FROST transactions as standard Ed25519
impl POHBlockchain {
    fn validate_transaction(&self, tx: &Transaction) -> bool {
        match tx.tx_type {
            // OLD: Only knows about mnemonic wallets
            TxType::Transfer => {
                ed25519_dalek::verify(&tx.signature, &tx.message, &tx.public_key)
            }
            
            // NEW: FROST wallets produce valid Ed25519 signatures too!
            // Old validators don't care about the ceremony - they just verify the final sig
            _ => ed25519_dalek::verify(&tx.signature, &tx.message, &tx.public_key)
        }
    }
}
```

**Key Insight:** FROST produces standard Ed25519 signatures. Old validators don't know about the threshold ceremony - they just verify the final aggregated signature like any other transaction.

---

## Conclusion

**Hot upgrades transform BlackBook L1 from a static blockchain into a living, evolving protocol.**

**Timeline for FROST Launch:**

```
Week 0: Mainnet launch (v1.0.0)
  └─ Mnemonic wallets only
  └─ Collect user feedback

Week 2-4: Develop FROST integration
  └─ Implement wallet_frost/ module
  └─ Test on staging network
  └─ Security audit

Week 5: Hot upgrade (v1.0.0 → v1.1.0)
  └─ Zero downtime
  └─ FROST wallets available
  └─ Mnemonic wallets continue working

Week 6+: Monitor & iterate
  └─ Track FROST adoption
  └─ Fix any issues via hot patches
```

**Benefits of This Approach:**

1. ✅ **Ship early**: Launch with proven BIP-39 wallets users understand
2. ✅ **Iterate fast**: Add FROST without scheduling maintenance windows
3. ✅ **Learn in production**: Real user feedback before institutional rollout
4. ✅ **Stay competitive**: Competitors still planning "Phase 2" while we ship it live

---

*Ready for zero-downtime evolution! 🚀*
