# 🗼 P2P Tower Network Implementation Roadmap
## BlackBook L1 Distributed Consensus - 100 Node Network

**Document Version:** 1.0  
**Start Date:** February 4, 2026  
**Target Completion:** April 2026 (10-12 weeks)  
**Architecture:** 1 Leader + 99 Validators, Tower BFT Consensus

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Implementation Phases](#2-implementation-phases)
3. [Phase 1: P2P Foundation](#phase-1-p2p-foundation-weeks-1-2)
4. [Phase 2: Vote Propagation](#phase-2-vote-propagation-weeks-3-4)
5. [Phase 3: Block Replication](#phase-3-block-replication-weeks-5-6)
6. [Phase 4: Leader Election](#phase-4-leader-election-weeks-7-8)
7. [Phase 5: Catchup & Sync](#phase-5-catchup--sync-weeks-9-10)
8. [Phase 6: Production Hardening](#phase-6-production-hardening-weeks-11-12)
9. [Testing Milestones](#testing-milestones)
10. [Risk Mitigation](#risk-mitigation)

---

## 1. Current State Assessment

### ✅ What's Already Implemented (Single-Node)

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| **PoH Clock** | `src/poh_blockchain.rs` | 70% ✅ | SHA-256 chain, 600ms slots |
| **Tower BFT** | `runtime/consensus.rs` | 65% ✅ | Lockouts, fork choice, supermajority |
| **Turbine Shredder** | `src/poh_blockchain.rs` | 60% ✅ | Block→shred, FEC encoding |
| **Gulf Stream** | `src/poh_blockchain.rs` | 60% ✅ | TX forwarding to leaders |
| **Sealevel Parallel** | `src/poh_blockchain.rs` | 75% ✅ | Multi-core TX execution |
| **Leader Schedule** | `src/poh_blockchain.rs` | 65% ✅ | Stake-weighted scheduling |
| **ReDB Storage** | `src/storage/` | 90% ✅ | ACID, crash-safe |
| **gRPC Settlement** | `src/grpc/` | 85% ✅ | L1↔L2 bridge |
| **3-Shard Wallet** | `src/wallet_mnemonic/` | 100% ✅ | SSS, Vault integration |

### ❌ What's Missing (Multi-Node)

| Component | File to Create | Est. LOC | Priority |
|-----------|----------------|----------|----------|
| **P2P Gossip** | `src/network/gossip.rs` | 2,000 | 🔴 Critical |
| **Vote Propagation** | `src/consensus/voting.rs` | 1,200 | 🔴 Critical |
| **Block Replication** | `src/network/replication.rs` | 1,500 | 🔴 Critical |
| **Leader Rotation** | `src/consensus/leader.rs` | 800 | 🔴 Critical |
| **Catchup Protocol** | `src/network/catchup.rs` | 1,000 | 🟡 High |
| **Network Discovery** | `src/network/discovery.rs` | 600 | 🟡 High |
| **Hot Failover** | `src/network/failover.rs` | 1,000 | 🟢 Medium |
| **Slashing** | `src/consensus/slashing.rs` | 500 | 🟢 Medium |

### 📦 Dependencies (Already Configured)

```toml
# Cargo.toml - libp2p ready to use!
libp2p = { version = "0.54", features = [
    "tokio", "gossipsub", "kad", "mdns", 
    "noise", "yamux", "tcp", "identify", "ping"
]}
```

---

## 2. Implementation Phases

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    P2P TOWER IMPLEMENTATION TIMELINE                    │
└─────────────────────────────────────────────────────────────────────────┘

Week 1-2    Week 3-4    Week 5-6    Week 7-8    Week 9-10   Week 11-12
   │           │           │           │           │           │
   ▼           ▼           ▼           ▼           ▼           ▼
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ P2P │───▶│Vote │───▶│Block│───▶│Lead-│───▶│Catch│───▶│ 100 │
│Found│    │Prop │    │Repl │    │ er  │    │ up  │    │Node │
│ation│    │agat.│    │icat.│    │Elect│    │Sync │    │Prod │
└─────┘    └─────┘    └─────┘    └─────┘    └─────┘    └─────┘
   │           │           │           │           │           │
   ▼           ▼           ▼           ▼           ▼           ▼
3-node     Votes      Blocks     Leader     New node   Security
testnet    gossip     sync       rotation   catchup    hardening
```

---

## Phase 1: P2P Foundation (Weeks 1-2)

### Objective
Establish peer-to-peer communication layer using libp2p with gossipsub for message propagation.

### Deliverables

#### 1.1 Network Module Structure
```
src/network/
├── mod.rs           # Module exports, NetworkMessage enum
├── gossip.rs        # GossipSub protocol, peer management
├── discovery.rs     # Kademlia DHT, mDNS local discovery
├── transport.rs     # TCP/Noise/Yamux stack
└── metrics.rs       # Network statistics
```

#### 1.2 Core Types (`src/network/mod.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    // Peer Discovery
    PeerAdvertise(PeerInfo),
    PeerRequest,
    PeerResponse(Vec<PeerInfo>),
    
    // Block Propagation (Turbine)
    BlockShred(Shred),
    BlockRequest { slot: u64 },
    BlockResponse(FinalizedBlock),
    
    // Voting (Tower BFT)
    Vote(Vote),
    VoteRequest { slot: u64 },
    TowerSync(TowerSync),
    
    // Leader
    LeaderSchedule(LeaderScheduleUpdate),
    LeaderChange { new_leader: String, slot: u64 },
    
    // Health
    Ping { timestamp: u64, sender: String },
    Pong { timestamp: u64, responder: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub validator_id: String,       // bb_... address
    pub listen_addr: SocketAddr,
    pub public_key: [u8; 32],       // Ed25519 pubkey
    pub stake: u64,                 // Voting weight
    pub version: String,            // Protocol version
    pub last_slot: u64,             // Latest known slot
}
```

#### 1.3 Gossip Service (`src/network/gossip.rs`)

```rust
pub struct GossipService {
    swarm: Swarm<BlackBookBehavior>,
    peers: DashMap<String, PeerInfo>,
    message_tx: broadcast::Sender<NetworkMessage>,
    local_peer_id: PeerId,
}

impl GossipService {
    pub async fn new(config: NetworkConfig) -> Result<Self>;
    pub async fn start(&mut self) -> Result<()>;
    pub async fn broadcast(&self, msg: NetworkMessage) -> Result<()>;
    pub async fn send_to(&self, peer_id: &str, msg: NetworkMessage) -> Result<()>;
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkMessage>;
    pub fn peer_count(&self) -> usize;
    pub fn connected_peers(&self) -> Vec<PeerInfo>;
}
```

### Success Milestones - Phase 1

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M1.1** | Network module compiles | `cargo build` | No errors |
| **M1.2** | 2 nodes discover each other | `cargo run -- --node 1` + `--node 2` | "Peer connected: bb_xxx" |
| **M1.3** | Ping/Pong exchange | Local testnet | <10ms RTT |
| **M1.4** | 3-node gossip propagation | Broadcast test | All 3 receive message |
| **M1.5** | Peer list synchronization | `/peers` endpoint | All nodes see 3 peers |

### Acceptance Criteria - Phase 1

- [ ] `src/network/` directory created with all modules
- [ ] libp2p swarm initializes without panic
- [ ] 3 local nodes connect and discover each other
- [ ] Messages broadcast to all peers within 100ms
- [ ] Network health endpoint returns connected peer count
- [ ] Unit tests pass: `cargo test network`

---

## Phase 2: Vote Propagation (Weeks 3-4)

### Objective
Wire the existing Tower BFT (`runtime/consensus.rs`) to the gossip network for vote broadcast and aggregation.

### Deliverables

#### 2.1 Vote Broadcasting (`src/consensus/voting.rs`)

```rust
pub struct VoteAggregator {
    tower_bft: Arc<TowerBFT>,
    gossip: Arc<GossipService>,
    keypair: ed25519_dalek::SigningKey,
    pending_votes: DashMap<u64, Vec<Vote>>,  // slot → votes
    quorum_threshold: f64,  // 0.67 (2/3 supermajority)
}

impl VoteAggregator {
    /// Cast and broadcast our vote for a slot
    pub async fn vote(&self, slot: u64, block_hash: [u8; 32]) -> Result<()>;
    
    /// Process incoming vote from network
    pub async fn receive_vote(&self, vote: Vote) -> Result<VoteResult>;
    
    /// Check if slot has reached supermajority
    pub fn has_quorum(&self, slot: u64) -> bool;
    
    /// Get vote statistics
    pub fn vote_stats(&self, slot: u64) -> VoteStats;
}
```

#### 2.2 Vote Message Format

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator: String,          // bb_... address
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub timestamp: u64,
    pub lockout: u8,                // Exponential lockout level
    pub signature: [u8; 64],        // Ed25519 signature
}

impl Vote {
    pub fn sign(keypair: &SigningKey, slot: u64, block_hash: [u8; 32]) -> Self;
    pub fn verify(&self, pubkey: &[u8; 32]) -> bool;
}
```

### Success Milestones - Phase 2

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M2.1** | Vote signing with Ed25519 | Unit test | Valid signatures |
| **M2.2** | Vote broadcast works | 3-node test | All nodes receive vote |
| **M2.3** | Vote aggregation | 3-node vote | Quorum detected at 2/3 |
| **M2.4** | Duplicate vote rejection | Double-vote test | Second vote ignored |
| **M2.5** | Tower lockout respected | Conflicting vote | Lockout violation rejected |

### Acceptance Criteria - Phase 2

- [ ] Votes signed with Ed25519 (not SHA-256 hash)
- [ ] 3-node cluster reaches consensus on same block
- [ ] Vote aggregation detects 67% quorum
- [ ] Invalid signatures rejected
- [ ] Lockout violations prevented
- [ ] Vote latency <50ms across 3 nodes

---

## Phase 3: Block Replication (Weeks 5-6)

### Objective
Connect Turbine shredder to network layer for actual block propagation using tree topology.

### Deliverables

#### 3.1 Replication Service (`src/network/replication.rs`)

```rust
pub struct ReplicationService {
    storage: Arc<ConcurrentBlockchain>,
    shredder: TurbineShredder,
    propagator: TurbinePropagator,
    gossip: Arc<GossipService>,
    pending_shreds: DashMap<u64, ShredBuffer>,
}

impl ReplicationService {
    /// Leader broadcasts new block as shreds
    pub async fn broadcast_block(&self, block: FinalizedBlock) -> Result<()>;
    
    /// Validator receives shred
    pub async fn receive_shred(&self, shred: Shred) -> Option<FinalizedBlock>;
    
    /// Request missing block (catchup)
    pub async fn request_block(&self, slot: u64) -> Result<FinalizedBlock>;
    
    /// Get replication stats
    pub fn stats(&self) -> ReplicationStats;
}
```

#### 3.2 Turbine Tree Topology

```
                    ┌─────────┐
                    │ LEADER  │ Slot 0
                    │ Node 0  │
                    └────┬────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
     ┌─────────┐    ┌─────────┐    ┌─────────┐
     │ Node 1  │    │ Node 2  │    │ Node 3  │  Tier 1 (3 nodes)
     └────┬────┘    └────┬────┘    └────┬────┘
          │              │              │
    ┌─────┼─────┐  ┌─────┼─────┐  ┌─────┼─────┐
    ▼     ▼     ▼  ▼     ▼     ▼  ▼     ▼     ▼
   4-6   7-9   ...                              Tier 2 (9 nodes)
                         │
                    (continues)
                         │
                        ...                      Tier N

Fanout: 3 (configurable)
100 nodes = ~5 tiers
Latency: O(log₃(100)) = 4-5 hops
```

### Success Milestones - Phase 3

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M3.1** | Shred creation works | Unit test | Valid FEC shreds |
| **M3.2** | Shred broadcast | 3-node test | All receive shreds |
| **M3.3** | Block reassembly | 3-node test | Block reconstructed |
| **M3.4** | FEC recovery | Drop 1/3 shreds | Block still recovers |
| **M3.5** | Tree propagation | 10-node test | Correct tier routing |

### Acceptance Criteria - Phase 3

- [ ] Blocks shredded and broadcast via gossip
- [ ] All validators receive complete blocks
- [ ] FEC allows recovery with 33% packet loss
- [ ] Block propagation <500ms for 10 nodes
- [ ] Storage updated on all nodes
- [ ] Integration test: `cargo test replication`

---

## Phase 4: Leader Election (Weeks 7-8)

### Objective
Implement multi-validator leader rotation with stake-weighted scheduling.

### Deliverables

#### 4.1 Leader Scheduler (`src/consensus/leader.rs`)

```rust
pub struct LeaderScheduler {
    schedule: RwLock<LeaderSchedule>,
    current_epoch: AtomicU64,
    gossip: Arc<GossipService>,
    validators: DashMap<String, ValidatorStake>,
}

impl LeaderScheduler {
    /// Get leader for specific slot
    pub fn get_leader(&self, slot: u64) -> Option<String>;
    
    /// Am I the leader for this slot?
    pub fn is_my_slot(&self, slot: u64) -> bool;
    
    /// Generate schedule for next epoch
    pub async fn rotate_epoch(&self) -> Result<()>;
    
    /// Handle leader change notification
    pub async fn on_leader_change(&self, slot: u64, new_leader: &str);
}
```

#### 4.2 Epoch Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                         EPOCH STRUCTURE                          │
└─────────────────────────────────────────────────────────────────┘

1 Epoch = 432,000 slots (~3 days at 600ms/slot)

Epoch 0                          Epoch 1
├───────────────────────────────┤├───────────────────────────────┤
│ Slot 0-431,999                ││ Slot 432,000-863,999          │
│ Schedule: [L₀, L₁, L₂, ...]   ││ Schedule: [L₃, L₀, L₁, ...]   │
└───────────────────────────────┘└───────────────────────────────┘

Leader Selection Algorithm:
1. Sort validators by stake (descending)
2. Weighted random selection using VRF
3. Each validator gets slots proportional to stake
4. Minimum: 4 slots per epoch per validator
```

### Success Milestones - Phase 4

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M4.1** | Schedule generation | Unit test | Valid schedule |
| **M4.2** | Stake-weighted selection | 3-node test | Proportional slots |
| **M4.3** | Leader rotation | 10-slot test | Correct leader each slot |
| **M4.4** | Epoch transition | Boundary test | Smooth handoff |
| **M4.5** | Leader skip detection | Kill leader | Next validator takes over |

### Acceptance Criteria - Phase 4

- [ ] Leader schedule deterministically generated
- [ ] All validators agree on current leader
- [ ] Leader rotation happens every slot (600ms)
- [ ] Missed leader detected within 2 slots
- [ ] Epoch transitions are seamless
- [ ] Integration test: `cargo test leader_rotation`

---

## Phase 5: Catchup & Sync (Weeks 9-10)

### Objective
Enable new validators to sync blockchain state and join the network.

### Deliverables

#### 5.1 Catchup Protocol (`src/network/catchup.rs`)

```rust
pub struct CatchupService {
    storage: Arc<ConcurrentBlockchain>,
    gossip: Arc<GossipService>,
    current_slot: Arc<AtomicU64>,
}

impl CatchupService {
    /// Sync from genesis or snapshot
    pub async fn full_sync(&self) -> Result<u64>;
    
    /// Sync from specific slot
    pub async fn sync_from(&self, start_slot: u64) -> Result<u64>;
    
    /// Request specific block range
    pub async fn request_blocks(&self, start: u64, end: u64) -> Result<Vec<FinalizedBlock>>;
    
    /// Verify chain integrity
    pub fn verify_chain(&self, start: u64, end: u64) -> Result<bool>;
}
```

#### 5.2 Sync Modes

```
┌─────────────────────────────────────────────────────────────────┐
│                         SYNC MODES                               │
└─────────────────────────────────────────────────────────────────┘

1. FULL SYNC (New Node)
   - Download all blocks from genesis
   - Verify each block's PoH chain
   - Rebuild state from transactions
   - Time: ~24 hours for 1M blocks

2. SNAPSHOT SYNC (Recommended)
   - Download latest state snapshot
   - Verify Merkle root matches network consensus
   - Download blocks since snapshot
   - Time: ~1 hour

3. WARP SYNC (Fast)
   - Trust latest finalized state from supermajority
   - Download only last 1000 blocks
   - Start participating immediately
   - Time: ~5 minutes
```

### Success Milestones - Phase 5

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M5.1** | Block range request | Unit test | Blocks returned |
| **M5.2** | New node syncs | Start node 4 | Catches up to slot N |
| **M5.3** | Snapshot creation | Operator command | Valid snapshot file |
| **M5.4** | Snapshot restore | New node | Syncs in <1 hour |
| **M5.5** | Chain verification | Integrity check | All blocks valid |

### Acceptance Criteria - Phase 5

- [ ] New validator syncs full chain within 24 hours
- [ ] Snapshot sync works within 1 hour
- [ ] Warp sync joins network in <5 minutes
- [ ] Chain integrity verified after sync
- [ ] Node begins voting after catchup complete
- [ ] Integration test: `cargo test catchup`

---

## Phase 6: Production Hardening (Weeks 11-12)

### Objective
Scale to 100 nodes with security hardening, monitoring, and failover.

### Deliverables

#### 6.1 Security Hardening

- [ ] **Slashing**: Detect and penalize double-voting
- [ ] **Rate Limiting**: Max 1000 msgs/sec per peer
- [ ] **DDoS Protection**: Blacklist misbehaving peers
- [ ] **Signature Verification**: All messages Ed25519 signed
- [ ] **Encryption**: All traffic Noise-encrypted

#### 6.2 Monitoring

```rust
pub struct NetworkMetrics {
    pub connected_peers: Gauge,
    pub messages_sent: Counter,
    pub messages_received: Counter,
    pub block_propagation_ms: Histogram,
    pub vote_latency_ms: Histogram,
    pub consensus_rounds: Counter,
}
```

#### 6.3 Failover

```rust
pub struct FailoverManager {
    primary_leader: String,
    backup_leaders: Vec<String>,
    last_heartbeat: Instant,
    failover_threshold: Duration,  // 3 slots = 1.8s
}

impl FailoverManager {
    pub async fn monitor_leader(&self) -> Result<()>;
    pub async fn trigger_failover(&self) -> Result<()>;
    pub async fn become_leader(&self) -> Result<()>;
}
```

### Success Milestones - Phase 6

| Milestone | Description | Test Command | Expected Result |
|-----------|-------------|--------------|-----------------|
| **M6.1** | 10-node stable | Run 1 hour | No crashes |
| **M6.2** | 50-node stable | Run 1 hour | <1% message loss |
| **M6.3** | 100-node stable | Run 1 hour | Consensus maintained |
| **M6.4** | Leader failover | Kill leader | Backup takes over <2s |
| **M6.5** | Slashing works | Double-vote | Validator penalized |
| **M6.6** | Monitoring works | Grafana dashboard | All metrics visible |

### Acceptance Criteria - Phase 6

- [ ] 100 nodes maintain consensus for 24 hours
- [ ] Block finality <20 seconds
- [ ] Message propagation <1 second network-wide
- [ ] Leader failover <3 seconds
- [ ] Slashing detects 100% of double-votes
- [ ] Prometheus metrics exported
- [ ] Grafana dashboard deployed

---

## Testing Milestones

### Unit Tests (Per Phase)

```bash
# Phase 1
cargo test network::gossip
cargo test network::discovery

# Phase 2
cargo test consensus::voting
cargo test consensus::vote_aggregation

# Phase 3
cargo test network::replication
cargo test network::turbine

# Phase 4
cargo test consensus::leader
cargo test consensus::epoch

# Phase 5
cargo test network::catchup
cargo test network::sync

# Phase 6
cargo test consensus::slashing
cargo test network::failover
```

### Integration Tests

| Test | Nodes | Duration | Success Criteria |
|------|-------|----------|------------------|
| `test_3_node_consensus` | 3 | 5 min | All nodes agree on 100 blocks |
| `test_10_node_scaling` | 10 | 15 min | <500ms block propagation |
| `test_leader_rotation` | 5 | 10 min | 10 successful leader changes |
| `test_node_join` | 4 | 30 min | New node syncs and votes |
| `test_node_crash_recovery` | 5 | 20 min | Crashed node rejoins |
| `test_network_partition` | 6 | 30 min | Heals after partition |
| `test_100_node_load` | 100 | 60 min | 10,000 TPS sustained |

### Load Tests

```bash
# Sustained load test
cargo run --release -- \
    --nodes 100 \
    --duration 3600 \
    --tps 10000 \
    --validate-consensus

# Expected output:
# ✅ 100 nodes online
# ✅ 36,000,000 transactions processed
# ✅ 0 consensus failures
# ✅ Avg block time: 598ms
# ✅ Avg finality: 19.2s
```

---

## Risk Mitigation

### High-Risk Items

| Risk | Impact | Mitigation |
|------|--------|------------|
| **libp2p complexity** | High | Start with minimal gossipsub, expand later |
| **Vote ordering** | High | Use PoH timestamps for deterministic ordering |
| **Network partitions** | High | Byzantine fault tolerance (33% threshold) |
| **Leader DoS** | Medium | Backup leader rotation, rate limiting |
| **State divergence** | Critical | Merkle roots in every block |

### Rollback Plan

Each phase has a clean rollback:
1. **Phase 1**: Revert to single-node mode
2. **Phase 2**: Disable vote propagation, use local voting
3. **Phase 3**: Disable shred propagation, direct block sync
4. **Phase 4**: Fixed leader mode (no rotation)
5. **Phase 5**: Manual sync via gRPC
6. **Phase 6**: Disable slashing, manual monitoring

---

## Summary

### Total Estimated LOC

| Phase | New Code | Modified | Tests |
|-------|----------|----------|-------|
| Phase 1 | 2,800 | 200 | 500 |
| Phase 2 | 1,200 | 300 | 400 |
| Phase 3 | 1,500 | 500 | 500 |
| Phase 4 | 800 | 400 | 300 |
| Phase 5 | 1,000 | 200 | 400 |
| Phase 6 | 2,100 | 500 | 600 |
| **Total** | **9,400** | **2,100** | **2,700** |

### Timeline Summary

```
Week 1-2:  P2P Foundation      → 3-node testnet working
Week 3-4:  Vote Propagation    → Votes gossip, quorum detected
Week 5-6:  Block Replication   → Blocks sync across nodes
Week 7-8:  Leader Election     → Multi-validator rotation
Week 9-10: Catchup & Sync      → New nodes can join
Week 11-12: Production         → 100-node network stable
```

### Go/No-Go Checkpoints

| Checkpoint | Week | Criteria | Decision |
|------------|------|----------|----------|
| **CP1** | 2 | 3 nodes gossip successfully | Continue/Pivot |
| **CP2** | 4 | Votes reach quorum | Continue/Pivot |
| **CP3** | 6 | Blocks propagate reliably | Continue/Pivot |
| **CP4** | 8 | Leader rotation works | Continue/Pivot |
| **CP5** | 10 | New nodes can sync | Continue/Pivot |
| **CP6** | 12 | 100 nodes stable | Launch/Delay |

---

## Ready to Begin?

**Pre-Implementation Checklist:**

- [ ] Review this document with team
- [ ] Set up 3 development machines for local testnet
- [ ] Configure CI/CD for multi-node testing
- [ ] Create branch: `feature/p2p-tower-network`
- [ ] Set up Prometheus + Grafana for monitoring

**First Step:**
Create `src/network/mod.rs` with `NetworkMessage` enum and module structure.

---

*Document maintained by: BlackBook L1 Team*  
*Last updated: February 4, 2026*
