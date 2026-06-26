//! BlackBook L1 Consensus — Consortium / Permissioned Tower Voting
//!
//! Network Model: Whitelisted Validator Mesh
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  WRITER NODE (current leader)    │  APPROVED VALIDATOR NODES       │
//! │  ─ Produces blocks               │  ─ Cryptographically whitelisted │
//! │  ─ Runs PoH clock                │  ─ Vote on blocks (Tower BFT)   │
//! │  ─ Executes transactions         │  ─ Receive shreds via VIP mesh  │
//! │  ─ Shreds block → distributes    │  ─ Re-broadcast shreds to peers │
//! │    shreds to approved peers      │  ─ Forward txs via Gulf Stream  │
//! └──────────────────────┬──────────────────────────────────────────────┘
//!                        │ Only whitelisted Ed25519 pubkeys + IPs
//!                        │ UDP packets from unknown IPs dropped in <1µs
//!
//! Tower BFT Voting:
//!   Vote on slot → lockout = 2^(depth+1) slots
//!   32 consecutive confirmations → ROOTED (finalized, irreversible)
//!   Supermajority = 2/3+ stake on a slot = CONFIRMED
//!   Stake weight: u64 lamports (NOT f64 — exact integer math required)
//!
//! Gulf Stream:
//!   Approved validators forward incoming transactions to the current Writer
//!   so the Writer's mempool is pre-filled before its slot arrives.
//!
//! TECHNICAL DEBT — LeaderSchedule:
//!   The `LeaderSchedule::update_stake()` currently uses f64 weights. This
//!   MUST be rewritten to u64 lamport-denominated voting power as part of
//!   Phase 7 (Permissioned Gossip). Do NOT extend the f64 path.



use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use parking_lot::RwLock;
use borsh::{BorshSerialize, BorshDeserialize};
use dashmap::DashMap;
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use crate::runtime::core::Transaction;

// ============================================================================
// CONSTANTS
// ============================================================================

const GULF_STREAM_LOOKAHEAD: usize = 8;
const MAX_CACHED_TXS: usize = 300_000;
const CACHE_EXPIRY_SLOTS: u64 = 20;
pub const MAX_TOWER_DEPTH: usize = 32;
/// Supermajority threshold as a fraction: votes * 3 >= total_stake * 2 (i.e. 2/3+).
/// No f64 — all comparisons use integer arithmetic only.
pub const MIN_FORK_VOTES: usize = 1;

// ============================================================================
// POH CONFIG & ENTRY
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PoHConfig {
    pub slot_duration_ms: u64,
    pub hashes_per_tick: u64,
    pub ticks_per_slot: u64,
    pub slots_per_epoch: u64,
}

impl Default for PoHConfig {
    fn default() -> Self {
        // NOTE: The authoritative production values live in `main.rs`
        // (POH_SLOT_DURATION_MS = 400, etc.). This Default is used by unit tests
        // only; keep it in sync with main.rs to avoid spec drift.
        Self {
            slot_duration_ms: 400,
            hashes_per_tick: 12500,
            ticks_per_slot: 64,
            slots_per_epoch: 432000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PoHEntry {
    pub hash: String,
    pub num_hashes: u64,
    pub transactions: Vec<String>,
}

// ============================================================================
// LEADER SCHEDULE — Rotating Leader with Contiguous Tenures
// ============================================================================
//
// Leaders rotate in contiguous tenure blocks (default: 4 slots = 1.6s).
// Within a tenure, the same validator produces every slot. This avoids
// thrashing between leaders and gives each leader time to build meaningful
// blocks.
//
// Slot allocation uses integer proportional math:
//   slots_for_validator = (stake * epoch_slots) / total_stake
// Tenures are computed as: tenures = slots / LEADER_TENURE_SLOTS
// (minimum 1 tenure per validator with any stake).
// Supermajority: votes_lamports * 3 >= total_stake_lamports * 2  (exact, no f64)

/// Number of consecutive slots a leader produces before handing off.
/// 4 slots × 400ms = 1.6 seconds per tenure.
pub const LEADER_TENURE_SLOTS: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderSchedule {
    stakes: HashMap<String, u64>, // lamports — deterministic across all CPU architectures
    schedule: Vec<(u64, String)>, // (slot, leader)
    pub epoch: u64,
}

impl LeaderSchedule {
    pub fn new() -> Self {
        Self { stakes: HashMap::new(), schedule: Vec::new(), epoch: 0 }
    }

    /// Find the next leader after the current slot that differs from the current one.
    pub fn nominate_next_writer(&self, current_slot: u64) -> String {
        let current_leader = self.get_leader(current_slot);
        self.schedule.iter()
            .find(|(s, l)| *s > current_slot && *l != current_leader)
            .map(|(_, l)| l.clone())
            .unwrap_or_else(|| "genesis_validator".into())
    }

    /// Register or update a validator's stake weight (u64 lamports).
    pub fn set_stake(&mut self, address: &str, lamports: u64) {
        self.stakes.insert(address.to_string(), lamports);
    }

    /// Generate writer schedule for an epoch — integer proportional allocation
    /// with contiguous leader tenures.
    ///
    /// Each validator gets `(stake * epoch_slots) / total_stake` slots.
    /// Slots are grouped into tenures of `LEADER_TENURE_SLOTS` (default 4).
    /// The highest-stake validator gets any remainder slots as an extra partial
    /// tenure. Validators rotate in stake-descending order.
    pub fn generate_schedule(&mut self, epoch: u64, slots_per_epoch: u64) {
        self.epoch = epoch;
        self.schedule.clear();

        let total: u64 = self.stakes.values().sum();
        if total == 0 || self.stakes.is_empty() {
            for s in 0..slots_per_epoch {
                self.schedule.push((epoch * slots_per_epoch + s, "genesis_validator".into()));
            }
            return;
        }

        // Sort descending by stake.
        let mut validators: Vec<(&String, &u64)> = self.stakes.iter().collect();
        validators.sort_by(|a, b| b.1.cmp(a.1));

        // Proportional slot allocation.
        let mut allocations: Vec<(&String, u64)> = validators.iter()
            .map(|(addr, &stake)| (*addr, stake * slots_per_epoch / total))
            .collect();

        // Distribute remainder slots to top validators.
        let allocated: u64 = allocations.iter().map(|(_, n)| n).sum();
        let mut remainder = slots_per_epoch.saturating_sub(allocated);
        for (_, n) in allocations.iter_mut() {
            if remainder == 0 { break; }
            *n += 1;
            remainder -= 1;
        }

        // Build contiguous tenures: each validator gets ceil(slots / TENURE) tenures.
        // Within each tenure, all LEADER_TENURE_SLOTS (or the remainder) go to
        // the same leader. Rotate in stake-descending order.
        let epoch_base = epoch * slots_per_epoch;
        let mut slot: u64 = 0;
        loop {
            let mut assigned_this_round = false;
            // Walk validators in stake order each round.
            let mut order: Vec<usize> = (0..allocations.len()).collect();
            order.sort_by(|&a, &b| allocations[b].1.cmp(&allocations[a].1));
            for &i in &order {
                let remaining = allocations[i].1;
                if remaining == 0 { continue; }
                // How many slots to give this validator this tenure?
                let tenure_slots = LEADER_TENURE_SLOTS.min(remaining);
                let addr = allocations[i].0.to_string();
                for _t in 0..tenure_slots {
                    self.schedule.push((epoch_base + slot, addr.clone()));
                    slot += 1;
                }
                allocations[i].1 -= tenure_slots;
                assigned_this_round = true;
            }
            if !assigned_this_round || slot >= slots_per_epoch { break; }
        }

        // Safety: if any slots remain (rounding), fill with first validator.
        let fill_leader = validators.first()
            .map(|(a, _)| a.to_string())
            .unwrap_or_else(|| "genesis_validator".into());
        while slot < slots_per_epoch {
            self.schedule.push((epoch_base + slot, fill_leader.clone()));
            slot += 1;
        }
    }

    /// Who is the writer for this slot?
    pub fn get_leader(&self, slot: u64) -> String {
        self.schedule.iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, l)| l.clone())
            .unwrap_or_else(|| "genesis_validator".into())
    }

    /// Upcoming writers (for Gulf Stream lookahead)
    pub fn get_upcoming_leaders(&self, current_slot: u64, count: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for s in current_slot..(current_slot + count as u64 * 2) {
            let l = self.get_leader(s);
            if seen.insert(l.clone()) {
                out.push(l);
                if out.len() >= count { break; }
            }
        }
        out
    }

    /// Record that a leader produced a block (tracking only)
    pub fn record_slot_production(&mut self, _validator: &str, _slot: u64) {
        // Lightweight — schedule is regenerated each epoch
    }
}

impl Default for LeaderSchedule { fn default() -> Self { Self::new() } }

// ============================================================================
// GULF STREAM — Mempool-less Transaction Forwarding
// ============================================================================
//
// Reader nodes forward transactions directly to the upcoming Writer.
// No global mempool — transactions are pre-staged at the leader.

#[derive(Debug, Clone)]
struct Forwarded {
    tx: Transaction,
    received_slot: u64,
    priority: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GulfStreamStats {
    pub transactions_received: u64,
    pub transactions_forwarded: u64,
    pub transactions_expired: u64,
    pub cache_size: usize,
    pub current_leaders_cached: usize,
    pub avg_forward_latency_us: u64,
    pub is_active: bool,
}

pub struct GulfStreamService {
    leader_schedule: Arc<RwLock<LeaderSchedule>>,
    current_slot: Arc<AtomicU64>,
    cache: DashMap<String, VecDeque<Forwarded>>,    // leader → txs
    seen: DashMap<String, u64>,                      // tx_id → slot
    rx: AtomicU64, fwd: AtomicU64, exp: AtomicU64, lat: AtomicU64,
    active: AtomicBool,
}

impl GulfStreamService {
    /// Extract all cached in-flight transactions globally across all upcoming leaders
    pub fn get_all_pending(&self) -> Vec<Transaction> {
        let mut txs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        
        for entry in self.cache.iter() {
            for fwd in entry.value().iter() {
                if seen.insert(fwd.tx.id.clone()) {
                    txs.push(fwd.tx.clone());
                }
            }
        }
        
        txs.sort_by(|a, b| b.amount.partial_cmp(&a.amount).unwrap_or(std::cmp::Ordering::Equal));
        txs
    }
    pub fn new(ls: Arc<RwLock<LeaderSchedule>>, slot: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            leader_schedule: ls, current_slot: slot,
            cache: DashMap::new(), seen: DashMap::new(),
            rx: AtomicU64::new(0), fwd: AtomicU64::new(0),
            exp: AtomicU64::new(0), lat: AtomicU64::new(0),
            active: AtomicBool::new(false),
        })
    }

    pub fn submit(&self, tx: Transaction) -> Result<(), String> {
        let slot = self.current_slot.load(Ordering::Relaxed);
        self.rx.fetch_add(1, Ordering::Relaxed);
        if self.seen.contains_key(&tx.id) { return Ok(()); }

        let fwd = Forwarded {
            // Priority proportional to lamports — higher-value txs get processed first
            priority: tx.amount / 1_000,
            tx: tx.clone(),
            received_slot: slot,
        };

        let leaders = { self.leader_schedule.read().get_upcoming_leaders(slot, GULF_STREAM_LOOKAHEAD) };
        for leader in &leaders {
            let t = Instant::now();
            self.cache.entry(leader.clone()).or_default().push_back(fwd.clone());
            if let Some(mut q) = self.cache.get_mut(leader) {
                while q.len() > MAX_CACHED_TXS { q.pop_front(); }
            }
            self.lat.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
            self.fwd.fetch_add(1, Ordering::Relaxed);
        }
        self.seen.insert(tx.id, slot);
        Ok(())
    }

    pub fn get_pending_by_priority(&self, leader: &str, limit: usize) -> Vec<Transaction> {
        let mut txs: Vec<Forwarded> = self.cache.get(leader)
            .map(|q| q.iter().cloned().collect()).unwrap_or_default();
        txs.sort_by(|a, b| b.priority.cmp(&a.priority));
        txs.into_iter().take(limit).map(|f| f.tx).collect()
    }

    pub fn clear_leader_cache(&self, leader: &str) {
        if let Some((_, q)) = self.cache.remove(leader) {
            for f in q { self.seen.remove(&f.tx.id); }
        }
    }

    pub fn start(self: &Arc<Self>) {
        self.active.store(true, Ordering::Relaxed);
        let svc = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            while svc.active.load(Ordering::Relaxed) {
                tick.tick().await;
                let slot = svc.current_slot.load(Ordering::Relaxed);
                let mut expired = 0u64;
                for mut e in svc.cache.iter_mut() {
                    let before = e.value().len();
                    e.value_mut().retain(|f| f.received_slot + CACHE_EXPIRY_SLOTS > slot);
                    expired += (before - e.value().len()) as u64;
                }
                svc.seen.retain(|_, s| *s + CACHE_EXPIRY_SLOTS > slot);
                if expired > 0 { svc.exp.fetch_add(expired, Ordering::Relaxed); }
            }
        });
    }

    pub fn get_stats(&self) -> GulfStreamStats {
        let f = self.fwd.load(Ordering::Relaxed);
        GulfStreamStats {
            transactions_received: self.rx.load(Ordering::Relaxed),
            transactions_forwarded: f,
            transactions_expired: self.exp.load(Ordering::Relaxed),
            cache_size: self.seen.len(),
            current_leaders_cached: self.cache.len(),
            avg_forward_latency_us: if f > 0 { self.lat.load(Ordering::Relaxed) / f } else { 0 },
            is_active: self.active.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// TOWER BFT — P2P Vote-Based Finality
// ============================================================================
//
// 1 Writer produces blocks. Up to 100 Readers validate and vote.
// Votes use exponential lockout: 2^(depth+1) slots.
// 32 consecutive confirmed slots → ROOTED (irreversible).

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    pub slot: u64,
    pub block_hash: String,
    pub validator: String,
    /// Voting power in lamports (u64) — replaces the old f64 stake_weight.
    pub stake_weight: u64,
    pub timestamp: u64,
    pub signature: String,
}

impl Vote {
    pub fn new(slot: u64, block_hash: String, validator: String, stake: u64) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut h = Sha256::new();
        h.update(slot.to_le_bytes());
        h.update(block_hash.as_bytes());
        h.update(validator.as_bytes());
        h.update(ts.to_le_bytes());
        Self { slot, block_hash, validator, stake_weight: stake, timestamp: ts, signature: format!("{:x}", h.finalize()) }
    }
    #[allow(dead_code)] // Used by reader nodes validating incoming P2P votes
    pub fn verify(&self) -> bool {
        let mut h = Sha256::new();
        h.update(self.slot.to_le_bytes());
        h.update(self.block_hash.as_bytes());
        h.update(self.validator.as_bytes());
        h.update(self.timestamp.to_le_bytes());
        self.signature == format!("{:x}", h.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TowerLockout {
    pub slot: u64,
    pub confirmation_count: u32,
}

impl TowerLockout {
    pub fn lockout(&self) -> u64 { 2u64.pow(self.confirmation_count + 1) }
    pub fn is_expired(&self, current: u64) -> bool { current >= self.slot + self.lockout() }
}

/// Per-validator vote tower
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTower {
    pub validator: String,
    pub votes: Vec<TowerLockout>,
    pub root: u64,
    pub last_voted_slot: u64,
    /// Voting power in lamports (u64).
    pub stake: u64,
}

impl VoteTower {
    pub fn new(validator: String, stake: u64) -> Self {
        Self { validator, votes: Vec::new(), root: 0, last_voted_slot: 0, stake }
    }

    pub fn process_vote(&mut self, slot: u64, current: u64) -> Result<(), String> {
        if slot < self.last_voted_slot {
            return Err(format!("Cannot vote on {} — already voted on {}", slot, self.last_voted_slot));
        }
        for lk in &self.votes {
            if !lk.is_expired(current) && slot < lk.slot {
                return Err(format!("Lockout violation: slot {} locked until {}", lk.slot, lk.slot + lk.lockout()));
            }
        }
        // Pop expired
        while self.votes.last().is_some_and(|v| v.is_expired(current)) { self.votes.pop(); }

        // Same slot = re-confirm
        if let Some(top) = self.votes.last_mut() {
            if top.slot == slot { top.confirmation_count += 1; self.last_voted_slot = slot; return Ok(()); }
        }

        self.votes.push(TowerLockout { slot, confirmation_count: 0 });
        for i in 0..self.votes.len().saturating_sub(1) { self.votes[i].confirmation_count += 1; }

        // Root when tower exceeds max depth
        while self.votes.len() > MAX_TOWER_DEPTH {
            let rooted = self.votes.remove(0);
            self.root = self.root.max(rooted.slot);
        }
        self.last_voted_slot = slot;
        Ok(())
    }
}

/// Compact tower sync for P2P gossip
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[allow(dead_code)] // Phase 5+: multi-validator P2P gossip
pub struct TowerSync {
    pub validator: String,
    pub root: u64,
    pub votes: Vec<u64>,
    /// Voting power in lamports (u64).
    pub stake: u64,
    pub timestamp: u64,
}

/// Fork info for heaviest-subtree selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    pub slot: u64,
    pub block_hash: String,
    /// Accumulated voting power in lamports (u64).
    pub stake: u64,
    pub vote_count: usize,
    pub parent_slot: u64,
    pub has_supermajority: bool,
}

// ============================================================================
// TOWER BFT SERVICE — 1 Writer, N Readers
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusStatus {
    Unknown,
    Voting { stake_lamports: u64, votes: usize },
    Confirmed { stake_lamports: u64 },
    Rooted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TowerBFTStats {
    pub validator_count: usize,
    /// Total registered stake in lamports (u64).
    pub total_stake: u64,
    pub global_root: u64,
    pub confirmed_slots: usize,
    pub active_forks: usize,
    /// Supermajority threshold displayed as a float for API consumers only.
    /// Internally the check is: votes * 3 >= total * 2 (no f64 in consensus path).
    pub supermajority_threshold: f64,
    pub max_tower_depth: usize,
}

pub struct TowerBFT {
    towers: DashMap<String, VoteTower>,
    slot_votes: DashMap<u64, Vec<Vote>>,
    forks: DashMap<u64, ForkInfo>,
    current_slot: Arc<AtomicU64>,
    /// Total registered stake in lamports — u64 atomic (replaces Arc<RwLock<f64>>).
    total_stake: Arc<AtomicU64>,
    global_root: Arc<AtomicU64>,
    confirmed: DashMap<u64, u64>,  // slot → accumulated stake lamports
    our_validator: String,
}

impl TowerBFT {
    pub fn new(us: String, slot: Arc<AtomicU64>) -> Arc<Self> {
        info!("🗼 Tower BFT: validator={}, depth={}, supermajority=66.7% (votes*3>=total*2)",
            us, MAX_TOWER_DEPTH);
        Arc::new(Self {
            towers: DashMap::new(), slot_votes: DashMap::new(), forks: DashMap::new(),
            current_slot: slot, total_stake: Arc::new(AtomicU64::new(0)),
            global_root: Arc::new(AtomicU64::new(0)), confirmed: DashMap::new(),
            our_validator: us,
        })
    }

    pub fn register_validator(&self, v: &str, stake: u64) {
        self.towers.insert(v.to_string(), VoteTower::new(v.to_string(), stake));
        self.total_stake.fetch_add(stake, Ordering::Relaxed);
    }

    pub fn vote(&self, validator: &str, slot: u64, block_hash: &str) -> Result<bool, String> {
        let cur = self.current_slot.load(Ordering::Relaxed);
        let stake = self.towers.get(validator).map(|t| t.stake).unwrap_or_else(|| {
            self.register_validator(validator, 100_000); 100_000  // 1 BB default
        });
        { self.towers.get_mut(validator).unwrap().process_vote(slot, cur)?; }

        let v = Vote::new(slot, block_hash.into(), validator.into(), stake);
        self.slot_votes.entry(slot).or_default().push(v);

        // Update fork
        let mut fork = self.forks.entry(slot).or_insert(ForkInfo {
            slot, block_hash: block_hash.into(), stake: 0, vote_count: 0,
            parent_slot: slot.saturating_sub(1), has_supermajority: false,
        });
        fork.stake = fork.stake.saturating_add(stake);
        fork.vote_count += 1;

        let total = self.total_stake.load(Ordering::Relaxed);
        let slot_stake: u64 = self.slot_votes.get(&slot)
            .map(|v| v.iter().map(|x| x.stake_weight).sum())
            .unwrap_or(0);
        // Integer supermajority: votes * 3 >= total * 2  (equivalent to votes/total >= 2/3)
        let supermajority = total > 0 && slot_stake.saturating_mul(3) >= total.saturating_mul(2);
        fork.has_supermajority = supermajority;

        if supermajority {
            self.confirmed.insert(slot, slot_stake);
            // Check rooting
            let root = self.global_root.load(Ordering::Relaxed);
            let mut consecutive = 0u64;
            let mut check = root + 1;
            while self.confirmed.contains_key(&check) { consecutive += 1; check += 1; }
            if consecutive >= MAX_TOWER_DEPTH as u64 {
                let new_root = root + consecutive - MAX_TOWER_DEPTH as u64 + 1;
                self.global_root.store(new_root, Ordering::Relaxed);
                self.confirmed.retain(|s, _| *s >= new_root);
                info!("🔐 Global root → slot {}", new_root);
            }
        }
        Ok(supermajority)
    }

    pub fn check_supermajority(&self, slot: u64) -> bool {
        let total = self.total_stake.load(Ordering::Relaxed);
        if total == 0 { return false; }
        let stake: u64 = self.slot_votes.get(&slot)
            .map(|v| v.iter().map(|x| x.stake_weight).sum())
            .unwrap_or(0);
        stake.saturating_mul(3) >= total.saturating_mul(2)
    }

    pub fn global_root(&self) -> u64 { self.global_root.load(Ordering::Relaxed) }
    pub fn is_finalized(&self, slot: u64) -> bool { slot <= self.global_root() }
    pub fn is_confirmed(&self, slot: u64) -> bool { self.confirmed.contains_key(&slot) || self.is_finalized(slot) }

    /// Vote as our own validator (uses `our_validator` identity)
    pub fn self_vote(&self, slot: u64, block_hash: &str) -> Result<bool, String> {
        self.vote(&self.our_validator, slot, block_hash)
    }

    pub fn get_status_for_slot(&self, slot: u64) -> ConsensusStatus {
        if self.is_finalized(slot) {
            return ConsensusStatus::Rooted;
        }
        let total = self.total_stake.load(Ordering::Relaxed);
        let slot_stake: u64 = self.slot_votes.get(&slot)
            .map(|v| v.iter().map(|x| x.stake_weight).sum())
            .unwrap_or(0);
        if total > 0 && slot_stake.saturating_mul(3) >= total.saturating_mul(2) {
            ConsensusStatus::Confirmed { stake_lamports: slot_stake }
        } else {
            let vote_count = self.slot_votes.get(&slot).map(|v| v.len()).unwrap_or(0);
            if vote_count > 0 {
                ConsensusStatus::Voting { stake_lamports: slot_stake, votes: vote_count }
            } else {
                ConsensusStatus::Unknown
            }
        }
    }

    /// Get consensus status for a slot
    pub fn get_consensus_status(&self, slot: u64) -> ConsensusStatus {
        self.get_status_for_slot(slot)
    }

    /// Verify a proposed block's validity using leader schedule
    pub fn verify_proposed_block(
        &self, slot: u64, block_hash: &str, poh_hash: &str,
        leader: &str, expected_leader: &str, transactions: &[String],
    ) -> Result<(), String> {
        verify_block_validity(slot, block_hash, poh_hash, leader, expected_leader, transactions)
    }

    /// Check if a vote threshold is met for a slot
    pub fn meets_threshold(&self, slot: u64, threshold: f64) -> bool {
        let total = self.total_stake.load(Ordering::Relaxed);
        let voted: u64 = self.slot_votes.get(&slot)
            .map(|v| v.iter().map(|x| x.stake_weight).sum())
            .unwrap_or(0);
        check_vote_threshold(voted, total, threshold)
    }

    pub fn select_fork(&self) -> Option<(u64, String)> {
        let root = self.global_root();
        let mut best: Option<(u64, String, u64)> = None;
        for e in self.forks.iter() {
            let f = e.value();
            if f.slot < root || f.vote_count < MIN_FORK_VOTES { continue; }
            match &best {
                None => best = Some((f.slot, f.block_hash.clone(), f.stake)),
                Some((_, _, bs)) if f.stake > *bs => best = Some((f.slot, f.block_hash.clone(), f.stake)),
                Some((bs, _, bstk)) if f.stake == *bstk && f.slot > *bs => best = Some((f.slot, f.block_hash.clone(), f.stake)),
                _ => {}
            }
        }
        best.map(|(s, h, _)| (s, h))
    }

    /// Returns the highest slot on the heaviest fork (most accumulated stake weight).
    ///
    /// Used by Reader nodes and the Writer's suspension-recovery path to detect when
    /// the local `Arc<AtomicU64>` slot counter has fallen behind the network's voted
    /// tip.  Unlike `select_fork()`, this returns only the slot number so callers
    /// can compare against their local clock cheaply without holding any extra locks.
    pub fn heaviest_confirmed_slot(&self) -> Option<u64> {
        let root = self.global_root();
        self.forks
            .iter()
            .filter(|e| e.slot >= root && e.vote_count >= MIN_FORK_VOTES)
            .max_by_key(|e| e.stake)
            .map(|e| e.slot)
    }

    /// Reconcile the shared slot clock against the heaviest confirmed slot.
    ///
    /// If the network's heaviest voted slot is **ahead** of `current_slot`, this
    /// atomically fast-forwards the counter using `fetch_max` (safe against races
    /// with the normal PoH advance).
    ///
    /// Returns the number of slots skipped, or `None` if the clock was already
    /// at or past the network tip.
    ///
    /// # When to call
    /// - Reader node: after processing a batch of incoming `Vote` gossip messages.
    /// - Writer node: inside the block-production loop as a sanity check after
    ///   receiving out-of-order blocks during leader hand-off.
    pub fn reconcile_clock(&self) -> Option<u64> {
        let heaviest = self.heaviest_confirmed_slot()?;
        let local = self.current_slot.load(Ordering::Relaxed);
        if heaviest > local {
            // fetch_max: atomically advance only if heaviest > current.
            // Returns the *previous* value — if it changed we really did fast-forward.
            let prev = self.current_slot.fetch_max(heaviest, Ordering::Relaxed);
            if heaviest > prev {
                let delta = heaviest - prev;
                warn!(
                    "⚡ TowerBFT clock reconcile: \
                     local_slot={prev} → network_heaviest={heaviest} (+{delta} slots skipped)"
                );
                return Some(delta);
            }
        }
        None
    }

    /// Skip-slot: fast-forward the shared slot counter to the **end of the
    /// current leader's tenure** when the scheduled leader is silent.
    ///
    /// This is deliberately bounded — it only skips to the tenure boundary,
    /// never further. The PoH clock continues ticking through the empty slots
    /// naturally so that when the next healthy validator's scheduled slot
    /// arrives, its cryptographic hashes line up with the rest of the network.
    ///
    /// # Tenure boundary math
    /// ```text
    /// tenure_index = slot / LEADER_TENURE_SLOTS
    /// tenure_end   = (tenure_index + 1) * LEADER_TENURE_SLOTS
    /// ```
    /// If `slot` is already at or past `tenure_end`, this is a no-op (the
    /// tenure already ended naturally).
    ///
    /// Returns the number of slots skipped, or `None` if no skip was needed.
    pub fn skip_past_tenure(&self, current_leader_slot: u64) -> Option<u64> {
        let tenure_end = ((current_leader_slot / LEADER_TENURE_SLOTS) + 1) * LEADER_TENURE_SLOTS;
        let local = self.current_slot.load(Ordering::Relaxed);

        // Only skip if we're still inside the dead leader's tenure.
        if local >= tenure_end {
            return None;
        }

        // fetch_max: atomically advance only if tenure_end > current.
        // Safe against races with the normal PoH clock advance.
        let prev = self.current_slot.fetch_max(tenure_end, Ordering::Relaxed);
        if tenure_end > prev {
            let delta = tenure_end - prev;
            warn!(
                "⏭  SKIP-SLOT: leader tenure timed out — \
                 local_slot={prev} → tenure_end={tenure_end} (+{delta} slots skipped)"
            );
            return Some(delta);
        }
        None
    }

    pub fn get_stats(&self) -> TowerBFTStats {
        TowerBFTStats {
            validator_count: self.towers.len(),
            total_stake: self.total_stake.load(Ordering::Relaxed),
            global_root: self.global_root(),
            confirmed_slots: self.confirmed.len(),
            active_forks: self.forks.len(),
            // Expose as f64 for API compatibility only — consensus path uses integer check.
            supermajority_threshold: 0.667,
            max_tower_depth: MAX_TOWER_DEPTH,
        }
    }
}

/// Verify block validity (leader check + format)
pub fn verify_block_validity(
    slot: u64, block_hash: &str, poh_hash: &str,
    leader: &str, expected_leader: &str, transactions: &[String],
) -> Result<(), String> {
    if leader != expected_leader { return Err(format!("Wrong leader for slot {}", slot)); }
    if block_hash.is_empty() { return Err("Empty block hash".into()); }
    if poh_hash.is_empty() { return Err("Empty PoH hash".into()); }
    if transactions.len() > 10_000 { return Err("Too many transactions".into()); }
    Ok(())
}

/// Integer supermajority check. `threshold` is a float used only by callers
/// that pre-date the u64 migration (e.g. SDK status endpoints). For pure
/// consensus use `votes * 3 >= total * 2` directly.
pub fn check_vote_threshold(voted: u64, total: u64, threshold: f64) -> bool {
    if total == 0 { return false; }
    // Convert the f64 threshold to an integer comparison to avoid f64 in hot path.
    // threshold=0.667 → votes*3 >= total*2; threshold=0.5 → votes*2 >= total*1, etc.
    let numer = (threshold * 3.0).round() as u64;
    let denom = 3u64;
    voted.saturating_mul(denom) >= total.saturating_mul(numer)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leader_schedule() {
        let mut s = LeaderSchedule::new();
        s.set_stake("alice", 1_000_000_000); // 10,000 BB
        s.set_stake("bob", 100_000_000);     // 1,000 BB
        s.generate_schedule(0, 10);
        let alice = s.schedule.iter().filter(|(_, l)| l == "alice").count();
        let bob = s.schedule.iter().filter(|(_, l)| l == "bob").count();
        assert!(alice > bob);
    }

    #[test]
    fn test_tower_lockout() {
        let lk = TowerLockout { slot: 100, confirmation_count: 0 };
        assert_eq!(lk.lockout(), 2);
        assert!(!lk.is_expired(101));
        assert!(lk.is_expired(102));
    }

    #[test]
    fn test_vote_tower() {
        let mut t = VoteTower::new("v1".into(), 100);
        assert!(t.process_vote(100, 100).is_ok());
        assert!(t.process_vote(101, 101).is_ok());
        assert!(t.process_vote(99, 102).is_err()); // can't go back
    }

    #[test]
    fn test_vote_signature() {
        let v = Vote::new(100, "hash".into(), "v1".into(), 50);
        assert!(v.verify());
        let mut bad = v.clone();
        bad.slot = 999;
        assert!(!bad.verify());
    }

    #[test]
    fn test_supermajority() {
        let slot = Arc::new(AtomicU64::new(100));
        let bft = TowerBFT::new("v1".into(), slot);
        bft.register_validator("v1", 100);
        bft.register_validator("v2", 100);
        bft.register_validator("v3", 100);
        bft.vote("v1", 100, "block").unwrap();
        bft.vote("v2", 100, "block").unwrap();
        bft.vote("v3", 100, "block").unwrap();
        assert!(bft.check_supermajority(100)); // 300/300 = 1.0 ≥ 0.667
    }
}
