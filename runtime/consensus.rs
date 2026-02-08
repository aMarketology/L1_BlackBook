//! BlackBook L1 Consensus — P2P Tower Voting
//!
//! 1-Writer / 100-Reader Node Model:
//! ┌──────────────────────────────────────────────────────────────┐
//! │  WRITER NODE (1)           │  READER NODES (up to 100)      │
//! │  ─ Produces blocks         │  ─ Validate & vote on blocks   │
//! │  ─ Runs PoH clock          │  ─ Replicate state via Turbine │
//! │  ─ Executes transactions   │  ─ Serve RPC queries           │
//! │  ─ The "leader" each slot  │  ─ Forward txs via Gulf Stream │
//! └──────────────────────────────────────────────────────────────┘
//!
//! Tower BFT Voting:
//!   Vote on slot → lockout = 2^(depth+1) slots
//!   32 consecutive confirmations → ROOTED (finalized, irreversible)
//!   Supermajority = 2/3+ stake on a slot = CONFIRMED
//!
//! Gulf Stream:
//!   Readers forward incoming transactions to the current Writer
//!   so the Writer's mempool is pre-filled before its slot arrives.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use parking_lot::RwLock;
use borsh::{BorshSerialize, BorshDeserialize};
use dashmap::DashMap;
use sha2::{Sha256, Digest};
use tracing::{info, debug};
use crate::runtime::core::Transaction;

// ============================================================================
// CONSTANTS
// ============================================================================

const GULF_STREAM_LOOKAHEAD: usize = 8;
const MAX_CACHED_TXS: usize = 50_000;
const CACHE_EXPIRY_SLOTS: u64 = 20;
pub const MAX_TOWER_DEPTH: usize = 32;
pub const SUPERMAJORITY_THRESHOLD: f64 = 0.667;
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
        Self {
            slot_duration_ms: 600,
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
// LEADER SCHEDULE — 1-Writer Rotation
// ============================================================================
//
// In the 1-writer model, only ONE node produces blocks per slot.
// Reader nodes validate, vote, and replicate.
// The schedule rotates the writer role based on engagement stake.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderSchedule {
    stakes: HashMap<String, f64>,
    schedule: Vec<(u64, String)>, // (slot, leader)
    pub epoch: u64,
}

impl LeaderSchedule {
    pub fn new() -> Self {
        Self { stakes: HashMap::new(), schedule: Vec::new(), epoch: 0 }
    }

    /// Register or update a node's engagement stake (logarithmic scaling)
    pub fn update_stake(&mut self, address: &str, raw_engagement: f64) {
        let weight = (1.0 + raw_engagement).ln();
        self.stakes.insert(address.to_string(), weight);
    }

    /// Generate writer schedule for an epoch — proportional to stake
    pub fn generate_schedule(&mut self, epoch: u64, slots_per_epoch: u64) {
        self.epoch = epoch;
        self.schedule.clear();

        let total: f64 = self.stakes.values().sum();
        if total == 0.0 || self.stakes.is_empty() {
            for s in 0..slots_per_epoch {
                self.schedule.push((epoch * slots_per_epoch + s, "genesis_validator".into()));
            }
            return;
        }

        let mut validators: Vec<_> = self.stakes.iter().collect();
        validators.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

        let mut slot = 0u64;
        while slot < slots_per_epoch {
            for (addr, weight) in &validators {
                let run = ((*weight / total) * 4.0).ceil() as u64;
                for _ in 0..run.max(1) {
                    if slot >= slots_per_epoch { break; }
                    self.schedule.push((epoch * slots_per_epoch + slot, addr.to_string()));
                    slot += 1;
                }
            }
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
            priority: (tx.amount * 100.0) as u64,
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
    pub stake_weight: f64,
    pub timestamp: u64,
    pub signature: String,
}

impl Vote {
    pub fn new(slot: u64, block_hash: String, validator: String, stake: f64) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut h = Sha256::new();
        h.update(slot.to_le_bytes());
        h.update(block_hash.as_bytes());
        h.update(validator.as_bytes());
        h.update(ts.to_le_bytes());
        Self { slot, block_hash, validator, stake_weight: stake, timestamp: ts, signature: format!("{:x}", h.finalize()) }
    }
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
    pub stake: f64,
}

impl VoteTower {
    pub fn new(validator: String, stake: f64) -> Self {
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
        while self.votes.last().map_or(false, |v| v.is_expired(current)) { self.votes.pop(); }

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
pub struct TowerSync {
    pub validator: String,
    pub root: u64,
    pub votes: Vec<u64>,
    pub stake: f64,
    pub timestamp: u64,
}

/// Fork info for heaviest-subtree selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    pub slot: u64,
    pub block_hash: String,
    pub stake: f64,
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
    Voting { stake: f64, votes: usize },
    Confirmed { stake: f64 },
    Rooted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TowerBFTStats {
    pub validator_count: usize,
    pub total_stake: f64,
    pub global_root: u64,
    pub confirmed_slots: usize,
    pub active_forks: usize,
    pub supermajority_threshold: f64,
    pub max_tower_depth: usize,
}

pub struct TowerBFT {
    towers: DashMap<String, VoteTower>,
    slot_votes: DashMap<u64, Vec<Vote>>,
    forks: DashMap<u64, ForkInfo>,
    current_slot: Arc<AtomicU64>,
    total_stake: Arc<RwLock<f64>>,
    global_root: Arc<AtomicU64>,
    confirmed: DashMap<u64, f64>,
    our_validator: String,
}

impl TowerBFT {
    pub fn new(us: String, slot: Arc<AtomicU64>) -> Arc<Self> {
        info!("🗼 Tower BFT: validator={}, depth={}, supermajority={:.0}%",
            us, MAX_TOWER_DEPTH, SUPERMAJORITY_THRESHOLD * 100.0);
        Arc::new(Self {
            towers: DashMap::new(), slot_votes: DashMap::new(), forks: DashMap::new(),
            current_slot: slot, total_stake: Arc::new(RwLock::new(0.0)),
            global_root: Arc::new(AtomicU64::new(0)), confirmed: DashMap::new(),
            our_validator: us,
        })
    }

    pub fn register_validator(&self, v: &str, stake: f64) {
        self.towers.insert(v.to_string(), VoteTower::new(v.to_string(), stake));
        *self.total_stake.write() += stake;
    }

    pub fn vote(&self, validator: &str, slot: u64, block_hash: &str) -> Result<bool, String> {
        let cur = self.current_slot.load(Ordering::Relaxed);
        let stake = self.towers.get(validator).map(|t| t.stake).unwrap_or_else(|| {
            self.register_validator(validator, 1.0); 1.0
        });
        { self.towers.get_mut(validator).unwrap().process_vote(slot, cur)?; }

        let v = Vote::new(slot, block_hash.into(), validator.into(), stake);
        self.slot_votes.entry(slot).or_default().push(v);

        // Update fork
        let mut fork = self.forks.entry(slot).or_insert(ForkInfo {
            slot, block_hash: block_hash.into(), stake: 0.0, vote_count: 0,
            parent_slot: slot.saturating_sub(1), has_supermajority: false,
        });
        fork.stake += stake;
        fork.vote_count += 1;

        let total = *self.total_stake.read();
        let slot_stake: f64 = self.slot_votes.get(&slot).map(|v| v.iter().map(|x| x.stake_weight).sum()).unwrap_or(0.0);
        let supermajority = total > 0.0 && slot_stake / total >= SUPERMAJORITY_THRESHOLD;
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
        let total = *self.total_stake.read();
        if total == 0.0 { return false; }
        let stake: f64 = self.slot_votes.get(&slot).map(|v| v.iter().map(|x| x.stake_weight).sum()).unwrap_or(0.0);
        stake / total >= SUPERMAJORITY_THRESHOLD
    }

    pub fn global_root(&self) -> u64 { self.global_root.load(Ordering::Relaxed) }
    pub fn is_finalized(&self, slot: u64) -> bool { slot <= self.global_root() }
    pub fn is_confirmed(&self, slot: u64) -> bool { self.confirmed.contains_key(&slot) || self.is_finalized(slot) }

    pub fn select_fork(&self) -> Option<(u64, String)> {
        let root = self.global_root();
        let mut best: Option<(u64, String, f64)> = None;
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

    pub fn get_stats(&self) -> TowerBFTStats {
        TowerBFTStats {
            validator_count: self.towers.len(),
            total_stake: *self.total_stake.read(),
            global_root: self.global_root(),
            confirmed_slots: self.confirmed.len(),
            active_forks: self.forks.len(),
            supermajority_threshold: SUPERMAJORITY_THRESHOLD,
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

pub fn check_vote_threshold(voted: f64, total: f64, threshold: f64) -> bool {
    total > 0.0 && voted / total >= threshold
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
        s.update_stake("alice", 1000.0);
        s.update_stake("bob", 100.0);
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
        let mut t = VoteTower::new("v1".into(), 100.0);
        assert!(t.process_vote(100, 100).is_ok());
        assert!(t.process_vote(101, 101).is_ok());
        assert!(t.process_vote(99, 102).is_err()); // can't go back
    }

    #[test]
    fn test_vote_signature() {
        let v = Vote::new(100, "hash".into(), "v1".into(), 50.0);
        assert!(v.verify());
        let mut bad = v.clone();
        bad.slot = 999;
        assert!(!bad.verify());
    }

    #[test]
    fn test_supermajority() {
        let slot = Arc::new(AtomicU64::new(100));
        let bft = TowerBFT::new("v1".into(), slot);
        bft.register_validator("v1", 100.0);
        bft.register_validator("v2", 100.0);
        bft.register_validator("v3", 100.0);
        bft.vote("v1", 100, "block").unwrap();
        bft.vote("v2", 100, "block").unwrap();
        assert!(bft.check_supermajority(100)); // 200/300 ≥ 0.667
    }
}
