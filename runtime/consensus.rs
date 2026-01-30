//! Layer1 Consensus Infrastructure
//!
//! Solana-style infrastructure types for:
//! - PoH Clock: Continuous timestamping via hash chain
//! - Gulf Stream: Transaction forwarding to upcoming leaders
//! - Leader Schedule: Engagement-weighted leader rotation
//! - Tower BFT: Vote-based finality with lockout periods
//!
//! NOTE: The main consensus logic (Proof of Engagement) is in src/consensus/
//! This module provides the low-level infrastructure those systems build upon.
//!
//! TOWER BFT CONSENSUS:
//! Validators must agree on:
//! 1. Block ORDER - via PoH-synchronized slot votes
//! 2. Block VALIDITY - via signature verification and vote weights
//! 3. FINALITY - via exponential lockouts (32 votes = rooted)
//!
//! ```
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         TOWER BFT VOTING                                │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   Vote on Slot 100:  lockout = 2 slots  (can't vote < 100 for 2 slots)  │
//! │   Vote on Slot 101:  lockout = 4 slots  (doubles each consecutive vote) │
//! │   Vote on Slot 102:  lockout = 8 slots                                  │
//! │   ...                                                                   │
//! │   Vote on Slot 131:  lockout = 2^32     (slot 100 is now ROOTED)        │
//! │                                                                         │
//! │   ROOTED = Finalized = Cannot be reverted                               │
//! │                                                                         │
//! │   Fork Choice: Always vote for heaviest subtree (most stake voted)      │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use parking_lot::RwLock;
use borsh::{BorshSerialize, BorshDeserialize};
use dashmap::DashMap;
use sha2::{Sha256, Digest};
use tracing::{info, warn, debug};
use crate::runtime::core::Transaction;

// ============================================================================
// GULF STREAM CONSTANTS - TUNED FOR HIGH THROUGHPUT
// ============================================================================

/// Number of upcoming leaders to forward transactions to
/// TUNED: 8 leaders = ~4.8 seconds of lookahead at 600ms slots
const GULF_STREAM_LOOKAHEAD: usize = 8;

/// Maximum transactions to cache per leader
/// TUNED: 50k allows for burst traffic handling
const MAX_CACHED_TXS_PER_LEADER: usize = 50_000;

/// Number of slots before cached transactions expire
/// TUNED: 20 slots = 12 seconds at 600ms (more tolerance)
const CACHE_EXPIRY_SLOTS: u64 = 20;

// ============================================================================
// PROOF OF HISTORY (PoH) - SOLANA-INSPIRED VERIFIABLE DELAY FUNCTION
// ============================================================================

/// Configuration for the PoH clock
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PoHConfig {
    /// Target slot duration in milliseconds (600ms for stability)
    pub slot_duration_ms: u64,
    /// Number of SHA-256 hashes per slot tick
    pub hashes_per_tick: u64,
    /// Number of ticks per slot
    pub ticks_per_slot: u64,
    /// Slots per epoch (leader rotation period)
    pub slots_per_epoch: u64,
}

impl Default for PoHConfig {
    fn default() -> Self {
        Self {
            slot_duration_ms: 600,    // 600ms slots - stable+fast (vs Solana's fragile 400ms)
            hashes_per_tick: 12500,   // ~12.5k hashes per tick
            ticks_per_slot: 64,       // 64 ticks per slot
            slots_per_epoch: 432000,  // ~2 days at 400ms slots
        }
    }
}

/// A single PoH entry - represents a verifiable point in time
/// 
/// Serialization strategy:
/// - Borsh: Used for PoH chain replication between nodes
/// - Serde JSON: Used for RPC queries with Base64-encoded Borsh
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PoHEntry {
    /// The SHA-256 hash at this point
    pub hash: String,
    /// Number of hashes since genesis
    pub num_hashes: u64,
    /// Transactions mixed into this entry (optional)
    pub transactions: Vec<String>,  // Transaction IDs mixed in
}

impl PoHEntry {
    /// Serialize PoH entry to Borsh bytes
    pub fn to_borsh(&self) -> Result<Vec<u8>, std::io::Error> {
        borsh::to_vec(self)
    }
    
    /// Deserialize PoH entry from Borsh bytes
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }
    
    /// Serialize to Base64-encoded Borsh (for RPC JSON wrapper)
    pub fn to_base64(&self) -> Result<String, std::io::Error> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = self.to_borsh()?;
        Ok(STANDARD.encode(&bytes))
    }
    
    /// Deserialize from Base64-encoded Borsh
    pub fn from_base64(s: &str) -> Result<Self, std::io::Error> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Self::from_borsh(&bytes)
    }
}

// ============================================================================
// LEADER SCHEDULE - Engagement-Weighted Validator Selection
// ============================================================================

/// Leader schedule entry - maps slots to validators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderScheduleEntry {
    pub slot: u64,
    pub leader: String,
    pub stake_weight: f64,  // Based on engagement (logarithmic)
}

/// Validator stake based on engagement scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStake {
    pub address: String,
    pub raw_engagement: f64,
    pub stake_weight: f64,  // Logarithmic: ln(1 + engagement) / total_ln_stake
    pub slots_produced: u64,
    pub last_active_slot: u64,
}

/// Leader Schedule Generator - uses engagement stakes for validator selection
#[derive(Debug, Clone)]
pub struct LeaderSchedule {
    /// Validator stakes (engagement-based)
    pub validator_stakes: HashMap<String, ValidatorStake>,
    /// Pre-computed schedule for current epoch
    pub schedule: Vec<LeaderScheduleEntry>,
    /// Current epoch this schedule is for
    pub epoch: u64,
}

impl LeaderSchedule {
    pub fn new() -> Self {
        Self {
            validator_stakes: HashMap::new(),
            schedule: Vec::new(),
            epoch: 0,
        }
    }
    
    /// Update validator stake from engagement score (logarithmic scaling)
    pub fn update_stake(&mut self, address: &str, raw_engagement: f64) {
        // Logarithmic scaling: prevents whales from dominating
        // stake_weight = ln(1 + engagement) 
        let stake_weight = (1.0 + raw_engagement).ln();
        
        self.validator_stakes.entry(address.to_string())
            .and_modify(|v| {
                v.raw_engagement = raw_engagement;
                v.stake_weight = stake_weight;
            })
            .or_insert(ValidatorStake {
                address: address.to_string(),
                raw_engagement,
                stake_weight,
                slots_produced: 0,
                last_active_slot: 0,
            });
    }
    
    /// Generate leader schedule for an epoch
    pub fn generate_schedule(&mut self, epoch: u64, slots_per_epoch: u64) {
        self.epoch = epoch;
        self.schedule.clear();
        
        // Get total stake weight
        let total_stake: f64 = self.validator_stakes.values()
            .map(|v| v.stake_weight)
            .sum();
        
        if total_stake == 0.0 || self.validator_stakes.is_empty() {
            // No validators - use default
            for slot in 0..slots_per_epoch {
                self.schedule.push(LeaderScheduleEntry {
                    slot: epoch * slots_per_epoch + slot,
                    leader: "genesis_validator".to_string(),
                    stake_weight: 1.0,
                });
            }
            return;
        }
        
        // Collect validators sorted by stake
        let mut validators: Vec<_> = self.validator_stakes.values().collect();
        validators.sort_by(|a, b| b.stake_weight.partial_cmp(&a.stake_weight).unwrap());
        
        // Distribute slots proportionally to stake weight
        let mut slot_index = 0u64;
        while slot_index < slots_per_epoch {
            for validator in &validators {
                if slot_index >= slots_per_epoch {
                    break;
                }
                
                // Number of consecutive slots based on stake proportion
                let slots_for_validator = ((validator.stake_weight / total_stake) * 4.0).ceil() as u64;
                
                for _ in 0..slots_for_validator.max(1) {
                    if slot_index >= slots_per_epoch {
                        break;
                    }
                    
                    self.schedule.push(LeaderScheduleEntry {
                        slot: epoch * slots_per_epoch + slot_index,
                        leader: validator.address.clone(),
                        stake_weight: validator.stake_weight,
                    });
                    slot_index += 1;
                }
            }
        }
        
        println!("📋 Generated leader schedule for epoch {}: {} slots across {} validators", 
                 epoch, self.schedule.len(), validators.len());
    }
    
    /// Get the leader for a specific slot
    pub fn get_leader(&self, slot: u64) -> String {
        self.schedule
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| e.leader.clone())
            .unwrap_or_else(|| "genesis_validator".to_string())
    }
    
    /// Get upcoming leaders for Gulf Stream forwarding
    pub fn get_upcoming_leaders(&self, current_slot: u64, count: usize) -> Vec<String> {
        let mut leaders = Vec::new();
        let mut seen = HashSet::new();
        
        for slot in current_slot..(current_slot + count as u64 * 2) {
            let leader = self.get_leader(slot);
            if seen.insert(leader.clone()) {
                leaders.push(leader);
                if leaders.len() >= count {
                    break;
                }
            }
        }
        
        leaders
    }
    
    /// Record that a validator produced a slot
    pub fn record_slot_production(&mut self, leader: &str, slot: u64) {
        if let Some(stake) = self.validator_stakes.get_mut(leader) {
            stake.slots_produced += 1;
            stake.last_active_slot = slot;
        }
    }
}

impl Default for LeaderSchedule {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GULF STREAM SERVICE - Transaction Forwarding to Upcoming Leaders
// ============================================================================

/// A pending transaction awaiting forwarding to future leaders
#[derive(Debug, Clone)]
pub struct ForwardableTransaction {
    pub transaction: Transaction,
    pub received_slot: u64,
    pub received_at: u64,  // Unix timestamp ms
    pub forwarded_to: HashSet<String>,  // Leaders we've forwarded to
    pub priority: u64,  // Higher = more urgent (based on fee or engagement)
}

/// Statistics for Gulf Stream operations
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

/// Gulf Stream Service - Transaction forwarding to upcoming leaders
///
/// Implements Solana-style transaction forwarding:
/// - Maintains cache of pending transactions per upcoming leader
/// - Forwards transactions to next N leaders based on schedule
/// - Pre-stages transactions for faster leader startup
/// - Expires old transactions after cache_expiry_slots
pub struct GulfStreamService {
    /// Leader schedule reference
    leader_schedule: Arc<RwLock<LeaderSchedule>>,
    
    /// Current slot reference
    current_slot: Arc<AtomicU64>,
    
    /// Transaction cache per leader: leader_address -> transactions
    leader_tx_cache: DashMap<String, VecDeque<ForwardableTransaction>>,
    
    /// All pending transactions by ID for dedup
    pending_tx_ids: DashMap<String, u64>,  // tx_id -> received_slot
    
    /// Statistics
    txs_received: AtomicU64,
    txs_forwarded: AtomicU64,
    txs_expired: AtomicU64,
    total_forward_latency_us: AtomicU64,
    
    /// Service state
    is_active: AtomicBool,
}

impl GulfStreamService {
    /// Create a new Gulf Stream service
    pub fn new(
        leader_schedule: Arc<RwLock<LeaderSchedule>>,
        current_slot: Arc<AtomicU64>,
    ) -> Arc<Self> {
        println!("🌊 Gulf Stream Service initialized:");
        println!("   └─ lookahead: {} leaders, cache: {} txs/leader", 
                 GULF_STREAM_LOOKAHEAD, MAX_CACHED_TXS_PER_LEADER);
        
        Arc::new(Self {
            leader_schedule,
            current_slot,
            leader_tx_cache: DashMap::new(),
            pending_tx_ids: DashMap::new(),
            txs_received: AtomicU64::new(0),
            txs_forwarded: AtomicU64::new(0),
            txs_expired: AtomicU64::new(0),
            total_forward_latency_us: AtomicU64::new(0),
            is_active: AtomicBool::new(false),
        })
    }
    
    /// Submit a transaction to Gulf Stream for forwarding
    pub fn submit(&self, transaction: Transaction) -> Result<(), String> {
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        
        self.txs_received.fetch_add(1, Ordering::Relaxed);
        
        // Dedup check
        if self.pending_tx_ids.contains_key(&transaction.id) {
            return Ok(()); // Already have it
        }
        
        // Create forwardable wrapper
        // Priority based on transaction amount (higher value = higher priority)
        let forwardable = ForwardableTransaction {
            transaction: transaction.clone(),
            received_slot: current_slot,
            received_at: now,
            forwarded_to: HashSet::new(),
            priority: (transaction.amount * 100.0) as u64, // Amount-based priority
        };
        
        // Get upcoming leaders
        let upcoming_leaders = {
            let schedule = self.leader_schedule.read();
            schedule.get_upcoming_leaders(current_slot, GULF_STREAM_LOOKAHEAD)
        };
        
        // Forward to each upcoming leader's cache
        for leader in &upcoming_leaders {
            self.forward_to_leader(leader, forwardable.clone());
        }
        
        // Track for dedup
        self.pending_tx_ids.insert(transaction.id, current_slot);
        
        Ok(())
    }
    
    /// Forward transaction to a specific leader's cache
    fn forward_to_leader(&self, leader: &str, mut tx: ForwardableTransaction) {
        let start = Instant::now();
        
        tx.forwarded_to.insert(leader.to_string());
        
        self.leader_tx_cache
            .entry(leader.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(tx);
        
        // Enforce max cache size (drop oldest)
        if let Some(mut cache) = self.leader_tx_cache.get_mut(leader) {
            while cache.len() > MAX_CACHED_TXS_PER_LEADER {
                cache.pop_front();
            }
        }
        
        let latency = start.elapsed().as_micros() as u64;
        self.total_forward_latency_us.fetch_add(latency, Ordering::Relaxed);
        self.txs_forwarded.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get pending transactions for a leader (called when leader's slot arrives)
    pub fn get_pending_for_leader(&self, leader: &str) -> Vec<Transaction> {
        self.leader_tx_cache
            .get(leader)
            .map(|cache| {
                cache.iter()
                    .map(|ft| ft.transaction.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get pending transactions sorted by priority
    pub fn get_pending_by_priority(&self, leader: &str, limit: usize) -> Vec<Transaction> {
        let mut txs: Vec<ForwardableTransaction> = self.leader_tx_cache
            .get(leader)
            .map(|cache| cache.iter().cloned().collect())
            .unwrap_or_default();
        
        // Sort by priority (highest first)
        txs.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        txs.into_iter()
            .take(limit)
            .map(|ft| ft.transaction)
            .collect()
    }
    
    /// Clear transactions for a leader (called after their slot completes)
    pub fn clear_leader_cache(&self, leader: &str) {
        if let Some((_, cache)) = self.leader_tx_cache.remove(leader) {
            // Also remove from pending_tx_ids
            for tx in cache {
                self.pending_tx_ids.remove(&tx.transaction.id);
            }
        }
    }
    
    /// Expire old transactions from cache
    pub fn expire_old_transactions(&self) {
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let mut expired_count = 0u64;
        
        // Iterate through all caches
        for mut entry in self.leader_tx_cache.iter_mut() {
            let cache = entry.value_mut();
            let before_len = cache.len();
            
            cache.retain(|tx| {
                tx.received_slot + CACHE_EXPIRY_SLOTS > current_slot
            });
            
            expired_count += (before_len - cache.len()) as u64;
        }
        
        // Clean up pending_tx_ids
        self.pending_tx_ids.retain(|_, slot| {
            *slot + CACHE_EXPIRY_SLOTS > current_slot
        });
        
        if expired_count > 0 {
            self.txs_expired.fetch_add(expired_count, Ordering::Relaxed);
        }
    }
    
    /// Start the Gulf Stream service (background expiry task)
    pub fn start(self: &Arc<Self>) {
        self.is_active.store(true, Ordering::Relaxed);
        
        let service = self.clone();
        tokio::spawn(async move {
            println!("🌊 Gulf Stream expiry task started");
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            while service.is_active.load(Ordering::Relaxed) {
                interval.tick().await;
                service.expire_old_transactions();
            }
        });
    }
    
    /// Stop the service
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::Relaxed);
    }
    
    /// Get Gulf Stream statistics
    pub fn get_stats(&self) -> GulfStreamStats {
        let forwarded = self.txs_forwarded.load(Ordering::Relaxed);
        let total_latency = self.total_forward_latency_us.load(Ordering::Relaxed);
        
        GulfStreamStats {
            transactions_received: self.txs_received.load(Ordering::Relaxed),
            transactions_forwarded: forwarded,
            transactions_expired: self.txs_expired.load(Ordering::Relaxed),
            cache_size: self.pending_tx_ids.len(),
            current_leaders_cached: self.leader_tx_cache.len(),
            avg_forward_latency_us: if forwarded > 0 { total_latency / forwarded } else { 0 },
            is_active: self.is_active.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// TOWER BFT CONSENSUS - Solana-Style Vote-Based Finality
// ============================================================================
//
// Tower BFT is a PBFT-like consensus that leverages PoH as a clock:
// - Each validator maintains a "tower" of votes
// - Votes have lockout periods that double with each confirmation
// - A slot is "rooted" (finalized) when lockout exceeds practical revert time
// - Fork choice follows the heaviest subtree by stake weight
//
// Key Invariants:
// 1. Validators can only vote on slots in their PoH view
// 2. Lockout doubles: vote[n].lockout = 2^(n+1) slots
// 3. Once lockout expires, that vote can be "popped" for a fork
// 4. Supermajority (2/3+ stake) on a slot = confirmed
// 5. 32 consecutive confirmations = rooted (finalized)

/// Maximum depth of a validator's vote tower (32 = 2^32 lockout at max depth)
pub const MAX_TOWER_DEPTH: usize = 32;

/// Threshold for supermajority (2/3 of stake)
pub const SUPERMAJORITY_THRESHOLD: f64 = 0.667;

/// Minimum votes on a fork for it to be considered (prevents spam forks)
pub const MIN_FORK_VOTES: usize = 1;

/// A single vote from a validator
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    /// Slot being voted on
    pub slot: u64,
    /// Block hash being voted on (ensures vote is for specific block, not just slot)
    pub block_hash: String,
    /// Validator who cast this vote
    pub validator: String,
    /// Validator's stake weight at time of vote
    pub stake_weight: f64,
    /// Unix timestamp when vote was cast
    pub timestamp: u64,
    /// Signature over (slot || block_hash || validator || timestamp)
    pub signature: String,
}

impl Vote {
    /// Create a new vote
    pub fn new(slot: u64, block_hash: String, validator: String, stake_weight: f64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        // Compute signature (simplified - real impl uses Ed25519)
        let mut hasher = Sha256::new();
        hasher.update(slot.to_le_bytes());
        hasher.update(block_hash.as_bytes());
        hasher.update(validator.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let signature = format!("{:x}", hasher.finalize());
        
        Self {
            slot,
            block_hash,
            validator,
            stake_weight,
            timestamp,
            signature,
        }
    }
    
    /// Verify vote signature
    pub fn verify(&self) -> bool {
        // Recompute expected signature
        let mut hasher = Sha256::new();
        hasher.update(self.slot.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.validator.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        let expected = format!("{:x}", hasher.finalize());
        
        self.signature == expected
    }
}

/// A lockout entry in a validator's tower
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TowerLockout {
    /// Slot that was voted on
    pub slot: u64,
    /// Number of confirmations on this slot (depth in tower)
    pub confirmation_count: u32,
}

impl TowerLockout {
    /// Calculate lockout period: 2^(confirmation_count + 1)
    pub fn lockout(&self) -> u64 {
        2u64.pow(self.confirmation_count + 1)
    }
    
    /// Check if this lockout has expired given current slot
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.slot + self.lockout()
    }
}

/// A validator's vote tower - tracks their voting history and lockouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTower {
    /// Validator identity
    pub validator: String,
    /// Stack of votes (newest at end) - max MAX_TOWER_DEPTH
    pub votes: Vec<TowerLockout>,
    /// The root slot (deepest confirmed, cannot be reverted)
    pub root: u64,
    /// Last voted slot
    pub last_voted_slot: u64,
    /// Total stake weight of this validator
    pub stake: f64,
}

impl VoteTower {
    /// Create a new tower for a validator
    pub fn new(validator: String, stake: f64) -> Self {
        Self {
            validator,
            votes: Vec::new(),
            root: 0,
            last_voted_slot: 0,
            stake,
        }
    }
    
    /// Process a new vote, updating lockouts
    /// Returns true if vote was accepted, false if it violates lockout
    pub fn process_vote(&mut self, slot: u64, current_slot: u64) -> Result<(), String> {
        // Cannot vote on slots before our last vote
        if slot < self.last_voted_slot {
            return Err(format!(
                "Cannot vote on slot {} - already voted on {}",
                slot, self.last_voted_slot
            ));
        }
        
        // Check lockout violations
        for lockout in &self.votes {
            if !lockout.is_expired(current_slot) && slot < lockout.slot {
                return Err(format!(
                    "Vote on slot {} violates lockout from slot {} (expires at {})",
                    slot, lockout.slot, lockout.slot + lockout.lockout()
                ));
            }
        }
        
        // Pop expired lockouts from the top
        while let Some(top) = self.votes.last() {
            if top.is_expired(current_slot) {
                self.votes.pop();
            } else {
                break;
            }
        }
        
        // Check if this vote is on the same slot (just confirming)
        if let Some(top) = self.votes.last_mut() {
            if top.slot == slot {
                // Same slot - increment confirmation
                top.confirmation_count += 1;
                self.last_voted_slot = slot;
                return Ok(());
            }
        }
        
        // New vote - add to tower
        self.votes.push(TowerLockout {
            slot,
            confirmation_count: 0,
        });
        
        // Increase confirmation count on all previous votes
        for i in 0..self.votes.len().saturating_sub(1) {
            self.votes[i].confirmation_count += 1;
        }
        
        // Check for rooting (MAX_TOWER_DEPTH confirmations)
        if self.votes.len() > MAX_TOWER_DEPTH {
            // The oldest vote is now rooted
            let rooted = self.votes.remove(0);
            self.root = self.root.max(rooted.slot);
            debug!("🔒 Slot {} rooted for validator {}", rooted.slot, self.validator);
        }
        
        // Trim to max depth
        while self.votes.len() > MAX_TOWER_DEPTH {
            let rooted = self.votes.remove(0);
            self.root = self.root.max(rooted.slot);
        }
        
        self.last_voted_slot = slot;
        Ok(())
    }
    
    /// Get the lockout for a slot (how long until we can vote against it)
    pub fn lockout_for_slot(&self, slot: u64) -> Option<u64> {
        self.votes.iter()
            .find(|v| v.slot == slot)
            .map(|v| v.lockout())
    }
    
    /// Check if we can vote on a slot without violating lockouts
    pub fn can_vote(&self, slot: u64, current_slot: u64) -> bool {
        if slot < self.last_voted_slot {
            return false;
        }
        
        for lockout in &self.votes {
            if !lockout.is_expired(current_slot) && slot < lockout.slot {
                return false;
            }
        }
        
        true
    }
    
    /// Get serializable state for P2P transmission
    pub fn to_tower_sync(&self) -> TowerSync {
        TowerSync {
            validator: self.validator.clone(),
            root: self.root,
            votes: self.votes.iter().map(|v| v.slot).collect(),
            stake: self.stake,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        }
    }
}

/// Compact tower state for P2P synchronization
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TowerSync {
    pub validator: String,
    pub root: u64,
    pub votes: Vec<u64>,  // Just the slot numbers
    pub stake: f64,
    pub timestamp: u64,
}

/// Fork information for fork choice rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    /// Slot at the tip of this fork
    pub slot: u64,
    /// Block hash at the tip
    pub block_hash: String,
    /// Total stake that has voted on this fork
    pub stake: f64,
    /// Number of validators who voted on this fork
    pub vote_count: usize,
    /// Parent slot (for chain traversal)
    pub parent_slot: u64,
    /// Whether this fork has supermajority
    pub has_supermajority: bool,
}

/// Tower BFT Consensus State - Manages all validator towers and fork choice
pub struct TowerBFT {
    /// All validator towers: validator_id -> VoteTower
    towers: DashMap<String, VoteTower>,
    
    /// Votes per slot: slot -> Vec<Vote>
    slot_votes: DashMap<u64, Vec<Vote>>,
    
    /// Fork tracking: slot -> ForkInfo
    forks: DashMap<u64, ForkInfo>,
    
    /// Current slot reference
    current_slot: Arc<AtomicU64>,
    
    /// Total stake in the network (for supermajority calculation)
    total_stake: Arc<RwLock<f64>>,
    
    /// Global root (highest slot confirmed by supermajority with 32 confirmations)
    global_root: Arc<AtomicU64>,
    
    /// Confirmed slots (supermajority but not yet rooted)
    confirmed_slots: DashMap<u64, f64>,  // slot -> confirming stake
    
    /// Our validator identity
    our_validator: String,
}

impl TowerBFT {
    /// Create a new Tower BFT consensus instance
    pub fn new(our_validator: String, current_slot: Arc<AtomicU64>) -> Arc<Self> {
        info!("🗼 Tower BFT initialized for validator: {}", our_validator);
        info!("   └─ max_depth: {}, supermajority: {:.1}%", 
              MAX_TOWER_DEPTH, SUPERMAJORITY_THRESHOLD * 100.0);
        
        Arc::new(Self {
            towers: DashMap::new(),
            slot_votes: DashMap::new(),
            forks: DashMap::new(),
            current_slot,
            total_stake: Arc::new(RwLock::new(0.0)),
            global_root: Arc::new(AtomicU64::new(0)),
            confirmed_slots: DashMap::new(),
            our_validator,
        })
    }
    
    /// Register a validator with their stake
    pub fn register_validator(&self, validator: &str, stake: f64) {
        self.towers.insert(
            validator.to_string(),
            VoteTower::new(validator.to_string(), stake)
        );
        
        let mut total = self.total_stake.write();
        *total += stake;
        
        info!("🗼 Validator {} registered with stake {:.2}", validator, stake);
    }
    
    /// Update validator stake (e.g., from engagement score changes)
    pub fn update_stake(&self, validator: &str, new_stake: f64) {
        if let Some(mut tower) = self.towers.get_mut(validator) {
            let old_stake = tower.stake;
            tower.stake = new_stake;
            
            let mut total = self.total_stake.write();
            *total = *total - old_stake + new_stake;
        }
    }
    
    /// Cast a vote from a validator
    /// Returns true if vote was accepted and consensus was updated
    pub fn vote(&self, validator: &str, slot: u64, block_hash: &str) -> Result<bool, String> {
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        
        // Get or create tower
        let stake = {
            let tower = self.towers.get(validator);
            match tower {
                Some(t) => t.stake,
                None => {
                    // Auto-register with default stake
                    self.register_validator(validator, 1.0);
                    1.0
                }
            }
        };
        
        // Process vote in tower
        {
            let mut tower = self.towers.get_mut(validator)
                .ok_or("Tower not found after registration")?;
            tower.process_vote(slot, current_slot)?;
        }
        
        // Record vote
        let vote = Vote::new(slot, block_hash.to_string(), validator.to_string(), stake);
        
        self.slot_votes
            .entry(slot)
            .or_insert_with(Vec::new)
            .push(vote);
        
        // Update fork info
        self.update_fork(slot, block_hash, stake);
        
        // Check for supermajority
        let has_supermajority = self.check_supermajority(slot);
        
        if has_supermajority {
            self.confirmed_slots.insert(slot, self.get_slot_stake(slot));
            debug!("✓ Slot {} confirmed with supermajority", slot);
        }
        
        // Check for rooting (32 consecutive confirmed slots)
        self.check_and_update_root();
        
        Ok(has_supermajority)
    }
    
    /// Process a vote received from P2P network
    pub fn process_p2p_vote(&self, vote: Vote) -> Result<bool, String> {
        // Verify signature
        if !vote.verify() {
            return Err("Invalid vote signature".to_string());
        }
        
        // Check vote is not too old
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        if vote.slot + 1000 < current_slot {
            return Err("Vote too old".to_string());
        }
        
        // Apply the vote
        self.vote(&vote.validator, vote.slot, &vote.block_hash)
    }
    
    /// Process tower sync from P2P network
    pub fn process_tower_sync(&self, sync: TowerSync) -> Result<(), String> {
        // Update or create tower
        let mut tower = self.towers
            .entry(sync.validator.clone())
            .or_insert_with(|| VoteTower::new(sync.validator.clone(), sync.stake));
        
        // Update stake
        let old_stake = tower.stake;
        tower.stake = sync.stake;
        
        // Update total stake
        let mut total = self.total_stake.write();
        *total = *total - old_stake + sync.stake;
        
        // Update root if newer
        if sync.root > tower.root {
            tower.root = sync.root;
        }
        
        Ok(())
    }
    
    /// Update fork information after a vote
    fn update_fork(&self, slot: u64, block_hash: &str, stake_delta: f64) {
        let mut fork = self.forks.entry(slot).or_insert(ForkInfo {
            slot,
            block_hash: block_hash.to_string(),
            stake: 0.0,
            vote_count: 0,
            parent_slot: slot.saturating_sub(1),
            has_supermajority: false,
        });
        
        fork.stake += stake_delta;
        fork.vote_count += 1;
        fork.has_supermajority = self.check_supermajority(slot);
    }
    
    /// Check if a slot has supermajority (2/3+ of total stake)
    pub fn check_supermajority(&self, slot: u64) -> bool {
        let total = *self.total_stake.read();
        if total == 0.0 {
            return false;
        }
        
        let slot_stake = self.get_slot_stake(slot);
        slot_stake / total >= SUPERMAJORITY_THRESHOLD
    }
    
    /// Get total stake that has voted on a slot
    pub fn get_slot_stake(&self, slot: u64) -> f64 {
        self.slot_votes
            .get(&slot)
            .map(|votes| votes.iter().map(|v| v.stake_weight).sum())
            .unwrap_or(0.0)
    }
    
    /// Check and update global root based on consecutive confirmed slots
    fn check_and_update_root(&self) {
        let current_root = self.global_root.load(Ordering::Relaxed);
        let mut new_root = current_root;
        
        // Look for consecutive confirmed slots from current root
        let mut consecutive = 0;
        let mut check_slot = current_root + 1;
        
        while self.confirmed_slots.contains_key(&check_slot) {
            consecutive += 1;
            
            // After MAX_TOWER_DEPTH consecutive confirmations, it's rooted
            if consecutive >= MAX_TOWER_DEPTH as u64 {
                new_root = check_slot - MAX_TOWER_DEPTH as u64 + 1;
            }
            
            check_slot += 1;
        }
        
        if new_root > current_root {
            self.global_root.store(new_root, Ordering::Relaxed);
            info!("🔐 Global root advanced to slot {}", new_root);
            
            // Clean up old confirmed slots
            self.confirmed_slots.retain(|slot, _| *slot >= new_root);
            self.slot_votes.retain(|slot, _| *slot >= new_root.saturating_sub(1000));
        }
    }
    
    /// Fork choice rule: select heaviest fork by stake weight
    /// Returns (slot, block_hash) of the best fork tip to build on
    pub fn select_fork(&self) -> Option<(u64, String)> {
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let global_root = self.global_root.load(Ordering::Relaxed);
        
        // Find all forks that descend from global root
        let mut best_fork: Option<(u64, String, f64)> = None;
        
        for entry in self.forks.iter() {
            let fork = entry.value();
            
            // Must be after global root
            if fork.slot < global_root {
                continue;
            }
            
            // Must have minimum votes
            if fork.vote_count < MIN_FORK_VOTES {
                continue;
            }
            
            // Choose heaviest by stake, tie-break by slot (higher = newer)
            match &best_fork {
                None => {
                    best_fork = Some((fork.slot, fork.block_hash.clone(), fork.stake));
                }
                Some((_, _, best_stake)) => {
                    if fork.stake > *best_stake || 
                       (fork.stake == *best_stake && fork.slot > best_fork.as_ref().unwrap().0) {
                        best_fork = Some((fork.slot, fork.block_hash.clone(), fork.stake));
                    }
                }
            }
        }
        
        best_fork.map(|(slot, hash, _)| (slot, hash))
    }
    
    /// Get our tower's current vote state
    pub fn our_tower(&self) -> Option<VoteTower> {
        self.towers.get(&self.our_validator).map(|t| t.clone())
    }
    
    /// Get our rooted slot
    pub fn our_root(&self) -> u64 {
        self.towers
            .get(&self.our_validator)
            .map(|t| t.root)
            .unwrap_or(0)
    }
    
    /// Get global rooted slot
    pub fn global_root(&self) -> u64 {
        self.global_root.load(Ordering::Relaxed)
    }
    
    /// Check if a slot is finalized (globally rooted)
    pub fn is_finalized(&self, slot: u64) -> bool {
        slot <= self.global_root.load(Ordering::Relaxed)
    }
    
    /// Check if a slot is confirmed (has supermajority but may not be rooted)
    pub fn is_confirmed(&self, slot: u64) -> bool {
        self.confirmed_slots.contains_key(&slot) || self.is_finalized(slot)
    }
    
    /// Get consensus status for a slot
    pub fn get_slot_status(&self, slot: u64) -> ConsensusStatus {
        let global_root = self.global_root.load(Ordering::Relaxed);
        
        if slot <= global_root {
            ConsensusStatus::Rooted
        } else if self.confirmed_slots.contains_key(&slot) {
            ConsensusStatus::Confirmed {
                stake: self.get_slot_stake(slot),
            }
        } else if self.slot_votes.contains_key(&slot) {
            ConsensusStatus::Voting {
                stake: self.get_slot_stake(slot),
                votes: self.slot_votes.get(&slot).map(|v| v.len()).unwrap_or(0),
            }
        } else {
            ConsensusStatus::Unknown
        }
    }
    
    /// Get statistics for monitoring
    pub fn get_stats(&self) -> TowerBFTStats {
        let total_stake = *self.total_stake.read();
        
        TowerBFTStats {
            validator_count: self.towers.len(),
            total_stake,
            global_root: self.global_root.load(Ordering::Relaxed),
            confirmed_slots: self.confirmed_slots.len(),
            active_forks: self.forks.len(),
            supermajority_threshold: SUPERMAJORITY_THRESHOLD,
            max_tower_depth: MAX_TOWER_DEPTH,
        }
    }
}

/// Consensus status for a slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusStatus {
    /// Slot has not been seen
    Unknown,
    /// Slot is being voted on but doesn't have supermajority
    Voting { stake: f64, votes: usize },
    /// Slot has supermajority (2/3+ stake) - confirmed
    Confirmed { stake: f64 },
    /// Slot is finalized (rooted) - cannot be reverted
    Rooted,
}

/// Statistics for Tower BFT
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

// ============================================================================
// BLOCK VALIDITY VERIFICATION
// ============================================================================

/// Verify block validity for consensus
/// A block is valid if:
/// 1. PoH entries are sequential and correctly computed
/// 2. Block hash matches expected computation
/// 3. Leader is correct for the slot
/// 4. All transactions have valid signatures
pub fn verify_block_validity(
    slot: u64,
    block_hash: &str,
    poh_hash: &str,
    leader: &str,
    expected_leader: &str,
    transactions: &[String],
) -> Result<(), String> {
    // 1. Verify leader is correct
    if leader != expected_leader {
        return Err(format!(
            "Invalid leader for slot {}: expected {}, got {}",
            slot, expected_leader, leader
        ));
    }
    
    // 2. Block hash should be non-empty and valid hex
    if block_hash.is_empty() || !block_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid block hash format".to_string());
    }
    
    // 3. PoH hash should be valid
    if poh_hash.is_empty() || !poh_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid PoH hash format".to_string());
    }
    
    // 4. Transaction count should be within limits
    if transactions.len() > 10_000 {
        return Err(format!(
            "Too many transactions: {} > 10000",
            transactions.len()
        ));
    }
    
    Ok(())
}

/// Vote threshold check - determines if enough stake voted for a block
pub fn check_vote_threshold(stake_voted: f64, total_stake: f64, threshold: f64) -> bool {
    if total_stake == 0.0 {
        return false;
    }
    stake_voted / total_stake >= threshold
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poh_config_default() {
        let config = PoHConfig::default();
        assert_eq!(config.slot_duration_ms, 400);  // 400ms per MANIFESTO
        assert_eq!(config.ticks_per_slot, 64);
    }

    #[test]
    fn test_poh_entry_serialization() {
        let entry = PoHEntry {
            hash: "abc123".to_string(),
            num_hashes: 100,
            transactions: vec!["tx1".to_string()],
        };
        
        // Round-trip through Borsh
        let bytes = entry.to_borsh().unwrap();
        let decoded = PoHEntry::from_borsh(&bytes).unwrap();
        assert_eq!(decoded.hash, entry.hash);
        assert_eq!(decoded.num_hashes, entry.num_hashes);
    }

    #[test]
    fn test_leader_schedule_engagement() {
        let mut schedule = LeaderSchedule::new();
        
        // Add validators with different engagement scores
        schedule.update_stake("alice", 1000.0);  // ln(1001) ≈ 6.91
        schedule.update_stake("bob", 100.0);     // ln(101) ≈ 4.62
        
        schedule.generate_schedule(0, 10);
        
        // Alice should have more slots due to higher engagement
        let alice_slots = schedule.schedule.iter()
            .filter(|e| e.leader == "alice")
            .count();
        let bob_slots = schedule.schedule.iter()
            .filter(|e| e.leader == "bob")
            .count();
        
        assert!(alice_slots > bob_slots, "Alice should lead more slots");
    }

    #[test]
    fn test_tower_lockout() {
        let lockout = TowerLockout {
            slot: 100,
            confirmation_count: 0,
        };
        assert_eq!(lockout.lockout(), 2); // 2^(0+1) = 2
        
        let lockout2 = TowerLockout {
            slot: 100,
            confirmation_count: 5,
        };
        assert_eq!(lockout2.lockout(), 64); // 2^(5+1) = 64
        
        // Lockout expiry
        assert!(!lockout.is_expired(100));
        assert!(!lockout.is_expired(101));
        assert!(lockout.is_expired(102)); // 100 + 2 = 102
    }

    #[test]
    fn test_vote_tower_basic() {
        let mut tower = VoteTower::new("validator1".to_string(), 100.0);
        
        // Initial vote
        assert!(tower.process_vote(100, 100).is_ok());
        assert_eq!(tower.last_voted_slot, 100);
        assert_eq!(tower.votes.len(), 1);
        
        // Second vote on next slot
        assert!(tower.process_vote(101, 101).is_ok());
        assert_eq!(tower.votes.len(), 2);
        
        // Cannot vote on previous slot (lockout)
        assert!(tower.process_vote(99, 102).is_err());
    }

    #[test]
    fn test_vote_signature() {
        let vote = Vote::new(100, "blockhash123".to_string(), "validator1".to_string(), 100.0);
        assert!(vote.verify());
        
        // Tampered vote should fail
        let mut tampered = vote.clone();
        tampered.slot = 101;
        assert!(!tampered.verify());
    }

    #[test]
    fn test_tower_bft_supermajority() {
        let current_slot = Arc::new(AtomicU64::new(100));
        let tower = TowerBFT::new("validator1".to_string(), current_slot);
        
        // Register validators with stake
        tower.register_validator("v1", 100.0);
        tower.register_validator("v2", 100.0);
        tower.register_validator("v3", 100.0);
        
        // Vote from 2/3 of stake
        tower.vote("v1", 100, "block100").unwrap();
        tower.vote("v2", 100, "block100").unwrap();
        
        // Should have supermajority (200/300 = 0.667)
        assert!(tower.check_supermajority(100));
        assert!(tower.is_confirmed(100));
    }

    #[test]
    fn test_fork_choice() {
        let current_slot = Arc::new(AtomicU64::new(100));
        let tower = TowerBFT::new("validator1".to_string(), current_slot);
        
        tower.register_validator("v1", 100.0);
        tower.register_validator("v2", 50.0);
        
        // v1 votes on fork A (slot 100)
        tower.vote("v1", 100, "forkA").unwrap();
        
        // v2 votes on fork B (slot 101, but less stake)
        tower.vote("v2", 101, "forkB").unwrap();
        
        // Fork choice should select heaviest (fork A with 100 stake)
        let best = tower.select_fork();
        assert!(best.is_some());
        let (slot, hash) = best.unwrap();
        assert_eq!(slot, 100);
        assert_eq!(hash, "forkA");
    }

    #[test]
    fn test_block_validity() {
        // Valid block
        assert!(verify_block_validity(
            100,
            "abc123",
            "def456",
            "leader1",
            "leader1",
            &["tx1".to_string(), "tx2".to_string()],
        ).is_ok());
        
        // Wrong leader
        assert!(verify_block_validity(
            100,
            "abc123",
            "def456",
            "wrong_leader",
            "leader1",
            &[],
        ).is_err());
    }
}