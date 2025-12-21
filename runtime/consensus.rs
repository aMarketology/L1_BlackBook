//! Layer1 Consensus Infrastructure
//!
//! Solana-style infrastructure types for:
//! - PoH Clock: Continuous timestamping via hash chain
//! - Gulf Stream: Transaction forwarding to upcoming leaders
//! - Leader Schedule: Engagement-weighted leader rotation
//!
//! NOTE: The main consensus logic (Proof of Engagement) is in src/consensus/
//! This module provides the low-level infrastructure those systems build upon.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use parking_lot::RwLock;
use borsh::{BorshSerialize, BorshDeserialize};
use dashmap::DashMap;
use crate::runtime::core::Transaction;

// ============================================================================
// GULF STREAM CONSTANTS
// ============================================================================

/// Number of upcoming leaders to forward transactions to
const GULF_STREAM_LOOKAHEAD: usize = 4;
/// Maximum transactions to cache per leader
const MAX_CACHED_TXS_PER_LEADER: usize = 10_000;
/// Number of slots before cached transactions expire
const CACHE_EXPIRY_SLOTS: u64 = 10;

// ============================================================================
// PROOF OF HISTORY (PoH) - SOLANA-INSPIRED VERIFIABLE DELAY FUNCTION
// ============================================================================

/// Configuration for the PoH clock
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PoHConfig {
    /// Target slot duration in milliseconds (400ms per MANIFESTO)
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
            slot_duration_ms: 400,    // 400ms slots per MANIFESTO
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
}
