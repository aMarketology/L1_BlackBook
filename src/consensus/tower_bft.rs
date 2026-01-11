// ============================================================================
// TOWER BFT - Solana-Style Optimistic Confirmation with Vote Lockouts
// ============================================================================
//
// Tower BFT is a practical implementation of PBFT that uses PoH as a global
// clock to reduce messaging overhead. Key features:
//
// 1. VOTE TOWER: Each validator maintains a stack of votes with exponential
//    lockouts. Voting for slot N at depth D means locked for 2^D slots.
//
// 2. STAKE-WEIGHTED VOTING: Votes are weighted by validator stake, not count.
//    Finality requires >2/3 of total stake voting for a slot.
//
// 3. OPTIMISTIC CONFIRMATION: When >2/3 stake votes for a block, it's
//    "optimistically confirmed" even before full finality (faster UX).
//
// 4. SLASHING: Validators who vote for conflicting blocks at the same height
//    (equivocation) lose a portion of their stake.
//
// Integration: Works alongside existing ForkChoiceManager and BlockProposer.
// ============================================================================

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum depth of vote tower (32 votes = 2^32 slot lockout at bottom)
pub const MAX_TOWER_DEPTH: usize = 32;

/// Minimum stake to participate in voting (in lamports)
pub const MIN_VOTING_STAKE: u64 = 1_000_000_000; // 1000 BB

/// Supermajority threshold (2/3 = 66.67%)
pub const SUPERMAJORITY_THRESHOLD: f64 = 0.6667;

/// Optimistic confirmation threshold (same as supermajority)
pub const OPTIMISTIC_CONFIRMATION_THRESHOLD: f64 = 0.6667;

/// Slots before a vote expires from consideration
pub const VOTE_EXPIRY_SLOTS: u64 = 150;

/// Slashing penalty for equivocation (5%)
pub const SLASHING_PENALTY_PERCENT: f64 = 5.0;

/// Confirmation levels
pub const SOFT_CONFIRMATION_DEPTH: usize = 2;  // Quick confirmation
pub const HARD_CONFIRMATION_DEPTH: usize = 32; // Full finality

// ============================================================================
// TOWER VOTE - Individual vote with stake weight
// ============================================================================

/// A single vote in a validator's tower
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TowerVote {
    /// Slot being voted for
    pub slot: u64,
    
    /// Block hash at this slot
    pub block_hash: String,
    
    /// Confirmation count (increments as more votes stack on top)
    pub confirmation_count: u32,
    
    /// Lockout expiration slot (slot + 2^confirmation_count)
    pub lockout_expiry: u64,
    
    /// Timestamp of vote (PoH tick)
    pub timestamp: u64,
}

impl TowerVote {
    pub fn new(slot: u64, block_hash: String, poh_tick: u64) -> Self {
        Self {
            slot,
            block_hash,
            confirmation_count: 1,
            lockout_expiry: slot + 2, // 2^1 = 2 slots initial lockout
            timestamp: poh_tick,
        }
    }
    
    /// Calculate lockout duration based on confirmation depth
    pub fn lockout_duration(&self) -> u64 {
        2u64.pow(self.confirmation_count)
    }
    
    /// Check if vote is still locked at given slot
    pub fn is_locked(&self, current_slot: u64) -> bool {
        current_slot < self.lockout_expiry
    }
    
    /// Increment confirmation and extend lockout
    pub fn increment_confirmation(&mut self) {
        if self.confirmation_count < MAX_TOWER_DEPTH as u32 {
            self.confirmation_count += 1;
            self.lockout_expiry = self.slot + self.lockout_duration();
        }
    }
}

// ============================================================================
// VOTE TOWER - Validator's vote stack with lockouts
// ============================================================================

/// A validator's tower of votes with exponential lockouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTower {
    /// Validator's public key
    pub validator_pubkey: String,
    
    /// Stack of votes (newest at end)
    pub votes: Vec<TowerVote>,
    
    /// Root slot (oldest finalized slot in tower)
    pub root_slot: u64,
    
    /// Last vote slot
    pub last_vote_slot: u64,
    
    /// Tower hash for persistence/verification
    pub tower_hash: String,
    
    /// Total stake of this validator (in lamports)
    pub stake: u64,
    
    /// Slots this validator has been slashed (for equivocation tracking)
    pub slashed_slots: HashSet<u64>,
}

impl VoteTower {
    pub fn new(validator_pubkey: String, stake: u64) -> Self {
        Self {
            validator_pubkey,
            votes: Vec::with_capacity(MAX_TOWER_DEPTH),
            root_slot: 0,
            last_vote_slot: 0,
            tower_hash: String::new(),
            stake,
            slashed_slots: HashSet::new(),
        }
    }
    
    /// Add a new vote to the tower
    /// Returns Err if vote violates lockout rules
    pub fn vote(&mut self, slot: u64, block_hash: String, poh_tick: u64) -> Result<(), TowerError> {
        // Can't vote for slots we're locked on
        if let Some(lockout_violation) = self.check_lockout_violation(slot) {
            return Err(TowerError::LockoutViolation {
                slot,
                locked_until: lockout_violation,
            });
        }
        
        // Can't vote for slots before our root
        if slot <= self.root_slot {
            return Err(TowerError::VoteTooOld {
                slot,
                root: self.root_slot,
            });
        }
        
        // Pop votes that are no longer locked
        self.pop_expired_votes(slot);
        
        // Increment confirmation counts for existing votes
        for vote in &mut self.votes {
            vote.increment_confirmation();
        }
        
        // Add new vote at top of tower
        let new_vote = TowerVote::new(slot, block_hash, poh_tick);
        self.votes.push(new_vote);
        
        // Trim tower if too deep
        if self.votes.len() > MAX_TOWER_DEPTH {
            // Bottom vote becomes new root
            let old_vote = self.votes.remove(0);
            self.root_slot = old_vote.slot;
        }
        
        self.last_vote_slot = slot;
        self.update_tower_hash();
        
        Ok(())
    }
    
    /// Check if voting for this slot would violate any lockout
    fn check_lockout_violation(&self, slot: u64) -> Option<u64> {
        for vote in &self.votes {
            if vote.is_locked(slot) && slot < vote.lockout_expiry {
                return Some(vote.lockout_expiry);
            }
        }
        None
    }
    
    /// Remove votes whose lockouts have expired
    fn pop_expired_votes(&mut self, current_slot: u64) {
        self.votes.retain(|vote| vote.is_locked(current_slot));
    }
    
    /// Update tower hash for persistence
    fn update_tower_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.validator_pubkey.as_bytes());
        hasher.update(self.root_slot.to_le_bytes());
        for vote in &self.votes {
            hasher.update(vote.slot.to_le_bytes());
            hasher.update(vote.block_hash.as_bytes());
        }
        self.tower_hash = hex::encode(hasher.finalize());
    }
    
    /// Get the highest slot this tower has voted for
    pub fn last_voted_slot(&self) -> u64 {
        self.votes.last().map(|v| v.slot).unwrap_or(self.root_slot)
    }
    
    /// Get confirmation count for a specific slot
    pub fn confirmation_count(&self, slot: u64) -> Option<u32> {
        self.votes.iter()
            .find(|v| v.slot == slot)
            .map(|v| v.confirmation_count)
    }
    
    /// Check if slot is in our vote history
    pub fn has_voted_for(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.slot == slot) || slot <= self.root_slot
    }
    
    /// Get current tower depth
    pub fn depth(&self) -> usize {
        self.votes.len()
    }
}

// ============================================================================
// VOTE STATE - On-chain vote account
// ============================================================================

/// On-chain vote account tracking validator voting history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteState {
    /// Validator's node pubkey
    pub node_pubkey: String,
    
    /// Validator's vote pubkey (separate from node key for security)
    pub vote_pubkey: String,
    
    /// Authorized withdrawer
    pub authorized_withdrawer: String,
    
    /// Commission rate (0-100%)
    pub commission: u8,
    
    /// Root slot history
    pub root_slots: VecDeque<u64>,
    
    /// Recent votes (slot, confirmation_count)
    pub votes: VecDeque<(u64, u32)>,
    
    /// Total stake delegated to this validator
    pub activated_stake: u64,
    
    /// Epoch credits earned
    pub epoch_credits: Vec<(u64, u64, u64)>, // (epoch, credits, prev_credits)
    
    /// Last timestamp
    pub last_timestamp: u64,
    
    /// Whether this validator has been slashed
    pub is_slashed: bool,
    
    /// Total amount slashed
    pub total_slashed: u64,
}

impl VoteState {
    pub fn new(node_pubkey: String, vote_pubkey: String, stake: u64) -> Self {
        Self {
            node_pubkey,
            vote_pubkey: vote_pubkey.clone(),
            authorized_withdrawer: vote_pubkey,
            commission: 10, // 10% default commission
            root_slots: VecDeque::with_capacity(32),
            votes: VecDeque::with_capacity(MAX_TOWER_DEPTH),
            activated_stake: stake,
            epoch_credits: Vec::new(),
            last_timestamp: 0,
            is_slashed: false,
            total_slashed: 0,
        }
    }
    
    /// Record a new vote
    pub fn record_vote(&mut self, slot: u64, confirmation_count: u32) {
        // Remove old votes
        while self.votes.len() >= MAX_TOWER_DEPTH {
            self.votes.pop_front();
        }
        self.votes.push_back((slot, confirmation_count));
    }
    
    /// Record a new root
    pub fn record_root(&mut self, slot: u64) {
        while self.root_slots.len() >= 32 {
            self.root_slots.pop_front();
        }
        self.root_slots.push_back(slot);
    }
    
    /// Apply slashing penalty
    pub fn slash(&mut self, amount: u64) {
        self.is_slashed = true;
        self.total_slashed += amount;
        self.activated_stake = self.activated_stake.saturating_sub(amount);
    }
}

// ============================================================================
// STAKE-WEIGHTED VOTE ACCUMULATOR
// ============================================================================

/// Aggregates stake-weighted votes for a slot
#[derive(Debug, Clone)]
pub struct StakeWeightedVotes {
    /// Slot being voted for
    pub slot: u64,
    
    /// Block hash
    pub block_hash: String,
    
    /// Map of validator pubkey -> (stake, vote)
    pub votes: HashMap<String, (u64, TowerVote)>,
    
    /// Total stake that has voted
    pub total_voted_stake: u64,
    
    /// Total stake in the network
    pub total_network_stake: u64,
    
    /// Whether optimistically confirmed (>2/3 stake)
    pub optimistically_confirmed: bool,
    
    /// Confirmation timestamp
    pub confirmed_at: Option<u64>,
}

impl StakeWeightedVotes {
    pub fn new(slot: u64, block_hash: String, total_network_stake: u64) -> Self {
        Self {
            slot,
            block_hash,
            votes: HashMap::new(),
            total_voted_stake: 0,
            total_network_stake,
            optimistically_confirmed: false,
            confirmed_at: None,
        }
    }
    
    /// Add a vote with stake weight
    pub fn add_vote(&mut self, validator_pubkey: String, stake: u64, vote: TowerVote) -> bool {
        if self.votes.contains_key(&validator_pubkey) {
            return false; // Already voted
        }
        
        self.votes.insert(validator_pubkey, (stake, vote));
        self.total_voted_stake += stake;
        
        // Check for optimistic confirmation
        if !self.optimistically_confirmed {
            let stake_ratio = self.total_voted_stake as f64 / self.total_network_stake as f64;
            if stake_ratio >= OPTIMISTIC_CONFIRMATION_THRESHOLD {
                self.optimistically_confirmed = true;
                self.confirmed_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                );
                return true; // Newly confirmed!
            }
        }
        
        false
    }
    
    /// Get stake ratio voted
    pub fn stake_ratio(&self) -> f64 {
        if self.total_network_stake == 0 {
            return 0.0;
        }
        self.total_voted_stake as f64 / self.total_network_stake as f64
    }
    
    /// Check if supermajority reached
    pub fn has_supermajority(&self) -> bool {
        self.stake_ratio() >= SUPERMAJORITY_THRESHOLD
    }
}

// ============================================================================
// OPTIMISTIC CONFIRMATION TRACKER
// ============================================================================

/// Tracks optimistically confirmed slots
#[derive(Debug)]
pub struct OptimisticConfirmationTracker {
    /// Map of slot -> stake-weighted votes
    confirmed_slots: HashMap<u64, StakeWeightedVotes>,
    
    /// Highest optimistically confirmed slot
    highest_confirmed: u64,
    
    /// Finalized root (never rolls back)
    finalized_root: u64,
    
    /// Total network stake
    total_stake: u64,
}

impl OptimisticConfirmationTracker {
    pub fn new(total_stake: u64) -> Self {
        Self {
            confirmed_slots: HashMap::new(),
            highest_confirmed: 0,
            finalized_root: 0,
            total_stake,
        }
    }
    
    /// Record a vote and check for confirmation
    pub fn record_vote(
        &mut self,
        slot: u64,
        block_hash: String,
        validator_pubkey: String,
        stake: u64,
        vote: TowerVote,
    ) -> Option<OptimisticConfirmationEvent> {
        let votes = self.confirmed_slots
            .entry(slot)
            .or_insert_with(|| StakeWeightedVotes::new(slot, block_hash.clone(), self.total_stake));
        
        let newly_confirmed = votes.add_vote(validator_pubkey.clone(), stake, vote);
        
        if newly_confirmed {
            self.highest_confirmed = self.highest_confirmed.max(slot);
            
            return Some(OptimisticConfirmationEvent {
                slot,
                block_hash,
                stake_ratio: votes.stake_ratio(),
                total_voted_stake: votes.total_voted_stake,
                timestamp: votes.confirmed_at.unwrap_or(0),
            });
        }
        
        None
    }
    
    /// Set new finalized root
    pub fn set_finalized_root(&mut self, slot: u64) {
        self.finalized_root = slot;
        // Clean up old confirmed slots
        self.confirmed_slots.retain(|&s, _| s > slot.saturating_sub(VOTE_EXPIRY_SLOTS));
    }
    
    /// Check if slot is optimistically confirmed
    pub fn is_confirmed(&self, slot: u64) -> bool {
        self.confirmed_slots.get(&slot)
            .map(|v| v.optimistically_confirmed)
            .unwrap_or(false)
    }
    
    /// Get stake ratio for slot
    pub fn get_stake_ratio(&self, slot: u64) -> Option<f64> {
        self.confirmed_slots.get(&slot).map(|v| v.stake_ratio())
    }
    
    /// Update total network stake
    pub fn update_total_stake(&mut self, stake: u64) {
        self.total_stake = stake;
    }
}

/// Event emitted when a slot is optimistically confirmed
#[derive(Debug, Clone)]
pub struct OptimisticConfirmationEvent {
    pub slot: u64,
    pub block_hash: String,
    pub stake_ratio: f64,
    pub total_voted_stake: u64,
    pub timestamp: u64,
}

// ============================================================================
// TOWER BFT ENGINE
// ============================================================================

/// Main Tower BFT consensus engine
pub struct TowerBFT {
    /// Local validator's tower
    pub local_tower: Arc<RwLock<VoteTower>>,
    
    /// All validators' vote states
    pub vote_states: Arc<RwLock<HashMap<String, VoteState>>>,
    
    /// Optimistic confirmation tracker
    pub confirmation_tracker: Arc<RwLock<OptimisticConfirmationTracker>>,
    
    /// Equivocation detector
    pub equivocation_detector: Arc<RwLock<EquivocationDetector>>,
    
    /// Our validator pubkey
    pub validator_pubkey: String,
    
    /// Our stake
    pub stake: u64,
    
    /// Epoch info for stake updates
    pub current_epoch: u64,
}

impl TowerBFT {
    pub fn new(validator_pubkey: String, stake: u64, total_network_stake: u64) -> Self {
        Self {
            local_tower: Arc::new(RwLock::new(VoteTower::new(validator_pubkey.clone(), stake))),
            vote_states: Arc::new(RwLock::new(HashMap::new())),
            confirmation_tracker: Arc::new(RwLock::new(OptimisticConfirmationTracker::new(total_network_stake))),
            equivocation_detector: Arc::new(RwLock::new(EquivocationDetector::new())),
            validator_pubkey,
            stake,
            current_epoch: 0,
        }
    }
    
    /// Vote for a slot/block
    pub fn vote(&self, slot: u64, block_hash: String, poh_tick: u64) -> Result<TowerVote, TowerError> {
        let mut tower = self.local_tower.write();
        tower.vote(slot, block_hash.clone(), poh_tick)?;
        
        let vote = tower.votes.last().cloned()
            .ok_or(TowerError::NoVote)?;
        
        // Record in confirmation tracker
        let mut tracker = self.confirmation_tracker.write();
        if let Some(event) = tracker.record_vote(
            slot,
            block_hash.clone(),
            self.validator_pubkey.clone(),
            self.stake,
            vote.clone(),
        ) {
            println!("🎯 Optimistic confirmation at slot {}: {:.2}% stake", 
                     event.slot, event.stake_ratio * 100.0);
        }
        
        Ok(vote)
    }
    
    /// Process vote from another validator
    pub fn receive_vote(
        &self,
        validator_pubkey: String,
        stake: u64,
        vote: TowerVote,
    ) -> Result<Option<OptimisticConfirmationEvent>, TowerError> {
        // Check for equivocation
        {
            let mut detector = self.equivocation_detector.write();
            if let Some(evidence) = detector.check_vote(&validator_pubkey, &vote) {
                return Err(TowerError::Equivocation(evidence));
            }
        }
        
        // Record vote in confirmation tracker
        let mut tracker = self.confirmation_tracker.write();
        let event = tracker.record_vote(
            vote.slot,
            vote.block_hash.clone(),
            validator_pubkey.clone(),
            stake,
            vote.clone(),
        );
        
        // Update vote state
        {
            let mut states = self.vote_states.write();
            let state = states.entry(validator_pubkey.clone())
                .or_insert_with(|| VoteState::new(validator_pubkey, String::new(), stake));
            state.record_vote(vote.slot, vote.confirmation_count);
        }
        
        Ok(event)
    }
    
    /// Check if a slot is optimistically confirmed
    pub fn is_optimistically_confirmed(&self, slot: u64) -> bool {
        self.confirmation_tracker.read().is_confirmed(slot)
    }
    
    /// Get current tower depth
    pub fn tower_depth(&self) -> usize {
        self.local_tower.read().depth()
    }
    
    /// Get last voted slot
    pub fn last_voted_slot(&self) -> u64 {
        self.local_tower.read().last_voted_slot()
    }
    
    /// Get finalized root
    pub fn finalized_root(&self) -> u64 {
        self.confirmation_tracker.read().finalized_root
    }
    
    /// Set new finalized root (called when block reaches 32 confirmations)
    pub fn set_finalized_root(&self, slot: u64) {
        self.confirmation_tracker.write().set_finalized_root(slot);
        println!("🔒 Finalized root set to slot {}", slot);
    }
    
    /// Slash a validator for equivocation
    pub fn slash_validator(&self, validator_pubkey: &str, evidence: EquivocationEvidence) -> u64 {
        let mut states = self.vote_states.write();
        
        if let Some(state) = states.get_mut(validator_pubkey) {
            let slash_amount = (state.activated_stake as f64 * SLASHING_PENALTY_PERCENT / 100.0) as u64;
            state.slash(slash_amount);
            
            println!("⚔️ SLASHED validator {} for equivocation at slot {}: -{} lamports",
                     &validator_pubkey[..16], evidence.slot, slash_amount);
            
            return slash_amount;
        }
        
        0
    }
}

// ============================================================================
// EQUIVOCATION DETECTION
// ============================================================================

/// Evidence of equivocation (voting for conflicting blocks)
#[derive(Debug, Clone)]
pub struct EquivocationEvidence {
    pub validator_pubkey: String,
    pub slot: u64,
    pub first_vote: TowerVote,
    pub second_vote: TowerVote,
    pub detected_at: u64,
}

/// Detects validators voting for conflicting blocks at the same slot
pub struct EquivocationDetector {
    /// Map of (validator, slot) -> first vote seen
    votes_by_slot: HashMap<(String, u64), TowerVote>,
    
    /// Detected equivocations
    equivocations: Vec<EquivocationEvidence>,
    
    /// Already slashed (validator, slot) pairs
    slashed: HashSet<(String, u64)>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self {
            votes_by_slot: HashMap::new(),
            equivocations: Vec::new(),
            slashed: HashSet::new(),
        }
    }
    
    /// Check if a vote constitutes equivocation
    /// Returns Some(evidence) if equivocation detected
    pub fn check_vote(&mut self, validator_pubkey: &str, vote: &TowerVote) -> Option<EquivocationEvidence> {
        let key = (validator_pubkey.to_string(), vote.slot);
        
        // Already slashed for this slot?
        if self.slashed.contains(&key) {
            return None;
        }
        
        if let Some(existing_vote) = self.votes_by_slot.get(&key) {
            // Same slot, different block hash = EQUIVOCATION!
            if existing_vote.block_hash != vote.block_hash {
                let evidence = EquivocationEvidence {
                    validator_pubkey: validator_pubkey.to_string(),
                    slot: vote.slot,
                    first_vote: existing_vote.clone(),
                    second_vote: vote.clone(),
                    detected_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                };
                
                self.equivocations.push(evidence.clone());
                self.slashed.insert(key);
                
                return Some(evidence);
            }
        } else {
            self.votes_by_slot.insert(key, vote.clone());
        }
        
        None
    }
    
    /// Clean up old votes
    pub fn prune(&mut self, current_slot: u64) {
        let cutoff = current_slot.saturating_sub(VOTE_EXPIRY_SLOTS);
        self.votes_by_slot.retain(|(_, slot), _| *slot > cutoff);
    }
    
    /// Get all detected equivocations
    pub fn get_equivocations(&self) -> &[EquivocationEvidence] {
        &self.equivocations
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum TowerError {
    LockoutViolation { slot: u64, locked_until: u64 },
    VoteTooOld { slot: u64, root: u64 },
    Equivocation(EquivocationEvidence),
    NoVote,
    InvalidVote(String),
}

impl std::fmt::Display for TowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TowerError::LockoutViolation { slot, locked_until } => {
                write!(f, "Cannot vote for slot {} - locked until slot {}", slot, locked_until)
            }
            TowerError::VoteTooOld { slot, root } => {
                write!(f, "Vote for slot {} is too old (root is {})", slot, root)
            }
            TowerError::Equivocation(e) => {
                write!(f, "Equivocation detected: validator {} voted for different blocks at slot {}",
                       &e.validator_pubkey[..16], e.slot)
            }
            TowerError::NoVote => write!(f, "No vote recorded"),
            TowerError::InvalidVote(msg) => write!(f, "Invalid vote: {}", msg),
        }
    }
}

impl std::error::Error for TowerError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vote_tower_basic() {
        let mut tower = VoteTower::new("validator1".to_string(), 1_000_000_000);
        
        // First vote
        assert!(tower.vote(1, "hash1".to_string(), 100).is_ok());
        assert_eq!(tower.depth(), 1);
        assert_eq!(tower.last_voted_slot(), 1);
        
        // Second vote
        assert!(tower.vote(2, "hash2".to_string(), 200).is_ok());
        assert_eq!(tower.depth(), 2);
        
        // Check confirmation counts increased
        assert_eq!(tower.votes[0].confirmation_count, 2);
        assert_eq!(tower.votes[1].confirmation_count, 1);
    }
    
    #[test]
    fn test_vote_tower_lockout() {
        let mut tower = VoteTower::new("validator1".to_string(), 1_000_000_000);
        
        // Vote for slot 10
        tower.vote(10, "hash10".to_string(), 100).unwrap();
        
        // Try to vote for slot 11 (should work, lockout is 2 slots)
        assert!(tower.vote(11, "hash11".to_string(), 200).is_ok());
    }
    
    #[test]
    fn test_stake_weighted_votes() {
        let total_stake = 10_000_000_000u64;
        let mut votes = StakeWeightedVotes::new(100, "block100".to_string(), total_stake);
        
        // Add votes until supermajority
        let vote = TowerVote::new(100, "block100".to_string(), 1000);
        
        // 30% stake - no confirmation
        votes.add_vote("v1".to_string(), 3_000_000_000, vote.clone());
        assert!(!votes.optimistically_confirmed);
        
        // 30% more = 60% - still no confirmation
        votes.add_vote("v2".to_string(), 3_000_000_000, vote.clone());
        assert!(!votes.optimistically_confirmed);
        
        // 10% more = 70% - CONFIRMED!
        let confirmed = votes.add_vote("v3".to_string(), 1_000_000_000, vote.clone());
        assert!(confirmed);
        assert!(votes.optimistically_confirmed);
    }
    
    #[test]
    fn test_equivocation_detection() {
        let mut detector = EquivocationDetector::new();
        
        let vote1 = TowerVote::new(100, "block_a".to_string(), 1000);
        let vote2 = TowerVote::new(100, "block_b".to_string(), 1001);
        
        // First vote - no equivocation
        assert!(detector.check_vote("validator1", &vote1).is_none());
        
        // Second vote for same slot, different block - EQUIVOCATION!
        let evidence = detector.check_vote("validator1", &vote2);
        assert!(evidence.is_some());
        
        let e = evidence.unwrap();
        assert_eq!(e.slot, 100);
        assert_eq!(e.first_vote.block_hash, "block_a");
        assert_eq!(e.second_vote.block_hash, "block_b");
    }
    
    #[test]
    fn test_tower_bft_integration() {
        let tower = TowerBFT::new("local_validator".to_string(), 5_000_000_000, 10_000_000_000);
        
        // Vote for slots
        tower.vote(1, "hash1".to_string(), 100).unwrap();
        tower.vote(2, "hash2".to_string(), 200).unwrap();
        
        assert_eq!(tower.tower_depth(), 2);
        assert_eq!(tower.last_voted_slot(), 2);
        
        // Receive vote from another validator (enough for confirmation)
        let other_vote = TowerVote::new(2, "hash2".to_string(), 200);
        let event = tower.receive_vote("other_validator".to_string(), 5_000_000_000, other_vote).unwrap();
        
        // Should be optimistically confirmed (10B total, 5B + 5B = 100% > 66.67%)
        assert!(event.is_some());
        assert!(tower.is_optimistically_confirmed(2));
    }
}
