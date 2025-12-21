//! Blockchain State Management
//!
//! PoH-aware state tracking and Archivers for distributed ledger storage.
//!
//! INFRASTRUCTURE NOTE: ChainState and extended slot tracking are built for
//! multi-validator coordination. ArchiveService is used for block persistence.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use dashmap::DashMap;

// =====================================================
// ARCHIVERS CONSTANTS
// =====================================================

/// Number of slots per segment (Solana uses ~400k)
const SLOTS_PER_SEGMENT: u64 = 1000;
/// Maximum segments to keep in memory
const MAX_SEGMENTS_IN_MEMORY: usize = 10;
/// Simulated archivers in the network
const SIMULATED_ARCHIVERS: usize = 100;
/// Replication factor for segments
const REPLICATION_FACTOR: usize = 3;

// =====================================================
// PROOF OF HISTORY - Block State Management
// =====================================================

/// PoH-aware block header for fast verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoHBlockHeader {
    pub slot: u64,
    pub parent_slot: u64,
    pub poh_hash: String,
    pub parent_poh_hash: String,
    pub leader: String,
    pub timestamp: u64,
    pub tick_count: u64,
    pub transaction_count: u32,
}

impl Default for PoHBlockHeader {
    fn default() -> Self {
        Self {
            slot: 0,
            parent_slot: 0,
            poh_hash: "genesis".to_string(),
            parent_poh_hash: "genesis".to_string(),
            leader: "genesis_leader".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tick_count: 0,
            transaction_count: 0,
        }
    }
}

/// Slot status for block finality tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlotStatus {
    Processing,
    Confirmed,
    Finalized,
    Skipped,
}

/// PoH chain state - tracks the verifiable history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoHChainState {
    pub current_slot: u64,
    pub current_poh_hash: String,
    pub current_tick: u64,
    pub slot_hashes: HashMap<u64, String>,
    pub slot_statuses: HashMap<u64, SlotStatus>,
    pub finalized_slot: u64,
    pub confirmed_slot: u64,
    pub genesis_hash: String,
}

impl Default for PoHChainState {
    fn default() -> Self {
        let genesis_hash = sha256_hash("layer1_genesis_v2_poh");
        Self {
            current_slot: 0,
            current_poh_hash: genesis_hash.clone(),
            current_tick: 0,
            slot_hashes: {
                let mut m = HashMap::new();
                m.insert(0, genesis_hash.clone());
                m
            },
            slot_statuses: {
                let mut m = HashMap::new();
                m.insert(0, SlotStatus::Finalized);
                m
            },
            finalized_slot: 0,
            confirmed_slot: 0,
            genesis_hash,
        }
    }
}

impl PoHChainState {
    pub fn advance_slot(&mut self, new_poh_hash: String, tick_count: u64) {
        self.current_slot += 1;
        self.current_poh_hash = new_poh_hash.clone();
        self.current_tick += tick_count;
        self.slot_hashes.insert(self.current_slot, new_poh_hash);
        self.slot_statuses.insert(self.current_slot, SlotStatus::Processing);
    }

    pub fn confirm_slot(&mut self, slot: u64) {
        if let Some(status) = self.slot_statuses.get_mut(&slot) {
            *status = SlotStatus::Confirmed;
            if slot > self.confirmed_slot {
                self.confirmed_slot = slot;
            }
        }
    }

    pub fn finalize_slot(&mut self, slot: u64) {
        if let Some(status) = self.slot_statuses.get_mut(&slot) {
            *status = SlotStatus::Finalized;
            if slot > self.finalized_slot {
                self.finalized_slot = slot;
            }
        }
    }

    pub fn get_slot_status(&self, slot: u64) -> Option<&SlotStatus> {
        self.slot_statuses.get(&slot)
    }

    pub fn is_slot_finalized(&self, slot: u64) -> bool {
        self.slot_statuses.get(&slot) == Some(&SlotStatus::Finalized)
    }

    pub fn get_recent_slots(&self, count: usize) -> Vec<(u64, SlotStatus)> {
        let start = self.current_slot.saturating_sub(count as u64 - 1);
        (start..=self.current_slot)
            .filter_map(|s| self.slot_statuses.get(&s).map(|status| (s, status.clone())))
            .collect()
    }
}

fn sha256_hash(data: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Thread-safe PoH state manager
#[derive(Clone)]
pub struct PoHStateManager {
    pub chain_state: Arc<RwLock<PoHChainState>>,
    pub slot_leaders: Arc<RwLock<HashMap<u64, String>>>,
}

impl Default for PoHStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PoHStateManager {
    pub fn new() -> Self {
        Self {
            chain_state: Arc::new(RwLock::new(PoHChainState::default())),
            slot_leaders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_leader(&self, slot: u64, leader: String) {
        self.slot_leaders.write().insert(slot, leader);
    }

    pub fn get_leader(&self, slot: u64) -> Option<String> {
        self.slot_leaders.read().get(&slot).cloned()
    }

    pub fn current_slot(&self) -> u64 {
        self.chain_state.read().current_slot
    }

    pub fn current_poh_hash(&self) -> String {
        self.chain_state.read().current_poh_hash.clone()
    }

    pub fn finalized_slot(&self) -> u64 {
        self.chain_state.read().finalized_slot
    }

    pub fn get_state_snapshot(&self) -> PoHChainState {
        self.chain_state.read().clone()
    }

    pub fn get_slot_info(&self) -> serde_json::Value {
        let state = self.chain_state.read();
        serde_json::json!({
            "current_slot": state.current_slot,
            "current_tick": state.current_tick,
            "confirmed_slot": state.confirmed_slot,
            "finalized_slot": state.finalized_slot,
            "poh_hash": state.current_poh_hash,
            "recent_slots": state.get_recent_slots(10)
                .iter()
                .map(|(slot, status)| serde_json::json!({
                    "slot": slot,
                    "status": format!("{:?}", status)
                }))
                .collect::<Vec<_>>()
        })
    }
}

// ============================================================================
// ARCHIVERS - Distributed Ledger Storage
// ============================================================================
//
// Solana's Archivers provide distributed storage for historical ledger data:
// 1. Ledger is split into "segments" (~400k slots each)
// 2. Segments are erasure-coded for redundancy
// 3. Archivers store random segments, incentivized by rewards
// 4. Proof of Replication ensures data availability
//
// In single-node mode, we simulate segment management for API compatibility.

/// A segment of the ledger (multiple slots worth of data)
#[derive(Debug, Clone, Serialize)]
pub struct Segment {
    /// Segment index (which segment in the ledger)
    pub index: u64,
    /// First slot in this segment
    pub first_slot: u64,
    /// Last slot in this segment
    pub last_slot: u64,
    /// Segment hash (merkle root of all blocks)
    pub segment_hash: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// When this segment was created
    pub created_at: u64,
    /// Block hashes in this segment (for verification)
    pub block_hashes: Vec<String>,
    /// Is this segment finalized
    pub finalized: bool,
    /// Archivers storing this segment (simulated)
    pub archiver_ids: Vec<String>,
}

impl Segment {
    pub fn new(index: u64) -> Self {
        let first_slot = index * SLOTS_PER_SEGMENT;
        let last_slot = first_slot + SLOTS_PER_SEGMENT - 1;
        
        Self {
            index,
            first_slot,
            last_slot,
            segment_hash: String::new(),
            size_bytes: 0,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            block_hashes: Vec::new(),
            finalized: false,
            archiver_ids: Vec::new(),
        }
    }
    
    /// Add a block hash to this segment
    pub fn add_block(&mut self, slot: u64, block_hash: String, size: u64) {
        if slot >= self.first_slot && slot <= self.last_slot {
            self.block_hashes.push(block_hash);
            self.size_bytes += size;
        }
    }
    
    /// Check if segment is complete
    pub fn is_complete(&self) -> bool {
        self.block_hashes.len() as u64 >= SLOTS_PER_SEGMENT
    }
    
    /// Finalize the segment (compute merkle root)
    pub fn finalize(&mut self) {
        if !self.block_hashes.is_empty() {
            // Simple merkle root: hash all block hashes together
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for hash in &self.block_hashes {
                hasher.update(hash.as_bytes());
            }
            self.segment_hash = format!("{:x}", hasher.finalize());
            self.finalized = true;
        }
    }
}

/// Simulated archiver node
#[derive(Debug, Clone, Serialize)]
pub struct Archiver {
    /// Unique archiver ID
    pub id: String,
    /// Segments this archiver is storing
    pub segments: Vec<u64>,
    /// Total bytes stored
    pub bytes_stored: u64,
    /// Proofs of replication submitted
    pub proofs_submitted: u64,
    /// Rewards earned (simulated)
    pub rewards_earned: f64,
    /// Last active timestamp
    pub last_active: u64,
    /// Is this archiver online
    pub online: bool,
}

impl Archiver {
    pub fn new(id: String) -> Self {
        Self {
            id,
            segments: Vec::new(),
            bytes_stored: 0,
            proofs_submitted: 0,
            rewards_earned: 0.0,
            last_active: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            online: true,
        }
    }
    
    /// Assign a segment to this archiver
    pub fn assign_segment(&mut self, segment_idx: u64, size: u64) {
        if !self.segments.contains(&segment_idx) {
            self.segments.push(segment_idx);
            self.bytes_stored += size;
        }
    }
}

/// Statistics for Archive service
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveStats {
    pub total_segments: u64,
    pub finalized_segments: u64,
    pub total_archivers: usize,
    pub online_archivers: usize,
    pub total_bytes_archived: u64,
    pub total_proofs_verified: u64,
    pub avg_replication_factor: f64,
    pub oldest_segment: u64,
    pub newest_segment: u64,
    pub is_active: bool,
}

/// Archive Service - Distributed ledger storage
///
/// Implements Solana-style archiving:
/// - Segments ledger into manageable chunks
/// - Assigns segments to archivers with replication
/// - Tracks proof of replication (simulated)
/// - Provides segment retrieval API
pub struct ArchiveService {
    /// All segments (indexed by segment number)
    segments: DashMap<u64, Segment>,
    
    /// Current (incomplete) segment
    current_segment: RwLock<Segment>,
    
    /// Simulated archivers
    archivers: DashMap<String, Archiver>,
    
    /// Segment to archiver mapping
    segment_archivers: DashMap<u64, Vec<String>>,
    
    /// Statistics
    total_segments: AtomicU64,
    finalized_segments: AtomicU64,
    total_bytes: AtomicU64,
    proofs_verified: AtomicU64,
    
    /// Service state
    is_active: AtomicBool,
}

impl ArchiveService {
    /// Create a new Archive service
    pub fn new() -> Arc<Self> {
        // Create simulated archivers
        let archivers = DashMap::new();
        for i in 0..SIMULATED_ARCHIVERS {
            let id = format!("archiver_{:03}", i);
            archivers.insert(id.clone(), Archiver::new(id));
        }
        
        println!("📚 Archive Service initialized:");
        println!("   └─ {} slots/segment, {} archivers, {}x replication", 
                 SLOTS_PER_SEGMENT, SIMULATED_ARCHIVERS, REPLICATION_FACTOR);
        
        Arc::new(Self {
            segments: DashMap::new(),
            current_segment: RwLock::new(Segment::new(0)),
            archivers,
            segment_archivers: DashMap::new(),
            total_segments: AtomicU64::new(0),
            finalized_segments: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            proofs_verified: AtomicU64::new(0),
            is_active: AtomicBool::new(false),
        })
    }
    
    /// Add a block to the archive
    pub fn archive_block(&self, slot: u64, block_hash: String, size: u64) {
        let expected_segment = slot / SLOTS_PER_SEGMENT;
        
        {
            let mut current = self.current_segment.write();
            
            // Check if we need to start a new segment
            if expected_segment > current.index {
                // Finalize current segment
                if !current.block_hashes.is_empty() {
                    current.finalize();
                    self.finalize_segment(current.clone());
                }
                
                // Start new segment
                *current = Segment::new(expected_segment);
            }
            
            // Add block to current segment
            current.add_block(slot, block_hash, size);
            self.total_bytes.fetch_add(size, Ordering::Relaxed);
            
            // Check if segment is now complete
            if current.is_complete() {
                current.finalize();
                self.finalize_segment(current.clone());
                *current = Segment::new(expected_segment + 1);
            }
        }
    }
    
    /// Finalize and distribute a segment
    fn finalize_segment(&self, segment: Segment) {
        let idx = segment.index;
        
        // Select archivers for this segment (round-robin with replication)
        let archiver_ids: Vec<String> = self.archivers.iter()
            .map(|e| e.key().clone())
            .collect::<Vec<_>>()
            .into_iter()
            .cycle()
            .skip((idx as usize * REPLICATION_FACTOR) % SIMULATED_ARCHIVERS)
            .take(REPLICATION_FACTOR)
            .collect();
        
        // Assign to archivers
        for archiver_id in &archiver_ids {
            if let Some(mut archiver) = self.archivers.get_mut(archiver_id) {
                archiver.assign_segment(idx, segment.size_bytes);
            }
        }
        
        // Store segment and mapping
        let mut final_segment = segment;
        final_segment.archiver_ids = archiver_ids.clone();
        
        self.segments.insert(idx, final_segment);
        self.segment_archivers.insert(idx, archiver_ids);
        
        self.total_segments.fetch_add(1, Ordering::Relaxed);
        self.finalized_segments.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get a segment by index
    pub fn get_segment(&self, index: u64) -> Option<Segment> {
        self.segments.get(&index).map(|s| s.clone())
    }
    
    /// Get segment for a specific slot
    pub fn get_segment_for_slot(&self, slot: u64) -> Option<Segment> {
        let segment_idx = slot / SLOTS_PER_SEGMENT;
        self.get_segment(segment_idx)
    }
    
    /// Verify proof of replication (simulated)
    pub fn verify_proof(&self, archiver_id: &str, segment_idx: u64) -> bool {
        // Check archiver has this segment
        if let Some(mut archiver) = self.archivers.get_mut(archiver_id) {
            if archiver.segments.contains(&segment_idx) {
                archiver.proofs_submitted += 1;
                archiver.last_active = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                self.proofs_verified.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
    
    /// Get archiver info
    pub fn get_archiver(&self, id: &str) -> Option<Archiver> {
        self.archivers.get(id).map(|a| a.clone())
    }
    
    /// Get all archivers for a segment
    pub fn get_segment_archivers(&self, segment_idx: u64) -> Vec<String> {
        self.segment_archivers.get(&segment_idx)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
    
    /// Start the archive service
    pub fn start(self: &Arc<Self>) {
        self.is_active.store(true, Ordering::Relaxed);
        println!("📚 Archive service activated");
    }
    
    /// Stop the service
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::Relaxed);
    }
    
    /// Get archive statistics
    pub fn get_stats(&self) -> ArchiveStats {
        let total = self.total_segments.load(Ordering::Relaxed);
        let online_count = self.archivers.iter()
            .filter(|a| a.online)
            .count();
        
        // Calculate average replication
        let total_assignments: usize = self.segment_archivers.iter()
            .map(|e| e.value().len())
            .sum();
        let avg_replication = if total > 0 {
            total_assignments as f64 / total as f64
        } else {
            0.0
        };
        
        // Find oldest and newest
        let (oldest, newest) = self.segments.iter()
            .fold((u64::MAX, 0u64), |(min, max), entry| {
                (min.min(*entry.key()), max.max(*entry.key()))
            });
        
        ArchiveStats {
            total_segments: total,
            finalized_segments: self.finalized_segments.load(Ordering::Relaxed),
            total_archivers: SIMULATED_ARCHIVERS,
            online_archivers: online_count,
            total_bytes_archived: self.total_bytes.load(Ordering::Relaxed),
            total_proofs_verified: self.proofs_verified.load(Ordering::Relaxed),
            avg_replication_factor: avg_replication,
            oldest_segment: if oldest == u64::MAX { 0 } else { oldest },
            newest_segment: newest,
            is_active: self.is_active.load(Ordering::Relaxed),
        }
    }
    
    /// Get recent segments
    pub fn get_recent_segments(&self, count: usize) -> Vec<Segment> {
        let mut segments: Vec<_> = self.segments.iter()
            .map(|e| e.value().clone())
            .collect();
        segments.sort_by(|a, b| b.index.cmp(&a.index));
        segments.into_iter().take(count).collect()
    }
}

impl Default for ArchiveService {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|_| {
            // Create minimal instance for default
            Self {
                segments: DashMap::new(),
                current_segment: RwLock::new(Segment::new(0)),
                archivers: DashMap::new(),
                segment_archivers: DashMap::new(),
                total_segments: AtomicU64::new(0),
                finalized_segments: AtomicU64::new(0),
                total_bytes: AtomicU64::new(0),
                proofs_verified: AtomicU64::new(0),
                is_active: AtomicBool::new(false),
            }
        })
    }
}
