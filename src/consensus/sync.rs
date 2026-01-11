// ============================================================================
// SYNC MANAGER - Network Catch-Up Protocol for New Nodes
// ============================================================================
//
// Enables new nodes to join the network and sync to the current state:
//
// 1. SNAPSHOT DOWNLOAD: Get latest snapshot from peers
// 2. BLOCK CATCH-UP: Download and verify blocks since snapshot
// 3. LIVE SYNC: Transition to real-time block processing
//
// STATE MACHINE:
// Initializing → DownloadingSnapshot → VerifyingSnapshot → 
// CatchingUp → Synced
//
// Based on Solana's sync architecture with improvements for BlackBook.
// ============================================================================

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::storage::snapshot::{SnapshotManifest, SnapshotChunk, SnapshotError};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum blocks to request at once
pub const MAX_BLOCKS_PER_REQUEST: u64 = 100;

/// Timeout for sync requests
pub const SYNC_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Maximum concurrent chunk downloads
pub const MAX_CONCURRENT_DOWNLOADS: usize = 8;

/// Retry attempts for failed downloads
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Minimum peers required to start sync
pub const MIN_SYNC_PEERS: usize = 1;

/// Slots behind before re-sync
pub const RESYNC_THRESHOLD_SLOTS: u64 = 1000;

// ============================================================================
// SYNC STATE - State machine states
// ============================================================================

/// Current sync state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Just started, gathering peer info
    Initializing,
    
    /// Downloading snapshot from peers
    DownloadingSnapshot {
        manifest: SnapshotManifest,
        chunks_downloaded: u32,
        chunks_total: u32,
        bytes_downloaded: u64,
    },
    
    /// Verifying downloaded snapshot
    VerifyingSnapshot {
        slot: u64,
        chunks_verified: u32,
        chunks_total: u32,
    },
    
    /// Applying snapshot to state
    ApplyingSnapshot {
        slot: u64,
        accounts_applied: u64,
        accounts_total: u64,
    },
    
    /// Downloading blocks since snapshot
    CatchingUp {
        start_slot: u64,
        current_slot: u64,
        target_slot: u64,
        blocks_downloaded: u64,
    },
    
    /// Fully synced, processing blocks in real-time
    Synced {
        slot: u64,
    },
    
    /// Sync failed
    Failed {
        error: String,
        retry_count: u32,
    },
}

impl SyncState {
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncState::Synced { .. })
    }
    
    pub fn progress_percent(&self) -> f64 {
        match self {
            SyncState::Initializing => 0.0,
            SyncState::DownloadingSnapshot { chunks_downloaded, chunks_total, .. } => {
                if *chunks_total == 0 { 0.0 }
                else { (*chunks_downloaded as f64 / *chunks_total as f64) * 30.0 }
            }
            SyncState::VerifyingSnapshot { chunks_verified, chunks_total, .. } => {
                if *chunks_total == 0 { 30.0 }
                else { 30.0 + (*chunks_verified as f64 / *chunks_total as f64) * 20.0 }
            }
            SyncState::ApplyingSnapshot { accounts_applied, accounts_total, .. } => {
                if *accounts_total == 0 { 50.0 }
                else { 50.0 + (*accounts_applied as f64 / *accounts_total as f64) * 20.0 }
            }
            SyncState::CatchingUp { start_slot, current_slot, target_slot, .. } => {
                let range = target_slot.saturating_sub(*start_slot) as f64;
                let progress = current_slot.saturating_sub(*start_slot) as f64;
                if range == 0.0 { 70.0 }
                else { 70.0 + (progress / range) * 30.0 }
            }
            SyncState::Synced { .. } => 100.0,
            SyncState::Failed { .. } => 0.0,
        }
    }
}

// ============================================================================
// SYNC MESSAGES - P2P sync protocol
// ============================================================================

/// Request for sync data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request latest snapshot info
    GetSnapshotInfo,
    
    /// Request snapshot manifest
    GetSnapshotManifest { slot: u64 },
    
    /// Request snapshot chunk
    GetSnapshotChunk { slot: u64, chunk_index: u32 },
    
    /// Request blocks in range
    GetBlocks { start_slot: u64, end_slot: u64 },
    
    /// Request specific block
    GetBlock { slot: u64 },
    
    /// Request current tip
    GetTip,
    
    /// Request account state proof
    GetAccountProof { address: String, slot: u64 },
}

/// Response to sync request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Snapshot info
    SnapshotInfo {
        latest_slot: u64,
        latest_hash: String,
        snapshot_slots: Vec<u64>,
    },
    
    /// Snapshot manifest
    SnapshotManifest(SnapshotManifest),
    
    /// Snapshot chunk data
    SnapshotChunk {
        slot: u64,
        chunk_index: u32,
        data: Vec<u8>,
    },
    
    /// Blocks
    Blocks(Vec<SyncBlock>),
    
    /// Single block
    Block(Option<SyncBlock>),
    
    /// Current tip
    Tip { slot: u64, hash: String },
    
    /// Account proof
    AccountProof {
        address: String,
        slot: u64,
        proof: Vec<String>,
        exists: bool,
    },
    
    /// Error
    Error(String),
}

/// Block data for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlock {
    pub slot: u64,
    pub hash: String,
    pub parent_hash: String,
    pub proposer: String,
    pub timestamp: u64,
    pub transactions: Vec<SyncTransaction>,
    pub state_root: String,
}

/// Transaction data for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTransaction {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub tx_type: String,
    pub signature: String,
}

// ============================================================================
// SYNC PEER - Track peer sync capabilities
// ============================================================================

/// A peer we can sync from
#[derive(Debug, Clone)]
pub struct SyncPeer {
    pub peer_id: String,
    pub address: String,
    pub latest_slot: u64,
    pub has_snapshot: bool,
    pub snapshot_slot: Option<u64>,
    pub latency_ms: u64,
    pub failed_requests: u32,
    pub last_response: Instant,
}

impl SyncPeer {
    pub fn new(peer_id: String, address: String) -> Self {
        Self {
            peer_id,
            address,
            latest_slot: 0,
            has_snapshot: false,
            snapshot_slot: None,
            latency_ms: 0,
            failed_requests: 0,
            last_response: Instant::now(),
        }
    }
    
    /// Is this peer healthy for syncing?
    pub fn is_healthy(&self) -> bool {
        self.failed_requests < MAX_RETRY_ATTEMPTS
            && self.last_response.elapsed() < Duration::from_secs(60)
    }
    
    /// Score peer for selection (higher is better)
    pub fn score(&self) -> u64 {
        let mut score = self.latest_slot;
        score = score.saturating_sub(self.latency_ms / 10);
        score = score.saturating_sub(self.failed_requests as u64 * 1000);
        if self.has_snapshot {
            score += 10000;
        }
        score
    }
}

// ============================================================================
// SYNC MANAGER - Coordinates sync process
// ============================================================================

/// Manages the sync process
pub struct SyncManager {
    /// Current sync state
    pub state: Arc<RwLock<SyncState>>,
    
    /// Known sync peers
    pub peers: Arc<RwLock<HashMap<String, SyncPeer>>>,
    
    /// Our local slot
    pub local_slot: Arc<RwLock<u64>>,
    
    /// Network's latest slot
    pub network_slot: Arc<RwLock<u64>>,
    
    /// Pending block requests
    pending_blocks: Arc<RwLock<HashSet<u64>>>,
    
    /// Downloaded but not yet applied blocks
    block_buffer: Arc<RwLock<VecDeque<SyncBlock>>>,
    
    /// Sync started at
    started_at: Instant,
    
    /// Callback for sync events
    event_callbacks: Arc<RwLock<Vec<Box<dyn Fn(SyncEvent) + Send + Sync>>>>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SyncState::Initializing)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            local_slot: Arc::new(RwLock::new(0)),
            network_slot: Arc::new(RwLock::new(0)),
            pending_blocks: Arc::new(RwLock::new(HashSet::new())),
            block_buffer: Arc::new(RwLock::new(VecDeque::new())),
            started_at: Instant::now(),
            event_callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Add a sync peer
    pub fn add_peer(&self, peer_id: String, address: String, latest_slot: u64, has_snapshot: bool) {
        let mut peers = self.peers.write();
        let mut peer = SyncPeer::new(peer_id.clone(), address);
        peer.latest_slot = latest_slot;
        peer.has_snapshot = has_snapshot;
        peers.insert(peer_id, peer);
        
        // Update network slot
        let mut net_slot = self.network_slot.write();
        *net_slot = (*net_slot).max(latest_slot);
    }
    
    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &str) {
        self.peers.write().remove(peer_id);
    }
    
    /// Get best peer for syncing
    pub fn get_best_peer(&self) -> Option<SyncPeer> {
        self.peers.read()
            .values()
            .filter(|p| p.is_healthy())
            .max_by_key(|p| p.score())
            .cloned()
    }
    
    /// Check if we need to sync
    pub fn needs_sync(&self) -> bool {
        let local = *self.local_slot.read();
        let network = *self.network_slot.read();
        network > local + RESYNC_THRESHOLD_SLOTS
    }
    
    /// Start sync process
    pub fn start_sync(&self, local_slot: u64) -> Result<(), SyncError> {
        *self.local_slot.write() = local_slot;
        
        // Check we have enough peers
        let peer_count = self.peers.read().len();
        if peer_count < MIN_SYNC_PEERS {
            return Err(SyncError::NotEnoughPeers { 
                have: peer_count, 
                need: MIN_SYNC_PEERS 
            });
        }
        
        // Find best peer
        let best_peer = self.get_best_peer()
            .ok_or(SyncError::NoPeersAvailable)?;
        
        println!("🔄 Starting sync from peer {} at slot {}", 
                 &best_peer.peer_id[..16.min(best_peer.peer_id.len())], 
                 best_peer.latest_slot);
        
        // Decide sync strategy
        let network_slot = best_peer.latest_slot;
        *self.network_slot.write() = network_slot;
        
        let slots_behind = network_slot.saturating_sub(local_slot);
        
        if slots_behind > RESYNC_THRESHOLD_SLOTS && best_peer.has_snapshot {
            // Full snapshot sync
            println!("📸 Will sync via snapshot ({} slots behind)", slots_behind);
            *self.state.write() = SyncState::Initializing;
        } else {
            // Incremental block sync
            println!("📦 Will sync blocks ({} slots behind)", slots_behind);
            *self.state.write() = SyncState::CatchingUp {
                start_slot: local_slot,
                current_slot: local_slot,
                target_slot: network_slot,
                blocks_downloaded: 0,
            };
        }
        
        self.emit_event(SyncEvent::Started { 
            local_slot, 
            target_slot: network_slot 
        });
        
        Ok(())
    }
    
    /// Process sync response from peer
    pub fn handle_response(&self, peer_id: &str, response: SyncResponse) -> Result<(), SyncError> {
        // Update peer last response time
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            peer.last_response = Instant::now();
        }
        
        match response {
            SyncResponse::SnapshotInfo { latest_slot, snapshot_slots, .. } => {
                if let Some(peer) = self.peers.write().get_mut(peer_id) {
                    peer.latest_slot = latest_slot;
                    peer.has_snapshot = !snapshot_slots.is_empty();
                    peer.snapshot_slot = snapshot_slots.first().copied();
                }
            }
            
            SyncResponse::SnapshotManifest(manifest) => {
                *self.state.write() = SyncState::DownloadingSnapshot {
                    manifest: manifest.clone(),
                    chunks_downloaded: 0,
                    chunks_total: manifest.chunk_count,
                    bytes_downloaded: 0,
                };
            }
            
            SyncResponse::SnapshotChunk { slot, chunk_index, data } => {
                let mut state = self.state.write();
                if let SyncState::DownloadingSnapshot { 
                    chunks_downloaded, 
                    chunks_total,
                    bytes_downloaded,
                    ..
                } = &mut *state {
                    *chunks_downloaded += 1;
                    *bytes_downloaded += data.len() as u64;
                    
                    let progress = *chunks_downloaded as f64 / *chunks_total as f64 * 100.0;
                    println!("📥 Chunk {}/{} ({:.1}%)", chunks_downloaded, chunks_total, progress);
                    
                    // Emit progress event
                    self.emit_event(SyncEvent::SnapshotProgress {
                        chunks_downloaded: *chunks_downloaded,
                        chunks_total: *chunks_total,
                        bytes_downloaded: *bytes_downloaded,
                    });
                }
            }
            
            SyncResponse::Blocks(blocks) => {
                let mut buffer = self.block_buffer.write();
                let mut state = self.state.write();
                
                for block in blocks {
                    if let SyncState::CatchingUp { 
                        current_slot,
                        blocks_downloaded,
                        ..
                    } = &mut *state {
                        *current_slot = (*current_slot).max(block.slot);
                        *blocks_downloaded += 1;
                    }
                    buffer.push_back(block);
                }
                
                // Emit progress
                if let SyncState::CatchingUp { 
                    start_slot, 
                    current_slot, 
                    target_slot,
                    blocks_downloaded,
                } = &*state {
                    self.emit_event(SyncEvent::BlocksProgress {
                        current_slot: *current_slot,
                        target_slot: *target_slot,
                        blocks_downloaded: *blocks_downloaded,
                    });
                }
            }
            
            SyncResponse::Tip { slot, hash } => {
                let mut net_slot = self.network_slot.write();
                *net_slot = (*net_slot).max(slot);
            }
            
            SyncResponse::Error(err) => {
                // Mark peer as failed
                if let Some(peer) = self.peers.write().get_mut(peer_id) {
                    peer.failed_requests += 1;
                }
                return Err(SyncError::PeerError(err));
            }
            
            _ => {}
        }
        
        Ok(())
    }
    
    /// Get next sync request to send
    pub fn get_next_request(&self) -> Option<(String, SyncRequest)> {
        let state = self.state.read();
        let peer = self.get_best_peer()?;
        
        match &*state {
            SyncState::Initializing => {
                Some((peer.peer_id, SyncRequest::GetSnapshotInfo))
            }
            
            SyncState::DownloadingSnapshot { manifest, chunks_downloaded, .. } => {
                if *chunks_downloaded < manifest.chunk_count {
                    Some((peer.peer_id, SyncRequest::GetSnapshotChunk {
                        slot: manifest.slot,
                        chunk_index: *chunks_downloaded,
                    }))
                } else {
                    None
                }
            }
            
            SyncState::CatchingUp { current_slot, target_slot, .. } => {
                if current_slot < target_slot {
                    let end = (*current_slot + MAX_BLOCKS_PER_REQUEST).min(*target_slot);
                    Some((peer.peer_id, SyncRequest::GetBlocks {
                        start_slot: *current_slot + 1,
                        end_slot: end,
                    }))
                } else {
                    None
                }
            }
            
            _ => None
        }
    }
    
    /// Pop next block from buffer for processing
    pub fn pop_block(&self) -> Option<SyncBlock> {
        self.block_buffer.write().pop_front()
    }
    
    /// Mark sync as complete
    pub fn complete_sync(&self, slot: u64) {
        *self.state.write() = SyncState::Synced { slot };
        *self.local_slot.write() = slot;
        
        self.emit_event(SyncEvent::Completed { 
            slot,
            duration_ms: self.started_at.elapsed().as_millis() as u64,
        });
        
        println!("✅ Sync complete at slot {} ({:.1}s)", 
                 slot, 
                 self.started_at.elapsed().as_secs_f64());
    }
    
    /// Mark sync as failed
    pub fn fail_sync(&self, error: String) {
        let retry_count = match &*self.state.read() {
            SyncState::Failed { retry_count, .. } => *retry_count + 1,
            _ => 1,
        };
        
        *self.state.write() = SyncState::Failed { 
            error: error.clone(), 
            retry_count 
        };
        
        self.emit_event(SyncEvent::Failed { error, retry_count });
    }
    
    /// Register event callback
    pub fn on_event<F>(&self, callback: F)
    where
        F: Fn(SyncEvent) + Send + Sync + 'static,
    {
        self.event_callbacks.write().push(Box::new(callback));
    }
    
    /// Emit sync event
    fn emit_event(&self, event: SyncEvent) {
        let callbacks = self.event_callbacks.read();
        for callback in callbacks.iter() {
            callback(event.clone());
        }
    }
    
    /// Get current sync status
    pub fn get_status(&self) -> SyncStatus {
        let state = self.state.read().clone();
        SyncStatus {
            state,
            local_slot: *self.local_slot.read(),
            network_slot: *self.network_slot.read(),
            peer_count: self.peers.read().len(),
            elapsed_ms: self.started_at.elapsed().as_millis() as u64,
        }
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SYNC STATUS - Current sync status
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub state: SyncState,
    pub local_slot: u64,
    pub network_slot: u64,
    pub peer_count: usize,
    pub elapsed_ms: u64,
}

impl SyncStatus {
    pub fn slots_behind(&self) -> u64 {
        self.network_slot.saturating_sub(self.local_slot)
    }
    
    pub fn is_synced(&self) -> bool {
        self.state.is_synced()
    }
    
    pub fn progress_percent(&self) -> f64 {
        self.state.progress_percent()
    }
}

// ============================================================================
// SYNC EVENTS - Events emitted during sync
// ============================================================================

#[derive(Debug, Clone)]
pub enum SyncEvent {
    Started { local_slot: u64, target_slot: u64 },
    SnapshotProgress { chunks_downloaded: u32, chunks_total: u32, bytes_downloaded: u64 },
    BlocksProgress { current_slot: u64, target_slot: u64, blocks_downloaded: u64 },
    Completed { slot: u64, duration_ms: u64 },
    Failed { error: String, retry_count: u32 },
    PeerAdded { peer_id: String },
    PeerRemoved { peer_id: String },
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum SyncError {
    NotEnoughPeers { have: usize, need: usize },
    NoPeersAvailable,
    PeerError(String),
    SnapshotError(String),
    BlockVerificationFailed { slot: u64, reason: String },
    Timeout { request: String },
    InvalidState(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NotEnoughPeers { have, need } => {
                write!(f, "Not enough peers: have {}, need {}", have, need)
            }
            SyncError::NoPeersAvailable => write!(f, "No healthy peers available"),
            SyncError::PeerError(e) => write!(f, "Peer error: {}", e),
            SyncError::SnapshotError(e) => write!(f, "Snapshot error: {}", e),
            SyncError::BlockVerificationFailed { slot, reason } => {
                write!(f, "Block {} verification failed: {}", slot, reason)
            }
            SyncError::Timeout { request } => write!(f, "Request timeout: {}", request),
            SyncError::InvalidState(e) => write!(f, "Invalid state: {}", e),
        }
    }
}

impl std::error::Error for SyncError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sync_state_progress() {
        assert_eq!(SyncState::Initializing.progress_percent(), 0.0);
        assert_eq!(SyncState::Synced { slot: 100 }.progress_percent(), 100.0);
        
        let downloading = SyncState::DownloadingSnapshot {
            manifest: SnapshotManifest::new(100, "hash".to_string(), 1),
            chunks_downloaded: 5,
            chunks_total: 10,
            bytes_downloaded: 5000,
        };
        assert!((downloading.progress_percent() - 15.0).abs() < 0.1);
    }
    
    #[test]
    fn test_sync_peer_scoring() {
        let mut peer1 = SyncPeer::new("peer1".to_string(), "127.0.0.1:9000".to_string());
        peer1.latest_slot = 1000;
        peer1.has_snapshot = true;
        peer1.latency_ms = 50;
        
        let mut peer2 = SyncPeer::new("peer2".to_string(), "127.0.0.1:9001".to_string());
        peer2.latest_slot = 1100;
        peer2.has_snapshot = false;
        peer2.latency_ms = 100;
        
        // peer1 should score higher due to snapshot
        assert!(peer1.score() > peer2.score());
    }
    
    #[test]
    fn test_sync_manager_peers() {
        let manager = SyncManager::new();
        
        manager.add_peer("peer1".to_string(), "127.0.0.1:9000".to_string(), 1000, true);
        manager.add_peer("peer2".to_string(), "127.0.0.1:9001".to_string(), 900, false);
        
        assert_eq!(manager.peers.read().len(), 2);
        assert_eq!(*manager.network_slot.read(), 1000);
        
        let best = manager.get_best_peer().unwrap();
        assert_eq!(best.peer_id, "peer1"); // Has snapshot
    }
    
    #[test]
    fn test_sync_needs_sync() {
        let manager = SyncManager::new();
        *manager.local_slot.write() = 100;
        *manager.network_slot.write() = 100;
        
        assert!(!manager.needs_sync());
        
        *manager.network_slot.write() = 100 + RESYNC_THRESHOLD_SLOTS + 1;
        assert!(manager.needs_sync());
    }
}
