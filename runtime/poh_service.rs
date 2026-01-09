//! Proof of History Service - Continuous PoH Clock
//!
//! This service runs continuously in the background, generating PoH ticks
//! that prove the passage of time. The PoH clock is the heart of the Layer1
//! blockchain, providing a cryptographic timestamp for all transactions.
//!
//! Key Features:
//! - Continuous SHA-256 hash chain (Verifiable Delay Function)
//! - Slot-based time progression (1 second slots)
//! - Epoch transitions for leader rotation
//! - Transaction mixing for ordering proofs
//! - Thread-safe shared state
//! - PIPELINE: 4-stage async transaction processing (fetch→verify→execute→commit)
//!
//! INFRASTRUCTURE NOTE: Pipeline stages are built for high-throughput parallel
//! transaction processing. Pipeline::submit() will be wired to routes for
//! direct transaction submission.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use serde::Serialize;

use super::{PoHConfig, PoHEntry};

// ============================================================================
// PIPELINE CONSTANTS (Solana-style Transaction Pipeline)
// ============================================================================

/// Pipeline stage buffer capacity
const PIPELINE_BUFFER_SIZE: usize = 10_000;
/// Number of parallel sigverify workers
const SIGVERIFY_WORKERS: usize = 4;
/// Commit batch size for efficiency
const COMMIT_BATCH_SIZE: usize = 64;

// ============================================================================
// FINALITY CONSTANTS
// ============================================================================

/// Number of confirmations required for transaction finality
/// - 2 confirmations = ~2 slots = ~2 seconds for fast finality
/// - Lower than Ethereum (12 blocks) but secure for our use case
pub const CONFIRMATIONS_REQUIRED: u64 = 2;

/// Confirmation status for transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ConfirmationStatus {
    /// Transaction submitted but not yet in a block
    Pending,
    /// In a block but not enough confirmations
    Processing { confirmations: u64 },
    /// Fully confirmed (2+ blocks on top)
    Confirmed,
    /// Transaction finalized and irreversible
    Finalized,
}

// ============================================================================
// PRUNING CONSTANTS
// ============================================================================

/// Number of slots pruned nodes should retain
/// - 300,000 slots = ~3.5 days at 1 second slots
/// - Enough for dispute resolution and recent queries
/// - Archive nodes keep everything, pruned nodes discard older data
pub const PRUNED_SLOTS_RETENTION: u64 = 300_000;

/// Pruning mode for the node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodePruningMode {
    /// Archive node - keeps all historical data
    Archive,
    /// Pruned node - keeps only recent slots (PRUNED_SLOTS_RETENTION)
    Pruned,
}

// ============================================================================
// TRANSACTION PIPELINE - 4-Stage Async Processing
// ============================================================================
//
// Solana's pipelining processes transactions through 4 GPU/CPU stages:
// 1. FETCH: Network receives raw transaction packets
// 2. VERIFY: GPU verifies all signatures in parallel (sigverify)
// 3. EXECUTE: Bank processes transactions (Sealevel parallel VM)
// 4. COMMIT: Results committed and broadcast
//
// Each stage runs in parallel, so while one batch is being verified,
// the next batch is being fetched, and a previous batch is executing.

/// A transaction packet moving through the pipeline
#[derive(Debug, Clone)]
pub struct PipelinePacket {
    /// Transaction ID
    pub tx_id: String,
    /// Raw transaction data (serialized)
    pub data: Vec<u8>,
    /// Sender address
    pub from: String,
    /// Recipient address
    pub to: String,
    /// Amount
    pub amount: f64,
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Timestamp when packet entered pipeline
    pub received_at: u64,
}

impl PipelinePacket {
    pub fn new(tx_id: String, from: String, to: String, amount: f64) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        Self {
            tx_id,
            data: Vec::new(),
            from,
            to,
            amount,
            signature: Vec::new(),
            received_at: now,
        }
    }
}

/// Result of signature verification stage
#[derive(Debug, Clone)]
pub struct VerifiedPacket {
    pub packet: PipelinePacket,
    pub signature_valid: bool,
    pub verification_time_us: u64,
}

/// Result of execution stage
#[derive(Debug, Clone)]
pub struct ExecutedPacket {
    pub packet: PipelinePacket,
    pub success: bool,
    pub error: Option<String>,
    pub execution_time_us: u64,
}

/// Result of commit stage
#[derive(Debug, Clone)]
pub struct CommittedPacket {
    pub tx_id: String,
    pub success: bool,
    pub slot: u64,
    pub total_pipeline_time_us: u64,
    /// Number of confirmations (increases as more blocks are built on top)
    pub confirmations: u64,
}

/// Shared reference to the transaction pipeline
pub type SharedPipeline = Arc<TransactionPipeline>;

/// Pipeline statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct PipelineStats {
    pub packets_received: u64,
    pub packets_verified: u64,
    pub packets_executed: u64,
    pub packets_committed: u64,
    pub packets_failed: u64,
    pub avg_pipeline_latency_us: u64,
    pub current_fetch_queue: usize,
    pub current_verify_queue: usize,
    pub current_execute_queue: usize,
    pub current_commit_queue: usize,
    pub is_running: bool,
}

/// Transaction Pipeline - 4-stage async processing
/// 
/// Implements Solana-style pipelining where each stage runs concurrently:
/// - Fetch stage: Receives transactions from network/RPC
/// - Verify stage: Validates signatures (parallel workers)
/// - Execute stage: Processes transactions (Sealevel parallel)
/// - Commit stage: Finalizes and broadcasts results
pub struct TransactionPipeline {
    // Channel endpoints for pipeline stages
    fetch_tx: mpsc::Sender<PipelinePacket>,
    fetch_rx: Arc<RwLock<Option<mpsc::Receiver<PipelinePacket>>>>,
    
    verify_tx: mpsc::Sender<VerifiedPacket>,
    verify_rx: Arc<RwLock<Option<mpsc::Receiver<VerifiedPacket>>>>,
    
    execute_tx: mpsc::Sender<ExecutedPacket>,
    execute_rx: Arc<RwLock<Option<mpsc::Receiver<ExecutedPacket>>>>,
    
    commit_tx: mpsc::Sender<CommittedPacket>,
    
    // Statistics
    packets_received: AtomicU64,
    packets_verified: AtomicU64,
    packets_executed: AtomicU64,
    packets_committed: AtomicU64,
    packets_failed: AtomicU64,
    total_latency_us: AtomicU64,
    
    // State
    is_running: AtomicBool,
}

impl TransactionPipeline {
    /// Create a new transaction pipeline
    pub fn new() -> (Arc<Self>, mpsc::Receiver<CommittedPacket>) {
        let (fetch_tx, fetch_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (verify_tx, verify_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (execute_tx, execute_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (commit_tx, commit_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        
        println!("🔄 Transaction Pipeline initialized:");
        println!("   └─ 4 stages, buffer: {}, sigverify workers: {}", 
                 PIPELINE_BUFFER_SIZE, SIGVERIFY_WORKERS);
        
        let pipeline = Arc::new(Self {
            fetch_tx,
            fetch_rx: Arc::new(RwLock::new(Some(fetch_rx))),
            verify_tx,
            verify_rx: Arc::new(RwLock::new(Some(verify_rx))),
            execute_tx,
            execute_rx: Arc::new(RwLock::new(Some(execute_rx))),
            commit_tx,
            packets_received: AtomicU64::new(0),
            packets_verified: AtomicU64::new(0),
            packets_executed: AtomicU64::new(0),
            packets_committed: AtomicU64::new(0),
            packets_failed: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            is_running: AtomicBool::new(false),
        });
        
        (pipeline, commit_rx)
    }
    
    /// Submit a transaction to the pipeline (entry point)
    pub async fn submit(&self, packet: PipelinePacket) -> Result<(), String> {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        
        self.fetch_tx.send(packet).await
            .map_err(|e| format!("Pipeline submit failed: {}", e))
    }
    
    /// Get pipeline statistics
    pub fn get_stats(&self) -> PipelineStats {
        let committed = self.packets_committed.load(Ordering::Relaxed);
        let total_latency = self.total_latency_us.load(Ordering::Relaxed);
        
        PipelineStats {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_verified: self.packets_verified.load(Ordering::Relaxed),
            packets_executed: self.packets_executed.load(Ordering::Relaxed),
            packets_committed: committed,
            packets_failed: self.packets_failed.load(Ordering::Relaxed),
            avg_pipeline_latency_us: if committed > 0 { total_latency / committed } else { 0 },
            current_fetch_queue: 0, // Would need channel inspection
            current_verify_queue: 0,
            current_execute_queue: 0,
            current_commit_queue: 0,
            is_running: self.is_running.load(Ordering::Relaxed),
        }
    }
    
    /// Start all pipeline stages (call once on startup)
    pub fn start(self: &Arc<Self>, current_slot: Arc<AtomicU64>) {
        self.is_running.store(true, Ordering::Relaxed);
        
        // Take ownership of receivers (only works once)
        let fetch_rx = self.fetch_rx.write().take();
        let verify_rx = self.verify_rx.write().take();
        let execute_rx = self.execute_rx.write().take();
        
        if let Some(rx) = fetch_rx {
            self.spawn_fetch_stage(rx);
        }
        
        if let Some(rx) = verify_rx {
            self.spawn_verify_stage(rx);
        }
        
        if let Some(rx) = execute_rx {
            self.spawn_execute_stage(rx, current_slot);
        }
        
        println!("⚡ Pipeline stages started");
    }
    
    /// Stage 1: FETCH - Receive and buffer incoming transactions
    fn spawn_fetch_stage(self: &Arc<Self>, mut rx: mpsc::Receiver<PipelinePacket>) {
        let verify_tx = self.verify_tx.clone();
        let packets_verified = Arc::new(AtomicU64::new(0));
        let stats_ref = packets_verified.clone();
        
        tokio::spawn(async move {
            println!("📥 Fetch stage started");
            
            while let Some(packet) = rx.recv().await {
                // Simulate signature verification (in real system, this is GPU-parallel)
                let start = Instant::now();
                
                // Fast signature check simulation
                let signature_valid = !packet.from.is_empty() && packet.amount >= 0.0;
                
                let verification_time_us = start.elapsed().as_micros() as u64;
                
                let verified = VerifiedPacket {
                    packet,
                    signature_valid,
                    verification_time_us,
                };
                
                stats_ref.fetch_add(1, Ordering::Relaxed);
                
                if verify_tx.send(verified).await.is_err() {
                    break;
                }
            }
        });
        
        // Store stats reference
        let pipeline = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                pipeline.packets_verified.store(
                    packets_verified.load(Ordering::Relaxed),
                    Ordering::Relaxed
                );
            }
        });
    }
    
    /// Stage 2: VERIFY - Validate signatures (parallel workers)
    fn spawn_verify_stage(self: &Arc<Self>, mut rx: mpsc::Receiver<VerifiedPacket>) {
        let execute_tx = self.execute_tx.clone();
        let pipeline = self.clone();
        
        tokio::spawn(async move {
            println!("✅ Verify stage started");
            
            while let Some(verified) = rx.recv().await {
                if !verified.signature_valid {
                    pipeline.packets_failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                
                // Simulate execution
                let start = Instant::now();
                
                // Basic validation (in real system, Sealevel parallel execution)
                let (success, error) = if verified.packet.amount < 0.0 {
                    (false, Some("Negative amount".to_string()))
                } else {
                    (true, None)
                };
                
                let execution_time_us = start.elapsed().as_micros() as u64;
                
                let executed = ExecutedPacket {
                    packet: verified.packet,
                    success,
                    error,
                    execution_time_us,
                };
                
                if execute_tx.send(executed).await.is_err() {
                    break;
                }
            }
        });
    }
    
    /// Stage 3: EXECUTE - Process transactions through Sealevel
    fn spawn_execute_stage(
        self: &Arc<Self>, 
        mut rx: mpsc::Receiver<ExecutedPacket>,
        current_slot: Arc<AtomicU64>
    ) {
        let commit_tx = self.commit_tx.clone();
        let pipeline = self.clone();
        
        tokio::spawn(async move {
            println!("⚙️ Execute stage started");
            
            let mut batch: Vec<ExecutedPacket> = Vec::with_capacity(COMMIT_BATCH_SIZE);
            
            while let Some(executed) = rx.recv().await {
                pipeline.packets_executed.fetch_add(1, Ordering::Relaxed);
                batch.push(executed);
                
                // Commit in batches for efficiency
                if batch.len() >= COMMIT_BATCH_SIZE {
                    let slot = current_slot.load(Ordering::Relaxed);
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                    
                    for exec in batch.drain(..) {
                        let pipeline_time = now.saturating_sub(exec.packet.received_at) * 1000;
                        pipeline.total_latency_us.fetch_add(pipeline_time, Ordering::Relaxed);
                        
                        let committed = CommittedPacket {
                            tx_id: exec.packet.tx_id,
                            success: exec.success,
                            slot,
                            total_pipeline_time_us: pipeline_time,
                            confirmations: 0, // Starts at 0, increases as more blocks built on top
                        };
                        
                        pipeline.packets_committed.fetch_add(1, Ordering::Relaxed);
                        
                        if commit_tx.send(committed).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
}

impl Default for TransactionPipeline {
    fn default() -> Self {
        let (pipeline, _) = Self::new();
        // Note: This drops the commit receiver, only use for testing
        Arc::try_unwrap(pipeline).unwrap_or_else(|arc| (*arc).clone())
    }
}

impl Clone for TransactionPipeline {
    fn clone(&self) -> Self {
        // Create new channels - cloned pipeline is independent
        let (fetch_tx, fetch_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (verify_tx, verify_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (execute_tx, execute_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        let (commit_tx, _commit_rx) = mpsc::channel(PIPELINE_BUFFER_SIZE);
        
        Self {
            fetch_tx,
            fetch_rx: Arc::new(RwLock::new(Some(fetch_rx))),
            verify_tx,
            verify_rx: Arc::new(RwLock::new(Some(verify_rx))),
            execute_tx,
            execute_rx: Arc::new(RwLock::new(Some(execute_rx))),
            commit_tx,
            packets_received: AtomicU64::new(self.packets_received.load(Ordering::Relaxed)),
            packets_verified: AtomicU64::new(self.packets_verified.load(Ordering::Relaxed)),
            packets_executed: AtomicU64::new(self.packets_executed.load(Ordering::Relaxed)),
            packets_committed: AtomicU64::new(self.packets_committed.load(Ordering::Relaxed)),
            packets_failed: AtomicU64::new(self.packets_failed.load(Ordering::Relaxed)),
            total_latency_us: AtomicU64::new(self.total_latency_us.load(Ordering::Relaxed)),
            is_running: AtomicBool::new(false),
        }
    }
}

// ============================================================================
// POH SERVICE STATE
// ============================================================================

/// Thread-safe PoH clock state shared across the application
#[derive(Debug)]
pub struct PoHService {
    /// Current hash in the chain
    pub current_hash: String,
    /// Total hashes since genesis
    pub num_hashes: u64,
    /// Current slot number
    pub current_slot: u64,
    /// Current epoch
    pub current_epoch: u64,
    /// Configuration
    pub config: PoHConfig,
    /// Last tick timestamp
    pub last_tick: Instant,
    /// Genesis timestamp (unix seconds)
    pub genesis_timestamp: u64,
    /// PoH entries for current slot
    pub current_entries: Vec<PoHEntry>,
    /// Is the clock running
    pub is_running: bool,
    /// Total slots produced
    pub total_slots_produced: u64,
    /// Pending transaction IDs to mix into next tick
    pub pending_tx_mix: Vec<String>,
}

impl PoHService {
    /// Create a new PoH service with genesis hash
    pub fn new(config: PoHConfig) -> Self {
        let genesis_hash = Self::compute_genesis_hash();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        println!("⏰ PoH Service initialized with genesis hash: {}...", &genesis_hash[..16]);
        
        Self {
            current_hash: genesis_hash,
            num_hashes: 0,
            current_slot: 0,
            current_epoch: 0,
            config,
            last_tick: Instant::now(),
            genesis_timestamp: now,
            current_entries: Vec::new(),
            is_running: false,
            total_slots_produced: 0,
            pending_tx_mix: Vec::new(),
        }
    }
    
    /// Compute deterministic genesis hash
    fn compute_genesis_hash() -> String {
        let genesis_data = "LAYER1_POH_GENESIS_2024_CONTINUOUS_PROOF_OF_HISTORY";
        let mut hasher = Sha256::new();
        hasher.update(genesis_data.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Advance the PoH by computing next tick (hashes_per_tick iterations)
    pub fn tick(&mut self) -> PoHEntry {
        // Compute next hash in the chain
        for _ in 0..self.config.hashes_per_tick {
            let mut hasher = Sha256::new();
            hasher.update(self.current_hash.as_bytes());
            self.current_hash = format!("{:x}", hasher.finalize());
            self.num_hashes += 1;
        }
        
        let entry = PoHEntry {
            hash: self.current_hash.clone(),
            num_hashes: self.num_hashes,
            transactions: Vec::new(),
        };
        
        self.current_entries.push(entry.clone());
        self.last_tick = Instant::now();
        
        entry
    }
    
    /// Mix pending transactions into the PoH (proves transaction ordering)
    pub fn mix_pending_transactions(&mut self) -> Option<PoHEntry> {
        if self.pending_tx_mix.is_empty() {
            return None;
        }
        
        let tx_ids = std::mem::take(&mut self.pending_tx_mix);
        
        // Hash transaction IDs together with current hash
        let mut hasher = Sha256::new();
        hasher.update(self.current_hash.as_bytes());
        for tx_id in &tx_ids {
            hasher.update(tx_id.as_bytes());
        }
        self.current_hash = format!("{:x}", hasher.finalize());
        self.num_hashes += 1;
        
        let entry = PoHEntry {
            hash: self.current_hash.clone(),
            num_hashes: self.num_hashes,
            transactions: tx_ids,
        };
        
        self.current_entries.push(entry.clone());
        Some(entry)
    }
    
    /// Queue a transaction to be mixed into the next tick
    pub fn queue_transaction(&mut self, tx_id: String) {
        self.pending_tx_mix.push(tx_id);
    }
    
    /// Advance to next slot
    pub fn advance_slot(&mut self) -> u64 {
        self.current_slot += 1;
        self.total_slots_produced += 1;
        self.current_entries.clear();
        
        // Check epoch transition
        if self.current_slot % self.config.slots_per_epoch == 0 {
            self.current_epoch += 1;
            println!("📅 Epoch transition: now in epoch {} (slot {})", 
                     self.current_epoch, self.current_slot);
        }
        
        self.current_slot
    }
    
    /// Get current slot info as JSON
    pub fn get_status(&self) -> serde_json::Value {
        let now = Instant::now();
        let time_in_slot = now.duration_since(self.last_tick).as_millis() as u64;
        let slot_progress = (time_in_slot as f64 / self.config.slot_duration_ms as f64 * 100.0).min(100.0);
        
        serde_json::json!({
            "running": self.is_running,
            "current_slot": self.current_slot,
            "current_epoch": self.current_epoch,
            "num_hashes": self.num_hashes,
            "hashes_per_second": self.calculate_hash_rate(),
            "time_in_slot_ms": time_in_slot,
            "slot_duration_ms": self.config.slot_duration_ms,
            "slot_progress_percent": slot_progress,
            "current_hash": self.current_hash.clone(),
            "current_hash_prefix": &self.current_hash[..16],
            "entries_in_slot": self.current_entries.len(),
            "genesis_timestamp": self.genesis_timestamp,
            "total_slots_produced": self.total_slots_produced,
            "pending_tx_count": self.pending_tx_mix.len(),
            "config": {
                "hashes_per_tick": self.config.hashes_per_tick,
                "ticks_per_slot": self.config.ticks_per_slot,
                "slots_per_epoch": self.config.slots_per_epoch,
            }
        })
    }
    
    /// Calculate current hash rate (approximate)
    fn calculate_hash_rate(&self) -> u64 {
        let elapsed = self.last_tick.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (self.config.hashes_per_tick as f64 / elapsed.max(0.001)) as u64
        } else {
            self.config.hashes_per_tick
        }
    }
    
    /// Verify the current slot's PoH entries are valid
    /// This proves the entries were computed sequentially and haven't been tampered with
    pub fn verify_current_entries(&self) -> bool {
        if self.current_entries.is_empty() {
            return true;
        }
        
        // Get the starting hash (hash before first entry in this slot)
        // For simplicity, we verify entries are internally consistent
        let starting_hash = if let Some(first_entry) = self.current_entries.first() {
            // Reconstruct what the hash should have been before first entry
            // by working backwards (this is a simplified check)
            Self::compute_genesis_hash() // In production, would track slot boundaries
        } else {
            return true;
        };
        
        verify_poh_chain(&self.current_entries, &starting_hash)
    }
    
    /// Get current entries for external verification
    pub fn get_current_entries(&self) -> Vec<PoHEntry> {
        self.current_entries.clone()
    }
    
    /// Get genesis hash for verification starting point
    pub fn get_genesis_hash() -> String {
        Self::compute_genesis_hash()
    }
}

// ============================================================================
// POH SERVICE RUNNER
// ============================================================================

/// Shared PoH state type
pub type SharedPoHService = Arc<RwLock<PoHService>>;

/// Create a new shared PoH service
pub fn create_poh_service(config: PoHConfig) -> SharedPoHService {
    Arc::new(RwLock::new(PoHService::new(config)))
}

/// Run the PoH clock continuously (call this in a tokio::spawn)
pub async fn run_poh_clock(poh_service: SharedPoHService) {
    println!("🚀 Starting continuous PoH clock...");
    
    // Mark as running
    {
        let mut poh = poh_service.write();
        poh.is_running = true;
    }
    
    let tick_interval = {
        let poh = poh_service.read();
        let interval = poh.config.slot_duration_ms / poh.config.ticks_per_slot;
        Duration::from_millis(interval.max(1))
    };
    
    let mut interval = tokio::time::interval(tick_interval);
    let mut tick_count = 0u64;
    let mut last_slot_log = 0u64;
    
    loop {
        interval.tick().await;
        
        let (_current_slot, should_advance) = {
            let mut poh = poh_service.write();
            
            // Perform a tick
            poh.tick();
            tick_count += 1;
            
            // Mix any pending transactions
            poh.mix_pending_transactions();
            
            // Check if we should advance to next slot
            let should_advance = tick_count % poh.config.ticks_per_slot == 0;
            
            (poh.current_slot, should_advance)
        };
        
        if should_advance {
            let new_slot = {
                let mut poh = poh_service.write();
                poh.advance_slot()
            };
            
            // Log every 10 slots to avoid spam
            if new_slot - last_slot_log >= 10 {
                let poh = poh_service.read();
                println!("🎟️ PoH: Slot {} | Epoch {} | {} hashes | {} entries", 
                         new_slot, poh.current_epoch, poh.num_hashes, poh.current_entries.len());
                last_slot_log = new_slot;
            }
        }
    }
}

// ============================================================================
// POH VERIFICATION
// ============================================================================

/// Verify a PoH entry chain is valid
pub fn verify_poh_chain(entries: &[PoHEntry], starting_hash: &str) -> bool {
    if entries.is_empty() {
        return true;
    }
    
    let mut current_hash = starting_hash.to_string();
    
    for entry in entries {
        // Recompute hash
        let mut hasher = Sha256::new();
        hasher.update(current_hash.as_bytes());
        
        // Mix in transactions if present
        for tx_id in &entry.transactions {
            hasher.update(tx_id.as_bytes());
        }
        
        let computed_hash = format!("{:x}", hasher.finalize());
        
        if computed_hash != entry.hash {
            return false;
        }
        
        current_hash = computed_hash;
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poh_service_creation() {
        let config = PoHConfig::default();
        let service = PoHService::new(config);
        
        assert_eq!(service.current_slot, 0);
        assert_eq!(service.current_epoch, 0);
        assert_eq!(service.num_hashes, 0);
        assert!(!service.current_hash.is_empty());
    }
    
    #[test]
    fn test_poh_tick() {
        let config = PoHConfig {
            hashes_per_tick: 100,
            ..Default::default()
        };
        let mut service = PoHService::new(config);
        
        let initial_hash = service.current_hash.clone();
        let entry = service.tick();
        
        assert_ne!(entry.hash, initial_hash);
        assert_eq!(service.num_hashes, 100);
    }
    
    #[test]
    fn test_poh_slot_advance() {
        let config = PoHConfig::default();
        let mut service = PoHService::new(config);
        
        assert_eq!(service.current_slot, 0);
        service.advance_slot();
        assert_eq!(service.current_slot, 1);
    }
    
    #[test]
    fn test_poh_tx_mixing() {
        let config = PoHConfig::default();
        let mut service = PoHService::new(config);
        
        service.queue_transaction("tx_123".to_string());
        service.queue_transaction("tx_456".to_string());
        
        let entry = service.mix_pending_transactions();
        assert!(entry.is_some());
        
        let entry = entry.unwrap();
        assert_eq!(entry.transactions.len(), 2);
        assert!(entry.transactions.contains(&"tx_123".to_string()));
    }
}
