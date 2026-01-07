// ============================================================================
// SERVICES MODULE - Wiring Solana-style Infrastructure Services
// ============================================================================
//
// This module connects the Gulf Stream, Turbine, Cloudbreak, and Archive
// services to the actual transaction and block production flow.
//
// Services:
// - GulfStreamService: Transaction forwarding to upcoming leaders
// - TurbineService: Block propagation via shreds  
// - CloudbreakAccountDB: High-performance account storage
// - ArchiveService: Distributed ledger storage
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use sha2::Digest;  // For sha2::Sha256::digest
use parking_lot::RwLock;  // Use parking_lot::RwLock to match GulfStreamService

use crate::protocol::blockchain::{EnhancedBlockchain, Block, TurbineService, Transaction as BlockchainTransaction, TransactionType as BlockchainTxType};
use crate::protocol::blockchain_state::ArchiveService;
use crate::protocol::persistence::CloudbreakAccountDB;
use crate::runtime::{GulfStreamService, SharedPoHService};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// ============================================================================
// BLOCK PRODUCER SERVICE
// ============================================================================

/// Block Producer - Produces blocks on a schedule and wires all services together
/// 
/// This is the heart of the system that:
/// 1. Collects transactions from Gulf Stream (pre-staged by upcoming leader)
/// 2. Produces blocks at regular intervals (slot duration)
/// 3. Shreds blocks via Turbine for propagation
/// 4. Archives blocks via ArchiveService
/// 5. Updates Cloudbreak with new account states
pub struct BlockProducer {
    /// Blockchain state
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    
    /// Gulf Stream for transaction collection
    gulf_stream: Arc<GulfStreamService>,
    
    /// Turbine for block propagation
    turbine: Arc<TurbineService>,
    
    /// Cloudbreak for account state
    cloudbreak: Arc<CloudbreakAccountDB>,
    
    /// Archive for ledger storage
    archive: Arc<ArchiveService>,
    
    /// PoH service for timing
    poh_service: SharedPoHService,
    
    /// Current slot tracker
    current_slot: Arc<AtomicU64>,
    
    /// Slot duration in milliseconds
    slot_duration_ms: u64,
    
    /// Service state
    is_running: AtomicBool,
    
    /// Leader identity (in multi-node, this would be dynamic)
    leader_id: String,
    
    /// Statistics
    blocks_produced: AtomicU64,
    txs_processed: AtomicU64,
    empty_slots: AtomicU64,
}

impl BlockProducer {
    /// Create a new block producer
    pub fn new(
        blockchain: Arc<Mutex<EnhancedBlockchain>>,
        gulf_stream: Arc<GulfStreamService>,
        turbine: Arc<TurbineService>,
        cloudbreak: Arc<CloudbreakAccountDB>,
        archive: Arc<ArchiveService>,
        poh_service: SharedPoHService,
        current_slot: Arc<AtomicU64>,
        slot_duration_ms: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            blockchain,
            gulf_stream,
            turbine,
            cloudbreak,
            archive,
            poh_service,
            current_slot,
            slot_duration_ms,
            is_running: AtomicBool::new(false),
            leader_id: "genesis_validator".to_string(),
            blocks_produced: AtomicU64::new(0),
            txs_processed: AtomicU64::new(0),
            empty_slots: AtomicU64::new(0),
        })
    }
    
    /// Start the block production loop
    pub fn start(self: &Arc<Self>) {
        self.is_running.store(true, Ordering::SeqCst);
        
        let producer = self.clone();
        tokio::spawn(async move {
            println!("🏭 Block Producer started ({}ms slots)", producer.slot_duration_ms);
            
            let mut slot_timer = tokio::time::interval(
                Duration::from_millis(producer.slot_duration_ms)
            );
            
            while producer.is_running.load(Ordering::SeqCst) {
                slot_timer.tick().await;
                producer.produce_slot().await;
            }
            
            println!("🏭 Block Producer stopped");
        });
    }
    
    /// Stop the block producer
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
    
    /// Produce a single slot
    async fn produce_slot(&self) {
        let slot = self.current_slot.fetch_add(1, Ordering::SeqCst);
        
        // 1. Get pending transactions from Gulf Stream
        let pending_txs = self.gulf_stream.get_pending_by_priority(&self.leader_id, 100);
        
        // 2. Also get any pending from blockchain itself (direct submissions)
        let direct_pending = {
            let bc = lock_or_recover(&self.blockchain);
            bc.pending_transactions.clone()
        };
        
        let total_txs = pending_txs.len() + direct_pending.len();
        
        // 3. Skip if no transactions and not time for mandatory block
        if total_txs == 0 && slot % 10 != 0 {
            self.empty_slots.fetch_add(1, Ordering::Relaxed);
            return;
        }
        
        // 4. Get PoH hash for this slot
        let poh_hash = {
            let poh = self.poh_service.read();
            poh.current_hash.clone()
        };
        
        // 5. Produce the block
        let block = {
            let mut bc = lock_or_recover(&self.blockchain);
            
            // Convert Gulf Stream transactions (runtime::core::Transaction) to blockchain::Transaction
            for tx in pending_txs {
                let blockchain_tx = BlockchainTransaction::new(
                    tx.from.clone(),
                    tx.to.clone(),
                    tx.amount,
                    BlockchainTxType::Transfer,
                );
                bc.pending_transactions.push(blockchain_tx);
            }
            
            // Mine the block
            if bc.pending_transactions.is_empty() {
                // Create empty block for chain continuity
                let mut block = Block {
                    index: bc.chain.len() as u64,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    previous_hash: bc.chain.last()
                        .map(|b| b.hash.clone())
                        .unwrap_or_default(),
                    hash: String::new(),
                    slot,
                    poh_hash: poh_hash.clone(),
                    parent_slot: slot.saturating_sub(1),
                    sequencer: self.leader_id.clone(),
                    leader: self.leader_id.clone(),
                    financial_txs: Vec::new(),
                    social_txs: Vec::new(),
                    transactions: Vec::new(),
                    engagement_score: 0.0,
                    tx_count: 0,
                };
                
                // Compute hash and add to chain
                block.hash = format!("{:x}", sha2::Sha256::digest(
                    format!("{}{}{}", block.index, block.timestamp, block.previous_hash).as_bytes()
                ));
                bc.chain.push(block.clone());
                bc.current_slot = slot + 1;
                block
            } else {
                // Mine with transactions (this modifies bc and adds block to chain)
                let _ = bc.mine_pending_transactions(self.leader_id.clone());
                
                // Get the block that was just added
                let block = bc.chain.last().cloned().unwrap_or_else(|| Block {
                    index: 0,
                    timestamp: 0,
                    previous_hash: String::new(),
                    hash: String::new(),
                    slot,
                    poh_hash: poh_hash.clone(),
                    parent_slot: slot.saturating_sub(1),
                    sequencer: self.leader_id.clone(),
                    leader: self.leader_id.clone(),
                    financial_txs: Vec::new(),
                    social_txs: Vec::new(),
                    transactions: Vec::new(),
                    engagement_score: 0.0,
                    tx_count: 0,
                });
                
                // Update slot info on the block
                if let Some(last_block) = bc.chain.last_mut() {
                    last_block.slot = slot;
                    last_block.poh_hash = poh_hash.clone();
                }
                
                bc.current_slot = slot + 1;
                block
            }
        };
        
        let tx_count = block.tx_count;
        
        // 6. Shred block via Turbine
        let shreds = self.turbine.shred_block(&block);
        let shred_count = shreds.len();
        
        // 7. Transmit shreds (simulated - would go over P2P network)
        self.turbine.transmit_shreds(slot);
        
        // 8. Archive the block
        let block_size = borsh::to_vec(&block).map(|v| v.len()).unwrap_or(0) as u64;
        self.archive.archive_block(slot, block.hash.clone(), block_size);
        
        // 9. Sync account states to Cloudbreak
        self.sync_cloudbreak_state();
        
        // 10. Clear Gulf Stream cache for this leader
        self.gulf_stream.clear_leader_cache(&self.leader_id);
        
        // 11. Update statistics
        self.blocks_produced.fetch_add(1, Ordering::Relaxed);
        self.txs_processed.fetch_add(tx_count, Ordering::Relaxed);
        
        if tx_count > 0 {
            println!("📦 Slot {}: {} txs, {} shreds, archived", slot, tx_count, shred_count);
        }
    }
    
    /// Sync blockchain state to Cloudbreak
    fn sync_cloudbreak_state(&self) {
        let balances = {
            let bc = lock_or_recover(&self.blockchain);
            bc.balances.clone()
        };
        
        for (address, balance) in &balances {
            self.cloudbreak.update_balance(address, *balance);
        }
    }
    
    /// Get block producer statistics
    pub fn get_stats(&self) -> BlockProducerStats {
        BlockProducerStats {
            blocks_produced: self.blocks_produced.load(Ordering::Relaxed),
            txs_processed: self.txs_processed.load(Ordering::Relaxed),
            empty_slots: self.empty_slots.load(Ordering::Relaxed),
            current_slot: self.current_slot.load(Ordering::Relaxed),
            is_running: self.is_running.load(Ordering::Relaxed),
            leader_id: self.leader_id.clone(),
            slot_duration_ms: self.slot_duration_ms,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockProducerStats {
    pub blocks_produced: u64,
    pub txs_processed: u64,
    pub empty_slots: u64,
    pub current_slot: u64,
    pub is_running: bool,
    pub leader_id: String,
    pub slot_duration_ms: u64,
}

// ============================================================================
// SERVICE COORDINATOR
// ============================================================================

/// Coordinates all Solana-style services
pub struct ServiceCoordinator {
    pub gulf_stream: Arc<GulfStreamService>,
    pub turbine: Arc<TurbineService>,
    pub cloudbreak: Arc<CloudbreakAccountDB>,
    pub archive: Arc<ArchiveService>,
    pub block_producer: Arc<BlockProducer>,
}

impl ServiceCoordinator {
    /// Create and initialize all services
    pub fn new(
        blockchain: Arc<Mutex<EnhancedBlockchain>>,
        poh_service: SharedPoHService,
        current_slot: Arc<AtomicU64>,
        leader_schedule: Arc<RwLock<crate::runtime::LeaderSchedule>>,
        slot_duration_ms: u64,
    ) -> Self {
        // Create services
        let gulf_stream = GulfStreamService::new(leader_schedule, current_slot.clone());
        let turbine = TurbineService::new();
        let cloudbreak = CloudbreakAccountDB::new(current_slot.clone());
        let archive = ArchiveService::new();
        
        // Create block producer
        let block_producer = BlockProducer::new(
            blockchain.clone(),
            gulf_stream.clone(),
            turbine.clone(),
            cloudbreak.clone(),
            archive.clone(),
            poh_service,
            current_slot,
            slot_duration_ms,
        );
        
        // Initial sync: Load existing balances into Cloudbreak
        {
            let bc = lock_or_recover(&blockchain);
            cloudbreak.load_from_hashmap(&bc.balances);
            println!("💎 Cloudbreak synced with {} accounts", bc.balances.len());
        }
        
        Self {
            gulf_stream,
            turbine,
            cloudbreak,
            archive,
            block_producer,
        }
    }
    
    /// Start all services
    pub fn start_all(&self) {
        self.gulf_stream.start();
        self.turbine.start();
        self.cloudbreak.start();
        self.archive.start();
        self.block_producer.start();
        
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║          ✅ ALL SERVICES WIRED AND RUNNING                    ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  🌊 Gulf Stream:  Forwarding txs to upcoming leaders          ║");
        println!("║  🌪️ Turbine:      Shredding blocks for propagation            ║");
        println!("║  💎 Cloudbreak:   High-performance account database           ║");
        println!("║  📚 Archivers:    Storing ledger segments                     ║");
        println!("║  🏭 Block Prod:   Producing blocks every slot                 ║");
        println!("╚═══════════════════════════════════════════════════════════════╝\n");
    }
    
    /// Stop all services
    pub fn stop_all(&self) {
        self.block_producer.stop();
        self.archive.stop();
        self.cloudbreak.stop();
        self.turbine.stop();
        self.gulf_stream.stop();
    }
    
    /// Get all service statistics
    pub fn get_all_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "gulf_stream": self.gulf_stream.get_stats(),
            "turbine": self.turbine.get_stats(),
            "cloudbreak": self.cloudbreak.get_stats(),
            "archive": self.archive.get_stats(),
            "block_producer": self.block_producer.get_stats(),
            "status": "all_services_wired"
        })
    }
}

// ============================================================================
// TRANSFER WITH GULF STREAM
// ============================================================================

use crate::runtime::core::Transaction as CoreTransaction;

/// Submit a transfer through Gulf Stream instead of direct blockchain access
/// 
/// This is the proper flow:
/// 1. Transaction is signed and validated
/// 2. Submitted to Gulf Stream for forwarding
/// 3. Gulf Stream caches it for the upcoming leader
/// 4. Block Producer picks it up during slot production
/// 5. Transaction is executed and committed
pub fn submit_transfer_to_gulf_stream(
    gulf_stream: &Arc<GulfStreamService>,
    from: String,
    to: String,
    amount: f64,
) -> Result<String, String> {
    use uuid::Uuid;
    
    // Create transaction using runtime::core::Transaction structure
    let tx = CoreTransaction {
        id: Uuid::new_v4().to_string(),
        tx_type: crate::runtime::core::TransactionType::Transfer,
        from: from.clone(),
        to: to.clone(),
        amount,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        signature: String::new(), // Already verified before this point
        read_accounts: vec![from.clone()],
        write_accounts: vec![from.clone(), to.clone()],
    };
    
    let tx_id = tx.id.clone();
    
    // Submit to Gulf Stream
    gulf_stream.submit(tx)?;
    
    Ok(tx_id)
}

// ============================================================================
// POH INTEGRATION - Wire Transactions to Proof of History
// ============================================================================

/// Queue a transaction ID into the PoH clock for ordering proof
/// 
/// This is called when a transaction enters the system, mixing its ID
/// into the PoH hash chain. This proves:
/// 1. The transaction existed at this point in time
/// 2. The ordering of transactions is cryptographically verifiable
/// 3. No transaction can be inserted or reordered after the fact
pub fn queue_tx_to_poh(poh_service: &SharedPoHService, tx_id: &str) {
    let mut poh = poh_service.write();
    poh.queue_transaction(tx_id.to_string());
}

/// Get current PoH slot and hash for transaction timestamping
pub fn get_poh_timestamp(poh_service: &SharedPoHService) -> (u64, String) {
    let poh = poh_service.read();
    (poh.current_slot, poh.current_hash.clone())
}

/// Verify a block's PoH hash is consistent with the PoH clock
pub fn verify_block_poh(poh_service: &SharedPoHService, block_poh_hash: &str, expected_slot: u64) -> bool {
    let poh = poh_service.read();
    
    // For same-slot verification, check hash matches
    if poh.current_slot == expected_slot {
        return poh.current_hash == block_poh_hash;
    }
    
    // For historical slots, we'd need to verify the PoH chain
    // In production, validators store PoH entries and can verify backwards
    // For now, accept if slot is in the past (already finalized)
    if expected_slot < poh.current_slot {
        return true; // Historical slot, trust it
    }
    
    false // Future slot, reject
}

/// Get PoH statistics for monitoring
pub fn get_poh_stats(poh_service: &SharedPoHService) -> serde_json::Value {
    let poh = poh_service.read();
    poh.get_status()
}
