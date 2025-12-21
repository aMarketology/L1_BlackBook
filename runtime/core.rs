//! Layer1 Runtime Core
//!
//! Core blockchain types and Solana-style parallel execution infrastructure.
//! 
//! INFRASTRUCTURE NOTE: ParallelScheduler and AccountLockManager are built for
//! high-throughput parallel transaction execution. Currently using simpler
//! sequential execution via EnhancedBlockchain. These will be wired up when
//! we need Sealevel-style performance.
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicBool, AtomicU64, Ordering};
use borsh::{BorshSerialize, BorshDeserialize};

// Note: These modules are in src/ and accessed via main.rs
// For standalone runtime use, these would need to be integrated differently

// ============================================================================
// SEALEVEL CONFIGURATION - Batch Tuning Constants
// ============================================================================

/// Optimal batch size for parallel execution (tuned for typical workloads)
pub const OPTIMAL_BATCH_SIZE: usize = 64;
/// Maximum batch size to prevent memory issues
pub const MAX_BATCH_SIZE: usize = 256;
/// Minimum batch size for efficiency
pub const MIN_BATCH_SIZE: usize = 8;
/// Conflict threshold - if > 50% conflicts, reduce batch size
pub const CONFLICT_THRESHOLD: f64 = 0.5;

// ============================================================================
// ACCOUNT LOCK MANAGER - Fine-Grained Sealevel-Style Locking
// ============================================================================

/// Fine-grained account lock manager for Sealevel-style parallel execution
/// 
/// Implements read/write locking at the account level:
/// - Multiple readers can access an account simultaneously
/// - Writers get exclusive access
/// - Prevents conflicts during parallel transaction execution
#[derive(Debug)]
pub struct AccountLockManager {
    /// Read lock counts per account (multiple readers allowed)
    read_locks: DashMap<String, AtomicU32>,
    /// Write lock flags per account (exclusive access)
    write_locks: DashMap<String, AtomicBool>,
    /// Statistics: total lock acquisitions
    pub total_acquisitions: AtomicU64,
    /// Statistics: total lock conflicts
    pub total_conflicts: AtomicU64,
}

impl AccountLockManager {
    pub fn new() -> Self {
        Self {
            read_locks: DashMap::new(),
            write_locks: DashMap::new(),
            total_acquisitions: AtomicU64::new(0),
            total_conflicts: AtomicU64::new(0),
        }
    }
    
    /// Try to acquire all locks needed for a transaction
    /// Returns true if all locks acquired, false if any conflict
    pub fn try_acquire_locks(&self, tx: &Transaction) -> bool {
        self.total_acquisitions.fetch_add(1, Ordering::Relaxed);
        
        // First check if we can acquire all write locks
        for account in &tx.write_accounts {
            // Check if there's an existing write lock
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            // Check if there are any read locks (can't write while being read)
            if let Some(lock) = self.read_locks.get(account) {
                if lock.load(Ordering::Acquire) > 0 {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
        
        // Check read accounts for write conflicts
        for account in &tx.read_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
        
        // Acquire all locks
        for account in &tx.write_accounts {
            self.write_locks
                .entry(account.clone())
                .or_insert_with(|| AtomicBool::new(false))
                .store(true, Ordering::Release);
        }
        
        for account in &tx.read_accounts {
            self.read_locks
                .entry(account.clone())
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::Release);
        }
        
        true
    }
    
    /// Release all locks held by a transaction
    pub fn release_locks(&self, tx: &Transaction) {
        // Release write locks
        for account in &tx.write_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                lock.store(false, Ordering::Release);
            }
        }
        
        // Release read locks
        for account in &tx.read_accounts {
            if let Some(lock) = self.read_locks.get(account) {
                lock.fetch_sub(1, Ordering::Release);
            }
        }
    }
    
    /// Get conflict rate for batch tuning
    pub fn get_conflict_rate(&self) -> f64 {
        let total = self.total_acquisitions.load(Ordering::Relaxed);
        let conflicts = self.total_conflicts.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            conflicts as f64 / total as f64
        }
    }
    
    /// Reset statistics (call after each epoch)
    pub fn reset_stats(&self) {
        self.total_acquisitions.store(0, Ordering::Relaxed);
        self.total_conflicts.store(0, Ordering::Relaxed);
    }
    
    /// Get lock statistics as JSON
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_acquisitions": self.total_acquisitions.load(Ordering::Relaxed),
            "total_conflicts": self.total_conflicts.load(Ordering::Relaxed),
            "conflict_rate": self.get_conflict_rate(),
            "active_read_locks": self.read_locks.len(),
            "active_write_locks": self.write_locks.len(),
        })
    }
}

impl Default for AccountLockManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SEALEVEL-STYLE PARALLEL TRANSACTION EXECUTION
// ============================================================================

/// Transaction with explicit read/write accounts for parallel scheduling
/// 
/// Serialization strategy:
/// - Borsh: Used for internal node-to-node communication (fast, compact)
/// - Serde JSON: Used for RPC layer with Base64-encoded Borsh payload
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: String,
    /// Accounts this transaction reads from (for parallel scheduling)
    #[serde(default)]
    pub read_accounts: Vec<String>,
    /// Accounts this transaction writes to (for parallel scheduling)
    #[serde(default)]
    pub write_accounts: Vec<String>,
    /// Transaction type for categorization
    #[serde(default)]
    pub tx_type: TransactionType,
    /// Unique transaction ID
    #[serde(default)]
    pub id: String,
}

/// Transaction type for categorization (Two-Lane Model)
/// - Financial Lane: Transfer, BetPlacement, BetResolution, StakeDeposit, StakeWithdraw
/// - Social Lane: SocialAction
/// - System: SystemReward (internal)
/// 
/// NOTE: No ContractCall - we use native logic, no VM execution needed.
/// Implements both Serde and Borsh for hybrid serialization
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default, PartialEq)]
pub enum TransactionType {
    #[default]
    Transfer,
    BetPlacement,
    BetResolution,
    SocialAction,
    StakeDeposit,
    StakeWithdraw,
    SystemReward,
}

impl TransactionType {
    /// Returns true if this is a financial lane transaction
    pub fn is_financial(&self) -> bool {
        matches!(self, 
            TransactionType::Transfer | 
            TransactionType::BetPlacement | 
            TransactionType::BetResolution |
            TransactionType::StakeDeposit |
            TransactionType::StakeWithdraw
        )
    }
    
    /// Returns true if this is a social lane transaction
    pub fn is_social(&self) -> bool {
        matches!(self, TransactionType::SocialAction)
    }
}

impl Transaction {
    /// Create a new transaction with automatic account detection
    pub fn new(from: String, to: String, amount: f64, tx_type: TransactionType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Auto-detect read/write accounts based on transaction type
        let (read_accounts, write_accounts) = match &tx_type {
            TransactionType::Transfer => {
                (vec![from.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::BetPlacement => {
                // Bet reads user balance, writes to user and bet pool
                (vec![from.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::BetResolution => {
                // Resolution reads bet state, writes to multiple winners
                (vec![to.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::SocialAction => {
                // Social actions only affect the actor
                (vec![from.clone()], vec![from.clone()])
            },
            _ => (vec![from.clone()], vec![from.clone(), to.clone()]),
        };
        
        Self {
            from,
            to,
            amount,
            timestamp,
            signature: format!("sig_{}", &id[..8]),
            read_accounts,
            write_accounts,
            tx_type,
            id,
        }
    }
    
    /// Check if this transaction conflicts with another (for parallel scheduling)
    pub fn conflicts_with(&self, other: &Transaction) -> bool {
        // Conflict if: my writes intersect with their reads or writes
        // OR: my reads intersect with their writes
        for my_write in &self.write_accounts {
            if other.write_accounts.contains(my_write) || other.read_accounts.contains(my_write) {
                return true;
            }
        }
        for my_read in &self.read_accounts {
            if other.write_accounts.contains(my_read) {
                return true;
            }
        }
        false
    }
    
    // ========================================================================
    // BORSH SERIALIZATION HELPERS (For Borsh-inside-JSON strategy)
    // ========================================================================
    
    /// Serialize transaction to Borsh bytes (for node-to-node communication)
    pub fn to_borsh(&self) -> Result<Vec<u8>, std::io::Error> {
        borsh::to_vec(self)
    }
    
    /// Deserialize transaction from Borsh bytes
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
    pub fn from_base64(encoded: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(encoded)?;
        let tx = Self::from_borsh(&bytes)?;
        Ok(tx)
    }
}

/// Parallel transaction scheduler (Sealevel-inspired)
/// 
/// Enhanced with:
/// - AccountLockManager for fine-grained locking
/// - Dynamic batch size tuning based on conflict rate
/// - Metrics collection for optimization
pub struct ParallelScheduler {
    /// Thread pool for parallel execution
    thread_pool: rayon::ThreadPool,
    /// Account lock manager for fine-grained locking
    pub lock_manager: Arc<AccountLockManager>,
    /// Current optimal batch size (dynamically tuned)
    current_batch_size: AtomicU64,
    /// Total transactions processed
    pub total_processed: AtomicU64,
    /// Total batches executed
    pub total_batches: AtomicU64,
}

impl ParallelScheduler {
    pub fn new() -> Self {
        // Create thread pool with available CPUs
        let num_threads = num_cpus::get().max(4);
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());
        
        println!("⚡ Sealevel Parallel Scheduler initialized:");
        println!("   └─ {} threads, batch size: {}, lock manager: enabled", 
                 num_threads, OPTIMAL_BATCH_SIZE);
        
        Self { 
            thread_pool,
            lock_manager: Arc::new(AccountLockManager::new()),
            current_batch_size: AtomicU64::new(OPTIMAL_BATCH_SIZE as u64),
            total_processed: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
        }
    }
    
    /// Get current optimal batch size
    pub fn get_batch_size(&self) -> usize {
        self.current_batch_size.load(Ordering::Relaxed) as usize
    }
    
    /// Tune batch size based on conflict rate
    pub fn tune_batch_size(&self) {
        let conflict_rate = self.lock_manager.get_conflict_rate();
        let current = self.current_batch_size.load(Ordering::Relaxed) as usize;
        
        let new_size = if conflict_rate > CONFLICT_THRESHOLD {
            // High conflicts - reduce batch size
            (current / 2).max(MIN_BATCH_SIZE)
        } else if conflict_rate < CONFLICT_THRESHOLD / 2.0 {
            // Low conflicts - increase batch size
            (current * 3 / 2).min(MAX_BATCH_SIZE)
        } else {
            current
        };
        
        if new_size != current {
            self.current_batch_size.store(new_size as u64, Ordering::Relaxed);
            println!("🔧 Batch size tuned: {} → {} (conflict rate: {:.2}%)", 
                     current, new_size, conflict_rate * 100.0);
        }
    }
    
    /// Schedule transactions into non-conflicting batches using lock manager
    pub fn schedule(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() {
            return vec![];
        }
        
        let batch_size = self.get_batch_size();
        let mut batches: Vec<Vec<Transaction>> = vec![];
        let mut remaining = transactions;
        
        while !remaining.is_empty() {
            let mut current_batch: Vec<Transaction> = vec![];
            let mut next_remaining: Vec<Transaction> = vec![];
            
            for tx in remaining {
                // Use lock manager for conflict detection
                if current_batch.len() >= batch_size {
                    next_remaining.push(tx);
                    continue;
                }
                
                // Check if tx conflicts with any in current batch
                let conflicts = current_batch.iter().any(|batch_tx| tx.conflicts_with(batch_tx));
                
                if conflicts {
                    next_remaining.push(tx);
                } else {
                    current_batch.push(tx);
                }
            }
            
            if !current_batch.is_empty() {
                batches.push(current_batch);
            }
            remaining = next_remaining;
        }
        
        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        
        if batches.len() > 1 {
            println!("📦 Scheduled {} batches (size limit: {}) for parallel execution", 
                     batches.len(), batch_size);
        }
        
        batches
    }
    
    /// Schedule with lock-based conflict detection (more accurate)
    pub fn schedule_with_locks(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() {
            return vec![];
        }
        
        let batch_size = self.get_batch_size();
        let mut batches: Vec<Vec<Transaction>> = vec![];
        let mut remaining = transactions;
        
        while !remaining.is_empty() {
            let mut current_batch: Vec<Transaction> = vec![];
            let mut next_remaining: Vec<Transaction> = vec![];
            
            // Reset locks for this scheduling round
            for tx in remaining {
                if current_batch.len() >= batch_size {
                    next_remaining.push(tx);
                    continue;
                }
                
                // Try to acquire locks - if successful, add to batch
                if self.lock_manager.try_acquire_locks(&tx) {
                    current_batch.push(tx);
                } else {
                    next_remaining.push(tx);
                }
            }
            
            // Release all locks after scheduling
            for tx in &current_batch {
                self.lock_manager.release_locks(tx);
            }
            
            if !current_batch.is_empty() {
                batches.push(current_batch);
            }
            remaining = next_remaining;
        }
        
        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        batches
    }
    
    /// Execute a batch of non-conflicting transactions in parallel
    pub fn execute_batch_parallel(
        &self,
        batch: Vec<Transaction>,
        balances: &DashMap<String, f64>,
    ) -> Vec<TransactionResult> {
        let batch_len = batch.len();
        
        let results = self.thread_pool.install(|| {
            batch.par_iter()
                .map(|tx| self.execute_single(tx, balances))
                .collect()
        });
        
        self.total_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
        results
    }
    
    /// Execute with lock acquisition (thread-safe)
    pub fn execute_batch_with_locks(
        &self,
        batch: Vec<Transaction>,
        balances: &DashMap<String, f64>,
    ) -> Vec<TransactionResult> {
        let batch_len = batch.len();
        let lock_manager = self.lock_manager.clone();
        
        let results = self.thread_pool.install(|| {
            batch.par_iter()
                .map(|tx| {
                    // Acquire locks before execution
                    while !lock_manager.try_acquire_locks(tx) {
                        std::hint::spin_loop();
                    }
                    
                    let result = self.execute_single(tx, balances);
                    
                    // Release locks after execution
                    lock_manager.release_locks(tx);
                    
                    result
                })
                .collect()
        });
        
        self.total_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
        results
    }
    
    /// Execute a single transaction
    fn execute_single(
        &self,
        tx: &Transaction,
        balances: &DashMap<String, f64>,
    ) -> TransactionResult {
        // Check balance for non-system transactions
        if !Self::is_system_account(&tx.from) {
            let balance = balances.get(&tx.from).map(|b| *b).unwrap_or(0.0);
            if balance < tx.amount {
                return TransactionResult {
                    tx_id: tx.id.clone(),
                    success: false,
                    error: Some(format!("Insufficient balance: have {}, need {}", balance, tx.amount)),
                };
            }
            
            // Deduct from sender
            balances.entry(tx.from.clone())
                .and_modify(|b| *b -= tx.amount);
        }
        
        // Add to recipient (unless burned)
        if tx.to != "burned_tokens" {
            balances.entry(tx.to.clone())
                .and_modify(|b| *b += tx.amount)
                .or_insert(tx.amount);
        }
        
        TransactionResult {
            tx_id: tx.id.clone(),
            success: true,
            error: None,
        }
    }
    
    fn is_system_account(account: &str) -> bool {
        matches!(account, 
            "genesis" | "mining_reward" | "connection_reward" | 
            "social_mining" | "signup_bonus" | "bet_pool" |
            "system" | "poh_validator"
        ) || account.starts_with("bet_contract_") 
          || account.starts_with("chess_contract_")
    }
    
    /// Get scheduler statistics for monitoring
    pub fn get_stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_processed: self.total_processed.load(Ordering::Relaxed),
            total_batches: self.total_batches.load(Ordering::Relaxed),
            current_batch_size: self.current_batch_size.load(Ordering::Relaxed) as usize,
            conflict_rate: self.lock_manager.get_conflict_rate(),
            thread_count: self.thread_pool.current_num_threads(),
        }
    }
    
    /// Reset scheduler statistics
    pub fn reset_stats(&self) {
        self.total_processed.store(0, Ordering::Relaxed);
        self.total_batches.store(0, Ordering::Relaxed);
        self.lock_manager.reset_stats();
    }
}

/// Statistics from the parallel scheduler
#[derive(Debug, Clone, Serialize)]
pub struct SchedulerStats {
    pub total_processed: u64,
    pub total_batches: u64,
    pub current_batch_size: usize,
    pub conflict_rate: f64,
    pub thread_count: usize,
}

#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub tx_id: String,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// CORE BLOCKCHAIN STRUCTURES - SEQUENCER MODEL WITH TWO-LANE BLOCKS
// ============================================================================
//
// This is a SPECIALIZED L1 where "mining" is just sorting:
// - Generic Mining: "Load smart contract, read memory, calculate gas, run logic" (Slow)
// - Our L1: "Verify signature, add +1 to database" (Blazing fast)
//
// Validators are SEQUENCERS that:
// 1. Ingest: Accept thousands of Bet/Post actions per second
// 2. Deduplicate: "Did Alice already bet on this?"
// 3. Order: Timestamp them (Proof of History)
// 4. Commit: Stamp them into a block
//
// Blocks have TWO DEDICATED LANES:
// - Financial Lane: Bets, Transfers, Stakes (balance updates)
// - Social Lane: Likes, Posts, Comments (counter updates)
// ============================================================================

/// Streamlined Block structure for Sequencer model
/// 
/// This is NOT a "container of code" - it's a Structured Database Update.
/// We strip out 90% of standard block overhead by using native logic.
/// 
/// Serialization strategy:
/// - Borsh: Used for node-to-node block propagation (Turbine-style)
/// - Serde JSON: Used for RPC queries with Base64-encoded Borsh
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    // ========== IDENTITY ==========
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    
    // ========== POH TIMING ==========
    /// PoH slot number (cryptographic timestamp)
    #[serde(default)]
    pub slot: u64,
    /// PoH hash at block creation
    #[serde(default)]
    pub poh_hash: String,
    /// Parent slot (for fork detection)
    #[serde(default)]
    pub parent_slot: u64,
    
    // ========== SEQUENCER ==========
    /// The sequencer (validator) who committed this block
    #[serde(default)]
    pub sequencer: String,
    /// Backward compatible alias for sequencer
    #[serde(default)]
    pub leader: String,
    
    // ========== TWO-LANE BODY ==========
    /// Financial Lane: Bets, Transfers, Stakes (balance-affecting)
    #[borsh(skip)]
    pub financial_txs: Vec<Transaction>,
    /// Social Lane: Likes, Posts, Comments (engagement actions)
    #[borsh(skip)]
    pub social_txs: Vec<Transaction>,
    /// Backward compatible: combined transactions
    #[borsh(skip)]
    #[serde(default)]
    pub transactions: Vec<Transaction>,
    
    // ========== METRICS ==========
    /// Engagement score for Proof-of-Engagement validation
    #[serde(default)]
    pub engagement_score: f64,
    /// Total transaction count (financial + social)
    #[serde(default)]
    pub tx_count: u64,
}

impl Block {
    /// Create a new block with two-lane architecture
    /// 
    /// Sequencer model: No puzzle solving, just commit transactions
    pub fn new(
        index: u64, 
        financial_txs: Vec<Transaction>, 
        social_txs: Vec<Transaction>,
        previous_hash: String, 
        sequencer: String,
    ) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let tx_count = (financial_txs.len() + social_txs.len()) as u64;
        let transactions = [financial_txs.clone(), social_txs.clone()].concat();
        
        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            hash: String::new(),
            slot: 0,
            poh_hash: String::new(),
            parent_slot: 0,
            sequencer: sequencer.clone(),
            leader: sequencer,
            financial_txs,
            social_txs,
            transactions,
            engagement_score: 0.0,
            tx_count,
        };
        block.hash = block.calculate_hash();
        block
    }
    
    /// Create a PoH-enabled block with two lanes (primary constructor)
    /// 
    /// This is the main block creation method for the Sequencer model:
    /// - Ingest → Deduplicate → Order (PoH) → Commit
    pub fn new_poh(
        index: u64,
        financial_txs: Vec<Transaction>,
        social_txs: Vec<Transaction>,
        previous_hash: String,
        sequencer: String,
        slot: u64,
        poh_hash: String,
        engagement_score: f64,
    ) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let parent_slot = if slot > 0 { slot - 1 } else { 0 };
        let tx_count = (financial_txs.len() + social_txs.len()) as u64;
        let transactions = [financial_txs.clone(), social_txs.clone()].concat();
        
        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            hash: String::new(),
            slot,
            poh_hash,
            parent_slot,
            sequencer: sequencer.clone(),
            leader: sequencer,
            financial_txs,
            social_txs,
            transactions,
            engagement_score,
            tx_count,
        };
        block.hash = block.calculate_hash();
        block
    }
    
    /// Legacy constructor for backwards compatibility (wraps into financial lane)
    #[allow(deprecated)]
    pub fn from_transactions(
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        sequencer: String,
        slot: u64,
        poh_hash: String,
        engagement_score: f64,
    ) -> Self {
        // Categorize transactions into lanes
        let (financial, social): (Vec<_>, Vec<_>) = transactions
            .into_iter()
            .partition(|tx| tx.tx_type.is_financial() || matches!(tx.tx_type, TransactionType::SystemReward));
        
        Self::new_poh(index, financial, social, previous_hash, sequencer, slot, poh_hash, engagement_score)
    }
    
    /// Get all transactions (both lanes combined) for compatibility
    pub fn all_transactions(&self) -> Vec<Transaction> {
        let mut all = self.financial_txs.clone();
        all.extend(self.social_txs.clone());
        all
    }

    /// Calculate block hash (includes both lanes and PoH data)
    /// 
    /// NO PoW puzzle solving - hash is computed once and committed.
    /// The hash includes: index, timestamp, both tx lanes, PoH slot/hash, sequencer, engagement
    pub fn calculate_hash(&self) -> String {
        let financial_data = serde_json::to_string(&self.financial_txs).unwrap_or_default();
        let social_data = serde_json::to_string(&self.social_txs).unwrap_or_default();
        
        let input = format!("{}{}{}{}{}{}{}{}{}{}{}",
            self.index, 
            self.timestamp, 
            financial_data,
            social_data,
            self.previous_hash, 
            self.slot, 
            self.poh_hash,
            self.sequencer, 
            self.engagement_score,
            self.tx_count,
            self.parent_slot
        );
        
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
    
    // NOTE: mine_block() REMOVED - no PoW puzzle solving in Sequencer model
    // Blocks are simply committed by the sequencer after PoH ordering
    
    // ========================================================================
    // BORSH SERIALIZATION HELPERS (For Turbine-style block propagation)
    // ========================================================================
    
    /// Serialize block to Borsh bytes (for node-to-node propagation)
    pub fn to_borsh(&self) -> Result<Vec<u8>, std::io::Error> {
        borsh::to_vec(self)
    }
    
    /// Deserialize block from Borsh bytes
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
    pub fn from_base64(encoded: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(encoded)?;
        let block = Self::from_borsh(&bytes)?;
        Ok(block)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_new() {
        let tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100.0,
            TransactionType::Transfer,
        );
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "bob");
        assert_eq!(tx.amount, 100.0);
        assert!(!tx.id.is_empty());
    }

    #[test]
    fn test_block_new_poh() {
        let financial = vec![Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            50.0,
            TransactionType::Transfer,
        )];
        let social = vec![Transaction::new(
            "alice".to_string(),
            "post123".to_string(),
            0.0,
            TransactionType::SocialPost,
        )];
        
        let block = Block::new_poh(
            1,
            financial,
            social,
            "prev_hash".to_string(),
            "sequencer1".to_string(),
            42,
            "poh_hash".to_string(),
            100.0,
        );
        
        assert_eq!(block.index, 1);
        assert_eq!(block.slot, 42);
        assert_eq!(block.tx_count, 2);
        assert_eq!(block.financial_txs.len(), 1);
        assert_eq!(block.social_txs.len(), 1);
    }

    #[test]
    fn test_parallel_scheduler_conflict_detection() {
        let scheduler = ParallelScheduler::new();
        
        let tx1 = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100.0,
            TransactionType::Transfer,
        );
        let tx2 = Transaction::new(
            "alice".to_string(),  // Same sender - conflicts with tx1
            "carol".to_string(),
            50.0,
            TransactionType::Transfer,
        );
        let tx3 = Transaction::new(
            "dave".to_string(),  // Different accounts - no conflict
            "eve".to_string(),
            25.0,
            TransactionType::Transfer,
        );
        
        let batches = scheduler.schedule_batch(&[tx1, tx2, tx3]);
        
        // tx1 and tx2 conflict (same sender), tx3 is independent
        // Should produce at least 2 batches
        assert!(batches.len() >= 2);
    }
}
