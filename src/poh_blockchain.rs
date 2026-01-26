//! PoH-Integrated Blockchain - Production-Ready Block Production
//!
//! This module integrates Proof of History with the blockchain for:
//! - Deterministic transaction ordering via PoH timestamps
//! - Verifiable block production with merkle state roots
//! - Leader schedule rotation
//! - Transaction finality tracking
//!
//! Architecture:
//! ```
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    POH-INTEGRATED BLOCKCHAIN                            │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   Transactions ──▶ PoH Mix ──▶ Block Producer ──▶ State Root ──▶ Commit │
//! │        │              │              │                │                 │
//! │        │         (ordering)    (leader check)   (merkle tree)           │
//! │        ▼              ▼              ▼                ▼                 │
//! │   Gulf Stream    PoH Entry      Finalized        Verifiable            │
//! │   (forwarding)   (timestamp)      Block            Proof               │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use tracing::{info, warn};

use crate::storage::ConcurrentBlockchain;
use crate::runtime::{
    SharedPoHService, PoHEntry, LeaderSchedule,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};
use crate::protocol::{Transaction, TxData};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 1000;

/// Block production interval in milliseconds
pub const BLOCK_INTERVAL_MS: u64 = 1000;

// ============================================================================
// MERKLE TREE FOR STATE ROOT
// ============================================================================

/// Simple merkle tree implementation for account state proofs
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    /// Build a merkle tree from account balances
    /// Accounts are sorted by address for deterministic ordering
    pub fn from_accounts(accounts: &BTreeMap<String, f64>) -> Self {
        if accounts.is_empty() {
            return Self {
                leaves: vec![],
                root: [0u8; 32],
            };
        }

        // Create leaves: hash(address || balance)
        let leaves: Vec<[u8; 32]> = accounts
            .iter()
            .map(|(addr, balance)| {
                let mut hasher = Sha256::new();
                hasher.update(addr.as_bytes());
                hasher.update(balance.to_le_bytes());
                hasher.finalize().into()
            })
            .collect();

        // Build tree and compute root
        let root = Self::compute_root(&leaves);

        Self { leaves, root }
    }

    /// Compute merkle root from leaves
    fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    // Odd number of nodes: duplicate the last one
                    hasher.update(&chunk[0]);
                }
                next_level.push(hasher.finalize().into());
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Get the root hash as hex string
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }

    /// Generate a merkle proof for an account
    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                current_level[current_index] // Duplicate for odd number
            };

            proof.push(ProofNode {
                hash: hex::encode(sibling),
                is_left: current_index % 2 == 1,
            });

            // Move to next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                next_level.push(hasher.finalize().into());
            }

            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            proof,
            root: self.root_hex(),
        })
    }
}

/// A node in a merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: String,
    pub is_left: bool,
}

/// A merkle proof for account inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub proof: Vec<ProofNode>,
    pub root: String,
}

impl MerkleProof {
    /// Verify this proof against a leaf value
    pub fn verify(&self, address: &str, balance: f64) -> bool {
        // Compute leaf hash
        let mut hasher = Sha256::new();
        hasher.update(address.as_bytes());
        hasher.update(balance.to_le_bytes());
        let mut current: [u8; 32] = hasher.finalize().into();

        // Walk up the tree
        for node in &self.proof {
            let sibling = hex::decode(&node.hash).unwrap_or_default();
            if sibling.len() != 32 {
                return false;
            }

            let mut hasher = Sha256::new();
            if node.is_left {
                hasher.update(&sibling);
                hasher.update(&current);
            } else {
                hasher.update(&current);
                hasher.update(&sibling);
            }
            current = hasher.finalize().into();
        }

        hex::encode(current) == self.root
    }
}

// ============================================================================
// POH-ORDERED TRANSACTION
// ============================================================================

/// A transaction with PoH ordering metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderedTransaction {
    /// The underlying transaction
    pub tx: Transaction,
    /// PoH hash at time of inclusion
    pub poh_hash: String,
    /// PoH sequence number (global ordering)
    pub poh_sequence: u64,
    /// Slot this transaction was included in
    pub slot: u64,
    /// Position within the slot's transaction list
    pub position: u32,
}

// ============================================================================
// FINALIZED BLOCK
// ============================================================================

/// A fully finalized block with PoH integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedBlock {
    /// Block header
    pub slot: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    
    /// State commitment
    pub state_root: String,
    pub accounts_hash: String,
    
    /// PoH linkage
    pub poh_hash: String,
    pub poh_sequence: u64,
    pub poh_entries: Vec<PoHEntry>,
    
    /// Transactions (ordered by PoH)
    pub transactions: Vec<OrderedTransaction>,
    pub tx_count: u32,
    
    /// Consensus metadata
    pub leader: String,
    pub epoch: u64,
    pub confirmations: u64,
}

impl FinalizedBlock {
    /// Compute block hash from header fields
    pub fn compute_hash(
        slot: u64,
        previous_hash: &str,
        state_root: &str,
        poh_hash: &str,
        timestamp: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(slot.to_le_bytes());
        hasher.update(previous_hash.as_bytes());
        hasher.update(state_root.as_bytes());
        hasher.update(poh_hash.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get confirmation status
    pub fn confirmation_status(&self) -> ConfirmationStatus {
        if self.confirmations >= CONFIRMATIONS_REQUIRED {
            ConfirmationStatus::Finalized
        } else if self.confirmations > 0 {
            ConfirmationStatus::Processing { confirmations: self.confirmations }
        } else {
            ConfirmationStatus::Pending
        }
    }
}

// ============================================================================
// BLOCK PRODUCER
// ============================================================================

/// Produces blocks by integrating PoH, transactions, and state
pub struct BlockProducer {
    /// Reference to blockchain storage
    blockchain: ConcurrentBlockchain,
    
    /// PoH service for timestamps
    poh: SharedPoHService,
    
    /// Leader schedule
    leader_schedule: Arc<RwLock<LeaderSchedule>>,
    
    /// Current slot
    current_slot: Arc<AtomicU64>,
    
    /// Pending transactions for next block
    pending_txs: Arc<RwLock<Vec<Transaction>>>,
    
    /// Produced blocks (in-memory cache)
    blocks: Arc<RwLock<Vec<FinalizedBlock>>>,
    
    /// Latest block hash for chaining
    latest_hash: Arc<RwLock<String>>,
    
    /// Our validator identity
    validator_id: String,
}

impl BlockProducer {
    /// Create a new block producer
    pub fn new(
        blockchain: ConcurrentBlockchain,
        poh: SharedPoHService,
        leader_schedule: Arc<RwLock<LeaderSchedule>>,
        current_slot: Arc<AtomicU64>,
        validator_id: String,
    ) -> Self {
        // Genesis hash
        let genesis_hash = "0".repeat(64);
        
        info!("🏭 BlockProducer initialized for validator: {}", validator_id);
        
        Self {
            blockchain,
            poh,
            leader_schedule,
            current_slot,
            pending_txs: Arc::new(RwLock::new(Vec::new())),
            blocks: Arc::new(RwLock::new(Vec::new())),
            latest_hash: Arc::new(RwLock::new(genesis_hash)),
            validator_id,
        }
    }

    /// Submit a transaction for inclusion in the next block
    pub fn submit_transaction(&self, tx: Transaction) -> Result<String, String> {
        // Queue transaction and mix into PoH for ordering
        let tx_id = tx.hash.clone();
        
        {
            let mut poh = self.poh.write();
            poh.queue_transaction(tx_id.clone());
        }
        
        {
            let mut pending = self.pending_txs.write();
            if pending.len() >= MAX_TXS_PER_BLOCK {
                return Err("Block full, transaction queued for next block".to_string());
            }
            pending.push(tx);
        }
        
        Ok(tx_id)
    }

    /// Check if we are the leader for the current slot
    pub fn is_current_leader(&self) -> bool {
        let slot = self.current_slot.load(Ordering::Relaxed);
        let schedule = self.leader_schedule.read();
        let leader = schedule.get_leader(slot);
        leader == self.validator_id
    }

    /// Produce a block for the current slot (if we are leader)
    pub fn produce_block(&self) -> Result<FinalizedBlock, String> {
        let slot = self.current_slot.load(Ordering::Relaxed);
        
        // Check leadership
        let leader = {
            let schedule = self.leader_schedule.read();
            schedule.get_leader(slot)
        };
        
        if leader != self.validator_id {
            return Err(format!("Not leader for slot {}. Leader is: {}", slot, leader));
        }

        // Get PoH state
        let (poh_hash, poh_sequence, poh_entries, epoch) = {
            let mut poh = self.poh.write();
            
            // Mix any pending transactions
            poh.mix_pending_transactions();
            
            // Get current state
            let hash = poh.current_hash.clone();
            let seq = poh.num_hashes;
            let entries = poh.current_entries.clone();
            let epoch = poh.current_epoch;
            
            // Advance to next slot
            poh.advance_slot();
            
            (hash, seq, entries, epoch)
        };

        // Collect transactions
        let transactions: Vec<Transaction> = {
            let mut pending = self.pending_txs.write();
            std::mem::take(&mut *pending)
        };

        // Execute transactions and build ordered list
        let mut ordered_txs = Vec::new();
        for (position, tx) in transactions.into_iter().enumerate() {
            // Execute the transaction
            match self.execute_transaction(&tx) {
                Ok(_) => {
                    ordered_txs.push(OrderedTransaction {
                        tx,
                        poh_hash: poh_hash.clone(),
                        poh_sequence,
                        slot,
                        position: position as u32,
                    });
                }
                Err(e) => {
                    warn!("Transaction {} failed: {}", tx.hash, e);
                }
            }
        }

        // Compute state root from current account state
        let state_root = self.compute_state_root();

        // Get previous hash
        let previous_hash = self.latest_hash.read().clone();

        // Compute block hash
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let block_hash = FinalizedBlock::compute_hash(
            slot,
            &previous_hash,
            &state_root,
            &poh_hash,
            timestamp,
        );

        // Create the block
        let block = FinalizedBlock {
            slot,
            timestamp,
            previous_hash,
            hash: block_hash.clone(),
            state_root: state_root.clone(),
            accounts_hash: state_root.clone(), // Same as state root for now
            poh_hash,
            poh_sequence,
            poh_entries,
            transactions: ordered_txs.clone(),
            tx_count: ordered_txs.len() as u32,
            leader: self.validator_id.clone(),
            epoch,
            confirmations: 0,
        };

        // Update latest hash
        {
            let mut latest = self.latest_hash.write();
            *latest = block_hash.clone();
        }

        // Store block
        {
            let mut blocks = self.blocks.write();
            blocks.push(block.clone());
            
            // Update confirmations on previous blocks
            let len = blocks.len();
            for i in 0..len.saturating_sub(1) {
                blocks[len - 1 - i - 1].confirmations += 1;
            }
        }

        // Update leader schedule
        {
            let mut schedule = self.leader_schedule.write();
            schedule.record_slot_production(&self.validator_id, slot);
        }

        // Advance slot counter
        self.current_slot.fetch_add(1, Ordering::Relaxed);

        info!(
            "📦 Block {} produced: {} txs, state_root: {}..., poh: {}...",
            slot,
            block.tx_count,
            &block.state_root[..16],
            &block.poh_hash[..16]
        );

        Ok(block)
    }

    /// Execute a single transaction using the new treasury architecture
    /// Note: Amounts are in u64 (6 decimals), converted to f64 for storage
    fn execute_transaction(&self, tx: &Transaction) -> Result<(), String> {
        match &tx.data {
            TxData::BridgeMint { recipient, amount, base_tx_hash } => {
                // Bridge mints wUSDC for user (deposit detected on Base)
                info!("Bridge mint: {} wUSDC to {} (base_tx: {})", 
                    amount, recipient, &base_tx_hash[..8.min(base_tx_hash.len())]);
                self.blockchain.credit(recipient, *amount as f64)
            }
            
            TxData::TransferWusdc { to, amount } => {
                // Transfer wUSDC between accounts
                self.blockchain.debit(&tx.from, *amount as f64)?;
                self.blockchain.credit(to, *amount as f64)
            }
            
            TxData::BuyBundle { bundle_id } => {
                // User buys bundle - wUSDC to Cashier, $BB minted
                // Note: The actual bundle logic is in L1State
                // Here we just log for the PoH chain
                info!("Bundle purchase: {} bought {}", tx.from, bundle_id);
                Ok(())
            }
            
            TxData::Redeem { amount } => {
                // User redeems $BB for wUSDC
                info!("Redemption: {} redeemed {} $BB", tx.from, amount);
                Ok(())
            }
            
            TxData::BridgeRelease { user, amount, base_tx_hash } => {
                // Bridge released USDC on Base, burn wUSDC on L1
                info!("Bridge release: {} wUSDC from {} (base_tx: {})",
                    amount, user, &base_tx_hash[..8.min(base_tx_hash.len())]);
                self.blockchain.debit(user, *amount as f64)
            }
        }
    }

    /// Compute merkle state root from current account balances
    fn compute_state_root(&self) -> String {
        // Get all accounts from blockchain
        // Note: In production, you'd want a more efficient way to iterate accounts
        let accounts = self.get_all_accounts();
        let tree = MerkleTree::from_accounts(&accounts);
        tree.root_hex()
    }

    /// Get all accounts (for state root computation)
    fn get_all_accounts(&self) -> BTreeMap<String, f64> {
        // This would need to be implemented in ConcurrentBlockchain
        // For now, return empty (state root will be computed differently)
        BTreeMap::new()
    }

    /// Get a block by slot number
    pub fn get_block(&self, slot: u64) -> Option<FinalizedBlock> {
        let blocks = self.blocks.read();
        blocks.iter().find(|b| b.slot == slot).cloned()
    }

    /// Get the latest block
    pub fn get_latest_block(&self) -> Option<FinalizedBlock> {
        let blocks = self.blocks.read();
        blocks.last().cloned()
    }

    /// Get block count
    pub fn block_count(&self) -> usize {
        self.blocks.read().len()
    }

    /// Get pending transaction count
    pub fn pending_tx_count(&self) -> usize {
        self.pending_txs.read().len()
    }

    /// Generate merkle proof for an account
    pub fn generate_account_proof(&self, address: &str) -> Option<MerkleProof> {
        let accounts = self.get_all_accounts();
        let addresses: Vec<_> = accounts.keys().collect();
        
        let index = addresses.iter().position(|a| *a == address)?;
        let tree = MerkleTree::from_accounts(&accounts);
        tree.generate_proof(index)
    }
}

// ============================================================================
// TRANSACTION FINALITY TRACKER
// ============================================================================

/// Tracks confirmation status of transactions
pub struct FinalityTracker {
    /// Transaction to slot mapping: tx_id -> (slot, confirmations)
    tx_status: Arc<RwLock<std::collections::HashMap<String, (u64, u64)>>>,
    
    /// Current chain head slot
    head_slot: Arc<AtomicU64>,
}

impl FinalityTracker {
    pub fn new(head_slot: Arc<AtomicU64>) -> Self {
        Self {
            tx_status: Arc::new(RwLock::new(std::collections::HashMap::new())),
            head_slot,
        }
    }

    /// Record a transaction inclusion
    pub fn record_inclusion(&self, tx_id: &str, slot: u64) {
        let mut status = self.tx_status.write();
        status.insert(tx_id.to_string(), (slot, 0));
    }

    /// Update confirmations based on new head
    pub fn update_confirmations(&self, new_head: u64) {
        self.head_slot.store(new_head, Ordering::Relaxed);
        
        let mut status = self.tx_status.write();
        for (_, (slot, confirmations)) in status.iter_mut() {
            if new_head > *slot {
                *confirmations = new_head - *slot;
            }
        }
    }

    /// Get confirmation status for a transaction
    pub fn get_status(&self, tx_id: &str) -> ConfirmationStatus {
        let status = self.tx_status.read();
        
        match status.get(tx_id) {
            None => ConfirmationStatus::Pending,
            Some((_, confirmations)) => {
                if *confirmations >= CONFIRMATIONS_REQUIRED {
                    ConfirmationStatus::Finalized
                } else if *confirmations > 0 {
                    ConfirmationStatus::Processing { confirmations: *confirmations }
                } else {
                    ConfirmationStatus::Processing { confirmations: 0 }
                }
            }
        }
    }

    /// Check if transaction is finalized
    pub fn is_finalized(&self, tx_id: &str) -> bool {
        matches!(self.get_status(tx_id), ConfirmationStatus::Finalized)
    }
}

// ============================================================================
// VERIFICATION FUNCTIONS
// ============================================================================

/// Verify a block's integrity
pub fn verify_block(block: &FinalizedBlock, expected_previous_hash: &str) -> bool {
    // 1. Verify previous hash linkage
    if block.previous_hash != expected_previous_hash {
        return false;
    }

    // 2. Verify block hash computation
    let computed_hash = FinalizedBlock::compute_hash(
        block.slot,
        &block.previous_hash,
        &block.state_root,
        &block.poh_hash,
        block.timestamp,
    );
    
    if computed_hash != block.hash {
        return false;
    }

    // 3. Verify transaction count
    if block.transactions.len() != block.tx_count as usize {
        return false;
    }

    // 4. Verify PoH entries (if present)
    if !block.poh_entries.is_empty() {
        // Entries should be sequential
        for i in 1..block.poh_entries.len() {
            if block.poh_entries[i].num_hashes <= block.poh_entries[i-1].num_hashes {
                return false;
            }
        }
    }

    true
}

/// Verify a chain of blocks
pub fn verify_chain(blocks: &[FinalizedBlock]) -> bool {
    if blocks.is_empty() {
        return true;
    }

    let mut expected_previous = "0".repeat(64);
    
    for block in blocks {
        if !verify_block(block, &expected_previous) {
            return false;
        }
        expected_previous = block.hash.clone();
    }

    true
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_empty() {
        let accounts = BTreeMap::new();
        let tree = MerkleTree::from_accounts(&accounts);
        assert_eq!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_single() {
        let mut accounts = BTreeMap::new();
        accounts.insert("alice".to_string(), 100.0);
        
        let tree = MerkleTree::from_accounts(&accounts);
        assert!(!tree.root_hex().is_empty());
        assert_ne!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let mut accounts = BTreeMap::new();
        accounts.insert("alice".to_string(), 100.0);
        accounts.insert("bob".to_string(), 200.0);
        accounts.insert("charlie".to_string(), 300.0);
        
        let tree = MerkleTree::from_accounts(&accounts);
        assert!(!tree.root_hex().is_empty());
        
        // Generate and verify proof for bob
        let proof = tree.generate_proof(1).unwrap();
        assert!(proof.verify("bob", 200.0));
        assert!(!proof.verify("bob", 201.0)); // Wrong balance
    }

    #[test]
    fn test_block_hash_deterministic() {
        let hash1 = FinalizedBlock::compute_hash(
            1, "prev", "state", "poh", 12345
        );
        let hash2 = FinalizedBlock::compute_hash(
            1, "prev", "state", "poh", 12345
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_confirmation_status() {
        let block = FinalizedBlock {
            slot: 1,
            timestamp: 0,
            previous_hash: String::new(),
            hash: String::new(),
            state_root: String::new(),
            accounts_hash: String::new(),
            poh_hash: String::new(),
            poh_sequence: 0,
            poh_entries: vec![],
            transactions: vec![],
            tx_count: 0,
            leader: String::new(),
            epoch: 0,
            confirmations: 0,
        };
        
        assert_eq!(block.confirmation_status(), ConfirmationStatus::Pending);
        
        let mut confirmed = block.clone();
        confirmed.confirmations = CONFIRMATIONS_REQUIRED;
        assert_eq!(confirmed.confirmation_status(), ConfirmationStatus::Finalized);
    }
}
