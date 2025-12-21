// ═══════════════════════════════════════════════════════════════════════════════
// BLOCK PROPOSAL PROTOCOL
// ═══════════════════════════════════════════════════════════════════════════════
//
// Round-robin block production with engagement verification.
// Each validator in the active set takes turns proposing blocks.
//
// Block Production Flow:
//   1. Slot time arrives (every 400ms)
//   2. Designated proposer (round-robin) creates block
//   3. Block is broadcast via P2P gossip
//   4. Other validators verify and vote
//   5. Block finalized when 2/3 supermajority votes received
//
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

/// A proposed block waiting for votes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedBlock {
    /// Block height/slot number
    pub slot: u64,
    /// Hash of the previous block
    pub parent_hash: String,
    /// Merkle root of transactions
    pub transactions_root: String,
    /// Merkle root of state changes
    pub state_root: String,
    /// Address of the block proposer
    pub proposer: String,
    /// Timestamp when block was created
    pub timestamp: DateTime<Utc>,
    /// Transactions included in this block
    pub transactions: Vec<BlockTransaction>,
    /// Proposer's signature over the block
    pub signature: String,
    /// Block hash (computed)
    pub hash: String,
}

impl ProposedBlock {
    pub fn new(
        slot: u64,
        parent_hash: String,
        proposer: String,
        transactions: Vec<BlockTransaction>,
    ) -> Self {
        let transactions_root = Self::compute_merkle_root(&transactions);
        let timestamp = Utc::now();
        
        let mut block = Self {
            slot,
            parent_hash,
            transactions_root,
            state_root: String::new(), // Computed after execution
            proposer,
            timestamp,
            transactions,
            signature: String::new(),
            hash: String::new(),
        };
        
        block.hash = block.compute_hash();
        block
    }
    
    /// Compute the block hash
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.slot.to_le_bytes());
        hasher.update(&self.parent_hash);
        hasher.update(&self.transactions_root);
        hasher.update(&self.proposer);
        hasher.update(self.timestamp.timestamp_millis().to_le_bytes());
        hex::encode(hasher.finalize())
    }
    
    /// Compute merkle root of transactions
    fn compute_merkle_root(transactions: &[BlockTransaction]) -> String {
        if transactions.is_empty() {
            return "0".repeat(64);
        }
        
        let hashes: Vec<String> = transactions.iter()
            .map(|tx| tx.hash.clone())
            .collect();
        
        Self::merkle_hash(&hashes)
    }
    
    fn merkle_hash(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return "0".repeat(64);
        }
        if hashes.len() == 1 {
            return hashes[0].clone();
        }
        
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]); // Duplicate if odd
            }
            next_level.push(hex::encode(hasher.finalize()));
        }
        
        Self::merkle_hash(&next_level)
    }
    
    /// Verify the block is valid
    pub fn verify(&self, expected_proposer: &str) -> Result<(), String> {
        // Check proposer
        if self.proposer != expected_proposer {
            return Err(format!(
                "Wrong proposer: expected {}, got {}",
                expected_proposer, self.proposer
            ));
        }
        
        // Verify hash
        let computed_hash = self.compute_hash();
        if computed_hash != self.hash {
            return Err("Block hash mismatch".to_string());
        }
        
        // Verify transactions root
        let computed_root = Self::compute_merkle_root(&self.transactions);
        if computed_root != self.transactions_root {
            return Err("Transactions root mismatch".to_string());
        }
        
        // TODO: Verify signature
        
        Ok(())
    }
}

/// A transaction included in a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransaction {
    pub hash: String,
    pub tx_type: TransactionType,
    pub from: String,
    pub to: Option<String>,
    pub amount: Option<f64>,
    pub data: Option<String>,
    pub signature: String,
    pub nonce: u64,
}

/// Types of transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    Transfer,
    StakeDeposit,
    StakeWithdraw,
    ValidatorRegister,
    ValidatorExit,
    MarketCreate,
    MarketBet,
    MarketSettle,
    BridgeDeposit,
    BridgeWithdraw,
    SocialMining,
}

/// A vote on a proposed block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVote {
    /// The block hash being voted on
    pub block_hash: String,
    /// The slot number
    pub slot: u64,
    /// Address of the voter
    pub voter: String,
    /// Whether they approve the block
    pub approve: bool,
    /// Voter's signature
    pub signature: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl BlockVote {
    pub fn new(block_hash: String, slot: u64, voter: String, approve: bool) -> Self {
        Self {
            block_hash,
            slot,
            voter,
            approve,
            signature: String::new(), // TODO: Sign
            timestamp: Utc::now(),
        }
    }
}

/// Status of a block in the proposal pipeline
#[derive(Debug, Clone, PartialEq)]
pub enum BlockStatus {
    /// Block proposed, waiting for votes
    Pending,
    /// Block has 2/3 votes, is finalized
    Finalized,
    /// Block was rejected (timeout or explicit rejection)
    Rejected,
    /// Block was orphaned (different block finalized for same slot)
    Orphaned,
}

/// Tracks voting progress on a block
#[derive(Debug, Clone)]
pub struct BlockVoting {
    pub block: ProposedBlock,
    pub status: BlockStatus,
    pub votes_for: HashSet<String>,
    pub votes_against: HashSet<String>,
    pub created_at: DateTime<Utc>,
}

impl BlockVoting {
    pub fn new(block: ProposedBlock) -> Self {
        Self {
            block,
            status: BlockStatus::Pending,
            votes_for: HashSet::new(),
            votes_against: HashSet::new(),
            created_at: Utc::now(),
        }
    }
    
    /// Add a vote and check if finality is reached
    pub fn add_vote(&mut self, vote: BlockVote, total_validators: usize, threshold: f64) -> bool {
        if vote.block_hash != self.block.hash {
            return false;
        }
        
        if vote.approve {
            self.votes_for.insert(vote.voter);
        } else {
            self.votes_against.insert(vote.voter);
        }
        
        // Check for finality
        let votes_needed = (total_validators as f64 * threshold).ceil() as usize;
        
        if self.votes_for.len() >= votes_needed {
            self.status = BlockStatus::Finalized;
            return true;
        }
        
        // Check for rejection (more than 1/3 against)
        let rejection_threshold = (total_validators as f64 * (1.0 - threshold)).ceil() as usize;
        if self.votes_against.len() > rejection_threshold {
            self.status = BlockStatus::Rejected;
        }
        
        false
    }
}

/// Manages the block proposal and voting process
pub struct BlockProposer {
    /// Block time in milliseconds
    block_time_ms: u64,
    /// Finality threshold (e.g., 0.67 for 2/3)
    finality_threshold: f64,
    /// Current slot
    current_slot: u64,
    /// Last finalized block hash
    last_finalized_hash: String,
    /// Pending blocks waiting for votes
    pending_blocks: HashMap<u64, BlockVoting>,
    /// Finalized blocks (recent history)
    finalized_blocks: Vec<ProposedBlock>,
    /// Maximum finalized blocks to keep in memory
    max_finalized_history: usize,
}

impl BlockProposer {
    pub fn new(block_time_ms: u64, finality_threshold: f64) -> Self {
        Self {
            block_time_ms,
            finality_threshold,
            current_slot: 0,
            last_finalized_hash: "0".repeat(64), // Genesis
            pending_blocks: HashMap::new(),
            finalized_blocks: Vec::new(),
            max_finalized_history: 1000,
        }
    }
    
    /// Create a new block proposal
    pub fn propose_block(
        &mut self,
        proposer: String,
        transactions: Vec<BlockTransaction>,
    ) -> ProposedBlock {
        let slot = self.current_slot;
        let parent_hash = self.last_finalized_hash.clone();
        
        let block = ProposedBlock::new(slot, parent_hash, proposer, transactions);
        
        // Add to pending
        self.pending_blocks.insert(slot, BlockVoting::new(block.clone()));
        
        block
    }
    
    /// Receive a block proposal from another validator
    pub fn receive_block(
        &mut self,
        block: ProposedBlock,
        expected_proposer: &str,
    ) -> Result<(), String> {
        // Verify the block
        block.verify(expected_proposer)?;
        
        // Check slot
        if block.slot != self.current_slot {
            return Err(format!(
                "Block for wrong slot: expected {}, got {}",
                self.current_slot, block.slot
            ));
        }
        
        // Check parent
        if block.parent_hash != self.last_finalized_hash {
            return Err("Block has wrong parent hash".to_string());
        }
        
        // Add to pending if not already there
        if !self.pending_blocks.contains_key(&block.slot) {
            self.pending_blocks.insert(block.slot, BlockVoting::new(block));
        }
        
        Ok(())
    }
    
    /// Vote on a pending block
    pub fn vote_on_block(
        &mut self,
        vote: BlockVote,
        total_validators: usize,
    ) -> Option<ProposedBlock> {
        if let Some(voting) = self.pending_blocks.get_mut(&vote.slot) {
            let finalized = voting.add_vote(vote, total_validators, self.finality_threshold);
            
            if finalized {
                let block = voting.block.clone();
                return Some(block);
            }
        }
        None
    }
    
    /// Finalize a block and advance to next slot
    pub fn finalize_block(&mut self, slot: u64) -> Option<ProposedBlock> {
        if let Some(voting) = self.pending_blocks.remove(&slot) {
            if voting.status == BlockStatus::Finalized {
                let block = voting.block;
                
                // Update state
                self.last_finalized_hash = block.hash.clone();
                self.current_slot = slot + 1;
                
                // Add to history
                self.finalized_blocks.push(block.clone());
                
                // Trim history if needed
                while self.finalized_blocks.len() > self.max_finalized_history {
                    self.finalized_blocks.remove(0);
                }
                
                // Clean up old pending blocks
                self.pending_blocks.retain(|s, _| *s >= slot);
                
                return Some(block);
            }
        }
        None
    }
    
    /// Advance to the next slot (called by timer)
    pub fn advance_slot(&mut self) {
        // Mark pending block for current slot as rejected if not finalized
        if let Some(voting) = self.pending_blocks.get_mut(&self.current_slot) {
            if voting.status == BlockStatus::Pending {
                voting.status = BlockStatus::Rejected;
            }
        }
        
        self.current_slot += 1;
    }
    
    /// Get current slot
    pub fn current_slot(&self) -> u64 {
        self.current_slot
    }
    
    /// Get block time in milliseconds
    pub fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }
    
    /// Get the last finalized block
    pub fn last_finalized(&self) -> Option<&ProposedBlock> {
        self.finalized_blocks.last()
    }
    
    /// Get finalized block by slot
    pub fn get_finalized_block(&self, slot: u64) -> Option<&ProposedBlock> {
        self.finalized_blocks.iter().find(|b| b.slot == slot)
    }
    
    /// Get pending block for slot
    pub fn get_pending_block(&self, slot: u64) -> Option<&BlockVoting> {
        self.pending_blocks.get(&slot)
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> BlockProposerStats {
        BlockProposerStats {
            current_slot: self.current_slot,
            last_finalized_hash: self.last_finalized_hash.clone(),
            pending_blocks: self.pending_blocks.len(),
            finalized_blocks_in_memory: self.finalized_blocks.len(),
            block_time_ms: self.block_time_ms,
            finality_threshold: self.finality_threshold,
        }
    }
}

/// Statistics about block proposal
#[derive(Debug, Clone, Serialize)]
pub struct BlockProposerStats {
    pub current_slot: u64,
    pub last_finalized_hash: String,
    pub pending_blocks: usize,
    pub finalized_blocks_in_memory: usize,
    pub block_time_ms: u64,
    pub finality_threshold: f64,
}

/// Messages broadcast over P2P for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// New block proposed
    BlockProposal(ProposedBlock),
    /// Vote on a block
    Vote(BlockVote),
    /// Request missing block
    RequestBlock { slot: u64 },
    /// Response with missing block
    BlockResponse(ProposedBlock),
    /// Announce finalization
    BlockFinalized { slot: u64, hash: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_block_creation() {
        let block = ProposedBlock::new(
            1,
            "0".repeat(64),
            "alice".to_string(),
            vec![],
        );
        
        assert_eq!(block.slot, 1);
        assert_eq!(block.proposer, "alice");
        assert!(!block.hash.is_empty());
    }
    
    #[test]
    fn test_block_verification() {
        let block = ProposedBlock::new(
            1,
            "0".repeat(64),
            "alice".to_string(),
            vec![],
        );
        
        // Should verify with correct proposer
        assert!(block.verify("alice").is_ok());
        
        // Should fail with wrong proposer
        assert!(block.verify("bob").is_err());
    }
    
    #[test]
    fn test_voting() {
        let block = ProposedBlock::new(
            1,
            "0".repeat(64),
            "alice".to_string(),
            vec![],
        );
        
        let mut voting = BlockVoting::new(block.clone());
        
        // Need 2/3 of 3 validators = 2 votes
        let vote1 = BlockVote::new(block.hash.clone(), 1, "bob".to_string(), true);
        let finalized = voting.add_vote(vote1, 3, 0.67);
        assert!(!finalized);
        
        let vote2 = BlockVote::new(block.hash.clone(), 1, "carol".to_string(), true);
        let finalized = voting.add_vote(vote2, 3, 0.67);
        assert!(finalized);
        
        assert_eq!(voting.status, BlockStatus::Finalized);
    }
    
    #[test]
    fn test_block_proposer() {
        let mut proposer = BlockProposer::new(400, 0.67);
        
        // Propose a block
        let block = proposer.propose_block("alice".to_string(), vec![]);
        assert_eq!(block.slot, 0);
        
        // Vote on it (simulate 3 validators, need 2/3)
        let vote1 = BlockVote::new(block.hash.clone(), 0, "bob".to_string(), true);
        let result = proposer.vote_on_block(vote1, 3);
        assert!(result.is_none()); // Not finalized yet
        
        let vote2 = BlockVote::new(block.hash.clone(), 0, "carol".to_string(), true);
        let result = proposer.vote_on_block(vote2, 3);
        assert!(result.is_some()); // Now finalized
        
        // Finalize
        let finalized = proposer.finalize_block(0);
        assert!(finalized.is_some());
        
        // Should advance to next slot
        assert_eq!(proposer.current_slot(), 1);
    }
}
