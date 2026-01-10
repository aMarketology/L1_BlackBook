//! Fork Choice Manager - LMD-GHOST Implementation
//!
//! Implements Latest Message Driven Greediest Heaviest Observed SubTree (LMD-GHOST)
//! fork choice rule weighted by validator engagement scores.
//!
//! Key Properties:
//! - Tracks multiple chain heads (handles forks)
//! - Weights blocks by validator engagement (Proof of Engagement)
//! - Handles chain reorganizations safely
//! - Provides finality after sufficient confirmations

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Minimum confirmations for soft finality
pub const SOFT_FINALITY_CONFIRMATIONS: u64 = 2;
/// Minimum confirmations for hard finality (cannot be reverted)
pub const HARD_FINALITY_CONFIRMATIONS: u64 = 32;
/// Maximum fork depth to track (prune older forks)
pub const MAX_FORK_DEPTH: u64 = 64;

/// Block metadata for fork choice (lightweight, no full transactions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMeta {
    pub hash: String,
    pub parent_hash: String,
    pub slot: u64,
    pub proposer: String,
    pub state_root: String,
    pub weight: u64,           // Cumulative engagement weight
    pub vote_count: u32,       // Votes received
    pub finality: FinalityStatus,
}

/// Finality status of a block
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub enum FinalityStatus {
    #[default]
    Pending,         // Not yet finalized
    SoftFinalized,   // 2+ confirmations, unlikely to revert
    HardFinalized,   // 32+ confirmations, cannot revert
}

/// Fork choice manager implementing LMD-GHOST
pub struct ForkChoiceManager {
    /// All known blocks by hash
    blocks: HashMap<String, BlockMeta>,
    /// Current best chain head
    best_head: String,
    /// Genesis block hash
    genesis_hash: String,
    /// Latest finalized block hash
    finalized_head: String,
    /// Validator votes: validator_address -> (block_hash, slot)
    votes: HashMap<String, (String, u64)>,
    /// Block children: parent_hash -> [child_hashes]
    children: HashMap<String, Vec<String>>,
}

impl ForkChoiceManager {
    /// Create new fork choice manager with genesis block
    pub fn new(genesis_hash: String, genesis_state_root: String) -> Self {
        let genesis = BlockMeta {
            hash: genesis_hash.clone(),
            parent_hash: "0".repeat(64),
            slot: 0,
            proposer: "genesis".to_string(),
            state_root: genesis_state_root,
            weight: 0,
            vote_count: 0,
            finality: FinalityStatus::HardFinalized,
        };
        
        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash.clone(), genesis);
        
        Self {
            blocks,
            best_head: genesis_hash.clone(),
            genesis_hash: genesis_hash.clone(),
            finalized_head: genesis_hash,
            votes: HashMap::new(),
            children: HashMap::new(),
        }
    }
    
    /// Add a new block to the fork choice
    pub fn add_block(&mut self, block: BlockMeta) -> Result<bool, String> {
        // Verify parent exists
        if !self.blocks.contains_key(&block.parent_hash) {
            return Err(format!("Unknown parent: {}", &block.parent_hash[..16]));
        }
        
        // Check for duplicate
        if self.blocks.contains_key(&block.hash) {
            return Ok(false); // Already have this block
        }
        
        let block_hash = block.hash.clone();
        let parent_hash = block.parent_hash.clone();
        
        // Add to blocks
        self.blocks.insert(block_hash.clone(), block);
        
        // Track parent-child relationship
        self.children
            .entry(parent_hash)
            .or_default()
            .push(block_hash.clone());
        
        // Update best head if this is heavier
        self.update_best_head();
        
        // Update finality
        self.update_finality();
        
        Ok(true)
    }
    
    /// Process a validator vote for a block
    pub fn process_vote(&mut self, validator: String, block_hash: String, engagement_weight: u64) {
        // Only accept votes for known blocks
        if !self.blocks.contains_key(&block_hash) {
            return;
        }
        
        // Get current vote slot
        let current_slot = self.blocks.get(&block_hash).map(|b| b.slot).unwrap_or(0);
        
        // Only accept newer votes (LMD = Latest Message Driven)
        if let Some((_, old_slot)) = self.votes.get(&validator) {
            if current_slot <= *old_slot {
                return;
            }
        }
        
        // Update vote
        self.votes.insert(validator, (block_hash.clone(), current_slot));
        
        // Add weight to block and all ancestors
        self.add_weight_to_chain(&block_hash, engagement_weight);
        
        // Update block vote count
        if let Some(block) = self.blocks.get_mut(&block_hash) {
            block.vote_count += 1;
        }
        
        self.update_best_head();
    }
    
    /// Add weight to a block and all its ancestors
    fn add_weight_to_chain(&mut self, block_hash: &str, weight: u64) {
        let mut current = block_hash.to_string();
        
        while let Some(block) = self.blocks.get_mut(&current) {
            block.weight += weight;
            if block.parent_hash == "0".repeat(64) {
                break; // Reached genesis
            }
            current = block.parent_hash.clone();
        }
    }
    
    /// Update best head using GHOST rule
    fn update_best_head(&mut self) {
        let mut current = self.finalized_head.clone();
        
        loop {
            // Get children of current block
            let children = match self.children.get(&current) {
                Some(c) if !c.is_empty() => c.clone(),
                _ => break, // No children, current is best head
            };
            
            // Find heaviest child (GHOST rule)
            let heaviest = children.iter()
                .filter_map(|h| self.blocks.get(h).map(|b| (h, b.weight)))
                .max_by_key(|(_, w)| *w)
                .map(|(h, _)| h.clone());
            
            match heaviest {
                Some(h) => current = h,
                None => break,
            }
        }
        
        self.best_head = current;
    }
    
    /// Update finality status of blocks
    fn update_finality(&mut self) {
        let best_slot = self.blocks.get(&self.best_head)
            .map(|b| b.slot)
            .unwrap_or(0);
        
        // Walk from genesis to best head, updating finality
        let mut current = self.genesis_hash.clone();
        
        loop {
            if let Some(block) = self.blocks.get_mut(&current) {
                let confirmations = best_slot.saturating_sub(block.slot);
                
                if confirmations >= HARD_FINALITY_CONFIRMATIONS {
                    block.finality = FinalityStatus::HardFinalized;
                    self.finalized_head = current.clone();
                } else if confirmations >= SOFT_FINALITY_CONFIRMATIONS {
                    block.finality = FinalityStatus::SoftFinalized;
                }
            }
            
            // Move to next block in best chain
            let next = self.children.get(&current)
                .and_then(|c| c.iter()
                    .find(|h| self.is_ancestor_of(h, &self.best_head))
                    .cloned());
            
            match next {
                Some(h) => current = h,
                None => break,
            }
        }
        
        // Prune old forks
        self.prune_old_forks();
    }
    
    /// Check if block_a is ancestor of block_b
    fn is_ancestor_of(&self, block_a: &str, block_b: &str) -> bool {
        if block_a == block_b {
            return true;
        }
        
        let mut current = block_b.to_string();
        while let Some(block) = self.blocks.get(&current) {
            if block.parent_hash == block_a {
                return true;
            }
            if block.parent_hash == "0".repeat(64) {
                break;
            }
            current = block.parent_hash.clone();
        }
        false
    }
    
    /// Prune blocks that are too old and not in the main chain
    fn prune_old_forks(&mut self) {
        let finalized_slot = self.blocks.get(&self.finalized_head)
            .map(|b| b.slot)
            .unwrap_or(0);
        
        // Collect blocks to remove
        let to_remove: Vec<String> = self.blocks.iter()
            .filter(|(hash, block)| {
                block.slot + MAX_FORK_DEPTH < finalized_slot &&
                !self.is_ancestor_of(hash, &self.best_head)
            })
            .map(|(h, _)| h.clone())
            .collect();
        
        for hash in to_remove {
            self.blocks.remove(&hash);
        }
    }
    
    /// Get the current best head hash
    pub fn best_head(&self) -> &str {
        &self.best_head
    }
    
    /// Get the finalized head hash
    pub fn finalized_head(&self) -> &str {
        &self.finalized_head
    }
    
    /// Get block by hash
    pub fn get_block(&self, hash: &str) -> Option<&BlockMeta> {
        self.blocks.get(hash)
    }
    
    /// Get chain from finalized to best head
    pub fn get_canonical_chain(&self) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = self.best_head.clone();
        
        while current != self.genesis_hash {
            chain.push(current.clone());
            current = match self.blocks.get(&current) {
                Some(b) => b.parent_hash.clone(),
                None => break,
            };
        }
        chain.push(self.genesis_hash.clone());
        chain.reverse();
        chain
    }
    
    /// Check if a block is finalized
    pub fn is_finalized(&self, hash: &str) -> bool {
        self.blocks.get(hash)
            .map(|b| b.finality == FinalityStatus::HardFinalized)
            .unwrap_or(false)
    }
    
    /// Get fork choice stats
    pub fn stats(&self) -> ForkChoiceStats {
        let finalized_slot = self.blocks.get(&self.finalized_head)
            .map(|b| b.slot)
            .unwrap_or(0);
        let best_slot = self.blocks.get(&self.best_head)
            .map(|b| b.slot)
            .unwrap_or(0);
        
        ForkChoiceStats {
            total_blocks: self.blocks.len(),
            best_head: self.best_head.clone(),
            best_slot,
            finalized_head: self.finalized_head.clone(),
            finalized_slot,
            active_validators: self.votes.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ForkChoiceStats {
    pub total_blocks: usize,
    pub best_head: String,
    pub best_slot: u64,
    pub finalized_head: String,
    pub finalized_slot: u64,
    pub active_validators: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fork_choice_basic() {
        let mut fc = ForkChoiceManager::new(
            "genesis".to_string(),
            "state0".to_string()
        );
        
        // Add block 1
        let block1 = BlockMeta {
            hash: "block1".to_string(),
            parent_hash: "genesis".to_string(),
            slot: 1,
            proposer: "validator1".to_string(),
            state_root: "state1".to_string(),
            weight: 0,
            vote_count: 0,
            finality: FinalityStatus::Pending,
        };
        
        assert!(fc.add_block(block1).unwrap());
        assert_eq!(fc.best_head(), "block1");
    }
    
    #[test]
    fn test_fork_choice_with_votes() {
        let mut fc = ForkChoiceManager::new(
            "genesis".to_string(),
            "state0".to_string()
        );
        
        // Add two competing blocks at slot 1
        let block1a = BlockMeta {
            hash: "block1a".to_string(),
            parent_hash: "genesis".to_string(),
            slot: 1,
            proposer: "v1".to_string(),
            state_root: "state1a".to_string(),
            weight: 0,
            vote_count: 0,
            finality: FinalityStatus::Pending,
        };
        
        let block1b = BlockMeta {
            hash: "block1b".to_string(),
            parent_hash: "genesis".to_string(),
            slot: 1,
            proposer: "v2".to_string(),
            state_root: "state1b".to_string(),
            weight: 0,
            vote_count: 0,
            finality: FinalityStatus::Pending,
        };
        
        fc.add_block(block1a).unwrap();
        fc.add_block(block1b).unwrap();
        
        // Vote for block1b with higher weight
        fc.process_vote("voter1".to_string(), "block1b".to_string(), 100);
        fc.process_vote("voter2".to_string(), "block1b".to_string(), 50);
        fc.process_vote("voter3".to_string(), "block1a".to_string(), 30);
        
        // block1b should win (weight 150 vs 30)
        assert_eq!(fc.best_head(), "block1b");
    }
}
