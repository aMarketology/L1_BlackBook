// ============================================================================
// PROOF OF RESERVES (PoR) - MERKLE TREE ARCHITECTURE
// ============================================================================
//
// WHAT THIS DOES:
// Allows users to verify that their $BB balance is included in the total
// reserve count without revealing their private data or other users' data.
//
// HOW IT WORKS:
// 1. Every block interval (600ms), we snapshot all account balances
// 2. Build a Merkle Tree from sorted (address, balance) pairs
// 3. Publish the Merkle Root (32-byte hash representing ALL balances)
// 4. Users can request a "proof" - the minimal path to prove inclusion
// 5. Anyone can verify the proof without needing the full balance sheet
//
// ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────────┐
// │                    PROOF OF RESERVES SYSTEM                         │
// ├─────────────────────────────────────────────────────────────────────┤
// │                                                                     │
// │   Accounts: [                                                       │
// │     (addr1, 1000 BB),                                               │
// │     (addr2, 5000 BB),       ──▶  Sort by Address                   │
// │     (addr3, 2500 BB),                 │                            │
// │     ...                               ▼                            │
// │   ]                          Hash each leaf                         │
// │                                       │                            │
// │                    ┌─────────────────┴─────────────────┐           │
// │                    ▼                                   ▼           │
// │            Hash(Hash1+Hash2)                   Hash(Hash3+Hash4)   │
// │                    │                                   │           │
// │                    └─────────────────┬─────────────────┘           │
// │                                      ▼                             │
// │                             MERKLE ROOT (PoR)                      │
// │                          [Published Publicly]                      │
// │                                                                     │
// │   User Request: "Prove my balance is included"                     │
// │                                      │                             │
// │                                      ▼                             │
// │            Return: [Sibling hashes along the path]                 │
// │                                      │                             │
// │                                      ▼                             │
// │            User verifies locally: Path → Root ✓                    │
// └─────────────────────────────────────────────────────────────────────┘
//
// PRIVACY:
// - User only learns their own balance path (not other users' balances)
// - Verifier only learns that balance was included (not the actual amount)
// - Optional: Hash balance with salt to hide amount in public proofs
//
// ============================================================================

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::{info, debug, warn};

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

/// A leaf in the Merkle Tree (one account balance)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountLeaf {
    /// Account address (wallet public key)
    pub address: String,
    /// Balance in $BB (6 decimals: 1000000 = 1 BB)
    pub balance: u64,
    /// Optional: Salt for privacy (hash includes this to hide balance)
    pub salt: Option<String>,
}

impl AccountLeaf {
    /// Create a new account leaf
    pub fn new(address: String, balance: u64) -> Self {
        Self {
            address,
            balance,
            salt: None,
        }
    }

    /// Create a new account leaf with privacy salt
    pub fn new_with_salt(address: String, balance: u64, salt: String) -> Self {
        Self {
            address,
            balance,
            salt: Some(salt),
        }
    }

    /// Hash this leaf (format: hash(address|balance|salt))
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.address.as_bytes());
        hasher.update(b"|");
        hasher.update(self.balance.to_le_bytes());
        if let Some(ref salt) = self.salt {
            hasher.update(b"|");
            hasher.update(salt.as_bytes());
        }
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// A Merkle Proof - the path from a leaf to the root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf being proven
    pub leaf: AccountLeaf,
    /// The sibling hashes along the path to root (bottom to top)
    pub siblings: Vec<MerkleNode>,
    /// The Merkle root this proof leads to
    pub root: String,
    /// Snapshot timestamp (which PoR snapshot this proves)
    pub snapshot_timestamp: u64,
    /// Total number of accounts in this snapshot
    pub total_accounts: usize,
    /// Total $BB in reserves at this snapshot
    pub total_reserves: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of this node
    pub hash: String,
    /// Is this sibling on the left (true) or right (false)?
    pub is_left: bool,
}

impl MerkleProof {
    /// Verify this proof is valid
    pub fn verify(&self) -> bool {
        let mut current_hash = self.leaf.hash();
        
        // Walk up the tree, combining with siblings
        for sibling in &self.siblings {
            current_hash = if sibling.is_left {
                // Sibling is on the left, we're on the right
                hash_pair(&sibling.hash, &current_hash)
            } else {
                // Sibling is on the right, we're on the left
                hash_pair(&current_hash, &sibling.hash)
            };
        }
        
        // Final hash should match the root
        current_hash == self.root
    }
}

/// A Proof of Reserves snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRSnapshot {
    /// Snapshot ID (block height or timestamp)
    pub snapshot_id: u64,
    /// Timestamp when snapshot was taken
    pub timestamp: u64,
    /// The Merkle root representing all balances
    pub merkle_root: String,
    /// Total number of accounts
    pub total_accounts: usize,
    /// Total $BB in reserves (sum of all balances)
    pub total_reserves: u64,
    /// Total USDT backing (should be total_reserves / 10)
    pub total_usdt_backing: u64,
    /// Total USDC SPL token supply on BlackBook L1
    pub usdc_spl_supply: u64,
    /// Number of USDC token accounts (ATAs)
    pub usdc_token_accounts: usize,
    /// The full Merkle tree (stored for proof generation)
    #[serde(skip)]
    pub tree: Option<MerkleTree>,
}

impl PoRSnapshot {
    /// Get a proof for a specific account
    pub fn get_proof(&self, address: &str) -> Option<MerkleProof> {
        self.tree.as_ref()?.get_proof(address).map(|mut proof| {
            proof.snapshot_timestamp = self.timestamp;
            proof.total_accounts = self.total_accounts;
            proof.total_reserves = self.total_reserves;
            proof
        })
    }

    /// Verify the invariant: total_usdt_backing * 10 = total_reserves
    pub fn verify_backing_ratio(&self) -> bool {
        self.total_usdt_backing * 10 == self.total_reserves
    }
}

// ============================================================================
// MERKLE TREE IMPLEMENTATION
// ============================================================================

/// A Merkle Tree for Proof of Reserves
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The sorted leaves (account, balance pairs)
    leaves: Vec<AccountLeaf>,
    /// The tree structure (level 0 = leaves, last level = root)
    levels: Vec<Vec<String>>,
    /// Map from address to leaf index (for fast lookup)
    leaf_index: HashMap<String, usize>,
}

impl MerkleTree {
    /// Build a new Merkle Tree from account balances
    pub fn new(mut leaves: Vec<AccountLeaf>) -> Self {
        // Sort leaves by address for deterministic ordering
        leaves.sort_by(|a, b| a.address.cmp(&b.address));
        
        // Build index for fast lookups
        let leaf_index: HashMap<String, usize> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| (leaf.address.clone(), i))
            .collect();
        
        // Level 0: Hash all leaves
        let mut levels: Vec<Vec<String>> = vec![
            leaves.iter().map(|leaf| leaf.hash()).collect()
        ];
        
        // Build tree bottom-up
        let mut current_level = 0;
        while levels[current_level].len() > 1 {
            let prev_level = &levels[current_level];
            let mut next_level = Vec::new();
            
            // Pair up hashes and combine them
            for i in (0..prev_level.len()).step_by(2) {
                if i + 1 < prev_level.len() {
                    // We have a pair
                    let combined = hash_pair(&prev_level[i], &prev_level[i + 1]);
                    next_level.push(combined);
                } else {
                    // Odd one out - promote to next level
                    next_level.push(prev_level[i].clone());
                }
            }
            
            levels.push(next_level);
            current_level += 1;
        }
        
        Self {
            leaves,
            levels,
            leaf_index,
        }
    }

    /// Get the Merkle root
    pub fn root(&self) -> String {
        self.levels.last()
            .and_then(|level| level.first())
            .cloned()
            .unwrap_or_else(|| "EMPTY_TREE".to_string())
    }

    /// Get the total number of accounts
    pub fn total_accounts(&self) -> usize {
        self.leaves.len()
    }

    /// Get the total reserves (sum of all balances)
    pub fn total_reserves(&self) -> u64 {
        self.leaves.iter().map(|leaf| leaf.balance).sum()
    }

    /// Generate a proof for a specific account
    pub fn get_proof(&self, address: &str) -> Option<MerkleProof> {
        // Find the leaf index
        let leaf_idx = *self.leaf_index.get(address)?;
        let leaf = self.leaves.get(leaf_idx)?.clone();
        
        let mut siblings = Vec::new();
        let mut current_idx = leaf_idx;
        
        // Walk up the tree, collecting siblings
        for level_num in 0..self.levels.len() - 1 {
            let level = &self.levels[level_num];
            
            // Find sibling
            let sibling_idx = if current_idx % 2 == 0 {
                // We're on the left, sibling is on the right
                if current_idx + 1 < level.len() {
                    Some((current_idx + 1, false)) // (index, is_left)
                } else {
                    None // No sibling (we're promoted alone)
                }
            } else {
                // We're on the right, sibling is on the left
                Some((current_idx - 1, true))
            };
            
            if let Some((sib_idx, is_left)) = sibling_idx {
                siblings.push(MerkleNode {
                    hash: level[sib_idx].clone(),
                    is_left,
                });
            }
            
            // Move to parent index in next level
            current_idx /= 2;
        }
        
        Some(MerkleProof {
            leaf,
            siblings,
            root: self.root(),
            snapshot_timestamp: 0, // Will be set by PoRSnapshot
            total_accounts: self.total_accounts(),
            total_reserves: self.total_reserves(),
        })
    }

    /// Get all leaves (for debugging)
    pub fn leaves(&self) -> &[AccountLeaf] {
        &self.leaves
    }
}

// ============================================================================
// PROOF OF RESERVES MANAGER
// ============================================================================

/// Manages Proof of Reserves snapshots
pub struct PoRManager {
    /// Current snapshot
    current_snapshot: Option<PoRSnapshot>,
    /// Historical snapshots (snapshot_id -> snapshot)
    history: HashMap<u64, PoRSnapshot>,
    /// Maximum number of snapshots to keep in memory
    max_history: usize,
}

impl PoRManager {
    /// Create a new PoR Manager
    pub fn new(max_history: usize) -> Self {
        Self {
            current_snapshot: None,
            history: HashMap::new(),
            max_history,
        }
    }

    /// Take a new snapshot of all account balances
    pub fn take_snapshot(
        &mut self,
        snapshot_id: u64,
        timestamp: u64,
        balances: HashMap<String, u64>,
        total_usdt_backing: u64,
    ) -> PoRSnapshot {
        self.take_snapshot_with_usdc(snapshot_id, timestamp, balances, total_usdt_backing, 0, 0)
    }

    /// Take a new snapshot including USDC SPL token reserve data.
    ///
    /// `usdc_spl_supply` — total USDC supply from the SPL Token mint
    /// `usdc_token_accounts` — number of ATAs holding USDC
    pub fn take_snapshot_with_usdc(
        &mut self,
        snapshot_id: u64,
        timestamp: u64,
        balances: HashMap<String, u64>,
        total_usdt_backing: u64,
        usdc_spl_supply: u64,
        usdc_token_accounts: usize,
    ) -> PoRSnapshot {
        // Convert balances to leaves
        let leaves: Vec<AccountLeaf> = balances
            .into_iter()
            .map(|(address, balance)| AccountLeaf::new(address, balance))
            .collect();
        
        if leaves.is_empty() {
            warn!("Taking PoR snapshot with zero accounts");
        }
        
        // Build Merkle tree
        let tree = MerkleTree::new(leaves);
        let merkle_root = tree.root();
        let total_accounts = tree.total_accounts();
        let total_reserves = tree.total_reserves();
        
        info!(
            "PoR Snapshot #{}: root={}, accounts={}, total_bb={}, usdt_backing={}",
            snapshot_id,
            &merkle_root[..16],
            total_accounts,
            total_reserves,
            total_usdt_backing
        );
        
        let snapshot = PoRSnapshot {
            snapshot_id,
            timestamp,
            merkle_root,
            total_accounts,
            total_reserves,
            total_usdt_backing,
            usdc_spl_supply,
            usdc_token_accounts,
            tree: Some(tree),
        };
        
        // Verify backing ratio
        if !snapshot.verify_backing_ratio() {
            warn!(
                "⚠️  PoR INVARIANT VIOLATION: USDT backing mismatch! \
                 Expected: {} USDT (reserves/10), Got: {} USDT",
                total_reserves / 10,
                total_usdt_backing
            );
        }
        
        // Store in history
        self.current_snapshot = Some(snapshot.clone());
        self.history.insert(snapshot_id, snapshot.clone());
        
        // Prune old history if needed
        if self.history.len() > self.max_history {
            let oldest_id = *self.history.keys().min().unwrap();
            self.history.remove(&oldest_id);
            debug!("Pruned old PoR snapshot #{}", oldest_id);
        }
        
        snapshot
    }

    /// Get the current snapshot
    pub fn current_snapshot(&self) -> Option<&PoRSnapshot> {
        self.current_snapshot.as_ref()
    }

    /// Get a specific snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: u64) -> Option<&PoRSnapshot> {
        self.history.get(&snapshot_id)
    }

    /// Get a proof for an account in the current snapshot
    pub fn get_current_proof(&self, address: &str) -> Option<MerkleProof> {
        self.current_snapshot.as_ref()?.get_proof(address)
    }

    /// Get a proof for an account in a specific snapshot
    pub fn get_historical_proof(&self, snapshot_id: u64, address: &str) -> Option<MerkleProof> {
        self.get_snapshot(snapshot_id)?.get_proof(address)
    }

    /// Get all snapshot IDs
    pub fn list_snapshots(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.history.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Hash two values together (order matters!)
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(b"|");
    hasher.update(right.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_leaf_hashing() {
        let leaf = AccountLeaf::new("addr1".to_string(), 1000000);
        let hash1 = leaf.hash();
        let hash2 = leaf.hash();
        assert_eq!(hash1, hash2, "Hashing should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA256 hash should be 64 hex chars");
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![AccountLeaf::new("addr1".to_string(), 1000000)];
        let tree = MerkleTree::new(leaves);
        assert_eq!(tree.total_accounts(), 1);
        assert_eq!(tree.total_reserves(), 1000000);
        assert!(!tree.root().is_empty());
    }

    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let leaves = vec![
            AccountLeaf::new("addr1".to_string(), 1000000),
            AccountLeaf::new("addr2".to_string(), 2000000),
            AccountLeaf::new("addr3".to_string(), 3000000),
        ];
        let tree = MerkleTree::new(leaves);
        assert_eq!(tree.total_accounts(), 3);
        assert_eq!(tree.total_reserves(), 6000000);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let leaves = vec![
            AccountLeaf::new("addr1".to_string(), 1000000),
            AccountLeaf::new("addr2".to_string(), 2000000),
            AccountLeaf::new("addr3".to_string(), 3000000),
            AccountLeaf::new("addr4".to_string(), 4000000),
        ];
        let tree = MerkleTree::new(leaves);
        
        // Get proof for addr2
        let proof = tree.get_proof("addr2").expect("Should have proof");
        assert_eq!(proof.leaf.address, "addr2");
        assert_eq!(proof.leaf.balance, 2000000);
        assert_eq!(proof.root, tree.root());
        
        // Verify the proof
        assert!(proof.verify(), "Proof should verify");
    }

    #[test]
    fn test_merkle_proof_all_accounts() {
        let leaves = vec![
            AccountLeaf::new("addr1".to_string(), 1000000),
            AccountLeaf::new("addr2".to_string(), 2000000),
            AccountLeaf::new("addr3".to_string(), 3000000),
        ];
        let tree = MerkleTree::new(leaves);
        
        // Every account should have a valid proof
        for addr in &["addr1", "addr2", "addr3"] {
            let proof = tree.get_proof(addr).expect("Should have proof");
            assert!(proof.verify(), "Proof for {} should verify", addr);
        }
    }

    #[test]
    fn test_por_manager() {
        let mut manager = PoRManager::new(10);
        
        let mut balances = HashMap::new();
        balances.insert("addr1".to_string(), 1000000);
        balances.insert("addr2".to_string(), 2000000);
        
        let snapshot = manager.take_snapshot(1, 1000, balances, 300000);
        assert_eq!(snapshot.total_accounts, 2);
        assert_eq!(snapshot.total_reserves, 3000000);
        assert!(snapshot.verify_backing_ratio());
        
        // Get proof from current snapshot
        let proof = manager.get_current_proof("addr1").expect("Should have proof");
        assert!(proof.verify());
    }

    #[test]
    fn test_por_backing_ratio() {
        let mut manager = PoRManager::new(10);
        
        let mut balances = HashMap::new();
        balances.insert("addr1".to_string(), 10000000); // 10 BB
        
        // Correct ratio: 10 BB needs 1 USDT backing (1000000 = 1.0 USDT in 6 decimals)
        let snapshot = manager.take_snapshot(1, 1000, balances, 1000000);
        assert!(snapshot.verify_backing_ratio());
        
        // Wrong ratio
        let mut balances2 = HashMap::new();
        balances2.insert("addr1".to_string(), 10000000);
        let snapshot2 = manager.take_snapshot(2, 2000, balances2, 500000); // Wrong backing
        assert!(!snapshot2.verify_backing_ratio());
    }
}
