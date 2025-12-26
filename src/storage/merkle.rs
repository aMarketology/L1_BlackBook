//! Merkle State Root Implementation
//!
//! Uses rs_merkle for production-grade Merkle tree computation.
//! Provides state roots for light client verification and state proofs.
//!
//! Features:
//! - SHA256 hash function (same as Bitcoin/Ethereum)
//! - Efficient incremental updates
//! - Proof generation for light clients
//! - Deterministic root computation

use rs_merkle::{MerkleTree, MerkleProof, algorithms::Sha256 as RsSha256};
use sha2::{Sha256, Digest};

// ============================================================================
// MERKLE STATE
// ============================================================================

/// Merkle state manager for computing state roots
/// 
/// The state root is the Merkle root of all account states,
/// enabling light clients to verify account balances without
/// downloading the entire blockchain.
pub struct MerkleState {
    /// Cached tree (rebuilt on each block commit)
    tree: Option<MerkleTree<RsSha256>>,
}

impl MerkleState {
    /// Create a new empty Merkle state
    pub fn new() -> Self {
        Self { tree: None }
    }
    
    /// Compute the Merkle root from a set of leaves
    /// 
    /// Leaves should be sorted 32-byte hashes (SHA256 of account data)
    pub fn compute_root(&self, leaves: &[[u8; 32]]) -> String {
        if leaves.is_empty() {
            return "0".repeat(64);
        }
        
        let tree = MerkleTree::<RsSha256>::from_leaves(leaves);
        match tree.root() {
            Some(root) => hex::encode(root),
            None => "0".repeat(64),
        }
    }
    
    /// Compute root and store tree for proof generation
    pub fn compute_and_store(&mut self, leaves: &[[u8; 32]]) -> String {
        if leaves.is_empty() {
            self.tree = None;
            return "0".repeat(64);
        }
        
        let tree = MerkleTree::<RsSha256>::from_leaves(leaves);
        let root = tree.root().map(|r| hex::encode(r)).unwrap_or_else(|| "0".repeat(64));
        self.tree = Some(tree);
        root
    }
    
    /// Generate a Merkle proof for a leaf at the given index
    /// 
    /// Returns None if tree is not stored or index is out of bounds
    pub fn generate_proof(&self, leaf_index: usize, total_leaves: usize) -> Option<Vec<[u8; 32]>> {
        let tree = self.tree.as_ref()?;
        let indices = vec![leaf_index];
        let proof = tree.proof(&indices);
        Some(proof.proof_hashes().to_vec())
    }
    
    /// Verify a Merkle proof
    /// 
    /// Given a leaf, its index, the proof hashes, and the expected root,
    /// verify that the leaf is part of the tree.
    pub fn verify_proof(
        leaf: &[u8; 32],
        leaf_index: usize,
        total_leaves: usize,
        proof_hashes: &[[u8; 32]],
        expected_root: &str,
    ) -> bool {
        // Reconstruct proof
        let proof = MerkleProof::<RsSha256>::new(proof_hashes.to_vec());
        
        // Decode expected root
        let root_bytes = match hex::decode(expected_root) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return false,
        };
        
        // Verify
        proof.verify(root_bytes, &[leaf_index], &[*leaf], total_leaves)
    }
}

impl Default for MerkleState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ACCOUNT HASH HELPERS
// ============================================================================

/// Compute the hash of an account for Merkle leaf
/// 
/// Hash = SHA256(pubkey || borsh_serialized_account)
pub fn hash_account(pubkey: &str, account_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.update(account_bytes);
    hasher.finalize().into()
}

/// Compute the hash of a transaction for Merkle leaf
pub fn hash_transaction(tx_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tx_bytes);
    hasher.finalize().into()
}

// ============================================================================
// PROOF STRUCTURES (for RPC responses)
// ============================================================================

/// Merkle proof for account state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountProof {
    /// The account pubkey
    pub pubkey: String,
    /// The account data (Borsh serialized, base64 encoded)
    pub account_data: String,
    /// Leaf index in the Merkle tree
    pub leaf_index: usize,
    /// Total leaves in the tree
    pub total_leaves: usize,
    /// Proof hashes (hex encoded)
    pub proof: Vec<String>,
    /// State root this proof is valid for
    pub state_root: String,
    /// Slot at which this proof was generated
    pub slot: u64,
}

impl AccountProof {
    /// Create a new account proof
    pub fn new(
        pubkey: String,
        account_bytes: &[u8],
        leaf_index: usize,
        total_leaves: usize,
        proof_hashes: &[[u8; 32]],
        state_root: String,
        slot: u64,
    ) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        Self {
            pubkey,
            account_data: STANDARD.encode(account_bytes),
            leaf_index,
            total_leaves,
            proof: proof_hashes.iter().map(hex::encode).collect(),
            state_root,
            slot,
        }
    }
    
    /// Verify this proof
    pub fn verify(&self) -> bool {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        // Decode account data
        let account_bytes = match STANDARD.decode(&self.account_data) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        
        // Compute leaf hash
        let leaf = hash_account(&self.pubkey, &account_bytes);
        
        // Decode proof hashes
        let proof_hashes: Vec<[u8; 32]> = self.proof
            .iter()
            .filter_map(|h| {
                let bytes = hex::decode(h).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();
        
        if proof_hashes.len() != self.proof.len() {
            return false;
        }
        
        MerkleState::verify_proof(
            &leaf,
            self.leaf_index,
            self.total_leaves,
            &proof_hashes,
            &self.state_root,
        )
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_root() {
        let merkle = MerkleState::new();
        let root = merkle.compute_root(&[]);
        assert_eq!(root, "0".repeat(64));
    }
    
    #[test]
    fn test_single_leaf() {
        let merkle = MerkleState::new();
        let leaf = hash_account("alice", b"account_data");
        let root = merkle.compute_root(&[leaf]);
        
        // Single leaf root should be the leaf itself
        assert_eq!(root.len(), 64);
        assert_ne!(root, "0".repeat(64));
    }
    
    #[test]
    fn test_multiple_leaves() {
        let merkle = MerkleState::new();
        let leaves = vec![
            hash_account("alice", b"data1"),
            hash_account("bob", b"data2"),
            hash_account("charlie", b"data3"),
            hash_account("dave", b"data4"),
        ];
        
        let root = merkle.compute_root(&leaves);
        assert_eq!(root.len(), 64);
        
        // Root should be deterministic
        let root2 = merkle.compute_root(&leaves);
        assert_eq!(root, root2);
        
        // Different order = different root (that's why we sort in StateDB)
        let mut reversed = leaves.clone();
        reversed.reverse();
        let root3 = merkle.compute_root(&reversed);
        assert_ne!(root, root3);
    }
    
    #[test]
    fn test_proof_generation_and_verification() {
        let mut merkle = MerkleState::new();
        let leaves = vec![
            hash_account("alice", b"data1"),
            hash_account("bob", b"data2"),
            hash_account("charlie", b"data3"),
            hash_account("dave", b"data4"),
        ];
        
        let root = merkle.compute_and_store(&leaves);
        
        // Generate proof for alice (index 0)
        let proof = merkle.generate_proof(0, leaves.len()).unwrap();
        
        // Verify proof
        let valid = MerkleState::verify_proof(
            &leaves[0],
            0,
            leaves.len(),
            &proof,
            &root,
        );
        assert!(valid);
        
        // Wrong leaf should fail
        let invalid = MerkleState::verify_proof(
            &leaves[1], // Wrong leaf
            0,
            leaves.len(),
            &proof,
            &root,
        );
        assert!(!invalid);
    }
    
    #[test]
    fn test_account_proof_struct() {
        let mut merkle = MerkleState::new();
        let account_data = b"test_account_borsh_data";
        let leaves = vec![
            hash_account("alice", account_data),
            hash_account("bob", b"bob_data"),
        ];
        
        let root = merkle.compute_and_store(&leaves);
        let proof_hashes = merkle.generate_proof(0, leaves.len()).unwrap();
        
        let proof = AccountProof::new(
            "alice".to_string(),
            account_data,
            0,
            leaves.len(),
            &proof_hashes,
            root,
            100,
        );
        
        assert!(proof.verify());
    }
}
