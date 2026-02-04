//! Merkle Tree Implementation for Batch Settlements
//!
//! Allows L2 to submit a single merkle root representing 100+ payouts,
//! and users can claim their winnings by providing a merkle proof.

use rs_merkle::{MerkleTree as RsMerkleTree, MerkleProof as RsMerkleProof, Hasher};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Custom hasher for our merkle trees (SHA-256)
#[derive(Clone)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Merkle tree wrapper
pub struct MerkleTree {
    inner: RsMerkleTree<Sha256Hasher>,
}

/// Merkle proof for a single withdrawal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hashes along the path from leaf to root
    pub proof_hashes: Vec<String>,
    /// Indices for proof verification
    pub proof_indices: Vec<usize>,
    /// Leaf index in the tree
    pub leaf_index: usize,
}

/// Payout leaf - what gets hashed into the merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutLeaf {
    pub address: String,
    pub amount: u64,  // Amount in smallest unit (e.g., satoshis)
}

impl PayoutLeaf {
    /// Create canonical bytes for hashing
    /// Format: address|amount
    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{}|{}", self.address, self.amount).into_bytes()
    }
    
    /// Compute the hash of this payout (the merkle leaf)
    pub fn hash(&self) -> [u8; 32] {
        Sha256Hasher::hash(&self.to_bytes())
    }
}

impl MerkleTree {
    /// Create a merkle tree from a list of payouts
    pub fn new(payouts: &[PayoutLeaf]) -> Self {
        let leaves: Vec<[u8; 32]> = payouts.iter().map(|p| p.hash()).collect();
        let inner = RsMerkleTree::<Sha256Hasher>::from_leaves(&leaves);
        Self { inner }
    }
    
    /// Get the merkle root as hex string
    pub fn root_hex(&self) -> String {
        self.inner
            .root()
            .map(|root| hex::encode(root))
            .unwrap_or_else(|| "0".repeat(64))
    }
    
    /// Get the merkle root as bytes
    pub fn root(&self) -> Option<[u8; 32]> {
        self.inner.root()
    }
    
    /// Generate a proof for a specific payout
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        let indices = vec![leaf_index];
        let proof = self.inner.proof(&indices);
        
        let proof_hashes: Vec<String> = proof
            .proof_hashes()
            .iter()
            .map(|hash| hex::encode(hash))
            .collect();
        
        // Note: rs_merkle doesn't expose proof_indices directly
        // We store the leaf index and reconstruct indices during verification
        let proof_indices: Vec<usize> = (0..proof_hashes.len()).collect();
            
        Some(MerkleProof {
            proof_hashes,
            proof_indices,
            leaf_index,
        })
    }
}

/// Create a merkle tree from payouts (convenience function)
pub fn create_merkle_tree(payouts: &[PayoutLeaf]) -> MerkleTree {
    MerkleTree::new(payouts)
}

/// Verify a merkle proof
pub fn verify_merkle_proof(
    payout: &PayoutLeaf,
    proof: &MerkleProof,
    root_hex: &str,
) -> bool {
    // Parse root from hex
    let root_bytes = match hex::decode(root_hex) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return false;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        Err(_) => return false,
    };
    
    // Parse proof hashes from hex
    let proof_hashes: Vec<[u8; 32]> = proof
        .proof_hashes
        .iter()
        .filter_map(|h| {
            hex::decode(h).ok().and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
        })
        .collect();
    
    if proof_hashes.len() != proof.proof_hashes.len() {
        return false; // Failed to parse all hashes
    }
    
    // Create Rs_MerkleProof
    let rs_proof = RsMerkleProof::<Sha256Hasher>::new(proof_hashes);
    
    // Verify using rs_merkle's verify method
    let leaf_hash = payout.hash();
    let indices = vec![proof.leaf_index];
    let leaves_to_prove = vec![leaf_hash];
    
    // Note: The total_leaves_count parameter is calculated from proof depth
    // depth = proof_hashes.len()
    // total_leaves = 2^depth (for a complete tree) or use actual leaf count
    // For safety, we calculate based on depth
    let depth = proof.proof_hashes.len();
    
    rs_proof.verify(
        root_bytes,
        &indices,
        &leaves_to_prove,
        depth + 1, // total leaves count approximation
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payout_leaf_hash() {
        let payout = PayoutLeaf {
            address: "bb_alice123".to_string(),
            amount: 100_000_000, // 100 BB
        };
        
        let hash = payout.hash();
        assert_eq!(hash.len(), 32);
        
        // Same payout should produce same hash
        let payout2 = PayoutLeaf {
            address: "bb_alice123".to_string(),
            amount: 100_000_000,
        };
        assert_eq!(hash, payout2.hash());
    }

    #[test]
    fn test_merkle_tree_single_payout() {
        let payouts = vec![PayoutLeaf {
            address: "bb_user1".to_string(),
            amount: 500_000_000,
        }];
        
        let tree = create_merkle_tree(&payouts);
        let root = tree.root_hex();
        
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars
        assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_merkle_tree_multiple_payouts() {
        let payouts = vec![
            PayoutLeaf { address: "bb_alice".to_string(), amount: 1000 },
            PayoutLeaf { address: "bb_bob".to_string(), amount: 2000 },
            PayoutLeaf { address: "bb_charlie".to_string(), amount: 3000 },
        ];
        
        let tree = create_merkle_tree(&payouts);
        let root = tree.root_hex();
        
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let payouts = vec![
            PayoutLeaf { address: "bb_winner1".to_string(), amount: 100_000_000 },
            PayoutLeaf { address: "bb_winner2".to_string(), amount: 200_000_000 },
            PayoutLeaf { address: "bb_winner3".to_string(), amount: 150_000_000 },
            PayoutLeaf { address: "bb_winner4".to_string(), amount: 50_000_000 },
        ];
        
        let tree = create_merkle_tree(&payouts);
        let root = tree.root_hex();
        
        // Generate proof for winner2 (index 1)
        let proof = tree.generate_proof(1).expect("Should generate proof");
        
        // Verify the proof
        let is_valid = verify_merkle_proof(&payouts[1], &proof, &root);
        assert!(is_valid, "Proof should be valid");
        
        // Verify that wrong payout fails verification
        let wrong_payout = PayoutLeaf {
            address: "bb_attacker".to_string(),
            amount: 999_999_999,
        };
        let is_invalid = verify_merkle_proof(&wrong_payout, &proof, &root);
        assert!(!is_invalid, "Wrong payout should fail verification");
    }

    #[test]
    fn test_large_batch() {
        // Test with 100 winners
        let mut payouts = Vec::new();
        for i in 0..100 {
            payouts.push(PayoutLeaf {
                address: format!("bb_winner{}", i),
                amount: (i as u64 + 1) * 1_000_000,
            });
        }
        
        let tree = create_merkle_tree(&payouts);
        let root = tree.root_hex();
        
        // Verify proof for winner #50
        let proof = tree.generate_proof(50).expect("Should generate proof");
        let is_valid = verify_merkle_proof(&payouts[50], &proof, &root);
        assert!(is_valid, "Proof for winner #50 should be valid");
        
        // Verify proof for first winner
        let proof0 = tree.generate_proof(0).expect("Should generate proof");
        let is_valid0 = verify_merkle_proof(&payouts[0], &proof0, &root);
        assert!(is_valid0, "Proof for winner #0 should be valid");
        
        // Verify proof for last winner
        let proof99 = tree.generate_proof(99).expect("Should generate proof");
        let is_valid99 = verify_merkle_proof(&payouts[99], &proof99, &root);
        assert!(is_valid99, "Proof for winner #99 should be valid");
    }

    #[test]
    fn test_invalid_proof() {
        let payouts = vec![
            PayoutLeaf { address: "bb_user1".to_string(), amount: 100 },
            PayoutLeaf { address: "bb_user2".to_string(), amount: 200 },
        ];
        
        let tree = create_merkle_tree(&payouts);
        let root = tree.root_hex();
        
        // Create fake proof
        let fake_proof = MerkleProof {
            proof_hashes: vec!["0".repeat(64)],
            proof_indices: vec![0],
            leaf_index: 0,
        };
        
        let is_valid = verify_merkle_proof(&payouts[0], &fake_proof, &root);
        assert!(!is_valid, "Fake proof should fail");
    }

    #[test]
    fn test_wrong_root() {
        let payouts = vec![
            PayoutLeaf { address: "bb_user1".to_string(), amount: 100 },
        ];
        
        let tree = create_merkle_tree(&payouts);
        let proof = tree.generate_proof(0).unwrap();
        
        // Use wrong root
        let wrong_root = "a".repeat(64);
        let is_valid = verify_merkle_proof(&payouts[0], &proof, &wrong_root);
        assert!(!is_valid, "Proof with wrong root should fail");
    }
}
