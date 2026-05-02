//! PoH-Integrated Blockchain - Production-Ready Block Production
//!
//! This module integrates Proof of History with the blockchain for:
//! - Deterministic transaction ordering via PoH timestamps
//! - Verifiable block production with merkle state roots
//! - Leader schedule rotation
//! - Transaction finality tracking
//! - Turbine-style data propagation via shreds
//!
//! Architecture:
//! ```text
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
//! │                                         │                              │
//! │                                         ▼                              │
//! │                                     Turbine                            │
//! │                                    (shredding)                         │
//! │                                         │                              │
//! │                              ┌─────────┴─────────┐                     │
//! │                              ▼                   ▼                     │
//! │                         Validator 1         Validator 2                │
//! │                          │     │             │     │                   │
//! │                          ▼     ▼             ▼     ▼                   │
//! │                        V3    V4            V5    V6  (tree propagation)│
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use tracing::error;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};
use borsh::{BorshSerialize, BorshDeserialize};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::storage::ConcurrentBlockchain;
use crate::runtime::{
    SharedPoHService, PoHEntry, LeaderSchedule,
    CONFIRMATIONS_REQUIRED, ConfirmationStatus,
};
use crate::protocol::{Transaction, TxData};
use crate::svm::runtime::BlackBookSVM;
use solana_sdk::{hash::Hash as SvmHash, pubkey::Pubkey};

// ============================================================================
// CONSTANTS - TUNED FOR HIGH THROUGHPUT (125K TPS TARGET)
// ============================================================================

/// Maximum transactions per block
/// TUNED: 240,000 txs/block at 400ms slots = 600,000 TPS theoretical max
pub const MAX_TXS_PER_BLOCK: usize = 240_000;

/// Block production interval in milliseconds
/// NOTE: The authoritative slot duration is POH_SLOT_DURATION_MS in main.rs.
/// Set to 400ms for high-throughput production mode.
#[allow(dead_code)] // Used by main_v4 and future scheduling
pub const BLOCK_INTERVAL_MS: u64 = 400;

/// Shred size in bytes (Turbine-style propagation)
/// Optimal for UDP MTU (1232 bytes after headers)
pub const SHRED_SIZE: usize = 1232;

/// Number of data shreds before a coding shred (Reed-Solomon erasure coding)
/// 32 data + 32 coding = 50% redundancy (can lose half and recover)
pub const DATA_SHREDS_PER_FEC_SET: usize = 32;

/// Maximum fanout per propagation level (tree branching factor)
/// Leader sends to 200 nodes, each sends to 200 more = 40,000 nodes in 2 hops
pub const TURBINE_FANOUT: usize = 200;

// ============================================================================
// TURBINE - BLOCK DATA PROPAGATION VIA SHREDS
// ============================================================================

/// A shred is a small piece of a block for efficient network propagation.
/// Inspired by Solana's Turbine protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shred {
    /// Slot this shred belongs to
    pub slot: u64,
    /// Index within the slot (0, 1, 2, ...)
    pub index: u32,
    /// Total number of shreds in this slot
    pub total_shreds: u32,
    /// Is this a data shred or coding (FEC) shred?
    pub is_coding: bool,
    /// FEC set index (for erasure coding recovery)
    pub fec_set_index: u32,
    /// The shred payload data
    pub data: Vec<u8>,
    /// Merkle proof for this shred (allows verification without full block)
    pub merkle_proof: Vec<String>,
    /// Leader signature over (slot, index, data_hash)
    pub signature: String,
}

impl Shred {
    /// Compute the hash of this shred's data
    #[allow(dead_code)] // Wired in Phase 5+ (P2P Turbine)
    pub fn data_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.slot.to_le_bytes());
        hasher.update(self.index.to_le_bytes());
        hasher.update(&self.data);
        format!("{:x}", hasher.finalize())
    }
    
    /// Verify the shred's integrity
    #[allow(dead_code)] // Wired in Phase 5+ (P2P Turbine)
    pub fn verify(&self, _expected_leader: &str) -> bool {
        // In production, verify Ed25519 signature
        // For now, check signature format
        !self.signature.is_empty() && self.data.len() <= SHRED_SIZE
    }
}

/// Turbine shredder - breaks blocks into shreds for propagation
pub struct TurbineShredder {
    /// Current slot being shredded
    slot: u64,
    /// Leader identity for signing
    leader: String,
}

impl TurbineShredder {
    pub fn new(slot: u64, leader: String) -> Self {
        Self { slot, leader }
    }
    
    /// Shred a finalized block into propagatable pieces
    pub fn shred_block(&self, block: &FinalizedBlock) -> Vec<Shred> {
        // Serialize using Borsh (50-80% smaller than JSON)
        let block_data = borsh::to_vec(block).unwrap_or_default();
        // Prefix with 4-byte big-endian payload length so RS padding can be
        // stripped cleanly on reassembly without re-serialising.
        let mut framed = (block_data.len() as u32).to_be_bytes().to_vec();
        framed.extend(block_data);
        let block_data = framed;

        // Split into shred-sized chunks
        let mut shreds = Vec::new();
        let chunks: Vec<&[u8]> = block_data.chunks(SHRED_SIZE).collect();
        let total_shreds = chunks.len() as u32;
        
        for (index, chunk) in chunks.iter().enumerate() {
            let shred = Shred {
                slot: self.slot,
                index: index as u32,
                total_shreds,
                is_coding: false,
                fec_set_index: (index / DATA_SHREDS_PER_FEC_SET) as u32,
                data: chunk.to_vec(),
                merkle_proof: vec![], // Simplified - full impl would have proof
                signature: format!("sig_{}_{}", self.leader, index),
            };
            shreds.push(shred);
        }
        
        // Add FEC coding shreds for recovery (simplified - real impl uses Reed-Solomon)
        let coding_shreds = self.generate_coding_shreds(&shreds);
        shreds.extend(coding_shreds);
        
        info!(
            "🌊 Turbine: Shredded block {} into {} data + {} coding shreds",
            self.slot,
            total_shreds,
            shreds.len() - total_shreds as usize
        );
        
        shreds
    }
    
    /// Generate Reed-Solomon coding shreds for Forward Error Correction.
    ///
    /// Uses GF(2^8) polynomial arithmetic via the `reed-solomon-erasure` crate.
    /// Each FEC set of `DATA_SHREDS_PER_FEC_SET` (32) data shreds produces an equal
    /// number of RS parity shreds — giving 50% erasure tolerance.  Any 32 of the 64
    /// shreds in a set are sufficient to reconstruct all 32 data shreds, regardless
    /// of which 32 are missing (vs XOR which can only recover exactly one drop).
    fn generate_coding_shreds(&self, data_shreds: &[Shred]) -> Vec<Shred> {
        let n = DATA_SHREDS_PER_FEC_SET;
        let rs = match ReedSolomon::new(n, n) {
            Ok(r)  => r,
            Err(e) => { warn!("🌊 Turbine: RS init failed: {}", e); return vec![]; }
        };

        let mut coding_shreds = Vec::new();

        for (fec_index, fec_set) in data_shreds.chunks(n).enumerate() {
            // Pad each data shard to exactly SHRED_SIZE (RS requires equal-length rows)
            let mut shards: Vec<Vec<u8>> = fec_set.iter()
                .map(|s| { let mut p = s.data.clone(); p.resize(SHRED_SIZE, 0); p })
                .collect();

            // If the last FEC set has < n data shreds, pad with zero shards so the
            // RS matrix is always n×n (lets the decoder use a fixed codec).
            while shards.len() < n {
                shards.push(vec![0u8; SHRED_SIZE]);
            }

            // Append n zero-filled parity shards — rs.encode() fills them in-place
            for _ in 0..n {
                shards.push(vec![0u8; SHRED_SIZE]);
            }

            // GF(2^8) erasure encode: parity rows written into shards[n..2n]
            if let Err(e) = rs.encode(&mut shards) {
                warn!("🌊 Turbine: RS encode failed for FEC set {}: {}", fec_index, e);
                continue;
            }

            // Emit one coding Shred per parity row
            for (c, parity_data) in shards[n..].iter().enumerate() {
                coding_shreds.push(Shred {
                    slot: self.slot,
                    index: (data_shreds.len() + fec_index * n + c) as u32,
                    total_shreds: data_shreds.len() as u32,
                    is_coding: true,
                    fec_set_index: fec_index as u32,
                    data: parity_data.clone(),
                    merkle_proof: vec![],
                    signature: format!("sig_{}_fec_{}_{}", self.leader, fec_index, c),
                });
            }
        }

        coding_shreds
    }
    
    /// Reassemble a block from shreds using Reed-Solomon recovery.
    ///
    /// Tolerates up to `DATA_SHREDS_PER_FEC_SET` (32) missing shreds per FEC window.
    /// Any combination of data + coding shreds totalling ≥ 32 per window is enough;
    /// the receiver does not need to know *which* shreds were dropped.
    #[allow(dead_code)] // Wired in Phase 5+ (P2P Turbine receiver)
    pub fn reassemble_block(shreds: &[Shred]) -> Result<FinalizedBlock, String> {
        if shreds.is_empty() {
            return Err("No shreds provided".to_string());
        }

        let n = DATA_SHREDS_PER_FEC_SET;

        // Total data shred count is encoded in every shred header
        let total_data = shreds.iter()
            .find(|s| !s.is_coding)
            .map(|s| s.total_shreds as usize)
            .ok_or("No data shreds found")?;

        let n_fec_sets = total_data.div_ceil(n);

        // Group all shreds by FEC set
        let mut by_fec: HashMap<u32, Vec<&Shred>> = HashMap::new();
        for s in shreds {
            by_fec.entry(s.fec_set_index).or_default().push(s);
        }

        let rs = ReedSolomon::new(n, n)
            .map_err(|e| format!("RS init failed: {}", e))?;

        let mut recovered: Vec<Option<Vec<u8>>> = vec![None; total_data];

        for fec_idx in 0..n_fec_sets {
            let set_shreds = by_fec.get(&(fec_idx as u32)).map(|v| v.as_slice()).unwrap_or(&[]);

            let data_start = fec_idx * n;
            let data_end   = (data_start + n).min(total_data);

            let data_in_set: Vec<_>   = set_shreds.iter().filter(|s| !s.is_coding).copied().collect();
            let coding_in_set: Vec<_> = set_shreds.iter().filter(|s|  s.is_coding).copied().collect();

            // Fast path — all data shreds present, no RS needed
            if data_in_set.len() == (data_end - data_start) {
                for s in data_in_set {
                    recovered[s.index as usize] = Some(s.data.clone());
                }
                continue;
            }

            // Build the shard matrix: rows 0..n are data, rows n..2n are parity
            let mut shard_opts: Vec<Option<Vec<u8>>> = vec![None; 2 * n];

            for s in &data_in_set {
                let local = s.index as usize - data_start;
                if local < n {
                    let mut padded = s.data.clone();
                    padded.resize(SHRED_SIZE, 0);
                    shard_opts[local] = Some(padded);
                }
            }

            // Coding shreds were emitted at global index:
            //   total_data + fec_idx * n + coding_col
            // so: coding_col = shred.index - total_data - fec_idx * n
            let coding_global_start = total_data + fec_idx * n;
            for s in &coding_in_set {
                let col = s.index as usize - coding_global_start;
                if col < n {
                    let mut padded = s.data.clone();
                    padded.resize(SHRED_SIZE, 0);
                    shard_opts[n + col] = Some(padded);
                }
            }

            let available = shard_opts.iter().filter(|o| o.is_some()).count();
            if available < n {
                return Err(format!(
                    "FEC set {fec_idx}: need {n} shards to reconstruct, only have {available} — unrecoverable"
                ));
            }

            // GF(2^8) reconstruction — fills in every None row
            rs.reconstruct_data(&mut shard_opts)
                .map_err(|e| format!("RS reconstruct FEC set {fec_idx}: {}", e))?;

            for local in 0..(data_end - data_start) {
                let global = data_start + local;
                if recovered[global].is_none() {
                    recovered[global] = shard_opts[local].take();
                }
            }
        }

        // Concatenate all data rows then strip the 4-byte length prefix
        let mut raw: Vec<u8> = Vec::with_capacity(total_data * SHRED_SIZE);
        for (i, shard) in recovered.into_iter().enumerate() {
            raw.extend(
                shard.ok_or_else(|| format!("Missing data shard {i} after RS recovery"))?
            );
        }

        if raw.len() < 4 {
            return Err("Reassembled payload too short to contain length prefix".to_string());
        }
        let len_bytes: [u8; 4] = raw[..4].try_into()
            .map_err(|_| "Failed to read length prefix from reassembled payload".to_string())?;
        let payload_len = u32::from_be_bytes(len_bytes) as usize;
        if raw.len() < 4 + payload_len {
            return Err(format!(
                "Truncated payload: expected {} bytes, got {}",
                4 + payload_len,
                raw.len()
            ));
        }

        borsh::from_slice(&raw[4..4 + payload_len])
            .map_err(|e| format!("Borsh deserialize failed: {}", e))
    }
}

/// Turbine propagation tree - determines who to send shreds to
#[allow(dead_code)] // Wired in Phase 5+ (P2P Turbine)
pub struct TurbinePropagator {
    /// Our node's position in the tree (0 = leader)
    pub layer: u32,
    /// Nodes we forward to (our children in the tree)
    pub children: Vec<String>,
    /// Node we receive from (our parent in the tree)
    pub parent: Option<String>,
}

impl TurbinePropagator {
    /// Calculate propagation path for a validator set
    pub fn calculate_tree(validators: &[String], leader: &str) -> Vec<(String, TurbinePropagator)> {
        let mut tree = Vec::new();
        
        // Leader is root (layer 0)
        let leader_children: Vec<String> = validators.iter()
            .filter(|v| *v != leader)
            .take(TURBINE_FANOUT)
            .cloned()
            .collect();
        
        tree.push((leader.to_string(), TurbinePropagator {
            layer: 0,
            children: leader_children.clone(),
            parent: None,
        }));
        
        // Layer 1 nodes
        for (i, validator) in validators.iter().filter(|v| *v != leader).enumerate() {
            let layer = 1 + (i / TURBINE_FANOUT) as u32;
            let parent = if layer == 1 {
                Some(leader.to_string())
            } else {
                Some(leader_children[(i / TURBINE_FANOUT) % leader_children.len()].clone())
            };
            
            // Each node forwards to TURBINE_FANOUT nodes in the next layer
            let start = i * TURBINE_FANOUT;
            let children: Vec<String> = validators.iter()
                .filter(|v| *v != leader && *v != validator)
                .skip(start)
                .take(TURBINE_FANOUT)
                .cloned()
                .collect();
            
            tree.push((validator.clone(), TurbinePropagator {
                layer,
                children,
                parent,
            }));
        }
        
        tree
    }
    
    /// Calculate max hops to reach all validators
    pub fn max_hops(validator_count: usize) -> u32 {
        if validator_count <= 1 {
            return 0;
        }
        let mut hops = 0;
        let mut reached = 1; // Leader
        while reached < validator_count {
            reached += TURBINE_FANOUT.pow(hops + 1);
            hops += 1;
        }
        hops
    }
}

// ============================================================================
// MERKLE TREE FOR STATE ROOT
// ============================================================================

/// Sorted-hash combiner — always places the lexicographically smaller
/// hash first so the result is position-independent.
/// Both the tree builder AND the proof verifier must use this same function.
/// The L2 must implement the identical convention (min-first SHA-256 pairing).
fn combine_hashes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if a <= b {
        hasher.update(a);
        hasher.update(b);
    } else {
        hasher.update(b);
        hasher.update(a);
    }
    hasher.finalize().into()
}

/// Simple merkle tree implementation for account state proofs
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    /// Build a merkle tree from account balances.
    /// Balances are u64 lamports — hashed deterministically across architectures.
    /// (f64 hashing is non-deterministic and lossy; never use it for state roots.)
    /// Accounts are sorted by address for deterministic ordering.
    pub fn from_accounts(accounts: &BTreeMap<String, u64>) -> Self {
        if accounts.is_empty() {
            return Self {
                leaves: vec![],
                root: [0u8; 32],
            };
        }

        // Create leaves: hash(address || lamports_le_bytes)
        let leaves: Vec<[u8; 32]> = accounts
            .iter()
            .map(|(addr, lamports)| {
                let mut hasher = Sha256::new();
                hasher.update(addr.as_bytes());
                hasher.update(lamports.to_le_bytes());
                hasher.finalize().into()
            })
            .collect();

        // Build tree and compute root
        let root = Self::compute_root(&leaves);

        Self { leaves, root }
    }

    /// Compute merkle root from leaves using sorted hashing.
    /// Each pair is combined via `combine_hashes` (smaller hash first),
    /// so the root is independent of insertion order.
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
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
                // Odd node: pair with itself (standard duplicate-last convention)
                let right = if chunk.len() > 1 { &chunk[1] } else { &chunk[0] };
                next_level.push(combine_hashes(&chunk[0], right));
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

            // Move to next level — must use the same combine_hashes as compute_root
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let right = if chunk.len() > 1 { &chunk[1] } else { &chunk[0] };
                next_level.push(combine_hashes(&chunk[0], right));
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
    /// Verify this proof against a leaf value.
    /// `lamports` is the raw u64 balance — must match what was hashed in `from_accounts`.
    pub fn verify(&self, address: &str, lamports: u64) -> bool {
        // Compute leaf hash
        let mut hasher = Sha256::new();
        hasher.update(address.as_bytes());
        hasher.update(lamports.to_le_bytes());
        let mut current: [u8; 32] = hasher.finalize().into();

        // Walk up the tree using sorted hashing — is_left is ignored;
        // direction is determined by lexicographic comparison, not position.
        for node in &self.proof {
            let sibling_vec = hex::decode(&node.hash).unwrap_or_default();
            if sibling_vec.len() != 32 {
                return false;
            }
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&sibling_vec);
            current = combine_hashes(&current, &sibling);
        }

        hex::encode(current) == self.root
    }
}

// ============================================================================
// POH-ORDERED TRANSACTION
// ============================================================================

/// A transaction with PoH ordering metadata
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
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

/// Leaf cache for the Incremental Sparse Merkle Tree.
///
/// Holds the full sorted set of account leaf hashes so that `compute_state_root`
/// can update only dirty/deleted leaves instead of rescanning `hot_state`
/// on every block (the old O(N) DashMap scan bottleneck).
///
/// Stored as a `BTreeMap` so the leaf order is always sorted lexicographically
/// by address string — matching the sort contract used by `MerkleTree`.
pub struct LeafCache {
    /// address → SHA-256(address ++ balance_le_bytes) leaf hash
    leaves: Arc<RwLock<BTreeMap<String, [u8; 32]>>>,
}

impl LeafCache {
    pub fn new() -> Self {
        Self { leaves: Arc::new(RwLock::new(BTreeMap::new())) }
    }

    /// Seed the cache from the SVM hot_state on a fresh start.
    /// Hashes raw u64 lamports — must match `MerkleTree::from_accounts`.
    pub fn warm_from_hot_state(&self, hot_state: &crate::svm::SvmAccountsDB) {
        use solana_sdk::account::ReadableAccount;
        use sha2::Digest;
        let mut leaves = self.leaves.write();
        for entry in hot_state.hot_state.iter() {
            let lamports = entry.value().lamports();
            if lamports > 0 {
                let addr = entry.key().to_string();
                let mut hasher = Sha256::new();
                hasher.update(addr.as_bytes());
                hasher.update(lamports.to_le_bytes());
                let hash: [u8; 32] = hasher.finalize().into();
                leaves.insert(addr, hash);
            }
        }
    }

    /// Apply a set of dirty (modified) and deleted accounts to the leaf cache.
    /// Returns the new `state_root` computed from the updated leaf set.
    pub fn apply_and_compute_root(
        &self,
        modified: &[[u8; 32]],   // pubkey byte arrays (DirtySet)
        deleted: &[[u8; 32]],    // pubkey byte arrays (DirtySet::deleted)
        hot_state: &crate::svm::SvmAccountsDB,
    ) -> String {
        use solana_sdk::account::ReadableAccount;
        use sha2::Digest;
        use solana_sdk::pubkey::Pubkey;

        let mut leaves = self.leaves.write();

        // Update modified leaves — recompute only for changed accounts (O(dirty)).
        // Hashes raw u64 lamports for cross-architecture determinism.
        for key_bytes in modified {
            let pubkey = Pubkey::new_from_array(*key_bytes);
            let addr = pubkey.to_string();
            if let Some(account) = hot_state.hot_state.get(&pubkey) {
                let lamports = account.lamports();
                if lamports > 0 {
                    let mut hasher = Sha256::new();
                    hasher.update(addr.as_bytes());
                    hasher.update(lamports.to_le_bytes());
                    let hash: [u8; 32] = hasher.finalize().into();
                    leaves.insert(addr, hash);
                } else {
                    // Lamports hit zero — treat as deletion
                    leaves.remove(&addr);
                }
            }
        }

        // Zero-out deleted leaves — they are no longer part of the state
        for key_bytes in deleted {
            let pubkey = Pubkey::new_from_array(*key_bytes);
            leaves.remove(&pubkey.to_string());
        }

        // Build tree from the cached leaf set (O(leaves) tree construction,
        // but we skipped the O(N) DashMap scan — only the leaf array rebuild
        // remains, which is fast in practice).
        let leaf_vec: Vec<[u8; 32]> = leaves.values().copied().collect();
        let root = MerkleTree::compute_root(&leaf_vec);
        hex::encode(root)
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.read().is_empty()
    }
}

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
    
    /// Pending transactions for next block (from Gulf Stream — will be executed)
    pending_txs: Arc<RwLock<Vec<Transaction>>>,

    /// Pre-executed transactions for next block (from handlers — already executed,
    /// just need to be recorded in the block for PoH ordering + persistence)
    executed_txs: Arc<RwLock<Vec<Transaction>>>,
    
    /// Produced blocks (in-memory cache, last N blocks)
    blocks: Arc<RwLock<Vec<FinalizedBlock>>>,
    
    /// Latest block hash for chaining
    latest_hash: Arc<RwLock<String>>,
    
    /// Our validator identity
    validator_id: String,

    /// SVM execution engine (Phase 1C: routes TransferBb through native Rust path)
    svm: Arc<std::sync::Mutex<BlackBookSVM>>,

    /// Last slot we produced a block for (prevents double-production)
    last_produced_slot: Arc<AtomicU64>,

    /// Incremental Merkle leaf cache (Phase 2 — avoids O(N) hot_state scan per block)
    leaf_cache: Arc<LeafCache>,
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
        let svm = {
            use sha2::{Sha256, Digest};
            let hash_bytes: [u8; 32] = Sha256::digest(b"BLACKBOOK_L1_GENESIS_2025").into();
            let genesis = SvmHash::new_from_array(hash_bytes);
            let bb_svm = BlackBookSVM::new(
                Arc::clone(&blockchain.svm_accounts),
                genesis,
            );
            Arc::new(std::sync::Mutex::new(bb_svm))
        };

        info!("🏭 BlockProducer initialized for validator: {}", validator_id);
        
        let leaf_cache = Arc::new(LeafCache::new());
        // Warm the leaf cache from whatever accounts are already on disk
        leaf_cache.warm_from_hot_state(&blockchain.svm_accounts);

        Self {
            blockchain,
            poh,
            leader_schedule,
            current_slot,
            pending_txs: Arc::new(RwLock::new(Vec::new())),
            executed_txs: Arc::new(RwLock::new(Vec::new())),
            blocks: Arc::new(RwLock::new(Vec::new())),
            latest_hash: Arc::new(RwLock::new(genesis_hash)),
            validator_id,
            svm,
            last_produced_slot: Arc::new(AtomicU64::new(u64::MAX)), // sentinel: no block produced yet
            leaf_cache,
        }
    }

    /// Restore chain state from a previous block after restart.
    /// Sets the latest hash for block chaining and the last produced slot
    /// to prevent re-producing already-persisted slots.
    pub fn restore_chain_state(&self, last_slot: u64, last_hash: String) {
        {
            let mut h = self.latest_hash.write();
            *h = last_hash.clone();
        }
        self.last_produced_slot.store(last_slot, Ordering::Relaxed);
        info!(
            "🔗 BlockProducer chain restored: slot {}, hash {}…",
            last_slot,
            &last_hash[..last_hash.len().min(16)]
        );
    }

    /// Flush pending/executed transactions into one final block (for graceful shutdown).
    /// Returns the number of transactions flushed.
    pub fn flush_final_block(&self) -> u64 {
        let pending = self.pending_txs.read().len();
        let executed = self.executed_txs.read().len();
        let total = pending + executed;
        if total == 0 {
            return 0;
        }
        // Advance slot by one to avoid the "already produced" guard
        let current = self.current_slot.load(Ordering::Relaxed);
        let next = current + 1;
        self.current_slot.store(next, Ordering::Relaxed);
        match self.produce_block() {
            Ok(block) => {
                info!(
                    "📦 Shutdown block {} produced: {} txs flushed",
                    block.slot, block.tx_count
                );
                block.tx_count as u64
            }
            Err(e) => {
                warn!("⚠️  Shutdown block failed: {} — {} txs lost", e, total);
                0
            }
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

    /// Record an already-executed transaction for inclusion in the next block.
    ///
    /// Unlike `submit_transaction()`, this does NOT execute the transaction —
    /// it only queues it so `produce_block()` packages it into the PoH block.
    /// Use this for transactions processed by HTTP handlers (SSS transfers,
    /// faucet mints) that are already committed to ReDB + SVM.
    pub fn record_executed_transaction(&self, tx: Transaction) {
        let tx_id = tx.hash.clone();

        // Mix into PoH for cryptographic ordering proof
        {
            let mut poh = self.poh.write();
            poh.queue_transaction(tx_id.clone());
        }

        // Queue for next block (will NOT be re-executed)
        {
            let mut executed = self.executed_txs.write();
            executed.push(tx);
        }

        tracing::debug!(tx_id = %tx_id, "Recorded pre-executed tx for next block");
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

        // Guard: don't double-produce the same slot
        let last = self.last_produced_slot.load(Ordering::Relaxed);
        if last == slot {
            return Err(format!("Already produced block for slot {}", slot));
        }
        
        // Check leadership
        let leader = {
            let schedule = self.leader_schedule.read();
            schedule.get_leader(slot)
        };
        
        if leader != self.validator_id {
            return Err(format!("Not leader for slot {}. Leader is: {}", slot, leader));
        }

        // Snapshot PoH state for this slot (PoH clock handles advancement)
        let (poh_hash, poh_sequence, poh_entries, epoch) = {
            let poh = self.poh.read();
            let hash = poh.current_hash.clone();
            let seq = poh.num_hashes;
            let entries = poh.current_entries.clone();
            let epoch = poh.current_epoch;
            (hash, seq, entries, epoch)
        };

        // Advance the SVM slot so intra-block transactions have a valid blockhash.
        {
            let slot_bytes: [u8; 32] = {
                use sha2::{Sha256, Digest};
                let mut h = Sha256::new();
                h.update(poh_hash.as_bytes());
                h.update(slot.to_le_bytes());
                h.finalize().into()
            };
            let slot_hash = SvmHash::new_from_array(slot_bytes);
            if let Ok(mut svm) = self.svm.lock() {
                svm.advance_slot(slot, slot_hash);
            }
        }

        // ---- Collect pre-executed transactions (from HTTP handlers) ----
        let pre_executed: Vec<Transaction> = {
            let mut executed = self.executed_txs.write();
            std::mem::take(&mut *executed)
        };

        // ---- Collect pending transactions (from Gulf Stream — need execution) ----
        let pending: Vec<Transaction> = {
            let mut pending = self.pending_txs.write();
            std::mem::take(&mut *pending)
        };

        // Build ordered transaction list
        let mut ordered_txs = Vec::new();
        let mut position: u32 = 0;

        // 1) Pre-executed transactions — already committed, just record in block
        for tx in pre_executed {
            ordered_txs.push(OrderedTransaction {
                tx,
                poh_hash: poh_hash.clone(),
                poh_sequence,
                slot,
                position,
            });
            position += 1;
        }

        // 2) Pending transactions — execute then record
        for tx in pending {
            match self.execute_transaction(&tx) {
                Ok(_) => {
                    ordered_txs.push(OrderedTransaction {
                        tx,
                        poh_hash: poh_hash.clone(),
                        poh_sequence,
                        slot,
                        position,
                    });
                    position += 1;
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
            .unwrap_or_default()
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

        // Store block in-memory cache (keep last 1000 blocks)
        {
            let mut blocks = self.blocks.write();
            blocks.push(block.clone());
            
            // Update confirmations on previous blocks
            let len = blocks.len();
            for i in 0..len.saturating_sub(1) {
                blocks[len - 1 - i - 1].confirmations += 1;
            }

            // Evict oldest if cache exceeded
            if blocks.len() > 1000 {
                let excess = blocks.len() - 1000;
                blocks.drain(0..excess);
            }
        }

        // Persist block to ReDB
        if let Err(e) = self.blockchain.store_block(slot, &block) {
            error!("Failed to persist block {} to ReDB: {}", slot, e);
        }

        // Update leader schedule
        {
            let mut schedule = self.leader_schedule.write();
            schedule.record_slot_production(&self.validator_id, slot);
        }

        // Flush SVM dirty accounts to ReDB for this block
        {
            if let Ok(mut svm) = self.svm.lock() {
                match svm.end_of_block() {
                    Ok(n) => if n > 0 { info!("💾 SVM flush: {} accounts persisted for slot {}", n, slot) },
                    Err(e) => warn!("SVM flush error at slot {}: {}", slot, e),
                }
            }
        }

        // Persist slot terminal hash for PoH chaining
        {
            use crate::storage::SlotMeta;
            let meta = SlotMeta { slot, terminal_hash: block_hash.clone() };
            if let Err(e) = self.blockchain.save_slot_meta(slot, &meta) {
                warn!("Failed to persist SlotMeta for slot {}: {}", slot, e);
            }
        }

        // Spawn background GC for orphaned Merkle nodes (non-blocking)
        {
            let db_clone = self.blockchain.clone();
            tokio::spawn(async move {
                if let Err(e) = db_clone.gc_merkle_nodes(slot) {
                    tracing::warn!(slot, error = %e, "gc_merkle_nodes failed");
                }
            });
        }

        // Mark this slot as produced
        self.last_produced_slot.store(slot, Ordering::Relaxed);

        if block.tx_count > 0 {
            info!(
                "📦 Block {} produced: {} txs, hash: {}…, poh: {}…",
                slot,
                block.tx_count,
                &block.hash[..16],
                &block.poh_hash[..16]
            );
        }

        Ok(block)
    }

    /// Execute a single transaction using the Two-Tier Vault architecture
    /// Note: Amounts are in u64 (6 decimals), converted to f64 for storage
    fn execute_transaction(&self, tx: &Transaction) -> Result<(), String> {
        match &tx.data {
            // ========== Tier 1: USDT → $BB Gateway ==========
            
            TxData::DepositUsdt { usdt_amount, external_tx_hash } => {
                let tx_hash = external_tx_hash.as_deref().unwrap_or("internal");
                info!("Tier1 deposit: {} deposited {} USDT (tx: {})", 
                    tx.from, usdt_amount, &tx_hash[..8.min(tx_hash.len())]);
                // Credit $BB to user (at 1:10 ratio) — stay in u64 lamports
                let bb_amount = usdt_amount.checked_mul(10)
                    .ok_or("BB amount overflow")?;
                let lamports = bb_amount.checked_mul(crate::svm::types::LAMPORTS_PER_BB)
                    .ok_or("Lamport amount overflow")?;
                self.blockchain.credit_lamports(&tx.from, lamports)
            }
            
            // ========== Token Transfers ==========
            
            TxData::TransferBb { to, amount } => {
                info!("Transfer: {} -> {} ({} $BB)", tx.from, to, amount);
                {
                    self.execute_transfer_via_svm(&tx.from, to, *amount)?;
                    Ok(())
                }
            }

            // ========== Global Escrow Smart Contract ==========

            TxData::EscrowDeposit { amount, escrow_address } => {
                info!("Escrow deposit: {} locked {} BB → escrow {}", tx.from, amount, &escrow_address[..16.min(escrow_address.len())]);
                // Already executed by the handler (debit user + credit escrow)
                Ok(())
            }

            TxData::EscrowStateRoot { market_id, merkle_root } => {
                info!("Escrow state root: market={} root={}…", market_id, &merkle_root[..16.min(merkle_root.len())]);
                // State root submission — no balance changes, just recorded in PoH
                Ok(())
            }

            TxData::EscrowWithdraw { market_id, amount, escrow_address } => {
                info!("Escrow withdraw: {} claimed {} BB from market {} (escrow {})", tx.from, amount, market_id, &escrow_address[..16.min(escrow_address.len())]);
                // Already executed by the handler (debit escrow + credit user)
                Ok(())
            }
        }
    }

    // =========================================================================
    // SVM EXECUTION HELPERS (feature = "svm")
    // =========================================================================

    /// Execute a $BB transfer through the SVM execution engine.
    ///
    /// SVM AccountsDB is the single source of truth — no lazy migration needed.
    /// `amount` is in $BB units (matching the `TransferBb.amount` field).
    /// Conversion to lamports happens here — the only place in the call tree.
    fn execute_transfer_via_svm(
        &self,
        from_addr: &str,
        to_addr: &str,
        amount_bb: u64,
    ) -> Result<(), String> {
        use crate::svm::types::LAMPORTS_PER_BB;

        let svm_guard = self.svm.lock()
            .map_err(|e| format!("SVM lock poisoned: {e}"))?;

        // --- Address parsing ---
        let from_pk = Self::legacy_addr_to_pubkey(from_addr)
            .map_err(|e| format!("Invalid from address: {e}"))?;
        let to_pk = Self::legacy_addr_to_pubkey(to_addr)
            .map_err(|e| format!("Invalid to address: {e}"))?;

        // --- Lamport conversion (u64 × u64 — no f64 involved) ---
        let lamports = amount_bb
            .checked_mul(LAMPORTS_PER_BB)
            .ok_or("Transfer amount overflows u64 lamports")?;

        // --- Build transfer request with the slot's current blockhash ---
        let recent_blockhash = svm_guard.current_blockhash();
        let req = crate::svm::runtime::TransferRequest {
            tx_id: format!("bp_{}", uuid_hex()),
            from: from_pk,
            to: to_pk,
            lamports,
            recent_blockhash,
        };

        let result = svm_guard.execute_transfer(&req);

        if result.success {
            tracing::debug!(
                from = %from_addr,
                to   = %to_addr,
                bb   = amount_bb,
                cu   = result.compute_units_consumed,
                "SVM transfer executed"
            );
            Ok(())
        } else {
            Err(result.error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown SVM error".into()))
        }
    }

    /// Deterministically derive a Solana `Pubkey` from a legacy `bb_<hex>` address.
    ///
    /// Strategy: strip the `bb_` prefix (if present), then SHA-256 hash the
    /// raw bytes of the remaining string to produce a stable 32-byte key.
    /// This is Option A from the migration design doc — explicit, reversible
    /// via the ADDRESS_MAP table (Phase 3A.3), and collision-free in practice.
    fn legacy_addr_to_pubkey(addr: &str) -> Result<Pubkey, String> {
        use sha2::{Sha256, Digest};
        let stripped = addr.strip_prefix("bb_").unwrap_or(addr);
        let bytes: [u8; 32] = Sha256::digest(stripped.as_bytes()).into();
        Ok(Pubkey::new_from_array(bytes))
    }

    /// Compute merkle state root incrementally using only dirty/deleted accounts.
    ///
    /// Instead of the O(N) full hot_state DashMap scan, we:
    ///   1. Drain only the accounts that changed this slot from the DirtySet.
    ///   2. Sort them lexicographically (bundles adjacent tree paths together).
    ///   3. Update only those leaves in the persistent LeafCache.
    ///   4. Rebuild the root from the cached leaf array — O(dirty) leaf updates
    ///      + one O(leaves) tree construction pass.
    fn compute_state_root(&self) -> String {
        let (modified, deleted) = self.blockchain.svm_accounts.dirty.drain_for_merkle();

        if modified.is_empty() && deleted.is_empty() && !self.leaf_cache.is_empty() {
            // Nothing changed — return whatever root the cache already has
            let leaf_vec: Vec<[u8; 32]> = self.leaf_cache.leaves.read().values().copied().collect();
            let root = MerkleTree::compute_root(&leaf_vec);
            return hex::encode(root);
        }

        self.leaf_cache.apply_and_compute_root(&modified, &deleted, &self.blockchain.svm_accounts)
    }

    /// Get all accounts (for state root computation).
    /// Reads exclusively from SVM AccountsDB (the single source of truth)
    /// and returns raw u64 lamports for deterministic merkle hashing.
    fn get_all_accounts(&self) -> BTreeMap<String, u64> {
        use solana_sdk::account::ReadableAccount;
        let mut accounts = BTreeMap::new();

        for entry in self.blockchain.svm_accounts.hot_state.iter() {
            let lamports = entry.value().lamports();
            if lamports > 0 {
                let key = entry.key().to_string();
                accounts.insert(key, lamports);
            }
        }

        accounts
    }

    /// Get a block by slot number (memory cache → ReDB fallback)
    pub fn get_block(&self, slot: u64) -> Option<FinalizedBlock> {
        // Check in-memory cache first
        let blocks = self.blocks.read();
        if let Some(block) = blocks.iter().find(|b| b.slot == slot) {
            return Some(block.clone());
        }
        drop(blocks);

        // Fallback to ReDB
        self.blockchain.load_block(slot).ok().flatten()
    }

    /// Get the latest block
    pub fn get_latest_block(&self) -> Option<FinalizedBlock> {
        let blocks = self.blocks.read();
        if let Some(block) = blocks.last() {
            return Some(block.clone());
        }
        drop(blocks);
        
        // Fallback to ReDB if cache is empty (e.g., right after startup)
        if let Ok(Some(slot)) = self.blockchain.latest_block_slot() {
            return self.blockchain.load_block(slot).ok().flatten();
        }
        None
    }

    /// Get total blocks produced (including ReDB-persisted)
    pub fn total_blocks_produced(&self) -> u64 {
        let last = self.last_produced_slot.load(Ordering::Relaxed);
        if last == u64::MAX { 0 } else { last + 1 }
    }

    /// Get cumulative transaction count across all in-memory cached blocks.
    /// O(n) over the cache (max 1000 blocks) — fast enough for RPC use.
    pub fn total_transaction_count(&self) -> u64 {
        self.blocks.read().iter().map(|b| b.tx_count as u64).sum()
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
#[allow(dead_code)] // Called by reader nodes in multi-validator mode
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
#[allow(dead_code)] // Called by reader nodes in multi-validator mode
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
// INTERNAL UTILITIES
// ============================================================================

/// Generate a short unique hex string for intra-block transaction IDs.
fn uuid_hex() -> String {
    use rand::Rng;
    let n: u64 = rand::thread_rng().gen();
    format!("{:016x}", n)
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
        accounts.insert("alice".to_string(), 100u64);
        
        let tree = MerkleTree::from_accounts(&accounts);
        assert!(!tree.root_hex().is_empty());
        assert_ne!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let mut accounts = BTreeMap::new();
        accounts.insert("alice".to_string(), 100u64);
        accounts.insert("bob".to_string(), 200u64);
        accounts.insert("charlie".to_string(), 300u64);
        
        let tree = MerkleTree::from_accounts(&accounts);
        assert!(!tree.root_hex().is_empty());
        
        // Generate and verify proof for bob
        let proof = tree.generate_proof(1).unwrap();
        assert!(proof.verify("bob", 200u64));
        assert!(!proof.verify("bob", 201u64)); // Wrong balance
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
