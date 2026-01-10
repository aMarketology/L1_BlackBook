// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 9: DISTRIBUTED NETWORK - PROOF OF ENGAGEMENT CONSENSUS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Unlike PoW (mining power) or PoS (money stake), Proof of Engagement rewards
// active community participation. Validators are selected based on their
// engagement score, not their wealth or computational resources.
//
// Architecture:
//   ┌─────────────────────────────────────────────────────────────────────┐
//   │                    LAYER1 DISTRIBUTED NETWORK                        │
//   ├─────────────────────────────────────────────────────────────────────┤
//   │   Validator Node 1      Validator Node 2      Validator Node 3     │
//   │   (Alice - 1000 eng)    (Bob - 850 eng)      (Carol - 920 eng)     │
//   │          │                     │                      │             │
//   │          └─────────────────────┴──────────────────────┘             │
//   │                              │                                      │
//   │                      P2P Gossip Network                             │
//   │                  (libp2p + DHT discovery)                           │
//   │                              │                                      │
//   │          ┌───────────────────┼───────────────────┐                 │
//   │          │                   │                   │                 │
//   │     Light Node           Full Node          Archive Node           │
//   │   (Mobile wallet)    (Complete chain)    (Full history + API)      │
//   └─────────────────────────────────────────────────────────────────────┘
//
// ═══════════════════════════════════════════════════════════════════════════════

// Consensus modules
pub mod block_proposal;
pub mod fork_choice;
pub mod hot_upgrades;
pub mod p2p;

// Re-export main types
pub use block_proposal::{BlockProposer, ProposedBlock, BlockVote};
pub use fork_choice::{ForkChoiceManager, BlockMeta, FinalityStatus, ForkChoiceStats};
pub use hot_upgrades::{UpgradeManager, UpgradeProposal, ProtocolVersion, FeatureFlags};
pub use p2p::{P2PNetwork, NetworkConfig, PeerInfo};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Node type in the distributed network
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NodeType {
    /// Full validator - can propose and vote on blocks
    Validator,
    /// Full node - stores complete chain, relays transactions
    FullNode,
    /// Light node - SPV client, only headers
    LightNode,
    /// Archive node - full history + API services
    ArchiveNode,
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Minimum engagement score to become a validator
    pub min_engagement_score: u64,
    /// Minimum stake (in tokens) to become a validator
    pub min_stake: f64,
    /// Number of validators in the active set
    pub validator_set_size: usize,
    /// Block time in milliseconds
    pub block_time_ms: u64,
    /// Finality threshold (2/3 of validators must agree)
    pub finality_threshold: f64,
    /// Epoch length in blocks (when validator set is recalculated)
    pub epoch_length: u64,
    /// Slashing penalty for misbehavior (percentage)
    pub slashing_penalty_percent: f64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            min_engagement_score: 100,      // Need 100 engagement points
            min_stake: 1000.0,               // Need 1000 tokens staked
            validator_set_size: 21,          // 21 validators like EOS/BNB
            block_time_ms: 400,              // 400ms blocks (Solana-like speed)
            finality_threshold: 0.67,        // 2/3 supermajority
            epoch_length: 432000,            // ~2 days at 400ms blocks
            slashing_penalty_percent: 5.0,   // 5% slashing for misbehavior
        }
    }
}

/// Main consensus engine that coordinates all components
pub struct ConsensusEngine {
    pub config: ConsensusConfig,
    pub node_type: NodeType,
    pub fork_choice: Arc<RwLock<ForkChoiceManager>>,
    pub block_proposer: Arc<RwLock<BlockProposer>>,
    pub p2p_network: Arc<RwLock<P2PNetwork>>,
    pub current_epoch: u64,
    pub current_slot: u64,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    pub fn new(config: ConsensusConfig, node_type: NodeType) -> Self {
        // Initialize fork choice with genesis
        let genesis_hash = "0".repeat(64);
        let fork_choice = ForkChoiceManager::new(genesis_hash.clone(), "genesis_state".to_string());
        
        // Initialize block proposer
        let block_proposer = BlockProposer::new(
            config.block_time_ms,
            config.finality_threshold,
        );
        
        // Initialize P2P network
        let network_config = NetworkConfig::default();
        let p2p_network = P2PNetwork::new(network_config);
        
        Self {
            config,
            node_type,
            fork_choice: Arc::new(RwLock::new(fork_choice)),
            block_proposer: Arc::new(RwLock::new(block_proposer)),
            p2p_network: Arc::new(RwLock::new(p2p_network)),
            current_epoch: 0,
            current_slot: 0,
        }
    }
    
    /// Check if this node is eligible to be a validator
    pub async fn is_validator_eligible(&self, _address: &str) -> bool {
        matches!(self.node_type, NodeType::Validator)
    }
    
    /// Get the current validator set
    pub async fn get_validator_set(&self) -> Vec<String> {
        // Return active validators from P2P network
        let network = self.p2p_network.read().await;
        network.get_peer_addresses()
    }
    
    /// Process a new epoch (recalculate validator set)
    pub async fn process_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
    }
    
    /// Import a new block into the fork choice
    pub async fn import_block(&self, block: BlockMeta) -> Result<bool, String> {
        let mut fc = self.fork_choice.write().await;
        fc.add_block(block)
    }
    
    /// Get the best chain head
    pub async fn best_head(&self) -> String {
        let fc = self.fork_choice.read().await;
        fc.best_head().to_string()
    }
    
    /// Get finalized head
    pub async fn finalized_head(&self) -> String {
        let fc = self.fork_choice.read().await;
        fc.finalized_head().to_string()
    }
    
    /// Check if a block is finalized
    pub async fn is_finalized(&self, block_hash: &str) -> bool {
        let fc = self.fork_choice.read().await;
        fc.is_finalized(block_hash)
    }
    
    /// Broadcast a message to the network
    pub async fn broadcast(&self, message: p2p::NetworkMessage) {
        let mut network = self.p2p_network.write().await;
        network.broadcast(message);
    }
    
    /// Get consensus statistics
    pub fn get_stats(&self) -> ConsensusStats {
        ConsensusStats {
            node_type: self.node_type.clone(),
            current_epoch: self.current_epoch,
            current_slot: self.current_slot,
            block_time_ms: self.config.block_time_ms,
            validator_set_size: self.config.validator_set_size,
        }
    }
    
    /// Get fork choice stats
    pub async fn get_fork_choice_stats(&self) -> ForkChoiceStats {
        let fc = self.fork_choice.read().await;
        fc.stats()
    }
}

/// Statistics about the consensus engine
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsensusStats {
    pub node_type: NodeType,
    pub current_epoch: u64,
    pub current_slot: u64,
    pub block_time_ms: u64,
    pub validator_set_size: usize,
}
