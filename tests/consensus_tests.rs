//! Consensus Module Tests
//!
//! Tests for consensus mechanisms including:
//! - Fork Choice (LMD-GHOST)
//! - Block Proposal and Voting
//! - P2P Network
//! - Hot Upgrades
//! - Protocol Versioning

use layer1::consensus::{
    ConsensusConfig, ConsensusEngine, ConsensusStats, NodeType,
    fork_choice::{ForkChoiceManager, BlockMeta, FinalityStatus, ForkChoiceStats},
    block_proposal::{BlockProposer, ProposedBlock, BlockTransaction, BlockVote},
    p2p::{P2PNetwork, NetworkConfig, NetworkMessage, PeerInfo},
    hot_upgrades::{ProtocolVersion, UpgradeManager, UpgradeProposal, FeatureFlags},
};
use std::sync::Arc;
use tokio::sync::RwLock;

// ============================================================================
// FORK CHOICE TESTS
// ============================================================================

#[test]
fn test_fork_choice_manager_creation() {
    let genesis_hash = "a".repeat(64);
    let genesis_state_root = "b".repeat(64);
    
    let fcm = ForkChoiceManager::new(genesis_hash.clone(), genesis_state_root);
    
    assert_eq!(fcm.best_head(), &genesis_hash, "Best head should be genesis");
    assert_eq!(fcm.finalized_head(), &genesis_hash, "Finalized head should be genesis");
}

#[test]
fn test_fork_choice_add_block() {
    let genesis_hash = "genesis".to_string() + &"0".repeat(57);
    let genesis_state_root = "state".to_string() + &"0".repeat(59);
    
    let mut fcm = ForkChoiceManager::new(genesis_hash.clone(), genesis_state_root);
    
    let block1 = BlockMeta {
        hash: "block1".to_string() + &"0".repeat(58),
        parent_hash: genesis_hash.clone(),
        slot: 1,
        proposer: "validator1".to_string(),
        state_root: "state1".to_string() + &"0".repeat(58),
        weight: 100,
        vote_count: 0,
        finality: FinalityStatus::Pending,
    };
    
    let result = fcm.add_block(block1.clone());
    assert!(result.is_ok(), "Adding block should succeed");
    assert!(result.unwrap(), "Should return true for new block");
    
    // Verify block is stored
    let retrieved = fcm.get_block(&block1.hash);
    assert!(retrieved.is_some(), "Block should be retrievable");
}

#[test]
fn test_fork_choice_reject_unknown_parent() {
    let genesis_hash = "genesis".to_string() + &"0".repeat(57);
    let genesis_state_root = "state".to_string() + &"0".repeat(59);
    
    let mut fcm = ForkChoiceManager::new(genesis_hash, genesis_state_root);
    
    let orphan_block = BlockMeta {
        hash: "orphan".to_string() + &"0".repeat(58),
        parent_hash: "unknown_parent".to_string() + &"0".repeat(50),
        slot: 1,
        proposer: "validator1".to_string(),
        state_root: "state1".to_string() + &"0".repeat(58),
        weight: 100,
        vote_count: 0,
        finality: FinalityStatus::Pending,
    };
    
    let result = fcm.add_block(orphan_block);
    assert!(result.is_err(), "Block with unknown parent should be rejected");
}

#[test]
fn test_fork_choice_duplicate_block() {
    let genesis_hash = "genesis".to_string() + &"0".repeat(57);
    let genesis_state_root = "state".to_string() + &"0".repeat(59);
    
    let mut fcm = ForkChoiceManager::new(genesis_hash.clone(), genesis_state_root);
    
    let block = BlockMeta {
        hash: "block1".to_string() + &"0".repeat(58),
        parent_hash: genesis_hash,
        slot: 1,
        proposer: "validator1".to_string(),
        state_root: "state1".to_string() + &"0".repeat(58),
        weight: 100,
        vote_count: 0,
        finality: FinalityStatus::Pending,
    };
    
    let _ = fcm.add_block(block.clone());
    let result = fcm.add_block(block);
    
    // Second add should return Ok(false) for duplicate
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Duplicate block should return false");
}

#[test]
fn test_fork_choice_get_canonical_chain() {
    let genesis_hash = "genesis".to_string() + &"0".repeat(57);
    let genesis_state_root = "state".to_string() + &"0".repeat(59);
    
    let mut fcm = ForkChoiceManager::new(genesis_hash.clone(), genesis_state_root);
    
    // Add a chain: genesis -> block1 -> block2
    let block1_hash = "block1".to_string() + &"0".repeat(58);
    let block2_hash = "block2".to_string() + &"0".repeat(58);
    
    let _ = fcm.add_block(BlockMeta {
        hash: block1_hash.clone(),
        parent_hash: genesis_hash.clone(),
        slot: 1,
        proposer: "v1".to_string(),
        state_root: "s1".to_string() + &"0".repeat(62),
        weight: 100,
        vote_count: 0,
        finality: FinalityStatus::Pending,
    });
    
    let _ = fcm.add_block(BlockMeta {
        hash: block2_hash.clone(),
        parent_hash: block1_hash.clone(),
        slot: 2,
        proposer: "v2".to_string(),
        state_root: "s2".to_string() + &"0".repeat(62),
        weight: 200,
        vote_count: 0,
        finality: FinalityStatus::Pending,
    });
    
    let chain = fcm.get_canonical_chain();
    assert!(chain.len() >= 1, "Canonical chain should have blocks");
}

#[test]
fn test_fork_choice_stats() {
    let genesis_hash = "genesis".to_string() + &"0".repeat(57);
    let genesis_state_root = "state".to_string() + &"0".repeat(59);
    
    let fcm = ForkChoiceManager::new(genesis_hash.clone(), genesis_state_root);
    
    let stats = fcm.stats();
    assert_eq!(stats.total_blocks, 1, "Should have genesis block");
    assert_eq!(stats.best_head, genesis_hash);
}

#[test]
fn test_finality_status_default() {
    let status: FinalityStatus = Default::default();
    assert_eq!(status, FinalityStatus::Pending);
}

// ============================================================================
// BLOCK PROPOSAL TESTS
// ============================================================================

#[test]
fn test_block_proposer_creation() {
    let bp = BlockProposer::new(
        400,    // block_time_ms
        0.67,   // finality_threshold
        64,     // max_finalized_history
    );
    
    assert_eq!(bp.current_slot(), 0, "Initial slot should be 0");
    assert_eq!(bp.block_time_ms(), 400);
}

#[test]
fn test_proposed_block_creation() {
    let proposed = ProposedBlock::new(
        1,                          // slot
        "parent_hash".to_string() + &"0".repeat(53),
        "state_root".to_string() + &"0".repeat(54),
        vec![],                     // transactions
        "proposer".to_string(),
    );
    
    assert_eq!(proposed.slot, 1);
    assert!(!proposed.hash.is_empty(), "Proposed block should have computed hash");
}

#[test]
fn test_proposed_block_with_transactions() {
    let txs = vec![
        BlockTransaction {
            hash: "tx1".to_string() + &"0".repeat(61),
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount: 100,
            nonce: 1,
            fee: 10,
        },
        BlockTransaction {
            hash: "tx2".to_string() + &"0".repeat(61),
            from: "bob".to_string(),
            to: "charlie".to_string(),
            amount: 50,
            nonce: 1,
            fee: 5,
        },
    ];
    
    let proposed = ProposedBlock::new(
        1,
        "parent".to_string() + &"0".repeat(58),
        "state".to_string() + &"0".repeat(59),
        txs,
        "proposer".to_string(),
    );
    
    assert_eq!(proposed.transactions.len(), 2);
    assert!(!proposed.transactions_root.is_empty());
}

#[test]
fn test_block_vote_creation() {
    let vote = BlockVote::new(
        "block_hash".to_string() + &"0".repeat(54),
        1,
        "voter".to_string(),
        true,
    );
    
    assert!(vote.approve);
    assert_eq!(vote.slot, 1);
}

#[test]
fn test_block_proposer_advance_slot() {
    let mut bp = BlockProposer::new(400, 0.67, 64);
    
    assert_eq!(bp.current_slot(), 0);
    bp.advance_slot();
    assert_eq!(bp.current_slot(), 1);
    bp.advance_slot();
    assert_eq!(bp.current_slot(), 2);
}

// ============================================================================
// P2P NETWORK TESTS
// ============================================================================

#[test]
fn test_p2p_network_creation() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec!["peer1:9000".to_string()],
        max_peers: 100,
        min_peers: 3,
    };
    
    let network = P2PNetwork::new(config);
    
    assert!(!network.is_running(), "Network should not be running initially");
    assert!(network.local_peer_id().is_some(), "Should have local peer ID");
}

#[test]
fn test_p2p_add_peer() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec![],
        max_peers: 100,
        min_peers: 3,
    };
    
    let mut network = P2PNetwork::new(config);
    
    let result = network.add_peer("peer1".to_string(), "127.0.0.1:9001".to_string());
    assert!(result.is_ok(), "Adding peer should succeed");
    
    let peers = network.get_peers();
    assert_eq!(peers.len(), 1, "Should have one peer");
}

#[test]
fn test_p2p_remove_peer() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec![],
        max_peers: 100,
        min_peers: 3,
    };
    
    let mut network = P2PNetwork::new(config);
    
    let _ = network.add_peer("peer1".to_string(), "127.0.0.1:9001".to_string());
    network.remove_peer("peer1");
    
    let peers = network.get_peers();
    assert_eq!(peers.len(), 0, "Should have no peers after removal");
}

#[test]
fn test_p2p_ban_peer() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec![],
        max_peers: 100,
        min_peers: 3,
    };
    
    let mut network = P2PNetwork::new(config);
    
    let _ = network.add_peer("bad_peer".to_string(), "127.0.0.1:9001".to_string());
    network.ban_peer("bad_peer");
    
    // Banned peer should be removed
    let peers = network.get_peers();
    assert_eq!(peers.len(), 0, "Banned peer should be removed");
    
    // Cannot re-add banned peer
    let result = network.add_peer("bad_peer".to_string(), "127.0.0.1:9002".to_string());
    assert!(result.is_err(), "Should not be able to add banned peer");
}

#[test]
fn test_p2p_has_enough_peers() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec![],
        max_peers: 100,
        min_peers: 2,  // Need at least 2 peers
    };
    
    let mut network = P2PNetwork::new(config);
    
    assert!(!network.has_enough_peers(), "Should not have enough peers initially");
    
    let _ = network.add_peer("peer1".to_string(), "127.0.0.1:9001".to_string());
    assert!(!network.has_enough_peers(), "Still not enough with 1 peer");
    
    let _ = network.add_peer("peer2".to_string(), "127.0.0.1:9002".to_string());
    assert!(network.has_enough_peers(), "Should have enough with 2 peers");
}

#[test]
fn test_network_message_variants() {
    // Test all message types can be created
    let block_announce = NetworkMessage::BlockAnnounce {
        hash: "hash".to_string(),
        slot: 1,
        proposer: "proposer".to_string(),
    };
    
    let vote = NetworkMessage::Vote {
        block_hash: "hash".to_string(),
        voter: "voter".to_string(),
        slot: 1,
        approve: true,
    };
    
    let tx_broadcast = NetworkMessage::TransactionBroadcast {
        tx_hash: "tx".to_string(),
        from: "alice".to_string(),
        to: "bob".to_string(),
    };
    
    let ping = NetworkMessage::Ping { nonce: 12345 };
    let pong = NetworkMessage::Pong { nonce: 12345 };
    
    // These should compile without error
    match block_announce {
        NetworkMessage::BlockAnnounce { slot, .. } => assert_eq!(slot, 1),
        _ => panic!("Wrong variant"),
    }
    
    match vote {
        NetworkMessage::Vote { approve, .. } => assert!(approve),
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_p2p_get_peer_addresses() {
    let config = NetworkConfig {
        listen_port: 9000,
        bootstrap_peers: vec![],
        max_peers: 100,
        min_peers: 1,
    };
    
    let mut network = P2PNetwork::new(config);
    
    let _ = network.add_peer("peer1".to_string(), "127.0.0.1:9001".to_string());
    let _ = network.add_peer("peer2".to_string(), "127.0.0.1:9002".to_string());
    
    let addresses = network.get_peer_addresses();
    assert_eq!(addresses.len(), 2, "Should have 2 peer addresses");
}

// ============================================================================
// HOT UPGRADES TESTS
// ============================================================================

#[test]
fn test_protocol_version() {
    let v1 = ProtocolVersion::new(1, 0, 0);
    let v2 = ProtocolVersion::new(1, 1, 0);
    let v3 = ProtocolVersion::new(2, 0, 0);
    
    assert!(v1 < v2, "Minor version should be compared");
    assert!(v2 < v3, "Major version should be compared");
    
    assert_eq!(format!("{}", v1), "1.0.0");
}

#[test]
fn test_protocol_version_current() {
    let current = ProtocolVersion::current();
    assert_eq!(current.major, 1);
    assert_eq!(current.minor, 0);
    assert_eq!(current.patch, 0);
}

#[test]
fn test_feature_flags() {
    let mut flags = FeatureFlags::new();
    
    assert!(!flags.is_enabled("new_feature"));
    
    flags.enable("new_feature");
    assert!(flags.is_enabled("new_feature"));
    
    flags.disable("new_feature");
    assert!(!flags.is_enabled("new_feature"));
}

#[test]
fn test_feature_flags_enabled_list() {
    let mut flags = FeatureFlags::new();
    
    flags.enable("feature_a");
    flags.enable("feature_b");
    flags.enable("feature_c");
    flags.disable("feature_b");
    
    let enabled = flags.enabled_list();
    assert_eq!(enabled.len(), 2, "Should have 2 enabled features");
}

#[test]
fn test_upgrade_manager_creation() {
    let manager = UpgradeManager::new();
    
    assert_eq!(manager.version, ProtocolVersion::current());
    assert!(manager.pending().is_empty(), "No pending upgrades initially");
}

#[test]
fn test_upgrade_proposal_creation() {
    let proposal = UpgradeProposal::new(
        "Enable Parallel Execution".to_string(),
        ProtocolVersion::new(1, 1, 0),
        1000, // activation_block
        "proposer_address".to_string(),
    );
    
    assert_eq!(proposal.name, "Enable Parallel Execution");
    assert!(!proposal.voting_ended(), "Voting should not have ended yet");
}

#[test]
fn test_upgrade_proposal_with_feature() {
    let proposal = UpgradeProposal::new(
        "Add Sealevel".to_string(),
        ProtocolVersion::new(1, 1, 0),
        1000,
        "proposer".to_string(),
    )
    .with_feature("parallel_execution")
    .with_feature("gulf_stream");
    
    assert!(proposal.feature_flags.contains(&"parallel_execution".to_string()));
    assert!(proposal.feature_flags.contains(&"gulf_stream".to_string()));
}

// ============================================================================
// CONSENSUS ENGINE TESTS
// ============================================================================

#[test]
fn test_consensus_config_default() {
    let config = ConsensusConfig::default();
    
    assert!(config.min_stake > 0.0);
    assert!(config.validator_set_size > 0);
    assert!(config.epoch_length > 0);
}

#[test]
fn test_consensus_engine_creation() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    assert_eq!(engine.current_epoch, 0);
    assert_eq!(engine.current_slot, 0);
}

#[test]
fn test_node_type_variants() {
    let validator = NodeType::Validator;
    let full_node = NodeType::FullNode;
    let light_node = NodeType::LightClient;
    
    // Test Debug trait
    assert_eq!(format!("{:?}", validator), "Validator");
    assert_eq!(format!("{:?}", full_node), "FullNode");
    assert_eq!(format!("{:?}", light_node), "LightClient");
}

#[test]
fn test_consensus_stats() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    let stats = engine.get_stats();
    
    assert_eq!(stats.current_epoch, 0);
    assert_eq!(stats.current_slot, 0);
    assert!(!stats.is_validator); // Not in validator set yet
}

#[tokio::test]
async fn test_consensus_engine_best_head() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    let head = engine.best_head().await;
    assert!(!head.is_empty(), "Best head should not be empty");
}

#[tokio::test]
async fn test_consensus_engine_finalized_head() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    let finalized = engine.finalized_head().await;
    assert!(!finalized.is_empty(), "Finalized head should not be empty");
}

#[tokio::test]
async fn test_consensus_engine_is_finalized() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    let genesis = engine.finalized_head().await;
    let is_finalized = engine.is_finalized(&genesis).await;
    
    assert!(is_finalized, "Genesis should be finalized");
}

#[tokio::test]
async fn test_consensus_engine_fork_choice_stats() {
    let config = ConsensusConfig::default();
    let engine = ConsensusEngine::new(config, NodeType::Validator);
    
    let stats = engine.get_fork_choice_stats().await;
    
    assert_eq!(stats.total_blocks, 1, "Should have genesis block");
    assert_eq!(stats.fork_count, 0, "No forks initially");
}

// ============================================================================
// CONSENSUS ENGINE WITH RWLOCK (Thread Safety Tests)
// ============================================================================

#[tokio::test]
async fn test_consensus_engine_thread_safe() {
    let config = ConsensusConfig::default();
    let engine = Arc::new(RwLock::new(ConsensusEngine::new(config, NodeType::Validator)));
    
    // Multiple read locks should be allowed
    let engine_clone = engine.clone();
    let handle1 = tokio::spawn(async move {
        let guard = engine_clone.read().await;
        guard.get_stats()
    });
    
    let engine_clone2 = engine.clone();
    let handle2 = tokio::spawn(async move {
        let guard = engine_clone2.read().await;
        guard.get_stats()
    });
    
    let (stats1, stats2) = tokio::join!(handle1, handle2);
    
    assert!(stats1.is_ok());
    assert!(stats2.is_ok());
}
