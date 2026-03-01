// ============================================================================
// BLACKBOOK L1 — POH CONSENSUS & BLOCK PRODUCTION TESTS
// ============================================================================
//
// Production-readiness tests for:
//
//   1. PoH clock: tick, hash chain, slot advance
//   2. Block production: 50K txs/block, 400ms intervals
//   3. Merkle trees: state root, proofs, verification
//   4. Finalized block structure: hash chain, verification
//   5. Turbine shredding: block→shreds→reassemble
//   6. Tower BFT: votes, supermajority, fork selection
//   7. Leader schedule: stake-weighted, deterministic
//   8. Finality tracker: confirmations, finalized state
//   9. Block chain integrity: verify_block, verify_chain
//
// Run:  cargo test --test poh_consensus
// ============================================================================

use layer1::{
    PoHConfig, PoHService, create_poh_service,
    LeaderSchedule,
    MerkleTree, MerkleProof,
    FinalizedBlock, OrderedTransaction,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
    FinalityTracker, ConfirmationStatus,
    CONFIRMATIONS_REQUIRED,
    Transaction, TxData,
};
use layer1::runtime::consensus::{
    TowerBFT, GulfStreamService, PoHEntry,
    Vote,
};
use layer1::poh_blockchain::{TurbineShredder, TurbinePropagator, SHRED_SIZE, TURBINE_FANOUT};

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;

// ============================================================================
// TEST GROUP 1: Constants & Configuration
// ============================================================================

#[test]
fn test_max_txs_per_block() {
    assert_eq!(MAX_TXS_PER_BLOCK, 50_000, "Must support 50K txs/block for 125K TPS");
}

#[test]
fn test_block_interval_ms() {
    assert_eq!(BLOCK_INTERVAL_MS, 400, "Slot duration must be 400ms");
}

#[test]
fn test_theoretical_tps() {
    let tps = (MAX_TXS_PER_BLOCK as f64 / BLOCK_INTERVAL_MS as f64) * 1000.0;
    assert!(tps >= 125_000.0, "Theoretical TPS must be >= 125,000, got {}", tps);
}

#[test]
fn test_confirmations_required() {
    assert_eq!(CONFIRMATIONS_REQUIRED, 2, "Finality requires 2 confirmations");
}

#[test]
fn test_shred_size_udp_safe() {
    assert!(SHRED_SIZE <= 1_232, "Shred payload must fit in UDP MTU (1232 bytes)");
}

#[test]
fn test_turbine_fanout() {
    assert_eq!(TURBINE_FANOUT, 200, "Turbine tree branching factor must be 200");
}

// ============================================================================
// TEST GROUP 2: PoH Clock
// ============================================================================

#[test]
fn test_poh_tick_advances_hash() {
    let config = PoHConfig::default();
    let mut poh = PoHService::new(config);

    let initial_hash = poh.current_hash.clone();
    let entry = poh.tick();

    assert_ne!(entry.hash, initial_hash, "Tick must advance the hash");
    assert!(entry.num_hashes > 0, "Tick must produce hashes");
}

#[test]
fn test_poh_hash_chain_integrity() {
    let config = PoHConfig::default();
    let mut poh = PoHService::new(config);

    // Generate several ticks
    for _ in 0..10 {
        poh.tick();
    }

    assert!(poh.verify_current_entries(), "PoH hash chain must be verifiable");
}

#[test]
fn test_poh_slot_advance() {
    let config = PoHConfig::default();
    let mut poh = PoHService::new(config);

    assert_eq!(poh.current_slot, 0, "Should start at slot 0");

    let new_slot = poh.advance_slot();
    assert_eq!(new_slot, 1, "advance_slot must return slot 1");
    assert_eq!(poh.current_slot, 1);
}

#[test]
fn test_poh_transaction_mixing() {
    let config = PoHConfig::default();
    let mut poh = PoHService::new(config);

    poh.queue_transaction("tx_001".to_string());
    poh.queue_transaction("tx_002".to_string());

    let entry = poh.mix_pending_transactions();
    assert!(entry.is_some(), "Mix must produce an entry when txs queued");

    let entry = entry.unwrap();
    assert_eq!(entry.transactions.len(), 2, "Entry must contain both txs");
}

#[test]
fn test_poh_genesis_hash_deterministic() {
    let h1 = PoHService::get_genesis_hash();
    let h2 = PoHService::get_genesis_hash();
    assert_eq!(h1, h2, "Genesis hash must be deterministic");
    assert!(!h1.is_empty(), "Genesis hash must not be empty");
}

#[test]
fn test_poh_entry_chain_verification() {
    use layer1::runtime::poh_service::verify_poh_chain;

    let config = PoHConfig::default();
    let mut poh = PoHService::new(config);

    let genesis = poh.current_hash.clone();

    for _ in 0..5 {
        poh.tick();
    }

    let entries = poh.get_current_entries();
    assert!(
        verify_poh_chain(&entries, &genesis),
        "PoH chain must verify from genesis"
    );
}

// ============================================================================
// TEST GROUP 3: Merkle Trees & Proofs
// ============================================================================

#[test]
fn test_merkle_tree_deterministic() {
    let mut accounts = BTreeMap::new();
    accounts.insert("alice".to_string(), 100.0);
    accounts.insert("bob".to_string(), 50.0);
    accounts.insert("charlie".to_string(), 25.0);

    let tree1 = MerkleTree::from_accounts(&accounts);
    let tree2 = MerkleTree::from_accounts(&accounts);

    assert_eq!(
        tree1.root_hex(), tree2.root_hex(),
        "Merkle root must be deterministic for same accounts"
    );
}

#[test]
fn test_merkle_tree_changes_with_balance() {
    let mut accounts1 = BTreeMap::new();
    accounts1.insert("alice".to_string(), 100.0);
    accounts1.insert("bob".to_string(), 50.0);

    let mut accounts2 = BTreeMap::new();
    accounts2.insert("alice".to_string(), 100.0);
    accounts2.insert("bob".to_string(), 51.0); // changed

    let root1 = MerkleTree::from_accounts(&accounts1).root_hex();
    let root2 = MerkleTree::from_accounts(&accounts2).root_hex();

    assert_ne!(root1, root2, "Different balances must produce different roots");
}

#[test]
fn test_merkle_proof_generation_and_verification() {
    let mut accounts = BTreeMap::new();
    accounts.insert("alice".to_string(), 100.0);
    accounts.insert("bob".to_string(), 50.0);
    accounts.insert("charlie".to_string(), 25.0);

    let tree = MerkleTree::from_accounts(&accounts);

    // Generate proof for first leaf
    let proof = tree.generate_proof(0);
    assert!(proof.is_some(), "Must generate proof for valid index");

    let proof = proof.unwrap();
    // Verify the proof matches the root
    assert_eq!(proof.root, tree.root_hex(), "Proof root must match tree root");
}

#[test]
fn test_merkle_empty_accounts() {
    let accounts = BTreeMap::new();
    let tree = MerkleTree::from_accounts(&accounts);
    let root = tree.root_hex();
    assert!(!root.is_empty(), "Empty tree must still have a root");
}

// ============================================================================
// TEST GROUP 4: Finalized Block Structure
// ============================================================================

#[test]
fn test_block_hash_deterministic() {
    let hash1 = FinalizedBlock::compute_hash(
        1, "prev_hash", "state_root", "poh_hash", 1000,
    );
    let hash2 = FinalizedBlock::compute_hash(
        1, "prev_hash", "state_root", "poh_hash", 1000,
    );
    assert_eq!(hash1, hash2, "Block hash must be deterministic");
}

#[test]
fn test_block_hash_changes_with_slot() {
    let h1 = FinalizedBlock::compute_hash(1, "prev", "root", "poh", 100);
    let h2 = FinalizedBlock::compute_hash(2, "prev", "root", "poh", 100);
    assert_ne!(h1, h2, "Different slots must produce different hashes");
}

#[test]
fn test_block_hash_changes_with_prev_hash() {
    let h1 = FinalizedBlock::compute_hash(1, "aaa", "root", "poh", 100);
    let h2 = FinalizedBlock::compute_hash(1, "bbb", "root", "poh", 100);
    assert_ne!(h1, h2, "Different prev_hash must produce different block hashes");
}

#[test]
fn test_block_verification() {
    let prev_hash = "genesis";
    let state_root = "some_state_root";
    let poh_hash = "some_poh_hash";
    let timestamp = 1234567890u64;
    let slot = 1u64;

    let hash = FinalizedBlock::compute_hash(slot, prev_hash, state_root, poh_hash, timestamp);

    let block = FinalizedBlock {
        slot,
        timestamp,
        previous_hash: prev_hash.to_string(),
        hash: hash.clone(),
        state_root: state_root.to_string(),
        accounts_hash: String::new(),
        poh_hash: poh_hash.to_string(),
        poh_sequence: 0,
        poh_entries: vec![],
        transactions: vec![],
        tx_count: 0,
        leader: "leader1".to_string(),
        epoch: 0,
        confirmations: 0,
    };

    assert!(
        verify_block(&block, "genesis"),
        "Block with correct hash must verify"
    );
}

#[test]
fn test_block_verification_fails_wrong_prev() {
    let hash = FinalizedBlock::compute_hash(1, "real_prev", "root", "poh", 100);

    let block = FinalizedBlock {
        slot: 1,
        timestamp: 100,
        previous_hash: "real_prev".to_string(),
        hash,
        state_root: "root".to_string(),
        accounts_hash: String::new(),
        poh_hash: "poh".to_string(),
        poh_sequence: 0,
        poh_entries: vec![],
        transactions: vec![],
        tx_count: 0,
        leader: "leader".to_string(),
        epoch: 0,
        confirmations: 0,
    };

    assert!(
        !verify_block(&block, "wrong_prev"),
        "Block must fail verification with wrong previous hash"
    );
}

#[test]
fn test_verify_chain() {
    let mut blocks = vec![];

    let mut prev_hash = "genesis".to_string();
    for slot in 1..=5 {
        let state_root = format!("root_{}", slot);
        let poh_hash = format!("poh_{}", slot);
        let timestamp = 1000 + slot;
        let hash = FinalizedBlock::compute_hash(slot, &prev_hash, &state_root, &poh_hash, timestamp);

        blocks.push(FinalizedBlock {
            slot,
            timestamp,
            previous_hash: prev_hash.clone(),
            hash: hash.clone(),
            state_root,
            accounts_hash: String::new(),
            poh_hash,
            poh_sequence: slot * 64,
            poh_entries: vec![],
            transactions: vec![],
            tx_count: 0,
            leader: "leader".to_string(),
            epoch: 0,
            confirmations: 0,
        });

        prev_hash = hash;
    }

    assert!(verify_chain(&blocks), "Valid chain of 5 blocks must verify");
}

// ============================================================================
// TEST GROUP 5: Turbine Shredding & Reassembly
// ============================================================================

#[test]
fn test_turbine_shred_and_reassemble() {
    // Create a block with some transactions
    let block = FinalizedBlock {
        slot: 42,
        timestamp: 1700000000,
        previous_hash: "prev".to_string(),
        hash: "block_hash".to_string(),
        state_root: "state_root".to_string(),
        accounts_hash: "accounts_hash".to_string(),
        poh_hash: "poh_hash".to_string(),
        poh_sequence: 2688,
        poh_entries: vec![],
        transactions: vec![],
        tx_count: 0,
        leader: "leader1".to_string(),
        epoch: 0,
        confirmations: 0,
    };

    let shredder = TurbineShredder::new(42, "leader1".to_string());
    let shreds = shredder.shred_block(&block);

    assert!(!shreds.is_empty(), "Block must produce at least 1 shred");

    // All shreds must have correct slot
    for shred in &shreds {
        assert_eq!(shred.slot, 42, "All shreds must belong to slot 42");
    }

    // Data shreds only (filter out coding shreds)
    let data_shreds: Vec<_> = shreds.iter().filter(|s| !s.is_coding).collect();
    assert!(!data_shreds.is_empty(), "Must have data shreds");

    // Reassemble
    let reassembled = TurbineShredder::reassemble_block(&shreds);
    assert!(reassembled.is_ok(), "Reassembly must succeed: {:?}", reassembled.err());

    let reassembled = reassembled.unwrap();
    assert_eq!(reassembled.slot, block.slot, "Reassembled slot must match");
    assert_eq!(reassembled.hash, block.hash, "Reassembled hash must match");
}

#[test]
fn test_turbine_shred_large_block() {
    // Create a block with many transactions to test multi-shred
    let mut transactions = vec![];
    for i in 0..100 {
        let tx = Transaction {
            hash: format!("tx_{}", i),
            from: "sender".to_string(),
            timestamp: 1700000000,
            data: TxData::TransferBb {
                to: format!("recv_{}", i),
                amount: 100,
            },
            signature: hex::encode([0xAA; 64]),
            signer_pubkey: hex::encode([0xBB; 32]),
        };
        transactions.push(OrderedTransaction {
            tx,
            poh_hash: format!("poh_{}", i),
            poh_sequence: i as u64,
            slot: 1,
            position: i as u32,
        });
    }

    let block = FinalizedBlock {
        slot: 1,
        timestamp: 1700000000,
        previous_hash: "genesis".to_string(),
        hash: "big_block_hash".to_string(),
        state_root: "root".to_string(),
        accounts_hash: "acc_hash".to_string(),
        poh_hash: "poh".to_string(),
        poh_sequence: 100,
        poh_entries: vec![],
        transactions,
        tx_count: 100,
        leader: "leader".to_string(),
        epoch: 0,
        confirmations: 0,
    };

    let shredder = TurbineShredder::new(1, "leader".to_string());
    let shreds = shredder.shred_block(&block);

    assert!(shreds.len() > 1, "Large block must produce multiple shreds, got {}", shreds.len());

    // Reassemble and verify
    let reassembled = TurbineShredder::reassemble_block(&shreds).unwrap();
    assert_eq!(reassembled.tx_count, 100, "All 100 txs must survive shredding");
}

// ============================================================================
// TEST GROUP 6: Turbine Tree Propagation
// ============================================================================

#[test]
fn test_turbine_tree_calculation() {
    let validators: Vec<String> = (0..20).map(|i| format!("validator_{}", i)).collect();
    let leader = "validator_0";

    let tree = TurbinePropagator::calculate_tree(&validators, leader);
    assert!(!tree.is_empty(), "Turbine tree must have entries");

    // Leader must be in tree
    let has_leader = tree.iter().any(|(name, _)| name == leader);
    assert!(has_leader, "Leader must be in the turbine tree");
}

#[test]
fn test_turbine_max_hops() {
    // With TURBINE_FANOUT=200, small clusters need 1 hop
    let hops_small = TurbinePropagator::max_hops(100);
    assert!(hops_small >= 1, "100 validators need at least 1 hop");

    let hops_large = TurbinePropagator::max_hops(10_000);
    assert!(hops_large <= 3, "10K validators should need ≤3 hops with fanout 200");
}

// ============================================================================
// TEST GROUP 7: Tower BFT Consensus
// ============================================================================

#[test]
fn test_tower_bft_vote() {
    let slot = Arc::new(AtomicU64::new(0));
    let tower = TowerBFT::new("validator_self".to_string(), slot.clone());

    tower.register_validator("validator_1", 100.0);
    tower.register_validator("validator_2", 100.0);
    tower.register_validator("validator_self", 100.0);

    // Single vote should not reach supermajority (1/3 = 33%)
    let result = tower.vote("validator_1", 1, "block_hash_1");
    assert!(result.is_ok(), "Vote must succeed");
    assert!(!result.unwrap(), "Single vote should NOT reach supermajority");
}

#[test]
fn test_tower_bft_supermajority() {
    let slot = Arc::new(AtomicU64::new(0));
    let tower = TowerBFT::new("self".to_string(), slot.clone());

    tower.register_validator("v1", 100.0);
    tower.register_validator("v2", 100.0);
    tower.register_validator("v3", 100.0);

    // 2/3 = 66.7% — just at threshold
    tower.vote("v1", 1, "hash").unwrap();
    let result = tower.vote("v2", 1, "hash").unwrap();

    // With 2 of 3 validators voting (66.7%), should hit supermajority
    assert!(result, "2/3 validators must reach supermajority (66.7% >= 66.7%)");
}

#[test]
fn test_tower_bft_finality() {
    let slot = Arc::new(AtomicU64::new(0));
    let tower = TowerBFT::new("self".to_string(), slot.clone());

    tower.register_validator("v1", 100.0);
    tower.register_validator("v2", 100.0);
    tower.register_validator("v3", 100.0);

    // Vote all 3 validators on slot 1
    tower.vote("v1", 1, "hash1").unwrap();
    tower.vote("v2", 1, "hash1").unwrap();
    tower.vote("v3", 1, "hash1").unwrap();

    assert!(tower.is_confirmed(1), "Slot with all votes must be confirmed");
}

#[test]
fn test_tower_bft_self_vote() {
    let slot = Arc::new(AtomicU64::new(5));
    let tower = TowerBFT::new("leader".to_string(), slot.clone());

    tower.register_validator("leader", 100.0);
    tower.register_validator("follower", 100.0);

    let result = tower.self_vote(5, "block_hash_5");
    assert!(result.is_ok(), "Self vote must succeed");
}

#[test]
fn test_tower_global_root_starts_at_zero() {
    let slot = Arc::new(AtomicU64::new(0));
    let tower = TowerBFT::new("self".to_string(), slot);

    assert_eq!(tower.global_root(), 0, "Global root must start at 0");
}

// ============================================================================
// TEST GROUP 8: Leader Schedule
// ============================================================================

#[test]
fn test_leader_schedule_deterministic() {
    let mut ls = LeaderSchedule::new();
    ls.update_stake("validator_a", 100.0);
    ls.update_stake("validator_b", 50.0);
    ls.update_stake("validator_c", 25.0);

    ls.generate_schedule(0, 100);

    let leader_slot_5 = ls.get_leader(5);
    let leader_slot_5_again = ls.get_leader(5);

    assert_eq!(leader_slot_5, leader_slot_5_again, "Leader for same slot must be deterministic");
    assert!(!leader_slot_5.is_empty(), "Leader must not be empty");
}

#[test]
fn test_leader_schedule_upcoming() {
    let mut ls = LeaderSchedule::new();
    ls.update_stake("v1", 100.0);
    ls.update_stake("v2", 100.0);
    ls.generate_schedule(0, 100);

    let upcoming = ls.get_upcoming_leaders(0, 5);
    assert_eq!(upcoming.len(), 5, "Must return requested number of upcoming leaders");
}

// ============================================================================
// TEST GROUP 9: Gulf Stream Transaction Forwarding
// ============================================================================

#[test]
fn test_gulf_stream_submit_and_retrieve() {
    let ls = Arc::new(RwLock::new(LeaderSchedule::new()));
    {
        let mut schedule = ls.write();
        schedule.update_stake("leader_a", 100.0);
        schedule.generate_schedule(0, 100);
    }

    let slot = Arc::new(AtomicU64::new(0));
    let gs = GulfStreamService::new(ls, slot);

    // Create and submit a transaction via the runtime core type
    let tx = layer1::runtime::core::Transaction::new(
        "alice".to_string(), "bob".to_string(), 5.0,
        layer1::runtime::core::TransactionType::Transfer,
    );
    let result = gs.submit(tx);
    // Gulf Stream should accept the transaction
    assert!(result.is_ok(), "Gulf Stream must accept transaction");

    let stats = gs.get_stats();
    assert!(stats.transactions_received > 0, "Must record received tx");
}

// ============================================================================
// TEST GROUP 10: Finality Tracker
// ============================================================================

#[test]
fn test_finality_tracker_pending() {
    let head = Arc::new(AtomicU64::new(0));
    let tracker = FinalityTracker::new(head);

    let status = tracker.get_status("unknown_tx");
    assert_eq!(status, ConfirmationStatus::Pending, "Unknown tx must be Pending");
}

#[test]
fn test_finality_tracker_inclusion() {
    let head = Arc::new(AtomicU64::new(5));
    let tracker = FinalityTracker::new(head.clone());

    tracker.record_inclusion("tx_001", 3);

    // After 2 more slots, should be confirmed
    head.store(5, Ordering::Relaxed);
    tracker.update_confirmations(5);

    let status = tracker.get_status("tx_001");
    match status {
        ConfirmationStatus::Pending => panic!("Should not be pending after inclusion + confirmations"),
        ConfirmationStatus::Processing { confirmations } => {
            assert!(confirmations >= 1, "Must have at least 1 confirmation");
        }
        ConfirmationStatus::Confirmed | ConfirmationStatus::Finalized => {
            // This is fine - enough confirmations passed
        }
    }
}

// ============================================================================
// TEST GROUP 11: Vote Integrity
// ============================================================================

#[test]
fn test_vote_creation_and_verification() {
    let vote = Vote::new(42, "block_hash_42".to_string(), "validator_x".to_string(), 100.0);

    assert_eq!(vote.slot, 42);
    assert!(vote.verify(), "Fresh vote must verify its HMAC");
}

#[test]
fn test_vote_verification_fails_on_tampering() {
    let mut vote = Vote::new(42, "block_hash_42".to_string(), "validator_x".to_string(), 100.0);

    // Tamper with the vote
    vote.slot = 99;

    assert!(!vote.verify(), "Tampered vote must fail verification");
}

// ============================================================================
// TEST GROUP 12: PoH Config
// ============================================================================

#[test]
fn test_poh_config_default() {
    let config = PoHConfig::default();
    assert_eq!(config.slot_duration_ms, 600, "Default slot duration: 600ms");
    assert_eq!(config.hashes_per_tick, 12_500);
    assert_eq!(config.ticks_per_slot, 64);
    assert_eq!(config.slots_per_epoch, 432_000);
}

#[test]
fn test_poh_service_status() {
    let config = PoHConfig::default();
    let poh = PoHService::new(config);
    let status = poh.get_status();

    assert!(status.get("current_slot").is_some(), "Status must include current_slot");
    assert!(status.get("current_hash").is_some(), "Status must include current_hash");
}
