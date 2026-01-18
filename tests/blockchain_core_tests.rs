//! Blockchain Core Tests
//!
//! Comprehensive tests for all core blockchain features:
//! - Genesis block creation
//! - Block creation and mining
//! - State root computation
//! - Transaction nonces
//! - Chain validation
//! - Block hashing
//! - Transactions root computation

use layer1::{EnhancedBlockchain, Transaction, TransactionType, Block};
use layer1::protocol::blockchain::{
    compute_genesis_hash,
    GENESIS_TIMESTAMP, LAMPORTS_PER_BB, Account,
};

// ============================================================================
// GENESIS BLOCK TESTS
// ============================================================================

#[test]
fn test_genesis_block_creation() {
    let blockchain = EnhancedBlockchain::new();
    
    // Genesis block should exist
    assert_eq!(blockchain.chain.len(), 1, "Should have exactly one genesis block");
    
    let genesis = &blockchain.chain[0];
    assert_eq!(genesis.index, 0, "Genesis index should be 0");
    assert_eq!(genesis.slot, 0, "Genesis slot should be 0");
    assert_eq!(genesis.timestamp, GENESIS_TIMESTAMP, "Genesis should have fixed timestamp");
}

#[test]
fn test_genesis_hash_deterministic() {
    // Genesis hash should be the same every time
    let hash1 = compute_genesis_hash();
    let hash2 = compute_genesis_hash();
    
    assert_eq!(hash1, hash2, "Genesis hash must be deterministic");
    assert_eq!(hash1.len(), 64, "Genesis hash should be 64 hex chars");
}

#[test]
fn test_genesis_previous_hash() {
    let blockchain = EnhancedBlockchain::new();
    let genesis = &blockchain.chain[0];
    
    // Genesis previous_hash should be all zeros
    assert_eq!(genesis.previous_hash, "0".repeat(64), 
        "Genesis previous_hash should be 64 zeros");
}

#[test]
fn test_zero_supply_at_genesis() {
    let blockchain = EnhancedBlockchain::new();
    
    // In 1:1 USDC-backed model, all balances start at 0
    // Tokens are only created when USDC is deposited
    assert_eq!(blockchain.actual_supply(), 0.0, 
        "Total supply should be 0 at genesis (1:1 USDC backed)");
    assert!(blockchain.validate_supply(),
        "Supply validation should pass");
}

// ============================================================================
// BLOCK CREATION TESTS
// ============================================================================

#[test]
fn test_block_creation_increments_slot() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let initial_slot = blockchain.current_slot;
    
    // Add transaction and mine
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    assert_eq!(blockchain.current_slot, initial_slot + 1, 
        "Slot should increment after mining");
}

#[test]
fn test_block_links_to_parent() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let genesis = &blockchain.chain[0];
    let block1 = &blockchain.chain[1];
    
    assert_eq!(block1.previous_hash, genesis.hash, 
        "Block 1 should link to genesis");
    assert_eq!(block1.parent_slot, genesis.slot,
        "Block 1 parent_slot should match genesis slot");
}

#[test]
fn test_block_index_sequential() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Create 3 blocks
    for i in 0..3 {
        blockchain.create_transaction("treasury".to_string(), format!("user_{}", i), 100.0);
        let _ = blockchain.mine_pending_transactions("miner".to_string());
    }
    
    for (i, block) in blockchain.chain.iter().enumerate() {
        assert_eq!(block.index as usize, i, 
            "Block index should be sequential");
    }
}

#[test]
fn test_block_hash_unique() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    blockchain.create_transaction("treasury".to_string(), "bob".to_string(), 200.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block1 = &blockchain.chain[1];
    let block2 = &blockchain.chain[2];
    
    assert_ne!(block1.hash, block2.hash, 
        "Different blocks should have different hashes");
}

#[test]
fn test_block_contains_transactions() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let tx_id = blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = &blockchain.chain[1];
    assert_eq!(block.tx_count, 1, "Block should have 1 transaction");
    assert!(!block.transactions.is_empty(), "Block transactions should not be empty");
}

// ============================================================================
// STATE ROOT TESTS
// ============================================================================

#[test]
fn test_state_root_computed() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = &blockchain.chain[1];
    assert!(!block.state_root.is_empty(), "State root should be computed");
    assert_eq!(block.state_root.len(), 64, "State root should be 64 hex chars");
}

#[test]
fn test_state_root_changes_with_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // First block
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    let state_root_1 = blockchain.chain.last().unwrap().state_root.clone();
    
    // Second block with different balance change
    blockchain.create_transaction("treasury".to_string(), "bob".to_string(), 200.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    let state_root_2 = blockchain.chain.last().unwrap().state_root.clone();
    
    assert_ne!(state_root_1, state_root_2, 
        "State roots should differ after balance changes");
}

#[test]
fn test_state_root_deterministic() {
    // Same operations should produce same state root
    let mut bc1 = EnhancedBlockchain::new();
    let mut bc2 = EnhancedBlockchain::new();
    
    bc1.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    bc2.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    
    let _ = bc1.mine_pending_transactions("miner".to_string());
    let _ = bc2.mine_pending_transactions("miner".to_string());
    
    // State roots should be the same for identical state
    let sr1 = bc1.compute_balances_hash();
    let sr2 = bc2.compute_balances_hash();
    
    assert_eq!(sr1, sr2, "State roots should be deterministic");
}

#[test]
fn test_compute_balances_hash_empty() {
    let blockchain = EnhancedBlockchain::new();
    
    // With only treasury, hash should be consistent
    let hash = blockchain.compute_balances_hash();
    assert_eq!(hash.len(), 64, "Balance hash should be 64 hex chars");
}

// ============================================================================
// TRANSACTIONS ROOT TESTS
// ============================================================================

#[test]
fn test_transactions_root_computed() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = &blockchain.chain[1];
    assert!(!block.transactions_root.is_empty(), "Transactions root should be computed");
    assert_eq!(block.transactions_root.len(), 64, "Transactions root should be 64 hex chars");
}

#[test]
fn test_transactions_root_different_for_different_txs() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Block with one tx to alice
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    let tr1 = blockchain.chain.last().unwrap().transactions_root.clone();
    
    // Block with one tx to bob (different recipient)
    blockchain.create_transaction("treasury".to_string(), "bob".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    let tr2 = blockchain.chain.last().unwrap().transactions_root.clone();
    
    assert_ne!(tr1, tr2, "Different transactions should have different roots");
}

// ============================================================================
// TRANSACTION NONCE TESTS
// ============================================================================

#[test]
fn test_transaction_nonce_assigned() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    
    let tx = &blockchain.pending_transactions[0];
    assert!(tx.nonce > 0, "Transaction should have nonce assigned");
}

#[test]
fn test_transaction_nonce_increments() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // First transaction from treasury
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let nonce1 = blockchain.pending_transactions[0].nonce;
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Second transaction from treasury
    blockchain.create_transaction("treasury".to_string(), "bob".to_string(), 100.0);
    let nonce2 = blockchain.pending_transactions[0].nonce;
    
    assert!(nonce2 > nonce1, "Nonce should increment for same sender");
}

#[test]
fn test_account_nonce_updated_after_mining() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Create account with initial state
    blockchain.get_or_create_account("sender");
    let initial_nonce = blockchain.accounts.get("sender").map(|a| a.nonce).unwrap_or(0);
    
    // Fund sender and send
    blockchain.create_transaction("treasury".to_string(), "sender".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    blockchain.create_transaction("sender".to_string(), "receiver".to_string(), 100.0);
    let tx_nonce = blockchain.pending_transactions[0].nonce;
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let final_nonce = blockchain.accounts.get("sender").map(|a| a.nonce).unwrap_or(0);
    assert_eq!(final_nonce, tx_nonce, "Account nonce should be updated after tx");
}

#[test]
fn test_transaction_with_nonce_constructor() {
    let tx = Transaction::with_nonce(
        "alice".to_string(),
        "bob".to_string(),
        50.0,
        TransactionType::Transfer,
        42,
    );
    
    assert_eq!(tx.nonce, 42, "Transaction should have explicit nonce");
    assert_eq!(tx.from, "alice");
    assert_eq!(tx.to, "bob");
    assert_eq!(tx.amount, 50.0);
}

// ============================================================================
// CHAIN VALIDATION TESTS
// ============================================================================

#[test]
fn test_chain_valid_after_creation() {
    let blockchain = EnhancedBlockchain::new();
    assert!(blockchain.is_chain_valid(), "New chain should be valid");
}

#[test]
fn test_chain_valid_after_multiple_blocks() {
    let mut blockchain = EnhancedBlockchain::new();
    
    for i in 0..5 {
        blockchain.create_transaction("treasury".to_string(), format!("user_{}", i), 100.0);
        let _ = blockchain.mine_pending_transactions("miner".to_string());
    }
    
    assert!(blockchain.is_chain_valid(), "Chain should be valid after multiple blocks");
}

#[test]
fn test_chain_length_correct() {
    let mut blockchain = EnhancedBlockchain::new();
    
    assert_eq!(blockchain.chain.len(), 1, "Initial chain has genesis only");
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    assert_eq!(blockchain.chain.len(), 2, "Chain should have 2 blocks after mining");
}

// ============================================================================
// POH (PROOF OF HISTORY) TESTS
// ============================================================================

#[test]
fn test_poh_hash_updates() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let initial_poh = blockchain.current_poh_hash.clone();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    assert_ne!(blockchain.current_poh_hash, initial_poh, 
        "PoH hash should change after mining");
}

#[test]
fn test_block_contains_poh_hash() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = &blockchain.chain[1];
    assert!(!block.poh_hash.is_empty(), "Block should have PoH hash");
    assert_eq!(block.poh_hash.len(), 64, "PoH hash should be 64 hex chars");
}

// ============================================================================
// RECENT BLOCKHASH TESTS
// ============================================================================

#[test]
fn test_recent_blockhash_stored() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let (slot, hash) = blockchain.get_recent_blockhash().expect("Should have recent blockhash");
    assert!(slot > 0, "Slot should be > 0");
    assert_eq!(hash.len(), 64, "Blockhash should be 64 hex chars");
}

#[test]
fn test_blockhash_validity() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block_hash = &blockchain.chain.last().unwrap().hash;
    assert!(blockchain.is_blockhash_valid(block_hash), 
        "Recent blockhash should be valid");
    
    assert!(!blockchain.is_blockhash_valid("invalid_hash"), 
        "Invalid hash should not be valid");
}

// ============================================================================
// BLOCK STRUCT TESTS
// ============================================================================

#[test]
fn test_block_calculate_hash() {
    let block = Block {
        index: 1,
        timestamp: 1234567890,
        previous_hash: "0".repeat(64),
        hash: String::new(),
        slot: 1,
        poh_hash: "a".repeat(64),
        parent_slot: 0,
        state_root: "b".repeat(64),
        transactions_root: "c".repeat(64),
        sequencer: "test_sequencer".to_string(),
        leader: "test_leader".to_string(),
        financial_txs: vec![],
        social_txs: vec![],
        transactions: vec![],
        engagement_score: 10.0,
        tx_count: 0,
    };
    
    let hash = block.calculate_hash();
    assert_eq!(hash.len(), 64, "Block hash should be 64 hex chars");
}

#[test]
fn test_block_hash_deterministic() {
    let block = Block {
        index: 1,
        timestamp: 1234567890,
        previous_hash: "0".repeat(64),
        hash: String::new(),
        slot: 1,
        poh_hash: "a".repeat(64),
        parent_slot: 0,
        state_root: "b".repeat(64),
        transactions_root: "c".repeat(64),
        sequencer: "test".to_string(),
        leader: "test".to_string(),
        financial_txs: vec![],
        social_txs: vec![],
        transactions: vec![],
        engagement_score: 0.0,
        tx_count: 0,
    };
    
    let hash1 = block.calculate_hash();
    let hash2 = block.calculate_hash();
    
    assert_eq!(hash1, hash2, "Block hash calculation should be deterministic");
}

// ============================================================================
// TRANSACTION TYPE TESTS
// ============================================================================

#[test]
fn test_transaction_type_is_financial() {
    assert!(TransactionType::Transfer.is_financial());
    assert!(TransactionType::BetPlacement.is_financial());
    assert!(TransactionType::BetResolution.is_financial());
    assert!(TransactionType::StakeDeposit.is_financial());
    assert!(TransactionType::StakeWithdraw.is_financial());
    
    assert!(!TransactionType::SocialAction.is_financial());
}

#[test]
fn test_transaction_type_is_social() {
    assert!(TransactionType::SocialAction.is_social());
    assert!(!TransactionType::Transfer.is_social());
}

#[test]
fn test_transaction_type_default() {
    let tx_type: TransactionType = Default::default();
    assert_eq!(tx_type, TransactionType::Transfer, "Default tx type should be Transfer");
}

// ============================================================================
// TWO-LANE TRANSACTION MODEL TESTS
// ============================================================================

#[test]
fn test_financial_and_social_separation() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Create financial transaction
    blockchain.create_transaction_typed(
        "treasury".to_string(),
        "alice".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = blockchain.chain.last().unwrap();
    assert!(!block.financial_txs.is_empty(), "Should have financial txs");
}

// ============================================================================
// ACCOUNT MODEL TESTS
// ============================================================================

#[test]
fn test_account_creation() {
    let account = Account::new("owner".to_string(), 1_000_000, 0);
    
    assert_eq!(account.lamports, 1_000_000);
    assert_eq!(account.nonce, 0);
    assert_eq!(account.owner, "owner");
    assert_eq!(account.created_slot, 0);
}

#[test]
fn test_account_from_bb_balance() {
    let account = Account::from_bb_balance("owner".to_string(), 1.5, 0);
    
    assert_eq!(account.lamports, (1.5 * LAMPORTS_PER_BB as f64) as u64);
    assert_eq!(account.balance_bb(), 1.5);
}

#[test]
fn test_account_debit_credit() {
    let mut account = Account::new("owner".to_string(), 1_000_000, 0);
    
    // Credit
    account.credit(500_000, 1);
    assert_eq!(account.lamports, 1_500_000);
    assert_eq!(account.last_modified_slot, 1);
    
    // Debit
    account.debit(300_000, 2).unwrap();
    assert_eq!(account.lamports, 1_200_000);
    assert_eq!(account.last_modified_slot, 2);
}

#[test]
fn test_account_debit_insufficient() {
    let mut account = Account::new("owner".to_string(), 100, 0);
    
    let result = account.debit(200, 1);
    assert!(result.is_err(), "Debit should fail with insufficient balance");
}

#[test]
fn test_account_nonce_validation() {
    let account = Account::new("owner".to_string(), 1_000_000, 0);
    
    // Nonce 0 has been used (initial state)
    assert!(!account.is_nonce_valid(0), "Nonce 0 should be invalid");
    assert!(account.is_nonce_valid(1), "Nonce 1 should be valid");
    assert!(account.is_nonce_valid(100), "Higher nonce should be valid");
}

#[test]
fn test_account_increment_nonce() {
    let mut account = Account::new("owner".to_string(), 1_000_000, 0);
    
    let new_nonce = account.increment_nonce();
    assert_eq!(new_nonce, 1);
    assert_eq!(account.nonce, 1);
    
    let new_nonce2 = account.increment_nonce();
    assert_eq!(new_nonce2, 2);
}

// ============================================================================
// ENGAGEMENT SCORE TESTS
// ============================================================================

#[test]
fn test_block_has_engagement_score() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let block = blockchain.chain.last().unwrap();
    assert!(block.engagement_score >= 0.0, "Block should have engagement score");
}

// ============================================================================
// PENDING TRANSACTIONS TESTS
// ============================================================================

#[test]
fn test_pending_transactions_cleared_after_mining() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "alice".to_string(), 100.0);
    assert!(!blockchain.pending_transactions.is_empty());
    
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    assert!(blockchain.pending_transactions.is_empty(), 
        "Pending transactions should be cleared after mining");
}

#[test]
fn test_mine_empty_pending_returns_error() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let result = blockchain.mine_pending_transactions("miner".to_string());
    assert!(result.is_err(), "Mining with no pending txs should error");
}
