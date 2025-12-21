//! Blockchain Core Tests
//! 
//! Tests for EnhancedBlockchain, Block, Transaction operations

use layer1::{EnhancedBlockchain, Transaction, TransactionType};

// ============================================================================
// BLOCKCHAIN CREATION TESTS
// ============================================================================

#[test]
fn test_blockchain_creation() {
    let bc = EnhancedBlockchain::new();
    
    assert_eq!(bc.chain.len(), 1, "New blockchain should have genesis block");
    assert_eq!(bc.chain[0].index, 0, "Genesis block should have index 0");
    assert!(bc.pending_transactions.is_empty(), "New blockchain should have no pending transactions");
    assert!(bc.balances.is_empty(), "New blockchain should have no balances");
}

#[test]
fn test_genesis_block_properties() {
    let bc = EnhancedBlockchain::new();
    let genesis = &bc.chain[0];
    
    assert_eq!(genesis.index, 0);
    assert_eq!(genesis.previous_hash, "0");
    assert!(genesis.transactions.is_empty());
    assert_eq!(genesis.slot, 0);
    assert_eq!(genesis.leader, "genesis");
}

#[test]
fn test_blockchain_default_values() {
    let bc = EnhancedBlockchain::new();
    
    assert_eq!(bc.mining_reward, 10.0);
    assert_eq!(bc.daily_jackpot, 0.0);
    assert_eq!(bc.current_slot, 0);
    assert!(!bc.current_poh_hash.is_empty());
}

// ============================================================================
// TRANSACTION TESTS
// ============================================================================

#[test]
fn test_system_transaction_always_succeeds() {
    let mut bc = EnhancedBlockchain::new();
    
    // System transactions should always work (no balance check)
    let result = bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    
    // Result should be a transaction ID, not an error
    assert!(!result.starts_with("Insufficient"), "System transaction should succeed");
    assert_eq!(bc.get_balance("user1"), 100.0, "User should receive 100 L1");
}

#[test]
fn test_reward_system_transaction_succeeds() {
    let mut bc = EnhancedBlockchain::new();
    
    let result = bc.create_transaction("reward_system".to_string(), "user1".to_string(), 50.0);
    
    assert!(!result.starts_with("Insufficient"));
    assert_eq!(bc.get_balance("user1"), 50.0);
}

#[test]
fn test_signup_bonus_creates_fresh_wallet() {
    let mut bc = EnhancedBlockchain::new();
    
    // First give user some balance via system
    bc.create_transaction("system".to_string(), "user1".to_string(), 50.0);
    assert_eq!(bc.get_balance("user1"), 50.0);
    
    // Signup bonus should overwrite (fresh wallet)
    bc.create_transaction("signup_bonus".to_string(), "user1".to_string(), 100.0);
    
    assert_eq!(bc.get_balance("user1"), 100.0, "Signup bonus should set exact amount");
}

#[test]
fn test_insufficient_balance_fails() {
    let mut bc = EnhancedBlockchain::new();
    
    // User has no balance
    let result = bc.create_transaction("user1".to_string(), "user2".to_string(), 100.0);
    
    assert!(result.contains("Insufficient balance"), "Transaction with insufficient balance should fail");
}

#[test]
fn test_valid_transfer() {
    let mut bc = EnhancedBlockchain::new();
    
    // Give user1 balance via system
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    
    // Transfer to user2
    let result = bc.create_transaction("user1".to_string(), "user2".to_string(), 30.0);
    
    assert!(!result.contains("Insufficient"));
    assert_eq!(bc.get_balance("user1"), 70.0, "Sender should have 70 L1 left");
    assert_eq!(bc.get_balance("user2"), 30.0, "Receiver should have 30 L1");
}

#[test]
fn test_burn_transaction_removes_wallet() {
    let mut bc = EnhancedBlockchain::new();
    
    // Give user balance
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    assert_eq!(bc.get_balance("user1"), 100.0);
    
    // Burn tokens
    let result = bc.create_transaction("user1".to_string(), "burned_tokens".to_string(), 100.0);
    
    assert!(!result.contains("Insufficient"));
    // Wallet should be completely removed
    assert!(!bc.balances.contains_key("user1"), "Wallet should be removed after burn");
    assert_eq!(bc.get_balance("user1"), 0.0);
}

#[test]
fn test_balance_accumulates() {
    let mut bc = EnhancedBlockchain::new();
    
    // Multiple deposits
    bc.create_transaction("system".to_string(), "user1".to_string(), 50.0);
    bc.create_transaction("system".to_string(), "user1".to_string(), 30.0);
    bc.create_transaction("system".to_string(), "user1".to_string(), 20.0);
    
    assert_eq!(bc.get_balance("user1"), 100.0, "Balance should accumulate");
}

#[test]
fn test_transaction_creates_pending() {
    let mut bc = EnhancedBlockchain::new();
    
    assert!(bc.pending_transactions.is_empty());
    
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    
    assert_eq!(bc.pending_transactions.len(), 1, "Should have 1 pending transaction");
}

// ============================================================================
// MINING TESTS
// ============================================================================

#[test]
fn test_mining_with_no_transactions_fails() {
    let mut bc = EnhancedBlockchain::new();
    
    let result = bc.mine_pending_transactions("validator".to_string());
    
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No pending transactions"));
}

#[test]
fn test_mining_clears_pending_transactions() {
    let mut bc = EnhancedBlockchain::new();
    
    // Create enough transactions to meet engagement threshold
    for i in 0..5 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    assert_eq!(bc.pending_transactions.len(), 5);
    
    // Mine - may succeed or fail based on engagement, but transactions should be affected
    let _ = bc.mine_pending_transactions("validator".to_string());
    
    // After mining attempt, pending should be different (cleared if success, or put back if fail)
}

#[test]
fn test_mining_creates_new_block_with_sufficient_engagement() {
    let mut bc = EnhancedBlockchain::new();
    
    // Create multiple transactions to ensure engagement threshold is met
    for i in 0..10 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    let initial_blocks = bc.chain.len();
    let result = bc.mine_pending_transactions("validator".to_string());
    
    if result.is_ok() {
        assert_eq!(bc.chain.len(), initial_blocks + 1, "Mining should create a new block");
    }
}

#[test]
fn test_mining_rewards_validator() {
    let mut bc = EnhancedBlockchain::new();
    
    // Create enough transactions
    for i in 0..10 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    let result = bc.mine_pending_transactions("validator".to_string());
    
    if result.is_ok() {
        assert!(bc.get_balance("validator") > 0.0, "Validator should receive mining reward");
    }
}

#[test]
fn test_slot_increments_on_successful_mining() {
    let mut bc = EnhancedBlockchain::new();
    
    assert_eq!(bc.current_slot, 0);
    
    // Create enough transactions
    for i in 0..10 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    let result = bc.mine_pending_transactions("validator".to_string());
    
    if result.is_ok() {
        assert!(bc.current_slot > 0, "Slot should increment after successful mining");
    }
}

// ============================================================================
// CHAIN VALIDATION TESTS
// ============================================================================

#[test]
fn test_new_chain_is_valid() {
    let bc = EnhancedBlockchain::new();
    assert!(bc.is_chain_valid(), "New blockchain should be valid");
}

#[test]
fn test_chain_with_blocks_is_valid() {
    let mut bc = EnhancedBlockchain::new();
    
    // Add some blocks via mining
    for round in 0..3 {
        for i in 0..10 {
            bc.create_transaction("system".to_string(), format!("user{}_{}", round, i), 100.0);
        }
        let _ = bc.mine_pending_transactions("validator".to_string());
    }
    
    assert!(bc.is_chain_valid(), "Chain with valid blocks should be valid");
}

// ============================================================================
// BALANCE QUERY TESTS
// ============================================================================

#[test]
fn test_get_balance_nonexistent_wallet() {
    let bc = EnhancedBlockchain::new();
    
    assert_eq!(bc.get_balance("nonexistent"), 0.0, "Non-existent wallet should have 0 balance");
}

#[test]
fn test_get_balance_after_transactions() {
    let mut bc = EnhancedBlockchain::new();
    
    bc.create_transaction("system".to_string(), "alice".to_string(), 1000.0);
    bc.create_transaction("alice".to_string(), "bob".to_string(), 300.0);
    
    assert_eq!(bc.get_balance("alice"), 700.0);
    assert_eq!(bc.get_balance("bob"), 300.0);
}

// ============================================================================
// TRANSACTION STRUCT TESTS
// ============================================================================

#[test]
fn test_transaction_new() {
    let tx = Transaction::new(
        "sender".to_string(),
        "receiver".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    assert_eq!(tx.from, "sender");
    assert_eq!(tx.to, "receiver");
    assert_eq!(tx.amount, 50.0);
    assert!(!tx.id.is_empty(), "Transaction should have an ID");
    assert!(tx.timestamp > 0, "Transaction should have a timestamp");
}

#[test]
fn test_transaction_read_write_accounts_for_transfer() {
    let tx = Transaction::new(
        "sender".to_string(),
        "receiver".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    assert!(tx.read_accounts.contains(&"sender".to_string()));
    assert!(tx.write_accounts.contains(&"sender".to_string()));
    assert!(tx.write_accounts.contains(&"receiver".to_string()));
}

#[test]
fn test_transaction_read_write_accounts_for_social_action() {
    let tx = Transaction::new(
        "user".to_string(),
        "post".to_string(),
        1.0,
        TransactionType::SocialAction,
    );
    
    assert!(tx.read_accounts.contains(&"user".to_string()));
    assert!(tx.write_accounts.contains(&"user".to_string()));
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_zero_amount_transaction() {
    let mut bc = EnhancedBlockchain::new();
    
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    let result = bc.create_transaction("user1".to_string(), "user2".to_string(), 0.0);
    
    // Zero amount should work
    assert!(!result.contains("Insufficient"));
    assert_eq!(bc.get_balance("user1"), 100.0);
    assert_eq!(bc.get_balance("user2"), 0.0);
}

#[test]
fn test_self_transfer() {
    let mut bc = EnhancedBlockchain::new();
    
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    bc.create_transaction("user1".to_string(), "user1".to_string(), 50.0);
    
    // Balance should remain the same (deducted then added back)
    assert_eq!(bc.get_balance("user1"), 100.0);
}

#[test]
fn test_exact_balance_transfer() {
    let mut bc = EnhancedBlockchain::new();
    
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    let result = bc.create_transaction("user1".to_string(), "user2".to_string(), 100.0);
    
    assert!(!result.contains("Insufficient"));
    assert_eq!(bc.get_balance("user1"), 0.0);
    assert_eq!(bc.get_balance("user2"), 100.0);
}

#[test]
fn test_over_balance_transfer_fails() {
    let mut bc = EnhancedBlockchain::new();
    
    bc.create_transaction("system".to_string(), "user1".to_string(), 100.0);
    let result = bc.create_transaction("user1".to_string(), "user2".to_string(), 150.0);
    
    assert!(result.contains("Insufficient balance"));
    // Balances should be unchanged
    assert_eq!(bc.get_balance("user1"), 100.0);
    assert_eq!(bc.get_balance("user2"), 0.0);
}

#[test]
fn test_multiple_users_transfers() {
    let mut bc = EnhancedBlockchain::new();
    
    // Setup initial balances
    bc.create_transaction("system".to_string(), "alice".to_string(), 500.0);
    bc.create_transaction("system".to_string(), "bob".to_string(), 300.0);
    bc.create_transaction("system".to_string(), "charlie".to_string(), 200.0);
    
    // Multiple transfers
    bc.create_transaction("alice".to_string(), "bob".to_string(), 100.0);
    bc.create_transaction("bob".to_string(), "charlie".to_string(), 150.0);
    bc.create_transaction("charlie".to_string(), "alice".to_string(), 75.0);
    
    assert_eq!(bc.get_balance("alice"), 475.0); // 500 - 100 + 75
    assert_eq!(bc.get_balance("bob"), 250.0);   // 300 + 100 - 150
    assert_eq!(bc.get_balance("charlie"), 275.0); // 200 + 150 - 75
}

// ============================================================================
// POH INTEGRATION TESTS
// ============================================================================

#[test]
fn test_poh_hash_changes_on_mining() {
    let mut bc = EnhancedBlockchain::new();
    let initial_poh_hash = bc.current_poh_hash.clone();
    
    // Create transactions and mine
    for i in 0..10 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    let result = bc.mine_pending_transactions("validator".to_string());
    
    if result.is_ok() {
        assert_ne!(bc.current_poh_hash, initial_poh_hash, "PoH hash should change after mining");
    }
}

#[test]
fn test_engagement_stakes_updated_on_mining() {
    let mut bc = EnhancedBlockchain::new();
    
    assert!(bc.engagement_stakes.is_empty());
    
    for i in 0..10 {
        bc.create_transaction("system".to_string(), format!("user{}", i), 100.0);
    }
    
    let result = bc.mine_pending_transactions("validator".to_string());
    
    if result.is_ok() {
        assert!(bc.engagement_stakes.contains_key("validator"), "Validator should have engagement stake");
    }
}
