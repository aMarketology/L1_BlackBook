//! Wallet and Transfer Tests for Layer1
//! 
//! Tests for wallet operations including:
//! - Balance queries
//! - Transfer operations
//! - Wallet creation/deletion flows
//! - System transactions (signup bonus, rewards)
//! - Burn operations

use layer1::{EnhancedBlockchain, Transaction, TransactionType};

// ============================================================================
// BALANCE QUERY TESTS
// ============================================================================

#[test]
fn test_get_balance_non_existent() {
    let blockchain = EnhancedBlockchain::new();
    
    let balance = blockchain.get_balance("non_existent_wallet");
    assert_eq!(balance, 0.0, "Non-existent wallet should have 0 balance");
}

#[test]
fn test_get_balance_after_signup() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Simulate signup bonus
    let _ = blockchain.create_transaction(
        "signup_bonus".to_string(),
        "new_user_wallet".to_string(),
        100.0,
    );
    
    let balance = blockchain.get_balance("new_user_wallet");
    assert_eq!(balance, 100.0, "New user should have signup bonus");
}

#[test]
fn test_get_balance_multiple_wallets() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Give different amounts to different wallets
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "wallet_a".to_string(), 100.0);
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "wallet_b".to_string(), 200.0);
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "wallet_c".to_string(), 50.0);
    
    assert_eq!(blockchain.get_balance("wallet_a"), 100.0);
    assert_eq!(blockchain.get_balance("wallet_b"), 200.0);
    assert_eq!(blockchain.get_balance("wallet_c"), 50.0);
}

// ============================================================================
// TRANSFER TESTS
// ============================================================================

#[test]
fn test_successful_transfer() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Setup: give sender initial balance
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "sender".to_string(), 100.0);
    
    // Perform transfer
    let tx_id = blockchain.create_transaction(
        "sender".to_string(),
        "receiver".to_string(),
        30.0,
    );
    
    // Verify successful transfer (not an error message)
    assert!(!tx_id.contains("Insufficient"), "Transfer should succeed");
    
    // Verify balances
    assert_eq!(blockchain.get_balance("sender"), 70.0);
    assert_eq!(blockchain.get_balance("receiver"), 30.0);
}

#[test]
fn test_transfer_exact_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "sender".to_string(), 100.0);
    let tx_id = blockchain.create_transaction("sender".to_string(), "receiver".to_string(), 100.0);
    
    assert!(!tx_id.contains("Insufficient"), "Transfer of exact balance should succeed");
    assert_eq!(blockchain.get_balance("sender"), 0.0);
    assert_eq!(blockchain.get_balance("receiver"), 100.0);
}

#[test]
fn test_transfer_insufficient_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "sender".to_string(), 50.0);
    let tx_id = blockchain.create_transaction("sender".to_string(), "receiver".to_string(), 100.0);
    
    assert!(tx_id.contains("Insufficient"), "Should fail with insufficient balance");
    assert_eq!(blockchain.get_balance("sender"), 50.0, "Sender balance should be unchanged");
    assert_eq!(blockchain.get_balance("receiver"), 0.0, "Receiver should not receive anything");
}

#[test]
fn test_transfer_zero_amount() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "sender".to_string(), 100.0);
    let tx_id = blockchain.create_transaction("sender".to_string(), "receiver".to_string(), 0.0);
    
    // Zero transfer should succeed (system doesn't prevent it)
    assert!(!tx_id.contains("Insufficient"));
    assert_eq!(blockchain.get_balance("sender"), 100.0);
    assert_eq!(blockchain.get_balance("receiver"), 0.0);
}

#[test]
fn test_multiple_transfers() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "alice".to_string(), 1000.0);
    
    // Alice sends to multiple recipients
    let _ = blockchain.create_transaction("alice".to_string(), "bob".to_string(), 100.0);
    let _ = blockchain.create_transaction("alice".to_string(), "charlie".to_string(), 200.0);
    let _ = blockchain.create_transaction("alice".to_string(), "david".to_string(), 50.0);
    
    assert_eq!(blockchain.get_balance("alice"), 650.0);
    assert_eq!(blockchain.get_balance("bob"), 100.0);
    assert_eq!(blockchain.get_balance("charlie"), 200.0);
    assert_eq!(blockchain.get_balance("david"), 50.0);
}

#[test]
fn test_chained_transfers() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "alice".to_string(), 500.0);
    
    // Alice -> Bob -> Charlie
    let _ = blockchain.create_transaction("alice".to_string(), "bob".to_string(), 300.0);
    let _ = blockchain.create_transaction("bob".to_string(), "charlie".to_string(), 200.0);
    
    assert_eq!(blockchain.get_balance("alice"), 200.0);
    assert_eq!(blockchain.get_balance("bob"), 100.0);
    assert_eq!(blockchain.get_balance("charlie"), 200.0);
}

#[test]
fn test_transfer_to_self() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "self_sender".to_string(), 100.0);
    let _ = blockchain.create_transaction("self_sender".to_string(), "self_sender".to_string(), 50.0);
    
    // Self-transfer should maintain balance (deduct then add back)
    assert_eq!(blockchain.get_balance("self_sender"), 100.0);
}

// ============================================================================
// SYSTEM TRANSACTION TESTS
// ============================================================================

#[test]
fn test_system_transaction_always_succeeds() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // System transactions should work even with no prior balance
    let tx_id = blockchain.create_transaction(
        "system".to_string(),
        "new_wallet".to_string(),
        1000000.0,
    );
    
    assert!(!tx_id.contains("Insufficient"));
    assert_eq!(blockchain.get_balance("new_wallet"), 1000000.0);
}

#[test]
fn test_reward_system_transaction() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let tx_id = blockchain.create_transaction(
        "reward_system".to_string(),
        "miner_wallet".to_string(),
        25.0,
    );
    
    assert!(!tx_id.contains("Insufficient"));
    assert_eq!(blockchain.get_balance("miner_wallet"), 25.0);
}

#[test]
fn test_signup_bonus_transaction() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let tx_id = blockchain.create_transaction(
        "signup_bonus".to_string(),
        "fresh_wallet".to_string(),
        210.0,
    );
    
    assert!(!tx_id.contains("Insufficient"));
    assert_eq!(blockchain.get_balance("fresh_wallet"), 210.0);
}

#[test]
fn test_multiple_signup_bonuses() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // First signup bonus
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "wallet".to_string(), 100.0);
    assert_eq!(blockchain.get_balance("wallet"), 100.0);
    
    // Second signup bonus (replaces due to signup_bonus logic)
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "wallet".to_string(), 200.0);
    // With the insert logic in create_transaction for signup_bonus, it overwrites
    assert_eq!(blockchain.get_balance("wallet"), 200.0);
}

// ============================================================================
// BURN TESTS
// ============================================================================

#[test]
fn test_burn_tokens() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "to_delete".to_string(), 500.0);
    assert_eq!(blockchain.get_balance("to_delete"), 500.0);
    
    // Burn tokens by sending to burned_tokens
    let tx_id = blockchain.create_transaction(
        "to_delete".to_string(),
        "burned_tokens".to_string(),
        500.0,
    );
    
    assert!(!tx_id.contains("Insufficient"));
    
    // Wallet should be removed from balances
    assert_eq!(blockchain.get_balance("to_delete"), 0.0);
}

#[test]
fn test_burn_partial_tokens() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "partial_burn".to_string(), 500.0);
    
    // Burn only part of the tokens
    let tx_id = blockchain.create_transaction(
        "partial_burn".to_string(),
        "burned_tokens".to_string(),
        300.0,
    );
    
    assert!(!tx_id.contains("Insufficient"));
    // With the current implementation, burning removes the wallet entirely
    // Check the implementation behavior
    assert_eq!(blockchain.get_balance("partial_burn"), 0.0);
}

// ============================================================================
// TRANSACTION TYPE TESTS
// ============================================================================

#[test]
fn test_transaction_new_transfer() {
    let tx = Transaction::new(
        "from_wallet".to_string(),
        "to_wallet".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    assert_eq!(tx.from, "from_wallet");
    assert_eq!(tx.to, "to_wallet");
    assert_eq!(tx.amount, 100.0);
    assert!(matches!(tx.tx_type, TransactionType::Transfer));
    assert!(!tx.id.is_empty());
    assert!(tx.timestamp > 0);
    assert!(tx.read_accounts.contains(&"from_wallet".to_string()));
    assert!(tx.write_accounts.contains(&"from_wallet".to_string()));
    assert!(tx.write_accounts.contains(&"to_wallet".to_string()));
}

#[test]
fn test_transaction_new_social_action() {
    let tx = Transaction::new(
        "user_wallet".to_string(),
        "post_123".to_string(),
        0.0,
        TransactionType::SocialAction,
    );
    
    assert!(matches!(tx.tx_type, TransactionType::SocialAction));
    assert!(tx.read_accounts.contains(&"user_wallet".to_string()));
    assert!(tx.write_accounts.contains(&"user_wallet".to_string()));
    // SocialAction doesn't write to the "to" account
    assert!(!tx.write_accounts.contains(&"post_123".to_string()));
}

#[test]
fn test_transaction_unique_ids() {
    let tx1 = Transaction::new(
        "wallet".to_string(),
        "recipient".to_string(),
        10.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "wallet".to_string(),
        "recipient".to_string(),
        10.0,
        TransactionType::Transfer,
    );
    
    assert_ne!(tx1.id, tx2.id, "Each transaction should have a unique ID");
}

// ============================================================================
// PENDING TRANSACTIONS TESTS
// ============================================================================

#[test]
fn test_pending_transactions_added() {
    let mut blockchain = EnhancedBlockchain::new();
    
    assert!(blockchain.pending_transactions.is_empty());
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user".to_string(), 100.0);
    
    assert_eq!(blockchain.pending_transactions.len(), 1);
}

#[test]
fn test_pending_transactions_multiple() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Create multiple transactions
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user1".to_string(), 100.0);
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user2".to_string(), 200.0);
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user3".to_string(), 300.0);
    
    assert_eq!(blockchain.pending_transactions.len(), 3);
}

#[test]
fn test_failed_transaction_not_added_to_pending() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Try to create transaction with insufficient balance
    let _ = blockchain.create_transaction(
        "empty_wallet".to_string(),
        "receiver".to_string(),
        1000.0,
    );
    
    // Failed transactions are still added to pending in current implementation
    // This test documents current behavior
    assert_eq!(blockchain.pending_transactions.len(), 0);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_fractional_amounts() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user".to_string(), 100.0);
    let _ = blockchain.create_transaction("user".to_string(), "recipient".to_string(), 33.33);
    
    let sender_balance = blockchain.get_balance("user");
    let receiver_balance = blockchain.get_balance("recipient");
    
    assert!((sender_balance - 66.67).abs() < 0.001);
    assert!((receiver_balance - 33.33).abs() < 0.001);
}

#[test]
fn test_very_small_amounts() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("signup_bonus".to_string(), "user".to_string(), 1.0);
    let _ = blockchain.create_transaction("user".to_string(), "recipient".to_string(), 0.0001);
    
    assert!((blockchain.get_balance("user") - 0.9999).abs() < 0.00001);
    assert!((blockchain.get_balance("recipient") - 0.0001).abs() < 0.00001);
}

#[test]
fn test_large_amounts() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction("system".to_string(), "whale".to_string(), 21_000_000.0);
    let _ = blockchain.create_transaction("whale".to_string(), "recipient".to_string(), 10_000_000.0);
    
    assert_eq!(blockchain.get_balance("whale"), 11_000_000.0);
    assert_eq!(blockchain.get_balance("recipient"), 10_000_000.0);
}

#[test]
fn test_special_characters_in_addresses() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let special_address = "0x1234ABCD!@#$%^&*()_+-=[]{}|;':\",./<>?";
    let _ = blockchain.create_transaction(
        "signup_bonus".to_string(),
        special_address.to_string(),
        100.0,
    );
    
    assert_eq!(blockchain.get_balance(special_address), 100.0);
}

#[test]
fn test_unicode_addresses() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let unicode_address = "钱包_ウォレット_지갑_🔥";
    let _ = blockchain.create_transaction(
        "signup_bonus".to_string(),
        unicode_address.to_string(),
        100.0,
    );
    
    assert_eq!(blockchain.get_balance(unicode_address), 100.0);
}

#[test]
fn test_empty_string_address() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let _ = blockchain.create_transaction(
        "signup_bonus".to_string(),
        "".to_string(),
        100.0,
    );
    
    // Empty string is valid as HashMap key
    assert_eq!(blockchain.get_balance(""), 100.0);
}
