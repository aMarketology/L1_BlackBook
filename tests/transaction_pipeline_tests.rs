//! Transaction Pipeline Tests
//!
//! Tests for the Sealevel-style transaction processing:
//! - Transaction creation and serialization
//! - Account lock manager
//! - Parallel scheduling
//! - Read/write account detection
//! - Conflict detection

use layer1::{Transaction, TransactionType};
use layer1::runtime::core::{
    AccountLockManager, 
    OPTIMAL_BATCH_SIZE, 
    MAX_BATCH_SIZE,
    MIN_BATCH_SIZE,
    CONFLICT_THRESHOLD,
};

// ============================================================================
// TRANSACTION CREATION TESTS
// ============================================================================

#[test]
fn test_transaction_new() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    assert_eq!(tx.from, "alice");
    assert_eq!(tx.to, "bob");
    assert_eq!(tx.amount, 100.0);
    assert!(!tx.id.is_empty(), "Transaction should have ID");
    assert!(tx.timestamp > 0, "Transaction should have timestamp");
}

#[test]
fn test_transaction_with_nonce() {
    let tx = Transaction::with_nonce(
        "alice".to_string(),
        "bob".to_string(),
        50.0,
        TransactionType::Transfer,
        42,
    );
    
    assert_eq!(tx.nonce, 42);
}

#[test]
fn test_transaction_auto_signature() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    assert!(!tx.signature.is_empty(), "Transaction should have auto-generated signature");
    assert!(tx.signature.starts_with("sig_"), "Signature should have prefix");
}

// ============================================================================
// READ/WRITE ACCOUNT DETECTION TESTS
// ============================================================================

#[test]
fn test_transfer_accounts() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    assert!(tx.read_accounts.contains(&"alice".to_string()), "Sender should be read");
    assert!(tx.write_accounts.contains(&"alice".to_string()), "Sender should be written");
    assert!(tx.write_accounts.contains(&"bob".to_string()), "Receiver should be written");
}

#[test]
fn test_bet_placement_accounts() {
    let tx = Transaction::new(
        "user".to_string(),
        "bet_pool".to_string(),
        50.0,
        TransactionType::BetPlacement,
    );
    
    assert!(tx.read_accounts.contains(&"user".to_string()));
    assert!(tx.write_accounts.contains(&"user".to_string()));
    assert!(tx.write_accounts.contains(&"bet_pool".to_string()));
}

#[test]
fn test_social_action_accounts() {
    let tx = Transaction::new(
        "user".to_string(),
        "".to_string(),
        0.0,
        TransactionType::SocialAction,
    );
    
    // Social actions only affect the actor
    assert!(tx.read_accounts.contains(&"user".to_string()));
    assert!(tx.write_accounts.contains(&"user".to_string()));
}

// ============================================================================
// CONFLICT DETECTION TESTS
// ============================================================================

#[test]
fn test_no_conflict_different_accounts() {
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "charlie".to_string(),
        "dave".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    assert!(!tx1.conflicts_with(&tx2), "Different accounts should not conflict");
    assert!(!tx2.conflicts_with(&tx1), "Conflict check should be symmetric");
}

#[test]
fn test_write_write_conflict() {
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "charlie".to_string(),
        "bob".to_string(),  // Same recipient
        50.0,
        TransactionType::Transfer,
    );
    
    assert!(tx1.conflicts_with(&tx2), "Same write account should conflict");
}

#[test]
fn test_read_write_conflict() {
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    // tx2 reads from alice (who tx1 writes to)
    let tx2 = Transaction::new(
        "alice".to_string(),  // Same sender
        "charlie".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    assert!(tx1.conflicts_with(&tx2), "Read-write conflict should be detected");
}

#[test]
fn test_self_transfer_conflict() {
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "bob".to_string(),  // tx2 sender is tx1 receiver
        "charlie".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    assert!(tx1.conflicts_with(&tx2), "Chained transactions should conflict");
}

// ============================================================================
// SERIALIZATION TESTS
// ============================================================================

#[test]
fn test_transaction_borsh_roundtrip() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let bytes = tx.to_borsh().expect("Borsh serialization should succeed");
    let decoded = Transaction::from_borsh(&bytes).expect("Borsh deserialization should succeed");
    
    assert_eq!(tx.from, decoded.from);
    assert_eq!(tx.to, decoded.to);
    assert_eq!(tx.amount, decoded.amount);
    assert_eq!(tx.nonce, decoded.nonce);
}

#[test]
fn test_transaction_base64_roundtrip() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let encoded = tx.to_base64().expect("Base64 encoding should succeed");
    let decoded = Transaction::from_base64(&encoded).expect("Base64 decoding should succeed");
    
    assert_eq!(tx.from, decoded.from);
    assert_eq!(tx.to, decoded.to);
    assert_eq!(tx.amount, decoded.amount);
}

#[test]
fn test_transaction_json_roundtrip() {
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::BetPlacement,
    );
    
    let json = serde_json::to_string(&tx).expect("JSON serialization should succeed");
    let decoded: Transaction = serde_json::from_str(&json).expect("JSON deserialization should succeed");
    
    assert_eq!(tx.from, decoded.from);
    assert_eq!(tx.tx_type, decoded.tx_type);
}

// ============================================================================
// ACCOUNT LOCK MANAGER TESTS
// ============================================================================

#[test]
fn test_lock_manager_creation() {
    let manager = AccountLockManager::new();
    
    assert_eq!(manager.get_conflict_rate(), 0.0, "Initial conflict rate should be 0");
}

#[test]
fn test_acquire_locks_success() {
    let manager = AccountLockManager::new();
    
    let tx = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let acquired = manager.try_acquire_locks(&tx);
    assert!(acquired, "Should acquire locks for first transaction");
}

#[test]
fn test_acquire_locks_conflict() {
    let manager = AccountLockManager::new();
    
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "alice".to_string(),  // Same sender - conflicts on alice
        "charlie".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    // First transaction acquires locks
    assert!(manager.try_acquire_locks(&tx1));
    
    // Second should fail due to conflict
    assert!(!manager.try_acquire_locks(&tx2), "Should fail due to write conflict on alice");
}

#[test]
fn test_release_locks() {
    let manager = AccountLockManager::new();
    
    let tx1 = Transaction::new(
        "alice".to_string(),
        "bob".to_string(),
        100.0,
        TransactionType::Transfer,
    );
    
    let tx2 = Transaction::new(
        "alice".to_string(),
        "charlie".to_string(),
        50.0,
        TransactionType::Transfer,
    );
    
    // Acquire locks for tx1
    manager.try_acquire_locks(&tx1);
    
    // Release locks
    manager.release_locks(&tx1);
    
    // Now tx2 should be able to acquire
    assert!(manager.try_acquire_locks(&tx2), "Should acquire after release");
}

#[test]
fn test_conflict_rate_tracking() {
    let manager = AccountLockManager::new();
    
    let tx1 = Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer);
    let tx2 = Transaction::new("alice".to_string(), "charlie".to_string(), 50.0, TransactionType::Transfer);
    
    // First succeeds
    manager.try_acquire_locks(&tx1);
    // Second fails
    manager.try_acquire_locks(&tx2);
    
    let rate = manager.get_conflict_rate();
    assert!(rate > 0.0, "Conflict rate should be > 0 after a conflict");
}

#[test]
fn test_lock_manager_stats() {
    let manager = AccountLockManager::new();
    
    let tx = Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer);
    manager.try_acquire_locks(&tx);
    
    let stats = manager.get_stats();
    assert!(stats.is_object(), "Stats should be a JSON object");
    
    let total = stats.get("total_acquisitions").and_then(|v| v.as_u64());
    assert_eq!(total, Some(1), "Should have 1 acquisition");
}

#[test]
fn test_lock_manager_reset_stats() {
    let manager = AccountLockManager::new();
    
    let tx = Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer);
    manager.try_acquire_locks(&tx);
    
    manager.reset_stats();
    
    let stats = manager.get_stats();
    let total = stats.get("total_acquisitions").and_then(|v| v.as_u64());
    assert_eq!(total, Some(0), "Stats should be reset to 0");
}

// ============================================================================
// BATCH CONSTANTS TESTS
// ============================================================================

#[test]
fn test_batch_size_constants() {
    assert_eq!(OPTIMAL_BATCH_SIZE, 64, "Optimal batch size should be 64");
    assert_eq!(MAX_BATCH_SIZE, 256, "Max batch size should be 256");
    assert_eq!(MIN_BATCH_SIZE, 8, "Min batch size should be 8");
}

#[test]
fn test_batch_size_ordering() {
    assert!(MIN_BATCH_SIZE < OPTIMAL_BATCH_SIZE);
    assert!(OPTIMAL_BATCH_SIZE < MAX_BATCH_SIZE);
}

#[test]
fn test_conflict_threshold() {
    assert_eq!(CONFLICT_THRESHOLD, 0.5, "Conflict threshold should be 50%");
}

// ============================================================================
// TRANSACTION TYPE SPECIFIC TESTS
// ============================================================================

#[test]
fn test_all_transaction_types_serializable() {
    let types = vec![
        TransactionType::Transfer,
        TransactionType::BetPlacement,
        TransactionType::BetResolution,
        TransactionType::SocialAction,
        TransactionType::StakeDeposit,
        TransactionType::StakeWithdraw,
        TransactionType::SystemReward,
        TransactionType::Mint,
        TransactionType::Burn,
    ];
    
    for tx_type in types {
        let tx = Transaction::new("a".to_string(), "b".to_string(), 1.0, tx_type.clone());
        let json = serde_json::to_string(&tx);
        assert!(json.is_ok(), "Transaction type {:?} should be serializable", tx_type);
    }
}

#[test]
fn test_bet_resolution_accounts() {
    let tx = Transaction::new(
        "market_pool".to_string(),
        "winner".to_string(),
        100.0,
        TransactionType::BetResolution,
    );
    
    // Resolution reads bet state, writes to winner
    assert!(tx.read_accounts.contains(&"winner".to_string()));
    assert!(tx.write_accounts.contains(&"market_pool".to_string()));
    assert!(tx.write_accounts.contains(&"winner".to_string()));
}

// ============================================================================
// PARALLEL EXECUTION SIMULATION
// ============================================================================

#[test]
fn test_parallel_batch_non_conflicting() {
    let manager = AccountLockManager::new();
    
    // Create 4 non-conflicting transactions
    let txs = vec![
        Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer),
        Transaction::new("charlie".to_string(), "dave".to_string(), 50.0, TransactionType::Transfer),
        Transaction::new("eve".to_string(), "frank".to_string(), 75.0, TransactionType::Transfer),
        Transaction::new("grace".to_string(), "henry".to_string(), 25.0, TransactionType::Transfer),
    ];
    
    let mut acquired_count = 0;
    for tx in &txs {
        if manager.try_acquire_locks(tx) {
            acquired_count += 1;
        }
    }
    
    assert_eq!(acquired_count, 4, "All non-conflicting txs should acquire locks");
}

#[test]
fn test_parallel_batch_with_conflicts() {
    let manager = AccountLockManager::new();
    
    // Create transactions with some conflicts
    let txs = vec![
        Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer),
        Transaction::new("alice".to_string(), "charlie".to_string(), 50.0, TransactionType::Transfer),  // Conflicts with first
        Transaction::new("dave".to_string(), "eve".to_string(), 75.0, TransactionType::Transfer),       // No conflict
    ];
    
    let mut acquired_count = 0;
    for tx in &txs {
        if manager.try_acquire_locks(tx) {
            acquired_count += 1;
        }
    }
    
    // Should acquire 2 (first and third)
    assert_eq!(acquired_count, 2, "Should acquire non-conflicting txs only");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_empty_account_lists() {
    let mut tx = Transaction::new("alice".to_string(), "bob".to_string(), 100.0, TransactionType::Transfer);
    tx.read_accounts = vec![];
    tx.write_accounts = vec![];
    
    let manager = AccountLockManager::new();
    assert!(manager.try_acquire_locks(&tx), "Empty account lists should not cause panic");
}

#[test]
fn test_same_read_and_write_account() {
    // A transaction that reads and writes the same account
    let tx = Transaction::new("alice".to_string(), "alice".to_string(), 0.0, TransactionType::Transfer);
    
    // Should have alice in both
    assert!(tx.read_accounts.contains(&"alice".to_string()));
    assert!(tx.write_accounts.contains(&"alice".to_string()));
}

#[test]
fn test_many_concurrent_locks() {
    let manager = AccountLockManager::new();
    
    // Create many transactions to different accounts
    for i in 0..100 {
        let tx = Transaction::new(
            format!("user_{}", i),
            format!("user_{}", i + 1000),
            1.0,
            TransactionType::Transfer,
        );
        assert!(manager.try_acquire_locks(&tx), "Lock {} should succeed", i);
    }
    
    // Verify stats
    let stats = manager.get_stats();
    let total = stats.get("total_acquisitions").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(total, 100);
}
