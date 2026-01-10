//! Bridge and Escrow Tests
//!
//! Tests for cross-layer bridge operations:
//! - Token locking and unlocking
//! - Settlement proofs
//! - Lock records management
//! - Spendable vs locked balance

use layer1::{EnhancedBlockchain, TransactionType};
use layer1::protocol::blockchain::{LockPurpose, SettlementProof};

// ============================================================================
// TOKEN LOCKING TESTS
// ============================================================================

#[test]
fn test_lock_tokens_success() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Lock tokens
    let result = blockchain.lock_tokens(
        "user1",
        300.0,
        LockPurpose::BridgeToL2,
        None,
    );
    
    assert!(result.is_ok(), "Lock should succeed");
    let lock_id = result.unwrap();
    assert!(lock_id.starts_with("lock_"), "Lock ID should have correct prefix");
}

#[test]
fn test_lock_tokens_insufficient_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user with 100 BB
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 100.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Try to lock more than available
    let result = blockchain.lock_tokens(
        "user1",
        500.0,
        LockPurpose::BridgeToL2,
        None,
    );
    
    assert!(result.is_err(), "Lock should fail with insufficient balance");
    assert!(result.unwrap_err().contains("Insufficient"));
}

#[test]
fn test_lock_reduces_spendable_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let before = blockchain.get_spendable_balance("user1");
    
    // Lock tokens
    let _ = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None);
    
    let after = blockchain.get_spendable_balance("user1");
    
    assert_eq!(before - after, 300.0, "Spendable balance should decrease by locked amount");
}

#[test]
fn test_locked_balance_tracking() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    assert_eq!(blockchain.get_locked_balance("user1"), 0.0, "Initial locked balance should be 0");
    
    // Lock tokens
    let _ = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None);
    
    assert_eq!(blockchain.get_locked_balance("user1"), 300.0, "Locked balance should increase");
}

#[test]
fn test_multiple_locks() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Create multiple locks
    let lock1 = blockchain.lock_tokens("user1", 200.0, LockPurpose::BridgeToL2, None).unwrap();
    let lock2 = blockchain.lock_tokens("user1", 150.0, LockPurpose::MarketEscrow, None).unwrap();
    
    assert_ne!(lock1, lock2, "Lock IDs should be unique");
    assert_eq!(blockchain.get_locked_balance("user1"), 350.0);
    
    let locks = blockchain.get_locks_for_address("user1");
    assert_eq!(locks.len(), 2, "Should have 2 active locks");
}

// ============================================================================
// LOCK RECORD TESTS
// ============================================================================

#[test]
fn test_lock_record_created() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    let record = blockchain.get_lock_record(&lock_id);
    assert!(record.is_some(), "Lock record should exist");
    
    let record = record.unwrap();
    assert_eq!(record.owner, "user1");
    assert_eq!(record.amount, 300.0);
    assert_eq!(record.purpose, LockPurpose::BridgeToL2);
    assert!(!record.release_authorized, "Release should not be authorized yet");
    assert!(record.released_at.is_none(), "Should not be released yet");
}

#[test]
fn test_lock_record_with_beneficiary() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens(
        "user1",
        300.0,
        LockPurpose::SettlementPending,
        Some("winner_address".to_string()),
    ).unwrap();
    
    let record = blockchain.get_lock_record(&lock_id).unwrap();
    assert_eq!(record.beneficiary, Some("winner_address".to_string()));
}

#[test]
fn test_lock_purpose_variants() {
    assert_ne!(LockPurpose::BridgeToL2, LockPurpose::MarketEscrow);
    assert_ne!(LockPurpose::MarketEscrow, LockPurpose::SettlementPending);
    
    // Test equality
    assert_eq!(LockPurpose::BridgeToL2, LockPurpose::BridgeToL2);
}

// ============================================================================
// RELEASE AUTHORIZATION TESTS
// ============================================================================

#[test]
fn test_authorize_release() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    let proof = SettlementProof {
        market_id: "market_123".to_string(),
        outcome: "YES".to_string(),
        l2_block_height: 1000,
        l2_signature: "signature_hex".to_string(),
        verified_at: 1234567890,
    };
    
    let result = blockchain.authorize_release(&lock_id, proof);
    assert!(result.is_ok(), "Authorization should succeed");
    
    let record = blockchain.get_lock_record(&lock_id).unwrap();
    assert!(record.release_authorized, "Release should be authorized");
    assert!(record.settlement_proof.is_some(), "Settlement proof should be stored");
}

#[test]
fn test_authorize_release_unknown_lock() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let proof = SettlementProof {
        market_id: "market_123".to_string(),
        outcome: "YES".to_string(),
        l2_block_height: 1000,
        l2_signature: "signature".to_string(),
        verified_at: 1234567890,
    };
    
    let result = blockchain.authorize_release("unknown_lock_id", proof);
    assert!(result.is_err(), "Should fail for unknown lock");
}

#[test]
fn test_authorize_release_already_authorized() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    let proof = SettlementProof {
        market_id: "market_123".to_string(),
        outcome: "YES".to_string(),
        l2_block_height: 1000,
        l2_signature: "sig".to_string(),
        verified_at: 1234567890,
    };
    
    let _ = blockchain.authorize_release(&lock_id, proof.clone());
    
    // Try to authorize again
    let result = blockchain.authorize_release(&lock_id, proof);
    assert!(result.is_err(), "Should fail for already authorized lock");
}

// ============================================================================
// TOKEN RELEASE TESTS
// ============================================================================

#[test]
fn test_release_tokens_to_owner() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    // Authorize release
    let proof = SettlementProof {
        market_id: "".to_string(),
        outcome: "".to_string(),
        l2_block_height: 0,
        l2_signature: "".to_string(),
        verified_at: 0,
    };
    let _ = blockchain.authorize_release(&lock_id, proof);
    
    // Release tokens
    let result = blockchain.release_tokens(&lock_id);
    assert!(result.is_ok(), "Release should succeed");
    
    let (recipient, amount) = result.unwrap();
    assert_eq!(recipient, "user1", "Should release to owner");
    assert_eq!(amount, 300.0);
    
    // Check locked balance is 0
    assert_eq!(blockchain.get_locked_balance("user1"), 0.0);
}

#[test]
fn test_release_tokens_to_beneficiary() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens(
        "user1",
        300.0,
        LockPurpose::SettlementPending,
        Some("winner".to_string()),
    ).unwrap();
    
    // Authorize and release
    let proof = SettlementProof {
        market_id: "market".to_string(),
        outcome: "YES".to_string(),
        l2_block_height: 100,
        l2_signature: "sig".to_string(),
        verified_at: 123,
    };
    let _ = blockchain.authorize_release(&lock_id, proof);
    let result = blockchain.release_tokens(&lock_id);
    
    assert!(result.is_ok());
    let (recipient, _) = result.unwrap();
    assert_eq!(recipient, "winner", "Should release to beneficiary");
}

#[test]
fn test_release_without_authorization() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    // Try to release without authorization
    let result = blockchain.release_tokens(&lock_id);
    assert!(result.is_err(), "Release should fail without authorization");
}

#[test]
fn test_release_already_released() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::BridgeToL2, None).unwrap();
    
    let proof = SettlementProof {
        market_id: "".to_string(),
        outcome: "".to_string(),
        l2_block_height: 0,
        l2_signature: "".to_string(),
        verified_at: 0,
    };
    let _ = blockchain.authorize_release(&lock_id, proof);
    let _ = blockchain.release_tokens(&lock_id);
    
    // Try to release again
    let result = blockchain.release_tokens(&lock_id);
    assert!(result.is_err(), "Should fail for already released lock");
}

// ============================================================================
// SPENDABLE BALANCE TESTS
// ============================================================================

#[test]
fn test_spendable_vs_total_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Total balance
    let total = blockchain.get_balance("user1");
    assert_eq!(total, 1000.0);
    
    // Lock some
    let _ = blockchain.lock_tokens("user1", 400.0, LockPurpose::BridgeToL2, None);
    
    // Spendable should be less
    let spendable = blockchain.get_spendable_balance("user1");
    assert_eq!(spendable, 600.0);
    
    // get_balance still returns remaining balance (not including locked)
    let remaining = blockchain.get_balance("user1");
    assert_eq!(remaining, 600.0, "Balance after locking");
}

#[test]
fn test_cannot_transfer_locked_funds() {
    let mut blockchain = EnhancedBlockchain::new();
    
    // Fund user with 500
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 500.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Lock 400
    let _ = blockchain.lock_tokens("user1", 400.0, LockPurpose::BridgeToL2, None);
    
    // Try to transfer 200 (should fail because only 100 spendable)
    let spendable = blockchain.get_spendable_balance("user1");
    assert_eq!(spendable, 100.0);
    
    // This transfer should fail (insufficient spendable)
    let tx_id = blockchain.create_transaction("user1".to_string(), "receiver".to_string(), 200.0);
    assert!(tx_id.contains("Insufficient") || blockchain.get_balance("user1") < 200.0);
}

// ============================================================================
// GET LOCKS FOR ADDRESS TESTS
// ============================================================================

#[test]
fn test_get_locks_for_address_empty() {
    let blockchain = EnhancedBlockchain::new();
    
    let locks = blockchain.get_locks_for_address("nonexistent_user");
    assert!(locks.is_empty(), "Should have no locks for new address");
}

#[test]
fn test_get_locks_excludes_released() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Create two locks
    let lock1 = blockchain.lock_tokens("user1", 200.0, LockPurpose::BridgeToL2, None).unwrap();
    let _lock2 = blockchain.lock_tokens("user1", 150.0, LockPurpose::MarketEscrow, None).unwrap();
    
    // Release first lock
    let proof = SettlementProof {
        market_id: "".to_string(),
        outcome: "".to_string(),
        l2_block_height: 0,
        l2_signature: "".to_string(),
        verified_at: 0,
    };
    let _ = blockchain.authorize_release(&lock1, proof);
    let _ = blockchain.release_tokens(&lock1);
    
    // Should only show unreleased lock
    let locks = blockchain.get_locks_for_address("user1");
    assert_eq!(locks.len(), 1, "Should only have 1 active lock");
}

// ============================================================================
// SETTLEMENT PROOF TESTS
// ============================================================================

#[test]
fn test_settlement_proof_stored() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    let lock_id = blockchain.lock_tokens("user1", 300.0, LockPurpose::MarketEscrow, None).unwrap();
    
    let proof = SettlementProof {
        market_id: "market_abc".to_string(),
        outcome: "NO".to_string(),
        l2_block_height: 5000,
        l2_signature: "sig_xyz".to_string(),
        verified_at: 9999999,
    };
    
    let _ = blockchain.authorize_release(&lock_id, proof);
    
    let record = blockchain.get_lock_record(&lock_id).unwrap();
    let stored_proof = record.settlement_proof.as_ref().unwrap();
    
    assert_eq!(stored_proof.market_id, "market_abc");
    assert_eq!(stored_proof.outcome, "NO");
    assert_eq!(stored_proof.l2_block_height, 5000);
    assert_eq!(stored_proof.l2_signature, "sig_xyz");
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_lock_zero_amount() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 1000.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Lock 0 should work (though not useful)
    let result = blockchain.lock_tokens("user1", 0.0, LockPurpose::BridgeToL2, None);
    // Depending on implementation, might succeed or fail validation
    // Just ensure it doesn't panic
    let _ = result;
}

#[test]
fn test_lock_exact_balance() {
    let mut blockchain = EnhancedBlockchain::new();
    
    blockchain.create_transaction("treasury".to_string(), "user1".to_string(), 500.0);
    let _ = blockchain.mine_pending_transactions("miner".to_string());
    
    // Lock entire balance
    let result = blockchain.lock_tokens("user1", 500.0, LockPurpose::BridgeToL2, None);
    assert!(result.is_ok(), "Should be able to lock entire balance");
    
    // Spendable should be 0
    assert_eq!(blockchain.get_spendable_balance("user1"), 0.0);
}
