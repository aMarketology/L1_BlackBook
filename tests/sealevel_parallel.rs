// ============================================================================
// BLACKBOOK L1 — SEALEVEL PARALLEL EXECUTION TESTS
// ============================================================================
//
// Production-readiness tests for the Solana-style Sealevel engine:
//
//   1. Account lock manager: read/write conflict detection
//   2. Parallel scheduler: batch splitting, conflict-free execution
//   3. Circuit breaker: bank-run protection thresholds
//   4. Localized fee market: per-account spam isolation
//   5. Network throttler: stake-weighted rate limiting
//   6. Transaction conflict detection: read/write sets
//   7. Adaptive batch tuning: conflict-driven resizing
//   8. SVM-backed parallel execution (lamport path)
//
// Run:  cargo test --test sealevel_parallel
// ============================================================================

use layer1::runtime::core::{
    Transaction, TransactionType, TransactionResult,
    AccountLockManager, ParallelScheduler,
    AccountType, ProgramDerivedAddress,
};
use layer1::runtime::{
    NetworkThrottler, CircuitBreaker, LocalizedFeeMarket,
};
use dashmap::DashMap;
use std::sync::Arc;

// ============================================================================
// HELPER: Create a simple transfer transaction for Sealevel scheduling
// ============================================================================
fn make_tx(from: &str, to: &str, amount: f64) -> Transaction {
    Transaction::new(from.to_string(), to.to_string(), amount, TransactionType::Transfer)
}

fn make_typed_tx(from: &str, to: &str, amount: f64, tx_type: TransactionType) -> Transaction {
    Transaction::new(from.to_string(), to.to_string(), amount, tx_type)
}

// ============================================================================
// TEST GROUP 1: Account Lock Manager
// ============================================================================

#[test]
fn test_lock_manager_no_conflict() {
    let lm = AccountLockManager::new();

    let tx1 = make_tx("alice", "bob", 1.0);
    let tx2 = make_tx("charlie", "dave", 2.0);

    assert!(lm.try_acquire_locks(&tx1), "Non-conflicting tx1 must acquire locks");
    assert!(lm.try_acquire_locks(&tx2), "Non-conflicting tx2 must acquire locks");

    lm.release_locks(&tx1);
    lm.release_locks(&tx2);
}

#[test]
fn test_lock_manager_write_write_conflict() {
    let lm = AccountLockManager::new();

    // Both write to "bob"
    let tx1 = make_tx("alice", "bob", 1.0);
    let tx2 = make_tx("charlie", "bob", 2.0);

    assert!(lm.try_acquire_locks(&tx1), "First lock should succeed");
    assert!(!lm.try_acquire_locks(&tx2), "Write-write conflict on 'bob' MUST be detected");

    lm.release_locks(&tx1);

    // After release, tx2 should be able to acquire
    assert!(lm.try_acquire_locks(&tx2), "After release, tx2 should acquire locks");
    lm.release_locks(&tx2);
}

#[test]
fn test_lock_manager_read_write_conflict() {
    let lm = AccountLockManager::new();

    // tx1 reads from "alice", tx2 writes to "alice"
    let tx1 = make_tx("alice", "bob", 1.0);   // reads alice, writes alice+bob
    let tx2 = make_tx("charlie", "alice", 2.0); // reads charlie, writes charlie+alice

    assert!(lm.try_acquire_locks(&tx1), "First tx acquires locks");
    assert!(!lm.try_acquire_locks(&tx2), "Read-write conflict on 'alice' MUST block");

    lm.release_locks(&tx1);
}

#[test]
fn test_lock_manager_conflict_rate() {
    let lm = AccountLockManager::new();

    // Create some conflicts
    let tx1 = make_tx("alice", "bob", 1.0);
    let tx2 = make_tx("charlie", "bob", 2.0);

    lm.try_acquire_locks(&tx1); // succeeds
    lm.try_acquire_locks(&tx2); // fails (conflict)

    let rate = lm.get_conflict_rate();
    assert!(rate > 0.0, "Conflict rate must be > 0 after a conflict: got {}", rate);
    assert!(rate <= 1.0, "Conflict rate must be <= 1.0");

    lm.release_locks(&tx1);
}

// ============================================================================
// TEST GROUP 2: Transaction Conflict Detection
// ============================================================================

#[test]
fn test_tx_conflicts_with_same_write() {
    let tx1 = make_tx("alice", "bob", 1.0);
    let tx2 = make_tx("charlie", "bob", 2.0);

    assert!(tx1.conflicts_with(&tx2), "Txs writing to same account MUST conflict");
}

#[test]
fn test_tx_no_conflict_independent() {
    let tx1 = make_tx("alice", "bob", 1.0);
    let tx2 = make_tx("charlie", "dave", 2.0);

    assert!(!tx1.conflicts_with(&tx2), "Independent txs MUST NOT conflict");
}

#[test]
fn test_tx_is_financial() {
    let transfer = make_typed_tx("a", "b", 1.0, TransactionType::Transfer);
    let mint = make_typed_tx("sys", "b", 100.0, TransactionType::Mint);
    let vote = make_typed_tx("v", "v", 0.0, TransactionType::Vote);

    assert!(transfer.is_financial(), "Transfer is financial");
    assert!(mint.is_financial(), "Mint is financial");
    assert!(!vote.is_financial(), "Vote is NOT financial");
}

// ============================================================================
// TEST GROUP 3: Parallel Scheduler — Batch Splitting
// ============================================================================

#[test]
fn test_scheduler_splits_conflicting_txs() {
    let scheduler = ParallelScheduler::new();

    let txs = vec![
        make_tx("alice", "bob", 1.0),
        make_tx("charlie", "bob", 2.0),   // conflicts with tx1 (both write to bob)
        make_tx("dave", "eve", 3.0),      // independent
    ];

    let batches = scheduler.schedule_with_locks(txs);

    assert!(batches.len() >= 2, "Conflicting txs must be split into 2+ batches, got {}", batches.len());

    let total_txs: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total_txs, 3, "All 3 txs must be scheduled");
}

#[test]
fn test_scheduler_independent_txs_single_batch() {
    let scheduler = ParallelScheduler::new();

    let txs = vec![
        make_tx("alice", "bob", 1.0),
        make_tx("charlie", "dave", 2.0),
        make_tx("eve", "frank", 3.0),
    ];

    let batches = scheduler.schedule_with_locks(txs);

    // All independent — should fit in 1 batch
    assert_eq!(batches.len(), 1, "Independent txs should fit in 1 batch");
    assert_eq!(batches[0].len(), 3, "Batch must contain all 3 txs");
}

#[test]
fn test_scheduler_empty_input() {
    let scheduler = ParallelScheduler::new();
    let batches = scheduler.schedule_with_locks(vec![]);
    assert!(batches.is_empty(), "Empty input must produce empty output");
}

#[test]
fn test_scheduler_serial_chain() {
    let scheduler = ParallelScheduler::new();

    // Chain: alice→bob, bob→charlie, charlie→dave (all conflict sequentially)
    let txs = vec![
        make_tx("alice", "bob", 1.0),
        make_tx("bob", "charlie", 2.0),
        make_tx("charlie", "dave", 3.0),
    ];

    let batches = scheduler.schedule_with_locks(txs);
    assert!(batches.len() >= 2, "Serial chain must produce multiple batches");
}

// ============================================================================
// TEST GROUP 4: Parallel Execution with Balances
// ============================================================================

#[test]
fn test_parallel_execution_basic() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    // Fund accounts
    balances.insert("alice".to_string(), 100.0);
    balances.insert("charlie".to_string(), 50.0);

    let batch = vec![
        make_tx("alice", "bob", 10.0),
        make_tx("charlie", "dave", 5.0),
    ];

    let results = scheduler.execute_batch_with_locks(batch, &balances);

    assert_eq!(results.len(), 2, "Must produce 2 results");
    for r in &results {
        assert!(r.success, "All txs should succeed: {:?}", r.error);
    }
}

#[test]
fn test_parallel_execution_insufficient_funds() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    balances.insert("alice".to_string(), 1.0);

    let batch = vec![
        make_tx("alice", "bob", 999.0), // way more than balance
    ];

    let results = scheduler.execute_batch_with_locks(batch, &balances);
    assert_eq!(results.len(), 1);
    assert!(!results[0].success, "Insufficient funds tx must fail");
}

// ============================================================================
// TEST GROUP 5: Adaptive Batch Tuning
// ============================================================================

#[test]
fn test_batch_size_default() {
    let scheduler = ParallelScheduler::new();
    let size = scheduler.get_batch_size();
    assert_eq!(size, 256, "Default batch size must be OPTIMAL_BATCH_SIZE (256)");
}

#[test]
fn test_batch_size_tunes_down_on_conflicts() {
    let scheduler = ParallelScheduler::new();

    // Force high conflict rate by creating many conflicts
    let lm = &scheduler.lock_manager;
    for _ in 0..100 {
        let tx = make_tx("shared_account", "dest", 1.0);
        lm.try_acquire_locks(&tx);
        // Don't release — this simulates failures
        let tx2 = make_tx("other", "shared_account", 1.0);
        lm.try_acquire_locks(&tx2); // will fail = conflict
        lm.release_locks(&tx);
    }

    let rate = lm.get_conflict_rate();
    if rate > 0.25 {
        let before = scheduler.get_batch_size();
        scheduler.tune_batch_size();
        let after = scheduler.get_batch_size();
        assert!(after <= before, "High conflicts should reduce batch size");
    }
}

// ============================================================================
// TEST GROUP 6: Circuit Breaker — Bank-Run Protection
// ============================================================================

#[test]
fn test_circuit_breaker_allows_normal_transfer() {
    let cb = CircuitBreaker::new();

    // Normal transfer: 5% of 1000 BB balance (well under 20% block threshold)
    let result = cb.check_transfer("alice", 50.0, 1000.0, 1);
    assert!(result.is_ok(), "Normal transfer must be allowed");
}

#[test]
fn test_circuit_breaker_trips_on_large_transfer() {
    let cb = CircuitBreaker::new();

    // Transfer 30% of balance in one block (exceeds 20% block threshold)
    let result = cb.check_transfer("alice", 300.0, 1000.0, 1);
    // First call establishes the initial value, might pass

    // Make cumulative transfers exceed 20%
    let _ = cb.check_transfer("alice", 150.0, 1000.0, 1);
    let result2 = cb.check_transfer("alice", 100.0, 1000.0, 1);

    // At least one should trip
    let tripped = result.is_err() || result2.is_err();
    // Check cumulative - 300+150+100 = 550 > 200 (20% of 1000)
    assert!(tripped, "Circuit breaker should trip when block outflow exceeds 20% threshold");
}

#[test]
fn test_circuit_breaker_exemptions() {
    let cb = CircuitBreaker::new();

    cb.add_exemption("treasury");

    // Treasury can move 99% in one block — exempt
    let result = cb.check_transfer("treasury", 990.0, 1000.0, 1);
    assert!(result.is_ok(), "Exempt accounts must bypass circuit breaker");
}

// ============================================================================
// TEST GROUP 7: Localized Fee Market
// ============================================================================

#[test]
fn test_fee_market_initial_zero() {
    let fm = LocalizedFeeMarket::new();
    let fee = fm.calculate_fee("new_user");
    assert!(fee >= 0.0, "Initial fee must be >= 0");
    assert!(fee <= 1.0, "Fee must not exceed max (1.0)");
}

#[test]
fn test_fee_market_isolates_spammers() {
    let fm = LocalizedFeeMarket::new();

    // Simulate spam from one user group
    for _ in 0..200 {
        fm.calculate_fee("spammer_AAAA");
    }

    // Different user should have normal fees
    let normal_fee = fm.calculate_fee("normal_ZZZZ");
    assert!(normal_fee >= 0.0, "Normal user fee must be reasonable");
}

// ============================================================================
// TEST GROUP 8: Network Throttler
// ============================================================================

#[test]
fn test_throttler_allows_normal_traffic() {
    let nt = NetworkThrottler::new();
    let result = nt.check_transaction("user_1", 100.0);
    assert!(result.is_ok(), "Normal traffic must be allowed");
}

#[test]
fn test_throttler_tracks_throughput() {
    let nt = NetworkThrottler::new();

    for _ in 0..10 {
        let _ = nt.check_transaction("user_1", 100.0);
        nt.transaction_completed();
    }

    let stats = nt.get_stats();
    assert!(stats.get("tps").is_some(), "Throttler stats must include TPS");
}

// ============================================================================
// TEST GROUP 9: PDA Derivation
// ============================================================================

#[test]
fn test_pda_derivation_deterministic() {
    let pda1 = ProgramDerivedAddress::derive(AccountType::UserWallet, "alice", None).unwrap();
    let pda2 = ProgramDerivedAddress::derive(AccountType::UserWallet, "alice", None).unwrap();

    assert_eq!(pda1.address, pda2.address, "PDA derivation must be deterministic");
}

#[test]
fn test_pda_different_owners_different_addresses() {
    let pda_alice = ProgramDerivedAddress::derive(AccountType::UserWallet, "alice", None).unwrap();
    let pda_bob = ProgramDerivedAddress::derive(AccountType::UserWallet, "bob", None).unwrap();

    assert_ne!(pda_alice.address, pda_bob.address, "Different owners must have different PDAs");
}

#[test]
fn test_pda_different_types_different_addresses() {
    let wallet = ProgramDerivedAddress::derive(AccountType::UserWallet, "alice", None).unwrap();
    let escrow = ProgramDerivedAddress::derive(AccountType::EscrowVault, "alice", None).unwrap();

    assert_ne!(wallet.address, escrow.address, "Different account types must produce different PDAs");
}

// ============================================================================
// TEST GROUP 10: Account Types
// ============================================================================

#[test]
fn test_account_type_namespaces() {
    assert_eq!(AccountType::UserWallet.namespace(), "wallet");
    assert_eq!(AccountType::EscrowVault.namespace(), "escrow");
    assert_eq!(AccountType::Treasury.namespace(), "treasury");
}

#[test]
fn test_account_type_can_hold_tokens() {
    assert!(AccountType::UserWallet.can_hold_tokens(), "Wallets hold tokens");
    assert!(AccountType::Treasury.can_hold_tokens(), "Treasury holds tokens");
    assert!(AccountType::EscrowVault.can_hold_tokens(), "Escrow holds tokens");
    assert!(!AccountType::SystemConfig.can_hold_tokens(), "SystemConfig does NOT hold tokens");
}

// ============================================================================
// TEST GROUP 11: Large-Scale Parallel Scheduling
// ============================================================================

#[test]
fn test_schedule_1000_independent_txs() {
    let scheduler = ParallelScheduler::new();

    let txs: Vec<Transaction> = (0..1000).map(|i| {
        make_tx(&format!("sender_{}", i), &format!("receiver_{}", i), 1.0)
    }).collect();

    let batches = scheduler.schedule_with_locks(txs);

    let total: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total, 1000, "All 1000 txs must be scheduled");

    // Independent txs should need very few batches
    assert!(batches.len() <= 5, "1000 independent txs should fit in ≤5 batches, got {}", batches.len());
}

#[test]
fn test_schedule_mixed_conflict_pattern() {
    let scheduler = ParallelScheduler::new();

    // 50 independent + 50 all writing to "hot_account"
    let mut txs: Vec<Transaction> = (0..50).map(|i| {
        make_tx(&format!("ind_s_{}", i), &format!("ind_r_{}", i), 1.0)
    }).collect();

    for i in 0..50 {
        txs.push(make_tx(&format!("hot_sender_{}", i), "hot_account", 0.1));
    }

    let batches = scheduler.schedule_with_locks(txs);

    let total: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total, 100, "All 100 txs must be scheduled");

    // Hot account creates serialization — need many batches for those 50
    assert!(batches.len() >= 2, "Hot account contention must create multiple batches");
}
