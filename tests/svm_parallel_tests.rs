// ============================================================================
// BLACKBOOK SVM — PARALLEL SCHEDULER INTEGRATION TESTS  (Milestone 1D)
// ============================================================================
//
// These tests prove that ParallelScheduler correctly routes Transfer
// transactions through the SVM (lamport) execution path while maintaining
// Sealevel-style account-level locking for conflict resolution.
//
// Run:  cargo test --features svm --test svm_parallel_tests
// ============================================================================

#[cfg(feature = "svm")]
mod tests {
    use std::sync::Arc;
    use tempfile::tempdir;
    use dashmap::DashMap;
    use sha2::{Sha256, Digest};
    use solana_sdk::{
        pubkey::Pubkey,
        account::{Account, AccountSharedData},
    };

    use layer1::runtime::{
        ParallelScheduler,
        core::{Transaction, TransactionType},
    };
    use layer1::storage::ConcurrentBlockchain;
    use layer1::svm::{SvmAccountsDB, LAMPORTS_PER_BB};

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    /// SHA-256 address → Pubkey (mirrors ParallelScheduler::execute_single_svm)
    fn addr_to_pk(addr: &str) -> Pubkey {
        let s = addr.strip_prefix("bb_").unwrap_or(addr);
        Pubkey::new_from_array(Sha256::digest(s.as_bytes()).into())
    }

    /// Seed a funded SVM account directly into hot_state.
    fn seed(db: &SvmAccountsDB, pk: &Pubkey, bb: u64) {
        let lamports = bb * LAMPORTS_PER_BB;
        let acct = AccountSharedData::from(Account {
            lamports,
            ..Default::default()
        });
        db.store_account(pk, acct);
    }

    /// Build a standalone SvmAccountsDB via ConcurrentBlockchain (reuses existing infra).
    fn make_db() -> (Arc<SvmAccountsDB>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let bc  = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
        let db  = Arc::clone(&bc.svm_accounts);
        (db, dir)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 1 — Non-conflicting transfers execute in parallel via SVM
    // ─────────────────────────────────────────────────────────────────────────

    /// Four transfers among disjoint account pairs (A→B, C→D, E→F, G→H).
    /// No account appears in more than one batch, so all four should execute
    /// in the same parallel wave.  Post-execution balances must be exact.
    #[test]
    fn test_parallel_no_conflicts() {
        let (db, _dir) = make_db();

        // Seed senders with 100 BB each
        let pairs = [("aa", "bb"), ("cc", "dd"), ("ee", "ff"), ("gg", "hh")];
        for (sender, _) in &pairs {
            seed(&db, &addr_to_pk(sender), 100);
        }

        // Build scheduler with SVM attached
        let balances: DashMap<String, f64> = DashMap::new(); // unused by SVM path
        let scheduler = ParallelScheduler::new().with_svm(Arc::clone(&db));

        // Build 4 non-conflicting Transfer transactions (10 BB each)
        let txs: Vec<Transaction> = pairs.iter().map(|(from, to)| {
            Transaction::new(from.to_string(), to.to_string(), 10.0, TransactionType::Transfer)
        }).collect();

        let results = scheduler.execute_batch_with_locks(txs, &balances);

        // All 4 must succeed
        assert_eq!(results.len(), 4);
        for r in &results {
            assert!(r.success, "Expected success but got: {:?}", r.error);
        }

        // Verify exact SVM balances
        for (sender, recipient) in &pairs {
            assert_eq!(
                db.get_lamports(&addr_to_pk(sender)),
                90 * LAMPORTS_PER_BB,
                "Sender {} should have 90 BB", sender
            );
            assert_eq!(
                db.get_lamports(&addr_to_pk(recipient)),
                10 * LAMPORTS_PER_BB,
                "Recipient {} should have 10 BB", recipient
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 2 — Conflicting transfers are serialized; final balance is correct
    // ─────────────────────────────────────────────────────────────────────────

    /// Alice has 100 BB.  Two transfers from Alice (40 BB + 40 BB = 80 BB total)
    /// contend on her write account.  The scheduler must serialize them — both
    /// should succeed (80 ≤ 100) and Alice ends at 20 BB.
    #[test]
    fn test_parallel_with_conflicts() {
        let (db, _dir) = make_db();

        let alice = addr_to_pk("alice");
        let bob   = addr_to_pk("bob");
        let carol = addr_to_pk("carol");

        seed(&db, &alice, 100);

        let balances: DashMap<String, f64> = DashMap::new();
        let scheduler = ParallelScheduler::new().with_svm(Arc::clone(&db));

        // Both txs write alice's account → conflict → scheduler serializes them
        let tx1 = Transaction::new("alice".into(), "bob".into(),   40.0, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 40.0, TransactionType::Transfer);

        let results = scheduler.execute_batch_with_locks(vec![tx1, tx2], &balances);

        // Both must succeed (100 BB is more than enough)
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.success, "Conflicting tx failed: {:?}", r.error);
        }

        // Alice: 100 - 40 - 40 = 20 BB
        assert_eq!(db.get_lamports(&alice), 20 * LAMPORTS_PER_BB);
        // Bob and Carol each received 40 BB
        assert_eq!(db.get_lamports(&bob),   40 * LAMPORTS_PER_BB);
        assert_eq!(db.get_lamports(&carol), 40 * LAMPORTS_PER_BB);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 3 — Failed transaction doesn't affect others (atomicity)
    // ─────────────────────────────────────────────────────────────────────────

    /// Three transactions in the same batch:
    ///   1. Alice → Bob  (10 BB)  — will SUCCEED
    ///   2. Dave  → Eve  (999 BB) — will FAIL (Dave has only 50 BB)
    ///   3. Frank → Grace (5 BB)  — will SUCCEED (disjoint accounts)
    ///
    /// The failure of tx2 must not affect tx1 or tx3.
    #[test]
    fn test_parallel_batch_atomicity() {
        let (db, _dir) = make_db();

        seed(&db, &addr_to_pk("alice"), 50);
        seed(&db, &addr_to_pk("dave"),  50);
        seed(&db, &addr_to_pk("frank"), 50);

        let balances: DashMap<String, f64> = DashMap::new();
        let scheduler = ParallelScheduler::new().with_svm(Arc::clone(&db));

        let tx1 = Transaction::new("alice".into(), "bob".into(),   10.0,  TransactionType::Transfer);
        let tx2 = Transaction::new("dave".into(),  "eve".into(),   999.0, TransactionType::Transfer); // overdraft
        let tx3 = Transaction::new("frank".into(), "grace".into(), 5.0,   TransactionType::Transfer);

        let results = scheduler.execute_batch_with_locks(vec![tx1, tx2, tx3], &balances);

        assert_eq!(results.len(), 3);
        assert!(results[0].success, "tx1 (alice→bob) should succeed");
        assert!(!results[1].success, "tx2 (dave→eve overdraft) should fail");
        assert!(results[2].success, "tx3 (frank→grace) should succeed");

        // Successful txs were applied
        assert_eq!(db.get_lamports(&addr_to_pk("alice")), 40 * LAMPORTS_PER_BB);
        assert_eq!(db.get_lamports(&addr_to_pk("bob")),   10 * LAMPORTS_PER_BB);
        assert_eq!(db.get_lamports(&addr_to_pk("frank")), 45 * LAMPORTS_PER_BB);
        assert_eq!(db.get_lamports(&addr_to_pk("grace")),  5 * LAMPORTS_PER_BB);

        // Failed tx left dave untouched
        assert_eq!(db.get_lamports(&addr_to_pk("dave")), 50 * LAMPORTS_PER_BB);
        assert_eq!(db.get_lamports(&addr_to_pk("eve")),   0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 4 — Scheduler still works without SVM (legacy f64 path, no regressions)
    // ─────────────────────────────────────────────────────────────────────────

    /// Creating a ParallelScheduler WITHOUT calling .with_svm() must fall back
    /// to the legacy DashMap<String, f64> execution path.  This proves the SVM
    /// wiring is additive and doesn't break anything when the feature is enabled
    /// but no SVM is attached.
    #[test]
    fn test_parallel_fallback_without_svm() {
        // No SVM attached
        let scheduler = ParallelScheduler::new();

        let balances: DashMap<String, f64> = DashMap::new();
        balances.insert("zara".into(), 200.0);

        let tx = Transaction::new("zara".into(), "yolanda".into(), 50.0, TransactionType::Transfer);
        let results = scheduler.execute_batch_with_locks(vec![tx], &balances);

        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Legacy path tx should succeed");

        // Legacy balances updated (f64 map)
        assert_eq!(*balances.get("zara").unwrap(), 150.0);
        assert_eq!(*balances.get("yolanda").unwrap(), 50.0);
    }
}
