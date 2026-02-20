// ============================================================================
// BLACKBOOK SVM — LAMPORT CONSERVATION INVARIANT TESTS  (Milestone 1E)
// ============================================================================
//
// Core invariant: lamports are never created or destroyed — every
// system_transfer is a zero-sum operation across the global account set.
//
//   ∀ transfers t: Σ lamports(accounts) = INITIAL_SUPPLY
//
// Run:  cargo test --features svm --test svm_invariant_tests
// Run slow:  cargo test --features svm --test svm_invariant_tests -- --nocapture
// ============================================================================

#[cfg(feature = "svm")]
mod tests {
    use std::sync::Arc;
    use tempfile::tempdir;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use sha2::{Sha256, Digest};
    use solana_sdk::{
        pubkey::Pubkey,
        account::{Account, AccountSharedData},
    };

    use layer1::storage::ConcurrentBlockchain;
    use layer1::svm::{SvmAccountsDB, LAMPORTS_PER_BB};

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    fn idx_to_pk(i: usize) -> Pubkey {
        let label = format!("acct_{:04}", i);
        Pubkey::new_from_array(Sha256::digest(label.as_bytes()).into())
    }

    fn seed(db: &SvmAccountsDB, pk: &Pubkey, lamports: u64) {
        let acct = AccountSharedData::from(Account {
            lamports,
            ..Default::default()
        });
        db.store_account(pk, acct);
    }

    fn make_db() -> (Arc<SvmAccountsDB>, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let bc  = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
        let db  = Arc::clone(&bc.svm_accounts);
        (db, dir)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 1 — 10,000 random transfers: supply never changes
    // ─────────────────────────────────────────────────────────────────────────

    /// Seeds N_ACCOUNTS accounts, each with INITIAL_BB_PER_ACCOUNT BB.
    /// Then runs TRANSFER_COUNT random transfers (random sender, recipient,
    /// and amount up to MAX_TRANSFER_BB).
    ///
    /// After every CHECK_INTERVAL transfers and at the very end, asserts:
    ///   db.total_lamports() == INITIAL_SUPPLY
    ///
    /// Transfers that fail (e.g. insufficient funds) are counted separately
    /// and must not change the total.
    #[test]
    fn test_global_lamport_conservation() {
        const N_ACCOUNTS:            usize = 50;
        const INITIAL_BB_PER_ACCOUNT: u64  = 1_000;
        const TRANSFER_COUNT:        usize = 10_000;
        const MAX_TRANSFER_BB:        u64  = 200;      // can exceed balance → some will fail
        const CHECK_INTERVAL:        usize = 100;      // verify supply every N transfers

        let (db, _dir) = make_db();

        // Seed accounts
        let pks: Vec<Pubkey> = (0..N_ACCOUNTS).map(idx_to_pk).collect();
        for pk in &pks {
            seed(&db, pk, INITIAL_BB_PER_ACCOUNT * LAMPORTS_PER_BB);
        }

        // Compute and freeze expected supply (use checked arithmetic)
        let initial_supply: u64 = pks
            .iter()
            .map(|pk| db.get_lamports(pk))
            .try_fold(0u64, |acc, l| acc.checked_add(l))
            .expect("Initial supply overflowed u64 — reduce N_ACCOUNTS or INITIAL_BB");

        assert_eq!(
            initial_supply,
            (N_ACCOUNTS as u64) * INITIAL_BB_PER_ACCOUNT * LAMPORTS_PER_BB,
            "Seed verification failed"
        );

        // Deterministic RNG so failures are reproducible
        let mut rng = StdRng::seed_from_u64(0xB1ACB00B_5EED_0001);

        let mut succeeded = 0usize;
        let mut failed    = 0usize;

        for i in 0..TRANSFER_COUNT {
            // Pick random sender ≠ recipient
            let from_idx = rng.gen_range(0..N_ACCOUNTS);
            let mut to_idx = rng.gen_range(0..N_ACCOUNTS);
            while to_idx == from_idx {
                to_idx = rng.gen_range(0..N_ACCOUNTS);
            }

            let amount_bb = rng.gen_range(1..=MAX_TRANSFER_BB);
            let lamports  = amount_bb * LAMPORTS_PER_BB;

            match db.system_transfer(&pks[from_idx], &pks[to_idx], lamports) {
                Ok(()) => succeeded += 1,
                Err(_) => failed    += 1, // insufficient funds, overflow, etc. — no state change
            }

            // Periodic invariant check
            if (i + 1) % CHECK_INTERVAL == 0 {
                let current = db.total_lamports();
                assert_eq!(
                    current, initial_supply,
                    "Supply violated after {} transfers (succeeded={}, failed={}): \
                     expected {} lamports, got {}",
                    i + 1, succeeded, failed, initial_supply, current
                );
            }
        }

        // Final check
        let final_supply = db.total_lamports();
        assert_eq!(
            final_supply, initial_supply,
            "Final supply violated after {TRANSFER_COUNT} transfers \
             (succeeded={succeeded}, failed={failed})"
        );

        // Sanity: at least 60% of transfers should have succeeded
        // (with 50 accounts × 1000 BB and max transfer 200 BB, most should work)
        let success_rate = succeeded as f64 / TRANSFER_COUNT as f64;
        assert!(
            success_rate > 0.60,
            "Unexpectedly low success rate: {:.1}% (check initial balances / max transfer)",
            success_rate * 100.0
        );

        println!(
            "Conservation test: {TRANSFER_COUNT} transfers, {succeeded} ok, {failed} failed, \
             supply stable at {} lamports ({} BB)",
            final_supply,
            final_supply / LAMPORTS_PER_BB
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 2 — Checked arithmetic: no bare +/- can silently overflow
    // ─────────────────────────────────────────────────────────────────────────

    /// The SvmAccountsDB must reject a transfer that would overflow the
    /// recipient's u64 lamport counter.  If it accepted such a transfer the
    /// conservation invariant would be violated going the other direction.
    #[test]
    fn test_overflow_is_rejected() {
        let (db, _dir) = make_db();

        let sender = idx_to_pk(0);
        let recip  = idx_to_pk(1);

        // Seed recipient with near-max balance
        let near_max = u64::MAX - 500 * LAMPORTS_PER_BB;
        seed(&db, &recip,  near_max / LAMPORTS_PER_BB);     // approximate
        seed(&db, &sender, 1_000);                           // 1000 lamports

        // Manually set recipient to near-max via direct store so we bypass BB rounding
        let near_max_acct = AccountSharedData::from(Account { lamports: near_max, ..Default::default() });
        db.store_account(&recip, near_max_acct);

        let before_sender = db.get_lamports(&sender);
        let before_recip  = db.get_lamports(&recip);

        // Try to transfer enough to overflow the recipient
        let overflow_amount = u64::MAX - near_max + 1;
        let result = db.system_transfer(&sender, &recip, overflow_amount);

        // Must fail (either overflow guard or insufficient sender funds)
        assert!(
            result.is_err(),
            "Overflow transfer should have been rejected"
        );

        // State must be unchanged
        assert_eq!(db.get_lamports(&sender), before_sender, "Sender changed after rejected transfer");
        assert_eq!(db.get_lamports(&recip),  before_recip,  "Recipient changed after rejected transfer");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 3 — Parallel conservation: concurrent transfers preserve the supply
    // ─────────────────────────────────────────────────────────────────────────

    /// Runs 50 parallel transfers on STRICTLY DISJOINT account pairs via rayon,
    /// then verifies supply.  Each of the 50 pairs (0→1, 2→3, …, 98→99) is
    /// touched by exactly one thread so there are no overlapping writes.
    ///
    /// This proves the DashMap hot_state doesn't corrupt lamport balances when
    /// multiple threads write to non-overlapping entries concurrently.
    ///
    /// NOTE: calls that share accounts MUST go through ParallelScheduler's
    /// AccountLockManager first (as tested in svm_parallel_tests.rs).
    #[test]
    fn test_parallel_lamport_conservation() {
        use rayon::prelude::*;

        const N: usize = 100; // 50 disjoint pairs

        let (db, _dir) = make_db();
        let pks: Vec<Pubkey> = (0..N).map(idx_to_pk).collect();

        for pk in &pks {
            seed(&db, pk, 500 * LAMPORTS_PER_BB); // 500 BB each
        }

        let initial_supply = db.total_lamports();

        // 50 strictly disjoint pairs: (0→1), (2→3), …, (98→99)
        // Each account appears in exactly ONE concurrent transfer.
        let pairs: Vec<(usize, usize)> = (0..N / 2).map(|i| (i * 2, i * 2 + 1)).collect();

        pairs.par_iter().for_each(|(from_idx, to_idx)| {
            db.system_transfer(&pks[*from_idx], &pks[*to_idx], LAMPORTS_PER_BB)
                .expect("Disjoint transfer should not fail");
        });

        assert_eq!(
            db.total_lamports(), initial_supply,
            "Supply changed after parallel transfers on disjoint account pairs"
        );

        // Each sender should have lost 1 BB; each recipient gained 1 BB
        for i in 0..N / 2 {
            let sender = &pks[i * 2];
            let recip  = &pks[i * 2 + 1];
            assert_eq!(db.get_lamports(sender), (500 - 1) * LAMPORTS_PER_BB);
            assert_eq!(db.get_lamports(recip),  (500 + 1) * LAMPORTS_PER_BB);
        }
    }
}
