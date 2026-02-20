// ============================================================================
// BLACKBOOK SVM — RUNTIME TESTS  (Milestone 1B.1)
// ============================================================================
//
// Tests for BlackBookSVM execution engine: native-Rust system transfers,
// blockhash queue management, and compute-unit accounting.
//
// All tests run under `#[cfg(feature = "svm")]` — they only exist in the
// SVM feature gate build.
//
// Run:  cargo test --features svm --test svm_runtime_tests
// ============================================================================

#[cfg(feature = "svm")]
mod tests {
    use std::sync::Arc;
    use tempfile::tempdir;
    use redb::Database;
    use solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        hash::Hash,
        pubkey::Pubkey,
    };
    use layer1::svm::{
        SvmAccountsDB,
        LAMPORTS_PER_BB,
        RENT_EPOCH_EXEMPT,
        MAX_RECENT_BLOCKHASHES,
    };
    use layer1::svm::runtime::{BlackBookSVM, TransferRequest};

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    fn setup_db() -> Arc<Database> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        Arc::new(Database::create(path).unwrap())
    }

    /// Build a SVM with a seeded genesis hash and two funded accounts.
    fn setup_svm_with_accounts(
        a_lamports: u64,
        b_lamports: u64,
    ) -> (BlackBookSVM, Pubkey, Pubkey, Hash) {
        let db = setup_db();
        let accounts_db = Arc::new(SvmAccountsDB::new(db).unwrap());

        let pk_a = Pubkey::new_unique();
        let pk_b = Pubkey::new_unique();

        let acc_a = AccountSharedData::new(
            a_lamports,
            0,
            &solana_sdk::system_program::id(),
        );
        let acc_b = AccountSharedData::new(
            b_lamports,
            0,
            &solana_sdk::system_program::id(),
        );
        accounts_db.store_account(&pk_a, acc_a);
        accounts_db.store_account(&pk_b, acc_b);

        let genesis_hash = Hash::new_unique();
        let svm = BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash);

        (svm, pk_a, pk_b, genesis_hash)
    }

    fn make_req(from: Pubkey, to: Pubkey, lamports: u64, blockhash: Hash) -> TransferRequest {
        TransferRequest {
            tx_id: format!("tx_{}", Pubkey::new_unique()),
            from,
            to,
            lamports,
            recent_blockhash: blockhash,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 1 — Basic transfer: 100 lamports A → B
    // ─────────────────────────────────────────────────────────────────────────

    /// Transfer 100 lamports from a funded account to another funded account.
    ///
    /// Verifies:
    ///   - Execution result is successful
    ///   - Sender balance decreases by exactly 100
    ///   - Recipient balance increases by exactly 100
    ///   - Compute units are reported (> 0)
    ///   - Lamport deltas match the transfer
    #[test]
    fn test_system_transfer_basic() {
        let initial = 1_000 * LAMPORTS_PER_BB;
        let (svm, pk_a, pk_b, genesis_hash) = setup_svm_with_accounts(initial, initial);

        let req = make_req(pk_a, pk_b, 100, genesis_hash);
        let result = svm.execute_transfer(&req);

        assert!(result.success, "Transfer should succeed; err = {:?}", result.error);
        assert_eq!(result.compute_units_consumed, 21_000); // System transfer baseline

        // Verify balances via accounts_db
        let a_balance = svm.accounts_db.get_lamports(&pk_a);
        let b_balance = svm.accounts_db.get_lamports(&pk_b);
        assert_eq!(a_balance, initial - 100, "Sender should be debited exactly 100");
        assert_eq!(b_balance, initial + 100, "Recipient should be credited exactly 100");

        // Verify deltas embedded in the result
        let from_delta = result.lamport_deltas.iter()
            .find(|(addr, _)| *addr == pk_a.to_string())
            .map(|(_, d)| *d)
            .unwrap_or(0);
        let to_delta = result.lamport_deltas.iter()
            .find(|(addr, _)| *addr == pk_b.to_string())
            .map(|(_, d)| *d)
            .unwrap_or(0);

        assert_eq!(from_delta, -100i64, "Sender delta should be -100");
        assert_eq!(to_delta, 100i64, "Recipient delta should be +100");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 2 — Insufficient funds: amount > sender balance
    // ─────────────────────────────────────────────────────────────────────────

    /// Attempt to overdraft — should fail gracefully with no state mutation.
    ///
    /// Verifies:
    ///   - Result is an error (not a panic)
    ///   - Sender balance is UNCHANGED after the failed transfer
    ///   - Recipient balance is UNCHANGED after the failed transfer
    #[test]
    fn test_system_transfer_insufficient() {
        let sender_balance = 50 * LAMPORTS_PER_BB;
        let (svm, pk_a, pk_b, genesis_hash) = setup_svm_with_accounts(sender_balance, 0);

        // Try to send more than the sender has
        let req = make_req(pk_a, pk_b, sender_balance + 1, genesis_hash);
        let result = svm.execute_transfer(&req);

        assert!(!result.success, "Overdraft should fail");
        assert!(result.error.is_some(), "Error must be populated on failure");

        if let Some(layer1::svm::SvmError::InsufficientFunds { available, required }) = &result.error {
            assert_eq!(*available, sender_balance);
            assert_eq!(*required, sender_balance + 1);
        } else {
            panic!("Expected InsufficientFunds error, got {:?}", result.error);
        }

        // State must be completely unchanged
        assert_eq!(
            svm.accounts_db.get_lamports(&pk_a),
            sender_balance,
            "Sender balance must be unchanged after failed transfer"
        );
        assert_eq!(
            svm.accounts_db.get_lamports(&pk_b),
            0,
            "Recipient balance must be unchanged after failed transfer"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 3 — Transfer to a new (non-existent) account
    // ─────────────────────────────────────────────────────────────────────────

    /// Send lamports to an address that has never been seen before.
    ///
    /// Solana semantics: the recipient account is created on-the-fly,
    /// owned by System Program with zero data and rent-exempt lamport balance.
    ///
    /// Verifies:
    ///   - Transfer succeeds
    ///   - New account is created with the transferred amount
    ///   - New account has rent_epoch = RENT_EPOCH_EXEMPT (BB L1 invariant)
    ///   - New account is owned by system_program
    #[test]
    fn test_system_transfer_to_new_account() {
        let initial = 1_000 * LAMPORTS_PER_BB;
        let db = setup_db();
        let accounts_db = Arc::new(SvmAccountsDB::new(db).unwrap());

        let pk_sender = Pubkey::new_unique();
        let pk_new = Pubkey::new_unique(); // This account does NOT exist yet

        accounts_db.store_account(
            &pk_sender,
            AccountSharedData::new(initial, 0, &solana_sdk::system_program::id()),
        );

        let genesis_hash = Hash::new_unique();
        let svm = BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash);

        // Verify the recipient doesn't exist before transfer
        assert!(
            svm.accounts_db.get_account(&pk_new).is_none(),
            "Recipient should not exist before transfer"
        );

        let req = make_req(pk_sender, pk_new, 500, genesis_hash);
        let result = svm.execute_transfer(&req);

        assert!(result.success, "Transfer to new account should succeed; err = {:?}", result.error);

        // Verify new account was created
        let new_account = svm.accounts_db.get_account(&pk_new)
            .expect("New account should exist after transfer");

        assert_eq!(new_account.lamports(), 500, "New account should have transferred lamports");
        assert_eq!(
            new_account.rent_epoch(),
            RENT_EPOCH_EXEMPT,
            "BB L1: all accounts must be rent-exempt forever"
        );
        assert_eq!(
            new_account.owner(),
            &solana_sdk::system_program::id(),
            "New account should be owned by system program"
        );

        // Sender is debited
        assert_eq!(
            svm.accounts_db.get_lamports(&pk_sender),
            initial - 500
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 4 — Blockhash validation: reject a hash not in the recent queue
    // ─────────────────────────────────────────────────────────────────────────

    /// A transaction referencing an unknown / stale blockhash must be rejected.
    ///
    /// Verifies:
    ///   - SVM rejects the transaction with InvalidBlockhash error
    ///   - No state mutation occurs
    ///   - Genesis hash (still in queue) is accepted for a valid transaction
    #[test]
    fn test_blockhash_validation() {
        let initial = 1_000 * LAMPORTS_PER_BB;
        let (svm, pk_a, pk_b, genesis_hash) = setup_svm_with_accounts(initial, 0);

        // Use a totally random hash not in the queue
        let stale_hash = Hash::new_unique();
        assert_ne!(stale_hash, genesis_hash);

        let bad_req = make_req(pk_a, pk_b, 100, stale_hash);
        let bad_result = svm.execute_transfer(&bad_req);

        assert!(!bad_result.success, "Stale blockhash should be rejected");
        assert!(
            matches!(bad_result.error, Some(layer1::svm::SvmError::InvalidBlockhash)),
            "Error must be InvalidBlockhash, got {:?}",
            bad_result.error
        );

        // No state mutation from the rejected transaction
        assert_eq!(
            svm.accounts_db.get_lamports(&pk_a),
            initial,
            "Sender balance must be unchanged after rejected transaction"
        );

        // Genesis hash is still valid — a good request succeeds
        let good_req = make_req(pk_a, pk_b, 100, genesis_hash);
        let good_result = svm.execute_transfer(&good_req);
        assert!(good_result.success, "Valid blockhash should succeed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 5 — Blockhash queue eviction: 151st entry evicts the oldest
    // ─────────────────────────────────────────────────────────────────────────

    /// After MAX_RECENT_BLOCKHASHES (150) slots have passed, the genesis hash
    /// must be evicted. A transaction still referencing that hash is rejected.
    ///
    /// Verifies:
    ///   - After 150 advance_slot calls the genesis hash is still valid
    ///   - After the 151st advance_slot call the genesis hash is evicted
    ///   - The newest hash is still valid after eviction
    #[test]
    fn test_blockhash_queue_eviction() {
        let db = setup_db();
        let accounts_db = Arc::new(SvmAccountsDB::new(db).unwrap());

        let genesis_hash = Hash::new_unique();
        let mut svm = BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash);

        // Genesis hash is seeded at slot 0 — queue length should be 1
        assert_eq!(svm.blockhash_queue_len(), 1);

        // Advance through MAX_RECENT_BLOCKHASHES - 1 additional slots.
        // Queue starts at 1 (genesis), adding 149 more → exactly 150 = cap.
        // Genesis is still the oldest entry (no eviction yet).
        let mut latest_hash = genesis_hash;
        for slot in 1..MAX_RECENT_BLOCKHASHES {
            latest_hash = Hash::new_unique();
            svm.advance_slot(slot, latest_hash);
        }

        // Queue should be exactly at the cap
        assert_eq!(
            svm.blockhash_queue_len() as u64,
            MAX_RECENT_BLOCKHASHES,
            "Queue should be full at {} entries",
            MAX_RECENT_BLOCKHASHES
        );

        // Genesis hash is still valid at exactly the limit
        assert!(
            svm.is_valid_blockhash(&genesis_hash),
            "Genesis hash should still be valid at the limit"
        );

        // Push one more slot — this makes 151 entries, evicting genesis
        let evicting_hash = Hash::new_unique();
        svm.advance_slot(MAX_RECENT_BLOCKHASHES, evicting_hash);

        assert_eq!(
            svm.blockhash_queue_len() as u64,
            MAX_RECENT_BLOCKHASHES,
            "Queue length must remain at cap after eviction"
        );

        // Genesis hash must now be invalid
        assert!(
            !svm.is_valid_blockhash(&genesis_hash),
            "Genesis hash must be evicted after {} + 1 slots",
            MAX_RECENT_BLOCKHASHES
        );

        // The most recently added hash must still be valid
        assert!(
            svm.is_valid_blockhash(&evicting_hash),
            "The freshest hash must remain valid"
        );
        assert!(
            svm.is_valid_blockhash(&latest_hash),
            "The second-newest hash must still be valid"
        );
    }
}
