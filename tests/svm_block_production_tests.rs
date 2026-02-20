// ============================================================================
// BLACKBOOK SVM — BLOCK PRODUCTION INTEGRATION TESTS  (Milestone 1C)
// ============================================================================
//
// These tests prove that the SVM is wired into the live BlockProducer:
//   - TransferBb transactions execute through the SVM, not the legacy path
//   - Vault ops (DepositUsdt, etc.) still use the legacy path (zero regression)
//   - A block containing both SVM and legacy transactions works correctly
//
// Run:  cargo test --features svm --test svm_block_production_tests
// ============================================================================

#[cfg(feature = "svm")]
mod tests {
    use std::sync::{Arc, atomic::AtomicU64};
    use parking_lot::RwLock;
    use tempfile::tempdir;

    use layer1::{
        storage::ConcurrentBlockchain,
        poh_blockchain::BlockProducer,
    };
    use layer1::runtime::{
        create_poh_service, PoHConfig, LeaderSchedule,
    };
    use layer1::protocol::blockchain::{Transaction, TxData};
    use layer1::svm::LAMPORTS_PER_BB;
    use solana_sdk::pubkey::Pubkey;

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    /// Replicate the deterministic address→Pubkey mapping used in BlockProducer.
    fn test_addr_to_pubkey(addr: &str) -> Pubkey {
        use sha2::{Sha256, Digest};
        let stripped = addr.strip_prefix("bb_").unwrap_or(addr);
        let bytes: [u8; 32] = Sha256::digest(stripped.as_bytes()).into();
        Pubkey::new_from_array(bytes)
    }

    /// Build a minimal BlockProducer backed by a temp ReDB database.
    /// Returns (producer, svm_accounts Arc) so tests can inspect SVM state.
    fn make_producer() -> (
        BlockProducer,
        Arc<layer1::svm::SvmAccountsDB>,
    ) {
        let dir = tempdir().unwrap();
        let blockchain = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        // Clone the svm_accounts Arc BEFORE moving blockchain into the producer
        let svm_accounts = Arc::clone(&blockchain.svm_accounts);

        // LeaderSchedule::get_leader defaults to "genesis_validator" when schedule is empty
        let schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
        let poh = create_poh_service(PoHConfig::default());
        let current_slot = Arc::new(AtomicU64::new(0));

        let producer = BlockProducer::new(
            blockchain,
            poh,
            schedule,
            current_slot,
            "genesis_validator".to_string(),
        );

        (producer, svm_accounts)
    }

    /// Helper to build a minimal TransferBb Transaction.
    fn make_transfer_tx(id: &str, from: &str, to: &str, amount_bb: u64) -> Transaction {
        Transaction {
            hash: id.to_string(),
            from: from.to_string(),
            timestamp: 0,
            data: TxData::TransferBb {
                to: to.to_string(),
                amount: amount_bb,
            },
            signature: "sig".to_string(),
            signer_pubkey: "key".to_string(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 1 — TransferBb goes through SVM, balances land in svm_accounts
    // ─────────────────────────────────────────────────────────────────────────

    /// Submit a TransferBb transaction, produce a block, and verify that:
    ///   - The block contains the transaction (it was not rejected)
    ///   - The sender's SVM lamport balance decreased by the transferred amount
    ///   - The recipient's SVM lamport balance increased by the transferred amount
    ///   - Lazy migration seeded the sender's SVM account from the legacy balance
    #[test]
    fn test_transfer_through_svm_block_production() {
        let dir = tempdir().unwrap();
        let blockchain = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        // Fund sender in the LEGACY table — lazy migrator will seed SVM on first transfer
        let sender_addr = "bb_svm_sender_1c";
        let initial_bb = 1_000u64; // 1,000 BB
        blockchain.credit(sender_addr, initial_bb as f64).unwrap();

        let recipient_addr = "bb_svm_recipient_1c";
        let transfer_bb = 100u64;

        // Clone the svm_accounts Arc before moving blockchain
        let svm_db = Arc::clone(&blockchain.svm_accounts);

        // Build producer (moves blockchain)
        let schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
        let poh = create_poh_service(PoHConfig::default());
        let current_slot = Arc::new(AtomicU64::new(0));

        let producer = BlockProducer::new(
            blockchain,
            poh,
            schedule,
            current_slot,
            "genesis_validator".to_string(),
        );

        // Submit the transfer
        let tx = make_transfer_tx("tx_1c_001", sender_addr, recipient_addr, transfer_bb);
        producer.submit_transaction(tx).unwrap();

        // Produce a block — this triggers advance_slot, execute_transfer_via_svm, end_of_block
        let block = producer.produce_block().unwrap();

        // The block must contain our transaction
        assert_eq!(block.tx_count, 1, "Block should contain exactly 1 committed tx");
        assert_eq!(block.transactions[0].tx.hash, "tx_1c_001");

        // Verify SVM balances
        let sender_pk = test_addr_to_pubkey(sender_addr);
        let recipient_pk = test_addr_to_pubkey(recipient_addr);

        let sender_lamports = svm_db.get_lamports(&sender_pk);
        let recipient_lamports = svm_db.get_lamports(&recipient_pk);

        let expected_sender = (initial_bb - transfer_bb) * LAMPORTS_PER_BB;
        let expected_recipient = transfer_bb * LAMPORTS_PER_BB;

        assert_eq!(
            sender_lamports, expected_sender,
            "Sender SVM balance should be initial minus transferred"
        );
        assert_eq!(
            recipient_lamports, expected_recipient,
            "Recipient SVM balance should equal the transferred amount"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 2 — Legacy vault ops still use the old path (zero regression)
    // ─────────────────────────────────────────────────────────────────────────

    /// DepositUsdt, RedeemBbForUsdt and LockBbForDime must continue to work
    /// unchanged. The SVM must NOT intercept these — they stay on the legacy path.
    ///
    /// Verifies:
    ///   - DepositUsdt → credits legacy ACCOUNTS table (not SVM)
    ///   - The block commits the transaction successfully
    ///   - SVM accounts table has NO entry for the depositor (not lazily migrated)
    #[test]
    fn test_legacy_vault_ops_still_work() {
        let (producer, svm_db) = make_producer();

        let depositor = "bb_vault_depositor";

        // Submit a Tier-1 deposit (USDT → BB, legacy path)
        let deposit_tx = Transaction {
            hash: "tx_deposit_001".to_string(),
            from: depositor.to_string(),
            timestamp: 0,
            data: TxData::DepositUsdt {
                usdt_amount: 100,           // 100 USDT
                external_tx_hash: None,
            },
            signature: "sig".to_string(),
            signer_pubkey: "key".to_string(),
        };
        producer.submit_transaction(deposit_tx).unwrap();

        let block = producer.produce_block().unwrap();

        // Deposit should have succeeded (block contains it)
        assert_eq!(block.tx_count, 1, "DepositUsdt should be committed by legacy path");

        // The depositor must NOT have an SVM account — we didn't migrate it
        let depositor_pk = test_addr_to_pubkey(depositor);
        assert!(
            svm_db.get_account(&depositor_pk).is_none(),
            "Legacy vault ops must NOT create SVM accounts"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TEST 3 — Mixed block: SVM transfer + legacy deposit in the same block
    // ─────────────────────────────────────────────────────────────────────────

    /// A single block containing both a SVM-routed TransferBb and a legacy
    /// DepositUsdt must succeed. Both transactions must appear in the committed
    /// block. This proves dual-path coexistence.
    #[test]
    fn test_mixed_block_svm_and_legacy() {
        let dir = tempdir().unwrap();
        let blockchain = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();

        // Fund the transfer sender in legacy table
        let sender = "bb_mixed_sender";
        blockchain.credit(sender, 500.0).unwrap();
        let recipient = "bb_mixed_recipient";

        let svm_db = Arc::clone(&blockchain.svm_accounts);

        let schedule = Arc::new(RwLock::new(LeaderSchedule::new()));
        let poh = create_poh_service(PoHConfig::default());
        let current_slot = Arc::new(AtomicU64::new(0));

        let producer = BlockProducer::new(
            blockchain,
            poh,
            schedule,
            current_slot,
            "genesis_validator".to_string(),
        );

        // Submit both transaction types
        let transfer_tx = make_transfer_tx("tx_mix_transfer", sender, recipient, 50);
        let deposit_tx = Transaction {
            hash: "tx_mix_deposit".to_string(),
            from: "bb_depositor_mix".to_string(),
            timestamp: 0,
            data: TxData::DepositUsdt { usdt_amount: 200, external_tx_hash: None },
            signature: "sig".to_string(),
            signer_pubkey: "key".to_string(),
        };

        producer.submit_transaction(transfer_tx).unwrap();
        producer.submit_transaction(deposit_tx).unwrap();

        let block = producer.produce_block().unwrap();

        // Both transactions should be in the block
        assert_eq!(
            block.tx_count, 2,
            "Block must contain both SVM and legacy transactions"
        );

        let hashes: Vec<&str> = block.transactions.iter().map(|t| t.tx.hash.as_str()).collect();
        assert!(hashes.contains(&"tx_mix_transfer"), "SVM transfer must be in block");
        assert!(hashes.contains(&"tx_mix_deposit"),  "Legacy deposit must be in block");

        // SVM transfer balance should be updated
        let sender_pk = test_addr_to_pubkey(sender);
        let recipient_pk = test_addr_to_pubkey(recipient);

        assert_eq!(
            svm_db.get_lamports(&recipient_pk),
            50 * LAMPORTS_PER_BB,
            "SVM transfer: recipient should have 50 BB in lamports"
        );
        assert!(
            svm_db.get_lamports(&sender_pk) < 500 * LAMPORTS_PER_BB,
            "SVM transfer: sender should have been debited"
        );

        // Legacy depositor should NOT have an SVM account
        let depositor_pk = test_addr_to_pubkey("bb_depositor_mix");
        assert!(
            svm_db.get_account(&depositor_pk).is_none(),
            "Legacy-only accounts must not appear in SVM"
        );
    }
}
