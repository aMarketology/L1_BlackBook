// ============================================================================
// BLACKBOOK L1 — Phase 2B: sendTransaction + Write RPC tests
//
// These tests exercise the write-path RPC methods added in Phase 2B:
//   - sendTransaction (System Program transfer via base64 VersionedTransaction)
//   - getTransaction (lookup by signature)
//   - getSignaturesForAddress (per-address history)
//   - Signature dedup / replay rejection
//
// Run: cargo test --features svm --test rpc_send_tests
// ============================================================================

#![cfg(feature = "svm")]

use std::sync::{Arc, Mutex, atomic::AtomicU64};
use tempfile::tempdir;
use redb::Database;
use solana_sdk::{
    account::AccountSharedData,
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use base64::Engine;

use layer1::{
    svm::{SvmAccountsDB, BlackBookSVM, LAMPORTS_PER_BB},
    solana_rpc::{BlackBookRpcImpl, BlackBookRpcServer},
};

// ─────────────────────────────────────────────────────────────────────────────
// Test harness helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a fresh RPC impl backed by a tmp ReDB file.
///
/// Unlike Phase 2A's `make_rpc`, this version returns the genesis hash
/// and the SVM so tests can advance the blockhash queue.
fn make_rpc_env(slot: u64) -> (BlackBookRpcImpl, Hash) {
    use sha2::{Sha256, Digest};

    let dir = tempdir().unwrap();
    let path = dir.path().join("rpc_send_test.redb");
    std::mem::forget(dir); // keep tempdir alive

    let db = Arc::new(Database::create(path).unwrap());
    let accounts_db = Arc::new(SvmAccountsDB::new(Arc::clone(&db)).unwrap());

    let genesis_bytes: [u8; 32] = Sha256::digest(b"BLACKBOOK_L1_GENESIS_2025").into();
    let genesis_hash = Hash::new_from_array(genesis_bytes);
    let svm = Arc::new(Mutex::new(BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash)));
    let current_slot = Arc::new(AtomicU64::new(slot));

    let rpc = BlackBookRpcImpl::new(accounts_db, svm, current_slot);
    (rpc, genesis_hash)
}

/// Fund an account with a given amount of BB tokens and return the keypair + b58 address.
fn fund_keypair(rpc: &BlackBookRpcImpl, keypair: &Keypair, lamports: u64) {
    let pk = keypair.pubkey();
    let account = AccountSharedData::new(lamports, 0, &system_program::id());
    rpc.svm_db.store_account(&pk, account);
}

/// Build a signed Solana System Program transfer transaction, base64-encoded.
///
/// This is exactly what OneKey / Phantom produce when the user clicks "Send".
fn build_system_transfer_b64(
    from: &Keypair,
    to: &Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) -> String {
    // Build the System Program transfer instruction
    let ix = solana_sdk::system_instruction::transfer(&from.pubkey(), to, lamports);

    // Build a legacy Message + Transaction
    let message = Message::new(&[ix], Some(&from.pubkey()));
    let mut tx = Transaction::new_unsigned(message);
    tx.sign(&[from], recent_blockhash);

    // Serialize with bincode (Solana wire format) and return base64
    let tx_bytes = bincode::serialize(&tx).unwrap();
    base64::engine::general_purpose::STANDARD.encode(&tx_bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// sendTransaction: a System Program transfer moves lamports correctly.
#[tokio::test]
async fn test_send_transaction_system_transfer() {
    let (rpc, genesis_hash) = make_rpc_env(1);

    // Create funded sender
    let sender = Keypair::new();
    fund_keypair(&rpc, &sender, 100 * LAMPORTS_PER_BB);

    // Create recipient (no pre-existing balance — will be created by SVM)
    let recipient = Keypair::new();

    // Build a signed transfer: 10 BB from sender → recipient
    let tx_b64 = build_system_transfer_b64(
        &sender,
        &recipient.pubkey(),
        10 * LAMPORTS_PER_BB,
        genesis_hash,
    );

    // Submit via sendTransaction
    let config = layer1::solana_rpc::SendTransactionConfig {
        encoding: Some("base64".into()),
        ..Default::default()
    };
    let signature = rpc.send_transaction(tx_b64, Some(config)).await.unwrap();

    // The returned signature should be a valid base58 string (88 chars for ed25519)
    assert!(!signature.is_empty(), "signature should not be empty");
    assert!(signature.len() >= 80, "signature should be base58 ed25519 (got len={})", signature.len());

    // Verify balances changed
    let sender_balance = rpc.svm_db.get_lamports(&sender.pubkey());
    let recipient_balance = rpc.svm_db.get_lamports(&recipient.pubkey());

    assert_eq!(sender_balance, 90 * LAMPORTS_PER_BB, "sender should have 90 BB left");
    assert_eq!(recipient_balance, 10 * LAMPORTS_PER_BB, "recipient should have 10 BB");
}

/// sendTransaction: fails when sender has insufficient funds.
#[tokio::test]
async fn test_send_transaction_rejected_when_insufficient_funds() {
    let (rpc, genesis_hash) = make_rpc_env(1);

    // Sender has only 5 BB, tries to send 100 BB
    let sender = Keypair::new();
    fund_keypair(&rpc, &sender, 5 * LAMPORTS_PER_BB);

    let recipient = Keypair::new();
    let tx_b64 = build_system_transfer_b64(
        &sender,
        &recipient.pubkey(),
        100 * LAMPORTS_PER_BB,
        genesis_hash,
    );

    let config = layer1::solana_rpc::SendTransactionConfig {
        encoding: Some("base64".into()),
        ..Default::default()
    };
    let result = rpc.send_transaction(tx_b64, Some(config)).await;

    assert!(result.is_err(), "should reject insufficient funds transfer");
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("Insufficient") || err_msg.contains("insufficient") || err_msg.contains("funds"),
        "error should mention insufficient funds, got: {}", err_msg
    );
}

/// sendTransaction: rejects replay of already-processed signatures.
#[tokio::test]
async fn test_send_transaction_rejects_replay() {
    let (rpc, genesis_hash) = make_rpc_env(1);

    let sender = Keypair::new();
    fund_keypair(&rpc, &sender, 100 * LAMPORTS_PER_BB);

    let recipient = Keypair::new();
    let tx_b64 = build_system_transfer_b64(
        &sender,
        &recipient.pubkey(),
        10 * LAMPORTS_PER_BB,
        genesis_hash,
    );

    let config = layer1::solana_rpc::SendTransactionConfig {
        encoding: Some("base64".into()),
        ..Default::default()
    };

    // First submit should succeed
    let sig1 = rpc.send_transaction(tx_b64.clone(), Some(config.clone())).await.unwrap();
    assert!(!sig1.is_empty());

    // Replay the exact same transaction — should be rejected
    let result = rpc.send_transaction(tx_b64, Some(config)).await;
    assert!(result.is_err(), "replay should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("already processed") || err_msg.contains("Duplicate"),
        "error should indicate duplicate, got: {}", err_msg
    );
}

/// getTransaction: returns the confirmed transaction after sendTransaction.
#[tokio::test]
async fn test_get_transaction_returns_confirmed() {
    let (rpc, genesis_hash) = make_rpc_env(42);

    let sender = Keypair::new();
    fund_keypair(&rpc, &sender, 50 * LAMPORTS_PER_BB);

    let recipient = Keypair::new();
    let tx_b64 = build_system_transfer_b64(
        &sender,
        &recipient.pubkey(),
        5 * LAMPORTS_PER_BB,
        genesis_hash,
    );

    let config = layer1::solana_rpc::SendTransactionConfig {
        encoding: Some("base64".into()),
        ..Default::default()
    };
    let signature = rpc.send_transaction(tx_b64, Some(config)).await.unwrap();

    // Now look it up via getTransaction
    let tx = rpc.get_transaction(signature.clone(), None).await.unwrap();
    assert!(tx.is_some(), "getTransaction should find a confirmed tx");

    let tx = tx.unwrap();
    assert_eq!(tx.slot, 42, "slot should match");
    assert!(tx.meta.err.is_none(), "successful tx should have no error");
    assert!(tx.meta.compute_units_consumed.is_some(), "CU should be set");
    assert_eq!(tx.transaction.signatures[0], signature, "signature should match");
    assert!(tx.block_time.is_some(), "block_time should be set");
}

/// getSignaturesForAddress: returns signatures involving a specific address.
#[tokio::test]
async fn test_get_signatures_for_address() {
    let (rpc, genesis_hash) = make_rpc_env(10);

    let alice = Keypair::new();
    let bob = Keypair::new();
    let carol = Keypair::new();

    // Fund Alice with 200 BB
    fund_keypair(&rpc, &alice, 200 * LAMPORTS_PER_BB);

    // Send 10 BB from Alice → Bob
    let tx1_b64 = build_system_transfer_b64(
        &alice,
        &bob.pubkey(),
        10 * LAMPORTS_PER_BB,
        genesis_hash,
    );
    let config = layer1::solana_rpc::SendTransactionConfig {
        encoding: Some("base64".into()),
        ..Default::default()
    };
    let sig1 = rpc.send_transaction(tx1_b64, Some(config.clone())).await.unwrap();

    // Send 20 BB from Alice → Carol
    let tx2_b64 = build_system_transfer_b64(
        &alice,
        &carol.pubkey(),
        20 * LAMPORTS_PER_BB,
        genesis_hash,
    );
    let sig2 = rpc.send_transaction(tx2_b64, Some(config.clone())).await.unwrap();

    // Query signatures for Alice — should have both
    let alice_b58 = bs58::encode(alice.pubkey().to_bytes()).into_string();
    let sigs = rpc.get_signatures_for_address(alice_b58, None).await.unwrap();
    assert_eq!(sigs.len(), 2, "Alice should have 2 transaction signatures");

    // Verify the signatures are in the list
    let sig_strs: Vec<&str> = sigs.iter().map(|s| s.signature.as_str()).collect();
    assert!(sig_strs.contains(&sig1.as_str()), "sig1 should be in Alice's history");
    assert!(sig_strs.contains(&sig2.as_str()), "sig2 should be in Alice's history");

    // Query signatures for Bob — should have 1
    let bob_b58 = bs58::encode(bob.pubkey().to_bytes()).into_string();
    let bob_sigs = rpc.get_signatures_for_address(bob_b58, None).await.unwrap();
    assert_eq!(bob_sigs.len(), 1, "Bob should have 1 transaction signature");
    assert_eq!(bob_sigs[0].signature, sig1, "Bob's signature should be sig1");
    assert_eq!(bob_sigs[0].confirmation_status.as_deref(), Some("finalized"));
}
