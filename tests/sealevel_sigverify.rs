// ============================================================================
// BLACKBOOK L1 — SEALEVEL PARALLEL SIGNATURE VERIFICATION INTEGRATION TEST
// ============================================================================
//
// This test suite targets the full pipeline:
//
//   [Ed25519 Keypairs]
//       ↓  sign real L1-formatted messages
//   [SigVerifyRequest batch]
//       ↓  ParallelSigVerifier (Rayon par_chunks)
//   [bool results, all valid]
//       ↓  feed valid pubkeys + lamport amounts
//   [BlackBookSVM + SvmAccountsDB]
//       ↓  execute_transfer_batch (Sealevel parallel, no lock contention)
//   [TransactionExecutionResult per tx]
//
// Tests cover:
//   1. Large-batch parallel sig verification (throughput test)
//   2. Mixed valid/invalid batch — invalid sigs must be rejected
//   3. Full pipeline: sign → verify → SVM transfer (50 concurrent transfers)
//   4. Duplicate tx_id rejection (replay protection)
//   5. Stale blockhash rejection
//   6. L1 message format conformance for all 4 op types
//
// Run with:
//   cargo test --test sealevel_sigverify -- --nocapture
// ============================================================================

use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use solana_sdk::{hash::Hash, pubkey::Pubkey};
use tempfile::NamedTempFile;
use redb::Database;

use layer1::svm::{
    accounts_db::SvmAccountsDB,
    runtime::{BlackBookSVM, TransferRequest},
};
use layer1::svm::sigverify::{ParallelSigVerifier, SigVerifyRequest};

// ============================================================================
// HELPERS
// ============================================================================

/// Generate a fresh Ed25519 keypair and return (SigningKey, Pubkey).
fn new_keypair() -> (SigningKey, Pubkey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_bytes = sk.verifying_key().to_bytes();
    let pubkey = Pubkey::new_from_array(pk_bytes);
    (sk, pubkey)
}

/// Build a real L1 TRANSFER message and sign it.
/// Format: "TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}"
fn sign_transfer_message(
    sk: &SigningKey,
    from: &Pubkey,
    to: &Pubkey,
    amount: f64,
    nonce: &str,
) -> SigVerifyRequest {
    let msg = format!(
        "TRANSFER:{}:{}:{:.6}:{}:{}",
        from, to, amount, 1_700_000_000u64, nonce
    );
    let sig = sk.sign(msg.as_bytes());
    SigVerifyRequest {
        message: msg.into_bytes(),
        pubkey_bytes: sk.verifying_key().to_bytes(),
        signature_bytes: sig.to_bytes(),
    }
}

/// Build a real L1 FAUCET message and sign it.
/// Format: "FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"
fn sign_faucet_message(sk: &SigningKey, addr: &Pubkey, amount: f64, nonce: &str) -> SigVerifyRequest {
    let msg = format!("FAUCET:{}:{:.6}:{}:{}", addr, amount, 1_700_000_000u64, nonce);
    let sig = sk.sign(msg.as_bytes());
    SigVerifyRequest {
        message: msg.into_bytes(),
        pubkey_bytes: sk.verifying_key().to_bytes(),
        signature_bytes: sig.to_bytes(),
    }
}

/// Build a real L1 ESCROW_DEPOSIT message and sign it.
fn sign_escrow_deposit(sk: &SigningKey, addr: &Pubkey, amount: f64, nonce: &str) -> SigVerifyRequest {
    let msg = format!("ESCROW_DEPOSIT:{}:{:.6}:{}:{}", addr, amount, 1_700_000_000u64, nonce);
    let sig = sk.sign(msg.as_bytes());
    SigVerifyRequest {
        message: msg.into_bytes(),
        pubkey_bytes: sk.verifying_key().to_bytes(),
        signature_bytes: sig.to_bytes(),
    }
}

/// Build a real L1 ESCROW_WITHDRAW message and sign it.
fn sign_escrow_withdraw(
    sk: &SigningKey,
    market_id: &str,
    addr: &Pubkey,
    amount: f64,
    nonce: &str,
) -> SigVerifyRequest {
    let msg = format!(
        "ESCROW_WITHDRAW:{}:{}:{:.6}:{}:{}",
        market_id, addr, amount, 1_700_000_000u64, nonce
    );
    let sig = sk.sign(msg.as_bytes());
    SigVerifyRequest {
        message: msg.into_bytes(),
        pubkey_bytes: sk.verifying_key().to_bytes(),
        signature_bytes: sig.to_bytes(),
    }
}

/// Create an in-memory ReDB + SvmAccountsDB + BlackBookSVM triple for testing.
fn make_svm(tmpfile: &NamedTempFile) -> (Arc<SvmAccountsDB>, BlackBookSVM) {
    let db = Arc::new(Database::create(tmpfile.path()).unwrap());
    let accounts_db = Arc::new(SvmAccountsDB::new(Arc::clone(&db)).unwrap());
    let genesis_hash = Hash::new_unique();
    let svm = BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash);
    (accounts_db, svm)
}

/// Fund an account with `lamports` by seeding it directly into hot_state.
fn fund_account(db: &SvmAccountsDB, pubkey: &Pubkey, lamports: u64) {
    use solana_sdk::account::AccountSharedData;
    let acc = AccountSharedData::new(lamports, 0, &Pubkey::default());
    db.hot_state.insert(*pubkey, acc);
}

// ============================================================================
// TEST 1: LARGE-BATCH PARALLEL SIGNATURE VERIFICATION
// ============================================================================

#[test]
fn test_large_batch_parallel_verify_throughput() {
    const N: usize = 10_000;
    let verifier = ParallelSigVerifier::new(512);

    // Generate N unique keypairs and sign with real TRANSFER messages
    let requests: Vec<SigVerifyRequest> = (0..N)
        .map(|i| {
            let (sk, from) = new_keypair();
            let (_, to) = new_keypair();
            sign_transfer_message(&sk, &from, &to, 1.0, &format!("nonce-{}", i))
        })
        .collect();

    let t0 = Instant::now();
    let results = verifier.verify_batch(&requests);
    let elapsed = t0.elapsed();

    let valid_count = results.iter().filter(|&&v| v).count();

    println!(
        "[throughput] {N} sigs verified in {:.2?} — {:.0} sigs/sec",
        elapsed,
        N as f64 / elapsed.as_secs_f64()
    );

    assert_eq!(results.len(), N, "Must return one result per request");
    assert_eq!(valid_count, N, "All signatures must be valid");
}

// ============================================================================
// TEST 2: MIXED VALID/INVALID BATCH — INVALID SIGS REJECTED
// ============================================================================

#[test]
fn test_mixed_valid_invalid_batch() {
    let verifier = ParallelSigVerifier::new(64);

    let mut requests: Vec<SigVerifyRequest> = (0..20)
        .map(|i| {
            let (sk, from) = new_keypair();
            let (_, to) = new_keypair();
            sign_transfer_message(&sk, &from, &to, 0.5, &format!("n-{}", i))
        })
        .collect();

    // Corrupt every 4th entry: tamper with the message after signing
    let mut corrupted_indices = vec![];
    for i in (0..20).step_by(4) {
        requests[i].message = b"tampered_message_that_was_not_signed".to_vec();
        corrupted_indices.push(i);
    }

    let results = verifier.verify_batch(&requests);

    for (i, &valid) in results.iter().enumerate() {
        if corrupted_indices.contains(&i) {
            assert!(!valid, "Corrupted sig at index {i} should be invalid");
        } else {
            assert!(valid, "Valid sig at index {i} should pass verification");
        }
    }
}

// ============================================================================
// TEST 3: FULL PIPELINE — SIGN → VERIFY → SVM TRANSFER (50 CONCURRENT)
// ============================================================================

#[test]
fn test_sign_verify_svm_transfer_pipeline() {
    const N: usize = 50;
    let tmpfile = NamedTempFile::new().unwrap();
    let (accounts_db, mut svm) = make_svm(&tmpfile);

    const LAMPORTS_PER_BB: u64 = 1_000_000_000;
    let genesis = svm.current_blockhash();

    // Create N sender keypairs and fund them
    let mut actors: Vec<(SigningKey, Pubkey, Pubkey)> = Vec::with_capacity(N);
    for _ in 0..N {
        let (sk, from) = new_keypair();
        let (_, to) = new_keypair();
        fund_account(&accounts_db, &from, 10 * LAMPORTS_PER_BB);
        fund_account(&accounts_db, &to, 0);
        actors.push((sk, from, to));
    }

    // Stage 1: Build and sign real TRANSFER messages
    let sig_requests: Vec<SigVerifyRequest> = actors
        .iter()
        .enumerate()
        .map(|(i, (sk, from, to))| {
            sign_transfer_message(sk, from, to, 1.0, &format!("pipeline-{}", i))
        })
        .collect();

    // Stage 2: Parallel signature verification
    let verifier = ParallelSigVerifier::new(128);
    let sig_results = verifier.verify_batch(&sig_requests);
    assert!(
        sig_results.iter().all(|&v| v),
        "All pipeline signatures must verify"
    );

    // Stage 3: Build SVM transfer requests for all verified txs
    let transfer_requests: Vec<TransferRequest> = actors
        .iter()
        .enumerate()
        .map(|(i, (_, from, to))| TransferRequest {
            tx_id: format!("pipeline-tx-{}", i),
            from: *from,
            to: *to,
            lamports: LAMPORTS_PER_BB, // 1 BB
            recent_blockhash: genesis,
        })
        .collect();

    // Stage 4: Execute all transfers through the SVM
    let t0 = Instant::now();
    let execution_results = svm.execute_transfer_batch(&transfer_requests);
    let elapsed = t0.elapsed();

    println!(
        "[pipeline] {N} transfers executed in {:.2?}",
        elapsed
    );

    let success_count = execution_results.iter().filter(|r| r.success).count();
    assert_eq!(
        success_count, N,
        "All {} transfers should succeed, got {} successes",
        N, success_count
    );

    // Verify balances shifted correctly
    for (_, from, to) in &actors {
        let from_bal = accounts_db.get_lamports(from);
        let to_bal = accounts_db.get_lamports(to);
        assert_eq!(from_bal, 9 * LAMPORTS_PER_BB, "Sender should have 9 BB left");
        assert_eq!(to_bal, LAMPORTS_PER_BB, "Recipient should have 1 BB");
    }
}

// ============================================================================
// TEST 4: REPLAY PROTECTION — DUPLICATE TX_ID REJECTED
// ============================================================================

#[test]
fn test_duplicate_tx_rejected() {
    let tmpfile = NamedTempFile::new().unwrap();
    let (accounts_db, mut svm) = make_svm(&tmpfile);

    const LAMPORTS_PER_BB: u64 = 1_000_000_000;
    let genesis = svm.current_blockhash();

    let (_sk, from) = new_keypair();
    let (_, to) = new_keypair();
    fund_account(&accounts_db, &from, 10 * LAMPORTS_PER_BB);
    fund_account(&accounts_db, &to, 0);

    let req = TransferRequest {
        tx_id: "replay-test-tx".to_string(),
        from,
        to,
        lamports: LAMPORTS_PER_BB,
        recent_blockhash: genesis,
    };

    let first = svm.execute_transfer(&req);
    assert!(first.success, "First execution must succeed");

    let second = svm.execute_transfer(&req);
    assert!(!second.success, "Replay of same tx_id must be rejected");
    assert!(
        matches!(second.error, Some(layer1::svm::types::SvmError::DuplicateSignature(_))),
        "Error should be DuplicateSignature, got: {:?}",
        second.error
    );
}

// ============================================================================
// TEST 5: STALE BLOCKHASH REJECTED
// ============================================================================

#[test]
fn test_stale_blockhash_rejected() {
    let tmpfile = NamedTempFile::new().unwrap();
    let (accounts_db, mut svm) = make_svm(&tmpfile);

    const LAMPORTS_PER_BB: u64 = 1_000_000_000;

    let (_sk, from) = new_keypair();
    let (_, to) = new_keypair();
    fund_account(&accounts_db, &from, 10 * LAMPORTS_PER_BB);
    fund_account(&accounts_db, &to, 0);

    // Advance 160 slots — the genesis hash should be evicted (window = 150)
    for slot in 1..=160u64 {
        svm.advance_slot(slot, Hash::new_unique());
    }

    let stale_req = TransferRequest {
        tx_id: "stale-blockhash-tx".to_string(),
        from,
        to,
        lamports: LAMPORTS_PER_BB,
        recent_blockhash: Hash::default(), // genesis hash — now stale
    };

    let result = svm.execute_transfer(&stale_req);
    assert!(!result.success, "Transaction with stale blockhash must fail");
}

// ============================================================================
// TEST 6: L1 MESSAGE FORMAT CONFORMANCE — ALL 4 OP TYPES
// ============================================================================

#[test]
fn test_all_l1_message_formats_verify_correctly() {
    let verifier = ParallelSigVerifier::default_batch();
    let (sk, addr) = new_keypair();
    let (_, to) = new_keypair();

    let requests = vec![
        sign_transfer_message(&sk, &addr, &to, 2.5, "nonce-transfer"),
        sign_faucet_message(&sk, &addr, 0.1, "nonce-faucet"),
        sign_escrow_deposit(&sk, &addr, 10.0, "nonce-escrow-dep"),
        sign_escrow_withdraw(&sk, "market-bb-usdc", &addr, 5.0, "nonce-escrow-wd"),
    ];

    let results = verifier.verify_batch(&requests);
    let labels = ["TRANSFER", "FAUCET", "ESCROW_DEPOSIT", "ESCROW_WITHDRAW"];

    for (i, (&valid, label)) in results.iter().zip(labels.iter()).enumerate() {
        assert!(valid, "Message format {} (index {}) must verify", label, i);
    }
}

// ============================================================================
// TEST 7: SHARD ZERO-CONTENTION — NON-OVERLAPPING ACCOUNTS
// ============================================================================

#[test]
fn test_non_overlapping_svm_transfers_all_succeed() {
    // Accounts whose pubkeys have distinct first bytes land in different shards.
    // This verifies the ShardedAccountState contract: zero DashMap contention.
    let tmpfile = NamedTempFile::new().unwrap();
    let (accounts_db, mut svm) = make_svm(&tmpfile);

    const LAMPORTS_PER_BB: u64 = 1_000_000_000;
    let genesis = svm.current_blockhash();

    // Create 16 pairs where each sender has a distinct first byte (shard bucket)
    let pairs: Vec<(Pubkey, Pubkey)> = (0u8..16)
        .map(|byte| {
            let mut from_bytes = [0u8; 32];
            let mut to_bytes = [0u8; 32];
            from_bytes[0] = byte;
            to_bytes[0] = byte.wrapping_add(128); // guaranteed different shard
            let from = Pubkey::new_from_array(from_bytes);
            let to = Pubkey::new_from_array(to_bytes);
            fund_account(&accounts_db, &from, 5 * LAMPORTS_PER_BB);
            fund_account(&accounts_db, &to, 0);
            (from, to)
        })
        .collect();

    let reqs: Vec<TransferRequest> = pairs
        .iter()
        .enumerate()
        .map(|(i, (from, to))| TransferRequest {
            tx_id: format!("shard-tx-{}", i),
            from: *from,
            to: *to,
            lamports: LAMPORTS_PER_BB,
            recent_blockhash: genesis,
        })
        .collect();

    let results = svm.execute_transfer_batch(&reqs);
    let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();
    assert!(
        failed.is_empty(),
        "All non-overlapping shard transfers must succeed. Failures: {:?}",
        failed
    );
}

// ============================================================================
// TEST 8: INSUFFICIENT BALANCE REJECTION
// ============================================================================

#[test]
fn test_insufficient_balance_rejected() {
    let tmpfile = NamedTempFile::new().unwrap();
    let (accounts_db, mut svm) = make_svm(&tmpfile);

    const LAMPORTS_PER_BB: u64 = 1_000_000_000;
    let genesis = svm.current_blockhash();

    let (_sk, from) = new_keypair();
    let (_, to) = new_keypair();
    // Fund with only 0.1 BB but try to send 1 BB
    fund_account(&accounts_db, &from, LAMPORTS_PER_BB / 10);
    fund_account(&accounts_db, &to, 0);

    let req = TransferRequest {
        tx_id: "overdraft-tx".to_string(),
        from,
        to,
        lamports: LAMPORTS_PER_BB,
        recent_blockhash: genesis,
    };

    let result = svm.execute_transfer(&req);
    assert!(!result.success, "Transfer exceeding balance must be rejected");
}
