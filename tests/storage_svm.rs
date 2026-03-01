// ============================================================================
// BLACKBOOK L1 — STORAGE & SVM TESTS
// ============================================================================
//
// Production-readiness tests for the unified storage layer:
//
//   1. SVM AccountsDB: single source of truth (u64 lamports)
//   2. Credit / Debit / Transfer atomicity
//   3. Address resolution (base58 + legacy bb_ prefix)
//   4. 5-decimal precision (LAMPORTS_PER_BB = 100,000)
//   5. Mirror cache consistency (SVM → DashMap)
//   6. Block persistence (ReDB ACID)
//   7. Transaction receipts & history
//   8. SPL Token (USDC) operations
//
// Run:  cargo test --test storage_svm
// ============================================================================

use layer1::storage::ConcurrentBlockchain;
use layer1::svm::LAMPORTS_PER_BB;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

// ============================================================================
// HELPER: Create a temp blockchain for each test (isolated ReDB)
// ============================================================================
fn temp_blockchain() -> (ConcurrentBlockchain, TempDir) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap())
        .expect("Failed to create blockchain");
    (bc, dir)
}

fn random_bs58_address() -> String {
    let sk = SigningKey::generate(&mut OsRng);
    bs58::encode(sk.verifying_key().to_bytes()).into_string()
}

// ============================================================================
// TEST GROUP 1: LAMPORTS_PER_BB = 100,000 (5 decimal precision)
// ============================================================================

#[test]
fn test_lamports_per_bb_is_100000() {
    assert_eq!(LAMPORTS_PER_BB, 100_000, "LAMPORTS_PER_BB must be 100,000 (5 decimals)");
}

#[test]
fn test_one_bb_equals_100000_lamports() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    bc.credit(&addr, 1.0).unwrap();

    let lamports = bc.get_balance_lamports(&addr);
    assert_eq!(lamports, 100_000, "1.0 BB must equal 100,000 lamports");

    let bb = bc.get_balance(&addr);
    assert!((bb - 1.0).abs() < 1e-10, "get_balance must return 1.0 BB");
}

#[test]
fn test_fractional_bb_precision() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    // 0.00001 BB = 1 lamport (smallest unit)
    bc.credit(&addr, 0.00001).unwrap();
    assert_eq!(bc.get_balance_lamports(&addr), 1, "0.00001 BB = 1 lamport");

    // 0.12345 BB = 12,345 lamports
    bc.credit(&addr, 0.12344).unwrap(); // total 0.12345
    assert_eq!(bc.get_balance_lamports(&addr), 12_345, "0.12345 BB = 12,345 lamports");
}

// ============================================================================
// TEST GROUP 2: Credit & Debit
// ============================================================================

#[test]
fn test_credit_creates_account() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    assert_eq!(bc.get_balance(&addr), 0.0, "New account starts at 0");
    bc.credit(&addr, 5.0).unwrap();
    assert!((bc.get_balance(&addr) - 5.0).abs() < 1e-10);
}

#[test]
fn test_credit_accumulates() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    bc.credit(&addr, 1.0).unwrap();
    bc.credit(&addr, 2.5).unwrap();
    bc.credit(&addr, 0.5).unwrap();

    assert!((bc.get_balance(&addr) - 4.0).abs() < 1e-10, "Credits must accumulate");
    assert_eq!(bc.get_balance_lamports(&addr), 400_000);
}

#[test]
fn test_debit_reduces_balance() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    bc.credit(&addr, 10.0).unwrap();
    bc.debit(&addr, 3.0).unwrap();

    assert!((bc.get_balance(&addr) - 7.0).abs() < 1e-10);
    assert_eq!(bc.get_balance_lamports(&addr), 700_000);
}

#[test]
fn test_debit_insufficient_funds_fails() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    bc.credit(&addr, 1.0).unwrap();
    let result = bc.debit(&addr, 2.0);
    assert!(result.is_err(), "Debit exceeding balance MUST fail");
}

#[test]
fn test_debit_zero_balance_fails() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    let result = bc.debit(&addr, 0.1);
    assert!(result.is_err(), "Debit from empty account MUST fail");
}

// ============================================================================
// TEST GROUP 3: Transfer Atomicity
// ============================================================================

#[test]
fn test_transfer_basic() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 10.0).unwrap();
    bc.transfer(&alice, &bob, 3.0).unwrap();

    assert!((bc.get_balance(&alice) - 7.0).abs() < 1e-10, "Alice should have 7 BB");
    assert!((bc.get_balance(&bob) - 3.0).abs() < 1e-10, "Bob should have 3 BB");
}

#[test]
fn test_transfer_exact_balance() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 5.0).unwrap();
    bc.transfer(&alice, &bob, 5.0).unwrap();

    assert_eq!(bc.get_balance_lamports(&alice), 0, "Alice should have 0 after full transfer");
    assert_eq!(bc.get_balance_lamports(&bob), 500_000, "Bob should have all 5 BB");
}

#[test]
fn test_transfer_insufficient_fails() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 1.0).unwrap();
    let result = bc.transfer(&alice, &bob, 2.0);
    assert!(result.is_err(), "Transfer exceeding balance MUST fail");

    // Balances unchanged
    assert!((bc.get_balance(&alice) - 1.0).abs() < 1e-10, "Alice balance must be unchanged");
    assert_eq!(bc.get_balance(&bob), 0.0, "Bob must still be 0");
}

#[test]
fn test_transfer_creates_recipient() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 10.0).unwrap();

    // Bob doesn't exist yet
    assert_eq!(bc.get_balance(&bob), 0.0);

    bc.transfer(&alice, &bob, 1.0).unwrap();
    assert!((bc.get_balance(&bob) - 1.0).abs() < 1e-10, "Transfer must auto-create recipient");
}

#[test]
fn test_transfer_with_receipt() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 10.0).unwrap();

    let sig_hex = hex::encode([0xAA; 64]);
    let result = bc.transfer_with_receipt(
        &alice, &bob, 3.0, &sig_hex,
        layer1::storage::AuthType::SSS,
    );
    assert!(result.is_ok(), "transfer_with_receipt should succeed");

    let tx_sig = result.unwrap();
    assert!(!tx_sig.is_empty(), "Should return a transaction signature");
}

// ============================================================================
// TEST GROUP 4: Address Resolution (addr_to_pubkey)
// ============================================================================

#[test]
fn test_addr_to_pubkey_base58_deterministic() {
    let addr = random_bs58_address();
    let pk1 = ConcurrentBlockchain::addr_to_pubkey(&addr);
    let pk2 = ConcurrentBlockchain::addr_to_pubkey(&addr);
    assert_eq!(pk1, pk2, "Same address must always resolve to same pubkey");
}

#[test]
fn test_addr_to_pubkey_legacy_prefix() {
    let pk = ConcurrentBlockchain::addr_to_pubkey("bb_alice");
    let pk2 = ConcurrentBlockchain::addr_to_pubkey("bb_alice");
    assert_eq!(pk, pk2, "Legacy bb_ prefix must be deterministic");

    // Different names must produce different keys
    let pk_bob = ConcurrentBlockchain::addr_to_pubkey("bb_bob");
    assert_ne!(pk, pk_bob, "Different legacy addresses must produce different pubkeys");
}

#[test]
fn test_addr_to_pubkey_base58_roundtrip() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk_bytes = sk.verifying_key().to_bytes();
    let bs58_addr = bs58::encode(&vk_bytes).into_string();

    let pk = ConcurrentBlockchain::addr_to_pubkey(&bs58_addr);
    // For base58 addresses, the pubkey bytes should match the decoded address
    assert_eq!(pk.to_bytes(), vk_bytes, "Base58 address must roundtrip to original pubkey");
}

// ============================================================================
// TEST GROUP 5: Mirror Cache Consistency (SVM → DashMap)
// ============================================================================

#[test]
fn test_cache_mirrors_svm() {
    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();

    bc.credit(&addr, 7.5).unwrap();

    // Check DashMap cache has the value
    let cached = bc.cache.get(&addr).map(|v| *v).unwrap_or(0.0);
    assert!((cached - 7.5).abs() < 1e-10, "DashMap cache must mirror SVM balance");
}

#[test]
fn test_cache_updates_on_transfer() {
    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 10.0).unwrap();
    bc.transfer(&alice, &bob, 4.0).unwrap();

    let alice_cached = bc.cache.get(&alice).map(|v| *v).unwrap_or(-1.0);
    let bob_cached = bc.cache.get(&bob).map(|v| *v).unwrap_or(-1.0);

    assert!((alice_cached - 6.0).abs() < 1e-10, "Alice cache must be 6.0 after transfer");
    assert!((bob_cached - 4.0).abs() < 1e-10, "Bob cache must be 4.0 after transfer");
}

// ============================================================================
// TEST GROUP 6: Total Supply Tracking
// ============================================================================

#[test]
fn test_total_supply_after_credits() {
    let (bc, _dir) = temp_blockchain();

    let a = random_bs58_address();
    let b = random_bs58_address();

    bc.credit(&a, 100.0).unwrap();
    bc.credit(&b, 50.0).unwrap();

    let supply = bc.total_supply();
    assert!((supply - 150.0).abs() < 1e-5, "Total supply must be sum of all credits: got {}", supply);
}

#[test]
fn test_total_supply_unchanged_by_transfer() {
    let (bc, _dir) = temp_blockchain();

    let a = random_bs58_address();
    let b = random_bs58_address();

    bc.credit(&a, 100.0).unwrap();
    let supply_before = bc.total_supply();

    bc.transfer(&a, &b, 30.0).unwrap();
    let supply_after = bc.total_supply();

    assert!(
        (supply_before - supply_after).abs() < 1e-5,
        "Transfer must NOT change total supply"
    );
}

// ============================================================================
// TEST GROUP 7: Blockchain Stats
// ============================================================================

#[test]
fn test_stats_account_count() {
    let (bc, _dir) = temp_blockchain();

    let a = random_bs58_address();
    let b = random_bs58_address();
    let c = random_bs58_address();

    bc.credit(&a, 1.0).unwrap();
    bc.credit(&b, 2.0).unwrap();
    bc.credit(&c, 3.0).unwrap();

    let stats = bc.stats();
    assert!(stats.total_accounts >= 3, "Stats must report at least 3 accounts: got {}", stats.total_accounts);
}

// ============================================================================
// TEST GROUP 8: SVM AccountsDB Direct
// ============================================================================

#[test]
fn test_svm_system_transfer() {
    let (bc, _dir) = temp_blockchain();

    let alice = random_bs58_address();
    let bob = random_bs58_address();

    // Fund Alice via the storage layer
    bc.credit(&alice, 10.0).unwrap();

    let alice_pk = ConcurrentBlockchain::addr_to_pubkey(&alice);
    let bob_pk = ConcurrentBlockchain::addr_to_pubkey(&bob);

    // Direct SVM system_transfer
    bc.svm_accounts.system_transfer(&alice_pk, &bob_pk, 300_000).unwrap(); // 3 BB

    let alice_lam = bc.svm_accounts.get_lamports(&alice_pk);
    let bob_lam = bc.svm_accounts.get_lamports(&bob_pk);

    assert_eq!(alice_lam, 700_000, "Alice should have 7 BB in SVM");
    assert_eq!(bob_lam, 300_000, "Bob should have 3 BB in SVM");
}

#[test]
fn test_svm_insufficient_transfer_fails() {
    let (bc, _dir) = temp_blockchain();

    let alice = random_bs58_address();
    let bob = random_bs58_address();

    bc.credit(&alice, 1.0).unwrap();

    let alice_pk = ConcurrentBlockchain::addr_to_pubkey(&alice);
    let bob_pk = ConcurrentBlockchain::addr_to_pubkey(&bob);

    let result = bc.svm_accounts.system_transfer(&alice_pk, &bob_pk, 200_000); // 2 BB > 1 BB
    assert!(result.is_err(), "SVM transfer exceeding balance MUST fail");
}

#[test]
fn test_svm_account_count() {
    let (bc, _dir) = temp_blockchain();

    let initial = bc.svm_accounts.account_count();

    let a = random_bs58_address();
    let b = random_bs58_address();
    bc.credit(&a, 1.0).unwrap();
    bc.credit(&b, 2.0).unwrap();

    assert_eq!(bc.svm_accounts.account_count(), initial + 2, "Account count must increase by 2");
}

// ============================================================================
// TEST GROUP 9: Wallet Share Storage (ReDB)
// ============================================================================

#[test]
fn test_wallet_share_storage_roundtrip() {
    let (bc, _dir) = temp_blockchain();
    let wallet_id = "test_wallet_123";
    let share_data = b"encrypted_share_data_here_32bytes";

    assert!(!bc.has_wallet_share(wallet_id), "Should not exist yet");

    bc.store_wallet_share(wallet_id, share_data).unwrap();
    assert!(bc.has_wallet_share(wallet_id), "Must exist after store");

    let retrieved = bc.get_wallet_share(wallet_id).unwrap().unwrap();
    assert_eq!(retrieved, share_data, "Retrieved share must match stored");
}

#[test]
fn test_wallet_share_delete() {
    let (bc, _dir) = temp_blockchain();
    let wallet_id = "delete_me";

    bc.store_wallet_share(wallet_id, b"data").unwrap();
    assert!(bc.has_wallet_share(wallet_id));

    let deleted = bc.delete_wallet_share(wallet_id).unwrap();
    assert!(deleted, "Delete should return true");
    assert!(!bc.has_wallet_share(wallet_id), "Must not exist after delete");
}

// ============================================================================
// TEST GROUP 10: FROST Share B Storage (for SSS wallets)
// ============================================================================

#[test]
fn test_frost_share_b_roundtrip() {
    let (bc, _dir) = temp_blockchain();
    let wallet_id = "my_sss_wallet";
    let share_b = b"encrypted_shard_b_blob_with_aes_gcm";

    bc.store_frost_share_b(wallet_id, share_b).unwrap();
    let retrieved = bc.get_frost_share_b(wallet_id).unwrap();
    assert_eq!(retrieved, share_b, "FROST Share B must roundtrip");
}

// ============================================================================
// TEST GROUP 11: SPL Token Engine (USDC)
// ============================================================================

#[test]
fn test_usdc_mint_address_deterministic() {
    let addr1 = layer1::svm::usdc_mint_address();
    let addr2 = layer1::svm::usdc_mint_address();
    assert_eq!(addr1, addr2, "USDC mint address must be deterministic");
    assert!(!addr1.is_empty(), "USDC mint address must not be empty");
}

#[test]
fn test_usdc_constants() {
    assert_eq!(layer1::svm::USDC_DECIMALS, 6, "USDC must have 6 decimals");
    assert_eq!(layer1::svm::USDC_UNIT, 1_000_000, "1 USDC = 1,000,000 raw units");
}

// ============================================================================
// TEST GROUP 12: Concurrent Access Safety
// ============================================================================

#[test]
fn test_concurrent_credits() {
    use std::thread;

    let (bc, _dir) = temp_blockchain();
    let addr = random_bs58_address();
    let bc = std::sync::Arc::new(bc);

    let mut handles = vec![];
    for _ in 0..10 {
        let bc = bc.clone();
        let addr = addr.clone();
        handles.push(thread::spawn(move || {
            bc.credit(&addr, 1.0).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let balance = bc.get_balance(&addr);
    assert!(
        (balance - 10.0).abs() < 1e-5,
        "10 concurrent credits of 1.0 BB must total 10.0 BB, got {}",
        balance
    );
}

#[test]
fn test_concurrent_transfers() {
    use std::thread;

    let (bc, _dir) = temp_blockchain();
    let alice = random_bs58_address();
    let bob = random_bs58_address();
    let bc = std::sync::Arc::new(bc);

    // Fund Alice with enough for all transfers
    bc.credit(&alice, 100.0).unwrap();

    let mut handles = vec![];
    for _ in 0..20 {
        let bc = bc.clone();
        let alice = alice.clone();
        let bob = bob.clone();
        handles.push(thread::spawn(move || {
            let _ = bc.transfer(&alice, &bob, 1.0);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let alice_bal = bc.get_balance(&alice);
    let bob_bal = bc.get_balance(&bob);
    let total = alice_bal + bob_bal;

    assert!(
        (total - 100.0).abs() < 1e-5,
        "Total supply must remain 100 BB after concurrent transfers, got {}",
        total
    );
}
