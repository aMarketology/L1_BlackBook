// ============================================================================
// BLACKBOOK L1 — Phase 2A: Solana JSON-RPC unit tests
//
// These tests exercise `BlackBookRpcImpl` directly (no HTTP server needed).
// Run: cargo test --features svm --test rpc_tests
// ============================================================================

#![cfg(feature = "svm")]

use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use tempfile::tempdir;
use redb::Database;
use solana_sdk::{
    account::AccountSharedData,
    hash::Hash,
    pubkey::Pubkey,
    system_program,
};

use layer1::{
    svm::{SvmAccountsDB, BlackBookSVM, LAMPORTS_PER_BB},
    solana_rpc::{BlackBookRpcImpl, BlackBookRpcServer},
};

// ─────────────────────────────────────────────────────────────────────────────
// Test harness helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a fresh in-memory RPC impl backed by a tmp ReDB file.
fn make_rpc(slot: u64) -> BlackBookRpcImpl {
    use sha2::{Sha256, Digest};

    let dir  = tempdir().unwrap();
    let path = dir.path().join("rpc_test.redb");
    // Keep `dir` alive by leaking it — tempfile cleans up on drop, but we need
    // the path to stay valid for the duration of the test.
    std::mem::forget(dir);

    let db = Arc::new(Database::create(path).unwrap());
    let accounts_db = Arc::new(SvmAccountsDB::new(Arc::clone(&db)).unwrap());

    let genesis_bytes: [u8; 32] = Sha256::digest(b"BLACKBOOK_L1_GENESIS_2025").into();
    let genesis_hash = Hash::new_from_array(genesis_bytes);
    let svm = Arc::new(Mutex::new(BlackBookSVM::new(Arc::clone(&accounts_db), genesis_hash)));
    let current_slot = Arc::new(AtomicU64::new(slot));

    BlackBookRpcImpl::new(accounts_db, svm, current_slot)
}

/// Fund an account with `lamports` and return its base58 pubkey string.
fn fund_account(rpc: &BlackBookRpcImpl, lamports: u64) -> (Pubkey, String) {
    let pk      = Pubkey::new_unique();
    let account = AccountSharedData::new(lamports, 0, &system_program::id());
    rpc.svm_db.store_account(&pk, account);
    let pk_b58 = bs58::encode(pk.to_bytes()).into_string();
    (pk, pk_b58)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// getHealth returns "ok"
#[tokio::test]
async fn test_rpc_get_health() {
    let rpc = make_rpc(0);
    let result = rpc.get_health().await.unwrap();
    assert_eq!(result, "ok");
}

/// getVersion returns a version string containing the BB version and a non-zero feature_set
#[tokio::test]
async fn test_rpc_get_version() {
    let rpc = make_rpc(0);
    let ver = rpc.get_version().await.unwrap();
    assert!(
        ver.solana_core.contains("5.0") || ver.solana_core.starts_with("BB"),
        "unexpected version string: {}", ver.solana_core
    );
    assert!(ver.feature_set > 0, "feature_set should be non-zero");
}

/// getGenesisHash returns a consistent base58-encoded SHA256 hash (44 chars)
#[tokio::test]
async fn test_rpc_get_genesis_hash() {
    let rpc1 = make_rpc(0);
    let rpc2 = make_rpc(99);
    let h1 = rpc1.get_genesis_hash().await.unwrap();
    let h2 = rpc2.get_genesis_hash().await.unwrap();

    // The same genesis string should produce the same hash regardless of slot.
    assert_eq!(h1, h2, "genesis_hash must be deterministic");

    // A base58-encoded 32-byte SHA256 hash is 44 characters.
    assert_eq!(h1.len(), 44, "genesis_hash should be 44 base58 chars");
}

/// getBalance returns the lamport balance stored in SvmAccountsDB
#[tokio::test]
async fn test_rpc_get_balance() {
    let rpc = make_rpc(7);
    let lamports = 42 * LAMPORTS_PER_BB;
    let (_pk, pk_b58) = fund_account(&rpc, lamports);

    let resp = rpc.get_balance(pk_b58).await.unwrap();
    assert_eq!(resp.value, lamports, "balance mismatch");
    assert_eq!(resp.context.slot, 7);
}

/// getBalance on an unknown pubkey returns 0 (not an error)
#[tokio::test]
async fn test_rpc_get_balance_unknown_returns_zero() {
    let rpc   = make_rpc(0);
    let pk    = Pubkey::new_unique();
    let pk_b58 = bs58::encode(pk.to_bytes()).into_string();

    let resp = rpc.get_balance(pk_b58).await.unwrap();
    assert_eq!(resp.value, 0, "unknown account should return 0 lamports");
}

/// getAccountInfo encodes account data as base64 and returns the correct lamport count
#[tokio::test]
async fn test_rpc_get_account_info_base64() {
    let rpc = make_rpc(1);
    let lamports = 5 * LAMPORTS_PER_BB;
    let (_pk, pk_b58) = fund_account(&rpc, lamports);

    let resp = rpc.get_account_info(pk_b58, None).await.unwrap();
    let ui   = resp.value.expect("account should be present");

    assert_eq!(ui.lamports, lamports);
    assert!(!ui.owner.is_empty(), "owner pubkey should be set");
    assert!(!ui.executable, "regular account should not be executable");

    // Data encoding must declare "base64"
    use layer1::solana_rpc::UiAccountData;
    match &ui.data {
        UiAccountData::Binary(_, enc) => assert_eq!(enc, "base64"),
        _ => panic!("expected Binary(data, \"base64\") encoding"),
    }
}

/// getLatestBlockhash returns a non-empty blockhash and a sane last_valid_block_height
#[tokio::test]
async fn test_rpc_get_latest_blockhash() {
    let slot = 1000u64;
    let rpc  = make_rpc(slot);

    let resp = rpc.get_latest_blockhash().await.unwrap();
    let bh   = resp.value;

    assert!(!bh.blockhash.is_empty(), "blockhash must not be empty");
    // last_valid_block_height should be slot + some headroom (≥ slot)
    assert!(bh.last_valid_block_height >= slot, "last_valid_block_height should be ≥ current slot");
}

/// getSlot returns the current slot exactly
#[tokio::test]
async fn test_rpc_get_slot() {
    let rpc = make_rpc(12345);
    let slot = rpc.get_slot().await.unwrap();
    assert_eq!(slot, 12345);
}

/// getEpochInfo computes epoch / slot_index correctly from slot
#[tokio::test]
async fn test_rpc_get_epoch_info() {
    // Slot 432_000 is exactly the start of epoch 1
    let rpc  = make_rpc(432_000);
    let info = rpc.get_epoch_info().await.unwrap();

    assert_eq!(info.epoch,        1, "epoch should be 1 at slot 432_000");
    assert_eq!(info.slot_index,   0, "slot_index should be 0 at epoch boundary");
    assert_eq!(info.slots_in_epoch, 432_000);
    assert_eq!(info.absolute_slot,  432_000);
    assert_eq!(info.block_height,   432_000);
}
