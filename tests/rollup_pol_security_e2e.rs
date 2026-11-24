//! Integration & security regression tests for the streamlined L1 architecture:
//!   1. 1:1 Atomic Rollup Lock → Consume → Monotonic State Root → Cumulative Watermark Exit
//!   2. Closed-Loop Protocol-Owned Liquidity (POL) atomic BB ↔ wUSDT swaps
//!   3. Single-transaction atomic bridge deposit mint + double-mint prevention
//!   4. P0 Auth Hardening: reserved PDA guards + Solana JSON-RPC `sendTransaction` Ed25519 sigverify

use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicU64;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use solana_sdk::hash::Hash;
use solana_sdk::message::{Message, VersionedMessage};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature as SolSignature;
use solana_sdk::system_instruction;
use solana_sdk::transaction::VersionedTransaction;
use tempfile::tempdir;

use layer1::solana_rpc::{BlackBookRpcImpl, BlackBookRpcServer, SendTransactionConfig};
use layer1::storage::{ConcurrentBlockchain, DepositRecord, RollupLockRecord};
use layer1::svm::{
    BlackBookSVM, LAMPORTS_PER_BB, SplTokenEngine, USDC_UNIT,
    swap_pool_address, swap_pool_pda, house_treasury_pda, usdc_mint_bytes,
};
use layer1::svm::pda::{is_reserved_pda, rollup_vault_address, rollup_vault_pda};

fn random_wallet() -> (SigningKey, Pubkey, String) {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();
    let pk = Pubkey::new_from_array(pk_bytes);
    let addr = bs58::encode(pk_bytes).into_string();
    (sk, pk, addr)
}

#[test]
fn rollup_l2_one_to_one_lock_root_monotonicity_and_cumulative_exit() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().to_str().unwrap();
    let bc = ConcurrentBlockchain::new(db_path).unwrap();

    let (_sk, _pk, alice) = random_wallet();
    let vault = rollup_vault_address("L2");

    // Seed Alice with 100 BB (10_000_000 lamports)
    let initial = 100 * LAMPORTS_PER_BB;
    bc.mint_lamports(&alice, initial).unwrap();
    assert_eq!(bc.get_balance_lamports(&alice), initial);
    assert_eq!(bc.get_balance_lamports(&vault), 0);

    // 1. Atomic 1:1 lock of 60 BB into L2 rollup vault
    let lock_amount = 60 * LAMPORTS_PER_BB;
    let lock_rec = RollupLockRecord {
        lock_id: "lock-001".to_string(),
        rollup_id: "L2".to_string(),
        creator_address: alice.clone(),
        bb_lamports: lock_amount,
        token_symbol_hint: None,
        locked_at: 1_700_000_000,
        vault_address: vault.clone(),
        consumed: false,
    };
    bc.atomic_rollup_lock_bb(&alice, &vault, lock_amount, &lock_rec).unwrap();

    assert_eq!(bc.get_balance_lamports(&alice), 40 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_balance_lamports(&vault), lock_amount);

    // 2. Consume lock once; second consume MUST fail with "already_consumed"
    bc.consume_rollup_lock("lock-001").unwrap();
    assert_eq!(bc.consume_rollup_lock("lock-001").unwrap_err(), "already_consumed");

    // 3. Per-rollup state root monotonicity
    let root1 = [0x11u8; 32];
    let root2 = [0x22u8; 32];
    bc.store_rollup_state_root("L2", 1, root1).unwrap();
    assert!(bc.store_rollup_state_root("L2", 1, root2).is_err());
    assert!(bc.store_rollup_state_root("L2", 0, root2).is_err());
    bc.store_rollup_state_root("L2", 2, root2).unwrap();
    assert_eq!(bc.load_rollup_state_root("L2", 2), Some(root2));

    // 4. Cumulative watermark exit: Alice withdraws 25 BB first, then +35 BB (total 60 BB)
    let exit_id = "exit-key-alice-l2";
    bc.atomic_rollup_bb_exit(&alice, &vault, exit_id, 0, 25 * LAMPORTS_PER_BB, 25 * LAMPORTS_PER_BB).unwrap();
    assert_eq!(bc.get_balance_lamports(&alice), 65 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_balance_lamports(&vault), 35 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_cumulative_exit(exit_id), 25 * LAMPORTS_PER_BB);

    // Stale prev_cumulative (concurrent race) MUST fail
    assert_eq!(
        bc.atomic_rollup_bb_exit(&alice, &vault, exit_id, 0, 10 * LAMPORTS_PER_BB, 10 * LAMPORTS_PER_BB).unwrap_err(),
        "exit_raced"
    );

    // Over-withdrawal beyond vault backing MUST fail with vault_insolvent
    assert_eq!(
        bc.atomic_rollup_bb_exit(&alice, &vault, exit_id, 25 * LAMPORTS_PER_BB, 40 * LAMPORTS_PER_BB, 65 * LAMPORTS_PER_BB).unwrap_err(),
        "vault_insolvent"
    );

    // Final valid delta (35 BB) drains exact remaining 1:1 balance back to Alice
    bc.atomic_rollup_bb_exit(&alice, &vault, exit_id, 25 * LAMPORTS_PER_BB, 35 * LAMPORTS_PER_BB, 60 * LAMPORTS_PER_BB).unwrap();
    assert_eq!(bc.get_balance_lamports(&alice), initial);
    assert_eq!(bc.get_balance_lamports(&vault), 0);

    // 5. Durability check across ReDB reopen (no flush_block needed!)
    drop(bc);
    let bc2 = ConcurrentBlockchain::new(db_path).unwrap();
    assert_eq!(bc2.get_balance_lamports(&alice), initial);
    assert_eq!(bc2.get_balance_lamports(&vault), 0);
    assert_eq!(bc2.get_cumulative_exit(exit_id), 60 * LAMPORTS_PER_BB);
    assert_eq!(bc2.load_rollup_state_root("L2", 2), Some(root2));
}

#[test]
fn pol_atomic_swaps_retain_fees_and_conserve_total_supply() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().to_str().unwrap();
    let bc = ConcurrentBlockchain::new(db_path).unwrap();

    let (_sk, user_pk, user_addr) = random_wallet();
    let pool_pk = swap_pool_pda();
    let pool_addr = swap_pool_address();
    let mint = usdc_mint_bytes();

    // Bootstrap wUSDT mint with swap_pool_pda as authority and seed POL reserves
    SplTokenEngine::bootstrap_usdc_mint(&bc.svm_accounts, &pool_pk).unwrap();
    SplTokenEngine::mint_to(&bc.svm_accounts, &mint, &pool_pk, 1_000 * USDC_UNIT).unwrap();
    bc.mint_lamports(&pool_addr, 10_000 * LAMPORTS_PER_BB).unwrap();
    bc.mint_lamports(&user_addr, 1_000 * LAMPORTS_PER_BB).unwrap();
    bc.svm_accounts.flush_block().unwrap();

    let initial_total_bb = bc.svm_accounts.total_lamports();
    let initial_total_wusdt = SplTokenEngine::get_mint_supply(&bc.svm_accounts, &mint).unwrap();

    // Swap 100 BB (10_000_000 lamports) → wUSDT at 10:1 with 30 bps (0.30%) POL fee
    let bb_in = 100 * LAMPORTS_PER_BB; // 10_000_000 lamports
    let gross_wusdt = 10 * USDC_UNIT;  // 10_000_000 micro-wUSDT
    let fee_wusdt = gross_wusdt * 30 / 10_000; // 30_000 micro-wUSDT
    let net_wusdt = gross_wusdt - fee_wusdt;   // 9_970_000 micro-wUSDT

    bc.atomic_pol_swap_bb_for_usdc(&user_addr, &user_pk, bb_in, net_wusdt).unwrap();

    assert_eq!(bc.get_balance_lamports(&user_addr), 900 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_balance_lamports(&pool_addr), 10_100 * LAMPORTS_PER_BB);
    assert_eq!(SplTokenEngine::get_token_balance(&bc.svm_accounts, &mint, &user_pk), net_wusdt);
    assert_eq!(
        SplTokenEngine::get_token_balance(&bc.svm_accounts, &mint, &pool_pk),
        1_000 * USDC_UNIT - net_wusdt
    );
    // Strict conservation: zero inflation of BB or wUSDT
    assert_eq!(bc.svm_accounts.total_lamports(), initial_total_bb);
    assert_eq!(SplTokenEngine::get_mint_supply(&bc.svm_accounts, &mint).unwrap(), initial_total_wusdt);

    // Reverse swap: user swaps all net_wusdt back to BB (another 30 bps fee retained in pool)
    let gross_bb_back = net_wusdt; // 10:1 at 5 vs 6 decimals => 1:1 raw integer units
    let fee_bb_back = gross_bb_back * 30 / 10_000;
    let net_bb_back = gross_bb_back - fee_bb_back;

    bc.atomic_pol_swap_usdc_for_bb(&user_addr, &user_pk, net_wusdt, net_bb_back).unwrap();

    // Pool now holds MORE BB than it started with (100% of fees retained in POL pool)
    assert!(bc.get_balance_lamports(&pool_addr) > 10_000 * LAMPORTS_PER_BB);
    assert_eq!(SplTokenEngine::get_token_balance(&bc.svm_accounts, &mint, &pool_pk), 1_000 * USDC_UNIT);
    assert_eq!(bc.svm_accounts.total_lamports(), initial_total_bb);

    // Crash durability: reopen ReDB immediately without flush_block
    let expected_user_bb = bc.get_balance_lamports(&user_addr);
    let expected_pool_bb = bc.get_balance_lamports(&pool_addr);
    drop(bc);
    let bc2 = ConcurrentBlockchain::new(db_path).unwrap();
    assert_eq!(bc2.get_balance_lamports(&user_addr), expected_user_bb);
    assert_eq!(bc2.get_balance_lamports(&pool_addr), expected_pool_bb);
    assert_eq!(SplTokenEngine::get_token_balance(&bc2.svm_accounts, &mint, &pool_pk), 1_000 * USDC_UNIT);
}

#[test]
fn atomic_bridge_deposit_prevents_double_mint_and_persists_atomically() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().to_str().unwrap();
    let bc = ConcurrentBlockchain::new(db_path).unwrap();

    let (_sk, _pk, user_addr) = random_wallet();
    let tx_hash = "5xSolanaTxHashUnique123";
    let deposit_lamports = 50 * LAMPORTS_PER_BB;
    let rec = DepositRecord {
        wallet_address: user_addr.clone(),
        external_tx_hash: tx_hash.to_string(),
        asset: "USDC".to_string(),
        amount_micro_stablecoin: 5 * USDC_UNIT,
        bb_lamports: deposit_lamports,
        status: "approved".to_string(),
        submitted_at: 1_700_000_000,
        approved_at: Some(1_700_000_010),
        contest_id: None,
    };

    let bal = bc.atomic_mint_bridge_deposit(tx_hash, &user_addr, deposit_lamports, "mint-1", Some(&rec), false).unwrap();
    assert_eq!(bal, deposit_lamports);
    assert!(bc.is_bridge_tx_processed(tx_hash));

    // Double-mint MUST be rejected
    assert!(bc.atomic_mint_bridge_deposit(tx_hash, &user_addr, deposit_lamports, "mint-2", Some(&rec), false).is_err());

    // Reopen ReDB without flush_block: both balance and processed seal must be durable
    drop(bc);
    let bc2 = ConcurrentBlockchain::new(db_path).unwrap();
    assert_eq!(bc2.get_balance_lamports(&user_addr), deposit_lamports);
    assert!(bc2.is_bridge_tx_processed(tx_hash));
}

#[tokio::test]
async fn solana_rpc_send_transaction_enforces_ed25519_sigverify_and_pda_guards() {
    // Verify reserved PDA detection
    assert!(is_reserved_pda(&swap_pool_pda()));
    assert!(is_reserved_pda(&house_treasury_pda()));
    assert!(is_reserved_pda(&rollup_vault_pda("L2")));
    assert!(is_reserved_pda(&rollup_vault_pda("L3")));
    assert!(is_reserved_pda(&rollup_vault_pda("L5")));

    let dir = tempdir().unwrap();
    let bc = ConcurrentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
    let (alice_sk, alice_pk, alice_addr) = random_wallet();
    let (attacker_sk, _attacker_pk, _attacker_addr) = random_wallet();
    let (_bob_sk, bob_pk, bob_addr) = random_wallet();
    assert!(!is_reserved_pda(&alice_pk));

    bc.mint_lamports(&alice_addr, 100 * LAMPORTS_PER_BB).unwrap();
    bc.mint_lamports(&rollup_vault_address("L2"), 500 * LAMPORTS_PER_BB).unwrap();

    let blockhash = Hash::new_unique();
    let svm = Arc::new(Mutex::new(BlackBookSVM::new(Arc::clone(&bc.svm_accounts), blockhash)));
    let rpc = BlackBookRpcImpl::new(Arc::clone(&bc.svm_accounts), svm, Arc::new(AtomicU64::new(1)));
    let cfg: Option<SendTransactionConfig> = Some(
        serde_json::from_value(serde_json::json!({ "encoding": "base64" })).unwrap()
    );

    // 1. Forged signature (attacker signs Alice's transfer) MUST be rejected
    let ix = system_instruction::transfer(&alice_pk, &bob_pk, 10 * LAMPORTS_PER_BB);
    let msg = Message::new_with_blockhash(&[ix], Some(&alice_pk), &blockhash);
    let versioned_msg = VersionedMessage::Legacy(msg);
    let bad_sig_bytes = attacker_sk.sign(&versioned_msg.serialize()).to_bytes();
    let forged_tx = VersionedTransaction {
        signatures: vec![SolSignature::from(bad_sig_bytes)],
        message: versioned_msg.clone(),
    };
    let forged_b64 = B64.encode(bincode::serialize(&forged_tx).unwrap());
    assert!(rpc.send_transaction(forged_b64, cfg.clone()).await.is_err());
    assert_eq!(bc.get_balance_lamports(&alice_addr), 100 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_balance_lamports(&bob_addr), 0);

    // 2. Valid Ed25519 signature by Alice MUST succeed
    let good_sig_bytes = alice_sk.sign(&versioned_msg.serialize()).to_bytes();
    let valid_tx = VersionedTransaction {
        signatures: vec![SolSignature::from(good_sig_bytes)],
        message: versioned_msg,
    };
    let valid_b64 = B64.encode(bincode::serialize(&valid_tx).unwrap());
    let sig_out = rpc.send_transaction(valid_b64, cfg.clone()).await.unwrap();
    assert!(!sig_out.is_empty());
    assert_eq!(bc.get_balance_lamports(&alice_addr), 90 * LAMPORTS_PER_BB);
    assert_eq!(bc.get_balance_lamports(&bob_addr), 10 * LAMPORTS_PER_BB);
}
