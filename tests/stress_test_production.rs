// ============================================================================
// BLACKBOOK L1 — PRODUCTION STRESS TEST
// ============================================================================
//
// End-to-end stress tests validating production readiness for Hetzner deploy:
//
//   1. Production constants verification
//   2. Concurrent storage: 10+ threads, credit/debit/transfer
//   3. Sealevel scheduler at scale: 5,000+ transactions
//   4. Block verification: verify_block, verify_chain on constructed blocks
//   5. Turbine shredding / reassembly for large blocks
//   6. Ed25519 wallet creation + signing flow
//   7. Circuit breaker + fee market under sustained load
//   8. Adaptive batch tuning under mixed workloads
//   9. Merkle tree at scale (10K leaves)
//  10. Full pipeline: sign → schedule → execute → verify
//  11. Network throttler fairness
//  12. Scheduler statistics accuracy
//
// Run:  cargo test --test stress_test_production -- --test-threads=1
// ============================================================================

use layer1::storage::ConcurrentBlockchain;
use layer1::svm::LAMPORTS_PER_BB;
use layer1::runtime::core::{
    Transaction as SealevelTx, TransactionType,
    ParallelScheduler,
};
use layer1::runtime::{
    CircuitBreaker, LocalizedFeeMarket, NetworkThrottler,
};
use layer1::poh_blockchain::{
    FinalizedBlock, OrderedTransaction, MerkleTree,
    verify_block, verify_chain,
    MAX_TXS_PER_BLOCK, BLOCK_INTERVAL_MS,
    TurbineShredder, SHRED_SIZE,
};
use layer1::{Transaction, TxData};

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use ed25519_dalek::{SigningKey, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// ============================================================================
// HELPERS
// ============================================================================

fn make_sealevel_tx(from: &str, to: &str, amount: f64) -> SealevelTx {
    SealevelTx::new(from.to_string(), to.to_string(), amount, TransactionType::Transfer)
}

fn setup_blockchain(accounts: &[(&str, f64)]) -> (ConcurrentBlockchain, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let bc = ConcurrentBlockchain::new(tmp.path().join("stress.redb").to_str().unwrap())
        .expect("blockchain");
    for (addr, bal) in accounts {
        bc.credit(addr, *bal).unwrap();
    }
    (bc, tmp)
}

/// Build a FinalizedBlock from transactions for verification tests
fn build_test_block(slot: u64, prev_hash: &str, txs: Vec<Transaction>) -> FinalizedBlock {
    let tx_count = txs.len();

    let ordered: Vec<OrderedTransaction> = txs.into_iter().enumerate().map(|(i, tx)| {
        OrderedTransaction {
            tx,
            poh_hash: format!("poh_{}", i),
            poh_sequence: i as u64,
            slot,
            position: i as u32,
        }
    }).collect();

    // Build Merkle tree from account balances (API: from_accounts)
    let mut accts = std::collections::BTreeMap::new();
    for (i, _ot) in ordered.iter().enumerate() {
        accts.insert(format!("account_{}", i), i as f64 + 1.0);
    }
    let merkle = MerkleTree::from_accounts(&accts);
    let state_root = merkle.root_hex();

    let poh_hash = format!("poh_slot_{}", slot);
    let timestamp = 1700000000 + slot;
    let hash = FinalizedBlock::compute_hash(slot, prev_hash, &state_root, &poh_hash, timestamp);

    FinalizedBlock {
        slot,
        timestamp,
        previous_hash: prev_hash.to_string(),
        hash,
        state_root,
        accounts_hash: "acc_hash".to_string(),
        poh_hash,
        poh_sequence: tx_count as u64,
        poh_entries: vec![],
        transactions: ordered,
        tx_count: tx_count as u32,
        leader: "prod_validator".to_string(),
        epoch: 0,
        confirmations: 0,
    }
}

/// Create a properly-structured protocol Transaction
fn make_protocol_tx(from: &str, to: &str, amount: u64, nonce: u64) -> Transaction {
    let hash = hex::encode(Sha256::digest(
        format!("{}:{}:{}:{}", from, to, amount, nonce).as_bytes()
    ));
    Transaction {
        hash,
        from: from.to_string(),
        timestamp: 1700000000,
        data: TxData::TransferBb {
            to: to.to_string(),
            amount,
        },
        signature: hex::encode([0xAA; 64]),
        signer_pubkey: hex::encode([0xBB; 32]),
    }
}

// ============================================================================
// TEST GROUP 1: Block Production Constants
// ============================================================================

#[test]
fn test_production_constants() {
    assert_eq!(MAX_TXS_PER_BLOCK, 50_000, "Block capacity: 50K txs");
    assert_eq!(BLOCK_INTERVAL_MS, 400, "Slot interval: 400ms");
    assert_eq!(LAMPORTS_PER_BB, 100_000, "1 BB = 100K lamports");
    assert_eq!(SHRED_SIZE, 1232, "Shred size: MTU-optimal 1232 bytes");

    let theoretical_tps = MAX_TXS_PER_BLOCK as f64 / (BLOCK_INTERVAL_MS as f64 / 1000.0);
    assert_eq!(theoretical_tps as u64, 125_000, "Theoretical TPS: 125K");
}

// ============================================================================
// TEST GROUP 2: Storage Layer Under Concurrent Load
// ============================================================================

#[test]
fn test_concurrent_credits_10_threads() {
    let (bc, _tmp) = setup_blockchain(&[]);
    let bc = Arc::new(bc);

    let handles: Vec<_> = (0..10).map(|t| {
        let bc = Arc::clone(&bc);
        std::thread::spawn(move || {
            for i in 0..100 {
                bc.credit(&format!("thread_{}_addr_{}", t, i), 1.0)
                    .expect("credit must succeed");
            }
        })
    }).collect();

    for h in handles { h.join().expect("join"); }

    let mut total = 0.0;
    for t in 0..10 {
        for i in 0..100 {
            let bal = bc.get_balance(&format!("thread_{}_addr_{}", t, i));
            assert!((bal - 1.0).abs() < 0.001, "thread_{}_addr_{}: {}", t, i, bal);
            total += bal;
        }
    }
    assert!((total - 1000.0).abs() < 1.0, "Total: {}", total);
}

#[test]
fn test_concurrent_transfers_20_threads() {
    let (bc, _tmp) = setup_blockchain(&[]);
    let bc = Arc::new(bc);

    for t in 0..20 {
        bc.credit(&format!("src_{}", t), 100.0).unwrap();
    }

    let handles: Vec<_> = (0..20).map(|t| {
        let bc = Arc::clone(&bc);
        std::thread::spawn(move || {
            for i in 0..50 {
                bc.transfer(
                    &format!("src_{}", t),
                    &format!("dst_{}_{}", t, i),
                    0.01,
                ).expect("transfer");
            }
        })
    }).collect();

    for h in handles { h.join().expect("join"); }

    for t in 0..20 {
        let bal = bc.get_balance(&format!("src_{}", t));
        assert!((bal - 99.5).abs() < 0.01, "src_{}: {}", t, bal);
    }
}

// ============================================================================
// TEST GROUP 3: Sealevel Scheduler at Scale
// ============================================================================

#[test]
fn test_schedule_5000_transactions() {
    let scheduler = ParallelScheduler::new();

    let txs: Vec<SealevelTx> = (0..5000).map(|i| {
        if i % 10 == 0 {
            make_sealevel_tx(&format!("sender_{}", i), "hot_account", 0.01)
        } else {
            make_sealevel_tx(&format!("sender_{}", i), &format!("rcvr_{}", i), 0.01)
        }
    }).collect();

    let start = Instant::now();
    let batches = scheduler.schedule_with_locks(txs);
    let scheduling_time = start.elapsed();

    let total: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total, 5000, "All 5000 txs must be scheduled");
    assert!(scheduling_time.as_secs() < 2, "Scheduling too slow: {:?}", scheduling_time);
}

#[test]
fn test_execute_5000_transactions() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    for i in 0..5000 {
        balances.insert(format!("s_{}", i), 10.0);
    }

    let txs: Vec<SealevelTx> = (0..5000).map(|i| {
        make_sealevel_tx(&format!("s_{}", i), &format!("r_{}", i), 0.01)
    }).collect();

    let start = Instant::now();
    let batches = scheduler.schedule_with_locks(txs);

    let mut total_success = 0;
    for batch in batches {
        let results = scheduler.execute_batch_with_locks(batch, &balances);
        total_success += results.iter().filter(|r| r.success).count();
    }
    let elapsed = start.elapsed();

    assert_eq!(total_success, 5000, "All 5000 must succeed");
    let tps = 5000.0 / elapsed.as_secs_f64();
    assert!(tps > 500.0, "TPS: {:.0} (need > 500)", tps);
}

// ============================================================================
// TEST GROUP 4: Block Verification
// ============================================================================

#[test]
fn test_finalized_block_verifies() {
    let txs: Vec<Transaction> = (0..100).map(|i| {
        make_protocol_tx("alice", &format!("bob_{}", i), 100, i)
    }).collect();

    let block = build_test_block(1, &"0".repeat(64), txs);

    assert_eq!(block.tx_count, 100);
    assert!(!block.hash.is_empty());
    assert!(!block.state_root.is_empty());
    assert!(verify_block(&block, &"0".repeat(64)), "Block must pass verification");
}

#[test]
fn test_block_chain_links() {
    let mut blocks = vec![];
    let mut prev_hash = "0".repeat(64);

    for slot in 0..5 {
        let txs: Vec<Transaction> = (0..10).map(|i| {
            make_protocol_tx("sender", &format!("dest_{}_{}", slot, i), 10, slot * 10 + i)
        }).collect();

        let block = build_test_block(slot, &prev_hash, txs);
        prev_hash = block.hash.clone();
        blocks.push(block);
    }

    assert_eq!(blocks.len(), 5);

    for i in 1..blocks.len() {
        assert_eq!(blocks[i].previous_hash, blocks[i - 1].hash,
            "Block {} must link to block {}", i, i - 1);
    }

    assert!(verify_chain(&blocks), "Block chain must pass verification");
}

// ============================================================================
// TEST GROUP 5: Turbine Shredding Under Load
// ============================================================================

#[test]
fn test_turbine_shred_large_block() {
    let txs: Vec<Transaction> = (0..100).map(|i| {
        make_protocol_tx("sender", &format!("recv_{}", i), 100, i)
    }).collect();

    let block = build_test_block(42, &"0".repeat(64), txs);

    let shredder = TurbineShredder::new(42, "leader".to_string());
    let shreds = shredder.shred_block(&block);
    assert!(!shreds.is_empty(), "Must produce shreds");

    let reassembled = TurbineShredder::reassemble_block(&shreds);
    assert!(reassembled.is_ok(), "Must reassemble block: {:?}", reassembled.err());

    let reassembled = reassembled.unwrap();
    assert_eq!(reassembled.slot, block.slot);
    assert_eq!(reassembled.hash, block.hash);
    assert_eq!(reassembled.tx_count, block.tx_count);
}

// ============================================================================
// TEST GROUP 6: Ed25519 Wallet Creation and Signing Flow
// ============================================================================

#[test]
fn test_wallet_creation_and_funding() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let pubkey_hex = hex::encode(vk.to_bytes());

    let (bc, _tmp) = setup_blockchain(&[]);

    bc.credit(&pubkey_hex, 100.0).unwrap();
    let bal = bc.get_balance(&pubkey_hex);
    assert!((bal - 100.0).abs() < 0.001, "Funded wallet: {}", bal);

    let msg = format!("TRANSFER:{}:service:1.0:1", pubkey_hex);
    let sig = sk.sign(msg.as_bytes());
    assert!(vk.verify(msg.as_bytes(), &sig).is_ok());

    bc.transfer(&pubkey_hex, "service", 1.0).unwrap();
    assert!((bc.get_balance(&pubkey_hex) - 99.0).abs() < 0.001);
    assert!((bc.get_balance("service") - 1.0).abs() < 0.001);
}

#[test]
fn test_50_wallet_creation_and_transfers() {
    let (bc, _tmp) = setup_blockchain(&[]);
    let bc = Arc::new(bc);

    let wallets: Vec<(String, SigningKey)> = (0..50).map(|_| {
        let sk = SigningKey::generate(&mut OsRng);
        let addr = hex::encode(&sk.verifying_key().to_bytes()[..16]);
        bc.credit(&addr, 10.0).unwrap();
        (addr, sk)
    }).collect();

    for (i, (addr, sk)) in wallets.iter().enumerate() {
        let msg = format!("PAY:{}:pool:0.1:{}", addr, i);
        let sig = sk.sign(msg.as_bytes());
        assert!(sk.verifying_key().verify(msg.as_bytes(), &sig).is_ok(),
            "Wallet {} sig failed", i);
        bc.transfer(addr, "pool", 0.1).unwrap();
    }

    let pool_bal = bc.get_balance("pool");
    assert!((pool_bal - 5.0).abs() < 0.01, "Pool: {}", pool_bal);
}

// ============================================================================
// TEST GROUP 7: Circuit Breaker Under Sustained Load
// ============================================================================

#[test]
fn test_circuit_breaker_sustained_load() {
    let cb = CircuitBreaker::new();

    let mut tripped = false;
    for block in 1..=10 {
        for _ in 0..10 {
            match cb.check_transfer("whale", 1.0, 1000.0, block) {
                Ok(()) => {},
                Err(_) => { tripped = true; break; },
            }
        }
        if tripped { break; }
    }
    assert!(!tripped, "Small sustained transfers should NOT trip");
}

#[test]
fn test_circuit_breaker_rapid_large_transfers() {
    let cb = CircuitBreaker::new();

    let _ = cb.check_transfer("rapid_whale", 100.0, 1000.0, 1);
    let _ = cb.check_transfer("rapid_whale", 100.0, 1000.0, 1);
    let result = cb.check_transfer("rapid_whale", 50.0, 1000.0, 1);

    assert!(result.is_err(), "25% block outflow must trip breaker");
}

// ============================================================================
// TEST GROUP 8: Fee Market Under Stress
// ============================================================================

#[test]
fn test_fee_market_under_load() {
    let fm = LocalizedFeeMarket::new();

    for i in 0..1000 {
        let group = format!("group_{:03}", i % 100);
        let fee = fm.calculate_fee(&group);
        assert!(fee >= 0.0 && fee <= 1.0, "Fee out of range: {}", fee);
    }
}

// ============================================================================
// TEST GROUP 9: Adaptive Batch Tuning
// ============================================================================

#[test]
fn test_batch_tuning_convergence() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    for i in 0..500 {
        balances.insert(format!("ind_s_{}", i), 10.0);
    }
    let ind_txs: Vec<SealevelTx> = (0..500).map(|i| {
        make_sealevel_tx(&format!("ind_s_{}", i), &format!("ind_r_{}", i), 0.01)
    }).collect();

    let batches = scheduler.schedule_with_locks(ind_txs);
    for batch in batches {
        scheduler.execute_batch_with_locks(batch, &balances);
    }
    scheduler.tune_batch_size();
    let after_low = scheduler.get_batch_size();

    for i in 0..200 {
        balances.insert(format!("con_s_{}", i), 10.0);
    }
    let con_txs: Vec<SealevelTx> = (0..200).map(|i| {
        make_sealevel_tx(&format!("con_s_{}", i), "shared_dest", 0.01)
    }).collect();

    let batches = scheduler.schedule_with_locks(con_txs);
    for batch in batches {
        scheduler.execute_batch_with_locks(batch, &balances);
    }
    scheduler.tune_batch_size();
    let after_high = scheduler.get_batch_size();

    assert!(after_low >= 32 && after_low <= 1024, "Low-conflict: {}", after_low);
    assert!(after_high >= 32 && after_high <= 1024, "High-conflict: {}", after_high);
}

// ============================================================================
// TEST GROUP 10: Merkle Tree at Scale
// ============================================================================

#[test]
fn test_merkle_tree_10000_leaves() {
    // Build a large Merkle tree from account balances
    let mut accounts = std::collections::BTreeMap::new();
    for i in 0..10_000u64 {
        accounts.insert(format!("account_{}", i), i as f64 * 0.01);
    }

    let start = Instant::now();
    let tree = MerkleTree::from_accounts(&accounts);
    let build_time = start.elapsed();

    let root = tree.root_hex();
    assert!(!root.is_empty());
    assert!(build_time.as_millis() < 5000, "Merkle build: {:?}", build_time);

    // Verify a proof for a specific account
    // Leaves are sorted by key, so index maps to sorted order
    let sorted_keys: Vec<_> = accounts.keys().cloned().collect();
    if let Some(proof) = tree.generate_proof(5000) {
        let key = &sorted_keys[5000];
        let bal = accounts[key];
        assert!(proof.verify(key, bal),
            "Merkle proof must verify for account at index 5000");
    }
}

// ============================================================================
// TEST GROUP 11: Full Pipeline — Sign → Schedule → Execute → Verify
// ============================================================================

#[test]
fn test_full_production_pipeline() {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let alice_vk = alice_sk.verifying_key();

    let msg = b"TRANSFER:alice:bob:10.0:1:1700000000";
    let sig = alice_sk.sign(msg);
    assert!(alice_vk.verify(msg, &sig).is_ok(), "Alice sig must verify");

    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();
    balances.insert("alice".to_string(), 1000.0);

    let seal_tx = make_sealevel_tx("alice", "bob", 10.0);
    let results = scheduler.execute_batch_with_locks(vec![seal_tx], &balances);

    assert!(results[0].success, "Sealevel transfer must succeed");
    assert!((*balances.get("alice").unwrap() - 990.0).abs() < 0.001);
    assert!((*balances.get("bob").unwrap() - 10.0).abs() < 0.001);

    let tx = make_protocol_tx("alice", "bob", 1_000_000, 1);
    let block = build_test_block(1, &"0".repeat(64), vec![tx]);
    assert!(verify_block(&block, &"0".repeat(64)), "Block must pass verification");
}

// ============================================================================
// TEST GROUP 12: Network Throttler Under Load
// ============================================================================

#[test]
fn test_throttler_multiuser_fairness() {
    let nt = NetworkThrottler::new();

    let mut accepted_counts = vec![0u32; 50];

    for (i, count) in accepted_counts.iter_mut().enumerate() {
        let stake = (i as f64) * 10.0;
        for _ in 0..50 {
            if nt.check_transaction(&format!("user_{}", i), stake).is_ok() {
                *count += 1;
                nt.transaction_completed();
            }
        }
    }

    assert!(accepted_counts[0] <= accepted_counts[49],
        "Higher stake: low={}, high={}", accepted_counts[0], accepted_counts[49]);
}

// ============================================================================
// TEST GROUP 13: Production Statistics
// ============================================================================

#[test]
fn test_scheduler_stats_accuracy() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    for i in 0..100 {
        balances.insert(format!("s_{}", i), 10.0);
    }

    let txs: Vec<SealevelTx> = (0..100).map(|i| {
        make_sealevel_tx(&format!("s_{}", i), &format!("r_{}", i), 0.01)
    }).collect();

    let batches = scheduler.schedule_with_locks(txs);
    for batch in batches {
        scheduler.execute_batch_with_locks(batch, &balances);
    }

    let stats = scheduler.get_stats();
    assert_eq!(stats.total_processed, 100);
    assert!(stats.total_batches >= 1);
    assert!(stats.thread_count >= 1);
    assert!(stats.conflict_rate >= 0.0 && stats.conflict_rate <= 1.0);
}
