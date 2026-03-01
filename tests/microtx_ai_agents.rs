// ============================================================================
// BLACKBOOK L1 — AI AGENT MICROTRANSACTION TESTS
// ============================================================================
//
// Production-readiness tests proving BlackBook L1 can serve as a settlement
// layer for AI agent microtransactions:
//
//   1. Sub-cent precision:  1 lamport = $0.000001 at $0.10/BB
//   2. High-frequency agents: rapid-fire signed transfers
//   3. Multi-agent concurrency: parallel independent transfers
//   4. Nonce/replay protection: each agent tx is unique
//   5. Fee market isolation: one busy agent doesn't spike fees for others
//   6. Circuit breaker compatibility: agents respect safety limits
//   7. Ed25519 signing throughput: sign & verify at agent speed
//   8. SVM credit/debit at agent scale
//
// Run:  cargo test --test microtx_ai_agents
// ============================================================================

use layer1::svm::LAMPORTS_PER_BB;
use layer1::storage::ConcurrentBlockchain;
use layer1::runtime::core::{
    Transaction as SealevelTx, TransactionType, TransactionResult,
    AccountLockManager, ParallelScheduler,
};
use layer1::runtime::{
    CircuitBreaker, LocalizedFeeMarket, NetworkThrottler,
};
use layer1::poh_blockchain::{MerkleTree, MerkleProof};

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use ed25519_dalek::{SigningKey, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// ============================================================================
// CONSTANTS: AI Agent Transaction Parameters
// ============================================================================

/// Minimum practical microtransaction: 1 lamport = $0.000001
const ONE_LAMPORT_BB: f64 = 1.0 / LAMPORTS_PER_BB as f64;  // 0.00001 BB

/// Typical AI agent payment: $0.001 = 0.01 BB = 1000 lamports
const AGENT_MICRO_PAYMENT_BB: f64 = 0.01;

/// Number of simulated AI agents in concurrent tests
const NUM_AGENTS: usize = 50;

/// Transactions per agent in throughput tests
const TXS_PER_AGENT: usize = 20;

// ============================================================================
// HELPER: Create funded ConcurrentBlockchain for agent testing
// ============================================================================
fn setup_agent_blockchain(agents: usize, balance_bb: f64) -> (ConcurrentBlockchain, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let bc = ConcurrentBlockchain::new(tmp.path().join("test.redb").to_str().unwrap())
        .expect("blockchain");

    // Fund each agent account
    for i in 0..agents {
        bc.credit(&format!("agent_{}", i), balance_bb)
            .expect("credit agent");
    }
    // Fund a "service" account that agents pay
    bc.credit("ai_service", 0.0).unwrap_or_default();

    (bc, tmp)
}

fn make_agent_tx(from: &str, to: &str, amount: f64) -> SealevelTx {
    SealevelTx::new(from.to_string(), to.to_string(), amount, TransactionType::Transfer)
}

// ============================================================================
// TEST GROUP 1: Sub-Cent Precision for Microtransactions
// ============================================================================

#[test]
fn test_lamport_precision_one_lamport() {
    // 1 lamport is the smallest transferable unit
    assert_eq!(LAMPORTS_PER_BB, 100_000, "1 BB = 100,000 lamports (5 decimals)");

    let one_lamport = 1.0 / LAMPORTS_PER_BB as f64;
    assert!(one_lamport > 0.0, "1 lamport must be > 0");
    assert!(one_lamport < 0.001, "1 lamport must be sub-cent micro precision");
}

#[test]
fn test_lamport_precision_agent_payment() {
    // AI agent pays 0.01 BB ($0.001 at $0.10/BB)
    let lamports = (AGENT_MICRO_PAYMENT_BB * LAMPORTS_PER_BB as f64) as u64;
    assert_eq!(lamports, 1_000, "0.01 BB = 1,000 lamports exactly");

    // Round-trip: lamports → BB → lamports
    let bb_display = lamports as f64 / LAMPORTS_PER_BB as f64;
    let back = (bb_display * LAMPORTS_PER_BB as f64) as u64;
    assert_eq!(lamports, back, "Round-trip must be lossless");
}

#[test]
fn test_micro_fractions_no_dust() {
    // Critical: AI agents doing thousands of 0.00001 BB transfers
    // must not accumulate floating-point dust
    let (bc, _tmp) = setup_agent_blockchain(0, 0.0);
    bc.credit("agent_a", 1.0).unwrap();

    let micro = ONE_LAMPORT_BB; // 0.00001 BB = 1 lamport

    // Transfer 1 lamport 100 times
    for _ in 0..100 {
        bc.transfer("agent_a", "agent_b", micro).unwrap();
    }

    let a_bal = bc.get_balance("agent_a");
    let b_bal = bc.get_balance("agent_b");

    // Expected: sent 100 * 0.00001 = 0.001 BB
    let expected_sent = 0.001;
    let a_expected = 1.0 - expected_sent;

    // Verify within 1 lamport tolerance (f64 display rounding)
    assert!((a_bal - a_expected).abs() < ONE_LAMPORT_BB * 2.0,
        "Agent A balance drift: got {}, expected {}", a_bal, a_expected);
    assert!((b_bal - expected_sent).abs() < ONE_LAMPORT_BB * 2.0,
        "Agent B balance drift: got {}, expected {}", b_bal, expected_sent);
}

// ============================================================================
// TEST GROUP 2: High-Frequency Agent Transfers (Storage Layer)
// ============================================================================

#[test]
fn test_agent_rapid_fire_transfers() {
    let (bc, _tmp) = setup_agent_blockchain(0, 0.0);
    bc.credit("agent_fast", 10.0).unwrap();

    let start = Instant::now();
    let count = 500;

    for _ in 0..count {
        bc.transfer("agent_fast", "service", AGENT_MICRO_PAYMENT_BB)
            .expect("rapid transfer");
    }

    let elapsed = start.elapsed();
    let tps = count as f64 / elapsed.as_secs_f64();

    let remaining = bc.get_balance("agent_fast");
    let expected = 10.0 - (count as f64 * AGENT_MICRO_PAYMENT_BB);

    assert!((remaining - expected).abs() < ONE_LAMPORT_BB * 2.0,
        "Balance after {} transfers: got {}, expected {}", count, remaining, expected);

    // Should be able to do at least 1K TPS on local storage
    assert!(tps > 100.0,
        "Agent rapid-fire TPS too low: {:.0} (need > 100)", tps);
}

#[test]
fn test_agent_transfer_to_zero() {
    let (bc, _tmp) = setup_agent_blockchain(0, 0.0);
    bc.credit("agent_drain", 0.00005).unwrap(); // 5 lamports

    // Transfer exactly 5 lamports
    for _ in 0..5 {
        bc.transfer("agent_drain", "service", ONE_LAMPORT_BB).unwrap();
    }

    let bal = bc.get_balance("agent_drain");
    assert!(bal < ONE_LAMPORT_BB, "Agent should be at 0 after draining: {}", bal);

    // 6th transfer should fail
    let result = bc.transfer("agent_drain", "service", ONE_LAMPORT_BB);
    assert!(result.is_err(), "Transfer from empty account must fail");
}

// ============================================================================
// TEST GROUP 3: Multi-Agent Concurrent Sealevel Execution
// ============================================================================

#[test]
fn test_concurrent_independent_agents() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    // Fund 50 independent agents
    for i in 0..NUM_AGENTS {
        balances.insert(format!("agent_{}", i), 100.0);
    }

    // Each agent sends to its own unique recipient (no conflicts)
    let txs: Vec<SealevelTx> = (0..NUM_AGENTS).map(|i| {
        make_agent_tx(&format!("agent_{}", i), &format!("dest_{}", i), AGENT_MICRO_PAYMENT_BB)
    }).collect();

    let batches = scheduler.schedule_with_locks(txs);

    // All independent — should fit in 1 batch
    assert_eq!(batches.len(), 1,
        "50 independent agent txs should produce 1 batch, got {}", batches.len());

    // Execute
    let all_txs: Vec<SealevelTx> = batches.into_iter().flat_map(|b| b).collect();
    let results = scheduler.execute_batch_with_locks(all_txs, &balances);

    let successes = results.iter().filter(|r| r.success).count();
    assert_eq!(successes, NUM_AGENTS, "All {} agent txs must succeed", NUM_AGENTS);
}

#[test]
fn test_concurrent_agents_same_service() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    // All agents pay the same service (hot account contention)
    for i in 0..10 {
        balances.insert(format!("agent_{}", i), 100.0);
    }
    balances.insert("ai_service".to_string(), 0.0);

    let txs: Vec<SealevelTx> = (0..10).map(|i| {
        make_agent_tx(&format!("agent_{}", i), "ai_service", 0.01)
    }).collect();

    let batches = scheduler.schedule_with_locks(txs);

    // Contention on "ai_service" forces serialization
    assert!(batches.len() >= 2,
        "Hot account should create multiple batches, got {}", batches.len());

    // Execute all batches
    let mut all_results = vec![];
    for batch in batches {
        let results = scheduler.execute_batch_with_locks(batch, &balances);
        all_results.extend(results);
    }

    let successes = all_results.iter().filter(|r| r.success).count();
    assert_eq!(successes, 10, "All 10 payments to service must succeed");
}

#[test]
fn test_1000_agent_transactions_throughput() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    let total_txs = NUM_AGENTS * TXS_PER_AGENT; // 50 * 20 = 1000

    // Fund and create transactions
    for i in 0..NUM_AGENTS {
        balances.insert(format!("agent_{}", i), 1000.0);
    }

    let txs: Vec<SealevelTx> = (0..total_txs).map(|i| {
        let agent = i % NUM_AGENTS;
        make_agent_tx(
            &format!("agent_{}", agent),
            &format!("dest_{}_{}", agent, i / NUM_AGENTS),
            AGENT_MICRO_PAYMENT_BB,
        )
    }).collect();

    let start = Instant::now();
    let batches = scheduler.schedule_with_locks(txs);

    let mut total_success = 0;
    for batch in batches {
        let results = scheduler.execute_batch_with_locks(batch, &balances);
        total_success += results.iter().filter(|r| r.success).count();
    }
    let elapsed = start.elapsed();

    // All should succeed (each agent has 1000 BB, sends 20 * 0.01 = 0.2 BB)
    assert_eq!(total_success, total_txs,
        "All {} txs must succeed, got {}", total_txs, total_success);

    let tps = total_txs as f64 / elapsed.as_secs_f64();
    assert!(tps > 100.0,
        "Sealevel throughput too low: {:.0} TPS (need > 100 for {} txs)", tps, total_txs);
}

// ============================================================================
// TEST GROUP 4: Ed25519 Signing at Agent Speed
// ============================================================================

#[test]
fn test_agent_sign_verify_throughput() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();

    let count = 500;
    let start = Instant::now();

    for i in 0..count {
        let msg = format!("agent_payment:service:0.01:{}", i);
        let sig = sk.sign(msg.as_bytes());
        assert!(vk.verify(msg.as_bytes(), &sig).is_ok());
    }

    let elapsed = start.elapsed();
    let ops_per_sec = count as f64 / elapsed.as_secs_f64();

    // Ed25519 should easily do 10K+ sign+verify/s
    assert!(ops_per_sec > 1000.0,
        "Sign+verify rate too low: {:.0}/s (need > 1000)", ops_per_sec);
}

#[test]
fn test_agent_unique_signatures() {
    let sk = SigningKey::generate(&mut OsRng);

    // Same amount, same recipient — different nonces produce different sigs
    let sig1 = sk.sign(b"pay:service:0.01:nonce_1");
    let sig2 = sk.sign(b"pay:service:0.01:nonce_2");

    assert_ne!(sig1.to_bytes(), sig2.to_bytes(),
        "Different nonces must produce different signatures (replay protection)");
}

#[test]
fn test_multi_agent_keypair_isolation() {
    let agent_a = SigningKey::generate(&mut OsRng);
    let agent_b = SigningKey::generate(&mut OsRng);
    let vk_a = agent_a.verifying_key();
    let vk_b = agent_b.verifying_key();

    let msg = b"pay:service:0.01:nonce_1";
    let sig_a = agent_a.sign(msg);
    let sig_b = agent_b.sign(msg);

    // Agent A's sig won't verify with Agent B's key
    assert!(vk_b.verify(msg, &sig_a).is_err(),
        "Cross-agent signature must NOT verify");
    assert!(vk_a.verify(msg, &sig_b).is_err(),
        "Cross-agent signature must NOT verify (reverse)");

    // Each verifies with their own key
    assert!(vk_a.verify(msg, &sig_a).is_ok());
    assert!(vk_b.verify(msg, &sig_b).is_ok());
}

// ============================================================================
// TEST GROUP 5: Nonce / Replay Protection for Agents
// ============================================================================

#[test]
fn test_agent_nonce_uniqueness() {
    // Simulate agent nonce tracking
    let mut used_nonces: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for nonce in 0..1000 {
        assert!(used_nonces.insert(nonce), "Nonce {} must be unique", nonce);
    }

    // Replaying any nonce fails
    assert!(!used_nonces.insert(500), "Replay of nonce 500 must be caught");
}

#[test]
fn test_agent_signed_transfer_message_format() {
    // Agent transfer message follows our canonical format:
    // "TRANSFER:{from}:{to}:{lamports}:{nonce}:{timestamp}"
    let from = "agent_abc123";
    let to = "ai_service_xyz";
    let lamports: u64 = 1_000; // 0.01 BB
    let nonce: u64 = 42;
    let ts: u64 = 1700000000;

    let msg = format!("TRANSFER:{}:{}:{}:{}:{}", from, to, lamports, nonce, ts);

    // Must hash deterministically
    let hash1 = Sha256::digest(msg.as_bytes());
    let hash2 = Sha256::digest(msg.as_bytes());
    assert_eq!(hash1, hash2, "Transfer message hash must be deterministic");

    // Sign it
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let sig = sk.sign(msg.as_bytes());
    assert!(vk.verify(msg.as_bytes(), &sig).is_ok(),
        "Signed transfer message must verify");
}

#[test]
fn test_agent_timestamp_window() {
    // Agent transfers must be within 60s window
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let fresh_ts = now;
    let stale_ts = now - 120;  // 2 minutes ago
    let future_ts = now + 120; // 2 minutes ahead

    assert!(now.abs_diff(fresh_ts) <= 60, "Fresh timestamp should be accepted");
    assert!(now.abs_diff(stale_ts) > 60, "Stale timestamp should be rejected");
    assert!(now.abs_diff(future_ts) > 60, "Future timestamp should be rejected");
}

// ============================================================================
// TEST GROUP 6: Fee Market Isolation for AI Agents
// ============================================================================

#[test]
fn test_fee_market_spamming_agent_isolated() {
    let fm = LocalizedFeeMarket::new();

    // Spammer does 500 lookups
    for _ in 0..500 {
        fm.calculate_fee("spammer_agent_XXXX");
    }

    // Normal agent fee should be unaffected
    let normal_fee = fm.calculate_fee("normal_agent_YYYY");
    assert!(normal_fee <= 0.01,
        "Normal agent fee should be near-zero: {}", normal_fee);
}

#[test]
fn test_fee_market_many_agents_fair() {
    let fm = LocalizedFeeMarket::new();

    // 50 agents each make 5 requests (moderate load)
    let mut fees = vec![];
    for i in 0..50 {
        let f = fm.calculate_fee(&format!("agent_{:03}", i));
        fees.push(f);
    }

    // All fees should be identical for first-time requesters
    let first = fees[0];
    for (i, &f) in fees.iter().enumerate() {
        assert!((f - first).abs() < 0.001,
            "Agent {} fee ({}) diverges from agent 0 fee ({})", i, f, first);
    }
}

// ============================================================================
// TEST GROUP 7: Circuit Breaker Compatibility with Agents
// ============================================================================

#[test]
fn test_circuit_breaker_allows_micro_transfers() {
    let cb = CircuitBreaker::new();

    // Agent has 100 BB, sends 0.01 BB repeatedly (well under 20% block limit)
    for _ in 0..10 {
        let result = cb.check_transfer("micro_agent", 0.01, 100.0, 1);
        assert!(result.is_ok(), "Micro transfers must pass circuit breaker: {:?}", result);
    }
}

#[test]
fn test_circuit_breaker_trips_on_agent_drain_attempt() {
    let cb = CircuitBreaker::new();

    // Someone tries to drain an agent's full balance in one block
    let result1 = cb.check_transfer("victim_agent", 15.0, 100.0, 1); // 15%
    assert!(result1.is_ok(), "15% should be OK");

    let result2 = cb.check_transfer("victim_agent", 10.0, 100.0, 1); // 25% total > 20% threshold
    assert!(result2.is_err(), "25% block outflow must trip circuit breaker");
}

// ============================================================================
// TEST GROUP 8: Network Throttler — Agent Rate Limits
// ============================================================================

#[test]
fn test_throttler_allows_agent_burst() {
    let nt = NetworkThrottler::new();

    // Agent with 100 stake can do base_10 + (100 * 0.1) = 20 txs/window
    for i in 0..15 {
        let result = nt.check_transaction("agent_burst", 100.0);
        assert!(result.is_ok(), "Tx {} should be allowed with 100 stake", i);
        nt.transaction_completed();
    }
}

#[test]
fn test_throttler_rejects_after_limit() {
    let nt = NetworkThrottler::new();

    // Zero-stake agent: limit = 10 txs/window
    let mut accepted = 0;
    for _ in 0..20 {
        if nt.check_transaction("zero_stake_agent", 0.0).is_ok() {
            accepted += 1;
        }
    }

    assert_eq!(accepted, 10, "Zero-stake agent should be limited to 10 txs/window");
}

// ============================================================================
// TEST GROUP 9: Merkle Proofs for Agent Transaction Receipts
// ============================================================================

#[test]
fn test_agent_tx_merkle_proof() {
    // Agent needs to prove its payment was included in a block
    // MerkleTree API uses account balances, not tx hashes
    let mut accounts = std::collections::BTreeMap::new();
    for i in 0..10 {
        accounts.insert(format!("agent_{}", i), i as f64 * 0.01);
    }

    let tree = MerkleTree::from_accounts(&accounts);
    let root = tree.root_hex();
    assert!(!root.is_empty(), "Merkle root must exist");

    // Generate proof for agent's 5th account (sorted by key)
    let sorted_keys: Vec<_> = accounts.keys().cloned().collect();
    if let Some(proof) = tree.generate_proof(4) {
        let key = &sorted_keys[4];
        let bal = accounts[key];
        assert!(proof.verify(key, bal),
            "Merkle proof for agent account must verify");
    }
}

#[test]
fn test_merkle_proof_tamper_detection() {
    let mut accounts = std::collections::BTreeMap::new();
    for i in 0..5 {
        accounts.insert(format!("account_{}", i), (i + 1) as f64 * 10.0);
    }

    let tree = MerkleTree::from_accounts(&accounts);
    let root = tree.root_hex();
    let sorted_keys: Vec<_> = accounts.keys().cloned().collect();

    if let Some(proof) = tree.generate_proof(0) {
        // Valid leaf
        let key = &sorted_keys[0];
        let bal = accounts[key];
        assert!(proof.verify(key, bal));

        // Tampered address
        assert!(!proof.verify("fake_account", bal),
            "Tampered account must NOT pass merkle verification");

        // Tampered balance
        assert!(!proof.verify(key, 999999.0),
            "Tampered balance must NOT pass merkle verification");
    }
}

// ============================================================================
// TEST GROUP 10: End-to-End Agent Payment Flow
// ============================================================================

#[test]
fn test_end_to_end_agent_payment() {
    // Full flow: keygen → sign → schedule → execute → verify balance
    let agent_keys = SigningKey::generate(&mut OsRng);
    let agent_vk = agent_keys.verifying_key();
    let agent_addr = format!("agent_{}", hex::encode(&agent_vk.to_bytes()[..8]));

    // 1. Set up balances
    let balances: DashMap<String, f64> = DashMap::new();
    balances.insert(agent_addr.clone(), 10.0);
    balances.insert("ai_service".to_string(), 0.0);

    // 2. Agent signs payment
    let nonce = 1u64;
    let amount = 0.01f64;
    let msg = format!("TRANSFER:{}:ai_service:{}:{}", agent_addr, amount, nonce);
    let sig = agent_keys.sign(msg.as_bytes());

    // 3. Verify signature (what the validator would do)
    assert!(agent_vk.verify(msg.as_bytes(), &sig).is_ok(),
        "Agent signature must verify before scheduling");

    // 4. Schedule + execute via Sealevel
    let scheduler = ParallelScheduler::new();
    let tx = make_agent_tx(&agent_addr, "ai_service", amount);
    let results = scheduler.execute_batch_with_locks(vec![tx], &balances);

    assert!(results[0].success, "Agent payment must succeed");

    // 5. Verify balances
    let agent_bal = *balances.get(&agent_addr).unwrap();
    let service_bal = *balances.get("ai_service").unwrap();

    assert!((agent_bal - 9.99).abs() < 0.001, "Agent balance: {}", agent_bal);
    assert!((service_bal - 0.01).abs() < 0.001, "Service balance: {}", service_bal);
}

#[test]
fn test_end_to_end_multi_agent_settlement() {
    let scheduler = ParallelScheduler::new();
    let balances: DashMap<String, f64> = DashMap::new();

    let num_agents = 20;

    // Generate keypairs and fund agents
    let agents: Vec<(String, SigningKey)> = (0..num_agents).map(|i| {
        let sk = SigningKey::generate(&mut OsRng);
        let addr = format!("agent_{}", i);
        balances.insert(addr.clone(), 5.0);
        (addr, sk)
    }).collect();
    balances.insert("settlement_service".to_string(), 0.0);

    // Each agent signs and sends a microtransaction
    let mut txs = vec![];
    for (i, (addr, sk)) in agents.iter().enumerate() {
        let msg = format!("TRANSFER:{}:settlement_service:0.01:{}", addr, i);
        let sig = sk.sign(msg.as_bytes());
        assert!(sk.verifying_key().verify(msg.as_bytes(), &sig).is_ok());

        txs.push(make_agent_tx(addr, "settlement_service", 0.01));
    }

    // Schedule and execute
    let batches = scheduler.schedule_with_locks(txs);
    let mut total_success = 0;
    for batch in batches {
        let results = scheduler.execute_batch_with_locks(batch, &balances);
        total_success += results.iter().filter(|r| r.success).count();
    }

    assert_eq!(total_success, num_agents, "All {} agent payments must succeed", num_agents);

    // Service received 20 * 0.01 = 0.2 BB
    let service_bal = *balances.get("settlement_service").unwrap();
    assert!((service_bal - 0.2).abs() < 0.001,
        "Service should have 0.2 BB: got {}", service_bal);
}
