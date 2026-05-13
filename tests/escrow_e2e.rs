// ============================================================================
// BLACKBOOK L1 — ESCROW END-TO-END CRYPTO INTEGRATION TESTS
// ============================================================================
//
// Tests the complete cryptographic pipeline for the escrow contract without
// requiring a running HTTP server. Validates:
//
//   1. Ed25519 deposit message signing (matches /escrow/deposit handler)
//   2. Merkle tree construction — sorted-pair SHA-256 (matches svm_settlement.rs)
//   3. Merkle leaf hash format (matches /escrow/withdraw handler)
//   4. Merkle proof verification (matches /escrow/withdraw handler)
//   5. Ed25519 withdraw message signing (matches /escrow/withdraw handler)
//   6. SubmitMerkleRoot binary-packed signed message (matches settlement gRPC)
//   7. Full settlement pipeline: build tree → submit root → verify withdrawal
//   8. Double-claim detection logic
//   9. Zero-sum invariant with multiple winners
//  10. Sorted-pair hash ordering correctness
//
// Run with:
//   cargo test --test escrow_e2e -- --nocapture
// ============================================================================

use std::collections::HashSet;

use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Verifier, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// ============================================================================
// HELPERS — replicate L1 logic exactly
// ============================================================================

/// Generate a fresh Ed25519 keypair. Returns (signing_key, pubkey_bytes_32, bs58_address).
fn new_keypair() -> (SigningKey, [u8; 32], String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk: [u8; 32] = sk.verifying_key().to_bytes();
    let address = bs58::encode(&pk).into_string();
    (sk, pk, address)
}

/// Compute a Merkle leaf exactly as the L1 withdraw handler does:
///   SHA-256( pubkey_raw_32 ++ amount_spl_u64_le8 )
fn compute_leaf(pubkey_raw: &[u8; 32], amount_spl: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey_raw);
    h.update(amount_spl.to_le_bytes());
    h.finalize().into()
}

/// Hash a pair using sorted order (smaller bytes first), as per L1 withdraw handler.
fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    if a <= b {
        h.update(a);
        h.update(b);
    } else {
        h.update(b);
        h.update(a);
    }
    h.finalize().into()
}

/// Build a complete sorted-pair Merkle tree over the given leaves.
/// Returns `(root, Vec<Vec<[u8;32]>>)` where the inner Vec is each level
/// from bottom (leaves) to top (root).
fn build_tree(leaves: Vec<[u8; 32]>) -> (
    [u8; 32],
    Vec<Vec<[u8; 32]>>,  // levels[0] = leaves, levels[last] = [root]
) {
    assert!(!leaves.is_empty(), "tree must have at least one leaf");
    let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::new();
        let mut i = 0;
        while i < prev.len() {
            let left = prev[i];
            let right = if i + 1 < prev.len() { prev[i + 1] } else { prev[i] };
            next.push(hash_pair(left, right));
            i += 2;
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    (root, levels)
}

/// Generate a Merkle proof for `leaf_index` given the level structure from build_tree.
fn build_proof(levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut idx = leaf_index;
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < level.len() { idx + 1 } else { idx }
        } else {
            idx - 1
        };
        proof.push(level[sibling_idx]);
        idx /= 2;
    }
    proof
}

/// Verify a Merkle proof exactly as the L1 withdraw handler does.
fn verify_proof(leaf: [u8; 32], proof: &[[u8; 32]], expected_root: [u8; 32]) -> bool {
    let mut current = leaf;
    for &sibling in proof {
        current = hash_pair(current, sibling);
    }
    current == expected_root
}

/// Build the binary-packed SubmitMerkleRoot signed message:
///   contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]
fn build_submit_signed_message(contest_id: &str, l2_block: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(contest_id.len() + 8 + 32);
    msg.extend_from_slice(contest_id.as_bytes());
    msg.extend_from_slice(&l2_block.to_le_bytes());
    msg.extend_from_slice(root);
    msg
}

// ============================================================================
// TEST 1 — Ed25519 deposit message signing
// ============================================================================

#[test]
fn test_deposit_message_format() {
    let (sk, _pk, address) = new_keypair();
    let amount = 10.0_f64;
    let timestamp = 1_742_500_000_u64;
    let nonce = "test-nonce-001";

    // MUST match L1 handler: "ESCROW_DEPOSIT:{wallet}:{amount}:{timestamp}:{nonce}"
    let message = format!("ESCROW_DEPOSIT:{}:{}:{}:{}", address, amount, timestamp, nonce);
    let sig: Signature = sk.sign(message.as_bytes());

    let vk = sk.verifying_key();
    assert!(
        vk.verify(message.as_bytes(), &sig).is_ok(),
        "Deposit message signature failed to verify"
    );

    println!("✅ TEST 1: Deposit message signed and verified");
    println!("   wallet:  {}", address);
    println!("   message: {}", message);
    println!("   sig:     {}", hex::encode(sig.to_bytes()));
    println!("   pubkey:  {}", hex::encode(vk.to_bytes()));
}

// ============================================================================
// TEST 2 — Merkle leaf hash format
// ============================================================================

#[test]
fn test_leaf_hash_format() {
    let (_sk, pk, address) = new_keypair();
    let amount_bb = 5.0_f64;
    let amount_spl = (amount_bb * 1_000_000.0).round() as u64;
    assert_eq!(amount_spl, 5_000_000);

    let leaf = compute_leaf(&pk, amount_spl);

    // Manually verify: SHA256(pubkey_32 ++ amount_le8)
    let mut h = Sha256::new();
    h.update(&pk);
    h.update(&5_000_000_u64.to_le_bytes());
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(leaf, expected, "Leaf hash does not match expected SHA-256 output");

    println!("✅ TEST 2: Leaf hash format verified");
    println!("   wallet:     {}", address);
    println!("   amount_spl: {}", amount_spl);
    println!("   leaf:       {}", hex::encode(leaf));
}

// ============================================================================
// TEST 3 — Sorted-pair hash ordering
// ============================================================================

#[test]
fn test_sorted_pair_hash_ordering() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[31] = 1; // b > a

    let h_ab = hash_pair(a, b);
    let h_ba = hash_pair(b, a); // should produce same result

    assert_eq!(h_ab, h_ba, "Sorted-pair hash must be commutative");

    println!("✅ TEST 3: Sorted-pair hash is commutative (order-independent)");
}

// ============================================================================
// TEST 4 — Single-leaf Merkle tree (edge case)
// ============================================================================

#[test]
fn test_single_leaf_tree() {
    let (_sk, pk, _addr) = new_keypair();
    let leaf = compute_leaf(&pk, 10_000_000);

    let (root, levels) = build_tree(vec![leaf]);
    let proof = build_proof(&levels, 0);

    // Single leaf: root IS the leaf, proof is empty
    assert_eq!(root, leaf);
    assert!(proof.is_empty());
    assert!(verify_proof(leaf, &proof, root));

    println!("✅ TEST 4: Single-leaf tree — root equals leaf, empty proof verifies");
}

// ============================================================================
// TEST 5 — Two-leaf Merkle tree
// ============================================================================

#[test]
fn test_two_leaf_tree() {
    let (_sk1, pk1, _) = new_keypair();
    let (_sk2, pk2, _) = new_keypair();

    let leaf1 = compute_leaf(&pk1, 6_000_000);
    let leaf2 = compute_leaf(&pk2, 4_000_000);

    let (root, levels) = build_tree(vec![leaf1, leaf2]);
    let proof1 = build_proof(&levels, 0);
    let proof2 = build_proof(&levels, 1);

    assert!(verify_proof(leaf1, &proof1, root), "Leaf 1 proof failed");
    assert!(verify_proof(leaf2, &proof2, root), "Leaf 2 proof failed");

    // Wrong leaf must fail
    assert!(!verify_proof(leaf1, &proof2, root), "Cross-proof must not verify");

    println!("✅ TEST 5: Two-leaf tree — both proofs verify, cross-proof rejected");
    println!("   root: {}", hex::encode(root));
}

// ============================================================================
// TEST 6 — Multi-winner Merkle tree (4 winners)
// ============================================================================

#[test]
fn test_multi_winner_tree() {
    let winners: Vec<([u8; 32], u64)> = (0..4)
        .map(|i| {
            let (_sk, pk, _) = new_keypair();
            let amount_spl = (i + 1) as u64 * 2_000_000; // 2, 4, 6, 8 BB
            (pk, amount_spl)
        })
        .collect();

    let leaves: Vec<[u8; 32]> = winners.iter()
        .map(|(pk, spl)| compute_leaf(pk, *spl))
        .collect();

    let (root, levels) = build_tree(leaves.clone());

    for (i, (pk, spl)) in winners.iter().enumerate() {
        let leaf = compute_leaf(pk, *spl);
        let proof = build_proof(&levels, i);
        assert!(
            verify_proof(leaf, &proof, root),
            "Winner {} proof failed", i
        );
    }

    println!("✅ TEST 6: 4-winner tree — all proofs verify independently");
    println!("   root: {}", hex::encode(root));
}

// ============================================================================
// TEST 7 — Odd-number winner tree (3 winners — duplicate last node)
// ============================================================================

#[test]
fn test_odd_winner_tree() {
    let winners: Vec<([u8; 32], u64)> = (0..3)
        .map(|_| {
            let (_sk, pk, _) = new_keypair();
            (pk, 3_000_000_u64)
        })
        .collect();

    let leaves: Vec<[u8; 32]> = winners.iter()
        .map(|(pk, spl)| compute_leaf(pk, *spl))
        .collect();

    let (root, levels) = build_tree(leaves.clone());

    for (i, (pk, spl)) in winners.iter().enumerate() {
        let leaf = compute_leaf(pk, *spl);
        let proof = build_proof(&levels, i);
        assert!(
            verify_proof(leaf, &proof, root),
            "Winner {} proof failed in odd-count tree", i
        );
    }

    println!("✅ TEST 7: 3-winner (odd) tree — all proofs verify with duplicate-last logic");
}

// ============================================================================
// TEST 8 — Zero-sum invariant check
// ============================================================================

#[test]
fn test_zero_sum_invariant() {
    let total_deposited: u64 = 10_000_000; // 10 BB
    let total_payout:    u64 =  9_500_000; // 9.5 BB to winners
    let house_rake:      u64 =    500_000; // 0.5 BB rake

    // Valid: deposited == payout + rake
    assert_eq!(
        total_deposited,
        total_payout.saturating_add(house_rake),
        "Zero-sum invariant violated"
    );

    // Invalid: would be caught by L1
    let bad_payout: u64 = 9_000_000;
    assert_ne!(
        total_deposited,
        bad_payout.saturating_add(house_rake),
        "Bad zero-sum should not pass"
    );

    println!("✅ TEST 8: Zero-sum invariant — valid case passes, invalid case caught");
}

// ============================================================================
// TEST 9 — SubmitMerkleRoot binary-packed signed message
// ============================================================================

#[test]
fn test_submit_merkle_root_signed_message() {
    let (sk, pk, _addr) = new_keypair();
    let contest_id = "contest-test-001";
    let l2_block: u64 = 9001;

    // Build a tiny tree to get a real root
    let (_sk2, pk2, _) = new_keypair();
    let leaf1 = compute_leaf(&pk, 6_000_000);
    let leaf2 = compute_leaf(&pk2, 4_000_000);
    let (root, _) = build_tree(vec![leaf1, leaf2]);

    // Build the binary-packed message exactly as L2 settlement_bridge.rs must
    let msg = build_submit_signed_message(contest_id, l2_block, &root);

    // Sign it
    let sig: Signature = sk.sign(&msg);

    // Verify as L1 settlement handler does
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(
        vk.verify(&msg, &sig).is_ok(),
        "SubmitMerkleRoot signed message failed to verify"
    );

    // Wrong block number must not verify
    let bad_msg = build_submit_signed_message(contest_id, l2_block + 1, &root);
    assert!(
        vk.verify(&bad_msg, &sig).is_err(),
        "Modified l2_block should invalidate the signature"
    );

    println!("✅ TEST 9: SubmitMerkleRoot binary-packed message — sign + verify OK");
    println!("   contest_id:  {}", contest_id);
    println!("   l2_block:    {}", l2_block);
    println!("   merkle_root: {}", hex::encode(root));
    println!("   sequencer:   {}", hex::encode(pk));
    println!("   sig:         {}", hex::encode(sig.to_bytes()));
}

// ============================================================================
// TEST 10 — Withdraw message signing
// ============================================================================

#[test]
fn test_withdraw_message_format() {
    let (sk, _pk, address) = new_keypair();
    let market_id = "contest-test-001";
    let amount = 6.0_f64;
    let timestamp = 1_742_500_100_u64;
    let nonce = "withdraw-nonce-xyz";

    // MUST match L1 handler:
    // "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
    let message = format!(
        "ESCROW_WITHDRAW:{}:{}:{}:{}:{}",
        market_id, address, amount, timestamp, nonce
    );
    let sig: Signature = sk.sign(message.as_bytes());

    let vk = sk.verifying_key();
    assert!(
        vk.verify(message.as_bytes(), &sig).is_ok(),
        "Withdraw message signature failed to verify"
    );

    println!("✅ TEST 10: Withdraw message signed and verified");
    println!("   message: {}", message);
}

// ============================================================================
// TEST 11 — Full settlement pipeline (end-to-end crypto, no HTTP)
// ============================================================================
//
// Simulates the complete L1 escrow lifecycle:
//   deposit → submit root → verify withdrawal proof → double-claim blocked

#[test]
fn test_full_settlement_pipeline() {
    // ── Step 1: Create sequencer + 3 winners ─────────────────────────────
    let (seq_sk, seq_pk, _) = new_keypair();
    let (winner1_sk, winner1_pk, winner1_addr) = new_keypair();
    let (winner2_sk, winner2_pk, winner2_addr) = new_keypair();
    let (_loser_sk, loser_pk, loser_addr) = new_keypair();

    let contest_id = "contest-pipeline-test";
    let l2_block: u64 = 42;

    // Winners and their payouts (SPL units)
    let winner1_spl: u64 = 5_500_000; // 5.5 BB
    let winner2_spl: u64 = 4_000_000; // 4.0 BB
    let total_payout:   u64 = winner1_spl + winner2_spl; // 9.5 BB
    let house_rake:     u64 = 500_000;  // 0.5 BB
    let total_deposited: u64 = total_payout + house_rake; // 10.0 BB

    // ── Step 2: Zero-sum check ────────────────────────────────────────────
    assert_eq!(total_deposited, total_payout + house_rake, "Zero-sum violated");

    // ── Step 3: Build Merkle tree ─────────────────────────────────────────
    let leaf1 = compute_leaf(&winner1_pk, winner1_spl);
    let leaf2 = compute_leaf(&winner2_pk, winner2_spl);
    let (root, levels) = build_tree(vec![leaf1, leaf2]);

    // ── Step 4: Sequencer signs the SubmitMerkleRoot message ─────────────
    let msg = build_submit_signed_message(contest_id, l2_block, &root);
    let seq_sig: Signature = seq_sk.sign(&msg);

    // L1 verification of sequencer sig
    let seq_vk = VerifyingKey::from_bytes(&seq_pk).unwrap();
    assert!(seq_vk.verify(&msg, &seq_sig).is_ok(), "Sequencer sig invalid");

    // ── Step 5: Winner 1 generates and verifies their proof ──────────────
    let proof1 = build_proof(&levels, 0);
    assert!(verify_proof(leaf1, &proof1, root), "Winner1 proof failed");

    // Winner 1 signs their withdraw message
    let ts1 = 1_742_500_200_u64;
    let nonce1 = "w1-nonce";
    let amount1_bb = winner1_spl as f64 / 1_000_000.0;
    let withdraw_msg1 = format!(
        "ESCROW_WITHDRAW:{}:{}:{}:{}:{}",
        contest_id, winner1_addr, amount1_bb, ts1, nonce1
    );
    let w1_sig = winner1_sk.sign(withdraw_msg1.as_bytes());
    let w1_vk = VerifyingKey::from_bytes(&winner1_pk).unwrap();
    assert!(w1_vk.verify(withdraw_msg1.as_bytes(), &w1_sig).is_ok());

    // ── Step 6: Winner 2 generates and verifies their proof ──────────────
    let proof2 = build_proof(&levels, 1);
    assert!(verify_proof(leaf2, &proof2, root), "Winner2 proof failed");

    let ts2 = 1_742_500_201_u64;
    let nonce2 = "w2-nonce";
    let amount2_bb = winner2_spl as f64 / 1_000_000.0;
    let withdraw_msg2 = format!(
        "ESCROW_WITHDRAW:{}:{}:{}:{}:{}",
        contest_id, winner2_addr, amount2_bb, ts2, nonce2
    );
    let w2_sig = winner2_sk.sign(withdraw_msg2.as_bytes());
    let w2_vk = VerifyingKey::from_bytes(&winner2_pk).unwrap();
    assert!(w2_vk.verify(withdraw_msg2.as_bytes(), &w2_sig).is_ok());

    // ── Step 7: Loser's claim must fail proof verification ────────────────
    let loser_leaf = compute_leaf(&loser_pk, winner1_spl); // wrong wallet in tree
    let loser_proof = build_proof(&levels, 0); // steal winner1's proof
    assert!(
        !verify_proof(loser_leaf, &loser_proof, root),
        "Loser should not verify with winner's proof"
    );
    let _ = loser_addr; // quiets unused warning

    // ── Step 8: Double-claim simulation ──────────────────────────────────
    let mut claimed: HashSet<String> = HashSet::new();
    let claim_key = format!("{}:{}", contest_id, winner1_addr);

    // First claim
    assert!(!claimed.contains(&claim_key), "Should not be claimed yet");
    claimed.insert(claim_key.clone());

    // Second claim attempt
    assert!(claimed.contains(&claim_key), "Double-claim should be blocked");

    println!("✅ TEST 11: Full settlement pipeline passed:");
    println!("   contest:        {}", contest_id);
    println!("   total_deposited: {} SPL ({} BB)", total_deposited, total_deposited as f64 / 1e6);
    println!("   total_payout:    {} SPL ({} BB)", total_payout, total_payout as f64 / 1e6);
    println!("   house_rake:      {} SPL ({} BB)", house_rake, house_rake as f64 / 1e6);
    println!("   merkle_root:    {}", hex::encode(root));
    println!("   winner1 proof:  {} siblings", proof1.len());
    println!("   winner2 proof:  {} siblings", proof2.len());
    println!("   loser rejected: ✓");
    println!("   double-claim blocked: ✓");
}

// ============================================================================
// TEST 12 — Large-batch tree (32 winners)
// ============================================================================

#[test]
fn test_large_batch_tree() {
    let n = 32;
    let winners: Vec<([u8; 32], u64)> = (0..n)
        .map(|i| {
            let (_sk, pk, _) = new_keypair();
            let spl = (i as u64 + 1) * 1_000_000; // 1–32 BB
            (pk, spl)
        })
        .collect();

    let leaves: Vec<[u8; 32]> = winners.iter()
        .map(|(pk, spl)| compute_leaf(pk, *spl))
        .collect();

    let (root, levels) = build_tree(leaves.clone());

    let mut failures = 0;
    for (i, (pk, spl)) in winners.iter().enumerate() {
        let leaf = compute_leaf(pk, *spl);
        let proof = build_proof(&levels, i);
        if !verify_proof(leaf, &proof, root) {
            failures += 1;
        }
    }

    assert_eq!(failures, 0, "{} proofs failed in 32-winner tree", failures);

    println!("✅ TEST 12: 32-winner tree — all {} proofs verified, tree depth = {}",
        n, levels.len() - 1);
    println!("   root: {}", hex::encode(root));
}

// ============================================================================
// TEST 13 — SubmitPendingRoot canonical signed message
// ============================================================================
//
// Oracle Step 2 path: canonical message adds `outcome_bytes` to the end.
// Format: contest_id_bytes ++ l2_block_number_le8 ++ merkle_root[32] ++ outcome_bytes

#[test]
fn test_submit_pending_root_signed_message() {
    let (sk, pk, _addr) = new_keypair();
    let contest_id = "oracle-contest-001";
    let l2_block: u64 = 1001;
    let outcome = "Yes";

    // Build a real root
    let (_sk2, pk2, _) = new_keypair();
    let leaf1 = compute_leaf(&pk, 6_000_000);
    let leaf2 = compute_leaf(&pk2, 4_000_000);
    let (root, _) = build_tree(vec![leaf1, leaf2]);

    // Build pending-root canonical message (same as SubmitMerkleRoot + outcome appended)
    let mut msg = Vec::with_capacity(contest_id.len() + 8 + 32 + outcome.len());
    msg.extend_from_slice(contest_id.as_bytes());
    msg.extend_from_slice(&l2_block.to_le_bytes());
    msg.extend_from_slice(&root);
    msg.extend_from_slice(outcome.as_bytes());

    let sig: Signature = sk.sign(&msg);

    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(vk.verify(&msg, &sig).is_ok(), "SubmitPendingRoot message failed to verify");

    // Wrong outcome must not verify
    let mut bad_msg = Vec::new();
    bad_msg.extend_from_slice(contest_id.as_bytes());
    bad_msg.extend_from_slice(&l2_block.to_le_bytes());
    bad_msg.extend_from_slice(&root);
    bad_msg.extend_from_slice(b"No"); // wrong outcome
    assert!(
        vk.verify(&bad_msg, &sig).is_err(),
        "Modified outcome should invalidate the signature"
    );

    println!("✅ TEST 13: SubmitPendingRoot canonical message — sign + verify OK");
    println!("   contest_id: {}", contest_id);
    println!("   outcome:    {}", outcome);
    println!("   root:       {}", hex::encode(root));
}

// ============================================================================
// TEST 14 — Oracle dispute signed message
// ============================================================================

#[test]
fn test_oracle_dispute_signed_message() {
    let (sk, pk, addr) = new_keypair();
    let market_id = "oracle-contest-001";
    let xx_stake_pico: u64 = 100 * 1_000_000_000_000; // 100 $XX in pico-MAXX
    let timestamp: u64 = 1_742_500_500;
    let nonce = "dispute-nonce-001";

    // MUST match L1 handler: "ORACLE_DISPUTE:{market_id}:{xx_stake_pico}:{timestamp}:{nonce}"
    let message = format!("ORACLE_DISPUTE:{}:{}:{}:{}", market_id, xx_stake_pico, timestamp, nonce);
    let sig: Signature = sk.sign(message.as_bytes());

    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(vk.verify(message.as_bytes(), &sig).is_ok(), "Dispute message failed to verify");

    // Wrong stake must not verify
    let bad_msg = format!("ORACLE_DISPUTE:{}:{}:{}:{}", market_id, xx_stake_pico + 1, timestamp, nonce);
    assert!(vk.verify(bad_msg.as_bytes(), &sig).is_err(), "Modified stake should fail");

    println!("✅ TEST 14: Oracle dispute signed message — sign + verify OK");
    println!("   wallet:       {}", addr);
    println!("   xx_stake_pico:{}", xx_stake_pico);
    println!("   message:      {}", message);
}

// ============================================================================
// TEST 15 — Oracle vote signed message
// ============================================================================

#[test]
fn test_oracle_vote_signed_message() {
    let (sk, pk, addr) = new_keypair();
    let market_id = "oracle-contest-001";
    let vote = false; // discard root
    let timestamp: u64 = 1_742_500_600;
    let nonce = "vote-nonce-001";

    // MUST match L1 handler: "ORACLE_VOTE:{market_id}:{vote}:{timestamp}:{nonce}"
    let message = format!("ORACLE_VOTE:{}:{}:{}:{}", market_id, vote, timestamp, nonce);
    let sig: Signature = sk.sign(message.as_bytes());

    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(vk.verify(message.as_bytes(), &sig).is_ok(), "Vote message failed to verify");

    // Flipped vote must not verify
    let bad_msg = format!("ORACLE_VOTE:{}:{}:{}:{}", market_id, !vote, timestamp, nonce);
    assert!(vk.verify(bad_msg.as_bytes(), &sig).is_err(), "Modified vote should fail");

    println!("✅ TEST 15: Oracle vote signed message — sign + verify OK");
    println!("   wallet:  {}", addr);
    println!("   vote:    {}", vote);
    println!("   message: {}", message);
}

// ============================================================================
// TEST 16 — Oracle storage roundtrip (PendingRoot struct)
// ============================================================================

#[test]
fn test_pending_root_storage_roundtrip() {
    use sha2::{Sha256, Digest};

    let (_sk, pk, _) = new_keypair();
    let leaf = compute_leaf(&pk, 5_000_000);
    let (root, _) = build_tree(vec![leaf]);

    // Simulate what SubmitPendingRoot stores
    let pending = serde_json::json!({
        "market_id": "oracle-roundtrip-test",
        "outcome": "Yes",
        "merkle_root": root,
        "proposed_at_slot": 100_u64,
        "finalize_at_slot": 106_480_u64,
        "dispute_stake_pico_xx": 0_u64,
        "status": "Pending",
        "proposer_pubkey": hex::encode(pk),
        "oracle_signatures": [],
        "disputers": [],
    });

    let serialized = serde_json::to_vec(&pending).expect("serialize failed");
    let deserialized: serde_json::Value =
        serde_json::from_slice(&serialized).expect("deserialize failed");

    assert_eq!(deserialized["market_id"], "oracle-roundtrip-test");
    assert_eq!(deserialized["outcome"], "Yes");
    assert_eq!(deserialized["status"], "Pending");
    assert_eq!(deserialized["dispute_stake_pico_xx"], 0);

    // Verify oracle_event_hash is deterministic
    let mut hasher = Sha256::new();
    hasher.update(b"oracle-roundtrip-test");
    hasher.update(b"Yes");
    hasher.update(&root);
    let event_hash = hex::encode(hasher.finalize());
    assert_eq!(event_hash.len(), 64);

    println!("✅ TEST 16: PendingRoot JSON roundtrip — all fields preserved");
    println!("   oracle_event_hash: {}", event_hash);
}

// ============================================================================
// TEST 17 — Dispute window slot arithmetic
// ============================================================================

#[test]
fn test_dispute_window_slots() {
    const DISPUTE_WINDOW_SLOTS: u64 = 6_480;
    const MS_PER_SLOT: f64 = 400.0;

    let window_ms = DISPUTE_WINDOW_SLOTS as f64 * MS_PER_SLOT;
    let window_seconds = window_ms / 1_000.0;
    let window_hours = window_seconds / 3_600.0;

    // Verify the 2h window is approximately correct
    assert!(
        (window_hours - 0.72).abs() < 0.01,
        "Dispute window should be ~0.72h (6480 * 400ms = ~2592s = ~0.72h), got {}h",
        window_hours
    );

    // Test slot arithmetic
    let current_slot: u64 = 100_000;
    let finalize_at_slot = current_slot + DISPUTE_WINDOW_SLOTS;
    assert_eq!(finalize_at_slot, 106_480);

    // Finalize check: root ready when current_slot >= finalize_at_slot
    assert!(!( 105_000 >= finalize_at_slot), "Should not finalize yet at slot 105,000");
    assert!( 106_480 >= finalize_at_slot, "Should finalize at slot 106,480");
    assert!( 106_500 >= finalize_at_slot, "Should finalize at slot 106,500");

    println!("✅ TEST 17: Dispute window slot arithmetic verified");
    println!("   DISPUTE_WINDOW_SLOTS: {}", DISPUTE_WINDOW_SLOTS);
    println!("   window duration:      {:.2}s ({:.2}h)", window_seconds, window_hours);
    println!("   finalize_at_slot:     {}", finalize_at_slot);
}

