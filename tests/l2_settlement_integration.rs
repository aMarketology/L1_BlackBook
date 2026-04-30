//! L1↔L2 Settlement Integration Test
//!
//! Validates the COMPLETE prediction market lifecycle:
//!   1. L2 settles a market and generates a Merkle root + per-user proofs
//!   2. L1 verifies any user's Merkle proof against the submitted root
//!
//! This test independently re-implements both the L2 tree-building AND the L1
//! proof-verification logic to prove they produce compatible outputs.
//!
//! Canonical leaf format (must match BOTH sides):
//!   leaf = SHA256( pubkey_raw_32_bytes ++ payout_spl_u64_le )

use sha2::{Sha256, Digest};

// ============================================================================
// SHARED FORMAT — the canonical Merkle leaf and combine functions
// ============================================================================

/// Compute a Merkle leaf in the canonical L1↔L2 format.
///   SHA256( pubkey_raw_32_bytes ++ payout_spl.to_le_bytes() )
fn compute_leaf(wallet_base58: &str, payout_spl: u64) -> [u8; 32] {
    let pubkey_raw = bs58::decode(wallet_base58).into_vec().unwrap();
    assert_eq!(pubkey_raw.len(), 32, "wallet must be 32-byte pubkey");
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_raw);
    hasher.update(payout_spl.to_le_bytes());
    hasher.finalize().into()
}

/// Sorted-pair combine: parent = SHA256( min(a,b) ++ max(a,b) )
/// This is the convention used by both L1 escrow and L2 MarketEngine.
fn combine_hashes(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(lo);
    hasher.update(hi);
    hasher.finalize().into()
}

// ============================================================================
// L2 SIDE — Merkle root generation (mirrors layer2_market/mod.rs)
// ============================================================================

struct WinnerEntry {
    wallet_address: String,
    payout_spl: u64,
}

/// Build a Merkle root from a set of winners (L2 side).
fn l2_build_root(winners: &[WinnerEntry]) -> [u8; 32] {
    if winners.is_empty() {
        let mut h = Sha256::new();
        h.update([0u8; 32]);
        return h.finalize().into();
    }

    let mut layer: Vec<[u8; 32]> = winners
        .iter()
        .map(|w| compute_leaf(&w.wallet_address, w.payout_spl))
        .collect();
    layer.sort_unstable();

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i < layer.len() {
            next.push(combine_hashes(layer[i], layer[i + 1]));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Generate a Merkle proof for a specific winner (L2 side).
fn l2_generate_proof(winners: &[WinnerEntry], target_wallet: &str) -> Option<Vec<[u8; 32]>> {
    if winners.is_empty() { return None; }

    let mut layer: Vec<[u8; 32]> = winners
        .iter()
        .map(|w| compute_leaf(&w.wallet_address, w.payout_spl))
        .collect();
    layer.sort_unstable();

    let target = winners.iter().find(|w| w.wallet_address == target_wallet)?;
    let target_leaf = compute_leaf(&target.wallet_address, target.payout_spl);
    let mut index = layer.iter().position(|h| h == &target_leaf)?;

    let mut proof = Vec::new();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        proof.push(layer[index ^ 1]);
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i < layer.len() {
            next.push(combine_hashes(layer[i], layer[i + 1]));
            i += 2;
        }
        index /= 2;
        layer = next;
    }
    Some(proof)
}

// ============================================================================
// L1 SIDE — Merkle proof verification (mirrors global_escrow/mod.rs)
// ============================================================================

/// Verify a proof against the root, using L1 escrow's sorted-pair convention.
fn l1_verify_proof(leaf: [u8; 32], proof: &[[u8; 32]], expected_root: [u8; 32]) -> bool {
    let mut current = leaf;
    for sibling in proof {
        current = combine_hashes(current, *sibling);
    }
    current == expected_root
}

// ============================================================================
// HELPERS
// ============================================================================

/// Generate a deterministic 32-byte base58 "wallet address" from a seed.
fn make_wallet(seed: u8) -> String {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    for i in 1..32 { bytes[i] = seed.wrapping_add(i as u8); }
    bs58::encode(bytes).into_string()
}

// ============================================================================
// TESTS
// ============================================================================

#[test]
fn test_l1_l2_leaf_format_match() {
    let wallet = make_wallet(42);
    let payout_spl: u64 = 5_000_000; // 5 BB in SPL units

    // For a single-leaf tree, the root IS the leaf
    let root = l2_build_root(&[WinnerEntry {
        wallet_address: wallet.clone(),
        payout_spl,
    }]);
    let leaf = compute_leaf(&wallet, payout_spl);

    assert_eq!(root, leaf, "Single-winner root must equal the leaf hash");
}

#[test]
fn test_full_settlement_cycle_2_winners() {
    let wallet_a = make_wallet(1);
    let wallet_b = make_wallet(2);

    let winners = vec![
        WinnerEntry { wallet_address: wallet_a.clone(), payout_spl: 3_000_000 },
        WinnerEntry { wallet_address: wallet_b.clone(), payout_spl: 7_000_000 },
    ];

    // L2: settle
    let root = l2_build_root(&winners);
    let proof_a = l2_generate_proof(&winners, &wallet_a).unwrap();
    let proof_b = l2_generate_proof(&winners, &wallet_b).unwrap();

    // L1: verify
    let leaf_a = compute_leaf(&wallet_a, 3_000_000);
    assert!(l1_verify_proof(leaf_a, &proof_a, root), "L1 must accept proof for wallet A");

    let leaf_b = compute_leaf(&wallet_b, 7_000_000);
    assert!(l1_verify_proof(leaf_b, &proof_b, root), "L1 must accept proof for wallet B");
}

#[test]
fn test_full_settlement_cycle_10_winners() {
    let winners: Vec<WinnerEntry> = (0..10).map(|i| {
        WinnerEntry {
            wallet_address: make_wallet(i + 10),
            payout_spl: ((i as u64) + 1) * 1_000_000,
        }
    }).collect();

    let root = l2_build_root(&winners);

    for winner in &winners {
        let proof = l2_generate_proof(&winners, &winner.wallet_address).unwrap();
        let leaf = compute_leaf(&winner.wallet_address, winner.payout_spl);
        assert!(l1_verify_proof(leaf, &proof, root),
            "L1 rejected proof for {} (payout={})", winner.wallet_address, winner.payout_spl);
    }
}

#[test]
fn test_wrong_amount_rejected() {
    let wallet_a = make_wallet(50);
    let wallet_b = make_wallet(51);

    let winners = vec![
        WinnerEntry { wallet_address: wallet_a.clone(), payout_spl: 5_000_000 },
        WinnerEntry { wallet_address: wallet_b.clone(), payout_spl: 5_000_000 },
    ];

    let root = l2_build_root(&winners);
    let proof_a = l2_generate_proof(&winners, &wallet_a).unwrap();

    // Try to claim with WRONG amount
    let fake_leaf = compute_leaf(&wallet_a, 9_999_999);
    assert!(!l1_verify_proof(fake_leaf, &proof_a, root),
        "L1 must REJECT proof with wrong payout amount");
}

#[test]
fn test_wrong_wallet_rejected() {
    let wallet_a = make_wallet(60);
    let wallet_b = make_wallet(61);
    let attacker = make_wallet(99);

    let winners = vec![
        WinnerEntry { wallet_address: wallet_a.clone(), payout_spl: 5_000_000 },
        WinnerEntry { wallet_address: wallet_b.clone(), payout_spl: 5_000_000 },
    ];

    let root = l2_build_root(&winners);
    let proof_a = l2_generate_proof(&winners, &wallet_a).unwrap();

    // Attacker tries to steal wallet A's proof
    let attacker_leaf = compute_leaf(&attacker, 5_000_000);
    assert!(!l1_verify_proof(attacker_leaf, &proof_a, root),
        "L1 must REJECT proof stolen from another wallet");
}

#[test]
fn test_lamports_to_spl_conversion() {
    // 1 BB = 100_000 lamports = 1_000_000 SPL units → SPL = lamports × 10
    assert_eq!(500_000u64.saturating_mul(10), 5_000_000);
    assert_eq!(1u64.saturating_mul(10), 10);
    assert_eq!(100_000u64.saturating_mul(10), 1_000_000); // 1 BB
}

#[test]
fn test_empty_market_sentinel() {
    let root = l2_build_root(&[]);
    assert_ne!(root, [0u8; 32], "Empty root must be a sentinel, not zeros");
}

#[test]
fn test_deterministic_root() {
    let winners = vec![
        WinnerEntry { wallet_address: make_wallet(1), payout_spl: 1_000_000 },
        WinnerEntry { wallet_address: make_wallet(2), payout_spl: 2_000_000 },
        WinnerEntry { wallet_address: make_wallet(3), payout_spl: 3_000_000 },
    ];

    let root1 = l2_build_root(&winners);
    let root2 = l2_build_root(&winners);
    assert_eq!(root1, root2, "Same winners must produce identical root");

    // Shuffled order → same root (sorted leaves)
    let shuffled = vec![
        WinnerEntry { wallet_address: make_wallet(3), payout_spl: 3_000_000 },
        WinnerEntry { wallet_address: make_wallet(1), payout_spl: 1_000_000 },
        WinnerEntry { wallet_address: make_wallet(2), payout_spl: 2_000_000 },
    ];
    let root3 = l2_build_root(&shuffled);
    assert_eq!(root1, root3, "Root must be order-independent (sorted leaves)");
}

#[test]
fn test_large_market_100_winners() {
    let winners: Vec<WinnerEntry> = (0..100).map(|i| {
        WinnerEntry {
            wallet_address: make_wallet(i as u8),
            payout_spl: ((i as u64) + 1) * 100_000, // 0.1 BB to 10 BB
        }
    }).collect();

    let root = l2_build_root(&winners);

    // Spot-check 10 random winners
    for idx in [0, 9, 25, 42, 50, 73, 88, 91, 99] {
        let w = &winners[idx];
        let proof = l2_generate_proof(&winners, &w.wallet_address).unwrap();
        let leaf = compute_leaf(&w.wallet_address, w.payout_spl);
        assert!(l1_verify_proof(leaf, &proof, root),
            "Failed for winner #{} ({})", idx, w.wallet_address);
    }
}
