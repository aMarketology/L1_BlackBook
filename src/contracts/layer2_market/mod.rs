#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// ============================================================================
// LAYER 2 SMART CONTRACT (Prediction Market Engine)
// ============================================================================
//
// This module outlines the off-chain/Layer 2 execution logic.
// While L1 handles escrow & global state, L2 takes care of:
//   - Orderbook matching for bets
//   - High-throughput execution (10k+ TPS)
//   - Price discovery and oracle updates
//   - Final settlement calculation (which results in the Merkle Root)
//
// Token economy:
//   - $BB      — native gas token; used for bet deposits
//   - wUSDT    — stablecoin settlement; used for prize payouts
//   - $MAXX    — bonding-curve governance token; traded on L2 markets
//   - $DECAY   — NFT-style access pass; each use unlocks a premium bet slot
// ============================================================================

/// A single bet order placed by a user on the L2.
/// `bet_amount` and `odds` are stored as integer raw units (micro-units) to
/// avoid floating-point precision loss in settlement math.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BetOrder {
    pub bet_id: String,
    pub market_id: String,
    /// Raw amount in the token's smallest unit (lamports for $BB, microUSDT for wUSDT).
    pub bet_amount_raw: u64,
    pub predicted_outcome: bool,
    /// Odds expressed as a fixed-point integer: 1000 = 1.000x, 1500 = 1.500x.
    pub odds_1000x: u32,
    pub user_wallet: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MatchedBet {
    pub match_id: String,
    pub long_order: BetOrder,
    pub short_order: BetOrder,
    pub matched_amount_raw: u64,
}

/// A single winner entry used to build the settlement Merkle tree.
/// `payout_spl` is the SPL token units (6 decimals) owed to `wallet_address`.
#[derive(Debug, Clone)]
pub struct WinnerEntry {
    /// Base58-encoded 32-byte Solana pubkey
    pub wallet_address: String,
    /// Payout in SPL units (6 decimals). 1 BB = 1_000_000 SPL units.
    pub payout_spl: u64,
}

pub struct MarketEngine {
    // Current live markets and their order books
}

impl MarketEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Place a bet in the L2 Engine.
    pub fn place_bet(&mut self, _order: BetOrder) -> Result<(), String> {
        Ok(())
    }

    /// Compute a single Merkle leaf, matching the L1 escrow format EXACTLY:
    ///   SHA-256( pubkey_raw_32_bytes ++ payout_spl.to_le_bytes() )
    ///
    /// The wallet_address is decoded from base58 to raw 32 bytes, NOT hashed
    /// as a UTF-8 string. This ensures L2-generated proofs verify on L1.
    fn compute_leaf(entry: &WinnerEntry) -> [u8; 32] {
        let pubkey_raw = bs58::decode(&entry.wallet_address)
            .into_vec()
            .expect("WinnerEntry wallet_address must be valid base58");
        let mut hasher = Sha256::new();
        hasher.update(&pubkey_raw);
        hasher.update(entry.payout_spl.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Combine two child hashes into a parent hash using sorted-pair ordering.
    /// Sorting ensures the same root regardless of insertion order, matching
    /// the `merkle_proof_verify()` logic in `global_escrow/mod.rs`.
    ///
    ///   parent = SHA-256( min(left, right) ++ max(left, right) )
    fn combine_hashes(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut hasher = Sha256::new();
        hasher.update(lo);
        hasher.update(hi);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Build a sorted-pair SHA-256 binary Merkle tree over the winner set and
    /// return the 32-byte root to be submitted to L1 `global_escrow`.
    ///
    /// Algorithm:
    ///   1. Compute one leaf per winner: SHA-256(address_bytes ++ payout_le64)
    ///   2. Sort leaves lexicographically for determinism
    ///   3. Iteratively combine pairs until a single root remains
    ///   4. If the tree has an odd number of nodes at any level, duplicate the
    ///      last node (standard Bitcoin-style balancing)
    ///
    /// An empty winner set returns the SHA-256 of 32 zero bytes (a defined
    /// sentinel rather than `[0u8;32]` so callers can detect the no-winner case).
    pub fn settle_market_and_generate_root(&self, winners: &[WinnerEntry]) -> [u8; 32] {
        if winners.is_empty() {
            // Defined sentinel for "no winners" — distinguishable from an
            // uninitialised placeholder.
            let mut hasher = Sha256::new();
            hasher.update([0u8; 32]);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            return out;
        }

        // Step 1 — compute leaves
        let mut layer: Vec<[u8; 32]> = winners
            .iter()
            .map(Self::compute_leaf)
            .collect();

        // Step 2 — sort for determinism
        layer.sort_unstable();

        // Step 3 — reduce layer by layer until one root remains
        while layer.len() > 1 {
            // Duplicate last node if odd count (standard balanced Merkle)
            if layer.len() % 2 == 1 {
                let last = *layer.last().unwrap();
                layer.push(last);
            }

            let mut next_layer: Vec<[u8; 32]> = Vec::with_capacity(layer.len() / 2);
            let mut i = 0;
            while i < layer.len() {
                next_layer.push(Self::combine_hashes(layer[i], layer[i + 1]));
                i += 2;
            }
            layer = next_layer;
        }

        layer[0]
    }
}

/// Generate a Merkle proof (sibling path) for a specific winner entry.
/// Returns the ordered list of sibling hashes required by `merkle_proof_verify()`
/// on the L1 escrow contract.
pub fn generate_merkle_proof(winners: &[WinnerEntry], target_wallet: &str) -> Option<Vec<[u8; 32]>> {
    if winners.is_empty() {
        return None;
    }

    let mut layer: Vec<[u8; 32]> = winners
        .iter()
        .map(MarketEngine::compute_leaf)
        .collect();
    layer.sort_unstable();

    // Find the index of the target leaf
    let target_entry = winners.iter().find(|e| e.wallet_address == target_wallet)?;
    let target_leaf = MarketEngine::compute_leaf(target_entry);
    let mut index = layer.iter().position(|h| h == &target_leaf)?;

    let mut proof: Vec<[u8; 32]> = Vec::new();

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }

        // Sibling is at index ^ 1 (flip last bit)
        let sibling_index = index ^ 1;
        proof.push(layer[sibling_index]);

        // Move up to parent layer
        let mut next_layer: Vec<[u8; 32]> = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i < layer.len() {
            next_layer.push(MarketEngine::combine_hashes(layer[i], layer[i + 1]));
            i += 2;
        }
        index /= 2;
        layer = next_layer;
    }

    Some(proof)
}
