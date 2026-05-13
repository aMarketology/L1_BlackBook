// ============================================================================
// BLACKBOOK SVM — PROGRAM-DERIVED ADDRESSES (PDAs)
// ============================================================================
//
// Unlike Solana mainnet PDAs, these addresses have NO private key in existence.
// There is no find_program_address bump because there is no BPF program_id.
// Each address is simply SHA-256(domain_separated_seed) — a preimage that
// cannot sign Ed25519 transactions because no one possesses the scalar.
//
// SECURITY PROPERTY:
//   - No private key → no one can sign transactions from these addresses
//   - Only the specific Rust handler that owns the seed can credit/debit them
//   - Even if the dealer key is leaked, attacker cannot touch PDA-held funds
//   - Structurally stronger than Solana mainnet PDAs (no upgrade authority risk)
//
// AUTHORITY MODEL:
//   swap_pool_pda()      → wUSDT mint authority + BB/wUSDT swap liquidity pool
//   maxx_curve_pda()     → MAXX ($XX) mint authority + bonding curve reserve
//   escrow_vault_pda()   → Global L2 prediction market collateral vault
//   decay_treasury_pda() → $DECAY recharge treasury
//
// ============================================================================

use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

// ─────────────────────────────────────────────────────────────────────────────
// SEED CONSTANTS — versioned for future migrations
// ─────────────────────────────────────────────────────────────────────────────

/// Owns the wUSDT liquidity pool and is the wUSDT mint authority.
pub const SWAP_POOL_SEED: &[u8] = b"bb_swap_pool_v1";

/// Owns the $XX (MAXX) bonding curve reserve and is the MAXX mint authority.
pub const MAXX_CURVE_SEED: &[u8] = b"bb_maxx_curve_v1";

/// Owns the global L2 escrow vault (prediction market settlement collateral).
///
/// **Deprecated for new deposits** — kept so existing testnet funds remain reachable.
/// New flows MUST use [`escrow_vault_pda_for`] (per-contest PDA) for fund isolation.
pub const ESCROW_VAULT_SEED: &[u8] = b"bb_escrow_vault_v1";

/// Per-contest L2 escrow vault seed (v2). Combined with `:{contest_id}` to derive
/// a unique vault PDA per market — each contest's funds are cryptographically
/// isolated from every other contest's.
pub const ESCROW_VAULT_CONTEST_SEED: &[u8] = b"bb_escrow_vault_v2";

/// Per-contest state PDA seed. Combined with `:{contest_id}` to derive the
/// `ContestState` account address (root, totals, status, claim deadline).
pub const CONTEST_STATE_SEED: &[u8] = b"bb_contest_state_v1";

/// Owns the $DECAY recharge treasury.
pub const DECAY_TREASURY_SEED: &[u8] = b"bb_decay_treasury_v1";

/// Owns the house / platform rake treasury.
/// Receives expired contest house_rake sweeps after the 30-day claim window.
/// Separate from $DECAY treasury for clean on-chain accounting.
pub const HOUSE_TREASURY_SEED: &[u8] = b"bb_house_treasury_v1";

// ─────────────────────────────────────────────────────────────────────────────
// DERIVATION
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministically derive a 32-byte address from a seed.
///
/// Uses SHA-256(seed). The resulting 32-byte array is mathematically guaranteed
/// not to correspond to any Ed25519 private key — there is no preimage that
/// produces a signing scalar for this point.
///
/// This function is `#[inline]` and allocation-free.
#[inline]
pub fn derive_pda(seed: &[u8]) -> [u8; 32] {
    Sha256::digest(seed).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBKEY ACCESSORS
// ─────────────────────────────────────────────────────────────────────────────

/// PDA that owns the wUSDT swap pool liquidity and has wUSDT mint authority.
/// The only code path that can move funds from this address is the swap handler.
#[inline]
pub fn swap_pool_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(SWAP_POOL_SEED))
}

/// PDA that owns the $MAXX bonding curve reserve and has MAXX mint authority.
/// The only code path that can mint MAXX is the bonding curve buy handler.
#[inline]
pub fn maxx_curve_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(MAXX_CURVE_SEED))
}

/// PDA that owns the global L2 escrow vault (user collateral for L2 markets).
///
/// **Deprecated:** prefer [`escrow_vault_pda_for`] for new flows. This global
/// vault is retained only so historical testnet balances remain addressable.
#[deprecated(note = "Use escrow_vault_pda_for(contest_id) for per-contest fund isolation")]
#[inline]
pub fn escrow_vault_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(ESCROW_VAULT_SEED))
}

/// Per-contest escrow vault PDA. The address is `Pubkey(SHA256(seed ++ b":" ++ contest_id))`.
///
/// Each contest gets its own untouchable vault — no cross-contest fund access
/// is possible, even from a buggy handler. The only code path that can move
/// funds out of the vault is the per-contest withdraw / sweep handler.
#[inline]
pub fn escrow_vault_pda_for(contest_id: &str) -> Pubkey {
    let mut hasher = Sha256::new();
    hasher.update(ESCROW_VAULT_CONTEST_SEED);
    hasher.update(b":");
    hasher.update(contest_id.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    Pubkey::new_from_array(bytes)
}

/// Per-contest `ContestState` PDA. Used as a logical address for the contest's
/// state account (root, totals, status, claim deadline). Distinct from the
/// vault PDA so a vault-balance read can never collide with a state-account read.
#[inline]
pub fn contest_state_pda(contest_id: &str) -> Pubkey {
    let mut hasher = Sha256::new();
    hasher.update(CONTEST_STATE_SEED);
    hasher.update(b":");
    hasher.update(contest_id.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    Pubkey::new_from_array(bytes)
}

/// PDA that owns the $DECAY recharge treasury.
#[inline]
pub fn decay_treasury_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(DECAY_TREASURY_SEED))
}

/// PDA that owns the house / platform rake treasury.
/// Receives expired contest house_rake after the claim window closes.
#[inline]
pub fn house_treasury_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(HOUSE_TREASURY_SEED))
}

// ─────────────────────────────────────────────────────────────────────────────
// BASE58 STRING ADDRESSES — for HTTP responses, logs, and account lookups
// ─────────────────────────────────────────────────────────────────────────────

/// Base58 string address of the swap pool PDA.
pub fn swap_pool_address() -> String {
    bs58::encode(swap_pool_pda().to_bytes()).into_string()
}

/// Base58 string address of the MAXX bonding curve PDA.
pub fn maxx_curve_address() -> String {
    bs58::encode(maxx_curve_pda().to_bytes()).into_string()
}

/// Base58 string address of the escrow vault PDA (legacy global).
#[deprecated(note = "Use escrow_vault_address_for(contest_id) for per-contest fund isolation")]
pub fn escrow_vault_address() -> String {
    #[allow(deprecated)]
    bs58::encode(escrow_vault_pda().to_bytes()).into_string()
}

/// Base58 string address of the per-contest escrow vault PDA.
pub fn escrow_vault_address_for(contest_id: &str) -> String {
    bs58::encode(escrow_vault_pda_for(contest_id).to_bytes()).into_string()
}

/// Base58 string address of the per-contest `ContestState` PDA.
pub fn contest_state_pda_address(contest_id: &str) -> String {
    bs58::encode(contest_state_pda(contest_id).to_bytes()).into_string()
}

/// Base58 string address of the DECAY treasury PDA.
pub fn decay_treasury_pda_address() -> String {
    bs58::encode(decay_treasury_pda().to_bytes()).into_string()
}

/// Base58 string address of the house treasury PDA.
pub fn house_treasury_pda_address() -> String {
    bs58::encode(house_treasury_pda().to_bytes()).into_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn swap_pool_pda_matches_sha256_of_seed() {
        let expected_bytes: [u8; 32] = Sha256::digest(b"bb_swap_pool_v1").into();
        let expected_pubkey = Pubkey::new_from_array(expected_bytes);
        assert_eq!(
            swap_pool_pda(),
            expected_pubkey,
            "swap_pool_pda() must equal Pubkey(SHA256(bb_swap_pool_v1))"
        );
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        assert_eq!(swap_pool_pda(), swap_pool_pda());
        assert_eq!(maxx_curve_pda(), maxx_curve_pda());
        assert_eq!(escrow_vault_pda(), escrow_vault_pda());
        assert_eq!(decay_treasury_pda(), decay_treasury_pda());
        assert_eq!(house_treasury_pda(), house_treasury_pda());
    }

    #[test]
    fn all_pdas_are_distinct() {
        let pdas = [
            swap_pool_pda(),
            maxx_curve_pda(),
            escrow_vault_pda(),
            decay_treasury_pda(),
        ];
        for i in 0..pdas.len() {
            for j in (i + 1)..pdas.len() {
                assert_ne!(
                    pdas[i], pdas[j],
                    "PDA collision between index {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn pda_address_strings_are_valid_base58() {
        // Each address string must round-trip through bs58 decode back to the same bytes
        let addr = swap_pool_address();
        let decoded = bs58::decode(&addr).into_vec().expect("must be valid base58");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), swap_pool_pda().to_bytes().as_slice());
    }

    // ── Per-contest PDA tests ───────────────────────────────────────────────

    #[test]
    fn per_contest_vault_is_deterministic() {
        assert_eq!(escrow_vault_pda_for("market_42"), escrow_vault_pda_for("market_42"));
        assert_eq!(contest_state_pda("market_42"), contest_state_pda("market_42"));
    }

    #[test]
    fn distinct_contest_ids_yield_distinct_pdas() {
        assert_ne!(escrow_vault_pda_for("a"), escrow_vault_pda_for("b"));
        assert_ne!(escrow_vault_pda_for(""), escrow_vault_pda_for("a"));
        assert_ne!(contest_state_pda("a"), contest_state_pda("b"));
    }

    #[test]
    fn per_contest_vault_does_not_collide_with_global_pdas() {
        let v = escrow_vault_pda_for("anything");
        assert_ne!(v, swap_pool_pda());
        assert_ne!(v, maxx_curve_pda());
        assert_ne!(v, decay_treasury_pda());
        assert_ne!(v, escrow_vault_pda(), "v2 per-contest must not collide with v1 global");
    }

    #[test]
    fn contest_state_pda_distinct_from_vault_pda_for_same_contest() {
        let id = "same_contest_id";
        assert_ne!(
            escrow_vault_pda_for(id),
            contest_state_pda(id),
            "vault and state PDAs for the same contest must be distinct"
        );
    }

    #[test]
    fn per_contest_address_strings_are_valid_base58() {
        let id = "test_market_xyz";
        let vault_addr = escrow_vault_address_for(id);
        let state_addr = contest_state_pda_address(id);
        let vault_decoded = bs58::decode(&vault_addr).into_vec().expect("vault base58");
        let state_decoded = bs58::decode(&state_addr).into_vec().expect("state base58");
        assert_eq!(vault_decoded.len(), 32);
        assert_eq!(state_decoded.len(), 32);
        assert_eq!(vault_decoded.as_slice(), escrow_vault_pda_for(id).to_bytes().as_slice());
        assert_eq!(state_decoded.as_slice(), contest_state_pda(id).to_bytes().as_slice());
    }
}
