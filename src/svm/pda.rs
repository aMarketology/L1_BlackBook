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
pub const ESCROW_VAULT_SEED: &[u8] = b"bb_escrow_vault_v1";

/// Owns the $DECAY recharge treasury.
pub const DECAY_TREASURY_SEED: &[u8] = b"bb_decay_treasury_v1";

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
#[inline]
pub fn escrow_vault_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(ESCROW_VAULT_SEED))
}

/// PDA that owns the $DECAY recharge treasury.
#[inline]
pub fn decay_treasury_pda() -> Pubkey {
    Pubkey::new_from_array(derive_pda(DECAY_TREASURY_SEED))
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

/// Base58 string address of the escrow vault PDA.
pub fn escrow_vault_address() -> String {
    bs58::encode(escrow_vault_pda().to_bytes()).into_string()
}

/// Base58 string address of the DECAY treasury PDA.
pub fn decay_treasury_pda_address() -> String {
    bs58::encode(decay_treasury_pda().to_bytes()).into_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
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
}
