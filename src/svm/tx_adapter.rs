// ============================================================================
// BLACKBOOK SVM — LEGACY TX ADAPTER
// ============================================================================
//
// Converts the existing `protocol::TxData` enum into SVM-native structures
// so that the legacy REST endpoints can route through the SVM without
// being rewritten.
//
// PHASE 1: Only `TxData::TransferBb` is mapped to SVM path.
// All vault operations (DepositUsdt, RedeemBbForUsdt, LockBbForDime) continue
// on the legacy path until Anchor programs exist (Phase 4).
//
// CONVERSION RULES
// ────────────────
//   TxData::TransferBb { to, amount }
//       → TransferRequest { from, to, lamports: amount * LAMPORTS_PER_BB }
//       INVARIANT: `amount` is the legacy f64 dollar amount. We convert ONCE
//       here to lamports (u64) and never use f64 again in the execution path.
//       Rounding: floor (truncate) — the sender never sends more than intended.
//
// ============================================================================

#[cfg(feature = "svm")]
use solana_sdk::{hash::Hash, pubkey::Pubkey};

use crate::svm::types::{SvmError, LAMPORTS_PER_BB};

#[cfg(feature = "svm")]
use crate::svm::runtime::TransferRequest;

// ============================================================================
// EXECUTION PATH ENUM — tells BlockProducer where to route the tx
// ============================================================================

/// Routing decision for a single `protocol::Transaction`.
///
/// The block producer inspects this and sends work to the right path.
pub enum TxRoute {
    /// Hand to SVM (Phase 1: transfers only).
    #[cfg(feature = "svm")]
    Svm(TransferRequest),

    /// Keep on the legacy path (vault ops, DIME, etc.)
    Legacy,

    /// Drop — invalid or unsupported in current phase.
    Reject(String),
}

// ============================================================================
// ADAPTER FUNCTION
// ============================================================================

/// Convert a legacy `protocol::Transaction` into a routing decision.
///
/// The `from_address` comes from the transaction's `from` field (already
/// validated by the REST layer). The `recent_blockhash` comes from the
/// current slot's PoH hash.
///
/// Returns:
///   - `TxRoute::Svm(_)` if the tx can execute through the SVM.
///   - `TxRoute::Legacy` if the tx must use the existing execution path.
///   - `TxRoute::Reject(_)` if the tx is structurally invalid.
#[cfg(feature = "svm")]
pub fn route_transaction(
    tx_id: &str,
    from_pubkey: &Pubkey,
    tx_data_json: &serde_json::Value,
    recent_blockhash: Hash,
) -> TxRoute {
    // Inspect the tx_type field to determine routing
    let tx_type = match tx_data_json.get("type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return TxRoute::Reject("missing tx.type field".into()),
    };

    match tx_type {
        "transfer_bb" | "transfer" => {
            let to_str = match tx_data_json.get("to").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => return TxRoute::Reject("missing transfer.to".into()),
            };

            // Parse recipient pubkey
            let to_pubkey = match to_str.parse::<Pubkey>() {
                Ok(p) => p,
                Err(_) => {
                    // Fall back: treat address as a raw hex string
                    match hex_to_pubkey(to_str) {
                        Ok(p) => p,
                        Err(e) => return TxRoute::Reject(e),
                    }
                }
            };

            // Amount — the ONLY place f64 is converted to lamports.
            // After this point, only lamports (u64) are used.
            let amount_bb = match tx_data_json.get("amount").and_then(|v| v.as_f64()) {
                Some(a) => a,
                None => return TxRoute::Reject("missing transfer.amount".into()),
            };

            if amount_bb <= 0.0 {
                return TxRoute::Reject(format!("invalid amount: {}", amount_bb));
            }

            // Floor-truncate: sender never sends more than intended.
            // E.g. 1.5 BB → 1_500_000_000 lamports
            let lamports = (amount_bb * LAMPORTS_PER_BB as f64) as u64;

            if lamports == 0 {
                return TxRoute::Reject("amount too small to represent in lamports".into());
            }

            TxRoute::Svm(TransferRequest {
                tx_id: tx_id.to_string(),
                from: *from_pubkey,
                to: to_pubkey,
                lamports,
                recent_blockhash,
            })
        }

        // Vault operations: legacy path until Anchor (Phase 4)
        "deposit_usdt" | "redeem_bb_for_usdt" | "lock_bb_for_dime" | "mint" | "burn" => {
            TxRoute::Legacy
        }

        other => TxRoute::Reject(format!("unknown tx type: {}", other)),
    }
}

/// Parse a 64-character hex string into a Pubkey.
#[cfg(feature = "svm")]
fn hex_to_pubkey(s: &str) -> Result<Pubkey, String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Pubkey::new_from_array(arr))
}

// ============================================================================
// LAMPORT CONVERSION UTILITIES  (display only — never use in arithmetic)
// ============================================================================

/// Convert BB (display f64) → lamports (u64).
/// Clamps to u64::MAX on overflow rather than wrapping.
/// Use this ONCE at the API boundary; after conversion always work in lamports.
pub fn bb_to_lamports(bb: f64) -> u64 {
    if bb < 0.0 { return 0; }
    let raw = bb * LAMPORTS_PER_BB as f64;
    if raw > u64::MAX as f64 { return u64::MAX; }
    raw as u64
}

/// Convert lamports (u64) → BB (display f64).
/// DISPLAY ONLY. Never use the result in arithmetic.
pub fn lamports_to_bb(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_BB as f64
}
