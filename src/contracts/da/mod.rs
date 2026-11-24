// ============================================================================
// DATA AVAILABILITY (DA) READ LAYER — L1 endpoints
// ============================================================================
//
// BlackBook L1 exposes read-only inspection endpoints for Oracle-finalized
// market roots and rollup vault liquidity pools:
//
//   GET  /da/:market_id
//     Returns the Oracle-finalized state root + status for a market.
//
//   GET  /da/:rollup_id/pool
//     Returns the rollup vault PDA $BB balance (1:1 locked real $BB backing).
//
// All fund locking and winner withdrawals go exclusively through the atomic
// rollup vault endpoints (`/rollup/:rollup_id/lock_bb`, `/submit_root`, `/exit`).
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::AppState;
use crate::svm::pda::rollup_vault_address;

// ─────────────────────────────────────────────────────────────────────────────
//  GET /da/:market_id  — Oracle-finalized state for a market
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_da_market_handler(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    use crate::storage::PendingRootStatus;

    if market_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "market_id is required" })),
        );
    }

    if let Some(root) = state.blockchain.load_pending_root(&market_id) {
        let status_str = match &root.status {
            PendingRootStatus::Pending => "Pending",
            PendingRootStatus::Disputed => "Disputed",
            PendingRootStatus::Finalized => "Finalized",
            PendingRootStatus::Discarded => "Discarded",
        };
        let claimable = matches!(root.status, PendingRootStatus::Finalized);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "market_id": market_id,
                "rollup_id": root.rollup_id,
                "status": status_str,
                "claimable": claimable,
                "merkle_root_hex": hex::encode(root.merkle_root),
                "outcome": root.outcome,
                "batch_id": root.batch_id,
                "proposed_at_slot": root.proposed_at_slot,
                "finalize_at_slot": root.finalize_at_slot,
                "dispute_window_slots": root.finalize_at_slot.saturating_sub(root.proposed_at_slot),
                "proposer_pubkey": root.proposer_pubkey,
                "note": "Settlement withdrawals execute via POST /rollup/L2/exit against cumulative rollup state roots."
            })),
        );
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "market_id": market_id,
            "status": "Unknown",
            "claimable": false,
        })),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /da/:rollup_id/pool  — Rollup vault balance (1:1 locked $BB on L1)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_da_pool_handler(
    State(state): State<AppState>,
    Path(rollup_id): Path<String>,
) -> impl IntoResponse {
    use crate::svm::types::LAMPORTS_PER_BB;

    let vault_address = rollup_vault_address(&rollup_id);
    let lamports = state.blockchain.get_balance_lamports(&vault_address);
    let bb = lamports as f64 / LAMPORTS_PER_BB as f64;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "rollup_id": rollup_id,
            "vault_address": vault_address,
            "balance_lamports": lamports,
            "balance_bb": bb,
        })),
    )
}
