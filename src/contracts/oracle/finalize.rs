//! Oracle Finalize Task — Step 2 of the optimistic oracle system.
//!
//! Runs as a background tokio task every FINALIZE_POLL_SECS seconds.
//! For every pending root whose dispute window has expired:
//!
//!   - `Pending` at `current_slot >= finalize_at_slot`
//!     → write to `ESCROW_MARKET_ROOTS`, mark `Finalized`,
//!       increment oracle node track records.
//!
//!   - `Disputed` at `current_slot >= finalize_at_slot`
//!     → governance vote timed out without resolution.
//!       Mark `Discarded`, return disputer stakes (conservative default).
//!
//! Step 3 will add oracle bond slashing for `Discarded` roots.

use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

use crate::AppState;
use crate::storage::PendingRootStatus;
use crate::svm::{SplTokenEngine, maxx_mint_bytes};

/// How often the finalize loop checks for ready-to-finalize roots (seconds).
const FINALIZE_POLL_SECS: u64 = 30;

/// Spawn the finalize background task.
///
/// Call this once at startup, after `AppState` is fully initialized.
pub fn spawn_finalize_task(state: AppState) {
    tokio::spawn(async move {
        info!("🔮 Oracle finalize task started (poll every {}s)", FINALIZE_POLL_SECS);
        loop {
            tokio::time::sleep(Duration::from_secs(FINALIZE_POLL_SECS)).await;
            finalize_ready_roots(&state).await;
        }
    });
}

/// Single iteration: scan `PENDING_ROOTS`, finalize or discard expired roots.
async fn finalize_ready_roots(state: &AppState) {
    let current_slot = state.current_slot.load(Ordering::Relaxed);

    // Collect all pending roots in one pass
    let all_roots = state.blockchain.load_all_pending_roots();

    for mut root in all_roots {
        // Skip roots that are already terminal states
        if matches!(root.status, PendingRootStatus::Finalized | PendingRootStatus::Discarded) {
            continue;
        }
        // Not yet past the dispute window
        if current_slot < root.finalize_at_slot {
            continue;
        }

        match root.status {
            PendingRootStatus::Pending => {
                // ── Finalize: no disputes reached escalation threshold ────────
                info!("✅ Oracle finalize: market={} outcome={} slot={}",
                    root.market_id, root.outcome, current_slot);

                // Write to ESCROW_MARKET_ROOTS (so users can claim via /escrow/withdraw)
                if let Err(e) = state.blockchain.store_escrow_market_root(
                    &root.market_id, &root.merkle_root
                ) {
                    warn!("Oracle finalize: failed to store market root for {}: {}", root.market_id, e);
                    continue;
                }

                // Update oracle node track records
                for sig in &root.oracle_signatures {
                    if let Some(mut node) = state.blockchain.load_oracle_node(&sig.pubkey_hex) {
                        node.total_resolutions += 1;
                        node.correct_resolutions += 1;
                        if let Err(e) = state.blockchain.store_oracle_node(&node) {
                            warn!("Oracle finalize: failed to update node track record {}: {}", sig.pubkey_hex, e);
                        }
                    }
                }

                // ── PERSISTENCE GUARANTEE: ReDB FIRST, cache AFTER ───────────
                // Mark the root Finalized in ReDB before touching any DashMap cache.
                // If this write fails, we leave status = Pending in ReDB so the next
                // finalize tick will retry naturally — cache is never mutated on error.
                root.status = PendingRootStatus::Finalized;
                if let Err(e) = state.blockchain.store_pending_root(&root) {
                    warn!("Oracle finalize: failed to persist Finalized status for {} — will retry next tick: {}", root.market_id, e);
                    continue;
                }

                // Persist ContestState update to ReDB before cache (same guarantee).
                if let Ok(Some(mut contest)) = state.blockchain.load_contest_state(&root.market_id) {
                    contest.merkle_root = root.merkle_root;
                    contest.status = crate::storage::ContestStatus::Settled;
                    if let Err(e) = state.blockchain.store_contest_state(&contest) {
                        warn!("Oracle finalize: failed to persist contest state for {} — cache not updated: {}", root.market_id, e);
                        // Don't continue — market root + Finalized status already persisted above.
                        // Cache update is best-effort here; will resync on next node boot from ReDB.
                    } else {
                        state.contest_states.insert(root.market_id.clone(), contest);
                    }
                }

                // ── UPDATE CACHE only after all durable writes succeeded ──────
                state.market_roots.insert(root.market_id.clone(), root.merkle_root);
                info!("📋 Oracle finalize: ReDB-first writes complete for market={}", root.market_id);
            }

            PendingRootStatus::Disputed => {
                // ── Disputed root expired without governance resolution → Discard ──
                warn!("⚠️  Oracle discard (timeout): market={} slot={}",
                    root.market_id, current_slot);

                // Return disputer stakes (best-effort, no slash in Step 2)
                let svm = &state.blockchain.svm_accounts;
                let maxx_mint = maxx_mint_bytes();
                let pool_addr = format!("oracle_dispute_pool_{}", root.market_id);
                let pool_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&pool_addr);
                for d in &root.disputers {
                    let d_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&d.wallet);
                    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &maxx_mint, &pool_pk, &d_pk, d.stake_pico_xx) {
                        warn!("Oracle discard: failed to return stake to {}: {}", d.wallet, e);
                    }
                }

                root.status = PendingRootStatus::Discarded;
                if let Err(e) = state.blockchain.store_pending_root(&root) {
                    warn!("Oracle discard: failed to persist Discarded status for {}: {}", root.market_id, e);
                }
            }

            // Already terminal — filtered above, but Rust requires exhaustive match
            PendingRootStatus::Finalized | PendingRootStatus::Discarded => {}
        }
    }
}
