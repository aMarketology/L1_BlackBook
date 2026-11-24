//! Oracle Finalize Task — Step 2 of the optimistic oracle system.
//!
//! Runs as a background tokio task every FINALIZE_POLL_SECS seconds.
//! For every pending root whose dispute window has expired:
//!
//!   - `Pending` at `current_slot >= finalize_at_slot`
//!     → mark `Finalized`, increment oracle node track records.
//!
//!   - `Disputed` at `current_slot >= finalize_at_slot`
//!     → governance vote timed out without resolution.
//!       Mark `Discarded`, return disputer stakes (conservative default).

use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

use crate::AppState;
use crate::storage::PendingRootStatus;

/// How often the finalize loop checks for ready-to-finalize roots (seconds).
const FINALIZE_POLL_SECS: u64 = 30;

/// Spawn the finalize background task.
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
    let all_roots = state.blockchain.load_all_pending_roots();

    for mut root in all_roots {
        if matches!(root.status, PendingRootStatus::Finalized | PendingRootStatus::Discarded) {
            continue;
        }
        if current_slot < root.finalize_at_slot {
            continue;
        }

        match root.status {
            PendingRootStatus::Pending => {
                info!("✅ Oracle finalize: market={} outcome={} slot={}",
                    root.market_id, root.outcome, current_slot);

                for sig in &root.oracle_signatures {
                    if let Some(mut node) = state.blockchain.load_oracle_node(&sig.pubkey_hex) {
                        node.total_resolutions += 1;
                        node.correct_resolutions += 1;
                        if let Err(e) = state.blockchain.store_oracle_node(&node) {
                            warn!("Oracle finalize: failed to update node track record {}: {}", sig.pubkey_hex, e);
                        }
                    }
                }

                root.status = PendingRootStatus::Finalized;
                if let Err(e) = state.blockchain.store_pending_root(&root) {
                    warn!("Oracle finalize: failed to persist Finalized status for {} — will retry next tick: {}", root.market_id, e);
                    continue;
                }
                info!("📋 Oracle finalize: ReDB writes complete for market={}", root.market_id);
            }

            PendingRootStatus::Disputed => {
                warn!("⚠️  Oracle discard (timeout): market={} slot={}",
                    root.market_id, current_slot);

                let pool_addr = format!("oracle_dispute_pool_{}", root.market_id);
                for d in &root.disputers {
                    let _ = state.blockchain.debit_svm_lamports(&pool_addr, d.stake_bb_lamports);
                    if let Err(e) = state.blockchain.credit_svm_lamports(&d.wallet, d.stake_bb_lamports) {
                        warn!("Oracle discard: failed to return BB stake to {}: {}", d.wallet, e);
                    }
                }

                root.status = PendingRootStatus::Discarded;
                if let Err(e) = state.blockchain.store_pending_root(&root) {
                    warn!("Oracle discard: failed to persist Discarded status for {}: {}", root.market_id, e);
                }
            }

            PendingRootStatus::Finalized | PendingRootStatus::Discarded => {}
        }
    }
}
