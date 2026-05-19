//! Expired Contest Sweep — background task
//!
//! After a contest's `claim_deadline_slot` elapses and the `house_rake` has
//! not yet been swept (`house_rake_swept_tx` is `None`), this task transfers
//! exactly `house_rake` lamports from the per-contest escrow vault PDA to the
//! house treasury PDA and marks the contest as `Expired` in ReDB.
//!
//! **Conservative by design**: only the platform cut (`house_rake`) is moved.
//! Unclaimed winner payouts remain in the vault — they are never confiscated.
//!
//! **Crash-safe**: `house_rake_swept_tx` is set and persisted to ReDB atomically
//! with the `Expired` status. On restart the task skips any contest that already
//! has `house_rake_swept_tx = Some(_)`.
//!
//! Run interval: 60 seconds (configurable via `SWEEP_INTERVAL_SECS` env var).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::{error, info, warn};

use crate::poh_blockchain::BlockProducer;
use crate::storage::{ConcurrentBlockchain, ContestState, ContestStatus};
use crate::svm::{house_treasury_pda_address, LAMPORTS_PER_BB};

/// Spawn the sweep task on the current tokio runtime.
///
/// Clones of all Arc fields are cheap — the task owns its own references for
/// its entire lifetime without blocking the caller.
pub fn spawn_sweep_task(
    blockchain: ConcurrentBlockchain,
    contest_states: Arc<dashmap::DashMap<String, ContestState>>,
    current_slot: Arc<std::sync::atomic::AtomicU64>,
    block_producer: Arc<BlockProducer>,
) {
    let interval_secs = std::env::var("SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // Discard the immediate first tick so we don't sweep before the node is
        // fully warmed up (accounts hydrated, PoH clock ticking, etc.).
        interval.tick().await;

        info!(
            interval_secs,
            "🧹 Expired-contest sweep task started"
        );

        loop {
            interval.tick().await;
            run_sweep_tick(
                &blockchain,
                &contest_states,
                &current_slot,
                &block_producer,
            )
            .await;
        }
    });
}

/// One sweep tick: scan all contests, sweep eligible ones, log a summary.
async fn run_sweep_tick(
    blockchain: &ConcurrentBlockchain,
    contest_states: &dashmap::DashMap<String, ContestState>,
    current_slot: &std::sync::atomic::AtomicU64,
    block_producer: &BlockProducer,
) {
    let slot = current_slot.load(Ordering::Relaxed);
    let treasury_addr = house_treasury_pda_address();

    // Snapshot eligible contest IDs — do NOT hold DashMap shard locks across
    // async I/O or expensive operations.
    let eligible: Vec<String> = contest_states
        .iter()
        .filter_map(|entry| {
            let c = entry.value();
            let is_expired =
                c.status == ContestStatus::Settled
                    && c.claim_deadline_slot > 0
                    && slot > c.claim_deadline_slot;
            let not_yet_swept = c.house_rake_swept_tx.is_none();
            let has_rake = c.house_rake > 0;
            if is_expired && not_yet_swept && has_rake {
                Some(c.contest_id.clone())
            } else {
                None
            }
        })
        .collect();

    if eligible.is_empty() {
        return;
    }

    let mut swept_count = 0u32;
    let mut swept_lamports_total = 0u64;

    for contest_id in &eligible {
        // Re-load from DashMap to get the freshest copy (another thread may
        // have settled it between the snapshot and now).
        let Some(contest) = contest_states.get(contest_id).map(|r| r.value().clone()) else {
            continue;
        };
        // Double-check guards inside the individual sweep (idempotent).
        if contest.house_rake_swept_tx.is_some()
            || contest.status != ContestStatus::Settled
            || slot <= contest.claim_deadline_slot
            || contest.house_rake == 0
        {
            continue;
        }

        if let Some(tx_hash) = sweep_one(
            blockchain,
            contest_states,
            &contest,
            &treasury_addr,
            block_producer,
        ) {
            swept_count += 1;
            swept_lamports_total += contest.house_rake;
            info!(
                contest_id = %contest_id,
                rake_lamports = contest.house_rake,
                tx_hash = %tx_hash,
                treasury = %treasury_addr,
                "🧹 Swept house rake"
            );
        }
    }

    if swept_count > 0 {
        let swept_bb = swept_lamports_total as f64 / LAMPORTS_PER_BB as f64;
        info!(
            swept_contests = swept_count,
            swept_bb,
            treasury = %treasury_addr,
            "🧹 Sweep tick complete"
        );
    }
}

/// Sweep house_rake from one contest vault → house treasury.
///
/// Returns `Some(tx_hash)` on success, `None` on failure (already logged).
fn sweep_one(
    blockchain: &ConcurrentBlockchain,
    contest_states: &dashmap::DashMap<String, ContestState>,
    contest: &ContestState,
    treasury_addr: &str,
    block_producer: &BlockProducer,
) -> Option<String> {
    let vault_addr = &contest.vault_pda;
    let tx_hash = uuid::Uuid::new_v4().to_string();

    // ── TRANSFER: per-contest vault PDA → house treasury PDA (u64 lamports) ──
    if let Err(e) = blockchain.debit_svm_lamports(vault_addr, contest.house_rake) {
        warn!(
            contest_id = %contest.contest_id,
            error = %e,
            "Sweep: vault debit failed — skipping"
        );
        return None;
    }
    if let Err(e) = blockchain.credit_svm_lamports(treasury_addr, contest.house_rake) {
        // Rollback the debit so funds are not lost
        if let Err(rb) = blockchain.credit_svm_lamports(vault_addr, contest.house_rake) {
            error!(
                contest_id = %contest.contest_id,
                rollback_error = %rb,
                "CRITICAL: sweep rollback failed — vault may be short of house_rake lamports"
            );
        }
        warn!(
            contest_id = %contest.contest_id,
            error = %e,
            "Sweep: treasury credit failed — rolled back"
        );
        return None;
    }

    // ── BUILD UPDATED ContestState (Expired + swept tx hash) ─────────────
    let mut updated = contest.clone();
    updated.status = ContestStatus::Expired;
    updated.house_rake_swept_tx = Some(tx_hash.clone());

    // ── PERSISTENCE GUARANTEE: ReDB FIRST, DashMap AFTER ─────────────────
    if let Err(e) = blockchain.store_contest_state(&updated) {
        // Rollback token transfer
        let _ = blockchain.debit_svm_lamports(treasury_addr, contest.house_rake);
        let _ = blockchain.credit_svm_lamports(vault_addr, contest.house_rake);
        error!(
            contest_id = %contest.contest_id,
            error = %e,
            "Sweep: ReDB persist failed — rolled back"
        );
        return None;
    }
    contest_states.insert(contest.contest_id.clone(), updated);

    // ── POH AUDIT TRAIL ───────────────────────────────────────────────────
    {
        use crate::protocol::Transaction as ProtoTx;
        use crate::protocol::TxData;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let proto_tx = ProtoTx {
            hash: tx_hash.clone(),
            from: vault_addr.to_string(),
            timestamp: now,
            data: TxData::EscrowSweep {
                contest_id: contest.contest_id.clone(),
                rake_lamports: contest.house_rake,
                treasury_address: treasury_addr.to_string(),
            },
            signature: String::new(), // system-initiated, no user sig
            signer_pubkey: String::new(),
        };
        block_producer.record_executed_transaction(proto_tx);
    }

    Some(tx_hash)
}
