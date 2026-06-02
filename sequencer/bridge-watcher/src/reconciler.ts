import type Database from "better-sqlite3";
import { getDueRetries, getStaleSubmitting, transition } from "./db/processed.js";
import { getFinalized } from "./solana/finality.js";
import { attributeTx } from "./attribution.js";
import { log } from "./logger.js";
import { inc } from "./metrics.js";
import type { SolanaRpcClient } from "./solana/rpc.js";
import type { Config } from "./config.js";

/**
 * Re-drive non-terminal signatures.
 * Called periodically (RECONCILE_INTERVAL_MS) and on startup.
 *
 * Handles two cases:
 *   1. `Retry` items whose backoff has elapsed → re-queue to `Seen`
 *   2. `Submitting` items stuck for > 2× reconcile interval → crash-recovery reset
 */
export async function reconcile(
  db: Database.Database,
  rpc: SolanaRpcClient,
  cfg: Config
): Promise<void> {
  const watchedMints = new Set(cfg.watchedMints.map((m) => m.mint));
  const mintLabels = new Map(cfg.watchedMints.map((m) => [m.mint, m.label]));

  // 1. Retry queue
  const retries = getDueRetries(db);
  for (const row of retries) {
    log.info("reconciler: re-queueing retry", { sig: row.sig, attempts: row.submit_attempts });
    transition(db, row.sig, "Seen");
    inc("reconciler_requeued");
  }

  // 2. Stale Submitting (crash recovery)
  const staleMs = cfg.reconcileIntervalMs * 2;
  const stale = getStaleSubmitting(db, staleMs);
  for (const row of stale) {
    log.warn("reconciler: stale Submitting → resetting to Seen", { sig: row.sig });
    transition(db, row.sig, "Seen");
    inc("reconciler_crash_recovered");
  }

  // 3. AwaitingFinality items — check if they've finalized now
  const awaitingRows = db
    .prepare("SELECT sig FROM signatures WHERE state = 'AwaitingFinality'")
    .all() as Array<{ sig: string }>;

  for (const { sig } of awaitingRows) {
    try {
      const tx = await getFinalized(rpc, sig);
      if (!tx) continue;

      const result = attributeTx(
        sig, tx, cfg.custodyWallet, watchedMints, mintLabels, cfg.minDepositMicro
      );

      if (result.deposit) {
        const { deposit: d } = result;
        transition(db, sig, "Parsed", {
          wallet: d.bbWallet,
          asset: d.asset,
          amount_micro: d.amountMicro,
          tx_slot: d.slot,
        });
        log.info("reconciler: AwaitingFinality → Parsed", { sig, wallet: d.bbWallet });
      } else {
        transition(db, sig, "Ignored", { reason: result.ignoreReason });
        log.info("reconciler: AwaitingFinality → Ignored", { sig, reason: result.ignoreReason });
      }
      inc("reconciler_finality_resolved");
    } catch (err) {
      log.warn("reconciler: finality check failed", { sig, err: String(err) });
    }
  }
}
