/**
 * BlackBook Bridge Watcher
 * ========================
 * Observes the custody wallet on Solana for finalized USDC/USDT deposits,
 * attributes them to BB wallets via memo, and drives the L1 mint sequence.
 *
 * State machine per signature:
 *   Seen → AwaitingFinality → Parsed → Submitting → Processed
 *                                   └→ Ignored
 *                                              └→ Retry → Submitting → …
 *
 * Replay protection:  L1 PROCESSED_BRIDGE_TXS seal (at-most-once mint).
 * Cursor invariant:   only advances past terminal states (Processed | Ignored).
 * Crash safety:       on restart, non-terminal sigs are re-scanned; 409 = no-op.
 */

import { loadConfig }          from "./config.js";
import { log, setLogLevel }    from "./logger.js";
import { openDb }              from "./db/sqlite.js";
import { getCursor, advanceCursor } from "./db/cursor.js";
import {
  insertSeen, transition, incrementAttempts,
  getPendingSigs, getSig,
} from "./db/processed.js";
import { SolanaRpcClient }     from "./solana/rpc.js";
import { fetchNewSignatures }  from "./solana/poller.js";
import { getFinalized }        from "./solana/finality.js";
import { attributeTx }         from "./attribution.js";
import { L1Client }            from "./l1/client.js";
import { reconcile }           from "./reconciler.js";
import { startServer }         from "./server.js";
import { inc, gauge }          from "./metrics.js";

// ── Boot ─────────────────────────────────────────────────────────────────────

const cfg = loadConfig();
setLogLevel(cfg.logLevel);

log.info("bridge-watcher starting", {
  custodyWallet: cfg.custodyWallet,
  l1Url: cfg.l1Url,
  solanaRpc: cfg.solanaRpcUrl.replace(/api-key=\S+/, "api-key=[REDACTED]"),
  pollIntervalMs: cfg.pollIntervalMs,
  minDepositMicro: cfg.minDepositMicro.toString(),
});

const db  = openDb(cfg.dbPath);
const rpc = new SolanaRpcClient({
  primaryUrl:  cfg.solanaRpcUrl,
  fallbackUrl: cfg.solanaRpcFallbackUrl,
  timeoutMs:   cfg.l1TimeoutMs,
});
const l1 = new L1Client(cfg.l1Url, cfg.l1TimeoutMs);

const watchedMints = new Set(cfg.watchedMints.map((m) => m.mint));
const mintLabels   = new Map(cfg.watchedMints.map((m) => [m.mint, m.label]));

startServer(cfg.port);

// ── Helpers ───────────────────────────────────────────────────────────────────

function backoffMs(attempts: number, maxMs: number): number {
  return Math.min(2 ** attempts * 1_000, maxMs);
}

/** Drive a single parsed deposit through to Processed or Retry. */
async function submitDeposit(sig: string): Promise<void> {
  const row = getSig(db, sig);
  if (!row || row.state !== "Parsed") return;

  transition(db, sig, "Submitting");

  // M2: The deposit was user-originated (POST /deposit/request already submitted).
  // The watcher polls until L1 confirms it's minted.
  try {
    const resp = await l1.pollDepositStatus(sig, {
      pollMs: 3_000,
      maxAttempts: 10,
    });

    if (resp.status === "approved") {
      transition(db, sig, "Processed");
      log.info("deposit processed", { sig, bb: resp.minted_bb, balance: resp.new_balance });
      inc("deposits_processed");
    } else if (resp.status === "not_found") {
      // User hasn't submitted a /deposit/request yet — leave Parsed, retry later
      log.warn("deposit not_found on L1 (user hasn't submitted request yet)", { sig });
      incrementAttempts(db, sig, Date.now() + backoffMs(row.submit_attempts + 1, cfg.maxBackoffMs));
      inc("deposits_awaiting_user_request");
    } else {
      // rejected or unknown
      transition(db, sig, "Ignored", { reason: `l1_rejected:${resp.status}` });
      log.warn("deposit rejected by L1", { sig, status: resp.status });
      inc("deposits_rejected");
    }
  } catch (err) {
    log.warn("deposit submit failed, scheduling retry", { sig, err: String(err) });
    incrementAttempts(db, sig, Date.now() + backoffMs(row.submit_attempts + 1, cfg.maxBackoffMs));
    inc("deposits_retried");
  }
}

// ── Main poll loop ────────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  const cursor = getCursor(db);
  log.debug("poll cycle", { cursor: cursor?.slice(0, 8) ?? "null" });

  let newSigs: Awaited<ReturnType<typeof fetchNewSignatures>>;
  try {
    newSigs = await fetchNewSignatures(rpc, cfg.custodyWallet, cursor, cfg.pollPageSize);
  } catch (err) {
    log.warn("getSignaturesForAddress failed", { err: String(err) });
    inc("poll_rpc_errors");
    return;
  }

  inc("poll_cycles");
  gauge("signatures_observed", newSigs.length);

  for (const sigInfo of newSigs) {
    const sig = sigInfo.signature;
    const existing = getSig(db, sig);

    if (existing && (existing.state === "Processed" || existing.state === "Ignored")) {
      advanceCursor(db, sig);
      continue;
    }
    if (!existing) {
      insertSeen(db, sig);
    }

    // Fetch finalized tx
    let tx;
    try {
      tx = await getFinalized(rpc, sig);
    } catch (err) {
      log.warn("getTransaction failed", { sig: sig.slice(0, 8), err: String(err) });
      inc("poll_rpc_errors");
      continue;
    }

    if (!tx) {
      // Not finalized yet — leave as AwaitingFinality, cursor does NOT advance
      transition(db, sig, "AwaitingFinality");
      log.debug("awaiting finality", { sig: sig.slice(0, 8) });
      continue;
    }

    // Attribute
    const result = attributeTx(sig, tx, cfg.custodyWallet, watchedMints, mintLabels, cfg.minDepositMicro);

    if (!result.deposit) {
      transition(db, sig, "Ignored", { reason: result.ignoreReason });
      log.debug("ignored", { sig: sig.slice(0, 8), reason: result.ignoreReason });
      inc("deposits_ignored");
      advanceCursor(db, sig);
      continue;
    }

    const { deposit: d } = result;
    transition(db, sig, "Parsed", {
      wallet: d.bbWallet,
      asset: d.asset,
      amount_micro: d.amountMicro,
      tx_slot: d.slot,
    });
    log.info("deposit parsed", {
      sig: sig.slice(0, 8),
      wallet: d.bbWallet,
      asset: d.asset,
      amount: d.amountMicro.toString(),
    });
    inc("deposits_parsed");

    await submitDeposit(sig);

    // Only advance cursor once in terminal state
    const finalRow = getSig(db, sig);
    if (finalRow?.state === "Processed" || finalRow?.state === "Ignored") {
      advanceCursor(db, sig);
    }
  }

  // Emit pending count gauge
  gauge("deposits_pending", getPendingSigs(db).length);
}

// ── Reconciler loop ───────────────────────────────────────────────────────────

async function runReconciler(): Promise<void> {
  try {
    await reconcile(db, rpc, cfg);
  } catch (err) {
    log.error("reconciler error", { err: String(err) });
  }
  setTimeout(runReconciler, cfg.reconcileIntervalMs);
}

// ── Ticker ────────────────────────────────────────────────────────────────────

async function runPoll(): Promise<void> {
  try {
    await poll();
  } catch (err) {
    log.error("poll loop error", { err: String(err) });
    inc("poll_errors");
  }
  setTimeout(runPoll, cfg.pollIntervalMs);
}

// ── Start ─────────────────────────────────────────────────────────────────────

// Verify L1 is reachable before starting
const l1Healthy = await l1.isL1Healthy();
if (!l1Healthy) {
  log.warn("L1 node is not reachable at startup — watcher will retry on first poll");
}

runReconciler();
runPoll();

log.info("bridge-watcher running", {
  port: cfg.port,
  db: cfg.dbPath,
  assets: cfg.watchedMints.map((m) => m.label).join(", "),
});
