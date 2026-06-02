import type Database from "better-sqlite3";
import type { SigRow, SigState } from "./sqlite.js";

// ── Writers ───────────────────────────────────────────────────────────────────

export function insertSeen(db: Database.Database, sig: string): void {
  const now = Date.now();
  db.prepare(
    `INSERT OR IGNORE INTO signatures (sig, state, created_at, updated_at)
     VALUES (?, 'Seen', ?, ?)`
  ).run(sig, now, now);
}

export function transition(
  db: Database.Database,
  sig: string,
  state: SigState,
  fields: Partial<Omit<SigRow, "sig" | "state" | "created_at">> = {}
): void {
  const now = Date.now();
  const sets: string[] = ["state = ?", "updated_at = ?"];
  const vals: unknown[] = [state, now];

  if ("reason" in fields)        { sets.push("reason = ?");        vals.push(fields.reason ?? null); }
  if ("wallet" in fields)        { sets.push("wallet = ?");        vals.push(fields.wallet ?? null); }
  if ("asset" in fields)         { sets.push("asset = ?");         vals.push(fields.asset  ?? null); }
  if ("amount_micro" in fields)  { sets.push("amount_micro = ?");  vals.push(fields.amount_micro != null ? String(fields.amount_micro) : null); }
  if ("tx_slot" in fields)       { sets.push("tx_slot = ?");       vals.push(fields.tx_slot ?? null); }
  if ("submit_attempts" in fields){ sets.push("submit_attempts = ?"); vals.push(fields.submit_attempts ?? 0); }
  if ("next_retry_at" in fields) { sets.push("next_retry_at = ?"); vals.push(fields.next_retry_at ?? null); }

  vals.push(sig);
  db.prepare(`UPDATE signatures SET ${sets.join(", ")} WHERE sig = ?`).run(...vals);
}

export function incrementAttempts(db: Database.Database, sig: string, nextRetryAt: number): void {
  db.prepare(
    `UPDATE signatures
     SET submit_attempts = submit_attempts + 1,
         next_retry_at   = ?,
         state           = 'Retry',
         updated_at      = ?
     WHERE sig = ?`
  ).run(nextRetryAt, Date.now(), sig);
}

// ── Readers ───────────────────────────────────────────────────────────────────

export function getSig(db: Database.Database, sig: string): SigRow | null {
  return (
    db.prepare<[string], SigRow>("SELECT * FROM signatures WHERE sig = ?").get(sig) ?? null
  );
}

export function isTerminal(db: Database.Database, sig: string): boolean {
  const row = getSig(db, sig);
  if (!row) return false;
  return row.state === "Processed" || row.state === "Ignored";
}

/** All signatures not yet in a terminal state — used to block cursor advance. */
export function getPendingSigs(db: Database.Database): SigRow[] {
  return db
    .prepare<[], SigRow>(
      `SELECT * FROM signatures WHERE state NOT IN ('Processed','Ignored') ORDER BY created_at`
    )
    .all();
}

/** Items in Retry state whose backoff has elapsed — for the reconciler. */
export function getDueRetries(db: Database.Database): SigRow[] {
  return db
    .prepare<[number], SigRow>(
      `SELECT * FROM signatures WHERE state = 'Retry' AND next_retry_at <= ? ORDER BY next_retry_at`
    )
    .all(Date.now());
}

/** Submitting items older than a threshold — likely crashed mid-flight. */
export function getStaleSubmitting(db: Database.Database, olderThanMs: number): SigRow[] {
  const cutoff = Date.now() - olderThanMs;
  return db
    .prepare<[number], SigRow>(
      `SELECT * FROM signatures WHERE state = 'Submitting' AND updated_at < ? ORDER BY updated_at`
    )
    .all(cutoff);
}
