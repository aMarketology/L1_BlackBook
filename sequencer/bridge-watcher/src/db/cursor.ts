import type Database from "better-sqlite3";

/** Returns the last successfully processed Solana signature, or null if none. */
export function getCursor(db: Database.Database): string | null {
  const row = db
    .prepare<[], { last_signature: string | null }>(
      "SELECT last_signature FROM cursor WHERE id = 1"
    )
    .get();
  return row?.last_signature ?? null;
}

/**
 * Advance the durable cursor to `sig`.
 * Only call this after the signature is in a terminal state (Processed or Ignored).
 */
export function advanceCursor(db: Database.Database, sig: string): void {
  const now = Date.now();
  db.prepare(
    `INSERT INTO cursor (id, last_signature, updated_at)
     VALUES (1, ?, ?)
     ON CONFLICT(id) DO UPDATE SET last_signature = excluded.last_signature,
                                   updated_at     = excluded.updated_at`
  ).run(sig, now);
}
