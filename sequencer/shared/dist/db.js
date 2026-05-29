import { DatabaseSync } from 'node:sqlite';
/**
 * Thin wrapper over Node's built-in `node:sqlite` (`DatabaseSync`) that
 * preserves the small slice of the better-sqlite3 API this codebase relies on
 * (`prepare`, `exec`, `pragma`, `transaction`).  Using the built-in driver
 * removes the native-build dependency entirely (no node-gyp / MSBuild).
 */
export class Db {
    raw;
    constructor(dbPath) {
        this.raw = new DatabaseSync(dbPath);
    }
    exec(sql) {
        this.raw.exec(sql);
    }
    prepare(sql) {
        return this.raw.prepare(sql);
    }
    /** better-sqlite3-style pragma helper — routed through exec. */
    pragma(directive) {
        this.raw.exec(`PRAGMA ${directive}`);
    }
    /**
     * better-sqlite3-style transaction wrapper: returns a function that runs
     * `fn` inside BEGIN/COMMIT, rolling back on any thrown error.
     */
    transaction(fn) {
        return (...args) => {
            this.raw.exec('BEGIN');
            try {
                const result = fn(...args);
                this.raw.exec('COMMIT');
                return result;
            }
            catch (err) {
                this.raw.exec('ROLLBACK');
                throw err;
            }
        };
    }
}
// ─── Schema ───────────────────────────────────────────────────────────────────
function applySchema(db) {
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    db.pragma('foreign_keys = ON');
    db.exec(`
    -- Locks pulled from L1 via POST /rollup/:id/lock_bb.
    -- consumed = 0 until the sequencer calls L1 consume and succeeds.
    CREATE TABLE IF NOT EXISTS locks (
      lock_id        TEXT    PRIMARY KEY,
      rollup_id      TEXT    NOT NULL,
      wallet_address TEXT    NOT NULL,
      bb_lamports    INTEGER NOT NULL,
      symbol_hint    TEXT,
      consumed       INTEGER NOT NULL DEFAULT 0,      -- 0=open, 1=consumed
      registered_at  INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS idx_locks_wallet   ON locks(wallet_address);
    CREATE INDEX IF NOT EXISTS idx_locks_consumed ON locks(consumed);

    -- Off-chain balances: one row per (rollup, address, asset_type).
    -- updated_at_batch tracks which batch last changed this balance.
    CREATE TABLE IF NOT EXISTS balances (
      rollup_id        TEXT    NOT NULL,
      address          TEXT    NOT NULL,
      asset_type       TEXT    NOT NULL DEFAULT 'BB',
      bb_lamports      INTEGER NOT NULL DEFAULT 0,
      updated_at_batch INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (rollup_id, address, asset_type)
    );

    -- Sealed batches: one row per (rollup, batch_id).
    -- batch_id is monotonically increasing per rollup.
    CREATE TABLE IF NOT EXISTS batches (
      batch_id       INTEGER NOT NULL,
      rollup_id      TEXT    NOT NULL,
      merkle_root    TEXT    NOT NULL,
      entry_count    INTEGER NOT NULL,
      sealed_at_slot INTEGER NOT NULL,
      sealed_at_ts   INTEGER NOT NULL DEFAULT (unixepoch()),
      PRIMARY KEY (rollup_id, batch_id)
    );

    -- Single-row watermark: last L1 slot fully processed by this sequencer.
    -- Seeded to 0 on first run; updated after every batch seal so the sequencer
    -- can resume from the right slot after a restart.
    CREATE TABLE IF NOT EXISTS slot_watermark (
      rollup_id TEXT    PRIMARY KEY,
      slot      INTEGER NOT NULL DEFAULT 0
    );
  `);
}
// ─── Open ──────────────────────────────────────────────────────────────────────
/**
 * Open (or create) the SQLite database at `dbPath`, apply schema, and return
 * the connection.  Safe to call multiple times — schema is idempotent.
 */
export function openDb(dbPath) {
    const db = new Db(dbPath);
    applySchema(db);
    return db;
}
/**
 * Register a lock locally (INSERT OR IGNORE — idempotent).
 * Call this when the sequencer learns a user has locked $BB on L1.
 * Verify the lock on L1 with `getLock()` before calling this.
 */
export function upsertLock(db, lockId, rollupId, walletAddress, bbLamports, symbolHint) {
    db.prepare(`
    INSERT OR IGNORE INTO locks
      (lock_id, rollup_id, wallet_address, bb_lamports, symbol_hint)
    VALUES (?, ?, ?, ?, ?)
  `).run(lockId, rollupId, walletAddress, bbLamports, symbolHint ?? null);
}
/**
 * Mark a lock as consumed in the local database only.
 * Call this AFTER `consumeLock()` on L1 succeeds.
 *
 * @returns true if the row was updated; false if already consumed or not found.
 */
export function consumeLockLocal(db, lockId) {
    const result = db.prepare(`
    UPDATE locks SET consumed = 1 WHERE lock_id = ? AND consumed = 0
  `).run(lockId);
    return Number(result.changes) > 0;
}
/** Read a lock row from the local database.  Returns undefined if not found. */
export function getLocalLock(db, lockId) {
    return db.prepare(`SELECT * FROM locks WHERE lock_id = ?`).get(lockId);
}
// ─── Balance helpers ───────────────────────────────────────────────────────────
/**
 * Add lamports to an account's off-chain balance (upsert).
 * Pass a negative `lamportsDelta` to debit — caller must ensure solvency.
 * `batchId` is stamped on the row so we can audit which batch last touched it.
 */
export function creditBalance(db, rollupId, address, assetType, lamportsDelta, batchId) {
    db.prepare(`
    INSERT INTO balances (rollup_id, address, asset_type, bb_lamports, updated_at_batch)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(rollup_id, address, asset_type) DO UPDATE SET
      bb_lamports      = bb_lamports + excluded.bb_lamports,
      updated_at_batch = excluded.updated_at_batch
  `).run(rollupId, address, assetType, Number(lamportsDelta), batchId);
}
/** Read an account's off-chain balance. Returns 0n if no row exists. */
export function getBalance(db, rollupId, address, assetType = 'BB') {
    const row = db.prepare(`
    SELECT bb_lamports FROM balances
    WHERE rollup_id = ? AND address = ? AND asset_type = ?
  `).get(rollupId, address, assetType);
    return BigInt(row?.bb_lamports ?? 0);
}
// ─── Batch helpers ─────────────────────────────────────────────────────────────
/**
 * Record a sealed batch.  Overwrites any existing row for the same
 * (rollup_id, batch_id) — safe to call on retry after a partial failure.
 */
export function sealBatch(db, rollupId, batchId, merkleRoot, entryCount, slot) {
    db.prepare(`
    INSERT OR REPLACE INTO batches
      (batch_id, rollup_id, merkle_root, entry_count, sealed_at_slot)
    VALUES (?, ?, ?, ?, ?)
  `).run(batchId, rollupId, merkleRoot, entryCount, slot);
}
/** Return the highest sealed batch_id for this rollup, or 0 if none exist. */
export function getLatestBatchId(db, rollupId) {
    const row = db.prepare(`
    SELECT MAX(batch_id) AS max_id FROM batches WHERE rollup_id = ?
  `).get(rollupId);
    return Number(row.max_id ?? 0);
}
// ─── Slot watermark ────────────────────────────────────────────────────────────
/** Return the last L1 slot fully processed by this sequencer, or 0. */
export function getSlotWatermark(db, rollupId) {
    const row = db.prepare(`
    SELECT slot FROM slot_watermark WHERE rollup_id = ?
  `).get(rollupId);
    return Number(row?.slot ?? 0);
}
/**
 * Persist the latest processed L1 slot.
 * Call this at the end of every batch seal, after `sealBatch()` succeeds.
 */
export function setSlotWatermark(db, rollupId, slot) {
    db.prepare(`
    INSERT INTO slot_watermark (rollup_id, slot) VALUES (?, ?)
    ON CONFLICT(rollup_id) DO UPDATE SET slot = excluded.slot
  `).run(rollupId, slot);
}
//# sourceMappingURL=db.js.map