import { DatabaseSync, type StatementSync } from 'node:sqlite';

/**
 * Thin wrapper over Node's built-in `node:sqlite` (`DatabaseSync`) that
 * preserves the small slice of the better-sqlite3 API this codebase relies on
 * (`prepare`, `exec`, `pragma`, `transaction`).  Using the built-in driver
 * removes the native-build dependency entirely (no node-gyp / MSBuild).
 */
export class Db {
  readonly raw: DatabaseSync;

  constructor(dbPath: string) {
    this.raw = new DatabaseSync(dbPath);
  }

  exec(sql: string): void {
    this.raw.exec(sql);
  }

  prepare(sql: string): StatementSync {
    return this.raw.prepare(sql);
  }

  /** better-sqlite3-style pragma helper — routed through exec. */
  pragma(directive: string): void {
    this.raw.exec(`PRAGMA ${directive}`);
  }

  /**
   * better-sqlite3-style transaction wrapper: returns a function that runs
   * `fn` inside BEGIN/COMMIT, rolling back on any thrown error.
   */
  transaction<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
    return (...args: A): R => {
      this.raw.exec('BEGIN');
      try {
        const result = fn(...args);
        this.raw.exec('COMMIT');
        return result;
      } catch (err) {
        this.raw.exec('ROLLBACK');
        throw err;
      }
    };
  }
}

export type DatabaseType = Db;

// ─── Schema ───────────────────────────────────────────────────────────────────

function applySchema(db: DatabaseType): void {
  // ── Durability & concurrency ──────────────────────────────────────────────
  // WAL: readers never block writers; writers never block readers.
  db.pragma('journal_mode = WAL');
  // NORMAL: fsync only at WAL checkpoints — safe with WAL, ~3× faster than FULL.
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  // Retry for up to 5 s on SQLITE_BUSY before throwing — essential when multiple
  // processes (PM2 cluster, batchSealer timer vs HTTP handler) share the same file.
  db.pragma('busy_timeout = 5000');

  // ── Read-path performance ─────────────────────────────────────────────────
  // 32 MB page cache (default = ~2 MB).  Hot tables (balances, positions) fit
  // entirely in cache after the first full-table scan, eliminating disk I/O for
  // repeated balance reads under burst load.
  db.pragma('cache_size = -32768');
  // Memory-map up to 128 MB of the database file.  Reads bypass read() syscalls
  // entirely via OS virtual memory — measurable win at ≥100 req/s.
  db.pragma('mmap_size = 134217728');

  // ── Write-path performance ────────────────────────────────────────────────
  // Temp tables and sort buffers for ORDER BY / GROUP BY live in RAM instead of
  // a temp file.  The batchSealer SELECT … ORDER BY batch_id benefits directly.
  db.pragma('temp_store = MEMORY');

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
export function openDb(dbPath: string): DatabaseType {
  const db = new Db(dbPath);
  applySchema(db);
  return db;
}

// ─── Lock helpers ──────────────────────────────────────────────────────────────

export interface LockRow {
  lock_id: string;
  rollup_id: string;
  wallet_address: string;
  bb_lamports: number;
  symbol_hint: string | null;
  /** SQLite integer: 0 = open, 1 = consumed. */
  consumed: number;
  registered_at: number;
}

/**
 * Register a lock locally (INSERT OR IGNORE — idempotent).
 * Call this when the sequencer learns a user has locked $BB on L1.
 * Verify the lock on L1 with `getLock()` before calling this.
 */
export function upsertLock(
  db: DatabaseType,
  lockId: string,
  rollupId: string,
  walletAddress: string,
  bbLamports: number,
  symbolHint: string | null,
): void {
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
export function consumeLockLocal(db: DatabaseType, lockId: string): boolean {
  const result = db.prepare(`
    UPDATE locks SET consumed = 1 WHERE lock_id = ? AND consumed = 0
  `).run(lockId);
  return Number(result.changes) > 0;
}

/** Read a lock row from the local database.  Returns undefined if not found. */
export function getLocalLock(db: DatabaseType, lockId: string): LockRow | undefined {
  return db.prepare(
    `SELECT * FROM locks WHERE lock_id = ?`,
  ).get(lockId) as LockRow | undefined;
}

// ─── Balance helpers ───────────────────────────────────────────────────────────

/**
 * Add lamports to an account's off-chain balance (upsert).
 * Pass a negative `lamportsDelta` to debit — caller must ensure solvency.
 * `batchId` is stamped on the row so we can audit which batch last touched it.
 */
export function creditBalance(
  db: DatabaseType,
  rollupId: string,
  address: string,
  assetType: string,
  lamportsDelta: bigint,
  batchId: number,
): void {
  db.prepare(`
    INSERT INTO balances (rollup_id, address, asset_type, bb_lamports, updated_at_batch)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(rollup_id, address, asset_type) DO UPDATE SET
      bb_lamports      = bb_lamports + excluded.bb_lamports,
      updated_at_batch = excluded.updated_at_batch
  `).run(rollupId, address, assetType, Number(lamportsDelta), batchId);
}

/** Read an account's off-chain balance. Returns 0n if no row exists. */
export function getBalance(
  db: DatabaseType,
  rollupId: string,
  address: string,
  assetType = 'BB',
): bigint {
  const row = db.prepare(`
    SELECT bb_lamports FROM balances
    WHERE rollup_id = ? AND address = ? AND asset_type = ?
  `).get(rollupId, address, assetType) as { bb_lamports: number } | undefined;
  return BigInt(row?.bb_lamports ?? 0);
}

// ─── Batch helpers ─────────────────────────────────────────────────────────────

/**
 * Record a sealed batch.  Overwrites any existing row for the same
 * (rollup_id, batch_id) — safe to call on retry after a partial failure.
 */
export function sealBatch(
  db: DatabaseType,
  rollupId: string,
  batchId: number,
  merkleRoot: string,
  entryCount: number,
  slot: number,
): void {
  db.prepare(`
    INSERT OR REPLACE INTO batches
      (batch_id, rollup_id, merkle_root, entry_count, sealed_at_slot)
    VALUES (?, ?, ?, ?, ?)
  `).run(batchId, rollupId, merkleRoot, entryCount, slot);
}

/** Return the highest sealed batch_id for this rollup, or 0 if none exist. */
export function getLatestBatchId(db: DatabaseType, rollupId: string): number {
  const row = db.prepare(`
    SELECT MAX(batch_id) AS max_id FROM batches WHERE rollup_id = ?
  `).get(rollupId) as { max_id: number | bigint | null };
  return Number(row.max_id ?? 0);
}

// ─── Slot watermark ────────────────────────────────────────────────────────────

/** Return the last L1 slot fully processed by this sequencer, or 0. */
export function getSlotWatermark(db: DatabaseType, rollupId: string): number {
  const row = db.prepare(`
    SELECT slot FROM slot_watermark WHERE rollup_id = ?
  `).get(rollupId) as { slot: number | bigint } | undefined;
  return Number(row?.slot ?? 0);
}

/**
 * Persist the latest processed L1 slot.
 * Call this at the end of every batch seal, after `sealBatch()` succeeds.
 */
export function setSlotWatermark(db: DatabaseType, rollupId: string, slot: number): void {
  db.prepare(`
    INSERT INTO slot_watermark (rollup_id, slot) VALUES (?, ?)
    ON CONFLICT(rollup_id) DO UPDATE SET slot = excluded.slot
  `).run(rollupId, slot);
}
