import { DatabaseSync, type StatementSync } from 'node:sqlite';
/**
 * Thin wrapper over Node's built-in `node:sqlite` (`DatabaseSync`) that
 * preserves the small slice of the better-sqlite3 API this codebase relies on
 * (`prepare`, `exec`, `pragma`, `transaction`).  Using the built-in driver
 * removes the native-build dependency entirely (no node-gyp / MSBuild).
 */
export declare class Db {
    readonly raw: DatabaseSync;
    constructor(dbPath: string);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    /** better-sqlite3-style pragma helper — routed through exec. */
    pragma(directive: string): void;
    /**
     * better-sqlite3-style transaction wrapper: returns a function that runs
     * `fn` inside BEGIN/COMMIT, rolling back on any thrown error.
     */
    transaction<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R;
}
export type DatabaseType = Db;
/**
 * Open (or create) the SQLite database at `dbPath`, apply schema, and return
 * the connection.  Safe to call multiple times — schema is idempotent.
 */
export declare function openDb(dbPath: string): DatabaseType;
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
export declare function upsertLock(db: DatabaseType, lockId: string, rollupId: string, walletAddress: string, bbLamports: number, symbolHint: string | null): void;
/**
 * Mark a lock as consumed in the local database only.
 * Call this AFTER `consumeLock()` on L1 succeeds.
 *
 * @returns true if the row was updated; false if already consumed or not found.
 */
export declare function consumeLockLocal(db: DatabaseType, lockId: string): boolean;
/** Read a lock row from the local database.  Returns undefined if not found. */
export declare function getLocalLock(db: DatabaseType, lockId: string): LockRow | undefined;
/**
 * Add lamports to an account's off-chain balance (upsert).
 * Pass a negative `lamportsDelta` to debit — caller must ensure solvency.
 * `batchId` is stamped on the row so we can audit which batch last touched it.
 */
export declare function creditBalance(db: DatabaseType, rollupId: string, address: string, assetType: string, lamportsDelta: bigint, batchId: number): void;
/** Read an account's off-chain balance. Returns 0n if no row exists. */
export declare function getBalance(db: DatabaseType, rollupId: string, address: string, assetType?: string): bigint;
/**
 * Record a sealed batch.  Overwrites any existing row for the same
 * (rollup_id, batch_id) — safe to call on retry after a partial failure.
 */
export declare function sealBatch(db: DatabaseType, rollupId: string, batchId: number, merkleRoot: string, entryCount: number, slot: number): void;
/** Return the highest sealed batch_id for this rollup, or 0 if none exist. */
export declare function getLatestBatchId(db: DatabaseType, rollupId: string): number;
/** Return the last L1 slot fully processed by this sequencer, or 0. */
export declare function getSlotWatermark(db: DatabaseType, rollupId: string): number;
/**
 * Persist the latest processed L1 slot.
 * Call this at the end of every batch seal, after `sealBatch()` succeeds.
 */
export declare function setSlotWatermark(db: DatabaseType, rollupId: string, slot: number): void;
//# sourceMappingURL=db.d.ts.map