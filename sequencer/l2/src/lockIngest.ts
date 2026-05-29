import {
  getLock,
  consumeLock,
  consumeLockLocal,
  upsertLock,
  creditBalance,
  getLocalLock,
} from '@bb/shared';
import type { SequencerConfig, DatabaseType } from '@bb/shared';

export interface RegisterLockResult {
  lock_id: string;
  wallet_address: string;
  bb_lamports: number;
  /** true = freshly credited; false = idempotent replay (already processed) */
  credited: boolean;
}

/**
 * Ingest a lock from L1 into the L2 sequencer.
 *
 * Flow (crash-safe):
 *   1. Check local DB — if already consumed, return idempotently.
 *   2. Fetch the lock from L1 to verify it's real, unconsumed, and for L2.
 *   3. CRASH RECOVERY: if L1 says consumed but local DB has no record,
 *      we must have crashed between step 4 and step 5 last time — re-credit.
 *   4. Consume the lock on L1 (authenticated, idempotent).
 *   5. Record in local DB + credit the user's off-chain balance.
 *
 * After this call the user's `balances` row is positive and they can place
 * bets at L2 speed with zero L1 latency.
 */
export async function registerLock(
  config: SequencerConfig,
  db: DatabaseType,
  lockId: string,
): Promise<RegisterLockResult> {
  // ── 1. Idempotency check ────────────────────────────────────────────────
  const local = getLocalLock(db, lockId);
  if (local?.consumed) {
    // Already fully processed — return the cached info.
    return {
      lock_id: lockId,
      wallet_address: local.wallet_address,
      bb_lamports: local.bb_lamports,
      credited: false,
    };
  }

  // ── 2. Verify on L1 ─────────────────────────────────────────────────────
  const l1Lock = await getLock(config, lockId);

  if (l1Lock.rollup_id !== 'L2') {
    throw new Error(
      `Lock ${lockId} belongs to rollup ${l1Lock.rollup_id}, not L2`,
    );
  }

  // ── 3. Crash recovery ────────────────────────────────────────────────────
  // L1 says consumed but no local record: we crashed after step 4 last time.
  // The only entity that can consume L2 locks is this sequencer, so it's safe
  // to credit now.
  if (l1Lock.consumed && !local) {
    upsertLock(db, lockId, 'L2', l1Lock.creator_address, l1Lock.bb_lamports, l1Lock.token_symbol_hint);
    consumeLockLocal(db, lockId);
    creditBalance(db, 'L2', l1Lock.creator_address, 'BB', BigInt(l1Lock.bb_lamports), 0);
    return {
      lock_id: lockId,
      wallet_address: l1Lock.creator_address,
      bb_lamports: l1Lock.bb_lamports,
      credited: true,
    };
  }

  if (l1Lock.consumed) {
    throw new Error(`Lock ${lockId} is already consumed on L1 by another party`);
  }

  // ── 4. Consume on L1 (authenticated) ────────────────────────────────────
  await consumeLock(config, lockId);

  // ── 5. Record locally + credit balance ──────────────────────────────────
  upsertLock(db, lockId, 'L2', l1Lock.creator_address, l1Lock.bb_lamports, l1Lock.token_symbol_hint);
  consumeLockLocal(db, lockId);
  creditBalance(db, 'L2', l1Lock.creator_address, 'BB', BigInt(l1Lock.bb_lamports), 0);

  return {
    lock_id: lockId,
    wallet_address: l1Lock.creator_address,
    bb_lamports: l1Lock.bb_lamports,
    credited: true,
  };
}
