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
 * Ingest a lock from L1 into the L5 sequencer, crediting the user's tradable
 * off-chain $BB balance. This is the on-ramp traders use before buying Creator
 * Coins on the bonding curve.
 *
 * NOTE: coin launches do NOT go through this path — `POST /launch-coin`
 * consumes its own lock and routes the $BB straight into the pool reserve
 * instead of an off-chain balance.
 *
 * Flow (crash-safe):
 *   1. Check local DB — if already consumed, return idempotently.
 *   2. Fetch the lock from L1 to verify it's real, unconsumed, and for L5.
 *   3. CRASH RECOVERY: if L1 says consumed but local DB has no record,
 *      we must have crashed between step 4 and step 5 last time — re-credit.
 *   4. Consume the lock on L1 (authenticated, idempotent).
 *   5. Record in local DB + credit the user's off-chain balance.
 */
export async function registerLock(
  config: SequencerConfig,
  db: DatabaseType,
  lockId: string,
): Promise<RegisterLockResult> {
  // ── 1. Idempotency check ────────────────────────────────────────────────
  const local = getLocalLock(db, lockId);
  if (local?.consumed) {
    return {
      lock_id: lockId,
      wallet_address: local.wallet_address,
      bb_lamports: local.bb_lamports,
      credited: false,
    };
  }

  // ── 2. Verify on L1 ─────────────────────────────────────────────────────
  const l1Lock = await getLock(config, lockId);

  if (l1Lock.rollup_id !== 'L5') {
    throw new Error(
      `Lock ${lockId} belongs to rollup ${l1Lock.rollup_id}, not L5`,
    );
  }

  // ── 3. Crash recovery ────────────────────────────────────────────────────
  if (l1Lock.consumed && !local) {
    upsertLock(db, lockId, 'L5', l1Lock.creator_address, l1Lock.bb_lamports, l1Lock.token_symbol_hint);
    consumeLockLocal(db, lockId);
    creditBalance(db, 'L5', l1Lock.creator_address, 'BB', BigInt(l1Lock.bb_lamports), 0);
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
  upsertLock(db, lockId, 'L5', l1Lock.creator_address, l1Lock.bb_lamports, l1Lock.token_symbol_hint);
  consumeLockLocal(db, lockId);
  creditBalance(db, 'L5', l1Lock.creator_address, 'BB', BigInt(l1Lock.bb_lamports), 0);

  return {
    lock_id: lockId,
    wallet_address: l1Lock.creator_address,
    bb_lamports: l1Lock.bb_lamports,
    credited: true,
  };
}
