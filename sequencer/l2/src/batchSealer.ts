import { buildMerkleTree, submitRoot, sealBatch, setSlotWatermark, getLatestBatchId } from '@bb/shared';
import type { BbEntry, SequencerConfig, DatabaseType } from '@bb/shared';
import { getAllBalances } from './markets.js';

export interface SealResult {
  batchId: number;
  merkleRoot: string;
  entryCount: number;
  slot: number;
}

/**
 * In-memory cache of the last root we successfully anchored on L1.
 * Used to skip redundant seals when the slot timer fires but no balance
 * has changed since the previous batch — prevents flooding L1 / ReDB with
 * duplicate roots under ever-incrementing batch IDs.
 *
 * Resets to null on process restart (one re-anchor after restart is harmless;
 * L1 is idempotent for duplicate roots).
 */
let lastSealedRoot: string | null = null;

/**
 * Serialization tail. Every seal request chains onto this promise so that the
 * PoH tick loop and the resolve handler can never run `sealAndSubmit`
 * concurrently. Without this, two callers can interleave at the `await
 * submitRoot` point — both compute the same next batch id, both POST to L1,
 * and the loser gets a spurious "monotonicity violation" rejection.
 *
 * `.catch(() => undefined)` keeps the chain alive: one caller's failure must
 * not poison subsequent seals. The original caller still receives the error
 * via its own returned promise.
 */
let sealChain: Promise<unknown> = Promise.resolve();

/**
 * Snapshot all L2 balances, build a Merkle tree, submit the root to L1,
 * and record the sealed batch locally.
 *
 * Called by:
 *   - The PoH tick loop every `config.slotsPerBatch` slots.
 *   - The resolve handler immediately after market settlement.
 *
 * Concurrency: calls are serialized one-at-a-time via `sealChain`, so a
 * timer-triggered seal and a resolve-triggered seal never race. The redundant
 * -seal guard then naturally skips the second caller when the first already
 * anchored the identical root.
 *
 * Ordering guarantee: L1 submit BEFORE local sealBatch write. If we crash
 * after L1 succeeds but before the local write, the next seal will re-submit
 * the same (or newer) root — L1 is idempotent for duplicate roots.
 *
 * @param slot  Current L1 slot (pass 0 for manual / non-slot-triggered seals).
 * @returns     SealResult on success, null if there are no balances to anchor.
 */
export function sealAndSubmit(
  config: SequencerConfig,
  db: DatabaseType,
  slot: number,
): Promise<SealResult | null> {
  const run = sealChain.then(() => doSeal(config, db, slot));
  // Advance the tail; swallow errors here so the chain survives a failed seal.
  sealChain = run.catch(() => undefined);
  return run;
}

async function doSeal(
  config: SequencerConfig,
  db: DatabaseType,
  slot: number,
): Promise<SealResult | null> {
  const balances = getAllBalances(db);
  if (balances.length === 0) {
    return null;
  }

  const entries: BbEntry[] = balances.map(b => ({
    type: 'BB',
    address: b.address,
    lamports: b.lamports,
  }));

  const { root } = buildMerkleTree('L2', entries);

  // ── REDUNDANT-SEAL GUARD ───────────────────────────────────────────────
  // Skip if the state root is identical to the last one we anchored. This
  // stops the PoH tick loop from re-submitting the same root every interval
  // when no bet/resolve/lock changed the balance set.
  if (root === lastSealedRoot) {
    console.log(`[Batch Sealer] Skipping seal @ slot ${slot}: state root unchanged (${root.slice(0, 16)}…)`);
    return null;
  }

  const batchId = getLatestBatchId(db, 'L2') + 1;

  // Persist to L1 first — durable anchor before any local state change.
  await submitRoot(config, batchId, root);

  // Record the batch locally.
  sealBatch(db, 'L2', batchId, root, entries.length, slot);
  setSlotWatermark(db, 'L2', slot);

  // Only advance the cache after a fully successful submit + local write.
  lastSealedRoot = root;

  return { batchId, merkleRoot: root, entryCount: entries.length, slot };
}
