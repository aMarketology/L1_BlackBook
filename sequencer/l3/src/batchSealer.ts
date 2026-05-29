import { buildMerkleTree, submitRoot, sealBatch, setSlotWatermark, getLatestBatchId } from '@bb/shared';
import type { NftEntry, SequencerConfig, DatabaseType } from '@bb/shared';
import { getAllNftSnapshots } from './nftEngine.js';

export interface SealResult {
  batchId: number;
  merkleRoot: string;
  entryCount: number;
  slot: number;
}

/**
 * Snapshot all L3 NFT ownership records, build a Merkle tree, submit the root
 * to L1, then record the sealed batch locally.
 *
 * Canonical leaf pre-image per NFT (must match L1 Rust exactly):
 *   "L3:NFT:{collectionId}:{tokenId}:{owner}:{metadataHash}"
 *
 * Ordering guarantee: L1 `submitRoot` succeeds BEFORE `sealBatch` writes
 * locally. On crash-restart the next seal submits a new (or identical) root.
 *
 * @param slot  Current L1 slot (pass 0 for manual / resolve-triggered seals).
 * @returns     SealResult, or null if the database has no NFTs yet.
 */
export async function sealAndSubmit(
  config: SequencerConfig,
  db: DatabaseType,
  slot: number,
): Promise<SealResult | null> {
  const snapshots = getAllNftSnapshots(db);
  if (snapshots.length === 0) {
    return null;
  }

  const entries: NftEntry[] = snapshots.map(s => ({
    type: 'NFT',
    collectionId: s.collectionId,
    tokenId: s.tokenId,
    owner: s.owner,
    metadataHash: s.metadataHash,
  }));

  const { root } = buildMerkleTree('L3', entries);
  const batchId = getLatestBatchId(db, 'L3') + 1;

  // Durable L1 anchor before any local state change.
  await submitRoot(config, batchId, root);

  sealBatch(db, 'L3', batchId, root, entries.length, slot);
  setSlotWatermark(db, 'L3', slot);

  return { batchId, merkleRoot: root, entryCount: entries.length, slot };
}
