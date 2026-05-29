import { openDb } from '@bb/shared';
import type { DatabaseType } from '@bb/shared';

// ─── L3-specific schema ───────────────────────────────────────────────────────
//
// Extends the shared schema (locks, balances, batches, slot_watermark) with
// a single NFT ownership table.  This is the entire L3 state machine — every
// 25 slots the full table is snapshotted into a 32-byte Merkle root on L1.

const L3_SCHEMA = `
  -- One row per (collection, token).  The entire row is the canonical NFT state.
  -- metadata_hash must match what was used to build the L1 Merkle leaf.
  -- metadata_uri is L3-local only (not hashed into the leaf).
  CREATE TABLE IF NOT EXISTS l3_nfts (
    collection_id  TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    owner_address  TEXT NOT NULL,
    metadata_hash  TEXT NOT NULL,
    metadata_uri   TEXT NOT NULL,
    minted_at_ts   INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_ts  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (collection_id, token_id)
  );

  CREATE INDEX IF NOT EXISTS idx_nfts_owner      ON l3_nfts(owner_address);
  CREATE INDEX IF NOT EXISTS idx_nfts_collection ON l3_nfts(collection_id);
`;

/** Open the L3 SQLite database, applying the shared schema + NFT table. */
export function openL3Db(dbPath: string): DatabaseType {
  const db = openDb(dbPath);
  db.exec(L3_SCHEMA);
  return db;
}
