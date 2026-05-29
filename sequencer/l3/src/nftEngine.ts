import type { DatabaseType } from '@bb/shared';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface NftRow {
  collection_id: string;
  token_id: string;
  owner_address: string;
  metadata_hash: string;
  metadata_uri: string;
  minted_at_ts: number;
  updated_at_ts: number;
}

/** Shape returned to the batch sealer — maps to the shared NftEntry type. */
export interface NftSnapshot {
  collectionId: string;
  tokenId: string;
  owner: string;
  metadataHash: string;
}

// ─── Mint ─────────────────────────────────────────────────────────────────────

/**
 * Mint a new NFT.  Fails if (collection_id, token_id) already exists — mints
 * are not idempotent by design; retry with a different token_id.
 *
 * Auth: caller (server.ts) must have verified the creator's signature or
 * applied whatever minting policy is in force before calling this.
 */
export function mintNft(
  db: DatabaseType,
  collectionId: string,
  tokenId: string,
  ownerAddress: string,
  metadataHash: string,
  metadataUri: string,
): void {
  db.prepare(`
    INSERT INTO l3_nfts
      (collection_id, token_id, owner_address, metadata_hash, metadata_uri)
    VALUES (?, ?, ?, ?, ?)
  `).run(collectionId, tokenId, ownerAddress, metadataHash, metadataUri);
}

// ─── Transfer ─────────────────────────────────────────────────────────────────

/**
 * Transfer ownership of an NFT to a new address.
 *
 * Preconditions (enforced by this function):
 *   - The NFT must exist.
 *   - `currentOwner` must be the recorded owner_address.
 *
 * Auth: server.ts verifies the Ed25519 signature over the canonical message
 *   "L3_TRANSFER:{collection_id}:{token_id}:{new_owner}:{timestamp}:{nonce}"
 * before calling this.  The `currentOwner` is read from the DB, not from
 * the request body — the signer's public key is compared against owner_address.
 */
export function transferNft(
  db: DatabaseType,
  collectionId: string,
  tokenId: string,
  currentOwner: string,
  newOwner: string,
): void {
  const result = db.prepare(`
    UPDATE l3_nfts
    SET owner_address = ?, updated_at_ts = unixepoch()
    WHERE collection_id = ? AND token_id = ? AND owner_address = ?
  `).run(newOwner, collectionId, tokenId, currentOwner);

  if (result.changes === 0) {
    // Either NFT doesn't exist or currentOwner doesn't match — both = reject.
    const nft = getNft(db, collectionId, tokenId);
    if (!nft) throw new Error(`NFT ${collectionId}/${tokenId} not found`);
    throw new Error(`Ownership mismatch: ${collectionId}/${tokenId} is owned by ${nft.owner_address}`);
  }
}

// ─── Reads ────────────────────────────────────────────────────────────────────

export function getNft(
  db: DatabaseType,
  collectionId: string,
  tokenId: string,
): NftRow | undefined {
  return db.prepare(
    `SELECT * FROM l3_nfts WHERE collection_id = ? AND token_id = ?`,
  ).get(collectionId, tokenId) as NftRow | undefined;
}

export function getCollection(db: DatabaseType, collectionId: string): NftRow[] {
  return db.prepare(
    `SELECT * FROM l3_nfts WHERE collection_id = ? ORDER BY minted_at_ts ASC`,
  ).all(collectionId) as unknown as NftRow[];
}

export function getNftsByOwner(db: DatabaseType, ownerAddress: string): NftRow[] {
  return db.prepare(
    `SELECT * FROM l3_nfts WHERE owner_address = ? ORDER BY minted_at_ts DESC`,
  ).all(ownerAddress) as unknown as NftRow[];
}

/**
 * Return every NFT as a snapshot suitable for `NftEntry` Merkle leaves.
 * Called by the batch sealer every 25 slots.
 */
export function getAllNftSnapshots(db: DatabaseType): NftSnapshot[] {
  const rows = db.prepare(
    `SELECT collection_id, token_id, owner_address, metadata_hash FROM l3_nfts`,
  ).all() as Pick<NftRow, 'collection_id' | 'token_id' | 'owner_address' | 'metadata_hash'>[];
  return rows.map(r => ({
    collectionId: r.collection_id,
    tokenId: r.token_id,
    owner: r.owner_address,
    metadataHash: r.metadata_hash,
  }));
}
