import { createHash } from 'node:crypto';
import type { MerkleEntry, MerkleTree } from './types.js';

// ─── Leaf preimage ────────────────────────────────────────────────────────────

/**
 * Build the canonical UTF-8 leaf preimage string.
 * Must match the L1 Rust exit verifier exactly. The L1 handler lowercases the
 * address/owner (`addr_lower`) before building the leaf, so we lowercase here
 * too — otherwise mixed-case base58 addresses would hash to a different leaf
 * and the exit proof would fail verification.
 *   BB:  "{rollupId}:BB:{address_lowercased}:{lamports}"
 *   NFT: "{rollupId}:NFT:{collectionId}:{tokenId}:{owner_lowercased}:{metadataHash}"
 */
export function buildLeafPreimage(rollupId: string, entry: MerkleEntry): string {
  if (entry.type === 'BB') {
    return `${rollupId}:BB:${entry.address.toLowerCase()}:${entry.lamports}`;
  }
  return `${rollupId}:NFT:${entry.collectionId}:${entry.tokenId}:${entry.owner.toLowerCase()}:${entry.metadataHash}`;
}

// ─── Hashing primitives ───────────────────────────────────────────────────────

/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/** Hash a leaf preimage string to a 64-char lowercase hex digest. */
export function hashLeaf(preimage: string): string {
  return sha256Hex(preimage);
}

/**
 * Sorted-pair combine, matching the L1 Rust verifier EXACTLY:
 *   hash_pair(a, b) = sha256_hex( min(a,b) ++ max(a,b) )
 * where a and b are the 64-char lowercase hex digests and the concatenation is
 * of the hex STRINGS (128 ASCII chars), not the raw bytes. Lexicographic string
 * comparison of equal-length lowercase hex is equivalent to byte comparison, so
 * the ordering is identical to L1.
 */
function hashPair(a: string, b: string): string {
  return a <= b ? sha256Hex(a + b) : sha256Hex(b + a);
}

// ─── Tree builder ─────────────────────────────────────────────────────────────

/**
 * Build a complete sorted-pair SHA-256 Merkle tree from an entry list.
 *
 * All node hashes are 64-char lowercase hex strings (matching the L1 verifier).
 * The list is padded to the next power of two (by duplicating the last leaf)
 * so that every leaf has a uniform-depth inclusion proof. Only the original
 * un-padded leaves are returned in `leaves` and `proofs`.
 *
 * @throws If `entries` is empty.
 */
export function buildMerkleTree(rollupId: string, entries: MerkleEntry[]): MerkleTree {
  if (entries.length === 0) {
    throw new Error('buildMerkleTree: entry list must not be empty');
  }

  const leaves = entries.map(e => hashLeaf(buildLeafPreimage(rollupId, e)));

  // Pad to the next power of two.
  let level = [...leaves];
  while (level.length & (level.length - 1)) {
    level.push(level[level.length - 1]);
  }

  // Build layers bottom-up.
  const layers: string[][] = [level];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next: string[] = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(hashPair(prev[i], prev[i + 1]));
    }
    layers.push(next);
  }

  const root = layers[layers.length - 1][0];

  // Inclusion proofs for the original (un-padded) leaves.
  const proofs: string[][] = leaves.map((_, leafIdx) => {
    const proof: string[] = [];
    let idx = leafIdx;
    for (let l = 0; l < layers.length - 1; l++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      const sibling = layers[l][siblingIdx];
      if (sibling !== undefined) proof.push(sibling);
      idx = Math.floor(idx / 2);
    }
    return proof;
  });

  return { root, leaves, proofs };
}

// ─── Proof verifier ───────────────────────────────────────────────────────────

/**
 * Verify a Merkle inclusion proof against a known root, using the same
 * sorted-pair hex-string combine as the L1 verifier.
 *
 * @param rollupId Rollup ID used to reconstruct the leaf preimage.
 * @param entry    Entry whose inclusion is being verified.
 * @param proof    Sibling hex digests from leaf up to (but not including) root.
 * @param root     Expected 64-char lowercase hex root.
 */
export function verifyProof(
  rollupId: string,
  entry: MerkleEntry,
  proof: string[],
  root: string,
): boolean {
  let hash = hashLeaf(buildLeafPreimage(rollupId, entry));
  for (const sibling of proof) {
    hash = hashPair(hash, sibling);
  }
  return hash === root;
}
