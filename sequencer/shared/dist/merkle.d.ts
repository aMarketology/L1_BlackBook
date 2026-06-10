import type { MerkleEntry, MerkleTree } from './types.js';
/** Build the canonical Borsh bytes for any MerkleEntry. */
export declare function buildLeafBytes(rollupId: string, entry: MerkleEntry): Uint8Array;
/**
 * @deprecated Use `buildLeafBytes` + `hashLeafBytes` instead.
 * Kept for any callers that still pass a preimage string directly.
 */
export declare function buildLeafPreimage(_rollupId: string, _entry: MerkleEntry): string;
/**
 * Hash a Borsh-serialized leaf to a 64-char lowercase hex digest.
 * This is the canonical leaf hash used in the Merkle tree.
 */
export declare function hashLeafBytes(leafBytes: Uint8Array): string;
/**
 * @deprecated Use `hashLeafBytes(buildLeafBytes(rollupId, entry))` instead.
 */
export declare function hashLeaf(_preimage: string): string;
/**
 * Build a complete sorted-pair SHA-256 Merkle tree from an entry list.
 *
 * Leaf digest = SHA-256( borsh(ClaimLeaf) )  ← deterministic binary, not a string
 * All node hashes are 64-char lowercase hex strings (matching the L1 verifier).
 * The list is padded to the next power of two (by duplicating the last leaf)
 * so that every leaf has a uniform-depth inclusion proof. Only the original
 * un-padded leaves are returned in `leaves` and `proofs`.
 *
 * @throws If `entries` is empty.
 */
export declare function buildMerkleTree(rollupId: string, entries: MerkleEntry[]): MerkleTree;
/**
 * Verify a Merkle inclusion proof against a known root.
 *
 * Leaf hash = SHA-256( borsh(ClaimLeaf) ) — Borsh-canonical, not a string.
 * Sibling combine uses sorted-pair hex-string SHA-256 (same as L1 Rust verifier).
 *
 * @param rollupId Rollup ID used to reconstruct the Borsh leaf bytes.
 * @param entry    Entry whose inclusion is being verified.
 * @param proof    Sibling hex digests from leaf up to (but not including) root.
 * @param root     Expected 64-char lowercase hex root.
 */
export declare function verifyProof(rollupId: string, entry: MerkleEntry, proof: string[], root: string): boolean;
//# sourceMappingURL=merkle.d.ts.map