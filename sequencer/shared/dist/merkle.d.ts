import type { MerkleEntry, MerkleTree } from './types.js';
/**
 * Build the canonical UTF-8 leaf preimage string.
 * Must match the L1 Rust exit verifier exactly. The L1 handler lowercases the
 * address/owner (`addr_lower`) before building the leaf, so we lowercase here
 * too — otherwise mixed-case base58 addresses would hash to a different leaf
 * and the exit proof would fail verification.
 *   BB:  "{rollupId}:BB:{address_lowercased}:{lamports}"
 *   NFT: "{rollupId}:NFT:{collectionId}:{tokenId}:{owner_lowercased}:{metadataHash}"
 */
export declare function buildLeafPreimage(rollupId: string, entry: MerkleEntry): string;
/** Hash a leaf preimage string to a 64-char lowercase hex digest. */
export declare function hashLeaf(preimage: string): string;
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
export declare function buildMerkleTree(rollupId: string, entries: MerkleEntry[]): MerkleTree;
/**
 * Verify a Merkle inclusion proof against a known root, using the same
 * sorted-pair hex-string combine as the L1 verifier.
 *
 * @param rollupId Rollup ID used to reconstruct the leaf preimage.
 * @param entry    Entry whose inclusion is being verified.
 * @param proof    Sibling hex digests from leaf up to (but not including) root.
 * @param root     Expected 64-char lowercase hex root.
 */
export declare function verifyProof(rollupId: string, entry: MerkleEntry, proof: string[], root: string): boolean;
//# sourceMappingURL=merkle.d.ts.map