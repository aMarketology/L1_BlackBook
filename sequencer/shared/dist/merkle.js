import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
// ─── Base58 decode (needed to convert addresses to raw [u8;32]) ───────────────
// bs58 is available in the workspace root — dynamic require avoids ESM issues.
const _require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bs58 = _require('bs58');
// ─── Borsh-canonical leaf serialization ──────────────────────────────────────
//
// PROBLEM: UTF-8 string hashing is fragile across language boundaries —
// integer formatting ("500000" vs "5e5"), whitespace, and encoding differ
// between TypeScript and Rust.
//
// SOLUTION: Borsh (Binary Object Representation Serializer for Hashing)
// guarantees identical byte layout in every language:
//   String  → u32_LE(len) || utf8_bytes
//   [u8;32] → 32 raw bytes (no length prefix — fixed-size)
//   u64     → 8 bytes little-endian
//
// ClaimLeaf (BB):
//   borsh( rollup_id: String, token: "BB", address: [u8;32], lamports: u64 )
//
// ClaimLeaf (NFT):
//   borsh( rollup_id: String, token: "NFT", collection_id: String,
//          token_id: u64, owner: [u8;32], metadata_hash: String )
//
// SHA-256 of the Borsh bytes = the canonical leaf digest used in the tree.
// Matches the Rust `ClaimLeaf` BorshSerialize derive in contracts/rollup/mod.rs
// and contracts/da/mod.rs.
/** Write a Borsh-encoded String (u32_LE length prefix + UTF-8 body) into buf. */
function borshWriteString(buf, s) {
    const bytes = new TextEncoder().encode(s);
    const len = bytes.length;
    // u32 little-endian length prefix
    buf.push(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff);
    for (const b of bytes)
        buf.push(b);
}
/** Write a Borsh-encoded u64 (8 bytes little-endian) into buf. */
function borshWriteU64(buf, v) {
    let n = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) {
        buf.push(Number(n & 0xffn));
        n >>= 8n;
    }
}
/**
 * Serialize a BB ClaimLeaf to canonical Borsh bytes.
 *
 * Layout (matches Rust `#[derive(BorshSerialize)] struct BbClaimLeaf`):
 *   rollup_id : String  → u32_LE(len) + utf8
 *   token     : String  → u32_LE(2) + "BB"
 *   address   : [u8;32] → 32 raw bytes (bs58-decoded pubkey)
 *   lamports  : u64     → 8 bytes LE
 */
function serializeBbLeaf(rollupId, address, lamports) {
    const buf = [];
    borshWriteString(buf, rollupId);
    borshWriteString(buf, 'BB');
    const addrBytes = bs58.decode(address);
    if (addrBytes.length !== 32)
        throw new Error(`BB leaf: address must decode to 32 bytes, got ${addrBytes.length}`);
    for (const b of addrBytes)
        buf.push(b);
    borshWriteU64(buf, lamports);
    return new Uint8Array(buf);
}
/**
 * Serialize an NFT ClaimLeaf to canonical Borsh bytes.
 *
 * Layout (matches Rust `#[derive(BorshSerialize)] struct NftClaimLeaf`):
 *   rollup_id     : String  → u32_LE(len) + utf8
 *   token         : String  → u32_LE(3) + "NFT"
 *   collection_id : String  → u32_LE(len) + utf8
 *   token_id      : u64     → 8 bytes LE
 *   owner         : [u8;32] → 32 raw bytes (bs58-decoded pubkey)
 *   metadata_hash : String  → u32_LE(64) + hex chars (64 ASCII bytes)
 */
function serializeNftLeaf(rollupId, collectionId, tokenId, owner, metadataHash) {
    const buf = [];
    borshWriteString(buf, rollupId);
    borshWriteString(buf, 'NFT');
    borshWriteString(buf, collectionId);
    borshWriteU64(buf, tokenId);
    const ownerBytes = bs58.decode(owner);
    if (ownerBytes.length !== 32)
        throw new Error(`NFT leaf: owner must decode to 32 bytes, got ${ownerBytes.length}`);
    for (const b of ownerBytes)
        buf.push(b);
    borshWriteString(buf, metadataHash);
    return new Uint8Array(buf);
}
/** Build the canonical Borsh bytes for any MerkleEntry. */
export function buildLeafBytes(rollupId, entry) {
    if (entry.type === 'BB') {
        return serializeBbLeaf(rollupId, entry.address, entry.lamports);
    }
    return serializeNftLeaf(rollupId, entry.collectionId, BigInt(entry.tokenId), entry.owner, entry.metadataHash);
}
/**
 * @deprecated Use `buildLeafBytes` + `hashLeafBytes` instead.
 * Kept for any callers that still pass a preimage string directly.
 */
export function buildLeafPreimage(_rollupId, _entry) {
    throw new Error('buildLeafPreimage is deprecated — use buildLeafBytes(rollupId, entry) for Borsh-canonical leaf serialization');
}
// ─── Hashing primitives ───────────────────────────────────────────────────────
/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
function sha256Hex(data) {
    return createHash('sha256').update(data, 'utf8').digest('hex');
}
/** SHA-256 of raw bytes, returned as lowercase hex. */
function sha256HexBytes(data) {
    return createHash('sha256').update(data).digest('hex');
}
/**
 * Hash a Borsh-serialized leaf to a 64-char lowercase hex digest.
 * This is the canonical leaf hash used in the Merkle tree.
 */
export function hashLeafBytes(leafBytes) {
    return sha256HexBytes(leafBytes);
}
/**
 * @deprecated Use `hashLeafBytes(buildLeafBytes(rollupId, entry))` instead.
 */
export function hashLeaf(_preimage) {
    throw new Error('hashLeaf is deprecated — use hashLeafBytes(buildLeafBytes(rollupId, entry))');
}
/**
 * Sorted-pair combine, matching the L1 Rust verifier EXACTLY:
 *   hash_pair(a, b) = sha256_hex( min(a,b) ++ max(a,b) )
 * where a and b are the 64-char lowercase hex digests and the concatenation is
 * of the hex STRINGS (128 ASCII chars), not the raw bytes. Lexicographic string
 * comparison of equal-length lowercase hex is equivalent to byte comparison, so
 * the ordering is identical to L1.
 */
function hashPair(a, b) {
    return a <= b ? sha256Hex(a + b) : sha256Hex(b + a);
}
// ─── Tree builder ─────────────────────────────────────────────────────────────
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
export function buildMerkleTree(rollupId, entries) {
    if (entries.length === 0) {
        throw new Error('buildMerkleTree: entry list must not be empty');
    }
    // Each leaf is SHA-256 of the Borsh-serialized ClaimLeaf struct.
    const leaves = entries.map(e => hashLeafBytes(buildLeafBytes(rollupId, e)));
    // Pad to the next power of two.
    let level = [...leaves];
    while (level.length & (level.length - 1)) {
        level.push(level[level.length - 1]);
    }
    // Build layers bottom-up.
    const layers = [level];
    while (layers[layers.length - 1].length > 1) {
        const prev = layers[layers.length - 1];
        const next = [];
        for (let i = 0; i < prev.length; i += 2) {
            next.push(hashPair(prev[i], prev[i + 1]));
        }
        layers.push(next);
    }
    const root = layers[layers.length - 1][0];
    // Inclusion proofs for the original (un-padded) leaves.
    const proofs = leaves.map((_, leafIdx) => {
        const proof = [];
        let idx = leafIdx;
        for (let l = 0; l < layers.length - 1; l++) {
            const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
            const sibling = layers[l][siblingIdx];
            if (sibling !== undefined)
                proof.push(sibling);
            idx = Math.floor(idx / 2);
        }
        return proof;
    });
    return { root, leaves, proofs };
}
// ─── Proof verifier ───────────────────────────────────────────────────────────
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
export function verifyProof(rollupId, entry, proof, root) {
    let hash = hashLeafBytes(buildLeafBytes(rollupId, entry));
    for (const sibling of proof) {
        hash = hashPair(hash, sibling);
    }
    return hash === root;
}
//# sourceMappingURL=merkle.js.map