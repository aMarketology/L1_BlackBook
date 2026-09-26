# Merkle Leaves & Proofs

This is the **canonical** encoding spec for state roots anchored on L1 and the
exit proofs that release assets. Source: `src/contracts/rollup/mod.rs` and
`sequencer/shared/src/merkle.ts`.

> **The L1 verifier is the authority.** A proof that does not match this exact
> byte layout will fail exit verification regardless of what a client library
> produced.

---

## Leaf encoding: Borsh

Leaves are **Borsh-serialized** structs, then SHA-256'd. Borsh gives a single
deterministic byte layout across languages:

| Type | Encoding |
|------|----------|
| `String` / `&str` | `u32_LE(len)` \|\| utf8 bytes |
| `[u8; 32]` | 32 raw bytes (no length prefix) |
| `u64` | 8 bytes little-endian |

### BB balance leaf

```rust
struct BbClaimLeaf {
    rollup_id: str,   // "L2" | "L3" | "L5"
    token:     str,   // always "BB"
    address:   [u8;32], // 32-byte Ed25519 pubkey (bs58-decoded wallet address)
    lamports:  u64,   // balance in $BB lamports (1 BB = 100_000)
}
leaf_hash = SHA-256( borsh(BbClaimLeaf) )
```

Field order matters. The byte layout is:

```
[u32_LE len("L2")] "L2"
[u32_LE 2] "BB"
[32 bytes address]
[8 bytes lamports LE]
```

### NFT ownership leaf

```rust
struct NftClaimLeaf {
    rollup_id:     str,   // "L2" | "L3" | "L5"
    token:         str,   // always "NFT"
    collection_id: str,
    token_id:      str,   // ⚠ string, NOT integer — see Pitfalls
    owner:         [u8;32],
    metadata_hash: str,   // SHA-256 hex of metadata JSON (64 ASCII chars)
}
leaf_hash = SHA-256( borsh(NftClaimLeaf) )
```

---

## Merkle tree construction

- **Sibling combine** (sorted pair): `hash_pair(a, b) = SHA-256( min(a,b) || max(a,b) )`
  where `a` and `b` are 64-char lowercase **hex** strings, concatenated as ASCII,
  then SHA-256'd.
- Leaf digests are 64-char hex strings; the tree is built over these hex
  strings, not raw bytes.

```rust
fn hash_pair(a: &str, b: &str) -> String {
    if a <= b { sha256_hex(&format!("{}{}", a, b)) }
    else      { sha256_hex(&format!("{}{}", b, a)) }
}
```

The sorted pair makes combination deterministic regardless of sibling order.

---

## Proof verification (exit path)

`verify_merkle_proof` walks from the leaf hash to the root:

```rust
current = leaf_hash
for (i, sibling) in siblings:
    if is_right[i]: current = hash_pair(current, sibling)
    else:           current = hash_pair(sibling, current)
return current   // must equal the anchored root
```

The exit request supplies the leaf hash inputs (address, lamports or NFT
fields), the sibling list, and the `is_right` direction flags. L1 recomputes
the leaf, walks the proof, and compares against the root anchored by
`submit_root` for that `batch_id`.

## Exit key / double-spend seal

After a successful exit, L1 writes a permanent seal:

```
BB:   SHA-256("{rollup_id}:BB:{address_lowercase}")
NFT:  SHA-256("{rollup_id}:NFT:{collection_id}:{token_id}")
```

Any later attempt with the same proof hits `409 Conflict` before state changes.

## Reference implementation

The TypeScript reference is `sequencer/shared/src/merkle.ts`
(`serializeBbLeaf`, `serializeNftLeaf`, `hashPair`). The Rust verifier is
`src/contracts/rollup/mod.rs` (`bb_leaf_hash`, `nft_leaf_hash`,
`verify_merkle_proof`).

> **⚠ Known discrepancy** — the TypeScript `merkle.ts` serializes NFT
> `tokenId` as `u64` (8-byte LE), but the Rust `NftClaimLeaf.token_id` is a
> `&str`. These produce **different bytes** for any token_id that is not purely
> numeric, and even for numeric IDs the `u64`-vs-string layout differs. NFT exit
> proofs built from the current TS code can fail L1 verification. See
> [Pitfalls](pitfalls.md#nft-token-id-type-mismatch).
