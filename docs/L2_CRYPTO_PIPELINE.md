# L2 Cryptographic Pipeline & Settlement Architecture

> **Ground truth documentation** for the L2 Prediction Market sequencer.
> All descriptions match the source code in `sequencer/l2/` and `sequencer/shared/`.
> Last updated: June 2026.

---

## Runtime Identity

| Property | Value |
|---|---|
| Language | TypeScript / Node.js 22+ |
| Database | SQLite (WAL mode, `node:sqlite` built-in) |
| HTTP server | Express.js on `:7072` |
| Signing library | `@noble/curves/ed25519` |
| Merkle tree | Hand-rolled SHA-256 Borsh-canonical (in `shared/src/merkle.ts`) |
| L1 transport | HTTP REST (not gRPC) |
| Key source | `L2_SEQUENCER_PRIVKEY` env var (64-char hex seed) |

---

## Crypto Primitives

### Ed25519 (Bet Signatures)

`sequencer/l2/src/server.ts` — `verifyEd25519()`:

```typescript
function verifyEd25519(message: string, signatureHex: string, publicKeyHex: string): boolean {
  const sig = hexToBytes(signatureHex);
  const pk  = hexToBytes(publicKeyHex);
  const msg = new TextEncoder().encode(message);
  return ed.verify(sig, msg, pk);   // @noble/curves — compatible with L1 ed25519-dalek
}
```

**Canonical bet message format:**
```
"L2_BET:{market_id}:{wallet_address}:{side}:{amount_lamports}:{timestamp}:{nonce}"
```

**Canonical resolve message format (sequencer key):**
```
"L2_RESOLVE:{market_id}:{outcome}:{timestamp}:{nonce}"
```

Ed25519 verification runs synchronously in the Express route handler (Node.js single-threaded I/O loop — not the same concurrency concern as Rust tokio async blocking).

### Ed25519 (Sequencer → L1 Signing)

`sequencer/shared/src/signing.ts` wraps `@noble/curves` for the sequencer's own signatures sent to L1.

Endpoints signed by the sequencer:
- `consumeLock` → `"CONSUME_LOCK:{rollup_id}:{lock_id}:{timestamp}"`
- `submitRoot`  → `"ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{timestamp}"`
- `submitOraclePendingRoot` → `"ORACLE_SUBMIT:{rollup_id}:{market_id}:{outcome}:{merkle_root_hex}:{batch_id}:{ts}:{nonce}"`

---

## Merkle Tree

`sequencer/shared/src/merkle.ts` — hand-rolled SHA-256 sorted-pair tree using **Borsh-canonical serialization**.

### Why Borsh?

UTF-8 string hashing is fragile across language boundaries (integer formatting, whitespace, encoding). Borsh guarantees identical byte layout in both TypeScript and Rust:

- `String` → `u32_LE(len) || utf8_bytes`
- `[u8;32]` → 32 raw bytes (bs58-decoded pubkey, no length prefix)
- `u64` → 8 bytes little-endian

### BB Leaf

```
SHA-256( borsh(rollup_id: String, token: "BB", address: [u8;32], lamports: u64) )
```

### NFT Leaf

```
SHA-256( borsh(rollup_id: String, token: "NFT", collection_id: String,
               token_id: u64, owner: [u8;32], metadata_hash: String) )
```

### Tree Combine

`SHA-256( min(a,b) || max(a,b) )` — sorted to be deterministic regardless of insertion order.

This matches the Rust `ClaimLeaf BorshSerialize` derive in `src/contracts/rollup/mod.rs` exactly.

---

## L2 Settlement Flow

```
User locks $BB on L1
  → POST /rollup/L2/lock_bb  (L1 Rollup Hub)
  → L1 stores RollupLockRecord in ReDB

User calls POST /register-lock on L2 sequencer
  → L2 fetches lock from L1 (GET /rollup/L2/locks/:lock_id)
  → L2 calls consume on L1 (POST /rollup/L2/locks/:lock_id/consume)
  → L2 credits off-chain balance in SQLite

User places bets at L2 speed (POST /markets/:id/bet)
  → Ed25519 signature verified on every bet
  → Balance debited in SQLite atomically

PoH slot tick (every `slotsPerBatch` L1 slots, default 25)
  → batchSealer.ts calls sealAndSubmit()
  → All off-chain balances snapshotted
  → Merkle tree built (Borsh-canonical leaves)
  → If root unchanged → skip (redundant-seal guard)
  → submitRoot() → POST /rollup/L2/submit_root on L1
  → On L1 success: sealBatch() written to SQLite

Market resolved (POST /markets/:id/resolve)
  → resolveMarket() distributes pro-rata payouts in SQLite
  → sealAndSubmit() triggered immediately
  → submitOraclePendingRoot() called fire-and-forget (non-blocking)

User exits (GET /proof/:address → POST /rollup/L2/exit on L1)
  → L2 provides Merkle inclusion proof
  → L1 verifies proof against anchored root
  → L1 releases $BB from rollup vault PDA
```

---

## Durability & Ordering Guarantees

| Property | Implementation |
|---|---|
| **L1 before local** | `submitRoot()` completes before `sealBatch()` writes SQLite. Crash after L1 success = harmless re-anchor on retry (L1 is idempotent for duplicate roots). |
| **No concurrent seals** | `sealChain` promise serialization in `batchSealer.ts` prevents interleaved PoH tick + resolve handler from racing on batch_id. |
| **batchId persistence** | `getLatestBatchId()` reads `MAX(batch_id)` from SQLite — survives restarts without any special seed logic. |
| **Timestamp freshness** | All bets and sequencer calls reject `|now - timestamp| > 60s`. |
| **idempotent lock ingest** | `registerLock()` has 5-step crash-recovery: checks local consumed, verifies L1, handles crash-between-consume-and-credit, consumes, credits. |

---

## Current Gaps vs. the Hardening Plan

The plan authored against `L2_BlackBook` (Rust/ReDB) describes a different implementation.
Here is the accurate gap analysis for **this** TypeScript L2:

### Gap 1 — Nonce Deduplication on `/markets/:id/bet` ❌ MISSING

`server.ts` checks timestamp freshness (`|now - timestamp| > 60s`) but **does not deduplicate nonces**. A bet signed with the same nonce can be replayed within the 60-second TTL window.

**Fix:** Add a `nonces` table to the shared SQLite schema (identical to `l5_nonces` in L5):
```sql
CREATE TABLE IF NOT EXISTS l2_nonces (
  nonce      TEXT    PRIMARY KEY,
  used_at_ts INTEGER NOT NULL DEFAULT (unixepoch())
);
```
Call `recordNonce(db, nonce)` inside a transaction wrapping `placeBet()` in the `/bet` handler. Add a periodic cleanup task (nonces older than 120s are safe to delete).

**Reference:** L5 already does this correctly in `sequencer/l5/src/coins.ts` — `recordNonce()`.

---

### Gap 2 — No WAL Retry for Failed `submitRoot` ❌ MISSING

If `submitRoot()` throws (L1 is down, network timeout), `batchSealer.ts` propagates the error and the batch is not locally sealed. The next PoH tick or seal trigger will attempt a new root (with the same or updated balances), which is correct but means:
- The failed-root batch_id is skipped permanently
- No retry of the specific failed call

**Fix:** Wrap the `submitRoot()` call in `batchSealer.ts` with a simple retry (3 attempts, exponential backoff) before propagating. For persistent failures, log the pending root to a `pending_roots` SQLite table and retry in a background `setInterval` loop.

---

### Gap 3 — `/resolve` and `/markets/:id/lock` Have No Nonce Dedup ⚠️ PARTIAL

`/resolve` verifies the sequencer's Ed25519 signature and checks timestamp freshness, but does not track nonces. Since only the sequencer itself calls `/resolve` (enforced by `public_key !== config.keypair.publicKeyHex` check), replay risk is low — but it should be hardened the same way as `/bet`.

---

### What Does NOT Need Changing

| Concern from original plan | Why it doesn't apply |
|---|---|
| "spawn_blocking for Ed25519" | TypeScript/Node.js is single-threaded; crypto runs in the same event loop with no reactor-blocking issue |
| "Persist l2_block_number across restarts" | `batchId` is read from `MAX(batch_id)` in SQLite — already persistent by design |
| "Persist nonce set to redb" | L2 uses SQLite, not ReDB; schema change is simpler |
| "startup_load() WAL recovery" | No such function exists in the TS sequencer; durability comes from SQLite WAL + L1 idempotency |

---

## File Map

```
sequencer/
  shared/src/
    merkle.ts      — Borsh-canonical SHA-256 Merkle tree (BB + NFT leaves + proofs)
    signing.ts     — signMessage() wrapping @noble/curves/ed25519
    l1Client.ts    — getLock, consumeLock, submitRoot, submitOraclePendingRoot
    db.ts          — SQLite schema (locks, balances, batches, slot_watermark)
    types.ts       — SequencerConfig, BbEntry, L1LockRecord, MerkleEntry, MerkleTree

  l2/src/
    index.ts       — Bootstrap: env vars, config, openL2Db, createServer, startPohLoop
    db.ts          — L2-specific schema: l2_markets, l2_positions
    server.ts      — Express routes: /register-lock, /balances, /proof, /markets, /bet, /resolve, /da
    lockIngest.ts  — registerLock() — 5-step crash-safe lock ingestion
    batchSealer.ts — sealAndSubmit() — serialized seal chain, redundant-seal guard
    markets.ts     — createMarket, placeBet, resolveMarket, getAllBalances
    pohLoop.ts     — WebSocket slot subscription → sealAndSubmit every N slots

  l5/src/
    coins.ts       — recordNonce() reference implementation ← L2 should adopt this pattern
```

---

## Priority Actions (Ranked)

| Priority | Action | File | Effort |
|---|---|---|---|
| **P0** | Add `l2_nonces` table + `recordNonce()` call in `/bet` handler | `shared/src/db.ts`, `l2/src/server.ts` | ~30 min |
| **P1** | Nonce dedup on `/resolve` | `l2/src/server.ts` | ~15 min |
| **P2** | Retry wrapper on `submitRoot()` in `batchSealer.ts` (3× backoff) | `l2/src/batchSealer.ts` | ~45 min |
| **P3** | Persistent `pending_roots` WAL table + background retry loop | `shared/src/db.ts`, `l2/src/batchSealer.ts` | ~2 hrs |
