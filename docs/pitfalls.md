# Pitfalls & Gotchas

Known traps and doc-vs-code discrepancies found while auditing the source.
Treat these as **actionable** — several are real bugs that will bite a
developer or operator.

---

## 1. NFT `token_id` type mismatch (BUG — exit proofs can fail)

**Severity: high.** The Rust and TypeScript disagree on the NFT leaf's
`token_id` type:

- Rust `NftClaimLeaf.token_id` is `&str` (Borsh encodes as `u32_LE(len) || utf8`).
- TypeScript `merkle.ts` `serializeNftLeaf` writes `tokenId` as **`u64`**
  (8 bytes LE, via `borshWriteU64`).

These produce different leaf bytes, so an NFT exit proof built by the current
TypeScript sequencer will **fail L1 `verify_merkle_proof`** for NFT exits.
BB exits are unaffected (no `token_id` field).

**Action:** align one side. Either change the TS `serializeNftLeaf` to
`borshWriteString(buf, tokenId)` (matching Rust `&str`), or change Rust
`token_id` to `u64` and update `NftClaimLeaf` + `nft_leaf_hash` callers. Confirm
against `sequencer/l3/src/batchSealer.ts` (which passes `tokenId: string`) and
the Rust `exit_handler` (`req.nft_token_id`).

---

## 2. `NODE_MODE` env var is dead config

`.env` sets `NODE_MODE=reader`, but the node **ignores** this env var. Mode is
selected by the **`--mode` CLI flag** only (`--mode writer|reader|validator`).

A developer reading `.env` will assume the node runs as a reader; it will
actually run in whatever the CLI says (default writer). **Action:** always pass
`--mode` explicitly; treat `.env`'s `NODE_MODE` as misleading.

---

## 3. `USDC_MINT_AUTHORITY` empty → fallback warning

If `USDC_MINT_AUTHORITY` is unset/empty, the node logs
`"Invalid USDC_MINT_AUTHORITY"` and bootstraps the wUSDT mint with a
deterministic genesis authority. This is fine for dev but means real wUSDT
minting control is **not** under your key. **Action:** set a real mint authority
for any non-toy deployment.

---

## 4. Faucet cap is 0.1 BB per epoch

`MAX_FAUCET_BB = 0.1`. Too small for real multi-token testing (a swap at 10 BB =
1 wUSDT needs >10 BB to get 1 wUSDT). **Action:** seed test wallets with
`GENESIS_SEEDS` (format `addr:lamports`, comma-separated) or use `unsafe_admin`
`POST /admin/mint` in dev builds.

---

## 5. `get_balance()` returns `f64`, not lamports

`/balance/:address` returns whole-BB `f64`. Any financial logic built on it is
lossy. Use lamports endpoints / `get_balance_lamports()`.

---

## 6. UDP ports do not traverse consumer NAT

TPU `:8003` and Turbine `:8004` are UDP. They won't reach the public internet
behind a home router without explicit forwarding, and generally should **not**
be exposed publicly (permissioned consortium mesh). Public-facing traffic should
go through TLS-fronted HTTP (`:8080`) + JSON-RPC (`:8899`).

---

## 7. `L5_SEQUENCER_PUBKEY` commonly unset → L5 disabled

Missing sequencer pubkey for a rollup → its `submit_root` / `consume_lock`
return `503`. `lock_bb` and `exit` still work. Local `.env` setups frequently
leave `L5_SEQUENCER_PUBKEY` unset. **Action:** set all three (`L2`/`L3`/`L5`)
if you exercise the full hub.

---

## 8. ReDB-before-DashMap ordering

Durability rule: persist to ReDB **first**, then update the in-memory DashMap
hot-state. A crash between the two leaves disk and memory consistent on restart.
Do not invert this.

---

## 9. Timestamp freshness windows

- Standard auth: ±60s (`MAX_TIMESTAMP_AGE_SECS`).
- Some payout/settlement paths use ±120s.

A client whose clock drifts, or that signs a request and then waits too long to
send, gets `400 Request expired`. Sign-and-send immediately.

---

## 10. Nonce must be fresh & unique

Reused nonce → `409 Conflict`. Nonces are scoped per `action:from`. Generate a
new nonce per request (e.g. `crypto.randomUUID()`); do not reuse across retries
unless you intend the request to be idempotent-but-rejected.

---

## 11. Integer formatting in signed messages

The signed message is a plain decimal string. Formatting like `1e6`, leading
zeros, or `+` breaks the signature. Always emit integers as plain ASCII decimal
(`1000000`, not `1e6`).

---

## 12. Transfer vs. action signing schemes differ

`/transfer` uses `[chain_id_byte] + payload + "\n" + ts + "\n" + nonce`. All
other action endpoints use `"{ACTION}:{from}:{body}:{ts}:{nonce}"`. Do not mix
the two. See [Authentication](authentication.md).

---

## 13. Merkle leaves are Borsh, not string concatenation

Older docs described leaves as `"{id}:BB:{addr}:{lamports}"` string hashes. The
**actual** encoding is Borsh (see [Merkle Proofs](merkle-proofs.md)). A proof
built from the string-concatenation form will not verify.

---

## 14. L2 market engine is binary-only (YES/NO)

`sequencer/l2/src/markets.ts` types `BetSide = 'YES' | 'NO'` and
`MarketOutcome = 'YES' | 'NO'`. N-way outcomes (e.g. MLS Survivor elimination
pools, Amazing Race winner) cannot be expressed without extending the market
engine. This is L2-scope but blocks the upcoming event use-cases.

## 15. L2 market creation is unauthenticated (TODO in code)

`sequencer/l2/src/server.ts` `POST /markets` has an explicit
`// TODO: restrict to oracle / admin key in production`. Any caller who can
reach the sequencer can create a market with an arbitrary `market_id` /
`question`. Until this is gated, the market registry is not trust-minimized.
`/markets/:id/lock` and `/markets/:id/resolve` are also not yet oracle-gated in
the same way (`lock` has no auth at all; `resolve` checks the sequencer key but
the market creator is unrestricted).
