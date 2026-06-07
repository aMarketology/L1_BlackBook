# BlackBook L1 — Copilot Instructions

## What This Codebase Is

BlackBook is a **Consortium / Permissioned Layer 1** blockchain written in Rust (engine v5.0.0, release v1.0.1, edition 2021).
It is NOT Solana, NOT Ethereum. It is a purpose-built, high-frequency settlement chain for L2
prediction markets — modeled after institutional-grade private networks (Visa backbone, Swift, HFT
settlement rails), NOT a permissionless public chain. Only cryptographically whitelisted validator
nodes may participate in consensus or receive block shreds.

**Core identity:** the L1 is an **asset-custody ledger, state machine, and transaction execution
environment** — nothing else. Its only relationship with keys is to (1) store a balance against a
public key, (2) receive an Ed25519-signed transaction, and (3) verify the signature before
executing. It NEVER generates, holds, or transmits user private keys or mnemonics — those are
created and kept client-side only. Do NOT add fiat onramps, key-generation endpoints, or any
custodial key handling to the L1.

Architecture is heavily inspired by
Solana internals but fully custom-implemented:

- **Proof of History (PoH)** clock in `runtime/poh_service.rs`
- **Sealevel parallel execution** (read/write lock scheduling) in `runtime/sealevel.rs`
- **Gulf Stream** mempool in `runtime/consensus.rs`
- **Tower BFT** consensus in `runtime/consensus.rs`
- **Turbine** permissioned shred gossip — whitelisted VIP mesh only in `runtime/turbine.rs`
- **SPL Token engine** (custom, not the real Solana one) in `src/svm/spl_token.rs`
- **ReDB** as the persistent KV store (`blockchain_data/blockchain.redb`)
- **DashMap** for in-memory state (write-behind cache over ReDB)
- **Axum 0.7** HTTP server on `:8080`
- **UDP TPU** on `:8003` (bincode binary protocol, 8 workers)

---

## Token Economy

| Token | Decimals | Unit Constant | Purpose |
|-------|----------|---------------|---------|
| `$BB` | 5 | `LAMPORTS_PER_BB = 100_000` | Native gas token, betting collateral, oracle staking |
| `wUSDT` | 6 | `USDC_UNIT = 1_000_000` | Wrapped stablecoin, swap reserve |

**BB ↔ wUSDT fixed rate**: 10 BB = 1 wUSDT (dealer market maker, not AMM).
**MAXX / DECAY / OZ**: removed from L1. Archived in `archive/contracts/`. Do NOT add them back.

---

## Critical Type Rules — NEVER Violate These

1. **ALL financial math uses integer types** (`u64` / `u128`). Never use `f64` for balances,
   amounts, or arithmetic. Convert to `f64` ONLY at the final display/API boundary.
2. **`get_balance()` returns `f64`** (whole BB units, legacy). Use `get_balance_lamports() -> u64`
   for financial logic.
3. **`TpuPacket.amount` is `u64` lamports** (NOT BB floats). Divide by `100_000.0` only at
   RuntimeTx/PipelinePacket dispatch.
4. **SPL token amounts** are always raw micro-units: `u64` for wUSDT.
5. **`TransactionRecord::with_id()`** — all amount/balance params are `u64`. Never pass `f64`.

---

## Authentication Pattern

Every state-changing POST endpoint uses Ed25519 via `src/auth.rs`:
```
verify_signed_action(state, "ACTION_NAME", from, public_key, signature, timestamp, nonce, body)
```

Canonical message format: `"ACTION:{from}:{body}:{timestamp}:{nonce}"`

Specific formats:
- Transfer: `"TRANSFER:{from}:{to}:{amount}:{ts}:{nonce}"`
- Swap BB→wUSDT: `"SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}"`
- Faucet: `"FAUCET:{addr}:{amount}:{ts}:{nonce}"`
- Rollup lock BB: `"ROLLUP_LOCK_BB:{rollup_id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"`
- Rollup consume lock: `"CONSUME_LOCK:{rollup_id}:{lock_id}:{ts}"`
- Rollup submit root: `"ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{ts}"`
- Rollup exit BB: `"ROLLUP_EXIT:{rollup_id}:BB:{address}:{batch_id}:{ts}:{nonce}"`
- Rollup exit NFT: `"ROLLUP_EXIT:{rollup_id}:NFT:{address}:{batch_id}:{ts}:{nonce}"`

Rate limiting follows auth: `state.throttler.check_transaction(&wallet, 0.0)` → HTTP 429.

---

## Key File Map

```
src/
  main.rs                      — AppState, all HTTP routes, startup bootstrap
  auth.rs                      — Shared Ed25519 verify helper
  svm/
    spl_token.rs               — SPL Token engine (mint, burn, transfer, ATA)
    types.rs                   — LAMPORTS_PER_BB, USDC_UNIT
    pda.rs                     — PDA derivation: rollup_vault_address(rollup_id)
    mod.rs                     — Re-exports: SplTokenEngine, usdc_*, LAMPORTS_PER_BB
  contracts/
    token_swap/mod.rs          — BB ↔ wUSDT fixed-rate swap handlers
    global_escrow/mod.rs       — L2 prediction market escrow + Merkle settlement
    deposit_gateway/mod.rs     — Bridge-in: deposit stablecoin → mint BB
    withdrawal_gateway/mod.rs  — Bridge-out: burn BB → release stablecoin
    layer2_market/mod.rs       — Merkle tree root generation for L2 settlements
    oracle/mod.rs              — Oracle node registration, dispute ($BB staking), vote
    oracle/finalize.rs         — Background task: auto-finalize expired roots
    rollup/mod.rs              — Universal Rollup Hub: lock_bb, submit_root, exit (BB+NFT)
    nft_bridge/mod.rs          — L3 NFT anchoring on L1 (put_nft, get_nft, AnchoredNft)
  storage/mod.rs               — ConcurrentBlockchain, TransactionRecord, ReDB ops

archive/contracts/             — ARCHIVED: maxx_token, decay_token, oz_token (do not restore)

runtime/
  core.rs                      — NetworkThrottler, CircuitBreaker, RuntimeTx, TransactionType
  tpu.rs                       — UDP TPU (TpuPacket: amount is u64 lamports)
  sealevel.rs                  — Parallel execution engine (read/write lock scheduler)
  poh_service.rs               — PoH clock, PipelinePacket, TransactionPipeline
  consensus.rs                 — GulfStreamService, TowerBFT

sdk/
  dealer.sdk.ts                — TypeScript SDK for L2 Dealer (Merkle, escrow, settlement)

blackbook-wallet/
  src/                         — React + TypeScript frontend wallet
```

---

## Build & Run

```powershell
# Development (with admin endpoints for seeding test liquidity)
cargo build --features unsafe_admin
.\target\debug\layer1.exe

# Production (no unsafe admin)
cargo build --release
.\target\release\layer1.exe
```

**The `unsafe_admin` feature** enables:
- `POST /admin/usdc/mint` — mint wUSDT to any address
- `POST /admin/dealer/send_wusdt` — seed dealer liquidity
- `POST /admin/mint` / `/admin/burn` — raw BB minting

**MAXX/wUSDT mints bootstrap automatically** at startup using a deterministic genesis
authority if `USDC_MINT_AUTHORITY` env var is not set. Always idempotent.

**Required env vars for Universal Rollup Hub:**
- `L2_SEQUENCER_PUBKEY` — 64-char hex Ed25519 pubkey for the L2 sequencer
- `L3_SEQUENCER_PUBKEY` — 64-char hex Ed25519 pubkey for the L3 sequencer
- `L5_SEQUENCER_PUBKEY` — 64-char hex Ed25519 pubkey for the L5 sequencer

If a sequencer env var is not set, that rollup's `submit_root` and `consume_lock`
endpoints return HTTP 503 (sequencer disabled), but `lock_bb` and `exit` still work.

---

## Security Rules

1. **All user input** — decode with proper error returns, never `.unwrap()` on user data.
2. **Nonce check+insert** — always use DashMap `entry()` API (atomic, no TOCTOU race).
3. **ReDB writes before DashMap** — persist to disk FIRST, update in-memory cache AFTER.
4. **Replay protection** — nonce stored in `state.used_nonces: DashMap<String, u64>`.
5. **Timestamp freshness** — reject transactions older than 60 seconds.
6. **Rate limiting** — `NetworkThrottler.max_per_window = 10` per wallet per window.

---

## L2 Settlement Flow

```
L2 bets → Dealer aggregates → settle_market_and_generate_root(winners)
→ SHA-256 sorted-pair Merkle tree → 32-byte root
→ POST /escrow/submit-state-root (L2 sequencer signed)
→ Users withdraw via POST /escrow/withdraw (with Merkle proof)
```

Merkle leaf: `SHA256(address_utf8 || payout_u64_le)`
Merkle combine: `SHA256(min(a,b) || max(a,b))` (sorted to be deterministic)

---

## Universal Rollup Hub (L2 / L3 / L5)

URL shape: `/rollup/:rollup_id/<action>` where `:rollup_id` is `"L2"`, `"L3"`, or `"L5"`.

| Endpoint | Purpose |
|---|---|
| `POST /rollup/:rollup_id/lock_bb` | User locks $BB into the per-rollup vault PDA |
| `GET  /rollup/:rollup_id/locks/:lock_id` | Sequencer reads a lock record |
| `POST /rollup/:rollup_id/locks/:lock_id/consume` | Sequencer marks lock as spent |
| `POST /rollup/:rollup_id/submit_root` | Sequencer anchors a new Merkle state root |
| `POST /rollup/:rollup_id/exit` | User exits assets back to L1 with Merkle proof |

**Canonical Merkle leaf encoding (sequencer must match exactly):**
```
BB leaf:   SHA-256( "{rollup_id}:BB:{address}:{balance_lamports}" )
NFT leaf:  SHA-256( "{rollup_id}:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}" )
```

**Exit `asset_type`**: `"BB"` releases lamports from vault → user. `"NFT"` calls `nft_bridge::put_nft()` to mint on L1.

**ReDB tables:**
- `ROLLUP_STATE_ROOTS: &str → &[u8]` — key: `"{rollup_id}:{batch_id:020}"` (zero-padded monotonic)
- `ROLLUP_CONSUMED_EXITS: &str → u64` — key: `SHA256("{rollup_id}:{batch_id}:{asset_type}:{address|collection:token}")` — permanent double-spend seal
- `ROLLUP_LOCKS: &str → &[u8]` — key: lock UUID → `RollupLockRecord` JSON

**AppState field:** `authorized_sequencers: Arc<DashMap<String, String>>` maps `rollup_id` → 64-char hex pubkey.

---

## Conventions

- Prefer `tracing::info!` / `warn!` / `error!` — not `println!`
- Handler return type: `impl IntoResponse` via `(StatusCode, Json(..)).into_response()`
- Error responses: `Json(serde_json::json!({ "error": "..." }))` — always JSON
- `AppState` is `Arc`-wrapped, cloned into all handlers via `State(state): State<AppState>`
- Feature flags: `#[cfg(feature = "unsafe_admin")]` wraps admin-only routes
