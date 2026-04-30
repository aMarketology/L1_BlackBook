# BlackBook L1 — Copilot Instructions

## What This Codebase Is

BlackBook is a custom Layer 1 blockchain written in Rust (v5.0.0, edition 2021).
It is NOT Solana, NOT Ethereum. It is a purpose-built settlement chain for high-frequency
L2 prediction markets. Architecture is heavily inspired by Solana internals but fully
custom-implemented:

- **Proof of History (PoH)** clock in `runtime/poh_service.rs`
- **Sealevel parallel execution** (read/write lock scheduling) in `runtime/sealevel.rs`
- **Gulf Stream** mempool in `runtime/consensus.rs`
- **Tower BFT** consensus in `runtime/consensus.rs`
- **Turbine** block propagation (architecture defined, relay skeleton in `proto/`)
- **SPL Token engine** (custom, not the real Solana one) in `src/svm/spl_token.rs`
- **ReDB** as the persistent KV store (`blockchain_data/blockchain.redb`)
- **DashMap** for in-memory state (write-behind cache over ReDB)
- **Axum 0.7** HTTP server on `:8080`
- **UDP TPU** on `:8003` (bincode binary protocol, 8 workers)

---

## Three-Token Economy

| Token | Decimals | Unit Constant | Purpose |
|-------|----------|---------------|---------|
| `$BB` | 5 | `LAMPORTS_PER_BB = 100_000` | Native gas token, betting collateral |
| `wUSDT` | 6 | `USDC_UNIT = 1_000_000` | Wrapped stablecoin, bonding curve reserve |
| `$XX` / MAXXCOIN | 12 | `MAXX_UNIT = 1_000_000_000_000` | Bonding curve governance token |
| `$DECAY` | NFT-like | per-instance | Value-recapture token, premium access |

**Bonding curve**: `P(s) = SLOPE × s` where `SLOPE = 5×10⁻⁸`, s = total $XX supply in whole units.
**BB ↔ wUSDT fixed rate**: 10 BB = 1 wUSDT (dealer market maker, not AMM).

---

## Critical Type Rules — NEVER Violate These

1. **ALL financial math uses integer types** (`u64` / `u128`). Never use `f64` for balances,
   amounts, or arithmetic. Convert to `f64` ONLY at the final display/API boundary.
2. **`get_balance()` returns `f64`** (whole BB units, legacy). Use `get_balance_lamports() -> u64`
   for financial logic.
3. **`TpuPacket.amount` is `u64` lamports** (NOT BB floats). Divide by `100_000.0` only at
   RuntimeTx/PipelinePacket dispatch.
4. **SPL token amounts** are always raw micro-units: `u64` for wUSDT, `u64` for $XX picoMAXX.
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
- MAXX buy: `"MAXX_BUY:{from}:{microUsdt}:{ts}:{nonce}"`
- MAXX sell: `"MAXX_SELL:{from}:{picoMaxx}:{ts}:{nonce}"`
- DECAY mint: `"DECAY_MINT:{from}:{backing_usdt}:{ts}:{nonce}"`
- Swap BB→wUSDT: `"SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}"`
- Faucet: `"FAUCET:{addr}:{amount}:{ts}:{nonce}"`

Rate limiting follows auth: `state.throttler.check_transaction(&wallet, 0.0)` → HTTP 429.

---

## Key File Map

```
src/
  main.rs                      — AppState, all HTTP routes, startup bootstrap
  auth.rs                      — Shared Ed25519 verify helper
  svm/
    spl_token.rs               — SPL Token engine (mint, burn, transfer, ATA)
    types.rs                   — LAMPORTS_PER_BB, USDC_UNIT, MAXX_UNIT, MAXX_DECIMALS
    mod.rs                     — Re-exports all svm symbols
  contracts/
    maxx_token/mod.rs          — $XX bonding curve buy/sell handlers
    decay_token/mod.rs         — $DECAY mint/use/recharge/stake handlers
    token_swap/mod.rs          — BB ↔ wUSDT fixed-rate swap handlers
    global_escrow/mod.rs       — L2 prediction market escrow + Merkle settlement
    deposit_gateway/mod.rs     — Bridge-in: deposit stablecoin → mint BB
    withdrawal_gateway/mod.rs  — Bridge-out: burn BB → release stablecoin
    layer2_market/mod.rs       — Merkle tree root generation for L2 settlements
  storage/mod.rs               — ConcurrentBlockchain, TransactionRecord, ReDB ops

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
  test_scripts/test_xx_bb.ts   — Integration test: full BB + $XX lifecycle
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

## Conventions

- Prefer `tracing::info!` / `warn!` / `error!` — not `println!`
- Handler return type: `impl IntoResponse` via `(StatusCode, Json(..)).into_response()`
- Error responses: `Json(serde_json::json!({ "error": "..." }))` — always JSON
- `AppState` is `Arc`-wrapped, cloned into all handlers via `State(state): State<AppState>`
- Feature flags: `#[cfg(feature = "unsafe_admin")]` wraps admin-only routes
