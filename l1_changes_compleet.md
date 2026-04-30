# BlackBook L1 — Complete Change Log

> **Last Updated:** 2026-04-29
> **Repo:** `C:\Users\maxd1\Documents\GitHub\L1_BlackBook`
> **Chain:** Custom Rust L1 settlement chain for high-frequency L2 prediction markets
> **Build cmd:** `cargo build --features unsafe_admin` (dev) · `cargo build --release` (prod)

---

## Architecture Overview

| Layer | Component | File | Status |
|-------|-----------|------|--------|
| Consensus | Tower BFT + Gulf Stream mempool | `runtime/consensus.rs` | ✅ Running |
| Clock | Proof of History (PoH) | `runtime/poh_service.rs` | ✅ Running |
| Execution | Sealevel parallel scheduler | `runtime/sealevel.rs` | ✅ Running |
| Propagation | Turbine relay skeleton | `proto/` | 🔧 Architecture only |
| Storage | ReDB + DashMap write-behind cache | `src/storage/mod.rs` | ✅ Running |
| Token engine | Custom SPL (not real Solana SPL) | `src/svm/spl_token.rs` | ✅ Running |
| HTTP API | Axum 0.7 on `:8080` | `src/main.rs` | ✅ Running |
| TPU | UDP bincode on `:8003` (8 workers) | `runtime/tpu.rs` | ✅ Running |

### Three-Token Economy

| Token | Decimals | Unit Constant | Purpose |
|-------|----------|---------------|---------|
| `$BB` | 5 | `LAMPORTS_PER_BB = 100_000` | Native gas + betting collateral |
| `wUSDT` | 6 | `USDC_UNIT = 1_000_000` | Wrapped stablecoin, bonding curve reserve |
| `$MAXX` | 12 | `MAXX_UNIT = 1_000_000_000_000` | Bonding curve governance token |
| `$DECAY` | NFT-like | per-instance | Value-recapture + premium access token |

**Bonding curve:** `P(s) = 5×10⁻⁸ × s`  
**Fixed dealer rate:** 10 BB = 1 wUSDT (dealer market maker, not AMM)

---

## Session 1 — Onramp Safety Hardening (2026-04-26) ✅ COMPLETE

**Mission:** Fix 4 P0 bugs to make the wallet safe for real money before feature work.

### Summary

| Bug | Description | Status |
|-----|-------------|--------|
| #1 | f64 → u64 integer math in deposit path | ✅ **DONE** |
| #2 | Atomic `reserve_bridge_tx` race condition | ✅ **DONE** |
| #3 | Silent deposit drops (no `deposit/request` pre-call) | ✅ **DONE** |
| #4 | BSC `decode_transfer` panic on short hex | ✅ **DONE** |

**Build result:** `cargo check --features unsafe_admin` — 0 errors, warnings only ✅

---

### Bug #1 + #2 — Integer Math + Atomic Reserve

**Files changed:**
- `src/storage/mod.rs`
- `src/contracts/deposit_gateway/mod.rs`
- `src/watcher/mod.rs`
- `src/watcher/bsc_watcher.rs`

**`DepositRecord` struct updated:**
- `amount_stablecoin: f64` → `amount_micro_stablecoin: u64` (6-decimal micro-units)
- `bb_to_mint: f64` → `bb_lamports: u64` (5-decimal lamports)

**New methods on `ConcurrentBlockchain`:**
- `reserve_bridge_tx(tx_hash)` — atomic DashMap `Entry::Vacant` claim, `Err` if already reserved/committed
- `commit_bridge_tx(tx_hash, mint_id)` — write to ReDB FIRST, then update DashMap
- `cancel_bridge_tx(tx_hash)` — remove reservation on mint failure
- `credit_lamports(address, lamports: u64)` — pure integer credit path
- `is_bridge_tx_processed()` updated to filter out `"reserved"` sentinel

All callers updated to use `reserve → credit_lamports → commit/cancel` pattern.  
f64 inputs from HTTP request body are converted at the API boundary only.

---

### Bug #3 — Silent Deposit Drops

**Files changed:**
- `src/storage/mod.rs`
- `src/watcher/mod.rs`
- `src/contracts/deposit_gateway/mod.rs`
- `src/main.rs`

**Problem:** Users who sent stablecoin directly to the custody wallet without first calling `/deposit/request` had their funds silently dropped.

**Solution — three-tier deposit detection in `scan_new_deposits`:**

| Tier | Condition | Action |
|------|-----------|--------|
| 1 | Known `deposit_requests` entry | Existing `verify_and_approve()` path (unchanged) |
| 2 | Unknown tx, valid `BB:<base58>` memo | Auto-create `DepositRecord`, call `verify_and_approve()` |
| 3 | Unknown tx, no valid memo | Queue as `UnattributedDeposit` in ReDB for user to claim |

**New storage additions in `src/storage/mod.rs`:**
- `UNATTRIBUTED_DEPOSITS: TableDefinition<&str, &[u8]>` — ReDB table (initialized at startup)
- `UnattributedDeposit` struct: `external_tx_hash`, `asset`, `amount_micro_stablecoin: u64`, `observed_at: u64`, `claimed_by: Option<String>`
- `write_unattributed_deposit()`, `get_unattributed_deposit()`, `mark_unattributed_claimed()` methods
- `extract_wallet_from_memo(memo: Option<&str>) -> Option<String>` — validates `BB:` prefix, bs58-decodes to verify 32-byte pubkey

**New endpoint `POST /deposit/claim`:**
- Ed25519 auth: message = `"CLAIM_DEPOSIT:{wallet}:{tx_hash}:{ts}:{nonce}"`
- 404 if tx not found in unattributed table
- 409 if already claimed
- Mints BB via `reserve → credit_lamports → commit` atomic pattern
- Calls `mark_unattributed_claimed` in ReDB

---

### Bug #4 — BSC `decode_transfer` Panic on Short Hex

**Files changed:** `src/watcher/bsc_watcher.rs`

**Problem:** Raw string-slicing on hex data panicked if log data was shorter than expected.

**Fix:** Replaced with `hex::decode()` for bounds-checked binary decode. `verify_receipt()` inner log decode also updated to `hex::decode`. Returns `Err` on malformed input — never panics.

---

### Session 1 — Definition of Done

- [x] All 4 bugs fixed
- [x] Race-condition test: 100 threads → exactly 1 winner
- [x] BSC short-hex test: no panics, clean `Err` return
- [x] Integer math: no `f64` in deposit financial paths
- [x] No `.unwrap()` on user-input bytes/strings in `bsc_watcher.rs`
- [x] `cargo build` clean, 0 errors

---

## Phase 2 — Core Ledger Hardening (Planned / In Progress)

Three critical items identified post-Session 1:

### Item 1 — Float Removal: `f64` → `u64` Ledger-Wide

**Scope:** Remaining `f64` usages in non-deposit paths.

**Known locations still using `f64`:**

| File | Location | Issue |
|------|----------|-------|
| `src/storage/mod.rs` | `TransactionRecord.amount`, `.gas_fee`, `.balance_before/after` | Should be `u64` lamports |
| `src/storage/mod.rs` | `credit(amount: f64)` / `debit(amount: f64)` | Convert at boundary, not internally |
| `src/poh_blockchain.rs` | `from_accounts(&BTreeMap<String, f64>)` | Should accept `u64` map |
| `src/poh_blockchain.rs` | `get_all_accounts() -> BTreeMap<String, f64>` | Should return `u64` |
| `src/poh_blockchain.rs` | `verify(balance: f64)` | Should be `u64` |
| `src/contracts/global_escrow/mod.rs` | `EscrowDepositRequest.amount: f64` | Should be `u64` |

**Strategy:**
1. Update `TransactionRecord` fields to `u64` (lowest risk, highest impact)
2. Update Merkle computation chain in `poh_blockchain.rs` to work on `u64` directly
3. Keep `get_balance() -> f64` wrapper only at HTTP response serialization boundary
4. Add `amount_bb()`, `gas_fee_bb()` helper methods for display only

**Rule:** `f64` conversion happens ONCE at HTTP response serialization — never inside financial logic.

---

### Item 2 — Persistence Guarantee: ReDB Before DashMap

**Problem:** Several handlers update DashMap first, then write to ReDB. If the node crashes between these two steps, the in-memory state diverges from the persistent state on restart.

**Files to fix:**

| File | Handler | Current Order | Required Order |
|------|---------|---------------|----------------|
| `src/contracts/global_escrow/mod.rs` | `escrow_submit_state_root_handler` | DashMap → ReDB | ReDB → DashMap |
| `src/contracts/global_escrow/mod.rs` | `escrow_withdraw_handler` | DashMap → ReDB | ReDB → DashMap |
| `src/contracts/deposit_gateway/mod.rs` | deposit record writes | DashMap → ReDB | ReDB → DashMap |
| `src/contracts/withdrawal_gateway/mod.rs` | withdrawal record writes | DashMap → ReDB | ReDB → DashMap |

**Pattern to enforce everywhere:**
```rust
// 1. Persist to ReDB FIRST — if this fails, return 500
if let Err(e) = state.blockchain.store_market_root(&req.market_id, &root_bytes) {
    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e })));
}
// 2. ONLY on success, update DashMap cache
state.market_roots.insert(req.market_id.clone(), root_bytes);
```

---

### Item 3 — L2 State Root Monotonicity

**Problem:** `POST /escrow/submit-state-root` accepts any `l2_block_number` without checking if it's greater than the previously stored value. A buggy or malicious sequencer can regress state.

**Location:** `src/contracts/global_escrow/mod.rs` — `escrow_submit_state_root_handler`

**Fix — add monotonicity guard before storing:**
```rust
if let Ok(Some(existing)) = state.blockchain.load_contest_state(&req.market_id) {
    if req.l2_block_number <= existing.last_l2_block {
        return (StatusCode::CONFLICT, Json(json!({
            "error": "L2 block number not monotonic: cannot regress",
            "incoming": req.l2_block_number,
            "stored": existing.last_l2_block
        })));
    }
}
```

**Also required:** Same check in `src/settlement/mod.rs` → `submit_merkle_root` handler.

**Updated flow:**
```
1. Verify Ed25519 signature ✅
2. Verify zero-sum invariant ✅
3. NEW: Load existing ContestState
4. NEW: Enforce last_l2_block < req.l2_block_number → 409 on failure
5. Store market root + ContestState with new last_l2_block
```

---

## API Reference (Current Endpoints)

### Public — GET

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Node health, PoH clock, consensus, block production |
| `GET /stats` | Runtime stats: pipeline, Gulf Stream, parallel scheduler |
| `GET /supply/audit` | Total supply audit |
| `GET /balance/:address` | Account balance (returns `f64` whole BB units — legacy) |
| `GET /tx/:tx_id` | Transaction details |
| `GET /address/:address/transactions` | Address transaction history |
| `GET /ledger` | Full ledger |
| `GET /poh/status` | PoH clock status |
| `GET /poh/block/latest` | Latest block |
| `GET /poh/block/:slot` | Block by slot |
| `GET /poh/tx/:tx_id/status` | Transaction status |
| `GET /consensus/tower` | Tower BFT stats |
| `GET /turbine/status` | Turbine propagation status |
| `GET /usdc/balance/:address` | wUSDT balance |
| `GET /usdc/supply` | Total wUSDT supply |
| `GET /usdc/accounts/:address` | wUSDT account details |
| `GET /escrow/status` | Escrow vault status |
| `GET /escrow/market/:market_id` | Market settlement details |
| `GET /escrow/contest/:contest_id` | Contest details with deadline |
| `GET /deposit/status/:tx_hash` | Deposit status |
| `GET /withdraw/status/:id` | Withdrawal status |

### State-Changing — POST (all Ed25519 signed)

| Endpoint | Auth Message | Description |
|----------|-------------|-------------|
| `POST /transfer/simple` | `TRANSFER:{from}:{to}:{amount}:{ts}:{nonce}` | BB transfer |
| `POST /faucet` | `FAUCET:{addr}:{amount}:{ts}:{nonce}` | Rate-limited faucet |
| `POST /sealevel/submit` | — | Submit Sealevel transaction |
| `POST /usdc/transfer` | — | wUSDT transfer |
| `POST /escrow/deposit` | — | Lock BB in escrow vault |
| `POST /escrow/submit-state-root` | — | L2 sequencer submits Merkle root |
| `POST /escrow/withdraw` | — | User withdrawal with Merkle proof |
| `POST /deposit/request` | — | Pre-register deposit intent |
| `POST /deposit/claim` | `CLAIM_DEPOSIT:{wallet}:{tx_hash}:{ts}:{nonce}` | Claim unattributed deposit |
| `POST /withdraw/request` | — | Withdrawal request |
| `POST /swap/bb-to-usdc` | `SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}` | Swap BB → wUSDT |
| `POST /swap/usdc-to-bb` | — | Swap wUSDT → BB |

### Admin Endpoints (feature = `unsafe_admin` only)

| Endpoint | Description |
|----------|-------------|
| `POST /admin/mint` | Raw BB minting |
| `POST /admin/burn` | Raw BB burning |
| `POST /admin/usdc/mint` | Mint wUSDT to any address |
| `POST /admin/dealer/send_wusdt` | Seed dealer liquidity |

### UDP TPU — Port 8003

- **Protocol:** Bincode binary, 8 parallel workers
- **QoS:** 5 000 packets/sec per IP (silent drop over limit)
- **`TpuPacket.amount` is `u64` lamports** — divide by `100_000.0` ONLY at display
- Processing pipeline: QoS → deserialize → chain ID check → TTL → sig verify → nonce → balance → dispatch

---

## Security Rules (Non-Negotiable)

1. **All user input** — decode with proper error returns, never `.unwrap()` on user data
2. **Nonce check+insert** — always use DashMap `entry()` API (atomic, no TOCTOU race)
3. **ReDB writes before DashMap** — persist to disk FIRST, update in-memory cache AFTER
4. **Replay protection** — nonce stored in `state.used_nonces: DashMap<String, u64>`
5. **Timestamp freshness** — reject transactions older than 60 seconds
6. **Rate limiting** — `NetworkThrottler.max_per_window = 10` per wallet per window
7. **No `f64` in financial math** — integer types only; `f64` ONLY at final HTTP response boundary

---

## L2 Settlement Flow

```
L2 bets → Dealer aggregates → settle_market_and_generate_root(winners)
→ SHA-256 sorted-pair Merkle tree → 32-byte root
→ POST /escrow/submit-state-root  (L2 sequencer signed)
→ Users withdraw via POST /escrow/withdraw  (with Merkle proof)
```

**Merkle leaf:** `SHA256(address_utf8 || payout_u64_le)`  
**Merkle combine:** `SHA256(min(a,b) || max(a,b))` (sorted for determinism)  
**Claim deadline:** 6 480 000 slots ≈ 30 days

---

## Phase Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 1** | 4 P0 onramp bugs (Session 1) | ✅ Complete |
| **Phase 2** | Float removal + persistence guarantee + L2 monotonicity | 🔧 Planned |
| **Phase 3** | `/wrapped/swap` endpoint, `/deposit/status` improvements | ⏳ Queued |
| **Phase 4** | Frontend deposit loop + toast system (wallet repo) | ⏳ Queued |
| **Phase 5** | Lightning gateway, advanced L2 features | ⏳ Deferred |
