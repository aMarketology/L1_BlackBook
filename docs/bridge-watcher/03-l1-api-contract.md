# 03 — L1 API Contract

This is the exact interface between the Bridge Watcher and the BlackBook L1.
Everything here is **verified against the current Rust source** in
`src/contracts/deposit_gateway/mod.rs` and `src/svm/types.rs`.

> The watcher is a client of these endpoints. The endpoints are the trust
> boundary; the watcher never bypasses them.

---

## 1. Units & conversion (source of truth)

| Token | Decimals | Unit constant | Notes |
|---|---|---|---|
| `USDC` / `USDT` (Solana SPL) | 6 | `USDT_UNIT = 1_000_000` | "micro" units |
| `$BB` (L1 native) | 5 | `LAMPORTS_PER_BB = 100_000` | "lamports" |

**Conversion is done by L1, not the watcher.** L1 applies:

```
bb_lamports = micro * LAMPORTS_PER_BB * rate / USDT_UNIT      (u128 intermediate)
```

where `rate = SWAP_RATES["BB_USDT"]` (genesis default `BB_PER_USDT_DEFAULT = 10`).
Source: `micro_stable_to_bb_lamports_at()` in `src/svm/types.rs`.

> The watcher passes **`amount_micro_stablecoin: u64`** and the **asset string**.
> It must **never** pre-compute BB amounts — that keeps the rate authority in L1
> and avoids float drift (consistent with the edge-boundary integer discipline).

---

## 2. Existing endpoints (Model B — user-originated, available today)

### `POST /deposit/request`  (user-signed)

Creates a pending `DepositRecord` and triggers immediate on-chain verification.
**Signed by the user's wallet key**, so the watcher cannot originate this — it is
called by the wallet UI. The watcher's job for Model B is to ensure the
referenced tx finalizes and gets approved.

Request body (`DepositRequestBody`):

```jsonc
{
  "wallet_address": "<base58 BB address>",
  "external_tx_hash": "<solana signature>",
  "asset": "USDC" | "USDT",
  "amount_micro_stablecoin": 1000000,        // u64, 6-dec micro units
  "public_key": "<hex, 32 bytes>",           // must derive to wallet_address
  "signature": "<hex, 64 bytes>",
  "timestamp": 1716950000,                    // within 60s of server time
  "nonce": "<random string>"
}
```

Canonical signed message:

```
DEPOSIT_REQUEST:{wallet_address}:{external_tx_hash}:{amount_micro_stablecoin}:{asset}:{timestamp}:{nonce}
```

Responses: `200` (`status: "pending"` or instantly `"approved"` if verified),
`400` invalid input, `401` bad signature / pubkey mismatch, `409` nonce reused or
tx already minted, `503` gateway not configured.

### `GET /deposit/status/:tx_hash`

Polled by the watcher (Model B) to observe whether L1 has approved. Returns
`found`, `status` (`pending` | `approved`), and amounts.

### `POST /admin/deposit/approve`  (`#[cfg(feature = "unsafe_admin")]`)

Body (`DepositApproveBody`): `{ "external_tx_hash": "<sig>" }`.
Mints BB for a pending record after off-chain verification. **Protected by the
`unsafe_admin` build feature today** — i.e. *not* production-safe as an
authenticated endpoint. This is the gap the bridge-authority work closes (below).

---

## 3. New endpoint to add — `POST /bridge/deposit` <a id="bridge-authority"></a>

Model A needs an endpoint the **watcher** can authenticate to without the user's
key and without the blanket `unsafe_admin` feature. Proposed contract:

```jsonc
// POST /bridge/deposit   — signed by the BRIDGE AUTHORITY key
{
  "external_tx_hash": "<solana signature>",
  "wallet_address": "<base58 BB address, from memo>",
  "asset": "USDC" | "USDT",
  "amount_micro_stablecoin": 1000000,
  "timestamp": 1716950000,
  "nonce": "<random>",
  "public_key": "<bridge authority pubkey, hex>",
  "signature": "<hex, 64 bytes>"
}
```

Canonical message (to be implemented in `src/auth.rs` / deposit gateway):

```
BRIDGE_DEPOSIT:{external_tx_hash}:{wallet_address}:{amount_micro_stablecoin}:{asset}:{timestamp}:{nonce}
```

**Server-side behavior (must mirror the existing approve path):**

1. Verify the signature is from the configured `BRIDGE_AUTHORITY_PUBKEY`.
2. Reject stale timestamp (>60s) and reused nonce (atomic `entry()` insert).
3. `is_bridge_tx_processed(tx_hash)` → `409` if already minted.
4. **Re-verify the transfer on Solana** (amount within tolerance + asset + dest =
   custody + finalized) using the existing `CustodyWatcher::verify_transaction`.
5. `reserve_bridge_tx` → `credit_lamports(wallet, bb_lamports)` → `commit_bridge_tx`
   (the exact reserve-before-mint sequence already in `deposit_approve_handler`).
6. Record PoH tx + `TransactionRecord::with_id(... TxType::BridgeIn ...)`.

> This endpoint is **not** built yet. Until it exists, the watcher operates in
> Model B (drive-finalization) only. Building it is milestone M3 in
> [07-implementation-plan.md](07-implementation-plan.md).

---

## 4. Endpoints the watcher consumes — summary table

| Method | Path | Auth | Used in | Built? |
|---|---|---|---|---|
| `GET` | `/health` | none | liveness check of L1 | ✅ |
| `GET` | `/deposit/status/:tx_hash` | none | Model B polling | ✅ |
| `POST` | `/deposit/request` | user Ed25519 | Model B (wallet UI, not watcher) | ✅ |
| `POST` | `/admin/deposit/approve` | `unsafe_admin` build flag | local testing only | ✅ (dev) |
| `POST` | `/bridge/deposit` | **bridge-authority Ed25519** | Model A (target) | ❌ to build (M3) |

---

## 5. Double-mint guarantee (L1-side, already implemented)

Regardless of which endpoint is used, L1 enforces **at-most-once** mint via the
`PROCESSED_BRIDGE_TXS` ReDB table and the `reserve → credit → commit /
cancel` sequence:

- `reserve_bridge_tx(tx_hash)` claims the hash **before** crediting (no TOCTOU).
- `credit_lamports` mints integer lamports (no f64).
- `commit_bridge_tx` finalizes; on mint failure `cancel_bridge_tx` releases the reservation.

The watcher therefore treats a `409 already-processed` as **success** (idempotent
no-op), never as an error to alert on.

---

## 6. Writer-only constraint (topology)

Mints are **writes**. In the 1-writer/N-reader topology, the watcher must call
the **writer's** HTTP base URL (`L1_WRITER_URL`), not a reader replica. Reader
nodes proxy writes to the writer anyway (`reader_proxy_middleware`), but the
watcher should target the writer directly to avoid an extra hop and to fail fast
if the writer is unavailable.
