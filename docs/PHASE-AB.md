# PHASE-AB.md — BlackBook L1 Pre-Launch Hardening

> **Goal:** Ship a secure Writer node to Hetzner by Monday March 3, 2026.
> **Estimated effort:** 8–10 hours for a single developer.
> **Last updated:** 2026-03-01

---

## How to Use This Document

8 fixes, ordered by priority. Work sequentially — each builds on the previous.
After all 8, run the Smoke Test (Section 9) to verify the node is launch-ready.

**What's already done** (from previous sessions):
- ✅ `.gitignore` already excludes `real_wallets/`
- ✅ Replay protection wired (nonce + 60s timestamp window on signed transfers)
- ✅ Faucet capped at 0.1 BB per epoch (was 99,999)
- ✅ No MD5 anywhere in codebase (SHA-256 throughout)
- ✅ ~3,500 lines of dead code removed (`main_v4`, `grpc/`, `proof_of_reserves`, `usdc/`, `consensus/`, `tx_adapter`)
- ✅ Unused deps pruned (`libp2p`, `memmap2`, `void`, `futures`)

---

## PHASE A — "Lock the Doors" (Day 1)

These 4 fixes prevent compromise. Do not deploy without them.

---

### Fix 1 — Remove `real_wallets/` from Dockerfile

**Problem:** The Dockerfile copies plaintext private keys into every container image.

**File:** `Dockerfile` (line 43–44)

#### Current code:

```dockerfile
# Copy real_wallets for genesis accounts
COPY real_wallets/ /app/real_wallets/
```

#### Replace with:

```dockerfile
# Genesis wallet keys injected via environment variables or mounted
# secrets at runtime — never baked into the image.
# COPY real_wallets/ /app/real_wallets/   ← REMOVED (security)
```

Also add environment configuration at the bottom:

```dockerfile
ENV RUST_LOG=info
ENV REDB_PATH=/data/blockchain_data/blockchain.redb
```

**Time: 15 minutes.**

---

### Fix 2 — Gate admin endpoints behind feature flag

**Problem:** Six endpoints allow anyone to mint/burn/migrate tokens with zero authentication:

| Endpoint | Risk |
|----------|------|
| `POST /admin/mint` | Mint unlimited $BB |
| `POST /admin/burn` | Burn from any address |
| `POST /admin/dealer/settle` | Batch mint to any addresses |
| `POST /admin/wallet/migrate` | Move balances between any wallets |
| `GET /admin/accounts` | Dump all addresses + balances |
| `POST /admin/usdc/mint` | Mint unlimited USDC |

The `unsafe_admin` feature flag exists in `Cargo.toml` but is **never checked** in code.

**File:** `src/main.rs` — `build_router()` function

#### What to do:

1. Change the admin route registration to be conditional:

```rust
        // Faucet (public, rate-limited)
        .route("/faucet", post(faucet_handler));

    // Admin endpoints — ONLY available with: cargo run --features unsafe_admin
    #[cfg(feature = "unsafe_admin")]
    let app_routes = app_routes
        .route("/admin/mint", post(admin_mint_handler))
        .route("/admin/burn", post(admin_burn_handler))
        .route("/admin/dealer/settle", post(dealer_settle_handler))
        .route("/admin/wallet/migrate", post(wallet_migrate_handler))
        .route("/admin/accounts", get(admin_accounts_handler))
        .route("/admin/usdc/mint", post(usdc_mint_handler));

    let app_routes = app_routes
        .route("/admin/security/stats", get(security_stats_handler))
```

2. Wrap each admin handler function with `#[cfg(feature = "unsafe_admin")]`:

```rust
#[cfg(feature = "unsafe_admin")]
async fn admin_mint_handler(/* ... */) -> impl IntoResponse {
    // ...existing code...
}
```

Do this for: `admin_mint_handler`, `admin_burn_handler`, `dealer_settle_handler`, `wallet_migrate_handler`, `admin_accounts_handler`, `usdc_mint_handler`.

#### How it works:
- **Development:** `cargo run --features unsafe_admin` — all admin endpoints available
- **Production (Hetzner):** `cargo run` — admin endpoints return 404

**Time: 1 hour.**

---

### Fix 3 — Lock down CORS

**Problem:** CORS is `allow_origin(Any)`. Any website a user visits can make requests to the node.

**File:** `src/main.rs` — `build_router()`

#### Current code:

```rust
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
```

#### Replace with:

```rust
    use axum::http::{Method, HeaderName};
    use tower_http::cors::AllowOrigin;

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "http://localhost:3000".parse().unwrap(),
            "http://localhost:5173".parse().unwrap(),
            "https://app.blackbook.finance".parse().unwrap(),
        ]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-session-token"),
        ]);
```

> Update the production origin to match your actual frontend domain.

**Time: 30 minutes.**

---

### Fix 4 — Authenticate Shard B retrieval with stored PIN hash

**Problem:** `get_shard_b_handler` hashes the PIN then verifies it against **itself** (tautology). The `TODO: compare against stored pin hash` is still open. Anyone who knows a wallet_id can fetch the server-side Shamir share.

**File:** `src/wallet_unified/handlers.rs`

#### Step 4a — Store PIN hash at wallet creation

In `create_wallet_handler`, after generating the wallet, store the PIN hash:

```rust
let pin_hash = super::security::hash_secret(&req.pin);
let metadata = serde_json::json!({
    "pin_hash": pin_hash,
    "created_at": chrono::Utc::now().timestamp(),
    "wallet_version": "v2",
});
let metadata_bytes = serde_json::to_vec(&metadata).unwrap();
state.blockchain.store_wallet_metadata(&wallet_address, &metadata_bytes)
    .map_err(|e| err(format!("metadata storage: {}", e)))?;
```

#### Step 4b — Verify PIN at Shard B retrieval

Replace the current tautology check in `get_shard_b_handler` with:

```rust
    // PIN is REQUIRED
    let pin = match &req.pin {
        Some(p) if !p.is_empty() => p,
        _ => return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "PIN is required to retrieve Shard B"
        })))),
    };

    // Load stored PIN hash from wallet metadata
    let stored_metadata = state.blockchain.get_wallet_metadata(&req.wallet_id)
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Wallet not found"
        }))))?;

    let metadata: serde_json::Value = serde_json::from_slice(&stored_metadata)
        .map_err(|_| err("Wallet metadata corrupted"))?;

    let stored_pin_hash = metadata.get("pin_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("No PIN hash on record"))?;

    if !super::security::verify_secret(pin, stored_pin_hash) {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid PIN"
        }))));
    }
```

**Time: 1 hour.**

---

## PHASE B — "Harden the Vault" (Day 2)

Data integrity and code cleanup before deploy.

---

### Fix 5 — Wire graceful shutdown

**Problem:** When the node receives SIGTERM (Hetzner restart, container stop, Ctrl+C), dirty SVM accounts in the DashMap are lost. `flush_final_block()` exists in `poh_blockchain.rs` (line 672) but is never called.

**File:** `src/main.rs` — shutdown handler

#### What to do:

In the `tokio::signal::ctrl_c()` handler, before exiting:

```rust
tokio::signal::ctrl_c().await.unwrap();
info!("🛑 Shutdown signal received — flushing state...");

// 1. Flush dirty SVM accounts to ReDB
state.blockchain.svm().end_of_block();
info!("✅ SVM accounts flushed to ReDB");

// 2. Produce final PoH block (empty) to seal the chain
let final_slot = state.block_producer.flush_final_block();
info!("✅ Final block produced at slot {}", final_slot);

// 3. Clean exit
info!("👋 BlackBook L1 shutdown complete");
std::process::exit(0);
```

#### Acceptance criteria:
- Start node → produce 10 blocks → Ctrl+C → restart → `getSlot` >= 10
- `getBalance` returns correct post-shutdown values

**Time: 1 hour.**

---

### Fix 6 — Per-account nonce tracking in storage

**Problem:** `storage/mod.rs` hardcodes `nonce: 0` for all transfers with a `// TODO` comment.

**File:** `src/storage/mod.rs`

#### Add to `ConcurrentBlockchain` struct:

```rust
pub account_nonces: DashMap<String, u64>,
```

#### Initialize in constructor:

```rust
account_nonces: DashMap::new(),
```

#### Replace in `transfer()` method:

```rust
// Before:
    0, // nonce - TODO: implement proper nonce tracking

// After:
    {
        let mut entry = self.account_nonces.entry(from.to_string()).or_insert(0);
        *entry.value_mut() += 1;
        *entry.value()
    },
```

**Time: 30 minutes.**

---

### Fix 7 — Remove dead bridge/lock code from storage

**Problem:** ~220 lines of bridge lock system (`BridgeLock`, `LockStatus`, `create_bridge_lock`, `release_bridge_lock`, `get_bridge_lock`) that is never called from anywhere.

**File:** `src/storage/mod.rs`

#### What to delete:

1. `BridgeLock` struct and `LockStatus` enum
2. `create_bridge_lock()` method
3. `release_bridge_lock()` method
4. `get_bridge_lock()` method
5. Any associated ReDB table definitions for bridge locks

Search for `BridgeLock` and `bridge_lock` — delete every match.

**Time: 30 minutes.**

---

### Fix 8 — Remove unreachable TxData variants

**Problem:** `TxData` enum in `protocol/blockchain.rs` has ~8 variants (`Stake`, `Market`, `System`, `Social`, `DKG`, etc.) that are never constructed anywhere. Every transaction in the codebase uses `TxData::Transfer` or `TxData::CreateWallet`. The extra variants add match arm boilerplate throughout the codebase.

**File:** `protocol/blockchain.rs`

#### Reduce TxData to only what's used:

```rust
pub enum TxData {
    Transfer { from: String, to: String, amount: f64 },
    CreateWallet { address: String, username: String },
    Faucet { to: String, amount: f64 },
    Mint { to: String, amount: f64 },           // admin mint
    UsdcMint { to: String, amount: f64 },        // USDC mint
}
```

Then fix any match arms in `main.rs` and `storage/mod.rs` that reference deleted variants (they'll be compiler errors — easy to find and fix).

**Time: 30 minutes.**

---

## 9. Smoke Test Checklist — Run After All 8 Fixes

```powershell
# 1. Build WITHOUT unsafe_admin (production mode)
cargo build --release

# 2. Start the node
cargo run --release

# 3. Health check
Invoke-RestMethod http://localhost:8080/health

# 4. Verify admin endpoints return 404
Invoke-RestMethod http://localhost:8080/admin/mint -Method POST `
    -ContentType "application/json" -Body '{"to":"test","amount":100}'
# Expected: 404 Not Found

# 5. Create a new wallet
Invoke-RestMethod http://localhost:8080/wallet/create -Method POST `
    -ContentType "application/json" `
    -Body '{"username":"smoke_test","password":"TestPass123!","pin":"9999"}'
# Expected: 200 with public_key, shard_a_encrypted, shard_c, mnemonic

# 6. Faucet (should cap at 0.1 BB)
Invoke-RestMethod http://localhost:8080/faucet -Method POST `
    -ContentType "application/json" -Body '{"to":"<pubkey>","amount":100}'
# Expected: minted = 0.1 (capped)

# 7. Check balance
Invoke-RestMethod http://localhost:8080/balance/<pubkey>
# Expected: balance = 0.1

# 8. Shard B WITHOUT pin (should fail)
Invoke-RestMethod http://localhost:8080/wallet/secure/shard-b -Method POST `
    -ContentType "application/json" -Body '{"wallet_id":"<pubkey>"}'
# Expected: 401 "PIN is required"

# 9. Shard B WITH correct pin
Invoke-RestMethod http://localhost:8080/wallet/secure/shard-b -Method POST `
    -ContentType "application/json" -Body '{"wallet_id":"<pubkey>","pin":"9999"}'
# Expected: 200 with shard_b data

# 10. Graceful shutdown test
# Ctrl+C the node → check logs for "SVM accounts flushed" and "Final block produced"
# Restart → verify getSlot returns a value >= previous

# 11. (Optional) Verify with dev admin
cargo run --features unsafe_admin
# Admin endpoints should now return 200
```

---

## 10. Summary — Before vs After

| # | Before | After |
|---|--------|-------|
| 1 | Private keys baked into Docker image | Removed from Dockerfile |
| 2 | Admin endpoints open to internet | Feature-gated (`--features unsafe_admin` only) |
| 3 | CORS allows any origin | Locked to known frontend domains |
| 4 | Shard B available without real auth | PIN required + verified against stored hash |
| 5 | Dirty accounts lost on restart | Graceful shutdown flushes SVM state + seals chain |
| 6 | Nonce always 0 in storage | Per-account nonce counter |
| 7 | ~220 lines of dead bridge code | Removed |
| 8 | ~110 lines of unreachable TxData variants | Removed |

---

## 11. After These 8 Fixes, You Are Ready To:

1. `cargo build --release` (production binary, no admin endpoints)
2. Build Docker image (no secrets baked in)
3. Deploy single Writer node to Hetzner
4. Generate fresh genesis wallets on the live node via `--features unsafe_admin` locally
5. Switch to production build
6. Point DNS + TLS (Caddy/nginx reverse proxy)
7. Smoke test on live URL
8. **Ship it** 🚀

---

*This document reflects the codebase as of 2026-03-01 (v5.0.0).*
*Previous 15-fix version archived — 7 fixes were already completed.*
