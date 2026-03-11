# PHASE-AB.md — BlackBook L1 Pre-Launch Security Hardening

> **Goal:** Fix all P0 and P1 blockers so the chain is safe to deploy on a single  
> node and onboard the first 50 US-based users.  
> **Estimated effort:** 5–7 days for a single developer.  
> **Date:** 2026-02-27

---

## How to Use This Document

Each fix is numbered, self-contained, and ordered by priority.  
Work through them **sequentially** — Fix 1 must land before Fix 2, etc.  
Every fix shows the **exact file, the current code, and the replacement code**.

After completing all 15 fixes, run the **Smoke Test Checklist** (Section 16) to verify the node is launch-ready.

---

## PHASE A — "Lock the Doors" (Day 1–2)

These 5 fixes prevent total compromise. Do not deploy without them.

---

### Fix 1 — Remove secrets from Git history

**Problem:** `real_wallets/` contains plaintext passwords, PINs, 24-word mnemonics, and raw Ed25519 keypairs for all 5 wallets (Max, Alice, Bob, Apollo, Dealer). The folder is **not** in `.gitignore`. If this repo has ever been public, those keys are permanently burned.

**Files:**
- `.gitignore`
- `real_wallets/*.json` (all 5 wallet files + `Max_keypair.json`)

#### Step 1a — Add to `.gitignore`

Append these lines to the bottom of `.gitignore`:

```gitignore
# Wallet secrets — never commit
real_wallets/
*.keypair.json
```

#### Step 1b — Remove from tracking (keep local copies)

```powershell
git rm -r --cached real_wallets/
git commit -m "security: remove wallet secrets from tracking"
```

#### Step 1c — Scrub Git history

Install [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) and run:

```powershell
# From OUTSIDE the repo
java -jar bfg.jar --delete-folders real_wallets --no-blob-protection L1_BlackBook.git
cd L1_BlackBook
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

#### Step 1d — Rotate ALL keys

Every key in the old `real_wallets/` is compromised. After the history scrub:

1. Generate **new** wallets via `POST /wallet/create` for each user
2. Use `POST /admin/wallet/migrate` to move balances from old → new addresses
3. Store the new wallet files **outside** the repo (e.g., encrypted USB, 1Password vault)
4. Update the hardcoded addresses in `src/main.rs` `account_name()` (lines 148–162)

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

The `unsafe_admin` feature flag already exists in `Cargo.toml` but is **never checked**.

**File:** `src/main.rs` — `build_router()` function (around line 1534)

#### Current code (lines 1567–1578):

```rust
        // Admin (Dealer)
        // Faucet (public)
        .route("/faucet", post(faucet_handler))
        // Admin (Dealer)
        .route("/admin/mint", post(admin_mint_handler))
        .route("/admin/burn", post(admin_burn_handler))
        .route("/admin/dealer/settle", post(dealer_settle_handler))
        .route("/admin/wallet/migrate", post(wallet_migrate_handler))
        .route("/admin/accounts", get(admin_accounts_handler))
        .route("/admin/security/stats", get(security_stats_handler))
        // USDC SPL Token
        .route("/admin/usdc/mint", post(usdc_mint_handler))
```

#### Replace with:

```rust
        // Faucet (public, rate-limited)
        .route("/faucet", post(faucet_handler));

    // Admin endpoints — ONLY available when compiled with: cargo run --features unsafe_admin
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

#### How it works:

- **Development:** `cargo run --features unsafe_admin` — all admin endpoints available
- **Production:** `cargo run` — admin endpoints don't exist (404)

#### After this fix, also gate the handler functions:

Wrap each admin handler with `#[cfg(feature = "unsafe_admin")]`:

```rust
#[cfg(feature = "unsafe_admin")]
async fn admin_mint_handler(/* ... */) -> impl IntoResponse {
    // ...existing code...
}
```

Do this for: `admin_mint_handler`, `admin_burn_handler`, `dealer_settle_handler`, `wallet_migrate_handler`, `admin_accounts_handler`, `usdc_mint_handler`.

---

### Fix 3 — Lock down CORS

**Problem:** CORS is `allow_origin(Any) + allow_methods(Any) + allow_headers(Any)`. Combined with admin endpoints (even after Fix 2 for dev builds), any website a user visits can make requests to the node.

**File:** `src/main.rs` — `build_router()` (line 1536)

#### Current code:

```rust
fn build_router(state: AppState, wallet_router: Router) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
```

#### Replace with:

```rust
fn build_router(state: AppState, wallet_router: Router) -> Router {
    use axum::http::{Method, HeaderName};
    use tower_http::cors::AllowOrigin;

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "http://localhost:3000".parse().unwrap(),      // Local dev frontend
            "http://localhost:5173".parse().unwrap(),      // Vite dev server
            "https://app.blackbook.finance".parse().unwrap(), // Production frontend
        ]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-session-token"),
        ]);
```

> **Note:** Update the production origin to match your actual frontend domain. Add additional origins as needed.

---

### Fix 4 — Enforce nonce / replay protection on signed transfers

**Problem:** `signed_transfer_handler` verifies Ed25519 signatures but never checks or records the nonce. The `used_nonces` DashMap in `AppState` is created but **never written to**. A valid signed transaction can be replayed infinitely.

**File:** `src/main.rs` — `signed_transfer_handler` (around line 340)

#### Current code (after signature verification succeeds, around line 378):

```rust
    if verifying_key.verify(&message, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // Execute transfer
    let from = &req.wallet_address;
    let balance = state.blockchain.get_balance(from);
```

#### Replace with:

```rust
    if verifying_key.verify(&message, &signature).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Signature verification failed" })));
    }

    // ── REPLAY PROTECTION ──────────────────────────────────────────────
    // Check nonce hasn't been used before (key = "address:nonce")
    let nonce_key = format!("{}:{}", req.wallet_address, req.nonce);
    if state.used_nonces.contains_key(&nonce_key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({
            "error": "Nonce already used — possible replay attack",
            "nonce": req.nonce
        })));
    }

    // Check timestamp freshness (reject transactions older than 60 seconds)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(req.timestamp) > 60 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Transaction too old (>60s)",
            "server_time": now,
            "tx_time": req.timestamp
        })));
    }

    // Record nonce BEFORE executing transfer (fail-safe: better to reject a valid tx
    // than to allow a replay)
    state.used_nonces.insert(nonce_key, now);

    // Prune old nonces (keep map bounded)
    if state.used_nonces.len() > 100_000 {
        let cutoff = now.saturating_sub(120); // remove entries older than 2 minutes
        state.used_nonces.retain(|_, &mut ts| ts > cutoff);
    }

    // Execute transfer
    let from = &req.wallet_address;
    let balance = state.blockchain.get_balance(from);
```

---

### Fix 5 — Authenticate Shard B retrieval with stored PIN hash

**Problem:** The `get_shard_b_handler` hashes the user's PIN, then verifies it against **itself** (a tautology). The `TODO: compare against stored pin hash` is still open. Anyone who knows a wallet_id can fetch the server-side Shamir share without authentication.

This fix requires two changes: (a) store the PIN hash at wallet creation, (b) verify against it at retrieval.

#### Step 5a — Store PIN hash at wallet creation

**File:** `src/wallet_unified/handlers.rs` — `create_wallet_handler`

Find the section where Shard B is stored in ReDB (the `store_frost_share_b` call). Before that call, also store the PIN hash in the wallet metadata.

Add a `pin` field to the wallet creation request struct:

```rust
#[derive(Deserialize)]
pub struct CreateWalletRequest {
    pub username: String,
    pub password: String,
    pub pin: String,           // ← ADD THIS FIELD
}
```

After generating the wallet, store the PIN hash alongside the shard:

```rust
// Hash PIN for future Shard B gating
let pin_hash = super::security::hash_secret(&req.pin);

// Store PIN hash in wallet metadata
let metadata = serde_json::json!({
    "pin_hash": pin_hash,
    "created_at": chrono::Utc::now().timestamp(),
    "wallet_version": "v2",
});
let metadata_bytes = serde_json::to_vec(&metadata).map_err(|e| err(format!("metadata: {}", e)))?;
state.blockchain.store_wallet_metadata(&wallet_address, &metadata_bytes)
    .map_err(|e| err(format!("metadata storage: {}", e)))?;
```

> **Note:** `store_wallet_metadata` already exists in `storage/mod.rs` — it writes to the `WALLET_METADATA` ReDB table.

#### Step 5b — Verify PIN hash at Shard B retrieval

**File:** `src/wallet_unified/handlers.rs` — `get_shard_b_handler` (line 438)

#### Current code:

```rust
pub async fn get_shard_b_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    _headers: HeaderMap,
    Json(req): Json<GetShardBRequest>,
) -> Result<Json<ShardBResponse>, (StatusCode, Json<serde_json::Value>)> {
    // PIN validation (if provided)
    if let Some(ref pin) = req.pin {
        let pin_hash = super::security::hash_secret(pin);
        // TODO: compare against stored pin hash for this wallet
        // For now, verify the hash is well-formed (exercises the security module)
        if !super::security::verify_secret(pin, &pin_hash) {
            return Err(err("PIN validation failed"));
        }
        info!("\u{1f512} PIN provided for shard B retrieval: {}", req.wallet_id);
    } else {
        info!("\u{26a0}\u{fe0f} Shard B retrieved WITHOUT PIN for {}", req.wallet_id);
    }
    
    let container_bytes = state.blockchain.get_frost_share_b(&req.wallet_id)
```

#### Replace with:

```rust
pub async fn get_shard_b_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    _headers: HeaderMap,
    Json(req): Json<GetShardBRequest>,
) -> Result<Json<ShardBResponse>, (StatusCode, Json<serde_json::Value>)> {
    // ── PIN REQUIRED ────────────────────────────────────────────────
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
        .ok_or_else(|| err("No PIN hash on record — wallet created before PIN enforcement"))?;

    // Verify PIN against stored hash
    if !super::security::verify_secret(pin, stored_pin_hash) {
        warn!("🚫 Invalid PIN attempt for shard B: {}", req.wallet_id);
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid PIN"
        }))));
    }

    info!("🔐 PIN verified — releasing Shard B for {}", req.wallet_id);

    let container_bytes = state.blockchain.get_frost_share_b(&req.wallet_id)
```

---

## PHASE B — "Harden the Vault" (Day 3–7)

These fixes prevent data integrity issues, pipeline bypasses, and operational failures.

---

### Fix 6 — Replace MD5 with SHA-256 for transaction hashing

**Problem:** `TransactionRecord::new()` uses `md5::compute()` for tx hashes. MD5 is cryptographically broken — collision attacks are trivial. Two different transactions could produce the same hash.

**File:** `src/storage/mod.rs` — `TransactionRecord::new()` (around line 244)

#### Current code:

```rust
        // Compute transaction hash
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx_id, tx_type, from, to, amount, timestamp, nonce
        );
        let tx_hash = format!("{:x}", md5::compute(hash_input.as_bytes()));
```

#### Replace with:

```rust
        // Compute transaction hash (SHA-256 — cryptographically secure)
        use sha2::{Sha256, Digest};
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx_id, tx_type, from, to, amount, timestamp, nonce
        );
        let hash_bytes = Sha256::digest(hash_input.as_bytes());
        let tx_hash = format!("{:x}", hash_bytes);
```

> `sha2` is already in your dependencies. After this, you can remove `md5` from `Cargo.toml` if no other code uses it (search for `md5::` to verify).

---

### Fix 7 — Wire real Ed25519 verification into the transaction pipeline

**Problem:** The 4-stage pipeline in `poh_service.rs` fakes signature verification:

```rust
// Current (line ~327):
let signature_valid = !packet.from.is_empty() && packet.amount >= 0.0;
```

This passes **everything**. The pipeline is used for Gulf Stream submissions (not `signed_transfer_handler`), but once wired into block production, this becomes a critical hole.

**File:** `runtime/poh_service.rs` — `spawn_sigverify_stage()` (around line 300)

#### Current code (inside the spawn_sigverify_stage tokio::spawn block):

```rust
            while let Some(packet) = sigverify_rx.recv().await {
                // Simulate signature verification
                let start = Instant::now();
                // In production: verify Ed25519 signature against packet.from pubkey
                let signature_valid = !packet.from.is_empty() && packet.amount >= 0.0;
```

#### Replace with:

```rust
            while let Some(packet) = sigverify_rx.recv().await {
                let start = Instant::now();

                // Real Ed25519 signature verification
                let signature_valid = if packet.signature.is_empty() || packet.from.is_empty() {
                    false
                } else {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    (|| -> Result<bool, Box<dyn std::error::Error>> {
                        let pubkey_bytes = hex::decode(&packet.from)?;
                        if pubkey_bytes.len() != 32 { return Ok(false); }
                        let sig_bytes = hex::decode(&packet.signature)?;
                        if sig_bytes.len() != 64 { return Ok(false); }
                        let vk = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into()?)?;
                        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into()?);
                        // Verify against the serialized payload
                        let msg = format!("{}:{}:{}", packet.from, packet.to, packet.amount);
                        Ok(vk.verify(msg.as_bytes(), &sig).is_ok())
                    })().unwrap_or(false)
                };
```

> **Note:** The message format (`from:to:amount`) must match what the SDK signs. Coordinate with Fix 13 (SDK alignment). For now this is a reasonable default that can be refined.

---

### Fix 8 — Reduce faucet limit for mainnet

**Problem:** The faucet allows 99,999 BB per address per epoch. For a mainnet with real value, this is far too generous.

**File:** `src/main.rs` — `faucet_handler` (line 749)

#### Current code:

```rust
/// POST /faucet — Mint up to 99,999 BB to any address (rate-limited per epoch)
async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    const MAX_FAUCET_BB: f64 = 99_999.0;
```

#### Replace with:

```rust
/// POST /faucet — Mint up to 10 BB to any address (rate-limited per epoch)
///
/// For mainnet beta testing. Reduce or remove entirely before full launch.
async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    const MAX_FAUCET_BB: f64 = 10.0;
```

Also update the error messages further down in the function that reference "99,999" to say "10".

---

### Fix 9 — Implement nonce tracking in storage layer

**Problem:** `storage/mod.rs` hardcodes `nonce: 0` for all transfers with a `// TODO` comment. The in-memory nonce map from Fix 4 handles HTTP-level replay protection, but the storage layer should also track per-account nonces for auditability.

**File:** `src/storage/mod.rs` — `transfer()` method (around line 833)

#### Current code:

```rust
        let tx_record = TransactionRecord::new(
            TxType::Transfer,
            from,
            to,
            amount,
            0, // nonce - TODO: implement proper nonce tracking
            from_balance_before,
            from_balance,
            to_balance,
            auth_type,
        );
```

#### Replace with:

```rust
        // Increment per-account nonce for ordering + audit
        let nonce = {
            let mut entry = self.account_nonces.entry(from.to_string()).or_insert(0);
            *entry.value_mut() += 1;
            *entry.value()
        };

        let tx_record = TransactionRecord::new(
            TxType::Transfer,
            from,
            to,
            amount,
            nonce,
            from_balance_before,
            from_balance,
            to_balance,
            auth_type,
        );
```

#### Also add the nonce map to `ConcurrentBlockchain`:

In the struct definition (around line 290 in storage/mod.rs), add:

```rust
    /// Per-account nonce counter (address → next_nonce)
    pub account_nonces: DashMap<String, u64>,
```

And in the `new()` / `open()` constructor, initialize it:

```rust
    account_nonces: DashMap::new(),
```

---

### Fix 10 — Persist USDC reserve and gRPC replay protection to ReDB

**Problem:** Three critical data structures are in-memory only and lost on restart:

| Structure | File | Impact if lost |
|-----------|------|----------------|
| `USDCReserve` (deposits/withdrawals) | `src/usdc/reserve.rs` | Reserve tracking resets — can't prove solvency |
| `used_nonces` (gRPC) | `src/grpc/mod.rs` | All replay protection resets — settled bets can be re-settled |
| `settled_bets` (gRPC) | `src/grpc/mod.rs` | Same — double-settlement possible |

#### Minimum viable fix:

Add a new ReDB table for each and flush on every write.

**File:** `src/storage/mod.rs` — Add table definitions:

```rust
/// USDC reserve deposit records
const USDC_DEPOSITS: TableDefinition<&str, &[u8]> = TableDefinition::new("usdc_deposits");

/// gRPC settled bet IDs (for idempotency across restarts)
const SETTLED_BETS: TableDefinition<&str, u64> = TableDefinition::new("settled_bets");
```

Then add methods to `ConcurrentBlockchain`:

```rust
/// Record a settled bet ID (persists across restarts)
pub fn record_settled_bet(&self, bet_id: &str, timestamp: u64) -> Result<(), String> {
    let write_txn = self.db.begin_write().map_err(|e| e.to_string())?;
    {
        let mut table = write_txn.open_table(SETTLED_BETS).map_err(|e| e.to_string())?;
        table.insert(bet_id, timestamp).map_err(|e| e.to_string())?;
    }
    write_txn.commit().map_err(|e| e.to_string())?;
    Ok(())
}

/// Check if a bet has already been settled
pub fn is_bet_settled(&self, bet_id: &str) -> bool {
    let read_txn = match self.db.begin_read() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let table = match read_txn.open_table(SETTLED_BETS) {
        Ok(t) => t,
        Err(_) => return false,
    };
    table.get(bet_id).ok().flatten().is_some()
}
```

Then update `src/grpc/mod.rs` to call these methods instead of (or in addition to) the in-memory DashMap.

---

### Fix 11 — Remove `real_wallets/` from Dockerfile

**Problem:** The Dockerfile copies `real_wallets/` into the production image, baking private keys into every container.

**File:** `Dockerfile` (line 44)

#### Current code:

```dockerfile
# Copy real_wallets for genesis accounts
COPY real_wallets/ /app/real_wallets/
```

#### Replace with:

```dockerfile
# NOTE: Genesis wallet keys are injected via environment variables or mounted
# secrets at runtime — never baked into the image.
# COPY real_wallets/ /app/real_wallets/   ← REMOVED (security)
```

If the node needs genesis accounts at boot, load them from environment variables or a mounted Docker secret volume instead.

---

### Fix 12 — Verify oracle signature on USDC deposits

**Problem:** `src/usdc/reserve.rs` — `record_deposit()` accepts an `oracle_signature` field but never validates it. Anyone who can call the function can fabricate USDC deposits.

**File:** `src/usdc/reserve.rs` — `record_deposit()`

#### Add before recording the deposit:

```rust
// Verify oracle attestation signature
if oracle_signature.is_empty() {
    return Err("Oracle signature required for USDC deposit".to_string());
}

// Verify Ed25519 signature from known oracle pubkey
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
let oracle_pubkey = std::env::var("USDC_ORACLE_PUBKEY")
    .map_err(|_| "USDC_ORACLE_PUBKEY not configured")?;
let oracle_key_bytes = hex::decode(&oracle_pubkey)
    .map_err(|_| "Invalid oracle pubkey hex")?;
let vk = VerifyingKey::from_bytes(oracle_key_bytes.as_slice().try_into()
    .map_err(|_| "Oracle pubkey must be 32 bytes")?)
    .map_err(|_| "Invalid oracle pubkey")?;

let message = format!("{}:{}:{}", user_l1_address, usdc_amount, external_tx_hash);
let sig_bytes = hex::decode(&oracle_signature)
    .map_err(|_| "Invalid oracle signature hex")?;
let sig = Signature::from_bytes(sig_bytes.as_slice().try_into()
    .map_err(|_| "Oracle signature must be 64 bytes")?);

vk.verify(message.as_bytes(), &sig)
    .map_err(|_| "Oracle signature verification failed")?;
```

Set the oracle public key as an environment variable:

```powershell
$env:USDC_ORACLE_PUBKEY = "<hex-encoded-ed25519-pubkey>"
```

---

### Fix 13 — Fix SDK endpoint mismatches

**Problem:** `sdk/wallet_sdk.js` calls 3 endpoints that don't exist on the server and has a route mismatch for transfers.

**File:** `sdk/wallet_sdk.js`

#### Issues to fix:

| SDK Method | Calls | Reality | Fix |
|------------|-------|---------|-----|
| `backupShardA()` | `POST /wallet/backup-shard-a` | Does not exist | Remove method or implement endpoint |
| `restoreShardA()` | `POST /wallet/restore-shard-a` | Does not exist | Remove method or implement endpoint |
| `recoverShardC()` | `POST /wallet/secure/recover-shard-c` | Does not exist | Remove method or implement endpoint |
| `transfer()` | `POST /wallet/transfer` | Actual route is `/transfer/simple` | Fix to `/transfer/simple` |

#### Recommended approach for launch:

**Option A (fastest — recommended):** Remove the three unimplemented methods from the SDK and add a comment that they're coming in v2. Fix the transfer route.

In `wallet_sdk.js`, find the `transfer()` method and change the URL:

```javascript
// BEFORE:
const response = await fetch(`${this.baseUrl}/wallet/transfer`, {

// AFTER:
const response = await fetch(`${this.baseUrl}/transfer/simple`, {
```

For the 3 recovery methods, add a guard:

```javascript
async backupShardA(sessionToken, shardAEncrypted) {
    throw new Error('backupShardA: Not yet implemented on the L1 server. Store Shard A client-side (localStorage / Supabase).');
}
```

**Option B (robust — recommended for 50-user launch):** Implement the 3 missing endpoints in `src/wallet_unified/handlers.rs`. Since Shard A and C are purely client-side per the `UNIFIED_WALLET.md` architecture, these endpoints should be simple pass-through storage in ReDB for users who opt-in to server-side backup.

---

### Fix 14 — Add TLS termination notes

**Problem:** Both HTTP (8080) and gRPC (50051) run over plaintext. All data including signed transactions, wallet shards, and balances travel unencrypted.

#### For Railway deployment (recommended):

Railway automatically provides TLS termination. No code change needed — just ensure the deploy uses HTTPS URLs in the SDK:

```javascript
const wallet = new BlackBookWallet('https://your-app.railway.app');
```

#### For self-hosted deployment:

Put nginx or Caddy in front:

```nginx
server {
    listen 443 ssl;
    server_name l1.blackbook.finance;

    ssl_certificate     /etc/letsencrypt/live/l1.blackbook.finance/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/l1.blackbook.finance/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

For gRPC, add TLS to the tonic server in `src/relay/mod.rs` or use a gRPC-aware proxy.

---

### Fix 15 — Remove `real_wallets/` Dockerfile bake + environment config

**File:** `Dockerfile` — Add proper environment documentation:

After removing the `COPY real_wallets/` line (Fix 11), add these ENV defaults:

```dockerfile
# Environment configuration
ENV RUST_LOG=info
ENV REDB_PATH=/data/blockchain_data/blockchain.redb
# Set these at runtime via Railway Variables or docker run -e
# ENV USDC_ORACLE_PUBKEY=<hex>
# ENV ADMIN_TOKEN=<random-256-bit-hex>
```

---

## 16. Smoke Test Checklist — Run After All Fixes

After implementing all 15 fixes, run through this checklist on a clean node:

```powershell
# 1. Build WITHOUT unsafe_admin (production mode)
cargo build --release

# 2. Start the node
cargo run --release

# 3. Health check
Invoke-RestMethod http://localhost:8080/health

# 4. Verify admin endpoints return 404
Invoke-RestMethod http://localhost:8080/admin/mint -Method POST -ContentType "application/json" -Body '{"to":"test","amount":100}'
# Expected: 404 Not Found

# 5. Create a new wallet
Invoke-RestMethod http://localhost:8080/wallet/create -Method POST -ContentType "application/json" -Body '{"username":"test_user","password":"TestPass123!","pin":"9999"}'
# Expected: 200 with public_key, shard_a_encrypted, shard_c, mnemonic

# 6. Faucet (should cap at 10 BB)
Invoke-RestMethod http://localhost:8080/faucet -Method POST -ContentType "application/json" -Body '{"to":"<public_key_from_step_5>","amount":100}'
# Expected: minted = 10.0 (capped)

# 7. Check balance
Invoke-RestMethod http://localhost:8080/balance/<public_key_from_step_5>
# Expected: balance = 10.0

# 8. Test Shard B WITHOUT pin (should fail)
Invoke-RestMethod http://localhost:8080/wallet/secure/shard-b -Method POST -ContentType "application/json" -Body '{"wallet_id":"<public_key>"}'
# Expected: 401 "PIN is required"

# 9. Test Shard B WITH correct pin
Invoke-RestMethod http://localhost:8080/wallet/secure/shard-b -Method POST -ContentType "application/json" -Body '{"wallet_id":"<public_key>","pin":"9999"}'
# Expected: 200 with shard_b data

# 10. Test CORS (from browser console on a random domain)
# fetch('http://localhost:8080/health').then(r => r.json()).then(console.log)
# Expected: CORS error (blocked by browser)

# 11. Test replay protection — send same signed tx twice
# Second call should return 409 "Nonce already used"

# 12. Verify with dev admin (rebuild with feature flag)
cargo run --features unsafe_admin
# Admin endpoints should now return 200
```

---

## Summary — Before vs After

| # | Before | After |
|---|--------|-------|
| 1 | Plaintext keys in git | Scrubbed + rotated |
| 2 | Admin endpoints open to internet | Feature-gated, only in dev builds |
| 3 | CORS allows any origin | Locked to known frontend domains |
| 4 | Signed txs replayable forever | Nonce + timestamp window enforced |
| 5 | Shard B available without auth | PIN required + verified against stored hash |
| 6 | MD5 tx hashes (collision-vulnerable) | SHA-256 |
| 7 | Pipeline accepts all txs as "verified" | Real Ed25519 sig verification |
| 8 | Faucet mints 99,999 BB per epoch | Capped at 10 BB |
| 9 | Nonce always 0 in storage | Per-account nonce counter |
| 10 | Replay protection lost on restart | Persisted to ReDB |
| 11 | Private keys baked into Docker image | Removed from Dockerfile |
| 12 | Oracle signature accepted but never checked | Ed25519 verification required |
| 13 | SDK calls nonexistent endpoints | Fixed routes + guarded stubs |
| 14 | All traffic plaintext | TLS via reverse proxy |
| 15 | No env-based config for secrets | Environment variable pattern |

---

**After these 15 fixes, you are ready to:**
1. Deploy a single writer node to Railway
2. Create fresh genesis wallets with new mnemonics
3. Fund them via `cargo run --features unsafe_admin` locally
4. Switch to production build (`cargo build --release`) 
5. Onboard your first 50 users with real Shamir wallets

*This document reflects the codebase as of 2026-02-27 (v5.0.0).*
