# Step-by-Step Guide: Implementing Session-Scoped Key Cache for BlackBook L1 Wallet

This guide outlines the step-by-step process to implement a 15-minute session-scoped key cache in the Rust backend. This allows the frontend wallet to perform fast-path transactions without requiring the user's password or Shard A for every transfer.

---

## Step 1: Add Required Dependencies to `Cargo.toml`

Add the following crates to your `Cargo.toml` (skip any you already have):

```toml
dashmap = "6"
aes-gcm = "0.10"
uuid = { version = "1", features = ["v4"] }
hex = "0.4"
rand = "0.8"
```

---

## Step 2: Create the Session Store Module

Create a new file `src/wallet_unified/session_store.rs`.
*Note: We are caching the 32-byte seed (`[u8; 32]`), not the full 64-byte keypair, to match the existing `handlers.rs` logic.*

```rust
use dashmap::DashMap;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::RngCore;
use std::time::{Duration, Instant};
use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_secs(15 * 60); // 15 minutes

pub struct SessionBlob {
    pub encrypted_seed: Vec<u8>,      // AES-256-GCM(seed_32, session_key)
    pub nonce: [u8; 12],              // GCM nonce
    pub wallet_id: String,
    pub created_at: Instant,
    pub ttl: Duration,
}

/// In-memory session store. One per node instance.
pub struct SessionStore {
    sessions: DashMap<String, SessionBlob>,  // session_token → blob
}

impl SessionStore {
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    /// Create a session: encrypt the 32-byte seed with a random SK,
    /// store the blob, return (session_token, session_key_hex).
    pub fn create_session(
        &self,
        wallet_id: &str,
        seed_bytes: &[u8; 32],
    ) -> (String, String) {
        self.revoke_by_wallet(wallet_id);

        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&session_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, seed_bytes.as_ref())
            .expect("AES-GCM encryption failed");

        let session_token = Uuid::new_v4().to_string();

        self.sessions.insert(session_token.clone(), SessionBlob {
            encrypted_seed: encrypted,
            nonce: nonce_bytes,
            wallet_id: wallet_id.to_string(),
            created_at: Instant::now(),
            ttl: SESSION_TTL,
        });

        (session_token, hex::encode(session_key))
    }

    /// Decrypt the seed using the session token + session key.
    pub fn decrypt_session(
        &self,
        session_token: &str,
        session_key_hex: &str,
    ) -> Result<[u8; 32], String> {
        let blob = self.sessions.get(session_token)
            .ok_or("Session not found or expired")?;

        if blob.created_at.elapsed() > blob.ttl {
            drop(blob);
            self.sessions.remove(session_token);
            return Err("Session expired".to_string());
        }

        let session_key = hex::decode(session_key_hex)
            .map_err(|_| "Invalid session key")?;
        if session_key.len() != 32 {
            return Err("Session key must be 32 bytes".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(&session_key)
            .map_err(|_| "Invalid session key")?;
        let nonce = Nonce::from_slice(&blob.nonce);
        let seed_vec = cipher.decrypt(nonce, blob.encrypted_seed.as_ref())
            .map_err(|_| "Session key mismatch — decryption failed")?;

        let mut seed_32 = [0u8; 32];
        if seed_vec.len() == 32 {
            seed_32.copy_from_slice(&seed_vec);
            Ok(seed_32)
        } else {
            Err("Invalid seed length in session".to_string())
        }
    }

    pub fn refresh_session(&self, session_token: &str) {
        if let Some(mut blob) = self.sessions.get_mut(session_token) {
            blob.created_at = Instant::now();
        }
    }

    pub fn revoke(&self, session_token: &str) {
        self.sessions.remove(session_token);
    }

    pub fn revoke_by_wallet(&self, wallet_id: &str) {
        self.sessions.retain(|_, blob| blob.wallet_id != wallet_id);
    }

    pub fn sweep_expired(&self) {
        self.sessions.retain(|_, blob| blob.created_at.elapsed() <= blob.ttl);
    }
}
```

---

## Step 3: Expose the Module

In `src/wallet_unified/mod.rs`, add the new module:

```rust
pub mod handlers;
pub mod migration;
pub mod security;
pub mod session_store; // <-- ADD THIS
```

---

## Step 4: Wire the Store into `UnifiedWalletState`

In `src/wallet_unified/handlers.rs`, update `UnifiedWalletState` to include the `SessionStore` and spawn the background sweeper task.

```rust
use crate::wallet_unified::session_store::SessionStore;

#[derive(Clone)]
pub struct UnifiedWalletState {
    pub blockchain: Arc<ConcurrentBlockchain>,
    pub supabase: Arc<SupabaseManager>,
    pub vault: Arc<VaultManager>,
    pub block_producer: Arc<BlockProducer>,
    pub session_store: Arc<SessionStore>, // <-- ADD THIS
}

impl UnifiedWalletState {
    pub fn new(
        blockchain: Arc<ConcurrentBlockchain>,
        supabase: Arc<SupabaseManager>,
        vault: Arc<VaultManager>,
        block_producer: Arc<BlockProducer>,
    ) -> Self {
        let session_store = Arc::new(SessionStore::new());
        
        // Spawn background sweeper
        let store_clone = session_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                store_clone.sweep_expired();
            }
        });

        info!("✅ Unified Wallet initialized with ReDB storage & Supabase Vault & HashiCorp Vault");
        Self { blockchain, supabase, vault, block_producer, session_store }
    }
}
```

---

## Step 5: Add a Login Endpoint (`POST /wallet/login`)

In `src/wallet_unified/handlers.rs`, add a new handler that reconstructs the seed, creates a session, and returns the tokens.

```rust
#[derive(Deserialize)]
pub struct LoginRequest {
    pub wallet_id: String,
    pub shard_1: String,
    pub shard_2: String,
    pub password: Option<String>,
    pub shard_2_is_server_encrypted: Option<bool>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub wallet_id: String,
    pub session_token: String,
    pub session_key: String,
}

pub async fn login_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Decode / decrypt shard 1
    let shard_1_bytes = if let Some(ref password) = req.password {
        security::decrypt_with_secret(password, &req.shard_1)
            .map_err(|e| err(format!("Failed to decrypt Shard 1: {}", e)))?
    } else {
        hex::decode(&req.shard_1).map_err(|_| err("Invalid hex for Shard 1"))?
    };

    // 2. Decode / decrypt shard 2
    let shard_2_bytes = if req.shard_2_is_server_encrypted.unwrap_or(false) {
        let master_key = get_server_master_key()?;
        security::decrypt_with_secret(&master_key, &req.shard_2)
            .map_err(|e| err(format!("Failed to decrypt Shard 2: {}", e)))?
    } else {
        hex::decode(&req.shard_2).map_err(|_| err("Invalid hex for Shard 2"))?
    };

    // 3. Reconstruct seed
    let shark = Sharks(2u8);
    let share_a = Share::try_from(shard_1_bytes.as_slice()).map_err(|_| err("Malformed Shard 1"))?;
    let share_b = Share::try_from(shard_2_bytes.as_slice()).map_err(|_| err("Malformed Shard 2"))?;
    let mut seed_bytes = shark.recover(&[share_a, share_b]).map_err(|e| err(format!("SSS reconstruction failed: {}", e)))?;

    if seed_bytes.len() < 32 {
        return Err(err("Reconstructed seed too short"));
    }

    let mut seed_32: [u8; 32] = seed_bytes[..32].try_into().unwrap();
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

    if derived_address != req.wallet_id {
        seed_32.zeroize();
        seed_bytes.zeroize();
        return Err(err("Derived address does not match. Wrong shards or password."));
    }

    // 4. Create Session
    let (session_token, session_key) = state.session_store.create_session(&req.wallet_id, &seed_32);

    // 5. Zeroize
    seed_32.zeroize();
    seed_bytes.zeroize();

    Ok(Json(LoginResponse {
        success: true,
        wallet_id: req.wallet_id,
        session_token,
        session_key,
    }))
}
```

---

## Step 6: Modify `transfer_with_sss` to Return Session Tokens

In `src/wallet_unified/handlers.rs`, inside `transfer_with_sss`, right before zeroizing `seed_32`, create a session and update the JSON response.

```rust
    // ... existing code ...
    let sig_hex = hex::encode(signature.to_bytes());

    // ── ADD THIS: Create session after password-auth transfer ────
    let (session_token, session_key) = state.session_store.create_session(&req.from_wallet_id, &seed_32);
    // ──────────────────────────────────────────────────────────────

    // Zeroize key material immediately after signing
    seed_32.zeroize();
    // ... existing code ...
```

And update the JSON response to include the new fields:

```rust
    Ok(Json(json!({
        "success": true,
        "signature": sig_hex,
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
        "from_balance": state.blockchain.get_balance(&req.from_wallet_id),
        "to_balance": state.blockchain.get_balance(&req.to_address),
        "session_token": session_token,
        "session_key": session_key
    })))
```

---

## Step 7: Add the Fast-Path `POST /transfer/session` Endpoint

In `src/wallet_unified/handlers.rs`, add the new handler for session-based transfers:

```rust
#[derive(Deserialize)]
pub struct SessionTransferRequest {
    pub from_wallet_id: String,
    pub to_address: String,
    pub amount: f64,
    pub session_token: String,
    pub session_key: String,
}

pub async fn transfer_session_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<SessionTransferRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if req.amount <= 0.0 {
        return Err(err("Amount must be positive"));
    }
    let balance = state.blockchain.get_balance(&req.from_wallet_id);
    if balance < req.amount {
        return Err(err(format!("Insufficient balance: {} < {}", balance, req.amount)));
    }

    // 1. Decrypt seed from session store
    let mut seed_32 = state.session_store
        .decrypt_session(&req.session_token, &req.session_key)
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(json!({ "error": e }))))?;

    // 2. Derive Keypair
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

    if derived_address != req.from_wallet_id {
        seed_32.zeroize();
        return Err(err("Session key does not match wallet"));
    }

    // 3. Sign the transfer message
    let tx_message = format!("{}:{}:{}", req.from_wallet_id, req.to_address, req.amount);
    let signature = signing_key.sign(tx_message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // 4. Zeroize
    seed_32.zeroize();

    // 5. Execute transfer on-chain
    state.blockchain.transfer_with_receipt(
        &req.from_wallet_id,
        &req.to_address,
        req.amount,
        &sig_hex,
        crate::storage::AuthType::SessionKey,
    ).map_err(|e| err(format!("Transfer failed: {}", e)))?;

    // Record in PoH block
    {
        use crate::protocol::{Transaction as ProtoTx, TxData};
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.from_wallet_id.clone(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            data: TxData::TransferBb {
                to: req.to_address.clone(),
                amount: (req.amount * 1_000_000_000.0) as u64,
            },
            signature: sig_hex.clone(),
            signer_pubkey: req.from_wallet_id.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    // 6. Refresh session TTL
    state.session_store.refresh_session(&req.session_token);

    Ok(Json(json!({
        "success": true,
        "signature": sig_hex,
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
        "from_balance": state.blockchain.get_balance(&req.from_wallet_id),
        "to_balance": state.blockchain.get_balance(&req.to_address),
        "session_token": req.session_token,
        "session_key": req.session_key,
    })))
}
```

---

## Step 8: Register the New Routes

In `src/wallet_unified/handlers.rs`, update the `router()` function to include the new endpoints:

```rust
pub fn router() -> Router<Arc<UnifiedWalletState>> {
    Router::new()
        .route("/wallet/create", post(create_hybrid_wallet))
        .route("/wallet/login", post(login_handler))
        .route("/transfer", post(transfer_with_sss))
        .route("/transfer/session", post(transfer_session_handler))
        .route("/wallet/secure/shard-b", post(get_shard_b_handler))
        .route("/wallet/secure/recover-shard-c", post(recover_shard_c))
        .route("/wallet/verify-sss", post(verify_sss_handler))
}
```

---

## Step 9: Optional Logout Endpoint

If you want the React app's logout to also kill the server-side session blob, add this handler to `src/wallet_unified/handlers.rs`:

```rust
#[derive(Deserialize)]
pub struct LogoutRequest {
    pub session_token: Option<String>,
    pub wallet_id: Option<String>,
}

pub async fn logout_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<LogoutRequest>,
) -> Json<serde_json::Value> {
    if let Some(token) = &req.session_token {
        state.session_store.revoke(token);
    }
    if let Some(wallet_id) = &req.wallet_id {
        state.session_store.revoke_by_wallet(wallet_id);
    }
    Json(json!({ "success": true }))
}
```

And register it in the router:
```rust
        .route("/wallet/logout", post(logout_handler))
```

---

## Security Notes

- **$SK is never stored on disk** — it lives only in the browser's JS heap (SDK `_session` field). Lost on page refresh or tab close.
- **The blob auto-expires** — the `sweep_expired()` task removes it after 15 minutes of inactivity.
- **One session per wallet** — `create_session()` calls `revoke_by_wallet()` first, preventing session accumulation.
- **Refresh on use** — `refresh_session()` resets the 15-min clock on each successful session transfer, so active users stay authenticated.
- **$SK alone is useless** — without the server-side blob, the session key decrypts nothing.
- **Blob alone is useless** — without the $SK from the client, AES-GCM decryption fails.
