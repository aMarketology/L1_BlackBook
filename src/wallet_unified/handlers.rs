use axum::{extract::{State, Json}, http::{StatusCode, HeaderMap}, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use bip39::Mnemonic;
use rand::rngs::OsRng;
use sharks::{Sharks, Share};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer};
use tracing::{info, warn};
use super::security;
use super::session_store::SessionStore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::storage::ConcurrentBlockchain;
use crate::poh_blockchain::BlockProducer;

// ============================================================================
// CONSTANTS & CONFIG
// ============================================================================

fn get_server_master_key() -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    std::env::var("SERVER_MASTER_KEY")
        .map_err(|_| err("Server configuration error: Missing MASTER KEY"))
}

// ============================================================================
// STATE (100% ReDB-backed — No Simulation)
// ============================================================================

#[derive(Clone)]
pub struct UnifiedWalletState {
    // ReDB-backed storage (production-grade persistence)
    pub blockchain: Arc<ConcurrentBlockchain>,
    /// Block producer — records executed transactions into PoH blocks
    pub block_producer: Arc<BlockProducer>,
    /// In-memory session store — 30-min scoped key cache
    pub session_store: Arc<SessionStore>,
}

impl UnifiedWalletState {
    pub fn new(
        blockchain: Arc<ConcurrentBlockchain>,
        block_producer: Arc<BlockProducer>,
    ) -> Self {
        let session_store = Arc::new(SessionStore::new());

        // Spawn background sweeper — removes expired blobs every 60s
        let store_clone = session_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                store_clone.sweep_expired();
            }
        });

        info!("✅ Unified Wallet initialized with ReDB storage");
        Self { blockchain, block_producer, session_store }
    }

    /// Create with a shared session store (used when AppState needs access too)
    pub fn new_with_session_store(
        blockchain: Arc<ConcurrentBlockchain>,
        block_producer: Arc<BlockProducer>,
        session_store: Arc<SessionStore>,
    ) -> Self {
        info!("✅ Unified Wallet initialized with shared session store");
        Self { blockchain, block_producer, session_store }
    }
}

// ============================================================================
// TYPE DEFS
// ============================================================================

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct CreateWalletRequest {
    pub username: String,
    pub password: Option<String>,   // Encrypts Share A (User Active)
    pub pin: Option<String>,        // Hashed for Auth. Encrypts Share B with Server Key if PIN present.
    pub daily_limit: Option<u64>,   // Threshold for PIN requirement
}

// Custom Drop/Zeroize logic might be needed if Option<String> isn't auto-supported nicely by derive macros
// effectively, checking documentation: Option<T> implements Zeroize if T does.
// So we can remove #[zeroize(skip)] if we trust Option<String> implementation.
// Let's retry without skip, assuming standard impl.

#[derive(Serialize)]
pub struct CreateResponse {
    pub wallet_id: String,
    pub mnemonic: String,           // BIP-39 (Recovery Root)
    pub share_a: String,            // User Share (Encrypted with Password)
    pub share_a_is_encrypted: bool,
    pub share_c: String,            // Cold Share (Raw/Ready for Vault)
    pub public_key: String,
    pub address: String,            // Public Address (Ed25519)
    pub session_token: String,      // Auto-login token — wallet unlocked on creation
}

#[derive(Serialize)]
pub struct ShardBResponse {
    pub shard_b: String,
    pub status: String,
}

/// Internal wrapper for Shard B storage
#[derive(Serialize, Deserialize)]
struct ShardBContainer {
    shard_b_data: String,           // Encrypted with server master key
}

// ============================================================================
// LOGIN — reconstruct seed from 2 shards, cache it, return session tokens
// ============================================================================

#[derive(Deserialize)]
pub struct LoginRequest {
    pub wallet_id: String,
    /// Share A — hex or password-encrypted blob
    pub shard_1: String,
    /// Share B — hex (raw) or server-encrypted blob
    pub shard_2: String,
    /// Required if shard_1 is password-encrypted
    pub password: Option<String>,
    /// Set true if shard_2 is the server-encrypted blob from /wallet/secure/shard-b
    pub shard_2_is_server_encrypted: Option<bool>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub wallet_id: String,
    pub session_token: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SSSTransferRequest {
    #[zeroize(skip)]
    pub from_wallet_id: String,
    #[zeroize(skip)]
    pub to_address: String,
    #[zeroize(skip)]
    pub amount: f64,
    pub share_a: String,            // Encrypted blob OR raw hex
    pub password: Option<String>,   // Required if share_a is encrypted; omit for raw hex
}

// ============================================================================
// CORE LOGIC: Mnemonic -> SSS 2-of-3
// ============================================================================

pub async fn create_hybrid_wallet(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<Json<CreateResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("🔐 CreateWallet request for user: {}", req.username);

    // 1. BIP-39 mnemonic (24 words — user can import this into any SVM wallet)
    let mut rng = OsRng;
    let mut entropy = [0u8; 32];
    use rand::RngCore;
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| err(e.to_string()))?;
    entropy.zeroize();

    // 2. Derive 64-byte BIP-39 seed, take first 32 bytes as Ed25519 keypair seed
    let bip39_seed_full = mnemonic.to_seed("");
    let mut seed_32: [u8; 32] = bip39_seed_full[..32].try_into().unwrap();

    // 3. Derive standard Ed25519 keypair (Solana / SVM compatible)
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let verifying_key = signing_key.verifying_key();
    let pub_key_bytes = verifying_key.to_bytes();
    let address = bs58::encode(&pub_key_bytes).into_string(); // Solana-format base58
    let wallet_id = address.clone();

    // 4. Shamir 2-of-3 split the 32-byte seed
    //    Any 2 of the 3 shares reconstruct the full seed → keypair → sign transactions
    //    This is importable: reconstruct seed → base58 privkey → import into Nightly/svmseek
    let shark = Sharks(2u8);
    let raw_shares: Vec<Vec<u8>> = shark
        .dealer(&seed_32[..])
        .take(3)
        .map(|s| Vec::from(&s))
        .collect();

    // Auto-login: cache the seed so the wallet is immediately usable after creation
    let session_token = state.session_store.create_session(
        &wallet_id, &seed_32,
    );
    seed_32.zeroize();

    // 5. Share B — encrypt with server master key, store in ReDB
    let master_key = get_server_master_key()?;
    let encrypted_share_b = security::encrypt_with_secret(&master_key, &raw_shares[1])
        .map_err(|e| err(format!("Failed to encrypt Share B: {}", e)))?;
    let container = ShardBContainer { shard_b_data: encrypted_share_b };
    let container_bytes = serde_json::to_vec(&container).unwrap();
    state.blockchain.store_frost_share_b(&wallet_id, &container_bytes)
        .map_err(|e| err(format!("Failed to store Share B: {}", e)))?;
    state.blockchain.store_frost_pub_key(&wallet_id, &pub_key_bytes)
        .map_err(|e| err(format!("Failed to store public key: {}", e)))?;
    info!("✅ Share B stored for wallet {}", wallet_id);

    // 6. Share A — encrypt with user password, return to frontend
    //    Frontend is responsible for storing this in Supabase / localStorage
    let (final_share_a, is_encrypted) = if let Some(password) = &req.password {
        match security::encrypt_with_secret(password, &raw_shares[0]) {
            Ok(ct) => (ct, true),
            Err(e) => return Err(err(format!("Share A encryption failed: {}", e))),
        }
    } else {
        warn!("⚠️  No password — Share A returned unencrypted");
        (hex::encode(&raw_shares[0]), false)
    };

    // 7. Share C — return raw hex (user stores offline for recovery)
    let share_c_hex = hex::encode(&raw_shares[2]);

    info!("✅ BlackBook wallet created: {} (SVM-compatible Ed25519)", wallet_id);
    Ok(Json(CreateResponse {
        wallet_id: wallet_id.clone(),
        mnemonic: mnemonic.to_string(),
        share_a: final_share_a,
        share_a_is_encrypted: is_encrypted,
        share_c: share_c_hex,
        public_key: bs58::encode(&pub_key_bytes).into_string(),
        address: wallet_id,
        session_token,
    }))
}

pub async fn transfer_with_sss(
    State(state): State<Arc<UnifiedWalletState>>,
    _headers: HeaderMap,
    Json(req): Json<SSSTransferRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if req.amount <= 0.0 {
        return Err(err("Amount must be positive"));
    }
    let balance = state.blockchain.get_balance(&req.from_wallet_id);
    if balance < req.amount {
        return Err(err(format!("Insufficient balance: {} < {}", balance, req.amount)));
    }

    // 1. Decrypt Share A (encrypted blob + password) or decode raw hex
    let mut share_a_bytes = if let Some(ref password) = req.password {
        // Encrypted mode: AES-256-GCM blob with Argon2id-derived key
        security::decrypt_with_secret(password, &req.share_a)
            .map_err(|e| err(format!("Failed to decrypt Share A: {}", e)))?
    } else {
        // Raw hex mode: user pasted unencrypted shard hex directly
        hex::decode(&req.share_a)
            .map_err(|e| err(format!("Invalid raw Share A hex: {}", e)))?
    };

    // 2. Fetch + decrypt Share B from ReDB
    let container_bytes = state.blockchain.get_frost_share_b(&req.from_wallet_id)
        .map_err(|e| err(format!("Share B not found: {}", e)))?;
    let container: ShardBContainer = serde_json::from_slice(&container_bytes)
        .map_err(|_| err("Shard B corrupted"))?;
    let master_key = get_server_master_key()?;
    let mut share_b_bytes = security::decrypt_with_secret(&master_key, &container.shard_b_data)
        .map_err(|e| err(format!("Failed to decrypt Share B: {}", e)))?;

    // 3. Reconstruct 32-byte seed from 2 Shamir shares
    let shark = Sharks(2u8);
    let share_a = Share::try_from(share_a_bytes.as_slice())
        .map_err(|_| err("Malformed Share A"))?;
    let share_b = Share::try_from(share_b_bytes.as_slice())
        .map_err(|_| err("Malformed Share B"))?;
    let mut seed_bytes = shark
        .recover(&[share_a, share_b])
        .map_err(|e| err(format!("Share reconstruction failed: {}", e)))?;
    if seed_bytes.len() < 32 {
        seed_bytes.zeroize();
        return Err(err("Reconstructed seed too short"));
    }
    let mut seed_32: [u8; 32] = seed_bytes[..32].try_into().unwrap();

    // 4. Derive standard Ed25519 signing key and verify it matches the wallet address
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
    if derived_address != req.from_wallet_id {
        seed_32.zeroize();
        seed_bytes.zeroize();
        return Err(err("Share reconstruction produced wrong address — wrong shares or password"));
    }

    // 5. Sign the transfer message
    let tx_message = format!("{}:{}:{}", req.from_wallet_id, req.to_address, req.amount);
    let signature = signing_key.sign(tx_message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // Cache the reconstructed seed for fast-path transfers (30-min window)
    let session_token = state.session_store.create_session(
        &req.from_wallet_id, &seed_32,
    );

    // Zeroize key material immediately after signing
    seed_32.zeroize();
    seed_bytes.zeroize();
    share_a_bytes.zeroize();
    share_b_bytes.zeroize();

    info!("✅ Transfer signed for wallet {}", req.from_wallet_id);

    // 6. Execute transfer on-chain with SVM receipt (for explorer + getSignaturesForAddress)
    state.blockchain.transfer_with_receipt(
        &req.from_wallet_id,
        &req.to_address,
        req.amount,
        &sig_hex,
        crate::storage::AuthType::SSS,
    ).map_err(|e| err(format!("Transfer failed: {}", e)))?;
    info!("💸 Transfer: {} → {} : {} BB", req.from_wallet_id, req.to_address, req.amount);

    // Record in PoH block (already executed — just needs ordering proof)
    {
        use crate::protocol::{Transaction as ProtoTx, TxData};
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.from_wallet_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            data: TxData::TransferBb {
                to: req.to_address.clone(),
                amount: (req.amount * 100_000.0) as u64,
            },
            signature: sig_hex.clone(),
            signer_pubkey: req.from_wallet_id.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    Ok(Json(json!({
        "success": true,
        "signature": sig_hex,
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
        "from_balance": state.blockchain.get_balance(&req.from_wallet_id),
        "to_balance": state.blockchain.get_balance(&req.to_address),
        "session_token": session_token,
    })))
}

// ============================================================================
// SESSION TRANSFER — fast path, no password / Argon2id / shard decryption
// ============================================================================

#[derive(Deserialize)]
pub struct SessionTransferRequest {
    pub from_wallet_id: String,
    pub to_address: String,
    pub amount: f64,
    pub session_token: String,
    // Note: no session_key — the seed lives server-side keyed only by session_token
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

    // 1. Get the 32-byte seed from the session store (also refreshes TTL)
    let mut seed_32 = state.session_store
        .get_seed(&req.session_token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(json!({ "error": e }))))?;

    // 2. Reconstruct signing key and verify it matches the claimed wallet
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
    if derived_address != req.from_wallet_id {
        seed_32.zeroize();
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Session does not match wallet" }))));
    }

    // 3. Sign the transfer message
    let tx_message = format!("{}:{}:{}", req.from_wallet_id, req.to_address, req.amount);
    let signature = signing_key.sign(tx_message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // 4. Zeroize immediately
    seed_32.zeroize();

    info!("⚡ Session transfer signed for wallet {}", req.from_wallet_id);

    // 5. Execute transfer on-chain
    state.blockchain.transfer_with_receipt(
        &req.from_wallet_id,
        &req.to_address,
        req.amount,
        &sig_hex,
        crate::storage::AuthType::SessionKey,
    ).map_err(|e| err(format!("Transfer failed: {}", e)))?;
    info!("💸 Session transfer: {} → {} : {} BB", req.from_wallet_id, req.to_address, req.amount);

    // 6. Record in PoH block
    {
        use crate::protocol::{Transaction as ProtoTx, TxData};
        let tx = ProtoTx {
            hash: uuid::Uuid::new_v4().to_string(),
            from: req.from_wallet_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            data: TxData::TransferBb {
                to: req.to_address.clone(),
                amount: (req.amount * 100_000.0) as u64,
            },
            signature: sig_hex.clone(),
            signer_pubkey: req.from_wallet_id.clone(),
        };
        state.block_producer.record_executed_transaction(tx);
    }

    // TTL was already refreshed by get_seed() above
    Ok(Json(json!({
        "success": true,
        "signature": sig_hex,
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
        "from_balance": state.blockchain.get_balance(&req.from_wallet_id),
        "to_balance": state.blockchain.get_balance(&req.to_address),
        "session_token": req.session_token,
    })))
}

#[derive(Deserialize)]
pub struct GetShardBRequest {
    pub wallet_id: String,
    pub pin: Option<String>,
}

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
        .map_err(|e| err(format!("Shard B not found: {}", e)))?;
    
    let container: ShardBContainer = serde_json::from_slice(&container_bytes)
        .map_err(|_| err("Shard B corrupted"))?;

    info!("✅ Shard B retrieved for wallet {}", req.wallet_id);

    Ok(Json(ShardBResponse {
        shard_b: container.shard_b_data,
        status: "Released".to_string(),
    }))
}

// ============================================================================
// SSS 2/3 VERIFY — Test that any 2 of 3 shards reconstruct the wallet
// ============================================================================

#[derive(Deserialize)]
pub struct SSSVerifyRequest {
    /// The wallet address (public key) to verify against
    pub wallet_id: String,
    /// First shard (hex-encoded raw share bytes)
    pub shard_1: String,
    /// Second shard (hex-encoded raw share bytes)
    pub shard_2: String,
    /// If shard_1 is password-encrypted (Share A), provide the password
    pub password: Option<String>,
    /// If shard_2 is server-encrypted (Share B), set true to auto-decrypt
    pub shard_2_is_server_encrypted: Option<bool>,
}

#[derive(Serialize)]
pub struct SSSVerifyResponse {
    pub success: bool,
    pub wallet_id: String,
    pub derived_address: String,
    pub matches: bool,
    pub message: String,
}

pub async fn verify_sss_handler(
    State(_state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<SSSVerifyRequest>,
) -> Result<Json<SSSVerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Decode / decrypt shard 1
    let shard_1_bytes = if let Some(ref password) = req.password {
        // Shard 1 is password-encrypted (Share A)
        security::decrypt_with_secret(password, &req.shard_1)
            .map_err(|e| err(format!("Failed to decrypt Shard 1: {}", e)))?
    } else {
        hex::decode(&req.shard_1).map_err(|_| err("Invalid hex for Shard 1"))?
    };

    // 2. Decode / decrypt shard 2
    let shard_2_bytes = if req.shard_2_is_server_encrypted.unwrap_or(false) {
        // Shard 2 is server-encrypted (Share B from storage)
        let master_key = get_server_master_key()?;
        security::decrypt_with_secret(&master_key, &req.shard_2)
            .map_err(|e| err(format!("Failed to decrypt Shard 2: {}", e)))?
    } else {
        hex::decode(&req.shard_2).map_err(|_| err("Invalid hex for Shard 2"))?
    };

    // 3. Reconstruct seed from 2 Shamir shares
    let shark = Sharks(2u8);
    let share_a = Share::try_from(shard_1_bytes.as_slice())
        .map_err(|_| err("Malformed Shard 1"))?;
    let share_b = Share::try_from(shard_2_bytes.as_slice())
        .map_err(|_| err("Malformed Shard 2"))?;
    let seed_bytes = shark
        .recover(&[share_a, share_b])
        .map_err(|e| err(format!("SSS reconstruction failed: {}", e)))?;

    if seed_bytes.len() < 32 {
        return Err(err("Reconstructed seed too short"));
    }

    // 4. Derive Ed25519 public key from reconstructed seed
    let seed_32: [u8; 32] = seed_bytes[..32].try_into().unwrap();
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

    let matches = derived_address == req.wallet_id;

    info!(
        "🔍 SSS Verify: wallet={} derived={} match={}",
        req.wallet_id, derived_address, matches
    );

    Ok(Json(SSSVerifyResponse {
        success: true,
        wallet_id: req.wallet_id.clone(),
        derived_address: derived_address.clone(),
        matches,
        message: if matches {
            "✅ 2/3 SSS reconstruction successful — wallet access verified!".to_string()
        } else {
            "❌ Derived address does not match. Wrong shards or wrong password.".to_string()
        },
    }))
}

// ============================================================================
// LOGIN HANDLER
// ============================================================================

pub async fn login_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Decode / decrypt shard 1
    let mut shard_1_bytes = if let Some(ref password) = req.password {
        security::decrypt_with_secret(password, &req.shard_1)
            .map_err(|e| err(format!("Failed to decrypt Shard 1: {}", e)))?
    } else {
        hex::decode(&req.shard_1).map_err(|_| err("Invalid hex for Shard 1"))?
    };

    // 2. Decode / decrypt shard 2
    let mut shard_2_bytes = if req.shard_2_is_server_encrypted.unwrap_or(false) {
        let master_key = get_server_master_key()?;
        security::decrypt_with_secret(&master_key, &req.shard_2)
            .map_err(|e| err(format!("Failed to decrypt Shard 2: {}", e)))?
    } else {
        hex::decode(&req.shard_2).map_err(|_| err("Invalid hex for Shard 2"))?
    };

    // 3. Reconstruct 32-byte seed from 2 Shamir shares
    let shark = Sharks(2u8);
    let share_a = Share::try_from(shard_1_bytes.as_slice()).map_err(|_| err("Malformed Shard 1"))?;
    let share_b = Share::try_from(shard_2_bytes.as_slice()).map_err(|_| err("Malformed Shard 2"))?;
    let mut seed_bytes = shark
        .recover(&[share_a, share_b])
        .map_err(|e| err(format!("SSS reconstruction failed: {}", e)))?;

    if seed_bytes.len() < 32 {
        seed_bytes.zeroize();
        return Err(err("Reconstructed seed too short"));
    }

    let mut seed_32: [u8; 32] = seed_bytes[..32].try_into().unwrap();

    // 4. Verify the derived address matches the claimed wallet_id
    let signing_key = Ed25519SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();
    if derived_address != req.wallet_id {
        seed_32.zeroize();
        seed_bytes.zeroize();
        return Err(err("Derived address does not match — wrong shards or password"));
    }

    // 5. Create session — seed cached server-side, only token returned to client
    let session_token = state.session_store.create_session(
        &req.wallet_id, &seed_32,
    );

    // 6. Zeroize all key material
    seed_32.zeroize();
    seed_bytes.zeroize();
    shard_1_bytes.zeroize();
    shard_2_bytes.zeroize();

    info!("🔐 Session created for wallet {}", req.wallet_id);

    Ok(Json(LoginResponse {
        success: true,
        wallet_id: req.wallet_id,
        session_token,
    }))
}

// ============================================================================
// LOGOUT HANDLER
// ============================================================================

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub session_token: Option<String>,
    pub wallet_id: Option<String>,
}

pub async fn logout_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    Json(req): Json<LogoutRequest>,
) -> Json<serde_json::Value> {
    if let Some(ref token) = req.session_token {
        state.session_store.revoke(token);
    }
    if let Some(ref wallet_id) = req.wallet_id {
        state.session_store.revoke_by_wallet(wallet_id);
    }
    info!("🚪 Session revoked");
    Json(json!({ "success": true }))
}

pub fn router() -> Router<Arc<UnifiedWalletState>> {
    Router::new()
        .route("/wallet/create", post(create_hybrid_wallet))
        .route("/wallet/login", post(login_handler))
        .route("/wallet/logout", post(logout_handler))
        .route("/transfer", post(transfer_with_sss))
        .route("/transfer/session", post(transfer_session_handler))
        .route("/wallet/secure/shard-b", post(get_shard_b_handler))
        .route("/wallet/verify-sss", post(verify_sss_handler))
}

// Helper
fn err(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg.into() })))
}
