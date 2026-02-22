use axum::{extract::{State, Json}, http::{StatusCode, HeaderMap}, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use bip39::Mnemonic;
use rand::rngs::OsRng;
use sharks::{Sharks, Share};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer};
use tracing::{info, warn, error};
use super::security;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::storage::ConcurrentBlockchain;

use crate::supabase::SupabaseManager;
use crate::vault_manager::VaultManager;

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
    pub supabase: Arc<SupabaseManager>,
    pub vault: Arc<VaultManager>,
}

impl UnifiedWalletState {
    pub fn new(blockchain: Arc<ConcurrentBlockchain>, supabase: Arc<SupabaseManager>, vault: Arc<VaultManager>) -> Self {
        info!("✅ Unified Wallet initialized with ReDB storage & Supabase Vault & HashiCorp Vault");
        Self { blockchain, supabase, vault }
    }
}

// ============================================================================
// TYPE DEFS
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
pub struct CreateWalletRequest {
    pub username: String,           // Required for User Vault ID
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

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SSSTransferRequest {
    #[zeroize(skip)]
    pub from_wallet_id: String,
    #[zeroize(skip)]
    pub to_address: String,
    #[zeroize(skip)]
    pub amount: f64,
    pub share_a: String,            // User provides encrypted Share A
    pub password: String,           // To decrypt Share A
}

// ============================================================================
// HELPERS
// ============================================================================

fn validate_jwt(headers: &HeaderMap) -> Result<Claims, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("Authorization")
        .ok_or_else(|| err("Missing Authorization header"))?
        .to_str()
        .map_err(|_| err("Invalid Authorization header"))?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(err("Invalid Bearer token format"));
    }
    
    let token = &auth_header[7..];
    
    // WARNING: Insecure Decode for Mainnet-Beta (Supabase using ES256, we skip cert verification for now)
    // TODO: Implement proper JWKS fetching for ES256 verification in Production 1.0
    let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(token)
        .map_err(|e| {
            let error_msg = format!("JWT Verification Failed: {}", e);
            error!("{}", error_msg);
            err(error_msg)
        })?;

    Ok(token_data.claims)
}

// ============================================================================
// CORE LOGIC: Mnemonic -> FROST 2-of-3
// ============================================================================

pub async fn create_hybrid_wallet(
    State(state): State<Arc<UnifiedWalletState>>,
    headers: HeaderMap,
    Json(req): Json<CreateWalletRequest>,
) -> Result<Json<CreateResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Ok(claims) = validate_jwt(&headers) {
        info!("🔐 Authenticated CreateWallet: {}", claims.sub);
    } else {
        warn!("⚠️  Unauthenticated CreateWallet!");
    }

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

    // 6. Share A — encrypt with user password, return to client for localStorage/Supabase
    let (final_share_a, is_encrypted) = if let Some(password) = &req.password {
        match security::encrypt_with_secret(password, &raw_shares[0]) {
            Ok(ct) => (ct, true),
            Err(e) => return Err(err(format!("Share A encryption failed: {}", e))),
        }
    } else {
        warn!("⚠️  No password — Share A returned unencrypted");
        (hex::encode(&raw_shares[0]), false)
    };
    if let Ok(claims) = validate_jwt(&headers) {
        if let Err(e) = state.supabase
            .store_encrypted_shard_a(&claims.sub, &req.username, &wallet_id, &wallet_id, &final_share_a)
            .await
        {
            error!("❌ Failed to sync Share A to Supabase: {}", e);
        } else {
            info!("☁️  Share A synced to Supabase");
        }
    }

    // 7. Share C — return raw hex (user writes offline / HashiCorp Vault backup)
    let share_c_hex = hex::encode(&raw_shares[2]);
    if let Ok(claims) = validate_jwt(&headers) {
        if let Err(e) = state.vault.store_shard_c(&claims.sub, &share_c_hex).await {
            warn!("⚠️  HashiCorp Vault backup skipped: {}", e);
        } else {
            info!("🔒 Share C stored in HashiCorp Vault");
        }
    }

    info!("✅ BlackBook wallet created: {} (SVM-compatible Ed25519)", wallet_id);
    Ok(Json(CreateResponse {
        wallet_id: wallet_id.clone(),
        mnemonic: mnemonic.to_string(),
        share_a: final_share_a,
        share_a_is_encrypted: is_encrypted,
        share_c: share_c_hex,
        public_key: bs58::encode(&pub_key_bytes).into_string(),
        address: wallet_id,
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

    // 1. Decrypt Share A (user provides encrypted blob + password)
    let mut share_a_bytes = security::decrypt_with_secret(&req.password, &req.share_a)
        .map_err(|e| err(format!("Failed to decrypt Share A: {}", e)))?;

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

    // Zeroize key material immediately after signing
    seed_32.zeroize();
    seed_bytes.zeroize();
    share_a_bytes.zeroize();
    share_b_bytes.zeroize();

    info!("✅ Transfer signed for wallet {}", req.from_wallet_id);

    // 6. Execute transfer on-chain
    state.blockchain.transfer(&req.from_wallet_id, &req.to_address, req.amount)
        .map_err(|e| err(format!("Transfer failed: {}", e)))?;
    info!("💸 Transfer: {} → {} : {} BB", req.from_wallet_id, req.to_address, req.amount);

    Ok(Json(json!({
        "success": true,
        "signature": sig_hex,
        "from": req.from_wallet_id,
        "to": req.to_address,
        "amount": req.amount,
        "from_balance": state.blockchain.get_balance(&req.from_wallet_id),
        "to_balance": state.blockchain.get_balance(&req.to_address)
    })))
}

#[derive(Deserialize)]
pub struct GetShardBRequest {
    pub wallet_id: String,
    pub pin: Option<String>,
}

#[derive(Deserialize)]
pub struct RecoverShardCRequest {
    // Intentionally empty. Relying on JWT strictly.
    // Future: Add 2FA token or Email OTP code here?
}

#[derive(Serialize)]
pub struct RecoverShardCResponse {
    pub shard_c: String,
    pub warning: String,
}

pub async fn recover_shard_c(
    State(state): State<Arc<UnifiedWalletState>>,
    headers: HeaderMap,
    Json(_req): Json<RecoverShardCRequest>,
) -> Result<Json<RecoverShardCResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. STRICT AUTH: The Bouncer
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| err("Unauthorized"))?;

    let user_id = state.supabase.verify_user(auth_header).await
        .map_err(|e| err(format!("Access Denied: {}", e)))?;

    info!("🚨 RECOVERY ALERT: User {} is requesting SHARD C from Vault!", user_id);

    // 2. Retrieve from HashiCorp Vault
    let shard_c = state.vault.retrieve_shard_c(&user_id).await
        .map_err(|e| {
            error!("Vault Retrieval Failed for {}: {}", user_id, e);
            err("Recovery failed. Contact support if this persists.")
        })?;

    // 3. Audit Log (Critical)
    // In a real system, we would fire an event to an Audit log, email the user, etc.
    info!("✅ Shard C released to {}", user_id);

    Ok(Json(RecoverShardCResponse {
        shard_c,
        warning: "This is your Recovery Shard. Combine with Shard B (Cloud) to restore wallet. DO NOT SHARE.".to_string(),
    }))
}

pub async fn get_shard_b_handler(
    State(state): State<Arc<UnifiedWalletState>>,
    headers: HeaderMap,
    Json(req): Json<GetShardBRequest>,
) -> Result<Json<ShardBResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Simple SSS: Just return Shard B from storage
    // No PIN, no encryption beyond what SSS provides
    
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

pub fn router() -> Router<Arc<UnifiedWalletState>> {
    Router::new()
        .route("/wallet/create", post(create_hybrid_wallet))
        .route("/transfer", post(transfer_with_sss))
        .route("/wallet/secure/shard-b", post(get_shard_b_handler))
        .route("/wallet/secure/recover-shard-c", post(recover_shard_c))
}

// Helper
fn err(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg.into() })))
}
