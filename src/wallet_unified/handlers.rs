use axum::{extract::{State, Json}, http::{StatusCode, HeaderMap}, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use bip39::Mnemonic;
use rand::rngs::OsRng;
use frost_ed25519 as frost;
use tracing::{info, warn, error};
use super::security;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::prelude::*;

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
    // 0. Verify Auth (Log only for now)
    if let Ok(claims) = validate_jwt(&headers) {
        info!("🔐 Authenticated CreateWallet: {}", claims.sub);
    } else {
        warn!("⚠️  Unauthenticated CreateWallet! Check logs for JWT failure details.");
    }

    // 1. Generate Mnemonic (BIP-39 Standard)
    let mut rng = OsRng;
    let mut entropy = [0u8; 32];
    use rand::RngCore;
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| err(e.to_string()))?;
    
    // SECURITY CRITICAL: Wipe raw entropy from memory immediately
    entropy.zeroize();
    
    // 2. Bootstrap FROST Keys (2-of-3 Shamir Secret Sharing)
    let max_signers = 3;
    let min_signers = 2;
    let (shares, pub_key_package) = frost::keys::generate_with_dealer(
        max_signers, min_signers, frost::keys::IdentifierList::Default, &mut rng
    ).map_err(|e| err(e.to_string()))?;

    // 3. Distribute Shares (ID 1=A, 2=B, 3=C per BlackBook spec)
    let id1 = frost::Identifier::try_from(1u16).unwrap();
    let id2 = frost::Identifier::try_from(2u16).unwrap();
    let id3 = frost::Identifier::try_from(3u16).unwrap();
    
    let share_a = shares.get(&id1).unwrap(); // User's Active shard
    let share_b = shares.get(&id2).unwrap(); // Cloud shard
    let share_c = shares.get(&id3).unwrap(); // Recovery shard

    // 4. Public Key Setup
    let verifying_key = pub_key_package.verifying_key();
    let pub_key_bytes = verifying_key.serialize().unwrap();
    let wallet_id = hex::encode(&pub_key_bytes);

    // 5. SHARD B (Cloud): Encrypt with Server Master Key (At-Rest Encryption)
    let share_b_bytes = serde_json::to_vec(&share_b).unwrap();
    let master_key = get_server_master_key()?;
    let encrypted_share_b = security::encrypt_with_secret(&master_key, &share_b_bytes)
        .map_err(|e| err(format!("Failed to encrypt Share B: {}", e)))?;
    
    let container = ShardBContainer {
        shard_b_data: encrypted_share_b, // Now contains salt:nonce:ciphertext
    };
    let container_bytes = serde_json::to_vec(&container).unwrap();

    // Store Container in ReDB
    state.blockchain.store_frost_share_b(&wallet_id, &container_bytes)
        .map_err(|e| err(format!("Failed to store Share B in ReDB: {}", e)))?;

    info!("✅ Shard B stored in ReDB for wallet {}", wallet_id);

    // Store PublicKeyPackage
    let pk_pkg_bytes = serde_json::to_vec(&pub_key_package).unwrap();
    state.blockchain.store_frost_pub_key_package(&wallet_id, &pk_pkg_bytes)
        .map_err(|e| err(format!("Failed to store PublicKeyPackage: {}", e)))?;
    state.blockchain.store_frost_pub_key(&wallet_id, &pub_key_bytes)
        .map_err(|e| err(format!("Failed to store public key: {}", e)))?;

    // 6. SHARD A (Active): Encrypt with Password
    let mut share_a_bytes = serde_json::to_vec(share_a).unwrap();
    let (final_share_a, is_encrypted) = if let Some(password) = &req.password {
        match security::encrypt_with_secret(password, &share_a_bytes) {
            Ok(ciphertext) => (ciphertext, true),
            Err(e) => return Err(err(format!("Share A encryption failed: {}", e)))
        }
    } else {
        warn!("⚠️ No Password provided! Returning Share A unencrypted (NOT RECOMMENDED)");
        (hex::encode(&share_a_bytes), false)
    };
    // Wipe raw Share A
    share_a_bytes.zeroize();

    // SYNC SHARD A TO SUPABASE
    if let Ok(claims) = validate_jwt(&headers) {
        if let Err(e) = state.supabase.store_encrypted_shard_a(&claims.sub, &req.username, &wallet_id, &wallet_id, &final_share_a).await {
             error!("❌ Failed to sync Share A to Supabase: {}", e);
             return Err(err(format!("Failed to sync Shard A: {}", e)));
        } else {
             info!("☁️  Synced Share A to Supabase User Vault");
        }
    }

    // 7. SHARD C (Recovery): Return raw
    // Note: Shard C is designed to be printed/written down, so it leaves the server "naked" 
    // but protected by physical security (paper/safe). 
    let mut share_c_bytes = serde_json::to_vec(share_c).unwrap();
    let share_c_hex = hex::encode(&share_c_bytes);
    share_c_bytes.zeroize();

    // SYNC SHARD C TO SUPABASE (Hidden Vault) --> REPLACED WITH HASHICORP VAULT
    if let Ok(claims) = validate_jwt(&headers) {
        if let Err(e) = state.vault.store_shard_c(&claims.sub, &share_c_hex).await {
             error!("❌ Failed to sync Share C to HashiCorp Vault: {}", e);
             warn!("⚠️  Continuing wallet creation without Vault backup. Shard C will be in JSON only.");
             // Non-blocking: Allow wallet creation to proceed
        } else {
             info!("🔒 Synced Share C to HashiCorp Vault Secrets for {}", claims.sub);
        }
    } else {
        warn!("⚠️  Skipping Vault Storage for Shard C (Unauthenticated)");
    }

    info!("✅ BlackBook Wallet created: {}", wallet_id);

    let response = CreateResponse {
        wallet_id: wallet_id.clone(),
        mnemonic: mnemonic.to_string(), // Mnemonic string will be dropped after response serialization
        share_a: final_share_a,
        share_a_is_encrypted: is_encrypted,
        share_c: share_c_hex,
        public_key: wallet_id.clone(),
        address: wallet_id,
    };
    
    // Explicitly drop mnemonic to ensure destruction (Rust ownership rules help here)
    // The 'mnemonic' variable is consumed into 'response' and then JSON serialized.
    // Ideally we would overwrite the string memory, but standard String/BIP39 impl 
    // makes that hard without unsafe code. We rely on entropy zeroization above.

    Ok(Json(response))
}

pub async fn transfer_with_sss(
    State(state): State<Arc<UnifiedWalletState>>,
    headers: HeaderMap,
    Json(req): Json<SSSTransferRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate input
    if req.amount <= 0.0 {
        return Err(err("Amount must be positive"));
    }

    // Check balance
    let balance = state.blockchain.get_balance(&req.from_wallet_id);
    if balance < req.amount {
        return Err(err(format!("Insufficient balance: {} < {}", balance, req.amount)));
    }

    // 1. DECRYPT Share A (Client encrypted with password)
    let mut share_a_decrypted = security::decrypt_with_secret(&req.password, &req.share_a)
        .map_err(|e| err(format!("Failed to decrypt Share A: {}", e)))?;
    let share_a: frost::keys::SecretShare = serde_json::from_slice(&share_a_decrypted)
        .map_err(|_| err("Malformed Share A after decryption"))?;

    // 2. FETCH Share B Container
    let container_bytes = state.blockchain.get_frost_share_b(&req.from_wallet_id)
        .map_err(|e| err(format!("Share B not found: {}", e)))?;
    
    let container: ShardBContainer = serde_json::from_slice(&container_bytes)
        .map_err(|_| err("Shard B corrupted"))?;

    // 3. DECRYPT Share B (Server Master Key) - with backward compatibility
    let master_key = get_server_master_key()?;
    let share_b_bytes = match security::decrypt_with_secret(&master_key, &container.shard_b_data) {
        Ok(decrypted) => decrypted,
        Err(_) => {
            // Fallback: Try Base64 decode for old wallets (before master key encryption)
            warn!("⚠️  Shard B not encrypted - using legacy Base64 format");
            BASE64_STANDARD.decode(&container.shard_b_data)
                .map_err(|_| err("Failed to decrypt Shard B (Server Key)"))?
        }
    };
    
    let share_b: frost::keys::SecretShare = serde_json::from_slice(&share_b_bytes)
        .map_err(|_| err("Malformed Share B"))?;

    // 4. Load Public Key Package from ReDB
    let pk_pkg_bytes = state.blockchain.get_frost_pub_key_package(&req.from_wallet_id)
        .map_err(|e| err(format!("PublicKeyPackage not found: {}", e)))?;
    let pub_key_package: frost::keys::PublicKeyPackage = serde_json::from_slice(&pk_pkg_bytes)
        .map_err(|_| err("Bad PublicKeyPackage format"))?;

    // 5. Construct KeyPackages
    let pkg_a = frost::keys::KeyPackage::try_from(share_a.clone()).map_err(|e| err(e.to_string()))?;
    let pkg_b = frost::keys::KeyPackage::try_from(share_b.clone()).map_err(|e| err(e.to_string()))?;

    // 6. Sign Transaction with FROST
    let mut rng = OsRng;
    let tx_message = format!("{}:{}:{}", req.from_wallet_id, req.to_address, req.amount);
    let message = tx_message.as_bytes();

    // Round 1: Commitments
    let (nonces_a, commitments_a) = frost::round1::commit(pkg_a.signing_share(), &mut rng);
    let (nonces_b, commitments_b) = frost::round1::commit(pkg_b.signing_share(), &mut rng);

    let mut commitments_map = std::collections::BTreeMap::new();
    commitments_map.insert(*share_a.identifier(), commitments_a);
    commitments_map.insert(*share_b.identifier(), commitments_b);
    
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: Signature Shares
    let sig_share_a = frost::round2::sign(&signing_package, &nonces_a, &pkg_a).map_err(|e| err(e.to_string()))?;
    let sig_share_b = frost::round2::sign(&signing_package, &nonces_b, &pkg_b).map_err(|e| err(e.to_string()))?;

    let mut sig_shares = std::collections::BTreeMap::new();
    sig_shares.insert(*share_a.identifier(), sig_share_a);
    sig_shares.insert(*share_b.identifier(), sig_share_b);

    let signature = frost::aggregate(&signing_package, &sig_shares, &pub_key_package)
        .map_err(|e| err(e.to_string()))?;

    info!("✅ Transaction signed with FROST for wallet {}", req.from_wallet_id);

    // 7. Execute Transfer on Blockchain
    state.blockchain.transfer(&req.from_wallet_id, &req.to_address, req.amount)
        .map_err(|e| err(format!("Transfer failed: {}", e)))?;

    info!("💸 Transfer: {} → {} : {} BB", req.from_wallet_id, req.to_address, req.amount);

    // Zeroize sensitive data
    share_a_decrypted.zeroize();
    
    Ok(Json(json!({
        "success": true,
        "signature": hex::encode(signature.serialize().unwrap()),
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
