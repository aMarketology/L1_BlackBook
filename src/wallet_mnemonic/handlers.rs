//! # Mnemonic Wallet HTTP Handlers
//!
//! Axum handlers for the Consumer Track (mnemonic-based) wallet operations.
//!
//! ## Endpoints
//!
//! - `POST /mnemonic/create` - Create new wallet (returns address, stores shares)
//! - `POST /mnemonic/sign` - Sign a transaction (reconstruct → sign → wipe)
//! - `POST /mnemonic/recover` - Recover wallet with 24 words
//! - `GET /mnemonic/export/:address` - Export 24 words (requires 2FA)
//! - `POST /mnemonic/share-b/store` - Store Share B on-chain
//! - `POST /mnemonic/share-b/release` - Release Share B (with ZKP)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, warn};

use crate::wallet_mnemonic::{
    mnemonic::{generate_wallet, recover_wallet, entropy_to_mnemonic, WalletKeys, MnemonicError},
    sss::{
        create_mnemonic_shares, reconstruct_from_ab, SecureShare,
        SSSError, MnemonicWalletShares,
    },
    signer::{MnemonicSigner, WalletSigner, SignerError},
    WalletSecurityMode, MnemonicConfig, WalletMetadata,
};
use crate::storage::ConcurrentBlockchain;

// ============================================================================
// HANDLER STATE
// ============================================================================

/// State for mnemonic wallet handlers
/// 
/// Architecture:
/// - Share B: Stored on L1 blockchain (ConcurrentBlockchain) for recovery
/// - Share C: In-memory for now (production: Supabase)  
/// - Metadata: In-memory cache (also persisted to blockchain)
/// - Password salts: In-memory cache (also persisted with metadata)
#[derive(Clone)]
pub struct MnemonicHandlers {
    /// Reference to L1 blockchain for Share B persistent storage
    blockchain: Option<Arc<ConcurrentBlockchain>>,
    /// In-memory wallet metadata cache (production: backed by DB)
    wallets: Arc<DashMap<String, WalletMetadata>>,
    /// In-memory Share B cache (for performance, backed by L1)
    share_b_cache: Arc<DashMap<String, SecureShare>>,
    /// Share C storage (production: Supabase)
    share_c_storage: Arc<DashMap<String, Vec<u8>>>,
    /// Password salts (stored with wallet metadata)
    password_salts: Arc<DashMap<String, Vec<u8>>>,
    /// Vault pepper (production: fetch from HashiCorp Vault)
    vault_pepper: Vec<u8>,
}

impl MnemonicHandlers {
    /// Create handlers without blockchain (for testing/fallback to in-memory)
    pub fn new() -> Self {
        Self {
            blockchain: None,
            wallets: Arc::new(DashMap::new()),
            share_b_cache: Arc::new(DashMap::new()),
            share_c_storage: Arc::new(DashMap::new()),
            password_salts: Arc::new(DashMap::new()),
            // In production, this comes from Vault
            vault_pepper: b"blackbook_pepper_32_bytes_long!!".to_vec(),
        }
    }
    
    /// Create handlers with blockchain for persistent Share B storage
    pub fn with_blockchain(blockchain: Arc<ConcurrentBlockchain>) -> Self {
        Self {
            blockchain: Some(blockchain),
            wallets: Arc::new(DashMap::new()),
            share_b_cache: Arc::new(DashMap::new()),
            share_c_storage: Arc::new(DashMap::new()),
            password_salts: Arc::new(DashMap::new()),
            vault_pepper: b"blackbook_pepper_32_bytes_long!!".to_vec(),
        }
    }
    
    /// Store Share B - persists to L1 blockchain if available
    fn store_share_b_internal(&self, address: &str, share: &SecureShare) -> Result<(), String> {
        // Always store in cache
        self.share_b_cache.insert(address.to_string(), share.clone());
        
        // Persist to blockchain if available
        if let Some(ref blockchain) = self.blockchain {
            let serialized = share.to_hex();
            blockchain.store_wallet_share(address, serialized.as_bytes())?;
            info!("📦 Share B stored on-chain for: {}", address);
        } else {
            info!("📦 Share B stored in-memory (no blockchain) for: {}", address);
        }
        Ok(())
    }
    
    /// Get Share B - checks cache first, then blockchain
    fn get_share_b_internal(&self, address: &str) -> Result<SecureShare, String> {
        // Check cache first
        if let Some(share) = self.share_b_cache.get(address) {
            return Ok(share.clone());
        }
        
        // Try blockchain
        if let Some(ref blockchain) = self.blockchain {
            if let Some(data) = blockchain.get_wallet_share(address)? {
                let hex_str = String::from_utf8(data)
                    .map_err(|e| format!("Invalid share data: {}", e))?;
                let share = SecureShare::from_hex(&hex_str)
                    .map_err(|e| format!("Invalid share format: {}", e))?;
                
                // Populate cache
                self.share_b_cache.insert(address.to_string(), share.clone());
                return Ok(share);
            }
        }
        
        Err("Share B not found".to_string())
    }
    
    /// Store wallet metadata (serialized to blockchain)
    fn store_metadata_internal(&self, metadata: &WalletMetadata) -> Result<(), String> {
        self.wallets.insert(metadata.address.clone(), metadata.clone());
        
        if let Some(ref blockchain) = self.blockchain {
            let serialized = serde_json::to_vec(metadata)
                .map_err(|e| format!("Failed to serialize metadata: {}", e))?;
            blockchain.store_wallet_metadata(&metadata.address, &serialized)?;
        }
        Ok(())
    }
    
    /// Get wallet metadata
    fn get_metadata_internal(&self, address: &str) -> Result<WalletMetadata, String> {
        // Check cache
        if let Some(metadata) = self.wallets.get(address) {
            return Ok(metadata.clone());
        }
        
        // Try blockchain
        if let Some(ref blockchain) = self.blockchain {
            if let Some(data) = blockchain.get_wallet_metadata(address)? {
                let metadata: WalletMetadata = serde_json::from_slice(&data)
                    .map_err(|e| format!("Failed to deserialize metadata: {}", e))?;
                self.wallets.insert(address.to_string(), metadata.clone());
                return Ok(metadata);
            }
        }
        
        Err("Wallet not found".to_string())
    }
    
    /// Create Axum router with all mnemonic routes
    pub fn router() -> Router<Self> {
        Router::new()
            // Wallet lifecycle
            .route("/mnemonic/create", post(Self::create_wallet))
            .route("/mnemonic/recover", post(Self::recover_from_mnemonic))
            .route("/mnemonic/export/:address", post(Self::export_mnemonic))
            // Signing
            .route("/mnemonic/sign", post(Self::sign_transaction))
            // Share management
            .route("/mnemonic/share-b/:address", get(Self::get_share_b))
            .route("/mnemonic/share-b", post(Self::store_share_b))
            .route("/mnemonic/share-c/:address", get(Self::get_share_c))
            // Recovery paths (2-of-3 combinations)
            .route("/mnemonic/recover/ab", post(Self::recover_via_ab))
            .route("/mnemonic/recover/ac", post(Self::recover_via_ac))
            .route("/mnemonic/recover/bc", post(Self::recover_via_bc))
            // Health
            .route("/mnemonic/health", get(Self::health))
            .route("/mnemonic/info/:address", get(Self::wallet_info))
    }
}

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateWalletRequest {
    /// User's password (used to bind Share A)
    pub password: String,
    /// Optional BIP-39 passphrase (25th word)
    #[serde(default)]
    pub bip39_passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct CreateWalletResponse {
    /// The wallet address (bb_...)
    pub wallet_address: String,
    /// Public key (hex)
    pub public_key: String,
    /// Share A (bound to password) - CLIENT MUST STORE THIS
    pub share_a_bound: String,
    /// Password salt - CLIENT MUST STORE THIS
    pub password_salt: String,
    /// Security mode
    pub security_mode: String,
    /// IMPORTANT: Mnemonic is NOT returned - it's split and distributed
    pub mnemonic_stored: bool,
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    /// The 24-word mnemonic
    pub mnemonic: String,
    /// New password for Share A binding
    pub password: String,
    /// Optional BIP-39 passphrase
    #[serde(default)]
    pub bip39_passphrase: String,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Wallet address
    pub wallet_address: String,
    /// Password (to unbind Share A)
    pub password: String,
    /// Share A bound (hex)
    pub share_a_bound: String,
    /// Message to sign (hex)
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    /// Signature (hex)
    pub signature: String,
    /// Public key (hex)
    pub public_key: String,
    /// Message that was signed (hex)
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    /// Password for verification
    pub password: String,
    /// 2FA code (production: implement properly)
    pub two_factor_code: String,
    /// Share A bound (hex)
    pub share_a_bound: String,
}

#[derive(Debug, Serialize)]
pub struct ExportResponse {
    /// The 24-word mnemonic (SENSITIVE!)
    pub mnemonic: String,
    /// Security warning
    pub warning: String,
}

#[derive(Debug, Deserialize)]
pub struct StoreShareBRequest {
    /// Wallet address
    pub wallet_address: String,
    /// Share B (hex)
    pub share_b: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub wallet_type: String,
    pub features: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WalletInfoResponse {
    pub wallet_address: String,
    pub public_key: String,
    pub security_mode: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// Recovery Request Types for 2-of-3 SSS combinations

/// Recover via Share A (password-bound) + Share B (L1 blockchain)
#[derive(Debug, Deserialize)]
pub struct RecoverABRequest {
    pub wallet_address: String,
    pub password: String,
    pub share_a_bound: String,
}

/// Recover via Share A (password-bound) + Share C (Vault-encrypted)
#[derive(Debug, Deserialize)]
pub struct RecoverACRequest {
    pub wallet_address: String,
    pub password: String,
    pub share_a_bound: String,
}

/// Recover via Share B (L1) + Share C (Vault) - PRIVILEGED PATH
#[derive(Debug, Deserialize)]
pub struct RecoverBCRequest {
    pub wallet_address: String,
    /// Admin/recovery key for privileged access
    pub admin_key: String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryResponse {
    pub success: bool,
    pub wallet_address: String,
    pub mnemonic: String,
    pub recovery_path: String,
    pub warning: String,
}

// ============================================================================
// HANDLERS
// ============================================================================

impl MnemonicHandlers {
    /// Health check
    async fn health() -> Json<HealthResponse> {
        Json(HealthResponse {
            status: "healthy".to_string(),
            wallet_type: "mnemonic-sss".to_string(),
            features: vec![
                "bip39-24-word".to_string(),
                "shamir-2-of-3".to_string(),
                "password-bound-share-a".to_string(),
                "vault-pepper-share-c".to_string(),
            ],
        })
    }
    
    /// Create new mnemonic wallet
    async fn create_wallet(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<CreateWalletRequest>,
    ) -> Result<Json<CreateWalletResponse>, (StatusCode, Json<ErrorResponse>)> {
        info!("Creating new mnemonic wallet");
        
        // Generate wallet (entropy → mnemonic → keys)
        let wallet = generate_wallet(&req.bip39_passphrase)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Convert mnemonic to entropy for SSS
        let entropy = crate::wallet_mnemonic::mnemonic::mnemonic_to_entropy(&wallet.mnemonic)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Split into shares
        let shares = create_mnemonic_shares(&entropy, &req.password, &state.vault_pepper)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Store Share B (uses L1 blockchain if available)
        state.store_share_b_internal(&wallet.address, &shares.share_b)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Store Share C encrypted (in production: in Supabase)
        state.share_c_storage.insert(
            wallet.address.clone(),
            shares.share_c_encrypted.clone(),
        );
        
        // Store password salt
        state.password_salts.insert(
            wallet.address.clone(),
            shares.password_salt.clone(),
        );
        
        // Store wallet metadata (uses blockchain if available)
        let metadata = WalletMetadata {
            address: wallet.address.clone(),
            public_key: hex::encode(wallet.public_key.to_bytes()),
            security_mode: WalletSecurityMode::Deterministic(MnemonicConfig {
                share_a_salt: hex::encode(&shares.password_salt),
                share_b_location: format!("l1:{}", wallet.address),
                share_c_vault_key: "blackbook/pepper".to_string(),
                derivation_path: "m/44'/501'/0'/0'".to_string(),
                has_been_exported: false,
            }),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        state.store_metadata_internal(&metadata)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Clone values before wallet is dropped
        let address = wallet.address.clone();
        let public_key_bytes = wallet.public_key.to_bytes();
        
        let storage_mode = if state.blockchain.is_some() { "L1-blockchain" } else { "in-memory" };
        info!("✅ Created mnemonic wallet: {} (Share B: {})", address, storage_mode);
        
        // Return (mnemonic is NOT returned - it's been split)
        Ok(Json(CreateWalletResponse {
            wallet_address: address,
            public_key: hex::encode(public_key_bytes),
            share_a_bound: shares.share_a_bound.to_hex(),
            password_salt: hex::encode(&shares.password_salt),
            security_mode: "Deterministic".to_string(),
            mnemonic_stored: true, // Mnemonic was split, not stored raw
        }))
        
        // NOTE: wallet.mnemonic is zeroized when WalletKeys is dropped
    }
    
    /// Sign a transaction
    async fn sign_transaction(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<SignRequest>,
    ) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
        info!("Signing transaction for: {}", req.wallet_address);
        
        // Get wallet metadata
        let metadata = state.get_metadata_internal(&req.wallet_address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Get Share B (from cache or blockchain)
        let share_b = state.get_share_b_internal(&req.wallet_address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Get password salt
        let salt = state.password_salts.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Password salt not found".to_string() })
            ))?;
        
        // Parse Share A from request
        let share_a = SecureShare::from_hex(&req.share_a_bound)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
            ))?;
        
        // Parse message
        let message = hex::decode(&req.message)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid message hex: {}", e) })
            ))?;
        
        // Parse public key
        let pk_bytes = hex::decode(&metadata.public_key)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Invalid stored public key: {}", e) })
            ))?;
        let pk_array: [u8; 32] = pk_bytes.try_into()
            .map_err(|_| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Invalid public key length".to_string() })
            ))?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Invalid public key: {}", e) })
            ))?;
        
        // Create signer
        let signer = MnemonicSigner::with_shares_ab(
            req.wallet_address.clone(),
            public_key,
            share_a,
            share_b,
            req.password.clone(),
            salt,
            String::new(), // BIP-39 passphrase
        );
        
        // Sign (reconstructs key, signs, wipes key)
        let result = signer.sign(&message).await
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Signing failed: {}", e) })
            ))?;
        
        info!("✅ Transaction signed for: {}", req.wallet_address);
        
        Ok(Json(SignResponse {
            signature: hex::encode(result.signature.to_bytes()),
            public_key: hex::encode(result.public_key.to_bytes()),
            message: hex::encode(&result.message),
        }))
    }
    
    /// Recover wallet from 24-word mnemonic
    async fn recover_from_mnemonic(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<RecoverRequest>,
    ) -> Result<Json<CreateWalletResponse>, (StatusCode, Json<ErrorResponse>)> {
        info!("Recovering wallet from mnemonic");
        
        // Validate word count
        let word_count = req.mnemonic.split_whitespace().count();
        if word_count != 24 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { 
                    error: format!("Expected 24 words, got {}", word_count) 
                })
            ));
        }
        
        // Recover wallet
        let wallet = recover_wallet(&req.mnemonic, &req.bip39_passphrase)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid mnemonic: {}", e) })
            ))?;
        
        // Convert mnemonic to entropy for SSS
        let entropy = crate::wallet_mnemonic::mnemonic::mnemonic_to_entropy(&req.mnemonic)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Split into new shares with new password
        let shares = create_mnemonic_shares(&entropy, &req.password, &state.vault_pepper)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() })
            ))?;
        
        // Store shares (overwrites if wallet already exists)
        state.store_share_b_internal(&wallet.address, &shares.share_b)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e })
            ))?;
        state.share_c_storage.insert(wallet.address.clone(), shares.share_c_encrypted.clone());
        state.password_salts.insert(wallet.address.clone(), shares.password_salt.clone());
        
        // Store/update metadata
        let metadata = WalletMetadata {
            address: wallet.address.clone(),
            public_key: hex::encode(wallet.public_key.to_bytes()),
            security_mode: WalletSecurityMode::Deterministic(MnemonicConfig {
                share_a_salt: hex::encode(&shares.password_salt),
                share_b_location: format!("l1:{}", wallet.address),
                share_c_vault_key: "blackbook/pepper".to_string(),
                derivation_path: "m/44'/501'/0'/0'".to_string(),
                has_been_exported: true, // User already has mnemonic
            }),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        state.store_metadata_internal(&metadata)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Clone values before wallet is dropped
        let address = wallet.address.clone();
        let public_key_bytes = wallet.public_key.to_bytes();
        
        info!("✅ Recovered wallet: {}", address);
        
        Ok(Json(CreateWalletResponse {
            wallet_address: address,
            public_key: hex::encode(public_key_bytes),
            share_a_bound: shares.share_a_bound.to_hex(),
            password_salt: hex::encode(&shares.password_salt),
            security_mode: "Deterministic".to_string(),
            mnemonic_stored: true,
        }))
    }
    
    /// Export 24-word mnemonic (SENSITIVE!)
    async fn export_mnemonic(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
        Json(req): Json<ExportRequest>,
    ) -> Result<Json<ExportResponse>, (StatusCode, Json<ErrorResponse>)> {
        warn!("⚠️ Mnemonic export requested for: {}", address);
        
        // Verify 2FA (in production: implement properly)
        if req.two_factor_code != "123456" {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "Invalid 2FA code".to_string() })
            ));
        }
        
        // Get shares
        let share_b = state.get_share_b_internal(&address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        let salt = state.password_salts.get(&address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Password salt not found".to_string() })
            ))?;
        
        // Parse Share A
        let share_a = SecureShare::from_hex(&req.share_a_bound)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
            ))?;
        
        // Reconstruct entropy
        let entropy = reconstruct_from_ab(&share_a, &share_b, &req.password, &salt)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Reconstruction failed: {}", e) })
            ))?;
        
        // Convert to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Mnemonic generation failed: {}", e) })
            ))?;
        
        // Mark as exported
        if let Some(mut metadata) = state.wallets.get_mut(&address) {
            if let WalletSecurityMode::Deterministic(ref mut config) = metadata.security_mode {
                config.has_been_exported = true;
            }
        }
        
        warn!("⚠️ Mnemonic exported for: {} - User now has full control", address);
        
        Ok(Json(ExportResponse {
            mnemonic,
            warning: "WRITE THIS DOWN AND STORE SAFELY. Anyone with these 24 words can access your wallet. This phrase can be imported into MetaMask, Phantom, or any BIP-39 compatible wallet.".to_string(),
        }))
    }
    
    /// Store Share B (in production: ZKP-gated L1 storage)
    async fn store_share_b(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<StoreShareBRequest>,
    ) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
        let share = SecureShare::from_hex(&req.share_b)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid share: {}", e) })
            ))?;
        
        state.store_share_b_internal(&req.wallet_address, &share)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e })
            ))?;
        
        info!("✅ Share B stored for: {}", req.wallet_address);
        Ok(StatusCode::OK)
    }
    
    /// Get Share B (in production: requires ZKP proof)
    async fn get_share_b(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
        // In production: add ZKP proof verification here
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        let share = state.get_share_b_internal(&address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        Ok(Json(serde_json::json!({
            "share_b": share.to_hex()
        })))
    }
    
    /// Get wallet info
    async fn wallet_info(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
    ) -> Result<Json<WalletInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
        let metadata = state.get_metadata_internal(&address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        Ok(Json(WalletInfoResponse {
            wallet_address: metadata.address,
            public_key: metadata.public_key,
            security_mode: match metadata.security_mode {
                WalletSecurityMode::Threshold(_) => "Threshold".to_string(),
                WalletSecurityMode::Deterministic(_) => "Deterministic".to_string(),
            },
            created_at: metadata.created_at,
        }))
    }
    
    /// Get Share C (encrypted) - for testing recovery paths
    async fn get_share_c(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        let share_c = state.share_c_storage.get(&address)
            .map(|s| hex::encode(s.value()))
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Share C not found".to_string() })
            ))?;
        
        Ok(Json(serde_json::json!({
            "share_c_encrypted": share_c
        })))
    }
    
    // ========================================================================
    // 2-of-3 SSS RECOVERY PATHS
    // ========================================================================
    
    /// Recovery Path: Share A (password-bound) + Share B (L1 blockchain)
    /// This is the NORMAL daily operation path
    async fn recover_via_ab(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<RecoverABRequest>,
    ) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
        info!("🔓 Recovery via A+B for: {}", req.wallet_address);
        
        // Get Share B from L1
        let share_b = state.get_share_b_internal(&req.wallet_address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Get password salt
        let salt = state.password_salts.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Password salt not found".to_string() })
            ))?;
        
        // Parse Share A
        let share_a = SecureShare::from_hex(&req.share_a_bound)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
            ))?;
        
        // Reconstruct via A+B
        let entropy = reconstruct_from_ab(&share_a, &share_b, &req.password, &salt)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Reconstruction failed: {}", e) })
            ))?;
        
        // Convert to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Mnemonic generation failed: {}", e) })
            ))?;
        
        info!("✅ Recovery via A+B successful for: {}", req.wallet_address);
        
        Ok(Json(RecoveryResponse {
            success: true,
            wallet_address: req.wallet_address,
            mnemonic,
            recovery_path: "A+B (Client + L1 Blockchain)".to_string(),
            warning: "⚠️ Store this mnemonic safely. Anyone with these 24 words can access your wallet.".to_string(),
        }))
    }
    
    /// Recovery Path: Share A (password-bound) + Share C (Vault-encrypted)
    /// Emergency recovery when L1 blockchain is unavailable
    async fn recover_via_ac(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<RecoverACRequest>,
    ) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
        warn!("⚠️ Recovery via A+C (emergency path) for: {}", req.wallet_address);
        
        // Get Share C encrypted
        let share_c_encrypted = state.share_c_storage.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Share C not found".to_string() })
            ))?;
        
        // Get password salt
        let salt = state.password_salts.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Password salt not found".to_string() })
            ))?;
        
        // Parse Share A
        let share_a = SecureShare::from_hex(&req.share_a_bound)
            .map_err(|e| (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
            ))?;
        
        // Reconstruct via A+C
        use crate::wallet_mnemonic::sss::reconstruct_from_ac;
        let entropy = reconstruct_from_ac(&share_a, &share_c_encrypted, &req.password, &salt, &state.vault_pepper)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Reconstruction failed: {}", e) })
            ))?;
        
        // Convert to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Mnemonic generation failed: {}", e) })
            ))?;
        
        warn!("✅ Recovery via A+C successful for: {} (emergency path used)", req.wallet_address);
        
        Ok(Json(RecoveryResponse {
            success: true,
            wallet_address: req.wallet_address,
            mnemonic,
            recovery_path: "A+C (Client + HashiCorp Vault)".to_string(),
            warning: "⚠️ EMERGENCY RECOVERY PATH USED. This bypassed L1 blockchain. Store mnemonic safely.".to_string(),
        }))
    }
    
    /// Recovery Path: Share B (L1) + Share C (Vault)
    /// PRIVILEGED PATH - Only for estate recovery, legal compliance, etc.
    /// ⚠️ This bypasses user authentication entirely!
    async fn recover_via_bc(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<RecoverBCRequest>,
    ) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
        warn!("🚨 PRIVILEGED Recovery via B+C requested for: {}", req.wallet_address);
        
        // Verify admin key (in production: proper admin authentication)
        const ADMIN_KEY: &str = "blackbook_admin_recovery_key_2026";
        if req.admin_key != ADMIN_KEY {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "Invalid admin key".to_string() })
            ));
        }
        
        // Get Share B from L1
        let share_b = state.get_share_b_internal(&req.wallet_address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Get Share C encrypted
        let share_c_encrypted = state.share_c_storage.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Share C not found".to_string() })
            ))?;
        
        // Reconstruct via B+C (PRIVILEGED - no password needed!)
        use crate::wallet_mnemonic::sss::reconstruct_from_bc;
        let entropy = reconstruct_from_bc(&share_b, &share_c_encrypted, &state.vault_pepper)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Reconstruction failed: {}", e) })
            ))?;
        
        // Convert to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Mnemonic generation failed: {}", e) })
            ))?;
        
        warn!("🚨 PRIVILEGED Recovery via B+C completed for: {} - User password bypassed!", req.wallet_address);
        
        Ok(Json(RecoveryResponse {
            success: true,
            wallet_address: req.wallet_address,
            mnemonic,
            recovery_path: "B+C (L1 Blockchain + HashiCorp Vault) - PRIVILEGED".to_string(),
            warning: "🚨 PRIVILEGED RECOVERY - User authentication was bypassed. This should only be used for estate recovery, legal compliance, or catastrophic loss scenarios.".to_string(),
        }))
    }
}

impl Default for MnemonicHandlers {
    fn default() -> Self {
        Self::new()
    }
}
