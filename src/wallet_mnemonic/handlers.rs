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
    extract::{Path, State, ConnectInfo},
    http::StatusCode,
    Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use dashmap::DashMap;
use tracing::{info, warn, error};

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
// CONSTANTS
// ============================================================================

/// High-value transaction threshold requiring Vault pepper fetch
/// Transactions >= 1000 BB must fetch pepper from HashiCorp Vault dynamically
const HIGH_VALUE_THRESHOLD: f64 = 1000.0;

/// Rate limiting: Maximum ZKP challenge requests per minute (per IP)
const MAX_CHALLENGES_PER_IP_PER_MIN: usize = 10;

/// Rate limiting: Maximum ZKP challenge requests per minute (per wallet)
const MAX_CHALLENGES_PER_WALLET_PER_MIN: usize = 3;

/// Rate limiting: Maximum failed ZKP attempts per hour (per wallet)
const MAX_FAILED_ZKP_PER_WALLET_PER_HOUR: usize = 5;

/// Rate limiting window (60 seconds)
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Failed ZKP lockout window (3600 seconds = 1 hour)
const FAILED_ZKP_LOCKOUT_SECS: u64 = 3600;

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
    /// ZKP challenges (address -> (challenge, expiry_timestamp))
    zkp_challenges: Arc<DashMap<String, (String, u64)>>,
    /// Rate limiting: IP -> Vec<(timestamp)> for challenge requests
    rate_limit_ip: Arc<DashMap<String, Vec<u64>>>,
    /// Rate limiting: wallet address -> Vec<(timestamp)> for challenge requests
    rate_limit_wallet: Arc<DashMap<String, Vec<u64>>>,
    /// Failed ZKP attempts: wallet address -> Vec<(timestamp)>
    failed_zkp_attempts: Arc<DashMap<String, Vec<u64>>>,
    /// Audit log storage (address -> Vec<AuditEvent>)
    audit_logs: Arc<DashMap<String, Vec<AuditEvent>>>,
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
            zkp_challenges: Arc::new(DashMap::new()),
            rate_limit_ip: Arc::new(DashMap::new()),
            rate_limit_wallet: Arc::new(DashMap::new()),
            failed_zkp_attempts: Arc::new(DashMap::new()),
            audit_logs: Arc::new(DashMap::new()),
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
            zkp_challenges: Arc::new(DashMap::new()),
            rate_limit_ip: Arc::new(DashMap::new()),
            rate_limit_wallet: Arc::new(DashMap::new()),
            failed_zkp_attempts: Arc::new(DashMap::new()),
            audit_logs: Arc::new(DashMap::new()),
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
    
    // ========================================================================
    // RATE LIMITING HELPERS
    // ========================================================================
    
    /// Check if IP address is rate limited for challenge requests
    fn check_ip_rate_limit(&self, ip: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut entry = self.rate_limit_ip.entry(ip.to_string()).or_insert_with(Vec::new);
        
        // Remove timestamps older than window
        entry.retain(|&ts| now - ts < RATE_LIMIT_WINDOW_SECS);
        
        // Check if over limit
        if entry.len() >= MAX_CHALLENGES_PER_IP_PER_MIN {
            return Err(format!(
                "Rate limit exceeded: {} requests/min from IP {}", 
                MAX_CHALLENGES_PER_IP_PER_MIN, ip
            ));
        }
        
        // Add current timestamp
        entry.push(now);
        Ok(())
    }
    
    /// Check if wallet address is rate limited for challenge requests
    fn check_wallet_rate_limit(&self, address: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut entry = self.rate_limit_wallet.entry(address.to_string()).or_insert_with(Vec::new);
        
        // Remove timestamps older than window
        entry.retain(|&ts| now - ts < RATE_LIMIT_WINDOW_SECS);
        
        // Check if over limit
        if entry.len() >= MAX_CHALLENGES_PER_WALLET_PER_MIN {
            return Err(format!(
                "Rate limit exceeded: {} requests/min for wallet {}", 
                MAX_CHALLENGES_PER_WALLET_PER_MIN, address
            ));
        }
        
        // Add current timestamp
        entry.push(now);
        Ok(())
    }
    
    /// Check if wallet has too many failed ZKP attempts (lockout protection)
    fn check_failed_zkp_lockout(&self, address: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut entry = self.failed_zkp_attempts.entry(address.to_string()).or_insert_with(Vec::new);
        
        // Remove timestamps older than lockout window
        entry.retain(|&ts| now - ts < FAILED_ZKP_LOCKOUT_SECS);
        
        // Check if locked out
        if entry.len() >= MAX_FAILED_ZKP_PER_WALLET_PER_HOUR {
            return Err(format!(
                "Wallet locked: {} failed ZKP attempts in 1 hour. Try again later.", 
                MAX_FAILED_ZKP_PER_WALLET_PER_HOUR
            ));
        }
        
        Ok(())
    }
    
    /// Record failed ZKP attempt
    fn record_failed_zkp(&self, address: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut entry = self.failed_zkp_attempts.entry(address.to_string()).or_insert_with(Vec::new);
        entry.push(now);
    }
    
    // ========================================================================
    // AUDIT LOGGING HELPERS
    // ========================================================================
    
    /// Log audit event to in-memory storage (production: send to SIEM/logging service)
    fn log_audit_event(&self, event: AuditEvent) {
        let address = event.wallet_address.clone();
        
        // Log to console (structured JSON for production parsing)
        let json = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
        info!("🔍 AUDIT: {}", json);
        
        // Store in memory (production: ship to Elasticsearch/Datadog/etc.)
        let mut entry = self.audit_logs.entry(address).or_insert_with(Vec::new);
        entry.push(event);
        
        // Keep only last 1000 events per wallet to prevent memory bloat
        if entry.len() > 1000 {
            entry.drain(0..100); // Remove oldest 100
        }
    }
    
    /// Log high-value transaction for compliance
    fn log_high_value_transfer(&self, from: &str, to: &str, amount: f64, tx_id: &str, vault_used: bool) {
        let event = AuditEvent::new(
            "high_value_transfer",
            from,
            None,
            serde_json::json!({
                "to": to,
                "amount": amount,
                "tx_id": tx_id,
                "vault_pepper_fetched": vault_used,
                "threshold": HIGH_VALUE_THRESHOLD
            }),
            true,
            None,
        );
        self.log_audit_event(event);
    }
    
    /// Log privileged B+C recovery attempt (admin bypass)
    fn log_privileged_recovery(&self, address: &str, admin_id: &str, success: bool, error: Option<String>) {
        let event = AuditEvent::new(
            "privileged_bc_recovery",
            address,
            None,
            serde_json::json!({
                "admin_identifier": admin_id,
                "bypass_password": true,
                "recovery_path": "B+C"
            }),
            success,
            error,
        );
        self.log_audit_event(event);
        
        if success {
            warn!("🚨 PRIVILEGED RECOVERY: Admin {} recovered wallet {} via B+C path (password bypassed)", 
                admin_id, address);
        }
    }
    
    // ========================================================================
    // ROUTER & METADATA HELPERS
    // ========================================================================
    
    /// Create Axum router with all mnemonic routes
    pub fn router() -> Router<Self> {
        Router::new()
            // Wallet lifecycle
            .route("/mnemonic/create", post(Self::create_wallet))
            .route("/mnemonic/recover", post(Self::recover_from_mnemonic))
            .route("/mnemonic/export/:address", post(Self::export_mnemonic))
            // Signing
            .route("/mnemonic/sign", post(Self::sign_transaction))
            // Transfer (sign + execute)
            .route("/mnemonic/transfer", post(Self::transfer))
            // ZKP Challenge for Share B retrieval
            .route("/mnemonic/zkp/challenge/:address", post(Self::request_zkp_challenge))
            // Share management (Share B requires ZKP)
            .route("/mnemonic/share-b/:address", post(Self::get_share_b_with_zkp))
            .route("/mnemonic/share-b", post(Self::store_share_b))
            .route("/mnemonic/share-c/:address", get(Self::get_share_c))
            // Recovery paths (2-of-3 combinations)
            .route("/mnemonic/recover/ab", post(Self::recover_via_ab))
            .route("/mnemonic/recover/ac", post(Self::recover_via_ac))
            .route("/mnemonic/recover/bc", post(Self::recover_via_bc))
            // Multi-sig B+C recovery (requires 2-of-3 admin signatures)
            .route("/mnemonic/recover/bc/multisig", post(Self::recover_via_bc_multisig))
            // Audit & SIEM
            .route("/audit/logs", get(Self::get_audit_logs))
            .route("/audit/logs/:address", get(Self::get_wallet_audit_logs))
            .route("/audit/export", post(Self::export_audit_logs))
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
    /// Whether to return the mnemonic in the response (default: false)
    #[serde(default)]
    pub show_mnemonic: bool,
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
    /// IMPORTANT: Mnemonic is NOT returned by default (it's split and distributed)
    pub mnemonic_stored: bool,
    /// 24-word mnemonic (only if show_mnemonic=true in request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
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

/// Transfer request - uses SSS to sign and execute transfer
#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    /// Sender wallet address
    pub from: String,
    /// Recipient wallet address
    pub to: String,
    /// Amount to transfer
    pub amount: f64,
    /// Sender's password
    pub password: String,
    /// Share A bound (hex)
    pub share_a_bound: String,
    /// Recovery path: "ab" (default), "ac", or "bc"
    #[serde(default = "default_recovery_path")]
    pub recovery_path: String,
    /// Share C encrypted (required for "ac" path)
    #[serde(default)]
    pub share_c_encrypted: Option<String>,
    /// Admin key (required for "bc" path)
    #[serde(default)]
    pub admin_key: Option<String>,
}

fn default_recovery_path() -> String {
    "ab".to_string()
}

#[derive(Debug, Serialize)]
pub struct TransferResponse {
    pub success: bool,
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub new_balance_from: f64,
    pub new_balance_to: f64,
    pub signature: String,
    pub recovery_path_used: String,
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

/// ZKP Proof Request for Share B retrieval
#[derive(Debug, Deserialize)]
pub struct ZKPProofRequest {
    /// Wallet's public key (hex, 32 bytes)
    pub public_key: String,
    /// Ed25519 signature of "BLACKBOOK_SHARE_B\n{challenge}\n{address}" (hex, 64 bytes)
    pub signature: String,
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

/// Audit event types for compliance and security monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event type (wallet_created, share_b_accessed, high_value_transfer, etc.)
    pub event_type: String,
    /// Wallet address involved
    pub wallet_address: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Client IP address (if available)
    pub ip_address: Option<String>,
    /// Additional metadata (JSON)
    pub metadata: serde_json::Value,
    /// Success/failure indicator
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl AuditEvent {
    /// Create new audit event
    fn new(
        event_type: &str,
        wallet_address: &str,
        ip: Option<String>,
        metadata: serde_json::Value,
        success: bool,
        error: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            event_type: event_type.to_string(),
            wallet_address: wallet_address.to_string(),
            timestamp,
            ip_address: ip,
            metadata,
            success,
            error,
        }
    }
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
            username: None, // Can be set via /mnemonic/wallet/{address}/username endpoint
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
        let mnemonic_words = if req.show_mnemonic {
            Some(wallet.mnemonic.clone())
        } else {
            None
        };
        
        let storage_mode = if state.blockchain.is_some() { "L1-blockchain" } else { "in-memory" };
        info!("✅ Created mnemonic wallet: {} (Share B: {})", address, storage_mode);
        
        // Return (mnemonic is only returned if show_mnemonic=true)
        Ok(Json(CreateWalletResponse {
            wallet_address: address,
            public_key: hex::encode(public_key_bytes),
            share_a_bound: shares.share_a_bound.to_hex(),
            password_salt: hex::encode(&shares.password_salt),
            security_mode: "Deterministic".to_string(),
            mnemonic_stored: true, // Mnemonic was split, not stored raw
            mnemonic: mnemonic_words,
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
    
    /// Transfer tokens using SSS-based signing
    /// 
    /// Supports all 3 recovery paths:
    /// - A+B (default): Password + L1 blockchain
    /// - A+C: Password + HashiCorp Vault (emergency)
    /// - B+C: L1 blockchain + Vault (privileged, admin only)
    async fn transfer(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<TransferRequest>,
    ) -> Result<Json<TransferResponse>, (StatusCode, Json<ErrorResponse>)> {
        info!("💸 Transfer: {} BB from {} to {}", req.amount, req.from, req.to);
        
        // Validate amount
        if req.amount <= 0.0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Amount must be positive".to_string() })
            ));
        }
        
        // Get blockchain reference
        let blockchain = state.blockchain.as_ref().ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Blockchain not available".to_string() })
        ))?;
        
        // Check sender balance
        let sender_balance = blockchain.get_balance(&req.from);
        if sender_balance < req.amount {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { 
                    error: format!("Insufficient balance: {} BB available, {} BB requested", 
                        sender_balance, req.amount) 
                })
            ));
        }
        
        // High-value transaction security: Fetch Vault pepper for >= 1000 BB
        let mut vault_pepper_fetched = false;
        if req.amount >= HIGH_VALUE_THRESHOLD {
            info!("⚠️  HIGH-VALUE TRANSFER: {} BB from {} to {}. Vault pepper fetch required.", 
                req.amount, req.from, req.to);
            
            // Attempt to fetch live pepper from HashiCorp Vault
            match crate::vault::get_pepper().await {
                Ok(pepper) => {
                    info!("✅ Vault pepper fetched successfully for {:.2} BB transfer", req.amount);
                    // Note: In production, update state.vault_pepper or use directly
                    // For now, we validate that Vault is accessible
                    vault_pepper_fetched = true;
                },
                Err(e) => {
                    warn!("❌ Vault pepper fetch failed: {}. Using cached pepper.", e);
                    // Continue with cached pepper (degraded mode)
                }
            }
        }
        
        // Reconstruct keypair based on recovery path
        let mnemonic = match req.recovery_path.as_str() {
            "ab" | "AB" => {
                // A+B: Password + L1 Blockchain (standard path)
                let share_a = SecureShare::from_hex(&req.share_a_bound)
                    .map_err(|e| (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
                    ))?;
                
                let share_b = state.get_share_b_internal(&req.from)
                    .map_err(|e| (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse { error: e })
                    ))?;
                
                let salt = state.password_salts.get(&req.from)
                    .map(|s| s.clone())
                    .ok_or_else(|| (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse { error: "Password salt not found".to_string() })
                    ))?;
                
                use crate::wallet_mnemonic::sss::reconstruct_from_ab;
                let entropy = reconstruct_from_ab(&share_a, &share_b, &req.password, &salt)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: format!("A+B reconstruction failed: {}", e) })
                    ))?;
                
                use crate::wallet_mnemonic::mnemonic::entropy_to_mnemonic;
                entropy_to_mnemonic(&entropy)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: e.to_string() })
                    ))?
            },
            "ac" | "AC" => {
                // A+C: Password + HashiCorp Vault (emergency path)
                let share_a = SecureShare::from_hex(&req.share_a_bound)
                    .map_err(|e| (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse { error: format!("Invalid Share A: {}", e) })
                    ))?;
                
                let share_c_encrypted = req.share_c_encrypted.as_ref().ok_or_else(|| (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: "share_c_encrypted required for A+C path".to_string() })
                ))?;
                
                let share_c_bytes = hex::decode(share_c_encrypted)
                    .map_err(|e| (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse { error: format!("Invalid Share C hex: {}", e) })
                    ))?;
                
                let salt = state.password_salts.get(&req.from)
                    .map(|s| s.clone())
                    .ok_or_else(|| (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse { error: "Password salt not found".to_string() })
                    ))?;
                
                use crate::wallet_mnemonic::sss::reconstruct_from_ac;
                let entropy = reconstruct_from_ac(&share_a, &share_c_bytes, &req.password, &salt, &state.vault_pepper)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: format!("A+C reconstruction failed: {}", e) })
                    ))?;
                
                use crate::wallet_mnemonic::mnemonic::entropy_to_mnemonic;
                entropy_to_mnemonic(&entropy)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: e.to_string() })
                    ))?
            },
            "bc" | "BC" => {
                // B+C: L1 Blockchain + Vault (privileged admin path)
                let admin_key = req.admin_key.as_ref().ok_or_else(|| (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: "admin_key required for B+C path".to_string() })
                ))?;
                
                // Verify admin key
                if admin_key != "blackbook_admin_recovery_key_2026" {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse { error: "Invalid admin key".to_string() })
                    ));
                }
                
                let share_b = state.get_share_b_internal(&req.from)
                    .map_err(|e| (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse { error: e })
                    ))?;
                
                let share_c_encrypted = state.share_c_storage.get(&req.from)
                    .map(|s| s.clone())
                    .ok_or_else(|| (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse { error: "Share C not found".to_string() })
                    ))?;
                
                use crate::wallet_mnemonic::sss::reconstruct_from_bc;
                let entropy = reconstruct_from_bc(&share_b, &share_c_encrypted, &state.vault_pepper)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: format!("B+C reconstruction failed: {}", e) })
                    ))?;
                
                use crate::wallet_mnemonic::mnemonic::entropy_to_mnemonic;
                entropy_to_mnemonic(&entropy)
                    .map_err(|e| (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: e.to_string() })
                    ))?
            },
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: format!("Invalid recovery_path: {}. Use 'ab', 'ac', or 'bc'", req.recovery_path) })
                ));
            }
        };
        
        // Recover wallet from mnemonic to get signing key
        use crate::wallet_mnemonic::mnemonic::recover_wallet;
        let wallet = recover_wallet(&mnemonic, "")
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Wallet recovery failed: {}", e) })
            ))?;
        
        // Create transfer message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tx_message = format!("TRANSFER|{}|{}|{}|{}", req.from, req.to, req.amount, timestamp);
        let tx_id = format!("tx_{:x}", md5::compute(&tx_message));
        
        // Sign the transfer using the secure private key
        use ed25519_dalek::Signer;
        let signing_key = wallet.private_key.to_signing_key();
        let signature = signing_key.sign(tx_message.as_bytes());
        
        // Execute the transfer on blockchain using atomic transfer() method
        // This properly logs as TRANSFER type (not separate BURN + MINT)
        blockchain.transfer(&req.from, &req.to, req.amount)
            .map_err(|e| (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("Transfer failed: {}", e) })
            ))?;
        
        // Get new balances
        let new_balance_from = blockchain.get_balance(&req.from);
        let new_balance_to = blockchain.get_balance(&req.to);
        
        // Audit logging for high-value transfers
        if req.amount >= HIGH_VALUE_THRESHOLD {
            state.log_high_value_transfer(&req.from, &req.to, req.amount, &tx_id, vault_pepper_fetched);
        }
        
        info!("✅ Transfer complete: {} BB from {} to {} (TX: {})", 
            req.amount, req.from, req.to, tx_id);
        
        Ok(Json(TransferResponse {
            success: true,
            tx_id,
            from: req.from.clone(),
            to: req.to.clone(),
            amount: req.amount,
            new_balance_from,
            new_balance_to,
            signature: hex::encode(signature.to_bytes()),
            recovery_path_used: req.recovery_path,
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
            username: None, // Can be set via /mnemonic/wallet/{address}/username endpoint
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
            mnemonic: None, // Mnemonic not returned in recovery (user already has it)
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

    /// Request ZKP challenge for Share B retrieval
    /// 
    /// Returns a random challenge that must be signed with the wallet's private key
    /// Challenge expires after 5 minutes
    /// 
    /// Rate limits:
    /// - 10 requests/min per IP address
    /// - 3 requests/min per wallet address
    async fn request_zkp_challenge(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        use rand::Rng;
        
        let ip = addr.ip().to_string();
        
        // Rate limiting: Check IP address
        if let Err(e) = state.check_ip_rate_limit(&ip) {
            warn!("🚫 Rate limit exceeded for IP {}: {}", ip, e);
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse { error: e })
            ));
        }
        
        // Rate limiting: Check wallet address
        if let Err(e) = state.check_wallet_rate_limit(&address) {
            warn!("🚫 Rate limit exceeded for wallet {}: {}", address, e);
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse { error: e })
            ));
        }
        
        // Clean up expired challenges (older than 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        state.zkp_challenges.retain(|_, (_, expiry)| *expiry > now);
        
        // Generate random 32-byte challenge
        let mut rng = rand::thread_rng();
        let challenge_bytes: [u8; 32] = rng.gen();
        let challenge = hex::encode(challenge_bytes);
        
        // Challenge expires in 5 minutes
        let expiry = now + 300;
        
        state.zkp_challenges.insert(address.clone(), (challenge.clone(), expiry));
        
        // Audit log
        let event = AuditEvent::new(
            "zkp_challenge_requested",
            &address,
            Some(ip.clone()),
            serde_json::json!({
                "challenge": &challenge[..16], // Log only first 16 chars for privacy
                "expires_at": expiry
            }),
            true,
            None,
        );
        state.log_audit_event(event);
        
        info!("🔐 ZKP challenge generated for wallet: {} (IP: {})", address, ip);
        
        Ok(Json(serde_json::json!({
            "challenge": challenge,
            "expires_at": expiry,
            "message": "Sign this challenge with your wallet's private key to prove ownership"
        })))
    }

    /// Get Share B with ZKP verification
    /// 
    /// Requires a signed challenge to prove wallet ownership
    /// Signature must be valid Ed25519 signature of: "BLACKBOOK_SHARE_B\n{challenge}\n{address}"
    /// 
    /// Security features:
    /// - Failed attempt tracking (5 failures = 1 hour lockout)
    /// - One-time challenge consumption
    /// - Public key → address validation
    /// - Audit logging
    async fn get_share_b_with_zkp(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        Json(req): Json<ZKPProofRequest>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        
        let ip = addr.ip().to_string();
        
        // Check failed attempt lockout
        if let Err(e) = state.check_failed_zkp_lockout(&address) {
            error!("🚫 ZKP lockout active for {}: {}", address, e);
            
            // Audit log failed access attempt during lockout
            let event = AuditEvent::new(
                "zkp_lockout_violation",
                &address,
                Some(ip),
                serde_json::json!({"reason": "too_many_failed_attempts"}),
                false,
                Some(e.clone()),
            );
            state.log_audit_event(event);
            
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: e })
            ));
        }
        
        // Check if challenge exists and is not expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let (challenge, expiry) = state.zkp_challenges.get(&address)
            .map(|entry| entry.clone())
            .ok_or_else(|| {
                // Record as failed attempt
                state.record_failed_zkp(&address);
                
                // Audit log
                let event = AuditEvent::new(
                    "zkp_verification_failed",
                    &address,
                    Some(ip.clone()),
                    serde_json::json!({"reason": "no_challenge_found"}),
                    false,
                    Some("No active challenge".to_string()),
                );
                state.log_audit_event(event);
                
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "No active challenge found. Request a challenge first.".to_string()
                    })
                )
            })?;
        
        if expiry < now {
            state.zkp_challenges.remove(&address);
            state.record_failed_zkp(&address);
            
            // Audit log
            let event = AuditEvent::new(
                "zkp_verification_failed",
                &address,
                Some(ip.clone()),
                serde_json::json!({"reason": "challenge_expired", "expiry": expiry, "now": now}),
                false,
                Some("Challenge expired".to_string()),
            );
            state.log_audit_event(event);
            
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Challenge expired. Request a new challenge.".to_string()
                })
            ));
        }
        
        // Verify the signature
        // Message format: "BLACKBOOK_SHARE_B\n{challenge}\n{address}"
        let message = format!("BLACKBOOK_SHARE_B\n{}\n{}", challenge, address);
        let message_bytes = message.as_bytes();
        
        // Decode public key and signature from hex
        let public_key_bytes = hex::decode(&req.public_key)
            .map_err(|_| {
                state.record_failed_zkp(&address);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: "Invalid public key hex".to_string() })
                )
            })?;
        
        let signature_bytes = hex::decode(&req.signature)
            .map_err(|_| {
                state.record_failed_zkp(&address);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: "Invalid signature hex".to_string() })
                )
            })?;
        
        if public_key_bytes.len() != 32 {
            state.record_failed_zkp(&address);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Public key must be 32 bytes".to_string() })
            ));
        }
        
        if signature_bytes.len() != 64 {
            state.record_failed_zkp(&address);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Signature must be 64 bytes".to_string() })
            ));
        }
        
        // Clone for address verification before consuming in try_into
        let pubkey_hex = hex::encode(&public_key_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().unwrap())
            .map_err(|_| {
                state.record_failed_zkp(&address);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: "Invalid public key".to_string() })
                )
            })?;
        
        let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());
        
        // Verify signature
        if let Err(_) = verifying_key.verify(message_bytes, &signature) {
            state.record_failed_zkp(&address);
            
            // Audit log failed signature verification
            let event = AuditEvent::new(
                "zkp_verification_failed",
                &address,
                Some(ip.clone()),
                serde_json::json!({
                    "reason": "invalid_signature",
                    "public_key": &pubkey_hex[..32]
                }),
                false,
                Some("Invalid Ed25519 signature".to_string()),
            );
            state.log_audit_event(event);
            
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid signature. ZKP verification failed.".to_string()
                })
            ));
        }
        
        // Verify the public key matches the wallet address
        let derived_address = format!("bb_{}", &pubkey_hex[..32]);
        
        if derived_address != address {
            state.record_failed_zkp(&address);
            
            // Audit log address mismatch
            let event = AuditEvent::new(
                "zkp_verification_failed",
                &address,
                Some(ip.clone()),
                serde_json::json!({
                    "reason": "address_mismatch",
                    "expected": &address,
                    "derived": &derived_address
                }),
                false,
                Some("Public key does not match address".to_string()),
            );
            state.log_audit_event(event);
            
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: format!("Public key does not match wallet address. Expected {}, got {}", address, derived_address)
                })
            ));
        }
        
        // ZKP verified! Remove the challenge (one-time use)
        state.zkp_challenges.remove(&address);
        
        // Retrieve Share B
        let share = state.get_share_b_internal(&address)
            .map_err(|e| (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: e })
            ))?;
        
        // Audit log successful ZKP verification
        let event = AuditEvent::new(
            "zkp_verification_success",
            &address,
            Some(ip.clone()),
            serde_json::json!({
                "auth_method": "ZKP_Ed25519",
                "public_key": &pubkey_hex[..32],
                "share_released": "B"
            }),
            true,
            None,
        );
        state.log_audit_event(event);
        
        info!("✅ ZKP verified! Share B released for wallet: {} (IP: {})", address, ip);
        
        Ok(Json(serde_json::json!({
            "share_b": share.to_hex(),
            "verified": true,
            "auth_method": "ZKP_Ed25519"
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
            // Audit log unauthorized access attempt
            state.log_privileged_recovery(
                &req.wallet_address,
                "unknown",
                false,
                Some("Invalid admin key".to_string())
            );
            
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "Invalid admin key".to_string() })
            ));
        }
        
        // Get Share B from L1
        let share_b = state.get_share_b_internal(&req.wallet_address)
            .map_err(|e| {
                state.log_privileged_recovery(
                    &req.wallet_address,
                    "admin",
                    false,
                    Some(format!("Share B not found: {}", e))
                );
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse { error: e })
                )
            })?;
        
        // Get Share C encrypted
        let share_c_encrypted = state.share_c_storage.get(&req.wallet_address)
            .map(|s| s.clone())
            .ok_or_else(|| {
                state.log_privileged_recovery(
                    &req.wallet_address,
                    "admin",
                    false,
                    Some("Share C not found".to_string())
                );
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse { error: "Share C not found".to_string() })
                )
            })?;
        
        // Reconstruct via B+C (PRIVILEGED - no password needed!)
        use crate::wallet_mnemonic::sss::reconstruct_from_bc;
        let entropy = reconstruct_from_bc(&share_b, &share_c_encrypted, &state.vault_pepper)
            .map_err(|e| {
                state.log_privileged_recovery(
                    &req.wallet_address,
                    "admin",
                    false,
                    Some(format!("Reconstruction failed: {}", e))
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: format!("Reconstruction failed: {}", e) })
                )
            })?;
        
        // Convert to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| {
                state.log_privileged_recovery(
                    &req.wallet_address,
                    "admin",
                    false,
                    Some(format!("Mnemonic generation failed: {}", e))
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: format!("Mnemonic generation failed: {}", e) })
                )
            })?;
        
        // SUCCESS: Audit log privileged recovery completion
        state.log_privileged_recovery(
            &req.wallet_address,
            "admin",
            true,
            None
        );
        
        warn!("🚨 PRIVILEGED Recovery via B+C completed for: {} - User password bypassed!", req.wallet_address);
        
        Ok(Json(RecoveryResponse {
            success: true,
            wallet_address: req.wallet_address,
            mnemonic,
            recovery_path: "B+C (L1 Blockchain + HashiCorp Vault) - PRIVILEGED".to_string(),
            warning: "🚨 PRIVILEGED RECOVERY - User authentication was bypassed. This should only be used for estate recovery, legal compliance, or catastrophic loss scenarios.".to_string(),
        }))
    }
    
    // ========================================================================
    // MULTI-SIG B+C RECOVERY (2-of-3 Admin Signatures Required)
    // ========================================================================
    
    /// Recovery Path: Share B (L1) + Share C (Vault) with Multi-Sig Admin Auth
    /// Requires 2-of-3 admin signatures for privileged recovery
    /// ⚠️ This bypasses user authentication but requires consensus!
    async fn recover_via_bc_multisig(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<MultiSigRecoverBCRequest>,
    ) -> Result<Json<RecoveryResponse>, (StatusCode, Json<ErrorResponse>)> {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        
        warn!("🚨 MULTI-SIG PRIVILEGED Recovery via B+C requested for: {}", req.wallet_address);
        
        // Admin public keys (in production: load from Vault or config)
        const ADMIN_PUBKEYS: [&str; 3] = [
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", // Admin 1 (CEO)
            "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a", // Admin 2 (CTO)
            "c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2", // Admin 3 (Security)
        ];
        
        // Verify we have at least 2 signatures
        if req.admin_signatures.len() < 2 {
            state.log_privileged_recovery(
                &req.wallet_address,
                "multisig_insufficient",
                false,
                Some(format!("Only {} signatures provided, need 2", req.admin_signatures.len()))
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "Multi-sig requires at least 2 of 3 admin signatures".to_string() })
            ));
        }
        
        // Message that admins must sign
        let message = format!(
            "BLACKBOOK_ADMIN_RECOVERY\n{}\n{}\n{}",
            req.wallet_address,
            req.nonce,
            req.timestamp
        );
        let message_bytes = message.as_bytes();
        
        // Verify timestamp is within 5 minutes
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if now.saturating_sub(req.timestamp) > 300 {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { error: "Request expired. Signatures must be within 5 minutes.".to_string() })
            ));
        }
        
        // Verify signatures from different admins
        let mut verified_admins: Vec<String> = Vec::new();
        
        for sig in &req.admin_signatures {
            // Find matching admin
            let admin_idx = ADMIN_PUBKEYS.iter().position(|&pk| pk == sig.admin_pubkey);
            
            if admin_idx.is_none() {
                continue; // Unknown admin, skip
            }
            
            // Check not already verified
            if verified_admins.contains(&sig.admin_pubkey) {
                continue; // Duplicate signature
            }
            
            // Verify signature
            let pubkey_bytes = match hex::decode(&sig.admin_pubkey) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            
            let sig_bytes = match hex::decode(&sig.signature) {
                Ok(b) if b.len() == 64 => b,
                _ => continue,
            };
            
            let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()) {
                Ok(k) => k,
                Err(_) => continue,
            };
            
            let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
            
            if verifying_key.verify(message_bytes, &signature).is_ok() {
                verified_admins.push(sig.admin_pubkey.clone());
                info!("✅ Admin signature verified: {}...{}", &sig.admin_pubkey[..8], &sig.admin_pubkey[56..]);
            }
        }
        
        // Check we have 2 valid signatures
        if verified_admins.len() < 2 {
            state.log_privileged_recovery(
                &req.wallet_address,
                &format!("multisig_failed({}/3)", verified_admins.len()),
                false,
                Some(format!("Only {} valid signatures, need 2", verified_admins.len()))
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse { 
                    error: format!("Multi-sig verification failed. Got {} valid signatures, need 2.", verified_admins.len()) 
                })
            ));
        }
        
        // Multi-sig verified! Proceed with recovery
        info!("✅ Multi-sig verified: {}/3 admins approved recovery for {}", verified_admins.len(), req.wallet_address);
        
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
        
        // Audit log with admin identifiers
        let event = AuditEvent::new(
            "multisig_bc_recovery",
            &req.wallet_address,
            None,
            serde_json::json!({
                "recovery_path": "B+C",
                "admins_approved": verified_admins,
                "threshold": "2-of-3",
                "nonce": req.nonce,
                "timestamp": req.timestamp
            }),
            true,
            None,
        );
        state.log_audit_event(event);
        
        warn!("🚨 MULTI-SIG Recovery via B+C completed for: {} - Approved by {} admins", 
            req.wallet_address, verified_admins.len());
        
        Ok(Json(RecoveryResponse {
            success: true,
            wallet_address: req.wallet_address,
            mnemonic,
            recovery_path: "B+C (Multi-Sig 2-of-3 Admin) - PRIVILEGED".to_string(),
            warning: format!("🚨 MULTI-SIG RECOVERY - Approved by {} of 3 admins. User authentication was bypassed.", verified_admins.len()),
        }))
    }
    
    // ========================================================================
    // SIEM / AUDIT LOG ENDPOINTS
    // ========================================================================
    
    /// Get all audit logs (admin only)
    async fn get_audit_logs(
        State(state): State<MnemonicHandlers>,
    ) -> Result<Json<AuditLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
        // In production: require admin authentication
        let mut all_logs: Vec<AuditEvent> = Vec::new();
        
        for entry in state.audit_logs.iter() {
            all_logs.extend(entry.value().clone());
        }
        
        // Sort by timestamp descending
        all_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Limit to last 1000
        all_logs.truncate(1000);
        
        Ok(Json(AuditLogsResponse {
            total: all_logs.len(),
            logs: all_logs,
        }))
    }
    
    /// Get audit logs for specific wallet
    async fn get_wallet_audit_logs(
        State(state): State<MnemonicHandlers>,
        Path(address): Path<String>,
    ) -> Result<Json<AuditLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
        let logs = state.audit_logs.get(&address)
            .map(|l| l.clone())
            .unwrap_or_default();
        
        Ok(Json(AuditLogsResponse {
            total: logs.len(),
            logs,
        }))
    }
    
    /// Export audit logs to SIEM (webhook)
    /// Supports: Elasticsearch, Splunk, Datadog, generic webhook
    async fn export_audit_logs(
        State(state): State<MnemonicHandlers>,
        Json(req): Json<SIEMExportRequest>,
    ) -> Result<Json<SIEMExportResponse>, (StatusCode, Json<ErrorResponse>)> {
        // Collect logs to export
        let mut logs: Vec<AuditEvent> = Vec::new();
        
        if let Some(address) = &req.wallet_address {
            if let Some(wallet_logs) = state.audit_logs.get(address) {
                logs.extend(wallet_logs.clone());
            }
        } else {
            for entry in state.audit_logs.iter() {
                logs.extend(entry.value().clone());
            }
        }
        
        // Filter by time range
        if let Some(since) = req.since_timestamp {
            logs.retain(|l| l.timestamp >= since);
        }
        
        // Filter by event type
        if let Some(ref event_types) = req.event_types {
            logs.retain(|l| event_types.contains(&l.event_type));
        }
        
        // Sort and limit
        logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let total_available = logs.len();
        logs.truncate(req.limit.unwrap_or(1000));
        
        // If webhook URL provided, ship logs
        let shipped = if let Some(ref webhook_url) = req.webhook_url {
            match ship_to_siem(&logs, webhook_url, &req.siem_type).await {
                Ok(count) => {
                    info!("📤 Shipped {} audit events to {} ({})", count, req.siem_type, webhook_url);
                    count
                },
                Err(e) => {
                    warn!("❌ Failed to ship audit logs: {}", e);
                    0
                }
            }
        } else {
            0
        };
        
        Ok(Json(SIEMExportResponse {
            success: true,
            total_available,
            exported: logs.len(),
            shipped_to_siem: shipped,
            logs: if req.include_logs.unwrap_or(false) { Some(logs) } else { None },
        }))
    }
}

// ============================================================================
// SIEM EXPORT HELPER
// ============================================================================

/// Ship audit logs to SIEM endpoint
async fn ship_to_siem(logs: &[AuditEvent], webhook_url: &str, siem_type: &str) -> Result<usize, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    
    let payload = match siem_type {
        "elasticsearch" => {
            // Elasticsearch bulk format
            let mut bulk = String::new();
            for log in logs {
                bulk.push_str(&format!(
                    "{{\"index\":{{\"_index\":\"blackbook-audit\"}}}}\n{}\n",
                    serde_json::to_string(log).unwrap_or_default()
                ));
            }
            bulk
        },
        "splunk" => {
            // Splunk HEC format
            let events: Vec<serde_json::Value> = logs.iter().map(|l| {
                serde_json::json!({
                    "time": l.timestamp,
                    "source": "blackbook-l1",
                    "sourcetype": "audit",
                    "event": l
                })
            }).collect();
            serde_json::to_string(&events).unwrap_or_default()
        },
        "datadog" => {
            // Datadog logs format
            let logs_array: Vec<serde_json::Value> = logs.iter().map(|l| {
                serde_json::json!({
                    "ddsource": "blackbook-l1",
                    "ddtags": format!("env:production,service:wallet,event:{}", l.event_type),
                    "hostname": "blackbook-l1",
                    "message": serde_json::to_string(l).unwrap_or_default(),
                    "status": if l.success { "info" } else { "error" }
                })
            }).collect();
            serde_json::to_string(&logs_array).unwrap_or_default()
        },
        _ => {
            // Generic webhook (raw JSON array)
            serde_json::to_string(&logs).unwrap_or_default()
        }
    };
    
    let response = client.post(webhook_url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if response.status().is_success() {
        Ok(logs.len())
    } else {
        Err(format!("SIEM returned status: {}", response.status()))
    }
}

// ============================================================================
// REQUEST/RESPONSE TYPES FOR NEW ENDPOINTS
// ============================================================================

/// Multi-sig admin signature
#[derive(Debug, Deserialize)]
pub struct AdminSignature {
    pub admin_pubkey: String,
    pub signature: String,
}

/// Multi-sig B+C recovery request
#[derive(Debug, Deserialize)]
pub struct MultiSigRecoverBCRequest {
    pub wallet_address: String,
    pub admin_signatures: Vec<AdminSignature>,
    pub nonce: String,
    pub timestamp: u64,
}

/// Audit logs response
#[derive(Debug, Serialize)]
pub struct AuditLogsResponse {
    pub total: usize,
    pub logs: Vec<AuditEvent>,
}

/// SIEM export request
#[derive(Debug, Deserialize)]
pub struct SIEMExportRequest {
    /// Filter by wallet address (optional)
    pub wallet_address: Option<String>,
    /// Filter by timestamp (logs after this time)
    pub since_timestamp: Option<u64>,
    /// Filter by event types
    pub event_types: Option<Vec<String>>,
    /// Max logs to export
    pub limit: Option<usize>,
    /// SIEM type: "elasticsearch", "splunk", "datadog", "webhook"
    #[serde(default = "default_siem_type")]
    pub siem_type: String,
    /// Webhook URL to ship logs to
    pub webhook_url: Option<String>,
    /// Include logs in response
    pub include_logs: Option<bool>,
}

fn default_siem_type() -> String {
    "webhook".to_string()
}

/// SIEM export response
#[derive(Debug, Serialize)]
pub struct SIEMExportResponse {
    pub success: bool,
    pub total_available: usize,
    pub exported: usize,
    pub shipped_to_siem: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<Vec<AuditEvent>>,
}

impl Default for MnemonicHandlers {
    fn default() -> Self {
        Self::new()
    }
}
