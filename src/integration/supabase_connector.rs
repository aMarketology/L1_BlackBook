use chrono;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Digest, Sha256}; 
use hex;
use std::sync::Arc;
use parking_lot::RwLock;
use flume;
use tokio;

// =====================================================
// GEYSER STREAMING - Solana-inspired Real-time Data
// RAM-to-Database streaming for blocks, transactions, accounts
// =====================================================

/// Geyser event types for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GeyserEvent {
    /// New slot started
    SlotUpdate {
        slot: u64,
        parent_slot: u64,
        status: String,  // "processing", "confirmed", "finalized"
    },
    /// Block produced
    BlockUpdate {
        slot: u64,
        block_hash: String,
        parent_hash: String,
        leader: String,
        transaction_count: u32,
        timestamp: u64,
    },
    /// Transaction processed
    TransactionUpdate {
        signature: String,
        slot: u64,
        success: bool,
        from_address: String,
        to_address: String,
        amount: u64,
        tx_type: String,
    },
    /// Account state changed
    AccountUpdate {
        address: String,
        slot: u64,
        balance: u64,
        owner: String,
        data_hash: String,
    },
    /// Engagement score updated
    EngagementUpdate {
        address: String,
        slot: u64,
        engagement_score: f64,
        stake_weight: f64,  // ln(1 + engagement)
    },
}

/// Geyser streaming configuration
#[derive(Debug, Clone)]
pub struct GeyserConfig {
    pub batch_size: usize,          // Events per batch
    pub flush_interval_ms: u64,     // Max time before flush
    pub buffer_size: usize,         // Channel buffer size
    pub enable_slot_updates: bool,
    pub enable_block_updates: bool,
    pub enable_tx_updates: bool,
    pub enable_account_updates: bool,
}

impl Default for GeyserConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            flush_interval_ms: 100,  // 100ms max latency
            buffer_size: 10000,
            enable_slot_updates: true,
            enable_block_updates: true,
            enable_tx_updates: true,
            enable_account_updates: true,
        }
    }
}

/// Geyser streaming service - streams blockchain events to Supabase
#[derive(Clone)]
pub struct GeyserStreamer {
    sender: flume::Sender<GeyserEvent>,
    receiver: flume::Receiver<GeyserEvent>,
    config: GeyserConfig,
    stats: Arc<RwLock<GeyserStats>>,
    supabase_url: String,
    supabase_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct GeyserStats {
    pub events_sent: u64,
    pub events_failed: u64,
    pub batches_sent: u64,
    pub last_slot_streamed: u64,
    pub last_flush_timestamp: u64,
}

impl GeyserStreamer {
    pub fn new(supabase_url: String, supabase_key: String, config: GeyserConfig) -> Self {
        let (sender, receiver) = flume::bounded(config.buffer_size);
        
        println!("🌊 Geyser streaming initialized");
        println!("   Batch size: {}", config.batch_size);
        println!("   Flush interval: {}ms", config.flush_interval_ms);
        
        Self {
            sender,
            receiver,
            config,
            stats: Arc::new(RwLock::new(GeyserStats::default())),
            supabase_url,
            supabase_key,
        }
    }

    /// Emit a slot update event
    pub fn emit_slot(&self, slot: u64, parent_slot: u64, status: &str) {
        if !self.config.enable_slot_updates { return; }
        
        let event = GeyserEvent::SlotUpdate {
            slot,
            parent_slot,
            status: status.to_string(),
        };
        let _ = self.sender.try_send(event);
    }

    /// Emit a block update event
    pub fn emit_block(&self, slot: u64, block_hash: &str, parent_hash: &str, 
                      leader: &str, transaction_count: u32, timestamp: u64) {
        if !self.config.enable_block_updates { return; }
        
        let event = GeyserEvent::BlockUpdate {
            slot,
            block_hash: block_hash.to_string(),
            parent_hash: parent_hash.to_string(),
            leader: leader.to_string(),
            transaction_count,
            timestamp,
        };
        let _ = self.sender.try_send(event);
    }

    /// Emit a transaction update event
    pub fn emit_transaction(&self, signature: &str, slot: u64, success: bool,
                            from_address: &str, to_address: &str, amount: u64, tx_type: &str) {
        if !self.config.enable_tx_updates { return; }
        
        let event = GeyserEvent::TransactionUpdate {
            signature: signature.to_string(),
            slot,
            success,
            from_address: from_address.to_string(),
            to_address: to_address.to_string(),
            amount,
            tx_type: tx_type.to_string(),
        };
        let _ = self.sender.try_send(event);
    }

    /// Emit an account update event
    pub fn emit_account(&self, address: &str, slot: u64, balance: u64, owner: &str) {
        if !self.config.enable_account_updates { return; }
        
        // Hash the data for comparison
        let data_hash = format!("{:x}", sha2::Sha256::digest(
            format!("{}:{}:{}", address, balance, slot).as_bytes()
        ));
        
        let event = GeyserEvent::AccountUpdate {
            address: address.to_string(),
            slot,
            balance,
            owner: owner.to_string(),
            data_hash,
        };
        let _ = self.sender.try_send(event);
    }

    /// Emit an engagement update event
    pub fn emit_engagement(&self, address: &str, slot: u64, engagement_score: f64) {
        let stake_weight = (1.0 + engagement_score).ln();  // Logarithmic stake weight
        
        let event = GeyserEvent::EngagementUpdate {
            address: address.to_string(),
            slot,
            engagement_score,
            stake_weight,
        };
        let _ = self.sender.try_send(event);
    }

    /// Start the background streaming task
    pub fn start_streaming(&self) -> tokio::task::JoinHandle<()> {
        let receiver = self.receiver.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let supabase_url = self.supabase_url.clone();
        let supabase_key = self.supabase_key.clone();
        
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut batch: Vec<GeyserEvent> = Vec::with_capacity(config.batch_size);
            let flush_duration = std::time::Duration::from_millis(config.flush_interval_ms);
            
            println!("🚀 Geyser streaming task started");
            
            loop {
                // Try to receive with timeout
                match tokio::time::timeout(flush_duration, async {
                    receiver.recv_async().await
                }).await {
                    Ok(Ok(event)) => {
                        batch.push(event);
                        
                        // Flush if batch is full
                        if batch.len() >= config.batch_size {
                            Self::flush_batch(&client, &supabase_url, &supabase_key, 
                                            &mut batch, &stats).await;
                        }
                    }
                    Ok(Err(_)) => {
                        // Channel closed, exit
                        println!("⚠️ Geyser channel closed, stopping streaming");
                        break;
                    }
                    Err(_) => {
                        // Timeout - flush whatever we have
                        if !batch.is_empty() {
                            Self::flush_batch(&client, &supabase_url, &supabase_key,
                                            &mut batch, &stats).await;
                        }
                    }
                }
            }
        })
    }

    /// Flush batch to Supabase
    async fn flush_batch(
        client: &reqwest::Client,
        supabase_url: &str,
        supabase_key: &str,
        batch: &mut Vec<GeyserEvent>,
        stats: &Arc<RwLock<GeyserStats>>,
    ) {
        if batch.is_empty() { return; }
        
        let events_count = batch.len() as u64;
        
        // Group events by type for efficient inserts
        let slot_updates: Vec<_> = batch.iter()
            .filter_map(|e| if let GeyserEvent::SlotUpdate { slot, parent_slot, status } = e {
                Some(serde_json::json!({
                    "slot": slot,
                    "parent_slot": parent_slot,
                    "status": status,
                    "streamed_at": chrono::Utc::now().to_rfc3339()
                }))
            } else { None })
            .collect();
            
        let block_updates: Vec<_> = batch.iter()
            .filter_map(|e| if let GeyserEvent::BlockUpdate { slot, block_hash, parent_hash, leader, transaction_count, timestamp } = e {
                Some(serde_json::json!({
                    "slot": slot,
                    "block_hash": block_hash,
                    "parent_hash": parent_hash,
                    "leader": leader,
                    "transaction_count": transaction_count,
                    "block_timestamp": timestamp,
                    "streamed_at": chrono::Utc::now().to_rfc3339()
                }))
            } else { None })
            .collect();

        let tx_updates: Vec<_> = batch.iter()
            .filter_map(|e| if let GeyserEvent::TransactionUpdate { signature, slot, success, from_address, to_address, amount, tx_type } = e {
                Some(serde_json::json!({
                    "signature": signature,
                    "slot": slot,
                    "success": success,
                    "from_address": from_address,
                    "to_address": to_address,
                    "amount": amount,
                    "tx_type": tx_type,
                    "streamed_at": chrono::Utc::now().to_rfc3339()
                }))
            } else { None })
            .collect();
        
        // Send to Supabase (non-blocking, best-effort)
        let mut success = true;
        
        if !slot_updates.is_empty() {
            if let Err(e) = client
                .post(&format!("{}/rest/v1/geyser_slots", supabase_url))
                .header("apikey", supabase_key)
                .header("Authorization", format!("Bearer {}", supabase_key))
                .header("Content-Type", "application/json")
                .header("Prefer", "resolution=ignore-duplicates")
                .json(&slot_updates)
                .send()
                .await
            {
                println!("⚠️ Geyser slot stream error: {}", e);
                success = false;
            }
        }
        
        if !block_updates.is_empty() {
            if let Err(e) = client
                .post(&format!("{}/rest/v1/geyser_blocks", supabase_url))
                .header("apikey", supabase_key)
                .header("Authorization", format!("Bearer {}", supabase_key))
                .header("Content-Type", "application/json")
                .header("Prefer", "resolution=ignore-duplicates")
                .json(&block_updates)
                .send()
                .await
            {
                println!("⚠️ Geyser block stream error: {}", e);
                success = false;
            }
        }
        
        if !tx_updates.is_empty() {
            if let Err(e) = client
                .post(&format!("{}/rest/v1/geyser_transactions", supabase_url))
                .header("apikey", supabase_key)
                .header("Authorization", format!("Bearer {}", supabase_key))
                .header("Content-Type", "application/json")
                .header("Prefer", "resolution=ignore-duplicates")
                .json(&tx_updates)
                .send()
                .await
            {
                println!("⚠️ Geyser tx stream error: {}", e);
                success = false;
            }
        }
        
        // Update stats
        {
            let mut s = stats.write();
            if success {
                s.events_sent += events_count;
                s.batches_sent += 1;
            } else {
                s.events_failed += events_count;
            }
            s.last_flush_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
        
        batch.clear();
    }

    /// Get streaming stats
    pub fn get_stats(&self) -> GeyserStats {
        self.stats.read().clone()
    }

    /// Get stats as JSON for API
    pub fn get_stats_json(&self) -> serde_json::Value {
        let stats = self.stats.read();
        serde_json::json!({
            "events_sent": stats.events_sent,
            "events_failed": stats.events_failed,
            "batches_sent": stats.batches_sent,
            "last_slot_streamed": stats.last_slot_streamed,
            "buffer_size": self.config.buffer_size,
            "batch_size": self.config.batch_size,
            "flush_interval_ms": self.config.flush_interval_ms
        })
    }
}

// =====================================================
// USER PROFILE - Matches Supabase public.profiles table
// =====================================================

/// User profile matching Supabase public.profiles table schema
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    /// Username (unique, primary key in Supabase)
    pub username: String,
    /// Account creation timestamp
    pub created_at: Option<String>,
    /// Last login timestamp
    pub last_login: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Creator category (e.g., "artist", "musician")
    pub creator_category: Option<String>,
    /// Reputation score (default 100.0)
    pub reputation_score: Option<f64>,
    /// Follower count
    pub follower_count: Option<i32>,
    /// Following count  
    pub following_count: Option<i32>,
    /// Post count
    pub post_count: Option<i32>,
    /// Session token UUID
    pub session_token: Option<String>,
    /// Session expiration timestamp
    pub session_expires_at: Option<String>,
    /// Last update timestamp
    pub updated_at: Option<String>,
    
    // =========== BlackBook Encrypted Vault Fields ===========
    /// Salt for Argon2id KDF (hex encoded, 32 bytes)
    /// Public - needed to derive encryption key before decryption
    /// Only changes on password change
    #[serde(default)]
    pub user_salt: String,
    
    /// AES-256-GCM encrypted vault containing mnemonic
    /// Format: base64(nonce || ciphertext || auth_tag)
    /// Only changes on password change (re-encrypted with new key)
    #[serde(default)]
    pub encrypted_vault: String,
    
    /// BlackBook wallet address (derived from m/44'/9000'/1'/0')
    /// Format: bb1_ prefix + 64 hex chars (pubkey)
    /// Maps to Supabase column "Blackbook_Address"
    pub blackbook_address: Option<String>,
    
    // =========== Backward Compatibility Aliases ===========
    /// Alias for blackbook_address (backward compatibility)
    #[serde(default)]
    pub wallet_address: Option<String>,
    
    /// Public key hex (derived from wallet creation)
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

/// Supabase Auth session response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseSession {
    /// JWT access token
    pub access_token: String,
    /// Refresh token for renewing session
    #[serde(default)]
    pub refresh_token: String,
    /// Token type (usually "bearer")
    #[serde(default)]
    pub token_type: String,
    /// Token expiration in seconds
    #[serde(default)]
    pub expires_in: u64,
    /// User information
    #[serde(default)]
    pub user: Option<SupabaseUser>,
}

/// Supabase user information from auth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseUser {
    /// User UUID
    pub id: String,
    /// User email
    #[serde(default)]
    pub email: Option<String>,
    /// Email confirmed
    #[serde(default)]
    pub email_confirmed_at: Option<String>,
    /// User metadata
    #[serde(default)]
    pub user_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
}

// FIXED: Simplified CryptoKeypair struct
#[derive(Debug, Clone)]
pub struct CryptoKeypair {
    pub verifying_key: VerifyingKey,
    pub signing_key: SigningKey,
}

impl CryptoKeypair {
    // FIXED: Proper key generation for ed25519-dalek 2.0
    pub fn generate() -> Self {
        // Generate random 32-byte seed
        let mut secret_key_bytes = [0u8; 32];
        for byte in &mut secret_key_bytes {
            *byte = rand::random();
        }
        
        let signing_key = SigningKey::from_bytes(&secret_key_bytes); // ✅ FIXED: Use from_bytes
        let verifying_key = signing_key.verifying_key();
        
        Self {
            verifying_key,
            signing_key,
        }
    }
    
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
    
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }
}

pub struct SupabaseConnector {
    pub client: reqwest::Client,
    pub url: String,
    pub api_key: String,
}

impl SupabaseConnector {
    pub fn new(url: String, api_key: String) -> Self {
        println!("🔗 Initializing decentralized social blockchain connector");
        println!("   URL: {}", url);
        
        Self {
            client: reqwest::Client::new(),
            url,
            api_key,
        }
    }

    // Generate deterministic wallet address from username
    // Uses 40 hex chars (160-bit security) like Bitcoin's RIPEMD160
    fn generate_wallet_address(&self, username: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("L1_SOCIAL_{}", username.to_lowercase()));
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);
        format!("L1{}", &hash_hex[0..40].to_uppercase()) // 42 chars total
    }

    // Test connection
    pub async fn test_connection(&self) -> Result<String, String> {
        let url = format!("{}/rest/v1/", self.url);
        println!("🧪 Testing connection to decentralized social database");

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        if response.status().is_success() {
            Ok("✅ Social blockchain database connected".to_string())
        } else {
            Err("❌ Database connection failed".to_string())
        }
    }

    // Get user profile by username
    pub async fn get_profile_by_username(&self, username: &str) -> Result<Option<UserProfile>, String> {
        println!("🔍 Looking up user: {}", username);

        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[("username", format!("eq.{}", username))])
            .send()
            .await
            .map_err(|e| format!("Failed to fetch profile: {}", e))?;

        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse profile: {}", e))?;
            
            if let Some(profile_data) = profiles.first() {
                let profile = UserProfile {
                    username: profile_data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    created_at: profile_data.get("created_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    last_login: profile_data.get("last_login").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    email: profile_data.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    creator_category: profile_data.get("creator_category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    reputation_score: profile_data.get("reputation_score").and_then(|v| v.as_f64()),
                    follower_count: profile_data.get("follower_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    following_count: profile_data.get("following_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    post_count: profile_data.get("post_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    session_token: profile_data.get("session_token").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    session_expires_at: profile_data.get("session_expires_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    updated_at: profile_data.get("updated_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    user_salt: profile_data.get("user_salt").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    encrypted_vault: profile_data.get("encrypted_vault").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    blackbook_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    wallet_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    public_key_hex: profile_data.get("public_key_hex").and_then(|v| v.as_str()).map(|s| s.to_string()),
                };
                
                println!("✅ Profile found: {} → Wallet: {}", username, profile.blackbook_address.as_deref().unwrap_or("No wallet"));
                Ok(Some(profile))
            } else {
                println!("ℹ️ No profile found for username: {}", username);
                Ok(None)
            }
        } else {
            Err("Failed to fetch profile from database".to_string())
        }
    }

    // Get user profile by wallet address
    pub async fn get_profile_by_wallet(&self, wallet_address: &str) -> Result<Option<UserProfile>, String> {
        println!("🔍 Looking up wallet: {}", wallet_address);

        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[("wallet_address", format!("eq.{}", wallet_address))])
            // ✅ ADD THIS LINE to specify which fields to return:
            .query(&[("select", "*")]) // Get all fields including email
            .send()
            .await
            .map_err(|e| format!("Failed to fetch profile by wallet: {}", e))?;

        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse profile: {}", e))?;
            
            if let Some(profile_data) = profiles.first() {
                let profile = UserProfile {
                    username: profile_data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    created_at: profile_data.get("created_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    last_login: profile_data.get("last_login").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    email: profile_data.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    creator_category: profile_data.get("creator_category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    reputation_score: profile_data.get("reputation_score").and_then(|v| v.as_f64()),
                    follower_count: profile_data.get("follower_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    following_count: profile_data.get("following_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    post_count: profile_data.get("post_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    session_token: profile_data.get("session_token").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    session_expires_at: profile_data.get("session_expires_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    updated_at: profile_data.get("updated_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    user_salt: profile_data.get("user_salt").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    encrypted_vault: profile_data.get("encrypted_vault").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    blackbook_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    wallet_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    public_key_hex: profile_data.get("public_key_hex").and_then(|v| v.as_str()).map(|s| s.to_string()),
                };
                
                println!("✅ Wallet found by address: {} → {}", wallet_address, profile.username);
                Ok(Some(profile))
            } else {
                println!("ℹ️ No profile found for wallet: {}", wallet_address);
                Ok(None)
            }
        } else {
            Err("Failed to fetch profile by wallet".to_string())
        }
    }

    // Get private key for signing (for blockchain operations)
    pub async fn get_user_private_key(&self, username: &str) -> Result<String, String> {
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[("username", format!("eq.{}", username))])
            .query(&[("select", "encrypted_private_keys")])
            .send()
            .await
            .map_err(|e| format!("Failed to get private key: {}", e))?;

        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse private key data: {}", e))?;
            
            if let Some(profile_data) = profiles.first() {
                if let Some(encrypted_keys) = profile_data.get("encrypted_private_keys") {
                    if let Some(private_key) = encrypted_keys.get("private_key").and_then(|pk| pk.as_str()) {
                        Ok(private_key.to_string())
                    } else {
                        Err("Private key not found in encrypted data".to_string())
                    }
                } else {
                    Err("No encrypted keys found".to_string())
                }
            } else {
                Err("Profile not found".to_string())
            }
        } else {
            Err("Failed to fetch private key".to_string())
        }
    }

    // Sign message for user (blockchain operation)
    pub async fn sign_message_for_user(&self, username: &str, message: &str) -> Result<String, String> {
        let private_key_hex = self.get_user_private_key(username).await?;
        
        // Convert hex private key to bytes
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| format!("Invalid private key hex: {}", e))?;
        
        // Create signing key from bytes (ed25519-dalek 2.0)
        if private_key_bytes.len() != 32 {
            return Err("Invalid private key length".to_string());
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key_bytes);
        
        let signing_key = SigningKey::from_bytes(&key_bytes);
        
        // Sign the message
        let signature = signing_key.sign(message.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        
        println!("🔐 Message signed for user: {}", username);
        Ok(signature_hex)
    }

    // Verify signature for user
    pub async fn verify_signature_for_user(&self, username: &str, message: &str, signature_hex: &str) -> Result<bool, String> {
        let public_key_bytes = self.get_user_public_key_bytes(username).await?;
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        
        // Create VerifyingKey and Signature (ed25519-dalek 2.0)
        if public_key_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        
        let mut pub_key_bytes = [0u8; 32];
        pub_key_bytes.copy_from_slice(&public_key_bytes);
        
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        
        if signature_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature_bytes);
        
        let signature = Signature::from_bytes(&sig_bytes);
        
        match verifying_key.verify(message.as_bytes(), &signature) {
            Ok(_) => {
                println!("✅ Signature verified for user: {}", username);
                Ok(true)
            },
            Err(_) => {
                println!("❌ Signature verification failed for user: {}", username);
                Ok(false)
            }
        }
    }

    // Helper: Get user public key as bytes
    async fn get_user_public_key_bytes(&self, username: &str) -> Result<Vec<u8>, String> {
        let profile = self.get_profile_by_username(username).await?;
        
        if let Some(user_profile) = profile {
            if let Some(address) = user_profile.blackbook_address.as_ref() {
                // Extract the raw public key from the BlackBook address (strip bb1_ prefix)
                let raw_pubkey = if address.starts_with("bb1_") {
                    &address[4..]
                } else {
                    address.as_str()
                };
                let public_key_bytes = hex::decode(raw_pubkey)
                    .map_err(|e| format!("Invalid public key hex: {}", e))?;
                Ok(public_key_bytes)
            } else {
                Err("No public key found for user".to_string())
            }
        } else {
            Err("User not found".to_string())
        }
    }

    // FIXED: Search users by partial username (social discovery)
    pub async fn search_users(&self, search_term: &str, limit: usize) -> Result<Vec<UserProfile>, String> {
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[("username", format!("ilike.%{}%", search_term))])
            .query(&[("select", "username,wallet_address,created_at,\"Blackbook_Address\"")])
            .query(&[("limit", limit.to_string())])
            .send()
            .await
            .map_err(|e| format!("Failed to search users: {}", e))?;

        if response.status().is_success() {
            let profiles_data: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse search results: {}", e))?;
            
            // Map search results to UserProfile structs
            let profiles: Vec<UserProfile> = profiles_data.into_iter().map(|profile_data| {
                UserProfile {
                    username: profile_data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    created_at: profile_data.get("created_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    last_login: None,
                    email: None,
                    creator_category: None,
                    reputation_score: None,
                    follower_count: None,
                    following_count: None,
                    post_count: None,
                    session_token: None,
                    session_expires_at: None,
                    updated_at: None,
                    user_salt: String::new(),
                    encrypted_vault: String::new(),
                    blackbook_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    // Backward compatibility aliases
                    wallet_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    public_key_hex: None,
                }
            }).collect();
            
            println!("🔍 Found {} users matching '{}'", profiles.len(), search_term);
            Ok(profiles)
        } else {
            Err("Failed to search users".to_string())
        }
    }

    // ADD: Record action timestamp (needed by main.rs)
    pub async fn record_action_timestamp(&self, wallet_address: &str, action_type: &str) -> Result<(), String> {
        println!("📝 Recording action timestamp: {} for {}", action_type, wallet_address);
        
        // For now, just return success since this is stored on blockchain
        // In a full implementation, you might want to track this in Supabase too
        Ok(())
    }

    // ADD: Missing methods that main.rs expects (compatibility layer)
    pub async fn delete_wallet(&self, username: &str) -> Result<(), String> {
        // For now, just return success - implement deletion if needed
        println!("🗑️ Wallet deletion requested for user: {}", username);
        Ok(())
    }

    // ADD: Generate wallet for existing user profile
    pub async fn add_wallet_to_existing_user(&self, username: &str) -> Result<UserProfile, String> {
        // First check if user profile exists
        let existing_profile = self.get_profile_by_username(username).await?;
        
        if existing_profile.is_none() {
            return Err("User profile not found. Please register in the app first.".to_string());
        }
        
        // Check if user already has a wallet
        if let Some(profile) = existing_profile {
            if profile.blackbook_address.is_some() {
                return Err("User already has a wallet address".to_string());
            }
            
            // Generate new wallet address and keys
            let crypto_keypair = CryptoKeypair::generate();
            let wallet_address = self.generate_wallet_address(username);
            
            println!("🔗 Adding wallet to existing user:");
            println!("   Username: {}", username);
            println!("   New Wallet: {}", wallet_address);
            println!("   Public Key: {}...", &crypto_keypair.public_key_hex()[0..16]);
            
            // Create encrypted private key storage
            let encrypted_keys = serde_json::json!({
                "private_key": crypto_keypair.private_key_hex(),
                "encryption_method": "none",
                "created_at": chrono::Utc::now().to_rfc3339()
            });
            
            // UPDATE existing profile with wallet info
            let update_data = serde_json::json!({
                "wallet_address": wallet_address,
                "public_key_hex": crypto_keypair.public_key_hex(),
                "encrypted_private_keys": encrypted_keys,
                "updated_at": chrono::Utc::now().to_rfc3339()
            });
            
            let response = self.client
                .patch(&format!("{}/rest/v1/profiles", self.url))
                .header("apikey", &self.api_key)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .header("Prefer", "return=representation")
                .query(&[("username", format!("eq.{}", username))])
                .json(&update_data)
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;
                
            if response.status().is_success() {
                let updated_profiles: Vec<UserProfile> = response.json().await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                    
                if let Some(updated_profile) = updated_profiles.into_iter().next() {
                    println!("✅ Wallet added to existing user successfully");
                    Ok(updated_profile)
                } else {
                    Err("Failed to get updated profile".to_string())
                }
            } else {
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Failed to add wallet: {}", error_text))
            }
        } else {
            Err("User profile not found".to_string())
        }
    }
    
    // ADD: Remove wallet from existing user (keep profile) - ENHANCED VERSION
    pub async fn remove_wallet_from_user(&self, username: &str) -> Result<(), String> {
        println!("🗑️ Completely removing wallet from user: {}", username);
        
        // ✅ ENHANCED: Remove ALL wallet-related data
        let update_data = serde_json::json!({
            "wallet_address": null,           // ✅ Completely remove
            "public_key_hex": null,          // ✅ Completely remove
            "encrypted_private_keys": null,  // ✅ Completely remove
            "blockchain_jwt": null,          // ✅ Clear blockchain JWT
            "blockchain_jwt_hash": null,     // ✅ Clear JWT hash
            "jwt_is_active": false,          // ✅ Deactivate JWT
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Failed to remove wallet: {}", e))?;
            
        if response.status().is_success() {
            println!("✅ Wallet and all related data completely removed from user profile");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to remove wallet: {}", error_text))
        }
    }
    
    // NEW: Update wallet address (legacy - single address)
    pub async fn update_wallet_address(&self, username: &str, new_wallet_address: &str) -> Result<(), String> {
        println!("🔄 Updating wallet address for user: {}", username);
        
        // ✅ FIX: If empty string, set to null to completely remove wallet
        let wallet_value = if new_wallet_address.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(new_wallet_address.to_string())
        };
        
        let update_data = serde_json::json!({
            "wallet_address": wallet_value,  // ✅ FIXED: null for empty, string for actual address
            "public_key_hex": if new_wallet_address.is_empty() { serde_json::Value::Null } else { serde_json::Value::Null }, // Clear public key too
            "encrypted_private_keys": if new_wallet_address.is_empty() { serde_json::Value::Null } else { serde_json::Value::Null }, // Clear private keys too
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Failed to update wallet: {}", e))?;
        
        if response.status().is_success() {
            if new_wallet_address.is_empty() {
                println!("✅ Wallet completely removed from database");
            } else {
                println!("✅ Wallet address updated successfully");
            }
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to update wallet address: {}", error_text))
        }
    }
    
    /// Update BlackBook address for a user
    /// 
    /// This stores the wallet address derived from the mnemonic.
    /// 
    /// # Arguments
    /// * `username` - User's username (primary key)
    /// * `address` - BlackBook address (bb1_ + 64 hex chars)
    pub async fn update_blackbook_address(
        &self,
        username: &str,
        address: &str,
    ) -> Result<(), String> {
        println!("🔄 Updating BlackBook address for user: {}", username);
        println!("   Address: {}...", &address[..address.len().min(20)]);
        
        let update_data = serde_json::json!({
            "Blackbook_Address": address,
            "wallet_address": address,  // Also update legacy field for compatibility
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ BlackBook address updated successfully");
            println!("   ✓ Blackbook_Address = {}", address);
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to update BlackBook address: {}", error_text))
        }
    }
    
    /// Clear BlackBook address for a user (wallet deletion)
    pub async fn clear_blackbook_address(&self, username: &str) -> Result<(), String> {
        println!("🗑️ Clearing BlackBook address for user: {}", username);
        
        let update_data = serde_json::json!({
            "Blackbook_Address": serde_json::Value::Null,
            "wallet_address": serde_json::Value::Null,
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ BlackBook address cleared successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to clear BlackBook address: {}", error_text))
        }
    }

    // ADD this missing verify_supabase_jwt method:
    pub async fn verify_supabase_jwt(&self, jwt_token: &str) -> Result<UserInfo, String> {
        println!("🔍 Verifying Supabase JWT token...");
        
        let response = self.client
            .get(&format!("{}/auth/v1/user", self.url))
            .header("Authorization", format!("Bearer {}", jwt_token))
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| format!("Failed to verify Supabase JWT: {}", e))?;
        
        if response.status().is_success() {
            let user_data: serde_json::Value = response.json().await
                .map_err(|e| format!("Failed to parse Supabase user data: {}", e))?;
            
            let user_info = UserInfo {
                id: user_data["id"].as_str().unwrap_or("").to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["user_metadata"]["username"]
                    .as_str()
                    .or_else(|| user_data["user_metadata"]["full_name"].as_str())
                    .map(|s| s.to_string()),
            };
            
            println!("✅ Supabase JWT verification successful for: {}", user_info.email);
            Ok(user_info)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            println!("❌ Supabase JWT verification failed: {}", error_text);
            Err(format!("Invalid or expired Supabase JWT token: {}", error_text))
        }
    }

    pub fn generate_ed25519_keypair() -> (String, String, String) {
        // FIXED: Use proper ed25519-dalek 2.0 key generation
        let mut secret_bytes = [0u8; 32];
        for byte in &mut secret_bytes {
            *byte = rand::random();
        }
        
        let signing_key = SigningKey::from_bytes(&secret_bytes); // ✅ FIXED: Use from_bytes instead of generate
        let verifying_key = signing_key.verifying_key();
        
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let wallet_address = format!("L1{}", &public_key_hex[0..40]);
        
        (wallet_address, public_key_hex, private_key_hex)
    }

    // ADD these methods to your SupabaseConnector impl:
    // Store JWT in Supabase profiles
    pub async fn update_user_jwt(
        &self,
        user_id: &str,
        blockchain_jwt: &str,
        supabase_jwt: &str,
        expires_at: String,
    ) -> Result<(), String> {
        println!("💾 Storing JWT in Supabase for user: {}", user_id);
        
        // Hash the JWTs for security
        let mut hasher = Sha256::new();
        hasher.update(blockchain_jwt);
        let blockchain_jwt_hash = hex::encode(hasher.finalize());
        
        let mut supabase_hasher = Sha256::new();
        supabase_hasher.update(supabase_jwt);
        let supabase_jwt_hash = hex::encode(supabase_hasher.finalize());
        
        let update_data = serde_json::json!({
            "blockchain_jwt": blockchain_jwt,
            "blockchain_jwt_hash": blockchain_jwt_hash,  // New column we just added
            "supabase_jwt_hash": supabase_jwt_hash,
            "jwt_expires_at": expires_at,
            "jwt_is_active": true,
            "last_login": chrono::Utc::now().to_rfc3339(),  // New column we just added
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles?id=eq.{}", self.url, user_id))
            .header("Authorization", format!("Bearer {}", self.api_key))  // ✅ FIXED: api_key
            .header("apikey", &self.api_key)                              // ✅ FIXED: api_key
            .header("Content-Type", "application/json")
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ JWT stored in Supabase successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            println!("❌ Failed to store JWT in Supabase: {}", error_text);
            Err(format!("Failed to update JWT in Supabase: {}", error_text))
        }
    }
    
    // Get user's active JWT from Supabase
    pub async fn get_user_active_jwt(&self, user_id: &str) -> Result<Option<String>, String> {
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("Authorization", format!("Bearer {}", self.api_key))  // ✅ FIXED: api_key
            .header("apikey", &self.api_key)                              // ✅ FIXED: api_key
            .query(&[
                ("select", "blockchain_jwt,jwt_expires_at,jwt_is_active"),
                ("id", &format!("eq.{}", user_id)),
                ("jwt_is_active", "eq.true")
            ])
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if let Some(profile) = profiles.first() {
                // Check if JWT is still valid
                if let Some(expires_str) = profile.get("jwt_expires_at").and_then(|v| v.as_str()) {
                    match chrono::DateTime::parse_from_rfc3339(expires_str) {
                        Ok(expires_at) => {
                            if expires_at > chrono::Utc::now() {
                                return Ok(profile.get("blockchain_jwt").and_then(|v| v.as_str()).map(|s| s.to_string()));
                            } else {
                                // JWT expired, mark as inactive
                                let _ = self.invalidate_user_jwt(user_id).await;
                                return Ok(None);
                            }
                        },
                        Err(_) => return Ok(None),
                    }
                }
                
                return Ok(profile.get("blockchain_jwt").and_then(|v| v.as_str()).map(|s| s.to_string()));
            }
        }
        
        Ok(None)
    }
    
    // Invalidate user's JWT in Supabase
    pub async fn invalidate_user_jwt(&self, user_id: &str) -> Result<(), String> {
        let update_data = serde_json::json!({
            "jwt_is_active": false,
            "blockchain_jwt": null,
            "blockchain_jwt_hash": null,
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles?id=eq.{}", self.url, user_id))
            .header("Authorization", format!("Bearer {}", self.api_key))  // ✅ FIXED: api_key
            .header("apikey", &self.api_key)                              // ✅ FIXED: api_key
            .header("Content-Type", "application/json")
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("🗑️ JWT invalidated in Supabase for user: {}", user_id);
            Ok(())
        } else {
            Err("Failed to invalidate JWT in Supabase".to_string())
        }
    }
    
    // Update wallet address and refresh JWT
    pub async fn update_wallet_and_refresh_jwt(
        &self,
        user_id: &str,
        new_wallet_address: &str,
        blockchain_jwt: &str,
    ) -> Result<(), String> {
        println!("🔄 Updating wallet address and refreshing JWT for user: {}", user_id);
        
        let update_data = serde_json::json!({
            "wallet_address": new_wallet_address,
            "blockchain_jwt": blockchain_jwt,
            "jwt_is_active": true,  // Mark as active when updating
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles?id=eq.{}", self.url, user_id))
            .header("Authorization", format!("Bearer {}", self.api_key))  // ✅ FIXED: api_key
            .header("apikey", &self.api_key)                              // ✅ FIXED: api_key
            .header("Content-Type", "application/json")
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ Wallet address and JWT updated in Supabase");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to update wallet and JWT: {}", error_text))
        }
    }
    
    // TEST JWT SYSTEM - Add this method for testing
    pub async fn test_jwt_system(&self, test_user_id: &str) -> Result<(), String> {
        println!("🧪 Testing complete JWT system...");
        
        let test_jwt = "test_blockchain_jwt_12345";
        let test_supabase_jwt = "test_supabase_jwt_67890";
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        
        // Test 1: Store JWT
        println!("📝 Test 1: Storing JWT...");
        match self.update_user_jwt(test_user_id, test_jwt, test_supabase_jwt, expires_at).await {
            Ok(_) => println!("✅ JWT storage successful"),
            Err(e) => return Err(format!("JWT storage failed: {}", e))
        }
        
        // Test 2: Retrieve JWT
        println!("📋 Test 2: Retrieving JWT...");
        match self.get_user_active_jwt(test_user_id).await {
            Ok(Some(retrieved_jwt)) => {
                if retrieved_jwt == test_jwt {
                    println!("✅ JWT retrieval successful");
                } else {
                    return Err("Retrieved JWT doesn't match stored JWT".to_string());
                }
            },
            Ok(None) => return Err("No JWT found after storing".to_string()),
            Err(e) => return Err(format!("JWT retrieval failed: {}", e))
        }
        
        // Test 3: Invalidate JWT
        println!("🗑️ Test 3: Invalidating JWT...");
        match self.invalidate_user_jwt(test_user_id).await {
            Ok(_) => println!("✅ JWT invalidation successful"),
            Err(e) => return Err(format!("JWT invalidation failed: {}", e))
        }
        
        // Test 4: Verify JWT is invalidated
        println!("🔍 Test 4: Verifying JWT invalidation...");
        match self.get_user_active_jwt(test_user_id).await {
            Ok(None) => println!("✅ JWT properly invalidated"),
            Ok(Some(_)) => return Err("JWT still active after invalidation".to_string()),
            Err(e) => return Err(format!("JWT invalidation check failed: {}", e))
        }
        
        println!("🎉 All JWT tests passed!");
        Ok(())
    }

    // Add this method to your SupabaseConnector implementation
    pub async fn create_user_profile(
        &self,
        _supabase_user_id: &str,
        email: &str,  // Keep this parameter for compatibility, but use it as username
        username: Option<&str>
    ) -> Result<UserProfile, String> {
        println!("🔧 Creating profile with data:");
        println!("   - username (from email): {}", email);
        println!("   - username override: {:?}", username);
        
        let final_username = username.unwrap_or(email);
        
        let profile_data = serde_json::json!({
            "username": final_username,
            // "email": email,  // ❌ REMOVE THIS LINE
            "wallet_address": null,
            "public_key_hex": null,
            "blockchain_jwt": null,
            "supabase_jwt_hash": null,
            "jwt_expires_at": null,
            "jwt_is_active": false,
            "blockchain_jwt_hash": null,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "updated_at": chrono::Utc::now().to_rfc3339(),
            "last_login": chrono::Utc::now().to_rfc3339()
        });
        
        println!("📝 Profile data to send: {}", serde_json::to_string_pretty(&profile_data).unwrap_or_default());
        
        let response = self.client
            .post(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=representation")
            .json(&profile_data)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

    let status = response.status();
    println!("📡 Supabase response status: {}", status);

    if status.is_success() {
        let response_text = response.text().await
            .map_err(|e| format!("Failed to read response text: {}", e))?;
            
        println!("📨 Supabase response body: {}", response_text);
        
        let profiles: Vec<UserProfile> = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse response JSON: {} - Response was: {}", e, response_text))?;
        
        profiles.into_iter().next()
            .ok_or_else(|| "No profile returned after creation - Response was empty".to_string())
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        println!("❌ Supabase error response: {}", error_text);
        Err(format!("Failed to create profile: {} - {}", status, error_text))
    }
}

    // =========================================================================
    // BLACKBOOK ENCRYPTED VAULT FUNCTIONS
    // =========================================================================
    
    /// Store BlackBook encrypted vault for a user
    /// 
    /// This is called during wallet creation:
    /// 1. Client generates mnemonic
    /// 2. Client derives L1/L2 keypairs using SLIP-0010
    /// 3. Client encrypts mnemonic with password using Argon2id + AES-256-GCM
    /// 4. This function stores the encrypted vault in Supabase
    /// 
    /// # Arguments
    /// * `username` - User's username (primary key)
    /// * `user_salt` - Hex-encoded salt for Argon2id KDF (32 bytes)
    /// * `encrypted_vault` - Base64-encoded encrypted mnemonic blob
    /// * `address` - BlackBook address (bb1_ + 64 hex chars)
    pub async fn store_blackbook_vault(
        &self,
        username: &str,
        user_salt: &str,
        encrypted_vault: &str,
        address: &str,
    ) -> Result<(), String> {
        println!("🔐 Storing BlackBook encrypted vault for user: {}", username);
        println!("   Address: {}...", &address[..address.len().min(20)]);
        
        let update_data = serde_json::json!({
            "user_salt": user_salt,
            "encrypted_vault": encrypted_vault,
            "Blackbook_Address": address,
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ BlackBook vault stored successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to store BlackBook vault: {}", error_text))
        }
    }
    
    /// Get vault salt for a user (needed before client-side decryption)
    /// 
    /// The salt is public and fetched before login so the client can
    /// derive the encryption key from the password.
    pub async fn get_vault_salt(&self, username: &str) -> Result<Option<String>, String> {
        println!("🔍 Fetching vault salt for user: {}", username);
        
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("username", format!("eq.{}", username)),
                ("select", "user_salt".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if let Some(profile) = profiles.first() {
                let salt = profile.get("user_salt")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                
                if salt.is_some() {
                    println!("✅ Vault salt found");
                } else {
                    println!("ℹ️ No vault salt found for user (wallet not created yet)");
                }
                Ok(salt)
            } else {
                println!("ℹ️ User not found: {}", username);
                Ok(None)
            }
        } else {
            Err("Failed to fetch vault salt".to_string())
        }
    }
    
    /// Get encrypted vault for a user (needed for client-side decryption)
    /// 
    /// Returns both the salt and encrypted vault so the client can:
    /// 1. Derive key from password + salt using Argon2id
    /// 2. Decrypt the vault using AES-256-GCM
    pub async fn get_encrypted_vault(&self, username: &str) -> Result<Option<(String, String)>, String> {
        println!("🔍 Fetching encrypted vault for user: {}", username);
        
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("username", format!("eq.{}", username)),
                ("select", "user_salt,encrypted_vault".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if let Some(profile) = profiles.first() {
                let salt = profile.get("user_salt").and_then(|v| v.as_str()).unwrap_or("");
                let vault = profile.get("encrypted_vault").and_then(|v| v.as_str()).unwrap_or("");
                
                if !salt.is_empty() && !vault.is_empty() {
                    println!("✅ Encrypted vault found");
                    Ok(Some((salt.to_string(), vault.to_string())))
                } else {
                    println!("ℹ️ No encrypted vault found for user (wallet not created yet)");
                    Ok(None)
                }
            } else {
                println!("ℹ️ User not found: {}", username);
                Ok(None)
            }
        } else {
            Err("Failed to fetch encrypted vault".to_string())
        }
    }
    
    /// Update vault on password change
    /// 
    /// When user changes password:
    /// 1. Client decrypts vault with old password
    /// 2. Client generates new salt
    /// 3. Client re-encrypts vault with new password
    /// 4. This function updates the database with new salt + encrypted_vault
    /// 
    /// Note: The mnemonic inside the vault NEVER changes - only the encryption.
    pub async fn update_vault_on_password_change(
        &self,
        username: &str,
        new_salt: &str,
        new_encrypted_vault: &str,
    ) -> Result<(), String> {
        println!("🔄 Updating vault for password change: {}", username);
        
        let update_data = serde_json::json!({
            "user_salt": new_salt,
            "encrypted_vault": new_encrypted_vault,
            "updated_at": chrono::Utc::now().to_rfc3339()
        });
        
        let response = self.client
            .patch(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("username", format!("eq.{}", username))])
            .json(&update_data)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            println!("✅ Vault updated for password change");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Failed to update vault: {}", error_text))
        }
    }
    
    /// Get BlackBook address for a user
    /// 
    /// Returns the wallet address if it exists
    pub async fn get_blackbook_address(&self, username: &str) -> Result<Option<String>, String> {
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("username", format!("eq.{}", username)),
                ("select", "\"Blackbook_Address\"".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if let Some(profile) = profiles.first() {
                let addr = profile.get("Blackbook_Address").and_then(|v| v.as_str());
                
                match addr {
                    Some(address) => Ok(Some(address.to_string())),
                    _ => Ok(None),
                }
            } else {
                Ok(None)
            }
        } else {
            Err("Failed to fetch BlackBook address".to_string())
        }
    }
    
    /// Lookup user profile by BlackBook address
    pub async fn get_profile_by_address(&self, address: &str) -> Result<Option<UserProfile>, String> {
        println!("🔍 Looking up profile by address: {}...", &address[..address.len().min(20)]);
        
        let response = self.client
            .get(&format!("{}/rest/v1/profiles", self.url))
            .header("apikey", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("\"Blackbook_Address\"", format!("eq.{}", address)),
                ("select", "*".to_string()),
            ])
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if response.status().is_success() {
            let profiles: Vec<serde_json::Value> = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if let Some(profile_data) = profiles.first() {
                let profile = UserProfile {
                    username: profile_data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    created_at: profile_data.get("created_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    last_login: profile_data.get("last_login").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    email: profile_data.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    creator_category: profile_data.get("creator_category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    reputation_score: profile_data.get("reputation_score").and_then(|v| v.as_f64()),
                    follower_count: profile_data.get("follower_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    following_count: profile_data.get("following_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    post_count: profile_data.get("post_count").and_then(|v| v.as_i64()).map(|n| n as i32),
                    session_token: profile_data.get("session_token").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    session_expires_at: profile_data.get("session_expires_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    updated_at: profile_data.get("updated_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    user_salt: profile_data.get("user_salt").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    encrypted_vault: profile_data.get("encrypted_vault").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    blackbook_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    wallet_address: profile_data.get("Blackbook_Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    public_key_hex: profile_data.get("public_key_hex").and_then(|v| v.as_str()).map(|s| s.to_string()),
                };
                
                println!("✅ Profile found by address: {}", profile.username);
                Ok(Some(profile))
            } else {
                println!("ℹ️ No profile found for address");
                Ok(None)
            }
        } else {
            Err("Failed to fetch profile by address".to_string())
        }
    }
    
    /// Authenticate user with email and derived password using Supabase Auth
    /// 
    /// This is used for "The Fork" authentication where:
    /// - The password is actually SHA256(real_password + salt + AUTH_CONSTANT)
    /// - Supabase stores a hash of this derived password
    /// - The server NEVER sees the real password
    /// 
    /// # Arguments
    /// * `email` - User's email address
    /// * `derived_password` - SHA256 hash derived from real password + salt
    /// 
    /// # Returns
    /// * Session with access_token if successful
    pub async fn authenticate_user_with_password(
        &self,
        email: &str,
        derived_password: &str,
    ) -> Result<SupabaseSession, String> {
        println!("🔐 Authenticating user with derived password: {}", email);
        
        let auth_payload = serde_json::json!({
            "email": email,
            "password": derived_password
        });
        
        let response = self.client
            .post(&format!("{}/auth/v1/token?grant_type=password", self.url))
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&auth_payload)
            .send()
            .await
            .map_err(|e| format!("Auth request failed: {}", e))?;
        
        if response.status().is_success() {
            let session: SupabaseSession = response.json().await
                .map_err(|e| format!("Failed to parse auth response: {}", e))?;
            
            println!("✅ Authentication successful");
            Ok(session)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            println!("❌ Authentication failed: {}", error_text);
            Err(format!("Authentication failed: {}", error_text))
        }
    }
    
    /// Sign up a new user with email and derived password using Supabase Auth
    /// 
    /// This creates a new Supabase auth user where the password is:
    /// SHA256(real_password + salt + AUTH_CONSTANT)
    /// 
    /// The server NEVER sees the real password.
    pub async fn signup_user_with_password(
        &self,
        email: &str,
        derived_password: &str,
        username: Option<&str>,
    ) -> Result<SupabaseSession, String> {
        println!("🔐 Signing up user with derived password: {}", email);
        
        let auth_payload = serde_json::json!({
            "email": email,
            "password": derived_password,
            "data": {
                "username": username.unwrap_or(&email)
            }
        });
        
        let response = self.client
            .post(&format!("{}/auth/v1/signup", self.url))
            .header("apikey", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&auth_payload)
            .send()
            .await
            .map_err(|e| format!("Signup request failed: {}", e))?;
        
        if response.status().is_success() {
            let session: SupabaseSession = response.json().await
                .map_err(|e| format!("Failed to parse signup response: {}", e))?;
            
            println!("✅ Signup successful");
            Ok(session)
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            println!("❌ Signup failed: {}", error_text);
            Err(format!("Signup failed: {}", error_text))
        }
    }

    // =========== BACKWARD COMPATIBILITY ALIASES ===========
    
    /// Alias for verify_supabase_jwt (backward compatibility)
    pub async fn verify_jwt_token(&self, jwt_token: &str) -> Result<UserInfo, String> {
        self.verify_supabase_jwt(jwt_token).await
    }
    
    /// Get profile by Supabase user ID (maps to get_profile_by_username via ID lookup)
    pub async fn get_profile(&self, supabase_user_id: &str) -> Result<Option<UserProfile>, String> {
        // For now, treat supabase_user_id as username since we might not have a direct mapping
        // The calling code should use the username from verify_jwt_token result
        self.get_profile_by_username(supabase_user_id).await
    }
    
    /// Create a new profile with wallet for a user
    pub async fn create_profile_with_wallet(&self, _supabase_user_id: &str, username: &str) -> Result<UserProfile, String> {
        // Use the existing add_wallet_to_existing_user which creates a profile with wallet
        self.add_wallet_to_existing_user(username).await
    }

} // ✅ This should be the END of your SupabaseConnector impl block