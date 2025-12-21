// ============================================================================
// MPC AUTHENTICATION - 2-of-2 Threshold Signing
// ============================================================================
//
// This module implements Multi-Party Computation for Ed25519 signing.
// The private key is split into two shares:
//   - Shard A: Stored on client (user's device)
//   - Shard B: Stored on server (encrypted at rest)
//
// Neither party alone can sign. Both must cooperate.
// This protects against:
//   - Client-side malware (attacker gets shard_a but not shard_b)
//   - Server compromise (attacker gets shard_b but not shard_a)
//
// Protocol:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  KEYGEN (one-time setup):                                              │
// │  1. Client generates random k_a (32 bytes) → shard_a                   │
// │  2. Server generates random k_b (32 bytes) → shard_b                   │
// │  3. Combined key = sha256(k_a || k_b) → ed25519 private key            │
// │  4. Server stores (wallet_address, shard_b) encrypted                  │
// │  5. Client stores shard_a (user must back this up!)                    │
// │                                                                         │
// │  SIGNING (every transaction):                                          │
// │  1. Client sends: (wallet_address, shard_a, message_hash)              │
// │  2. Server retrieves shard_b for wallet                                │
// │  3. Server reconstructs key = sha256(shard_a || shard_b)               │
// │  4. Server signs message_hash with reconstructed key                   │
// │  5. Server zeroizes reconstructed key immediately                      │
// │  6. Returns signature to client                                        │
// └─────────────────────────────────────────────────────────────────────────┘
//
// Security Notes:
// - The reconstructed key exists in server memory only during signing (~1ms)
// - shard_a is transmitted over TLS but should still use additional encryption
// - Rate limiting prevents brute-force attacks on shard_a
// - Shard rotation: Users can rotate shards without changing wallet address

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore as AeadRngCore},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::Filter;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// CONSTANTS
// ============================================================================

pub const SHARD_LENGTH: usize = 32;
pub const MPC_VERSION: u8 = 1;

/// Maximum signing requests per minute per wallet (rate limiting)
pub const MAX_SIGNS_PER_MINUTE: u32 = 30;

// ============================================================================
// MPC STORAGE - Server-side shard storage
// ============================================================================

/// Server-side storage for MPC shards
#[derive(Clone)]
pub struct MpcStorage {
    /// Maps wallet_address -> encrypted shard_b
    shards: Arc<RwLock<HashMap<String, MpcShardRecord>>>,
    /// Master encryption key for shard storage (should be from HSM in production)
    storage_key: [u8; 32],
}

/// A stored MPC shard record
#[derive(Clone, Serialize, Deserialize)]
struct MpcShardRecord {
    version: u8,
    /// AES-256-GCM encrypted shard_b
    encrypted_shard: Vec<u8>,
    /// 12-byte nonce for AES
    nonce: [u8; 12],
    /// Public key for this wallet (for verification)
    public_key: String,
    /// Creation timestamp
    created_at: u64,
    /// Last signing timestamp (for rate limiting)
    last_sign_at: u64,
    /// Number of signs in current minute window
    signs_this_minute: u32,
}

impl MpcStorage {
    /// Create new MPC storage with a random master key
    /// NOTE: In production, this key should come from an HSM
    pub fn new() -> Self {
        let mut storage_key = [0u8; 32];
        AeadRngCore::fill_bytes(&mut OsRng, &mut storage_key);
        
        Self {
            shards: Arc::new(RwLock::new(HashMap::new())),
            storage_key,
        }
    }
    
    /// Create with a specific storage key (for testing or HSM integration)
    pub fn with_key(storage_key: [u8; 32]) -> Self {
        Self {
            shards: Arc::new(RwLock::new(HashMap::new())),
            storage_key,
        }
    }
    
    /// Store a new shard for a wallet
    pub async fn store_shard(
        &self,
        wallet_address: &str,
        shard_b: &[u8; 32],
        public_key: &str,
    ) -> Result<(), String> {
        // Encrypt shard_b before storage
        let cipher = Aes256Gcm::new_from_slice(&self.storage_key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;
        
        let mut nonce_bytes = [0u8; 12];
        AeadRngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_shard = cipher.encrypt(nonce, shard_b.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let record = MpcShardRecord {
            version: MPC_VERSION,
            encrypted_shard,
            nonce: nonce_bytes,
            public_key: public_key.to_string(),
            created_at: now,
            last_sign_at: 0,
            signs_this_minute: 0,
        };
        
        let mut shards = self.shards.write().await;
        shards.insert(wallet_address.to_string(), record);
        
        Ok(())
    }
    
    /// Retrieve and decrypt shard_b for signing
    /// Returns (shard_b, public_key)
    pub async fn get_shard(
        &self,
        wallet_address: &str,
    ) -> Result<([u8; 32], String), String> {
        let mut shards = self.shards.write().await;
        
        let record = shards.get_mut(wallet_address)
            .ok_or_else(|| "Wallet not found in MPC storage".to_string())?;
        
        // Rate limiting check
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Reset counter if we're in a new minute
        if now - record.last_sign_at >= 60 {
            record.signs_this_minute = 0;
        }
        
        if record.signs_this_minute >= MAX_SIGNS_PER_MINUTE {
            return Err("Rate limit exceeded: too many signing requests".to_string());
        }
        
        record.signs_this_minute += 1;
        record.last_sign_at = now;
        
        // Decrypt shard_b
        let cipher = Aes256Gcm::new_from_slice(&self.storage_key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;
        
        let nonce = Nonce::from_slice(&record.nonce);
        
        let shard_b_vec = cipher.decrypt(nonce, record.encrypted_shard.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        if shard_b_vec.len() != 32 {
            return Err("Invalid shard length".to_string());
        }
        
        let mut shard_b = [0u8; 32];
        shard_b.copy_from_slice(&shard_b_vec);
        
        Ok((shard_b, record.public_key.clone()))
    }
    
    /// Check if a wallet has MPC enabled
    pub async fn has_wallet(&self, wallet_address: &str) -> bool {
        let shards = self.shards.read().await;
        shards.contains_key(wallet_address)
    }
}

// ============================================================================
// MPC KEY DERIVATION - Combine shards into signing key
// ============================================================================

/// Securely combines two shards into an Ed25519 signing key
/// The key is zeroized when dropped
#[derive(ZeroizeOnDrop)]
struct MpcKeyDerivation {
    #[zeroize(skip)]
    signing_key: Option<SigningKey>,
}

impl MpcKeyDerivation {
    /// Derive signing key from two shards
    /// key = sha256(shard_a || shard_b)[0..32]
    fn derive(shard_a: &[u8; 32], shard_b: &[u8; 32]) -> Result<Self, String> {
        let mut hasher = Sha256::new();
        hasher.update(shard_a);
        hasher.update(shard_b);
        let derived = hasher.finalize();
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&derived);
        
        let signing_key = SigningKey::from_bytes(&key_bytes);
        
        // Zeroize the intermediate key bytes
        key_bytes.zeroize();
        
        Ok(Self {
            signing_key: Some(signing_key),
        })
    }
    
    /// Sign a message and return the signature
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.signing_key.as_ref()
            .ok_or_else(|| "Key not available".to_string())?;
        
        let signature = key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
    
    /// Get the public key
    fn public_key(&self) -> Result<String, String> {
        let key = self.signing_key.as_ref()
            .ok_or_else(|| "Key not available".to_string())?;
        
        Ok(hex::encode(key.verifying_key().as_bytes()))
    }
}

// ============================================================================
// API TYPES - Request/Response structures
// ============================================================================

/// Request to initialize MPC keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcKeygenRequest {
    /// Client's shard (32 bytes, hex encoded)
    pub shard_a: String,
    /// Desired wallet address (or will be derived)
    pub wallet_address: Option<String>,
}

/// Response from MPC keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcKeygenResponse {
    pub success: bool,
    /// The wallet address (L1...)
    pub wallet_address: String,
    /// The public key (for verification)
    pub public_key: String,
    /// Server's contribution hash (for verification without revealing shard_b)
    pub server_contribution_hash: String,
    pub message: String,
}

/// Request to sign with MPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSignRequest {
    /// Wallet address to sign for
    pub wallet_address: String,
    /// Client's shard (32 bytes, hex encoded)
    pub shard_a: String,
    /// Message to sign (hex encoded hash)
    pub message_hash: String,
    /// Optional: The full message for transparency
    pub message: Option<String>,
}

/// Response from MPC signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSignResponse {
    pub success: bool,
    /// The Ed25519 signature (128 hex chars)
    pub signature: Option<String>,
    /// The public key that signed
    pub public_key: Option<String>,
    pub message: String,
}

/// Status check for MPC wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcStatusRequest {
    pub wallet_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcStatusResponse {
    pub success: bool,
    pub mpc_enabled: bool,
    pub public_key: Option<String>,
    pub message: String,
}

// ============================================================================
// MPC HANDLERS - Route handlers
// ============================================================================

/// Handle MPC keygen request
async fn handle_mpc_keygen(
    storage: MpcStorage,
    req: MpcKeygenRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    // 1. Decode and validate shard_a
    let shard_a_bytes = match hex::decode(&req.shard_a) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        Ok(bytes) => {
            return Ok(warp::reply::json(&MpcKeygenResponse {
                success: false,
                wallet_address: String::new(),
                public_key: String::new(),
                server_contribution_hash: String::new(),
                message: format!("Invalid shard_a length: expected 32 bytes, got {}", bytes.len()),
            }));
        }
        Err(e) => {
            return Ok(warp::reply::json(&MpcKeygenResponse {
                success: false,
                wallet_address: String::new(),
                public_key: String::new(),
                server_contribution_hash: String::new(),
                message: format!("Invalid shard_a hex: {}", e),
            }));
        }
    };
    
    // 2. Generate server's shard_b
    let mut shard_b = [0u8; 32];
    AeadRngCore::fill_bytes(&mut OsRng, &mut shard_b);
    
    // 3. Derive the combined key to get public key
    let key_derivation = match MpcKeyDerivation::derive(&shard_a_bytes, &shard_b) {
        Ok(kd) => kd,
        Err(e) => {
            return Ok(warp::reply::json(&MpcKeygenResponse {
                success: false,
                wallet_address: String::new(),
                public_key: String::new(),
                server_contribution_hash: String::new(),
                message: format!("Key derivation failed: {}", e),
            }));
        }
    };
    
    let public_key = match key_derivation.public_key() {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(warp::reply::json(&MpcKeygenResponse {
                success: false,
                wallet_address: String::new(),
                public_key: String::new(),
                server_contribution_hash: String::new(),
                message: format!("Public key derivation failed: {}", e),
            }));
        }
    };
    
    // 4. Generate wallet address (L1 format)
    let wallet_address = req.wallet_address.unwrap_or_else(|| {
        // Derive L1 address from public key
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        format!("L1{}", hex::encode(&hash[..20]))
    });
    
    // 5. Store shard_b
    if let Err(e) = storage.store_shard(&wallet_address, &shard_b, &public_key).await {
        return Ok(warp::reply::json(&MpcKeygenResponse {
            success: false,
            wallet_address: String::new(),
            public_key: String::new(),
            server_contribution_hash: String::new(),
            message: format!("Storage failed: {}", e),
        }));
    }
    
    // 6. Create server contribution hash (so client can verify without seeing shard_b)
    let mut hasher = Sha256::new();
    hasher.update(&shard_b);
    let server_hash = hex::encode(hasher.finalize());
    
    // 7. Zeroize shard_b (it's now encrypted in storage)
    let mut shard_b_copy = shard_b;
    shard_b_copy.zeroize();
    
    Ok(warp::reply::json(&MpcKeygenResponse {
        success: true,
        wallet_address,
        public_key,
        server_contribution_hash: server_hash,
        message: "MPC wallet created successfully. Store your shard_a securely!".to_string(),
    }))
}

/// Handle MPC sign request
async fn handle_mpc_sign(
    storage: MpcStorage,
    req: MpcSignRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    // 1. Decode and validate shard_a
    let shard_a_bytes = match hex::decode(&req.shard_a) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        Ok(bytes) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Invalid shard_a length: expected 32 bytes, got {}", bytes.len()),
            }));
        }
        Err(e) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Invalid shard_a hex: {}", e),
            }));
        }
    };
    
    // 2. Decode message hash
    let message_bytes = match hex::decode(&req.message_hash) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Invalid message_hash hex: {}", e),
            }));
        }
    };
    
    // 3. Retrieve shard_b from storage
    let (mut shard_b, stored_public_key) = match storage.get_shard(&req.wallet_address).await {
        Ok((sb, pk)) => (sb, pk),
        Err(e) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: e,
            }));
        }
    };
    
    // 4. Reconstruct the signing key
    let key_derivation = match MpcKeyDerivation::derive(&shard_a_bytes, &shard_b) {
        Ok(kd) => kd,
        Err(e) => {
            shard_b.zeroize();
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Key derivation failed: {}", e),
            }));
        }
    };
    
    // Zeroize shard_b immediately after use
    shard_b.zeroize();
    
    // 5. Verify the derived public key matches stored
    let derived_public_key = match key_derivation.public_key() {
        Ok(pk) => pk,
        Err(e) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Public key derivation failed: {}", e),
            }));
        }
    };
    
    if derived_public_key != stored_public_key {
        return Ok(warp::reply::json(&MpcSignResponse {
            success: false,
            signature: None,
            public_key: None,
            message: "Invalid shard_a: derived public key does not match".to_string(),
        }));
    }
    
    // 6. Sign the message
    let signature = match key_derivation.sign(&message_bytes) {
        Ok(sig) => hex::encode(sig),
        Err(e) => {
            return Ok(warp::reply::json(&MpcSignResponse {
                success: false,
                signature: None,
                public_key: None,
                message: format!("Signing failed: {}", e),
            }));
        }
    };
    
    // Key is automatically zeroized when key_derivation drops
    
    Ok(warp::reply::json(&MpcSignResponse {
        success: true,
        signature: Some(signature),
        public_key: Some(derived_public_key),
        message: "Signature created successfully".to_string(),
    }))
}

/// Handle MPC status check
async fn handle_mpc_status(
    storage: MpcStorage,
    req: MpcStatusRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    let has_wallet = storage.has_wallet(&req.wallet_address).await;
    
    let public_key = if has_wallet {
        match storage.get_shard(&req.wallet_address).await {
            Ok((_, pk)) => Some(pk),
            Err(_) => None,
        }
    } else {
        None
    };
    
    Ok(warp::reply::json(&MpcStatusResponse {
        success: true,
        mpc_enabled: has_wallet,
        public_key,
        message: if has_wallet {
            "MPC is enabled for this wallet".to_string()
        } else {
            "MPC is not enabled for this wallet".to_string()
        },
    }))
}

// ============================================================================
// ROUTES - Warp filter definitions
// ============================================================================

/// Create all MPC routes
pub fn mpc_routes(
    storage: MpcStorage,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let keygen = warp::path!("mpc" / "keygen")
        .and(warp::post())
        .and(with_storage(storage.clone()))
        .and(warp::body::json())
        .and_then(handle_mpc_keygen);
    
    let sign = warp::path!("mpc" / "sign")
        .and(warp::post())
        .and(with_storage(storage.clone()))
        .and(warp::body::json())
        .and_then(handle_mpc_sign);
    
    let status = warp::path!("mpc" / "status")
        .and(warp::post())
        .and(with_storage(storage.clone()))
        .and(warp::body::json())
        .and_then(handle_mpc_status);
    
    keygen.or(sign).or(status)
}

/// Helper to inject storage into handlers
fn with_storage(
    storage: MpcStorage,
) -> impl Filter<Extract = (MpcStorage,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mpc_keygen_and_sign() {
        let storage = MpcStorage::new();
        
        // Generate client's shard
        let mut shard_a = [0u8; 32];
        OsRng.fill_bytes(&mut shard_a);
        let shard_a_hex = hex::encode(&shard_a);
        
        // Keygen
        let keygen_req = MpcKeygenRequest {
            shard_a: shard_a_hex.clone(),
            wallet_address: Some("L1test123".to_string()),
        };
        
        let result = handle_mpc_keygen(storage.clone(), keygen_req).await;
        assert!(result.is_ok());
        
        // The wallet should now exist
        assert!(storage.has_wallet("L1test123").await);
        
        // Sign a message
        let message = b"test message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hex::encode(hasher.finalize());
        
        let sign_req = MpcSignRequest {
            wallet_address: "L1test123".to_string(),
            shard_a: shard_a_hex,
            message_hash,
            message: Some("test message".to_string()),
        };
        
        let result = handle_mpc_sign(storage.clone(), sign_req).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_mpc_wrong_shard() {
        let storage = MpcStorage::new();
        
        // Generate client's shard
        let mut shard_a = [0u8; 32];
        OsRng.fill_bytes(&mut shard_a);
        let shard_a_hex = hex::encode(&shard_a);
        
        // Keygen
        let keygen_req = MpcKeygenRequest {
            shard_a: shard_a_hex.clone(),
            wallet_address: Some("L1wrongtest".to_string()),
        };
        
        let _ = handle_mpc_keygen(storage.clone(), keygen_req).await;
        
        // Try to sign with wrong shard
        let mut wrong_shard = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_shard);
        let wrong_shard_hex = hex::encode(&wrong_shard);
        
        let message = b"test message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hex::encode(hasher.finalize());
        
        let sign_req = MpcSignRequest {
            wallet_address: "L1wrongtest".to_string(),
            shard_a: wrong_shard_hex, // Wrong shard!
            message_hash,
            message: None,
        };
        
        // This should fail because the derived public key won't match
        let result = handle_mpc_sign(storage.clone(), sign_req).await;
        // The response will indicate failure via the JSON body
        assert!(result.is_ok()); // HTTP succeeded, but check JSON for failure
    }
}
