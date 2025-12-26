// ============================================================================
// UNIFIED AUTHENTICATION V2 - Pure ZK Signature Verification (NO JWT)
// ============================================================================
//
// This module provides STATELESS authentication using:
// 
// 1. ENCRYPTED BLOB: Client-side encrypted wallet vault (AES-256-GCM)
// 2. SALT: Public random salt for key derivation (stored in Supabase)
// 3. ZK SIGNATURE: Ed25519 signature proves wallet ownership
// 4. NO JWT: Every request includes a fresh signature
//
// Flow:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  1. Client derives private key from password + salt + encrypted blob   │
// │  2. Client signs request payload with ed25519 private key              │
// │  3. Layer1 verifies signature with public key                          │
// │  4. ✅ Valid → Execute request                                          │
// │  5. ❌ Invalid → Reject                                                 │
// │                                                                         │
// │  NO SESSION STATE - Each request is independently verified             │
// └─────────────────────────────────────────────────────────────────────────┘

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey, Signer};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;
use std::num::NonZeroUsize;
use warp::Filter;
use zeroize::{Zeroize, ZeroizeOnDrop};
use lru::LruCache;
use once_cell::sync::Lazy;

// ============================================================================
// NONCE DEDUPLICATION CACHE - Prevents replay attacks
// ============================================================================

/// Maximum number of nonces to track per time bucket
/// Each bucket holds 50k entries, with 2 buckets (current + previous)
/// Total: ~100k entries, but flood attacks only affect current bucket
const NONCE_BUCKET_SIZE: usize = 50_000;

/// Time bucket duration in seconds (must be >= REQUEST_EXPIRY_SECS)
/// We use 10 minutes so a nonce is valid for at least 5 minutes (expiry window)
const NONCE_BUCKET_DURATION_SECS: u64 = 600;

/// Nonce cache with time-bucketed storage
/// This prevents cache flood attacks: attackers can only evict entries from the current bucket,
/// but valid nonces from the previous bucket (still within 5-min expiry) are protected.
struct NonceBucketCache {
    /// Current time bucket
    current_bucket: LruCache<String, u64>,
    /// Previous time bucket (for nonces that span bucket boundaries)
    previous_bucket: LruCache<String, u64>,
    /// Start time of current bucket
    current_bucket_start: u64,
}

impl NonceBucketCache {
    fn new() -> Self {
        Self {
            current_bucket: LruCache::new(NonZeroUsize::new(NONCE_BUCKET_SIZE).unwrap()),
            previous_bucket: LruCache::new(NonZeroUsize::new(NONCE_BUCKET_SIZE).unwrap()),
            current_bucket_start: 0,
        }
    }
    
    /// Rotate buckets if we've entered a new time period
    fn maybe_rotate(&mut self, now: u64) {
        let bucket_start = (now / NONCE_BUCKET_DURATION_SECS) * NONCE_BUCKET_DURATION_SECS;
        
        if bucket_start > self.current_bucket_start {
            // New bucket period - rotate
            std::mem::swap(&mut self.current_bucket, &mut self.previous_bucket);
            self.current_bucket.clear();
            self.current_bucket_start = bucket_start;
            println!("🔄 Nonce cache rotated to new bucket (start: {})", bucket_start);
        }
    }
    
    /// Check if nonce exists in either bucket
    fn contains(&mut self, key: &str) -> Option<u64> {
        // Check current bucket first (most likely)
        if let Some(&ts) = self.current_bucket.get(key) {
            return Some(ts);
        }
        // Check previous bucket (for nonces near bucket boundary)
        if let Some(&ts) = self.previous_bucket.get(key) {
            return Some(ts);
        }
        None
    }
    
    /// Insert nonce into current bucket
    fn insert(&mut self, key: String, timestamp: u64) {
        self.current_bucket.put(key, timestamp);
    }
}

/// Global time-bucketed nonce cache
static NONCE_CACHE: Lazy<Mutex<NonceBucketCache>> = Lazy::new(|| {
    Mutex::new(NonceBucketCache::new())
});

/// Check if a nonce has been used and mark it as used
/// Returns Ok(()) if nonce is fresh, Err if replay attack detected
fn check_and_mark_nonce(public_key: &str, nonce: &str, timestamp: u64) -> Result<(), String> {
    let cache_key = format!("{}:{}", public_key, nonce);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    let mut cache = NONCE_CACHE.lock()
        .map_err(|_| "Nonce cache lock poisoned")?;
    
    // Rotate buckets if needed
    cache.maybe_rotate(now);
    
    // Check if nonce was already used (in either bucket)
    if let Some(used_at) = cache.contains(&cache_key) {
        return Err(format!(
            "Nonce replay attack detected: nonce '{}' was already used at timestamp {}",
            &nonce[..nonce.len().min(8)], used_at
        ));
    }
    
    // Mark nonce as used in current bucket
    cache.insert(cache_key, timestamp);
    
    Ok(())
}

// ============================================================================
// CONSTANTS
// ============================================================================

pub const SALT_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;
pub const VAULT_VERSION: u8 = 1;

pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;

pub const AUTH_CONSTANT: &str = "BLACKBOOK_AUTH_V1";
pub const WALLET_CONSTANT: &str = "BLACKBOOK_WALLET_V1";

/// Request expiry time (5 minutes for replay protection)
pub const REQUEST_EXPIRY_SECS: u64 = 300;

/// Signature format version (increment when changing signing logic)
pub const SIGNATURE_VERSION: u8 = 2;

// ============================================================================
// CANONICAL PAYLOAD SCHEMA - Operation Type Registry (V2)
// ============================================================================
// 
// Each operation type defines the EXACT fields and ORDER that must be signed.
// This prevents:
// 1. JSON.stringify non-determinism (key ordering varies by implementation)
// 2. Field injection attacks (attacker adds extra fields)
// 3. Type confusion (amount as string vs number)
//
// CRITICAL: Must match PAYLOAD_SCHEMAS in unified-wallet-sdk.js exactly!

/// Get the canonical field order for an operation type
pub fn get_payload_schema(operation_type: &str) -> Option<Vec<&'static str>> {
    match operation_type {
        // Transfer tokens between addresses
        "transfer" => Some(vec!["to", "amount"]),
        
        // Bridge operations (L1 ↔ L2)
        "bridge_deposit" => Some(vec!["amount"]),
        "bridge_withdraw" => Some(vec!["amount"]),
        
        // Dealer operations
        "dealer_deposit" => Some(vec!["user_address", "amount"]),
        "dealer_withdraw" => Some(vec!["user_address", "amount"]),
        "dealer_settle" => Some(vec!["user_address", "amount", "game_id"]),
        
        // Wallet operations
        "wallet_register" => Some(vec!["username"]),
        "wallet_login" => Some(vec![]),  // No payload fields, just proves ownership
        
        // Social mining
        "social_claim" => Some(vec!["action_type"]),
        "social_post" => Some(vec!["content_hash"]),
        
        // Market operations
        "market_order" => Some(vec!["market_id", "side", "amount"]),
        "market_cancel" => Some(vec!["order_id"]),
        
        // Generic fallback (uses alphabetically sorted keys)
        "generic" => None,
        
        // Unknown operation
        _ => None,
    }
}

/// Create a canonical hash of payload fields (must match JS implementation exactly)
pub fn create_canonical_payload_hash(
    operation_type: &str, 
    payload_fields: &serde_json::Value
) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(operation_type.as_bytes());
    
    match get_payload_schema(operation_type) {
        Some(fields) => {
            // Known operation type: hash fields in exact schema order
            for field_name in fields {
                if let Some(value) = payload_fields.get(field_name) {
                    hasher.update(field_name.as_bytes());
                    hasher.update(normalize_field_value(value)?.as_bytes());
                } else {
                    return Err(format!("Missing required field '{}' for operation '{}'", field_name, operation_type));
                }
            }
        },
        None => {
            // Generic fallback: sort keys alphabetically
            println!("⚠️ Using generic payload schema for '{}' - consider adding explicit schema", operation_type);
            if let Some(obj) = payload_fields.as_object() {
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort();
                for key in keys {
                    hasher.update(key.as_bytes());
                    hasher.update(normalize_field_value(&obj[key])?.as_bytes());
                }
            }
        }
    }
    
    Ok(hex::encode(hasher.finalize()))
}

/// Normalize a field value to a deterministic string (must match JS normalizeFieldValue exactly)
fn normalize_field_value(value: &serde_json::Value) -> Result<String, String> {
    match value {
        serde_json::Value::Null => Ok("null".to_string()),
        serde_json::Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        serde_json::Value::Number(n) => {
            // Integer handling
            if let Some(i) = n.as_i64() {
                return Ok(i.to_string());
            }
            if let Some(u) = n.as_u64() {
                return Ok(u.to_string());
            }
            // Float handling (match JS toPrecision behavior)
            if let Some(f) = n.as_f64() {
                // Use full precision, trim trailing zeros
                let s = format!("{:.15}", f);
                let trimmed = s.trim_end_matches('0').trim_end_matches('.');
                return Ok(trimmed.to_string());
            }
            Err("Invalid number format".to_string())
        },
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Array(arr) => {
            // Sort array elements for determinism
            let mut strings: Vec<String> = arr.iter()
                .map(|v| v.to_string())
                .collect();
            strings.sort();
            Ok(serde_json::to_string(&strings).unwrap_or_default())
        },
        serde_json::Value::Object(_) => Err("Cannot normalize nested objects. Flatten in schema.".to_string()),
    }
}

// ============================================================================
// DOMAIN SEPARATION - Prevents L1/L2 Replay Attacks
// ============================================================================

/// Layer 1 (Bank/Vault) Chain ID - Prepended to all L1 signatures
/// Ensures signatures for L1 transactions cannot be replayed on L2
pub const CHAIN_ID_L1: u8 = 0x01;

/// Layer 2 (Gaming/Casino) Chain ID - Prepended to all L2 signatures
/// Ensures signatures for L2 transactions cannot be replayed on L1
pub const CHAIN_ID_L2: u8 = 0x02;

// ============================================================================
// SIGNED REQUEST - Every API call includes a signature (NO JWT!)
// ============================================================================

/// A signed request that proves wallet ownership via ed25519 signature
/// Supports both V1 (legacy JSON) and V2 (canonical hash) formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// Ed25519 public key (64 hex chars) - used for signature verification
    pub public_key: String,
    
    /// Optional wallet address (L1...) - used for balance operations
    /// If not provided, public_key is used as the address
    #[serde(default)]
    pub wallet_address: Option<String>,
    
    // === V1 (Legacy) Fields ===
    /// The actual request payload (JSON string) - V1 legacy format
    #[serde(default)]
    pub payload: Option<String>,
    
    // === V2 (Canonical Hash) Fields ===
    /// SHA256 hash of canonically-ordered payload fields - V2 format
    #[serde(default)]
    pub payload_hash: Option<String>,
    
    /// The individual payload field values - V2 format
    #[serde(default)]
    pub payload_fields: Option<serde_json::Value>,
    
    /// Operation type (e.g., "transfer", "bridge_deposit") - V2 format
    #[serde(default)]
    pub operation_type: Option<String>,
    
    /// Schema version (1 = legacy JSON, 2 = canonical hash)
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    
    /// Unix timestamp (for replay protection)
    pub timestamp: u64,
    
    /// Random nonce (UUID for V2, counter string for V1)
    pub nonce: String,
    
    /// Chain ID for domain separation (0x01 = L1, 0x02 = L2)
    /// This prevents replay attacks between layers
    /// Default to L1 for backward compatibility
    #[serde(default = "default_chain_id")]
    pub chain_id: u8,
    
    /// Request path (e.g., "/transfer", "/wallet/balance")
    /// Prevents cross-endpoint replay attacks
    /// If not provided, signature verification still works but is less secure
    #[serde(default)]
    pub request_path: Option<String>,
    
    /// Ed25519 signature (128 hex chars)
    /// V1: Signs chain_id + request_path + payload + timestamp + nonce
    /// V2: Signs chain_id + request_path + payload_hash + timestamp + nonce
    pub signature: String,
}

/// Default schema version is 1 for backward compatibility
fn default_schema_version() -> u8 {
    1
}

/// Default chain ID is L1 for backward compatibility
fn default_chain_id() -> u8 {
    CHAIN_ID_L1
}

impl SignedRequest {
    /// Verify this request's signature with domain separation
    pub fn verify(&self) -> Result<String, String> {
        self.verify_with_path(None)
    }
    
    /// Verify this request's signature with domain separation and path binding
    /// 
    /// The `expected_path` parameter allows the server to enforce that the signature
    /// was created for this specific endpoint, preventing cross-endpoint replay attacks.
    /// 
    /// Supports both V1 (legacy JSON) and V2 (canonical hash) signature formats.
    pub fn verify_with_path(&self, expected_path: Option<&str>) -> Result<String, String> {
        // 1. Check timestamp freshness (5 min window)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let age = now.saturating_sub(self.timestamp);
        if age > REQUEST_EXPIRY_SECS {
            return Err(format!("Request expired: {} seconds old", age));
        }
        
        // 2. Validate chain_id
        if self.chain_id != CHAIN_ID_L1 && self.chain_id != CHAIN_ID_L2 {
            return Err(format!("Invalid chain_id: 0x{:02x}. Must be 0x01 (L1) or 0x02 (L2)", self.chain_id));
        }
        
        // 3. If server expects a specific path, verify it matches
        if let Some(expected) = expected_path {
            if let Some(ref signed_path) = self.request_path {
                if signed_path != expected {
                    return Err(format!(
                        "Path mismatch: signature is for '{}' but request is to '{}'",
                        signed_path, expected
                    ));
                }
            }
            // If request_path is None, we accept for backward compatibility
            // but log a warning
            else {
                println!("⚠️  Request missing request_path field (backward compatibility mode)");
            }
        }
        
        // 4. Check for nonce replay attack (deduplication)
        check_and_mark_nonce(&self.public_key, &self.nonce, self.timestamp)?;
        
        // 5. Reconstruct the signed message based on schema version
        let payload_component = self.get_payload_component()?;
        let path_component = self.request_path.as_deref().unwrap_or("");
        
        let payload_str = if path_component.is_empty() {
            // Backward compatibility: no path in signature
            format!("{}\n{}\n{}", payload_component, self.timestamp, self.nonce)
        } else {
            // New format: path included in signature
            format!("{}\n{}\n{}\n{}", path_component, payload_component, self.timestamp, self.nonce)
        };
        
        let mut signed_msg = Vec::new();
        signed_msg.push(self.chain_id);  // <--- CRITICAL: Domain separator
        signed_msg.extend_from_slice(payload_str.as_bytes());
        
        // 6. Decode public key
        let pubkey_bytes = hex::decode(&self.public_key)
            .map_err(|_| "Invalid public key hex")?;
        
        if pubkey_bytes.len() != 32 {
            return Err(format!("Invalid public key length: {}", pubkey_bytes.len()));
        }
        
        let verifying_key = VerifyingKey::from_bytes(
            pubkey_bytes.as_slice().try_into().unwrap()
        ).map_err(|e| format!("Invalid ed25519 key: {}", e))?;
        
        // 7. Decode signature
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| "Invalid signature hex")?;
        
        if sig_bytes.len() != 64 {
            return Err(format!("Invalid signature length: {}", sig_bytes.len()));
        }
        
        let signature = Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap()
        );
        
        // 8. Verify signature (DOMAIN-SEPARATED)
        // This will FAIL if:
        // - Signature was created for L1 (0x01) but verified against L2 (0x02)
        // - Signature was created for L2 (0x02) but verified against L1 (0x01)
        verifying_key.verify(&signed_msg, &signature)
            .map_err(|_| format!("Invalid signature for chain 0x{:02x} (schema v{})", self.chain_id, self.schema_version))?;
        
        // 9. Return wallet address (derived from public key)
        let chain_name = if self.chain_id == CHAIN_ID_L1 { "L1" } else { "L2" };
        println!("🔐 Domain-separated signature verified for {} chain (schema v{})", chain_name, self.schema_version);
        Ok(self.derive_wallet_address())
    }
    
    /// Get the payload component for signature verification
    /// V1: Returns the raw JSON payload string
    /// V2: Reconstructs the canonical hash from payload_fields
    fn get_payload_component(&self) -> Result<String, String> {
        if self.schema_version >= 2 {
            // V2: Use canonical payload hash
            if let (Some(ref op_type), Some(ref fields)) = (&self.operation_type, &self.payload_fields) {
                // Reconstruct the hash server-side to verify it matches
                let computed_hash = create_canonical_payload_hash(op_type, fields)?;
                
                // If client sent a payload_hash, verify it matches our computation
                if let Some(ref client_hash) = self.payload_hash {
                    if client_hash != &computed_hash {
                        return Err(format!(
                            "Payload hash mismatch: client sent {} but fields compute to {}",
                            &client_hash[..16], &computed_hash[..16]
                        ));
                    }
                }
                
                Ok(computed_hash)
            } else {
                Err("V2 signature requires operation_type and payload_fields".to_string())
            }
        } else {
            // V1: Use legacy JSON payload string
            self.payload.clone().ok_or_else(|| "V1 signature requires payload field".to_string())
        }
    }
    
    /// Get wallet address - uses wallet_address if provided, else public_key
    fn derive_wallet_address(&self) -> String {
        // Path B: Use wallet_address (L1...) if provided for balance operations
        // The signature is still verified against public_key
        self.wallet_address.clone().unwrap_or_else(|| self.public_key.clone())
    }
    
    /// Parse the payload as JSON (V1) or return payload_fields (V2)
    pub fn parse_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        if self.schema_version >= 2 {
            // V2: payload_fields already parsed
            if let Some(ref fields) = self.payload_fields {
                serde_json::from_value(fields.clone())
                    .map_err(|e| format!("Invalid payload_fields: {}", e))
            } else {
                Err("V2 signature requires payload_fields".to_string())
            }
        } else {
            // V1: parse JSON string
            if let Some(ref payload) = self.payload {
                serde_json::from_str(payload)
                    .map_err(|e| format!("Invalid payload JSON: {}", e))
            } else {
                Err("V1 signature requires payload field".to_string())
            }
        }
    }
    
    /// Get operation type (V2) or infer from path (V1)
    pub fn get_operation_type(&self) -> Option<String> {
        if let Some(ref op) = self.operation_type {
            return Some(op.clone());
        }
        // Infer from request_path for V1
        self.request_path.as_ref().and_then(|path| {
            match path.as_str() {
                "/transfer" => Some("transfer".to_string()),
                "/bridge/deposit" => Some("bridge_deposit".to_string()),
                "/bridge/withdraw" => Some("bridge_withdraw".to_string()),
                _ => None,
            }
        })
    }
}

// ============================================================================
// ENCRYPTED BLOB - Wallet vault stored in Supabase
// ============================================================================

/// The encrypted vault payload stored in Supabase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub version: u8,
    pub salt: String,           // 64 hex chars (32 bytes)
    pub ciphertext: String,     // Base64 encoded
    pub nonce: String,          // 24 hex chars (12 bytes)
    pub address: String,        // BlackBook address
    pub created_at: u64,
}

/// The decrypted blob contents (zeroized on drop)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BlobContents {
    pub mnemonic: String,
    pub created_at: u64,
    #[zeroize(skip)]
    pub label: Option<String>,
}

/// Derived encryption key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    bytes: [u8; KEY_LENGTH],
}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.bytes
    }
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

pub fn derive_encryption_key(password: &[u8], salt: &[u8]) -> Result<DerivedKey, String> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    ).map_err(|e| format!("Invalid Argon2 params: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut key_bytes = [0u8; KEY_LENGTH];
    argon2
        .hash_password_into(password, salt, &mut key_bytes)
        .map_err(|e| format!("Argon2 failed: {}", e))?;
    
    Ok(DerivedKey { bytes: key_bytes })
}

pub fn derive_login_password(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    hasher.update(AUTH_CONSTANT.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn derive_wallet_key(password: &str, salt_hex: &str) -> Result<DerivedKey, String> {
    let wallet_input = format!("{}{}", password, WALLET_CONSTANT);
    let salt = hex::decode(salt_hex)
        .map_err(|e| format!("Invalid hex salt: {}", e))?;
    derive_encryption_key(wallet_input.as_bytes(), &salt)
}

// ============================================================================
// BLOB ENCRYPTION/DECRYPTION
// ============================================================================

pub fn encrypt_blob(
    contents: &BlobContents,
    key: &DerivedKey,
) -> Result<(Vec<u8>, [u8; NONCE_LENGTH]), String> {
    let plaintext = serde_json::to_vec(contents)
        .map_err(|e| format!("Serialization failed: {}", e))?;
    
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| format!("AES-GCM encrypt failed: {}", e))?;
    
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_blob(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    key: &DerivedKey,
) -> Result<BlobContents, String> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| format!("Invalid key: {}", e))?;
    
    let nonce = Nonce::from_slice(nonce);
    
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed - wrong password or corrupted blob".to_string())?;
    
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Invalid blob format: {}", e))
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_salt_hex() -> String {
    hex::encode(generate_salt())
}

// ============================================================================
// HIGH-LEVEL BLOB OPERATIONS
// ============================================================================

pub fn create_encrypted_blob(
    mnemonic: &str,
    password: &str,
    address: &str,
    label: Option<String>,
) -> Result<EncryptedBlob, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    let salt = generate_salt();
    let salt_hex = hex::encode(&salt);
    
    let key = derive_encryption_key(password.as_bytes(), &salt)?;
    
    let contents = BlobContents {
        mnemonic: mnemonic.to_string(),
        created_at: now,
        label,
    };
    
    let (ciphertext, nonce) = encrypt_blob(&contents, &key)?;
    
    Ok(EncryptedBlob {
        version: VAULT_VERSION,
        salt: salt_hex,
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
        nonce: hex::encode(nonce),
        address: address.to_string(),
        created_at: now,
    })
}

pub fn unlock_encrypted_blob(
    blob: &EncryptedBlob,
    password: &str,
) -> Result<BlobContents, String> {
    let key = derive_key_from_hex_salt(password, &blob.salt)?;
    
    let nonce_bytes = hex::decode(&blob.nonce)
        .map_err(|e| format!("Invalid hex nonce: {}", e))?;
    
    if nonce_bytes.len() != NONCE_LENGTH {
        return Err(format!("Invalid nonce length: {}", nonce_bytes.len()));
    }
    
    let nonce: [u8; NONCE_LENGTH] = nonce_bytes.try_into().unwrap();
    
    let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &blob.ciphertext)
        .map_err(|e| format!("Invalid base64 blob: {}", e))?;
    
    decrypt_blob(&ciphertext, &nonce, &key)
}

pub fn derive_key_from_hex_salt(password: &str, salt_hex: &str) -> Result<DerivedKey, String> {
    let salt = hex::decode(salt_hex)
        .map_err(|e| format!("Invalid hex salt: {}", e))?;
    
    if salt.len() != SALT_LENGTH {
        return Err(format!("Salt must be {} bytes", SALT_LENGTH));
    }
    
    derive_encryption_key(password.as_bytes(), &salt)
}

// ============================================================================
// WARP FILTER - Signature-based authentication (NO JWT!)
// ============================================================================

#[derive(Debug)]
pub struct AuthError(pub String);
impl warp::reject::Reject for AuthError {}

/// Warp filter that verifies ed25519 signature on EVERY request
/// Returns the verified wallet address
pub fn with_signature_auth() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::body::json()
        .and_then(|request: SignedRequest| async move {
            match request.verify() {
                Ok(wallet_address) => {
                    println!("✅ Signature verified: {}...", &wallet_address[..16.min(wallet_address.len())]);
                    Ok(wallet_address)
                },
                Err(e) => {
                    println!("❌ Signature verification failed: {}", e);
                    Err(warp::reject::custom(AuthError(e)))
                }
            }
        })
}

/// Warp filter that extracts both wallet address and parsed payload
pub fn with_signature_auth_and_payload<T>() -> impl Filter<Extract = ((String, T),), Error = warp::Rejection> + Clone 
where
    T: serde::de::DeserializeOwned + Send,
{
    warp::body::json()
        .and_then(|request: SignedRequest| async move {
            match request.verify() {
                Ok(wallet_address) => {
                    match request.parse_payload::<T>() {
                        Ok(payload) => {
                            println!("✅ Signature verified: {}...", &wallet_address[..16.min(wallet_address.len())]);
                            Ok((wallet_address, payload))
                        },
                        Err(e) => {
                            println!("❌ Invalid payload: {}", e);
                            Err(warp::reject::custom(AuthError(e)))
                        }
                    }
                },
                Err(e) => {
                    println!("❌ Signature verification failed: {}", e);
                    Err(warp::reject::custom(AuthError(e)))
                }
            }
        })
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

pub fn generate_keypair() -> (String, String) {
    let mut secret_bytes = [0u8; 32];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut secret_bytes);
    
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    
    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());
    
    (private_hex, public_hex)
}

/// Generate keypair from a deterministic seed (for testing)
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> (String, String) {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    
    let public_hex = hex::encode(verifying_key.to_bytes());
    let private_hex = hex::encode(signing_key.to_bytes());
    
    (public_hex, private_hex)
}

// ============================================================================
// DOMAIN-SEPARATED SIGNING UTILITIES
// ============================================================================

/// Sign a message with domain separation for a specific chain
/// 
/// This is the CLIENT-SIDE signing function that creates signatures
/// that can only be verified on the intended chain (L1 or L2).
/// 
/// # Arguments
/// * `private_key_hex` - The user's private key (64 hex chars)
/// * `message` - The message to sign (payload\ntimestamp\nnonce)
/// * `chain_id` - Target chain (CHAIN_ID_L1 or CHAIN_ID_L2)
/// 
/// # Returns
/// Hex-encoded signature (128 hex chars)
pub fn sign_with_domain_separation(
    private_key_hex: &str,
    message: &str,
    chain_id: u8,
) -> Result<String, String> {
    // 1. Validate chain_id
    if chain_id != CHAIN_ID_L1 && chain_id != CHAIN_ID_L2 {
        return Err(format!("Invalid chain_id: 0x{:02x}", chain_id));
    }
    
    // 2. Decode private key
    let key_bytes = hex::decode(private_key_hex)
        .map_err(|_| "Invalid private key hex")?;
    
    if key_bytes.len() != 32 {
        return Err(format!("Invalid private key length: {}", key_bytes.len()));
    }
    
    let signing_key = SigningKey::from_bytes(
        key_bytes.as_slice().try_into().unwrap()
    );
    
    // 3. Construct domain-separated message
    let mut signed_msg = Vec::new();
    signed_msg.push(chain_id);  // <--- CRITICAL: Domain separator
    signed_msg.extend_from_slice(message.as_bytes());
    
    // 4. Sign
    let signature = signing_key.sign(&signed_msg);
    
    Ok(hex::encode(signature.to_bytes()))
}

/// Create a SignedRequest with domain separation
/// 
/// This is a convenience function for creating properly signed requests
/// for either L1 or L2 chains.
pub fn create_signed_request(
    private_key_hex: &str,
    public_key_hex: &str,
    payload: String,
    chain_id: u8,
) -> Result<SignedRequest, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let nonce = uuid::Uuid::new_v4().to_string();
    
    // Construct the message to sign
    let message = format!("{}\n{}\n{}", payload, timestamp, nonce);
    
    // Sign with domain separation
    let signature = sign_with_domain_separation(private_key_hex, &message, chain_id)?;
    
    // Create V1 (legacy) format request for backward compatibility
    Ok(SignedRequest {
        public_key: public_key_hex.to_string(),
        wallet_address: None,
        payload: Some(payload),  // V1: payload as JSON string
        payload_hash: None,      // V2 only
        payload_fields: None,    // V2 only
        operation_type: None,    // V2 only
        schema_version: 1,       // V1 format
        timestamp,
        nonce,
        chain_id,
        request_path: None,  // No path binding in this helper (for backward compat)
        signature,
    })
}

// ============================================================================
// TEST ACCOUNTS - Full-Featured Alice & Bob + 9 L2 Accounts
// ============================================================================
// Alice and Bob are comprehensive test accounts with:
// - Ed25519 keypairs for signing
// - L1 and L2 balances
// - Deterministic generation (always same keys)
// - Full access to: transfer, bridge, social mining, MPC
// 
// The 9 L2 accounts are for prediction market testing

/// Full test account with all capabilities
/// 
/// UNIFIED WALLET MODEL:
/// - total_balance: User's total funds (what they see)
/// - l1_available: Unlocked funds on L1 (can transfer or bridge)
/// - l1_locked: Funds locked during L2 session (cannot transfer)
/// - l2_balance: Active gaming balance on L2 (bridged from L1)
/// 
/// Invariant: total_balance = l1_available + l1_locked
/// When bridged: l1_locked == l2_balance (mirrored)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullTestAccount {
    pub name: &'static str,
    pub public_key: String,        // Ed25519 public key (hex)
    pub private_key: String,       // Ed25519 private key (hex) - ONLY for testing!
    pub address: String,           // Unified wallet address (works on both L1 and L2)
    pub total_balance: f64,        // User's total balance (what they see in UI)
    pub l1_available: f64,         // Available on L1 (not locked)
    pub l1_locked: f64,            // Locked on L1 (bridged to L2)
    pub l2_balance: f64,           // Active balance on L2 (for betting)
    pub email: String,             // For Supabase integration
    pub username: String,          // For social features
}

/// Get Alice's full test account - deterministic and always available
/// Alice starts with 10,000 BB all available on L1 (nothing locked, nothing on L2)
pub fn get_alice_account() -> FullTestAccount {
    let (public_key, private_key) = get_alice_keypair();
    FullTestAccount {
        name: "Alice",
        public_key: public_key.clone(),
        private_key,
        address: "L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD".to_string(),  // L1_ + SHA256(pubkey).slice(0,40)
        total_balance: 10000.0,   // Total funds (what Alice sees in UI)
        l1_available: 10000.0,    // All funds available on L1
        l1_locked: 0.0,           // Nothing locked (no active L2 session)
        l2_balance: 0.0,          // No funds on L2 yet (must bridge first)
        email: "alice@blackbook.test".to_string(),
        username: "alice_test".to_string(),
    }
}

/// Get Bob's full test account - deterministic and always available
/// Bob starts with 5,000 BB all available on L1 (nothing locked, nothing on L2)
pub fn get_bob_account() -> FullTestAccount {
    let (public_key, private_key) = get_bob_keypair();
    FullTestAccount {
        name: "Bob",
        public_key: public_key.clone(),
        private_key,
        address: "L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9".to_string(),  // L1_ + SHA256(pubkey).slice(0,40)
        total_balance: 5000.0,    // Total funds (what Bob sees in UI)
        l1_available: 5000.0,     // All funds available on L1
        l1_locked: 0.0,           // Nothing locked (no active L2 session)
        l2_balance: 0.0,          // No funds on L2 yet (must bridge first)
        email: "bob@blackbook.test".to_string(),
        username: "bob_test".to_string(),
    }
}

/// Get all full test accounts (Alice + Bob)
pub fn get_all_full_test_accounts() -> Vec<FullTestAccount> {
    vec![
        get_alice_account(),
        get_bob_account(),
    ]
}

// ============================================================================
// DEALER ORACLE ACCOUNT - L2 Native "God Mode" Account
// ============================================================================
//
// ⚠️ CRITICAL SECURITY DIFFERENCE FROM ALICE/BOB:
//
// Alice/Bob: Test accounts with private keys IN the codebase (for testing)
// Dealer:    PRODUCTION oracle - private key NEVER stored in code
//
// The Dealer is the "House" - it can:
// - Create prediction markets on L2
// - Resolve markets (declare winners)
// - Push payouts to winners
// - Operate with infinite L2 liquidity (backed by L1 vault)
//
// The private key must be:
// 1. Generated ONCE and stored securely offline
// 2. Loaded from environment variable DEALER_PRIVATE_KEY when signing
// 3. NEVER committed to version control
// ============================================================================

/// Dealer's L1 wallet address (for bankroll on Layer 1)
/// Generated from BIP-39 mnemonic with derivation path m/44'/1337'/0'/0'/0'
/// Note: Dealer uses L1_ prefix for token custody, L2_ for betting operations
pub const DEALER_ADDRESS: &str = "L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3";

/// Dealer's PUBLIC KEY ONLY - the private key is NEVER stored in code
/// This public key is used to verify Dealer signatures on market operations
/// Private key stored in environment variable: DEALER_PRIVATE_KEY
pub const DEALER_PUBLIC_KEY: &str = "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a";

/// Get the Dealer's public key for signature verification
/// The private key must come from environment variable DEALER_PRIVATE_KEY
pub fn get_dealer_public_key() -> String {
    DEALER_PUBLIC_KEY.to_string()
}

/// Get the Dealer's private key from environment variable
/// SECURITY: This is ONLY for signing - never log or expose this value!
/// Returns None if DEALER_PRIVATE_KEY is not set (safer for production)
pub fn get_dealer_private_key() -> Option<String> {
    std::env::var("DEALER_PRIVATE_KEY").ok()
}

/// Check if Dealer private key is configured
pub fn is_dealer_configured() -> bool {
    std::env::var("DEALER_PRIVATE_KEY").is_ok()
}

/// Sign a message as the Dealer (for L2 market operations)
/// Returns Err if DEALER_PRIVATE_KEY is not set
pub fn sign_as_dealer(message: &str) -> Result<String, String> {
    let private_key = get_dealer_private_key()
        .ok_or_else(|| "DEALER_PRIVATE_KEY not set in environment".to_string())?;
    
    sign_message(&private_key, message)
}

/// Get the Dealer's address
pub fn get_dealer_address() -> String {
    DEALER_ADDRESS.to_string()
}

/// Verify a signature was made by the Dealer
/// This ONLY uses the public key - never touches the private key
pub fn verify_dealer_signature(message: &str, signature: &str) -> Result<bool, String> {
    // Decode public key
    let pubkey_bytes = hex::decode(DEALER_PUBLIC_KEY)
        .map_err(|_| "Invalid dealer public key hex")?;
    
    let verifying_key = VerifyingKey::from_bytes(
        pubkey_bytes.as_slice().try_into().map_err(|_| "Invalid key length")?
    ).map_err(|e| format!("Invalid ed25519 key: {}", e))?;
    
    // Decode signature
    let sig_bytes = hex::decode(signature)
        .map_err(|_| "Invalid signature hex")?;
    
    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: {}", sig_bytes.len()));
    }
    
    let sig = Signature::from_bytes(
        sig_bytes.as_slice().try_into().unwrap()
    );
    
    // Verify
    match verifying_key.verify(message.as_bytes(), &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if an address is the Dealer's address
pub fn is_dealer_address(address: &str) -> bool {
    address == DEALER_ADDRESS
}

/// Check if a public key is the Dealer's public key
pub fn is_dealer_public_key(public_key: &str) -> bool {
    public_key == DEALER_PUBLIC_KEY
}

/// Alice's Ed25519 keypair - derived from BIP-39 mnemonic
/// Mnemonic: "machine sword cause scrub simple damage program together spoon lock ball banana"
/// Derivation: m/44'/1337'/0'/0'/0' (SLIP-0010)
pub fn get_alice_keypair() -> (String, String) {
    // BIP-39 derived seed for Alice
    // Generated by: sdk/generate-test-accounts.js
    let seed: [u8; 32] = [
        0x18, 0xf2, 0xc2, 0xe3, 0xbc, 0xb7, 0xa4, 0xb5,
        0x32, 0x9c, 0xfe, 0xd4, 0xbd, 0x79, 0xbf, 0x17,
        0xdf, 0x4d, 0x47, 0xaa, 0x18, 0x88, 0xa6, 0xb3,
        0xd1, 0xa1, 0x45, 0x0f, 0xb5, 0x3a, 0x8a, 0x24,
    ];
    generate_keypair_from_seed(&seed)
}

/// Bob's Ed25519 keypair - derived from BIP-39 mnemonic
/// Mnemonic: "base echo grape penalty hawk resemble obscure unusual throw paddle carpet elder"
/// Derivation: m/44'/1337'/0'/0'/0' (SLIP-0010)
pub fn get_bob_keypair() -> (String, String) {
    // BIP-39 derived seed for Bob
    // Generated by: sdk/generate-test-accounts.js
    let seed: [u8; 32] = [
        0xe4, 0xac, 0x49, 0xe5, 0xa0, 0x4e, 0xf7, 0xdf,
        0xc6, 0xe1, 0xa8, 0x38, 0xfd, 0xf1, 0x45, 0x97,
        0xf2, 0xd5, 0x14, 0xd0, 0x02, 0x9a, 0x82, 0xcb,
        0x45, 0xc9, 0x16, 0x29, 0x34, 0x87, 0xc2, 0x5b,
    ];
    generate_keypair_from_seed(&seed)
}

pub fn sign_message(private_key_hex: &str, message: &str) -> Result<String, String> {
    let private_bytes = hex::decode(private_key_hex)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    
    let signing_key = SigningKey::from_bytes(
        private_bytes.as_slice().try_into()
            .map_err(|_| "Invalid private key length")?
    );
    
    let signature = signing_key.sign(message.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_verification() {
        let (private, public) = generate_keypair();
        let payload = r#"{"to":"recipient","amount":10.5}"#;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let nonce = "abc123";
        
        let message = format!("{}\n{}\n{}", payload, timestamp, nonce);
        let signature = sign_message(&private, &message).unwrap();
        
        // Create V1 (legacy) format request for test
        let request = SignedRequest {
            public_key: public.clone(),
            wallet_address: Some(public),
            payload: Some(payload.to_string()),  // V1 format
            payload_hash: None,
            payload_fields: None,
            operation_type: None,
            schema_version: 1,
            timestamp,
            nonce: nonce.to_string(),
            chain_id: CHAIN_ID_L1,
            request_path: None,
            signature,
        };
        
        assert!(request.verify().is_ok());
    }
    
    #[test]
    fn test_blob_encryption() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "TestPassword123!";
        
        let blob = create_encrypted_blob(mnemonic, password, "bb1_test", None).unwrap();
        let contents = unlock_encrypted_blob(&blob, password).unwrap();
        
        assert_eq!(contents.mnemonic, mnemonic);
    }
}
