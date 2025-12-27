// ============================================================================
// UNIFIED AUTH - L1 Wallet Authentication (Ed25519 Signatures)
// ============================================================================
//
// Core authentication for L1 BlackBook blockchain:
// - Ed25519 signature verification
// - Nonce replay protection
// - Domain separation (L1/L2)
//
// ~300 lines of focused, production-ready code
// ============================================================================

use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use once_cell::sync::Lazy;

// ============================================================================
// CONSTANTS
// ============================================================================

/// L1 Chain ID for domain separation
pub const CHAIN_ID_L1: u8 = 0x01;

/// L2 Chain ID for domain separation  
pub const CHAIN_ID_L2: u8 = 0x02;

/// Request expiry window (5 minutes)
const REQUEST_EXPIRY_SECS: u64 = 300;

/// Maximum nonces to cache (prevents memory exhaustion)
const MAX_NONCE_CACHE: usize = 100_000;

// ============================================================================
// NONCE CACHE - Replay Attack Prevention
// ============================================================================

struct NonceCache {
    nonces: HashMap<String, u64>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            nonces: HashMap::new(),
        }
    }

    fn check_and_mark(&mut self, key: &str, timestamp: u64) -> Result<(), String> {
        // Cleanup old entries if cache is full
        if self.nonces.len() >= MAX_NONCE_CACHE {
            let cutoff = timestamp.saturating_sub(REQUEST_EXPIRY_SECS);
            self.nonces.retain(|_, &mut ts| ts > cutoff);
        }

        // Check for replay
        if self.nonces.contains_key(key) {
            return Err(format!("Nonce already used: {}", &key[..key.len().min(16)]));
        }

        self.nonces.insert(key.to_string(), timestamp);
        Ok(())
    }
}

static NONCE_CACHE: Lazy<Mutex<NonceCache>> = Lazy::new(|| Mutex::new(NonceCache::new()));

fn check_nonce(public_key: &str, nonce: &str, timestamp: u64) -> Result<(), String> {
    let key = format!("{}:{}", public_key, nonce);
    NONCE_CACHE
        .lock()
        .map_err(|_| "Nonce cache error")?
        .check_and_mark(&key, timestamp)
}

// ============================================================================
// SIGNED REQUEST - Core Authentication Structure
// ============================================================================

/// A signed request proving wallet ownership via Ed25519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    /// Ed25519 public key (64 hex chars)
    pub public_key: String,

    /// Wallet address (L1_xxx) - if not provided, derived from public_key
    #[serde(default)]
    pub wallet_address: Option<String>,

    /// Request payload as JSON string
    #[serde(default)]
    pub payload: Option<String>,

    /// Unix timestamp in seconds
    pub timestamp: u64,

    /// Unique nonce (UUID recommended)
    pub nonce: String,

    /// Chain ID: 1 = L1, 2 = L2
    #[serde(default = "default_chain_id")]
    pub chain_id: u8,

    /// Ed25519 signature (128 hex chars)
    pub signature: String,
}

fn default_chain_id() -> u8 {
    CHAIN_ID_L1
}

impl SignedRequest {
    /// Verify signature and return wallet address
    pub fn verify(&self) -> Result<String, String> {
        // 1. Check timestamp (5 min window)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now.saturating_sub(self.timestamp) > REQUEST_EXPIRY_SECS {
            return Err(format!("Request expired ({} seconds old)", now - self.timestamp));
        }

        // 2. Validate chain_id
        if self.chain_id != CHAIN_ID_L1 && self.chain_id != CHAIN_ID_L2 {
            return Err(format!("Invalid chain_id: {}", self.chain_id));
        }

        // 3. Check nonce replay
        check_nonce(&self.public_key, &self.nonce, self.timestamp)?;

        // 4. Get payload
        let payload = self.payload.as_deref().unwrap_or("{}");

        // 5. Build signed message: chain_id_byte + "{payload}\n{timestamp}\n{nonce}"
        let message = format!("{}\n{}\n{}", payload, self.timestamp, self.nonce);
        let mut signed_bytes = vec![self.chain_id];
        signed_bytes.extend_from_slice(message.as_bytes());

        // 6. Decode public key
        let pubkey_bytes = hex::decode(&self.public_key)
            .map_err(|_| "Invalid public key hex")?;
        
        if pubkey_bytes.len() != 32 {
            return Err(format!("Invalid public key length: {}", pubkey_bytes.len()));
        }

        let verifying_key = VerifyingKey::from_bytes(
            pubkey_bytes.as_slice().try_into().unwrap()
        ).map_err(|e| format!("Invalid public key: {}", e))?;

        // 7. Decode signature
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| "Invalid signature hex")?;
        
        if sig_bytes.len() != 64 {
            return Err(format!("Invalid signature length: {}", sig_bytes.len()));
        }

        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        // 8. Verify signature
        verifying_key
            .verify(&signed_bytes, &signature)
            .map_err(|_| format!("Invalid signature for chain 0x{:02x}", self.chain_id))?;

        // 9. Return wallet address
        let address = self.get_wallet_address();
        let chain = if self.chain_id == CHAIN_ID_L1 { "L1" } else { "L2" };
        println!("🔐 Verified {} sig for {}", chain, &address[..address.len().min(14)]);
        
        Ok(address)
    }

    /// Get wallet address (prefer explicit, fallback to public_key)
    pub fn get_wallet_address(&self) -> String {
        println!("   📍 wallet_address field: {:?}", self.wallet_address);
        self.wallet_address
            .clone()
            .unwrap_or_else(|| self.public_key.clone())
    }

    /// Parse payload as JSON
    pub fn parse_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        let payload = self.payload.as_deref().unwrap_or("{}");
        serde_json::from_str(payload).map_err(|e| format!("Invalid payload: {}", e))
    }
}

// ============================================================================
// WARP FILTERS - Middleware for Route Authentication
// ============================================================================

/// Extract and verify signature, return wallet address
pub fn with_signature_auth() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::body::json::<SignedRequest>().and_then(|req: SignedRequest| async move {
        match req.verify() {
            Ok(addr) => Ok(addr),
            Err(e) => {
                println!("❌ Auth failed: {}", e);
                Err(warp::reject::custom(AuthError(e)))
            }
        }
    })
}

/// Auth rejection type
#[derive(Debug)]
pub struct AuthError(pub String);
impl warp::reject::Reject for AuthError {}

// ============================================================================
// KEY GENERATION UTILITIES
// ============================================================================

/// Generate a new Ed25519 keypair
/// Returns (public_key_hex, private_key_hex)
pub fn generate_keypair() -> (String, String) {
    // Generate 32 random bytes for the seed
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("Failed to generate random bytes");
    generate_keypair_from_seed(&seed)
}

/// Generate keypair from a 32-byte seed (deterministic)
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> (String, String) {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    
    (
        hex::encode(verifying_key.as_bytes()),
        hex::encode(signing_key.to_bytes()),
    )
}

/// Derive L1 wallet address from public key
/// Format: L1_<SHA256(pubkey)[0..20]> (40 hex chars)
pub fn derive_l1_address(public_key: &str) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    
    let pubkey_bytes = hex::decode(public_key)
        .map_err(|_| "Invalid public key hex")?;
    
    // SHA256 and take first 20 bytes (160 bits)
    let hash = Sha256::digest(&pubkey_bytes);
    let addr_bytes = &hash[0..20];
    
    Ok(format!("L1_{}", hex::encode(addr_bytes).to_uppercase()))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pubkey, privkey) = generate_keypair();
        assert_eq!(pubkey.len(), 64);  // 32 bytes = 64 hex
        assert_eq!(privkey.len(), 64); // 32 bytes = 64 hex
    }

    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        let (pub1, priv1) = generate_keypair_from_seed(&seed);
        let (pub2, priv2) = generate_keypair_from_seed(&seed);
        assert_eq!(pub1, pub2);
        assert_eq!(priv1, priv2);
    }

    #[test]
    fn test_address_derivation() {
        let (pubkey, _) = generate_keypair();
        let addr = derive_l1_address(&pubkey).unwrap();
        assert!(addr.starts_with("L1_"));
        assert_eq!(addr.len(), 43); // "L1_" + 40 hex chars
    }
}
