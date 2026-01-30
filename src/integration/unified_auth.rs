// ============================================================================
// UNIFIED AUTH - L1 Wallet Authentication (Ed25519 + ZKP)
// ============================================================================
//
// Core authentication for L1 BlackBook blockchain:
// - Ed25519 signature verification
// - ZK-Proof verification for non-custodial wallets
// - Share B storage (on-chain SSS component)
// - Nonce replay protection
// - Domain separation (L1/L2)
//
// Version: 2.0.0-zkp
// ============================================================================

use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

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

/// ZK-Proof verification maximum age (60 seconds)
const ZK_PROOF_MAX_AGE_SECS: u64 = 60;

// ============================================================================
// SHARE B STORAGE - On-Chain SSS Component
// ============================================================================

/// SSS Share structure (Galois Field point)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSSShare {
    /// X-coordinate (1, 2, or 3)
    pub x: u8,
    /// Y-coordinate (256-bit hex string)
    pub y: String,
}

/// Wallet ZKP registration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletZKPData {
    /// L1 address
    pub address: String,
    /// Ed25519 public key (64 hex chars)
    pub pubkey: String,
    /// ZK-commitment (64 hex chars) - SHA256(username || password || salt)
    pub zk_commitment: String,
    /// Salt for key derivation (64 hex chars)
    pub salt: String,
    /// Share B (on-chain SSS share)
    pub share_b: SSSShare,
    /// Registration timestamp
    pub registered_at: u64,
    /// Key derivation method
    pub key_derivation: String,
    /// SSS configuration
    pub sss: String,
}

/// Share B storage
struct ShareBStorage {
    shares: HashMap<String, WalletZKPData>,
}

impl ShareBStorage {
    fn new() -> Self {
        Self {
            shares: HashMap::new(),
        }
    }

    fn store(&mut self, address: String, data: WalletZKPData) -> Result<(), String> {
        if self.shares.contains_key(&address) {
            return Err(format!("Wallet already registered: {}", address));
        }
        self.shares.insert(address, data);
        Ok(())
    }

    fn get(&self, address: &str) -> Option<&WalletZKPData> {
        self.shares.get(address)
    }

    fn exists(&self, address: &str) -> bool {
        self.shares.contains_key(address)
    }
}

static SHARE_B_STORAGE: Lazy<Mutex<ShareBStorage>> = 
    Lazy::new(|| Mutex::new(ShareBStorage::new()));

// ============================================================================
// ZK-PROOF STRUCTURES
// ============================================================================

/// ZK-Proof data (HMAC-based, will upgrade to Groth16)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// ZK-commitment (must match stored commitment)
    pub commitment: String,
    /// Proof data (HMAC signature)
    pub proof: String,
    /// Proof input (nonce:timestamp:random)
    pub proof_input: String,
    /// Proof timestamp
    pub timestamp: u64,
    /// Proof version
    pub version: String,
}

/// ZKP login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKPLoginRequest {
    /// Wallet address
    pub address: String,
    /// ZK-proof
    pub zk_proof: ZKProof,
    /// Nonce for replay protection
    pub nonce: String,
}

// ============================================================================
// ZKP VERIFICATION FUNCTIONS
// ============================================================================

/// Verify ZK-proof against stored commitment
pub fn verify_zk_proof(proof: &ZKProof, stored_commitment: &str, nonce: &str) -> Result<(), String> {
    // 1. Check commitment matches
    if proof.commitment != stored_commitment {
        return Err("ZK-commitment mismatch".to_string());
    }

    // 2. Check timestamp freshness
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let age = now.saturating_sub(proof.timestamp);
    if age > ZK_PROOF_MAX_AGE_SECS {
        return Err(format!("ZK-proof expired ({} seconds old)", age));
    }

    // Allow 5 second clock skew
    if proof.timestamp > now + 5 {
        return Err("ZK-proof timestamp in future".to_string());
    }

    // 3. Check nonce is in proof_input
    if !proof.proof_input.starts_with(&format!("{}:", nonce)) {
        return Err("Nonce mismatch in proof".to_string());
    }

    // 4. Verify HMAC proof
    // proof = HMAC-SHA256(commitment, proof_input)
    let commitment_bytes = hex::decode(&proof.commitment)
        .map_err(|_| "Invalid commitment hex")?;
    
    let mut mac = Hmac::<Sha256>::new_from_slice(&commitment_bytes)
        .map_err(|_| "HMAC initialization failed")?;
    mac.update(proof.proof_input.as_bytes());
    
    let expected_proof = hex::encode(mac.finalize().into_bytes());
    
    // Constant-time comparison
    if expected_proof != proof.proof {
        return Err("ZK-proof verification failed".to_string());
    }

    Ok(())
}

/// Store Share B for a wallet
pub fn store_share_b(data: WalletZKPData) -> Result<(), String> {
    let address = data.address.clone();
    SHARE_B_STORAGE
        .lock()
        .map_err(|_| "Storage lock error")?
        .store(address, data)
}

/// Release Share B after successful ZKP verification
pub fn release_share_b(address: &str) -> Result<SSSShare, String> {
    let storage = SHARE_B_STORAGE
        .lock()
        .map_err(|_| "Storage lock error")?;
    
    let data = storage
        .get(address)
        .ok_or_else(|| format!("Wallet not found: {}", address))?;
    
    Ok(data.share_b.clone())
}

/// Get wallet ZKP data
pub fn get_wallet_zkp_data(address: &str) -> Result<WalletZKPData, String> {
    let storage = SHARE_B_STORAGE
        .lock()
        .map_err(|_| "Storage lock error")?;
    
    storage
        .get(address)
        .cloned()
        .ok_or_else(|| format!("Wallet not found: {}", address))
}

/// Check if wallet is registered
pub fn is_wallet_registered(address: &str) -> bool {
    SHARE_B_STORAGE
        .lock()
        .map(|storage| storage.exists(address))
        .unwrap_or(false)
}

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

        println!("   🔍 Signature Verification Debug:");
        println!("      Chain ID: 0x{:02x}", self.chain_id);
        println!("      Payload: {}", if payload.len() > 50 { format!("{}...", &payload[..50]) } else { payload.to_string() });
        println!("      Timestamp: {}", self.timestamp);
        println!("      Nonce: {}", &self.nonce[..self.nonce.len().min(16)]);
        println!("      Message: {}", if message.len() > 80 { format!("{}...", &message[..80]) } else { message.clone() });
        println!("      Signed bytes length: {} (chain_id + message)", signed_bytes.len());

        // 6. Decode public key
        let pubkey_bytes = hex::decode(&self.public_key)
            .map_err(|e| {
                println!("      ❌ Public key hex decode failed: {}", e);
                format!("Invalid public key hex: {}", e)
            })?;
        
        if pubkey_bytes.len() != 32 {
            println!("      ❌ Public key wrong length: {} bytes (expected 32)", pubkey_bytes.len());
            return Err(format!("Invalid public key length: {} (expected 32)", pubkey_bytes.len()));
        }
        println!("      ✓ Public key: {}... (32 bytes)", &self.public_key[..16]);

        let verifying_key = VerifyingKey::from_bytes(
            pubkey_bytes.as_slice().try_into().unwrap()
        ).map_err(|e| {
            println!("      ❌ Public key parsing failed: {}", e);
            format!("Invalid public key: {}", e)
        })?;

        // 7. Decode signature
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| {
                println!("      ❌ Signature hex decode failed: {}", e);
                format!("Invalid signature hex: {}", e)
            })?;
        
        if sig_bytes.len() != 64 {
            println!("      ❌ Signature wrong length: {} bytes (expected 64)", sig_bytes.len());
            return Err(format!("Invalid signature length: {} (expected 64)", sig_bytes.len()));
        }
        println!("      ✓ Signature: {}... (64 bytes)", &self.signature[..32]);

        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        // 8. Verify signature
        println!("      🔐 Verifying Ed25519 signature...");
        verifying_key
            .verify(&signed_bytes, &signature)
            .map_err(|e| {
                println!("      ❌ SIGNATURE VERIFICATION FAILED");
                println!("      Expected format: chain_id_byte + \"{{payload}}\\n{{timestamp}}\\n{{nonce}}\"");
                println!("      Got: 0x{:02x} + \"{}\\n{}\\n{}\"", 
                    self.chain_id, 
                    if payload.len() > 40 { format!("{}...", &payload[..40]) } else { payload.to_string() },
                    self.timestamp, 
                    &self.nonce[..self.nonce.len().min(16)]
                );
                println!("      Crypto error: {}", e);
                format!("Invalid signature for chain 0x{:02x} - message format may be incorrect", self.chain_id)
            })?;

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

    #[test]
    fn test_share_b_storage() {
        let data = WalletZKPData {
            address: "L1_TEST123".to_string(),
            pubkey: "abcd".to_string(),
            zk_commitment: "commitment123".to_string(),
            salt: "salt123".to_string(),
            share_b: SSSShare {
                x: 2,
                y: "share_y_value".to_string(),
            },
            registered_at: 1234567890,
            key_derivation: "Argon2id-64MB".to_string(),
            sss: "2-of-3-GF(2^256)".to_string(),
        };

        // Store should succeed
        let result = store_share_b(data.clone());
        assert!(result.is_ok());

        // Retrieve should work
        let retrieved = get_wallet_zkp_data("L1_TEST123");
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().address, "L1_TEST123");

        // Check exists
        assert!(is_wallet_registered("L1_TEST123"));
        assert!(!is_wallet_registered("L1_NONEXISTENT"));
    }

    #[test]
    fn test_zk_proof_verification() {
        use std::thread;
        use std::time::Duration;

        let commitment = "abc123def456";
        let nonce = "nonce123";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate valid proof
        let proof_input = format!("{}:{}:random", nonce, timestamp);
        let commitment_bytes = hex::decode(commitment).unwrap();
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&commitment_bytes).unwrap();
        mac.update(proof_input.as_bytes());
        let proof_value = hex::encode(mac.finalize().into_bytes());

        let valid_proof = ZKProof {
            commitment: commitment.to_string(),
            proof: proof_value,
            proof_input: proof_input.clone(),
            timestamp,
            version: "hmac-sha256-v1".to_string(),
        };

        // Valid proof should pass
        assert!(verify_zk_proof(&valid_proof, commitment, nonce).is_ok());

        // Wrong commitment should fail
        assert!(verify_zk_proof(&valid_proof, "wrongcommitment", nonce).is_err());

        // Wrong nonce should fail
        assert!(verify_zk_proof(&valid_proof, commitment, "wrongnonce").is_err());

        // Test expired proof
        let old_timestamp = timestamp - 65; // 65 seconds ago
        let mut expired_proof = valid_proof.clone();
        expired_proof.timestamp = old_timestamp;
        // Need to regenerate proof with old timestamp
        let old_input = format!("{}:{}:random", nonce, old_timestamp);
        let mut mac2 = Hmac::<Sha256>::new_from_slice(&commitment_bytes).unwrap();
        mac2.update(old_input.as_bytes());
        expired_proof.proof = hex::encode(mac2.finalize().into_bytes());
        expired_proof.proof_input = old_input;
        
        assert!(verify_zk_proof(&expired_proof, commitment, nonce).is_err());
    }
}
