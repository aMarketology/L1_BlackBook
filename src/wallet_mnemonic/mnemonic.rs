//! # BIP-39 Mnemonic Generation
//!
//! 24-word mnemonic generation and key derivation for the Consumer Track.
//!
//! ## Security Properties
//! - 256-bit entropy (24 words)
//! - SLIP-10 Ed25519 derivation (compatible with Solana/Phantom)
//! - Secure memory wiping via `zeroize`

use bip39::{Language, Mnemonic};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Errors that can occur during mnemonic operations
#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),
    
    #[error("Entropy generation failed: {0}")]
    EntropyError(String),
    
    #[error("Key derivation failed: {0}")]
    DerivationError(String),
    
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
}

// ============================================================================
// SECURE TYPES (Auto-zeroize on drop)
// ============================================================================

/// 256-bit entropy that auto-wipes from memory
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureEntropy([u8; 32]);

impl SecureEntropy {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Seed derived from mnemonic (auto-wipes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; 64]);

impl SecureSeed {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Private key that auto-wipes from memory
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecurePrivateKey([u8; 32]);

impl SecurePrivateKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Create Ed25519 signing key (CAUTION: key exists in memory)
    pub fn to_signing_key(&self) -> SigningKey {
        // ed25519-dalek 2.0: from_bytes is infallible for 32-byte arrays
        SigningKey::from_bytes(&self.0)
    }
}

// ============================================================================
// MNEMONIC GENERATION
// ============================================================================

/// Generate cryptographically secure 256-bit entropy
pub fn generate_entropy() -> Result<SecureEntropy, MnemonicError> {
    use rand_core::{OsRng, RngCore};
    
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    
    // Verify we got actual randomness (not all zeros)
    if entropy.iter().all(|&b| b == 0) {
        return Err(MnemonicError::EntropyError(
            "RNG produced all zeros - system entropy may be compromised".to_string()
        ));
    }
    
    Ok(SecureEntropy::new(entropy))
}

/// Convert 256-bit entropy to 24-word BIP-39 mnemonic
pub fn entropy_to_mnemonic(entropy: &SecureEntropy) -> Result<String, MnemonicError> {
    let mnemonic = Mnemonic::from_entropy(entropy.as_bytes())
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;
    
    Ok(mnemonic.word_iter().collect::<Vec<_>>().join(" "))
}

/// Convert 24-word mnemonic back to entropy
pub fn mnemonic_to_entropy(phrase: &str) -> Result<SecureEntropy, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;
    
    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        return Err(MnemonicError::InvalidMnemonic(
            format!("Expected 32 bytes, got {}", entropy.len())
        ));
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&entropy);
    Ok(SecureEntropy::new(bytes))
}

/// Validate a mnemonic phrase without revealing it
pub fn validate_mnemonic(phrase: &str) -> bool {
    Mnemonic::parse_in(Language::English, phrase).is_ok()
}

/// Get the word count (should be 24 for our system)
pub fn word_count(phrase: &str) -> usize {
    phrase.split_whitespace().count()
}

// ============================================================================
// KEY DERIVATION (SLIP-10 Ed25519)
// ============================================================================

/// Derive seed from mnemonic using BIP-39 standard
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<SecureSeed, MnemonicError> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| MnemonicError::InvalidMnemonic(e.to_string()))?;
    
    let seed = mnemonic.to_seed(passphrase);
    Ok(SecureSeed::new(seed))
}

/// Derive Ed25519 private key using SLIP-10 hardened derivation
/// 
/// Path format: m/44'/501'/0'/0' (Solana-compatible)
pub fn derive_key_slip10(
    seed: &SecureSeed,
    path: &str,
) -> Result<(SecurePrivateKey, VerifyingKey), MnemonicError> {
    // Parse path components
    let components = parse_derivation_path(path)?;
    
    // SLIP-10 master key derivation
    let mut hmac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
        .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;
    hmac.update(seed.as_bytes());
    let result = hmac.finalize().into_bytes();
    
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    
    // Derive through path (SLIP-10 hardened only)
    for index in components {
        let mut hmac = Hmac::<Sha512>::new_from_slice(&chain_code)
            .map_err(|e| MnemonicError::DerivationError(e.to_string()))?;
        hmac.update(&[0x00]); // Ed25519 marker
        hmac.update(&key);
        hmac.update(&index.to_be_bytes());
        let result = hmac.finalize().into_bytes();
        
        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }
    
    // Create signing key and derive public key
    let private_key = SecurePrivateKey::new(key);
    let signing_key = private_key.to_signing_key();
    let verifying_key = signing_key.verifying_key();
    
    // Zeroize intermediate values
    key.zeroize();
    chain_code.zeroize();
    
    Ok((private_key, verifying_key))
}

/// Parse BIP-44 style derivation path
fn parse_derivation_path(path: &str) -> Result<Vec<u32>, MnemonicError> {
    let path = path.trim();
    if !path.starts_with("m/") {
        return Err(MnemonicError::InvalidPath(
            "Path must start with 'm/'".to_string()
        ));
    }
    
    let mut components = Vec::new();
    for part in path[2..].split('/') {
        if part.is_empty() {
            continue;
        }
        
        let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
            (&part[..part.len()-1], true)
        } else {
            (part, false)
        };
        
        let num: u32 = num_str.parse()
            .map_err(|_| MnemonicError::InvalidPath(format!("Invalid path component: {}", part)))?;
        
        // SLIP-10 Ed25519 requires all hardened
        if !hardened {
            return Err(MnemonicError::InvalidPath(
                "SLIP-10 Ed25519 requires hardened derivation (use ' suffix)".to_string()
            ));
        }
        
        // Add hardened offset (0x80000000)
        components.push(num | 0x80000000);
    }
    
    Ok(components)
}

// ============================================================================
// HIGH-LEVEL API
// ============================================================================

/// Result of wallet generation
pub struct WalletKeys {
    /// The 24-word mnemonic (SENSITIVE - wipe after use!)
    pub mnemonic: String,
    /// Derived private key (SENSITIVE - wipe after use!)
    pub private_key: SecurePrivateKey,
    /// Public key (safe to store)
    pub public_key: VerifyingKey,
    /// L1 wallet address
    pub address: String,
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        // Zeroize mnemonic string
        unsafe {
            let bytes = self.mnemonic.as_bytes_mut();
            for byte in bytes {
                *byte = 0;
            }
        }
    }
}

/// Generate a complete wallet from scratch
/// 
/// WARNING: The returned mnemonic should be split via SSS immediately
/// and then zeroized. Never store the full mnemonic!
pub fn generate_wallet(passphrase: &str) -> Result<WalletKeys, MnemonicError> {
    // Generate entropy
    let entropy = generate_entropy()?;
    
    // Convert to mnemonic
    let mnemonic = entropy_to_mnemonic(&entropy)?;
    
    // Derive seed
    let seed = mnemonic_to_seed(&mnemonic, passphrase)?;
    
    // Derive keys using Solana-compatible path
    let path = "m/44'/501'/0'/0'";
    let (private_key, public_key) = derive_key_slip10(&seed, path)?;
    
    // Generate L1 address from public key
    let pk_bytes = public_key.to_bytes();
    let address = format!("bb_{}", hex::encode(&pk_bytes[..16]));
    
    Ok(WalletKeys {
        mnemonic,
        private_key,
        public_key,
        address,
    })
}

/// Recover wallet from mnemonic phrase
pub fn recover_wallet(phrase: &str, passphrase: &str) -> Result<WalletKeys, MnemonicError> {
    // Validate mnemonic
    if !validate_mnemonic(phrase) {
        return Err(MnemonicError::InvalidMnemonic("Invalid phrase".to_string()));
    }
    
    // Derive seed
    let seed = mnemonic_to_seed(phrase, passphrase)?;
    
    // Derive keys
    let path = "m/44'/501'/0'/0'";
    let (private_key, public_key) = derive_key_slip10(&seed, path)?;
    
    // Generate address
    let pk_bytes = public_key.to_bytes();
    let address = format!("bb_{}", hex::encode(&pk_bytes[..16]));
    
    Ok(WalletKeys {
        mnemonic: phrase.to_string(),
        private_key,
        public_key,
        address,
    })
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy_generation() {
        let entropy = generate_entropy().unwrap();
        assert_eq!(entropy.as_bytes().len(), 32);
        
        // Should not be all zeros
        assert!(!entropy.as_bytes().iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_entropy_to_mnemonic() {
        let entropy = generate_entropy().unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        
        // Should be 24 words
        assert_eq!(word_count(&mnemonic), 24);
    }
    
    #[test]
    fn test_mnemonic_roundtrip() {
        let entropy = generate_entropy().unwrap();
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let recovered = mnemonic_to_entropy(&mnemonic).unwrap();
        
        assert_eq!(entropy.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    fn test_wallet_generation() {
        let wallet = generate_wallet("").unwrap();
        
        // Address should start with bb_
        assert!(wallet.address.starts_with("bb_"));
        
        // Mnemonic should be 24 words
        assert_eq!(word_count(&wallet.mnemonic), 24);
    }
    
    #[test]
    fn test_wallet_recovery_same_address() {
        let wallet1 = generate_wallet("test_pass").unwrap();
        let wallet2 = recover_wallet(&wallet1.mnemonic, "test_pass").unwrap();
        
        // Same mnemonic + passphrase = same address
        assert_eq!(wallet1.address, wallet2.address);
    }
    
    #[test]
    fn test_different_passphrase_different_address() {
        let wallet1 = generate_wallet("pass1").unwrap();
        let wallet2 = recover_wallet(&wallet1.mnemonic, "pass2").unwrap();
        
        // Different passphrase = different address
        assert_ne!(wallet1.address, wallet2.address);
    }
}
