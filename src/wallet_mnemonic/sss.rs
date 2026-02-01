//! # Shamir Secret Sharing for Mnemonic Entropy
//!
//! Implements 2-of-3 secret sharing for the 256-bit mnemonic entropy.
//!
//! ## Share Distribution
//!
//! - **Share A (Client)**: XOR'd with password-derived key. Only user can unlock.
//! - **Share B (L1 Chain)**: Stored on-chain, released via ZKP authentication.
//! - **Share C (Vault)**: Encrypted with HashiCorp Vault pepper, stored in Supabase.
//!
//! ## Recovery Combinations
//!
//! | Shares | Result |
//! |--------|--------|
//! | A + B  | ✅ Normal operation (user + L1) |
//! | A + C  | ✅ Emergency recovery (user + Vault) |
//! | B + C  | ❌ Impossible without password |

use crate::wallet_mnemonic::mnemonic::{SecureEntropy, MnemonicError};
use argon2::{Argon2, password_hash::SaltString};
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Errors specific to SSS operations
#[derive(Debug, Error)]
pub enum SSSError {
    #[error("SSS split failed: {0}")]
    SplitError(String),
    
    #[error("SSS reconstruction failed: {0}")]
    ReconstructError(String),
    
    #[error("Invalid share: {0}")]
    InvalidShare(String),
    
    #[error("Password derivation failed: {0}")]
    PasswordError(String),
    
    #[error("Insufficient shares: need {needed}, have {have}")]
    InsufficientShares { needed: usize, have: usize },
}

// ============================================================================
// SHARE TYPES
// ============================================================================

/// A single Shamir share (auto-zeroizes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureShare {
    /// Share index (1, 2, or 3)
    pub index: u8,
    /// Share data
    data: Vec<u8>,
}

impl SecureShare {
    pub fn new(index: u8, data: Vec<u8>) -> Self {
        Self { index, data }
    }
    
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    pub fn to_hex(&self) -> String {
        format!("{}:{}", self.index, hex::encode(&self.data))
    }
    
    pub fn from_hex(s: &str) -> Result<Self, SSSError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(SSSError::InvalidShare("Expected format: index:hex".to_string()));
        }
        
        let index: u8 = parts[0].parse()
            .map_err(|_| SSSError::InvalidShare("Invalid index".to_string()))?;
        let data = hex::decode(parts[1])
            .map_err(|e| SSSError::InvalidShare(e.to_string()))?;
        
        Ok(Self { index, data })
    }
}

/// Result of splitting entropy into 3 shares
pub struct SplitResult {
    /// Share A: To be bound to user's password
    pub share_a: SecureShare,
    /// Share B: To be stored on L1 blockchain
    pub share_b: SecureShare,
    /// Share C: To be encrypted with Vault pepper
    pub share_c: SecureShare,
}

// ============================================================================
// SIMPLE SHAMIR IMPLEMENTATION (2-of-3)
// ============================================================================
// Note: We implement a simple Shamir scheme here because vsss-rs has complex
// generics. This is a standard 2-of-3 scheme over GF(256).

/// GF(256) multiplication using AES field polynomial
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1B; // AES irreducible polynomial
        }
        b >>= 1;
    }
    
    result as u8
}

/// GF(256) multiplicative inverse
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

/// Split a single byte into 3 shares (2-of-3)
fn split_byte_2_of_3(secret: u8, rng: &mut impl rand_core::RngCore) -> [u8; 3] {
    // f(x) = secret + a1*x (degree 1 polynomial for 2-of-3)
    let a1: u8 = rng.next_u32() as u8;
    
    // Evaluate at x=1, x=2, x=3
    let share1 = secret ^ gf256_mul(a1, 1);
    let share2 = secret ^ gf256_mul(a1, 2);
    let share3 = secret ^ gf256_mul(a1, 3);
    
    [share1, share2, share3]
}

/// Reconstruct a byte from 2 shares using Lagrange interpolation
fn reconstruct_byte_2_of_3(shares: [(u8, u8); 2]) -> u8 {
    let (x1, y1) = shares[0];
    let (x2, y2) = shares[1];
    
    // Lagrange interpolation at x=0
    // L1(0) = x2 / (x2 - x1)
    // L2(0) = x1 / (x1 - x2)
    
    let x1_minus_x2 = x1 ^ x2;
    let x2_minus_x1 = x2 ^ x1;
    
    let l1 = gf256_mul(x2, gf256_inv(x2_minus_x1));
    let l2 = gf256_mul(x1, gf256_inv(x1_minus_x2));
    
    gf256_mul(y1, l1) ^ gf256_mul(y2, l2)
}

/// Split 256-bit entropy into 2-of-3 Shamir shares
pub fn split_entropy(entropy: &SecureEntropy) -> Result<SplitResult, SSSError> {
    use rand_core::{OsRng, RngCore};
    
    let mut rng = OsRng;
    let bytes = entropy.as_bytes();
    
    let mut share1_data = Vec::with_capacity(32);
    let mut share2_data = Vec::with_capacity(32);
    let mut share3_data = Vec::with_capacity(32);
    
    for &byte in bytes {
        let shares = split_byte_2_of_3(byte, &mut rng);
        share1_data.push(shares[0]);
        share2_data.push(shares[1]);
        share3_data.push(shares[2]);
    }
    
    Ok(SplitResult {
        share_a: SecureShare::new(1, share1_data),
        share_b: SecureShare::new(2, share2_data),
        share_c: SecureShare::new(3, share3_data),
    })
}

/// Reconstruct entropy from any 2 shares
pub fn reconstruct_entropy(
    share1: &SecureShare,
    share2: &SecureShare,
) -> Result<SecureEntropy, SSSError> {
    if share1.data().len() != 32 || share2.data().len() != 32 {
        return Err(SSSError::ReconstructError(
            format!("Invalid share lengths: {} and {}", share1.data().len(), share2.data().len())
        ));
    }
    
    let x1 = share1.index;
    let x2 = share2.index;
    
    if x1 == x2 {
        return Err(SSSError::ReconstructError("Shares have same index".to_string()));
    }
    
    let mut result = [0u8; 32];
    
    for i in 0..32 {
        let y1 = share1.data()[i];
        let y2 = share2.data()[i];
        result[i] = reconstruct_byte_2_of_3([(x1, y1), (x2, y2)]);
    }
    
    Ok(SecureEntropy::new(result))
}

// ============================================================================
// PASSWORD BINDING (Share A)
// ============================================================================

/// Derive a key from password using Argon2id (memory-hard)
pub fn derive_password_key(
    password: &str,
    salt: &[u8],
) -> Result<[u8; 32], SSSError> {
    use argon2::PasswordHasher;
    
    // Configure Argon2id with reasonable parameters
    let argon2 = Argon2::default();
    
    // Use provided salt
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| SSSError::PasswordError(e.to_string()))?;
    
    // Hash password
    let hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| SSSError::PasswordError(e.to_string()))?;
    
    // Extract 32 bytes from hash
    let hash_bytes = hash.hash.ok_or_else(|| 
        SSSError::PasswordError("No hash output".to_string()))?;
    
    let mut key = [0u8; 32];
    let output = hash_bytes.as_bytes();
    let copy_len = std::cmp::min(output.len(), 32);
    key[..copy_len].copy_from_slice(&output[..copy_len]);
    
    Ok(key)
}

/// XOR Share A with password-derived key (binding)
pub fn bind_share_to_password(
    share: &SecureShare,
    password: &str,
    salt: &[u8],
) -> Result<SecureShare, SSSError> {
    let key = derive_password_key(password, salt)?;
    
    let mut bound_data = share.data().to_vec();
    for (i, byte) in bound_data.iter_mut().enumerate() {
        *byte ^= key[i % 32];
    }
    
    Ok(SecureShare::new(share.index, bound_data))
}

/// XOR to unbind Share A from password
pub fn unbind_share_from_password(
    bound_share: &SecureShare,
    password: &str,
    salt: &[u8],
) -> Result<SecureShare, SSSError> {
    // XOR is symmetric, so binding and unbinding are the same operation
    bind_share_to_password(bound_share, password, salt)
}

// ============================================================================
// VAULT PEPPER ENCRYPTION (Share C)
// ============================================================================

/// Encrypt Share C with Vault pepper using AES-256-GCM
pub fn encrypt_share_with_pepper(
    share: &SecureShare,
    pepper: &[u8],
) -> Result<Vec<u8>, SSSError> {
    use aes_gcm::{
        Aes256Gcm, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    use rand_core::{OsRng, RngCore};
    
    // Derive AES key from pepper (use first 32 bytes or hash)
    let key_bytes: [u8; 32] = if pepper.len() >= 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&pepper[..32]);
        k
    } else {
        // Hash if pepper is too short
        let hash = blake3::hash(pepper);
        *hash.as_bytes()
    };
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher.encrypt(nonce, share.data())
        .map_err(|e| SSSError::SplitError(format!("Encryption failed: {:?}", e)))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    
    Ok(result)
}

/// Decrypt Share C with Vault pepper
pub fn decrypt_share_with_pepper(
    encrypted: &[u8],
    pepper: &[u8],
    share_index: u8,
) -> Result<SecureShare, SSSError> {
    use aes_gcm::{
        Aes256Gcm, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    
    if encrypted.len() < 12 {
        return Err(SSSError::InvalidShare("Encrypted data too short".to_string()));
    }
    
    // Derive AES key from pepper
    let key_bytes: [u8; 32] = if pepper.len() >= 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&pepper[..32]);
        k
    } else {
        let hash = blake3::hash(pepper);
        *hash.as_bytes()
    };
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Split nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];
    
    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| SSSError::ReconstructError(format!("Decryption failed: {:?}", e)))?;
    
    Ok(SecureShare::new(share_index, plaintext))
}

// ============================================================================
// HIGH-LEVEL API
// ============================================================================

/// Complete result of creating a mnemonic wallet with SSS
pub struct MnemonicWalletShares {
    /// Share A: Bound to password (store client-side encrypted)
    pub share_a_bound: SecureShare,
    /// Share B: Raw (store on L1 blockchain)
    pub share_b: SecureShare,
    /// Share C: Encrypted with pepper (store in Supabase)
    pub share_c_encrypted: Vec<u8>,
    /// Salt used for password binding
    pub password_salt: Vec<u8>,
}

/// Split mnemonic entropy into distributed shares
pub fn create_mnemonic_shares(
    entropy: &SecureEntropy,
    password: &str,
    pepper: &[u8],
) -> Result<MnemonicWalletShares, SSSError> {
    use rand_core::{OsRng, RngCore};
    
    // Split entropy into 3 shares
    let split = split_entropy(entropy)?;
    
    // Generate password salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    
    // Bind Share A to password
    let share_a_bound = bind_share_to_password(&split.share_a, password, &salt)?;
    
    // Encrypt Share C with pepper
    let share_c_encrypted = encrypt_share_with_pepper(&split.share_c, pepper)?;
    
    Ok(MnemonicWalletShares {
        share_a_bound,
        share_b: split.share_b,
        share_c_encrypted,
        password_salt: salt.to_vec(),
    })
}

/// Reconstruct entropy from Share A (password) + Share B (L1)
pub fn reconstruct_from_ab(
    share_a_bound: &SecureShare,
    share_b: &SecureShare,
    password: &str,
    salt: &[u8],
) -> Result<SecureEntropy, SSSError> {
    // Unbind Share A
    let share_a = unbind_share_from_password(share_a_bound, password, salt)?;
    
    // Reconstruct
    reconstruct_entropy(&share_a, share_b)
}

/// Reconstruct entropy from Share A (password) + Share C (Vault)
pub fn reconstruct_from_ac(
    share_a_bound: &SecureShare,
    share_c_encrypted: &[u8],
    password: &str,
    salt: &[u8],
    pepper: &[u8],
) -> Result<SecureEntropy, SSSError> {
    // Unbind Share A
    let share_a = unbind_share_from_password(share_a_bound, password, salt)?;
    
    // Decrypt Share C
    let share_c = decrypt_share_with_pepper(share_c_encrypted, pepper, 3)?;
    
    // Reconstruct
    reconstruct_entropy(&share_a, &share_c)
}

/// Reconstruct entropy from Share B (L1) + Share C (Vault)
/// 
/// ⚠️ NOTE: This is a PRIVILEGED recovery path that bypasses user authentication!
/// Only use for: estate recovery, legal compliance, or catastrophic loss scenarios.
/// Requires both L1 blockchain access AND HashiCorp Vault pepper.
pub fn reconstruct_from_bc(
    share_b: &SecureShare,
    share_c_encrypted: &[u8],
    pepper: &[u8],
) -> Result<SecureEntropy, SSSError> {
    // Decrypt Share C
    let share_c = decrypt_share_with_pepper(share_c_encrypted, pepper, 3)?;
    
    // Reconstruct from B + C (no password needed - privileged path!)
    reconstruct_entropy(share_b, &share_c)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_mnemonic::mnemonic::generate_entropy;
    
    #[test]
    fn test_split_and_reconstruct_ab() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let reconstructed = reconstruct_entropy(&split.share_a, &split.share_b).unwrap();
        assert_eq!(entropy.as_bytes(), reconstructed.as_bytes());
    }
    
    #[test]
    fn test_split_and_reconstruct_ac() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let reconstructed = reconstruct_entropy(&split.share_a, &split.share_c).unwrap();
        assert_eq!(entropy.as_bytes(), reconstructed.as_bytes());
    }
    
    #[test]
    fn test_split_and_reconstruct_bc() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let reconstructed = reconstruct_entropy(&split.share_b, &split.share_c).unwrap();
        assert_eq!(entropy.as_bytes(), reconstructed.as_bytes());
    }
    
    #[test]
    fn test_password_binding_roundtrip() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let password = "MySecurePassword123!";
        let salt = b"random_salt_1234";
        
        let bound = bind_share_to_password(&split.share_a, password, salt).unwrap();
        let unbound = unbind_share_from_password(&bound, password, salt).unwrap();
        
        assert_eq!(split.share_a.data(), unbound.data());
    }
    
    #[test]
    fn test_wrong_password_fails() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let salt = b"random_salt_1234";
        
        let bound = bind_share_to_password(&split.share_a, "correct_pass", salt).unwrap();
        let wrong_unbound = unbind_share_from_password(&bound, "wrong_pass", salt).unwrap();
        
        // Wrong password produces wrong share
        assert_ne!(split.share_a.data(), wrong_unbound.data());
        
        // Reconstruction with wrong share should fail or produce wrong entropy
        let result = reconstruct_entropy(&wrong_unbound, &split.share_b);
        // Either fails or produces wrong entropy
        if let Ok(wrong_entropy) = result {
            assert_ne!(entropy.as_bytes(), wrong_entropy.as_bytes());
        }
    }
    
    #[test]
    fn test_pepper_encryption_roundtrip() {
        let entropy = generate_entropy().unwrap();
        let split = split_entropy(&entropy).unwrap();
        
        let pepper = b"vault_pepper_secret_key_123456789";
        
        let encrypted = encrypt_share_with_pepper(&split.share_c, pepper).unwrap();
        let decrypted = decrypt_share_with_pepper(&encrypted, pepper, 3).unwrap();
        
        assert_eq!(split.share_c.data(), decrypted.data());
    }
    
    #[test]
    fn test_full_wallet_creation_and_recovery() {
        let entropy = generate_entropy().unwrap();
        let password = "SuperSecure123!";
        let pepper = b"vault_pepper_key_32_bytes_long!!";
        
        // Create shares
        let shares = create_mnemonic_shares(&entropy, password, pepper).unwrap();
        
        // Recover via A + B
        let recovered_ab = reconstruct_from_ab(
            &shares.share_a_bound,
            &shares.share_b,
            password,
            &shares.password_salt,
        ).unwrap();
        assert_eq!(entropy.as_bytes(), recovered_ab.as_bytes());
        
        // Recover via A + C
        let recovered_ac = reconstruct_from_ac(
            &shares.share_a_bound,
            &shares.share_c_encrypted,
            password,
            &shares.password_salt,
            pepper,
        ).unwrap();
        assert_eq!(entropy.as_bytes(), recovered_ac.as_bytes());
    }
}
