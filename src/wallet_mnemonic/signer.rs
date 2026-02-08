//! # Unified Signer Trait
//!
//! Abstraction layer for wallet signing operations.
//!
//! ## Current Implementation
//!
//! BlackBook L1 MVP uses only Mnemonic (Consumer) wallets.
//! FROST Institutional wallets will be added via hot upgrade in Phase 2.
//!
//! ## Why This Matters
//!
//! The blockchain doesn't care HOW a signature was produced, only that:
//! 1. The signature is valid Ed25519
//! 2. It matches the public key on the account
//!
//! This trait is designed to support both:
//! - Mnemonic: Single-party hash after SSS reconstruction
//! - FROST (Future): Multi-party ceremony with partial signatures

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

/// Errors from signing operations
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Signing failed: {0}")]
    SigningError(String),
    
    #[error("Key reconstruction failed: {0}")]
    KeyError(String),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
}

/// Result of a signing operation
#[derive(Debug, Clone)]
pub struct SigningResult {
    /// The Ed25519 signature
    pub signature: Signature,
    /// The message that was signed
    pub message: Vec<u8>,
    /// The public key that signed
    pub public_key: VerifyingKey,
    /// Whether this used threshold signing (FROST) or direct signing (Mnemonic)
    pub is_threshold: bool,
}

/// Unified signer interface for wallet operations
/// 
/// Current Implementation: MnemonicSigner (Consumer Track)
/// Future (Hot Upgrade Phase 2): FrostSigner (Institutional Track)
#[async_trait]
pub trait WalletSigner: Send + Sync {
    /// Get the wallet's public key
    fn public_key(&self) -> &VerifyingKey;
    
    /// Get the wallet's L1 address
    fn address(&self) -> &str;
    
    /// Check if this is a threshold wallet
    /// Current: Always false (only Mnemonic wallets exist)
    /// Future: Will return true for FROST wallets
    fn is_threshold(&self) -> bool;
    
    /// Sign a message
    /// 
    /// For Mnemonic: Reconstructs the key and signs directly
    /// For FROST (Future): Will initiate a signing ceremony
    async fn sign(&self, message: &[u8]) -> Result<SigningResult, SignerError>;
    
    /// Verify a signature (same for both types)
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool, SignerError> {
        use ed25519_dalek::Verifier;
        Ok(self.public_key().verify(message, signature).is_ok())
    }
}

// ============================================================================
// MNEMONIC SIGNER IMPLEMENTATION
// ============================================================================

use crate::wallet_mnemonic::mnemonic::{recover_wallet, SecurePrivateKey, MnemonicError};
use crate::wallet_mnemonic::sss::{
    SecureShare, reconstruct_from_ab, reconstruct_from_ac, SSSError,
};
use crate::wallet_mnemonic::mnemonic::entropy_to_mnemonic;

/// Signer for mnemonic-based (Consumer) wallets
pub struct MnemonicSigner {
    /// The wallet address
    address: String,
    /// Public key
    public_key: VerifyingKey,
    /// Bound Share A (client holds)
    share_a_bound: SecureShare,
    /// Share B (from L1) OR None if using A+C
    share_b: Option<SecureShare>,
    /// Encrypted Share C OR None if using A+B
    share_c_encrypted: Option<Vec<u8>>,
    /// Password for unbinding Share A
    password: String,
    /// Salt for password derivation
    password_salt: Vec<u8>,
    /// Vault pepper (for Share C decryption)
    pepper: Option<Vec<u8>>,
    /// BIP-39 passphrase (usually empty)
    bip39_passphrase: String,
}

impl MnemonicSigner {
    /// Create signer with Share A + B (normal operation)
    pub fn with_shares_ab(
        address: String,
        public_key: VerifyingKey,
        share_a_bound: SecureShare,
        share_b: SecureShare,
        password: String,
        password_salt: Vec<u8>,
        bip39_passphrase: String,
    ) -> Self {
        Self {
            address,
            public_key,
            share_a_bound,
            share_b: Some(share_b),
            share_c_encrypted: None,
            password,
            password_salt,
            pepper: None,
            bip39_passphrase,
        }
    }
    
    /// Create signer with Share A + C (emergency recovery)
    pub fn with_shares_ac(
        address: String,
        public_key: VerifyingKey,
        share_a_bound: SecureShare,
        share_c_encrypted: Vec<u8>,
        password: String,
        password_salt: Vec<u8>,
        pepper: Vec<u8>,
        bip39_passphrase: String,
    ) -> Self {
        Self {
            address,
            public_key,
            share_a_bound,
            share_b: None,
            share_c_encrypted: Some(share_c_encrypted),
            password,
            password_salt,
            pepper: Some(pepper),
            bip39_passphrase,
        }
    }
    
    /// Reconstruct the private key (SENSITIVE - zeroize after use!)
    fn reconstruct_key(&self) -> Result<SecurePrivateKey, SignerError> {
        // Reconstruct entropy from shares
        let entropy = if let Some(ref share_b) = self.share_b {
            reconstruct_from_ab(
                &self.share_a_bound,
                share_b,
                &self.password,
                &self.password_salt,
            ).map_err(|e| SignerError::KeyError(e.to_string()))?
        } else if let (Some(ref share_c), Some(ref pepper)) = (&self.share_c_encrypted, &self.pepper) {
            reconstruct_from_ac(
                &self.share_a_bound,
                share_c,
                &self.password,
                &self.password_salt,
                pepper,
            ).map_err(|e| SignerError::KeyError(e.to_string()))?
        } else {
            return Err(SignerError::KeyError("No valid share combination".to_string()));
        };
        
        // Convert entropy to mnemonic
        let mnemonic = entropy_to_mnemonic(&entropy)
            .map_err(|e| SignerError::KeyError(e.to_string()))?;
        
        // Recover wallet (derive key) and clone the private key before drop
        let wallet = recover_wallet(&mnemonic, &self.bip39_passphrase)
            .map_err(|e| SignerError::KeyError(e.to_string()))?;
        
        // Clone the private key bytes before WalletKeys is dropped
        Ok(SecurePrivateKey::new(*wallet.private_key.as_bytes()))
    }
}

#[async_trait]
impl WalletSigner for MnemonicSigner {
    fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
    
    fn address(&self) -> &str {
        &self.address
    }
    
    fn is_threshold(&self) -> bool {
        false
    }
    
    async fn sign(&self, message: &[u8]) -> Result<SigningResult, SignerError> {
        use ed25519_dalek::Signer;
        
        // Reconstruct the private key
        let private_key = self.reconstruct_key()?;
        
        // Create signing key
        let signing_key = private_key.to_signing_key();
        
        // Sign the message
        let signature = signing_key.sign(message);
        
        // Private key is zeroized when dropped (SecurePrivateKey implements ZeroizeOnDrop)
        
        Ok(SigningResult {
            signature,
            message: message.to_vec(),
            public_key: self.public_key.clone(),
            is_threshold: false,
        })
    }
}

// ============================================================================
// SIGNER FACTORY
// ============================================================================

use crate::wallet_mnemonic::{WalletSecurityMode, WalletMetadata};

/// Create the appropriate signer based on wallet metadata
pub fn create_signer_for_wallet(
    metadata: &WalletMetadata,
    // Additional data needed for signing...
    password: Option<&str>,
    share_a: Option<&SecureShare>,
    share_b: Option<&SecureShare>,
    share_c_encrypted: Option<&[u8]>,
    password_salt: Option<&[u8]>,
    pepper: Option<&[u8]>,
) -> Result<Box<dyn WalletSigner>, SignerError> {
    match &metadata.security_mode {
        WalletSecurityMode::Deterministic(config) => {
            // Need password and shares
            let password = password.ok_or_else(|| 
                SignerError::AuthError("Password required for mnemonic wallet".to_string()))?;
            let share_a = share_a.ok_or_else(||
                SignerError::KeyError("Share A required".to_string()))?;
            let salt = password_salt.ok_or_else(||
                SignerError::KeyError("Password salt required".to_string()))?;
            
            // Parse public key
            let pk_bytes = hex::decode(&metadata.public_key)
                .map_err(|e| SignerError::KeyError(e.to_string()))?;
            let pk_array: [u8; 32] = pk_bytes.try_into()
                .map_err(|_| SignerError::KeyError("Invalid public key length".to_string()))?;
            let public_key = VerifyingKey::from_bytes(&pk_array)
                .map_err(|e| SignerError::KeyError(e.to_string()))?;
            
            // Create signer with available shares
            if let Some(sb) = share_b {
                Ok(Box::new(MnemonicSigner::with_shares_ab(
                    metadata.address.clone(),
                    public_key,
                    share_a.clone(),
                    sb.clone(),
                    password.to_string(),
                    salt.to_vec(),
                    String::new(), // BIP-39 passphrase
                )))
            } else if let (Some(sc), Some(p)) = (share_c_encrypted, pepper) {
                Ok(Box::new(MnemonicSigner::with_shares_ac(
                    metadata.address.clone(),
                    public_key,
                    share_a.clone(),
                    sc.to_vec(),
                    password.to_string(),
                    salt.to_vec(),
                    p.to_vec(),
                    String::new(),
                )))
            } else {
                Err(SignerError::KeyError(
                    "Need either Share B or (Share C + pepper)".to_string()
                ))
            }
        }
    }
}
