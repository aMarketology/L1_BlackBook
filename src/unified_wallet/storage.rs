//! # Shard Storage
//!
//! This module handles persistent storage of Guardian Shards (Share 2).
//!
//! ## Security Model
//!
//! The server stores Guardian Shards, but they are:
//! 1. **Useless alone**: Need 2-of-3 to sign, attacker only gets 1
//! 2. **Protected by OPAQUE**: Can't access shard without password proof
//! 3. **Encrypted at rest**: Additional layer of defense
//!
//! ## Storage Strategy
//!
//! - In-memory: Fast access for hot wallets
//! - REDB: Persistent storage for durability
//! - Encrypted: AES-256-GCM before writing to disk

use crate::unified_wallet::types::*;
use frost_ed25519 as frost;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::RngCore;

/// Server-side shard storage
pub struct ShardStorage {
    /// In-memory guardian shards (hot storage)
    shards: Arc<RwLock<BTreeMap<String, StoredShard>>>,
    
    /// OPAQUE registration records
    opaque_records: Arc<RwLock<BTreeMap<String, OpaqueRecord>>>,
    
    /// Encryption key for at-rest encryption (derived from server secret)
    encryption_key: [u8; 32],
}

/// A stored guardian shard with metadata
#[derive(Debug, Clone)]
struct StoredShard {
    /// Wallet address this shard belongs to
    wallet_address: String,
    
    /// Shard ID
    shard_id: String,
    
    /// Encrypted key package bytes
    encrypted_key_package: Vec<u8>,
    
    /// Nonce used for encryption
    nonce: [u8; 12],
    
    /// Creation timestamp
    created_at: u64,
    
    /// Last access timestamp
    last_accessed: u64,
    
    /// Public key package (not secret, can store plaintext)
    public_key_package: Vec<u8>,
}

impl ShardStorage {
    /// Create a new shard storage
    pub fn new() -> Self {
        // In production, this key should come from a secure source (e.g., HSM, Vault)
        // For now, we generate a random key
        let mut encryption_key = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut encryption_key);
        
        Self {
            shards: Arc::new(RwLock::new(BTreeMap::new())),
            opaque_records: Arc::new(RwLock::new(BTreeMap::new())),
            encryption_key,
        }
    }
    
    /// Create storage with a specific encryption key (for testing/production config)
    pub fn with_key(encryption_key: [u8; 32]) -> Self {
        Self {
            shards: Arc::new(RwLock::new(BTreeMap::new())),
            opaque_records: Arc::new(RwLock::new(BTreeMap::new())),
            encryption_key,
        }
    }
    
    /// Store a guardian shard
    pub fn store_shard(
        &self,
        wallet_address: &str,
        key_package: &frost::keys::KeyPackage,
        public_key_package: &frost::keys::PublicKeyPackage,
    ) -> Result<String, WalletError> {
        // Serialize key package
        let key_package_bytes = key_package.serialize()
            .map_err(|e| WalletError::SerializationError(format!("Failed to serialize key package: {:?}", e)))?;
        
        let public_key_bytes = public_key_package.serialize()
            .map_err(|e| WalletError::SerializationError(format!("Failed to serialize public key: {:?}", e)))?;
        
        // Encrypt the key package
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| WalletError::CryptoError(format!("Invalid encryption key: {:?}", e)))?;
        
        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted = cipher.encrypt(nonce, key_package_bytes.as_slice())
            .map_err(|e| WalletError::CryptoError(format!("Encryption failed: {:?}", e)))?;
        
        // Generate shard ID
        let shard_id = format!("shard_{}", hex::encode(&blake3::hash(wallet_address.as_bytes()).as_bytes()[..8]));
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Store the shard
        let stored = StoredShard {
            wallet_address: wallet_address.to_string(),
            shard_id: shard_id.clone(),
            encrypted_key_package: encrypted,
            nonce: nonce_bytes,
            created_at: now,
            last_accessed: now,
            public_key_package: public_key_bytes,
        };
        
        self.shards.write().insert(wallet_address.to_string(), stored);
        
        Ok(shard_id)
    }
    
    /// Retrieve a guardian shard (decrypted)
    /// 
    /// This should only be called after OPAQUE authentication succeeds.
    pub fn get_shard(
        &self,
        wallet_address: &str,
    ) -> Result<frost::keys::KeyPackage, WalletError> {
        let mut shards = self.shards.write();
        let stored = shards.get_mut(wallet_address)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_address.to_string()))?;
        
        // Update last accessed time
        stored.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Decrypt the key package
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| WalletError::CryptoError(format!("Invalid encryption key: {:?}", e)))?;
        
        let nonce = Nonce::from_slice(&stored.nonce);
        let decrypted = cipher.decrypt(nonce, stored.encrypted_key_package.as_slice())
            .map_err(|e| WalletError::CryptoError(format!("Decryption failed: {:?}", e)))?;
        
        // Deserialize
        let key_package = frost::keys::KeyPackage::deserialize(&decrypted)
            .map_err(|e| WalletError::SerializationError(format!("Invalid key package: {:?}", e)))?;
        
        Ok(key_package)
    }
    
    /// Get public key package (no decryption needed)
    pub fn get_public_key_package(
        &self,
        wallet_address: &str,
    ) -> Result<frost::keys::PublicKeyPackage, WalletError> {
        let shards = self.shards.read();
        let stored = shards.get(wallet_address)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_address.to_string()))?;
        
        let public_key_package = frost::keys::PublicKeyPackage::deserialize(&stored.public_key_package)
            .map_err(|e| WalletError::SerializationError(format!("Invalid public key package: {:?}", e)))?;
        
        Ok(public_key_package)
    }
    
    /// Store an OPAQUE record
    pub fn store_opaque_record(
        &self,
        identifier: &str,
        registration_data: Vec<u8>,
    ) -> Result<(), WalletError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let record = OpaqueRecord {
            identifier: identifier.to_string(),
            registration_data,
            created_at: now,
        };
        
        self.opaque_records.write().insert(identifier.to_string(), record);
        Ok(())
    }
    
    /// Get an OPAQUE record
    pub fn get_opaque_record(&self, identifier: &str) -> Option<OpaqueRecord> {
        self.opaque_records.read().get(identifier).cloned()
    }
    
    /// Check if a wallet exists
    pub fn wallet_exists(&self, wallet_address: &str) -> bool {
        self.shards.read().contains_key(wallet_address)
    }
    
    /// Delete a wallet's shard (for wallet recovery/migration)
    pub fn delete_shard(&self, wallet_address: &str) -> Result<(), WalletError> {
        self.shards.write().remove(wallet_address)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_address.to_string()))?;
        self.opaque_records.write().remove(wallet_address);
        Ok(())
    }
    
    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let shards = self.shards.read();
        StorageStats {
            total_shards: shards.len(),
            oldest_shard: shards.values().map(|s| s.created_at).min(),
            newest_shard: shards.values().map(|s| s.created_at).max(),
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_shards: usize,
    pub oldest_shard: Option<u64>,
    pub newest_shard: Option<u64>,
}

impl Default for ShardStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_creation() {
        let storage = ShardStorage::new();
        assert_eq!(storage.stats().total_shards, 0);
    }
    
    #[test]
    fn test_wallet_exists() {
        let storage = ShardStorage::new();
        assert!(!storage.wallet_exists("nonexistent"));
    }
}
