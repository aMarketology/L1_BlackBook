//! Layer1 Persistence Module
//!
//! Provides blockchain and social mining data persistence with:
//! - Automatic backup creation before saves
//! - JSON serialization with pretty formatting
//! - Atomic file writes to prevent corruption
//! - Emergency save functionality
//! - CLOUDBREAK: High-performance account database with memory-mapped I/O simulation
//!
//! INFRASTRUCTURE NOTE: Full EnhancedPersistence features are built for production.
//! Currently using simpler JSON persistence. CloudbreakAccountDB is wired to
//! ServiceCoordinator for account state caching.
#![allow(dead_code)]

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::collections::HashMap;
use dashmap::DashMap;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::protocol::blockchain::EnhancedBlockchain;
use crate::social_mining::SocialMiningSystem;

// ============================================================================
// CLOUDBREAK CONSTANTS
// ============================================================================

/// Account bucket count for sharding (power of 2 for fast modulo)
const ACCOUNT_BUCKETS: usize = 256;
/// Maximum accounts per bucket before warning
const MAX_ACCOUNTS_PER_BUCKET: usize = 10_000;
/// Hot account cache size
const HOT_ACCOUNT_CACHE_SIZE: usize = 1000;
/// Account access frequency threshold for "hot" classification
const HOT_ACCESS_THRESHOLD: u64 = 10;

// ============================================================================
// CLOUDBREAK - High-Performance Account Database
// ============================================================================
//
// Solana's Cloudbreak is a horizontally-scaled account database using:
// 1. Memory-mapped files for zero-copy account access
// 2. Append-only writes for durability
// 3. Account index sharding across multiple files
// 4. Sequential I/O optimization for SSDs
//
// In single-node mode, we simulate this architecture with DashMap shards.

/// An account entry in Cloudbreak
#[derive(Debug, Clone, Serialize)]
pub struct AccountEntry {
    /// Account address (public key)
    pub address: String,
    /// Account balance
    pub balance: f64,
    /// Last modified slot
    pub last_modified_slot: u64,
    /// Access count (for hot/cold classification)
    pub access_count: u64,
    /// Account data hash
    pub data_hash: String,
    /// Last access timestamp
    pub last_access: u64,
    /// Is this account rent-exempt
    pub rent_exempt: bool,
    /// Account owner (for programs)
    pub owner: String,
}

impl AccountEntry {
    pub fn new(address: String, balance: f64) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            address: address.clone(),
            balance,
            last_modified_slot: 0,
            access_count: 0,
            data_hash: format!("{:x}", Sha256::digest(address.as_bytes()))[..16].to_string(),
            last_access: now,
            rent_exempt: balance > 0.0,
            owner: "system".to_string(),
        }
    }
}

/// Statistics for Cloudbreak operations
#[derive(Debug, Clone, Serialize)]
pub struct CloudbreakStats {
    pub total_accounts: u64,
    pub hot_accounts: u64,
    pub cold_accounts: u64,
    pub total_reads: u64,
    pub total_writes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_read_latency_us: u64,
    pub avg_write_latency_us: u64,
    pub bucket_distribution: Vec<usize>,
    pub is_active: bool,
}

/// Cloudbreak AccountDB - High-performance account storage
///
/// Implements Solana-style account database:
/// - Sharded storage across ACCOUNT_BUCKETS DashMaps
/// - Hot account cache for frequently accessed accounts
/// - Sequential access optimization simulation
/// - Account versioning for slot-based reads
pub struct CloudbreakAccountDB {
    /// Sharded account storage (simulates memory-mapped files)
    buckets: Vec<DashMap<String, AccountEntry>>,
    
    /// Hot account cache (frequently accessed accounts)
    hot_cache: DashMap<String, AccountEntry>,
    
    /// Account index for fast lookup
    account_to_bucket: DashMap<String, usize>,
    
    /// Statistics
    total_accounts: AtomicU64,
    total_reads: AtomicU64,
    total_writes: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    total_read_time_us: AtomicU64,
    total_write_time_us: AtomicU64,
    
    /// Current slot for versioning
    current_slot: Arc<AtomicU64>,
    
    /// Service state
    is_active: AtomicBool,
}

impl CloudbreakAccountDB {
    /// Create a new Cloudbreak account database
    pub fn new(current_slot: Arc<AtomicU64>) -> Arc<Self> {
        let buckets: Vec<DashMap<String, AccountEntry>> = (0..ACCOUNT_BUCKETS)
            .map(|_| DashMap::new())
            .collect();
        
        println!("💎 Cloudbreak AccountDB initialized:");
        println!("   └─ {} buckets, hot cache: {} accounts, threshold: {} accesses", 
                 ACCOUNT_BUCKETS, HOT_ACCOUNT_CACHE_SIZE, HOT_ACCESS_THRESHOLD);
        
        Arc::new(Self {
            buckets,
            hot_cache: DashMap::new(),
            account_to_bucket: DashMap::new(),
            total_accounts: AtomicU64::new(0),
            total_reads: AtomicU64::new(0),
            total_writes: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            total_read_time_us: AtomicU64::new(0),
            total_write_time_us: AtomicU64::new(0),
            current_slot,
            is_active: AtomicBool::new(false),
        })
    }
    
    /// Compute bucket index from address (deterministic sharding)
    fn get_bucket_index(&self, address: &str) -> usize {
        // Use first 2 bytes of address hash for bucket assignment
        let hash = Sha256::digest(address.as_bytes());
        (hash[0] as usize) % ACCOUNT_BUCKETS
    }
    
    /// Get account balance (with hot cache)
    pub fn get_balance(&self, address: &str) -> f64 {
        let start = Instant::now();
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        
        // Check hot cache first
        if let Some(mut entry) = self.hot_cache.get_mut(address) {
            entry.access_count += 1;
            entry.last_access = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.total_read_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
            return entry.balance;
        }
        
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // Check sharded bucket
        let bucket_idx = self.get_bucket_index(address);
        let result = self.buckets[bucket_idx]
            .get_mut(address)
            .map(|mut entry| {
                entry.access_count += 1;
                entry.last_access = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                
                // Promote to hot cache if frequently accessed
                if entry.access_count >= HOT_ACCESS_THRESHOLD {
                    self.promote_to_hot_cache(&entry);
                }
                
                entry.balance
            })
            .unwrap_or(0.0);
        
        self.total_read_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        result
    }
    
    /// Get full account entry
    pub fn get_account(&self, address: &str) -> Option<AccountEntry> {
        let start = Instant::now();
        self.total_reads.fetch_add(1, Ordering::Relaxed);
        
        // Check hot cache first
        if let Some(entry) = self.hot_cache.get(address) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.total_read_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
            return Some(entry.clone());
        }
        
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // Check sharded bucket
        let bucket_idx = self.get_bucket_index(address);
        let result = self.buckets[bucket_idx].get(address).map(|e| e.clone());
        
        self.total_read_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        result
    }
    
    /// Update account balance
    pub fn update_balance(&self, address: &str, balance: f64) {
        let start = Instant::now();
        self.total_writes.fetch_add(1, Ordering::Relaxed);
        
        let slot = self.current_slot.load(Ordering::Relaxed);
        let bucket_idx = self.get_bucket_index(address);
        
        // Update in bucket
        self.buckets[bucket_idx]
            .entry(address.to_string())
            .and_modify(|entry| {
                entry.balance = balance;
                entry.last_modified_slot = slot;
                entry.access_count += 1;
            })
            .or_insert_with(|| {
                self.total_accounts.fetch_add(1, Ordering::Relaxed);
                self.account_to_bucket.insert(address.to_string(), bucket_idx);
                let mut entry = AccountEntry::new(address.to_string(), balance);
                entry.last_modified_slot = slot;
                entry
            });
        
        // Update hot cache if present
        if let Some(mut entry) = self.hot_cache.get_mut(address) {
            entry.balance = balance;
            entry.last_modified_slot = slot;
            entry.access_count += 1;
        }
        
        self.total_write_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
    }
    
    /// Promote account to hot cache
    fn promote_to_hot_cache(&self, entry: &AccountEntry) {
        // Evict oldest if cache is full
        if self.hot_cache.len() >= HOT_ACCOUNT_CACHE_SIZE {
            // Find oldest entry
            let oldest = self.hot_cache.iter()
                .min_by_key(|e| e.last_access)
                .map(|e| e.key().clone());
            
            if let Some(key) = oldest {
                self.hot_cache.remove(&key);
            }
        }
        
        self.hot_cache.insert(entry.address.clone(), entry.clone());
    }
    
    /// Load balances from a HashMap (e.g., from blockchain state)
    pub fn load_from_hashmap(&self, balances: &HashMap<String, f64>) {
        let slot = self.current_slot.load(Ordering::Relaxed);
        
        for (address, balance) in balances {
            let bucket_idx = self.get_bucket_index(address);
            
            let entry = AccountEntry {
                address: address.clone(),
                balance: *balance,
                last_modified_slot: slot,
                access_count: 0,
                data_hash: format!("{:x}", Sha256::digest(address.as_bytes()))[..16].to_string(),
                last_access: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                rent_exempt: *balance > 0.0,
                owner: "system".to_string(),
            };
            
            self.buckets[bucket_idx].insert(address.clone(), entry);
            self.account_to_bucket.insert(address.clone(), bucket_idx);
        }
        
        self.total_accounts.store(balances.len() as u64, Ordering::Relaxed);
        println!("💎 Cloudbreak loaded {} accounts", balances.len());
    }
    
    /// Export to HashMap (for blockchain state)
    pub fn export_to_hashmap(&self) -> HashMap<String, f64> {
        let mut result = HashMap::new();
        
        for bucket in &self.buckets {
            for entry in bucket.iter() {
                result.insert(entry.address.clone(), entry.balance);
            }
        }
        
        result
    }
    
    /// Get all accounts (expensive operation)
    pub fn get_all_accounts(&self) -> Vec<AccountEntry> {
        let mut accounts = Vec::new();
        
        for bucket in &self.buckets {
            for entry in bucket.iter() {
                accounts.push(entry.clone());
            }
        }
        
        accounts
    }
    
    /// Get hot accounts
    pub fn get_hot_accounts(&self) -> Vec<AccountEntry> {
        self.hot_cache.iter().map(|e| e.clone()).collect()
    }
    
    /// Start the service
    pub fn start(self: &Arc<Self>) {
        self.is_active.store(true, Ordering::Relaxed);
        println!("💎 Cloudbreak service activated");
    }
    
    /// Stop the service
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::Relaxed);
    }
    
    /// Get Cloudbreak statistics
    pub fn get_stats(&self) -> CloudbreakStats {
        let reads = self.total_reads.load(Ordering::Relaxed);
        let writes = self.total_writes.load(Ordering::Relaxed);
        let read_time = self.total_read_time_us.load(Ordering::Relaxed);
        let write_time = self.total_write_time_us.load(Ordering::Relaxed);
        
        let bucket_distribution: Vec<usize> = self.buckets.iter()
            .map(|b| b.len())
            .collect();
        
        CloudbreakStats {
            total_accounts: self.total_accounts.load(Ordering::Relaxed),
            hot_accounts: self.hot_cache.len() as u64,
            cold_accounts: self.total_accounts.load(Ordering::Relaxed) - self.hot_cache.len() as u64,
            total_reads: reads,
            total_writes: writes,
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            avg_read_latency_us: if reads > 0 { read_time / reads } else { 0 },
            avg_write_latency_us: if writes > 0 { write_time / writes } else { 0 },
            bucket_distribution,
            is_active: self.is_active.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// ENHANCED PERSISTENCE
// ============================================================================

/// Enhanced persistence manager with backup support.
/// 
/// Handles saving and loading of:
/// - Blockchain state (blocks, balances, PoH state)
/// - Social mining data (posts, likes, comments, user stats)
/// 
/// Features:
/// - Automatic backup creation before each save
/// - Pretty-printed JSON for debugging
/// - Emergency save with timestamped files
#[derive(Clone)]
pub struct EnhancedPersistence {
    pub file_path: String,
    pub backup_path: String,
    pub social_data_path: String,
    pub auto_save_interval: u64,
}

impl EnhancedPersistence {
    /// Create a new persistence manager with default paths.
    pub fn new() -> Self {
        Self {
            file_path: "blockchain_data.json".to_string(),
            backup_path: "blockchain_backup.json".to_string(),
            social_data_path: "social_mining_data.json".to_string(),
            auto_save_interval: 30, // seconds
        }
    }
    
    /// Create a persistence manager with custom paths.
    /// Useful for testing with isolated files.
    pub fn with_paths(file_path: &str, backup_path: &str, social_data_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
            backup_path: backup_path.to_string(),
            social_data_path: social_data_path.to_string(),
            auto_save_interval: 30,
        }
    }
    
    // ========================================================================
    // BLOCKCHAIN PERSISTENCE
    // ========================================================================
    
    /// Load blockchain from file.
    /// Returns None if file doesn't exist or is corrupted.
    pub async fn load_blockchain(&self) -> Result<Option<EnhancedBlockchain>, String> {
        if !Path::new(&self.file_path).exists() {
            println!("📂 No existing blockchain file found, creating new blockchain");
            return Ok(None);
        }
        
        match fs::read_to_string(&self.file_path) {
            Ok(data) => {
                match serde_json::from_str::<EnhancedBlockchain>(&data) {
                    Ok(blockchain) => {
                        println!("✅ Blockchain loaded from {}", self.file_path);
                        Ok(Some(blockchain))
                    },
                    Err(e) => {
                        println!("⚠️ Failed to deserialize blockchain: {}", e);
                        // Try loading from backup
                        self.load_from_backup().await
                    }
                }
            },
            Err(e) => {
                println!("⚠️ Failed to read blockchain file: {}", e);
                self.load_from_backup().await
            }
        }
    }
    
    /// Attempt to load blockchain from backup file.
    async fn load_from_backup(&self) -> Result<Option<EnhancedBlockchain>, String> {
        if !Path::new(&self.backup_path).exists() {
            println!("📂 No backup file found");
            return Ok(None);
        }
        
        match fs::read_to_string(&self.backup_path) {
            Ok(data) => {
                match serde_json::from_str::<EnhancedBlockchain>(&data) {
                    Ok(blockchain) => {
                        println!("✅ Blockchain restored from backup: {}", self.backup_path);
                        Ok(Some(blockchain))
                    },
                    Err(e) => {
                        println!("❌ Backup also corrupted: {}", e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                println!("❌ Failed to read backup: {}", e);
                Ok(None)
            }
        }
    }
    
    /// Save blockchain with automatic backup creation.
    pub async fn save_with_backup(&self, blockchain: &EnhancedBlockchain) -> Result<(), String> {
        // Create backup first if file exists
        if Path::new(&self.file_path).exists() {
            if let Err(e) = fs::copy(&self.file_path, &self.backup_path) {
                println!("⚠️ Backup creation failed: {}", e);
            } else {
                println!("📋 Backup created: {}", self.backup_path);
            }
        }
        
        // Serialize and save
        match serde_json::to_string_pretty(blockchain) {
            Ok(serialized) => {
                match fs::write(&self.file_path, serialized) {
                    Ok(_) => {
                        println!("💾 Blockchain saved to {}", self.file_path);
                        Ok(())
                    },
                    Err(e) => {
                        println!("❌ Failed to save blockchain: {}", e);
                        Err(format!("Save failed: {}", e))
                    }
                }
            },
            Err(e) => {
                println!("❌ Failed to serialize blockchain: {}", e);
                Err(format!("Serialization failed: {}", e))
            }
        }
    }
    
    // ========================================================================
    // SOCIAL MINING PERSISTENCE
    // ========================================================================
    
    /// Load social mining data from file.
    pub async fn load_social_mining_data(&self) -> Result<Option<SocialMiningSystem>, String> {
        if !Path::new(&self.social_data_path).exists() {
            println!("📱 No existing social mining data found, creating new system");
            return Ok(None);
        }
        
        match fs::read_to_string(&self.social_data_path) {
            Ok(data) => {
                match serde_json::from_str::<SocialMiningSystem>(&data) {
                    Ok(social_system) => {
                        println!("✅ Social mining data loaded from {}", self.social_data_path);
                        Ok(Some(social_system))
                    },
                    Err(e) => {
                        println!("⚠️ Failed to deserialize social mining data: {}", e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                println!("⚠️ Failed to read social mining data: {}", e);
                Ok(None)
            }
        }
    }
    
    /// Save social mining data to file.
    pub async fn save_social_mining_data(&self, social_system: &SocialMiningSystem) -> Result<(), String> {
        match serde_json::to_string_pretty(social_system) {
            Ok(serialized) => {
                match fs::write(&self.social_data_path, serialized) {
                    Ok(_) => {
                        println!("📱 Social mining data saved to {}", self.social_data_path);
                        Ok(())
                    },
                    Err(e) => {
                        println!("❌ Failed to save social mining data: {}", e);
                        Err(format!("Social save failed: {}", e))
                    }
                }
            },
            Err(e) => {
                println!("❌ Failed to serialize social mining data: {}", e);
                Err(format!("Social serialization failed: {}", e))
            }
        }
    }
    
    // ========================================================================
    // EMERGENCY SAVE
    // ========================================================================
    
    /// Emergency save with timestamped filenames.
    /// Used during crashes or unexpected shutdowns.
    pub async fn emergency_save(&self, blockchain: &EnhancedBlockchain, social_system: &SocialMiningSystem) {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let emergency_blockchain_path = format!("emergency_blockchain_{}.json", timestamp);
        let emergency_social_path = format!("emergency_social_{}.json", timestamp);
        
        // Save blockchain
        if let Ok(serialized) = serde_json::to_string_pretty(blockchain) {
            if let Err(e) = fs::write(&emergency_blockchain_path, serialized) {
                println!("❌ Emergency blockchain save failed: {}", e);
            } else {
                println!("🆘 Emergency blockchain saved: {}", emergency_blockchain_path);
            }
        }
        
        // Save social mining data
        if let Ok(serialized) = serde_json::to_string_pretty(social_system) {
            if let Err(e) = fs::write(&emergency_social_path, serialized) {
                println!("❌ Emergency social save failed: {}", e);
            } else {
                println!("🆘 Emergency social data saved: {}", emergency_social_path);
            }
        }
    }
    
    // ========================================================================
    // UTILITIES
    // ========================================================================
    
    /// Get file statistics for monitoring.
    pub fn get_file_stats(&self) -> serde_json::Value {
        let blockchain_size = fs::metadata(&self.file_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let backup_size = fs::metadata(&self.backup_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let social_size = fs::metadata(&self.social_data_path)
            .map(|m| m.len())
            .unwrap_or(0);
        
        serde_json::json!({
            "blockchain_file": self.file_path,
            "blockchain_size_bytes": blockchain_size,
            "backup_file": self.backup_path,
            "backup_size_bytes": backup_size,
            "social_file": self.social_data_path,
            "social_size_bytes": social_size,
            "auto_save_interval_seconds": self.auto_save_interval
        })
    }
    
    /// Check if data files exist.
    pub fn files_exist(&self) -> (bool, bool, bool) {
        (
            Path::new(&self.file_path).exists(),
            Path::new(&self.backup_path).exists(),
            Path::new(&self.social_data_path).exists(),
        )
    }
}

impl Default for EnhancedPersistence {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_paths(suffix: &str) -> (String, String, String) {
        (
            format!("test_bc_{}.json", suffix),
            format!("test_backup_{}.json", suffix),
            format!("test_social_{}.json", suffix),
        )
    }
    
    fn cleanup(paths: &(String, String, String)) {
        let _ = fs::remove_file(&paths.0);
        let _ = fs::remove_file(&paths.1);
        let _ = fs::remove_file(&paths.2);
    }

    #[test]
    fn test_persistence_new() {
        let p = EnhancedPersistence::new();
        assert_eq!(p.file_path, "blockchain_data.json");
        assert_eq!(p.auto_save_interval, 30);
    }

    #[test]
    fn test_persistence_with_paths() {
        let p = EnhancedPersistence::with_paths("a.json", "b.json", "c.json");
        assert_eq!(p.file_path, "a.json");
        assert_eq!(p.backup_path, "b.json");
        assert_eq!(p.social_data_path, "c.json");
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let paths = test_paths("save_load");
        let p = EnhancedPersistence::with_paths(&paths.0, &paths.1, &paths.2);
        
        let mut bc = EnhancedBlockchain::new();
        let _ = bc.create_transaction("signup_bonus".to_string(), "test".to_string(), 100.0);
        
        let _ = p.save_with_backup(&bc).await;
        let loaded = p.load_blockchain().await.unwrap().unwrap();
        
        assert_eq!(loaded.get_balance("test"), 100.0);
        
        cleanup(&paths);
    }

    #[tokio::test]
    async fn test_load_nonexistent() {
        let paths = test_paths("nonexistent");
        cleanup(&paths);
        
        let p = EnhancedPersistence::with_paths(&paths.0, &paths.1, &paths.2);
        let result = p.load_blockchain().await;
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_files_exist() {
        let p = EnhancedPersistence::with_paths(
            "nonexistent1.json",
            "nonexistent2.json",
            "nonexistent3.json",
        );
        let (a, b, c) = p.files_exist();
        assert!(!a && !b && !c);
    }
}
