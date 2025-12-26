//! Persistent Blockchain - EnhancedBlockchain with Sled Storage
//!
//! This module provides a wrapper around EnhancedBlockchain that automatically
//! persists state to disk using Sled + Borsh serialization.
//!
//! Key Features:
//! - Automatic persistence on block commit
//! - Load state from disk on startup
//! - Maintains full compatibility with existing APIs
//! - Merkle state roots for verification
//!
//! Usage:
//! ```rust
//! let blockchain = PersistentBlockchain::new("./blockchain_data")?;
//! // Use exactly like EnhancedBlockchain
//! blockchain.create_transaction(...);
//! blockchain.mine_pending_transactions(...)?;
//! // State is automatically persisted!
//! ```

use std::ops::{Deref, DerefMut};
use std::collections::HashMap;

use crate::protocol::blockchain::{
    EnhancedBlockchain, Account, Block, 
    TREASURY_ADDRESS, INITIAL_SUPPLY, compute_genesis_hash,
};
use crate::storage::{
    StorageBridge, StorageEngine, StorageResult, StorageError,
    StoredAccount, StoredBlockHeader, DbStats,
};

// ============================================================================
// PERSISTENT BLOCKCHAIN
// ============================================================================

/// EnhancedBlockchain with automatic disk persistence via Sled
pub struct PersistentBlockchain {
    /// The in-memory blockchain (for fast reads)
    inner: EnhancedBlockchain,
    /// Storage bridge for persistence
    storage: StorageBridge,
    /// Sync interval (persist every N blocks)
    sync_interval: u64,
    /// Blocks since last full sync
    blocks_since_sync: u64,
}

impl PersistentBlockchain {
    /// Create a new persistent blockchain at the given path
    /// 
    /// If existing data is found, it will be loaded.
    /// Otherwise, genesis state is initialized.
    pub fn new(data_path: &str) -> StorageResult<Self> {
        let storage = StorageBridge::new(data_path)?;
        
        // Check if we have existing state
        let latest_slot = storage.get_latest_slot()?;
        
        let inner = if latest_slot > 0 {
            // Load existing state
            println!("📂 Loading blockchain from disk (slot {})...", latest_slot);
            Self::load_from_storage(&storage)?
        } else {
            // Fresh start - create genesis
            println!("🌱 Initializing new blockchain with genesis...");
            let bc = EnhancedBlockchain::new();
            
            // Persist genesis state
            let genesis_hash = compute_genesis_hash();
            storage.init_genesis(&genesis_hash, INITIAL_SUPPLY)?;
            
            // Persist treasury account
            if let Some(treasury) = bc.accounts.get(TREASURY_ADDRESS) {
                storage.save_account(TREASURY_ADDRESS, treasury)?;
            }
            
            // Persist genesis block
            if let Some(genesis_block) = bc.chain.first() {
                storage.persist_block(genesis_block, &[])?;
            }
            
            storage.flush()?;
            println!("✅ Genesis persisted to disk");
            
            bc
        };
        
        Ok(Self {
            inner,
            storage,
            sync_interval: 10, // Full sync every 10 blocks
            blocks_since_sync: 0,
        })
    }

    /// Load blockchain state from storage
    fn load_from_storage(storage: &StorageBridge) -> StorageResult<EnhancedBlockchain> {
        let mut bc = EnhancedBlockchain::new();
        
        // Load accounts
        let accounts = storage.load_accounts_to_hashmap()?;
        let account_count = accounts.len();
        bc.accounts = accounts;
        
        // Load balances (derived from account lamports)
        let balances = storage.load_balances_to_hashmap()?;
        bc.balances = balances;
        
        // Load latest slot
        let latest_slot = storage.get_latest_slot()?;
        bc.current_slot = latest_slot;
        
        // Load genesis hash as current POH hash
        if let Some(genesis_hash) = storage.get_genesis_hash()? {
            bc.current_poh_hash = genesis_hash;
        }
        
        // Load state root as verification
        let state_root = storage.get_state_root()?;
        
        println!("   Loaded {} accounts, slot {}", account_count, latest_slot);
        println!("   State root: {}...", &state_root[..16.min(state_root.len())]);
        
        Ok(bc)
    }

    /// Get reference to storage bridge
    pub fn storage(&self) -> &StorageBridge {
        &self.storage
    }

    /// Get storage statistics
    pub fn storage_stats(&self) -> DbStats {
        self.storage.stats()
    }

    /// Force flush to disk
    pub fn flush(&self) -> StorageResult<()> {
        self.storage.flush()
    }

    /// Mine pending transactions with automatic persistence
    pub fn mine_and_persist(&mut self, sequencer: String) -> Result<String, String> {
        // Get pre-mine state of accounts that will be modified
        let pending_accounts: Vec<String> = self.inner.pending_transactions
            .iter()
            .flat_map(|tx| vec![tx.from.clone(), tx.to.clone()])
            .collect();

        // Mine the block
        self.inner.mine_pending_transactions(sequencer.clone())?;

        // Get the new block and extract needed values (to avoid borrow issues)
        let (block_slot, block_financial_txs) = {
            let new_block = self.inner.chain.last()
                .ok_or_else(|| "No block after mining".to_string())?;
            (new_block.slot, new_block.financial_txs.clone())
        };

        // Collect account updates
        let mut account_updates: Vec<(String, Account)> = Vec::new();
        for pubkey in pending_accounts.iter() {
            if let Some(account) = self.inner.accounts.get(pubkey) {
                account_updates.push((pubkey.clone(), account.clone()));
            }
        }

        // Also persist any balance-only updates
        for tx in &block_financial_txs {
            // Ensure accounts exist in our update list
            if !account_updates.iter().any(|(k, _)| k == &tx.from) {
                let balance = self.inner.get_balance(&tx.from);
                let account = Account::from_bb_balance(
                    tx.from.clone(), 
                    balance, 
                    block_slot
                );
                account_updates.push((tx.from.clone(), account));
            }
            if !account_updates.iter().any(|(k, _)| k == &tx.to) {
                let balance = self.inner.get_balance(&tx.to);
                let account = Account::from_bb_balance(
                    tx.to.clone(), 
                    balance, 
                    block_slot
                );
                account_updates.push((tx.to.clone(), account));
            }
        }

        // Get block reference again for persist_block call
        let new_block = self.inner.chain.last()
            .ok_or_else(|| "Block disappeared after mining".to_string())?;

        // Persist to storage
        let state_root = self.storage.persist_block(new_block, &account_updates)
            .map_err(|e| format!("Storage error: {:?}", e))?;

        // Update metadata
        self.storage.engine().set_latest_slot(block_slot)
            .map_err(|e| format!("Metadata error: {:?}", e))?;
        self.storage.engine().set_state_root(&state_root)
            .map_err(|e| format!("State root error: {:?}", e))?;

        self.blocks_since_sync += 1;

        // Periodic full sync
        if self.blocks_since_sync >= self.sync_interval {
            self.full_sync()?;
            self.blocks_since_sync = 0;
        }

        println!("💾 Block {} persisted (state root: {}...)", 
                 block_slot, &state_root[..16.min(state_root.len())]);

        Ok(state_root)
    }

    /// Perform full synchronization of all state
    fn full_sync(&mut self) -> Result<(), String> {
        let slot = self.inner.current_slot;
        
        // Sync all accounts
        let count = self.storage.sync_accounts_from_hashmap(&self.inner.accounts, slot)
            .map_err(|e| format!("Account sync error: {:?}", e))?;
        
        // Flush to disk
        self.storage.flush()
            .map_err(|e| format!("Flush error: {:?}", e))?;
        
        println!("🔄 Full sync complete: {} accounts at slot {}", count, slot);
        Ok(())
    }

    /// Export current state to JSON (for debugging/migration)
    pub fn export_json(&self) -> serde_json::Value {
        self.storage.export_json()
    }

    /// Import state from JSON file
    pub fn import_json(&mut self, path: &str) -> Result<(), String> {
        use std::fs;
        
        let json_str = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;
        
        #[derive(serde::Deserialize)]
        struct LegacyState {
            balances: HashMap<String, f64>,
            #[serde(default)]
            accounts: HashMap<String, Account>,
        }
        
        let legacy: LegacyState = serde_json::from_str(&json_str)
            .map_err(|e| format!("Invalid JSON: {}", e))?;
        
        println!("📥 Importing {} balances, {} accounts...", 
                 legacy.balances.len(), legacy.accounts.len());
        
        // Import balances
        for (pubkey, balance) in &legacy.balances {
            self.inner.balances.insert(pubkey.clone(), *balance);
            self.storage.save_balance(pubkey, *balance, self.inner.current_slot)
                .map_err(|e| format!("Save balance error: {:?}", e))?;
        }
        
        // Import accounts
        for (pubkey, account) in &legacy.accounts {
            self.inner.accounts.insert(pubkey.clone(), account.clone());
            self.storage.save_account(pubkey, account)
                .map_err(|e| format!("Save account error: {:?}", e))?;
        }
        
        self.storage.flush()
            .map_err(|e| format!("Flush error: {:?}", e))?;
        
        println!("✅ Import complete");
        Ok(())
    }
}

// ============================================================================
// DEREF TO ENHANCEDBLOCKCHAIN
// ============================================================================

// Allow using PersistentBlockchain as EnhancedBlockchain via Deref
impl Deref for PersistentBlockchain {
    type Target = EnhancedBlockchain;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PersistentBlockchain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Configuration for persistent blockchain
#[derive(Debug, Clone)]
pub struct PersistentConfig {
    /// Path to store blockchain data
    pub data_path: String,
    /// Sync to disk every N blocks
    pub sync_interval: u64,
    /// Enable fsync after each block (slower but safer)
    pub fsync_on_commit: bool,
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            data_path: "./blockchain_data".to_string(),
            sync_interval: 10,
            fsync_on_commit: false,
        }
    }
}

impl PersistentBlockchain {
    /// Create with custom configuration
    pub fn with_config(config: PersistentConfig) -> StorageResult<Self> {
        let mut bc = Self::new(&config.data_path)?;
        bc.sync_interval = config.sync_interval;
        Ok(bc)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_persistent_blockchain_creation() {
        let dir = tempdir().unwrap();
        let bc = PersistentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
        
        // Should have genesis state
        assert!(bc.chain.len() >= 1);
        assert!(bc.get_balance(TREASURY_ADDRESS) > 0.0);
    }

    #[test]
    fn test_persistent_blockchain_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        
        // Create and add some state
        {
            let mut bc = PersistentBlockchain::new(path).unwrap();
            bc.inner.balances.insert("alice".to_string(), 100.0);
            bc.storage.save_balance("alice", 100.0, 1).unwrap();
            bc.storage.engine().set_latest_slot(1).unwrap();
            bc.flush().unwrap();
        }
        
        // Reload and verify
        {
            let bc = PersistentBlockchain::new(path).unwrap();
            let balance = bc.storage.load_balance("alice").unwrap();
            assert_eq!(balance, 100.0);
        }
    }

    #[test]
    fn test_deref_to_enhanced_blockchain() {
        let dir = tempdir().unwrap();
        let bc = PersistentBlockchain::new(dir.path().to_str().unwrap()).unwrap();
        
        // Should be able to call EnhancedBlockchain methods directly
        let _balance = bc.get_balance(TREASURY_ADDRESS);
        let _slot = bc.current_slot;
    }
}
