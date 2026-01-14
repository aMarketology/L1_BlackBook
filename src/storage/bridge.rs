//! Storage Bridge - Connects EnhancedBlockchain to StorageEngine
//!
//! This module provides conversion between existing types and storage types,
//! enabling gradual migration from HashMap-based storage to Sled.
//!
//! Architecture:
//! ```text
//! EnhancedBlockchain (in-memory, fast)
//!         │
//!         ▼
//!   StorageBridge (conversion layer)
//!         │
//!         ▼
//!   StorageEngine (Sled + Borsh, persistent)
//! ```

use crate::protocol::blockchain::{Account, Block, LAMPORTS_PER_BB};
use crate::runtime::core::{Transaction, TransactionType};
use crate::storage::{
    StorageEngine, StoredAccount, StoredBlockHeader, StoredSocialData, TxLocation,
    StorageResult, StorageError,
};
use borsh::{BorshSerialize, BorshDeserialize};

// ============================================================================
// ACCOUNT CONVERSION
// ============================================================================

impl From<&Account> for StoredAccount {
    fn from(account: &Account) -> Self {
        StoredAccount {
            lamports: account.lamports,
            nonce: account.nonce,
            owner: account.owner.clone(),
            data_hash: account.data_hash.clone(),
            created_slot: account.created_slot,
            last_modified_slot: account.last_modified_slot,
            rent_exempt: account.rent_exempt,
        }
    }
}

impl From<&StoredAccount> for Account {
    fn from(stored: &StoredAccount) -> Self {
        use crate::protocol::blockchain::AccountType;
        Account {
            lamports: stored.lamports,
            nonce: stored.nonce,
            owner: stored.owner.clone(),
            data_hash: stored.data_hash.clone(),
            created_slot: stored.created_slot,
            last_modified_slot: stored.last_modified_slot,
            rent_exempt: stored.rent_exempt,
            executable: false,
            program_id: None,
            data: Vec::new(),
            account_type: AccountType::User,
        }
    }
}

// ============================================================================
// BLOCK CONVERSION
// ============================================================================

impl From<&Block> for StoredBlockHeader {
    fn from(block: &Block) -> Self {
        StoredBlockHeader {
            index: block.index,
            slot: block.slot,
            timestamp: block.timestamp,
            previous_hash: block.previous_hash.clone(),
            hash: block.hash.clone(),
            poh_hash: block.poh_hash.clone(),
            parent_slot: block.parent_slot,
            sequencer: block.sequencer.clone(),
            state_root: String::new(), // Will be computed during commit
            financial_tx_count: block.financial_txs.len() as u32,
            social_tx_count: block.social_txs.len() as u32,
            engagement_score: block.engagement_score,
        }
    }
}

// ============================================================================
// TRANSACTION CONVERSION
// ============================================================================

impl Transaction {
    /// Create TxLocation for storage indexing
    pub fn to_location(&self, slot: u64, index: u32) -> TxLocation {
        TxLocation {
            slot,
            block_index: index,
            is_financial: self.tx_type.is_financial(),
        }
    }
}

// ============================================================================
// STORAGE BRIDGE
// ============================================================================

/// Bridge between EnhancedBlockchain and StorageEngine
/// 
/// Provides methods to:
/// - Persist blockchain state to disk
/// - Load blockchain state from disk
/// - Sync in-memory state with persistent storage
pub struct StorageBridge {
    engine: StorageEngine,
}

impl StorageBridge {
    /// Create a new storage bridge
    pub fn new(data_path: &str) -> StorageResult<Self> {
        let engine = StorageEngine::new(data_path)?;
        Ok(Self { engine })
    }

    /// Get reference to underlying storage engine
    pub fn engine(&self) -> &StorageEngine {
        &self.engine
    }

    // ========================================================================
    // ACCOUNT OPERATIONS
    // ========================================================================

    /// Save an account from EnhancedBlockchain
    pub fn save_account(&self, pubkey: &str, account: &Account) -> StorageResult<()> {
        let stored = StoredAccount::from(account);
        self.engine.save_account(pubkey, &stored)
    }

    /// Load an account for EnhancedBlockchain
    pub fn load_account(&self, pubkey: &str) -> StorageResult<Option<Account>> {
        match self.engine.get_account(pubkey)? {
            Some(stored) => Ok(Some(Account::from(&stored))),
            None => Ok(None),
        }
    }

    /// Save balance (creates/updates account with lamport conversion)
    pub fn save_balance(&self, pubkey: &str, balance_bb: f64, slot: u64) -> StorageResult<()> {
        let lamports = (balance_bb * LAMPORTS_PER_BB as f64) as u64;
        
        let stored = match self.engine.get_account(pubkey)? {
            Some(mut existing) => {
                existing.lamports = lamports;
                existing.last_modified_slot = slot;
                existing.rent_exempt = lamports >= 1_000;
                existing
            }
            None => StoredAccount::new(pubkey.to_string(), lamports, slot),
        };
        
        self.engine.save_account(pubkey, &stored)
    }

    /// Load balance (returns BB tokens, not lamports)
    pub fn load_balance(&self, pubkey: &str) -> StorageResult<f64> {
        match self.engine.get_account(pubkey)? {
            Some(stored) => Ok(stored.balance_bb()),
            None => Ok(0.0),
        }
    }

    // ========================================================================
    // BLOCK OPERATIONS
    // ========================================================================

    /// Persist a mined block with all state changes
    /// 
    /// This is the atomic commit point - all data is persisted together.
    pub fn persist_block(
        &self,
        block: &Block,
        account_updates: &[(String, Account)],
    ) -> StorageResult<String> {
        // Convert accounts to storage format
        let stored_accounts: Vec<(String, StoredAccount)> = account_updates
            .iter()
            .map(|(pubkey, account)| (pubkey.clone(), StoredAccount::from(account)))
            .collect();

        // Convert block to header with state root
        let mut header = StoredBlockHeader::from(block);
        
        // Compute state root from account updates
        header.state_root = self.compute_state_root(&stored_accounts);

        // Index transactions
        let mut tx_indices: Vec<(String, TxLocation)> = Vec::new();
        
        for (idx, tx) in block.financial_txs.iter().enumerate() {
            let sig = if tx.signature.is_empty() { &tx.id } else { &tx.signature };
            tx_indices.push((sig.clone(), tx.to_location(block.slot, idx as u32)));
        }
        
        for (idx, tx) in block.social_txs.iter().enumerate() {
            let sig = if tx.signature.is_empty() { &tx.id } else { &tx.signature };
            let offset = block.financial_txs.len() as u32;
            tx_indices.push((sig.clone(), tx.to_location(block.slot, offset + idx as u32)));
        }

        // Atomic commit
        self.engine.commit_block(&header, &stored_accounts, &tx_indices, &[])
    }

    /// Load block header by slot
    pub fn load_block(&self, slot: u64) -> StorageResult<Option<StoredBlockHeader>> {
        self.engine.get_block(slot)
    }

    /// Load latest block
    pub fn load_latest_block(&self) -> StorageResult<Option<StoredBlockHeader>> {
        self.engine.get_latest_block()
    }

    /// Load block range (for sync/replay)
    pub fn load_block_range(&self, start: u64, end: u64) -> StorageResult<Vec<StoredBlockHeader>> {
        self.engine.get_blocks_range(start, end)
    }

    // ========================================================================
    // METADATA OPERATIONS
    // ========================================================================

    /// Check if genesis has already been initialized
    pub fn has_genesis(&self) -> StorageResult<bool> {
        Ok(self.engine.get_genesis_hash()?.is_some())
    }

    /// Initialize genesis state - ONLY called for fresh databases
    /// This sets the initial state and should NEVER be called on existing data
    pub fn init_genesis(&self, genesis_hash: &str, total_supply_bb: f64) -> StorageResult<()> {
        // SAFETY: Check if genesis already exists - NEVER overwrite!
        if self.has_genesis()? {
            println!("⚠️  Genesis already exists - skipping init_genesis (this is normal on restart)");
            return Ok(());
        }
        
        println!("🌱 First-time genesis initialization...");
        
        // Set genesis hash (this marks the database as initialized)
        self.engine.set_genesis_hash(genesis_hash)?;
        
        // Set initial supply
        let total_lamports = (total_supply_bb * LAMPORTS_PER_BB as f64) as u64;
        self.engine.set_total_supply(total_lamports)?;
        
        // Set slot to 1 (not 0!) so we can detect existing data
        // Slot 0 is reserved for "uninitialized"
        self.engine.set_latest_slot(1)?;
        
        // Initial state root
        self.engine.set_state_root(&"0".repeat(64))?;
        
        // Force sync to disk
        self.engine.flush()?;
        
        println!("✅ Genesis initialized and flushed to disk");
        Ok(())
    }

    /// Get genesis hash
    pub fn get_genesis_hash(&self) -> StorageResult<Option<String>> {
        self.engine.get_genesis_hash()
    }

    /// Get latest slot
    pub fn get_latest_slot(&self) -> StorageResult<u64> {
        Ok(self.engine.get_latest_slot()?.unwrap_or(0))
    }

    /// Get state root
    pub fn get_state_root(&self) -> StorageResult<String> {
        Ok(self.engine.get_state_root()?.unwrap_or_else(|| "0".repeat(64)))
    }

    /// Get total supply in BB tokens
    pub fn get_total_supply_bb(&self) -> StorageResult<f64> {
        match self.engine.get_total_supply()? {
            Some(lamports) => Ok(lamports as f64 / LAMPORTS_PER_BB as f64),
            None => Ok(0.0),
        }
    }

    // ========================================================================
    // SOCIAL MINING DATA
    // ========================================================================

    /// Save social mining data
    pub fn save_social_data(&self, pubkey: &str, data: &StoredSocialData) -> StorageResult<()> {
        self.engine.save_social_data(pubkey, data)
    }

    /// Load social mining data
    pub fn load_social_data(&self, pubkey: &str) -> StorageResult<Option<StoredSocialData>> {
        self.engine.get_social_data(pubkey)
    }

    // ========================================================================
    // TRANSACTION LOOKUP
    // ========================================================================

    /// Find transaction by signature
    pub fn find_transaction(&self, signature: &str) -> StorageResult<Option<TxLocation>> {
        self.engine.find_transaction(signature)
    }

    // ========================================================================
    // SYNC OPERATIONS
    // ========================================================================

    /// Sync all accounts from HashMap to storage
    pub fn sync_accounts_from_hashmap(
        &self,
        accounts: &std::collections::HashMap<String, Account>,
        slot: u64,
    ) -> StorageResult<usize> {
        let mut count = 0;
        for (pubkey, account) in accounts {
            self.save_account(pubkey, account)?;
            count += 1;
        }
        Ok(count)
    }

    /// Sync all balances from HashMap to storage
    pub fn sync_balances_from_hashmap(
        &self,
        balances: &std::collections::HashMap<String, f64>,
        slot: u64,
    ) -> StorageResult<usize> {
        let mut count = 0;
        for (pubkey, balance) in balances {
            self.save_balance(pubkey, *balance, slot)?;
            count += 1;
        }
        Ok(count)
    }

    /// Load all accounts into HashMap
    pub fn load_accounts_to_hashmap(&self) -> StorageResult<std::collections::HashMap<String, Account>> {
        let mut accounts = std::collections::HashMap::new();
        for (pubkey, stored) in self.engine.iter_accounts() {
            accounts.insert(pubkey, Account::from(&stored));
        }
        Ok(accounts)
    }

    /// Load all balances into HashMap
    pub fn load_balances_to_hashmap(&self) -> StorageResult<std::collections::HashMap<String, f64>> {
        let mut balances = std::collections::HashMap::new();
        for (pubkey, stored) in self.engine.iter_accounts() {
            balances.insert(pubkey, stored.balance_bb());
        }
        Ok(balances)
    }

    // ========================================================================
    // UTILITIES
    // ========================================================================

    /// Compute state root from account updates
    fn compute_state_root(&self, accounts: &[(String, StoredAccount)]) -> String {
        use sha2::{Sha256, Digest};
        
        if accounts.is_empty() {
            return "0".repeat(64);
        }
        
        // Create leaves: hash of (pubkey || borsh_serialized_account)
        let mut leaves: Vec<[u8; 32]> = accounts
            .iter()
            .map(|(pubkey, account)| {
                let account_bytes = borsh::to_vec(account).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(pubkey.as_bytes());
                hasher.update(&account_bytes);
                hasher.finalize().into()
            })
            .collect();
        
        // Sort for deterministic ordering
        leaves.sort();
        
        // Simple Merkle root computation
        if leaves.len() == 1 {
            return hex::encode(&leaves[0]);
        }
        
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate odd leaf
                }
                next_level.push(hasher.finalize().into());
            }
            leaves = next_level;
        }
        
        hex::encode(&leaves[0])
    }

    /// Flush to disk
    pub fn flush(&self) -> StorageResult<()> {
        self.engine.flush()
    }

    /// Get database statistics
    pub fn stats(&self) -> crate::storage::DbStats {
        self.engine.stats()
    }

    /// Export to JSON (for debugging/migration)
    pub fn export_json(&self) -> serde_json::Value {
        self.engine.export_json()
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
    fn test_account_conversion() {
        let account = Account {
            lamports: 1_000_000,
            nonce: 5,
            owner: "owner123".to_string(),
            data_hash: "hash123".to_string(),
            created_slot: 10,
            last_modified_slot: 20,
            rent_exempt: true,
        };

        let stored = StoredAccount::from(&account);
        let back = Account::from(&stored);

        assert_eq!(account.lamports, back.lamports);
        assert_eq!(account.nonce, back.nonce);
        assert_eq!(account.owner, back.owner);
    }

    #[test]
    fn test_storage_bridge() {
        let dir = tempdir().unwrap();
        let bridge = StorageBridge::new(dir.path().to_str().unwrap()).unwrap();

        // Test balance operations
        bridge.save_balance("alice", 100.0, 1).unwrap();
        let balance = bridge.load_balance("alice").unwrap();
        assert_eq!(balance, 100.0);

        // Test account operations
        let account = Account {
            lamports: 50_000_000,
            nonce: 3,
            owner: "alice".to_string(),
            data_hash: String::new(),
            created_slot: 5,
            last_modified_slot: 10,
            rent_exempt: true,
        };
        bridge.save_account("bob", &account).unwrap();
        let loaded = bridge.load_account("bob").unwrap().unwrap();
        assert_eq!(loaded.lamports, 50_000_000);
        assert_eq!(loaded.nonce, 3);
    }
}
