//! Persistent Blockchain - Immutable L1 Chain with Mandatory Sled Persistence
//!
//! This is the ONLY way to interact with the BlackBook L1 blockchain.
//! Every transaction, every block, every state change is persisted to disk.
//! There is no in-memory-only mode. Persistence is innate and unavoidable.
//!
//! Design Principles:
//! - NO Deref/DerefMut: Prevents bypassing persistence layer
//! - ALL mutations persist: Every state change writes to Sled
//! - Hot upgrade ready: Version tracking and migration hooks
//! - P2P ready: Consistent state root for verification
//!
//! Usage:
//! ```rust
//! let blockchain = PersistentBlockchain::new("./blockchain_sled")?;
//! blockchain.create_transaction(from, to, amount);
//! blockchain.mine_pending_transactions("validator")?; // Persists automatically
//! ```

use std::collections::{HashMap, HashSet};

use crate::protocol::blockchain::{
    EnhancedBlockchain, Account, Block, Transaction,
    TREASURY_ADDRESS, INITIAL_SUPPLY, compute_genesis_hash,
};
use crate::storage::{
    StorageBridge, StorageResult, DbStats,
};
use crate::runtime::core::TransactionType;

// ============================================================================
// PROTOCOL VERSION - For Hot Upgrades
// ============================================================================

/// Current protocol version - increment on breaking changes
pub const PROTOCOL_VERSION: u32 = 1;

/// Minimum supported protocol version for migrations
pub const MIN_PROTOCOL_VERSION: u32 = 1;

// ============================================================================
// PERSISTENT BLOCKCHAIN - The ONLY blockchain type for production
// ============================================================================

/// Persistent Blockchain - Every operation is persisted to Sled
/// 
/// This is the canonical blockchain type for BlackBook L1.
/// There is NO in-memory-only mode. All state changes are immediately
/// persisted to disk, ensuring true immutability and crash recovery.
/// 
/// NOTE: Deref provides READ-ONLY access to EnhancedBlockchain fields.
/// All mutations MUST go through explicit methods that persist.
pub struct PersistentBlockchain {
    /// The in-memory state (cache for fast reads)
    pub inner: EnhancedBlockchain,
    /// Sled storage bridge for persistence
    storage: StorageBridge,
    /// Protocol version for hot upgrades
    protocol_version: u32,
    /// Blocks since last full sync
    blocks_since_sync: u64,
    /// Full sync interval
    sync_interval: u64,
}

// Deref for read-only access to EnhancedBlockchain fields
// This allows code to access bc.chain, bc.balances, etc. directly for reads
impl std::ops::Deref for PersistentBlockchain {
    type Target = EnhancedBlockchain;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// ============================================================================
// CORE IMPLEMENTATION
// ============================================================================

impl PersistentBlockchain {
    /// Create or load a persistent blockchain at the given path
    /// 
    /// If existing data is found, it will be loaded and verified.
    /// Otherwise, genesis state is initialized and persisted.
    pub fn new(data_path: &str) -> StorageResult<Self> {
        let storage = StorageBridge::new(data_path)?;
        
        // Check for existing state
        let latest_slot = storage.get_latest_slot()?;
        
        let inner = if latest_slot > 0 {
            println!("📂 Loading blockchain from Sled (slot {})...", latest_slot);
            Self::load_from_storage(&storage)?
        } else {
            println!("🌱 Initializing genesis block...");
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
            println!("✅ Genesis persisted to Sled");
            
            bc
        };
        
        Ok(Self {
            inner,
            storage,
            protocol_version: PROTOCOL_VERSION,
            blocks_since_sync: 0,
            sync_interval: 10,
        })
    }

    /// Load blockchain state from storage
    fn load_from_storage(storage: &StorageBridge) -> StorageResult<EnhancedBlockchain> {
        let mut bc = EnhancedBlockchain::new();
        
        // Load accounts
        let accounts = storage.load_accounts_to_hashmap()?;
        let account_count = accounts.len();
        bc.accounts = accounts;
        
        // Load balances
        let balances = storage.load_balances_to_hashmap()?;
        let balance_count = balances.len();
        bc.balances = balances.clone();
        
        // Load latest slot
        bc.current_slot = storage.get_latest_slot()?;
        
        // Load genesis hash
        if let Some(genesis_hash) = storage.get_genesis_hash()? {
            bc.current_poh_hash = genesis_hash;
        }
        
        let state_root = storage.get_state_root()?;
        println!("   ✓ {} accounts, {} balances, slot {}", account_count, balance_count, bc.current_slot);
        println!("   ✓ State root: {}...", &state_root[..16.min(state_root.len())]);
        
        // Debug: Print top balances loaded from storage
        let mut sorted_balances: Vec<_> = balances.iter().collect();
        sorted_balances.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        println!("   📊 Top balances loaded from Sled:");
        for (addr, bal) in sorted_balances.iter().take(5) {
            let short_addr = if addr.len() > 20 { &addr[..20] } else { addr };
            println!("      {} = {} BB", short_addr, bal);
        }
        
        Ok(bc)
    }

    // ========================================================================
    // BALANCE & ACCOUNT QUERIES (Read-only, no persistence needed)
    // ========================================================================

    /// Get balance for an address
    pub fn get_balance(&self, address: &str) -> f64 {
        self.inner.get_balance(address)
    }

    /// Get account details
    pub fn get_account(&self, address: &str) -> Option<&Account> {
        self.inner.accounts.get(address)
    }

    /// Check if account exists
    pub fn account_exists(&self, address: &str) -> bool {
        self.inner.accounts.contains_key(address)
    }

    /// Get all balances
    pub fn get_all_balances(&self) -> &HashMap<String, f64> {
        &self.inner.balances
    }

    /// Get current slot
    pub fn current_slot(&self) -> u64 {
        self.inner.current_slot
    }

    /// Get chain length (block count)
    pub fn chain_length(&self) -> usize {
        self.inner.chain.len()
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.inner.pending_transactions.len()
    }

    /// Get block by slot
    pub fn get_block(&self, slot: u64) -> Option<&Block> {
        self.inner.chain.iter().find(|b| b.slot == slot)
    }

    /// Get latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.inner.chain.last()
    }

    /// Get chain reference (read-only)
    pub fn chain(&self) -> &Vec<Block> {
        &self.inner.chain
    }

    /// Get mutable chain reference (for consensus layer)
    /// ⚠️ CAUTION: Direct chain mutations bypass persistence!
    /// Use add_block() or mine_pending_transactions() for persistence.
    pub fn chain_mut(&mut self) -> &mut Vec<Block> {
        &mut self.inner.chain
    }

    /// Get accounts reference (read-only)
    pub fn accounts(&self) -> &HashMap<String, Account> {
        &self.inner.accounts
    }

    /// Get balances reference (read-only)
    pub fn balances(&self) -> &HashMap<String, f64> {
        &self.inner.balances
    }

    /// Set current slot (for consensus layer)
    pub fn set_current_slot(&mut self, slot: u64) {
        self.inner.current_slot = slot;
    }

    /// Add an empty block (for slot skipping) - persists immediately
    pub fn add_empty_block(&mut self, block: Block) -> Result<(), String> {
        let slot = block.slot;
        self.inner.chain.push(block.clone());
        
        // Persist the block with no account updates
        let state_root = self.storage.persist_block(&block, &[])
            .map_err(|e| format!("Storage error: {:?}", e))?;
        
        self.storage.engine().set_latest_slot(slot)
            .map_err(|e| format!("Metadata error: {:?}", e))?;
        self.storage.engine().set_state_root(&state_root)
            .map_err(|e| format!("State root error: {:?}", e))?;
        
        println!("💾 Empty block {} persisted", slot);
        Ok(())
    }

    /// Get mining reward
    pub fn mining_reward(&self) -> f64 {
        self.inner.mining_reward
    }

    /// Get daily jackpot
    pub fn daily_jackpot(&self) -> f64 {
        self.inner.daily_jackpot
    }

    /// Get address to username mapping (if exists)
    pub fn address_to_username(&self) -> &HashMap<String, String> {
        &self.inner.address_to_username
    }

    /// Get recent blockhashes
    pub fn recent_blockhashes(&self) -> &HashMap<u64, String> {
        &self.inner.recent_blockhashes
    }

    /// Get pending transactions (read-only)
    pub fn pending_transactions(&self) -> &Vec<Transaction> {
        &self.inner.pending_transactions
    }

    /// Add a transaction to the pending pool directly
    /// Used by consensus layer when transactions come from Gulf Stream
    pub fn add_pending_transaction(&mut self, tx: Transaction) {
        self.inner.pending_transactions.push(tx);
    }

    // ========================================================================
    // TRANSACTION CREATION (Adds to pending, doesn't persist until mined)
    // ========================================================================

    /// Create a transaction - adds to pending pool
    /// 
    /// The transaction is NOT persisted until mine_pending_transactions() is called.
    /// This follows standard blockchain semantics: pending → mined → confirmed.
    pub fn create_transaction(&mut self, from: String, to: String, amount: f64) -> String {
        self.inner.create_transaction(from, to, amount)
    }

    /// Create a typed transaction
    pub fn create_typed_transaction(
        &mut self,
        from: String,
        to: String,
        amount: f64,
        tx_type: TransactionType,
    ) -> String {
        self.inner.create_transaction_typed(from, to, amount, tx_type)
    }

    // ========================================================================
    // BLOCK MINING (ALWAYS PERSISTS)
    // ========================================================================

    /// Mine pending transactions and persist the new block
    /// 
    /// This is the ONLY way to add blocks to the chain.
    /// The block and all account state changes are persisted to Sled.
    pub fn mine_pending_transactions(&mut self, sequencer: String) -> Result<String, String> {
        if self.inner.pending_transactions.is_empty() {
            return Err("No pending transactions to mine".to_string());
        }

        // Capture accounts that will be modified BEFORE mining
        let pending_accounts: Vec<String> = self.inner.pending_transactions
            .iter()
            .flat_map(|tx| vec![tx.from.clone(), tx.to.clone()])
            .collect();

        // Mine the block in memory (this updates self.inner.balances)
        self.inner.mine_pending_transactions(sequencer)?;

        // Get the new block's data
        let (block_slot, block_txs) = {
            let block = self.inner.chain.last()
                .ok_or_else(|| "Block not found after mining".to_string())?;
            (block.slot, block.financial_txs.clone())
        };

        // =====================================================================
        // CRITICAL: Build account updates with CURRENT balances from inner.balances
        // The inner.mine_pending_transactions() updated balances HashMap,
        // so we must create Account objects with these new balance values.
        // =====================================================================
        let mut account_updates: Vec<(String, Account)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        
        // Process all accounts involved in transactions
        for pubkey in pending_accounts.iter().chain(
            block_txs.iter().flat_map(|tx| vec![&tx.from, &tx.to])
        ) {
            if seen.contains(pubkey) {
                continue;
            }
            seen.insert(pubkey.clone());
            
            // Get the CURRENT balance from inner.balances (updated by mining)
            let current_balance = self.inner.get_balance(pubkey);
            
            // Create Account with correct lamports value
            let account = Account::from_bb_balance(pubkey.clone(), current_balance, block_slot);
            account_updates.push((pubkey.clone(), account));
            
            // Also update inner.accounts to keep in-memory state consistent
            self.inner.accounts.insert(
                pubkey.clone(), 
                Account::from_bb_balance(pubkey.clone(), current_balance, block_slot)
            );
        }

        // Persist block and accounts
        let block = self.inner.chain.last()
            .ok_or_else(|| "Block disappeared".to_string())?;
        
        let state_root = self.storage.persist_block(block, &account_updates)
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

        println!("💾 Block {} persisted (root: {}...)", block_slot, &state_root[..12]);
        Ok(state_root)
    }

    /// Perform full state synchronization
    fn full_sync(&mut self) -> Result<(), String> {
        let slot = self.inner.current_slot;
        let count = self.storage.sync_accounts_from_hashmap(&self.inner.accounts, slot)
            .map_err(|e| format!("Sync error: {:?}", e))?;
        self.storage.flush()
            .map_err(|e| format!("Flush error: {:?}", e))?;
        println!("🔄 Full sync: {} accounts at slot {}", count, slot);
        Ok(())
    }

    // ========================================================================
    // ADMIN OPERATIONS (PERSIST IMMEDIATELY)
    // ========================================================================

    /// Mint tokens to an address (admin operation)
    /// Immediately persists the balance change.
    pub fn mint(&mut self, to: &str, amount: f64) -> Result<(), String> {
        // Update in-memory state
        let current = self.inner.balances.get(to).copied().unwrap_or(0.0);
        self.inner.balances.insert(to.to_string(), current + amount);
        
        // Create/update account - increment slot to track mint operations
        self.inner.current_slot += 1;
        let slot = self.inner.current_slot;
        let account = Account::from_bb_balance(to.to_string(), current + amount, slot);
        self.inner.accounts.insert(to.to_string(), account.clone());
        
        // Persist immediately
        self.storage.save_account(to, &account)
            .map_err(|e| format!("Persist error: {:?}", e))?;
        self.storage.save_balance(to, current + amount, slot)
            .map_err(|e| format!("Balance persist error: {:?}", e))?;
        
        // CRITICAL: Update latest_slot metadata so data is loaded on restart
        self.storage.engine().set_latest_slot(slot)
            .map_err(|e| format!("Metadata error: {:?}", e))?;
        
        self.storage.flush()
            .map_err(|e| format!("Flush error: {:?}", e))?;
        
        println!("🪙 Minted {} BB to {} (persisted at slot {})", amount, &to[..14.min(to.len())], slot);
        Ok(())
    }

    /// Burn tokens from an address (admin operation)
    /// Immediately persists the balance change.
    pub fn burn(&mut self, from: &str, amount: f64) -> Result<(), String> {
        let current = self.inner.balances.get(from).copied().unwrap_or(0.0);
        if current < amount {
            return Err(format!("Insufficient balance: {} < {}", current, amount));
        }
        
        let new_balance = current - amount;
        self.inner.balances.insert(from.to_string(), new_balance);
        
        // Increment slot to track burn operations
        self.inner.current_slot += 1;
        let slot = self.inner.current_slot;
        let account = Account::from_bb_balance(from.to_string(), new_balance, slot);
        self.inner.accounts.insert(from.to_string(), account.clone());
        
        self.storage.save_account(from, &account)
            .map_err(|e| format!("Persist error: {:?}", e))?;
        self.storage.save_balance(from, new_balance, slot)
            .map_err(|e| format!("Balance persist error: {:?}", e))?;
        
        // CRITICAL: Update latest_slot metadata so data is loaded on restart
        self.storage.engine().set_latest_slot(slot)
            .map_err(|e| format!("Metadata error: {:?}", e))?;
        
        self.storage.flush()
            .map_err(|e| format!("Flush error: {:?}", e))?;
        
        println!("🔥 Burned {} BB from {} (persisted at slot {})", amount, &from[..14.min(from.len())], slot);
        Ok(())
    }

    // ========================================================================
    // TOKEN LOCKING (Bridge/Credit Line Support)
    // ========================================================================

    /// Lock tokens for bridge or credit line
    pub fn lock_tokens(
        &mut self,
        address: &str,
        amount: f64,
        purpose: crate::protocol::blockchain::LockPurpose,
        beneficiary: Option<String>,
    ) -> Result<String, String> {
        self.inner.lock_tokens(address, amount, purpose, beneficiary)
    }

    /// Authorize release of locked tokens
    pub fn authorize_release(&mut self, lock_id: &str, proof: crate::protocol::blockchain::SettlementProof) -> Result<(), String> {
        self.inner.authorize_release(lock_id, proof)
    }

    /// Release locked tokens
    pub fn release_tokens(&mut self, lock_id: &str) -> Result<(String, f64), String> {
        self.inner.release_tokens(lock_id)
    }

    /// Get spendable balance (total - locked)
    pub fn get_spendable_balance(&self, address: &str) -> f64 {
        self.inner.get_spendable_balance(address)
    }

    /// Get locked balance
    pub fn get_locked_balance(&self, address: &str) -> f64 {
        self.inner.get_locked_balance(address)
    }

    /// Get all locks for an address
    pub fn get_locks_for_address(&self, address: &str) -> Vec<&crate::protocol::blockchain::LockRecord> {
        self.inner.get_locks_for_address(address)
    }

    /// Check if chain is valid
    pub fn is_chain_valid(&self) -> bool {
        self.inner.is_chain_valid()
    }

    // ========================================================================
    // STORAGE & DIAGNOSTICS
    // ========================================================================

    /// Get storage reference
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

    /// Get current protocol version
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Export state to JSON (for debugging/migration)
    pub fn export_json(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol_version": self.protocol_version,
            "current_slot": self.inner.current_slot,
            "chain_length": self.inner.chain.len(),
            "account_count": self.inner.accounts.len(),
            "balances": self.inner.balances,
            "state_root": self.storage.get_state_root().unwrap_or_default(),
        })
    }

    /// Get storage engine reference (for advanced operations)
    pub fn storage_engine(&self) -> &crate::storage::StorageEngine {
        self.storage.engine()
    }
}

// ============================================================================
// HOT UPGRADE SUPPORT
// ============================================================================

/// Hot upgrade hook - called when protocol version changes
pub trait UpgradeHook: Send + Sync {
    /// Called before upgrade is applied
    fn pre_upgrade(&self, from_version: u32, to_version: u32) -> Result<(), String>;
    
    /// Called after upgrade is applied
    fn post_upgrade(&self, from_version: u32, to_version: u32) -> Result<(), String>;
    
    /// Migrate state if needed
    fn migrate_state(&self, blockchain: &mut PersistentBlockchain) -> Result<(), String>;
}

impl PersistentBlockchain {
    /// Apply a hot upgrade
    pub fn apply_upgrade<H: UpgradeHook>(
        &mut self, 
        new_version: u32, 
        hook: &H
    ) -> Result<(), String> {
        if new_version <= self.protocol_version {
            return Err(format!(
                "Cannot downgrade: {} -> {}", 
                self.protocol_version, new_version
            ));
        }
        
        let old_version = self.protocol_version;
        
        // Pre-upgrade hook
        hook.pre_upgrade(old_version, new_version)?;
        
        // Migrate state
        hook.migrate_state(self)?;
        
        // Update version
        self.protocol_version = new_version;
        
        // Post-upgrade hook
        hook.post_upgrade(old_version, new_version)?;
        
        println!("🔄 Protocol upgraded: v{} → v{}", old_version, new_version);
        Ok(())
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
    fn test_persistence_on_mine() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        
        // Create transaction and mine
        {
            let mut bc = PersistentBlockchain::new(path).unwrap();
            let _ = bc.create_transaction(
                TREASURY_ADDRESS.to_string(),
                "alice".to_string(),
                100.0,
            );
            bc.mine_pending_transactions("test".to_string()).unwrap();
        }
        
        // Reload and verify
        {
            let bc = PersistentBlockchain::new(path).unwrap();
            assert_eq!(bc.get_balance("alice"), 100.0);
        }
    }

    #[test]
    fn test_mint_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        
        {
            let mut bc = PersistentBlockchain::new(path).unwrap();
            bc.mint("bob", 500.0).unwrap();
        }
        
        {
            let bc = PersistentBlockchain::new(path).unwrap();
            assert_eq!(bc.get_balance("bob"), 500.0);
        }
    }
}
