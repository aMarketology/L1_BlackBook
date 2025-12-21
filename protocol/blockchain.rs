//! Blockchain Core - EnhancedBlockchain
//!
//! The main blockchain implementation with two-lane transaction architecture
//! (Financial + Social) and Turbine block propagation.
//!
//! Block and Transaction types are defined in runtime/core.rs (single source of truth).
//!
//! INFRASTRUCTURE NOTE: TurbineService is wired to ServiceCoordinator for block
//! shredding and propagation simulation. Full P2P will be enabled for mainnet.
#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use borsh::{BorshSerialize, BorshDeserialize};
use dashmap::DashMap;

// Import core types from runtime (SINGLE SOURCE OF TRUTH)
pub use crate::runtime::core::{Block, Transaction, TransactionType};

// ============================================================================
// TURBINE CONSTANTS
// ============================================================================

/// Maximum size of a shred in bytes (Solana uses ~1KB)
const SHRED_SIZE: usize = 1024;
/// Number of data shreds before generating coding shreds
const DATA_SHREDS_PER_FEC: usize = 32;
/// Forward fanout - number of peers to forward each shred to
const TURBINE_FANOUT: usize = 200;
/// Retransmit layers in the tree
const TURBINE_LAYERS: usize = 3;

// ============================================================================
// ACCOUNT STRUCTURE - Solana-style Account Model
// ============================================================================
//
// Each account tracks:
// - lamports: Balance in smallest unit (1 BB = 1_000_000 lamports)
// - nonce: Per-account transaction counter for replay protection
// - owner: Program/authority that owns this account
// - data_hash: Hash of account data (for verification)
// - created_slot: Slot when account was created
// - last_modified_slot: Last slot account was modified
//
// This enables:
// - Per-account nonces (no global nonce tracking needed)
// - Rent-exempt checking
// - Account ownership verification
// - State proofs via data_hash
// ============================================================================

/// Lamports per BB token (1 BB = 1,000,000 lamports)
pub const LAMPORTS_PER_BB: u64 = 1_000_000;

/// Minimum lamports for rent exemption (0.001 BB)
pub const RENT_EXEMPT_MINIMUM: u64 = 1_000;

/// Solana-style Account structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Balance in lamports (1 BB = 1_000_000 lamports)
    pub lamports: u64,
    
    /// Per-account transaction nonce (monotonically increasing)
    /// Each transaction from this account must have nonce > last_nonce
    pub nonce: u64,
    
    /// Owner/authority of this account (pubkey of program or user)
    pub owner: String,
    
    /// Hash of account data (for verification without full data)
    pub data_hash: String,
    
    /// Slot when account was created
    pub created_slot: u64,
    
    /// Last slot when account was modified
    pub last_modified_slot: u64,
    
    /// Is this account rent-exempt? (has minimum balance)
    pub rent_exempt: bool,
}

impl Account {
    /// Create a new account with initial balance
    pub fn new(owner: String, lamports: u64, current_slot: u64) -> Self {
        let rent_exempt = lamports >= RENT_EXEMPT_MINIMUM;
        Self {
            lamports,
            nonce: 0,
            owner,
            data_hash: String::new(),
            created_slot: current_slot,
            last_modified_slot: current_slot,
            rent_exempt,
        }
    }
    
    /// Create account from BB balance (converts to lamports)
    pub fn from_bb_balance(owner: String, bb_balance: f64, current_slot: u64) -> Self {
        let lamports = (bb_balance * LAMPORTS_PER_BB as f64) as u64;
        Self::new(owner, lamports, current_slot)
    }
    
    /// Get balance in BB tokens
    pub fn balance_bb(&self) -> f64 {
        self.lamports as f64 / LAMPORTS_PER_BB as f64
    }
    
    /// Increment nonce and return the new value
    pub fn increment_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }
    
    /// Check if a transaction nonce is valid (must be > current nonce)
    pub fn is_nonce_valid(&self, tx_nonce: u64) -> bool {
        tx_nonce > self.nonce
    }
    
    /// Debit lamports from account
    pub fn debit(&mut self, amount: u64, slot: u64) -> Result<(), String> {
        if self.lamports < amount {
            return Err(format!(
                "Insufficient balance: have {} lamports, need {}",
                self.lamports, amount
            ));
        }
        self.lamports -= amount;
        self.last_modified_slot = slot;
        self.rent_exempt = self.lamports >= RENT_EXEMPT_MINIMUM;
        Ok(())
    }
    
    /// Credit lamports to account
    pub fn credit(&mut self, amount: u64, slot: u64) {
        self.lamports += amount;
        self.last_modified_slot = slot;
        self.rent_exempt = self.lamports >= RENT_EXEMPT_MINIMUM;
    }
    
    /// Debit in BB tokens
    pub fn debit_bb(&mut self, amount: f64, slot: u64) -> Result<(), String> {
        let lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        self.debit(lamports, slot)
    }
    
    /// Credit in BB tokens
    pub fn credit_bb(&mut self, amount: f64, slot: u64) {
        let lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        self.credit(lamports, slot);
    }
}

// ============================================================================
// ENHANCED BLOCKCHAIN
// ============================================================================

/// Number of recent blockhashes to retain (for transaction validation)
pub const RECENT_BLOCKHASH_SLOTS: u64 = 150;

// ============================================================================
// LOCK RECORD - Escrow for Cross-Layer Bridge Operations
// ============================================================================

/// Represents locked tokens in escrow (for L1↔L2 bridge)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    pub lock_id: String,
    pub owner: String,               // L1 address that locked the tokens
    pub amount: f64,
    pub purpose: LockPurpose,
    pub created_at: u64,             // Unix timestamp
    pub created_slot: u64,           // L1 slot when locked
    pub release_authorized: bool,   // True if L2 has verified settlement
    pub settlement_proof: Option<SettlementProof>,
    pub released_at: Option<u64>,    // Unix timestamp when released
    pub beneficiary: Option<String>, // Who receives tokens on release (can differ from owner)
}

/// Purpose of the lock (determines validation rules)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LockPurpose {
    BridgeToL2,          // User bridging to L2 for gaming
    MarketEscrow,        // Funds locked for an active market/bet
    SettlementPending,   // Market resolved, awaiting payout
}

/// Proof from L2 that a settlement is valid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    pub market_id: String,
    pub outcome: String,
    pub l2_block_height: u64,
    pub l2_signature: String,        // Ed25519 signature from L2 authority
    pub verified_at: u64,            // When L1 verified this proof
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedBlockchain {
    pub chain: Vec<Block>,
    pub pending_transactions: Vec<Transaction>,
    pub balances: HashMap<String, f64>,
    pub mining_reward: f64,
    pub daily_jackpot: f64,
    pub jackpot_last_reset: u64,
    #[serde(default)]
    pub current_slot: u64,
    #[serde(default)]
    pub current_poh_hash: String,
    #[serde(default)]
    pub engagement_stakes: HashMap<String, f64>,
    #[serde(default)]
    pub username_balances: HashMap<String, f64>,
    #[serde(default)]
    pub address_to_username: HashMap<String, String>,
    
    // ========== NEW: Account Model ==========
    /// Proper account storage with per-account nonces
    #[serde(default)]
    pub accounts: HashMap<String, Account>,
    
    /// Recent blockhashes for transaction validation (slot -> hash)
    #[serde(default)]
    pub recent_blockhashes: HashMap<u64, String>,
    
    // ========== BRIDGE ESCROW ==========
    /// Locked balances (tokens in escrow, not spendable)
    #[serde(default)]
    pub locked_balances: HashMap<String, f64>,
    
    /// Lock records for audit trail and verification
    #[serde(default)]
    pub lock_records: HashMap<String, LockRecord>,
}

impl EnhancedBlockchain {
    pub fn new() -> Self {
        let mut blockchain = Self {
            chain: Vec::new(),
            pending_transactions: Vec::new(),
            balances: HashMap::new(),
            mining_reward: 10.0,
            daily_jackpot: 0.0,
            jackpot_last_reset: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            current_slot: 0,
            current_poh_hash: "genesis".to_string(),
            engagement_stakes: HashMap::new(),
            username_balances: HashMap::new(),
            address_to_username: HashMap::new(),
            accounts: HashMap::new(),
            recent_blockhashes: HashMap::new(),
            locked_balances: HashMap::new(),
            lock_records: HashMap::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }
    
    fn create_genesis_block(&mut self) {
        let genesis_seed = format!("layer1_genesis_v2_poh_{}", 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        let poh_hash = format!("{:x}", Sha256::digest(genesis_seed.as_bytes()));
        
        let genesis_block = Block {
            index: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            previous_hash: "0".to_string(),
            hash: poh_hash.clone(),
            slot: 0,
            poh_hash: poh_hash.clone(),
            parent_slot: 0,
            sequencer: "genesis".to_string(),
            leader: "genesis".to_string(),
            financial_txs: Vec::new(),
            social_txs: Vec::new(),
            transactions: Vec::new(),
            engagement_score: 0.0,
            tx_count: 0,
        };
        
        self.chain.push(genesis_block);
        self.current_poh_hash = poh_hash.clone();
        
        // Store genesis blockhash for transaction validation
        self.add_recent_blockhash(0, poh_hash);
        
        println!("🌱 PoH Genesis block created (Slot 0)");
    }
    
    pub fn create_transaction(&mut self, from: String, to: String, amount: f64) -> String {
        let transaction_id = Uuid::new_v4().to_string();
        
        let read_accounts = vec![from.clone()];
        let write_accounts = vec![from.clone(), to.clone()];
        
        let transaction = Transaction {
            id: transaction_id.clone(),
            from: from.clone(),
            to: to.clone(),
            amount,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            signature: String::new(),
            read_accounts,
            write_accounts,
            tx_type: TransactionType::Transfer,
        };
        
        if from != "system" && from != "reward_system" && from != "signup_bonus" {
            let from_balance = self.balances.get(&from).unwrap_or(&0.0);
            if *from_balance >= amount {
                if to == "burned_tokens" {
                    self.balances.remove(&from);
                } else {
                    self.balances.insert(from.clone(), from_balance - amount);
                }
            } else {
                return format!("Insufficient balance for {}", from);
            }
        }
        
        if to == "burned_tokens" {
            println!("🔥 {} L1 tokens burned from deleted wallet {}", amount, from);
        } else {
            if from == "signup_bonus" {
                self.balances.insert(to.clone(), amount);
                println!("🎉 Signup bonus granted: {} -> {} L1 (Fresh wallet)", to, amount);
            } else {
                self.balances.entry(to.clone())
                    .and_modify(|balance| *balance += amount)
                    .or_insert(amount);
            }
        }
        
        self.pending_transactions.push(transaction);
        
        println!("💰 Transaction created: {} -> {} ({} L1)", from, to, amount);
        transaction_id
    }
    
    pub fn get_balance(&self, address: &str) -> f64 {
        let canonical_address = self.normalize_to_l1_address(address);
        
        if let Some(username) = self.address_to_username.get(&canonical_address) {
            return *self.username_balances.get(username).unwrap_or(&0.0);
        }
        
        *self.balances.get(&canonical_address).unwrap_or(&0.0)
    }
    
    pub fn normalize_to_l1_address(&self, address: &str) -> String {
        // Support multiple address formats:
        // 1. L1_XXXX...XXXX (current format, 43 chars: L1_ + 40 hex)
        // 2. L1XXXX...XXXX (legacy format, 42 chars: L1 + 40 hex)
        // 3. L2_XXX (Layer2, convert to L1)
        // 4. bb2_XXX (old Layer2, convert to L1)
        // 5. Raw public key hex (64 chars)
        
        if address.starts_with("L1_") && address.len() == 43 {
            // Current format (43 chars: L1_ + 40 hex)
            address.to_string()
        } else if address.starts_with("L1") && address.len() == 42 {
            // Legacy format without underscore - convert to new format
            format!("L1_{}", &address[2..])
        } else if address.starts_with("L2_") {
            // L2 address - convert to L1 (same hash)
            format!("L1_{}", &address[3..])
        } else if address.starts_with("bb2_") {
            // Old Layer2 address - convert to L1
            format!("L1_{}", &address[4..])
        } else if address.len() == 64 && address.chars().all(|c| c.is_ascii_hexdigit()) {
            // Raw public key - generate L1 address
            crate::protocol::helpers::generate_l1_address(address)
        } else {
            // Unknown format - return as-is
            address.to_string()
        }
    }
    
    pub fn register_user_address(&mut self, username: &str, address: &str) {
        println!("📝 Registering unified balance for user: {}", username);
        println!("   Address: {}", address);
        
        self.address_to_username.insert(address.to_string(), username.to_string());
        
        let existing_address_balance = *self.balances.get(address).unwrap_or(&0.0);
        let existing_username_balance = *self.username_balances.get(username).unwrap_or(&0.0);
        
        let total = existing_address_balance.max(existing_username_balance);
        
        if total > 0.0 {
            self.username_balances.insert(username.to_string(), total);
            self.balances.insert(address.to_string(), total);
            println!("   Migrated balance: {} $BB", total);
        }
    }
    
    pub fn get_balance_by_username(&self, username: &str) -> f64 {
        *self.username_balances.get(username).unwrap_or(&0.0)
    }
    
    pub fn set_user_balance(&mut self, username: &str, address: &str, amount: f64) {
        self.username_balances.insert(username.to_string(), amount);
        self.balances.insert(address.to_string(), amount);
    }
    
    pub fn add_to_user_balance(&mut self, username: &str, address: &str, amount: f64) {
        let current = self.get_balance_by_username(username);
        self.set_user_balance(username, address, current + amount);
    }
    
    pub fn subtract_from_user_balance(&mut self, username: &str, address: &str, amount: f64) -> Result<(), String> {
        let current = self.get_balance_by_username(username);
        if current < amount {
            return Err(format!("Insufficient balance: {} $BB available, {} $BB required", current, amount));
        }
        self.set_user_balance(username, address, current - amount);
        Ok(())
    }
    
    // ========== ACCOUNT MODEL METHODS ==========
    
    /// Get or create an account for an address
    pub fn get_or_create_account(&mut self, address: &str) -> &mut Account {
        let current_slot = self.current_slot;
        let balance_bb = self.get_balance(address);
        
        self.accounts.entry(address.to_string()).or_insert_with(|| {
            Account::from_bb_balance(address.to_string(), balance_bb, current_slot)
        })
    }
    
    /// Get account if it exists (read-only)
    pub fn get_account(&self, address: &str) -> Option<&Account> {
        self.accounts.get(address)
    }
    
    /// Validate transaction nonce against account
    pub fn validate_account_nonce(&self, address: &str, tx_nonce: u64) -> Result<(), String> {
        if let Some(account) = self.accounts.get(address) {
            if !account.is_nonce_valid(tx_nonce) {
                return Err(format!(
                    "Invalid nonce: expected > {}, got {}",
                    account.nonce, tx_nonce
                ));
            }
        }
        // If account doesn't exist, any nonce > 0 is valid
        Ok(())
    }
    
    /// Update account nonce after successful transaction
    pub fn update_account_nonce(&mut self, address: &str, new_nonce: u64) {
        if let Some(account) = self.accounts.get_mut(address) {
            if new_nonce > account.nonce {
                account.nonce = new_nonce;
                account.last_modified_slot = self.current_slot;
            }
        }
    }
    
    /// Sync account balance from legacy balances HashMap
    pub fn sync_account_balance(&mut self, address: &str) {
        let balance_bb = self.get_balance(address);
        let current_slot = self.current_slot;
        
        if let Some(account) = self.accounts.get_mut(address) {
            let new_lamports = (balance_bb * LAMPORTS_PER_BB as f64) as u64;
            if account.lamports != new_lamports {
                account.lamports = new_lamports;
                account.last_modified_slot = current_slot;
                account.rent_exempt = account.lamports >= RENT_EXEMPT_MINIMUM;
            }
        }
    }
    
    // ========== RECENT BLOCKHASH METHODS ==========
    
    /// Add a new blockhash and prune old ones
    pub fn add_recent_blockhash(&mut self, slot: u64, hash: String) {
        self.recent_blockhashes.insert(slot, hash);
        
        // Prune hashes older than RECENT_BLOCKHASH_SLOTS
        if self.recent_blockhashes.len() > (RECENT_BLOCKHASH_SLOTS as usize * 2) {
            let min_slot = slot.saturating_sub(RECENT_BLOCKHASH_SLOTS);
            self.recent_blockhashes.retain(|&s, _| s >= min_slot);
        }
    }
    
    /// Get the most recent blockhash
    pub fn get_recent_blockhash(&self) -> Option<(u64, String)> {
        self.recent_blockhashes.iter()
            .max_by_key(|(slot, _)| *slot)
            .map(|(slot, hash)| (*slot, hash.clone()))
    }
    
    /// Validate that a blockhash is recent (within RECENT_BLOCKHASH_SLOTS)
    pub fn is_blockhash_valid(&self, blockhash: &str) -> bool {
        let current_slot = self.current_slot;
        
        self.recent_blockhashes.iter().any(|(slot, hash)| {
            hash == blockhash && current_slot.saturating_sub(*slot) <= RECENT_BLOCKHASH_SLOTS
        })
    }
    
    /// Get the slot for a blockhash
    pub fn get_blockhash_slot(&self, blockhash: &str) -> Option<u64> {
        self.recent_blockhashes.iter()
            .find(|(_, hash)| *hash == blockhash)
            .map(|(slot, _)| *slot)
    }
    
    // ========== BRIDGE ESCROW METHODS ==========
    
    /// Lock tokens in escrow for cross-layer bridge operations
    /// Returns the lock_id on success
    pub fn lock_tokens(
        &mut self,
        owner: &str,
        amount: f64,
        purpose: LockPurpose,
        beneficiary: Option<String>,
    ) -> Result<String, String> {
        // Check spendable balance
        let available = self.get_spendable_balance(owner);
        if available < amount {
            return Err(format!(
                "Insufficient spendable balance: {} BB available, {} BB requested",
                available, amount
            ));
        }
        
        // Generate unique lock_id
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lock_id = format!(
            "lock_{}_{}_{}", 
            now,
            self.current_slot,
            &owner[..owner.len().min(8)]
        );
        
        // Deduct from spendable balance
        *self.balances.entry(owner.to_string()).or_insert(0.0) -= amount;
        
        // Add to locked balance
        *self.locked_balances.entry(owner.to_string()).or_insert(0.0) += amount;
        
        // Create lock record
        let lock_record = LockRecord {
            lock_id: lock_id.clone(),
            owner: owner.to_string(),
            amount,
            purpose,
            created_at: now,
            created_slot: self.current_slot,
            release_authorized: false,
            settlement_proof: None,
            released_at: None,
            beneficiary,
        };
        
        self.lock_records.insert(lock_id.clone(), lock_record);
        
        println!("🔒 Locked {} BB from {} (lock_id: {})", amount, owner, lock_id);
        Ok(lock_id)
    }
    
    /// Authorize release of locked tokens (called after L2 verifies settlement)
    pub fn authorize_release(
        &mut self,
        lock_id: &str,
        proof: SettlementProof,
    ) -> Result<(), String> {
        let lock = self.lock_records.get_mut(lock_id)
            .ok_or_else(|| format!("Lock not found: {}", lock_id))?;
        
        if lock.release_authorized {
            return Err("Lock already authorized for release".to_string());
        }
        
        lock.release_authorized = true;
        lock.settlement_proof = Some(proof);
        
        println!("✅ Release authorized for lock_id: {}", lock_id);
        Ok(())
    }
    
    /// Release locked tokens after authorization
    /// Tokens go to beneficiary if set, otherwise back to owner
    pub fn release_tokens(&mut self, lock_id: &str) -> Result<(String, f64), String> {
        // Get lock info (need to clone to avoid borrow issues)
        let lock = self.lock_records.get(lock_id)
            .ok_or_else(|| format!("Lock not found: {}", lock_id))?
            .clone();
        
        if !lock.release_authorized {
            return Err("Release not authorized. Call authorize_release first.".to_string());
        }
        
        if lock.released_at.is_some() {
            return Err("Tokens already released".to_string());
        }
        
        let recipient = lock.beneficiary.clone().unwrap_or_else(|| lock.owner.clone());
        let amount = lock.amount;
        
        // Remove from locked balance
        if let Some(locked) = self.locked_balances.get_mut(&lock.owner) {
            *locked -= amount;
            if *locked <= 0.0 {
                self.locked_balances.remove(&lock.owner);
            }
        }
        
        // Credit recipient's spendable balance
        *self.balances.entry(recipient.clone()).or_insert(0.0) += amount;
        
        // Update lock record
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(lock_record) = self.lock_records.get_mut(lock_id) {
            lock_record.released_at = Some(now);
        }
        
        println!("🔓 Released {} BB to {} (lock_id: {})", amount, recipient, lock_id);
        Ok((recipient, amount))
    }
    
    /// Get spendable balance (total - locked)
    pub fn get_spendable_balance(&self, address: &str) -> f64 {
        let total = *self.balances.get(address).unwrap_or(&0.0);
        let locked = *self.locked_balances.get(address).unwrap_or(&0.0);
        total.max(0.0) // locked is already subtracted in lock_tokens
    }
    
    /// Get locked balance for an address
    pub fn get_locked_balance(&self, address: &str) -> f64 {
        *self.locked_balances.get(address).unwrap_or(&0.0)
    }
    
    /// Get a lock record by ID
    pub fn get_lock_record(&self, lock_id: &str) -> Option<&LockRecord> {
        self.lock_records.get(lock_id)
    }
    
    /// Get all lock records for an address
    pub fn get_locks_for_address(&self, address: &str) -> Vec<&LockRecord> {
        self.lock_records.values()
            .filter(|lock| lock.owner == address && lock.released_at.is_none())
            .collect()
    }

    fn calculate_block_engagement_score(&self, transactions: &[Transaction]) -> f64 {
        transactions.iter().map(|tx| self.calculate_transaction_engagement_score(tx)).sum()
    }
    
    fn calculate_transaction_engagement_score(&self, transaction: &Transaction) -> f64 {
        let mut score = 1.0;
        
        match transaction.from.as_str() {
            "post_creation" => score += 5.0,
            "like_action" => score += 1.0,
            "comment_action" => score += 3.0,
            "share_action" => score += 2.0,
            "follow_action" => score += 1.5,
            "daily_login" => score += 0.5,
            "profile_update" => score += 1.0,
            _ => score += 0.1,
        }
        
        let hours_since_epoch = transaction.timestamp / 3600;
        let daily_activity_bonus = (hours_since_epoch % 24) as f64 * 0.1;
        score += daily_activity_bonus;
        
        let amount_score = (transaction.amount * 0.1).min(2.0);
        score += amount_score;
        
        score
    }
    
    pub fn mine_pending_transactions(&mut self, sequencer: String) -> Result<(), String> {
        if self.pending_transactions.is_empty() {
            return Err("No pending transactions to commit".to_string());
        }
        
        let transactions = self.pending_transactions.clone();
        self.pending_transactions.clear();
        
        let previous_hash = self.chain.last().map(|b| b.hash.clone()).unwrap_or_else(|| "0".to_string());
        let parent_slot = self.chain.last().map(|b| b.slot).unwrap_or(0);
        
        self.current_slot += 1;
        let tick_input = format!("{}:{}:{}", self.current_poh_hash, self.current_slot, 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        self.current_poh_hash = format!("{:x}", Sha256::digest(tick_input.as_bytes()));
        
        let engagement_score = self.calculate_block_engagement_score(&transactions);
        let engagement_threshold = 5.0;
        
        if engagement_score >= engagement_threshold {
            let (financial_txs, social_txs): (Vec<_>, Vec<_>) = transactions.into_iter()
                .partition(|tx| matches!(tx.tx_type, 
                    TransactionType::Transfer | 
                    TransactionType::BetPlacement | 
                    TransactionType::BetResolution |
                    TransactionType::StakeDeposit |
                    TransactionType::StakeWithdraw |
                    TransactionType::SystemReward
                ));
            
            let tx_count = (financial_txs.len() + social_txs.len()) as u64;
            
            // Combine transactions for backward compatibility
            let mut all_txs = financial_txs.clone();
            all_txs.extend(social_txs.clone());
            
            let mut new_block = Block {
                index: self.chain.len() as u64,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                previous_hash,
                hash: String::new(),
                slot: self.current_slot,
                poh_hash: self.current_poh_hash.clone(),
                parent_slot,
                sequencer: sequencer.clone(),
                leader: sequencer.clone(),
                financial_txs: financial_txs.clone(),
                social_txs: social_txs.clone(),
                transactions: all_txs,
                engagement_score,
                tx_count,
            };
            
            let hash_input = format!("{}{}{}{}{}{}{}{}", 
                new_block.index, 
                new_block.timestamp, 
                new_block.poh_hash,
                serde_json::to_string(&new_block.financial_txs).unwrap_or_default(),
                serde_json::to_string(&new_block.social_txs).unwrap_or_default(),
                new_block.previous_hash, 
                new_block.sequencer,
                engagement_score as u64
            );
            new_block.hash = format!("{:x}", Sha256::digest(hash_input.as_bytes()));
            
            for tx in &financial_txs {
                if tx.from != "system" && tx.from != "reward_system" && tx.from != "signup_bonus" {
                    self.balances.entry(tx.from.clone())
                        .and_modify(|b| *b -= tx.amount);
                }
                self.balances.entry(tx.to.clone())
                    .and_modify(|b| *b += tx.amount)
                    .or_insert(tx.amount);
            }
            
            self.chain.push(new_block.clone());
            
            // Store blockhash for transaction validation
            self.add_recent_blockhash(self.current_slot, new_block.hash.clone());
            
            let stake = (1.0 + engagement_score).ln();
            self.engagement_stakes.entry(sequencer.clone())
                .and_modify(|s| *s += stake)
                .or_insert(stake);
            
            let engagement_reward = (engagement_score * 2.0).min(50.0);
            self.balances.entry(sequencer.clone())
                .and_modify(|balance| *balance += engagement_reward)
                .or_insert(engagement_reward);
                
            println!("⚡ Slot {} committed (💰{} 💬{} Engagement: {:.1}, Reward: {:.1} L1)", 
                     self.current_slot, financial_txs.len(), social_txs.len(), 
                     engagement_score, engagement_reward);
            Ok(())
        } else {
            self.pending_transactions = transactions.into_iter().collect();
            self.current_slot -= 1;
            Err(format!("Insufficient engagement score: {:.1} (required: {:.1})", 
                       engagement_score, engagement_threshold))
        }
    }
    
    pub fn is_chain_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.previous_hash != previous.hash { return false; }
        }
        true
    }
}

impl Default for EnhancedBlockchain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TURBINE - Block Propagation via Shreds
// ============================================================================
//
// Solana's Turbine protocol breaks blocks into small pieces called "shreds"
// and propagates them through a tree structure. This enables:
// 1. Parallel transmission - different shreds sent to different nodes
// 2. Erasure coding - recover blocks even with 33% packet loss
// 3. Streaming - nodes can start validating before full block arrives
// 4. Low latency - O(log n) propagation time instead of O(n)
//
// In single-node mode, we simulate this for API compatibility and metrics.

/// A shred is a small piece of a block, optimized for network transmission
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Shred {
    /// Slot this shred belongs to
    pub slot: u64,
    /// Index within the slot (0..N for data, N..M for coding)
    pub index: u32,
    /// Shred type (data or coding for FEC)
    pub shred_type: ShredType,
    /// Parent slot reference
    pub parent_slot: u64,
    /// Block hash reference
    pub block_hash: String,
    /// The actual data payload
    pub data: Vec<u8>,
    /// FEC set index for recovery grouping
    pub fec_set_index: u32,
    /// Merkle proof for this shred (future: light client verification)
    pub merkle_hash: String,
    /// Timestamp when shred was created
    pub timestamp: u64,
}

/// Type of shred - data carries block content, coding enables recovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ShredType {
    /// Contains actual block data
    Data,
    /// Forward Error Correction for recovery
    Coding,
    /// Last data shred in the slot (signals completion)
    LastInSlot,
}

/// Statistics for Turbine propagation
#[derive(Debug, Clone, Serialize)]
pub struct TurbineStats {
    pub blocks_shredded: u64,
    pub total_shreds_created: u64,
    pub data_shreds_created: u64,
    pub coding_shreds_created: u64,
    pub shreds_transmitted: u64,
    pub avg_shreds_per_block: f64,
    pub avg_shred_creation_time_us: u64,
    pub is_active: bool,
}

/// Turbine Service - Block propagation via shredding
///
/// Implements Solana-style block propagation:
/// - Breaks blocks into fixed-size shreds
/// - Adds erasure coding for recovery
/// - Simulates tree-based propagation
/// - Tracks propagation metrics
pub struct TurbineService {
    /// Pending shreds waiting to be "transmitted"
    pending_shreds: DashMap<u64, Vec<Shred>>,  // slot -> shreds
    
    /// Received shreds for block reconstruction
    received_shreds: DashMap<u64, Vec<Shred>>,  // slot -> shreds
    
    /// Statistics
    blocks_shredded: AtomicU64,
    total_shreds: AtomicU64,
    data_shreds: AtomicU64,
    coding_shreds: AtomicU64,
    shreds_transmitted: AtomicU64,
    total_shred_time_us: AtomicU64,
    
    /// Service state
    is_active: AtomicBool,
}

impl TurbineService {
    /// Create a new Turbine service
    pub fn new() -> Arc<Self> {
        println!("🌪️ Turbine Service initialized:");
        println!("   └─ shred size: {} bytes, fanout: {}, FEC every {} shreds", 
                 SHRED_SIZE, TURBINE_FANOUT, DATA_SHREDS_PER_FEC);
        
        Arc::new(Self {
            pending_shreds: DashMap::new(),
            received_shreds: DashMap::new(),
            blocks_shredded: AtomicU64::new(0),
            total_shreds: AtomicU64::new(0),
            data_shreds: AtomicU64::new(0),
            coding_shreds: AtomicU64::new(0),
            shreds_transmitted: AtomicU64::new(0),
            total_shred_time_us: AtomicU64::new(0),
            is_active: AtomicBool::new(false),
        })
    }
    
    /// Shred a block for propagation
    pub fn shred_block(&self, block: &Block) -> Vec<Shred> {
        let start = Instant::now();
        
        // Serialize block to bytes
        let block_data = match borsh::to_vec(block) {
            Ok(data) => data,
            Err(_) => {
                // Fallback to JSON if Borsh fails
                serde_json::to_vec(block).unwrap_or_default()
            }
        };
        
        let mut shreds = Vec::new();
        let mut fec_set_index = 0u32;
        let mut shred_index = 0u32;
        
        // Create data shreds
        for (i, chunk) in block_data.chunks(SHRED_SIZE).enumerate() {
            let is_last = i == (block_data.len() / SHRED_SIZE);
            
            let shred = Shred {
                slot: block.slot,
                index: shred_index,
                shred_type: if is_last { ShredType::LastInSlot } else { ShredType::Data },
                parent_slot: block.parent_slot,
                block_hash: block.hash.clone(),
                data: chunk.to_vec(),
                fec_set_index,
                merkle_hash: self.compute_merkle_hash(chunk),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            };
            
            shreds.push(shred);
            shred_index += 1;
            self.data_shreds.fetch_add(1, Ordering::Relaxed);
            
            // Generate coding shred every DATA_SHREDS_PER_FEC data shreds
            if shred_index as usize % DATA_SHREDS_PER_FEC == 0 {
                let coding_shred = self.generate_coding_shred(
                    block.slot,
                    shred_index,
                    fec_set_index,
                    &block.hash,
                    block.parent_slot,
                );
                shreds.push(coding_shred);
                shred_index += 1;
                fec_set_index += 1;
                self.coding_shreds.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Update statistics
        let shred_count = shreds.len() as u64;
        self.blocks_shredded.fetch_add(1, Ordering::Relaxed);
        self.total_shreds.fetch_add(shred_count, Ordering::Relaxed);
        self.total_shred_time_us.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        
        // Store for "transmission"
        self.pending_shreds.insert(block.slot, shreds.clone());
        
        shreds
    }
    
    /// Generate a coding shred for FEC recovery
    fn generate_coding_shred(
        &self,
        slot: u64,
        index: u32,
        fec_set_index: u32,
        block_hash: &str,
        parent_slot: u64,
    ) -> Shred {
        // Simplified FEC - in real Turbine, this would be Reed-Solomon encoded
        let fec_data = format!("FEC_{}_{}", slot, fec_set_index);
        let merkle_hash = format!("{:x}", Sha256::digest(fec_data.as_bytes()));
        
        Shred {
            slot,
            index,
            shred_type: ShredType::Coding,
            parent_slot,
            block_hash: block_hash.to_string(),
            data: fec_data.into_bytes(),
            fec_set_index,
            merkle_hash,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
        }
    }
    
    /// Compute merkle hash for a shred
    fn compute_merkle_hash(&self, data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }
    
    /// Simulate shred transmission (in multi-node, this would send over network)
    pub fn transmit_shreds(&self, slot: u64) -> usize {
        if let Some(shreds) = self.pending_shreds.get(&slot) {
            let count = shreds.len();
            
            // Simulate tree propagation - each shred goes to TURBINE_FANOUT peers
            // who then forward to their TURBINE_FANOUT peers (TURBINE_LAYERS deep)
            let simulated_transmissions = count * TURBINE_FANOUT * TURBINE_LAYERS;
            self.shreds_transmitted.fetch_add(simulated_transmissions as u64, Ordering::Relaxed);
            
            // Move to received (simulating local receipt)
            if let Some((_, shreds)) = self.pending_shreds.remove(&slot) {
                self.received_shreds.insert(slot, shreds);
            }
            
            count
        } else {
            0
        }
    }
    
    /// Receive a shred (simulates network receipt)
    pub fn receive_shred(&self, shred: Shred) {
        self.received_shreds
            .entry(shred.slot)
            .or_insert_with(Vec::new)
            .push(shred);
    }
    
    /// Try to reconstruct a block from received shreds
    pub fn try_reconstruct_block(&self, slot: u64) -> Option<Vec<u8>> {
        self.received_shreds.get(&slot).and_then(|shreds| {
            // Check if we have enough shreds (all data shreds present)
            let data_shreds: Vec<_> = shreds.iter()
                .filter(|s| matches!(s.shred_type, ShredType::Data | ShredType::LastInSlot))
                .collect();
            
            // Check for LastInSlot marker
            let has_last = shreds.iter().any(|s| s.shred_type == ShredType::LastInSlot);
            
            if has_last {
                // Sort by index and concatenate
                let mut sorted: Vec<_> = data_shreds.clone();
                sorted.sort_by_key(|s| s.index);
                
                let block_data: Vec<u8> = sorted.iter()
                    .flat_map(|s| s.data.clone())
                    .collect();
                
                Some(block_data)
            } else {
                None // Still waiting for more shreds
            }
        })
    }
    
    /// Check if a slot has all shreds
    pub fn is_slot_complete(&self, slot: u64) -> bool {
        self.received_shreds.get(&slot)
            .map(|shreds| shreds.iter().any(|s| s.shred_type == ShredType::LastInSlot))
            .unwrap_or(false)
    }
    
    /// Clear old shreds to free memory
    pub fn clear_slot(&self, slot: u64) {
        self.pending_shreds.remove(&slot);
        self.received_shreds.remove(&slot);
    }
    
    /// Start the Turbine service
    pub fn start(self: &Arc<Self>) {
        self.is_active.store(true, Ordering::Relaxed);
        println!("🌪️ Turbine service activated");
    }
    
    /// Stop the service
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::Relaxed);
    }
    
    /// Get Turbine statistics
    pub fn get_stats(&self) -> TurbineStats {
        let blocks = self.blocks_shredded.load(Ordering::Relaxed);
        let total = self.total_shreds.load(Ordering::Relaxed);
        let total_time = self.total_shred_time_us.load(Ordering::Relaxed);
        
        TurbineStats {
            blocks_shredded: blocks,
            total_shreds_created: total,
            data_shreds_created: self.data_shreds.load(Ordering::Relaxed),
            coding_shreds_created: self.coding_shreds.load(Ordering::Relaxed),
            shreds_transmitted: self.shreds_transmitted.load(Ordering::Relaxed),
            avg_shreds_per_block: if blocks > 0 { total as f64 / blocks as f64 } else { 0.0 },
            avg_shred_creation_time_us: if blocks > 0 { total_time / blocks } else { 0 },
            is_active: self.is_active.load(Ordering::Relaxed),
        }
    }
}

impl Default for TurbineService {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|arc| {
            // Clone internals for standalone use
            Self {
                pending_shreds: DashMap::new(),
                received_shreds: DashMap::new(),
                blocks_shredded: AtomicU64::new(0),
                total_shreds: AtomicU64::new(0),
                data_shreds: AtomicU64::new(0),
                coding_shreds: AtomicU64::new(0),
                shreds_transmitted: AtomicU64::new(0),
                total_shred_time_us: AtomicU64::new(0),
                is_active: AtomicBool::new(false),
            }
        })
    }
}

/// Extension trait to add shredding capability to Block
impl Block {
    /// Convert this block to shreds for Turbine propagation
    pub fn to_shreds(&self) -> Vec<Shred> {
        let service = TurbineService::new();
        service.shred_block(self)
    }
    
    /// Get estimated shred count for this block
    pub fn estimated_shred_count(&self) -> usize {
        let estimated_size = std::mem::size_of::<Block>() 
            + self.financial_txs.len() * 200  // ~200 bytes per tx
            + self.social_txs.len() * 100;    // ~100 bytes per social tx
        
        (estimated_size / SHRED_SIZE) + 1 + (estimated_size / SHRED_SIZE / DATA_SHREDS_PER_FEC)
    }
}
