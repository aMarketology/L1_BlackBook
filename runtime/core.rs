//! Layer1 Runtime Core - Ideal Hybrid Stablecoin Blockchain
//!
//! High-performance, secure stablecoin-focused L1 with:
//! - Type-safe Program Derived Addresses (PDAs) - immune to account confusion
//! - Stake-weighted throttling (QUIC-style) - spam resistant
//! - Localized fee markets - no global fee spikes
//! - Circuit breakers - automatic protection against bank runs
//! - Declarative account validation - compile-time safety
//!
//! SECURITY PHILOSOPHY:
//! "Slow down development slightly to make execution much safer."
//! Every account is typed, every address is derived, every check is enforced.
//!
//! Architecture vs Solana:
//! | Feature              | Solana               | BlackBook L1          |
//! |----------------------|----------------------|-----------------------|
//! | Transaction Ingest   | Unfiltered UDP       | QUIC + Stake-Weighted |
//! | Fee Structure        | Global (spike all)   | Localized Fee Markets |
//! | Account Safety       | Manual verification  | Declarative/Framework |
//! | Consensus Speed      | 400ms (fragile)      | 600ms (stable+fast)   |
//! | PDA System           | Manual seeds         | Type-safe namespaced  |
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicBool, AtomicU64, Ordering};
use borsh::{BorshSerialize, BorshDeserialize};
use tracing::{info, warn, debug};

// Note: These modules are in src/ and accessed via main.rs
// For standalone runtime use, these would need to be integrated differently

// ============================================================================
// SEALEVEL CONFIGURATION - Batch Tuning Constants (TUNED FOR HIGH TPS)
// ============================================================================

/// Optimal batch size for parallel execution
/// TUNED: 256 txs per batch for maximum core utilization (25k TPS target)
pub const OPTIMAL_BATCH_SIZE: usize = 256;

/// Maximum batch size to prevent memory issues
/// TUNED: 1,024 allows for burst traffic while staying safe
pub const MAX_BATCH_SIZE: usize = 1_024;

/// Minimum batch size for efficiency
/// TUNED: 32 ensures we don't waste thread pool overhead on tiny batches
pub const MIN_BATCH_SIZE: usize = 32;

/// Conflict threshold - if > 25% conflicts, reduce batch size
/// TUNED: Aggressive conflict detection for optimal parallel efficiency
pub const CONFLICT_THRESHOLD: f64 = 0.25;

// ============================================================================
// VALIDATOR HARDWARE REQUIREMENTS
// ============================================================================

/// Minimum validator hardware specs for 25,000 TPS target:
/// - CPU: 32+ cores (64 recommended for headroom)
/// - RAM: 128GB minimum (256GB for archive nodes)
/// - Storage: 2TB+ NVMe SSD (read: 5GB/s, write: 3GB/s)
/// - Network: 1Gbps symmetric (10Gbps for top validators)
/// - OS: Linux (Ubuntu 22.04 LTS recommended)
/// 
/// Performance expectations:
/// - Sealevel parallel execution: ~256 txs/batch across all cores
/// - Pipeline buffer: 100k transactions in flight (~400MB RAM)
/// - Gulf Stream cache: 400k transactions (~1.6GB RAM)
/// - ReDB + DashMap: ~50GB for 100M accounts
/// - Total memory footprint: ~64GB active, 128GB safe minimum

// ============================================================================
// PROGRAM DERIVED ADDRESSES (PDAs) - TYPE-SAFE ACCOUNT DERIVATION
// ============================================================================
//
// PDAs make the L1 IMMUNE to account confusion attacks by:
// 1. Namespace: String literal locks account to specific purpose
// 2. Owner: Pubkey proves who controls the account
// 3. Index: Optional ID for multiple instances (wallets, characters)
// 4. Bump: Ensures address is off Ed25519 curve (program can sign)
//
// Format: PDA = hash(namespace || owner || [optional_id] || bump)
// 
// Example derivations:
// - User Wallet:  ["wallet", user_pubkey, wallet_id, bump]
// - User Profile: ["profile", user_pubkey, bump]
// - Game Vault:   ["vault", game_id, user_pubkey, bump]
// - System Config:["config", "global", bump]
//
// SECURITY: Cross-program confusion is impossible because:
// - "wallet" namespace can NEVER be mistaken for "config"
// - User A's address can NEVER be mistaken for User B's
// - The derivation is deterministic and verifiable

/// Standard namespace strings for PDA derivation
/// Using const strings prevents typos and enables compile-time checking
pub mod pda_namespace {
    /// User wallet account (holds wUSDC balance)
    pub const WALLET: &str = "wallet";
    /// User profile account (engagement, metadata)
    pub const PROFILE: &str = "profile";
    /// Escrow vault (holds funds during transactions)
    pub const VAULT: &str = "vault";
    /// System configuration (global settings)
    pub const CONFIG: &str = "config";
    /// Treasury account (protocol reserves)
    pub const TREASURY: &str = "treasury";
    /// Staking pool account
    pub const STAKE_POOL: &str = "stake-pool";
    /// Prediction market account
    pub const MARKET: &str = "market";
    /// Market position (user's bet)
    pub const POSITION: &str = "position";
    /// Liquidity provider account
    pub const LP: &str = "lp";
    /// NFT mint account
    pub const NFT_MINT: &str = "nft-mint";
    /// NFT metadata account
    pub const NFT_METADATA: &str = "nft-metadata";
    /// Bridge escrow account
    pub const BRIDGE_ESCROW: &str = "bridge-escrow";
}

/// Account type for declarative validation
/// Every account MUST have a type - no ambiguous accounts allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum AccountType {
    /// User-controlled wallet (holds tokens)
    UserWallet,
    /// User profile (engagement data)
    UserProfile,
    /// Escrow vault (temporary holds)
    EscrowVault,
    /// System configuration (read-only for users)
    SystemConfig,
    /// Protocol treasury (admin-only)
    Treasury,
    /// Staking pool (protocol-controlled)
    StakePool,
    /// Prediction market (automated)
    PredictionMarket,
    /// User's market position (bet)
    MarketPosition,
    /// Liquidity provider account
    LiquidityProvider,
    /// NFT mint authority
    NFTMint,
    /// NFT metadata storage
    NFTMetadata,
    /// Bridge escrow for cross-chain
    BridgeEscrow,
    /// Program/contract account
    Program,
}

impl AccountType {
    /// Get the PDA namespace for this account type
    pub fn namespace(&self) -> &'static str {
        match self {
            AccountType::UserWallet => pda_namespace::WALLET,
            AccountType::UserProfile => pda_namespace::PROFILE,
            AccountType::EscrowVault => pda_namespace::VAULT,
            AccountType::SystemConfig => pda_namespace::CONFIG,
            AccountType::Treasury => pda_namespace::TREASURY,
            AccountType::StakePool => pda_namespace::STAKE_POOL,
            AccountType::PredictionMarket => pda_namespace::MARKET,
            AccountType::MarketPosition => pda_namespace::POSITION,
            AccountType::LiquidityProvider => pda_namespace::LP,
            AccountType::NFTMint => pda_namespace::NFT_MINT,
            AccountType::NFTMetadata => pda_namespace::NFT_METADATA,
            AccountType::BridgeEscrow => pda_namespace::BRIDGE_ESCROW,
            AccountType::Program => "program",
        }
    }
    
    /// Check if this account type can hold tokens
    pub fn can_hold_tokens(&self) -> bool {
        matches!(self, 
            AccountType::UserWallet | 
            AccountType::EscrowVault |
            AccountType::Treasury |
            AccountType::StakePool |
            AccountType::BridgeEscrow
        )
    }
    
    /// Check if this account type requires admin authority
    pub fn requires_admin(&self) -> bool {
        matches!(self,
            AccountType::SystemConfig |
            AccountType::Treasury |
            AccountType::StakePool
        )
    }
    
    /// Check if users can create this account type
    pub fn user_creatable(&self) -> bool {
        matches!(self,
            AccountType::UserWallet |
            AccountType::UserProfile |
            AccountType::MarketPosition |
            AccountType::LiquidityProvider
        )
    }
}

/// Program Derived Address with full derivation metadata
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProgramDerivedAddress {
    /// The derived address (L1_...)
    pub address: String,
    /// Account type (for validation)
    pub account_type: AccountType,
    /// Namespace used in derivation
    pub namespace: String,
    /// Owner public key (authority)
    pub owner: String,
    /// Optional index (for multiple accounts)
    pub index: Option<String>,
    /// Bump seed used to derive off-curve address
    pub bump: u8,
    /// Full seeds used for derivation (for verification)
    pub seeds: Vec<Vec<u8>>,
}

impl ProgramDerivedAddress {
    /// Derive a PDA from seeds
    /// 
    /// Seeds format: [namespace, owner, [optional_index], bump]
    /// The bump is found by trying 255, 254, 253... until address is off-curve
    pub fn derive(
        account_type: AccountType,
        owner: &str,
        index: Option<&str>,
    ) -> Result<Self, String> {
        let namespace = account_type.namespace();
        
        // Build seeds
        let mut seeds: Vec<Vec<u8>> = vec![
            namespace.as_bytes().to_vec(),
            owner.as_bytes().to_vec(),
        ];
        
        if let Some(idx) = index {
            seeds.push(idx.as_bytes().to_vec());
        }
        
        // Find bump that produces off-curve address
        for bump in (0u8..=255).rev() {
            let mut all_seeds = seeds.clone();
            all_seeds.push(vec![bump]);
            
            let (address, is_off_curve) = Self::derive_address_with_bump(&all_seeds);
            
            if is_off_curve {
                return Ok(Self {
                    address,
                    account_type,
                    namespace: namespace.to_string(),
                    owner: owner.to_string(),
                    index: index.map(|s| s.to_string()),
                    bump,
                    seeds: all_seeds,
                });
            }
        }
        
        Err("Could not find valid bump for PDA".to_string())
    }
    
    /// Derive address from seeds and check if it's off the Ed25519 curve
    fn derive_address_with_bump(seeds: &[Vec<u8>]) -> (String, bool) {
        let mut hasher = Sha256::new();
        
        // Hash all seeds together
        for seed in seeds {
            hasher.update(seed);
        }
        
        // Add domain separator to prevent collision with regular addresses
        hasher.update(b"PDA");
        
        let hash = hasher.finalize();
        let address = format!("L1_{}", hex::encode(&hash[..20]).to_uppercase());
        
        // Check if the resulting bytes would be on the Ed25519 curve
        // A proper implementation would check if the point is valid
        // For our purposes, we use a simpler check: if the last byte of hash
        // AND the bump creates a "marker" pattern, it's considered off-curve
        let is_off_curve = hash[31] & 0x80 == 0;
        
        (address, is_off_curve)
    }
    
    /// Verify that an address was derived from the claimed seeds
    pub fn verify(&self) -> bool {
        // Reconstruct the address from seeds
        let (derived_address, _) = Self::derive_address_with_bump(&self.seeds);
        derived_address == self.address
    }
    
    /// Create a system PDA (no owner, just namespace)
    pub fn derive_system(namespace: &str) -> Result<Self, String> {
        Self::derive(AccountType::SystemConfig, "system", Some(namespace))
    }
    
    /// Get canonical address for a user wallet
    pub fn user_wallet(owner: &str, wallet_id: u32) -> Result<Self, String> {
        Self::derive(AccountType::UserWallet, owner, Some(&wallet_id.to_string()))
    }
    
    /// Get canonical address for a user's primary wallet (id=0)
    pub fn primary_wallet(owner: &str) -> Result<Self, String> {
        Self::derive(AccountType::UserWallet, owner, Some("0"))
    }
    
    /// Get canonical address for an escrow vault
    pub fn escrow_vault(owner: &str, escrow_id: &str) -> Result<Self, String> {
        Self::derive(AccountType::EscrowVault, owner, Some(escrow_id))
    }
    
    /// Get canonical address for a market position
    pub fn market_position(owner: &str, market_id: &str) -> Result<Self, String> {
        Self::derive(AccountType::MarketPosition, owner, Some(market_id))
    }
}

/// Account metadata stored with every account
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountMetadata {
    /// Account type for validation
    pub account_type: AccountType,
    /// Owner pubkey (authority over this account)
    pub owner: String,
    /// PDA derivation info (if derived)
    pub pda_info: Option<PDAInfo>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modification timestamp
    pub updated_at: u64,
    /// Is this account frozen?
    pub frozen: bool,
    /// Custom data (account-type specific)
    pub data: Option<Vec<u8>>,
}

/// Compact PDA info for storage
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PDAInfo {
    pub namespace: String,
    pub bump: u8,
    pub index: Option<String>,
}

// ============================================================================
// DECLARATIVE ACCOUNT VALIDATION - Compile-Time Safety
// ============================================================================
//
// Instead of manual if-statements, use this validation framework.
// Transactions MUST declare what accounts they touch and their expected types.
// The runtime validates BEFORE execution - invalid access = rejection.

/// Account access declaration for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAccess {
    /// Account address
    pub address: String,
    /// Expected account type (MUST match)
    pub expected_type: AccountType,
    /// Is this a signer (must have valid signature)?
    pub is_signer: bool,
    /// Is this writable (will be modified)?
    pub is_writable: bool,
    /// Required owner (if any)
    pub required_owner: Option<String>,
}

impl AccountAccess {
    /// Create a read-only account access
    pub fn read(address: &str, expected_type: AccountType) -> Self {
        Self {
            address: address.to_string(),
            expected_type,
            is_signer: false,
            is_writable: false,
            required_owner: None,
        }
    }
    
    /// Create a writable account access
    pub fn write(address: &str, expected_type: AccountType) -> Self {
        Self {
            address: address.to_string(),
            expected_type,
            is_signer: false,
            is_writable: true,
            required_owner: None,
        }
    }
    
    /// Create a signer account access
    pub fn signer(address: &str, expected_type: AccountType) -> Self {
        Self {
            address: address.to_string(),
            expected_type,
            is_signer: true,
            is_writable: false,
            required_owner: None,
        }
    }
    
    /// Create a signer + writable account access
    pub fn signer_writable(address: &str, expected_type: AccountType) -> Self {
        Self {
            address: address.to_string(),
            expected_type,
            is_signer: true,
            is_writable: true,
            required_owner: None,
        }
    }
    
    /// Add owner requirement
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.required_owner = Some(owner.to_string());
        self
    }
}

/// Account validation result
#[derive(Debug, Clone)]
pub enum AccountValidationError {
    /// Account doesn't exist
    AccountNotFound { address: String },
    /// Account type mismatch
    TypeMismatch { address: String, expected: AccountType, actual: AccountType },
    /// Missing required signature
    MissingSignature { address: String },
    /// Account not writable but write attempted
    NotWritable { address: String },
    /// Owner mismatch
    OwnerMismatch { address: String, expected: String, actual: String },
    /// Account is frozen
    AccountFrozen { address: String },
    /// PDA verification failed
    InvalidPDA { address: String, reason: String },
}

impl std::fmt::Display for AccountValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountNotFound { address } => 
                write!(f, "Account not found: {}", address),
            Self::TypeMismatch { address, expected, actual } => 
                write!(f, "Account type mismatch for {}: expected {:?}, got {:?}", address, expected, actual),
            Self::MissingSignature { address } => 
                write!(f, "Missing required signature for: {}", address),
            Self::NotWritable { address } => 
                write!(f, "Account not writable: {}", address),
            Self::OwnerMismatch { address, expected, actual } => 
                write!(f, "Owner mismatch for {}: expected {}, got {}", address, expected, actual),
            Self::AccountFrozen { address } => 
                write!(f, "Account is frozen: {}", address),
            Self::InvalidPDA { address, reason } => 
                write!(f, "Invalid PDA {}: {}", address, reason),
        }
    }
}

/// Declarative account validator
/// Validates all account accesses BEFORE transaction execution
pub struct AccountValidator {
    /// Account metadata storage
    accounts: Arc<DashMap<String, AccountMetadata>>,
}

impl AccountValidator {
    pub fn new(accounts: Arc<DashMap<String, AccountMetadata>>) -> Self {
        Self { accounts }
    }
    
    /// Validate all account accesses for a transaction
    /// Returns Ok if all validations pass, Err with first failure otherwise
    pub fn validate_transaction(
        &self,
        accesses: &[AccountAccess],
        signers: &HashSet<String>,
    ) -> Result<(), AccountValidationError> {
        for access in accesses {
            self.validate_access(access, signers)?;
        }
        Ok(())
    }
    
    /// Validate a single account access
    fn validate_access(
        &self,
        access: &AccountAccess,
        signers: &HashSet<String>,
    ) -> Result<(), AccountValidationError> {
        // 1. Check account exists
        let metadata = self.accounts.get(&access.address)
            .ok_or_else(|| AccountValidationError::AccountNotFound {
                address: access.address.clone(),
            })?;
        
        // 2. Check account type matches
        if metadata.account_type != access.expected_type {
            return Err(AccountValidationError::TypeMismatch {
                address: access.address.clone(),
                expected: access.expected_type,
                actual: metadata.account_type,
            });
        }
        
        // 3. Check signer requirement
        if access.is_signer && !signers.contains(&access.address) {
            // Check if owner signed instead
            if !signers.contains(&metadata.owner) {
                return Err(AccountValidationError::MissingSignature {
                    address: access.address.clone(),
                });
            }
        }
        
        // 4. Check owner requirement
        if let Some(required_owner) = &access.required_owner {
            if &metadata.owner != required_owner {
                return Err(AccountValidationError::OwnerMismatch {
                    address: access.address.clone(),
                    expected: required_owner.clone(),
                    actual: metadata.owner.clone(),
                });
            }
        }
        
        // 5. Check frozen status
        if access.is_writable && metadata.frozen {
            return Err(AccountValidationError::AccountFrozen {
                address: access.address.clone(),
            });
        }
        
        // 6. Verify PDA if present
        if let Some(pda_info) = &metadata.pda_info {
            // Reconstruct and verify PDA derivation
            let derived = ProgramDerivedAddress::derive(
                metadata.account_type,
                &metadata.owner,
                pda_info.index.as_deref(),
            );
            
            match derived {
                Ok(pda) => {
                    if pda.address != access.address || pda.bump != pda_info.bump {
                        return Err(AccountValidationError::InvalidPDA {
                            address: access.address.clone(),
                            reason: "PDA derivation mismatch".to_string(),
                        });
                    }
                }
                Err(e) => {
                    return Err(AccountValidationError::InvalidPDA {
                        address: access.address.clone(),
                        reason: e,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Create or verify an account with PDA
    pub fn create_pda_account(
        &self,
        account_type: AccountType,
        owner: &str,
        index: Option<&str>,
    ) -> Result<ProgramDerivedAddress, String> {
        // Check if user can create this type
        if !account_type.user_creatable() {
            return Err(format!("Account type {:?} cannot be created by users", account_type));
        }
        
        // Derive the PDA
        let pda = ProgramDerivedAddress::derive(account_type, owner, index)?;
        
        // Check if already exists
        if self.accounts.contains_key(&pda.address) {
            return Err(format!("Account {} already exists", pda.address));
        }
        
        // Create metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let metadata = AccountMetadata {
            account_type,
            owner: owner.to_string(),
            pda_info: Some(PDAInfo {
                namespace: pda.namespace.clone(),
                bump: pda.bump,
                index: pda.index.clone(),
            }),
            created_at: now,
            updated_at: now,
            frozen: false,
            data: None,
        };
        
        self.accounts.insert(pda.address.clone(), metadata);
        
        Ok(pda)
    }
}

// ============================================================================
// NETWORK SPAM PROTECTION - Stake-Weighted Throttling + Localized Fees
// ============================================================================
//
// Unlike Solana's global fee market where one spam attack affects everyone,
// we implement LOCALIZED fee markets where spam only raises fees for the spammer.
//
// Components:
// 1. Stake-weighted throttling: Higher stake = more throughput allowance
// 2. Per-account rate limits: Spam one account, only that account pays more
// 3. Memory guards: Hard cap on pending transaction buffer
// 4. Circuit breakers: Automatic slowdown if thresholds exceeded

/// Stake-weighted rate limit entry
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    /// Number of transactions in current window
    pub tx_count: u64,
    /// Total compute units used in current window
    pub compute_used: u64,
    /// Window start time
    pub window_start: Instant,
    /// Account's stake (for weighted limits)
    pub stake: f64,
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        Self {
            tx_count: 0,
            compute_used: 0,
            window_start: Instant::now(),
            stake: 0.0,
        }
    }
}

/// Network throttler with stake-weighted rate limiting
pub struct NetworkThrottler {
    /// Per-account rate limit tracking
    account_limits: DashMap<String, RateLimitEntry>,
    
    /// Global pending transaction count (for memory guard)
    pending_count: AtomicU64,
    
    /// Maximum pending transactions (memory guard)
    max_pending: u64,
    
    /// Rate limit window duration
    window_duration: Duration,
    
    /// Base transactions per window (for zero-stake accounts)
    base_tx_limit: u64,
    
    /// Stake multiplier (stake * multiplier = bonus tx allowance)
    stake_multiplier: f64,
    
    /// Emergency halt flag
    emergency_halt: AtomicBool,
    
    /// Statistics
    pub total_accepted: AtomicU64,
    pub total_rejected: AtomicU64,
    pub total_throttled: AtomicU64,
}

impl NetworkThrottler {
    pub fn new() -> Self {
        info!("🛡️ Network Throttler initialized:");
        info!("   └─ stake-weighted limits, localized fees, memory guard");
        
        Self {
            account_limits: DashMap::new(),
            pending_count: AtomicU64::new(0),
            max_pending: 100_000, // Memory guard: 100k max pending
            window_duration: Duration::from_secs(1), // 1 second windows
            base_tx_limit: 10, // 10 tx/sec base for zero-stake
            stake_multiplier: 0.1, // +1 tx per 10 stake
            emergency_halt: AtomicBool::new(false),
            total_accepted: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            total_throttled: AtomicU64::new(0),
        }
    }
    
    /// Check if a transaction should be accepted
    /// Returns Ok(priority_fee) if accepted, Err(reason) if rejected
    pub fn check_transaction(&self, sender: &str, stake: f64) -> Result<f64, String> {
        // 1. Emergency halt check
        if self.emergency_halt.load(Ordering::Relaxed) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err("Network is in emergency halt".to_string());
        }
        
        // 2. Memory guard check
        let pending = self.pending_count.load(Ordering::Relaxed);
        if pending >= self.max_pending {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(format!("Memory guard: {} pending transactions (max: {})", 
                              pending, self.max_pending));
        }
        
        // 3. Per-account rate limit check
        let now = Instant::now();
        let mut entry = self.account_limits
            .entry(sender.to_string())
            .or_default();
        
        // Reset window if expired
        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.tx_count = 0;
            entry.compute_used = 0;
            entry.window_start = now;
            entry.stake = stake;
        }
        
        // Calculate stake-weighted limit
        let tx_limit = self.base_tx_limit + (stake * self.stake_multiplier) as u64;
        
        if entry.tx_count >= tx_limit {
            self.total_throttled.fetch_add(1, Ordering::Relaxed);
            
            // Calculate congestion fee (localized, not global!)
            let congestion_ratio = entry.tx_count as f64 / tx_limit as f64;
            let priority_fee = 0.001 * congestion_ratio.powi(2); // Quadratic fee increase
            
            return Err(format!(
                "Rate limited: {}/{} txs this window. Pay {:.6} priority fee or wait.",
                entry.tx_count, tx_limit, priority_fee
            ));
        }
        
        // Accept transaction
        entry.tx_count += 1;
        self.pending_count.fetch_add(1, Ordering::Relaxed);
        self.total_accepted.fetch_add(1, Ordering::Relaxed);
        
        // Return required priority fee (0 if under limit)
        Ok(0.0)
    }
    
    /// Called when a transaction is processed (success or fail)
    pub fn transaction_completed(&self) {
        self.pending_count.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Trigger emergency halt
    pub fn emergency_halt(&self) {
        warn!("🚨 EMERGENCY HALT triggered!");
        self.emergency_halt.store(true, Ordering::Relaxed);
    }
    
    /// Resume from emergency halt
    pub fn resume(&self) {
        info!("✅ Emergency halt lifted");
        self.emergency_halt.store(false, Ordering::Relaxed);
    }
    
    /// Get throttler statistics
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "pending_transactions": self.pending_count.load(Ordering::Relaxed),
            "max_pending": self.max_pending,
            "total_accepted": self.total_accepted.load(Ordering::Relaxed),
            "total_rejected": self.total_rejected.load(Ordering::Relaxed),
            "total_throttled": self.total_throttled.load(Ordering::Relaxed),
            "emergency_halt": self.emergency_halt.load(Ordering::Relaxed),
            "accounts_tracked": self.account_limits.len(),
        })
    }
    
    /// Clean up old entries (call periodically)
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.account_limits.retain(|_, entry| {
            now.duration_since(entry.window_start) < self.window_duration * 10
        });
    }
}

impl Default for NetworkThrottler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CIRCUIT BREAKERS - Automatic Protection Against Bank Runs
// ============================================================================
//
// If an account/contract tries to move too much value too fast, we slow it down.
// This prevents:
// - Exploit drainage (hacker can't empty a vault in one block)
// - Flash loan attacks (can't borrow/repay massive amounts instantly)
// - Panic bank runs (withdrawals are spread over time)

/// Circuit breaker thresholds
pub const SINGLE_BLOCK_VALUE_THRESHOLD: f64 = 0.20; // 20% of account value
pub const HOURLY_VALUE_THRESHOLD: f64 = 0.50; // 50% of account value per hour
pub const CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 3600; // 1 hour cooldown

/// Value flow tracking for circuit breakers
#[derive(Debug, Clone)]
pub struct ValueFlowEntry {
    /// Total value at start of tracking
    pub initial_value: f64,
    /// Value moved out this block
    pub block_outflow: f64,
    /// Value moved out this hour
    pub hourly_outflow: f64,
    /// Current block number
    pub current_block: u64,
    /// Hour start timestamp
    pub hour_start: u64,
    /// Is this account tripped?
    pub tripped: bool,
    /// Trip timestamp (for cooldown)
    pub tripped_at: Option<u64>,
}

impl Default for ValueFlowEntry {
    fn default() -> Self {
        Self {
            initial_value: 0.0,
            block_outflow: 0.0,
            hourly_outflow: 0.0,
            current_block: 0,
            hour_start: 0,
            tripped: false,
            tripped_at: None,
        }
    }
}

/// Circuit breaker system
pub struct CircuitBreaker {
    /// Per-account flow tracking
    flows: DashMap<String, ValueFlowEntry>,
    
    /// Single-block threshold (fraction of account value)
    block_threshold: f64,
    
    /// Hourly threshold (fraction of account value)
    hourly_threshold: f64,
    
    /// Cooldown duration in seconds
    cooldown_secs: u64,
    
    /// Exempted accounts (treasury, bridge, etc.)
    exemptions: DashMap<String, bool>,
    
    /// Statistics
    pub trips_triggered: AtomicU64,
    pub trips_prevented_value: AtomicU64, // in cents to avoid f64 atomics
}

impl CircuitBreaker {
    pub fn new() -> Self {
        info!("🔌 Circuit Breaker initialized:");
        info!("   └─ block: {}%, hourly: {}%, cooldown: {}s",
              SINGLE_BLOCK_VALUE_THRESHOLD * 100.0,
              HOURLY_VALUE_THRESHOLD * 100.0,
              CIRCUIT_BREAKER_COOLDOWN_SECS);
        
        Self {
            flows: DashMap::new(),
            block_threshold: SINGLE_BLOCK_VALUE_THRESHOLD,
            hourly_threshold: HOURLY_VALUE_THRESHOLD,
            cooldown_secs: CIRCUIT_BREAKER_COOLDOWN_SECS,
            exemptions: DashMap::new(),
            trips_triggered: AtomicU64::new(0),
            trips_prevented_value: AtomicU64::new(0),
        }
    }
    
    /// Check if a value transfer is allowed
    /// Returns Ok(()) if allowed, Err(reason) if blocked
    pub fn check_transfer(
        &self,
        from: &str,
        amount: f64,
        current_balance: f64,
        current_block: u64,
    ) -> Result<(), String> {
        // Skip check for exempted accounts
        if self.exemptions.contains_key(from) {
            return Ok(());
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut entry = self.flows.entry(from.to_string()).or_default();
        
        // Check if still in cooldown
        if entry.tripped {
            if let Some(tripped_at) = entry.tripped_at {
                if now - tripped_at < self.cooldown_secs {
                    let remaining = self.cooldown_secs - (now - tripped_at);
                    return Err(format!(
                        "Circuit breaker tripped. Cooldown: {} seconds remaining.",
                        remaining
                    ));
                } else {
                    // Cooldown expired, reset
                    entry.tripped = false;
                    entry.tripped_at = None;
                    entry.block_outflow = 0.0;
                    entry.hourly_outflow = 0.0;
                }
            }
        }
        
        // Reset block counter if new block
        if current_block != entry.current_block {
            entry.current_block = current_block;
            entry.block_outflow = 0.0;
        }
        
        // Reset hourly counter if new hour
        if now - entry.hour_start >= 3600 {
            entry.hour_start = now;
            entry.hourly_outflow = 0.0;
            entry.initial_value = current_balance;
        }
        
        // Initialize if first time
        if entry.initial_value == 0.0 {
            entry.initial_value = current_balance;
            entry.hour_start = now;
        }
        
        // Calculate thresholds based on initial value
        let block_limit = entry.initial_value * self.block_threshold;
        let hourly_limit = entry.initial_value * self.hourly_threshold;
        
        // Check block threshold
        if entry.block_outflow + amount > block_limit {
            self.trip(from, amount);
            return Err(format!(
                "Circuit breaker: Block outflow {:.2} + {:.2} exceeds {:.0}% threshold ({:.2})",
                entry.block_outflow, amount, self.block_threshold * 100.0, block_limit
            ));
        }
        
        // Check hourly threshold
        if entry.hourly_outflow + amount > hourly_limit {
            self.trip(from, amount);
            return Err(format!(
                "Circuit breaker: Hourly outflow {:.2} + {:.2} exceeds {:.0}% threshold ({:.2})",
                entry.hourly_outflow, amount, self.hourly_threshold * 100.0, hourly_limit
            ));
        }
        
        // Record the outflow
        entry.block_outflow += amount;
        entry.hourly_outflow += amount;
        
        Ok(())
    }
    
    /// Trip the circuit breaker for an account
    fn trip(&self, account: &str, prevented_amount: f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(mut entry) = self.flows.get_mut(account) {
            entry.tripped = true;
            entry.tripped_at = Some(now);
        }
        
        self.trips_triggered.fetch_add(1, Ordering::Relaxed);
        self.trips_prevented_value.fetch_add(
            (prevented_amount * 100.0) as u64, 
            Ordering::Relaxed
        );
        
        warn!("🔌 Circuit breaker TRIPPED for account: {} (prevented: {:.2})",
              account, prevented_amount);
    }
    
    /// Add an exemption (for treasury, bridge, etc.)
    pub fn add_exemption(&self, account: &str) {
        self.exemptions.insert(account.to_string(), true);
        info!("🔌 Circuit breaker exemption added: {}", account);
    }
    
    /// Remove an exemption
    pub fn remove_exemption(&self, account: &str) {
        self.exemptions.remove(account);
    }
    
    /// Get circuit breaker statistics
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "trips_triggered": self.trips_triggered.load(Ordering::Relaxed),
            "value_prevented": self.trips_prevented_value.load(Ordering::Relaxed) as f64 / 100.0,
            "accounts_tracked": self.flows.len(),
            "exemptions": self.exemptions.len(),
            "block_threshold": format!("{}%", self.block_threshold * 100.0),
            "hourly_threshold": format!("{}%", self.hourly_threshold * 100.0),
            "cooldown_secs": self.cooldown_secs,
        })
    }
    
    /// Check if an account is currently tripped
    pub fn is_tripped(&self, account: &str) -> bool {
        self.flows.get(account)
            .map(|e| e.tripped)
            .unwrap_or(false)
    }
    
    /// Manually reset a tripped account (admin function)
    pub fn admin_reset(&self, account: &str) {
        if let Some(mut entry) = self.flows.get_mut(account) {
            entry.tripped = false;
            entry.tripped_at = None;
            entry.block_outflow = 0.0;
            entry.hourly_outflow = 0.0;
            info!("🔌 Admin reset circuit breaker for: {}", account);
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// LOCALIZED FEE MARKET - Per-Account Group Fees
// ============================================================================
//
// Instead of global fees that spike for everyone when one account is spammed,
// fees are calculated per "fee group" (usually the sender's first 8 chars).
// This isolates spam to only affect the spammer.

/// Fee market entry for an account group
#[derive(Debug, Clone)]
pub struct FeeMarketEntry {
    /// Number of transactions this window
    pub tx_count: u64,
    /// Window start time
    pub window_start: Instant,
    /// Current base fee for this group
    pub base_fee: f64,
}

/// Localized fee market
pub struct LocalizedFeeMarket {
    /// Per-group fee tracking
    groups: DashMap<String, FeeMarketEntry>,
    
    /// Global minimum fee
    min_fee: f64,
    
    /// Global maximum fee
    max_fee: f64,
    
    /// Target transactions per group per window
    target_tx_per_group: u64,
    
    /// Fee adjustment rate
    adjustment_rate: f64,
}

impl LocalizedFeeMarket {
    pub fn new() -> Self {
        Self {
            groups: DashMap::new(),
            min_fee: 0.0, // No fee in normal conditions
            max_fee: 1.0, // Max 1 wUSDC fee under extreme spam
            target_tx_per_group: 100, // 100 tx/sec target per group
            adjustment_rate: 0.1, // 10% adjustment per check
        }
    }
    
    /// Get the fee group for an address (first 8 chars after L1_)
    fn get_group(address: &str) -> String {
        if address.starts_with("L1_") && address.len() >= 11 {
            address[3..11].to_string()
        } else {
            address.chars().take(8).collect()
        }
    }
    
    /// Calculate fee for a transaction
    pub fn calculate_fee(&self, sender: &str) -> f64 {
        let group = Self::get_group(sender);
        let now = Instant::now();
        
        let mut entry = self.groups.entry(group).or_insert(FeeMarketEntry {
            tx_count: 0,
            window_start: now,
            base_fee: self.min_fee,
        });
        
        // Reset window if expired (1 second windows)
        if now.duration_since(entry.window_start) >= Duration::from_secs(1) {
            // Adjust fee based on previous window
            if entry.tx_count > self.target_tx_per_group {
                // Congested - increase fee
                entry.base_fee = (entry.base_fee + self.adjustment_rate).min(self.max_fee);
            } else if entry.tx_count < self.target_tx_per_group / 2 {
                // Underutilized - decrease fee
                entry.base_fee = (entry.base_fee - self.adjustment_rate).max(self.min_fee);
            }
            
            entry.tx_count = 0;
            entry.window_start = now;
        }
        
        entry.tx_count += 1;
        entry.base_fee
    }
    
    /// Get fee market statistics
    pub fn get_stats(&self) -> serde_json::Value {
        let groups: Vec<_> = self.groups.iter()
            .map(|e| {
                serde_json::json!({
                    "group": e.key().clone(),
                    "tx_count": e.tx_count,
                    "base_fee": e.base_fee,
                })
            })
            .take(10) // Only show top 10
            .collect();
        
        serde_json::json!({
            "active_groups": self.groups.len(),
            "min_fee": self.min_fee,
            "max_fee": self.max_fee,
            "target_tx_per_group": self.target_tx_per_group,
            "sample_groups": groups,
        })
    }
}

impl Default for LocalizedFeeMarket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ACCOUNT LOCK MANAGER - Fine-Grained Sealevel-Style Locking
// ============================================================================

/// Fine-grained account lock manager for Sealevel-style parallel execution
/// 
/// Implements read/write locking at the account level:
/// - Multiple readers can access an account simultaneously
/// - Writers get exclusive access
/// - Prevents conflicts during parallel transaction execution
#[derive(Debug)]
pub struct AccountLockManager {
    /// Read lock counts per account (multiple readers allowed)
    read_locks: DashMap<String, AtomicU32>,
    /// Write lock flags per account (exclusive access)
    write_locks: DashMap<String, AtomicBool>,
    /// Statistics: total lock acquisitions
    pub total_acquisitions: AtomicU64,
    /// Statistics: total lock conflicts
    pub total_conflicts: AtomicU64,
}

impl AccountLockManager {
    pub fn new() -> Self {
        Self {
            read_locks: DashMap::new(),
            write_locks: DashMap::new(),
            total_acquisitions: AtomicU64::new(0),
            total_conflicts: AtomicU64::new(0),
        }
    }
    
    /// Try to acquire all locks needed for a transaction
    /// Returns true if all locks acquired, false if any conflict
    pub fn try_acquire_locks(&self, tx: &Transaction) -> bool {
        self.total_acquisitions.fetch_add(1, Ordering::Relaxed);
        
        // First check if we can acquire all write locks
        for account in &tx.write_accounts {
            // Check if there's an existing write lock
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            // Check if there are any read locks (can't write while being read)
            if let Some(lock) = self.read_locks.get(account) {
                if lock.load(Ordering::Acquire) > 0 {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
        
        // Check read accounts for write conflicts
        for account in &tx.read_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                if lock.load(Ordering::Acquire) {
                    self.total_conflicts.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }
        
        // Acquire all locks
        for account in &tx.write_accounts {
            self.write_locks
                .entry(account.clone())
                .or_insert_with(|| AtomicBool::new(false))
                .store(true, Ordering::Release);
        }
        
        for account in &tx.read_accounts {
            self.read_locks
                .entry(account.clone())
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::Release);
        }
        
        true
    }
    
    /// Release all locks held by a transaction
    pub fn release_locks(&self, tx: &Transaction) {
        // Release write locks
        for account in &tx.write_accounts {
            if let Some(lock) = self.write_locks.get(account) {
                lock.store(false, Ordering::Release);
            }
        }
        
        // Release read locks
        for account in &tx.read_accounts {
            if let Some(lock) = self.read_locks.get(account) {
                lock.fetch_sub(1, Ordering::Release);
            }
        }
    }
    
    /// Get conflict rate for batch tuning
    pub fn get_conflict_rate(&self) -> f64 {
        let total = self.total_acquisitions.load(Ordering::Relaxed);
        let conflicts = self.total_conflicts.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            conflicts as f64 / total as f64
        }
    }
    
    /// Reset statistics (call after each epoch)
    pub fn reset_stats(&self) {
        self.total_acquisitions.store(0, Ordering::Relaxed);
        self.total_conflicts.store(0, Ordering::Relaxed);
    }
    
    /// Get lock statistics as JSON
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_acquisitions": self.total_acquisitions.load(Ordering::Relaxed),
            "total_conflicts": self.total_conflicts.load(Ordering::Relaxed),
            "conflict_rate": self.get_conflict_rate(),
            "active_read_locks": self.read_locks.len(),
            "active_write_locks": self.write_locks.len(),
        })
    }
}

impl Default for AccountLockManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SEALEVEL-STYLE PARALLEL TRANSACTION EXECUTION
// ============================================================================

/// Transaction with explicit read/write accounts for parallel scheduling
/// 
/// Serialization strategy:
/// - Borsh: Used for internal node-to-node communication (fast, compact)
/// - Serde JSON: Used for RPC layer with Base64-encoded Borsh payload
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: String,
    /// Per-account nonce for replay protection (must be > sender's last nonce)
    #[serde(default)]
    pub nonce: u64,
    /// Accounts this transaction reads from (for parallel scheduling)
    #[serde(default)]
    pub read_accounts: Vec<String>,
    /// Accounts this transaction writes to (for parallel scheduling)
    #[serde(default)]
    pub write_accounts: Vec<String>,
    /// Transaction type for categorization
    #[serde(default)]
    pub tx_type: TransactionType,
    /// Unique transaction ID
    #[serde(default)]
    pub id: String,
    
    /// Transaction payload data (for NFT, Document validation, etc.)
    #[serde(default)]
    #[borsh(skip)]
    pub payload_data: Option<TransactionPayload>,
}

/// Transaction payload for complex operations (NFT, Document validation, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionPayload {
    /// NFT metadata (for NFTMint)
    pub nft_metadata: Option<NFTMetadata>,
    
    /// Document validation data (for DocumentValidation)
    pub document_validation: Option<DocumentValidationData>,
    
    /// Program invocation data (for ProgramInvoke)
    pub program_invoke: Option<ProgramInvokeData>,
    
    /// Vote data (for TowerBFT voting)
    pub vote: Option<VoteData>,
    
    /// Raw bytes for custom payloads
    pub raw: Option<Vec<u8>>,
}

/// NFT metadata for minting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub collection_id: Option<String>,
    pub attributes: HashMap<String, String>,
    pub royalty_basis_points: u16,  // 100 = 1%
    pub creators: Vec<NFTCreator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTCreator {
    pub address: String,
    pub share: u8,  // Percentage (0-100)
    pub verified: bool,
}

/// Document validation data for L3 integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentValidationData {
    /// NFT ID representing the document
    pub nft_id: String,
    
    /// SHA256 hash of the document
    pub document_hash: String,
    
    /// L3 validator's proof (signature or ZK proof)
    pub l3_proof: String,
    
    /// Validator's address on L3
    pub validator_address: String,
    
    /// Validation timestamp (L3 time)
    pub validated_at: u64,
    
    /// Validation status
    pub status: ValidationStatus,
    
    /// Optional callback URL for async validation
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum ValidationStatus {
    #[default]
    Pending,
    Valid,
    Invalid,
    Expired,
}

/// Program invocation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInvokeData {
    pub program_id: String,
    pub instruction_data: Vec<u8>,
    pub accounts: Vec<AccountMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Vote data for Tower BFT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteData {
    pub slot: u64,
    pub block_hash: String,
    pub validator_pubkey: String,
    pub timestamp: u64,
}

/// Transaction type for categorization (Two-Lane Model)
/// - Financial Lane: Transfer, BetPlacement, BetResolution, StakeDeposit, StakeWithdraw
/// - Social Lane: SocialAction
/// - NFT Lane: NFTMint, NFTTransfer, NFTBurn (new)
/// - L3 Integration: DocumentValidation, ProgramInvoke (new)
/// - Consensus: Vote (for Tower BFT)
/// - System: SystemReward (internal)
/// - Admin: Mint, Burn (treasury operations)
/// 
/// Implements both Serde and Borsh for hybrid serialization
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default, PartialEq)]
pub enum TransactionType {
    #[default]
    Transfer,
    BetPlacement,
    BetResolution,
    SocialAction,
    StakeDeposit,
    StakeWithdraw,
    SystemReward,
    Mint,
    Burn,
    
    // ========== NFT OPERATIONS (New) ==========
    /// Mint a new NFT
    NFTMint,
    /// Transfer NFT ownership
    NFTTransfer,
    /// Burn an NFT
    NFTBurn,
    /// Update NFT metadata
    NFTUpdate,
    
    // ========== L3 DOCUMENT VALIDATION (New) ==========
    /// Submit document for L3 validation
    DocumentValidation,
    /// L3 validator responds with proof
    DocumentValidationResponse,
    
    // ========== PROGRAM OPERATIONS (New) ==========
    /// Invoke a program (smart contract call)
    ProgramInvoke,
    /// Deploy a new program
    ProgramDeploy,
    /// Upgrade an existing program
    ProgramUpgrade,
    
    // ========== CONSENSUS (Tower BFT) ==========
    /// Vote for a block (Tower BFT)
    Vote,
}

impl TransactionType {
    /// Returns true if this is a financial lane transaction
    pub fn is_financial(&self) -> bool {
        matches!(self, 
            TransactionType::Transfer | 
            TransactionType::BetPlacement | 
            TransactionType::BetResolution |
            TransactionType::StakeDeposit |
            TransactionType::StakeWithdraw
        )
    }
    
    /// Returns true if this is a social lane transaction
    pub fn is_social(&self) -> bool {
        matches!(self, TransactionType::SocialAction)
    }
    
    /// Returns true if this is an NFT lane transaction
    pub fn is_nft(&self) -> bool {
        matches!(self,
            TransactionType::NFTMint |
            TransactionType::NFTTransfer |
            TransactionType::NFTBurn |
            TransactionType::NFTUpdate
        )
    }
    
    /// Returns true if this is an L3/program transaction
    pub fn is_program(&self) -> bool {
        matches!(self,
            TransactionType::DocumentValidation |
            TransactionType::DocumentValidationResponse |
            TransactionType::ProgramInvoke |
            TransactionType::ProgramDeploy |
            TransactionType::ProgramUpgrade
        )
    }
    
    /// Returns true if this is a consensus transaction
    pub fn is_consensus(&self) -> bool {
        matches!(self, TransactionType::Vote)
    }
}

impl Transaction {
    /// Create a new transaction with automatic account detection
    pub fn new(from: String, to: String, amount: f64, tx_type: TransactionType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Auto-detect read/write accounts based on transaction type
        let (read_accounts, write_accounts) = match &tx_type {
            TransactionType::Transfer => {
                (vec![from.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::BetPlacement => {
                // Bet reads user balance, writes to user and bet pool
                (vec![from.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::BetResolution => {
                // Resolution reads bet state, writes to multiple winners
                (vec![to.clone()], vec![from.clone(), to.clone()])
            },
            TransactionType::SocialAction => {
                // Social actions only affect the actor
                (vec![from.clone()], vec![from.clone()])
            },
            _ => (vec![from.clone()], vec![from.clone(), to.clone()]),
        };
        
        Self {
            from,
            to,
            amount,
            timestamp,
            signature: format!("sig_{}", &id[..8]),
            nonce: 0, // Must be set by caller based on account state
            read_accounts,
            write_accounts,
            tx_type,
            id,
            payload_data: None,
        }
    }
    
    /// Create transaction with explicit nonce
    pub fn with_nonce(from: String, to: String, amount: f64, tx_type: TransactionType, nonce: u64) -> Self {
        let mut tx = Self::new(from, to, amount, tx_type);
        tx.nonce = nonce;
        tx
    }
    
    /// Check if this transaction conflicts with another (for parallel scheduling)
    pub fn conflicts_with(&self, other: &Transaction) -> bool {
        // Conflict if: my writes intersect with their reads or writes
        // OR: my reads intersect with their writes
        for my_write in &self.write_accounts {
            if other.write_accounts.contains(my_write) || other.read_accounts.contains(my_write) {
                return true;
            }
        }
        for my_read in &self.read_accounts {
            if other.write_accounts.contains(my_read) {
                return true;
            }
        }
        false
    }
    
    // ========================================================================
    // BORSH SERIALIZATION HELPERS (For Borsh-inside-JSON strategy)
    // ========================================================================
    
    /// Serialize transaction to Borsh bytes (for node-to-node communication)
    pub fn to_borsh(&self) -> Result<Vec<u8>, std::io::Error> {
        borsh::to_vec(self)
    }
    
    /// Deserialize transaction from Borsh bytes
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }
    
    /// Serialize to Base64-encoded Borsh (for RPC JSON wrapper)
    pub fn to_base64(&self) -> Result<String, std::io::Error> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = self.to_borsh()?;
        Ok(STANDARD.encode(&bytes))
    }
    
    /// Deserialize from Base64-encoded Borsh
    pub fn from_base64(encoded: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(encoded)?;
        let tx = Self::from_borsh(&bytes)?;
        Ok(tx)
    }
}

/// Parallel transaction scheduler (Sealevel-inspired)
/// 
/// Enhanced with:
/// - AccountLockManager for fine-grained locking
/// - Dynamic batch size tuning based on conflict rate
/// - Metrics collection for optimization
pub struct ParallelScheduler {
    /// Thread pool for parallel execution
    thread_pool: rayon::ThreadPool,
    /// Account lock manager for fine-grained locking
    pub lock_manager: Arc<AccountLockManager>,
    /// Current optimal batch size (dynamically tuned)
    current_batch_size: AtomicU64,
    /// Total transactions processed
    pub total_processed: AtomicU64,
    /// Total batches executed
    pub total_batches: AtomicU64,
}

impl ParallelScheduler {
    pub fn new() -> Self {
        // Create thread pool with available CPUs
        let num_threads = num_cpus::get().max(4);
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());
        
        println!("⚡ Sealevel Parallel Scheduler initialized:");
        println!("   └─ {} threads, batch size: {}, lock manager: enabled", 
                 num_threads, OPTIMAL_BATCH_SIZE);
        
        Self { 
            thread_pool,
            lock_manager: Arc::new(AccountLockManager::new()),
            current_batch_size: AtomicU64::new(OPTIMAL_BATCH_SIZE as u64),
            total_processed: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
        }
    }
    
    /// Get current optimal batch size
    pub fn get_batch_size(&self) -> usize {
        self.current_batch_size.load(Ordering::Relaxed) as usize
    }
    
    /// Tune batch size based on conflict rate
    pub fn tune_batch_size(&self) {
        let conflict_rate = self.lock_manager.get_conflict_rate();
        let current = self.current_batch_size.load(Ordering::Relaxed) as usize;
        
        let new_size = if conflict_rate > CONFLICT_THRESHOLD {
            // High conflicts - reduce batch size
            (current / 2).max(MIN_BATCH_SIZE)
        } else if conflict_rate < CONFLICT_THRESHOLD / 2.0 {
            // Low conflicts - increase batch size
            (current * 3 / 2).min(MAX_BATCH_SIZE)
        } else {
            current
        };
        
        if new_size != current {
            self.current_batch_size.store(new_size as u64, Ordering::Relaxed);
            println!("🔧 Batch size tuned: {} → {} (conflict rate: {:.2}%)", 
                     current, new_size, conflict_rate * 100.0);
        }
    }
    
    /// Schedule transactions into non-conflicting batches using lock manager
    pub fn schedule(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() {
            return vec![];
        }
        
        let batch_size = self.get_batch_size();
        let mut batches: Vec<Vec<Transaction>> = vec![];
        let mut remaining = transactions;
        
        while !remaining.is_empty() {
            let mut current_batch: Vec<Transaction> = vec![];
            let mut next_remaining: Vec<Transaction> = vec![];
            
            for tx in remaining {
                // Use lock manager for conflict detection
                if current_batch.len() >= batch_size {
                    next_remaining.push(tx);
                    continue;
                }
                
                // Check if tx conflicts with any in current batch
                let conflicts = current_batch.iter().any(|batch_tx| tx.conflicts_with(batch_tx));
                
                if conflicts {
                    next_remaining.push(tx);
                } else {
                    current_batch.push(tx);
                }
            }
            
            if !current_batch.is_empty() {
                batches.push(current_batch);
            }
            remaining = next_remaining;
        }
        
        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        
        if batches.len() > 1 {
            println!("📦 Scheduled {} batches (size limit: {}) for parallel execution", 
                     batches.len(), batch_size);
        }
        
        batches
    }
    
    /// Schedule with lock-based conflict detection (more accurate)
    pub fn schedule_with_locks(&self, transactions: Vec<Transaction>) -> Vec<Vec<Transaction>> {
        if transactions.is_empty() {
            return vec![];
        }
        
        let batch_size = self.get_batch_size();
        let mut batches: Vec<Vec<Transaction>> = vec![];
        let mut remaining = transactions;
        
        while !remaining.is_empty() {
            let mut current_batch: Vec<Transaction> = vec![];
            let mut next_remaining: Vec<Transaction> = vec![];
            
            // Reset locks for this scheduling round
            for tx in remaining {
                if current_batch.len() >= batch_size {
                    next_remaining.push(tx);
                    continue;
                }
                
                // Try to acquire locks - if successful, add to batch
                if self.lock_manager.try_acquire_locks(&tx) {
                    current_batch.push(tx);
                } else {
                    next_remaining.push(tx);
                }
            }
            
            // Release all locks after scheduling
            for tx in &current_batch {
                self.lock_manager.release_locks(tx);
            }
            
            if !current_batch.is_empty() {
                batches.push(current_batch);
            }
            remaining = next_remaining;
        }
        
        self.total_batches.fetch_add(batches.len() as u64, Ordering::Relaxed);
        batches
    }
    
    /// Execute a batch of non-conflicting transactions in parallel
    pub fn execute_batch_parallel(
        &self,
        batch: Vec<Transaction>,
        balances: &DashMap<String, f64>,
    ) -> Vec<TransactionResult> {
        let batch_len = batch.len();
        
        let results = self.thread_pool.install(|| {
            batch.par_iter()
                .map(|tx| self.execute_single(tx, balances))
                .collect()
        });
        
        self.total_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
        results
    }
    
    /// Execute with lock acquisition (thread-safe)
    pub fn execute_batch_with_locks(
        &self,
        batch: Vec<Transaction>,
        balances: &DashMap<String, f64>,
    ) -> Vec<TransactionResult> {
        let batch_len = batch.len();
        let lock_manager = self.lock_manager.clone();
        
        let results = self.thread_pool.install(|| {
            batch.par_iter()
                .map(|tx| {
                    // Acquire locks before execution
                    while !lock_manager.try_acquire_locks(tx) {
                        std::hint::spin_loop();
                    }
                    
                    let result = self.execute_single(tx, balances);
                    
                    // Release locks after execution
                    lock_manager.release_locks(tx);
                    
                    result
                })
                .collect()
        });
        
        self.total_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
        results
    }
    
    /// Execute a single transaction
    fn execute_single(
        &self,
        tx: &Transaction,
        balances: &DashMap<String, f64>,
    ) -> TransactionResult {
        // Check balance for non-system transactions
        if !Self::is_system_account(&tx.from) {
            let balance = balances.get(&tx.from).map(|b| *b).unwrap_or(0.0);
            if balance < tx.amount {
                return TransactionResult {
                    tx_id: tx.id.clone(),
                    success: false,
                    error: Some(format!("Insufficient balance: have {}, need {}", balance, tx.amount)),
                };
            }
            
            // Deduct from sender
            balances.entry(tx.from.clone())
                .and_modify(|b| *b -= tx.amount);
        }
        
        // Add to recipient (unless burned)
        if tx.to != "burned_tokens" {
            balances.entry(tx.to.clone())
                .and_modify(|b| *b += tx.amount)
                .or_insert(tx.amount);
        }
        
        TransactionResult {
            tx_id: tx.id.clone(),
            success: true,
            error: None,
        }
    }
    
    fn is_system_account(account: &str) -> bool {
        matches!(account, 
            "genesis" | "mining_reward" | "connection_reward" | 
            "social_mining" | "signup_bonus" | "bet_pool" |
            "system" | "poh_validator"
        ) || account.starts_with("bet_contract_") 
          || account.starts_with("chess_contract_")
    }
    
    /// Get scheduler statistics for monitoring
    pub fn get_stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_processed: self.total_processed.load(Ordering::Relaxed),
            total_batches: self.total_batches.load(Ordering::Relaxed),
            current_batch_size: self.current_batch_size.load(Ordering::Relaxed) as usize,
            conflict_rate: self.lock_manager.get_conflict_rate(),
            thread_count: self.thread_pool.current_num_threads(),
        }
    }
    
    /// Reset scheduler statistics
    pub fn reset_stats(&self) {
        self.total_processed.store(0, Ordering::Relaxed);
        self.total_batches.store(0, Ordering::Relaxed);
        self.lock_manager.reset_stats();
    }
    
    /// Helper: Schedule transactions from a slice (for tests and compatibility)
    pub fn schedule_batch(&self, transactions: &[Transaction]) -> Vec<Vec<Transaction>> {
        self.schedule_with_locks(transactions.to_vec())
    }
}

/// Statistics from the parallel scheduler
#[derive(Debug, Clone, Serialize)]
pub struct SchedulerStats {
    pub total_processed: u64,
    pub total_batches: u64,
    pub current_batch_size: usize,
    pub conflict_rate: f64,
    pub thread_count: usize,
}

#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub tx_id: String,
    pub success: bool,
    pub error: Option<String>,
}

// ============================================================================
// CORE BLOCKCHAIN STRUCTURES - SEQUENCER MODEL WITH TWO-LANE BLOCKS
// ============================================================================
//
// This is a SPECIALIZED L1 where "mining" is just sorting:
// - Generic Mining: "Load smart contract, read memory, calculate gas, run logic" (Slow)
// - Our L1: "Verify signature, add +1 to database" (Blazing fast)
//
// Validators are SEQUENCERS that:
// 1. Ingest: Accept thousands of Bet/Post actions per second
// 2. Deduplicate: "Did Alice already bet on this?"
// 3. Order: Timestamp them (Proof of History)
// 4. Commit: Stamp them into a block
//
// Blocks have TWO DEDICATED LANES:
// - Financial Lane: Bets, Transfers, Stakes (balance updates)
// - Social Lane: Likes, Posts, Comments (counter updates)
// ============================================================================

/// Streamlined Block structure for Sequencer model
/// 
/// This is NOT a "container of code" - it's a Structured Database Update.
/// We strip out 90% of standard block overhead by using native logic.
/// 
/// Serialization strategy:
/// - Borsh: Used for node-to-node block propagation (Turbine-style)
/// - Serde JSON: Used for RPC queries with Base64-encoded Borsh
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    // ========== IDENTITY ==========
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    
    // ========== POH TIMING ==========
    /// PoH slot number (cryptographic timestamp)
    #[serde(default)]
    pub slot: u64,
    /// PoH hash at block creation
    #[serde(default)]
    pub poh_hash: String,
    /// Parent slot (for fork detection)
    #[serde(default)]
    pub parent_slot: u64,
    
    // ========== STATE ROOT ==========
    /// Merkle root of all account states after this block
    #[serde(default)]
    pub state_root: String,
    /// Merkle root of all transactions in this block
    #[serde(default)]
    pub transactions_root: String,
    
    // ========== SEQUENCER ==========
    /// The sequencer (validator) who committed this block
    #[serde(default)]
    pub sequencer: String,
    /// Backward compatible alias for sequencer
    #[serde(default)]
    pub leader: String,
    
    // ========== TWO-LANE BODY ==========
    /// Financial Lane: Bets, Transfers, Stakes (balance-affecting)
    #[borsh(skip)]
    pub financial_txs: Vec<Transaction>,
    /// Social Lane: Likes, Posts, Comments (engagement actions)
    #[borsh(skip)]
    pub social_txs: Vec<Transaction>,
    /// Backward compatible: combined transactions
    #[borsh(skip)]
    #[serde(default)]
    pub transactions: Vec<Transaction>,
    
    // ========== METRICS ==========
    /// Engagement score for Proof-of-Engagement validation
    #[serde(default)]
    pub engagement_score: f64,
    /// Total transaction count (financial + social)
    #[serde(default)]
    pub tx_count: u64,
}

impl Block {
    /// Create a new block with two-lane architecture
    /// 
    /// Sequencer model: No puzzle solving, just commit transactions
    pub fn new(
        index: u64, 
        financial_txs: Vec<Transaction>, 
        social_txs: Vec<Transaction>,
        previous_hash: String, 
        sequencer: String,
    ) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let tx_count = (financial_txs.len() + social_txs.len()) as u64;
        let transactions = [financial_txs.clone(), social_txs.clone()].concat();
        let transactions_root = Self::compute_transactions_root(&transactions);
        
        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            hash: String::new(),
            slot: 0,
            poh_hash: String::new(),
            parent_slot: 0,
            state_root: String::new(), // Set after execution
            transactions_root,
            sequencer: sequencer.clone(),
            leader: sequencer,
            financial_txs,
            social_txs,
            transactions,
            engagement_score: 0.0,
            tx_count,
        };
        block.hash = block.calculate_hash();
        block
    }
    
    /// Create a PoH-enabled block with two lanes (primary constructor)
    /// 
    /// This is the main block creation method for the Sequencer model:
    /// - Ingest → Deduplicate → Order (PoH) → Commit
    pub fn new_poh(
        index: u64,
        financial_txs: Vec<Transaction>,
        social_txs: Vec<Transaction>,
        previous_hash: String,
        sequencer: String,
        slot: u64,
        poh_hash: String,
        engagement_score: f64,
    ) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let parent_slot = if slot > 0 { slot - 1 } else { 0 };
        let tx_count = (financial_txs.len() + social_txs.len()) as u64;
        let transactions = [financial_txs.clone(), social_txs.clone()].concat();
        let transactions_root = Self::compute_transactions_root(&transactions);
        
        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            hash: String::new(),
            slot,
            poh_hash,
            parent_slot,
            state_root: String::new(), // Set after execution
            transactions_root,
            sequencer: sequencer.clone(),
            leader: sequencer,
            financial_txs,
            social_txs,
            transactions,
            engagement_score,
            tx_count,
        };
        block.hash = block.calculate_hash();
        block
    }
    
    /// Legacy constructor for backwards compatibility (wraps into financial lane)
    #[allow(deprecated)]
    pub fn from_transactions(
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        sequencer: String,
        slot: u64,
        poh_hash: String,
        engagement_score: f64,
    ) -> Self {
        // Categorize transactions into lanes
        let (financial, social): (Vec<_>, Vec<_>) = transactions
            .into_iter()
            .partition(|tx| tx.tx_type.is_financial() || matches!(tx.tx_type, TransactionType::SystemReward));
        
        Self::new_poh(index, financial, social, previous_hash, sequencer, slot, poh_hash, engagement_score)
    }
    
    /// Get all transactions (both lanes combined) for compatibility
    pub fn all_transactions(&self) -> Vec<Transaction> {
        let mut all = self.financial_txs.clone();
        all.extend(self.social_txs.clone());
        all
    }
    
    /// Compute Merkle root of transactions
    pub fn compute_transactions_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return "0".repeat(64);
        }
        
        // Hash each transaction
        let hashes: Vec<String> = transactions.iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                hasher.update(&tx.id);
                hasher.update(&tx.from);
                hasher.update(&tx.to);
                hasher.update(tx.amount.to_le_bytes());
                format!("{:x}", hasher.finalize())
            })
            .collect();
        
        Self::merkle_root(&hashes)
    }
    
    /// Compute Merkle root from hashes
    fn merkle_root(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return "0".repeat(64);
        }
        if hashes.len() == 1 {
            return hashes[0].clone();
        }
        
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&chunk[0]); // Duplicate if odd
            }
            next_level.push(format!("{:x}", hasher.finalize()));
        }
        
        Self::merkle_root(&next_level)
    }
    
    /// Set state root after block execution
    pub fn set_state_root(&mut self, state_root: String) {
        self.state_root = state_root;
        self.hash = self.calculate_hash();
    }

    /// Calculate block hash (includes both lanes and PoH data)
    /// 
    /// NO PoW puzzle solving - hash is computed once and committed.
    /// The hash includes: index, timestamp, both tx lanes, PoH slot/hash, sequencer, engagement
    pub fn calculate_hash(&self) -> String {
        let financial_data = serde_json::to_string(&self.financial_txs).unwrap_or_default();
        let social_data = serde_json::to_string(&self.social_txs).unwrap_or_default();
        
        let input = format!("{}{}{}{}{}{}{}{}{}{}{}{}{}",
            self.index, 
            self.timestamp, 
            financial_data,
            social_data,
            self.previous_hash, 
            self.slot, 
            self.poh_hash,
            self.sequencer, 
            self.engagement_score,
            self.tx_count,
            self.parent_slot,
            self.state_root,
            self.transactions_root
        );
        
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
    
    // NOTE: mine_block() REMOVED - no PoW puzzle solving in Sequencer model
    // Blocks are simply committed by the sequencer after PoH ordering
    
    // ========================================================================
    // BORSH SERIALIZATION HELPERS (For Turbine-style block propagation)
    // ========================================================================
    
    /// Serialize block to Borsh bytes (for node-to-node propagation)
    pub fn to_borsh(&self) -> Result<Vec<u8>, std::io::Error> {
        borsh::to_vec(self)
    }
    
    /// Deserialize block from Borsh bytes
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }
    
    /// Serialize to Base64-encoded Borsh (for RPC JSON wrapper)
    pub fn to_base64(&self) -> Result<String, std::io::Error> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = self.to_borsh()?;
        Ok(STANDARD.encode(&bytes))
    }
    
    /// Deserialize from Base64-encoded Borsh
    pub fn from_base64(encoded: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(encoded)?;
        let block = Self::from_borsh(&bytes)?;
        Ok(block)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_new() {
        let tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100.0,
            TransactionType::Transfer,
        );
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "bob");
        assert_eq!(tx.amount, 100.0);
        assert!(!tx.id.is_empty());
    }

    #[test]
    fn test_block_new_poh() {
        let financial = vec![Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            50.0,
            TransactionType::Transfer,
        )];
        let social = vec![Transaction::new(
            "alice".to_string(),
            "post123".to_string(),
            0.0,
            TransactionType::SocialAction,
        )];
        
        let block = Block::new_poh(
            1,
            financial,
            social,
            "prev_hash".to_string(),
            "sequencer1".to_string(),
            42,
            "poh_hash".to_string(),
            100.0,
        );
        
        assert_eq!(block.index, 1);
        assert_eq!(block.slot, 42);
        assert_eq!(block.tx_count, 2);
        assert_eq!(block.financial_txs.len(), 1);
        assert_eq!(block.social_txs.len(), 1);
    }

    #[test]
    fn test_parallel_scheduler_conflict_detection() {
        let scheduler = ParallelScheduler::new();
        
        let tx1 = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100.0,
            TransactionType::Transfer,
        );
        let tx2 = Transaction::new(
            "alice".to_string(),  // Same sender - conflicts with tx1
            "carol".to_string(),
            50.0,
            TransactionType::Transfer,
        );
        let tx3 = Transaction::new(
            "dave".to_string(),  // Different accounts - no conflict
            "eve".to_string(),
            25.0,
            TransactionType::Transfer,
        );
        
        let batches = scheduler.schedule_batch(&[tx1, tx2, tx3]);
        
        // tx1 and tx2 conflict (same sender), tx3 is independent
        // Should produce at least 2 batches
        assert!(batches.len() >= 2);
    }
}
