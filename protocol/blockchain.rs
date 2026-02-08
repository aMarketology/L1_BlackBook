// ============================================================================
// BlackBook L1 Protocol - Digital Central Bank & Vault
// ============================================================================
//
// Three Core Jobs:
//   1. GATEKEEPER (Tier 1): USDT → $BB at 1:10 ratio
//   2. TIME MACHINE (Tier 2): $BB → $DIME with vintage stamps (inflation protection)
//   3. SSS WALLET: Shamir Secret Sharing (handled in wallet_mnemonic module)
//
// Invariants:
//   - Tier 1: vault_usdt * 10 = total_bb_supply (always!)
//   - Tier 2: sum(vintage_bb_locked) = total_bb_in_vault
//
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ============================================================================
// CONSTANTS
// ============================================================================

/// 1 USDT = 10 $BB (fixed ratio)
pub const USDT_TO_BB_RATIO: u64 = 10;

/// Decimals for all tokens (6, like USDC/USDT)
pub const TOKEN_DECIMALS: u8 = 6;

/// Default base CPI (100.0 = baseline)
pub const DEFAULT_BASE_CPI: f64 = 100.0;

/// Oracle PDA address
pub const CPI_ORACLE_ADDRESS: &str = "CPI_ORACLE_PDA";

/// Tier 1 Gateway PDA
pub const TIER1_GATEWAY_PDA: &str = "TIER1_GATEWAY_PDA";

/// Tier 2 Vault PDA  
pub const TIER2_VAULT_PDA: &str = "TIER2_VAULT_PDA";

// ============================================================================
// TOKENS
// ============================================================================

/// BlackBook Token ($BB) - 10-cent stablecoin backed by USDT
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlackBookLedger {
    pub balances: HashMap<String, u64>,  // address -> balance (6 decimals)
    pub total_supply: u64,
}

/// DIME Token - Inflation-protected savings token
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DimeLedger {
    pub balances: HashMap<String, u64>,  // address -> balance (6 decimals)
    pub total_supply: u64,
}

// ============================================================================
// TIER 1: USDT → $BB GATEWAY (The Gatekeeper)
// ============================================================================

/// Tier 1 Gateway - Manages USDT deposits and $BB minting
/// INVARIANT: vault_usdt_balance * 10 = total_bb_minted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1Gateway {
    /// Total USDT locked in the reserve vault (6 decimals)
    pub vault_usdt_balance: u64,
    
    /// Total $BB minted through this gateway
    pub total_bb_minted: u64,
    
    /// Deposit history for audit trail
    pub deposits: Vec<Tier1Deposit>,
    
    /// Is gateway active (can pause for emergencies)
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier1Deposit {
    pub user: String,
    pub usdt_amount: u64,
    pub bb_minted: u64,
    pub timestamp: u64,
    pub external_tx_hash: Option<String>,
}

impl Default for Tier1Gateway {
    fn default() -> Self {
        Self {
            vault_usdt_balance: 0,
            total_bb_minted: 0,
            deposits: Vec::new(),
            is_active: true,
        }
    }
}

impl Tier1Gateway {
    /// Check solvency invariant: vault_usdt * 10 = total_bb
    pub fn check_solvency(&self) -> bool {
        self.vault_usdt_balance.checked_mul(USDT_TO_BB_RATIO)
            .map(|expected| expected == self.total_bb_minted)
            .unwrap_or(false)
    }
}

// ============================================================================
// TIER 2: $BB → $DIME VAULT (The Time Machine)
// ============================================================================

/// Tier 2 Inflation Vault - Protects purchasing power with vintages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Vault {
    /// Total $BB locked in this vault
    pub total_bb_locked: u64,
    
    /// Total $DIME outstanding
    pub total_dime_supply: u64,
    
    /// Current CPI index (e.g., 103.2 for 3.2% inflation since launch)
    pub current_cpi: f64,
    
    /// Base CPI at system launch (denominator)
    pub base_cpi: f64,
    
    /// All vintages (vintage_id -> Vintage)
    pub vintages: HashMap<String, DimeVintage>,
    
    /// User's vintage IDs (user -> [vintage_ids])
    pub user_vintages: HashMap<String, Vec<String>>,
    
    /// Is vault active
    pub is_active: bool,
    
    /// Last CPI update timestamp
    pub last_cpi_update: u64,
}

/// A DIME Vintage - "stamps" the purchase price forever
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimeVintage {
    pub id: String,
    pub owner: String,
    
    /// The EXACT $BB amount locked (returned on redemption)
    pub bb_locked: u64,
    
    /// $DIME minted for this vintage
    pub dime_minted: u64,
    
    /// CPI at time of lock (the "stamp")
    pub cpi_at_lock: f64,
    
    /// Timestamp when created
    pub created_at: u64,
    
    /// Has this been redeemed?
    pub is_redeemed: bool,
}

impl Default for Tier2Vault {
    fn default() -> Self {
        Self {
            total_bb_locked: 0,
            total_dime_supply: 0,
            current_cpi: DEFAULT_BASE_CPI,
            base_cpi: DEFAULT_BASE_CPI,
            vintages: HashMap::new(),
            user_vintages: HashMap::new(),
            is_active: true,
            last_cpi_update: 0,
        }
    }
}

impl Tier2Vault {
    /// Check invariant: sum of unredeemed vintage bb_locked = total_bb_locked
    pub fn check_invariant(&self) -> bool {
        let sum: u64 = self.vintages.values()
            .filter(|v| !v.is_redeemed)
            .map(|v| v.bb_locked)
            .sum();
        sum == self.total_bb_locked
    }
    
    /// Convert $BB to $DIME at current CPI
    /// Higher CPI = fewer $DIME per $BB
    pub fn bb_to_dime(&self, bb_amount: u64) -> u64 {
        let ratio = self.base_cpi / self.current_cpi;
        (bb_amount as f64 * ratio) as u64
    }
}

// ============================================================================
// ACCOUNT SECURITY (SSS Wallet Support)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSecurity {
    pub root_pubkey: String,              // Root key (SSS-backed, offline)
    pub authorized_op_pubkeys: HashSet<String>, // Op keys for daily use
    pub kdf_params_hash: String,          // KDF commitment
    pub sequence: u64,                    // Replay protection
    pub created_at: u64,
}

// ============================================================================
// TRANSACTIONS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub timestamp: u64,
    pub data: TxData,
    pub signature: String,
    pub signer_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxData {
    // ========== Account Operations ==========
    CreateAccount {
        root_pubkey: String,
        initial_op_pubkey: String,
        kdf_params_hash: String,
    },
    
    RotateOpKey {
        new_op_pubkey: String,
        kdf_params_hash: String,
    },
    
    // ========== Tier 1: USDT → $BB ==========
    
    /// Deposit USDT, mint $BB at 1:10 ratio
    DepositUsdt {
        usdt_amount: u64,
        external_tx_hash: Option<String>,
    },
    
    /// Redeem $BB for USDT
    RedeemBbForUsdt {
        bb_amount: u64,
    },
    
    // ========== Tier 2: $BB → $DIME ==========
    
    /// Lock $BB, mint $DIME with vintage stamp
    LockBbForDime {
        bb_amount: u64,
    },
    
    /// Redeem vintage for exact original $BB
    RedeemDimeVintage {
        vintage_id: String,
    },
    
    // ========== Oracle ==========
    
    /// Update CPI index (oracle only)
    UpdateCpi {
        new_cpi_index: f64,
    },
    
    // ========== Token Operations ==========
    
    /// Transfer $BB between accounts
    TransferBb {
        to: String,
        amount: u64,
    },
    
    /// Transfer $DIME between accounts
    TransferDime {
        to: String,
        amount: u64,
    },
}

// ============================================================================
// EVENTS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L1Event {
    AccountCreated { user: String, timestamp: u64 },
    
    // Tier 1 Events
    UsdtDeposited { user: String, usdt_amount: u64, bb_minted: u64, timestamp: u64 },
    BbRedeemed { user: String, bb_amount: u64, usdt_released: u64, timestamp: u64 },
    
    // Tier 2 Events
    BbLocked { user: String, bb_amount: u64, dime_minted: u64, vintage_id: String, timestamp: u64 },
    VintageRedeemed { user: String, vintage_id: String, dime_burned: u64, bb_released: u64, timestamp: u64 },
    
    // Oracle Events
    CpiUpdated { old_cpi: f64, new_cpi: f64, timestamp: u64 },
    
    // Transfer Events
    BbTransfer { from: String, to: String, amount: u64, timestamp: u64 },
    DimeTransfer { from: String, to: String, amount: u64, timestamp: u64 },
}

// ============================================================================
// L1 STATE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1State {
    // Account registry
    pub accounts: HashMap<String, AccountSecurity>,
    
    // Token ledgers
    pub bb_ledger: BlackBookLedger,
    pub dime_ledger: DimeLedger,
    
    // Two-Tier Vault System
    pub tier1: Tier1Gateway,
    pub tier2: Tier2Vault,
    
    // Event log
    pub events: Vec<L1Event>,
    
    // Block tracking  
    pub block_height: u64,
}

impl Default for L1State {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
            bb_ledger: BlackBookLedger::default(),
            dime_ledger: DimeLedger::default(),
            tier1: Tier1Gateway::default(),
            tier2: Tier2Vault::default(),
            events: Vec::new(),
            block_height: 0,
        }
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Account already exists: {0}")]
    AccountExists(String),
    
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    
    #[error("Unauthorized signer")]
    UnauthorizedSigner,
    
    #[error("Root key required for this operation")]
    RootKeyRequired,
    
    #[error("Insufficient $BB: have {have}, need {need}")]
    InsufficientBB { have: u64, need: u64 },
    
    #[error("Insufficient $DIME: have {have}, need {need}")]
    InsufficientDime { have: u64, need: u64 },
    
    #[error("Insufficient USDT in vault: have {have}, need {need}")]
    InsufficientVaultUsdt { have: u64, need: u64 },
    
    #[error("Vintage not found: {0}")]
    VintageNotFound(String),
    
    #[error("Vintage already redeemed: {0}")]
    VintageAlreadyRedeemed(String),
    
    #[error("Not vintage owner")]
    NotVintageOwner,
    
    #[error("Solvency violation: Tier 1 invariant broken")]
    Tier1SolvencyViolation,
    
    #[error("Invariant violation: Tier 2 invariant broken")]
    Tier2InvariantViolation,
    
    #[error("Gateway is paused")]
    GatewayPaused,
    
    #[error("Vault is paused")]
    VaultPaused,
    
    #[error("Unauthorized oracle")]
    UnauthorizedOracle,
    
    #[error("Invalid amount")]
    InvalidAmount,
    
    #[error("Overflow")]
    Overflow,
}

// ============================================================================
// STATE MACHINE IMPLEMENTATION
// ============================================================================

impl L1State {
    /// Apply a transaction to the state
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        // Authenticate (skip for account creation)
        if !matches!(tx.data, TxData::CreateAccount { .. }) {
            self.authenticate(tx)?;
        }
        
        match &tx.data {
            TxData::CreateAccount { root_pubkey, initial_op_pubkey, kdf_params_hash } => {
                self.create_account(&tx.from, root_pubkey, initial_op_pubkey, kdf_params_hash, tx.timestamp)
            }
            
            TxData::RotateOpKey { new_op_pubkey, kdf_params_hash } => {
                self.rotate_op_key(&tx.from, new_op_pubkey, kdf_params_hash, &tx.signer_pubkey, tx.timestamp)
            }
            
            TxData::DepositUsdt { usdt_amount, external_tx_hash } => {
                self.deposit_usdt(&tx.from, *usdt_amount, external_tx_hash.clone(), tx.timestamp)
            }
            
            TxData::RedeemBbForUsdt { bb_amount } => {
                self.redeem_bb_for_usdt(&tx.from, *bb_amount, tx.timestamp)
            }
            
            TxData::LockBbForDime { bb_amount } => {
                self.lock_bb_for_dime(&tx.from, *bb_amount, tx.timestamp)
            }
            
            TxData::RedeemDimeVintage { vintage_id } => {
                self.redeem_dime_vintage(&tx.from, vintage_id, tx.timestamp)
            }
            
            TxData::UpdateCpi { new_cpi_index } => {
                self.update_cpi(&tx.from, *new_cpi_index, tx.timestamp)
            }
            
            TxData::TransferBb { to, amount } => {
                self.transfer_bb(&tx.from, to, *amount, tx.timestamp)
            }
            
            TxData::TransferDime { to, amount } => {
                self.transfer_dime(&tx.from, to, *amount, tx.timestamp)
            }
        }
    }
    
    // ========== Authentication ==========
    
    fn authenticate(&self, tx: &Transaction) -> Result<(), ChainError> {
        // Oracle has special auth
        if tx.from == CPI_ORACLE_ADDRESS {
            return Ok(());
        }
        
        let account = self.accounts.get(&tx.from)
            .ok_or_else(|| ChainError::AccountNotFound(tx.from.clone()))?;
        
        let is_root = tx.signer_pubkey == account.root_pubkey;
        let is_op = account.authorized_op_pubkeys.contains(&tx.signer_pubkey);
        
        if !is_root && !is_op {
            return Err(ChainError::UnauthorizedSigner);
        }
        
        Ok(())
    }
    
    // ========== Account Operations ==========
    
    fn create_account(&mut self, address: &str, root: &str, op: &str, kdf: &str, ts: u64) -> Result<(), ChainError> {
        if self.accounts.contains_key(address) {
            return Err(ChainError::AccountExists(address.to_string()));
        }
        
        let mut ops = HashSet::new();
        ops.insert(op.to_string());
        
        self.accounts.insert(address.to_string(), AccountSecurity {
            root_pubkey: root.to_string(),
            authorized_op_pubkeys: ops,
            kdf_params_hash: kdf.to_string(),
            sequence: 0,
            created_at: ts,
        });
        
        self.events.push(L1Event::AccountCreated {
            user: address.to_string(),
            timestamp: ts,
        });
        
        Ok(())
    }
    
    fn rotate_op_key(&mut self, user: &str, new_op: &str, kdf: &str, signer: &str, _ts: u64) -> Result<(), ChainError> {
        let account = self.accounts.get_mut(user)
            .ok_or_else(|| ChainError::AccountNotFound(user.to_string()))?;
        
        if signer != account.root_pubkey {
            return Err(ChainError::RootKeyRequired);
        }
        
        account.authorized_op_pubkeys.clear();
        account.authorized_op_pubkeys.insert(new_op.to_string());
        account.kdf_params_hash = kdf.to_string();
        
        Ok(())
    }
    
    // ========== Tier 1: USDT → $BB ==========
    
    fn deposit_usdt(&mut self, user: &str, usdt_amount: u64, external_tx: Option<String>, ts: u64) -> Result<(), ChainError> {
        if !self.tier1.is_active {
            return Err(ChainError::GatewayPaused);
        }
        
        if usdt_amount == 0 {
            return Err(ChainError::InvalidAmount);
        }
        
        // Calculate $BB to mint (1:10 ratio)
        let bb_to_mint = usdt_amount.checked_mul(USDT_TO_BB_RATIO)
            .ok_or(ChainError::Overflow)?;
        
        // Update Tier 1 vault
        self.tier1.vault_usdt_balance = self.tier1.vault_usdt_balance
            .checked_add(usdt_amount).ok_or(ChainError::Overflow)?;
        self.tier1.total_bb_minted = self.tier1.total_bb_minted
            .checked_add(bb_to_mint).ok_or(ChainError::Overflow)?;
        
        // Record deposit
        self.tier1.deposits.push(Tier1Deposit {
            user: user.to_string(),
            usdt_amount,
            bb_minted: bb_to_mint,
            timestamp: ts,
            external_tx_hash: external_tx,
        });
        
        // Credit $BB to user
        *self.bb_ledger.balances.entry(user.to_string()).or_insert(0) += bb_to_mint;
        self.bb_ledger.total_supply += bb_to_mint;
        
        // Verify solvency
        if !self.tier1.check_solvency() {
            return Err(ChainError::Tier1SolvencyViolation);
        }
        
        self.events.push(L1Event::UsdtDeposited {
            user: user.to_string(),
            usdt_amount,
            bb_minted: bb_to_mint,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    fn redeem_bb_for_usdt(&mut self, user: &str, bb_amount: u64, ts: u64) -> Result<(), ChainError> {
        if !self.tier1.is_active {
            return Err(ChainError::GatewayPaused);
        }
        
        if bb_amount == 0 {
            return Err(ChainError::InvalidAmount);
        }
        
        // Check user has enough $BB
        let user_bb = self.bb_ledger.balances.get(user).copied().unwrap_or(0);
        if user_bb < bb_amount {
            return Err(ChainError::InsufficientBB { have: user_bb, need: bb_amount });
        }
        
        // Calculate USDT to release
        let usdt_to_release = bb_amount / USDT_TO_BB_RATIO;
        
        // Check vault has enough USDT
        if self.tier1.vault_usdt_balance < usdt_to_release {
            return Err(ChainError::InsufficientVaultUsdt {
                have: self.tier1.vault_usdt_balance,
                need: usdt_to_release,
            });
        }
        
        // Burn $BB from user
        *self.bb_ledger.balances.get_mut(user).unwrap() -= bb_amount;
        self.bb_ledger.total_supply -= bb_amount;
        
        // Update Tier 1 vault
        self.tier1.vault_usdt_balance -= usdt_to_release;
        self.tier1.total_bb_minted -= bb_amount;
        
        // Verify solvency
        if !self.tier1.check_solvency() {
            return Err(ChainError::Tier1SolvencyViolation);
        }
        
        self.events.push(L1Event::BbRedeemed {
            user: user.to_string(),
            bb_amount,
            usdt_released: usdt_to_release,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    // ========== Tier 2: $BB → $DIME ==========
    
    fn lock_bb_for_dime(&mut self, user: &str, bb_amount: u64, ts: u64) -> Result<(), ChainError> {
        if !self.tier2.is_active {
            return Err(ChainError::VaultPaused);
        }
        
        if bb_amount == 0 {
            return Err(ChainError::InvalidAmount);
        }
        
        // Check user has enough $BB
        let user_bb = self.bb_ledger.balances.get(user).copied().unwrap_or(0);
        if user_bb < bb_amount {
            return Err(ChainError::InsufficientBB { have: user_bb, need: bb_amount });
        }
        
        // Calculate $DIME to mint (adjusted for CPI)
        let dime_to_mint = self.tier2.bb_to_dime(bb_amount);
        
        // Generate vintage ID
        let vintage_id = format!("vtg_{}_{}_{}", user, ts, self.tier2.vintages.len());
        
        // Create vintage (stamps the purchase price)
        let vintage = DimeVintage {
            id: vintage_id.clone(),
            owner: user.to_string(),
            bb_locked: bb_amount,
            dime_minted: dime_to_mint,
            cpi_at_lock: self.tier2.current_cpi,
            created_at: ts,
            is_redeemed: false,
        };
        
        // Deduct $BB from user (it's now locked in vault)
        *self.bb_ledger.balances.get_mut(user).unwrap() -= bb_amount;
        self.bb_ledger.total_supply -= bb_amount;
        
        // Update Tier 2 vault
        self.tier2.total_bb_locked += bb_amount;
        self.tier2.total_dime_supply += dime_to_mint;
        self.tier2.vintages.insert(vintage_id.clone(), vintage);
        self.tier2.user_vintages.entry(user.to_string()).or_default().push(vintage_id.clone());
        
        // Credit $DIME to user
        *self.dime_ledger.balances.entry(user.to_string()).or_insert(0) += dime_to_mint;
        self.dime_ledger.total_supply += dime_to_mint;
        
        // Verify invariant
        if !self.tier2.check_invariant() {
            return Err(ChainError::Tier2InvariantViolation);
        }
        
        self.events.push(L1Event::BbLocked {
            user: user.to_string(),
            bb_amount,
            dime_minted: dime_to_mint,
            vintage_id,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    fn redeem_dime_vintage(&mut self, user: &str, vintage_id: &str, ts: u64) -> Result<(), ChainError> {
        if !self.tier2.is_active {
            return Err(ChainError::VaultPaused);
        }
        
        // Get vintage
        let vintage = self.tier2.vintages.get(vintage_id)
            .ok_or_else(|| ChainError::VintageNotFound(vintage_id.to_string()))?;
        
        // Verify ownership
        if vintage.owner != user {
            return Err(ChainError::NotVintageOwner);
        }
        
        // Verify not already redeemed
        if vintage.is_redeemed {
            return Err(ChainError::VintageAlreadyRedeemed(vintage_id.to_string()));
        }
        
        let bb_to_release = vintage.bb_locked;
        let dime_to_burn = vintage.dime_minted;
        
        // Check user has enough $DIME
        let user_dime = self.dime_ledger.balances.get(user).copied().unwrap_or(0);
        if user_dime < dime_to_burn {
            return Err(ChainError::InsufficientDime { have: user_dime, need: dime_to_burn });
        }
        
        // Mark vintage as redeemed
        self.tier2.vintages.get_mut(vintage_id).unwrap().is_redeemed = true;
        
        // Burn $DIME from user
        *self.dime_ledger.balances.get_mut(user).unwrap() -= dime_to_burn;
        self.dime_ledger.total_supply -= dime_to_burn;
        
        // Update Tier 2 vault
        self.tier2.total_bb_locked -= bb_to_release;
        self.tier2.total_dime_supply -= dime_to_burn;
        
        // Credit $BB back to user (the EXACT original amount)
        *self.bb_ledger.balances.entry(user.to_string()).or_insert(0) += bb_to_release;
        self.bb_ledger.total_supply += bb_to_release;
        
        // Verify invariant
        if !self.tier2.check_invariant() {
            return Err(ChainError::Tier2InvariantViolation);
        }
        
        self.events.push(L1Event::VintageRedeemed {
            user: user.to_string(),
            vintage_id: vintage_id.to_string(),
            dime_burned: dime_to_burn,
            bb_released: bb_to_release,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    // ========== Oracle ==========
    
    fn update_cpi(&mut self, caller: &str, new_cpi: f64, ts: u64) -> Result<(), ChainError> {
        if caller != CPI_ORACLE_ADDRESS {
            return Err(ChainError::UnauthorizedOracle);
        }
        
        if new_cpi <= 0.0 {
            return Err(ChainError::InvalidAmount);
        }
        
        let old_cpi = self.tier2.current_cpi;
        self.tier2.current_cpi = new_cpi;
        self.tier2.last_cpi_update = ts;
        
        self.events.push(L1Event::CpiUpdated {
            old_cpi,
            new_cpi,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    // ========== Token Transfers ==========
    
    fn transfer_bb(&mut self, from: &str, to: &str, amount: u64, ts: u64) -> Result<(), ChainError> {
        if amount == 0 {
            return Err(ChainError::InvalidAmount);
        }
        
        let from_bal = self.bb_ledger.balances.get(from).copied().unwrap_or(0);
        if from_bal < amount {
            return Err(ChainError::InsufficientBB { have: from_bal, need: amount });
        }
        
        *self.bb_ledger.balances.get_mut(from).unwrap() -= amount;
        *self.bb_ledger.balances.entry(to.to_string()).or_insert(0) += amount;
        
        self.events.push(L1Event::BbTransfer {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    fn transfer_dime(&mut self, from: &str, to: &str, amount: u64, ts: u64) -> Result<(), ChainError> {
        if amount == 0 {
            return Err(ChainError::InvalidAmount);
        }
        
        let from_bal = self.dime_ledger.balances.get(from).copied().unwrap_or(0);
        if from_bal < amount {
            return Err(ChainError::InsufficientDime { have: from_bal, need: amount });
        }
        
        *self.dime_ledger.balances.get_mut(from).unwrap() -= amount;
        *self.dime_ledger.balances.entry(to.to_string()).or_insert(0) += amount;
        
        self.events.push(L1Event::DimeTransfer {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            timestamp: ts,
        });
        
        Ok(())
    }
    
    // ========== Query Methods ==========
    
    pub fn bb_balance(&self, address: &str) -> u64 {
        self.bb_ledger.balances.get(address).copied().unwrap_or(0)
    }
    
    pub fn dime_balance(&self, address: &str) -> u64 {
        self.dime_ledger.balances.get(address).copied().unwrap_or(0)
    }
    
    pub fn get_user_vintages(&self, user: &str) -> Vec<&DimeVintage> {
        self.tier2.user_vintages.get(user)
            .map(|ids| ids.iter().filter_map(|id| self.tier2.vintages.get(id)).collect())
            .unwrap_or_default()
    }
    
    /// Proof of reserves - shows the system is solvent
    pub fn proof_of_reserves(&self) -> ProofOfReserves {
        ProofOfReserves {
            // Tier 1
            tier1_usdt_locked: self.tier1.vault_usdt_balance,
            tier1_bb_minted: self.tier1.total_bb_minted,
            tier1_solvent: self.tier1.check_solvency(),
            
            // Tier 2
            tier2_bb_locked: self.tier2.total_bb_locked,
            tier2_dime_supply: self.tier2.total_dime_supply,
            tier2_valid: self.tier2.check_invariant(),
            
            // Overall
            bb_total_supply: self.bb_ledger.total_supply,
            dime_total_supply: self.dime_ledger.total_supply,
            current_cpi: self.tier2.current_cpi,
        }
    }
}

// ============================================================================
// PROOF OF RESERVES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfReserves {
    // Tier 1: USDT → $BB
    pub tier1_usdt_locked: u64,
    pub tier1_bb_minted: u64,
    pub tier1_solvent: bool,
    
    // Tier 2: $BB → $DIME
    pub tier2_bb_locked: u64,
    pub tier2_dime_supply: u64,
    pub tier2_valid: bool,
    
    // Totals
    pub bb_total_supply: u64,
    pub dime_total_supply: u64,
    pub current_cpi: f64,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_state() -> L1State {
        L1State::default()
    }
    
    fn create_account_tx(address: &str) -> Transaction {
        Transaction {
            hash: format!("tx_{}", address),
            from: address.to_string(),
            timestamp: 1000,
            data: TxData::CreateAccount {
                root_pubkey: format!("root_{}", address),
                initial_op_pubkey: format!("op_{}", address),
                kdf_params_hash: "argon2id".to_string(),
            },
            signature: "sig".to_string(),
            signer_pubkey: format!("root_{}", address),
        }
    }
    
    #[test]
    fn test_tier1_deposit_and_redeem() {
        let mut state = create_test_state();
        
        // Create account
        state.apply_transaction(&create_account_tx("alice")).unwrap();
        
        // Deposit 100 USDT (100_000_000 with 6 decimals)
        let deposit_tx = Transaction {
            hash: "tx_deposit".to_string(),
            from: "alice".to_string(),
            timestamp: 2000,
            data: TxData::DepositUsdt {
                usdt_amount: 100_000_000,
                external_tx_hash: Some("base_tx_123".to_string()),
            },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        
        state.apply_transaction(&deposit_tx).unwrap();
        
        // Should have 1000 $BB (10x ratio)
        assert_eq!(state.bb_balance("alice"), 1_000_000_000);
        assert_eq!(state.tier1.vault_usdt_balance, 100_000_000);
        assert!(state.tier1.check_solvency());
        
        // Redeem 500 $BB for 50 USDT
        let redeem_tx = Transaction {
            hash: "tx_redeem".to_string(),
            from: "alice".to_string(),
            timestamp: 3000,
            data: TxData::RedeemBbForUsdt { bb_amount: 500_000_000 },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        
        state.apply_transaction(&redeem_tx).unwrap();
        
        assert_eq!(state.bb_balance("alice"), 500_000_000);
        assert_eq!(state.tier1.vault_usdt_balance, 50_000_000);
        assert!(state.tier1.check_solvency());
    }
    
    #[test]
    fn test_tier2_lock_and_vintage() {
        let mut state = create_test_state();
        
        // Create account and deposit
        state.apply_transaction(&create_account_tx("alice")).unwrap();
        
        let deposit_tx = Transaction {
            hash: "tx_deposit".to_string(),
            from: "alice".to_string(),
            timestamp: 2000,
            data: TxData::DepositUsdt { usdt_amount: 100_000_000, external_tx_hash: None },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&deposit_tx).unwrap();
        
        // Lock 500 $BB for $DIME
        let lock_tx = Transaction {
            hash: "tx_lock".to_string(),
            from: "alice".to_string(),
            timestamp: 3000,
            data: TxData::LockBbForDime { bb_amount: 500_000_000 },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&lock_tx).unwrap();
        
        // Should have 500 $BB remaining, and 500 $DIME
        assert_eq!(state.bb_balance("alice"), 500_000_000);
        assert_eq!(state.dime_balance("alice"), 500_000_000);
        assert_eq!(state.tier2.total_bb_locked, 500_000_000);
        assert!(state.tier2.check_invariant());
        
        // Get vintage
        let vintages = state.get_user_vintages("alice");
        assert_eq!(vintages.len(), 1);
        assert_eq!(vintages[0].bb_locked, 500_000_000);
    }
    
    #[test]
    fn test_vintage_preserves_value() {
        let mut state = create_test_state();
        
        // Setup
        state.apply_transaction(&create_account_tx("alice")).unwrap();
        let deposit_tx = Transaction {
            hash: "tx1".to_string(),
            from: "alice".to_string(),
            timestamp: 1000,
            data: TxData::DepositUsdt { usdt_amount: 100_000_000, external_tx_hash: None },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&deposit_tx).unwrap();
        
        // Lock $BB at CPI 100
        let lock_tx = Transaction {
            hash: "tx2".to_string(),
            from: "alice".to_string(),
            timestamp: 2000,
            data: TxData::LockBbForDime { bb_amount: 500_000_000 },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&lock_tx).unwrap();
        
        let vintage_id = state.get_user_vintages("alice")[0].id.clone();
        
        // Simulate 50% inflation: CPI goes to 150
        let cpi_tx = Transaction {
            hash: "tx3".to_string(),
            from: CPI_ORACLE_ADDRESS.to_string(),
            timestamp: 3000,
            data: TxData::UpdateCpi { new_cpi_index: 150.0 },
            signature: "oracle_sig".to_string(),
            signer_pubkey: "oracle".to_string(),
        };
        state.apply_transaction(&cpi_tx).unwrap();
        
        // Redeem vintage - should get EXACT original 500 $BB back
        let redeem_tx = Transaction {
            hash: "tx4".to_string(),
            from: "alice".to_string(),
            timestamp: 4000,
            data: TxData::RedeemDimeVintage { vintage_id },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&redeem_tx).unwrap();
        
        // Should have original 1000 $BB back
        assert_eq!(state.bb_balance("alice"), 1_000_000_000);
        assert_eq!(state.dime_balance("alice"), 0);
    }
    
    #[test]
    fn test_proof_of_reserves() {
        let mut state = create_test_state();
        
        state.apply_transaction(&create_account_tx("alice")).unwrap();
        
        let deposit_tx = Transaction {
            hash: "tx1".to_string(),
            from: "alice".to_string(),
            timestamp: 1000,
            data: TxData::DepositUsdt { usdt_amount: 100_000_000, external_tx_hash: None },
            signature: "sig".to_string(),
            signer_pubkey: "op_alice".to_string(),
        };
        state.apply_transaction(&deposit_tx).unwrap();
        
        let proof = state.proof_of_reserves();
        
        assert_eq!(proof.tier1_usdt_locked, 100_000_000);
        assert_eq!(proof.tier1_bb_minted, 1_000_000_000);
        assert!(proof.tier1_solvent);
        assert!(proof.tier2_valid);
    }
}
