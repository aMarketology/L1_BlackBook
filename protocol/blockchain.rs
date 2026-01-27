// ============================================================================
// BlackBook L1 Protocol - Treasury & Blockchain Layer
// ============================================================================
// Architecture:
//   1. Bridge Contract (Base) - Holds USDC, multi-sig controlled
//   2. Wrapped USDC (L1) - 1:1 mint when bridge detects deposit  
//   3. BlackBook Token ($BB) - Only Cashier mints, only Redemption burns
//   4. Cashier Contract - wUSDC → FanGold (L2) + $BB (L1)
//   5. Redemption Contract - Burns $BB, releases value
//   6. Account Security - Dual Key System (Root/Recovery + Operational/Daily)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ============================================================================
// TOKENS
// ============================================================================

/// Wrapped USDC - 1:1 backed by USDC locked on Base
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WusdcLedger {
    pub balances: HashMap<String, u64>,      // address -> balance (6 decimals)
    pub total_supply: u64,                    // Must equal USDC locked on Base
}

/// BlackBook Token ($BB) - The sweepstakes prize token
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlackBookLedger {
    pub balances: HashMap<String, u64>,      // address -> balance (6 decimals)
    pub total_supply: u64,
}

// ============================================================================
// ACCOUNT SECURITY
// ============================================================================

/// Account Security Configuration
/// Implements the "Dual Key" model:
/// - Root Key: High entropy, offline, SSS-backed. Used only for recovery/rotation.
/// - Op Key: Password derived (Argon2id), online. Used for daily signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSecurity {
    pub root_pubkey: String,              // The User's Identity Root
    pub authorized_op_pubkeys: HashSet<String>, // Keys allowed to sign daily txs
    pub kdf_params_hash: String,          // Commit to KDF params (prevents downgrade attacks)
    pub sequence: u64,                    // Replay protection
    pub created_at: u64,
}

// ============================================================================
// CONTRACTS / AUTHORITIES
// ============================================================================

/// Bridge Authority - Multi-sig that controls wUSDC minting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAuthority {
    pub address: String,
    pub signers: Vec<String>,                // Multi-sig participants
    pub threshold: u8,                        // Required signatures
    pub processed_deposits: HashSet<String>, // base_tx_hash -> prevent replay
}

/// Cashier Contract - The ONLY entity that can mint $BB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashierContract {
    pub address: String,
    pub wusdc_received: u64,
    pub bb_minted: u64,
    pub bundles_sold: u64,
}

/// Redemption Contract - The ONLY entity that can burn $BB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionContract {
    pub address: String,
    pub bb_burned: u64,
    pub wusdc_released: u64,
    pub pending_releases: Vec<PendingRelease>, // Awaiting bridge confirmation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRelease {
    pub user: String,
    pub amount: u64,
    pub timestamp: u64,
    pub bridge_tx_hash: Option<String>,
}

// ============================================================================
// BUNDLE CONFIGURATION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub id: String,
    pub name: String,
    pub price_wusdc: u64,                    // Cost in wUSDC (6 decimals)
    pub fan_gold_amount: u64,                // FanGold credited on L2
    pub bb_bonus: u64,                       // $BB minted on L1
    pub active: bool,
}

impl Bundle {
    pub fn starter_pack() -> Self {
        Bundle {
            id: "starter_20".to_string(),
            name: "Starter Pack".to_string(),
            price_wusdc: 20_000_000,         // $20 (6 decimals)
            fan_gold_amount: 20_000,         // 20,000 FanGold
            bb_bonus: 20_000_000,            // 20 $BB (6 decimals)
            active: true,
        }
    }
    
    pub fn whale_pack() -> Self {
        Bundle {
            id: "whale_100".to_string(),
            name: "Whale Pack".to_string(),
            price_wusdc: 100_000_000,        // $100
            fan_gold_amount: 110_000,        // 110,000 FanGold (10% bonus)
            bb_bonus: 100_000_000,           // 100 $BB
            active: true,
        }
    }
}

// ============================================================================
// EVENTS (For L2 Indexer)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L1Event {
    AccountCreated { user: String, timestamp: u64 },
    KeyRotated { user: String, timestamp: u64 },
    
    WusdcMinted {
        user: String,
        amount: u64,
        base_tx_hash: String,
    },
    
    BundlePurchased {
        user: String,
        bundle_id: String,
        wusdc_spent: u64,
        bb_received: u64,
        fan_gold_to_credit: u64,
        timestamp: u64,
    },
    
    Redeemed {
        user: String,
        bb_burned: u64,
        wusdc_released: u64,
        timestamp: u64,
    },
    
    BridgeReleased {
        user: String,
        amount: u64,
        base_tx_hash: String,
    },
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
    pub signer_pubkey: String, // Explicitly state which key signed this
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxData {
    // ========== Security Operations ==========
    
    /// Create new account with Root/Op key separation
    CreateAccount {
        root_pubkey: String,
        initial_op_pubkey: String,
        kdf_params_hash: String, 
    },
    
    /// Rotate Operational Key (Must be signed by ROOT Key)
    RotateOpKey {
        new_op_pubkey: String,
        kdf_params_hash: String,
    },

    // ========== Bridge Operations ==========
    
    BridgeMint {
        recipient: String,
        amount: u64,
        base_tx_hash: String,
    },
    
    // ========== User Operations ==========
    
    TransferWusdc {
        to: String,
        amount: u64,
    },
    
    BuyBundle {
        bundle_id: String,
    },
    
    Redeem {
        amount: u64,
    },
    
    Burn {
        amount: u64,
    },
    
    // ========== Bridge Release ==========
    
    BridgeRelease {
        user: String,
        amount: u64,
        base_tx_hash: String,
    },
}

// ============================================================================
// L1 STATE
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1State {
    // Security Registry
    pub accounts: HashMap<String, AccountSecurity>,
    
    // Token Ledgers
    pub wusdc: WusdcLedger,
    pub blackbook: BlackBookLedger,
    
    // Contracts
    pub bridge: BridgeAuthority,
    pub cashier: CashierContract,
    pub redemption: RedemptionContract,
    
    // Configuration
    pub bundles: HashMap<String, Bundle>,
    
    // Event Log
    pub events: Vec<L1Event>,
    
    pub base_usdc_locked: u64,
    pub block_height: u64,
}

impl Default for L1State {
    fn default() -> Self {
        let mut bundles = HashMap::new();
        let starter = Bundle::starter_pack();
        let whale = Bundle::whale_pack();
        bundles.insert(starter.id.clone(), starter);
        bundles.insert(whale.id.clone(), whale);
        
        Self {
            accounts: HashMap::new(),
            wusdc: WusdcLedger::default(),
            blackbook: BlackBookLedger::default(),
            bridge: BridgeAuthority {
                address: "BRIDGE_AUTHORITY".to_string(),
                signers: vec!["BRIDGE_SIGNER_1".to_string()],
                threshold: 1,
                processed_deposits: HashSet::new(),
            },
            cashier: CashierContract {
                address: "CASHIER_CONTRACT".to_string(),
                wusdc_received: 0,
                bb_minted: 0,
                bundles_sold: 0,
            },
            redemption: RedemptionContract {
                address: "REDEMPTION_CONTRACT".to_string(),
                bb_burned: 0,
                wusdc_released: 0,
                pending_releases: Vec::new(),
            },
            bundles,
            events: Vec::new(),
            base_usdc_locked: 0,
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
    
    #[error("Invalid signature from key: {0}")]
    InvalidSignature(String),
    
    #[error("Unauthorized signer (Key not in authorized list)")]
    UnauthorizedSigner,
    
    #[error("Root Key required for this operation")]
    RootKeyRequired,
    
    #[error("Insufficient wUSDC balance: have {have}, need {need}")]
    InsufficientWusdc { have: u64, need: u64 },
    
    #[error("Insufficient $BB balance: have {have}, need {need}")]
    InsufficientBB { have: u64, need: u64 },
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Bundle not found: {0}")]
    BundleNotFound(String),
    
    #[error("Duplicate bridge deposit: {0}")]
    DuplicateDeposit(String),
    
    #[error("Solvency violation")]
    SolvencyViolation,
}

// ============================================================================
// STATE MACHINE
// ============================================================================

impl L1State {
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        // 1. Authenticate Sender & Key
        self.authenticate(tx)?;
        
        // 2. Route Logic
        match &tx.data {
            TxData::CreateAccount { root_pubkey, initial_op_pubkey, kdf_params_hash } => {
                self.create_account(&tx.from, root_pubkey, initial_op_pubkey, kdf_params_hash, tx.timestamp)?;
            }
            
            TxData::RotateOpKey { new_op_pubkey, kdf_params_hash } => {
                self.rotate_op_key(&tx.from, new_op_pubkey, kdf_params_hash, tx.signer_pubkey.clone(), tx.timestamp)?;
            }
            
            TxData::BridgeMint { recipient, amount, base_tx_hash } => {
                self.bridge_mint(&tx.from, recipient, *amount, base_tx_hash)?;
            }
            
            TxData::TransferWusdc { to, amount } => {
                self.transfer_wusdc(&tx.from, to, *amount)?;
            }
            
            TxData::BuyBundle { bundle_id } => {
                self.buy_bundle(&tx.from, bundle_id, tx.timestamp)?;
            }
            
            TxData::Redeem { amount } => {
                self.redeem(&tx.from, *amount, tx.timestamp)?;
            }

            TxData::Burn { amount } => {
                 let bb_bal = self.blackbook.balances.get(&tx.from).copied().unwrap_or(0);
                 if bb_bal < *amount { return Err(ChainError::InsufficientBB{have: bb_bal, need: *amount}); }
                 
                 *self.blackbook.balances.get_mut(&tx.from).unwrap() -= amount;
                 self.blackbook.total_supply -= amount;
            }
            
            TxData::BridgeRelease { user, amount, base_tx_hash } => {
                self.bridge_release(&tx.from, user, *amount, base_tx_hash)?;
            }
        }
        
        Ok(())
    }
    
    // ========== Security & Auth ==========
    
    fn authenticate(&self, tx: &Transaction) -> Result<(), ChainError> {
        // Special case: CreateAccount creates the entry, so strict auth is skipped (signature verification still applies to the key used)
        if let TxData::CreateAccount { .. } = tx.data {
            // In a real system, we'd verify the signature matches the provided root_pubkey or op_key
            // Here we assume self-signed by root for creation
            return Ok(());
        }
        
        // 1. Check Account Exists
        let account = self.accounts.get(&tx.from);
        
        // 2. Check Signer is Authorized
        // NOTE: Bridge/Cashier/Redemption are special "system accounts" without keys in this simple map, 
        // they are authorized by address check in the logic.
        if tx.from == self.bridge.address || tx.from == self.cashier.address || tx.from == self.redemption.address {
            return Ok(());
        }

        let account = account.ok_or_else(|| ChainError::AccountNotFound(tx.from.clone()))?;
        
        // Root key is always valid signer, but business logic may restrict its uses (e.g. CreateAccount only? No, RotateKey uses it.)
        // But business logic in RotateKey *checks* if signer == root_key.
        // Here we just check "Is this key KNOWN to the account?"
        
        let is_root = tx.signer_pubkey == account.root_pubkey;
        let is_op = account.authorized_op_pubkeys.contains(&tx.signer_pubkey);
        
        if !is_root && !is_op {
            return Err(ChainError::UnauthorizedSigner);
        }
        
        // 3. Verify Signature (Mock)
        // verify(tx.hash, tx.signature, tx.signer_pubkey)
        
        Ok(())
    }
    
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
    
    fn rotate_op_key(&mut self, user: &str, new_op: &str, kdf: &str, signer: String, ts: u64) -> Result<(), ChainError> {
        let account = self.accounts.get_mut(user).unwrap();
        
        // CRITICAL: Only Root Key can rotate/recover
        if signer != account.root_pubkey {
            return Err(ChainError::RootKeyRequired);
        }
        
        // Revoke old Ops (Logic: Clear list, add new one)
        account.authorized_op_pubkeys.clear();
        account.authorized_op_pubkeys.insert(new_op.to_string());
        account.kdf_params_hash = kdf.to_string();
        
        self.events.push(L1Event::KeyRotated {
            user: user.to_string(),
            timestamp: ts,
        });
        
        Ok(())
    }

    // ========== Existing Logic (Bridge/User) ==========
    
    fn bridge_mint(&mut self, sender: &str, recipient: &str, amount: u64, base_tx_hash: &str) -> Result<(), ChainError> {
        if sender != self.bridge.address { return Err(ChainError::Unauthorized("Bridge Only".into())); }
        if self.bridge.processed_deposits.contains(base_tx_hash) { return Err(ChainError::DuplicateDeposit(base_tx_hash.into())); }
        
        *self.wusdc.balances.entry(recipient.to_string()).or_insert(0) += amount;
        self.wusdc.total_supply += amount;
        self.base_usdc_locked += amount;
        self.bridge.processed_deposits.insert(base_tx_hash.to_string());
        
        self.events.push(L1Event::WusdcMinted { user: recipient.into(), amount, base_tx_hash: base_tx_hash.into() });
        Ok(())
    }
    
    fn transfer_wusdc(&mut self, from: &str, to: &str, amount: u64) -> Result<(), ChainError> {
        let bal = self.wusdc.balances.get(from).copied().unwrap_or(0);
        if bal < amount { return Err(ChainError::InsufficientWusdc{have: bal, need: amount}); }
        *self.wusdc.balances.get_mut(from).unwrap() -= amount;
        *self.wusdc.balances.entry(to.to_string()).or_insert(0) += amount;
        Ok(())
    }
    
    fn buy_bundle(&mut self, buyer: &str, bundle_id: &str, ts: u64) -> Result<(), ChainError> {
        let bundle = self.bundles.get(bundle_id).ok_or_else(|| ChainError::BundleNotFound(bundle_id.into()))?.clone();
        
        // 1. Charge wUSDC
        let bal = self.wusdc.balances.get(buyer).copied().unwrap_or(0);
        if bal < bundle.price_wusdc { return Err(ChainError::InsufficientWusdc{have: bal, need: bundle.price_wusdc}); }
        *self.wusdc.balances.get_mut(buyer).unwrap() -= bundle.price_wusdc;
        *self.wusdc.balances.entry(self.cashier.address.clone()).or_insert(0) += bundle.price_wusdc;
        
        // 2. Mint $BB
        *self.blackbook.balances.entry(buyer.to_string()).or_insert(0) += bundle.bb_bonus;
        self.blackbook.total_supply += bundle.bb_bonus;
        
        // 3. Update Stats
        self.cashier.wusdc_received += bundle.price_wusdc;
        self.cashier.bb_minted += bundle.bb_bonus;
        self.cashier.bundles_sold += 1;
        
        self.events.push(L1Event::BundlePurchased {
            user: buyer.to_string(), bundle_id: bundle_id.into(), wusdc_spent: bundle.price_wusdc,
            bb_received: bundle.bb_bonus, fan_gold_to_credit: bundle.fan_gold_amount, timestamp: ts
        });
        Ok(())
    }
    
    fn redeem(&mut self, user: &str, amount: u64, ts: u64) -> Result<(), ChainError> {
        let bb_bal = self.blackbook.balances.get(user).copied().unwrap_or(0);
        if bb_bal < amount { return Err(ChainError::InsufficientBB{have: bb_bal, need: amount}); }
        
        let cash_bal = self.wusdc.balances.get(&self.cashier.address).copied().unwrap_or(0);
        if cash_bal < amount { return Err(ChainError::InsufficientWusdc{have: cash_bal, need: amount}); }
        
        // Burn BB
        *self.blackbook.balances.get_mut(user).unwrap() -= amount;
        self.blackbook.total_supply -= amount;
        
        // Release wUSDC
        *self.wusdc.balances.get_mut(&self.cashier.address).unwrap() -= amount;
        *self.wusdc.balances.entry(user.to_string()).or_insert(0) += amount;
        
        self.redemption.bb_burned += amount;
        self.redemption.wusdc_released += amount;
        
        self.events.push(L1Event::Redeemed { user: user.into(), bb_burned: amount, wusdc_released: amount, timestamp: ts });
        Ok(())
    }
    
    fn bridge_release(&mut self, sender: &str, user: &str, amount: u64, base_tx_hash: &str) -> Result<(), ChainError> {
        if sender != self.bridge.address { return Err(ChainError::Unauthorized("Bridge Only".into())); }
        let bal = self.wusdc.balances.get(user).copied().unwrap_or(0);
        if bal < amount { return Err(ChainError::InsufficientWusdc{have: bal, need: amount}); }
        
        *self.wusdc.balances.get_mut(user).unwrap() -= amount;
        self.wusdc.total_supply -= amount;
        self.base_usdc_locked -= amount;
        
        self.events.push(L1Event::BridgeReleased { user: user.into(), amount, base_tx_hash: base_tx_hash.into() });
        Ok(())
    }
    
    // ========== Query ==========
    
    pub fn wusdc_balance(&self, address: &str) -> u64 { self.wusdc.balances.get(address).copied().unwrap_or(0) }
    pub fn bb_balance(&self, address: &str) -> u64 { self.blackbook.balances.get(address).copied().unwrap_or(0) }
    
    pub fn proof_of_reserves(&self) -> ProofOfReserves {
        ProofOfReserves {
            wusdc_total_supply: self.wusdc.total_supply,
            base_usdc_locked: self.base_usdc_locked,
            bb_total_supply: self.blackbook.total_supply,
            cashier_wusdc: self.wusdc.balances.get(&self.cashier.address).copied().unwrap_or(0),
            bundles_sold: self.cashier.bundles_sold,
            total_redeemed: self.redemption.bb_burned,
            is_solvent: self.wusdc.total_supply == self.base_usdc_locked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfReserves {
    pub wusdc_total_supply: u64,
    pub base_usdc_locked: u64,
    pub bb_total_supply: u64,
    pub cashier_wusdc: u64,
    pub bundles_sold: u64,
    pub total_redeemed: u64,
    pub is_solvent: bool,
}
