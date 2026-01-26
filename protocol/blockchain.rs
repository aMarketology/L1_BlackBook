// ============================================================================
// BlackBook L1 Protocol - Treasury & Blockchain Layer
// ============================================================================
// Architecture:
//   1. Bridge Contract (Base) - Holds USDC, multi-sig controlled
//   2. Wrapped USDC (L1) - 1:1 mint when bridge detects deposit  
//   3. BlackBook Token ($BB) - Only Cashier mints, only Redemption burns
//   4. Cashier Contract - wUSDC → FanGold (L2) + $BB (L1)
//   5. Redemption Contract - Burns $BB, releases value
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ============================================================================
// TOKENS
// ============================================================================

/// Wrapped USDC - 1:1 backed by USDC locked on Base
/// Only the Bridge can mint, transferable by users
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WusdcLedger {
    pub balances: HashMap<String, u64>,      // address -> balance (6 decimals)
    pub total_supply: u64,                    // Must equal USDC locked on Base
}

/// BlackBook Token ($BB) - The sweepstakes prize token
/// Only Cashier can mint, only Redemption can burn
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlackBookLedger {
    pub balances: HashMap<String, u64>,      // address -> balance (6 decimals)
    pub total_supply: u64,
}

// ============================================================================
// CONTRACTS / AUTHORITIES
// ============================================================================

/// Bridge Authority - Multi-sig that controls wUSDC minting
/// Watches Base chain for USDC deposits, mints wUSDC 1:1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAuthority {
    pub address: String,
    pub signers: Vec<String>,                // Multi-sig participants
    pub threshold: u8,                        // Required signatures
    pub processed_deposits: HashSet<String>, // base_tx_hash -> prevent replay
}

/// Cashier Contract - The ONLY entity that can mint $BB
/// Accepts wUSDC, triggers FanGold mint on L2, mints $BB on L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashierContract {
    pub address: String,
    pub wusdc_received: u64,                 // Total wUSDC collected
    pub bb_minted: u64,                      // Total $BB minted
    pub bundles_sold: u64,                   // Count of bundles
}

/// Redemption Contract - The ONLY entity that can burn $BB
/// Checks unplayed balance (via L2 oracle), burns $BB, signals bridge release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionContract {
    pub address: String,
    pub bb_burned: u64,                      // Total $BB burned
    pub wusdc_released: u64,                 // Total wUSDC returned to users
    pub pending_releases: Vec<PendingRelease>, // Awaiting bridge confirmation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRelease {
    pub user: String,
    pub amount: u64,
    pub timestamp: u64,
    pub bridge_tx_hash: Option<String>,      // Set when Base bridge confirms
}

// ============================================================================
// BUNDLE CONFIGURATION
// ============================================================================

/// Bundle defines a purchasable package
/// Example: $20 wUSDC → 20,000 FanGold (L2) + 20 $BB (L1)
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
    /// Bridge minted wUSDC for a user (deposit detected on Base)
    WusdcMinted {
        user: String,
        amount: u64,
        base_tx_hash: String,
    },
    
    /// User purchased a bundle
    BundlePurchased {
        user: String,
        bundle_id: String,
        wusdc_spent: u64,
        bb_received: u64,
        fan_gold_to_credit: u64,             // L2 indexer reads this
        timestamp: u64,
    },
    
    /// User redeemed $BB for value
    Redeemed {
        user: String,
        bb_burned: u64,
        wusdc_released: u64,
        timestamp: u64,
    },
    
    /// Bridge released USDC on Base
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxData {
    // ========== Bridge Operations ==========
    
    /// Bridge mints wUSDC when deposit detected on Base
    /// Sender: Bridge Authority (multi-sig)
    BridgeMint {
        recipient: String,
        amount: u64,
        base_tx_hash: String,                // Proof of Base deposit
    },
    
    // ========== User Operations ==========
    
    /// Transfer wUSDC between accounts
    TransferWusdc {
        to: String,
        amount: u64,
    },
    
    /// Buy a bundle - wUSDC to Cashier, receive $BB
    BuyBundle {
        bundle_id: String,
    },
    
    /// Redeem $BB for wUSDC (triggers bridge release)
    Redeem {
        amount: u64,
    },
    
    // ========== Bridge Release ==========
    
    /// Bridge confirms USDC released on Base
    /// Sender: Bridge Authority (multi-sig)
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
    // Token Ledgers
    pub wusdc: WusdcLedger,
    pub blackbook: BlackBookLedger,
    
    // Contracts
    pub bridge: BridgeAuthority,
    pub cashier: CashierContract,
    pub redemption: RedemptionContract,
    
    // Configuration
    pub bundles: HashMap<String, Bundle>,
    
    // Event Log (for L2 indexer)
    pub events: Vec<L1Event>,
    
    // Proof of Reserves
    pub base_usdc_locked: u64,               // Reported by bridge watchers
    
    // Chain metadata
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
            wusdc: WusdcLedger::default(),
            blackbook: BlackBookLedger::default(),
            bridge: BridgeAuthority {
                address: "BRIDGE_AUTHORITY".to_string(),
                signers: vec![
                    "BRIDGE_SIGNER_1".to_string(),
                    "BRIDGE_SIGNER_2".to_string(),
                    "BRIDGE_SIGNER_3".to_string(),
                ],
                threshold: 2,
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
    #[error("Insufficient wUSDC balance: have {have}, need {need}")]
    InsufficientWusdc { have: u64, need: u64 },
    
    #[error("Insufficient $BB balance: have {have}, need {need}")]
    InsufficientBB { have: u64, need: u64 },
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Bundle not found: {0}")]
    BundleNotFound(String),
    
    #[error("Bundle inactive: {0}")]
    BundleInactive(String),
    
    #[error("Duplicate bridge deposit: {0}")]
    DuplicateDeposit(String),
    
    #[error("Solvency violation: L1 supply {l1_supply} != Base locked {base_locked}")]
    SolvencyViolation { l1_supply: u64, base_locked: u64 },
    
    #[error("User has unplayed balance, cannot redeem")]
    UnplayedBalanceRemaining,
    
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
}

// ============================================================================
// STATE MACHINE
// ============================================================================

impl L1State {
    /// Apply a transaction to the state
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        match &tx.data {
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
            
            TxData::BridgeRelease { user, amount, base_tx_hash } => {
                self.bridge_release(&tx.from, user, *amount, base_tx_hash)?;
            }
        }
        
        Ok(())
    }
    
    // ========== Bridge Operations ==========
    
    /// Bridge mints wUSDC when deposit detected on Base
    /// CRITICAL: Only Bridge Authority can call this
    fn bridge_mint(
        &mut self,
        sender: &str,
        recipient: &str,
        amount: u64,
        base_tx_hash: &str,
    ) -> Result<(), ChainError> {
        // Authorization check
        if sender != self.bridge.address {
            return Err(ChainError::Unauthorized(
                "Only Bridge Authority can mint wUSDC".to_string()
            ));
        }
        
        // Replay protection
        if self.bridge.processed_deposits.contains(base_tx_hash) {
            return Err(ChainError::DuplicateDeposit(base_tx_hash.to_string()));
        }
        
        // Mint wUSDC 1:1
        *self.wusdc.balances.entry(recipient.to_string()).or_insert(0) += amount;
        self.wusdc.total_supply += amount;
        self.base_usdc_locked += amount;
        
        // Mark deposit as processed
        self.bridge.processed_deposits.insert(base_tx_hash.to_string());
        
        // Emit event
        self.events.push(L1Event::WusdcMinted {
            user: recipient.to_string(),
            amount,
            base_tx_hash: base_tx_hash.to_string(),
        });
        
        // Solvency check
        self.verify_solvency()?;
        
        Ok(())
    }
    
    // ========== User Operations ==========
    
    /// Transfer wUSDC between accounts
    fn transfer_wusdc(&mut self, from: &str, to: &str, amount: u64) -> Result<(), ChainError> {
        let balance = self.wusdc.balances.get(from).copied().unwrap_or(0);
        
        if balance < amount {
            return Err(ChainError::InsufficientWusdc {
                have: balance,
                need: amount,
            });
        }
        
        *self.wusdc.balances.get_mut(from).unwrap() -= amount;
        *self.wusdc.balances.entry(to.to_string()).or_insert(0) += amount;
        
        Ok(())
    }
    
    /// Buy a bundle - THE CORE MONETIZATION FLOW
    /// User sends wUSDC → Cashier mints $BB → L2 credits FanGold
    fn buy_bundle(&mut self, buyer: &str, bundle_id: &str, timestamp: u64) -> Result<(), ChainError> {
        // Get bundle configuration
        let bundle = self.bundles.get(bundle_id)
            .ok_or_else(|| ChainError::BundleNotFound(bundle_id.to_string()))?
            .clone();
        
        if !bundle.active {
            return Err(ChainError::BundleInactive(bundle_id.to_string()));
        }
        
        // Check buyer has enough wUSDC
        let balance = self.wusdc.balances.get(buyer).copied().unwrap_or(0);
        if balance < bundle.price_wusdc {
            return Err(ChainError::InsufficientWusdc {
                have: balance,
                need: bundle.price_wusdc,
            });
        }
        
        // ===== ATOMIC SWAP =====
        
        // 1. Debit wUSDC from buyer
        *self.wusdc.balances.get_mut(buyer).unwrap() -= bundle.price_wusdc;
        
        // 2. Credit wUSDC to Cashier (treasury)
        *self.wusdc.balances
            .entry(self.cashier.address.clone())
            .or_insert(0) += bundle.price_wusdc;
        
        // 3. Mint $BB to buyer (ONLY Cashier can do this)
        *self.blackbook.balances.entry(buyer.to_string()).or_insert(0) += bundle.bb_bonus;
        self.blackbook.total_supply += bundle.bb_bonus;
        
        // 4. Update Cashier stats
        self.cashier.wusdc_received += bundle.price_wusdc;
        self.cashier.bb_minted += bundle.bb_bonus;
        self.cashier.bundles_sold += 1;
        
        // ===== EMIT EVENT FOR L2 =====
        // The L2 indexer reads this event and credits FanGold
        self.events.push(L1Event::BundlePurchased {
            user: buyer.to_string(),
            bundle_id: bundle_id.to_string(),
            wusdc_spent: bundle.price_wusdc,
            bb_received: bundle.bb_bonus,
            fan_gold_to_credit: bundle.fan_gold_amount,
            timestamp,
        });
        
        Ok(())
    }
    
    /// Redeem $BB for wUSDC
    /// GATEKEEPER: Must check unplayed balance (via L2 oracle in production)
    fn redeem(&mut self, user: &str, amount: u64, timestamp: u64) -> Result<(), ChainError> {
        if amount == 0 {
            return Err(ChainError::InvalidAmount("Cannot redeem 0".to_string()));
        }
        
        // Check $BB balance
        let bb_balance = self.blackbook.balances.get(user).copied().unwrap_or(0);
        if bb_balance < amount {
            return Err(ChainError::InsufficientBB {
                have: bb_balance,
                need: amount,
            });
        }
        
        // TODO: In production, check L2 oracle for unplayed balance
        // if self.check_unplayed_balance(user) > 0 {
        //     return Err(ChainError::UnplayedBalanceRemaining);
        // }
        
        // Check Cashier has enough wUSDC to release
        let cashier_wusdc = self.wusdc.balances
            .get(&self.cashier.address)
            .copied()
            .unwrap_or(0);
        
        if cashier_wusdc < amount {
            return Err(ChainError::InsufficientWusdc {
                have: cashier_wusdc,
                need: amount,
            });
        }
        
        // ===== ATOMIC REDEMPTION =====
        
        // 1. Burn $BB from user (ONLY Redemption can do this)
        *self.blackbook.balances.get_mut(user).unwrap() -= amount;
        self.blackbook.total_supply -= amount;
        
        // 2. Transfer wUSDC from Cashier to user
        *self.wusdc.balances.get_mut(&self.cashier.address).unwrap() -= amount;
        *self.wusdc.balances.entry(user.to_string()).or_insert(0) += amount;
        
        // 3. Update Redemption stats
        self.redemption.bb_burned += amount;
        self.redemption.wusdc_released += amount;
        
        // 4. Add to pending releases (for bridge to process)
        self.redemption.pending_releases.push(PendingRelease {
            user: user.to_string(),
            amount,
            timestamp,
            bridge_tx_hash: None,
        });
        
        // Emit event
        self.events.push(L1Event::Redeemed {
            user: user.to_string(),
            bb_burned: amount,
            wusdc_released: amount,
            timestamp,
        });
        
        Ok(())
    }
    
    // ========== Bridge Release ==========
    
    /// Bridge confirms USDC released on Base
    fn bridge_release(
        &mut self,
        sender: &str,
        user: &str,
        amount: u64,
        base_tx_hash: &str,
    ) -> Result<(), ChainError> {
        // Authorization check
        if sender != self.bridge.address {
            return Err(ChainError::Unauthorized(
                "Only Bridge Authority can confirm releases".to_string()
            ));
        }
        
        // Burn wUSDC from user (they got real USDC on Base)
        let balance = self.wusdc.balances.get(user).copied().unwrap_or(0);
        if balance < amount {
            return Err(ChainError::InsufficientWusdc {
                have: balance,
                need: amount,
            });
        }
        
        *self.wusdc.balances.get_mut(user).unwrap() -= amount;
        self.wusdc.total_supply -= amount;
        self.base_usdc_locked -= amount;
        
        // Emit event
        self.events.push(L1Event::BridgeReleased {
            user: user.to_string(),
            amount,
            base_tx_hash: base_tx_hash.to_string(),
        });
        
        // Solvency check
        self.verify_solvency()?;
        
        Ok(())
    }
    
    // ========== Invariant Checks ==========
    
    /// Verify solvency: wUSDC supply must equal Base USDC locked
    fn verify_solvency(&self) -> Result<(), ChainError> {
        if self.wusdc.total_supply != self.base_usdc_locked {
            return Err(ChainError::SolvencyViolation {
                l1_supply: self.wusdc.total_supply,
                base_locked: self.base_usdc_locked,
            });
        }
        Ok(())
    }
    
    // ========== Query Methods ==========
    
    /// Get wUSDC balance for an address
    pub fn wusdc_balance(&self, address: &str) -> u64 {
        self.wusdc.balances.get(address).copied().unwrap_or(0)
    }
    
    /// Get $BB balance for an address
    pub fn bb_balance(&self, address: &str) -> u64 {
        self.blackbook.balances.get(address).copied().unwrap_or(0)
    }
    
    /// Get proof of reserves data
    pub fn proof_of_reserves(&self) -> ProofOfReserves {
        ProofOfReserves {
            wusdc_total_supply: self.wusdc.total_supply,
            base_usdc_locked: self.base_usdc_locked,
            bb_total_supply: self.blackbook.total_supply,
            cashier_wusdc: self.wusdc.balances
                .get(&self.cashier.address)
                .copied()
                .unwrap_or(0),
            bundles_sold: self.cashier.bundles_sold,
            total_redeemed: self.redemption.bb_burned,
            is_solvent: self.wusdc.total_supply == self.base_usdc_locked,
        }
    }
    
    /// Get recent events for L2 indexer
    pub fn get_events_since(&self, start_index: usize) -> &[L1Event] {
        if start_index >= self.events.len() {
            &[]
        } else {
            &self.events[start_index..]
        }
    }
}

// ============================================================================
// PROOF OF RESERVES (Texas Compliance)
// ============================================================================

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

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn make_tx(from: &str, data: TxData) -> Transaction {
        Transaction {
            hash: format!("tx_{}", rand::random::<u32>()),
            from: from.to_string(),
            timestamp: 1700000000,
            data,
            signature: "test_sig".to_string(),
        }
    }
    
    #[test]
    fn test_full_user_flow() {
        let mut state = L1State::default();
        
        // 1. User deposits $20 USDC on Base, Bridge mints wUSDC
        let bridge_mint = make_tx(
            "BRIDGE_AUTHORITY",
            TxData::BridgeMint {
                recipient: "alice".to_string(),
                amount: 20_000_000, // $20
                base_tx_hash: "base_tx_001".to_string(),
            },
        );
        state.apply_transaction(&bridge_mint).unwrap();
        
        assert_eq!(state.wusdc_balance("alice"), 20_000_000);
        assert_eq!(state.wusdc.total_supply, 20_000_000);
        
        // 2. Alice buys a starter pack
        let buy_bundle = make_tx(
            "alice",
            TxData::BuyBundle {
                bundle_id: "starter_20".to_string(),
            },
        );
        state.apply_transaction(&buy_bundle).unwrap();
        
        // Alice should have:
        // - 0 wUSDC (spent on bundle)
        // - 20 $BB (from bundle)
        assert_eq!(state.wusdc_balance("alice"), 0);
        assert_eq!(state.bb_balance("alice"), 20_000_000);
        
        // Cashier should have the wUSDC
        assert_eq!(state.wusdc_balance("CASHIER_CONTRACT"), 20_000_000);
        
        // Check event was emitted for L2 indexer
        let events = state.get_events_since(0);
        assert!(events.iter().any(|e| matches!(e, L1Event::BundlePurchased { fan_gold_to_credit: 20_000, .. })));
        
        // 3. Alice redeems her $BB
        let redeem = make_tx(
            "alice",
            TxData::Redeem {
                amount: 20_000_000,
            },
        );
        state.apply_transaction(&redeem).unwrap();
        
        // Alice should have:
        // - 20 wUSDC (from redemption)
        // - 0 $BB (burned)
        assert_eq!(state.wusdc_balance("alice"), 20_000_000);
        assert_eq!(state.bb_balance("alice"), 0);
        
        // 4. Bridge releases USDC on Base
        let bridge_release = make_tx(
            "BRIDGE_AUTHORITY",
            TxData::BridgeRelease {
                user: "alice".to_string(),
                amount: 20_000_000,
                base_tx_hash: "base_tx_002".to_string(),
            },
        );
        state.apply_transaction(&bridge_release).unwrap();
        
        // wUSDC burned, Alice got real USDC on Base
        assert_eq!(state.wusdc_balance("alice"), 0);
        assert_eq!(state.wusdc.total_supply, 0);
        assert_eq!(state.base_usdc_locked, 0);
        
        // Verify solvency
        let reserves = state.proof_of_reserves();
        assert!(reserves.is_solvent);
    }
    
    #[test]
    fn test_unauthorized_mint_rejected() {
        let mut state = L1State::default();
        
        // Evil user tries to mint wUSDC
        let evil_mint = make_tx(
            "evil_user",
            TxData::BridgeMint {
                recipient: "evil_user".to_string(),
                amount: 1_000_000_000,
                base_tx_hash: "fake_tx".to_string(),
            },
        );
        
        let result = state.apply_transaction(&evil_mint);
        assert!(matches!(result, Err(ChainError::Unauthorized(_))));
    }
    
    #[test]
    fn test_replay_protection() {
        let mut state = L1State::default();
        
        // First deposit works
        let mint1 = make_tx(
            "BRIDGE_AUTHORITY",
            TxData::BridgeMint {
                recipient: "alice".to_string(),
                amount: 10_000_000,
                base_tx_hash: "base_tx_001".to_string(),
            },
        );
        state.apply_transaction(&mint1).unwrap();
        
        // Replay attempt fails
        let mint2 = make_tx(
            "BRIDGE_AUTHORITY",
            TxData::BridgeMint {
                recipient: "alice".to_string(),
                amount: 10_000_000,
                base_tx_hash: "base_tx_001".to_string(), // Same tx hash
            },
        );
        
        let result = state.apply_transaction(&mint2);
        assert!(matches!(result, Err(ChainError::DuplicateDeposit(_))));
    }
    
    #[test]
    fn test_insufficient_balance_rejected() {
        let mut state = L1State::default();
        
        // Alice has no wUSDC, tries to buy bundle
        let buy = make_tx(
            "alice",
            TxData::BuyBundle {
                bundle_id: "starter_20".to_string(),
            },
        );
        
        let result = state.apply_transaction(&buy);
        assert!(matches!(result, Err(ChainError::InsufficientWusdc { .. })));
    }
}
