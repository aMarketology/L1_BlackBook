//! Dual Balance Storage - Two HashMaps + Oracle Pool
//!
//! L1: Bank/Vault (available + locked) - $BC tokens
//! L2: Gaming Layer (locked only - bets in flight) - $BB tokens
//! Oracle: Oversees bridge operations between L1 and L2

use super::{L1Account, L2Account, WalletId, OraclePool};
use std::collections::HashMap;

/// Core storage: L1 accounts, L2 accounts, and the Oracle
#[derive(Debug, Default)]
pub struct DualBalanceStorage {
    pub l1: HashMap<[u8; 14], L1Account>,
    pub l2: HashMap<[u8; 14], L2Account>,
    pub oracle: OraclePool,
}

impl DualBalanceStorage {
    pub fn new() -> Self { Self::default() }
    
    pub fn with_oracle_seed(amount_bc: f64) -> Self {
        Self {
            oracle: OraclePool::with_seed(amount_bc),
            ..Default::default()
        }
    }
    
    // Deprecated alias for backward compatibility
    pub fn with_dealer_seed(amount_bb: f64) -> Self {
        Self::with_oracle_seed(amount_bb)
    }
    
    // L1 Operations
    pub fn get_l1(&self, id: &WalletId) -> Option<&L1Account> {
        self.l1.get(id.as_bytes())
    }
    
    pub fn get_l1_mut(&mut self, id: &WalletId) -> &mut L1Account {
        self.l1.entry(*id.as_bytes()).or_default()
    }
    
    pub fn credit_l1(&mut self, id: &WalletId, amount: f64) {
        self.get_l1_mut(id).available += amount;
    }
    
    pub fn debit_l1(&mut self, id: &WalletId, amount: f64) -> bool {
        let acc = self.get_l1_mut(id);
        if acc.available >= amount {
            acc.available -= amount;
            true
        } else {
            false
        }
    }
    
    // L2 Operations
    pub fn get_l2(&self, id: &WalletId) -> Option<&L2Account> {
        self.l2.get(id.as_bytes())
    }
    
    pub fn get_l2_mut(&mut self, id: &WalletId) -> &mut L2Account {
        self.l2.entry(*id.as_bytes()).or_default()
    }
    
    /// JIT Bridge: L1.available → L2.locked (atomic)
    pub fn bridge_to_l2(&mut self, id: &WalletId, amount: f64) -> bool {
        let l1 = self.get_l1_mut(id);
        if l1.available < amount { return false; }
        l1.available -= amount;
        
        let l2 = self.get_l2_mut(id);
        l2.locked += amount;
        l2.active_bet_count += 1;
        true
    }
    
    /// Settle: L2.locked → L1 (win) or Oracle (loss)
    pub fn settle(&mut self, id: &WalletId, stake: f64, payout: f64) -> bool {
        let l2 = self.get_l2_mut(id);
        if l2.locked < stake { return false; }
        l2.locked -= stake;
        l2.active_bet_count = l2.active_bet_count.saturating_sub(1);
        
        if payout > 0.0 {
            // Win: payout to L1, oracle facilitates the profit
            self.get_l1_mut(id).available += payout;
            self.oracle.payout((payout - stake).max(0.0)); // profit portion
        } else {
            // Loss: stake goes to oracle
            self.oracle.collect(stake);
        }
        true
    }
    
    // Stats
    pub fn account_count(&self) -> (usize, usize) {
        (self.l1.len(), self.l2.len())
    }
}
