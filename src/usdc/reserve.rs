//! USDC Reserve System
//! 
//! Maintains 1:1 backing of BB tokens with USDC.
//! Every BB token in circulation has exactly 1 USDC locked in reserve.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main reserve system tracking all USDC ↔ BB relationships
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct USDCReserve {
    /// Total USDC locked across all users
    pub total_locked_usdc: f64,
    
    /// Total BB tokens minted from USDC deposits
    pub total_minted_bb: f64,
    
    /// Per-user reserve tracking: user_address => locked_usdc_amount
    pub user_reserves: HashMap<String, f64>,
    
    /// All processed deposits (prevents double-processing)
    pub deposits: Vec<DepositRecord>,
    
    /// All withdrawal requests
    pub withdrawals: Vec<WithdrawalRecord>,
    
    /// Oracle public key for signature verification
    pub oracle_pubkey: Option<String>,
    
    /// Ethereum deposit address (multisig)
    pub eth_deposit_address: Option<String>,
}

/// Record of a USDC deposit from Ethereum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRecord {
    /// Unique deposit ID
    pub id: String,
    
    /// User's L1 address (receives BB tokens)
    pub user_l1_address: String,
    
    /// User's Ethereum address (sent USDC)
    pub user_eth_address: String,
    
    /// Amount of USDC deposited
    pub usdc_amount: f64,
    
    /// Amount of BB tokens minted (should equal usdc_amount for 1:1)
    pub bb_minted: f64,
    
    /// Ethereum transaction hash (proof of deposit)
    pub eth_tx_hash: String,
    
    /// Ethereum block number when deposit was made
    pub eth_block_number: u64,
    
    /// Number of Ethereum block confirmations when processed
    pub confirmations: u32,
    
    /// Unix timestamp when L1 processed this deposit
    pub processed_at: u64,
    
    /// Oracle signature authorizing this mint
    pub oracle_signature: String,
    
    /// Status: pending, confirmed, minted, failed
    pub status: DepositStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DepositStatus {
    /// Deposit detected on Ethereum, waiting for confirmations
    Pending,
    /// Enough confirmations, ready to mint
    Confirmed,
    /// BB tokens minted successfully
    Minted,
    /// Something went wrong
    Failed(String),
}

/// Record of a BB → USDC withdrawal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    /// Unique withdrawal ID
    pub id: String,
    
    /// User's L1 address (burning BB tokens)
    pub user_l1_address: String,
    
    /// User's Ethereum address (receives USDC)
    pub user_eth_address: String,
    
    /// Amount of BB tokens burned
    pub bb_burned: f64,
    
    /// Amount of USDC to release (should equal bb_burned for 1:1)
    pub usdc_amount: f64,
    
    /// Unix timestamp when withdrawal was requested
    pub requested_at: u64,
    
    /// Ethereum transaction hash (proof of USDC release)
    pub eth_tx_hash: Option<String>,
    
    /// Unix timestamp when USDC was sent
    pub completed_at: Option<u64>,
    
    /// Status: requested, processing, completed, failed
    pub status: WithdrawalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WithdrawalStatus {
    /// User requested withdrawal, BB burned
    Requested,
    /// Oracle is processing the Ethereum transaction
    Processing,
    /// USDC sent successfully
    Completed,
    /// Something went wrong (BB refunded)
    Failed(String),
}

impl USDCReserve {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Initialize with Oracle and deposit address
    pub fn with_config(oracle_pubkey: String, eth_deposit_address: String) -> Self {
        Self {
            oracle_pubkey: Some(oracle_pubkey),
            eth_deposit_address: Some(eth_deposit_address),
            ..Default::default()
        }
    }
    
    /// Check if a deposit has already been processed (by Ethereum tx hash)
    pub fn is_deposit_processed(&self, eth_tx_hash: &str) -> bool {
        self.deposits.iter().any(|d| d.eth_tx_hash == eth_tx_hash)
    }
    
    /// Record a new deposit and update reserves
    pub fn record_deposit(&mut self, deposit: DepositRecord) -> Result<(), String> {
        // Prevent double processing
        if self.is_deposit_processed(&deposit.eth_tx_hash) {
            return Err("Deposit already processed".to_string());
        }
        
        // Update user reserve
        *self.user_reserves
            .entry(deposit.user_l1_address.clone())
            .or_insert(0.0) += deposit.usdc_amount;
        
        // Update totals
        self.total_locked_usdc += deposit.usdc_amount;
        self.total_minted_bb += deposit.bb_minted;
        
        // Store deposit record
        self.deposits.push(deposit);
        
        Ok(())
    }
    
    /// Create a withdrawal request
    pub fn request_withdrawal(
        &mut self,
        user_l1_address: String,
        user_eth_address: String,
        amount: f64,
    ) -> Result<WithdrawalRecord, String> {
        // Check user has enough reserve
        let user_reserve = self.user_reserves.get(&user_l1_address).copied().unwrap_or(0.0);
        if user_reserve < amount {
            return Err(format!(
                "Insufficient reserve: have {}, requested {}",
                user_reserve, amount
            ));
        }
        
        // Generate withdrawal ID
        let id = format!(
            "withdraw_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            &user_l1_address[..8.min(user_l1_address.len())]
        );
        
        let record = WithdrawalRecord {
            id: id.clone(),
            user_l1_address: user_l1_address.clone(),
            user_eth_address,
            bb_burned: amount,
            usdc_amount: amount, // 1:1 ratio
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            eth_tx_hash: None,
            completed_at: None,
            status: WithdrawalStatus::Requested,
        };
        
        // Deduct from user reserve (funds are now "in transit")
        *self.user_reserves.get_mut(&user_l1_address).unwrap() -= amount;
        
        self.withdrawals.push(record.clone());
        
        Ok(record)
    }
    
    /// Mark a withdrawal as completed (called by Oracle after sending USDC)
    pub fn complete_withdrawal(&mut self, withdrawal_id: &str, eth_tx_hash: String) -> Result<(), String> {
        let withdrawal = self.withdrawals
            .iter_mut()
            .find(|w| w.id == withdrawal_id)
            .ok_or("Withdrawal not found")?;
        
        if withdrawal.status != WithdrawalStatus::Requested 
            && withdrawal.status != WithdrawalStatus::Processing {
            return Err("Withdrawal not in valid state".to_string());
        }
        
        withdrawal.eth_tx_hash = Some(eth_tx_hash);
        withdrawal.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        withdrawal.status = WithdrawalStatus::Completed;
        
        // Update totals
        self.total_locked_usdc -= withdrawal.usdc_amount;
        self.total_minted_bb -= withdrawal.bb_burned;
        
        Ok(())
    }
    
    /// Get user's current reserve balance
    pub fn get_user_reserve(&self, user_l1_address: &str) -> f64 {
        self.user_reserves.get(user_l1_address).copied().unwrap_or(0.0)
    }
    
    /// Verify reserve integrity: total_locked should equal sum of user_reserves
    pub fn verify_integrity(&self) -> Result<(), String> {
        let sum: f64 = self.user_reserves.values().sum();
        
        // Account for pending withdrawals
        let pending_withdrawals: f64 = self.withdrawals
            .iter()
            .filter(|w| w.status == WithdrawalStatus::Requested || w.status == WithdrawalStatus::Processing)
            .map(|w| w.usdc_amount)
            .sum();
        
        let expected = sum + pending_withdrawals;
        
        if (self.total_locked_usdc - expected).abs() > 0.001 {
            return Err(format!(
                "Reserve mismatch: total_locked={}, sum={}, pending={}",
                self.total_locked_usdc, sum, pending_withdrawals
            ));
        }
        
        Ok(())
    }
    
    /// Get reserve statistics for public dashboard
    pub fn get_stats(&self) -> ReserveStats {
        ReserveStats {
            total_usdc_locked: self.total_locked_usdc,
            total_bb_minted: self.total_minted_bb,
            total_users: self.user_reserves.len(),
            total_deposits: self.deposits.len(),
            total_withdrawals: self.withdrawals.len(),
            pending_withdrawals: self.withdrawals
                .iter()
                .filter(|w| w.status == WithdrawalStatus::Requested || w.status == WithdrawalStatus::Processing)
                .count(),
            backing_ratio: if self.total_minted_bb > 0.0 {
                self.total_locked_usdc / self.total_minted_bb
            } else {
                1.0
            },
        }
    }
}

/// Public reserve statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveStats {
    pub total_usdc_locked: f64,
    pub total_bb_minted: f64,
    pub total_users: usize,
    pub total_deposits: usize,
    pub total_withdrawals: usize,
    pub pending_withdrawals: usize,
    /// Should always be 1.0 for 1:1 backing
    pub backing_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deposit_and_withdraw() {
        let mut reserve = USDCReserve::new();
        
        // Simulate deposit
        let deposit = DepositRecord {
            id: "dep_1".to_string(),
            user_l1_address: "L1_ALICE".to_string(),
            user_eth_address: "0xAlice".to_string(),
            usdc_amount: 100.0,
            bb_minted: 100.0,
            eth_tx_hash: "0xabc123".to_string(),
            eth_block_number: 12345,
            confirmations: 12,
            processed_at: 1000,
            oracle_signature: "sig".to_string(),
            status: DepositStatus::Minted,
        };
        
        reserve.record_deposit(deposit).unwrap();
        
        assert_eq!(reserve.total_locked_usdc, 100.0);
        assert_eq!(reserve.get_user_reserve("L1_ALICE"), 100.0);
        
        // Request withdrawal
        let withdrawal = reserve.request_withdrawal(
            "L1_ALICE".to_string(),
            "0xAlice".to_string(),
            50.0,
        ).unwrap();
        
        assert_eq!(reserve.get_user_reserve("L1_ALICE"), 50.0);
        
        // Complete withdrawal
        reserve.complete_withdrawal(&withdrawal.id, "0xdef456".to_string()).unwrap();
        
        assert_eq!(reserve.total_locked_usdc, 50.0);
    }
    
    #[test]
    fn test_double_deposit_prevention() {
        let mut reserve = USDCReserve::new();
        
        let deposit = DepositRecord {
            id: "dep_1".to_string(),
            user_l1_address: "L1_ALICE".to_string(),
            user_eth_address: "0xAlice".to_string(),
            usdc_amount: 100.0,
            bb_minted: 100.0,
            eth_tx_hash: "0xabc123".to_string(),
            eth_block_number: 12345,
            confirmations: 12,
            processed_at: 1000,
            oracle_signature: "sig".to_string(),
            status: DepositStatus::Minted,
        };
        
        reserve.record_deposit(deposit.clone()).unwrap();
        
        // Try to process same deposit again
        let result = reserve.record_deposit(deposit);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Deposit already processed");
    }
    
    #[test]
    fn test_insufficient_reserve() {
        let mut reserve = USDCReserve::new();
        
        // Try to withdraw with no reserve
        let result = reserve.request_withdrawal(
            "L1_ALICE".to_string(),
            "0xAlice".to_string(),
            100.0,
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient reserve"));
    }
}
