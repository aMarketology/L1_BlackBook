//! Oracle - Overseeing role for L1↔L2 bridge operations
//!
//! The Oracle monitors and validates state between L1 and L2.
//! It uses the same wallet address on both layers for consistency.

use serde::{Deserialize, Serialize};

/// Oracle's wallet ID (hardcoded, consistent across L1 and L2)
pub const ORACLE_ID: &str = "ORACLE_VALIDATOR_01";

/// Oracle's L1 address (derived from DEALER_PRIVATE_KEY in .env)
/// This is the same address used for signing bridge messages
pub const ORACLE_L1_ADDRESS: &str = "L1_ORACLE";

/// Oracle's L2 address (mirrors L1)
pub const ORACLE_L2_ADDRESS: &str = "L2_ORACLE";

/// Check if an address/ID is the oracle
pub fn is_oracle(id: &str) -> bool {
    id == ORACLE_ID || id.starts_with("ORACLE") || id.contains("_ORACLE")
}

/// Oracle Pool - L1↔L2 bridge validator and liquidity provider
/// 
/// The Oracle oversees bridge operations between L1 ($BC) and L2 ($BB).
/// It validates state transitions and ensures 1:1 backing of L2 tokens.
/// This is the L1-side representation of the Oracle's state.
/// Amounts stored as f64: 1.00 = $1, 0.01 = 1 cent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OraclePool {
    /// Available balance ($BC) - liquidity for bridge operations
    pub available: f64,
    /// Total in pending bridge operations
    pub pending_settlements: f64,
    /// Total settled lifetime
    pub total_settled: f64,
    /// Last sync timestamp
    pub last_sync: u64,
}

impl OraclePool {
    pub fn new() -> Self { Self::default() }
    
    pub fn with_seed(amount: f64) -> Self {
        OraclePool {
            available: amount,
            ..Default::default()
        }
    }
    
    pub fn available_bc(&self) -> f64 { self.available }
    pub fn pending_bc(&self) -> f64 { self.pending_settlements }
    
    /// Lock tokens for bridge operation (L1 → L2)
    pub fn lock_for_bridge(&mut self, amount: f64) -> bool {
        if self.available >= amount {
            self.available -= amount;
            self.pending_settlements += amount;
            true
        } else {
            false
        }
    }
    
    /// Payout winnings to user (oracle facilitates the payout)
    pub fn payout(&mut self, profit: f64) {
        // Oracle facilitates payout for winning bets
        self.available = (self.available - profit).max(0.0);
    }
    
    /// Collect losing bet stake
    pub fn collect(&mut self, stake: f64) {
        // User lost, oracle collects the stake
        self.available += stake;
    }
    
    /// Record a settlement from L1 (bridge completion)
    pub fn record_settlement(&mut self, amount: f64) {
        self.available += amount;
        if self.pending_settlements >= amount {
            self.pending_settlements -= amount;
        } else {
            self.pending_settlements = 0.0;
        }
        self.total_settled += amount;
        self.last_sync = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Settle a completed bridge operation
    pub fn settle(&mut self, amount: f64) {
        self.pending_settlements = (self.pending_settlements - amount).max(0.0);
        self.total_settled += amount;
        self.available += amount;
    }
}
