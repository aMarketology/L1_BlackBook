//! Dealer - Hardcoded counterparty for all bets (lives on L2)
//!
//! The Dealer is NOT a normal wallet. It's the house liquidity pool.
//! Full dealer logic is implemented on Layer 2 - this is just the L1 reference.

use serde::{Deserialize, Serialize};

/// Dealer's wallet ID (hardcoded, not derived from keypair)
pub const DEALER_ID: &str = "DEALER_HOUSE_01";

/// Check if an address/ID is the dealer
pub fn is_dealer(id: &str) -> bool {
    id == DEALER_ID || id.starts_with("DEALER")
}

/// Dealer Pool - L2 liquidity provider
/// 
/// The Dealer fronts bets on L2 and later claims reimbursement from L1.
/// This is the L1-side representation of the Dealer's state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DealerPool {
    /// Available balance (microtokens) - what the dealer can front
    pub available: u64,
    /// Total fronted but not yet settled (microtokens)
    pub pending_settlements: u64,
    /// Total settled lifetime (microtokens)
    pub total_settled: u64,
    /// Last sync timestamp
    pub last_sync: u64,
}

impl DealerPool {
    pub fn new() -> Self { Self::default() }
    
    pub fn with_seed(amount: u64) -> Self {
        DealerPool {
            available: amount,
            ..Default::default()
        }
    }
    
    pub fn available_bb(&self) -> f64 { self.available as f64 / 1_000_000.0 }
    pub fn pending_bb(&self) -> f64 { self.pending_settlements as f64 / 1_000_000.0 }
    
    /// Front tokens for a bet (L2 operation)
    pub fn front(&mut self, amount: u64) -> bool {
        if self.available >= amount {
            self.available -= amount;
            self.pending_settlements += amount;
            true
        } else {
            false
        }
    }
    
    /// Payout winnings to user (dealer pays the profit portion)
    pub fn payout(&mut self, profit: u64) {
        // Dealer pays the profit portion of a winning bet
        // If dealer doesn't have enough, this is a risk management issue
        self.available = self.available.saturating_sub(profit);
    }
    
    /// Collect losing bet stake (dealer wins)
    pub fn collect(&mut self, stake: u64) {
        // User lost, dealer collects the stake
        self.available += stake;
    }
    
    /// Record a settlement from L1 (reimbursement received)
    pub fn record_settlement(&mut self, amount: u64) {
        self.available += amount;
        if self.pending_settlements >= amount {
            self.pending_settlements -= amount;
        }
        self.total_settled += amount;
        self.last_sync = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}
