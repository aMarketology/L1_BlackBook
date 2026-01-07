//! Core Account Types - WalletId, L1Account, L2Account
//!
//! L1 = Bank (available + locked)
//! L2 = Gaming (locked ONLY - no available field!)

use serde::{Deserialize, Serialize};

pub const WALLET_ID_LEN: usize = 14;

/// Wallet ID as raw bytes (14 ASCII chars)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct WalletId([u8; WALLET_ID_LEN]);

impl WalletId {
    pub fn from_str(s: &str) -> Result<Self, WalletError> {
        let bytes = s.as_bytes();
        if bytes.len() != WALLET_ID_LEN {
            return Err(WalletError::InvalidWalletId);
        }
        let mut arr = [0u8; WALLET_ID_LEN];
        arr.copy_from_slice(bytes);
        Ok(WalletId(arr))
    }
    
    pub fn as_bytes(&self) -> &[u8; WALLET_ID_LEN] { &self.0 }
    pub fn to_l1_address(&self) -> String { format!("L1_{}", self) }
    pub fn to_l2_address(&self) -> String { format!("L2_{}", self) }
}

impl std::fmt::Display for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

/// L1 Account - Bank/Vault (SOURCE OF TRUTH)
/// Holds $BC (BlackCoin) - the L1 native token
/// Amounts stored as f64: 1.00 = $1, 0.01 = 1 cent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L1Account {
    pub available: f64,  // $BC balance (e.g., 100.50 = $100.50)
    pub locked: f64,
    pub last_sync: u64,
}

impl L1Account {
    pub fn new() -> Self { Self::default() }
    pub fn with_balance(amount: f64) -> Self { L1Account { available: amount, ..Default::default() } }
    pub fn available_bc(&self) -> f64 { self.available }
}

/// L2 Account - Gaming Layer (NO available field = invariant enforced!)
/// Holds $BB (BlackBook) - L2 gaming token, 1:1 backed by locked $BC
/// Amounts stored as f64: 1.00 = $1, 0.01 = 1 cent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L2Account {
    pub locked: f64,           // Active bets only ($BB)
    pub active_bet_count: u32,
    pub last_sync: u64,
}

impl L2Account {
    pub fn new() -> Self { Self::default() }
    pub fn locked_bb(&self) -> f64 { self.locked }
}

/// Wallet errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum WalletError {
    #[error("Invalid wallet ID")]
    InvalidWalletId,
    #[error("Insufficient funds: need {required}, have {available}")]
    InsufficientFunds { required: f64, available: f64 },
    #[error("Account not found: {0}")]
    AccountNotFound(String),
}

// Removed microtoken conversions - now using direct f64 values
// 1.00 = $1, 0.01 = 1 cent

// ============================================================================
// ADDRESS HELPERS - L1/L2 prefix system
// ============================================================================
// Address format: L1_ + 40 hex chars OR L2_ + 40 hex chars (43 chars total)
// L1 and L2 addresses share the SAME hash - only prefix differs
// Example: L1_ALICE000000001
//          L2_ALICE000000001

/// Strip L1_/L2_ prefix from an address to get the hash
pub fn strip_prefix(addr: &str) -> String {
    if addr.starts_with("L1_") || addr.starts_with("L2_") {
        // Current format: L1_HASH or L2_HASH
        addr[3..].to_string()
    } else if addr.starts_with("L1") || addr.starts_with("L2") {
        // Legacy format without underscore: L1HASH or L2HASH
        addr[2..].to_string()
    } else {
        addr.to_string()
    }
}

/// Convert any address to L1 format (L1_ + 40 hex chars = 43 chars)
pub fn to_l1_address(addr: &str) -> String {
    let base = strip_prefix(addr);
    format!("L1_{}", base)
}

/// Convert any address to L2 format (L2_ + 40 hex chars = 43 chars)
pub fn to_l2_address(addr: &str) -> String {
    let base = strip_prefix(addr);
    format!("L2_{}", base)
}

/// Check if address has L1 prefix
pub fn is_l1_address(addr: &str) -> bool {
    addr.starts_with("L1_") || addr.starts_with("L1")
}

/// Check if address has L2 prefix
pub fn is_l2_address(addr: &str) -> bool {
    addr.starts_with("L2_") || addr.starts_with("L2")
}
