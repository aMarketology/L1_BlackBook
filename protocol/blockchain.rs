//! BlackBook L1 Blockchain - Core Types
//!
//! MINIMAL, PRODUCTION-READY BLOCKCHAIN CORE
//!
//! Design Philosophy:
//! - 1:1 USDC Backed: Every BB token is backed by $1 USDC
//! - No Treasury: Tokens only exist when USDC is deposited
//! - Zero-Sum: Transfers never create or destroy tokens
//! - Audit Trail: Every mint/burn is recorded with USDC tx hash
//!
//! Token Flow:
//!   USDC Deposit  → mint_tokens()  → BB created
//!   USDC Withdraw → burn_tokens()  → BB destroyed
//!   Transfer      → debit/credit   → Zero-sum (no change in supply)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Genesis timestamp (fixed for deterministic genesis hash)
pub const GENESIS_TIMESTAMP: u64 = 1735689600;

/// Micro-units per BB token (for integer math)
pub const LAMPORTS_PER_BB: u64 = 1_000_000;

/// Compute deterministic genesis hash
pub fn compute_genesis_hash() -> String {
    let seed = "BlackBook_L1_Genesis_2024_USDC_Backed";
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

// ============================================================================
// BLOCK
// ============================================================================

/// A block in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub slot: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub state_root: String,
}

impl Block {
    /// Create genesis block
    pub fn genesis() -> Self {
        let hash = compute_genesis_hash();
        Self {
            slot: 0,
            timestamp: GENESIS_TIMESTAMP,
            previous_hash: "0".repeat(64),
            hash: hash.clone(),
            transactions: Vec::new(),
            state_root: hash,
        }
    }

    /// Create new block
    pub fn new(slot: u64, previous_hash: String, transactions: Vec<Transaction>, state_root: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let hash_input = format!("{}{}{}{:?}", slot, previous_hash, timestamp, transactions);
        let hash = format!("{:x}", Sha256::digest(hash_input.as_bytes()));

        Self {
            slot,
            timestamp,
            previous_hash,
            hash,
            transactions,
            state_root,
        }
    }
}

// ============================================================================
// TRANSACTION
// ============================================================================

/// Transaction types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxType {
    /// USDC deposited → BB minted
    Mint,
    /// BB burned → USDC withdrawn  
    Burn,
    /// BB transferred between accounts (zero-sum)
    Transfer,
}

/// A transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub tx_type: TxType,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: u64,
    /// For Mint: USDC deposit tx hash. For Burn: USDC withdrawal ID
    pub usdc_reference: Option<String>,
}

impl Transaction {
    pub fn new(tx_type: TxType, from: &str, to: &str, amount: f64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let id = format!("{:x}", Sha256::digest(
            format!("{}{}{}{}{}", from, to, amount, timestamp, fastrand::u64(..)).as_bytes()
        ));

        Self {
            id,
            tx_type,
            from: from.to_string(),
            to: to.to_string(),
            amount,
            timestamp,
            usdc_reference: None,
        }
    }

    pub fn mint(to: &str, amount: f64, usdc_tx_hash: Option<String>) -> Self {
        let mut tx = Self::new(TxType::Mint, "system", to, amount);
        tx.usdc_reference = usdc_tx_hash;
        tx
    }

    pub fn burn(from: &str, amount: f64, usdc_withdrawal_id: Option<String>) -> Self {
        let mut tx = Self::new(TxType::Burn, from, "system", amount);
        tx.usdc_reference = usdc_withdrawal_id;
        tx
    }

    pub fn transfer(from: &str, to: &str, amount: f64) -> Self {
        Self::new(TxType::Transfer, from, to, amount)
    }
}

// ============================================================================
// LOCK (For L2 Credit Sessions)
// ============================================================================

/// Why tokens are locked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LockPurpose {
    /// Locked for L2 gaming session
    CreditSession,
    /// Locked for market escrow
    Escrow,
}

/// A lock record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    pub id: String,
    pub wallet: String,
    pub amount: f64,
    pub purpose: LockPurpose,
    pub created_at: u64,
    pub released: bool,
}

// ============================================================================
// SETTLEMENT PROOF (L2 → L1)
// ============================================================================

/// Proof from L2 that a session has ended
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    pub session_id: String,
    pub wallet: String,
    pub net_pnl: f64,
    pub l2_signature: String,
    pub timestamp: u64,
}

// ============================================================================
// ACCOUNT (Compatibility with Solana-style)
// ============================================================================

/// Account type
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub enum AccountType {
    #[default]
    User,
    Program,
    System,
}

/// An account (Solana-compatible structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub lamports: u64,
    pub owner: String,
    pub nonce: u64,
    pub account_type: AccountType,
}

impl Account {
    pub fn new(owner: &str, lamports: u64) -> Self {
        Self {
            lamports,
            owner: owner.to_string(),
            nonce: 0,
            account_type: AccountType::User,
        }
    }

    /// Get balance in BB (from lamports)
    pub fn balance_bb(&self) -> f64 {
        self.lamports as f64 / LAMPORTS_PER_BB as f64
    }

    /// Set balance from BB amount
    pub fn set_balance_bb(&mut self, bb: f64) {
        self.lamports = (bb * LAMPORTS_PER_BB as f64) as u64;
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_deterministic() {
        let h1 = compute_genesis_hash();
        let h2 = compute_genesis_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        assert_eq!(genesis.slot, 0);
        assert_eq!(genesis.timestamp, GENESIS_TIMESTAMP);
        assert_eq!(genesis.previous_hash, "0".repeat(64));
    }

    #[test]
    fn test_mint_transaction() {
        let tx = Transaction::mint("alice", 100.0, Some("usdc_tx_123".to_string()));
        assert_eq!(tx.tx_type, TxType::Mint);
        assert_eq!(tx.from, "system");
        assert_eq!(tx.to, "alice");
        assert_eq!(tx.amount, 100.0);
        assert_eq!(tx.usdc_reference, Some("usdc_tx_123".to_string()));
    }

    #[test]
    fn test_burn_transaction() {
        let tx = Transaction::burn("alice", 50.0, Some("withdraw_456".to_string()));
        assert_eq!(tx.tx_type, TxType::Burn);
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "system");
        assert_eq!(tx.amount, 50.0);
    }

    #[test]
    fn test_transfer_transaction() {
        let tx = Transaction::transfer("alice", "bob", 25.0);
        assert_eq!(tx.tx_type, TxType::Transfer);
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "bob");
    }

    #[test]
    fn test_account_balance_conversion() {
        let mut acc = Account::new("alice", 0);
        acc.set_balance_bb(100.5);
        assert_eq!(acc.lamports, 100_500_000);
        assert!((acc.balance_bb() - 100.5).abs() < 0.0001);
    }
}
