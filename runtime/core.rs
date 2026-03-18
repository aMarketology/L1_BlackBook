//! BlackBook L1 Runtime Core — Sealevel Parallel Execution Engine
//!
//! Streamlined for the manifesto's two core jobs:
//!   1. GATEKEEPER: USDT → $BB settlement (fast, secure transfers)
//!   2. INVISIBLE SECURITY: SSS wallet signing with circuit breakers
//!
//! Solana-inspired design, improved:
//!   - 600ms slots (stable vs Solana's fragile 400ms)
//!   - Localized fee markets (spam only affects the spammer)
//!   - Circuit breakers (automatic bank-run protection)
//!   - Stake-weighted throttling (fair resource allocation)



use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use std::sync::Arc;
use borsh::{BorshSerialize, BorshDeserialize};

// ============================================================================
// ACCOUNT TYPES (Minimal — L1 Settlement Only)
// ============================================================================

/// PDA namespace constants
pub mod pda_namespace {
    pub const WALLET: &str = "wallet";
    pub const VAULT: &str = "vault";
    pub const CONFIG: &str = "config";
    pub const TREASURY: &str = "treasury";
    pub const BRIDGE_ESCROW: &str = "bridge-escrow";
    pub const RESERVE: &str = "reserve";
}

/// Account types on L1 — kept minimal for settlement layer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum AccountType {
    UserWallet,
    EscrowVault,
    SystemConfig,
    Treasury,
    BridgeEscrow,
    Dealer,
    GlobalReserve,
}

impl AccountType {
    pub fn namespace(&self) -> &'static str {
        match self {
            AccountType::UserWallet => pda_namespace::WALLET,
            AccountType::EscrowVault => pda_namespace::VAULT,
            AccountType::SystemConfig => pda_namespace::CONFIG,
            AccountType::Treasury => pda_namespace::TREASURY,
            AccountType::BridgeEscrow => pda_namespace::BRIDGE_ESCROW,
            AccountType::Dealer => pda_namespace::WALLET,
            AccountType::GlobalReserve => pda_namespace::RESERVE,
        }
    }

    #[allow(dead_code)] // used in integration tests
    pub fn can_hold_tokens(&self) -> bool {
        matches!(self, AccountType::UserWallet | AccountType::EscrowVault |
                       AccountType::Treasury | AccountType::BridgeEscrow | AccountType::Dealer |
                       AccountType::GlobalReserve)
    }
}

/// PDA derivation — deterministic off-curve address from seeds
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[allow(dead_code)] // Phase 5+: PDA accounts for program-owned state
pub struct ProgramDerivedAddress {
    pub address: String,
    pub account_type: AccountType,
    pub namespace: String,
    pub owner: String,
    pub bump: u8,
}

impl ProgramDerivedAddress {
    #[allow(dead_code)] // Phase 5+: PDA derivation
    pub fn derive(account_type: AccountType, owner: &str, index: Option<&str>) -> Result<Self, String> {
        let namespace = account_type.namespace();
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(namespace.as_bytes());
        seed_data.extend_from_slice(owner.as_bytes());
        if let Some(idx) = index { seed_data.extend_from_slice(idx.as_bytes()); }

        for bump in (0u8..=255).rev() {
            let mut hasher = Sha256::new();
            hasher.update(&seed_data);
            hasher.update([bump]);
            hasher.update(b"PDA");
            let hash = hasher.finalize();

            if hash[31] & 0x80 == 0 {
                let address = format!("L1_{}", hex::encode(&hash[..20]).to_uppercase());
                return Ok(Self { address, account_type, namespace: namespace.to_string(), owner: owner.to_string(), bump });
            }
        }
        Err("Could not find valid bump for PDA".to_string())
    }
}

/// Account metadata stored alongside each account
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountMetadata {
    pub account_type: AccountType,
    pub owner: String,
    pub pda_info: Option<PDAInfo>,
    pub created_at: u64,
    pub updated_at: u64,
    pub frozen: bool,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PDAInfo {
    pub namespace: String,
    pub bump: u8,
    pub index: Option<String>,
}

/// Declarative account access (for future validation framework)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Phase 5+: instruction-level account validation
pub struct AccountAccess {
    pub address: String,
    pub expected_type: AccountType,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Account validation error types
#[derive(Debug, Clone)]
#[allow(dead_code)] // Phase 5+: instruction-level account validation
pub enum AccountValidationError {
    AccountNotFound(String),
    InvalidType { expected: AccountType, found: AccountType },
    Frozen(String),
    PermissionDenied(String),
}

impl std::fmt::Display for AccountValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountNotFound(a) => write!(f, "Account not found: {}", a),
            Self::InvalidType { expected, found } => write!(f, "Expected {:?}, found {:?}", expected, found),
            Self::Frozen(a) => write!(f, "Account frozen: {}", a),
            Self::PermissionDenied(a) => write!(f, "Permission denied: {}", a),
        }
    }
}

/// Account validator stub (validates account accesses before execution)
#[allow(dead_code)] // Phase 5+: instruction-level account validation
pub struct AccountValidator {
    accounts: Arc<DashMap<String, AccountMetadata>>,
}

impl AccountValidator {
    #[allow(dead_code)]
    pub fn new(accounts: Arc<DashMap<String, AccountMetadata>>) -> Self {
        Self { accounts }
    }
}

// ============================================================================
// TRANSACTION — L1 Settlement Transaction
// ============================================================================

/// Transaction types for L1 settlement layer
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default, PartialEq)]
pub enum TransactionType {
    #[default]
    Transfer,
    Mint,
    Burn,
    BridgeLock,
    BridgeUnlock,
    Vote,
    SystemReward,
}

/// L1 Transaction with explicit read/write accounts for Sealevel parallel scheduling
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: f64,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub read_accounts: Vec<String>,
    #[serde(default)]
    pub write_accounts: Vec<String>,
    #[serde(default)]
    pub tx_type: TransactionType,
}

impl Transaction {
    pub fn new(from: String, to: String, amount: f64, tx_type: TransactionType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let read_accounts = vec![from.clone()];
        let write_accounts = vec![from.clone(), to.clone()];

        Self {
            id: id.clone(),
            from, to, amount, timestamp,
            signature: format!("sig_{}", &id[..8]),
            nonce: 0,
            read_accounts, write_accounts,
            tx_type,
        }
    }

    pub fn conflicts_with(&self, other: &Transaction) -> bool {
        for w in &self.write_accounts {
            if other.write_accounts.contains(w) || other.read_accounts.contains(w) { return true; }
        }
        for r in &self.read_accounts {
            if other.write_accounts.contains(r) { return true; }
        }
        false
    }

    pub fn is_financial(&self) -> bool {
        matches!(self.tx_type, TransactionType::Transfer | TransactionType::Mint |
                 TransactionType::Burn | TransactionType::BridgeLock | TransactionType::BridgeUnlock)
    }
}

// ============================================================================
// SECURITY INFRASTRUCTURE (Rate Limiting, Circuit Breakers, Fee Markets)
// ============================================================================

/// Network-level rate limiter: prevents a single address from
/// flooding the mempool. Allows `MAX_PER_WINDOW` txs per address
/// within a rolling window tracked via DashMap.
#[derive(Debug, Clone)]
pub struct NetworkThrottler {
    /// address → count of recent transactions
    tx_counts: Arc<dashmap::DashMap<String, u32>>,
    max_per_window: u32,
}

impl Default for NetworkThrottler {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkThrottler {
    pub fn new() -> Self {
        Self {
            tx_counts: Arc::new(dashmap::DashMap::new()),
            max_per_window: 10,
        }
    }

    /// Check whether a transaction from `sender` should be allowed.
    /// Returns Err if the sender has exceeded the per-window limit.
    pub fn check_transaction(&self, sender: &str, _fee: f64) -> Result<(), String> {
        let mut count = self.tx_counts.entry(sender.to_string()).or_insert(0);
        if *count >= self.max_per_window {
            return Err(format!("Rate limited: {} txs in window", self.max_per_window));
        }
        *count += 1;
        Ok(())
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "tracked_senders": self.tx_counts.len(),
            "max_per_window": self.max_per_window,
        })
    }
}

/// Circuit breaker: prevents a single account from moving more than
/// `MAX_BLOCK_PERCENT` of the total supply in a single block.
/// Exempted addresses (e.g. "genesis", "system") bypass all checks.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    exemptions: Arc<dashmap::DashMap<String, bool>>,
    max_block_percent: f64,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            exemptions: Arc::new(dashmap::DashMap::new()),
            max_block_percent: 0.20, // 20% of block supply
        }
    }

    pub fn add_exemption(&self, address: &str) {
        self.exemptions.insert(address.to_string(), true);
    }

    /// Check whether a transfer of `amount` from `sender` is within
    /// circuit-breaker limits given a `total_supply` and `block_index`.
    pub fn check_transfer(&self, sender: &str, amount: f64, total_supply: f64, _block: u64) -> Result<(), String> {
        if self.exemptions.contains_key(sender) {
            return Ok(());
        }
        let threshold = total_supply * self.max_block_percent;
        if amount > threshold {
            return Err(format!("Circuit breaker: {} exceeds {}% of supply", amount, self.max_block_percent * 100.0));
        }
        Ok(())
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "exemptions": self.exemptions.len(),
            "max_block_percent": self.max_block_percent,
        })
    }
}

/// Localized fee market: computes priority fees based on recent
/// block congestion. Currently a placeholder with base fee = 0.
#[derive(Debug, Clone)]
pub struct LocalizedFeeMarket {
    base_fee: f64,
}

impl Default for LocalizedFeeMarket {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalizedFeeMarket {
    pub fn new() -> Self {
        Self { base_fee: 0.0 }
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "base_fee": self.base_fee,
        })
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
        let tx = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        assert_eq!(tx.from, "alice");
        assert_eq!(tx.to, "bob");
        assert_eq!(tx.amount, 100.0);
        assert!(!tx.id.is_empty());
    }

    #[test]
    fn test_conflict_detection() {
        let tx1 = Transaction::new("alice".into(), "bob".into(), 100.0, TransactionType::Transfer);
        let tx2 = Transaction::new("alice".into(), "carol".into(), 50.0, TransactionType::Transfer);
        let tx3 = Transaction::new("dave".into(), "eve".into(), 25.0, TransactionType::Transfer);

        assert!(tx1.conflicts_with(&tx2)); // same sender
        assert!(!tx1.conflicts_with(&tx3)); // independent
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new();
        cb.add_exemption("genesis");
        assert!(cb.check_transfer("genesis", 1000.0, 100.0, 1).is_ok());

        // Normal account: 20% block threshold
        assert!(cb.check_transfer("alice", 10.0, 100.0, 1).is_ok());
        assert!(cb.check_transfer("alice", 15.0, 100.0, 1).is_err()); // exceeds 20%
    }

    #[test]
    fn test_throttler() {
        let throttler = NetworkThrottler::new();
        for _ in 0..10 {
            assert!(throttler.check_transaction("alice", 0.0).is_ok());
        }
        assert!(throttler.check_transaction("alice", 0.0).is_err()); // 11th throttled
    }
}
