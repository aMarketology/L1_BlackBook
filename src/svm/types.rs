// ============================================================================
// BLACKBOOK SVM — TYPES
// ============================================================================
//
// Core types for the SVM execution layer.
//
// CRITICAL DESIGN DECISIONS (never break these):
//
// 1. NO f64 FOR CURRENCY — ever.
//    All balances are u64 (lamports). 1 BB = LAMPORTS_PER_BB lamports.
//    Floating-point arithmetic creates "dust" that destroys the 1:1 USDT
//    backing over time. u64 is mathematically exact.
//
// 2. RENT = 0 (RENT_EPOCH_EXEMPT = u64::MAX).
//    Accounts on BlackBook L1 never pay rent. Users should not need to worry
//    about their $dime accounts silently burning away. Setting rent_epoch to
//    u64::MAX marks every account as rent-exempt in Solana's model.
//
// 3. StoredAccount is the Borsh-serializable wire format.
//    Solana's AccountSharedData does not implement Borsh, and we must store
//    accounts in ReDB with deterministic serialization. StoredAccount is the
//    intermediate representation; convert to/from AccountSharedData at the
//    boundary.
//
// ============================================================================

use borsh::{BorshDeserialize, BorshSerialize};
use chrono;
use thiserror::Error;
use solana_sdk::account::AccountSharedData;
use solana_sdk::pubkey::Pubkey;

// ============================================================================
// CONSTANTS
// ============================================================================

/// 1 BB token = 100,000 lamports (5 decimal places, i.e. 10^5).
///
/// At $0.10/BB the smallest unit (1 lamport) = $0.000001 — practical for
/// micro-transactions with sub-cent precision.
///
/// NEVER divide to get a fractional BB — always work in lamports and convert
/// to human-readable BB only at display time.
pub const LAMPORTS_PER_BB: u64 = 100_000;

/// USDT has 6 decimal places. 1 USDT = 1_000_000 micro-USDT.
pub const USDT_UNIT: u64 = 1_000_000;

// ============================================================================
// $BB — INTERNAL ACCOUNTING UNIT (not a stablecoin)
//
// $BB represents exactly $0.10 USD of internal network compute/settlement
// value. It is NOT a stablecoin and NOT pegged to any external asset.
// It is an Internal Accounting Unit — like an arcade token, API credit, or
// casino chip — that is redeemable via the bridge at the current exchange rate.
//
// BB_USD_CENTS is IMMUTABLE: it defines the internal ledger value of compute.
// BB_PER_USDT_DEFAULT is the BASELINE exchange rate at node genesis. The active
// market rate is stored in ReDB (SWAP_RATES table, key "BB_USDT") and may be
// adjusted by the Oracle/Dealer to reflect real-world wUSDT conditions.
// ============================================================================

/// Internal ledger value of 1 BB: exactly 10 US cents of network compute.
/// IMMUTABLE — this is the foundation of all internal accounting.
pub const BB_USD_CENTS: u64 = 10;

/// Baseline exchange rate at node genesis: 10 BB per 1 wUSDT.
/// The live rate is stored in ReDB (key "BB_USDT") and may flex if wUSDT depegs.
/// Use `ConcurrentBlockchain::get_swap_rate("BB_USDT")` at runtime.
pub const BB_PER_USDT_DEFAULT: u64 = 10;

// Compile-time invariants: the internal accounting unit and decimal precision
// are fixed. Only the external exchange rate (BB_PER_USDT_DEFAULT) may flex.
const _: () = assert!(BB_USD_CENTS    == 10,       "$BB internal ledger value is exactly 10 US cents");
const _: () = assert!(LAMPORTS_PER_BB == 100_000,  "BB always has exactly 5 decimal places (10^5 lamports)");

/// Convert micro-stablecoin (6 dec) → BB lamports (5 dec) at a given exchange rate.
///
/// Formula: `bb_lamports = micro * LAMPORTS_PER_BB * rate / USDT_UNIT`
///
/// Uses u128 intermediate to prevent overflow on deposits up to ~$18 trillion.
/// Pass `BB_PER_USDT_DEFAULT` for genesis baseline or the live ReDB rate.
pub fn micro_stable_to_bb_lamports_at(micro: u64, rate: u64) -> u64 {
    ((micro as u128) * (LAMPORTS_PER_BB as u128) * (rate as u128)
        / (USDT_UNIT as u128)) as u64
}

/// Convenience wrapper using the genesis default rate.
/// For deposit gateway and bridge operations. For swap handlers, use
/// `micro_stable_to_bb_lamports_at(micro, state.blockchain.get_swap_rate("BB_USDT"))`.
pub fn micro_stable_to_bb_lamports(micro: u64) -> u64 {
    micro_stable_to_bb_lamports_at(micro, BB_PER_USDT_DEFAULT)
}

/// Maximum u64 used as the rent_epoch sentinel that means "rent-exempt forever".
///
/// Every account created on BlackBook L1 sets this field to RENT_EPOCH_EXEMPT.
/// No account ever has its lamports reduced by rent collection.
pub const RENT_EPOCH_EXEMPT: u64 = u64::MAX;

/// Maximum compute units per transaction (matches Solana's limit).
pub const MAX_COMPUTE_UNITS: u64 = 1_400_000;

/// Maximum age (in slots) for a recent blockhash to remain valid.
pub const MAX_RECENT_BLOCKHASHES: u64 = 150;

// ============================================================================
// STORED ACCOUNT — ReDB wire format
// ============================================================================

/// Borsh-serializable account representation stored in ReDB.
///
/// This is the on-disk format. In memory, the SVM hot-state uses Solana's
/// `AccountSharedData` directly for zero-copy efficiency.
///
/// Field invariants:
/// - `lamports` is always u64. Zero means the account is effectively deleted.
/// - `rent_epoch` is always `RENT_EPOCH_EXEMPT` for accounts created on BB L1.
/// - `owner` is the 32-byte pubkey of the program that owns this account.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredAccount {
    /// Balance in lamports. 1 BB = LAMPORTS_PER_BB.
    /// INVARIANT: this is the source of truth; f64 conversions are read-only,
    /// display-only and round-tripped through lamports.
    pub lamports: u64,

    /// Arbitrary account state data (program state, token metadata, etc.)
    pub data: Vec<u8>,

    /// 32-byte pubkey of the program that owns this account.
    /// System accounts (wallets) are owned by the System Program (all zeros).
    pub owner: [u8; 32],

    /// Is this account a BPF program (executable)?
    pub executable: bool,

    /// ALWAYS set to RENT_EPOCH_EXEMPT (u64::MAX) on BlackBook L1.
    /// Accounts never pay rent — this epoch marker means "exempt forever".
    pub rent_epoch: u64,
}

impl StoredAccount {
    /// Create a new empty wallet account owned by the System Program.
    ///
    /// `lamports` is the initial balance in lamports (use `LAMPORTS_PER_BB`
    /// as the multiplier, never floating-point).
    pub fn new_wallet(lamports: u64) -> Self {
        Self {
            lamports,
            data: vec![],
            owner: [0u8; 32], // System program owns plain wallets
            executable: false,
            rent_epoch: RENT_EPOCH_EXEMPT,
        }
    }

    /// Safely add lamports, returning an error on overflow to guard the
    /// zero-sum invariant (total supply must never increase by accident).
    pub fn checked_add_lamports(&mut self, amount: u64) -> Result<(), SvmError> {
        self.lamports = self
            .lamports
            .checked_add(amount)
            .ok_or(SvmError::LamportOverflow)?;
        Ok(())
    }

    /// Safely subtract lamports, returning an error on underflow (insufficient
    /// funds). This enforces the zero-sum game: you cannot debit more than
    /// you have.
    pub fn checked_sub_lamports(&mut self, amount: u64) -> Result<(), SvmError> {
        self.lamports = self
            .lamports
            .checked_sub(amount)
            .ok_or(SvmError::InsufficientFunds {
                available: self.lamports,
                required: amount,
            })?;
        Ok(())
    }

    /// Return the balance as a human-readable BB amount (display only).
    /// NEVER use this value in arithmetic; always use `lamports` directly.
    pub fn bb_display(&self) -> f64 {
        self.lamports as f64 / LAMPORTS_PER_BB as f64
    }
}

// ============================================================================
// CONVERSIONS — AccountSharedData ↔ StoredAccount
// ============================================================================
impl From<&AccountSharedData> for StoredAccount {
    fn from(acc: &AccountSharedData) -> Self {
        use solana_sdk::account::ReadableAccount;
        Self {
            lamports: acc.lamports(),
            data: acc.data().to_vec(),
            owner: acc.owner().to_bytes(),
            executable: acc.executable(),
            // Always enforce rent-exempt on BlackBook L1
            rent_epoch: RENT_EPOCH_EXEMPT,
        }
    }
}
impl From<StoredAccount> for AccountSharedData {
    fn from(stored: StoredAccount) -> Self {
        use solana_sdk::account::Account;
        AccountSharedData::from(Account {
            lamports: stored.lamports,
            data: stored.data,
            owner: Pubkey::new_from_array(stored.owner),
            executable: stored.executable,
            rent_epoch: RENT_EPOCH_EXEMPT,
        })
    }
}

// ============================================================================
// SVM ERRORS
// ============================================================================

/// Errors that can occur during SVM execution.
///
/// Every error variant carries enough context to pinpoint the root cause
/// without a debugger — important for production incident response.
#[derive(Debug, Error, Clone)]
pub enum SvmError {
    // -- Account errors
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Insufficient funds: have {available} lamports, need {required}")]
    InsufficientFunds { available: u64, required: u64 },

    #[error("Lamport overflow: result would exceed u64::MAX (supply creation bug)")]
    LamportOverflow,

    #[error("Account frozen: {0}")]
    AccountFrozen(String),

    // -- Transaction errors
    #[error("Invalid blockhash — transaction may be stale or replayed")]
    InvalidBlockhash,

    #[error("Duplicate signature: {0}")]
    DuplicateSignature(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // -- Execution errors
    #[error("Program execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Compute budget exceeded: used {used}, limit {limit}")]
    ComputeBudgetExceeded { used: u64, limit: u64 },

    #[error("Unknown program: {0}")]
    UnknownProgram(String),

    // -- Storage errors
    #[error("ReDB storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<redb::Error> for SvmError {
    fn from(e: redb::Error) -> Self {
        SvmError::StorageError(e.to_string())
    }
}

impl From<redb::TransactionError> for SvmError {
    fn from(e: redb::TransactionError) -> Self {
        SvmError::StorageError(e.to_string())
    }
}

impl From<redb::TableError> for SvmError {
    fn from(e: redb::TableError) -> Self {
        SvmError::StorageError(e.to_string())
    }
}

impl From<redb::CommitError> for SvmError {
    fn from(e: redb::CommitError) -> Self {
        SvmError::StorageError(e.to_string())
    }
}

impl From<redb::StorageError> for SvmError {
    fn from(e: redb::StorageError) -> Self {
        SvmError::StorageError(e.to_string())
    }
}

impl From<std::io::Error> for SvmError {
    fn from(e: std::io::Error) -> Self {
        SvmError::SerializationError(e.to_string())
    }
}

// ============================================================================
// TRANSACTION EXECUTION RESULT
// ============================================================================

/// Result of executing a single transaction through the SVM.
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Transaction ID / signature (hex-encoded).
    pub tx_id: String,

    /// Whether execution succeeded.
    pub success: bool,

    /// Error if execution failed (None on success).
    pub error: Option<SvmError>,

    /// Compute units actually consumed.
    pub compute_units_consumed: u64,

    /// Net lamport changes per account (positive = credit, negative = debit).
    /// Used by the scheduler to apply batch results atomically.
    pub lamport_deltas: Vec<(String, i64)>,
}

impl TransactionExecutionResult {
    pub fn ok(tx_id: String, cu: u64, deltas: Vec<(String, i64)>) -> Self {
        Self {
            tx_id,
            success: true,
            error: None,
            compute_units_consumed: cu,
            lamport_deltas: deltas,
        }
    }

    pub fn err(tx_id: String, error: SvmError) -> Self {
        Self {
            tx_id,
            success: false,
            error: Some(error),
            compute_units_consumed: 0,
            lamport_deltas: vec![],
        }
    }
}

// ============================================================================
// STORED TRANSACTION RESULT — Phase 2B ReDB wire format
// ============================================================================

/// Borsh-serializable transaction result stored in SVM_TX_LOG.
///
/// This is the on-disk format for confirmed transactions. `getTransaction`
/// reads this back and converts it into a Solana-compatible JSON response.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredTransactionResult {
    /// Transaction signature (base58-encoded).
    pub signature: String,

    /// Slot in which this transaction was processed.
    pub slot: u64,

    /// Whether execution succeeded.
    pub success: bool,

    /// Error message if execution failed (empty string on success).
    pub error_msg: String,

    /// Compute units actually consumed.
    pub compute_units_consumed: u64,

    /// Fee charged in lamports (Phase 1: always 0; Phase 6: priority fee market).
    pub fee: u64,

    /// Accounts involved in this transaction (base58-encoded pubkeys).
    pub account_keys: Vec<String>,

    /// Net lamport changes per account: (pubkey_b58, delta_i64).
    pub lamport_deltas: Vec<(String, i64)>,

    /// Block time (Unix timestamp in seconds).
    pub block_time: i64,
}

impl StoredTransactionResult {
    /// Create from a `TransactionExecutionResult` after it has been confirmed.
    pub fn from_execution(
        result: &TransactionExecutionResult,
        slot: u64,
        account_keys: Vec<String>,
    ) -> Self {
        Self {
            signature: result.tx_id.clone(),
            slot,
            success: result.success,
            error_msg: result.error.as_ref().map(|e| e.to_string()).unwrap_or_default(),
            compute_units_consumed: result.compute_units_consumed,
            fee: 0, // Phase 1: no fees
            account_keys,
            lamport_deltas: result.lamport_deltas.clone(),
            block_time: chrono::Utc::now().timestamp(),
        }
    }
}
