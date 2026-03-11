// ============================================================================
// BLACKBOOK SVM — MODULE ROOT
// ============================================================================
//
// This module implements the Solana Virtual Machine execution layer for
// BlackBook L1.  The SVM is always compiled and active — there are no
// feature gates.  This is the production writer-node execution engine.
//
// Module layout:
//   types.rs      — StoredAccount, SvmError, constants, TransactionExecutionResult
//   accounts_db.rs — SvmAccountsDB (DashMap hot-state + ReDB flush)
//   runtime.rs    — BlackBookSVM (execution engine, blockhash queue)
//   spl_token.rs  — SPL Token engine (USDC bridge minting)
//
// Feature set per phase:
//   Phase 1 (live):  types + accounts_db + runtime (system transfers + SPL)
//   Phase 2:         InvokeContext, rBPF, Anchor programs
//
// ============================================================================

pub mod types;
pub mod accounts_db;
pub mod runtime;
pub mod spl_token;
pub mod sigverify;

// Re-export the most-used types at the svm:: level for ergonomic imports.
pub use types::{
    StoredTransactionResult,
    LAMPORTS_PER_BB,
};

pub use accounts_db::SvmAccountsDB;
pub use runtime::{BlackBookSVM, TransferRequest};


// Re-export SPL Token types and helpers
pub use spl_token::{
    SplTokenEngine,
    usdc_mint_address,
    usdc_mint_bytes,
    USDC_DECIMALS,
    USDC_UNIT,
};
