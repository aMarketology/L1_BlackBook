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
//   tx_adapter.rs — Legacy TxData → TransferRequest routing
//
// Feature set per phase:
//   Phase 1 (live):  types + accounts_db + runtime + tx_adapter (system transfers)
//   Phase 2:         SPL Token engine (USDC bridge minting)
//   Phase 3:         InvokeContext, rBPF, Anchor programs
//
// ============================================================================

pub mod types;
pub mod accounts_db;
pub mod runtime;
pub mod tx_adapter;
pub mod spl_token;

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
