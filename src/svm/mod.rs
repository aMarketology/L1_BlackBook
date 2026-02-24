// ============================================================================
// BLACKBOOK SVM — MODULE ROOT
// ============================================================================
//
// This module implements the Solana Virtual Machine execution layer for
// BlackBook L1.  All SVM code is behind `#[cfg(feature = "svm")]` at the
// call sites so that a plain `cargo build` (without --features svm) compiles
// the existing production code without any regressions.
//
// Module layout:
//   types.rs      — StoredAccount, SvmError, constants, TransactionExecutionResult
//   accounts_db.rs — SvmAccountsDB (DashMap hot-state + ReDB flush)
//   runtime.rs    — BlackBookSVM (execution engine, blockhash queue)
//   tx_adapter.rs — Legacy TxData → TransferRequest routing
//
// Feature set per phase:
//   Phase 1A (current): types + accounts_db compile-gated
//   Phase 1B:           runtime executes system transfers
//   Phase 1C:           tx_adapter wires into BlockProducer
//   Phase 2+:           InvokeContext, rBPF, Anchor programs
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
