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

// Re-export the most-used types at the svm:: level for ergonomic imports.
pub use types::{
    StoredAccount,
    SvmError,
    TransactionExecutionResult,
    LAMPORTS_PER_BB,
    RENT_EPOCH_EXEMPT,
    MAX_COMPUTE_UNITS,
    MAX_RECENT_BLOCKHASHES,
};

pub use accounts_db::{
    SvmAccountsDB,
    SVM_ACCOUNTS,
    SVM_PROGRAMS,
    BLOCKHASH_QUEUE,
    SVM_SIGNATURES,
};

#[cfg(feature = "svm")]
pub use runtime::{BlackBookSVM, TransferRequest, BlockhashQueue};

pub use tx_adapter::{bb_to_lamports, lamports_to_bb};
