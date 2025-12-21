// ============================================================================
// RPC MODULE - Internal and Cross-Layer RPC Communications
// ============================================================================
//
// This module contains RPC-related functionality for L1 ↔ L2 communication:
//
// - `cross_layer_rpc`: HTTP-based cross-layer RPC (for public endpoints)
// - `signed_transaction`: Cross-layer signed transaction verification
// - `internal_rpc`: TCP-based internal RPC (for localhost L1↔L2 comms)
// - `settlement`: Dealer/Solver settlement (User L1 → Dealer L1)

pub mod cross_layer_rpc;
pub mod signed_transaction;
pub mod internal_rpc;
pub mod settlement;

// Re-exports for convenience
pub use internal_rpc::{
    InternalRpcServer,
    Request as InternalRpcRequest,
    Response as InternalRpcResponse,
    INTERNAL_RPC_PORT,
};

pub use cross_layer_rpc::CrossLayerServer;
pub use signed_transaction::{SignedTransaction, verify_cross_layer, VerificationResult};
pub use settlement::{SettlementExecutor, SolverIntent, SignedIntent, SettlementReceipt, BatchSettlementResult};
