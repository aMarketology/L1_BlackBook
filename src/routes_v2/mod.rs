// ============================================================================
// LAYER1 ROUTES V2 - Pure Signature-Based Authentication
// ============================================================================
//
// All routes use Ed25519 signature verification via SignedRequest.
// NO JWT, NO Supabase - just cryptographic signatures.
//
// Route Organization:
// - auth.rs:     Profile, keypair generation (public + authenticated)
// - wallet.rs:   Balance, wallet info (authenticated)
// - transfer.rs: Token transfers (authenticated)
// - social.rs:   Social mining actions (authenticated)
// - rpc.rs:      Health, stats, JSON-RPC (public + authenticated)
// - bridge.rs:   Cross-layer L1 ↔ L2 bridge operations
// - admin.rs:    Admin token minting (OPEN ACCESS - DEVELOPMENT)
// - markets.rs:  L2 market/event initial liquidity management

pub mod auth;
pub mod wallet;
pub mod transfer;
pub mod social;
pub mod rpc;
pub mod bridge;
pub mod admin;
pub mod markets;
pub mod services;

// Re-export all routes for easy access from main_v2.rs
// Note: Routes are accessed via routes_v2::module::function() pattern

// Re-export service coordinator for easy access
pub use services::ServiceCoordinator;
