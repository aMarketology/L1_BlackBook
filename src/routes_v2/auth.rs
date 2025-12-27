// ============================================================================
// AUTH ROUTES - Signature Verification & Test Accounts (Supabase-Free)
// ============================================================================
//
// This module handles signature-based authentication for blockchain operations.
// Password authentication is now handled client-side via Supabase SDK.
//
// ARCHITECTURE:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Client → Supabase (registration, login, vault storage)                │
// │  Client → Rust Server (blockchain ops with Ed25519 signatures)         │
// │                                                                         │
// │  Rust Server: Verifies signatures, executes transactions               │
// │  Supabase: Stores encrypted vaults, manages auth                       │
// └─────────────────────────────────────────────────────────────────────────┘

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::integration::unified_auth::{
    SignedRequest, with_signature_auth, generate_keypair,
};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// ============================================================================
// TEST & UTILITY ROUTES
// ============================================================================

/// POST /auth/keypair - Generate a new Ed25519 keypair for testing
/// 
/// Returns: { public_key, private_key, address }
/// 
/// ⚠️ TESTING ONLY - In production, keypairs are derived client-side from mnemonic
pub fn generate_keypair_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("keypair"))
        .and(warp::post())
        .and_then(|| async move {
            let (private_key, public_key) = generate_keypair();
            
            println!("🔑 Generated keypair: {}...", &public_key[..16]);
            
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "keypair": {
                    "public_key": public_key,
                    "private_key": private_key,
                    "address": format!("L1_{}", &public_key[..40].to_uppercase())
                },
                "note": "⚠️ Store private_key securely. Use it to sign all blockchain transactions."
            })))
        })
}

/// GET /auth/test-accounts - Get Alice & Bob test accounts with full credentials
/// 
/// Returns comprehensive test accounts with UNIFIED WALLET MODEL.
/// Alice: 10,000 BB starting balance
/// Bob: 5,000 BB starting balance
pub fn test_accounts_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("test-accounts"))
        .and(warp::get())
        .and_then(|| async move {
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "message": "UNIFIED WALLET MODEL - Test accounts for L1 and L2",
                "alice": {
                    "name": "Alice",
                    "username": "alice_test",
                    "email": "alice@blackbook.test",
                    "l1_address": "L1_ALICE000000001",
                    "public_key": "c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705",
                    "private_key": "18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24",
                    "initial_balance": 10000.0
                },
                "bob": {
                    "name": "Bob",
                    "username": "bob_test",
                    "email": "bob@blackbook.test",
                    "l1_address": "L1_BOB00000000001",
                    "public_key": "582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a",
                    "private_key": "e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b",
                    "initial_balance": 5000.0
                },
                "dealer": {
                    "name": "Dealer",
                    "l1_address": "L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3",
                    "public_key": "d9d4a8d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
                    "initial_balance": 100000.0
                },
                "note": "⚠️ PRIVATE KEYS EXPOSED - For testing only!"
            })))
        })
}

// ============================================================================
// AUTHENTICATED ROUTES (Ed25519 Signature Required)
// ============================================================================

/// POST /profile - Get authenticated user's blockchain profile
/// 
/// Requires: SignedRequest with valid Ed25519 signature
/// Returns: wallet address, balance, transaction count
pub fn profile_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("profile")
        .and(warp::post())
        .and(with_signature_auth())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            async move {
                let (balance, tx_count) = {
                    let bc = lock_or_recover(&blockchain);
                    let balance = bc.get_balance(&wallet_address);
                    let tx_count = bc.chain.iter()
                        .flat_map(|block| block.financial_txs.iter().chain(block.social_txs.iter()))
                        .filter(|tx| tx.from == wallet_address || tx.to == wallet_address)
                        .count();
                    (balance, tx_count)
                };
                
                println!("👤 Profile requested: {}... Balance: {} BB", 
                         &wallet_address[..16.min(wallet_address.len())], balance);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "profile": {
                        "wallet_address": wallet_address,
                        "balance": balance,
                        "transaction_count": tx_count
                    }
                })))
            }
        })
}

/// POST /auth/verify - Verify an Ed25519 signature
/// 
/// Request: SignedRequest with signature
/// Returns: verification result + recovered wallet address
pub fn verify_signature_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("verify"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|request: SignedRequest| async move {
            match request.verify() {
                Ok(wallet_address) => {
                    println!("✅ Signature verified for: {}...", &wallet_address[..16]);
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "verified": true,
                        "wallet_address": wallet_address,
                        "message": "Signature is valid"
                    })))
                },
                Err(e) => {
                    println!("❌ Signature verification failed: {}", e);
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "verified": false,
                        "error": e
                    })))
                }
            }
        })
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/// GET /auth/health - Health check endpoint
pub fn health_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("health"))
        .and(warp::get())
        .and_then(|| async move {
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "service": "BlackBook L1 Auth Service",
                "status": "healthy",
                "capabilities": [
                    "Ed25519 signature verification",
                    "Test account generation",
                    "Blockchain profile queries"
                ],
                "note": "Registration and login now handled via Supabase SDK on client"
            })))
        })
}
