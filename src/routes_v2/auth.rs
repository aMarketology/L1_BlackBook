// ============================================================================
// AUTH ROUTES - Signature Verification
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
use crate::storage::PersistentBlockchain;
use crate::integration::unified_auth::{
    SignedRequest, with_signature_auth, generate_keypair,
};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<PersistentBlockchain>) -> MutexGuard<'a, PersistentBlockchain> {
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
/// Returns comprehensive test accounts with REAL Ed25519 addresses.
/// Balances persist across server restarts.
pub fn test_accounts_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("test-accounts"))
        .and(warp::get())
        .and_then(|| async move {
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "message": "Real Ed25519 test accounts - balances persist across sessions",
                "alice": {
                    "name": "Alice",
                    "username": "alice_test",
                    "email": "alice@blackbook.test",
                    "l1_address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
                    "seed": "18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24",
                    "public_key": "c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705",
                    "initial_balance": 20000.0,
                    "note": "Use seed with nacl.sign.keyPair.fromSeed() to derive keypair"
                },
                "bob": {
                    "name": "Bob",
                    "username": "bob_test",
                    "email": "bob@blackbook.test",
                    "l1_address": "L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433",
                    "seed": "e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b",
                    "public_key": "582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a",
                    "initial_balance": 10000.0,
                    "note": "Use seed with nacl.sign.keyPair.fromSeed() to derive keypair"
                },
                "dealer": {
                    "name": "Dealer",
                    "l1_address": "L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC",
                    "seed": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
                    "public_key": "65328794ed4a81cc2a92b93738c22a545f066cc6c0b6a72aa878cfa289f0ba32",
                    "initial_balance": 100000.0,
                    "note": "House bankroll - seed exposed for testing only"
                },
                "warning": "⚠️ Seeds exposed - For testing only!"
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
    blockchain: Arc<Mutex<PersistentBlockchain>>
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
                    let tx_count = bc.chain().iter()
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
