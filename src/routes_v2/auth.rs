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
            let alice = crate::integration::unified_auth::get_alice_account();
            let bob = crate::integration::unified_auth::get_bob_account();
            
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "message": "UNIFIED WALLET MODEL - Test accounts for L1 and L2",
                "architecture": {
                    "description": "Users see ONE total balance. Funds must be bridged to L2 for betting.",
                    "flow": [
                        "1. User starts with all funds in L1 (available)",
                        "2. bridgeToL2(amount) → locks on L1, credits L2",
                        "3. User bets on L2 (instant, off-chain)",
                        "4. withdrawToL1() → settles L2 balance back to L1"
                    ]
                },
                "alice": {
                    "name": alice.name,
                    "email": alice.email,
                    "username": alice.username,
                    "public_key": alice.public_key,
                    "private_key": alice.private_key,
                    "address": alice.address,
                    "total_balance": alice.total_balance,
                    "l1_available": alice.l1_available,
                    "l1_locked": alice.l1_locked,
                    "l2_balance": alice.l2_balance,
                    "capabilities": [
                        "✅ Sign transactions with Ed25519",
                        "✅ L1 transfers",
                        "✅ Bridge L1 → L2",
                        "✅ Bet on L2",
                        "✅ Withdraw L2 → L1",
                        "✅ Social mining"
                    ]
                },
                "bob": {
                    "name": bob.name,
                    "email": bob.email,
                    "username": bob.username,
                    "public_key": bob.public_key,
                    "private_key": bob.private_key,
                    "address": bob.address,
                    "total_balance": bob.total_balance,
                    "l1_available": bob.l1_available,
                    "l1_locked": bob.l1_locked,
                    "l2_balance": bob.l2_balance,
                    "capabilities": [
                        "✅ Sign transactions with Ed25519",
                        "✅ L1 transfers",
                        "✅ Bridge L1 → L2",
                        "✅ Bet on L2",
                        "✅ Withdraw L2 → L1",
                        "✅ Social mining"
                    ]
                },
                "testing": {
                    "l1_rpc": "http://localhost:8080",
                    "l2_rpc": std::env::var("L2_RPC_URL").unwrap_or_else(|_| "http://localhost:1234".to_string()),
                    "examples": {
                        "transfer": "Alice sends 100 BB to Bob on L1",
                        "bridge": "Bob bridges 50 BB from L1 to L2",
                        "social": "Alice creates a post for social mining rewards"
                    }
                },
                "note": "⚠️ PRIVATE KEYS EXPOSED - For testing only! Never use in production."
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
