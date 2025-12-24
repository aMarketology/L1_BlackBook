// ============================================================================
// AUTH ROUTES - Profile & Keypair Generation (V2 - Pure Signature Auth)
// ============================================================================
//
// These routes handle identity and profile management.
// Uses Ed25519 signatures for authentication - NO JWT!

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::integration::unified_auth::{
    SignedRequest, with_signature_auth,
    generate_keypair, EncryptedBlob,
};
use crate::integration::supabase_connector::SupabaseConnector;

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// ============================================================================
// REGISTRATION TYPES
// ============================================================================

/// Request body for wallet registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWalletRequest {
    /// Username (unique identifier)
    pub username: String,
    /// User's email (optional)
    #[serde(default)]
    pub email: Option<String>,
    /// The encrypted wallet vault (AES-256-GCM encrypted mnemonic)
    pub encrypted_vault: EncryptedBlob,
    /// Public key (hex, 64 chars) - derived from the mnemonic
    pub public_key: String,
}

// ============================================================================
// PUBLIC ROUTES (No signature required)
// ============================================================================

/// POST /auth/register - Register a new wallet with encrypted vault
/// 
/// This stores the encrypted wallet vault in Supabase for cross-device recovery.
/// The vault is encrypted CLIENT-SIDE using the user's password + Argon2id.
/// 
/// Request body:
/// ```json
/// {
///   "username": "alice",
///   "email": "alice@example.com",  // optional
///   "encrypted_vault": {
///     "version": 1,
///     "salt": "64 hex chars",
///     "nonce": "24 hex chars",
///     "ciphertext": "base64 encrypted mnemonic",
///     "address": "L1_..."
///   },
///   "public_key": "64 hex chars"
/// }
/// ```
pub fn register_wallet_route(
    supabase: Arc<SupabaseConnector>,
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("register"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: RegisterWalletRequest| {
            let supabase = supabase.clone();
            let blockchain = blockchain.clone();
            async move {
                println!("📝 Registering new wallet for: {}", request.username);
                
                // 1. Validate inputs
                if request.username.len() < 3 || request.username.len() > 32 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Username must be 3-32 characters"
                    })));
                }
                
                if request.public_key.len() != 64 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid public key length (expected 64 hex chars)"
                    })));
                }
                
                // Validate hex
                if hex::decode(&request.public_key).is_err() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid public key (not valid hex)"
                    })));
                }
                
                // 2. Check if username already exists
                match supabase.get_profile_by_username(&request.username).await {
                    Ok(Some(_)) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Username already taken"
                        })));
                    }
                    Ok(None) => { /* Good - username available */ }
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Database error: {}", e)
                        })));
                    }
                }
                
                // 3. Create user profile in Supabase
                let email = request.email.as_deref().unwrap_or(&request.username);
                match supabase.create_user_profile("", email, Some(&request.username)).await {
                    Ok(_profile) => {
                        println!("✅ Profile created for: {}", request.username);
                        
                        // 4. Store encrypted vault
                        let vault_json = serde_json::to_string(&request.encrypted_vault)
                            .unwrap_or_default();
                        
                        match supabase.store_blackbook_vault(
                            &request.username,
                            &request.encrypted_vault.salt,
                            &vault_json,
                            &request.encrypted_vault.address,
                        ).await {
                            Ok(()) => {
                                println!("✅ Encrypted vault stored for: {}", request.username);
                                
                                // 5. Register address in blockchain (for initial balance, etc.)
                                {
                                    let mut bc = lock_or_recover(&blockchain);
                                    bc.register_user_address(&request.username, &request.encrypted_vault.address);
                                }
                                
                                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                    "success": true,
                                    "message": "Wallet registered successfully",
                                    "profile": {
                                        "username": request.username,
                                        "address": request.encrypted_vault.address,
                                        "public_key": request.public_key
                                    },
                                    "note": "Your encrypted vault is stored. Use your password to unlock it on any device."
                                })))
                            }
                            Err(e) => {
                                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                    "success": false,
                                    "error": format!("Failed to store vault: {}", e)
                                })))
                            }
                        }
                    }
                    Err(e) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Failed to create profile: {}", e)
                        })))
                    }
                }
            }
        })
}

/// POST /auth/vault/salt - Get vault salt for a user (needed before login)
/// 
/// The salt is public - it's needed to derive the encryption key from the password.
pub fn get_vault_salt_route(
    supabase: Arc<SupabaseConnector>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("vault"))
        .and(warp::path("salt"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |body: serde_json::Value| {
            let supabase = supabase.clone();
            async move {
                let username = body.get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                if username.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Username is required"
                    })));
                }
                
                match supabase.get_vault_salt(username).await {
                    Ok(Some(salt)) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "username": username,
                            "salt": salt
                        })))
                    }
                    Ok(None) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "User not found or no wallet registered"
                        })))
                    }
                    Err(e) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Database error: {}", e)
                        })))
                    }
                }
            }
        })
}

/// POST /auth/vault/fetch - Get encrypted vault for a user (for client-side decryption)
/// 
/// Returns the encrypted vault which the client decrypts using password + salt.
pub fn get_vault_route(
    supabase: Arc<SupabaseConnector>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("vault"))
        .and(warp::path("fetch"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |body: serde_json::Value| {
            let supabase = supabase.clone();
            async move {
                let username = body.get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                if username.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Username is required"
                    })));
                }
                
                match supabase.get_encrypted_vault(username).await {
                    Ok(Some((salt, vault))) => {
                        // Try to parse vault as JSON, otherwise return as string
                        let vault_obj: serde_json::Value = serde_json::from_str(&vault)
                            .unwrap_or(serde_json::json!(vault));
                        
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "username": username,
                            "salt": salt,
                            "encrypted_vault": vault_obj
                        })))
                    }
                    Ok(None) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "User not found or no wallet registered"
                        })))
                    }
                    Err(e) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Database error: {}", e)
                        })))
                    }
                }
            }
        })
}

/// POST /auth/keypair - Generate a new keypair for testing
/// 
/// Returns: { public_key, private_key }
/// 
/// This is for TESTING ONLY - in production, keypairs are derived client-side
/// from mnemonic using the BlackBook SDK.
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
                    "address": public_key  // Address = public key in BlackBook
                },
                "note": "Store private_key securely. Use it to sign all authenticated requests."
            })))
        })
}

/// GET /auth/test-accounts - Get Alice & Bob full test accounts
/// 
/// Returns comprehensive test accounts with UNIFIED WALLET MODEL:
/// - Alice & Bob: Full accounts with unified L1/L2 addresses
/// - All funds start in L1 (available), must bridge to L2 to bet
pub fn test_accounts_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("test-accounts"))
        .and(warp::get())
        .and_then(|| async move {
            // Get full test accounts (Alice + Bob)
            let alice = crate::integration::unified_auth::get_alice_account();
            let bob = crate::integration::unified_auth::get_bob_account();
            
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "message": "UNIFIED WALLET MODEL - Test accounts for L1 and L2",
                "wallet_model": {
                    "description": "Users see ONE total balance. Funds must be bridged to L2 for betting.",
                    "flow": [
                        "1. User starts with all funds in L1 (available)",
                        "2. bridgeToL2(amount) → locks on L1, credits L2",
                        "3. User bets on L2 (instant, off-chain)",
                        "4. withdrawToL1() → settles L2 balance back to L1"
                    ]
                },
                
                // Alice - Full test account with UNIFIED WALLET
                "alice": {
                    "name": alice.name,
                    "email": alice.email,
                    "username": alice.username,
                    "public_key": alice.public_key,
                    "private_key": alice.private_key,
                    "address": alice.address,  // Unified address for both L1 and L2
                    
                    // UNIFIED WALLET MODEL
                    "total_balance": alice.total_balance,  // What user sees in UI
                    "l1_available": alice.l1_available,    // Can transfer or bridge
                    "l1_locked": alice.l1_locked,          // Locked (bridged to L2)
                    "l2_balance": alice.l2_balance,        // Active on L2 for betting
                    
                    "capabilities": [
                        "✅ Sign transactions",
                        "✅ L1 transfers",
                        "✅ Bridge L1 → L2 (lock funds)",
                        "✅ Bet on L2 (instant)",
                        "✅ Withdraw L2 → L1 (unlock + profit)",
                        "✅ Social mining"
                    ]
                },
                
                // Bob - Full test account with UNIFIED WALLET
                "bob": {
                    "name": bob.name,
                    "email": bob.email,
                    "username": bob.username,
                    "public_key": bob.public_key,
                    "private_key": bob.private_key,
                    "address": bob.address,  // Unified address for both L1 and L2
                    
                    // UNIFIED WALLET MODEL
                    "total_balance": bob.total_balance,    // What user sees in UI
                    "l1_available": bob.l1_available,      // Can transfer or bridge
                    "l1_locked": bob.l1_locked,            // Locked (bridged to L2)
                    "l2_balance": bob.l2_balance,          // Active on L2 for betting
                    
                    "capabilities": [
                        "✅ Sign transactions",
                        "✅ L1 transfers",
                        "✅ Bridge L1 → L2 (lock funds)",
                        "✅ Bet on L2 (instant)",
                        "✅ Withdraw L2 → L1 (unlock + profit)",
                        "✅ Social mining"
                    ]
                },
                
                // Testing instructions
                "testing": {
                    "l1_rpc": "http://localhost:8080",
                    "l2_rpc": std::env::var("L2_RPC_URL").unwrap_or_else(|_| "http://localhost:1234".to_string()),
                    "examples": {
                        "transfer": "Alice sends 100 BB to Bob on L1",
                        "bridge": "Bob bridges 50 BB from L1 to L2",
                        "social": "Alice creates a post for social mining rewards",
                        "mpc": "Alice sets up MPC 2-of-2 threshold signing"
                    }
                },
                
                "note": "⚠️ PRIVATE KEYS EXPOSED - For testing only! Never use in production."
            })))
        })
}

// ============================================================================
// AUTHENTICATED ROUTES (Signature required)
// ============================================================================

/// POST /profile - Get authenticated user's profile
/// 
/// Request: SignedRequest with empty payload {}
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
                
                println!("👤 Profile: {}... Balance: {} L1", 
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

/// POST /auth/verify - Verify a signature (for testing)
/// 
/// Request: SignedRequest
/// Returns: verification result
pub fn verify_signature_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("verify"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|request: SignedRequest| async move {
            match request.verify() {
                Ok(wallet_address) => {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "verified": true,
                        "wallet_address": wallet_address,
                        "message": "Signature is valid"
                    })))
                },
                Err(e) => {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "verified": false,
                        "error": e
                    })))
                }
            }
        })
}
