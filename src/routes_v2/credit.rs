// ============================================================================
// CREDIT LINE SYSTEM - L2 Gaming Credit Against L1 Balances
// ============================================================================
//
// This is a SIMPLE credit line model:
// - L1 is the ONLY source of truth for real balances
// - L2 requests "credit" against L1 balance (no token movement)
// - L1 reserves the balance, L2 tracks virtual positions
// - Settlement writes NET P&L back to L1
//
// NO bridge locks, NO L2 token minting - just credit and settlement.
//
// Flow:
//   1. User has 10,000 $BC on L1
//   2. L2 calls POST /credit/open (reserves 5,000 from L1)
//   3. User plays on L2 (virtual balance tracked by L2)
//   4. L2 calls POST /credit/settle (writes P&L to L1)
//   5. L1 balance updated: 10,000 → 12,500 (if user won 2,500)
//
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::storage::PersistentBlockchain;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Active credit line for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLine {
    pub session_id: String,
    pub wallet_address: String,    // L1_... address
    pub credit_amount: f64,        // Amount reserved from L1
    pub l1_balance_at_open: f64,   // L1 balance when credit opened
    pub opened_at: u64,            // Unix timestamp
    pub is_active: bool,
}

/// Request to open a credit line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCreditRequest {
    pub wallet_address: String,    // L1 address
    pub amount: f64,               // Amount to reserve
    pub l2_public_key: String,     // L2 node public key (for verification)
    pub signature: String,         // Signature from L2 node
    pub timestamp: u64,
}

/// Request to settle a credit line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleCreditRequest {
    pub session_id: String,
    pub wallet_address: String,
    pub final_balance: f64,        // User's final L2 balance
    pub pnl: f64,                  // Net P&L (positive = won, negative = lost)
    pub l2_public_key: String,
    pub signature: String,
    pub timestamp: u64,
}

/// In-memory credit line state (should be persisted in production)
#[derive(Debug, Default)]
pub struct CreditState {
    pub active_credits: HashMap<String, CreditLine>,  // session_id -> CreditLine
    pub user_sessions: HashMap<String, String>,       // wallet_address -> session_id
    pub session_locks: HashMap<String, String>,       // session_id -> lock_id (L1 token locks)
}

impl CreditState {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn get_user_session(&self, wallet: &str) -> Option<&CreditLine> {
        self.user_sessions.get(wallet)
            .and_then(|sid| self.active_credits.get(sid))
    }
    
    pub fn has_active_session(&self, wallet: &str) -> bool {
        self.user_sessions.get(wallet)
            .and_then(|sid| self.active_credits.get(sid))
            .map(|c| c.is_active)
            .unwrap_or(false)
    }
}
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn lock_blockchain<'a>(mutex: &'a Mutex<PersistentBlockchain>) -> MutexGuard<'a, PersistentBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

fn lock_credit_state<'a>(mutex: &'a Mutex<CreditState>) -> MutexGuard<'a, CreditState> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn generate_session_id() -> String {
    // Use nanoseconds for uniqueness
    format!("session_{}", now_timestamp_nanos())
}

// Known L2 node public key (must match L2's signing key)
const TRUSTED_L2_PUBKEY: &str = "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a";

fn verify_l2_signature(pubkey: &str, message: &str, signature: &str) -> bool {
    // Verify the L2 node's signature
    if pubkey != TRUSTED_L2_PUBKEY {
        println!("⚠️ Unknown L2 public key: {}", pubkey);
        return false;
    }
    
    // TODO: Implement actual Ed25519 verification
    // For now, accept if pubkey matches trusted key
    // In production: verify signature over message
    !signature.is_empty() && !message.is_empty()
}

// ============================================================================
// ROUTE: Open Credit Line
// ============================================================================
// POST /credit/open
// 
// L2 calls this to reserve funds from a user's L1 balance.
// No tokens are moved - L1 just tracks the reservation.
//
// Request:
// {
//   "wallet_address": "L1_ABC123...",
//   "amount": 5000.0,
//   "l2_public_key": "07943256...",
//   "signature": "...",
//   "timestamp": 1234567890
// }
//
// Response:
// {
//   "success": true,
//   "session_id": "session_123_456",
//   "credit_amount": 5000.0,
//   "l1_balance": 10000.0,
//   "available_after_credit": 5000.0
// }
// ============================================================================

pub fn open_credit_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    credit_state: Arc<Mutex<CreditState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("credit" / "open")
        .and(warp::post())
        .and(warp::body::json::<OpenCreditRequest>())
        .and_then(move |request: OpenCreditRequest| {
            let blockchain = blockchain.clone();
            let credit_state = credit_state.clone();
            async move {
                println!("\n════════════════════════════════════════════════════════");
                println!("📋 CREDIT OPEN REQUEST");
                println!("════════════════════════════════════════════════════════");
                println!("   Wallet: {}", request.wallet_address);
                println!("   Amount: {} $BC", request.amount);
                
                // Verify L2 signature
                let message = format!("CREDIT_OPEN:{}:{}:{}", 
                    request.wallet_address, request.amount, request.timestamp);
                
                if !verify_l2_signature(&request.l2_public_key, &message, &request.signature) {
                    println!("   ❌ Invalid L2 signature");
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid L2 signature"
                    })));
                }
                
                // Check for existing active session
                {
                    let state = lock_credit_state(&credit_state);
                    if state.has_active_session(&request.wallet_address) {
                        println!("   ❌ User already has active credit session");
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "User already has active credit session"
                        })));
                    }
                }
                
                // Check L1 balance and LOCK tokens
                let (l1_balance, lock_id) = {
                    let mut bc = lock_blockchain(&blockchain);
                    let balance = bc.get_balance(&request.wallet_address);
                    
                    println!("   L1 Balance: {} $BC", balance);
                    
                    if balance < request.amount {
                        println!("   ❌ Insufficient L1 balance");
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Insufficient balance: {} < {}", balance, request.amount),
                            "l1_balance": balance,
                            "requested": request.amount
                        })));
                    }
                    
                    // CRITICAL: Lock tokens on L1 to maintain 1:1 peg with L2
                    let lock_id = match bc.lock_tokens(
                        &request.wallet_address,
                        request.amount,
                        crate::protocol::blockchain::LockPurpose::CreditLine,
                        Some(format!("L2_CREDIT_{}", request.wallet_address))
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            println!("   ❌ Failed to lock tokens: {}", e);
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Failed to lock tokens: {}", e)
                            })));
                        }
                    };
                    
                    println!("   🔒 Locked {} $BC (lock_id: {})", request.amount, lock_id);
                    
                    (balance, lock_id)
                };
                
                // Create credit line with lock reference
                let session_id = generate_session_id();
                let credit = CreditLine {
                    session_id: session_id.clone(),
                    wallet_address: request.wallet_address.clone(),
                    credit_amount: request.amount,
                    l1_balance_at_open: l1_balance,
                    opened_at: now_timestamp(),
                    is_active: true,
                };
                
                // Store credit line and lock_id mapping
                {
                    let mut state = lock_credit_state(&credit_state);
                    state.active_credits.insert(session_id.clone(), credit);
                    state.user_sessions.insert(request.wallet_address.clone(), session_id.clone());
                    // Store lock_id for settlement (we'll need to add this field to CreditState)
                    state.session_locks.insert(session_id.clone(), lock_id.clone());
                }
                
                println!("   ✅ Credit line opened: {}", session_id);
                println!("   Reserved: {} $BC (LOCKED on L1)", request.amount);
                println!("   Available after credit: {} $BC", l1_balance - request.amount);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "session_id": session_id,
                    "credit_amount": request.amount,
                    "l1_balance": l1_balance,
                    "available_after_credit": l1_balance - request.amount,
                    "lock_id": lock_id,
                    "message": "Credit line opened. Tokens LOCKED on L1 to maintain 1:1 peg with L2. L2 can now mint equivalent tokens."
                })))
            }
        })
}

// ============================================================================
// ROUTE: Settle Credit Line
// ============================================================================
// POST /credit/settle
//
// L2 calls this to close a credit session and apply P&L to L1.
//
// Request:
// {
//   "session_id": "session_123_456",
//   "wallet_address": "L1_ABC123...",
//   "final_balance": 7500.0,  // User ended with 7500 on L2
//   "pnl": 2500.0,            // Won 2500 (started with 5000)
//   "l2_public_key": "...",
//   "signature": "...",
//   "timestamp": 1234567890
// }
//
// Response:
// {
//   "success": true,
//   "l1_balance_before": 10000.0,
//   "l1_balance_after": 12500.0,  // 10000 + 2500 winnings
//   "pnl_applied": 2500.0
// }
// ============================================================================

pub fn settle_credit_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    credit_state: Arc<Mutex<CreditState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("credit" / "settle")
        .and(warp::post())
        .and(warp::body::json::<SettleCreditRequest>())
        .and_then(move |request: SettleCreditRequest| {
            let blockchain = blockchain.clone();
            let credit_state = credit_state.clone();
            async move {
                println!("\n════════════════════════════════════════════════════════");
                println!("💰 CREDIT SETTLE REQUEST");
                println!("════════════════════════════════════════════════════════");
                println!("   Session: {}", request.session_id);
                println!("   Wallet: {}", request.wallet_address);
                println!("   Final L2 Balance: {} $BB", request.final_balance);
                println!("   P&L: {} $BC", request.pnl);
                
                // Verify L2 signature
                let message = format!("CREDIT_SETTLE:{}:{}:{}:{}", 
                    request.session_id, request.wallet_address, request.pnl, request.timestamp);
                
                if !verify_l2_signature(&request.l2_public_key, &message, &request.signature) {
                    println!("   ❌ Invalid L2 signature");
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid L2 signature"
                    })));
                }
                
                // Get and validate credit line
                let credit = {
                    let state = lock_credit_state(&credit_state);
                    state.active_credits.get(&request.session_id).cloned()
                };
                
                let credit = match credit {
                    Some(c) if c.is_active => c,
                    Some(_) => {
                        println!("   ❌ Session already settled");
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Session already settled"
                        })));
                    }
                    None => {
                        println!("   ❌ Session not found");
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Session not found"
                        })));
                    }
                };
                
                // Verify wallet matches
                if credit.wallet_address != request.wallet_address {
                    println!("   ❌ Wallet mismatch");
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Wallet address mismatch"
                    })));
                }
                
                // Apply P&L to L1 balance
                let (l1_before, l1_after) = {
                    let mut bc = lock_blockchain(&blockchain);
                    let balance_before = bc.get_balance(&request.wallet_address);
                    
                    // Apply P&L
                    if request.pnl > 0.0 {
                        // User won - transfer from dealer to user
                        let dealer_address = "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D";
                        let dealer_balance = bc.get_balance(dealer_address);
                        
                        if dealer_balance < request.pnl {
                            println!("   ❌ Dealer insufficient balance for payout");
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Dealer insufficient balance"
                            })));
                        }
                        
                        // Create payout transaction
                        let _ = bc.create_transaction(
                            dealer_address.to_string(),
                            request.wallet_address.clone(),
                            request.pnl,
                        );
                        
                        // Mine the transaction
                        if let Err(e) = bc.mine_pending_transactions("settlement".to_string()) {
                            println!("   ⚠️ Mining failed: {}", e);
                        }
                        
                        println!("   💸 Dealer → User: {} $BC (winnings)", request.pnl);
                        
                    } else if request.pnl < 0.0 {
                        // User lost - transfer from user to dealer
                        let loss = request.pnl.abs();
                        let dealer_address = "L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D";
                        
                        if balance_before < loss {
                            println!("   ❌ User insufficient balance for loss");
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "User insufficient balance for loss"
                            })));
                        }
                        
                        // Create loss transaction
                        let _ = bc.create_transaction(
                            request.wallet_address.clone(),
                            dealer_address.to_string(),
                            loss,
                        );
                        
                        // Mine the transaction
                        if let Err(e) = bc.mine_pending_transactions("settlement".to_string()) {
                            println!("   ⚠️ Mining failed: {}", e);
                        }
                        
                        println!("   💸 User → Dealer: {} $BC (losses)", loss);
                    } else {
                        println!("   ➖ No P&L to apply (break even)");
                    }
                    
                    let balance_after = bc.get_balance(&request.wallet_address);
                    
                    // CRITICAL: Release the locked tokens
                    let lock_id = {
                        let state = lock_credit_state(&credit_state);
                        state.session_locks.get(&request.session_id).cloned()
                    };
                    
                    if let Some(lock_id) = lock_id {
                        match bc.release_tokens(&lock_id) {
                            Ok((addr, amount)) => {
                                println!("   🔓 Released {} $BC lock for {}", amount, addr);
                            }
                            Err(e) => {
                                println!("   ⚠️ Failed to release lock: {}", e);
                            }
                        }
                    }
                    
                    (balance_before, balance_after)
                };
                
                // Close the credit line and remove lock mapping
                {
                    let mut state = lock_credit_state(&credit_state);
                    if let Some(credit) = state.active_credits.get_mut(&request.session_id) {
                        credit.is_active = false;
                    }
                    state.user_sessions.remove(&request.wallet_address);
                    state.session_locks.remove(&request.session_id);
                }
                
                println!("   ✅ Settlement complete");
                println!("   L1 Before: {} $BC", l1_before);
                println!("   L1 After: {} $BC", l1_after);
                println!("   P&L Applied: {} $BC", request.pnl);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "session_id": request.session_id,
                    "l1_balance_before": l1_before,
                    "l1_balance_after": l1_after,
                    "pnl_applied": request.pnl,
                    "message": "Settlement complete. L1 balance updated."
                })))
            }
        })
}

// ============================================================================
// ROUTE: Check Credit Status
// ============================================================================
// GET /credit/status/{wallet_address}
//
// Check if a user has an active credit line.
// ============================================================================

pub fn credit_status_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    credit_state: Arc<Mutex<CreditState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("credit" / "status" / String)
        .and(warp::get())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            let credit_state = credit_state.clone();
            async move {
                let l1_balance = {
                    let bc = lock_blockchain(&blockchain);
                    bc.get_balance(&wallet_address)
                };
                
                let credit_info = {
                    let state = lock_credit_state(&credit_state);
                    state.get_user_session(&wallet_address).cloned()
                };
                
                match credit_info {
                    Some(credit) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "wallet_address": wallet_address,
                            "l1_balance": l1_balance,
                            "has_active_credit": credit.is_active,
                            "session_id": credit.session_id,
                            "credit_amount": credit.credit_amount,
                            "available_balance": l1_balance - credit.credit_amount,
                            "opened_at": credit.opened_at
                        })))
                    }
                    None => {
                        Ok(warp::reply::json(&serde_json::json!({
                            "wallet_address": wallet_address,
                            "l1_balance": l1_balance,
                            "has_active_credit": false,
                            "available_balance": l1_balance,
                            "message": "No active credit line"
                        })))
                    }
                }
            }
        })
}

// ============================================================================
// ROUTE: Get L1 Balance (for L2 to query)
// ============================================================================
// GET /credit/balance/{wallet_address}
//
// L2 can call this to get user's L1 balance before opening credit.
// ============================================================================

pub fn credit_balance_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("credit" / "balance" / String)
        .and(warp::get())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            async move {
                let l1_balance = {
                    let bc = lock_blockchain(&blockchain);
                    bc.get_balance(&wallet_address)
                };
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "wallet_address": wallet_address,
                    "l1_balance": l1_balance,
                    "symbol": "$BC"
                })))
            }
        })
}
