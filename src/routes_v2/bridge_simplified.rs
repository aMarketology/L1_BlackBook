// ============================================================================
// BRIDGE ROUTES - Simplified L1 ↔ L2 Communication
// ============================================================================
// Core functionality:
// - Bridge tokens L1 → L2 (lock on L1)
// - Credit line management (Casino Bank Model)
// - Signature verification
// - Balance queries
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::storage::PersistentBlockchain;
use crate::protocol::blockchain::LockPurpose;
use crate::integration::unified_auth::SignedRequest;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn lock_or_recover<'a>(mutex: &'a Mutex<PersistentBlockchain>) -> MutexGuard<'a, PersistentBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

fn lock_bridge_state<'a>(mutex: &'a Mutex<BridgeState>) -> MutexGuard<'a, BridgeState> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInitiatePayload {
    pub amount: f64,
    pub target_layer: String, // "L2"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditApprovalRequest {
    pub wallet_address: String,
    pub public_key: String,
    pub credit_limit: f64,
    pub expires_in_hours: u64,
    pub signature: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditApproval {
    pub approval_id: String,
    pub wallet_address: String,
    pub credit_limit: f64,
    pub total_drawn: f64,
    pub is_active: bool,
    pub expires_at: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Session {
    pub session_id: String,
    pub wallet_address: String,
    pub l2_balance: f64,
    pub total_drawn: f64,
    pub is_active: bool,
    pub started_at: u64,
}

#[derive(Debug, Default)]
pub struct BridgeState {
    pub credit_approvals: HashMap<String, CreditApproval>,
    pub sessions: HashMap<String, L2Session>,
}

impl BridgeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_credit_approval(&self, wallet: &str) -> Option<&CreditApproval> {
        self.credit_approvals.get(wallet)
    }

    pub fn add_credit_approval(&mut self, approval: CreditApproval) {
        self.credit_approvals.insert(approval.wallet_address.clone(), approval);
    }

    pub fn get_session(&self, wallet: &str) -> Option<&L2Session> {
        self.sessions.values().find(|s| s.wallet_address == wallet && s.is_active)
    }

    pub fn add_session(&mut self, session: L2Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }
}

// ============================================================================
// ROUTE: Bridge Initiate (L1 → L2)
// ============================================================================

pub fn bridge_initiate_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("initiate"))
        .and(warp::post())
        .and(warp::body::json::<SignedRequest>())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            let _bridge_state = bridge_state.clone();
            async move {
                // Verify signature
                let wallet_address = match request.verify() {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature verification failed: {}", e)
                        })));
                    }
                };

                // Parse payload
                let payload: BridgeInitiatePayload = match request.parse_payload() {
                    Ok(p) => p,
                    Err(_) => {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid bridge payload"
                        })));
                    }
                };

                // Validate
                if payload.amount <= 0.0 {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }

                // Lock tokens on L1
                let lock_id = {
                    let mut bc = lock_or_recover(&blockchain);
                    match bc.lock_tokens(
                        &wallet_address,
                        payload.amount,
                        LockPurpose::BridgeToL2,
                        None,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Lock failed: {}", e)
                            })));
                        }
                    }
                };

                println!("🌉 Bridge initiated: {} locked {} BB on L1", 
                         &wallet_address[..8], payload.amount);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "lock_id": lock_id,
                    "amount": payload.amount,
                    "target_layer": payload.target_layer,
                    "message": "Tokens locked on L1. Transfer to L2 in progress."
                })))
            }
        })
}

// ============================================================================
// ROUTE: Bridge Status
// ============================================================================

pub fn bridge_status_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("status"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |wallet_address: String| {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                let session = state.get_session(&wallet_address);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "has_active_session": session.is_some(),
                    "session": session
                })))
            }
        })
}

// ============================================================================
// ROUTE: Credit Approve
// ============================================================================

pub fn credit_approve_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("approve"))
        .and(warp::post())
        .and(warp::body::json::<CreditApprovalRequest>())
        .and_then(move |request: CreditApprovalRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🏦 Credit approval: {} for {} BB", 
                         request.wallet_address, request.credit_limit);

                // Verify signature
                let message = format!(
                    "APPROVE_CREDIT:{}:{}:{}",
                    request.wallet_address,
                    request.credit_limit,
                    request.nonce
                );

                match verify_ed25519_signature(&request.public_key, &message, &request.signature) {
                    Ok(true) => {},
                    Ok(false) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid signature"
                        })));
                    },
                    Err(e) => {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature error: {}", e)
                        })));
                    }
                }

                // Check L1 balance
                let l1_balance = {
                    let bc = lock_or_recover(&blockchain);
                    bc.get_balance(&request.wallet_address)
                };

                if request.credit_limit > l1_balance {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Credit limit exceeds L1 balance"
                    })));
                }

                // Check for existing approval
                {
                    let state = lock_bridge_state(&bridge_state);
                    if let Some(existing) = state.get_credit_approval(&request.wallet_address) {
                        if existing.is_active {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Active credit approval already exists",
                                "existing_session_id": existing.approval_id,
                                "existing_credit_limit": existing.credit_limit
                            })));
                        }
                    }
                }

                // Create approval
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let approval_id = format!("credit_{}_{}", now, &request.wallet_address[..10]);
                
                let approval = CreditApproval {
                    approval_id: approval_id.clone(),
                    wallet_address: request.wallet_address.clone(),
                    credit_limit: request.credit_limit,
                    total_drawn: 0.0,
                    is_active: true,
                    expires_at: now + (request.expires_in_hours * 3600),
                    created_at: now,
                };

                // Create session
                let session = L2Session {
                    session_id: approval_id.clone(),
                    wallet_address: request.wallet_address.clone(),
                    l2_balance: 0.0,
                    total_drawn: 0.0,
                    is_active: true,
                    started_at: now,
                };

                // Save
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.add_credit_approval(approval.clone());
                    state.add_session(session.clone());
                }

                println!("✅ Credit approved: {} - {} BB", &approval_id[..16], request.credit_limit);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "approval": approval,
                    "session": serde_json::json!({
                        "session_id": session.session_id,
                        "credit_limit": request.credit_limit,
                    })
                })))
            }
        })
}

// ============================================================================
// ROUTE: Credit Status
// ============================================================================

pub fn credit_status_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("status"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                let l1_balance = {
                    let bc = lock_or_recover(&blockchain);
                    bc.get_balance(&wallet_address)
                };

                let (approval, session) = {
                    let state = lock_bridge_state(&bridge_state);
                    (
                        state.get_credit_approval(&wallet_address).cloned(),
                        state.get_session(&wallet_address).cloned()
                    )
                };

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "wallet_address": wallet_address,
                    "l1_balance": l1_balance,
                    "has_active_approval": approval.is_some(),
                    "approval": approval,
                    "session": session
                })))
            }
        })
}

// ============================================================================
// ROUTE: Bridge Stats
// ============================================================================

pub fn bridge_stats_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("stats"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "total_approvals": state.credit_approvals.len(),
                    "active_sessions": state.sessions.values().filter(|s| s.is_active).count(),
                    "total_sessions": state.sessions.len()
                })))
            }
        })
}

// ============================================================================
// ROUTE: Bridge Pending (Placeholder)
// ============================================================================

pub fn bridge_pending_route(
    _bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("pending"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |_wallet_address: String| {
            async move {
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "pending": []
                })))
            }
        })
}

// ============================================================================
// SIGNATURE VERIFICATION HELPERS
// ============================================================================

fn verify_ed25519_signature(public_key: &str, message: &str, signature: &str) -> Result<bool, String> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    let pubkey_bytes = hex::decode(public_key)
        .map_err(|_| "Invalid public key hex")?;
    
    if pubkey_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }
    
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| "Invalid public key length")?;
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|_| "Invalid public key")?;
    
    let sig_bytes = hex::decode(signature)
        .map_err(|_| "Invalid signature hex")?;
    
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".to_string());
    }
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "Invalid signature length")?;
    
    let sig = Signature::from_bytes(&sig_array);
    
    match verifying_key.verify(message.as_bytes(), &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// PLACEHOLDER ROUTES (Not yet implemented)
// ============================================================================

pub fn credit_draw_route(
    _blockchain: Arc<Mutex<PersistentBlockchain>>,
    _bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("draw"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |_req: serde_json::Value| {
            async move {
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": false,
                    "error": "Credit draw not yet implemented"
                })))
            }
        })
}

pub fn credit_settle_route(
    _blockchain: Arc<Mutex<PersistentBlockchain>>,
    _bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("settle"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |_req: serde_json::Value| {
            async move {
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": false,
                    "error": "Credit settle not yet implemented"
                })))
            }
        })
}
