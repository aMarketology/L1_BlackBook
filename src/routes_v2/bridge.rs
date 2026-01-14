// ============================================================================
// BRIDGE ROUTES - Simplified L1 ↔ L2 Communication
// ============================================================================
// Token Naming:
// - $BC (BlackCoin) = L1 native token
// - $BB (BlackBook) = L2 gaming token (1:1 backed by locked $BC)
//
// Core functionality:
// - Bridge tokens L1 → L2 (lock $BC on L1, mint $BB on L2)
// - Credit line management (Casino Bank Model)
// - L2 State Root anchoring (Optimistic Rollup)
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
use crate::unified_wallet::strip_prefix;
use ed25519_dalek::{SigningKey, Signer};

// ============================================================================
// L1 NODE SIGNING - Signs messages to prove L1 authority to L2
// ============================================================================

/// Get the L1 node's signing key from environment (DEALER_PRIVATE_KEY)
fn get_l1_signing_key() -> Option<SigningKey> {
    let key_hex = std::env::var("DEALER_PRIVATE_KEY").ok()?;
    let key_bytes = hex::decode(&key_hex).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }
    let key_array: [u8; 32] = key_bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&key_array))
}

/// Get L1 node's public key (hex string)
#[allow(dead_code)]
fn get_l1_public_key() -> Option<String> {
    let signing_key = get_l1_signing_key()?;
    Some(hex::encode(signing_key.verifying_key().as_bytes()))
}

/// Sign a message with L1 node's key for L2 verification
/// Format expected by L2: BRIDGE_LOCK:{user_address}:{amount}:{lock_id}
fn sign_bridge_lock_message(user_address: &str, amount: f64, lock_id: &str) -> Option<(String, String)> {
    let signing_key = get_l1_signing_key()?;
    let message = format!("BRIDGE_LOCK:{}:{}:{}", user_address, amount, lock_id);
    let signature = signing_key.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
    println!("🔐 L1 signing bridge lock: {}", message);
    Some((signature_hex, public_key_hex))
}

// ============================================================================
// REQUEST STRUCTURES FOR CREDIT OPERATIONS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditDrawRequest {
    pub wallet_address: String,
    pub public_key: String,
    pub amount: f64,
    pub reason: String,
    pub signature: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditSettleRequest {
    pub wallet_address: String,
    pub public_key: String,
    pub session_id: String,
    pub final_l2_balance: f64,
    pub locked_in_bets: f64,
    pub signature: String,
    pub nonce: u64,
}

// ============================================================================
// L2 STATE ROOT STRUCTURES (Optimistic Rollup)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2StateRootSubmission {
    pub state_root: String,        // 64 hex chars (256-bit hash)
    pub block_height: u64,         // L2 block number
    pub timestamp: u64,            // Unix timestamp
    pub tx_count: u64,             // Number of transactions in this batch
    pub prev_state_root: String,   // Previous state root for chain validation
    pub signature: Option<String>, // Optional L2 sequencer signature
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchoredStateRoot {
    pub state_root: String,
    pub l2_block_height: u64,
    pub l1_block_height: u64,      // L1 block when this was anchored
    pub anchored_at: u64,          // Unix timestamp when anchored on L1
    pub tx_count: u64,
    pub status: StateRootStatus,
    pub challenge_period_ends: u64, // When this root becomes finalized
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StateRootStatus {
    Pending,      // Within challenge period
    Finalized,    // Challenge period passed, root is final
    Challenged,   // Someone disputed this root
    Invalid,      // Root was proven invalid
}

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
    pub available_credit: f64,  // credit_limit - total_drawn
    pub lock_id: Option<String>, // L1 lock ID for the escrowed funds
    pub is_active: bool,
    pub expires_at: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Session {
    pub session_id: String,
    pub wallet_address: String,
    pub l2_balance: f64,       // Current credited balance on L2
    pub total_drawn: f64,       // Total drawn from credit line
    pub total_winnings: f64,    // Net winnings from betting
    pub is_active: bool,
    pub started_at: u64,
}

// Challenge period for optimistic rollup (in seconds)
// 7 days = 604800 seconds (PRODUCTION)
const CHALLENGE_PERIOD_SECONDS: u64 = 604800;

#[derive(Debug, Default)]
pub struct BridgeState {
    pub credit_approvals: HashMap<String, CreditApproval>,
    pub sessions: HashMap<String, L2Session>,
    pub anchored_state_roots: Vec<AnchoredStateRoot>,
    pub latest_l2_block: u64,
    pub latest_state_root: Option<String>,
}

impl BridgeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_credit_approval(&self, wallet: &str) -> Option<&CreditApproval> {
        self.credit_approvals.get(wallet)
    }

    pub fn get_credit_approval_mut(&mut self, wallet: &str) -> Option<&mut CreditApproval> {
        self.credit_approvals.get_mut(wallet)
    }

    pub fn add_credit_approval(&mut self, approval: CreditApproval) {
        self.credit_approvals.insert(approval.wallet_address.clone(), approval);
    }

    pub fn get_session(&self, wallet: &str) -> Option<&L2Session> {
        self.sessions.values().find(|s| s.wallet_address == wallet && s.is_active)
    }

    pub fn get_session_mut(&mut self, wallet: &str) -> Option<&mut L2Session> {
        self.sessions.values_mut().find(|s| s.wallet_address == wallet && s.is_active)
    }

    pub fn get_session_by_id_mut(&mut self, session_id: &str) -> Option<&mut L2Session> {
        self.sessions.get_mut(session_id)
    }

    pub fn add_session(&mut self, session: L2Session) {
        self.sessions.insert(session.session_id.clone(), session);
    }

    pub fn anchor_state_root(&mut self, submission: L2StateRootSubmission, l1_block: u64) -> AnchoredStateRoot {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let anchored = AnchoredStateRoot {
            state_root: submission.state_root.clone(),
            l2_block_height: submission.block_height,
            l1_block_height: l1_block,
            anchored_at: now,
            tx_count: submission.tx_count,
            status: StateRootStatus::Pending,
            challenge_period_ends: now + CHALLENGE_PERIOD_SECONDS,
        };

        self.latest_l2_block = submission.block_height;
        self.latest_state_root = Some(submission.state_root);
        self.anchored_state_roots.push(anchored.clone());
        
        anchored
    }

    pub fn get_latest_finalized_root(&self) -> Option<&AnchoredStateRoot> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.anchored_state_roots
            .iter()
            .rev()
            .find(|r| r.status == StateRootStatus::Finalized || 
                      (r.status == StateRootStatus::Pending && r.challenge_period_ends <= now))
    }

    pub fn finalize_expired_roots(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for root in &mut self.anchored_state_roots {
            if root.status == StateRootStatus::Pending && root.challenge_period_ends <= now {
                root.status = StateRootStatus::Finalized;
            }
        }
    }
}

// L2 Base URL for bridge operations
const L2_BASE_URL: &str = "http://localhost:1234";

// ============================================================================
// ROUTE: Bridge Initiate (L1 → L2) - LOW LATENCY
// ============================================================================
// Flow:
// 1. Verify signature (fast, in-memory)
// 2. Lock tokens on L1 (fast, Sled write)
// 3. Fire async HTTP to L2 (non-blocking)
// 4. Return immediately with lock_id
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
                let start_time = std::time::Instant::now();
                
                // === BRIDGE LOCK REQUEST RECEIVED ===
                println!("\n============================================================");
                println!("🌉 BRIDGE LOCK REQUEST RECEIVED");
                println!("============================================================");
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                println!("   ⏰ Timestamp: {}", now);
                println!("   📦 Payload: {}", request.payload.as_deref().unwrap_or("<none>"));
                println!("   🔑 Public Key: {}...", &request.public_key[..16.min(request.public_key.len())]);
                
                // Verify signature (fast)
                let wallet_address = match request.verify() {
                    Ok(addr) => addr,
                    Err(e) => {
                        println!("   ❌ Signature verification FAILED: {}", e);
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature verification failed: {}", e)
                        })));
                    }
                };
                
                println!("   ✅ Signature verified for: {}", wallet_address);

                // Parse payload (fast)
                let payload: BridgeInitiatePayload = match request.parse_payload() {
                    Ok(p) => p,
                    Err(_) => {
                        println!("   ❌ Invalid bridge payload");
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid bridge payload"
                        })));
                    }
                };
                
                println!("   💰 Amount: {} $BC → $BB", payload.amount);
                println!("   🎯 Target: {}", payload.target_layer);

                // Validate
                if payload.amount <= 0.0 {
                    println!("   ❌ Invalid amount: must be positive");
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }

                // Lock tokens on L1 (fast Sled write)
                let lock_id = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Check balance first
                    let current_balance = bc.balances.get(&wallet_address).copied().unwrap_or(0.0);
                    println!("   📊 Current L1 balance: {} $BC", current_balance);
                    
                    // Use full wallet_address with L1_ prefix (balances stored with prefix)
                    match bc.lock_tokens(
                        &wallet_address,
                        payload.amount,
                        LockPurpose::BridgeToL2,
                        None,
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            println!("   ❌ Lock FAILED: {}", e);
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Lock failed: {}", e)
                            })));
                        }
                    }
                };

                let l1_lock_time = start_time.elapsed();
                println!("   ✅ Lock ID: {}", lock_id);
                println!("   ⏱️  Lock time: {:?}", l1_lock_time);

                // ============================================================
                // ASYNC L2 CREDIT - Fire and await (fast HTTP)
                // ============================================================
                let l2_url = format!("{}/bridge/credit", L2_BASE_URL);
                let l2_wallet = wallet_address.replace("L1_", "L2_");
                
                println!("   📤 Sending credit to L2: {}", l2_wallet);
                
                // Sign the bridge lock message for L2 verification
                let (l1_signature, l1_public_key) = match sign_bridge_lock_message(
                    &l2_wallet,
                    payload.amount,
                    &lock_id
                ) {
                    Some((sig, pk)) => {
                        println!("   🔐 L1 signature: {}...", &sig[..32.min(sig.len())]);
                        println!("   🔑 L1 pubkey: {}...", &pk[..32.min(pk.len())]);
                        (sig, pk)
                    },
                    None => {
                        println!("   ⚠️ L1 signing FAILED (DEALER_PRIVATE_KEY not set?)");
                        (String::new(), String::new())
                    }
                };

                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let l2_payload = serde_json::json!({
                    "user_address": l2_wallet,
                    "amount": payload.amount,
                    "lock_id": lock_id,
                    "l1_public_key": l1_public_key,
                    "l1_signature": l1_signature,
                    "l1_tx_hash": lock_id,
                    "timestamp": timestamp,
                    "source": "L1_bridge"
                });

                // Use reqwest with connection pooling for low latency
                let client = reqwest::Client::builder()
                    .pool_max_idle_per_host(10)
                    .timeout(std::time::Duration::from_millis(2000))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());

                let l2_result = client
                    .post(&l2_url)
                    .json(&l2_payload)
                    .send()
                    .await;

                let l2_response = match l2_result {
                    Ok(response) => {
                        let status = response.status();
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                let total_time = start_time.elapsed();
                                println!("🌉 Bridge L1→L2 complete in {:?} (L1: {:?})", total_time, l1_lock_time);
                                println!("   ✅ L2 credited {} $BB to {}", payload.amount, l2_wallet);
                                Some(json)
                            }
                            Err(e) => {
                                println!("   ⚠️ L2 response parse error: {}", e);
                                Some(serde_json::json!({
                                    "status": status.as_u16(),
                                    "error": format!("L2 response parse error: {}", e)
                                }))
                            }
                        }
                    }
                    Err(e) => {
                        // L2 not reachable - tokens are still locked on L1
                        // User can retry or L2 can sync from L1 locks
                        println!("   ⚠️ L2 not reachable: {} (tokens safe on L1)", e);
                        None
                    }
                };

                let l2_success = l2_response
                    .as_ref()
                    .and_then(|r| r.get("success"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let l2_balance = l2_response
                    .as_ref()
                    .and_then(|r| r.get("new_balance"))
                    .and_then(|v| v.as_f64());

                let total_time = start_time.elapsed();
                println!("🌉 Bridge initiated: {} locked {} $BC on L1 → $BB on L2 (total: {:?})", 
                         &wallet_address[..8], payload.amount, total_time);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "lock_id": lock_id,
                    "amount": payload.amount,
                    "target_layer": payload.target_layer,
                    "l2_credited": l2_success,
                    "l2_balance": l2_balance,
                    "latency_ms": total_time.as_millis(),
                    "message": if l2_success { 
                        "Tokens locked on L1 and credited on L2" 
                    } else { 
                        "Tokens locked on L1. L2 credit pending." 
                    }
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
                println!("🏦 Credit approval: {} for {} $BC", 
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

                // LOCK TOKENS ON L1 - This is the escrow for the credit line
                let lock_id = {
                    let mut bc = lock_or_recover(&blockchain);
                    let internal_address = strip_prefix(&request.wallet_address);
                    match bc.lock_tokens(
                        &internal_address,
                        request.credit_limit,
                        LockPurpose::MarketEscrow, // Credit line is market escrow
                        None, // Returns to same wallet
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Failed to lock tokens: {}", e)
                            })));
                        }
                    }
                };

                // Create approval with lock reference
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let approval_id = format!("credit_{}_{}", now, &request.wallet_address[..10]);
                
                let approval = CreditApproval {
                    approval_id: approval_id.clone(),
                    wallet_address: request.wallet_address.clone(),
                    credit_limit: request.credit_limit,
                    total_drawn: 0.0,
                    available_credit: request.credit_limit,
                    lock_id: Some(lock_id.clone()),
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
                    total_winnings: 0.0,
                    is_active: true,
                    started_at: now,
                };

                // Save
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.add_credit_approval(approval.clone());
                    state.add_session(session.clone());
                }

                println!("✅ Credit approved: {} - {} $BC locked (lock_id: {})", 
                         &approval_id[..16], request.credit_limit, &lock_id[..16]);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "approval": approval,
                    "lock_id": lock_id,
                    "session": serde_json::json!({
                        "session_id": session.session_id,
                        "credit_limit": request.credit_limit,
                        "tokens_locked": request.credit_limit,
                    }),
                    "message": format!("{} $BC locked on L1 as credit line collateral", request.credit_limit)
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
// ROUTE: Bridge Release - L2 calls this to release locked tokens
// ============================================================================
// POST /bridge/release
// Body: { lock_id, l2_signature, l2_public_key, settlement_data }
//
// L2 calls this after verifying settlement on L2 side.
// L1 verifies the L2 signature, then releases the locked tokens.
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeReleaseRequest {
    pub lock_id: String,
    pub l2_signature: String,        // L2 sequencer's signature
    pub l2_public_key: String,       // L2 sequencer's public key
    pub wallet_signature: String,    // Wallet owner's signature (REQUIRED)
    pub wallet_public_key: String,   // Wallet owner's public key
    pub settlement_data: SettlementData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementData {
    pub wallet_address: String,
    pub final_balance: f64,          // User's final balance on L2
    pub pnl: f64,                    // Profit/Loss from session
    pub session_id: String,
    pub l2_block_height: u64,
}

pub fn bridge_release_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("release"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: BridgeReleaseRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🔓 Bridge Release Request:");
                println!("   Lock ID: {}", &request.lock_id[..16.min(request.lock_id.len())]);
                println!("   Wallet: {}", request.settlement_data.wallet_address);
                println!("   Final Balance: {} BB", request.settlement_data.final_balance);
                println!("   P&L: {:+.2} BB", request.settlement_data.pnl);

                // 1. Verify WALLET signature (wallet owner must approve release)
                let wallet_message = format!(
                    "BRIDGE_RELEASE:{}:{}:{}",
                    request.lock_id,
                    request.settlement_data.session_id,
                    request.settlement_data.pnl
                );

                match verify_ed25519_signature(
                    &request.wallet_public_key,
                    &wallet_message,
                    &request.wallet_signature,
                ) {
                    Ok(true) => {
                        println!("   ✅ Wallet signature verified");
                        
                        // Verify wallet public key matches address
                        let derived_address = crate::unified_wallet::strip_prefix(&request.settlement_data.wallet_address);
                        if derived_address != request.wallet_public_key {
                            println!("   ❌ Wallet public key mismatch");
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Wallet public key does not match address"
                            })));
                        }
                    }
                    Ok(false) => {
                        println!("   ❌ Invalid wallet signature");
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid wallet signature - only wallet owner can authorize release"
                        })));
                    }
                    Err(e) => {
                        println!("   ❌ Wallet signature verification error: {}", e);
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Wallet signature verification failed: {}", e)
                        })));
                    }
                }

                // 2. Verify L2 signature (L2 sequencer confirms settlement)
                let message = format!(
                    "BRIDGE_RELEASE:{}:{}:{}:{}",
                    request.lock_id,
                    request.settlement_data.wallet_address,
                    request.settlement_data.final_balance,
                    request.settlement_data.session_id
                );

                match verify_ed25519_signature(
                    &request.l2_public_key,
                    &message,
                    &request.l2_signature,
                ) {
                    Ok(true) => {
                        println!("   ✅ L2 signature verified");
                    }
                    Ok(false) => {
                        println!("   ❌ Invalid L2 signature");
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid L2 signature"
                        })));
                    }
                    Err(e) => {
                        println!("   ❌ Signature verification error: {}", e);
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature verification failed: {}", e)
                        })));
                    }
                }

                // 3. Get lock record and validate
                let lock_record = {
                    let bc = lock_or_recover(&blockchain);
                    match bc.get_lock_record(&request.lock_id) {
                        Some(lock) => lock.clone(),
                        None => {
                            println!("   ❌ Lock not found: {}", request.lock_id);
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Lock not found: {}", request.lock_id)
                            })));
                        }
                    }
                };

                // 4. Check if already released
                if lock_record.released_at.is_some() {
                    println!("   ⚠️  Tokens already released");
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Tokens already released"
                    })));
                }

                // 5. Authorize and release tokens
                let proof = crate::protocol::blockchain::SettlementProof {
                    market_id: request.settlement_data.session_id.clone(),
                    outcome: format!("Settlement: P&L = {:+.2}", request.settlement_data.pnl),
                    l2_block_height: request.settlement_data.l2_block_height,
                    l2_signature: request.l2_signature.clone(),
                    verified_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let (recipient, amount) = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Authorize release
                    if let Err(e) = bc.authorize_release(&request.lock_id, proof) {
                        println!("   ❌ Authorization failed: {}", e);
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Authorization failed: {}", e)
                        })));
                    }

                    // Release tokens
                    match bc.release_tokens(&request.lock_id) {
                        Ok((recipient, amount)) => {
                            println!("   ✅ Released {} BB to {}", amount, recipient);
                            
                            // Flush to disk
                            if let Err(e) = bc.flush() {
                                println!("   ⚠️  Flush error: {}", e);
                            }
                            
                            (recipient, amount)
                        }
                        Err(e) => {
                            println!("   ❌ Release failed: {}", e);
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Release failed: {}", e)
                            })));
                        }
                    }
                };

                // 6. Update bridge state to mark session as settled
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    if let Some(session) = state.get_session_by_id_mut(&request.settlement_data.session_id) {
                        session.is_active = false;
                        session.l2_balance = request.settlement_data.final_balance;
                        session.total_winnings = request.settlement_data.pnl;
                    }
                    if let Some(approval) = state.get_credit_approval_mut(&request.settlement_data.wallet_address) {
                        approval.is_active = false;
                    }
                }

                // 7. Return success
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "released": {
                        "lock_id": request.lock_id,
                        "recipient": recipient,
                        "amount": amount,
                        "pnl": request.settlement_data.pnl,
                        "session_id": request.settlement_data.session_id,
                    },
                    "message": format!("Released {} BB to {} - Verified by both wallet and L2", amount, recipient)
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
// ROUTE: Credit Draw - L2 draws from approved credit line
// ============================================================================
// This is called by L2 when a user needs funds for betting.
// The user's SDK signs the request, L2 forwards it, L1 validates.
// ============================================================================

pub fn credit_draw_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("draw"))
        .and(warp::post())
        .and(warp::body::json::<CreditDrawRequest>())
        .and_then(move |request: CreditDrawRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("💳 Credit draw request: {} for {} $BB", 
                         &request.wallet_address[..16], request.amount);

                // Verify signature
                let message = format!(
                    "CREDIT_DRAW:{}:{}:{}:{}",
                    request.wallet_address,
                    request.amount,
                    request.reason,
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

                // Validate amount
                if request.amount <= 0.0 {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Draw amount must be positive"
                    })));
                }

                // Check approval exists and has available credit
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                
                let (approval_id, new_total_drawn, new_available, new_l2_balance) = {
                    let mut state = lock_bridge_state(&bridge_state);
                    
                    // Get approval
                    let approval = match state.get_credit_approval_mut(&request.wallet_address) {
                        Some(a) => a,
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "No credit approval found. Call /credit/approve first."
                            })));
                        }
                    };

                    // Check active and not expired
                    if !approval.is_active {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Credit approval is not active"
                        })));
                    }

                    if now > approval.expires_at {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Credit approval has expired"
                        })));
                    }

                    // Check sufficient credit
                    if request.amount > approval.available_credit {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Insufficient credit available",
                            "requested": request.amount,
                            "available": approval.available_credit
                        })));
                    }

                    // Update approval
                    approval.total_drawn += request.amount;
                    approval.available_credit -= request.amount;
                    let approval_id = approval.approval_id.clone();
                    let new_total = approval.total_drawn;
                    let new_avail = approval.available_credit;

                    // Update session
                    let session = match state.get_session_mut(&request.wallet_address) {
                        Some(s) => s,
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "No active session found"
                            })));
                        }
                    };

                    session.l2_balance += request.amount;
                    session.total_drawn += request.amount;
                    let new_l2 = session.l2_balance;

                    (approval_id, new_total, new_avail, new_l2)
                };

                // Log the draw
                println!("✅ Credit draw completed: {} drew {} $BB (total: {}, available: {})", 
                         &request.wallet_address[..16], request.amount, new_total_drawn, new_available);

                // ============================================================
                // NOTIFY L2 - Send signed credit to L2 for balance update
                // ============================================================
                let l2_wallet = request.wallet_address.replace("L1_", "L2_");
                let lock_id = format!("draw_{}_{}", approval_id, now);
                
                // Sign the bridge lock message for L2 verification
                let (l1_signature, l1_public_key) = match sign_bridge_lock_message(
                    &l2_wallet,
                    request.amount,
                    &lock_id
                ) {
                    Some((sig, pk)) => (sig, pk),
                    None => {
                        println!("⚠️ L1 signing failed for credit draw");
                        (String::new(), String::new())
                    }
                };

                let l2_url = format!("{}/bridge/credit", L2_BASE_URL);
                let l2_payload = serde_json::json!({
                    "user_address": l2_wallet,
                    "amount": request.amount,
                    "lock_id": lock_id,
                    "l1_public_key": l1_public_key,
                    "l1_signature": l1_signature,
                    "l1_tx_hash": approval_id,
                    "timestamp": now,
                    "source": "L1_credit_draw"
                });

                // Async notify L2
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_millis(2000))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());

                let l2_result = client.post(&l2_url).json(&l2_payload).send().await;
                
                let l2_notified = match l2_result {
                    Ok(resp) => {
                        let status = resp.status();
                        println!("📡 L2 notified: {} - {:?}", status, resp.text().await.ok());
                        status.is_success()
                    },
                    Err(e) => {
                        println!("⚠️ L2 notification failed: {}", e);
                        false
                    }
                };

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "draw": {
                        "amount": request.amount,
                        "reason": request.reason,
                        "approval_id": approval_id
                    },
                    "credit_status": {
                        "total_drawn": new_total_drawn,
                        "available_credit": new_available
                    },
                    "l2_balance": new_l2_balance,
                    "l2_notified": l2_notified,
                    "message": format!("{} $BB credited to L2 balance", request.amount)
                })))
            }
        })
}

// ============================================================================
// ROUTE: Credit Settle - Close session and return unused funds
// ============================================================================
// Called when user ends their betting session.
// Returns unused credit to L1, keeps winnings in L2 balance.
// ============================================================================

pub fn credit_settle_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("credit")
        .and(warp::path("settle"))
        .and(warp::post())
        .and(warp::body::json::<CreditSettleRequest>())
        .and_then(move |request: CreditSettleRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🔄 Credit settle request: {} session {} (final L2: {} $BB)", 
                         &request.wallet_address[..16], &request.session_id[..16], request.final_l2_balance);

                // Verify signature
                let message = format!(
                    "CREDIT_SETTLE:{}:{}:{}:{}:{}",
                    request.wallet_address,
                    request.session_id,
                    request.final_l2_balance,
                    request.locked_in_bets,
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

                // Get session and approval info
                let (lock_id, credit_limit, total_drawn, l2_balance_before) = {
                    let state = lock_bridge_state(&bridge_state);
                    
                    let approval = match state.get_credit_approval(&request.wallet_address) {
                        Some(a) => a,
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "No credit approval found"
                            })));
                        }
                    };

                    let session = match state.sessions.get(&request.session_id) {
                        Some(s) => s,
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Session not found"
                            })));
                        }
                    };

                    if !session.is_active {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Session already settled"
                        })));
                    }

                    (
                        approval.lock_id.clone(),
                        approval.credit_limit,
                        approval.total_drawn,
                        session.l2_balance,
                    )
                };

                // Calculate settlement
                // Winnings = final_l2_balance - total_drawn (positive = profit, negative = loss)
                let net_pnl = request.final_l2_balance - total_drawn;
                let unused_credit = credit_limit - total_drawn;
                
                // Amount to return to user = unused_credit + any profit (capped at locked amount)
                // If loss: locked funds cover the loss
                let amount_to_return = if net_pnl >= 0.0 {
                    // Won or broke even: return unused credit + winnings
                    unused_credit + net_pnl
                } else {
                    // Lost: return unused credit (loss comes from drawn funds)
                    unused_credit
                };

                // Release the lock on L1
                if let Some(lid) = &lock_id {
                    let mut bc = lock_or_recover(&blockchain);
                    let internal_address = strip_prefix(&request.wallet_address);
                    
                    // Authorize and release the lock
                    match bc.release_tokens(lid) {
                        Ok((owner, released_amount)) => {
                            println!("🔓 Released {} $BC from lock {} (owner: {})", 
                                     released_amount, &lid[..16], &owner[..16]);
                            
                            // Credit the settlement amount back to user's L1 balance
                            // The full locked amount was released, now we add back what user should get
                            if amount_to_return > 0.0 {
                                // Add winnings/unused to balance
                                // Note: release_tokens already added the locked amount back
                                // We need to adjust if there was a loss
                                if net_pnl < 0.0 {
                                    // User lost some - deduct the loss from their balance
                                    let _ = bc.create_transaction(
                                        internal_address.clone(),
                                        "L1_DEALER_HOUSE".to_string(), // House keeps losses
                                        net_pnl.abs()
                                    );
                                } else if net_pnl > 0.0 {
                                    // User won - they get paid from house
                                    let _ = bc.create_transaction(
                                        "L1_DEALER_HOUSE".to_string(),
                                        internal_address.clone(),
                                        net_pnl
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": format!("Failed to release lock: {}", e)
                            })));
                        }
                    }
                }

                // Mark session and approval as inactive
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    
                    if let Some(session) = state.get_session_by_id_mut(&request.session_id) {
                        session.is_active = false;
                        session.l2_balance = 0.0;
                        session.total_winnings = net_pnl;
                    }

                    if let Some(approval) = state.get_credit_approval_mut(&request.wallet_address) {
                        approval.is_active = false;
                    }
                }

                println!("✅ Session settled: {} | P&L: {} $BB | Returned: {} $BC", 
                         &request.session_id[..16], net_pnl, amount_to_return);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "settlement": {
                        "session_id": request.session_id,
                        "credit_limit": credit_limit,
                        "total_drawn": total_drawn,
                        "final_l2_balance": request.final_l2_balance,
                        "net_pnl": net_pnl,
                        "amount_returned_to_l1": amount_to_return
                    },
                    "message": if net_pnl >= 0.0 {
                        format!("Session closed. Won {} $BB! {} $BC returned to L1.", net_pnl, amount_to_return)
                    } else {
                        format!("Session closed. Lost {} $BB. {} $BC returned to L1.", net_pnl.abs(), amount_to_return)
                    }
                })))
            }
        })
}
// ============================================================================
// ROUTE: L2 State Root Submission (Optimistic Rollup)
// ============================================================================
// L2 posts state roots to L1 for anchoring. After challenge period (7 days prod,
// 60s test), the root becomes finalized and L2 withdrawals can be processed.
// ============================================================================

pub fn l2_state_root_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("l2")
        .and(warp::path("state_root"))
        .and(warp::post())
        .and(warp::body::json::<L2StateRootSubmission>())
        .and_then(move |submission: L2StateRootSubmission| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                let start_time = std::time::Instant::now();

                // Validate state root format (64 hex chars = 256 bits)
                if submission.state_root.len() != 64 || 
                   !submission.state_root.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid state root format. Expected 64 hex characters."
                    })));
                }

                // Get current L1 block height (use current_slot as L1 block equivalent)
                let l1_block = {
                    let bc = lock_or_recover(&blockchain);
                    bc.current_slot
                };

                // Validate block height is sequential
                {
                    let state = lock_bridge_state(&bridge_state);
                    if submission.block_height <= state.latest_l2_block && state.latest_l2_block > 0 {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!(
                                "Block height {} is not greater than latest anchored block {}",
                                submission.block_height,
                                state.latest_l2_block
                            )
                        })));
                    }

                    // Validate prev_state_root matches (if not genesis)
                    if let Some(ref latest) = state.latest_state_root {
                        if submission.prev_state_root != *latest {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Previous state root mismatch. L2 chain may have forked.",
                                "expected": latest,
                                "received": submission.prev_state_root
                            })));
                        }
                    }
                }

                // Anchor the state root
                let anchored = {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.anchor_state_root(submission.clone(), l1_block)
                };

                let latency = start_time.elapsed();
                
                println!("📦 L2 State Root anchored in {:?}", latency);
                println!("   └─ L2 Block: {} | State: {}...{}", 
                         anchored.l2_block_height,
                         &anchored.state_root[..8],
                         &anchored.state_root[56..]);
                println!("   └─ L1 Block: {} | Finalized at: {}", 
                         anchored.l1_block_height,
                         anchored.challenge_period_ends);

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "anchored": {
                        "state_root": anchored.state_root,
                        "l2_block_height": anchored.l2_block_height,
                        "l1_block_height": anchored.l1_block_height,
                        "anchored_at": anchored.anchored_at,
                        "tx_count": anchored.tx_count,
                        "status": "pending",
                        "challenge_period_ends": anchored.challenge_period_ends,
                        "challenge_period_seconds": CHALLENGE_PERIOD_SECONDS
                    },
                    "latency_ms": latency.as_millis(),
                    "message": format!(
                        "State root anchored. Will finalize after {} seconds (challenge period).",
                        CHALLENGE_PERIOD_SECONDS
                    )
                })))
            }
        })
}

// ============================================================================
// ROUTE: Get Latest State Root
// ============================================================================

pub fn l2_latest_state_root_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("l2")
        .and(warp::path("state_root"))
        .and(warp::path("latest"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let mut state = lock_bridge_state(&bridge_state);
                
                // Finalize any roots past their challenge period
                state.finalize_expired_roots();

                let latest = state.get_latest_finalized_root().cloned();
                let pending_count = state.anchored_state_roots
                    .iter()
                    .filter(|r| r.status == StateRootStatus::Pending)
                    .count();

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "latest_finalized": latest,
                    "latest_l2_block": state.latest_l2_block,
                    "latest_state_root": state.latest_state_root,
                    "pending_roots": pending_count,
                    "total_anchored": state.anchored_state_roots.len()
                })))
            }
        })
}

// ============================================================================
// ROUTE: Get All State Roots (for debugging/monitoring)
// ============================================================================

pub fn l2_all_state_roots_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("l2")
        .and(warp::path("state_roots"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let mut state = lock_bridge_state(&bridge_state);
                state.finalize_expired_roots();

                let roots: Vec<_> = state.anchored_state_roots
                    .iter()
                    .map(|r| serde_json::json!({
                        "state_root": r.state_root,
                        "l2_block_height": r.l2_block_height,
                        "l1_block_height": r.l1_block_height,
                        "anchored_at": r.anchored_at,
                        "tx_count": r.tx_count,
                        "status": format!("{:?}", r.status),
                        "challenge_period_ends": r.challenge_period_ends
                    }))
                    .collect();

                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "state_roots": roots,
                    "count": roots.len()
                })))
            }
        })
}
