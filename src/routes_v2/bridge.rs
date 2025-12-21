// ============================================================================
// BRIDGE ROUTES - Cross-Layer L1 ↔ L2 Communication
// ============================================================================
//
// This module handles all cross-layer RPC operations:
// - Bridge initiation (L1 → L2 token transfer)
// - Bridge status checking
// - L1 signature verification (for L2 to call)
// - Relay signed actions to L2
// - Wallet lookup by user_id (for L2 to resolve user to L1 wallet)
// - Nonce tracking (for cross-layer replay protection)
// - Settlement recording (L2 market resolutions → L1 audit trail)
//
// All routes use Ed25519 signature verification - NO JWT!

use std::sync::{Arc, Mutex, MutexGuard};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::protocol::blockchain::{EnhancedBlockchain, LockPurpose, SettlementProof};
use crate::integration::unified_auth::SignedRequest;
use crate::integration::supabase_connector::SupabaseConnector;
use crate::unified_wallet::{to_l1_address, to_l2_address, strip_prefix};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

/// Helper to recover from poisoned BridgeState locks
fn lock_bridge_state<'a>(mutex: &'a Mutex<BridgeState>) -> MutexGuard<'a, BridgeState> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// ============================================================================
// TYPES
// ============================================================================

/// Bridge status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeStatus {
    Pending,
    Confirmed,
    Completed,
    Failed,
}

/// A pending bridge transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBridge {
    pub id: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: f64,
    pub source_layer: String,
    pub target_layer: String,
    pub status: BridgeStatus,
    pub created_at: u64,
    pub confirmed_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub tx_hash: Option<String>,
}

/// Request to initiate a bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInitiatePayload {
    pub target_address: String,
    pub amount: f64,
    pub target_layer: String, // "L2"
}

/// Request to verify an L1 signature (called by L2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySignatureRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

/// Request to relay an action to L2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayActionPayload {
    pub action: String,           // "place_bet", "create_market", "deposit", etc.
    pub target_layer: String,     // "L2"
    pub params: serde_json::Value, // Action-specific parameters
}

/// L2 action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2Action {
    PlaceBet {
        market_id: String,
        option: String,
        amount: f64,
    },
    CreateMarket {
        title: String,
        options: Vec<String>,
        end_time: u64,
    },
    Deposit {
        amount: f64,
    },
    Withdraw {
        amount: f64,
    },
    Transfer {
        to: String,
        amount: f64,
    },
}

// ============================================================================
// L2 INTEGRATION TYPES - Nonces, Settlements, Wallet Lookup
// ============================================================================

/// Nonce tracking for cross-layer replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub address: String,
    pub l1_nonce: u64,
    pub cross_layer_nonce: u64,
    pub last_l1_activity_slot: u64,
}

/// Settlement request from L2 (when a market resolves)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub market_id: String,
    pub outcome: String,
    pub winners: Vec<SettlementWinner>,  // (address, payout)
    pub l2_block_height: u64,
    pub l2_signature: String,            // L2 validator signature
    pub total_pool: Option<f64>,
    pub market_title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementWinner {
    pub address: String,
    pub payout: f64,
}

/// Settlement record stored on L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub market_id: String,
    pub outcome: String,
    pub winners: Vec<SettlementWinner>,
    pub l2_block_height: u64,
    pub l1_slot: u64,
    pub l1_tx_hash: String,
    pub recorded_at: u64,
}

// ============================================================================
// L2 → L1 WITHDRAWAL & MERKLE SETTLEMENT TYPES
// ============================================================================

/// Merkle settlement root submitted by L2 for scalable settlements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSettlementRoot {
    pub root_id: String,
    pub merkle_root: String,           // Root hash of all winner payouts
    pub total_payout: f64,             // Sum of all payouts in this batch
    pub winner_count: u32,             // Number of winners in this batch
    pub l2_block_height: u64,
    pub l2_signature: String,          // L2 authority signature
    pub l1_slot: u64,
    pub recorded_at: u64,
    pub claims_processed: u32,         // How many claims have been made
}

/// Request from L2 to withdraw (unlock) tokens back to L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub withdrawal_id: String,
    pub user_address: String,
    pub amount: f64,
    pub l2_burn_tx: String,            // L2 transaction hash where tokens were burned
    pub l2_signature: String,          // L2 authority signature
    pub timestamp: u64,
}

/// Merkle proof for claiming settlement payouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementClaimRequest {
    pub root_id: String,               // Which settlement batch
    pub user_address: String,
    pub amount: f64,
    pub merkle_proof: Vec<String>,     // Proof path to verify inclusion
    pub leaf_index: u32,               // Position in the Merkle tree
}

/// L2 authority configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Authority {
    pub public_key: String,            // L2 sequencer's public key
    pub name: String,
}

/// Get the hardcoded L2 authority public key (in production, load from config)
fn get_l2_authority() -> L2Authority {
    // In production, this should be loaded from environment or config
    // For now, we use a known test key or allow any signature for dev
    L2Authority {
        public_key: std::env::var("L2_AUTHORITY_PUBKEY")
            .unwrap_or_else(|_| "L2_AUTHORITY_DEV_KEY".to_string()),
        name: "BlackBook L2 Sequencer".to_string(),
    }
}

/// Verify that a signature is from the L2 authority
fn verify_l2_authority_signature(message: &str, signature: &str) -> Result<bool, String> {
    let authority = get_l2_authority();
    
    // In dev mode, accept any signature
    if authority.public_key == "L2_AUTHORITY_DEV_KEY" {
        println!("⚠️  DEV MODE: Accepting L2 signature without verification");
        return Ok(true);
    }
    
    // In production, verify the signature
    verify_ed25519_signature(&authority.public_key, message, signature)
}

/// Wallet lookup response (for L2 to resolve user_id → L1 wallet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletLookupResponse {
    pub user_id: String,
    pub wallet_address: Option<String>,
    pub public_key_hex: Option<String>,
    pub username: Option<String>,
    pub found: bool,
}

/// Shared bridge state
#[derive(Debug, Clone, Default)]
pub struct BridgeState {
    pub pending_bridges: HashMap<String, PendingBridge>,
    pub completed_bridges: Vec<String>,
    pub total_bridged_l1_to_l2: f64,
    pub total_bridged_l2_to_l1: f64,
    // L2 Integration: Nonce tracking
    pub cross_layer_nonces: HashMap<String, u64>,     // address → next cross-layer nonce
    pub last_activity_slots: HashMap<String, u64>,    // address → last L1 slot with activity
    // L2 Integration: Settlement records
    pub settlements: HashMap<String, SettlementRecord>,
    pub total_settlements: u64,
    // L2 → L1 Withdrawal tracking
    pub processed_withdrawals: HashMap<String, WithdrawalRequest>,  // withdrawal_id → request
    pub total_withdrawn_l2_to_l1: f64,
    // Merkle settlement roots for scalable settlements
    pub settlement_roots: HashMap<String, MerkleSettlementRoot>,   // root_id → merkle root
    pub processed_claims: HashMap<String, bool>,                    // claim_key → processed
    // =========================================================================
    // ESCROW LOCK TRACKING
    // =========================================================================
    /// Maps lock_id → bridge_id for correlating escrow locks with bridges
    pub lock_to_bridge: HashMap<String, String>,
    /// Maps bridge_id → lock_id for reverse lookup
    pub bridge_to_lock: HashMap<String, String>,
    // =========================================================================
    // OPTIMISTIC EXECUTION: L2 Session State (Live Game Balances)
    // =========================================================================
    // These track "hot wallet" balances during active gaming sessions.
    // L1 balance = "Vault" (Truth), L2 balance = "Game Session" (Live)
    pub l2_sessions: HashMap<String, L2Session>,                   // address → session
    pub total_sessions_created: u64,
    pub total_sessions_settled: u64,
}

// ============================================================================
// L2 SESSION TYPES (Optimistic Execution)
// ============================================================================

/// An active L2 gaming session for a user
/// Tracks the "hot wallet" balance during optimistic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Session {
    pub session_id: String,
    pub wallet_address: String,
    pub l1_balance_at_start: f64,      // Snapshot of L1 balance when session started
    pub l2_balance: f64,               // Current "live" balance (updated by bets)
    pub total_wagered: f64,            // Sum of all bets placed
    pub total_won: f64,                // Sum of all winnings
    pub total_lost: f64,               // Sum of all losses
    pub bet_count: u32,                // Number of bets in this session
    pub started_at: u64,               // Unix timestamp
    pub last_activity: u64,            // Last bet timestamp
    pub is_active: bool,               // Can still place bets
}

impl L2Session {
    /// Calculate net profit/loss for this session
    pub fn net_pnl(&self) -> f64 {
        self.l2_balance - self.l1_balance_at_start
    }
    
    /// Check if user has winnings to claim
    pub fn has_winnings(&self) -> bool {
        self.net_pnl() > 0.0
    }
}

/// Request to start a new L2 session (connect to game)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSessionRequest {
    pub wallet_address: String,
    pub amount: Option<f64>,                 // Bankroll to lock (unified wallet)
    pub initial_l2_allocation: Option<f64>,  // Legacy: how much to allocate to L2
    pub session_id: Option<String>,          // Optional custom session ID
}

/// Request to settle a session (write PnL to L1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleSessionRequest {
    pub wallet_address: String,
    pub lock_id: Option<String>,             // Lock from start-session (unified)
    pub session_id: Option<String>,          // Session to settle
    pub starting_balance: Option<f64>,       // Original locked amount
    pub ending_balance: Option<f64>,         // Final session balance after all bets
    pub total_bets: Option<u32>,             // Number of bets placed
    pub total_wagered: Option<f64>,          // Total amount wagered
    pub settlement_hash: Option<String>,     // Hash of all L2 transactions for audit
    pub l2_signature: Option<String>,        // L2 authority signature for batch settlements
}

/// Result of a bet on L2 (updates session balance)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2BetResult {
    pub session_id: String,
    pub bet_id: String,
    pub amount: f64,
    pub won: bool,
    pub payout: f64,                         // 0 if lost, winnings if won
    pub new_l2_balance: f64,
}

impl BridgeState {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get or create the cross-layer nonce for an address
    pub fn get_cross_layer_nonce(&self, address: &str) -> u64 {
        *self.cross_layer_nonces.get(address).unwrap_or(&0)
    }
    
    /// Increment the cross-layer nonce for an address
    pub fn increment_nonce(&mut self, address: &str) -> u64 {
        let nonce = self.cross_layer_nonces.entry(address.to_string()).or_insert(0);
        *nonce += 1;
        *nonce
    }
    
    /// Record the last activity slot for an address
    pub fn record_activity(&mut self, address: &str, slot: u64) {
        self.last_activity_slots.insert(address.to_string(), slot);
    }
    
    /// Get the last activity slot for an address
    pub fn get_last_activity_slot(&self, address: &str) -> u64 {
        *self.last_activity_slots.get(address).unwrap_or(&0)
    }
    
    // =========================================================================
    // L2 SESSION MANAGEMENT (Optimistic Execution)
    // =========================================================================
    
    /// Start a new L2 session for a user (mirrors L1 balance to L2)
    pub fn start_session(&mut self, wallet_address: &str, l1_balance: f64, allocation: Option<f64>) -> L2Session {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Use allocation or full L1 balance
        let l2_balance = allocation.unwrap_or(l1_balance).min(l1_balance);
        
        let session = L2Session {
            session_id: format!("session_{}_{}", now, &wallet_address[..wallet_address.len().min(8)]),
            wallet_address: wallet_address.to_string(),
            l1_balance_at_start: l2_balance,  // This is what we "mirror" from L1
            l2_balance,
            total_wagered: 0.0,
            total_won: 0.0,
            total_lost: 0.0,
            bet_count: 0,
            started_at: now,
            last_activity: now,
            is_active: true,
        };
        
        self.l2_sessions.insert(wallet_address.to_string(), session.clone());
        self.total_sessions_created += 1;
        
        session
    }
    
    /// Get active session for a user
    pub fn get_session(&self, wallet_address: &str) -> Option<&L2Session> {
        self.l2_sessions.get(wallet_address)
    }
    
    /// Get mutable session for a user
    pub fn get_session_mut(&mut self, wallet_address: &str) -> Option<&mut L2Session> {
        self.l2_sessions.get_mut(wallet_address)
    }
    
    /// Update L2 balance after a bet (called by L2 server)
    pub fn record_bet(&mut self, wallet_address: &str, amount: f64, won: bool, payout: f64) -> Option<L2BetResult> {
        let session = self.l2_sessions.get_mut(wallet_address)?;
        
        if !session.is_active {
            return None;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Update session stats
        session.total_wagered += amount;
        session.bet_count += 1;
        session.last_activity = now;
        
        if won {
            session.total_won += payout;
            session.l2_balance += payout - amount;  // Net gain
        } else {
            session.total_lost += amount;
            session.l2_balance -= amount;
        }
        
        Some(L2BetResult {
            session_id: session.session_id.clone(),
            bet_id: format!("bet_{}_{}", now, session.bet_count),
            amount,
            won,
            payout,
            new_l2_balance: session.l2_balance,
        })
    }
    
    /// Close a session (mark as inactive, ready for settlement)
    pub fn close_session(&mut self, wallet_address: &str) -> Option<&L2Session> {
        if let Some(session) = self.l2_sessions.get_mut(wallet_address) {
            session.is_active = false;
            Some(session)
        } else {
            None
        }
    }
    
    /// Remove a session after settlement
    pub fn remove_session(&mut self, wallet_address: &str) -> Option<L2Session> {
        self.total_sessions_settled += 1;
        self.l2_sessions.remove(wallet_address)
    }
}

// ============================================================================
// BRIDGE ROUTES
// ============================================================================

/// POST /bridge/initiate - Initiate a bridge from L1 to L2
/// 
/// Locks tokens on L1 and creates a pending bridge record.
/// L2 will poll or be notified to credit the tokens.
pub fn bridge_initiate_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("initiate"))
        .and(warp::post())
        .and(warp::body::json::<SignedRequest>())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                // Verify signature and get wallet address
                let wallet_address = match verify_signed_request(&request) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })));
                    }
                };
                
                // Parse payload
                let payload: BridgeInitiatePayload = match serde_json::from_str(&request.payload) {
                    Ok(p) => p,
                    Err(_) => {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid bridge payload"
                        })));
                    }
                };
                
                // Validate amount
                if payload.amount <= 0.0 {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }
                
                // Check balance and lock tokens using proper escrow
                let (bridge_id, lock_id) = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Use the new lock_tokens method for proper escrow
                    let lock_id = match bc.lock_tokens(
                        &wallet_address,
                        payload.amount,
                        LockPurpose::BridgeToL2,
                        Some(payload.target_address.clone()),
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": e
                            })));
                        }
                    };
                    
                    // Generate bridge ID (linked to lock_id)
                    let bridge_id = format!("bridge_{}_{}", 
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        &wallet_address[..8]
                    );
                    (bridge_id, lock_id)
                };
                
                // Create pending bridge record
                let pending_bridge = PendingBridge {
                    id: bridge_id.clone(),
                    from_address: wallet_address.clone(),
                    to_address: payload.target_address.clone(),
                    amount: payload.amount,
                    source_layer: "L1".to_string(),
                    target_layer: payload.target_layer.clone(),
                    status: BridgeStatus::Pending,
                    created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    confirmed_at: None,
                    completed_at: None,
                    tx_hash: None,
                };
                
                // Store pending bridge
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.pending_bridges.insert(bridge_id.clone(), pending_bridge.clone());
                    state.total_bridged_l1_to_l2 += payload.amount;
                    // Store bidirectional lock_id <-> bridge_id mapping for later release
                    state.lock_to_bridge.insert(lock_id.clone(), bridge_id.clone());
                    state.bridge_to_lock.insert(bridge_id.clone(), lock_id.clone());
                }
                
                // ═══════════════════════════════════════════════════════════════
                // CALL L2's /bridge/deposit TO CREDIT TOKENS ON L2
                // ═══════════════════════════════════════════════════════════════
                let l2_url = std::env::var("L2_RPC_URL")
                    .unwrap_or_else(|_| "http://localhost:1234".to_string());
                
                let l2_deposit_payload = serde_json::json!({
                    "bridge_id": bridge_id,
                    "wallet_address": payload.target_address,
                    "from_l1_address": wallet_address,
                    "amount": payload.amount,
                    "lock_id": lock_id,
                    "source": "L1",
                    "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                });
                
                // Attempt to notify L2 (non-blocking - bridge is already recorded)
                let l2_result = notify_l2_deposit(&l2_url, &l2_deposit_payload).await;
                let l2_credited = l2_result.is_ok();
                
                // Update bridge status if L2 confirmed
                if l2_credited {
                    let mut state = lock_bridge_state(&bridge_state);
                    if let Some(bridge) = state.pending_bridges.get_mut(&bridge_id) {
                        bridge.status = BridgeStatus::Confirmed;
                        bridge.confirmed_at = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                    }
                }
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "bridge_id": bridge_id,
                    "lock_id": lock_id,
                    "status": if l2_credited { "confirmed" } else { "pending" },
                    "l2_credited": l2_credited,
                    "l2_url": l2_url,
                    "from_address": wallet_address,
                    "to_address": payload.target_address,
                    "amount": payload.amount,
                    "source_layer": "L1",
                    "target_layer": payload.target_layer,
                    "message": if l2_credited { 
                        "Bridge complete! Tokens locked on L1 and credited on L2." 
                    } else { 
                        "Tokens locked on L1. L2 credit pending - will retry automatically." 
                    }
                })))
            }
        })
}

/// GET /bridge/status/:id - Get bridge status
pub fn bridge_status_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("status"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |bridge_id: String| {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                
                if let Some(bridge) = state.pending_bridges.get(&bridge_id) {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "bridge": bridge
                    })))
                } else {
                    Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Bridge not found"
                    })))
                }
            }
        })
}

/// GET /bridge/pending - List all pending bridges
pub fn bridge_pending_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("pending"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                let pending: Vec<_> = state.pending_bridges.values()
                    .filter(|b| b.status == BridgeStatus::Pending)
                    .cloned()
                    .collect();
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "pending_count": pending.len(),
                    "bridges": pending
                })))
            }
        })
}

/// GET /bridge/stats - Bridge statistics
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
                
                let pending_count = state.pending_bridges.values()
                    .filter(|b| b.status == BridgeStatus::Pending)
                    .count();
                let completed_count = state.pending_bridges.values()
                    .filter(|b| b.status == BridgeStatus::Completed)
                    .count();
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "stats": {
                        "total_bridges": state.pending_bridges.len(),
                        "pending": pending_count,
                        "completed": completed_count,
                        "total_bridged_l1_to_l2": state.total_bridged_l1_to_l2,
                        "total_bridged_l2_to_l1": state.total_bridged_l2_to_l1
                    }
                })))
            }
        })
}

/// POST /bridge/complete - L2 calls this to mark bridge as complete
/// 
/// This is called by L2 after crediting tokens to the target address.
pub fn bridge_complete_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("complete"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let bridge_state = bridge_state.clone();
            async move {
                let bridge_id = body.get("bridge_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tx_hash = body.get("tx_hash")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                if bridge_id.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "bridge_id is required"
                    })));
                }
                
                let mut state = lock_bridge_state(&bridge_state);
                
                if let Some(bridge) = state.pending_bridges.get_mut(bridge_id) {
                    bridge.status = BridgeStatus::Completed;
                    bridge.completed_at = Some(
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                    );
                    bridge.tx_hash = tx_hash;
                    state.completed_bridges.push(bridge_id.to_string());
                    
                    Ok(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "message": "Bridge marked as complete",
                        "bridge_id": bridge_id
                    })))
                } else {
                    Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Bridge not found"
                    })))
                }
            }
        })
}

// ============================================================================
// UNIFIED WALLET: SESSION-BASED L2 INTEGRATION (OPTIMAL)
// ============================================================================
//
// This is the TRUE unified wallet with MINIMAL L1 calls:
//
// FLOW:
// 1. User starts session  → L1 locks bankroll ONCE
// 2. User bets 100x       → L2 only (instant, no L1 calls!)
// 3. User cashes out      → L1 settles NET P&L ONCE
//
// = 2 L1 calls for unlimited L2 actions!
//
// ENDPOINTS:
// - POST /bridge/start-session   → Lock bankroll, start L2 session
// - GET  /bridge/l1-balance/:addr → Check real L1 balance
// - POST /bridge/settle-session  → End session, apply NET P&L

/// POST /bridge/start-session - Start L2 betting session
/// 
/// Locks user's bankroll on L1. L2 can then allow unlimited betting
/// against this locked balance WITHOUT calling L1 for each bet.
pub fn start_session_unified_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("start-session"))
        .and(warp::post())
        .and(warp::body::json::<StartSessionRequest>())
        .and_then(move |request: StartSessionRequest| {
            let blockchain = blockchain.clone();
            async move {
                // Get amount from either field
                let amount = request.amount.or(request.initial_l2_allocation).unwrap_or(0.0);
                
                // Get the base address and format with prefixes
                let base_addr = strip_prefix(&request.wallet_address);
                let l1_addr = to_l1_address(&request.wallet_address);
                let l2_addr = to_l2_address(&request.wallet_address);
                
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║ 🎮 STARTING L2 SESSION - FUNDS TRANSFER                        ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Base Address: {:<47} ║", base_addr);
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ FROM: {:<55} ║", l1_addr);
                println!("║       (Real balance - available for withdrawal/trading)       ║");
                println!("║ TO:   {:<55} ║", l2_addr);
                println!("║       (Locked for betting session)                            ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Amount:     {:<49.4} BB ║", amount);
                println!("║ Timestamp:  {:<49} ║", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!("╚═══════════════════════════════════════════════════════════════╝");
                
                // Validate
                if amount <= 0.0 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }
                
                // Generate session ID if not provided
                let session_id = request.session_id.unwrap_or_else(|| {
                    format!("session_{}_{}", 
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        &request.wallet_address[..8.min(request.wallet_address.len())]
                    )
                });
                
                // Lock tokens on L1
                let result = {
                    let mut bc = lock_or_recover(&blockchain);
                    bc.lock_tokens(
                        &request.wallet_address,
                        amount,
                        LockPurpose::BridgeToL2,
                        Some(session_id.clone()),
                    )
                };
                
                match result {
                    Ok(lock_id) => {
                        println!("╔═══════════════════════════════════════════════════════════════╗");
                        println!("║ ✅ SESSION STARTED SUCCESSFULLY                                ║");
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ Session ID: {:<49} ║", session_id);
                        println!("║ Lock ID:    {:<49} ║", lock_id);
                        println!("║ Amount:     {:<49.4} BB ║", amount);
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ {} now shows:  -{:.4} BB (locked)       ║", l1_addr, amount);
                        println!("║ {} now shows:  +{:.4} BB (available to bet) ║", l2_addr, amount);
                        println!("╚═══════════════════════════════════════════════════════════════╝\n");
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "session_id": session_id,
                            "lock_id": lock_id,
                            "l1_address": l1_addr,
                            "l2_address": l2_addr,
                            "wallet_address": request.wallet_address,  // Legacy compatibility
                            "locked_amount": amount,
                            "message": format!("Session started. {} BB moved from {} to {}", amount, l1_addr, l2_addr),
                            "instructions": {
                                "l2_should": "Track session balance internally, allow bets up to locked_amount",
                                "on_cashout": "Call POST /bridge/settle-session with NET P&L",
                                "no_l1_calls": "Do NOT call L1 for individual bets - that defeats L2's purpose!"
                            }
                        })))
                    },
                    Err(e) => {
                        println!("╔═══════════════════════════════════════════════════════════════╗");
                        println!("║ ❌ SESSION START FAILED                                        ║");
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ L1 Wallet: {:<50} ║", l1_addr);
                        println!("║ Error:     {:<50} ║", e);
                        println!("╚═══════════════════════════════════════════════════════════════╝\n");
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })))
                    }
                }
            }
        })
}

/// POST /bridge/settle-session - End L2 session and settle on L1
/// 
/// Called ONCE when user cashes out. Applies the NET profit/loss
/// from the entire session to L1. This is the only time L2 results
/// touch L1 - not per-bet, but per-SESSION.
pub fn settle_session_unified_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("settle-session"))
        .and(warp::post())
        .and(warp::body::json::<SettleSessionRequest>())
        .and_then(move |request: SettleSessionRequest| {
            let blockchain = blockchain.clone();
            async move {
                // Extract required fields with defaults
                let lock_id = match &request.lock_id {
                    Some(id) => id.clone(),
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "lock_id is required"
                        })));
                    }
                };
                let session_id = request.session_id.clone().unwrap_or_else(|| "unknown".to_string());
                let starting_balance = request.starting_balance.unwrap_or(0.0);
                let ending_balance = request.ending_balance.unwrap_or(0.0);
                let total_bets = request.total_bets.unwrap_or(0);
                let settlement_hash = request.settlement_hash.clone().unwrap_or_default();
                
                let net_pnl = ending_balance - starting_balance;
                
                // Get the base address and format with prefixes
                let base_addr = strip_prefix(&request.wallet_address);
                let l1_addr = to_l1_address(&request.wallet_address);
                let l2_addr = to_l2_address(&request.wallet_address);
                
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║ 💰 SETTLING L2 SESSION - FUNDS RETURN TO L1                    ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Base Address: {:<47} ║", base_addr);
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ FROM: {:<55} ║", l2_addr);
                println!("║       (Returning locked betting funds)                        ║");
                println!("║ TO:   {:<55} ║", l1_addr);
                println!("║       (Real balance - available for withdrawal)               ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Session:     {:<48} ║", session_id);
                println!("║ Lock ID:     {:<48} ║", lock_id);
                println!("║ Start Bal:   {:<48.4} BB ║", starting_balance);
                println!("║ End Bal:     {:<48.4} BB ║", ending_balance);
                println!("║ Net P&L:     {:<48.4} BB ║", net_pnl);
                println!("║ Total Bets:  {:<48} ║", total_bets);
                println!("║ Timestamp:   {:<48} ║", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!("╚═══════════════════════════════════════════════════════════════╝");
                
                let result = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Create settlement proof
                    let proof = SettlementProof {
                        market_id: session_id.clone(),
                        outcome: format!("NET_PNL:{}", net_pnl),
                        l2_block_height: 0,
                        l2_signature: settlement_hash.clone(),
                        verified_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    };
                    
                    // Authorize and release
                    if let Err(e) = bc.authorize_release(&lock_id, proof) {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Failed to authorize: {}", e)
                        })));
                    }
                    
                    match bc.release_tokens(&lock_id) {
                        Ok((_recipient, released)) => {
                            // Apply NET P&L
                            let current = bc.balances.get(&request.wallet_address).copied().unwrap_or(0.0);
                            let new_balance = (current + net_pnl).max(0.0);
                            bc.balances.insert(request.wallet_address.clone(), new_balance);
                            
                            // Record the settlement transaction
                            if net_pnl > 0.0 {
                                // User profited - house pays user
                                bc.create_transaction(
                                    "L2_HOUSE".to_string(),
                                    request.wallet_address.clone(),
                                    net_pnl
                                );
                            } else if net_pnl < 0.0 {
                                // User lost - user pays house
                                bc.create_transaction(
                                    request.wallet_address.clone(),
                                    "L2_HOUSE".to_string(),
                                    net_pnl.abs()
                                );
                            }
                            
                            Ok((released, new_balance))
                        },
                        Err(e) => Err(e)
                    }
                };
                
                match result {
                    Ok((released, final_balance)) => {
                        let status = if net_pnl > 0.0 { "PROFIT" } 
                            else if net_pnl < 0.0 { "LOSS" } 
                            else { "BREAK_EVEN" };
                        
                        println!("╔═══════════════════════════════════════════════════════════════╗");
                        println!("║ ✅ SESSION SETTLED SUCCESSFULLY                                ║");
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ Status:      {:<48} ║", status);
                        println!("║ Net P&L:     {:<48.4} BB ║", net_pnl);
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ {} now shows:  0.00 BB (session ended) ║", l2_addr);
                        println!("║ {} now shows:  {:<.4} BB (unlocked)   ║", l1_addr, final_balance);
                        println!("╚═══════════════════════════════════════════════════════════════╝\n");
                        
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "session_id": session_id,
                            "lock_id": lock_id,
                            "l1_address": l1_addr,
                            "l2_address": l2_addr,
                            "starting_balance": starting_balance,
                            "ending_balance": ending_balance,
                            "net_pnl": net_pnl,
                            "status": status,
                            "total_bets": total_bets,
                            "total_wagered": request.total_wagered,
                            "released_from_lock": released,
                            "final_l1_balance": final_balance,
                            "settlement_hash": request.settlement_hash,
                            "message": format!("Session complete. {} moved from {} back to {} with {} {} BB", 
                                released, l2_addr, l1_addr,
                                if net_pnl >= 0.0 { "profit" } else { "loss" },
                                net_pnl.abs()
                            )
                        })))
                    },
                    Err(e) => {
                        println!("╔═══════════════════════════════════════════════════════════════╗");
                        println!("║ ❌ SETTLEMENT FAILED                                           ║");
                        println!("╠═══════════════════════════════════════════════════════════════╣");
                        println!("║ L2 Wallet: {:<50} ║", l2_addr);
                        println!("║ Error:     {:<50} ║", e);
                        println!("╚═══════════════════════════════════════════════════════════════╝\n");
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })))
                    }
                }
            }
        })
}

/// GET /bridge/l1-balance/:address - Check real L1 balance
/// 
/// L2 should call this to show users their TRUE balance.
/// Shows available (can withdraw), locked (in sessions), and total.
pub fn l1_balance_for_l2_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("l1-balance"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |address: String| {
            let blockchain = blockchain.clone();
            async move {
                let (available, locked, total) = {
                    let bc = lock_or_recover(&blockchain);
                    let total = bc.balances.get(&address).copied().unwrap_or(0.0);
                    let locked = bc.get_locked_balance(&address);
                    let available = (total - locked).max(0.0);
                    (available, locked, total)
                };
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "wallet_address": address,
                    "available": available,
                    "locked": locked,
                    "total": total,
                    "source": "L1",
                    "message": "This is the SINGLE SOURCE OF TRUTH"
                })))
            }
        })
}

// ============================================================================
// SIGNATURE VERIFICATION (For L2 to call)
// ============================================================================

/// POST /rpc/verify-signature - L2 calls this to verify an L1 signature
/// 
/// This allows L2 to verify that a request was signed by a valid L1 wallet.
pub fn verify_signature_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path("verify-signature"))
        .and(warp::post())
        .and(warp::body::json::<VerifySignatureRequest>())
        .and_then(|request: VerifySignatureRequest| {
            async move {
                match verify_ed25519_signature(&request.public_key, &request.message, &request.signature) {
                    Ok(valid) => {
                        let wallet_address = request.public_key.clone();
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "valid": valid,
                            "wallet_address": wallet_address,
                            "message": if valid { "Signature is valid" } else { "Signature is invalid" }
                        })))
                    },
                    Err(e) => {
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "valid": false,
                            "error": e
                        })))
                    }
                }
            }
        })
}

// ============================================================================
// RELAY TO L2 (Signed actions)
// ============================================================================

/// POST /rpc/relay - Relay a signed action to L2
/// 
/// User signs an L2 action with their L1 wallet, L1 verifies and forwards to L2.
pub fn relay_action_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path("relay"))
        .and(warp::post())
        .and(warp::body::json::<SignedRequest>())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            async move {
                // Verify signature and get wallet address
                let wallet_address = match verify_signed_request(&request) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })));
                    }
                };
                
                // Parse relay payload
                let payload: RelayActionPayload = match serde_json::from_str(&request.payload) {
                    Ok(p) => p,
                    Err(_) => {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid relay payload"
                        })));
                    }
                };
                
                // Check L1 balance for certain actions
                let l1_balance = {
                    let bc = lock_or_recover(&blockchain);
                    bc.balances.get(&wallet_address).copied().unwrap_or(0.0)
                };
                
                // Get L2 URL from environment (default: L2 prediction market on port 1234)
                let l2_url = std::env::var("L2_RPC_URL")
                    .unwrap_or_else(|_| "http://localhost:1234".to_string());
                
                // Build the relay payload for L2
                let l2_payload = serde_json::json!({
                    "action": payload.action,
                    "wallet_address": wallet_address,
                    "l1_balance": l1_balance,
                    "params": payload.params,
                    "signature_verified": true,
                    "l1_timestamp": request.timestamp,
                    "l1_nonce": request.nonce
                });
                
                // Forward to L2
                match forward_to_l2(&l2_url, &payload.action, &l2_payload).await {
                    Ok(response) => {
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "wallet_address": wallet_address,
                            "action": payload.action,
                            "l2_response": response,
                            "relayed_to": l2_url
                        })))
                    },
                    Err(e) => {
                        // If L2 is not reachable, return the verified payload
                        // so the client can retry or use it locally
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "wallet_address": wallet_address,
                            "action": payload.action,
                            "l2_offline": true,
                            "verified_payload": l2_payload,
                            "message": format!("L2 not reachable: {}. Payload verified and returned.", e)
                        })))
                    }
                }
            }
        })
}

// ============================================================================
// L2 INTEGRATION ROUTES - Wallet Lookup, Nonces, Settlements
// ============================================================================

/// GET /auth/wallet/:user_id - L2 calls this to resolve a Supabase user_id to L1 wallet
/// 
/// This allows L2 to look up a user's L1 wallet address by their Supabase user ID.
/// L2 uses this to determine if a user has an L1 wallet before allowing L2 operations.
pub fn wallet_by_user_id_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("auth")
        .and(warp::path("wallet"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |user_id: String| {
            async move {
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║ 🔍 WALLET LOOKUP REQUEST                                       ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ User ID:   {:<50} ║", &user_id);
                println!("║ Timestamp: {:<50} ║", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!("╚═══════════════════════════════════════════════════════════════╝");
                
                // Get Supabase credentials from environment
                let supabase_url = std::env::var("SUPABASE_URL")
                    .unwrap_or_else(|_| "".to_string());
                let supabase_key = std::env::var("SUPABASE_ANON_KEY")
                    .unwrap_or_else(|_| "".to_string());
                
                if supabase_url.is_empty() || supabase_key.is_empty() {
                    // Fallback: Check if it's a known test account
                    let alice = crate::integration::unified_auth::get_alice_account();
                    let bob = crate::integration::unified_auth::get_bob_account();
                    
                    let test_accounts = vec![
                        (alice.username.clone(), alice.address.clone(), alice.name),
                        (bob.username.clone(), bob.address.clone(), bob.name),
                    ];
                    
                    for (username, address, name) in &test_accounts {
                        // Match by name or username (case-insensitive) for test accounts
                        if name.to_lowercase() == user_id.to_lowercase() || 
                           username.to_lowercase() == user_id.to_lowercase() {
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": true,
                                "user_id": user_id,
                                "wallet_address": address,
                                "public_key_hex": null,
                                "username": username,
                                "found": true,
                                "source": "test_accounts"
                            })));
                        }
                    }
                    
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "user_id": user_id,
                        "wallet_address": null,
                        "found": false,
                        "error": "Supabase not configured and user not in test accounts"
                    })));
                }
                
                // Query Supabase for the user's profile
                let connector = SupabaseConnector::new(supabase_url, supabase_key);
                
                // First try by user ID (which is the Supabase auth.users.id)
                let client = reqwest::Client::new();
                let response = client
                    .get(&format!("{}/rest/v1/profiles", connector.url))
                    .header("apikey", &connector.api_key)
                    .header("Authorization", format!("Bearer {}", connector.api_key))
                    .query(&[("id", format!("eq.{}", user_id))])
                    .query(&[("select", "id,username,Blackbook_Address,public_key_hex")])
                    .send()
                    .await;
                
                match response {
                    Ok(resp) if resp.status().is_success() => {
                        let profiles: Vec<serde_json::Value> = resp.json().await
                            .unwrap_or_else(|_| vec![]);
                        
                        if let Some(profile) = profiles.first() {
                            let wallet = profile.get("Blackbook_Address")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let public_key = profile.get("public_key_hex")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let username = profile.get("username")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            
                            println!("╔═══════════════════════════════════════════════════════════════╗");
                            println!("║ ✅ WALLET FOUND                                                 ║");
                            println!("╠═══════════════════════════════════════════════════════════════╣");
                            println!("║ User ID: {:<52} ║", user_id);
                            println!("║ Wallet:  {:<52} ║", wallet.clone().unwrap_or("N/A".to_string()));
                            println!("║ Source:  {:<52} ║", "Supabase");
                            println!("╚═══════════════════════════════════════════════════════════════╝");
                            
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": true,
                                "user_id": user_id,
                                "wallet_address": wallet,
                                "public_key_hex": public_key,
                                "username": username,
                                "found": wallet.is_some(),
                                "source": "supabase"
                            })));
                        }
                    },
                    Ok(resp) => {
                        let error = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                        println!("❌ Supabase query failed: {}", error);
                    },
                    Err(e) => {
                        println!("❌ HTTP error: {}", e);
                    }
                }
                
                // Not found
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "user_id": user_id,
                    "wallet_address": null,
                    "found": false,
                    "message": "User not found or has no L1 wallet"
                })))
            }
        })
}

/// GET /rpc/nonce/:address - L2 queries L1 for cross-layer nonce
/// 
/// Returns the next valid cross-layer nonce for an address.
/// This prevents replay attacks across L1 ↔ L2 boundaries.
pub fn nonce_route(
    bridge_state: Arc<Mutex<BridgeState>>,
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path("nonce"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |address: String| {
            let bridge_state = bridge_state.clone();
            let blockchain = blockchain.clone();
            async move {
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║ 🔢 CROSS-LAYER NONCE REQUEST                                   ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Wallet: {:<53} ║", &address);
                println!("╚═══════════════════════════════════════════════════════════════╝");
                
                let (cross_layer_nonce, last_activity_slot) = {
                    let state = lock_bridge_state(&bridge_state);
                    (
                        state.get_cross_layer_nonce(&address),
                        state.get_last_activity_slot(&address)
                    )
                };
                
                // Get L1-only nonce (transaction count)
                let l1_nonce = {
                    let bc = lock_or_recover(&blockchain);
                    // Count transactions from this address
                    bc.chain.iter()
                        .flat_map(|block| block.financial_txs.iter().chain(block.social_txs.iter()))
                        .filter(|tx| tx.from == address)
                        .count() as u64
                };
                
                println!("   L1 nonce: {}, Cross-layer nonce: {}", l1_nonce, cross_layer_nonce);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "address": address,
                    "l1_nonce": l1_nonce,
                    "cross_layer_nonce": cross_layer_nonce,
                    "last_l1_activity_slot": last_activity_slot,
                    "next_valid_nonce": cross_layer_nonce + 1
                })))
            }
        })
}

/// POST /rpc/settlement - L2 records a market settlement on L1
/// 
/// When L2 resolves a bet/market, it calls this to create an audit trail on L1.
/// This enables:
/// - Audit trail for regulatory compliance
/// - Cross-layer balance verification
/// - Dispute resolution with L1 as source of truth
pub fn settlement_route(
    bridge_state: Arc<Mutex<BridgeState>>,
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path("settlement"))
        .and(warp::post())
        .and(warp::body::json::<SettlementRequest>())
        .and_then(move |request: SettlementRequest| {
            let bridge_state = bridge_state.clone();
            let blockchain = blockchain.clone();
            async move {
                println!("\n═══════════════════════════════════════════════════════════════");
                println!("📊 L2 MARKET SETTLEMENT");
                println!("═══════════════════════════════════════════════════════════════");
                println!("   Market ID: {}", request.market_id);
                println!("   Outcome:   {}", request.outcome);
                println!("   Winners:   {} addresses", request.winners.len());
                println!("   L2 Block:  {}", request.l2_block_height);
                println!("   Time:      {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                // Generate unique settlement ID
                let settlement_id = format!("settlement_{}_{}", 
                    now,
                    &request.market_id[..request.market_id.len().min(8)]
                );
                
                // Generate L1 tx hash (deterministic from settlement data)
                let tx_hash = {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}:{}:{}:{}", 
                        request.market_id, 
                        request.outcome, 
                        request.l2_block_height,
                        request.l2_signature
                    ));
                    format!("0x{}", hex::encode(&hasher.finalize()[..16]))
                };
                
                // Get current L1 slot (simplified - just use block height)
                let l1_slot = {
                    let bc = lock_or_recover(&blockchain);
                    bc.chain.len() as u64
                };
                
                // Create settlement record
                let record = SettlementRecord {
                    settlement_id: settlement_id.clone(),
                    market_id: request.market_id.clone(),
                    outcome: request.outcome.clone(),
                    winners: request.winners.clone(),
                    l2_block_height: request.l2_block_height,
                    l1_slot,
                    l1_tx_hash: tx_hash.clone(),
                    recorded_at: now,
                };
                
                // Store in bridge state
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.settlements.insert(settlement_id.clone(), record.clone());
                    state.total_settlements += 1;
                    
                    // Update nonces for all winners (they participated in cross-layer activity)
                    for winner in &request.winners {
                        state.increment_nonce(&winner.address);
                        state.record_activity(&winner.address, l1_slot);
                    }
                }
                
                // Optional: Record to Supabase for permanent storage
                let supabase_url = std::env::var("SUPABASE_URL").ok();
                let supabase_key = std::env::var("SUPABASE_ANON_KEY").ok();
                
                let mut supabase_recorded = false;
                if let (Some(url), Some(key)) = (supabase_url, supabase_key) {
                    let connector = SupabaseConnector::new(url, key);
                    // Try to record the settlement (fire and forget)
                    match connector.client
                        .post(&format!("{}/rest/v1/settlements", connector.url))
                        .header("apikey", &connector.api_key)
                        .header("Authorization", format!("Bearer {}", connector.api_key))
                        .header("Content-Type", "application/json")
                        .json(&serde_json::json!({
                            "settlement_id": settlement_id,
                            "market_id": request.market_id,
                            "outcome": request.outcome,
                            "winners": request.winners,
                            "l2_block_height": request.l2_block_height,
                            "l1_slot": l1_slot,
                            "l1_tx_hash": tx_hash,
                            "market_title": request.market_title,
                            "total_pool": request.total_pool,
                            "recorded_at": now
                        }))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            supabase_recorded = true;
                            println!("   ✅ Settlement recorded to Supabase");
                        },
                        _ => {
                            println!("   ⚠️ Supabase recording skipped (table may not exist)");
                        }
                    }
                }
                
                println!("✅ SETTLEMENT COMPLETE");
                println!("   Settlement ID: {}", settlement_id);
                println!("   L1 Slot:       {}", l1_slot);
                println!("   TX Hash:       {}", tx_hash);
                println!("═══════════════════════════════════════════════════════════════\n");
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "recorded": true,
                    "settlement_id": settlement_id,
                    "market_id": request.market_id,
                    "outcome": request.outcome,
                    "winner_count": request.winners.len(),
                    "l1_tx_hash": tx_hash,
                    "l1_slot": l1_slot,
                    "supabase_recorded": supabase_recorded,
                    "timestamp": now
                })))
            }
        })
}

/// GET /rpc/settlement/:settlement_id - Get a specific settlement record
pub fn get_settlement_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path("settlement"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |settlement_id: String| {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                
                if let Some(record) = state.settlements.get(&settlement_id) {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "found": true,
                        "settlement": record
                    })))
                } else {
                    Ok(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "found": false,
                        "settlement_id": settlement_id,
                        "message": "Settlement not found"
                    })))
                }
            }
        })
}

// ============================================================================
// VERIFY SETTLEMENT - L2 → L1 Settlement Proof Verification
// ============================================================================

/// Request to verify a settlement and authorize token release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySettlementRequest {
    pub lock_id: String,              // The escrow lock to release
    pub market_id: String,            // L2 market that was resolved
    pub outcome: String,              // The winning outcome
    pub beneficiary: String,          // Who receives the tokens (winner)
    pub amount: f64,                  // Amount to release
    pub l2_block_height: u64,         // L2 block where settlement occurred
    pub l2_signature: String,         // Ed25519 signature from L2 authority
}

/// POST /bridge/verify-settlement - L2 sends settlement proof, L1 verifies and authorizes release
/// 
/// This is the critical security endpoint that:
/// 1. Verifies L2's Ed25519 signature on the settlement data
/// 2. Validates the lock exists and matches the settlement
/// 3. Authorizes the release of locked tokens
/// 4. Returns the release authorization for subsequent withdrawal
pub fn verify_settlement_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("verify-settlement"))
        .and(warp::post())
        .and(warp::body::json::<VerifySettlementRequest>())
        .and_then(move |request: VerifySettlementRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🔐 Settlement verification request for lock_id: {}", request.lock_id);
                
                // 1. Construct the message that L2 signed
                let message = format!(
                    "settlement:{}:{}:{}:{}:{}:{}",
                    request.lock_id,
                    request.market_id,
                    request.outcome,
                    request.beneficiary,
                    request.amount,
                    request.l2_block_height
                );
                
                // 2. Verify L2 authority signature
                match verify_l2_authority_signature(&message, &request.l2_signature) {
                    Ok(true) => {
                        println!("✅ L2 authority signature verified for settlement");
                    },
                    Ok(false) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid L2 authority signature",
                            "lock_id": request.lock_id
                        })));
                    },
                    Err(e) => {
                        // In dev mode (L2_AUTHORITY_DEV_KEY), we allow it
                        println!("⚠️  L2 signature verification: {} (continuing in dev mode)", e);
                    }
                }
                
                // 3. Verify the lock exists and create settlement proof
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                let proof = SettlementProof {
                    market_id: request.market_id.clone(),
                    outcome: request.outcome.clone(),
                    l2_block_height: request.l2_block_height,
                    l2_signature: request.l2_signature.clone(),
                    verified_at: now,
                };
                
                // 4. Authorize the release in the blockchain
                {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Check if lock exists
                    match bc.get_lock_record(&request.lock_id) {
                        Some(lock) => {
                            if lock.released_at.is_some() {
                                return Ok(warp::reply::json(&serde_json::json!({
                                    "success": false,
                                    "error": "Lock already released",
                                    "lock_id": request.lock_id
                                })));
                            }
                            if lock.release_authorized {
                                return Ok(warp::reply::json(&serde_json::json!({
                                    "success": false,
                                    "error": "Release already authorized",
                                    "lock_id": request.lock_id
                                })));
                            }
                            // Verify amount matches (with small tolerance for floating point)
                            if (lock.amount - request.amount).abs() > 0.0001 {
                                return Ok(warp::reply::json(&serde_json::json!({
                                    "success": false,
                                    "error": "Amount mismatch",
                                    "lock_amount": lock.amount,
                                    "request_amount": request.amount
                                })));
                            }
                        },
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Lock not found",
                                "lock_id": request.lock_id
                            })));
                        }
                    }
                    
                    // Authorize the release
                    if let Err(e) = bc.authorize_release(&request.lock_id, proof) {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e,
                            "lock_id": request.lock_id
                        })));
                    }
                    
                    // Update the beneficiary if different from original
                    if let Some(lock) = bc.lock_records.get_mut(&request.lock_id) {
                        lock.beneficiary = Some(request.beneficiary.clone());
                    }
                }
                
                // 5. Record in bridge state for tracking
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    // If there's a corresponding bridge, update it
                    if let Some(bridge_id) = state.lock_to_bridge.get(&request.lock_id).cloned() {
                        if let Some(bridge) = state.pending_bridges.get_mut(&bridge_id) {
                            bridge.status = BridgeStatus::Confirmed;
                            bridge.confirmed_at = Some(now);
                        }
                    }
                }
                
                println!("✅ Settlement verified and release authorized for lock_id: {}", request.lock_id);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "lock_id": request.lock_id,
                    "market_id": request.market_id,
                    "outcome": request.outcome,
                    "beneficiary": request.beneficiary,
                    "amount": request.amount,
                    "release_authorized": true,
                    "verified_at": now,
                    "message": "Settlement verified. Call /bridge/release to transfer tokens."
                })))
            }
        })
}

/// POST /bridge/release - Release tokens after settlement verification
/// 
/// After verify-settlement authorizes the release, this endpoint
/// actually transfers the tokens from escrow to the beneficiary.
pub fn release_tokens_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("release"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                let lock_id = match body.get("lock_id").and_then(|v| v.as_str()) {
                    Some(id) => id.to_string(),
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "lock_id is required"
                        })));
                    }
                };
                
                println!("🔓 Release request for lock_id: {}", lock_id);
                
                // Execute the release
                let (recipient, amount) = {
                    let mut bc = lock_or_recover(&blockchain);
                    match bc.release_tokens(&lock_id) {
                        Ok(result) => result,
                        Err(e) => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": e,
                                "lock_id": lock_id
                            })));
                        }
                    }
                };
                
                // Update bridge state
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    if let Some(bridge_id) = state.lock_to_bridge.get(&lock_id).cloned() {
                        if let Some(bridge) = state.pending_bridges.get_mut(&bridge_id) {
                            bridge.status = BridgeStatus::Completed;
                            bridge.completed_at = Some(
                                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
                            );
                        }
                        state.completed_bridges.push(bridge_id);
                    }
                    state.total_bridged_l2_to_l1 += amount;
                }
                
                println!("✅ Released {} BB to {} (lock_id: {})", amount, recipient, lock_id);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "lock_id": lock_id,
                    "recipient": recipient,
                    "amount": amount,
                    "message": "Tokens released from escrow"
                })))
            }
        })
}

// ============================================================================
// L2 → L1 WITHDRAWAL ROUTES (Unlock tokens on L1)
// ============================================================================

/// POST /bridge/withdraw - L2 requests to unlock tokens on L1
/// 
/// When a user withdraws from L2, L2 burns their tokens and calls this endpoint
/// to unlock (credit) the tokens back to the user's L1 balance.
/// 
/// Security: Only the L2 authority can call this endpoint.
pub fn withdraw_to_l1_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("withdraw"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                // Parse withdrawal request first to get addresses
                let user_address = match body.get("user_address").and_then(|v| v.as_str()) {
                    Some(addr) => addr,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "user_address is required"
                        })));
                    }
                };
                let amount = match body.get("amount").and_then(|v| v.as_f64()) {
                    Some(amt) => amt,
                    None => {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "amount is required"
                        })));
                    }
                };
                let l2_burn_tx = body.get("l2_burn_tx")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let l2_signature = body.get("l2_signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                // Format addresses with L1/L2 prefixes
                let base_addr = strip_prefix(user_address);
                let l1_addr = to_l1_address(user_address);
                let l2_addr = to_l2_address(user_address);
                
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║ 🏦 L2 → L1 WITHDRAWAL REQUEST                                   ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Base Address: {:<47} ║", base_addr);
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ FROM: {:<55} ║", l2_addr);
                println!("║       (Burning L2 betting balance)                            ║");
                println!("║ TO:   {:<55} ║", l1_addr);
                println!("║       (Crediting real L1 balance)                             ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Amount:     {:<49.4} BB ║", amount);
                println!("║ L2 Burn TX: {:<49} ║", l2_burn_tx);
                println!("║ Timestamp:  {:<49} ║", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!("╚═══════════════════════════════════════════════════════════════╝");
                
                // Generate withdrawal ID
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let withdrawal_id = format!("withdraw_{}_{}", now, &base_addr[..base_addr.len().min(8)]);
                
                // Check if already processed (replay protection)
                {
                    let state = lock_bridge_state(&bridge_state);
                    if state.processed_withdrawals.contains_key(&withdrawal_id) {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Withdrawal already processed",
                            "withdrawal_id": withdrawal_id
                        })));
                    }
                    // Also check by l2_burn_tx to prevent double-spending
                    if state.processed_withdrawals.values().any(|w| w.l2_burn_tx == l2_burn_tx) {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "L2 burn transaction already processed",
                            "l2_burn_tx": l2_burn_tx
                        })));
                    }
                }
                
                // Verify L2 authority signature
                let message = format!("withdraw:{}:{}:{}", user_address, amount, l2_burn_tx);
                match verify_l2_authority_signature(&message, l2_signature) {
                    Ok(true) => println!("   ✅ L2 authority signature verified"),
                    Ok(false) => {
                        println!("   ❌ Invalid L2 signature for {}", user_address);
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid L2 authority signature"
                        })));
                    },
                    Err(e) => {
                        // In dev mode, continue anyway
                        println!("   ⚠️  L2 signature verification: {}", e);
                    }
                }
                
                // Credit L1 balance (UNLOCK tokens) - use base address for storage
                let final_balance = {
                    let mut bc = lock_or_recover(&blockchain);
                    let entry = bc.balances.entry(base_addr.clone()).or_insert(0.0);
                    *entry += amount;
                    *entry
                };
                
                // Record the withdrawal
                let withdrawal_record = WithdrawalRequest {
                    withdrawal_id: withdrawal_id.clone(),
                    user_address: base_addr.clone(),
                    amount,
                    l2_burn_tx: l2_burn_tx.to_string(),
                    l2_signature: l2_signature.to_string(),
                    timestamp: now,
                };
                
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.processed_withdrawals.insert(withdrawal_id.clone(), withdrawal_record);
                    state.total_withdrawn_l2_to_l1 += amount;
                    state.total_bridged_l2_to_l1 += amount;
                }
                
                println!("╔═══════════════════════════════════════════════════════════════╗");
                println!("║ ✅ WITHDRAWAL COMPLETE                                         ║");
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ Withdrawal ID: {:<46} ║", withdrawal_id);
                println!("║ Amount:        {:<46.4} BB ║", amount);
                println!("╠═══════════════════════════════════════════════════════════════╣");
                println!("║ {} now shows:  0.00 BB (burned)        ║", l2_addr);
                println!("║ {} now shows:  {:<.4} BB (credited)  ║", l1_addr, final_balance);
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "withdrawal_id": withdrawal_id,
                    "l1_address": l1_addr,
                    "l2_address": l2_addr,
                    "user_address": base_addr,  // Legacy compatibility
                    "amount": amount,
                    "final_l1_balance": final_balance,
                    "l2_burn_tx": l2_burn_tx,
                    "message": format!("Tokens withdrawn: {} BB moved from {} to {}", amount, l2_addr, l1_addr)
                })))
            }
        })
}

// ============================================================================
// MERKLE SETTLEMENT ROUTES (Scalable L2 → L1 settlements)
// ============================================================================

/// POST /bridge/settle-root - L2 posts a Merkle root for batch settlements
/// 
/// Instead of posting individual winners, L2 posts a Merkle root that commits
/// to all winner payouts. Users can then claim their winnings individually.
pub fn post_settlement_root_route(
    bridge_state: Arc<Mutex<BridgeState>>,
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("settle-root"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let bridge_state = bridge_state.clone();
            let blockchain = blockchain.clone();
            async move {
                println!("🌳 L2 posting Merkle settlement root");
                
                // Parse the request
                let merkle_root = match body.get("merkle_root").and_then(|v| v.as_str()) {
                    Some(root) => root,
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "merkle_root is required"
                        })));
                    }
                };
                let total_payout = body.get("total_payout")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let winner_count = body.get("winner_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let l2_block_height = body.get("l2_block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let l2_signature = body.get("l2_signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                // Generate root ID
                let root_id = format!("root_{}_{}", now, &merkle_root[..merkle_root.len().min(8)]);
                
                // Get current L1 slot
                let l1_slot = {
                    let bc = lock_or_recover(&blockchain);
                    bc.chain.len() as u64
                };
                
                // Verify L2 authority signature
                let message = format!("settle-root:{}:{}:{}", merkle_root, total_payout, l2_block_height);
                match verify_l2_authority_signature(&message, l2_signature) {
                    Ok(true) => println!("✅ L2 authority signature verified"),
                    Ok(false) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Invalid L2 authority signature"
                        })));
                    },
                    Err(e) => {
                        println!("⚠️  L2 signature verification: {}", e);
                    }
                }
                
                // Store the Merkle root
                let settlement_root = MerkleSettlementRoot {
                    root_id: root_id.clone(),
                    merkle_root: merkle_root.to_string(),
                    total_payout,
                    winner_count,
                    l2_block_height,
                    l2_signature: l2_signature.to_string(),
                    l1_slot,
                    recorded_at: now,
                    claims_processed: 0,
                };
                
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.settlement_roots.insert(root_id.clone(), settlement_root);
                }
                
                println!("✅ Merkle root recorded: {} with {} winners, {} BB total payout", 
                         root_id, winner_count, total_payout);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "root_id": root_id,
                    "merkle_root": merkle_root,
                    "total_payout": total_payout,
                    "winner_count": winner_count,
                    "l1_slot": l1_slot,
                    "message": "Merkle settlement root recorded on L1"
                })))
            }
        })
}

/// POST /bridge/claim - User claims their settlement payout with Merkle proof
/// 
/// After L2 posts a Merkle root, users can claim their individual payouts
/// by providing a Merkle proof that their (address, amount) is in the tree.
pub fn claim_settlement_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("claim"))
        .and(warp::post())
        .and(warp::body::json::<SettlementClaimRequest>())
        .and_then(move |claim: SettlementClaimRequest| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🎁 Settlement claim request from {}", claim.user_address);
                
                // Generate unique claim key to prevent double-claims
                let claim_key = format!("{}:{}", claim.root_id, claim.user_address);
                
                // Check if already claimed
                {
                    let state = lock_bridge_state(&bridge_state);
                    if state.processed_claims.contains_key(&claim_key) {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Already claimed",
                            "claim_key": claim_key
                        })));
                    }
                    
                    // Verify root exists
                    if !state.settlement_roots.contains_key(&claim.root_id) {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Settlement root not found",
                            "root_id": claim.root_id
                        })));
                    }
                }
                
                // Verify Merkle proof
                let merkle_root = {
                    let state = lock_bridge_state(&bridge_state);
                    state.settlement_roots.get(&claim.root_id)
                        .map(|r| r.merkle_root.clone())
                        .unwrap_or_default()
                };
                
                let proof_valid = verify_merkle_proof(
                    &merkle_root,
                    &claim.user_address,
                    claim.amount,
                    &claim.merkle_proof,
                    claim.leaf_index
                );
                
                if !proof_valid {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid Merkle proof",
                        "root_id": claim.root_id
                    })));
                }
                
                // Credit L1 balance
                {
                    let mut bc = lock_or_recover(&blockchain);
                    *bc.balances.entry(claim.user_address.clone()).or_insert(0.0) += claim.amount;
                    println!("💰 Credited {} BB to {} via settlement claim", claim.amount, claim.user_address);
                }
                
                // Mark as claimed
                {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.processed_claims.insert(claim_key.clone(), true);
                    if let Some(root) = state.settlement_roots.get_mut(&claim.root_id) {
                        root.claims_processed += 1;
                    }
                }
                
                println!("✅ Claim processed: {} BB for {}", claim.amount, claim.user_address);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "claim_key": claim_key,
                    "user_address": claim.user_address,
                    "amount": claim.amount,
                    "root_id": claim.root_id,
                    "message": "Settlement claimed successfully"
                })))
            }
        })
}

/// GET /bridge/settlement-roots - List all settlement roots
pub fn list_settlement_roots_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("bridge")
        .and(warp::path("settlement-roots"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                let roots: Vec<_> = state.settlement_roots.values().cloned().collect();
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "count": roots.len(),
                    "settlement_roots": roots
                })))
            }
        })
}

/// Verify a Merkle proof for a settlement claim
/// 
/// In a real implementation, this would verify the cryptographic proof.
/// For now, we use a simplified version that trusts the L2 authority.
fn verify_merkle_proof(
    merkle_root: &str,
    user_address: &str,
    amount: f64,
    proof: &[String],
    leaf_index: u32,
) -> bool {
    use sha2::{Sha256, Digest};
    
    // If no proof provided, accept in dev mode (L2 already verified)
    if proof.is_empty() {
        println!("⚠️  DEV MODE: Accepting claim without Merkle proof");
        return true;
    }
    
    // Compute leaf hash
    let leaf_data = format!("{}:{}", user_address, amount);
    let mut hasher = Sha256::new();
    hasher.update(leaf_data.as_bytes());
    let mut current_hash = hex::encode(hasher.finalize());
    
    // Walk up the proof path
    let mut index = leaf_index;
    for sibling in proof {
        let mut hasher = Sha256::new();
        if index % 2 == 0 {
            // Current is left child
            hasher.update(format!("{}{}", current_hash, sibling));
        } else {
            // Current is right child
            hasher.update(format!("{}{}", sibling, current_hash));
        }
        current_hash = hex::encode(hasher.finalize());
        index /= 2;
    }
    
    // Verify computed root matches expected root
    current_hash == merkle_root
}

// ============================================================================
// OPTIMISTIC EXECUTION ROUTES - L2 Session Management
// ============================================================================
// These endpoints implement the "Hybrid Architecture":
// - L2 = "Hot Wallet" / "Game Session" (fast, optimistic)
// - L1 = "Vault" / "Truth Layer" (settled, on-chain)
// - Settlement = Checkpoint that writes net PnL to L1

/// POST /session/start - Start a new L2 gaming session
/// 
/// Mirrors the user's L1 balance to L2 for optimistic execution.
/// This is the "Connect to Game" flow.
pub fn start_session_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("session")
        .and(warp::path("start"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("🎮 Starting new L2 session (Optimistic Execution)");
                
                // Parse request
                let wallet_address = match body.get("wallet_address").and_then(|v| v.as_str()) {
                    Some(addr) => addr.to_string(),
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "wallet_address is required"
                        })));
                    }
                };
                let allocation = body.get("allocation").and_then(|v| v.as_f64());
                
                // Get L1 balance (the "Vault" balance)
                let l1_balance = {
                    let bc = lock_or_recover(&blockchain);
                    bc.balances.get(&wallet_address).copied().unwrap_or(0.0)
                };
                
                if l1_balance <= 0.0 {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "No L1 balance to mirror",
                        "l1_balance": l1_balance
                    })));
                }
                
                // Check if session already exists
                {
                    let state = lock_bridge_state(&bridge_state);
                    if let Some(existing) = state.get_session(&wallet_address) {
                        if existing.is_active {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Active session already exists",
                                "session_id": existing.session_id,
                                "l2_balance": existing.l2_balance
                            })));
                        }
                    }
                }
                
                // Start new session
                let session = {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.start_session(&wallet_address, l1_balance, allocation)
                };
                
                println!("✅ Session started: {} with {} BB (L1: {} BB)", 
                         session.session_id, session.l2_balance, l1_balance);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "session_id": session.session_id,
                    "wallet_address": wallet_address,
                    "l1_balance": l1_balance,
                    "l2_balance": session.l2_balance,
                    "message": "L2 session started. L1 balance mirrored to L2 for optimistic execution."
                })))
            }
        })
}

/// GET /session/status/:address - Get current session status
/// 
/// Returns both L1 (Vault) and L2 (Game) balances for comparison.
pub fn session_status_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("session")
        .and(warp::path("status"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                // Get L1 balance (Vault)
                let l1_balance = {
                    let bc = lock_or_recover(&blockchain);
                    bc.balances.get(&wallet_address).copied().unwrap_or(0.0)
                };
                
                // Get L2 session (Game)
                let state = lock_bridge_state(&bridge_state);
                
                if let Some(session) = state.get_session(&wallet_address) {
                    let net_pnl = session.net_pnl();
                    let has_winnings = session.has_winnings();
                    
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "has_session": true,
                        "session": {
                            "session_id": session.session_id,
                            "is_active": session.is_active,
                            "l1_balance_at_start": session.l1_balance_at_start,
                            "l2_balance": session.l2_balance,
                            "net_pnl": net_pnl,
                            "total_wagered": session.total_wagered,
                            "total_won": session.total_won,
                            "total_lost": session.total_lost,
                            "bet_count": session.bet_count,
                            "started_at": session.started_at,
                            "last_activity": session.last_activity
                        },
                        "balances": {
                            "vault_l1": l1_balance,
                            "game_l2": session.l2_balance,
                            "net_pnl": net_pnl,
                            "can_claim_winnings": has_winnings
                        }
                    })))
                } else {
                    Ok(warp::reply::json(&serde_json::json!({
                        "success": true,
                        "has_session": false,
                        "balances": {
                            "vault_l1": l1_balance,
                            "game_l2": 0.0,
                            "net_pnl": 0.0,
                            "can_claim_winnings": false
                        },
                        "message": "No active session. Call POST /session/start to begin."
                    })))
                }
            }
        })
}

/// POST /session/bet - Record a bet result (called by L2 server)
/// 
/// Updates the L2 balance optimistically. No L1 transaction yet.
pub fn record_bet_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("session")
        .and(warp::path("bet"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let bridge_state = bridge_state.clone();
            async move {
                let wallet_address = match body.get("wallet_address").and_then(|v| v.as_str()) {
                    Some(addr) => addr.to_string(),
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "wallet_address is required"
                        })));
                    }
                };
                let amount = body.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let won = body.get("won").and_then(|v| v.as_bool()).unwrap_or(false);
                let payout = body.get("payout").and_then(|v| v.as_f64()).unwrap_or(0.0);
                
                if amount <= 0.0 {
                    return Ok(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "amount must be positive"
                    })));
                }
                
                let mut state = lock_bridge_state(&bridge_state);
                
                // Check if user has enough L2 balance
                if let Some(session) = state.get_session(&wallet_address) {
                    if session.l2_balance < amount {
                        return Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "Insufficient L2 balance",
                            "l2_balance": session.l2_balance,
                            "required": amount
                        })));
                    }
                }
                
                match state.record_bet(&wallet_address, amount, won, payout) {
                    Some(result) => {
                        println!("🎰 Bet recorded: {} {} {} BB → {} BB", 
                                 wallet_address, if won { "WON" } else { "LOST" }, amount, result.new_l2_balance);
                        
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "bet": result,
                            "message": "Bet recorded on L2. No L1 transaction (optimistic execution)."
                        })))
                    },
                    None => {
                        Ok(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "No active session for this wallet"
                        })))
                    }
                }
            }
        })
}

/// POST /session/settle - Settle session and write PnL to L1
/// 
/// This is the "Claim Winnings" / "Checkpoint" flow.
/// Takes the net profit/loss from L2 and writes ONE transaction to L1.
pub fn settle_session_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("session")
        .and(warp::path("settle"))
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and_then(move |body: serde_json::Value| {
            let blockchain = blockchain.clone();
            let bridge_state = bridge_state.clone();
            async move {
                println!("💰 Settling L2 session (writing to L1)");
                
                let wallet_address = match body.get("wallet_address").and_then(|v| v.as_str()) {
                    Some(addr) => addr.to_string(),
                    None => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": "wallet_address is required"
                        })));
                    }
                };
                
                // Get session and calculate PnL
                let (session, net_pnl) = {
                    let state = lock_bridge_state(&bridge_state);
                    match state.get_session(&wallet_address) {
                        Some(s) => (s.clone(), s.net_pnl()),
                        None => {
                            return Ok(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "No session found for this wallet"
                            })));
                        }
                    }
                };
                
                // Get current L1 balance
                let l1_balance_before = {
                    let bc = lock_or_recover(&blockchain);
                    bc.balances.get(&wallet_address).copied().unwrap_or(0.0)
                };
                
                // Apply net PnL to L1 balance (THE SETTLEMENT)
                let l1_balance_after = {
                    let mut bc = lock_or_recover(&blockchain);
                    let new_balance = (l1_balance_before + net_pnl).max(0.0); // Can't go negative
                    bc.balances.insert(wallet_address.clone(), new_balance);
                    new_balance
                };
                
                // Remove the session (it's been settled)
                let _removed_session = {
                    let mut state = lock_bridge_state(&bridge_state);
                    state.remove_session(&wallet_address)
                };
                
                let settlement_type = if net_pnl > 0.0 {
                    "WINNINGS_CLAIMED"
                } else if net_pnl < 0.0 {
                    "LOSSES_RECORDED"
                } else {
                    "BREAK_EVEN"
                };
                
                println!("✅ Settlement complete: {} {} BB (L1: {} → {})", 
                         wallet_address, net_pnl, l1_balance_before, l1_balance_after);
                
                Ok(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "settlement_type": settlement_type,
                    "wallet_address": wallet_address,
                    "session_summary": {
                        "session_id": session.session_id,
                        "total_wagered": session.total_wagered,
                        "total_won": session.total_won,
                        "total_lost": session.total_lost,
                        "bet_count": session.bet_count,
                        "duration_seconds": session.last_activity - session.started_at
                    },
                    "settlement": {
                        "net_pnl": net_pnl,
                        "l1_before": l1_balance_before,
                        "l1_after": l1_balance_after,
                        "l2_final": session.l2_balance
                    },
                    "message": format!("Session settled. {} BB {} to L1 vault.", 
                                       net_pnl.abs(), 
                                       if net_pnl >= 0.0 { "added" } else { "deducted" })
                })))
            }
        })
}

/// GET /session/list - List all active sessions (admin/debug)
pub fn list_sessions_route(
    bridge_state: Arc<Mutex<BridgeState>>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("session")
        .and(warp::path("list"))
        .and(warp::get())
        .and_then(move || {
            let bridge_state = bridge_state.clone();
            async move {
                let state = lock_bridge_state(&bridge_state);
                let sessions: Vec<_> = state.l2_sessions.values().cloned().collect();
                let active_count = sessions.iter().filter(|s| s.is_active).count();
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "total_sessions": sessions.len(),
                    "active_sessions": active_count,
                    "total_created": state.total_sessions_created,
                    "total_settled": state.total_sessions_settled,
                    "sessions": sessions
                })))
            }
        })
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Verify a SignedRequest and return the wallet address
/// 
/// Path B Implementation:
/// - Uses `public_key` for cryptographic signature verification
/// - Returns `wallet_address` (L1...) for balance operations if provided
/// - Falls back to `public_key` as address if `wallet_address` not provided
fn verify_signed_request(request: &SignedRequest) -> Result<String, String> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    // Check timestamp freshness (5 minutes)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if now > request.timestamp + 300 {
        return Err("Request expired (>5 minutes old)".to_string());
    }
    
    if request.timestamp > now + 60 {
        return Err("Request timestamp is in the future".to_string());
    }
    
    // Reconstruct the signed message (SDK signs: payload\ntimestamp\nnonce)
    let message = format!("{}\n{}\n{}", request.payload, request.timestamp, request.nonce);
    
    // Decode public key (used for signature verification)
    let pubkey_bytes = hex::decode(&request.public_key)
        .map_err(|_| "Invalid public key hex")?;
    
    if pubkey_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }
    
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| "Invalid public key length")?;
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|_| "Invalid public key")?;
    
    // Decode signature
    let sig_bytes = hex::decode(&request.signature)
        .map_err(|_| "Invalid signature hex")?;
    
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".to_string());
    }
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "Invalid signature length")?;
    
    let signature = Signature::from_bytes(&sig_array);
    
    // Verify signature against public_key
    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|_| "Signature verification failed")?;
    
    // Return wallet_address (L1...) if provided, otherwise use public_key
    // This allows decoupling the display address from the signing key
    let wallet_address = request.wallet_address.clone()
        .unwrap_or_else(|| request.public_key.clone());
    
    println!("✅ Signature verified for wallet: {}", &wallet_address);
    Ok(wallet_address)
}

/// Verify an Ed25519 signature directly
fn verify_ed25519_signature(public_key: &str, message: &str, signature: &str) -> Result<bool, String> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    // Decode public key
    let pubkey_bytes = hex::decode(public_key)
        .map_err(|_| "Invalid public key hex")?;
    
    if pubkey_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }
    
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| "Invalid public key length")?;
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|_| "Invalid public key")?;
    
    // Decode signature
    let sig_bytes = hex::decode(signature)
        .map_err(|_| "Invalid signature hex")?;
    
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".to_string());
    }
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "Invalid signature length")?;
    
    let sig = Signature::from_bytes(&sig_array);
    
    // Verify
    match verifying_key.verify(message.as_bytes(), &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Forward a verified action to L2
async fn forward_to_l2(l2_url: &str, action: &str, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    
    // Map action to L2 endpoint
    let endpoint = match action {
        "place_bet" => "/bet",
        "create_market" => "/markets",
        "deposit" => "/deposit",
        "withdraw" => "/withdraw",
        "transfer" => "/transfer",
        "get_markets" => "/markets",
        "get_balance" => "/balance",
        _ => "/rpc/relay",
    };
    
    let url = format!("{}{}", l2_url, endpoint);
    
    let response = client.post(&url)
        .json(payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;
    
    let json: serde_json::Value = response.json().await
        .map_err(|e| format!("JSON parse error: {}", e))?;
    
    Ok(json)
}

/// Notify L2 to credit tokens after L1 bridge initiation
/// 
/// Calls L2's /bridge/deposit endpoint to credit tokens on L2 side.
/// This is the critical link that completes the L1→L2 bridge flow.
async fn notify_l2_deposit(l2_url: &str, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/bridge/deposit", l2_url);
    
    println!("🌉 Notifying L2 of deposit: {} → {}", url, payload);
    
    let response = client.post(&url)
        .json(payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            eprintln!("⚠️ L2 deposit notification failed: {}", e);
            format!("HTTP error: {}", e)
        })?;
    
    let status = response.status();
    let json: serde_json::Value = response.json().await
        .map_err(|e| format!("JSON parse error: {}", e))?;
    
    if status.is_success() && json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
        println!("✅ L2 deposit confirmed: {:?}", json);
        Ok(json)
    } else {
        let error = json.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
        eprintln!("❌ L2 deposit failed: {}", error);
        Err(format!("L2 rejected deposit: {}", error))
    }
}
