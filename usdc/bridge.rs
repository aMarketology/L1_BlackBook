//! USDC Bridge Endpoints
//! 
//! HTTP handlers for deposit notifications and withdrawal requests.

use serde::{Deserialize, Serialize};

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

/// Request to process a USDC deposit (from Oracle)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRequest {
    /// User's L1 address to receive BB tokens
    pub user_l1_address: String,
    
    /// User's Ethereum address that sent USDC
    pub user_eth_address: String,
    
    /// Amount of USDC deposited
    pub amount: f64,
    
    /// Ethereum transaction hash
    pub eth_tx_hash: String,
    
    /// Ethereum block number
    pub eth_block_number: u64,
    
    /// Number of confirmations
    pub confirmations: u32,
    
    /// Oracle's signature authorizing this deposit
    pub oracle_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositResponse {
    pub success: bool,
    pub deposit_id: Option<String>,
    pub bb_minted: Option<f64>,
    pub new_bb_balance: Option<f64>,
    pub error: Option<String>,
}

/// Request to withdraw USDC (from user)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// User's L1 address (must match authenticated user)
    pub user_l1_address: String,
    
    /// User's Ethereum address to receive USDC
    pub user_eth_address: String,
    
    /// Amount of BB to burn / USDC to receive
    pub amount: f64,
    
    /// User's signature authorizing the withdrawal
    pub user_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalResponse {
    pub success: bool,
    pub withdrawal_id: Option<String>,
    pub bb_burned: Option<f64>,
    pub estimated_completion: Option<String>,
    pub error: Option<String>,
}

/// Request to confirm withdrawal completion (from Oracle)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalConfirmRequest {
    /// Withdrawal ID to confirm
    pub withdrawal_id: String,
    
    /// Ethereum transaction hash of USDC transfer
    pub eth_tx_hash: String,
    
    /// Oracle's signature
    pub oracle_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalConfirmResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Get reserve statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveStatsResponse {
    pub total_usdc_locked: f64,
    pub total_bb_backed: f64,
    pub backing_ratio: f64,
    pub total_users: usize,
    pub pending_withdrawals: usize,
}

/// Get user's reserve info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReserveResponse {
    pub user_l1_address: String,
    pub usdc_locked: f64,
    pub bb_balance: f64,
    pub deposit_count: usize,
    pub withdrawal_count: usize,
}

// ============================================================================
// ENDPOINT HANDLERS (integrate with your router)
// ============================================================================

/// Verify Oracle signature on deposit request
pub fn verify_oracle_signature(request: &DepositRequest, oracle_pubkey: &str) -> bool {
    // TODO: Implement Ed25519 signature verification
    // For now, accept all (DEVELOPMENT ONLY)
    
    if oracle_pubkey.is_empty() {
        println!("⚠️  WARNING: Oracle pubkey not configured, skipping signature check");
        return true;
    }
    
    // Message format: "DEPOSIT:{user}:{amount}:{eth_tx}"
    let _message = format!(
        "DEPOSIT:{}:{}:{}",
        request.user_l1_address,
        request.amount,
        request.eth_tx_hash
    );
    
    // TODO: Verify signature against message using oracle_pubkey
    // ed25519_verify(oracle_pubkey, message, request.oracle_signature)
    
    true // Placeholder
}

/// Verify user signature on withdrawal request
pub fn verify_user_signature(request: &WithdrawalRequest, user_pubkey: &str) -> bool {
    // TODO: Implement Ed25519 signature verification
    
    if user_pubkey.is_empty() {
        return false;
    }
    
    // Message format: "WITHDRAW:{user}:{eth_address}:{amount}"
    let _message = format!(
        "WITHDRAW:{}:{}:{}",
        request.user_l1_address,
        request.user_eth_address,
        request.amount
    );
    
    // TODO: Verify signature
    
    true // Placeholder
}

// ============================================================================
// ROUTE REGISTRATION (example with axum)
// ============================================================================
// 
// Add these routes to your main router:
// 
// .route("/usdc/deposit", post(handle_deposit))
// .route("/usdc/withdraw", post(handle_withdrawal))
// .route("/usdc/confirm_withdrawal", post(handle_withdrawal_confirm))
// .route("/usdc/stats", get(handle_stats))
// .route("/usdc/user/:address", get(handle_user_reserve))
// 
// Handler implementations would look like:
// 
// async fn handle_deposit(
//     State(state): State<AppState>,
//     Json(req): Json<DepositRequest>,
// ) -> Result<Json<DepositResponse>, StatusCode> {
//     let mut reserve = state.usdc_reserve.lock().unwrap();
//     
//     // Verify oracle signature
//     if !verify_oracle_signature(&req, &reserve.oracle_pubkey.as_ref().unwrap_or(&String::new())) {
//         return Ok(Json(DepositResponse {
//             success: false,
//             error: Some("Invalid oracle signature".to_string()),
//             ..Default::default()
//         }));
//     }
//     
//     // Record deposit and mint BB
//     // ...
// }
