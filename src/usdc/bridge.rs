//! USDC Bridge Endpoints
//! 
//! HTTP handlers for deposit notifications and withdrawal requests.

use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};

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

/// Verify Ed25519 signature helper
fn verify_ed25519_signature(pubkey_hex: &str, message: &[u8], signature_hex: &str) -> Result<bool, String> {
    // Decode public key
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| format!("Invalid pubkey hex: {}", e))?;
    
    if pubkey_bytes.len() != 32 {
        return Err(format!("Invalid pubkey length: {} (expected 32)", pubkey_bytes.len()));
    }
    
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| "Failed to convert pubkey to array")?;
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    // Decode signature
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    
    if sig_bytes.len() != 64 {
        return Err(format!("Invalid signature length: {} (expected 64)", sig_bytes.len()));
    }
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "Failed to convert signature to array")?;
    
    let signature = Signature::from_bytes(&sig_array);
    
    // Verify
    match verifying_key.verify(message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Derive L1 address from public key (SHA256 → first 20 bytes → uppercase hex)
fn derive_address_from_pubkey(pubkey_hex: &str) -> Result<String, String> {
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| format!("Invalid pubkey hex: {}", e))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_bytes);
    let hash = hasher.finalize();
    
    let address_bytes = &hash[..20];
    let address = format!("L1_{}", hex::encode(address_bytes).to_uppercase());
    
    Ok(address)
}

/// Verify Oracle signature on deposit request (PRODUCTION)
pub fn verify_oracle_signature(request: &DepositRequest, oracle_pubkey: &str) -> bool {
    if oracle_pubkey.is_empty() {
        println!("⚠️  WARNING: Oracle pubkey not configured, skipping signature check");
        return true;
    }
    
    if request.oracle_signature.is_empty() {
        println!("❌ [USDC Bridge] Deposit missing oracle signature");
        return false;
    }
    
    // Message format: "DEPOSIT:{user}:{amount}:{eth_tx}"
    let message = format!(
        "DEPOSIT:{}:{}:{}",
        request.user_l1_address,
        request.amount,
        request.eth_tx_hash
    );
    
    match verify_ed25519_signature(oracle_pubkey, message.as_bytes(), &request.oracle_signature) {
        Ok(true) => {
            println!("✅ [USDC Bridge] Oracle signature verified for deposit");
            true
        }
        Ok(false) => {
            println!("❌ [USDC Bridge] Oracle signature verification FAILED");
            false
        }
        Err(e) => {
            println!("❌ [USDC Bridge] Oracle signature error: {}", e);
            false
        }
    }
}

/// Verify user signature on withdrawal request (PRODUCTION)
pub fn verify_user_signature(request: &WithdrawalRequest, user_pubkey: &str) -> bool {
    if user_pubkey.is_empty() {
        println!("❌ [USDC Bridge] User pubkey not provided for withdrawal");
        return false;
    }
    
    if request.user_signature.is_empty() {
        println!("❌ [USDC Bridge] Withdrawal missing user signature");
        return false;
    }
    
    // Message format: "WITHDRAW:{user}:{eth_address}:{amount}"
    let message = format!(
        "WITHDRAW:{}:{}:{}",
        request.user_l1_address,
        request.user_eth_address,
        request.amount
    );
    
    // Verify pubkey derives to claimed address
    match derive_address_from_pubkey(user_pubkey) {
        Ok(derived) if derived == request.user_l1_address => {
            println!("✅ [USDC Bridge] User pubkey matches claimed address");
        }
        Ok(derived) => {
            println!("❌ [USDC Bridge] Address mismatch: derived={}, claimed={}", 
                derived, request.user_l1_address);
            return false;
        }
        Err(e) => {
            println!("❌ [USDC Bridge] Address derivation error: {}", e);
            return false;
        }
    }
    
    match verify_ed25519_signature(user_pubkey, message.as_bytes(), &request.user_signature) {
        Ok(true) => {
            println!("✅ [USDC Bridge] User signature verified for withdrawal");
            true
        }
        Ok(false) => {
            println!("❌ [USDC Bridge] User signature verification FAILED");
            false
        }
        Err(e) => {
            println!("❌ [USDC Bridge] User signature error: {}", e);
            false
        }
    }
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
