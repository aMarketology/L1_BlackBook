// ============================================================================
// TRANSFER ROUTES - Token Transfers (V2 - Pure Signature Auth)
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::integration::unified_auth::SignedRequest;
use crate::runtime::SharedPoHService;

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

/// Transfer payload embedded in SignedRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPayload {
    pub to: String,
    pub amount: f64,
    #[serde(default)]
    pub memo: Option<String>,
}

/// POST /transfer - Transfer tokens (authenticated)
/// 
/// Request: SignedRequest with TransferPayload in payload field
/// ```json
/// {
///   "public_key": "...",
///   "payload": "{\"to\":\"recipient_address\",\"amount\":10.5}",
///   "timestamp": 1234567890,
///   "nonce": "random_nonce",
///   "signature": "..."
/// }
/// ```
pub fn transfer_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("transfer")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            async move {
                // 1. Verify signature
                let from_address = match request.verify() {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature verification failed: {}", e)
                        })));
                    }
                };
                
                // 2. Parse transfer payload
                let transfer: TransferPayload = match request.parse_payload() {
                    Ok(t) => t,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Invalid transfer payload: {}", e)
                        })));
                    }
                };
                
                // 3. Validate transfer
                if transfer.amount <= 0.0 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }
                
                if transfer.to.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Recipient address is required"
                    })));
                }
                
                if from_address == transfer.to {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Cannot transfer to yourself"
                    })));
                }
                
                // 4. Execute transfer
                let (tx_id, from_balance, to_balance) = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Check balance
                    let current_balance = bc.get_balance(&from_address);
                    println!("💳 Transfer check: from={}, balance={}", &from_address[..14], current_balance);
                    
                    if current_balance < transfer.amount {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Insufficient balance: {} L1 (need {} L1)", 
                                           current_balance, transfer.amount)
                        })));
                    }
                    
                    // Create transaction
                    let tx_id = bc.create_transaction(
                        from_address.clone(),
                        transfer.to.clone(),
                        transfer.amount
                    );
                    
                    // Mine immediately (single-transaction block)
                    let _ = bc.mine_pending_transactions("transfer_miner".to_string());
                    
                    let from_bal = bc.get_balance(&from_address);
                    let to_bal = bc.get_balance(&transfer.to);
                    
                    (tx_id, from_bal, to_bal)
                };
                
                // Enhanced logging with L2 detection
                let from_layer = if from_address.starts_with("L2_") { "L2" } else { "L1" };
                let to_layer = if transfer.to.starts_with("L2_") { "L2" } else { "L1" };
                
                if from_layer == "L2" || to_layer == "L2" {
                    println!("🌉 CROSS-LAYER Transfer Detected!");
                    println!("   From: {} ({})", &from_address, from_layer);
                    println!("   To:   {} ({})", &transfer.to, to_layer);
                    println!("   Amount: {} BB", transfer.amount);
                    println!("   TX: {}", &tx_id[..16]);
                } else {
                    println!("💸 Transfer: {} -> {} : {} BB (tx: {})", 
                             &from_address[..14], &transfer.to[..14.min(transfer.to.len())], 
                             transfer.amount, &tx_id[..8]);
                }
                
                // Log final balances
                println!("   📊 Balances after: from={} BB, to={} BB", from_balance, to_balance);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "transaction": {
                        "id": tx_id,
                        "from": from_address,
                        "to": transfer.to,
                        "amount": transfer.amount,
                        "memo": transfer.memo
                    },
                    "balances": {
                        "from": from_balance,
                        "to": to_balance
                    }
                })))
            }
        })
}

/// POST /transfer/poh - Transfer with PoH timestamping (authenticated)
/// 
/// Enhanced version that records the transaction in the PoH clock
/// for cryptographic ordering proof.
pub fn transfer_poh_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    poh_service: SharedPoHService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("transfer" / "poh")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            let poh_service = poh_service.clone();
            async move {
                // 1. Verify signature
                let from_address = match request.verify() {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Signature verification failed: {}", e)
                        })));
                    }
                };
                
                // 2. Parse transfer payload
                let transfer: TransferPayload = match request.parse_payload() {
                    Ok(t) => t,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Invalid transfer payload: {}", e)
                        })));
                    }
                };
                
                // 3. Get PoH timestamp BEFORE processing
                let (poh_slot, poh_hash) = {
                    let poh = poh_service.read();
                    (poh.current_slot, poh.current_hash.clone())
                };
                
                // 4. Validate and execute transfer
                if transfer.amount <= 0.0 || transfer.to.is_empty() || from_address == transfer.to {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid transfer parameters"
                    })));
                }
                
                let (tx_id, from_balance, to_balance) = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    let current_balance = bc.get_balance(&from_address);
                    if current_balance < transfer.amount {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Insufficient balance: {} BB", current_balance)
                        })));
                    }
                    
                    let tx_id = bc.create_transaction(
                        from_address.clone(),
                        transfer.to.clone(),
                        transfer.amount
                    );
                    
                    // 5. Queue transaction ID into PoH clock (ordering proof)
                    {
                        let mut poh = poh_service.write();
                        poh.queue_transaction(tx_id.clone());
                    }
                    
                    let _ = bc.mine_pending_transactions("poh_miner".to_string());
                    (tx_id, bc.get_balance(&from_address), bc.get_balance(&transfer.to))
                };
                
                println!("⏰ PoH Transfer: {} -> {} : {} BB (slot: {}, tx: {})", 
                         &from_address[..14], &transfer.to[..14.min(transfer.to.len())], 
                         transfer.amount, poh_slot, &tx_id[..8]);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "transaction": {
                        "id": tx_id,
                        "from": from_address,
                        "to": transfer.to,
                        "amount": transfer.amount,
                        "poh_slot": poh_slot,
                        "poh_hash": &poh_hash[..16],
                        "ordering_proof": true
                    },
                    "balances": {
                        "from": from_balance,
                        "to": to_balance
                    }
                })))
            }
        })
}

/// POST /transactions - Get transaction history (authenticated)
/// 
/// Request: SignedRequest with empty payload {}
pub fn transactions_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("transactions")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
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
                
                let transactions: Vec<serde_json::Value> = {
                    let bc = lock_or_recover(&blockchain);
                    bc.chain.iter()
                        .flat_map(|block| {
                            block.financial_txs.iter()
                                .chain(block.social_txs.iter())
                                .filter(|tx| tx.from == wallet_address || tx.to == wallet_address)
                                .map(|tx| serde_json::json!({
                                    "id": tx.id,
                                    "from": tx.from,
                                    "to": tx.to,
                                    "amount": tx.amount,
                                    "timestamp": tx.timestamp,
                                    "direction": if tx.from == wallet_address { "sent" } else { "received" }
                                }))
                        })
                        .collect()
                };
                
                println!("📜 Transactions: {}... ({} txs)", 
                         &wallet_address[..16.min(wallet_address.len())], transactions.len());
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "wallet_address": wallet_address,
                    "transactions": transactions,
                    "count": transactions.len()
                })))
            }
        })
}
