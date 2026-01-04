// ============================================================================
// WALLET ROUTES - Balance & Wallet Info (V2 - Pure Signature Auth)
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::integration::unified_auth::with_signature_auth;
use crate::unified_wallet::{to_l1_address, to_l2_address, strip_prefix};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

/// POST /wallet/balance - Get wallet balance (authenticated)
/// 
/// Request: SignedRequest with empty payload {}
/// Returns: balance in L1 tokens with L1/L2 addresses
pub fn balance_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("wallet")
        .and(warp::path("balance"))
        .and(warp::post())
        .and(with_signature_auth())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            async move {
                // Get the base address and format with L1/L2 prefixes
                let base_addr = strip_prefix(&wallet_address);
                let l1_addr = to_l1_address(&wallet_address);
                let l2_addr = to_l2_address(&wallet_address);
                
                let (available, locked, total) = {
                    let bc = lock_or_recover(&blockchain);
                    // Use L1 address for balance lookup (get_balance normalizes internally)
                    // Also check base_addr for backwards compatibility
                    let total = bc.get_balance(&l1_addr).max(bc.get_balance(&base_addr));
                    let locked = bc.get_locked_balance(&l1_addr).max(bc.get_locked_balance(&base_addr));
                    let available = (total - locked).max(0.0);
                    (available, locked, total)
                };
                
                println!("💰 Balance check: {} = {} BB (L1: {}, L2: {})", 
                         l1_addr, total, available, locked);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "wallet_address": base_addr,
                    "l1_address": l1_addr,
                    "l2_address": l2_addr,
                    "balance": total,
                    "l1_available": available,
                    "l2_locked": locked,
                    "message": format!("{} has {} BB available, {} BB locked in L2 sessions", l1_addr, available, locked)
                })))
            }
        })
}

/// POST /wallet/info - Get detailed wallet info (authenticated)
/// 
/// Request: SignedRequest with empty payload {}
/// Returns: balance, transaction history summary, L1/L2 addresses
pub fn wallet_info_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("wallet")
        .and(warp::path("info"))
        .and(warp::post())
        .and(with_signature_auth())
        .and_then(move |wallet_address: String| {
            let blockchain = blockchain.clone();
            async move {
                // Get the base address and format with L1/L2 prefixes
                let base_addr = strip_prefix(&wallet_address);
                let l1_addr = to_l1_address(&wallet_address);
                let l2_addr = to_l2_address(&wallet_address);
                
                let (available, locked, total, sent_count, received_count, total_sent, total_received) = {
                    let bc = lock_or_recover(&blockchain);
                    // Use L1 address for balance lookup, with fallback to base_addr
                    let total = bc.get_balance(&l1_addr).max(bc.get_balance(&base_addr));
                    let locked = bc.get_locked_balance(&l1_addr).max(bc.get_locked_balance(&base_addr));
                    let available = (total - locked).max(0.0);
                    
                    let mut sent_count = 0;
                    let mut received_count = 0;
                    let mut total_sent = 0.0;
                    let mut total_received = 0.0;
                    
                    for block in &bc.chain {
                        for tx in block.financial_txs.iter().chain(block.social_txs.iter()) {
                            // Match by base address (strip any prefix from stored addresses)
                            let tx_from = strip_prefix(&tx.from);
                            let tx_to = strip_prefix(&tx.to);
                            
                            if tx_from == base_addr {
                                sent_count += 1;
                                total_sent += tx.amount;
                            }
                            if tx_to == base_addr {
                                received_count += 1;
                                total_received += tx.amount;
                            }
                        }
                    }
                    
                    (available, locked, total, sent_count, received_count, total_sent, total_received)
                };
                
                println!("📋 Wallet info: {}", l1_addr);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "wallet": {
                        "base_address": base_addr,
                        "l1_address": l1_addr,
                        "l2_address": l2_addr,
                        "balance": {
                            "total": total,
                            "l1_available": available,
                            "l2_locked": locked
                        },
                        "transactions": {
                            "sent_count": sent_count,
                            "received_count": received_count,
                            "total_sent": total_sent,
                            "total_received": total_received
                        }
                    }
                })))
            }
        })
}
