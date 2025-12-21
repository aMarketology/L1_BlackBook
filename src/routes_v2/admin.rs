// ============================================================================
// ADMIN ROUTES - Token Minting & Protocol Upgrades
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::protocol::blockchain::EnhancedBlockchain;
// TODO: Re-enable when upgrade_manager is added to blockchain
// use crate::consensus::hot_upgrades::{ProtocolVersion, UpgradeStatus};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

/// Mint request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintRequest {
    pub to: String,
    pub amount: f64,
}

/// POST /admin/mint - Mint new tokens (OPEN ACCESS - DEVELOPMENT ONLY)
/// 
/// Request:
/// ```json
/// {
///   "to": "L1BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
///   "amount": 10000.0
/// }
/// ```
/// 
/// Accepts:
/// - L1 address format: L1XXXX...XXXX (42 chars: L1 + 40 hex)
/// - Legacy format: L1XXXXXXXXXXXXXX (16 chars: L1 + 14 hex)
/// - bb1_ format: bb1_...
/// - Raw public key hex (64 chars)
/// 
/// Response:
/// ```json
/// {
///   "success": true,
///   "transaction": {
///     "id": "uuid",
///     "to": "L1...",
///     "amount": 10000.0,
///     "new_balance": 10000.0
///   }
/// }
/// ```
pub fn mint_tokens_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("admin" / "mint")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: MintRequest| {
            let blockchain = blockchain.clone();
            async move {
                // Validate input
                if request.amount <= 0.0 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Amount must be positive"
                    })));
                }
                
                if request.to.is_empty() {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Recipient address is required"
                    })));
                }
                
                // Validate address format - accepts L1_/L2_ format (43 chars) and legacy formats
                let is_l1_format_new = request.to.starts_with("L1_") && request.to.len() == 43;  // L1_ format (160-bit)
                let is_l2_format_new = request.to.starts_with("L2_") && request.to.len() == 43;  // L2_ format (160-bit)
                let is_l1_format_no_underscore = request.to.starts_with("L1") && !request.to.starts_with("L1_") && request.to.len() == 42;  // Legacy no underscore
                let is_l2_format_no_underscore = request.to.starts_with("L2") && !request.to.starts_with("L2_") && request.to.len() == 42;  // Legacy no underscore
                let is_l1_format_legacy = request.to.starts_with("L1_") && request.to.len() == 17;  // Legacy format (L1_ + 14 chars)
                let is_l2_format_legacy = request.to.starts_with("L2_") && request.to.len() == 17;  // Legacy L2 format
                let is_bb_format = request.to.starts_with("bb1_") || request.to.starts_with("bb2_");
                let is_pubkey_hex = request.to.len() == 64 && request.to.chars().all(|c| c.is_ascii_hexdigit());
                
                if !is_l1_format_new && !is_l2_format_new && !is_l1_format_no_underscore && !is_l2_format_no_underscore && !is_l1_format_legacy && !is_l2_format_legacy && !is_bb_format && !is_pubkey_hex {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid address format (must be L1/L2 address, bb1_/bb2_ format, or raw public key)"
                    })));
                }
                
                // Mint tokens using system account
                let (tx_id, new_balance) = {
                    let mut bc = lock_or_recover(&blockchain);
                    
                    // Create transaction from "system" account (mints new tokens)
                    let tx_id = bc.create_transaction(
                        "system".to_string(),
                        request.to.clone(),
                        request.amount
                    );
                    
                    // Mine immediately
                    let _ = bc.mine_pending_transactions("admin_mint".to_string());
                    
                    let balance = bc.get_balance(&request.to);
                    
                    (tx_id, balance)
                };
                
                println!("🏦 ADMIN MINT: {} BB -> {} (new balance: {} BB, tx: {})", 
                         request.amount, &request.to, 
                         new_balance, &tx_id[..8]);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "transaction": {
                        "id": tx_id,
                        "to": request.to,
                        "amount": request.amount,
                        "new_balance": new_balance
                    }
                })))
            }
        })
}

// ============================================================================
// PROTOCOL UPGRADE ROUTES - Hot Upgrades Without Downtime
// ============================================================================
// TODO: Re-enable when upgrade_manager is integrated into EnhancedBlockchain

/*
/// Proposal request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeUpgradeRequest {
    pub name: String,
    pub version: String,  // "1.1.0" format
    pub activation_block: u64,
    pub proposer: String,
    pub feature_flags: Vec<String>,
}

/// Vote request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteUpgradeRequest {
    pub proposal_id: String,
    pub voter: String,
    pub approve: bool,
}

/// POST /admin/upgrades/propose - Propose a protocol upgrade
pub fn propose_upgrade_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("admin" / "upgrades" / "propose")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: ProposeUpgradeRequest| {
            let blockchain = blockchain.clone();
            async move {
                let mut bc = lock_or_recover(&blockchain);
                
                // Parse version
                let parts: Vec<&str> = request.version.split('.').collect();
                if parts.len() != 3 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Version must be in format X.Y.Z"
                    })));
                }
                
                let version = ProtocolVersion::new(
                    parts[0].parse().unwrap_or(1),
                    parts[1].parse().unwrap_or(0),
                    parts[2].parse().unwrap_or(0),
                );
                
                match bc.upgrade_manager.propose(
                    request.name.clone(),
                    version,
                    request.activation_block,
                    request.proposer.clone()
                ) {
                    Ok(proposal_id) => {
                        // Add feature flags
                        if let Some(proposal) = bc.upgrade_manager.pending().iter()
                            .find(|p| p.id == proposal_id) {
                            
                            println!("🎯 UPGRADE PROPOSED: {} v{} (activation: block {})", 
                                     request.name, request.version, request.activation_block);
                            
                            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": true,
                                "proposal": {
                                    "id": proposal_id,
                                    "name": proposal.name,
                                    "version": proposal.target_version.to_string(),
                                    "activation_block": proposal.activation_block,
                                    "status": "Proposed",
                                    "voting_deadline": proposal.voting_deadline.to_rfc3339(),
                                }
                            })))
                        } else {
                            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": "Proposal created but not found"
                            })))
                        }
                    }
                    Err(e) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })))
                    }
                }
            }
        })
}

/// POST /admin/upgrades/vote - Vote on a protocol upgrade
pub fn vote_upgrade_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("admin" / "upgrades" / "vote")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: VoteUpgradeRequest| {
            let blockchain = blockchain.clone();
            async move {
                let mut bc = lock_or_recover(&blockchain);
                
                // Assume 3 validators for now (Alice, Bob, Carol)
                let total_validators = 3;
                
                match bc.upgrade_manager.vote(
                    &request.proposal_id,
                    request.voter.clone(),
                    request.approve,
                    total_validators
                ) {
                    Ok(status) => {
                        let status_str = match status {
                            UpgradeStatus::Proposed => "Proposed",
                            UpgradeStatus::Approved => "Approved",
                            UpgradeStatus::Rejected => "Rejected",
                            UpgradeStatus::Activated => "Activated",
                        };
                        
                        println!("🗳️  UPGRADE VOTE: {} voted {} on proposal {}", 
                                 request.voter, 
                                 if request.approve { "YES" } else { "NO" },
                                 &request.proposal_id[..8]);
                        
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "status": status_str,
                            "voter": request.voter
                        })))
                    }
                    Err(e) => {
                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": e
                        })))
                    }
                }
            }
        })
}

/// GET /admin/upgrades - List all upgrade proposals
pub fn list_upgrades_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("admin" / "upgrades")
        .and(warp::get())
        .and_then(move || {
            let blockchain = blockchain.clone();
            async move {
                let bc = lock_or_recover(&blockchain);
                
                let pending: Vec<_> = bc.upgrade_manager.pending().iter().map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "name": p.name,
                        "version": p.target_version.to_string(),
                        "activation_block": p.activation_block,
                        "proposer": p.proposer,
                        "status": match p.status {
                            UpgradeStatus::Proposed => "Proposed",
                            UpgradeStatus::Approved => "Approved",
                            UpgradeStatus::Rejected => "Rejected",
                            UpgradeStatus::Activated => "Activated",
                        },
                        "votes_for": p.votes_for.len(),
                        "votes_against": p.votes_against.len(),
                        "voting_deadline": p.voting_deadline.to_rfc3339(),
                    })
                }).collect();
                
                let history: Vec<_> = bc.upgrade_manager.history().iter().map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "version": p.target_version.to_string(),
                        "activation_block": p.activation_block,
                        "activated_at": p.proposed_at.to_rfc3339(),
                    })
                }).collect();
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "current_version": bc.upgrade_manager.version.to_string(),
                    "pending": pending,
                    "history": history,
                    "enabled_features": bc.upgrade_manager.features.enabled_list(),
                })))
            }
        })
}

/// GET /admin/upgrades/status - Get current protocol status
pub fn upgrade_status_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("admin" / "upgrades" / "status")
        .and(warp::get())
        .and_then(move || {
            let blockchain = blockchain.clone();
            async move {
                let bc = lock_or_recover(&blockchain);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "version": bc.upgrade_manager.version.to_string(),
                    "features": bc.upgrade_manager.features.enabled_list(),
                    "current_block": bc.chain.len(),
                    "pending_proposals": bc.upgrade_manager.pending().len(),
                })))
            }
        })
}
*/