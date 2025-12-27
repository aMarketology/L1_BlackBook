// ============================================================================
// RPC ROUTES - Health, Stats, JSON-RPC, PoH Status (V2 - Pure Signature Auth)
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::runtime::{SharedPoHService, verify_poh_chain, PoHService};

/// Helper to recover from poisoned locks
/// When a thread panics while holding a Mutex, the lock becomes "poisoned"
/// This helper recovers by extracting the inner data
fn lock_or_recover<'a>(
    mutex: &'a Mutex<EnhancedBlockchain>
) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("⚠️ Recovering from poisoned lock");
            poisoned.into_inner()
        }
    }
}

/// GET /health - Health check (public)
pub fn health_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("health")
        .and(warp::get())
        .and_then(|| async {
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "success": true,
                "status": "healthy",
                "service": "Layer1 Blockchain",
                "version": "2.0.0",
                "auth": "signature-based (Ed25519)",
                "features": ["PoH", "Two-Lane Tx", "L1-L2 Bridge"],
                "timestamp": chrono::Utc::now().to_rfc3339()
            })))
        })
}

/// GET /poh/status - Proof of History clock status (public)
pub fn poh_status_route(
    poh_service: SharedPoHService
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("poh")
        .and(warp::path("status"))
        .and(warp::get())
        .and_then(move || {
            let poh = poh_service.clone();
            async move {
                let status = {
                    let poh_lock = poh.read();
                    serde_json::json!({
                        "current_slot": poh_lock.current_slot,
                        "current_epoch": poh_lock.current_epoch,
                        "num_hashes": poh_lock.num_hashes,
                        "current_hash": &poh_lock.current_hash[..16],  // First 16 chars
                        "is_running": poh_lock.is_running,
                        "total_slots_produced": poh_lock.total_slots_produced,
                        "genesis_timestamp": poh_lock.genesis_timestamp,
                        "pending_tx_mix_count": poh_lock.pending_tx_mix.len(),
                        "config": {
                            "slot_duration_ms": poh_lock.config.slot_duration_ms,
                            "hashes_per_tick": poh_lock.config.hashes_per_tick,
                            "ticks_per_slot": poh_lock.config.ticks_per_slot,
                            "slots_per_epoch": poh_lock.config.slots_per_epoch
                        }
                    })
                };
                
                println!("⏰ PoH status requested");
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "poh": status,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })))
            }
        })
}

/// GET /poh/verify - Verify current PoH chain integrity (public)
/// 
/// This endpoint verifies that the Proof of History chain is valid,
/// proving that all entries were computed sequentially.
pub fn poh_verify_route(
    poh_service: SharedPoHService
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("poh")
        .and(warp::path("verify"))
        .and(warp::get())
        .and_then(move || {
            let poh = poh_service.clone();
            async move {
                let (is_valid, entries_count, current_slot, current_hash, genesis_hash) = {
                    let poh_lock = poh.read();
                    let entries = poh_lock.get_current_entries();
                    let genesis = PoHService::get_genesis_hash();
                    
                    // Verify the chain
                    let valid = if entries.is_empty() {
                        true
                    } else {
                        verify_poh_chain(&entries, &genesis)
                    };
                    
                    (valid, entries.len(), poh_lock.current_slot, poh_lock.current_hash.clone(), genesis)
                };
                
                println!("🔍 PoH verification requested - Valid: {}, Entries: {}", is_valid, entries_count);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "verification": {
                        "is_valid": is_valid,
                        "entries_verified": entries_count,
                        "current_slot": current_slot,
                        "current_hash_prefix": &current_hash[..16.min(current_hash.len())],
                        "genesis_hash_prefix": &genesis_hash[..16.min(genesis_hash.len())],
                        "message": if is_valid {
                            "PoH chain integrity verified - entries computed sequentially"
                        } else {
                            "PoH chain integrity FAILED - possible tampering detected"
                        }
                    },
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })))
            }
        })
}

/// GET /stats - Blockchain statistics (public)
pub fn stats_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("stats")
        .and(warp::get())
        .and_then(move || {
            let blockchain = blockchain.clone();
            async move {
                let stats = {
                    let bc = lock_or_recover(&blockchain);
                    serde_json::json!({
                        "total_blocks": bc.chain.len(),
                        "pending_transactions": bc.pending_transactions.len(),
                        "total_wallets": bc.balances.len(),
                        "total_supply": bc.balances.values().sum::<f64>(),
                        "mining_reward": bc.mining_reward,
                        "daily_jackpot": bc.daily_jackpot,
                        "chain_valid": bc.is_chain_valid()
                    })
                };
                
                println!("📊 Stats requested");
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "stats": stats,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })))
            }
        })
}

/// GET /balance/{address} - Get L1 balance only (public)
/// 
/// LAYER 1 RESTRICTION:
/// - ONLY accepts L1_ prefixed addresses
/// - L2_ addresses: Rejected (query L2 server instead)
/// - No prefix: Rejected (must specify L1_ explicitly)
/// 
/// This ensures proper layer separation:
/// - L1 server = L1 balances only (real money)
/// - L2 server = L2 balances only (gaming/betting)
pub fn public_balance_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use crate::unified_wallet::strip_prefix;
    
    warp::path("balance")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and_then(move |address: String| {
            let blockchain = blockchain.clone();
            async move {
                // LAYER 1 ONLY: Reject anything that's not L1_ prefixed
                if !address.starts_with("L1_") {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid address format",
                        "message": if address.starts_with("L2_") {
                            "L2 balances must be queried from L2 server"
                        } else {
                            "Address must start with L1_ prefix (43 chars total)"
                        },
                        "expected_format": "L1_<40_hex_chars>",
                        "example": "L1_ALICE000000001"
                    })));
                }
                
                // Validate address length (L1_ + 40 hex = 43 chars)
                if address.len() != 43 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Invalid address length",
                        "message": "L1 address must be exactly 43 characters (L1_ + 40 hex)",
                        "received_length": address.len()
                    })));
                }
                
                let (balance, layer) = match blockchain.lock() {
                    Ok(bc) => {
                        // Strip L1_ prefix and query balance
                        let base_addr = strip_prefix(&address);
                        
                        // Check both formats for backward compatibility:
                        // 1. New format: just the hash (40 hex chars)
                        // 2. Old format: L1_<hash> (full address as key)
                        let balance = bc.get_balance(&base_addr).max(
                            bc.get_balance(&address)
                        );
                        
                        (balance, "L1")
                    },
                    Err(_) => (0.0, "Error")
                };
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "address": address,
                    "balance": balance,
                    "layer": layer
                })))
            }
        })
}

/// POST /rpc - JSON-RPC endpoint
pub fn rpc_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("rpc")
        .and(warp::path::end()) // Ensure exact match for /rpc
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |body: serde_json::Value| {
            let blockchain = blockchain.clone();
            async move {
                let method = body.get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                let id = body.get("id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                
                let params = body.get("params").cloned().unwrap_or(serde_json::json!([]));
                
                let result = match method {
                    // ============ Basic Chain Methods ============
                    "getBlockHeight" => {
                        let bc = lock_or_recover(&blockchain);
                        let latest_block = bc.chain.last();
                        match latest_block {
                            Some(block) => serde_json::json!({
                                "height": bc.chain.len(),
                                "blockhash": block.hash.clone(),
                                "slot": bc.current_slot,
                                "timestamp": block.timestamp
                            }),
                            None => serde_json::json!({
                                "height": 0,
                                "blockhash": "",
                                "slot": 0,
                                "timestamp": 0
                            })
                        }
                    },
                    "getBalance" => {
                        let address = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bc = lock_or_recover(&blockchain);
                        serde_json::json!(bc.get_balance(address))
                    },
                    "getTotalSupply" => {
                        let bc = lock_or_recover(&blockchain);
                        serde_json::json!(bc.balances.values().sum::<f64>())
                    },
                    "getWalletCount" => {
                        let bc = lock_or_recover(&blockchain);
                        serde_json::json!(bc.balances.len())
                    },
                    "getChainStats" => {
                        let bc = lock_or_recover(&blockchain);
                        serde_json::json!({
                            "block_height": bc.chain.len(),
                            "wallet_count": bc.balances.len(),
                            "total_supply": bc.balances.values().sum::<f64>(),
                            "pending_tx": bc.pending_transactions.len(),
                            "chain_valid": bc.is_chain_valid()
                        })
                    },
                    
                    // ============ Account Methods ============
                    "getAccounts" => {
                        let bc = lock_or_recover(&blockchain);
                        let accounts: Vec<_> = bc.balances.iter()
                            .map(|(addr, bal)| serde_json::json!({
                                "address": addr,
                                "balance": bal
                            }))
                            .collect();
                        serde_json::json!(accounts)
                    },
                    "getAccountInfo" => {
                        let address = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bc = lock_or_recover(&blockchain);
                        let balance = bc.get_balance(address);
                        let username = bc.address_to_username.get(address).cloned();
                        serde_json::json!({
                            "address": address,
                            "balance": balance,
                            "username": username,
                            "exists": bc.balances.contains_key(address)
                        })
                    },
                    
                    // ============ Transaction Methods ============
                    "getTransactions" => {
                        let address = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bc = lock_or_recover(&blockchain);
                        let txs: Vec<_> = bc.chain.iter()
                            .flat_map(|b| b.financial_txs.iter().chain(b.social_txs.iter()))
                            .filter(|tx| tx.from == address || tx.to == address)
                            .cloned()
                            .collect();
                        serde_json::json!(txs)
                    },
                    "getPendingTransactions" => {
                        let bc = lock_or_recover(&blockchain);
                        serde_json::json!(bc.pending_transactions)
                    },
                    
                    // ============ Block Methods ============
                    "getBlock" => {
                        let index = params.get(0)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        let bc = lock_or_recover(&blockchain);
                        if let Some(block) = bc.chain.get(index) {
                            serde_json::json!(block)
                        } else {
                            serde_json::json!(null)
                        }
                    },
                    "getLatestBlock" => {
                        let bc = lock_or_recover(&blockchain);
                        if let Some(block) = bc.chain.last() {
                            serde_json::json!(block)
                        } else {
                            serde_json::json!(null)
                        }
                    },
                    
                    // ============ Recent Blockhash Methods (Critical for Tx Validity) ============
                    // Solana-compatible: getRecentBlockhash returns hash client uses in tx
                    "getRecentBlockhash" => {
                        let bc = lock_or_recover(&blockchain);
                        let latest_block = bc.chain.last();
                        match latest_block {
                            Some(block) => serde_json::json!({
                                "blockhash": block.hash.clone(),
                                "feeCalculator": {
                                    "lamportsPerSignature": 5000  // 0.005 BB fee
                                },
                                "slot": block.slot,
                                "lastValidBlockHeight": block.index + 150  // Valid for ~150 slots
                            }),
                            None => serde_json::json!({
                                "error": "No blocks in chain"
                            })
                        }
                    },
                    // getLatestBlockhash (Solana v1.9+) - returns blockhash + last valid slot
                    "getLatestBlockhash" => {
                        let bc = lock_or_recover(&blockchain);
                        let latest_block = bc.chain.last();
                        let current_slot = bc.current_slot;
                        match latest_block {
                            Some(block) => serde_json::json!({
                                "value": {
                                    "blockhash": block.hash.clone(),
                                    "lastValidBlockHeight": block.index + 150
                                },
                                "context": {
                                    "slot": current_slot
                                }
                            }),
                            None => serde_json::json!({
                                "error": "No blocks in chain"
                            })
                        }
                    },
                    // isBlockhashValid - Check if blockhash is still recent enough
                    "isBlockhashValid" => {
                        let blockhash = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bc = lock_or_recover(&blockchain);
                        
                        // Find the slot for this blockhash
                        let slot_for_hash = bc.recent_blockhashes.iter()
                            .find(|(_, hash)| *hash == blockhash)
                            .map(|(slot, _)| *slot);
                        
                        match slot_for_hash {
                            Some(slot) => {
                                let is_valid = bc.current_slot.saturating_sub(slot) <= 150; // 150 slot window
                                serde_json::json!({
                                    "value": is_valid,
                                    "context": {
                                        "slot": bc.current_slot
                                    }
                                })
                            },
                            None => {
                                // Also check chain blocks if not in recent_blockhashes
                                let found_in_chain = bc.chain.iter()
                                    .rev()
                                    .take(150)  // Only check last 150 blocks
                                    .find(|b| b.hash == blockhash);
                                
                                match found_in_chain {
                                    Some(block) => {
                                        let is_valid = bc.current_slot.saturating_sub(block.slot) <= 150;
                                        serde_json::json!({
                                            "value": is_valid,
                                            "context": {
                                                "slot": bc.current_slot,
                                                "blockhash_slot": block.slot
                                            }
                                        })
                                    },
                                    None => serde_json::json!({
                                        "value": false,
                                        "context": {
                                            "slot": bc.current_slot,
                                            "error": "Blockhash not found or too old"
                                        }
                                    })
                                }
                            }
                        }
                    },
                    // getFeeForMessage - Calculate fee for a message/transaction
                    "getFeeForMessage" => {
                        // Fixed fee structure for now (could be dynamic based on congestion)
                        let current_slot = {
                            let bc = lock_or_recover(&blockchain);
                            bc.current_slot
                        };
                        serde_json::json!({
                            "value": 5000,  // 5000 lamports = 0.005 BB
                            "context": {
                                "slot": current_slot
                            }
                        })
                    },
                    
                    // ============ Blockhash Expiry Methods (Enhanced) ============
                    // getBlockhashExpiry - Get detailed expiry info for a blockhash
                    "getBlockhashExpiry" => {
                        let blockhash = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bc = lock_or_recover(&blockchain);
                        
                        // Find blockhash in chain
                        let block_info = bc.chain.iter()
                            .rev()
                            .take(200)  // Search last 200 blocks
                            .find(|b| b.hash == blockhash);
                        
                        match block_info {
                            Some(block) => {
                                let age_slots = bc.current_slot.saturating_sub(block.slot);
                                let remaining_slots = if age_slots <= 150 { 150 - age_slots } else { 0 };
                                let is_valid = age_slots <= 150;
                                let expires_at_slot = block.slot + 150;
                                
                                serde_json::json!({
                                    "blockhash": blockhash,
                                    "slot": block.slot,
                                    "blockHeight": block.index,
                                    "isValid": is_valid,
                                    "ageSlots": age_slots,
                                    "remainingSlots": remaining_slots,
                                    "expiresAtSlot": expires_at_slot,
                                    "expiresAtBlockHeight": block.index + 150,
                                    "currentSlot": bc.current_slot,
                                    "maxAgeSlots": 150
                                })
                            },
                            None => serde_json::json!({
                                "blockhash": blockhash,
                                "isValid": false,
                                "error": "Blockhash not found (may have expired or never existed)",
                                "currentSlot": bc.current_slot,
                                "maxAgeSlots": 150
                            })
                        }
                    },
                    // getSlotLeader - Get the leader for a specific slot
                    "getSlotLeader" => {
                        let slot = params.get(0)
                            .and_then(|v| v.as_u64());
                        let bc = lock_or_recover(&blockchain);
                        
                        match slot {
                            Some(s) => {
                                // Find leader from block at that slot, or indicate it's future
                                let block = bc.chain.iter().find(|b| b.slot == s);
                                match block {
                                    Some(b) => serde_json::json!({
                                        "slot": s,
                                        "leader": b.leader,
                                        "sequencer": b.sequencer,
                                        "blockProduced": true
                                    }),
                                    None => serde_json::json!({
                                        "slot": s,
                                        "leader": null,
                                        "blockProduced": false,
                                        "status": if s > bc.current_slot { "future" } else { "skipped_or_missing" }
                                    })
                                }
                            },
                            None => {
                                // Return current slot leader
                                let latest = bc.chain.last();
                                match latest {
                                    Some(b) => serde_json::json!({
                                        "slot": b.slot,
                                        "leader": b.leader,
                                        "sequencer": b.sequencer,
                                        "isCurrent": true
                                    }),
                                    None => serde_json::json!({
                                        "error": "No blocks in chain"
                                    })
                                }
                            }
                        }
                    },
                    // getMinimumBalanceForRentExemption - Get rent-exempt minimum
                    "getMinimumBalanceForRentExemption" => {
                        let data_size = params.get(0)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        // Rent exemption: base 1000 lamports + 1 lamport per byte
                        let rent_exempt = 1000 + data_size;
                        serde_json::json!({
                            "value": rent_exempt,
                            "dataSize": data_size,
                            "baseLamports": 1000,
                            "perByteLamports": 1
                        })
                    },
                    
                    // ============ L2 Integration Methods ============
                    "getL2Config" => {
                        let l2_url = std::env::var("L2_RPC_URL")
                            .unwrap_or_else(|_| "http://localhost:8080".to_string());
                        serde_json::json!({
                            "l2_url": l2_url,
                            "bridge_enabled": true,
                            "supported_actions": [
                                "place_bet",
                                "create_market",
                                "deposit",
                                "withdraw",
                                "transfer",
                                "get_markets",
                                "get_balance"
                            ]
                        })
                    },
                    "verifyL1Signature" => {
                        let public_key = params.get(0)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let message = params.get(1)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let signature = params.get(2)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        match verify_signature(public_key, message, signature) {
                            Ok(valid) => serde_json::json!({
                                "valid": valid,
                                "wallet_address": public_key
                            }),
                            Err(e) => serde_json::json!({
                                "valid": false,
                                "error": e
                            })
                        }
                    },
                    
                    // ============ Unknown Method ============
                    _ => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32601,
                                "message": format!("Method not found: {}", method),
                                "available_methods": [
                                    // Chain Info
                                    "getBlockHeight", "getBalance", "getTotalSupply", "getWalletCount", "getChainStats",
                                    // Accounts
                                    "getAccounts", "getAccountInfo",
                                    // Transactions
                                    "getTransactions", "getPendingTransactions",
                                    // Blocks
                                    "getBlock", "getLatestBlock", "getSlotLeader",
                                    // Blockhash & Validity (critical for tx construction)
                                    "getRecentBlockhash", "getLatestBlockhash", "isBlockhashValid", 
                                    "getBlockhashExpiry", "getFeeForMessage", "getMinimumBalanceForRentExemption",
                                    // L2 Integration
                                    "getL2Config", "verifyL1Signature"
                                ]
                            }
                        })));
                    }
                };
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })))
            }
        })
}

/// Helper to verify Ed25519 signature
fn verify_signature(public_key: &str, message: &str, signature: &str) -> Result<bool, String> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    
    if public_key.is_empty() || message.is_empty() || signature.is_empty() {
        return Err("Missing required parameters".to_string());
    }
    
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
