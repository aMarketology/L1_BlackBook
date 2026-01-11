// ============================================================================
// MARKETS ROUTES - L2 Market/Event Initial Liquidity Management
// ============================================================================
//
// This module handles market initialization for L2 events:
// - POST /markets/initial-liquidity - Provide initial liquidity for a market/event
//
// This endpoint mints tokens on L1 and relays the liquidity to L2 at:
// localhost:1234/markets/initial-liquidity/{market_id}

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::storage::PersistentBlockchain;

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<PersistentBlockchain>) -> MutexGuard<'a, PersistentBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

// L2 Prediction Market URL
const L2_BASE_URL: &str = "http://localhost:1234";

// ============================================================================
// TYPES
// ============================================================================

/// Request payload for initial liquidity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialLiquidityRequest {
    /// The market/event ID on L2 that needs liquidity
    pub market_id: String,
    /// Amount of tokens to provide as initial liquidity
    pub amount: f64,
    /// Optional: Whether the house is funding this (for L2)
    #[serde(default)]
    pub house_funded: Option<bool>,
    /// Optional: Description of the market/event
    #[serde(default)]
    pub market_title: Option<String>,
    /// Optional: L2 address that will hold the liquidity pool
    #[serde(default)]
    pub pool_address: Option<String>,
    /// Optional: Token type (defaults to "BB" - BlackBook tokens)
    #[serde(default)]
    pub token_type: Option<String>,
}

/// L2 request payload (what we send to L2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2LiquidityRequest {
    pub amount: f64,
    pub house_funded: bool,
}

/// Response for initial liquidity provisioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialLiquidityResponse {
    pub success: bool,
    pub market_id: String,
    pub amount_provided: f64,
    pub token_type: String,
    pub pool_address: String,
    pub l1_tx_id: String,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l2_response: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Liquidity pool record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub market_id: String,
    pub pool_address: String,
    pub initial_amount: f64,
    pub current_amount: f64,
    pub token_type: String,
    pub created_at: u64,
    pub tx_id: String,
    pub market_title: Option<String>,
}

// ============================================================================
// ROUTES
// ============================================================================

/// POST /markets/initial-liquidity/:market_id
/// 
/// Provides initial liquidity for an L2 market/event.
/// 1. Mints tokens on L1
/// 2. Relays request to L2 at localhost:1234/markets/initial-liquidity/{market_id}
/// 
/// URL: POST /markets/initial-liquidity/asml_hutto_jobs
/// 
/// Request Body:
/// ```json
/// {
///   "amount": 10000.0,
///   "house_funded": true
/// }
/// ```
/// 
/// Response:
/// ```json
/// {
///   "success": true,
///   "market_id": "asml_hutto_jobs",
///   "amount_provided": 10000.0,
///   "token_type": "BB",
///   "pool_address": "L2_POOL_ASML_HUTTO_JOBS",
///   "l1_tx_id": "liq_...",
///   "l2_response": { ... },
///   "timestamp": 1702500000
/// }
/// ```
pub fn initial_liquidity_route(
    blockchain: Arc<Mutex<PersistentBlockchain>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("markets" / "initial-liquidity" / String)
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |market_id: String, body: LiquidityBody| {
            let blockchain = blockchain.clone();
            async move {
                // Convert path param + body into full request
                let request = InitialLiquidityRequest {
                    market_id,
                    amount: body.amount,
                    house_funded: body.house_funded,
                    market_title: None,
                    pool_address: None,
                    token_type: None,
                };
                handle_initial_liquidity(blockchain, request).await
            }
        })
}

/// Request body for liquidity (market_id comes from URL path)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityBody {
    pub amount: f64,
    #[serde(default)]
    pub house_funded: Option<bool>,
}

async fn handle_initial_liquidity(
    blockchain: Arc<Mutex<PersistentBlockchain>>,
    request: InitialLiquidityRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Validate input
    if request.market_id.is_empty() {
        return Ok(warp::reply::json(&InitialLiquidityResponse {
            success: false,
            market_id: request.market_id,
            amount_provided: 0.0,
            token_type: "BB".to_string(),
            pool_address: String::new(),
            l1_tx_id: String::new(),
            timestamp: get_timestamp(),
            l2_response: None,
            error: Some("market_id is required".to_string()),
        }));
    }

    if request.amount <= 0.0 {
        return Ok(warp::reply::json(&InitialLiquidityResponse {
            success: false,
            market_id: request.market_id,
            amount_provided: 0.0,
            token_type: "BB".to_string(),
            pool_address: String::new(),
            l1_tx_id: String::new(),
            timestamp: get_timestamp(),
            l2_response: None,
            error: Some("Amount must be positive".to_string()),
        }));
    }

    // Token type defaults to "BB" (BlackBook tokens)
    let token_type = request.token_type.clone().unwrap_or_else(|| "BB".to_string());
    
    // Generate pool address if not provided
    let pool_address = request.pool_address.clone().unwrap_or_else(|| {
        format!("L2_POOL_{}", request.market_id.to_uppercase())
    });

    // Generate unique transaction ID
    let l1_tx_id = format!("liq_{}_{}", request.market_id, get_timestamp());
    let timestamp = get_timestamp();

    // Step 1: Mint tokens on L1 to the pool address
    let l1_result = {
        let mut bc = lock_or_recover(&blockchain);
        
        // Create transaction from "system" account (mints new tokens for liquidity)
        let _system_tx_id = bc.create_transaction(
            "system".to_string(),
            pool_address.clone(),
            request.amount
        );
        
        // Mine immediately
        let _ = bc.mine_pending_transactions("liquidity_provision".to_string());
        
        let new_balance = bc.get_balance(&pool_address);
        
        println!("💧 L1 MINT: {} {} -> {} for market '{}' (balance: {} {})", 
            request.amount, 
            token_type,
            pool_address,
            request.market_id,
            new_balance,
            token_type
        );
        
        Ok::<_, String>(new_balance)
    };

    if let Err(e) = l1_result {
        return Ok(warp::reply::json(&InitialLiquidityResponse {
            success: false,
            market_id: request.market_id,
            amount_provided: 0.0,
            token_type,
            pool_address: String::new(),
            l1_tx_id: String::new(),
            timestamp,
            l2_response: None,
            error: Some(format!("L1 mint failed: {}", e)),
        }));
    }

    // Step 2: Relay to L2 at localhost:1234/markets/initial-liquidity/{market_id}
    let l2_url = format!("{}/markets/initial-liquidity/{}", L2_BASE_URL, request.market_id);
    let l2_payload = L2LiquidityRequest {
        amount: request.amount,
        house_funded: request.house_funded.unwrap_or(true),
    };

    println!("🔗 Relaying to L2: POST {}", l2_url);
    println!("   📦 Payload: {:?}", l2_payload);

    // Make HTTP request to L2
    let client = reqwest::Client::new();
    let l2_response = match client
        .post(&l2_url)
        .json(&l2_payload)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            match response.json::<serde_json::Value>().await {
                Ok(json) => {
                    println!("   ✅ L2 Response ({}): {:?}", status, json);
                    Some(json)
                }
                Err(e) => {
                    println!("   ⚠️ L2 Response parse error: {}", e);
                    Some(serde_json::json!({
                        "status": status.as_u16(),
                        "error": format!("Failed to parse L2 response: {}", e)
                    }))
                }
            }
        }
        Err(e) => {
            println!("   ❌ L2 Request failed: {}", e);
            Some(serde_json::json!({
                "error": format!("Failed to reach L2: {}", e),
                "l2_url": l2_url
            }))
        }
    };

    // Check if L2 was successful
    let l2_success = l2_response
        .as_ref()
        .and_then(|r| r.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if l2_success {
        println!("   🎉 Liquidity successfully provided to L2 market '{}'", request.market_id);
    } else {
        println!("   ⚠️ L2 liquidity provision may have failed - check L2 response");
    }

    Ok(warp::reply::json(&InitialLiquidityResponse {
        success: l2_success,
        market_id: request.market_id,
        amount_provided: request.amount,
        token_type,
        pool_address,
        l1_tx_id,
        timestamp,
        l2_response,
        error: if l2_success { None } else { Some("L2 liquidity provision failed - check l2_response".to_string()) },
    }))
}

// ============================================================================
// HELPERS
// ============================================================================

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_liquidity_request_deserialization() {
        let json = r#"{
            "market_id": "asml_hutto_jobs",
            "amount": 50000.0,
            "house_funded": true,
            "market_title": "Will ASML build in Hutto?"
        }"#;
        
        let request: InitialLiquidityRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.market_id, "asml_hutto_jobs");
        assert_eq!(request.amount, 50000.0);
        assert_eq!(request.house_funded, Some(true));
        assert_eq!(request.market_title, Some("Will ASML build in Hutto?".to_string()));
    }

    #[test]
    fn test_initial_liquidity_request_minimal() {
        let json = r#"{
            "market_id": "asml_hutto_jobs",
            "amount": 10000.0
        }"#;
        
        let request: InitialLiquidityRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.market_id, "asml_hutto_jobs");
        assert_eq!(request.amount, 10000.0);
        assert!(request.house_funded.is_none());
        assert!(request.market_title.is_none());
        assert!(request.pool_address.is_none());
        assert!(request.token_type.is_none());
    }

    #[test]
    fn test_l2_liquidity_request() {
        let request = L2LiquidityRequest {
            amount: 10000.0,
            house_funded: true,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"amount\":10000.0"));
        assert!(json.contains("\"house_funded\":true"));
    }
}
