// ============================================================================
// SOCIAL ROUTES - Social Mining Actions (V2 - Pure Signature Auth)
// ============================================================================

use std::sync::{Arc, Mutex, MutexGuard};
use warp::Filter;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;
use crate::protocol::blockchain::EnhancedBlockchain;
use crate::integration::unified_auth::SignedRequest;
use crate::social_mining::{SocialMiningSystem, SocialActionType};

/// Helper to recover from poisoned locks
fn lock_or_recover<'a>(mutex: &'a Mutex<EnhancedBlockchain>) -> MutexGuard<'a, EnhancedBlockchain> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    }
}

/// Post payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostPayload {
    pub content: String,
    #[serde(default)]
    pub media_url: Option<String>,
}

/// Like/interact payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractPayload {
    pub post_id: String,
}

/// POST /social/post - Create a social post (authenticated)
pub fn create_post_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    social_system: Arc<TokioMutex<SocialMiningSystem>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("social")
        .and(warp::path("post"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            let social_system = social_system.clone();
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
                let post: PostPayload = match request.parse_payload() {
                    Ok(p) => p,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Invalid post payload: {}", e)
                        })));
                    }
                };
                
                if post.content.is_empty() || post.content.len() > 280 {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "success": false,
                        "error": "Post content must be 1-280 characters"
                    })));
                }
                
                // Create post and get reward
                let (post_id, reward) = {
                    let mut social = social_system.lock().await;
                    match social.create_post(&wallet_address, &post.content, post.media_url.clone()) {
                        Ok(id) => {
                            let reward = social.calculate_reward(&SocialActionType::Post, 21_000_000.0);
                            (id, reward)
                        },
                        Err(e) => {
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": e
                            })));
                        }
                    }
                };
                
                // Add reward to blockchain
                let new_balance = {
                    let mut bc = lock_or_recover(&blockchain);
                    let _tx = bc.create_transaction(
                        "social_mining".to_string(),
                        wallet_address.clone(),
                        reward
                    );
                    let _ = bc.mine_pending_transactions("social_miner".to_string());
                    bc.get_balance(&wallet_address)
                };
                
                println!("📝 Post: {}... -> +{} L1", 
                         &wallet_address[..16.min(wallet_address.len())], reward);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "post": {
                        "id": post_id,
                        "content": post.content
                    },
                    "reward": reward,
                    "new_balance": new_balance
                })))
            }
        })
}

/// POST /social/like - Like a post (authenticated)
pub fn like_post_route(
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    social_system: Arc<TokioMutex<SocialMiningSystem>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("social")
        .and(warp::path("like"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SignedRequest| {
            let blockchain = blockchain.clone();
            let social_system = social_system.clone();
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
                let like: InteractPayload = match request.parse_payload() {
                    Ok(l) => l,
                    Err(e) => {
                        return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": false,
                            "error": format!("Invalid like payload: {}", e)
                        })));
                    }
                };
                
                // Process like
                let reward = {
                    let mut social = social_system.lock().await;
                    match social.like_post(&wallet_address, &like.post_id) {
                        Ok(_) => social.calculate_reward(&SocialActionType::Like, 21_000_000.0),
                        Err(e) => {
                            return Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "success": false,
                                "error": e
                            })));
                        }
                    }
                };
                
                // Add reward
                let new_balance = {
                    let mut bc = lock_or_recover(&blockchain);
                    let _tx = bc.create_transaction(
                        "social_mining".to_string(),
                        wallet_address.clone(),
                        reward
                    );
                    let _ = bc.mine_pending_transactions("social_miner".to_string());
                    bc.get_balance(&wallet_address)
                };
                
                println!("❤️ Like: {}... -> +{} L1", 
                         &wallet_address[..16.min(wallet_address.len())], reward);
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "liked_post": like.post_id,
                    "reward": reward,
                    "new_balance": new_balance
                })))
            }
        })
}

/// GET /social/stats - Get social mining stats (public)
pub fn social_stats_route(
    social_system: Arc<TokioMutex<SocialMiningSystem>>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("social")
        .and(warp::path("stats"))
        .and(warp::get())
        .and_then(move || {
            let social_system = social_system.clone();
            async move {
                let stats = {
                    let social = social_system.lock().await;
                    serde_json::json!({
                        "total_posts": social.posts.len(),
                        "total_users": social.user_earnings.len(),
                        "total_likes": social.total_likes,
                        "total_comments": social.total_comments,
                        "total_rewards_distributed": social.total_rewards_distributed,
                        "reward_rates": {
                            "post": social.calculate_reward(&SocialActionType::Post, 21_000_000.0),
                            "like": social.calculate_reward(&SocialActionType::Like, 21_000_000.0),
                            "comment": social.calculate_reward(&SocialActionType::Comment, 21_000_000.0),
                            "repost": social.calculate_reward(&SocialActionType::Repost, 21_000_000.0),
                        }
                    })
                };
                
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "success": true,
                    "stats": stats
                })))
            }
        })
}
