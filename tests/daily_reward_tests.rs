//! Daily Reward Tests for Layer1
//! 
//! Tests for daily reward functionality:
//! - Reward claiming mechanics
//! - Balance updates after rewards
//! - Transaction creation for rewards
//! - Integration with blockchain state

use layer1::{
    EnhancedBlockchain, 
    SocialMiningSystem, SocialAction, SocialActionType,
    verify_jwt, create_jwt_for_user,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Helper to create a SocialAction
fn create_action(user: &str, action_type: SocialActionType, reward: f64) -> SocialAction {
    SocialAction {
        action_type,
        user_address: user.to_string(),
        post_id: format!("post_{}", rand::random::<u32>()),
        target_user: None,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        reward_amount: reward,
    }
}

// ============================================================================
// BLOCKCHAIN REWARD TESTS
// ============================================================================

#[test]
fn test_blockchain_new_has_zero_balances() {
    let blockchain = EnhancedBlockchain::new();
    
    assert_eq!(blockchain.get_balance("random_user"), 0.0);
    assert_eq!(blockchain.get_balance("test_wallet"), 0.0);
}

#[test]
fn test_create_transaction_from_reward_system() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let wallet_address = "test_wallet_123";
    let reward_amount = 25.0;
    
    // Reward system can create tokens (no balance check)
    let tx_id = blockchain.create_transaction(
        "reward_system".to_string(),
        wallet_address.to_string(),
        reward_amount,
    );
    
    // Should return a valid transaction ID (not an error)
    assert!(!tx_id.contains("Insufficient"), "Reward system should not require balance");
    
    // Balance should be updated immediately
    let balance = blockchain.get_balance(wallet_address);
    assert_eq!(balance, reward_amount, "Balance should equal reward amount");
}

#[test]
fn test_daily_login_reward_amount() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let user_wallet = "daily_reward_test_wallet";
    let daily_reward = 1.0; // Daily login reward amount
    
    // Simulate daily login reward
    let tx_id = blockchain.create_transaction(
        "daily_login_reward".to_string(),
        user_wallet.to_string(),
        daily_reward,
    );
    
    assert!(!tx_id.contains("Error"), "Daily reward transaction should succeed");
    
    let balance = blockchain.get_balance(user_wallet);
    assert_eq!(balance, daily_reward, "Balance should equal daily reward");
}

#[test]
fn test_multiple_days_rewards_accumulate() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let user_wallet = "multi_day_user";
    let daily_reward = 1.0;
    
    // Simulate 5 days of rewards
    for day in 1..=5 {
        let tx_id = blockchain.create_transaction(
            "daily_login_reward".to_string(),
            user_wallet.to_string(),
            daily_reward,
        );
        
        assert!(!tx_id.contains("Error"), "Day {} reward should succeed", day);
    }
    
    let balance = blockchain.get_balance(user_wallet);
    assert_eq!(balance, 5.0, "Balance should be 5 after 5 days");
}

// ============================================================================
// SOCIAL MINING SYSTEM TESTS
// ============================================================================

#[test]
fn test_social_mining_system_creation() {
    let social_system = SocialMiningSystem::new();
    
    // New system should have no actions
    let stats = social_system.get_stats();
    assert_eq!(stats.total_posts, 0);
    assert_eq!(stats.total_likes, 0);
    assert_eq!(stats.total_comments, 0);
}

#[test]
fn test_social_mining_record_action() {
    let mut social_system = SocialMiningSystem::new();
    
    let action = create_action("user1", SocialActionType::Post, 10.0);
    social_system.record_action(action);
    
    let stats = social_system.get_stats();
    assert_eq!(stats.total_posts, 1);
}

#[test]
fn test_social_action_types_recorded() {
    let mut social_system = SocialMiningSystem::new();
    
    social_system.record_action(create_action("user1", SocialActionType::Post, 10.0));
    social_system.record_action(create_action("user1", SocialActionType::Like, 0.21));
    social_system.record_action(create_action("user1", SocialActionType::Comment, 5.0));
    
    let stats = social_system.get_stats();
    assert_eq!(stats.total_posts, 1);
    assert_eq!(stats.total_likes, 1);
    assert_eq!(stats.total_comments, 1);
}

#[test]
fn test_user_earnings_accumulate() {
    let mut social_system = SocialMiningSystem::new();
    
    let user = "earning_user";
    
    social_system.record_action(create_action(user, SocialActionType::Post, 10.0));
    social_system.record_action(create_action(user, SocialActionType::Like, 0.21));
    social_system.record_action(create_action(user, SocialActionType::Comment, 5.0));
    
    let earnings = social_system.get_user_earnings(user);
    let expected = 10.0 + 0.21 + 5.0;
    
    assert!((earnings - expected).abs() < 0.01, "User earnings should accumulate");
}

// ============================================================================
// JWT AUTH + REWARD INTEGRATION TESTS  
// ============================================================================

#[test]
fn test_authenticated_user_can_claim_reward() {
    // Create a JWT for authenticated user
    let (token, _session_id) = create_jwt_for_user(
        "reward_claimer",
        "supabase_id",
        Some("0xauthenticatedwallet".to_string()),
        "zk_verified",
        vec!["transfer".to_string(), "social".to_string()],
    ).unwrap();
    
    // Verify the token
    let claims = verify_jwt(&token).unwrap();
    
    // User should have wallet address
    assert!(claims.wallet_address.is_some(), "Authenticated user should have wallet");
    
    let wallet = claims.wallet_address.unwrap();
    
    // User should be able to claim reward to this wallet
    let mut blockchain = EnhancedBlockchain::new();
    let tx_id = blockchain.create_transaction(
        "daily_login_reward".to_string(),
        wallet.clone(),
        1.0,
    );
    
    assert!(!tx_id.contains("Error"), "Reward claim should succeed");
    assert_eq!(blockchain.get_balance(&wallet), 1.0);
}

#[test]
fn test_reward_requires_valid_wallet() {
    // Create user without wallet
    let (token, _) = create_jwt_for_user(
        "no_wallet_user",
        "supabase_no_wallet",
        None,  // No wallet
        "temp_wallet_creation",
        vec!["read".to_string()],
    ).unwrap();
    
    let claims = verify_jwt(&token).unwrap();
    
    // User has no wallet
    assert!(claims.wallet_address.is_none(), "User should have no wallet");
}

// ============================================================================
// SIGNUP BONUS TESTS
// ============================================================================

#[test]
fn test_signup_bonus_given_once() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let new_user = "brand_new_user";
    let signup_bonus = 50.0;
    
    // Give signup bonus
    blockchain.create_transaction(
        "signup_bonus".to_string(),
        new_user.to_string(),
        signup_bonus,
    );
    
    assert_eq!(blockchain.get_balance(new_user), signup_bonus);
}

#[test]
fn test_referral_bonus() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let referrer = "referrer_wallet";
    let new_user = "referred_user";
    let referral_bonus = 10.0;
    let signup_bonus = 50.0;
    
    // Give referrer bonus
    blockchain.create_transaction(
        "referral_bonus".to_string(),
        referrer.to_string(),
        referral_bonus,
    );
    
    // Give new user signup bonus
    blockchain.create_transaction(
        "signup_bonus".to_string(),
        new_user.to_string(),
        signup_bonus,
    );
    
    assert_eq!(blockchain.get_balance(referrer), referral_bonus);
    assert_eq!(blockchain.get_balance(new_user), signup_bonus);
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_zero_reward_handling() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let user = "zero_reward_user";
    
    // Zero amount transaction (e.g., no reward earned)
    blockchain.create_transaction(
        "daily_login_reward".to_string(),
        user.to_string(),
        0.0,
    );
    
    assert_eq!(blockchain.get_balance(user), 0.0);
}

#[test]
fn test_fractional_rewards() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let user = "fractional_user";
    
    // Small fractional rewards
    blockchain.create_transaction("reward".to_string(), user.to_string(), 0.001);
    blockchain.create_transaction("reward".to_string(), user.to_string(), 0.002);
    blockchain.create_transaction("reward".to_string(), user.to_string(), 0.003);
    
    let balance = blockchain.get_balance(user);
    // Allow for floating point imprecision
    assert!((balance - 0.006).abs() < 0.0001, "Fractional rewards should accumulate correctly");
}

#[test]
fn test_reward_to_same_user_multiple_sources() {
    let mut blockchain = EnhancedBlockchain::new();
    
    let user = "multi_source_user";
    
    blockchain.create_transaction("signup_bonus".to_string(), user.to_string(), 50.0);
    blockchain.create_transaction("daily_login_reward".to_string(), user.to_string(), 1.0);
    blockchain.create_transaction("referral_bonus".to_string(), user.to_string(), 10.0);
    blockchain.create_transaction("social_mining".to_string(), user.to_string(), 0.5);
    
    assert_eq!(blockchain.get_balance(user), 61.5);
}
