//! Social Mining Tests for Layer1
//! 
//! Tests for SocialMiningSystem including:
//! - Daily limits enforcement
//! - Reward calculations
//! - Post/Like/Comment/Repost actions
//! - Statistics tracking
//! - User earnings

use layer1::social_mining::{SocialMiningSystem, SocialActionType};

// ============================================================================
// INITIALIZATION TESTS
// ============================================================================

#[test]
fn test_social_mining_system_new() {
    let system = SocialMiningSystem::new();
    
    assert!(system.actions.is_empty(), "Actions should start empty");
    assert!(system.daily_limits.is_empty(), "Daily limits should start empty");
    assert!(system.posts.is_empty(), "Posts should start empty");
    assert!(system.user_earnings.is_empty(), "User earnings should start empty");
    assert_eq!(system.total_posts, 0);
    assert_eq!(system.total_likes, 0);
    assert_eq!(system.total_comments, 0);
    assert_eq!(system.total_rewards_distributed, 0.0);
    assert_eq!(system.difficulty_adjustment, 1.0);
}

// ============================================================================
// REWARD CALCULATION TESTS
// ============================================================================

#[test]
fn test_reward_calculation_post() {
    let system = SocialMiningSystem::new();
    let reward = system.calculate_reward(&SocialActionType::Post, 21_000_000.0);
    assert_eq!(reward, 10.0, "Post reward should be 10 L1");
}

#[test]
fn test_reward_calculation_like() {
    let system = SocialMiningSystem::new();
    let reward = system.calculate_reward(&SocialActionType::Like, 21_000_000.0);
    assert_eq!(reward, 0.21, "Like reward should be 0.21 L1");
}

#[test]
fn test_reward_calculation_comment() {
    let system = SocialMiningSystem::new();
    let reward = system.calculate_reward(&SocialActionType::Comment, 21_000_000.0);
    assert_eq!(reward, 5.0, "Comment reward should be 5 L1");
}

#[test]
fn test_reward_calculation_share() {
    let system = SocialMiningSystem::new();
    let reward = system.calculate_reward(&SocialActionType::Share, 21_000_000.0);
    assert_eq!(reward, 0.21, "Share reward should be 0.21 L1");
}

#[test]
fn test_reward_calculation_repost() {
    let system = SocialMiningSystem::new();
    let reward = system.calculate_reward(&SocialActionType::Repost, 21_000_000.0);
    assert_eq!(reward, 2.5, "Repost reward should be 2.5 L1");
}

// ============================================================================
// CREATE POST TESTS
// ============================================================================

#[test]
fn test_create_post_success() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.create_post(
        "wallet_123",
        "Hello Layer1!",
        None,
    );
    
    assert!(result.is_ok(), "Post creation should succeed");
    let post_id = result.unwrap();
    assert!(post_id.starts_with("post_"), "Post ID should start with 'post_'");
    assert!(post_id.contains("wallet_123"), "Post ID should contain author");
}

#[test]
fn test_create_post_records_action() {
    let mut system = SocialMiningSystem::new();
    
    let _ = system.create_post("author1", "Content", None);
    
    assert_eq!(system.actions.len(), 1, "Should have 1 action recorded");
    
    let action = &system.actions[0];
    assert_eq!(action.user_address, "author1");
    assert_eq!(action.reward_amount, 10.0);
    assert!(matches!(action.action_type, SocialActionType::Post));
}

#[test]
fn test_create_multiple_posts() {
    let mut system = SocialMiningSystem::new();
    
    for i in 0..5 {
        let _ = system.create_post(&format!("author_{}", i), "Content", None);
    }
    
    assert_eq!(system.actions.len(), 5, "Should have 5 actions recorded");
}

// ============================================================================
// LIKE POST TESTS
// ============================================================================

#[test]
fn test_like_post_success() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.like_post("post_123", "wallet_456");
    
    assert!(result.is_ok(), "Like should succeed");
}

#[test]
fn test_like_post_records_action() {
    let mut system = SocialMiningSystem::new();
    
    let _ = system.like_post("post_123", "liker_wallet");
    
    assert_eq!(system.actions.len(), 1);
    
    let action = &system.actions[0];
    assert_eq!(action.user_address, "liker_wallet");
    assert_eq!(action.post_id, "post_123");
    assert_eq!(action.reward_amount, 0.21);
    assert!(matches!(action.action_type, SocialActionType::Like));
}

#[test]
fn test_multiple_likes_from_same_user() {
    let mut system = SocialMiningSystem::new();
    
    for i in 0..10 {
        let _ = system.like_post(&format!("post_{}", i), "same_user");
    }
    
    assert_eq!(system.actions.len(), 10, "All likes should be recorded");
}

// ============================================================================
// COMMENT TESTS
// ============================================================================

#[test]
fn test_comment_on_post_success() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.comment_on_post("post_123", "commenter_wallet", "Great post!");
    
    assert!(result.is_ok(), "Comment should succeed");
    let comment_id = result.unwrap();
    assert!(comment_id.starts_with("comment_"), "Comment ID should start with 'comment_'");
}

#[test]
fn test_comment_records_action() {
    let mut system = SocialMiningSystem::new();
    
    let _ = system.comment_on_post("post_123", "commenter", "Nice!");
    
    assert_eq!(system.actions.len(), 1);
    
    let action = &system.actions[0];
    assert_eq!(action.user_address, "commenter");
    assert_eq!(action.post_id, "post_123");
    assert_eq!(action.reward_amount, 5.0);
    assert!(matches!(action.action_type, SocialActionType::Comment));
}

// ============================================================================
// REPOST TESTS
// ============================================================================

#[test]
fn test_repost_success() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.repost("original_post_123", "reposter_wallet", Some("Check this out!"));
    
    assert!(result.is_ok(), "Repost should succeed");
    let repost_id = result.unwrap();
    assert!(repost_id.starts_with("repost_"), "Repost ID should start with 'repost_'");
}

#[test]
fn test_repost_costs_tokens() {
    let mut system = SocialMiningSystem::new();
    
    let _ = system.repost("original_post_123", "reposter", None);
    
    assert_eq!(system.actions.len(), 1);
    
    let action = &system.actions[0];
    assert_eq!(action.reward_amount, -2.5, "Repost should cost 2.5 L1 (negative reward)");
    assert!(matches!(action.action_type, SocialActionType::Repost));
}

// ============================================================================
// DAILY LIMITS TESTS
// ============================================================================

#[test]
fn test_daily_limits_initialization() {
    let mut system = SocialMiningSystem::new();
    
    // First action should initialize daily limits
    let _ = system.create_post("new_user", "First post", None);
    
    assert!(system.daily_limits.contains_key("new_user"));
    
    let limits = system.daily_limits.get("new_user").unwrap();
    assert_eq!(limits.posts, 1, "Posts should be 1 after first post");
    assert_eq!(limits.likes, 0);
    assert_eq!(limits.comments, 0);
    assert_eq!(limits.reposts, 0);
}

#[test]
fn test_daily_limits_increment() {
    let mut system = SocialMiningSystem::new();
    
    // Create multiple posts
    for _ in 0..3 {
        let _ = system.create_post("user1", "Content", None);
    }
    
    // Like some posts
    for _ in 0..5 {
        let _ = system.like_post("post_1", "user1");
    }
    
    // Comment
    let _ = system.comment_on_post("post_1", "user1", "Comment");
    
    let limits = system.daily_limits.get("user1").unwrap();
    assert_eq!(limits.posts, 3);
    assert_eq!(limits.likes, 5);
    assert_eq!(limits.comments, 1);
}

#[test]
fn test_check_daily_limits_pass() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.check_daily_limits("new_user", &SocialActionType::Post);
    assert!(result.is_ok(), "New user should pass daily limits check");
}

// ============================================================================
// USER EARNINGS TESTS
// ============================================================================

#[test]
fn test_get_user_earnings_no_actions() {
    let system = SocialMiningSystem::new();
    
    let earnings = system.get_user_earnings("nonexistent_user");
    assert_eq!(earnings, 0.0, "User with no actions should have 0 earnings");
}

#[test]
fn test_get_user_earnings_single_post() {
    let mut system = SocialMiningSystem::new();
    
    let _ = system.create_post("earner", "Post content", None);
    
    let earnings = system.get_user_earnings("earner");
    assert_eq!(earnings, 10.0, "User should earn 10 L1 for one post");
}

#[test]
fn test_get_user_earnings_multiple_actions() {
    let mut system = SocialMiningSystem::new();
    
    // Create post (10 L1)
    let _ = system.create_post("active_user", "Post", None);
    
    // Like 5 posts (5 * 0.21 = 1.05 L1)
    for _ in 0..5 {
        let _ = system.like_post("some_post", "active_user");
    }
    
    // Comment (5 L1)
    let _ = system.comment_on_post("some_post", "active_user", "Comment");
    
    let earnings = system.get_user_earnings("active_user");
    let expected = 10.0 + (5.0 * 0.21) + 5.0; // 16.05
    assert!((earnings - expected).abs() < 0.001, 
            "Earnings should be {} but got {}", expected, earnings);
}

#[test]
fn test_get_user_earnings_with_repost_cost() {
    let mut system = SocialMiningSystem::new();
    
    // Create post (10 L1)
    let _ = system.create_post("user", "Post", None);
    
    // Repost costs 2.5 L1 (negative)
    let _ = system.repost("other_post", "user", None);
    
    let earnings = system.get_user_earnings("user");
    let expected = 10.0 + (-2.5); // 7.5
    assert!((earnings - expected).abs() < 0.001,
            "Earnings should be {} but got {}", expected, earnings);
}

// ============================================================================
// STATISTICS TESTS
// ============================================================================

#[test]
fn test_get_stats_empty() {
    let system = SocialMiningSystem::new();
    let stats = system.get_stats();
    
    assert_eq!(stats.total_posts, 0);
    assert_eq!(stats.total_likes, 0);
    assert_eq!(stats.total_comments, 0);
    assert_eq!(stats.total_reposts, 0);
    assert_eq!(stats.total_rewards_distributed, 0.0);
    assert_eq!(stats.active_users, 0);
    assert!(stats.top_earners.is_empty());
}

#[test]
fn test_get_stats_with_activity() {
    let mut system = SocialMiningSystem::new();
    
    // User 1: 2 posts
    let _ = system.create_post("user1", "Post 1", None);
    let _ = system.create_post("user1", "Post 2", None);
    
    // User 2: 3 likes
    let _ = system.like_post("post_1", "user2");
    let _ = system.like_post("post_2", "user2");
    let _ = system.like_post("post_3", "user2");
    
    // User 3: 1 comment and 1 repost
    let _ = system.comment_on_post("post_1", "user3", "Nice!");
    let _ = system.repost("post_1", "user3", None);
    
    let stats = system.get_stats();
    
    assert_eq!(stats.total_posts, 2);
    assert_eq!(stats.total_likes, 3);
    assert_eq!(stats.total_comments, 1);
    assert_eq!(stats.total_reposts, 1);
    assert_eq!(stats.active_users, 3);
    
    // Check top earners
    assert_eq!(stats.top_earners.len(), 3);
    assert_eq!(*stats.top_earners.get("user1").unwrap(), 20.0); // 2 posts
    assert!((*stats.top_earners.get("user2").unwrap() - 0.63).abs() < 0.001); // 3 likes
}

// ============================================================================
// GET ALL POSTS TESTS
// ============================================================================

#[test]
fn test_get_all_posts_empty() {
    let system = SocialMiningSystem::new();
    let posts = system.get_all_posts();
    assert!(posts.is_empty());
}

#[test]
fn test_get_all_posts_returns_posts_only() {
    let mut system = SocialMiningSystem::new();
    
    // Mix of actions
    let _ = system.create_post("author1", "Post 1", None);
    let _ = system.like_post("post_1", "liker");
    let _ = system.create_post("author2", "Post 2", None);
    let _ = system.comment_on_post("post_1", "commenter", "Comment");
    let _ = system.create_post("author1", "Post 3", None);
    
    let posts = system.get_all_posts();
    
    assert_eq!(posts.len(), 3, "Should return only posts, not likes/comments");
    
    // Verify each returned item is a post
    for post in &posts {
        assert!(post.get("post_id").is_some());
        assert!(post.get("author").is_some());
        assert!(post.get("timestamp").is_some());
        assert!(post.get("reward_earned").is_some());
    }
}

// ============================================================================
// CLEANUP TESTS
// ============================================================================

#[test]
fn test_cleanup_old_actions_below_threshold() {
    let mut system = SocialMiningSystem::new();
    
    // Add 100 actions (below 1000 threshold)
    for i in 0..100 {
        let _ = system.like_post(&format!("post_{}", i), &format!("user_{}", i));
    }
    
    let before_count = system.actions.len();
    system.cleanup_old_actions();
    let after_count = system.actions.len();
    
    assert_eq!(before_count, after_count, "Cleanup should not remove actions below threshold");
}

// ============================================================================
// SHARE POST TESTS
// ============================================================================

#[test]
fn test_share_post() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.share_post("post_123", "sharer_wallet");
    
    assert!(result.is_ok(), "Share should succeed");
    assert_eq!(system.actions.len(), 1);
    
    // Share is implemented as like
    let action = &system.actions[0];
    assert!(matches!(action.action_type, SocialActionType::Like));
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_empty_content_post() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.create_post("user", "", None);
    
    // System doesn't validate content length, so it should succeed
    assert!(result.is_ok());
}

#[test]
fn test_special_characters_in_user_address() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.create_post("0x1234AbCdEf!@#$%", "Special chars test", None);
    
    assert!(result.is_ok());
    assert_eq!(system.actions[0].user_address, "0x1234AbCdEf!@#$%");
}

#[test]
fn test_unicode_content() {
    let mut system = SocialMiningSystem::new();
    
    let result = system.create_post("user", "Hello 世界! 🚀", None);
    
    assert!(result.is_ok());
}

#[test]
fn test_concurrent_users() {
    let mut system = SocialMiningSystem::new();
    
    // Simulate many different users
    for i in 0..50 {
        let user = format!("user_{}", i);
        let _ = system.create_post(&user, "Post", None);
        let _ = system.like_post("post_0", &user);
    }
    
    let stats = system.get_stats();
    assert_eq!(stats.active_users, 50);
    assert_eq!(stats.total_posts, 50);
    assert_eq!(stats.total_likes, 50);
}

#[test]
fn test_action_type_filtering() {
    let mut system = SocialMiningSystem::new();
    
    // Create diverse set of actions
    let _ = system.create_post("user1", "Post", None);       // Post
    let _ = system.like_post("post_1", "user2");             // Like
    let _ = system.comment_on_post("post_1", "user3", "Hi"); // Comment
    let _ = system.repost("post_1", "user4", None);          // Repost
    
    // Get stats and verify counts
    let stats = system.get_stats();
    
    assert_eq!(stats.total_posts, 1);
    assert_eq!(stats.total_likes, 1);
    assert_eq!(stats.total_comments, 1);
    assert_eq!(stats.total_reposts, 1);
}
