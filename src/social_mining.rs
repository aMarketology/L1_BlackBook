use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Core Social Action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAction {
    pub action_type: SocialActionType,
    pub user_address: String,  // ✅ Changed from 'user' to 'user_address'
    pub post_id: String,       // ✅ Changed from 'target_id' to 'post_id'
    pub target_user: Option<String>, // For likes/comments - who gets the reward
    pub timestamp: u64,
    pub reward_amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocialActionType {
    Post,    // Creating a post (10 L1)
    Like,    // Liking someone's post (0.21 L1)
    Comment, // Commenting on someone's post (5 L1)
    Share,   // Sharing a post (0.21 L1)
    Repost,  // ✅ NEW: Reposting someone's content (costs 2.5 L1)
}

// Main Social Mining System - ✅ FIXED STRUCTURE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialMiningSystem {
    pub actions: Vec<SocialAction>,                    // ✅ Added back 'actions' field
    pub daily_limits: HashMap<String, DailyLimits>,   // ✅ Added back 'daily_limits' field
    pub posts: HashMap<String, SocialPost>,           // Keep your existing posts
    pub user_earnings: HashMap<String, f64>,          // Keep your existing user_earnings
    pub total_posts: u64,                             // Keep your existing totals
    pub total_likes: u64,                             
    pub total_comments: u64,
    pub total_rewards_distributed: f64,
    pub difficulty_adjustment: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyLimits {
    pub date: String,
    pub posts: u64,
    pub likes: u64,
    pub comments: u64,
    pub reposts: u64,  // ✅ NEW: Track daily reposts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialPost {
    pub id: String,
    pub author: String,
    pub content: String,
    pub timestamp: u64,
    pub likes: std::collections::HashSet<String>,
    pub comments: Vec<SocialComment>,
    pub reward_earned: f64,
    pub hashtags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialComment {
    pub id: String,
    pub author: String,
    pub content: String,
    pub timestamp: u64,
}

// API Request/Response Structures
#[derive(Deserialize)]
pub struct SocialPostRequest {
    pub user_address: String,
    pub post_id: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct SocialLikeRequest {
    pub user_address: String,
    pub post_id: String,
    pub post_author: String,
}

#[derive(Deserialize)]
pub struct SocialCommentRequest {
    pub user_address: String,
    pub post_id: String,
    pub post_author: String,
    pub comment_content: String,
}

#[derive(Serialize)]
pub struct SocialActionResponse {
    pub success: bool,
    pub message: String,
    pub reward_amount: f64,
    pub action_type: String,
}

#[derive(Serialize)]
pub struct SocialStatsResponse {
    pub total_posts: u64,
    pub total_likes: u64,
    pub total_comments: u64,
    pub total_reposts: u64,            // ✅ NEW: Track total reposts
    pub total_rewards_distributed: f64,
    pub active_users: usize,
    pub top_earners: HashMap<String, f64>,
    pub difficulty_adjustment: f64,
}

#[derive(Serialize)]
pub struct UserEarnings {
    pub user_address: String,
    pub username: Option<String>,
    pub total_earnings: f64,
    pub posts_count: u64,
}

impl SocialMiningSystem {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),                          // ✅ Initialize actions
            daily_limits: HashMap::new(),                 // ✅ Initialize daily_limits
            posts: HashMap::new(),                        // Keep existing
            user_earnings: HashMap::new(),                // Keep existing
            total_posts: 0,                               // Keep existing
            total_likes: 0,
            total_comments: 0,
            total_rewards_distributed: 0.0,
            difficulty_adjustment: 1.0,
        }
    }

    // Get today as string for daily limits
    fn get_today() -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let days = now / 86400; // Convert to days
        format!("day_{}", days)
    }

    // Check if user can perform action (daily limits)
    pub fn check_daily_limits(&mut self, user_address: &str, action_type: &SocialActionType) -> Result<(), String> {
        let today = Self::get_today();
        let limits = self.daily_limits
            .entry(user_address.to_string())
            .or_insert(DailyLimits {
                date: today.clone(),
                posts: 0,
                likes: 0,
                comments: 0,
                reposts: 0,  // ✅ NEW: Initialize reposts
            });

        // Reset if new day
        if limits.date != today {
            limits.date = today;
            limits.posts = 0;
            limits.likes = 0;
            limits.comments = 0;
            limits.reposts = 0;  // ✅ NEW: Reset reposts
        }

        // Check limits
        match action_type {
            SocialActionType::Post => {
                if limits.posts >= 50 { return Err("Daily post limit reached (50)".to_string()); }
            },
            SocialActionType::Like => {
                if limits.likes >= 1000 { return Err("Daily like limit reached (1000)".to_string()); }
            },
            SocialActionType::Comment => {
                if limits.comments >= 200 { return Err("Daily comment limit reached (200)".to_string()); }
            },
            SocialActionType::Share => {
                if limits.likes >= 500 { return Err("Daily share limit reached (500)".to_string()); }
            },
            SocialActionType::Repost => {  // ✅ NEW: Repost limits
                if limits.reposts >= 100 { return Err("Daily repost limit reached (100)".to_string()); }
            },
        }

        Ok(())
    }

    // Update daily limits after successful action
    pub fn update_daily_limits(&mut self, user_address: &str, action_type: &SocialActionType) {
        let today = Self::get_today();
        let limits = self.daily_limits
            .entry(user_address.to_string())
            .or_insert(DailyLimits {
                date: today.clone(),
                posts: 0,
                likes: 0,
                comments: 0,
                reposts: 0,  // ✅ NEW: Initialize reposts
            });

        match action_type {
            SocialActionType::Post => limits.posts += 1,
            SocialActionType::Like => limits.likes += 1,
            SocialActionType::Comment => limits.comments += 1,
            SocialActionType::Share => limits.likes += 1,
            SocialActionType::Repost => limits.reposts += 1,  // ✅ NEW: Increment reposts
        }
    }

    // Calculate reward amount based on action type
    pub fn calculate_reward(&self, action_type: &SocialActionType, _max_supply: f64) -> f64 {
        match action_type {
            SocialActionType::Post => 10.0,    // Fixed 10 L1 for posts
            SocialActionType::Like => 0.21,    // Small reward for likes
            SocialActionType::Comment => 5.0,  // ✅ UPDATED: 5 L1 for comments
            SocialActionType::Share => 0.21,   // Small reward for shares
            SocialActionType::Repost => 2.5,   // ✅ NEW: 2.5 L1 for reposts
        }
    }

    // Record a social action
    pub fn record_action(&mut self, action: SocialAction) {
        self.actions.push(action);
    }

    // Get social mining statistics - ✅ FIXED
    pub fn get_stats(&self) -> SocialStatsResponse {
        let total_posts = self.actions.iter().filter(|a| matches!(a.action_type, SocialActionType::Post)).count() as u64;
        let total_likes = self.actions.iter().filter(|a| matches!(a.action_type, SocialActionType::Like)).count() as u64;
        let total_comments = self.actions.iter().filter(|a| matches!(a.action_type, SocialActionType::Comment)).count() as u64;
        let total_reposts = self.actions.iter().filter(|a| matches!(a.action_type, SocialActionType::Repost)).count() as u64; // ✅ NEW
        let total_rewards_distributed = self.actions.iter().map(|a| a.reward_amount).sum();

        // Calculate top earners as HashMap - ✅ FIXED
        let mut top_earners: HashMap<String, f64> = HashMap::new();

        for action in &self.actions {
            *top_earners.entry(action.user_address.clone()).or_insert(0.0) += action.reward_amount;
        }

        // Get unique active users
        let active_users = self.actions.iter()
            .map(|a| &a.user_address)
            .collect::<std::collections::HashSet<_>>()
            .len();

        SocialStatsResponse {
            total_posts,
            total_likes,
            total_comments,
            total_reposts,          // ✅ NEW: Include reposts
            total_rewards_distributed,
            active_users,
            top_earners,
            difficulty_adjustment: self.difficulty_adjustment,
        }
    }

    // Get user's social earnings
    pub fn get_user_earnings(&self, user_address: &str) -> f64 {
        self.actions
            .iter()
            .filter(|action| action.user_address == user_address)
            .map(|action| action.reward_amount)
            .sum()
    }

    // Cleanup old actions (keep last 1000 actions for performance)
    pub fn cleanup_old_actions(&mut self) {
        if self.actions.len() > 1000 {
            let keep_count = 1000;
            self.actions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            self.actions.truncate(keep_count);
            println!("🧹 Social Mining: Cleaned up old actions, keeping latest {}", keep_count);
        }
    }

    // ✅ FIXED: All methods now use correct field names
    pub fn create_post(&mut self, author: &str, _content: &str, _media_url: Option<String>) -> Result<String, String> {
        // Check daily limits
        self.check_daily_limits(author, &SocialActionType::Post)?;
        
        // Generate post ID
        let post_id = format!("post_{}_{}", author, self.actions.len());
        
        // Calculate reward
        let reward = self.calculate_reward(&SocialActionType::Post, 21_000_000.0);
        
        // Record action
        let action = SocialAction {
            action_type: SocialActionType::Post,
            user_address: author.to_string(),  // ✅ Correct field name
            post_id: post_id.clone(),          // ✅ Correct field name
            target_user: None,                 // ✅ Correct field name
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            reward_amount: reward,
        };
        
        self.record_action(action);
        self.update_daily_limits(author, &SocialActionType::Post);
        
        Ok(post_id)
    }

    pub fn like_post(&mut self, post_id: &str, wallet_address: &str) -> Result<String, String> {
        // Check daily limits
        self.check_daily_limits(wallet_address, &SocialActionType::Like)?;
        
        // Calculate reward
        let reward = self.calculate_reward(&SocialActionType::Like, 21_000_000.0);
        
        // Record action using wallet address
        let action = SocialAction {
            action_type: SocialActionType::Like,
            user_address: wallet_address.to_string(),  // ✅ Correct field name
            post_id: post_id.to_string(),              // ✅ Correct field name
            target_user: None,                         // ✅ Correct field name
            reward_amount: reward,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        self.record_action(action);
        self.update_daily_limits(wallet_address, &SocialActionType::Like);
        
        Ok("Post liked successfully!".to_string())
    }

    pub fn comment_on_post(&mut self, post_id: &str, wallet_address: &str, _content: &str) -> Result<String, String> {
        // Check daily limits
        self.check_daily_limits(wallet_address, &SocialActionType::Comment)?;
        
        // Calculate reward
        let reward = self.calculate_reward(&SocialActionType::Comment, 21_000_000.0);
        
        // Generate comment ID
        let comment_id = format!("comment_{}_{}", post_id, self.actions.len());
        
        // Record action using wallet address
        let action = SocialAction {
            action_type: SocialActionType::Comment,
            user_address: wallet_address.to_string(),  // ✅ Correct field name
            post_id: post_id.to_string(),              // ✅ Correct field name
            target_user: None,                         // ✅ Correct field name
            reward_amount: reward,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        self.record_action(action);
        self.update_daily_limits(wallet_address, &SocialActionType::Comment);
        
        Ok(comment_id)
    }

    pub fn share_post(&mut self, post_id: &str, user_id: &str) -> Result<String, String> {
        // For now, treat sharing like liking (you can create a separate action type later)
        self.like_post(post_id, user_id)
    }

    pub fn get_all_posts(&self) -> Vec<serde_json::Value> {
        // Return posts from actions
        self.actions
            .iter()
            .filter(|action| matches!(action.action_type, SocialActionType::Post))
            .map(|action| serde_json::json!({
                "post_id": action.post_id,
                "author": action.user_address,  // ✅ Correct field name
                "timestamp": action.timestamp,
                "reward_earned": action.reward_amount
            }))
            .collect()
    }

    // ✅ NEW: Repost functionality (costs 2.5 L1)
    pub fn repost(&mut self, original_post_id: &str, wallet_address: &str, _repost_content: Option<&str>) -> Result<String, String> {
        // Check daily limits
        self.check_daily_limits(wallet_address, &SocialActionType::Repost)?;
        
        // Generate repost ID
        let repost_id = format!("repost_{}_{}", original_post_id, self.actions.len());
        
        // Repost has negative reward (it costs money)
        let cost = -2.5; // Negative because it's a cost
        
        // Record action
        let action = SocialAction {
            action_type: SocialActionType::Repost,
            user_address: wallet_address.to_string(),
            post_id: repost_id.clone(),
            target_user: None, // Could store original author for future features
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            reward_amount: cost, // Negative amount = cost
        };
        
        self.record_action(action);
        self.update_daily_limits(wallet_address, &SocialActionType::Repost);
        
        Ok(repost_id)
    }
}
