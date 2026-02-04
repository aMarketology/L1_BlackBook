//! Claim Registry - Prevents Double-Spending of Withdrawals
//!
//! Tracks which withdrawals have been claimed to prevent users from
//! claiming the same payout multiple times.

use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Status of a withdrawal claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// Not yet claimed
    Unclaimed,
    /// Successfully claimed
    Claimed,
    /// Claim attempted but failed
    Failed,
}

/// A single claim record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub batch_id: String,
    pub withdrawal_id: String,  // Usually: hash(batch_id|address|amount)
    pub address: String,
    pub amount: u64,
    pub status: ClaimStatus,
    pub claimed_at: Option<u64>,  // Unix timestamp
    pub tx_hash: Option<String>,  // L1 transaction that credited the user
}

/// Thread-safe registry for tracking claims
pub struct ClaimRegistry {
    /// batch_id -> set of claimed withdrawal_ids
    claims: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// withdrawal_id -> full claim record
    records: Arc<RwLock<HashMap<String, ClaimRecord>>>,
}

impl ClaimRegistry {
    pub fn new() -> Self {
        Self {
            claims: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Check if a withdrawal has been claimed
    pub fn is_claimed(&self, batch_id: &str, withdrawal_id: &str) -> bool {
        let claims = self.claims.read().unwrap();
        claims
            .get(batch_id)
            .map(|set| set.contains(withdrawal_id))
            .unwrap_or(false)
    }
    
    /// Mark a withdrawal as claimed
    pub fn mark_claimed(
        &self,
        batch_id: String,
        withdrawal_id: String,
        address: String,
        amount: u64,
        tx_hash: String,
    ) -> Result<(), String> {
        // Check if already claimed
        if self.is_claimed(&batch_id, &withdrawal_id) {
            return Err(format!("Withdrawal {} already claimed", withdrawal_id));
        }
        
        // Add to claims set
        {
            let mut claims = self.claims.write().unwrap();
            claims
                .entry(batch_id.clone())
                .or_insert_with(HashSet::new)
                .insert(withdrawal_id.clone());
        }
        
        // Store full record
        {
            let mut records = self.records.write().unwrap();
            records.insert(
                withdrawal_id.clone(),
                ClaimRecord {
                    batch_id,
                    withdrawal_id,
                    address,
                    amount,
                    status: ClaimStatus::Claimed,
                    claimed_at: Some(current_timestamp()),
                    tx_hash: Some(tx_hash),
                },
            );
        }
        
        Ok(())
    }
    
    /// Get claim record for a withdrawal
    pub fn get_record(&self, withdrawal_id: &str) -> Option<ClaimRecord> {
        let records = self.records.read().unwrap();
        records.get(withdrawal_id).cloned()
    }
    
    /// Get all claims for a batch
    pub fn get_batch_claims(&self, batch_id: &str) -> Vec<String> {
        let claims = self.claims.read().unwrap();
        claims
            .get(batch_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }
    
    /// Get claim count for a batch
    pub fn get_claim_count(&self, batch_id: &str) -> usize {
        let claims = self.claims.read().unwrap();
        claims.get(batch_id).map(|set| set.len()).unwrap_or(0)
    }
    
    /// Register a new batch (initialize empty claim set)
    pub fn register_batch(&self, batch_id: String) {
        let mut claims = self.claims.write().unwrap();
        claims.entry(batch_id).or_insert_with(HashSet::new);
    }
}

impl Default for ClaimRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Generate a deterministic withdrawal ID
pub fn generate_withdrawal_id(batch_id: &str, address: &str, amount: u64) -> String {
    use sha2::{Sha256, Digest};
    let data = format!("{}|{}|{}", batch_id, address, amount);
    let hash = Sha256::digest(data.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_registry_new() {
        let registry = ClaimRegistry::new();
        assert!(!registry.is_claimed("batch1", "withdrawal1"));
    }

    #[test]
    fn test_mark_claimed() {
        let registry = ClaimRegistry::new();
        
        let result = registry.mark_claimed(
            "batch_123".to_string(),
            "withdrawal_abc".to_string(),
            "bb_alice".to_string(),
            100_000_000,
            "tx_xyz".to_string(),
        );
        
        assert!(result.is_ok());
        assert!(registry.is_claimed("batch_123", "withdrawal_abc"));
    }

    #[test]
    fn test_double_claim_prevention() {
        let registry = ClaimRegistry::new();
        
        // First claim succeeds
        let result1 = registry.mark_claimed(
            "batch_1".to_string(),
            "withdrawal_1".to_string(),
            "bb_user".to_string(),
            1000,
            "tx_1".to_string(),
        );
        assert!(result1.is_ok());
        
        // Second claim fails
        let result2 = registry.mark_claimed(
            "batch_1".to_string(),
            "withdrawal_1".to_string(),
            "bb_user".to_string(),
            1000,
            "tx_2".to_string(),
        );
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("already claimed"));
    }

    #[test]
    fn test_get_record() {
        let registry = ClaimRegistry::new();
        
        registry.mark_claimed(
            "batch_abc".to_string(),
            "withdrawal_xyz".to_string(),
            "bb_bob".to_string(),
            500_000_000,
            "tx_123".to_string(),
        ).unwrap();
        
        let record = registry.get_record("withdrawal_xyz").unwrap();
        assert_eq!(record.address, "bb_bob");
        assert_eq!(record.amount, 500_000_000);
        assert_eq!(record.status, ClaimStatus::Claimed);
        assert!(record.claimed_at.is_some());
    }

    #[test]
    fn test_batch_claims() {
        let registry = ClaimRegistry::new();
        
        registry.mark_claimed(
            "batch_1".to_string(),
            "w1".to_string(),
            "user1".to_string(),
            100,
            "tx1".to_string(),
        ).unwrap();
        
        registry.mark_claimed(
            "batch_1".to_string(),
            "w2".to_string(),
            "user2".to_string(),
            200,
            "tx2".to_string(),
        ).unwrap();
        
        let claims = registry.get_batch_claims("batch_1");
        assert_eq!(claims.len(), 2);
        assert!(claims.contains(&"w1".to_string()));
        assert!(claims.contains(&"w2".to_string()));
        
        assert_eq!(registry.get_claim_count("batch_1"), 2);
    }

    #[test]
    fn test_generate_withdrawal_id() {
        let id1 = generate_withdrawal_id("batch1", "bb_alice", 1000);
        let id2 = generate_withdrawal_id("batch1", "bb_alice", 1000);
        
        // Same inputs produce same ID
        assert_eq!(id1, id2);
        
        // Different inputs produce different IDs
        let id3 = generate_withdrawal_id("batch1", "bb_bob", 1000);
        assert_ne!(id1, id3);
        
        let id4 = generate_withdrawal_id("batch1", "bb_alice", 2000);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_multiple_batches() {
        let registry = ClaimRegistry::new();
        
        registry.mark_claimed(
            "batch_1".to_string(),
            "w1".to_string(),
            "user".to_string(),
            100,
            "tx1".to_string(),
        ).unwrap();
        
        registry.mark_claimed(
            "batch_2".to_string(),
            "w1".to_string(),  // Same withdrawal_id, different batch
            "user".to_string(),
            100,
            "tx2".to_string(),
        ).unwrap();
        
        assert!(registry.is_claimed("batch_1", "w1"));
        assert!(registry.is_claimed("batch_2", "w1"));
        assert_eq!(registry.get_claim_count("batch_1"), 1);
        assert_eq!(registry.get_claim_count("batch_2"), 1);
    }
}
