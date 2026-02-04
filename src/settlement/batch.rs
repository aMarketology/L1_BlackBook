//! Batch Settlement Logic
//!
//! Handles batch settlements where L2 submits a merkle root representing
//! 100+ payouts, and users claim their winnings individually.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use super::{SettlementError, SettlementResult};
use super::merkle::{MerkleProof, PayoutLeaf, verify_merkle_proof};
use super::claims::{ClaimRegistry, generate_withdrawal_id};

/// A single withdrawal in a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    pub address: String,
    pub amount: u64,  // Amount in smallest unit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<MerkleProof>,
}

/// Batch settlement submitted by L2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSettlement {
    /// Unique batch ID (usually market_id + resolution timestamp)
    pub batch_id: String,
    
    /// Market ID this settlement belongs to
    pub market_id: String,
    
    /// Merkle root of all withdrawals
    pub merkle_root: String,
    
    /// Total number of winners
    pub total_winners: u32,
    
    /// Total payout amount (sum of all withdrawals)
    pub total_payout: u64,
    
    /// Total collateral locked in the market
    pub total_collateral: u64,
    
    /// Fees collected by protocol/LPs
    pub fees_collected: u64,
    
    /// L2 sequencer signature (signs merkle_root + batch_id)
    pub l2_signature: String,
    
    /// L2 public key (for signature verification)
    pub l2_public_key: String,
    
    /// Timestamp when batch was created
    pub timestamp: u64,
    
    /// Optional: All withdrawals (for initial submission)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<Withdrawal>>,
}

/// Status of a batch settlement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatus {
    /// Batch submitted, merkle root stored
    Pending,
    /// Partially claimed (some winners claimed)
    PartiallyComplete,
    /// All winners have claimed
    Complete,
    /// Settlement failed validation
    Failed,
}

/// Batch settlement record stored on L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRecord {
    pub settlement: BatchSettlement,
    pub status: SettlementStatus,
    pub claims_processed: u32,
    pub submitted_at: u64,
    pub completed_at: Option<u64>,
}

/// Manager for batch settlements
pub struct BatchSettlementManager {
    /// batch_id -> BatchRecord
    batches: Arc<RwLock<HashMap<String, BatchRecord>>>,
    /// Claim registry for tracking withdrawals
    claims: Arc<ClaimRegistry>,
}

impl BatchSettlementManager {
    pub fn new() -> Self {
        Self {
            batches: Arc::new(RwLock::new(HashMap::new())),
            claims: Arc::new(ClaimRegistry::new()),
        }
    }
    
    /// Submit a new batch settlement
    pub fn submit_batch(&self, settlement: BatchSettlement) -> SettlementResult<String> {
        // Validate zero-sum invariant
        self.validate_zero_sum(&settlement)?;
        
        // Verify L2 signature (TODO: implement signature verification)
        // For now, we assume signature is valid
        
        let batch_id = settlement.batch_id.clone();
        
        // Check if batch already exists
        {
            let batches = self.batches.read().unwrap();
            if batches.contains_key(&batch_id) {
                return Err(SettlementError::InvalidBatch(
                    format!("Batch {} already exists", batch_id)
                ));
            }
        }
        
        // Register batch in claim registry
        self.claims.register_batch(batch_id.clone());
        
        // Store batch record
        {
            let mut batches = self.batches.write().unwrap();
            batches.insert(
                batch_id.clone(),
                BatchRecord {
                    settlement,
                    status: SettlementStatus::Pending,
                    claims_processed: 0,
                    submitted_at: current_timestamp(),
                    completed_at: None,
                },
            );
        }
        
        Ok(batch_id)
    }
    
    /// Process a single withdrawal claim
    pub fn process_claim(
        &self,
        batch_id: &str,
        withdrawal: &Withdrawal,
    ) -> SettlementResult<String> {
        // Get batch record
        let batch_record = {
            let batches = self.batches.read().unwrap();
            batches
                .get(batch_id)
                .ok_or_else(|| SettlementError::BatchNotFound(batch_id.to_string()))?
                .clone()
        };
        
        // Generate withdrawal ID
        let withdrawal_id = generate_withdrawal_id(
            batch_id,
            &withdrawal.address,
            withdrawal.amount,
        );
        
        // Check if already claimed
        if self.claims.is_claimed(batch_id, &withdrawal_id) {
            return Err(SettlementError::AlreadyClaimed);
        }
        
        // Verify merkle proof
        let proof = withdrawal
            .merkle_proof
            .as_ref()
            .ok_or_else(|| SettlementError::InvalidBatch("Missing merkle proof".to_string()))?;
        
        let payout = PayoutLeaf {
            address: withdrawal.address.clone(),
            amount: withdrawal.amount,
        };
        
        let is_valid = verify_merkle_proof(
            &payout,
            proof,
            &batch_record.settlement.merkle_root,
        );
        
        if !is_valid {
            return Err(SettlementError::InvalidMerkleProof);
        }
        
        // Mark as claimed (would normally credit user's L1 balance here)
        let tx_hash = format!("tx_{}", current_timestamp());
        self.claims
            .mark_claimed(
                batch_id.to_string(),
                withdrawal_id.clone(),
                withdrawal.address.clone(),
                withdrawal.amount,
                tx_hash.clone(),
            )
            .map_err(|e| SettlementError::StorageError(e))?;
        
        // Update batch status
        {
            let mut batches = self.batches.write().unwrap();
            if let Some(record) = batches.get_mut(batch_id) {
                record.claims_processed += 1;
                
                // Check if all claims processed
                if record.claims_processed >= batch_record.settlement.total_winners {
                    record.status = SettlementStatus::Complete;
                    record.completed_at = Some(current_timestamp());
                } else {
                    record.status = SettlementStatus::PartiallyComplete;
                }
            }
        }
        
        Ok(tx_hash)
    }
    
    /// Get batch record
    pub fn get_batch(&self, batch_id: &str) -> Option<BatchRecord> {
        let batches = self.batches.read().unwrap();
        batches.get(batch_id).cloned()
    }
    
    /// Get claim count for a batch
    pub fn get_claim_count(&self, batch_id: &str) -> usize {
        self.claims.get_claim_count(batch_id)
    }
    
    /// Check if a specific withdrawal has been claimed
    pub fn is_claimed(&self, batch_id: &str, withdrawal_id: &str) -> bool {
        self.claims.is_claimed(batch_id, withdrawal_id)
    }
    
    /// Validate zero-sum invariant
    fn validate_zero_sum(&self, settlement: &BatchSettlement) -> SettlementResult<()> {
        let expected_payout = settlement.total_collateral.saturating_sub(settlement.fees_collected);
        
        // Allow 1 unit tolerance for rounding
        let diff = (settlement.total_payout as i64 - expected_payout as i64).abs();
        
        if diff > 1 {
            return Err(SettlementError::ZeroSumViolation {
                payouts: settlement.total_payout as f64 / 1_000_000.0,
                collateral: settlement.total_collateral as f64 / 1_000_000.0,
                fees: settlement.fees_collected as f64 / 1_000_000.0,
            });
        }
        
        Ok(())
    }
}

impl Default for BatchSettlementManager {
    fn default() -> Self {
        Self::new()
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::merkle::{create_merkle_tree, PayoutLeaf};

    fn create_test_settlement(
        batch_id: &str,
        payouts: &[PayoutLeaf],
    ) -> (BatchSettlement, Vec<Withdrawal>) {
        let tree = create_merkle_tree(payouts);
        let merkle_root = tree.root_hex();
        
        let total_payout: u64 = payouts.iter().map(|p| p.amount).sum();
        let fees = total_payout / 20; // 5% fees
        let total_collateral = total_payout + fees;
        
        let mut withdrawals = Vec::new();
        for (i, payout) in payouts.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            withdrawals.push(Withdrawal {
                address: payout.address.clone(),
                amount: payout.amount,
                merkle_proof: Some(proof),
            });
        }
        
        let settlement = BatchSettlement {
            batch_id: batch_id.to_string(),
            market_id: "market_test".to_string(),
            merkle_root,
            total_winners: payouts.len() as u32,
            total_payout,
            total_collateral,
            fees_collected: fees,
            l2_signature: "sig_placeholder".to_string(),
            l2_public_key: "pubkey_placeholder".to_string(),
            timestamp: current_timestamp(),
            withdrawals: None,
        };
        
        (settlement, withdrawals)
    }

    #[test]
    fn test_submit_batch() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_alice".to_string(), amount: 100_000_000 },
            PayoutLeaf { address: "bb_bob".to_string(), amount: 200_000_000 },
        ];
        
        let (settlement, _) = create_test_settlement("batch_1", &payouts);
        
        let result = manager.submit_batch(settlement);
        assert!(result.is_ok());
        
        let batch = manager.get_batch("batch_1").unwrap();
        assert_eq!(batch.status, SettlementStatus::Pending);
        assert_eq!(batch.claims_processed, 0);
    }

    #[test]
    fn test_process_claim() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_winner1".to_string(), amount: 50_000_000 },
            PayoutLeaf { address: "bb_winner2".to_string(), amount: 75_000_000 },
        ];
        
        let (settlement, withdrawals) = create_test_settlement("batch_2", &payouts);
        
        manager.submit_batch(settlement).unwrap();
        
        // Process first claim
        let result = manager.process_claim("batch_2", &withdrawals[0]);
        assert!(result.is_ok());
        
        let batch = manager.get_batch("batch_2").unwrap();
        assert_eq!(batch.status, SettlementStatus::PartiallyComplete);
        assert_eq!(batch.claims_processed, 1);
    }

    #[test]
    fn test_double_claim_prevention() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_user".to_string(), amount: 100_000_000 },
        ];
        
        let (settlement, withdrawals) = create_test_settlement("batch_3", &payouts);
        
        manager.submit_batch(settlement).unwrap();
        
        // First claim succeeds
        let result1 = manager.process_claim("batch_3", &withdrawals[0]);
        assert!(result1.is_ok());
        
        // Second claim fails
        let result2 = manager.process_claim("batch_3", &withdrawals[0]);
        assert!(result2.is_err());
        assert!(matches!(result2, Err(SettlementError::AlreadyClaimed)));
    }

    #[test]
    fn test_batch_completion() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_w1".to_string(), amount: 10_000_000 },
            PayoutLeaf { address: "bb_w2".to_string(), amount: 20_000_000 },
        ];
        
        let (settlement, withdrawals) = create_test_settlement("batch_4", &payouts);
        
        manager.submit_batch(settlement).unwrap();
        
        // Process both claims
        manager.process_claim("batch_4", &withdrawals[0]).unwrap();
        manager.process_claim("batch_4", &withdrawals[1]).unwrap();
        
        let batch = manager.get_batch("batch_4").unwrap();
        assert_eq!(batch.status, SettlementStatus::Complete);
        assert_eq!(batch.claims_processed, 2);
        assert!(batch.completed_at.is_some());
    }

    #[test]
    fn test_invalid_proof() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_real".to_string(), amount: 100_000_000 },
        ];
        
        let (settlement, _) = create_test_settlement("batch_5", &payouts);
        
        manager.submit_batch(settlement).unwrap();
        
        // Create fake withdrawal with wrong proof
        let fake_withdrawal = Withdrawal {
            address: "bb_attacker".to_string(),
            amount: 999_999_999,
            merkle_proof: Some(super::super::merkle::MerkleProof {
                proof_hashes: vec!["0".repeat(64)],
                proof_indices: vec![0],
                leaf_index: 0,
            }),
        };
        
        let result = manager.process_claim("batch_5", &fake_withdrawal);
        assert!(result.is_err());
        assert!(matches!(result, Err(SettlementError::InvalidMerkleProof)));
    }

    #[test]
    fn test_zero_sum_violation() {
        let manager = BatchSettlementManager::new();
        
        let payouts = vec![
            PayoutLeaf { address: "bb_user".to_string(), amount: 100_000_000 },
        ];
        
        let tree = create_merkle_tree(&payouts);
        
        // Create settlement that violates zero-sum
        let bad_settlement = BatchSettlement {
            batch_id: "batch_bad".to_string(),
            market_id: "market_bad".to_string(),
            merkle_root: tree.root_hex(),
            total_winners: 1,
            total_payout: 100_000_000,
            total_collateral: 50_000_000,  // Only half the payout!
            fees_collected: 0,
            l2_signature: "sig".to_string(),
            l2_public_key: "pub".to_string(),
            timestamp: current_timestamp(),
            withdrawals: None,
        };
        
        let result = manager.submit_batch(bad_settlement);
        assert!(result.is_err());
        assert!(matches!(result, Err(SettlementError::ZeroSumViolation { .. })));
    }
}
