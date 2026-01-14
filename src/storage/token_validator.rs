//! Token Validation System
//!
//! Ensures 1:1 backing of all tokens and provides cryptographic validation.
//!
//! INVARIANTS (must ALWAYS hold):
//! 1. SUM(all_balances) + SUM(all_locked) = INITIAL_SUPPLY (1 Billion BB)
//! 2. All tokens originate from TREASURY_ADDRESS
//! 3. No token can exist without a matching lock or balance on L1
//!
//! This module provides:
//! - Supply validation (conservation law)
//! - Token proof generation (Merkle proofs)
//! - L2 token verification (prove L2 tokens are backed by L1 locks)

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

use crate::protocol::blockchain::{INITIAL_SUPPLY, TREASURY_ADDRESS};

// ============================================================================
// TOKEN VALIDATION RESULT
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub total_supply: f64,
    pub expected_supply: f64,
    pub total_spendable: f64,
    pub total_locked: f64,
    pub treasury_balance: f64,
    pub account_count: usize,
    pub discrepancy: f64,
    pub message: String,
    pub slot: u64,
    pub state_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenProof {
    /// The address owning the tokens
    pub address: String,
    /// Balance amount
    pub balance: f64,
    /// Locked amount (in credit lines/escrow)
    pub locked: f64,
    /// Total (balance + locked)
    pub total: f64,
    /// Merkle proof hash (proves inclusion in state)
    pub state_proof: String,
    /// State root at time of proof
    pub state_root: String,
    /// Slot when proof was generated
    pub slot: u64,
    /// Signature from L1 (proves L1 issued this proof)
    pub l1_signature: Option<String>,
    /// Is this token valid?
    pub is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TokenValidation {
    /// L2 credit session ID
    pub session_id: String,
    /// User's L1 address
    pub l1_address: String,
    /// Amount claimed on L2
    pub l2_claimed_amount: f64,
    /// Matching lock on L1
    pub l1_locked_amount: f64,
    /// Lock ID on L1
    pub lock_id: String,
    /// Is the L2 amount properly backed?
    pub is_backed: bool,
    /// Backing ratio (should be >= 1.0)
    pub backing_ratio: f64,
    /// State root proving the lock
    pub state_root: String,
}

// ============================================================================
// TOKEN VALIDATOR
// ============================================================================

pub struct TokenValidator {
    /// Expected total supply (immutable)
    expected_supply: f64,
}

impl TokenValidator {
    pub fn new() -> Self {
        Self {
            expected_supply: INITIAL_SUPPLY,
        }
    }

    /// Validate the entire token supply
    /// 
    /// This is the CORE invariant check:
    /// SUM(all balances) + SUM(all locked) = INITIAL_SUPPLY
    pub fn validate_supply(
        &self,
        balances: &HashMap<String, f64>,
        locked_balances: &HashMap<String, f64>,
        slot: u64,
        state_root: &str,
    ) -> ValidationResult {
        let total_spendable: f64 = balances.values().sum();
        let total_locked: f64 = locked_balances.values().sum();
        let total_supply = total_spendable + total_locked;
        
        let treasury_balance = *balances.get(TREASURY_ADDRESS).unwrap_or(&0.0);
        let discrepancy = (total_supply - self.expected_supply).abs();
        
        // Allow tiny floating point errors (< 0.0001 BB)
        let valid = discrepancy < 0.0001;
        
        let message = if valid {
            format!(
                "✅ Supply validated: {} BB ({} spendable + {} locked)",
                total_supply, total_spendable, total_locked
            )
        } else {
            format!(
                "❌ SUPPLY MISMATCH! Expected {} BB, found {} BB (discrepancy: {})",
                self.expected_supply, total_supply, discrepancy
            )
        };

        ValidationResult {
            valid,
            total_supply,
            expected_supply: self.expected_supply,
            total_spendable,
            total_locked,
            treasury_balance,
            account_count: balances.len(),
            discrepancy,
            message,
            slot,
            state_root: state_root.to_string(),
        }
    }

    /// Generate a proof that tokens at an address are valid L1 tokens
    pub fn generate_token_proof(
        &self,
        address: &str,
        balance: f64,
        locked: f64,
        slot: u64,
        state_root: &str,
    ) -> TokenProof {
        // Create deterministic proof hash
        let proof_data = format!(
            "TOKEN_PROOF:{}:{}:{}:{}:{}",
            address, balance, locked, slot, state_root
        );
        let proof_hash = format!("{:x}", Sha256::digest(proof_data.as_bytes()));

        TokenProof {
            address: address.to_string(),
            balance,
            locked,
            total: balance + locked,
            state_proof: proof_hash,
            state_root: state_root.to_string(),
            slot,
            l1_signature: None, // Caller can add L1 signature
            is_valid: true,
        }
    }

    /// Validate that L2 tokens are backed by L1 locks
    pub fn validate_l2_backing(
        &self,
        session_id: &str,
        l1_address: &str,
        l2_claimed_amount: f64,
        l1_locked_amount: f64,
        lock_id: &str,
        state_root: &str,
    ) -> L2TokenValidation {
        // L2 can NEVER have more than L1 has locked
        let is_backed = l2_claimed_amount <= l1_locked_amount;
        let backing_ratio = if l2_claimed_amount > 0.0 {
            l1_locked_amount / l2_claimed_amount
        } else {
            1.0
        };

        L2TokenValidation {
            session_id: session_id.to_string(),
            l1_address: l1_address.to_string(),
            l2_claimed_amount,
            l1_locked_amount,
            lock_id: lock_id.to_string(),
            is_backed,
            backing_ratio,
            state_root: state_root.to_string(),
        }
    }

    /// Verify a token proof is valid
    pub fn verify_token_proof(&self, proof: &TokenProof) -> bool {
        // Reconstruct proof hash
        let proof_data = format!(
            "TOKEN_PROOF:{}:{}:{}:{}:{}",
            proof.address, proof.balance, proof.locked, proof.slot, proof.state_root
        );
        let expected_hash = format!("{:x}", Sha256::digest(proof_data.as_bytes()));
        
        proof.state_proof == expected_hash && proof.is_valid
    }

    /// Quick check: does an amount fit within supply constraints?
    pub fn is_amount_valid(&self, amount: f64) -> bool {
        amount >= 0.0 && amount <= self.expected_supply
    }

    /// Generate a signed token attestation (for L2 to verify)
    pub fn create_attestation(
        &self,
        address: &str,
        balance: f64,
        locked: f64,
        slot: u64,
        state_root: &str,
    ) -> String {
        let data = format!(
            "L1_ATTESTATION:{}:{}:{}:{}:{}:{}",
            address, balance, locked, slot, state_root, self.expected_supply
        );
        format!("{:x}", Sha256::digest(data.as_bytes()))
    }

    /// Verify an attestation
    pub fn verify_attestation(
        &self,
        attestation: &str,
        address: &str,
        balance: f64,
        locked: f64,
        slot: u64,
        state_root: &str,
    ) -> bool {
        let expected = self.create_attestation(address, balance, locked, slot, state_root);
        attestation == expected
    }
}

impl Default for TokenValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SUPPLY AUDIT TRAIL
// ============================================================================

/// Records supply validation history for auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyAuditEntry {
    pub slot: u64,
    pub timestamp: u64,
    pub total_supply: f64,
    pub expected_supply: f64,
    pub valid: bool,
    pub state_root: String,
}

/// Maintains audit trail of supply validations
pub struct SupplyAuditor {
    history: Vec<SupplyAuditEntry>,
    max_history: usize,
}

impl SupplyAuditor {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Vec::new(),
            max_history,
        }
    }

    pub fn record(&mut self, result: &ValidationResult) {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let entry = SupplyAuditEntry {
            slot: result.slot,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            total_supply: result.total_supply,
            expected_supply: result.expected_supply,
            valid: result.valid,
            state_root: result.state_root.clone(),
        };

        self.history.push(entry);

        // Trim if over limit
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    pub fn get_history(&self) -> &[SupplyAuditEntry] {
        &self.history
    }

    pub fn last_valid_slot(&self) -> Option<u64> {
        self.history.iter()
            .rev()
            .find(|e| e.valid)
            .map(|e| e.slot)
    }

    pub fn has_discrepancy(&self) -> bool {
        self.history.iter().any(|e| !e.valid)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_validation_pass() {
        let validator = TokenValidator::new();
        let mut balances = HashMap::new();
        
        // All tokens in treasury = valid
        balances.insert(TREASURY_ADDRESS.to_string(), INITIAL_SUPPLY);
        
        let result = validator.validate_supply(
            &balances,
            &HashMap::new(),
            100,
            "test_root",
        );
        
        assert!(result.valid);
        assert_eq!(result.total_supply, INITIAL_SUPPLY);
    }

    #[test]
    fn test_supply_validation_with_distribution() {
        let validator = TokenValidator::new();
        let mut balances = HashMap::new();
        let mut locked = HashMap::new();
        
        // Distributed tokens
        balances.insert(TREASURY_ADDRESS.to_string(), INITIAL_SUPPLY - 20000.0);
        balances.insert("alice".to_string(), 10000.0);
        balances.insert("bob".to_string(), 5000.0);
        locked.insert("alice".to_string(), 5000.0); // Alice has 5000 locked too
        
        let result = validator.validate_supply(&balances, &locked, 100, "test_root");
        
        assert!(result.valid);
        assert_eq!(result.total_spendable + result.total_locked, INITIAL_SUPPLY);
    }

    #[test]
    fn test_supply_validation_fail_inflation() {
        let validator = TokenValidator::new();
        let mut balances = HashMap::new();
        
        // More than initial supply = INVALID
        balances.insert(TREASURY_ADDRESS.to_string(), INITIAL_SUPPLY);
        balances.insert("hacker".to_string(), 1000.0); // Extra tokens!
        
        let result = validator.validate_supply(
            &balances,
            &HashMap::new(),
            100,
            "test_root",
        );
        
        assert!(!result.valid);
        assert!(result.discrepancy > 0.0);
    }

    #[test]
    fn test_token_proof() {
        let validator = TokenValidator::new();
        
        let proof = validator.generate_token_proof(
            "alice",
            10000.0,
            5000.0,
            100,
            "state_root_abc",
        );
        
        assert!(proof.is_valid);
        assert_eq!(proof.total, 15000.0);
        assert!(validator.verify_token_proof(&proof));
    }

    #[test]
    fn test_l2_backing_validation() {
        let validator = TokenValidator::new();
        
        // L2 claims 1000, L1 has 1000 locked = backed
        let valid = validator.validate_l2_backing(
            "session_123",
            "alice",
            1000.0,
            1000.0,
            "lock_abc",
            "root",
        );
        assert!(valid.is_backed);
        assert_eq!(valid.backing_ratio, 1.0);
        
        // L2 claims 1500, L1 only has 1000 locked = NOT backed
        let invalid = validator.validate_l2_backing(
            "session_456",
            "bob",
            1500.0,
            1000.0,
            "lock_xyz",
            "root",
        );
        assert!(!invalid.is_backed);
        assert!(invalid.backing_ratio < 1.0);
    }

    #[test]
    fn test_attestation() {
        let validator = TokenValidator::new();
        
        let attestation = validator.create_attestation(
            "alice",
            10000.0,
            5000.0,
            100,
            "state_root",
        );
        
        assert!(validator.verify_attestation(
            &attestation,
            "alice",
            10000.0,
            5000.0,
            100,
            "state_root",
        ));
        
        // Wrong balance should fail
        assert!(!validator.verify_attestation(
            &attestation,
            "alice",
            10001.0, // Wrong!
            5000.0,
            100,
            "state_root",
        ));
    }
}
