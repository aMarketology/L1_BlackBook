//! settlement.rs - L1 Validator Settlement Logic (Dealer/Solver Model)
//! 
//! ============================================================================
//! ARCHITECTURE: L1 IS A BANK TELLER, NOT A PIT BOSS
//! ============================================================================
//! 
//! The L1 Validator does NOT know about:
//! - Bets, markets, outcomes, or odds
//! - L2 state or prediction market logic
//! 
//! The L1 Validator ONLY knows:
//! - Did the user sign an authorization to transfer X tokens to the Dealer?
//! - Does the user have sufficient balance?
//! - Has this nonce been used before (replay protection)?
//!
//! FLOW:
//! 1. User places bet on L2 → Dealer FRONTS the L2 tokens instantly
//! 2. User signs Intent authorizing L1 reimbursement to Dealer
//! 3. Dealer batches Intents and submits to L1 for settlement
//! 4. L1 verifies signatures, debits users, credits Dealer
//!
//! This is optimized for HIGH VOLUME - no L2 logic bloat on L1.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use sha2::{Sha256, Digest};

// Global counter for settlement receipts
static SETTLEMENT_ID: AtomicU64 = AtomicU64::new(1);
static BATCH_ID: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// CORE TYPES
// ============================================================================

/// Microtokens (1 BB = 1,000,000 microtokens)
pub type Microtokens = u64;

/// Convert BB to microtokens
pub fn bb_to_microtokens(bb: f64) -> Microtokens { (bb * 1_000_000.0) as Microtokens }

/// Convert microtokens to BB  
pub fn microtokens_to_bb(mt: Microtokens) -> f64 { mt as f64 / 1_000_000.0 }

/// L1 Account - Simple balance tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L1Account {
    pub available: Microtokens,
    pub last_nonce: u64,
    pub last_sync: u64,
}

impl L1Account {
    pub fn new() -> Self { Self::default() }
    pub fn with_balance(amount: Microtokens) -> Self { 
        L1Account { available: amount, ..Default::default() } 
    }
    pub fn available_bb(&self) -> f64 { microtokens_to_bb(self.available) }
}

/// Settlement errors - L1 only cares about these
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettlementError {
    InvalidSignature,
    ReplayAttack { nonce: u64 },
    InsufficientFunds { required: Microtokens, available: Microtokens },
    InvalidPublicKey,
    BatchEmpty,
    DealerNotFound,
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::ReplayAttack { nonce } => write!(f, "Replay attack: nonce {} already used", nonce),
            Self::InsufficientFunds { required, available } => 
                write!(f, "Insufficient funds: need {}, have {}", required, available),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::BatchEmpty => write!(f, "Batch is empty"),
            Self::DealerNotFound => write!(f, "Dealer account not found"),
        }
    }
}

impl std::error::Error for SettlementError {}

// ============================================================================
// INTENT - The "Check" the user signs
// ============================================================================

/// SolverIntent - User's signed authorization for L1 transfer to Dealer
/// 
/// This is the ONLY thing L1 needs to see. The bet_metadata_hash proves
/// the user agreed to specific bet terms, but L1 doesn't decode it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverIntent {
    /// User's wallet address (the one being debited)
    pub user_address: String,
    /// Amount in microtokens
    pub amount: Microtokens,
    /// Unique nonce for replay protection (must be > last_nonce)
    pub nonce: u64,
    /// Dealer's wallet address (the one being credited)
    pub dealer_address: String,
    /// SHA256 hash of bet metadata (market_id, outcome, price, etc.)
    /// L1 doesn't parse this - just includes in signature verification
    pub metadata_hash: [u8; 32],
    /// Unix timestamp when intent was created
    pub timestamp: u64,
}

impl SolverIntent {
    /// Create signing message (what the user actually signs)
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"BLACKBOOK_SETTLEMENT_V1:");
        msg.extend_from_slice(self.user_address.as_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(self.dealer_address.as_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&self.metadata_hash);
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg
    }
    
    /// Hash the intent for logging/receipts
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.signing_message());
        hasher.finalize().into()
    }
}

/// Signed intent ready for settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedIntent {
    pub intent: SolverIntent,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
}

/// Hex serialization helper for byte arrays
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// SETTLEMENT RECEIPT - Proof of L1 transfer
// ============================================================================

/// Individual settlement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: u64,
    pub user_address: String,
    pub dealer_address: String,
    pub amount: Microtokens,
    pub user_remaining: Microtokens,
    pub intent_hash: [u8; 32],
    pub timestamp: u64,
}

/// Batch settlement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSettlementResult {
    pub batch_id: u64,
    pub total_settled: Microtokens,
    pub successful: Vec<SettlementReceipt>,
    pub failed: Vec<(String, SettlementError)>, // (user_address, error)
    pub timestamp: u64,
}

// ============================================================================
// SETTLEMENT EXECUTOR
// ============================================================================

/// Settlement Executor - Processes intents and updates L1 balances
pub struct SettlementExecutor {
    /// L1 accounts (address -> account)
    accounts: HashMap<String, L1Account>,
    /// Dealer's L1 account
    dealer_account: L1Account,
    dealer_address: String,
}

impl SettlementExecutor {
    pub fn new(dealer_address: String, dealer_initial_balance: Microtokens) -> Self {
        let mut accounts = HashMap::new();
        let dealer_account = L1Account::with_balance(dealer_initial_balance);
        accounts.insert(dealer_address.clone(), dealer_account.clone());
        
        Self {
            accounts,
            dealer_account,
            dealer_address,
        }
    }
    
    /// Get or create an L1 account
    pub fn get_account(&self, address: &str) -> Option<&L1Account> {
        self.accounts.get(address)
    }
    
    /// Get mutable account
    pub fn get_account_mut(&mut self, address: &str) -> Option<&mut L1Account> {
        self.accounts.get_mut(address)
    }
    
    /// Create account with initial balance (for testing/airdrops)
    pub fn create_account(&mut self, address: String, initial_balance: Microtokens) {
        self.accounts.insert(address, L1Account::with_balance(initial_balance));
    }
    
    /// Execute a single settlement
    pub fn execute_single(&mut self, signed: &SignedIntent) -> Result<SettlementReceipt, SettlementError> {
        let intent = &signed.intent;
        
        // 1. SIGNATURE VERIFICATION
        if !self.verify_signature(signed)? {
            return Err(SettlementError::InvalidSignature);
        }
        
        // 2. GET USER ACCOUNT
        let user_acc = self.accounts.get_mut(&intent.user_address)
            .ok_or(SettlementError::InsufficientFunds { 
                required: intent.amount, 
                available: 0 
            })?;
        
        // 3. REPLAY PROTECTION
        if user_acc.last_nonce >= intent.nonce {
            return Err(SettlementError::ReplayAttack { nonce: intent.nonce });
        }
        
        // 4. BALANCE CHECK
        if user_acc.available < intent.amount {
            return Err(SettlementError::InsufficientFunds {
                required: intent.amount,
                available: user_acc.available,
            });
        }
        
        // 5. ATOMIC SETTLEMENT
        let now = get_timestamp();
        user_acc.available -= intent.amount;
        user_acc.last_nonce = intent.nonce;
        user_acc.last_sync = now;
        
        let user_remaining = user_acc.available;
        
        // Credit dealer
        self.dealer_account.available += intent.amount;
        self.dealer_account.last_sync = now;
        
        // Update dealer in accounts map too
        if let Some(dealer) = self.accounts.get_mut(&self.dealer_address) {
            dealer.available = self.dealer_account.available;
            dealer.last_sync = now;
        }
        
        Ok(SettlementReceipt {
            settlement_id: SETTLEMENT_ID.fetch_add(1, Ordering::SeqCst),
            user_address: intent.user_address.clone(),
            dealer_address: intent.dealer_address.clone(),
            amount: intent.amount,
            user_remaining,
            intent_hash: intent.hash(),
            timestamp: now,
        })
    }
    
    /// Execute batch settlement (optimized for high volume)
    pub fn execute_batch(&mut self, intents: Vec<SignedIntent>) -> BatchSettlementResult {
        if intents.is_empty() {
            return BatchSettlementResult {
                batch_id: BATCH_ID.fetch_add(1, Ordering::SeqCst),
                total_settled: 0,
                successful: vec![],
                failed: vec![],
                timestamp: get_timestamp(),
            };
        }
        
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut total_settled: Microtokens = 0;
        
        for signed in intents {
            let user_addr = signed.intent.user_address.clone();
            match self.execute_single(&signed) {
                Ok(receipt) => {
                    total_settled += receipt.amount;
                    successful.push(receipt);
                }
                Err(e) => {
                    failed.push((user_addr, e));
                }
            }
        }
        
        BatchSettlementResult {
            batch_id: BATCH_ID.fetch_add(1, Ordering::SeqCst),
            total_settled,
            successful,
            failed,
            timestamp: get_timestamp(),
        }
    }
    
    /// Verify Ed25519 signature
    fn verify_signature(&self, signed: &SignedIntent) -> Result<bool, SettlementError> {
        // Convert Vec<u8> to fixed arrays
        let pk_bytes: [u8; 32] = signed.public_key.as_slice()
            .try_into()
            .map_err(|_| SettlementError::InvalidPublicKey)?;
        
        let sig_bytes: [u8; 64] = signed.signature.as_slice()
            .try_into()
            .map_err(|_| SettlementError::InvalidSignature)?;
        
        let public_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| SettlementError::InvalidPublicKey)?;
        
        let signature = Signature::from_bytes(&sig_bytes);
        let message = signed.intent.signing_message();
        
        Ok(public_key.verify(&message, &signature).is_ok())
    }
    
    /// Get dealer's current balance
    pub fn dealer_balance(&self) -> Microtokens {
        self.dealer_account.available
    }
    
    /// Get total accounts count
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

// ============================================================================
// HELPERS
// ============================================================================

fn get_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Create metadata hash from bet details (for L2 to use)
pub fn hash_bet_metadata(market_id: &str, outcome: &str, price_bps: u32, bet_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BET:");
    hasher.update(market_id.as_bytes());
    hasher.update(b":");
    hasher.update(outcome.as_bytes());
    hasher.update(b":");
    hasher.update(&price_bps.to_le_bytes());
    hasher.update(b":");
    hasher.update(bet_id.as_bytes());
    hasher.finalize().into()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    
    fn create_test_intent(user: &str, amount: Microtokens, nonce: u64, dealer: &str) -> SolverIntent {
        SolverIntent {
            user_address: user.to_string(),
            amount,
            nonce,
            dealer_address: dealer.to_string(),
            metadata_hash: hash_bet_metadata("market_1", "YES", 5000, "bet_123"),
            timestamp: get_timestamp(),
        }
    }
    
    fn sign_intent(intent: &SolverIntent, signing_key: &SigningKey) -> SignedIntent {
        let message = intent.signing_message();
        let signature = signing_key.sign(&message);
        
        SignedIntent {
            intent: intent.clone(),
            signature: signature.to_bytes().to_vec(),
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
        }
    }
    
    #[test]
    fn test_single_settlement() {
        let mut executor = SettlementExecutor::new("DEALER".to_string(), 0);
        executor.create_account("ALICE".to_string(), bb_to_microtokens(1000.0));
        
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let intent = create_test_intent("ALICE", bb_to_microtokens(100.0), 1, "DEALER");
        let signed = sign_intent(&intent, &signing_key);
        
        let result = executor.execute_single(&signed);
        assert!(result.is_ok());
        
        let receipt = result.unwrap();
        assert_eq!(receipt.amount, bb_to_microtokens(100.0));
        assert_eq!(executor.dealer_balance(), bb_to_microtokens(100.0));
    }
    
    #[test]
    fn test_replay_protection() {
        let mut executor = SettlementExecutor::new("DEALER".to_string(), 0);
        executor.create_account("ALICE".to_string(), bb_to_microtokens(1000.0));
        
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let intent = create_test_intent("ALICE", bb_to_microtokens(50.0), 1, "DEALER");
        let signed = sign_intent(&intent, &signing_key);
        
        // First settlement should succeed
        assert!(executor.execute_single(&signed).is_ok());
        
        // Same nonce should fail
        let result = executor.execute_single(&signed);
        assert!(matches!(result, Err(SettlementError::ReplayAttack { .. })));
    }
    
    #[test]
    fn test_insufficient_funds() {
        let mut executor = SettlementExecutor::new("DEALER".to_string(), 0);
        executor.create_account("BOB".to_string(), bb_to_microtokens(10.0));
        
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let intent = create_test_intent("BOB", bb_to_microtokens(100.0), 1, "DEALER");
        let signed = sign_intent(&intent, &signing_key);
        
        let result = executor.execute_single(&signed);
        assert!(matches!(result, Err(SettlementError::InsufficientFunds { .. })));
    }
    
    #[test]
    fn test_batch_settlement() {
        let mut executor = SettlementExecutor::new("DEALER".to_string(), 0);
        executor.create_account("ALICE".to_string(), bb_to_microtokens(1000.0));
        executor.create_account("BOB".to_string(), bb_to_microtokens(500.0));
        
        let alice_key = SigningKey::generate(&mut rand::thread_rng());
        let bob_key = SigningKey::generate(&mut rand::thread_rng());
        
        let intents = vec![
            sign_intent(&create_test_intent("ALICE", bb_to_microtokens(100.0), 1, "DEALER"), &alice_key),
            sign_intent(&create_test_intent("BOB", bb_to_microtokens(50.0), 1, "DEALER"), &bob_key),
            sign_intent(&create_test_intent("ALICE", bb_to_microtokens(200.0), 2, "DEALER"), &alice_key),
        ];
        
        let result = executor.execute_batch(intents);
        
        assert_eq!(result.successful.len(), 3);
        assert_eq!(result.failed.len(), 0);
        assert_eq!(result.total_settled, bb_to_microtokens(350.0));
        assert_eq!(executor.dealer_balance(), bb_to_microtokens(350.0));
    }
}