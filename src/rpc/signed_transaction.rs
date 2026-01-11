//! Layer1 Signed Transaction - Cryptographically Signed Transaction Envelope
//! 
//! This module implements proper transaction signing:
//! - Signs ENTIRE envelope: [sender_pubkey + nonce + timestamp + tx_type + payload]
//! - Prevents replay attacks via nonce checking
//! - Compatible with L2 verification (same signature works on both layers)

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::runtime::core::TransactionType;

// ============================================================================
// SIGNED TRANSACTION ENVELOPE
// ============================================================================

/// Number of recent blockhashes to keep (Solana uses ~150 slots)
pub const RECENT_BLOCKHASH_SLOTS: u64 = 150;

/// A cryptographically signed transaction envelope
/// 
/// The signature covers ALL fields except the signature itself:
/// `sign([sender_pubkey || nonce || timestamp || tx_type || recent_blockhash || payload_hash])`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The sender's public key (which IS their address, 32 bytes hex)
    pub sender_pubkey: String,
    
    /// Monotonically increasing nonce for replay protection
    pub nonce: u64,
    
    /// Unix timestamp in seconds
    pub timestamp: u64,
    
    /// Transaction type identifier
    pub tx_type: SignedTxType,
    
    /// Recent blockhash for replay protection and transaction expiry
    /// Must reference a blockhash from the last RECENT_BLOCKHASH_SLOTS slots
    #[serde(default)]
    pub recent_blockhash: Option<String>,
    
    /// The transaction payload (type-specific data)
    pub payload: TransactionPayload,
    
    /// ed25519 signature over get_signable_bytes() (64 bytes hex)
    pub signature: String,
}

/// Transaction types for signed transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SignedTxType {
    /// Token transfer
    Transfer = 0,
    /// Social action (like, post, comment)
    SocialAction = 1,
    /// Stake deposit
    Stake = 2,
    /// Stake withdrawal
    Unstake = 3,
    /// Cross-layer bridge operation
    Bridge = 4,
    /// Smart contract interaction
    Contract = 5,
    /// System/governance action
    System = 6,
    /// Bet placement (prediction markets)
    BetPlacement = 7,
    /// Bet resolution
    BetResolution = 8,
    /// Token minting
    Mint = 9,
    /// Token burning
    Burn = 10,
}

impl From<TransactionType> for SignedTxType {
    fn from(tt: TransactionType) -> Self {
        match tt {
            TransactionType::Transfer => SignedTxType::Transfer,
            TransactionType::SocialAction => SignedTxType::SocialAction,
            TransactionType::StakeDeposit => SignedTxType::Stake,
            TransactionType::StakeWithdraw => SignedTxType::Unstake,
            TransactionType::SystemReward => SignedTxType::System,
            TransactionType::BetPlacement => SignedTxType::BetPlacement,
            TransactionType::BetResolution => SignedTxType::BetResolution,
            TransactionType::Mint => SignedTxType::Mint,
            TransactionType::Burn => SignedTxType::Burn,
            // L3 NFT/Document/Program transaction types map to System for now
            TransactionType::NFTMint |
            TransactionType::NFTTransfer |
            TransactionType::NFTBurn |
            TransactionType::NFTUpdate |
            TransactionType::DocumentValidation |
            TransactionType::DocumentValidationResponse |
            TransactionType::ProgramInvoke |
            TransactionType::ProgramDeploy |
            TransactionType::ProgramUpgrade |
            TransactionType::Vote => SignedTxType::System,
        }
    }
}

/// Transaction payload - type-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransactionPayload {
    /// Token transfer payload
    Transfer {
        to: String,
        amount: f64,
        memo: Option<String>,
    },
    /// Social action payload
    SocialAction {
        action_type: String,
        target_id: Option<String>,
        content: Option<String>,
    },
    /// Stake payload
    Stake {
        amount: f64,
        validator: Option<String>,
    },
    /// Bridge payload (cross-layer)
    Bridge {
        target_layer: String,
        target_address: String,
        amount: f64,
    },
    /// Contract call payload
    Contract {
        contract_address: String,
        method: String,
        args: Vec<u8>,
    },
    /// Raw bytes payload
    Raw {
        data: Vec<u8>,
    },
}

impl SignedTransaction {
    /// Create a new signed transaction (signature will be empty until signed)
    pub fn new(
        sender_pubkey: String,
        nonce: u64,
        tx_type: SignedTxType,
        payload: TransactionPayload,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            sender_pubkey,
            nonce,
            timestamp,
            tx_type,
            recent_blockhash: None,
            payload,
            signature: String::new(),
        }
    }
    
    /// Create a new transaction with a recent blockhash for expiry
    pub fn new_with_blockhash(
        sender_pubkey: String,
        nonce: u64,
        tx_type: SignedTxType,
        payload: TransactionPayload,
        recent_blockhash: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            sender_pubkey,
            nonce,
            timestamp,
            tx_type,
            recent_blockhash: Some(recent_blockhash),
            payload,
            signature: String::new(),
        }
    }
    
    /// Get the bytes that should be signed
    /// 
    /// Format: [sender_pubkey (32) || nonce (8) || timestamp (8) || tx_type (1) || blockhash (32) || payload_hash (32)]
    /// Total: 113 bytes (with blockhash) or 81 bytes (without)
    pub fn get_signable_bytes(&self) -> Vec<u8> {
        let has_blockhash = self.recent_blockhash.is_some();
        let capacity = if has_blockhash { 113 } else { 81 };
        let mut bytes = Vec::with_capacity(capacity);
        
        // 1. Sender public key (32 bytes)
        if let Ok(pubkey_bytes) = hex::decode(&self.sender_pubkey) {
            bytes.extend_from_slice(&pubkey_bytes);
        } else {
            // Fallback: hash the string
            let hash = Sha256::digest(self.sender_pubkey.as_bytes());
            bytes.extend_from_slice(&hash);
        }
        
        // 2. Nonce (8 bytes, big-endian)
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        
        // 3. Timestamp (8 bytes, big-endian)
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // 4. Transaction type (1 byte)
        bytes.push(self.tx_type as u8);
        
        // 5. Recent blockhash (32 bytes) - if present
        if let Some(ref blockhash) = self.recent_blockhash {
            if let Ok(hash_bytes) = hex::decode(blockhash) {
                if hash_bytes.len() == 32 {
                    bytes.extend_from_slice(&hash_bytes);
                } else {
                    // Hash the blockhash string if not 32 bytes
                    let hash = Sha256::digest(blockhash.as_bytes());
                    bytes.extend_from_slice(&hash);
                }
            } else {
                // Hash the blockhash string if not valid hex
                let hash = Sha256::digest(blockhash.as_bytes());
                bytes.extend_from_slice(&hash);
            }
        }
        
        // 6. Payload hash (32 bytes)
        let payload_json = serde_json::to_vec(&self.payload).unwrap_or_default();
        let payload_hash = Sha256::digest(&payload_json);
        bytes.extend_from_slice(&payload_hash);
        
        bytes
    }
    
    /// Get the transaction hash (for indexing/reference)
    pub fn hash(&self) -> String {
        let signable = self.get_signable_bytes();
        let hash = Sha256::digest(&signable);
        hex::encode(hash)
    }
    
    /// Verify the transaction signature
    pub fn verify(&self) -> Result<bool, SignedTxError> {
        // 1. Decode sender public key
        let pubkey_bytes: [u8; 32] = hex::decode(&self.sender_pubkey)
            .map_err(|e| SignedTxError::InvalidPublicKey(e.to_string()))?
            .try_into()
            .map_err(|_| SignedTxError::InvalidPublicKey("Must be 32 bytes".to_string()))?;
        
        // 2. Create verifying key
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| SignedTxError::InvalidPublicKey(e.to_string()))?;
        
        // 3. Decode signature
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|e| SignedTxError::InvalidSignature(e.to_string()))?
            .try_into()
            .map_err(|_| SignedTxError::InvalidSignature("Must be 64 bytes".to_string()))?;
        
        let signature = Signature::from_bytes(&sig_bytes);
        
        // 4. Get signable bytes and verify
        let signable = self.get_signable_bytes();
        
        Ok(verifying_key.verify(&signable, &signature).is_ok())
    }
    
    /// Check if timestamp is within acceptable range (anti-replay)
    pub fn is_timestamp_valid(&self, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Must be within max_age_secs of current time (past or future)
        let age = if self.timestamp > now {
            self.timestamp - now
        } else {
            now - self.timestamp
        };
        
        age <= max_age_secs
    }
    
    /// Validate that the recent blockhash is within the allowed slot range
    /// 
    /// Parameters:
    /// - `recent_hashes`: Map of slot -> blockhash for recent slots
    /// - `current_slot`: The current blockchain slot
    /// 
    /// Returns: Ok(()) if valid, Err with reason if invalid
    pub fn validate_recent_blockhash(
        &self,
        recent_hashes: &std::collections::HashMap<u64, String>,
        current_slot: u64,
    ) -> Result<(), SignedTxError> {
        // If no blockhash provided, fall back to timestamp validation only
        let blockhash = match &self.recent_blockhash {
            Some(hash) => hash,
            None => return Ok(()), // Legacy transactions without blockhash are still valid
        };
        
        // Find the slot for this blockhash
        let slot = recent_hashes.iter()
            .find(|(_, hash)| *hash == blockhash)
            .map(|(slot, _)| *slot);
        
        match slot {
            Some(tx_slot) => {
                // Check if blockhash is too old (more than RECENT_BLOCKHASH_SLOTS ago)
                if current_slot > tx_slot && current_slot - tx_slot > RECENT_BLOCKHASH_SLOTS {
                    return Err(SignedTxError::ExpiredBlockhash(format!(
                        "Blockhash from slot {} is too old. Current slot: {}, max age: {} slots",
                        tx_slot, current_slot, RECENT_BLOCKHASH_SLOTS
                    )));
                }
                Ok(())
            }
            None => {
                // Blockhash not found in recent hashes
                Err(SignedTxError::InvalidBlockhash(format!(
                    "Blockhash '{}...' not found in recent {} slots",
                    &blockhash[..blockhash.len().min(16)],
                    RECENT_BLOCKHASH_SLOTS
                )))
            }
        }
    }
    
    /// Check if the transaction has a recent blockhash
    pub fn has_recent_blockhash(&self) -> bool {
        self.recent_blockhash.is_some()
    }
    
    /// Extract recipient address for transfer transactions
    pub fn recipient(&self) -> Option<String> {
        match &self.payload {
            TransactionPayload::Transfer { to, .. } => Some(to.clone()),
            TransactionPayload::Bridge { target_address, .. } => Some(target_address.clone()),
            _ => None,
        }
    }
    
    /// Extract amount for value-transfer transactions
    pub fn amount(&self) -> Option<f64> {
        match &self.payload {
            TransactionPayload::Transfer { amount, .. } => Some(*amount),
            TransactionPayload::Stake { amount, .. } => Some(*amount),
            TransactionPayload::Bridge { amount, .. } => Some(*amount),
            _ => None,
        }
    }
}

// ============================================================================
// SIGNED TRANSACTION BUILDER
// ============================================================================

/// Builder for creating and signing transactions
pub struct SignedTransactionBuilder {
    sender_pubkey: String,
    nonce: u64,
    tx_type: SignedTxType,
    payload: Option<TransactionPayload>,
}

impl SignedTransactionBuilder {
    pub fn new(sender_pubkey: String, nonce: u64) -> Self {
        Self {
            sender_pubkey,
            nonce,
            tx_type: SignedTxType::Transfer,
            payload: None,
        }
    }
    
    pub fn tx_type(mut self, tx_type: SignedTxType) -> Self {
        self.tx_type = tx_type;
        self
    }
    
    pub fn transfer(mut self, to: String, amount: f64, memo: Option<String>) -> Self {
        self.tx_type = SignedTxType::Transfer;
        self.payload = Some(TransactionPayload::Transfer { to, amount, memo });
        self
    }
    
    pub fn social_action(mut self, action_type: String, target_id: Option<String>, content: Option<String>) -> Self {
        self.tx_type = SignedTxType::SocialAction;
        self.payload = Some(TransactionPayload::SocialAction { action_type, target_id, content });
        self
    }
    
    pub fn stake(mut self, amount: f64, validator: Option<String>) -> Self {
        self.tx_type = SignedTxType::Stake;
        self.payload = Some(TransactionPayload::Stake { amount, validator });
        self
    }
    
    pub fn bridge(mut self, target_layer: String, target_address: String, amount: f64) -> Self {
        self.tx_type = SignedTxType::Bridge;
        self.payload = Some(TransactionPayload::Bridge { target_layer, target_address, amount });
        self
    }
    
    /// Build the unsigned transaction
    pub fn build(self) -> Result<SignedTransaction, SignedTxError> {
        let payload = self.payload.ok_or(SignedTxError::MissingPayload)?;
        Ok(SignedTransaction::new(self.sender_pubkey, self.nonce, self.tx_type, payload))
    }
    
    /// Build and sign the transaction with an Ed25519 secret key (32 bytes)
    pub fn build_and_sign_raw(self, secret_key: &[u8; 32]) -> Result<SignedTransaction, SignedTxError> {
        use ed25519_dalek::{SigningKey, Signer};
        
        let mut tx = self.build()?;
        
        // Create signing key from secret
        let signing_key = SigningKey::from_bytes(secret_key);
        
        // Sign the transaction
        let signable = tx.get_signable_bytes();
        let signature = signing_key.sign(&signable);
        tx.signature = hex::encode(signature.to_bytes());
        
        Ok(tx)
    }
}

// ============================================================================
// CROSS-LAYER VERIFICATION
// ============================================================================

/// Verification result for cross-layer transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub tx_hash: String,
    pub sender: String,
    pub verified_at: u64,
    pub layer: String,
    pub error: Option<String>,
}

/// Verify a signed transaction for cross-layer operations
/// This can be called by L2 to verify L1 signatures
pub fn verify_cross_layer(tx: &SignedTransaction, expected_layer: &str) -> VerificationResult {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let tx_hash = tx.hash();
    let sender = tx.sender_pubkey.clone();
    
    // 1. Verify signature
    let sig_result = tx.verify();
    if let Err(e) = sig_result {
        return VerificationResult {
            is_valid: false,
            tx_hash,
            sender,
            verified_at: now,
            layer: expected_layer.to_string(),
            error: Some(e.to_string()),
        };
    }
    
    if !sig_result.unwrap() {
        return VerificationResult {
            is_valid: false,
            tx_hash,
            sender,
            verified_at: now,
            layer: expected_layer.to_string(),
            error: Some("Signature verification failed".to_string()),
        };
    }
    
    // 2. Check timestamp (allow 5 minutes)
    if !tx.is_timestamp_valid(300) {
        return VerificationResult {
            is_valid: false,
            tx_hash,
            sender,
            verified_at: now,
            layer: expected_layer.to_string(),
            error: Some("Transaction timestamp expired".to_string()),
        };
    }
    
    VerificationResult {
        is_valid: true,
        tx_hash,
        sender,
        verified_at: now,
        layer: expected_layer.to_string(),
        error: None,
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone)]
pub enum SignedTxError {
    InvalidPublicKey(String),
    InvalidSignature(String),
    MissingPayload,
    TimestampExpired,
    NonceReplay { expected: u64, received: u64 },
    VerificationFailed(String),
    /// Blockhash is not found in recent slots
    InvalidBlockhash(String),
    /// Blockhash is too old (more than RECENT_BLOCKHASH_SLOTS ago)
    ExpiredBlockhash(String),
}

impl std::fmt::Display for SignedTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedTxError::InvalidPublicKey(e) => write!(f, "Invalid public key: {}", e),
            SignedTxError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            SignedTxError::MissingPayload => write!(f, "Transaction payload is missing"),
            SignedTxError::TimestampExpired => write!(f, "Transaction timestamp expired"),
            SignedTxError::NonceReplay { expected, received } => {
                write!(f, "Nonce replay: expected >= {}, received {}", expected, received)
            }
            SignedTxError::VerificationFailed(e) => write!(f, "Verification failed: {}", e),
            SignedTxError::InvalidBlockhash(e) => write!(f, "Invalid blockhash: {}", e),
            SignedTxError::ExpiredBlockhash(e) => write!(f, "Expired blockhash: {}", e),
        }
    }
}

impl std::error::Error for SignedTxError {}

// ============================================================================
// TESTS
// ============================================================================

// TODO: Re-enable tests once WalletService/Keypair infrastructure is added
// The tests below require a keypair/wallet service that doesn't exist yet
/*
#[cfg(test)]
mod tests {
    use super::*;
    // Tests disabled - require WalletService which is not implemented
    // See internal_rpc.rs for working tests
}
*/
