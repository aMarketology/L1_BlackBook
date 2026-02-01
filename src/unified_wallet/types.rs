//! # Common Types for S+ Tier Wallet System
//!
//! This module defines all shared types used across the wallet system.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// All possible wallet system errors
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("DKG failed: {0}")]
    DKGError(String),
    
    #[error("Signing failed: {0}")]
    SigningError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Invalid shard: {0}")]
    InvalidShard(String),
    
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Session expired: {0}")]
    SessionExpired(String),
    
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),
    
    #[error("Threshold not met: need {required}, got {received}")]
    ThresholdNotMet { required: usize, received: usize },
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// ============================================================================
// RESULT TYPES
// ============================================================================

/// Result of wallet creation via DKG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCreationResult {
    /// The wallet's public address (derived from group public key)
    pub wallet_address: String,
    
    /// The group public key (Ed25519) in hex
    pub public_key_hex: String,
    
    /// Device shard (Share 1) - encrypted, stays on user device
    /// This is what the client stores locally
    pub device_shard_encrypted: String,
    
    /// Guardian shard ID - reference to server-stored shard
    /// The actual shard (Share 2) is stored server-side
    pub guardian_shard_id: String,
    
    /// Recovery mnemonic (Share 3) - 24 words for offline backup
    pub recovery_mnemonic: String,
    
    /// Key package verification hash
    pub verification_hash: String,
}

/// Result of a threshold signing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    /// The aggregated Ed25519 signature (hex)
    pub signature_hex: String,
    
    /// Message that was signed (hex)
    pub message_hex: String,
    
    /// Public key that can verify this signature
    pub public_key_hex: String,
    
    /// Nonce used in this signing session
    pub nonce_hex: String,
}

/// Result of OPAQUE authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Session key (ephemeral, derived during OPAQUE)
    /// This is used for subsequent encrypted communications
    pub session_key_hex: String,
    
    /// Server's authentication proof
    pub server_mac_hex: String,
    
    /// Session expiry timestamp
    pub expires_at: u64,
    
    /// Wallet address authenticated
    pub wallet_address: String,
}

// ============================================================================
// SESSION TYPES
// ============================================================================

/// Active signing session state
/// 
/// FROST signing is a 2-round protocol:
/// 1. Commitment round: parties share commitments
/// 2. Signing round: parties share signature shares
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// Unique session identifier
    pub session_id: String,
    
    /// Wallet being used to sign
    pub wallet_address: String,
    
    /// Message to be signed
    pub message: Vec<u8>,
    
    /// Commitments received from participants
    pub commitments: Vec<SigningCommitment>,
    
    /// Signature shares received (round 2)
    pub signature_shares: Vec<SignatureShare>,
    
    /// Session creation time
    pub created_at: u64,
    
    /// Session expiry time
    pub expires_at: u64,
    
    /// Current round (1 = commitment, 2 = signing)
    pub round: u8,
}

/// A participant's commitment in FROST signing round 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCommitment {
    /// Participant identifier (1, 2, or 3)
    pub participant_id: u16,
    
    /// Hiding commitment (D)
    pub hiding_hex: String,
    
    /// Binding commitment (E)
    pub binding_hex: String,
}

/// A participant's signature share in FROST signing round 2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    /// Participant identifier
    pub participant_id: u16,
    
    /// The signature share (z_i)
    pub share_hex: String,
}

/// DKG session state
/// 
/// FROST DKG is a multi-round protocol where parties jointly
/// generate key shares without any party knowing the full key.
#[derive(Debug, Clone)]
pub struct DKGSession {
    /// Unique session identifier
    pub session_id: String,
    
    /// Username associated with this DKG
    pub username: String,
    
    /// Round 1 packages received
    pub round1_packages: Vec<DKGRound1Package>,
    
    /// Round 2 packages received
    pub round2_packages: Vec<DKGRound2Package>,
    
    /// Session creation time
    pub created_at: u64,
    
    /// Session expiry time
    pub expires_at: u64,
    
    /// Current round (1 or 2)
    pub round: u8,
    
    /// Number of participants (n)
    pub num_participants: u16,
    
    /// Threshold required to sign (t)
    pub threshold: u16,
}

/// DKG Round 1 package (commitment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRound1Package {
    /// Participant identifier
    pub participant_id: u16,
    
    /// Commitment data (serialized)
    pub package_hex: String,
}

/// DKG Round 2 package (shares)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRound2Package {
    /// Sender participant identifier
    pub from_participant_id: u16,
    
    /// Recipient participant identifier
    pub to_participant_id: u16,
    
    /// Encrypted share data
    pub package_hex: String,
}

// ============================================================================
// STORAGE TYPES
// ============================================================================

/// Stored guardian shard (server-side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianShard {
    /// Shard identifier
    pub shard_id: String,
    
    /// Associated wallet address
    pub wallet_address: String,
    
    /// Encrypted key package (the actual shard)
    pub key_package_encrypted: Vec<u8>,
    
    /// OPAQUE password file (for authentication)
    pub opaque_record: Vec<u8>,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Last used timestamp
    pub last_used_at: u64,
}

/// OPAQUE registration record (stored server-side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueRecord {
    /// Username / wallet address
    pub identifier: String,
    
    /// Serialized OPAQUE ServerRegistration
    pub registration_data: Vec<u8>,
    
    /// Creation timestamp
    pub created_at: u64,
}

// ============================================================================
// API REQUEST/RESPONSE TYPES
// ============================================================================

/// Request to start wallet creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    /// Username for the wallet
    pub username: String,
    
    /// Client's DKG round 1 package
    pub client_round1_package: String,
    
    /// OPAQUE registration start message
    pub opaque_registration_message: String,
}

/// Response for wallet creation start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletResponse {
    /// Server's DKG round 1 package
    pub server_round1_package: String,
    
    /// OPAQUE registration response
    pub opaque_registration_response: String,
    
    /// Session ID for continuing the protocol
    pub session_id: String,
}

/// Request to sign a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Wallet address to sign with
    pub wallet_address: String,
    
    /// Message to sign (hex)
    pub message_hex: String,
    
    /// Client's commitment (round 1)
    pub client_commitment: SigningCommitment,
    
    /// OPAQUE login finish message (proves identity)
    pub opaque_credential_message: String,
}

/// Response for signing round 1 (commitment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCommitmentResponse {
    /// Server's commitment
    pub server_commitment: SigningCommitment,
    
    /// Session ID for round 2
    pub session_id: String,
}

/// Request for signing round 2 (share)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignShareRequest {
    /// Session ID from round 1
    pub session_id: String,
    
    /// Client's signature share
    pub client_share: SignatureShare,
}

/// OPAQUE login start request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// Username / wallet address
    pub identifier: String,
    
    /// OPAQUE CredentialRequest message
    pub opaque_message: String,
}

/// OPAQUE login start response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// OPAQUE CredentialResponse message
    pub opaque_response: String,
    
    /// Session ID for finish
    pub session_id: String,
}

// ============================================================================
// HELPER IMPLEMENTATIONS
// ============================================================================

impl SigningSession {
    /// Create a new signing session
    pub fn new(session_id: String, wallet_address: String, message: Vec<u8>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            session_id,
            wallet_address,
            message,
            commitments: Vec::new(),
            signature_shares: Vec::new(),
            created_at: now,
            expires_at: now + 300, // 5 minute expiry
            round: 1,
        }
    }
    
    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

impl DKGSession {
    /// Create a new DKG session
    pub fn new(session_id: String, username: String, num_participants: u16, threshold: u16) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            session_id,
            username,
            round1_packages: Vec::new(),
            round2_packages: Vec::new(),
            created_at: now,
            expires_at: now + 600, // 10 minute expiry for DKG
            round: 1,
            num_participants,
            threshold,
        }
    }
    
    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signing_session_expiry() {
        let session = SigningSession::new(
            "test-session".to_string(),
            "bb_test".to_string(),
            vec![1, 2, 3],
        );
        assert!(!session.is_expired());
    }
    
    #[test]
    fn test_dkg_session_creation() {
        let session = DKGSession::new(
            "dkg-test".to_string(),
            "alice".to_string(),
            3,
            2,
        );
        assert_eq!(session.threshold, 2);
        assert_eq!(session.num_participants, 3);
    }
}
