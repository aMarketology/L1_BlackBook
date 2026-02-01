//! # FROST Threshold Signature Scheme (TSS)
//!
//! This module implements the signing phase of FROST where multiple parties
//! collaborate to produce a signature WITHOUT reconstructing the private key.
//!
//! ## Why This Is S+ Tier
//!
//! In traditional multi-sig:
//! - Each party signs independently with their full key
//! - Result: multiple signatures that all must verify
//!
//! In FROST TSS:
//! - Each party produces a PARTIAL signature with their SHARD
//! - Partials combine into ONE valid Ed25519 signature
//! - The private key NEVER exists, not even momentarily
//!
//! ## Protocol Overview (2-of-3)
//!
//! ```text
//! Round 1 (Commitment):
//!   Each signer generates nonces (d, e) and commitments (D, E)
//!   Party i -> {D_i, E_i} -> Coordinator
//!
//! Round 2 (Signing):
//!   Coordinator sends signing package to each signer
//!   Each signer computes signature share z_i
//!   Party i -> {z_i} -> Coordinator
//!
//! Aggregation:
//!   Coordinator combines {z_1, z_2} into final signature (R, z)
//!   Anyone can verify with group public key
//! ```

use crate::unified_wallet::types::*;
use frost_ed25519 as frost;
use rand_core::OsRng;
use std::collections::BTreeMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Server participant ID
const SERVER_PARTICIPANT_ID: u16 = 2;

/// Threshold signer using FROST
/// 
/// This holds our key package (Guardian Shard) and coordinates
/// the signing protocol with clients.
pub struct ThresholdSigner {
    /// Active signing sessions
    sessions: Arc<RwLock<BTreeMap<String, SigningState>>>,
    
    /// Our nonce commitments (used in round 1)
    /// Map: session_id -> (nonces, commitments)
    nonces: Arc<RwLock<BTreeMap<String, (frost::round1::SigningNonces, frost::round1::SigningCommitments)>>>,
}

/// Internal signing session state
struct SigningState {
    /// Basic session info
    session: SigningSession,
    
    /// Key package we're signing with
    key_package: frost::keys::KeyPackage,
    
    /// Public key package (for verification)
    public_key_package: frost::keys::PublicKeyPackage,
    
    /// Received commitments from other signers
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    
    /// Our signing nonces (secret, used in round 2)
    our_nonces: Option<frost::round1::SigningNonces>,
    
    /// Signing package (created after all commitments received)
    signing_package: Option<frost::SigningPackage>,
}

impl ThresholdSigner {
    /// Create a new threshold signer
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            nonces: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    
    /// Start signing round 1 - generate our commitment
    /// 
    /// This creates our nonces and returns our commitment for broadcast.
    pub fn start_signing(
        &self,
        session_id: &str,
        wallet_address: &str,
        message: &[u8],
        key_package: frost::keys::KeyPackage,
        public_key_package: frost::keys::PublicKeyPackage,
    ) -> Result<SigningCommitment, WalletError> {
        // Generate our nonces and commitments
        let (nonces, commitments) = frost::round1::commit(
            key_package.signing_share(),
            &mut OsRng,
        );
        
        // Store nonces (needed for round 2)
        self.nonces.write().insert(session_id.to_string(), (nonces.clone(), commitments.clone()));
        
        // Create session state
        let session = SigningSession::new(
            session_id.to_string(),
            wallet_address.to_string(),
            message.to_vec(),
        );
        
        let state = SigningState {
            session,
            key_package,
            public_key_package,
            commitments: BTreeMap::new(),
            our_nonces: Some(nonces),
            signing_package: None,
        };
        
        self.sessions.write().insert(session_id.to_string(), state);
        
        // Serialize our commitment
        let hiding = commitments.hiding();
        let binding = commitments.binding();
        
        let hiding_bytes = hiding.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let binding_bytes = binding.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        
        Ok(SigningCommitment {
            participant_id: SERVER_PARTICIPANT_ID,
            hiding_hex: hex::encode(&hiding_bytes),
            binding_hex: hex::encode(&binding_bytes),
        })
    }
    
    /// Receive commitment from another signer
    pub fn receive_commitment(
        &self,
        session_id: &str,
        commitment: SigningCommitment,
    ) -> Result<(), WalletError> {
        let mut sessions = self.sessions.write();
        let state = sessions.get_mut(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Deserialize commitment
        let hiding_bytes = hex::decode(&commitment.hiding_hex)
            .map_err(|e| WalletError::SerializationError(format!("Invalid hiding hex: {}", e)))?;
        let binding_bytes = hex::decode(&commitment.binding_hex)
            .map_err(|e| WalletError::SerializationError(format!("Invalid binding hex: {}", e)))?;
        
        // Reconstruct the commitment
        // Note: frost-ed25519 requires specific deserialization
        let hiding = frost::round1::NonceCommitment::deserialize(&hiding_bytes)
            .map_err(|e| WalletError::SerializationError(format!("Invalid hiding: {:?}", e)))?;
        let binding = frost::round1::NonceCommitment::deserialize(&binding_bytes)
            .map_err(|e| WalletError::SerializationError(format!("Invalid binding: {:?}", e)))?;
        
        let commitments = frost::round1::SigningCommitments::new(hiding, binding);
        
        // Get sender identifier
        let sender_id = frost::Identifier::try_from(commitment.participant_id)
            .map_err(|e| WalletError::InvalidShard(format!("Invalid participant ID: {:?}", e)))?;
        
        state.commitments.insert(sender_id, commitments);
        
        Ok(())
    }
    
    /// Generate our signature share (round 2)
    /// 
    /// After receiving all commitments, we can compute our partial signature.
    pub fn generate_share(
        &self,
        session_id: &str,
    ) -> Result<SignatureShare, WalletError> {
        let mut sessions = self.sessions.write();
        let state = sessions.get_mut(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Verify we have enough commitments (need t total including ours)
        // For 2-of-3, we need 1 other commitment
        if state.commitments.is_empty() {
            return Err(WalletError::ThresholdNotMet {
                required: 1,
                received: 0,
            });
        }
        
        // Get our nonces
        let nonces = self.nonces.write().remove(session_id)
            .ok_or_else(|| WalletError::SigningError("Nonces not found".to_string()))?;
        
        // Build commitment map including ourselves
        let mut all_commitments = state.commitments.clone();
        let our_id = frost::Identifier::try_from(SERVER_PARTICIPANT_ID)
            .map_err(|e| WalletError::InvalidShard(format!("Invalid our ID: {:?}", e)))?;
        all_commitments.insert(our_id, nonces.1);
        
        // Create signing package
        let signing_package = frost::SigningPackage::new(
            all_commitments,
            &state.session.message,
        );
        
        // Generate our signature share
        let signature_share = frost::round2::sign(
            &signing_package,
            &nonces.0,
            &state.key_package,
        ).map_err(|e| WalletError::SigningError(format!("Signing failed: {:?}", e)))?;
        
        // Store signing package for aggregation
        state.signing_package = Some(signing_package);
        state.session.round = 2;
        
        // Serialize our share
        let share_bytes = signature_share.serialize();
        
        Ok(SignatureShare {
            participant_id: SERVER_PARTICIPANT_ID,
            share_hex: hex::encode(share_bytes),
        })
    }
    
    /// Aggregate signature shares into final signature
    /// 
    /// Once we have enough shares (t), combine them into a valid Ed25519 signature.
    pub fn aggregate(
        &self,
        session_id: &str,
        shares: Vec<SignatureShare>,
    ) -> Result<SignatureResult, WalletError> {
        let sessions = self.sessions.read();
        let state = sessions.get(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        let signing_package = state.signing_package.as_ref()
            .ok_or_else(|| WalletError::SigningError("Signing package not ready".to_string()))?;
        
        // Deserialize all signature shares
        let mut share_map: BTreeMap<frost::Identifier, frost::round2::SignatureShare> = BTreeMap::new();
        
        for share in shares {
            let share_bytes = hex::decode(&share.share_hex)
                .map_err(|e| WalletError::SerializationError(format!("Invalid share hex: {}", e)))?;
            
            let sig_share = frost::round2::SignatureShare::deserialize(&share_bytes)
                .map_err(|e| WalletError::SerializationError(format!("Invalid share: {:?}", e)))?;
            
            let participant_id = frost::Identifier::try_from(share.participant_id)
                .map_err(|e| WalletError::InvalidShard(format!("Invalid participant ID: {:?}", e)))?;
            
            share_map.insert(participant_id, sig_share);
        }
        
        // Aggregate into final signature
        let signature = frost::aggregate(
            signing_package,
            &share_map,
            &state.public_key_package,
        ).map_err(|e| WalletError::SigningError(format!("Aggregation failed: {:?}", e)))?;
        
        // Verify the signature (sanity check)
        let verifying_key = state.public_key_package.verifying_key();
        verifying_key.verify(&state.session.message, &signature)
            .map_err(|e| WalletError::SigningError(format!("Signature verification failed: {:?}", e)))?;
        
        // Serialize result
        let sig_bytes = signature.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let pk_bytes = verifying_key.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        
        Ok(SignatureResult {
            signature_hex: hex::encode(&sig_bytes),
            message_hex: hex::encode(&state.session.message),
            public_key_hex: hex::encode(&pk_bytes),
            nonce_hex: String::new(), // Nonce is embedded in signature
        })
    }
    
    /// Sign a message (simplified API for UnifiedWalletSystem)
    /// 
    /// This is a convenience method that handles the full signing flow
    /// when we already have the client's commitment.
    pub async fn sign(
        &self,
        wallet_address: &str,
        message: &[u8],
        client_commitment: &[u8],
    ) -> Result<SignatureResult, WalletError> {
        // This requires the full multi-round protocol
        // The handlers orchestrate this properly
        Err(WalletError::SigningError(
            "Use the multi-round signing protocol (start_signing -> receive_commitment -> generate_share -> aggregate)".to_string()
        ))
    }
    
    /// Clean up expired sessions
    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write();
        sessions.retain(|_, state| !state.session.is_expired());
        
        // Also clean up orphaned nonces
        let valid_sessions: Vec<String> = sessions.keys().cloned().collect();
        self.nonces.write().retain(|id, _| valid_sessions.contains(id));
    }
}

impl Default for ThresholdSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signer_creation() {
        let signer = ThresholdSigner::new();
        // Signer should be empty initially
        assert!(signer.sessions.read().is_empty());
    }
}
