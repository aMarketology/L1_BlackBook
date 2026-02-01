//! # FROST Distributed Key Generation (DKG)
//!
//! This module implements the DKG phase of FROST (Flexible Round-Optimized
//! Schnorr Threshold Signatures).
//!
//! ## Why DKG Matters
//!
//! In traditional wallets, a single party generates the private key and then
//! potentially splits it using SSS. The problem: that party SAW the full key.
//!
//! With DKG, multiple parties jointly generate a key where:
//! - Each party gets a SHARD (key share)
//! - The full private key NEVER exists
//! - Any t-of-n parties can sign, but < t parties learn nothing
//!
//! ## Protocol Overview (2-of-3)
//!
//! ```text
//! Round 1: Each party generates and broadcasts commitments
//!          Party i -> {C_i, proof_i} -> All parties
//!
//! Round 2: Each party sends encrypted shares to other parties
//!          Party i -> {share_ij encrypted for j} -> Party j
//!
//! Result:  Each party derives their key package (shard)
//!          Group public key is computed (same for all parties)
//! ```

use crate::unified_wallet::types::*;
use frost_ed25519 as frost;
use rand_core::OsRng;
use std::collections::BTreeMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Server-side participant ID (Share 2 = Guardian Shard)
const SERVER_PARTICIPANT_ID: u16 = 2;

/// FROST DKG coordinator
/// 
/// The server acts as participant #2 in a 2-of-3 threshold scheme:
/// - Participant 1: Device Shard (user's device)
/// - Participant 2: Guardian Shard (this server)
/// - Participant 3: Recovery Shard (offline backup)
pub struct FrostDKG {
    /// Our participant identifier
    participant_id: frost::Identifier,
    
    /// Active DKG sessions
    sessions: Arc<RwLock<BTreeMap<String, DKGState>>>,
    
    /// Completed key packages (guardian shards we hold)
    key_packages: Arc<RwLock<BTreeMap<String, frost::keys::KeyPackage>>>,
    
    /// Group public keys (derived from DKG)
    group_public_keys: Arc<RwLock<BTreeMap<String, frost::keys::PublicKeyPackage>>>,
}

/// Internal DKG state for a session
struct DKGState {
    /// Session info
    session: DKGSession,
    
    /// Our round 1 secret package (kept private)
    our_round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    
    /// Received round 1 packages from other participants
    received_round1: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    
    /// Our round 2 secret package (kept private)
    our_round2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    
    /// Received round 2 packages for us
    received_round2: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
}

impl FrostDKG {
    /// Create a new DKG coordinator
    pub fn new() -> Self {
        let participant_id = frost::Identifier::try_from(SERVER_PARTICIPANT_ID)
            .expect("Invalid participant ID");
        
        Self {
            participant_id,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            key_packages: Arc::new(RwLock::new(BTreeMap::new())),
            group_public_keys: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    
    /// Start DKG Round 1
    /// 
    /// Generates our commitment and broadcasts it.
    /// The client should call this to get the server's round 1 package.
    pub fn start_round1(
        &self,
        session_id: &str,
        username: &str,
    ) -> Result<DKGRound1Package, WalletError> {
        // 2-of-3 threshold scheme
        let max_signers = 3u16;
        let min_signers = 2u16;
        
        // Generate our round 1 contribution
        let (round1_secret, round1_package) = frost::keys::dkg::part1(
            self.participant_id,
            max_signers,
            min_signers,
            &mut OsRng,
        ).map_err(|e| WalletError::DKGError(format!("Round 1 generation failed: {:?}", e)))?;
        
        // Serialize our package for transmission
        let package_bytes = round1_package.serialize()
            .map_err(|e| WalletError::SerializationError(format!("Failed to serialize round 1: {:?}", e)))?;
        
        // Create session state
        let session = DKGSession::new(
            session_id.to_string(),
            username.to_string(),
            max_signers,
            min_signers,
        );
        
        let state = DKGState {
            session,
            our_round1_secret: Some(round1_secret),
            received_round1: BTreeMap::new(),
            our_round2_secret: None,
            received_round2: BTreeMap::new(),
        };
        
        // Store session
        self.sessions.write().insert(session_id.to_string(), state);
        
        Ok(DKGRound1Package {
            participant_id: SERVER_PARTICIPANT_ID,
            package_hex: hex::encode(package_bytes),
        })
    }
    
    /// Process Round 1 package from another participant
    pub fn receive_round1(
        &self,
        session_id: &str,
        package: DKGRound1Package,
    ) -> Result<(), WalletError> {
        let mut sessions = self.sessions.write();
        let state = sessions.get_mut(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Decode the package
        let package_bytes = hex::decode(&package.package_hex)
            .map_err(|e| WalletError::SerializationError(format!("Invalid hex: {}", e)))?;
        
        let round1_package = frost::keys::dkg::round1::Package::deserialize(&package_bytes)
            .map_err(|e| WalletError::SerializationError(format!("Invalid round 1 package: {:?}", e)))?;
        
        // Get sender's identifier
        let sender_id = frost::Identifier::try_from(package.participant_id)
            .map_err(|e| WalletError::InvalidShard(format!("Invalid participant ID: {:?}", e)))?;
        
        // Store the package
        state.received_round1.insert(sender_id, round1_package);
        
        Ok(())
    }
    
    /// Generate Round 2 packages
    /// 
    /// After receiving all round 1 packages, generate shares for each participant.
    pub fn generate_round2(
        &self,
        session_id: &str,
    ) -> Result<Vec<DKGRound2Package>, WalletError> {
        let mut sessions = self.sessions.write();
        let state = sessions.get_mut(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Verify we have enough round 1 packages
        // We need packages from all n-1 other participants
        let expected = (state.session.num_participants - 1) as usize;
        if state.received_round1.len() < expected {
            return Err(WalletError::ThresholdNotMet {
                required: expected,
                received: state.received_round1.len(),
            });
        }
        
        // Take our round 1 secret
        let round1_secret = state.our_round1_secret.take()
            .ok_or_else(|| WalletError::DKGError("Round 1 secret missing".to_string()))?;
        
        // Generate round 2
        let (round2_secret, round2_packages) = frost::keys::dkg::part2(
            round1_secret,
            &state.received_round1,
        ).map_err(|e| WalletError::DKGError(format!("Round 2 generation failed: {:?}", e)))?;
        
        // Store our round 2 secret
        state.our_round2_secret = Some(round2_secret);
        state.session.round = 2;
        
        // Serialize packages for each recipient
        let mut result = Vec::new();
        for (recipient_id, package) in round2_packages {
            let package_bytes = package.serialize()
                .map_err(|e| WalletError::SerializationError(format!("Failed to serialize: {:?}", e)))?;
            
            // Convert identifier to u16
            let recipient_u16: u16 = recipient_id.serialize()[0] as u16;
            
            result.push(DKGRound2Package {
                from_participant_id: SERVER_PARTICIPANT_ID,
                to_participant_id: recipient_u16,
                package_hex: hex::encode(package_bytes),
            });
        }
        
        Ok(result)
    }
    
    /// Process Round 2 package (our share from another participant)
    pub fn receive_round2(
        &self,
        session_id: &str,
        package: DKGRound2Package,
    ) -> Result<(), WalletError> {
        // Only accept packages destined for us
        if package.to_participant_id != SERVER_PARTICIPANT_ID {
            return Err(WalletError::InvalidShard(
                "Package not addressed to server".to_string()
            ));
        }
        
        let mut sessions = self.sessions.write();
        let state = sessions.get_mut(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Decode the package
        let package_bytes = hex::decode(&package.package_hex)
            .map_err(|e| WalletError::SerializationError(format!("Invalid hex: {}", e)))?;
        
        let round2_package = frost::keys::dkg::round2::Package::deserialize(&package_bytes)
            .map_err(|e| WalletError::SerializationError(format!("Invalid round 2 package: {:?}", e)))?;
        
        // Get sender's identifier
        let sender_id = frost::Identifier::try_from(package.from_participant_id)
            .map_err(|e| WalletError::InvalidShard(format!("Invalid participant ID: {:?}", e)))?;
        
        // Store the package
        state.received_round2.insert(sender_id, round2_package);
        
        Ok(())
    }
    
    /// Finalize DKG - derive our key package (Guardian Shard)
    pub fn finalize(
        &self,
        session_id: &str,
    ) -> Result<WalletCreationResult, WalletError> {
        let mut sessions = self.sessions.write();
        let state = sessions.remove(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Take our round 2 secret
        let round2_secret = state.our_round2_secret
            .ok_or_else(|| WalletError::DKGError("Round 2 secret missing".to_string()))?;
        
        // Finalize DKG
        let (key_package, public_key_package) = frost::keys::dkg::part3(
            &round2_secret,
            &state.received_round1,
            &state.received_round2,
        ).map_err(|e| WalletError::DKGError(format!("DKG finalization failed: {:?}", e)))?;
        
        // Derive wallet address from group public key
        let group_public_key = public_key_package.verifying_key();
        let pk_bytes = group_public_key.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let wallet_address = format!("bb_{}", hex::encode(&pk_bytes[..16]));
        
        // Store our key package (Guardian Shard)
        let shard_id = format!("shard_{}_{}", state.session.username, session_id);
        self.key_packages.write().insert(wallet_address.clone(), key_package.clone());
        self.group_public_keys.write().insert(wallet_address.clone(), public_key_package);
        
        // Create verification hash
        let key_package_bytes = key_package.serialize()
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let verification_hash = hex::encode(blake3::hash(&key_package_bytes).as_bytes());
        
        Ok(WalletCreationResult {
            wallet_address,
            public_key_hex: hex::encode(&pk_bytes),
            device_shard_encrypted: String::new(), // Client generates this
            guardian_shard_id: shard_id,
            recovery_mnemonic: String::new(), // Client generates this
            verification_hash,
        })
    }
    
    /// Create a wallet (simplified flow for API)
    pub async fn create_wallet(&self, session_id: &str) -> Result<WalletCreationResult, WalletError> {
        // This is called from UnifiedWalletSystem
        // The full DKG requires multiple round-trips, so this is a placeholder
        // In practice, the handlers orchestrate the multi-round protocol
        Err(WalletError::DKGError(
            "Use the multi-round DKG protocol (start_round1 -> receive_round1 -> generate_round2 -> receive_round2 -> finalize)".to_string()
        ))
    }
    
    /// Get our key package for a wallet (used during signing)
    pub fn get_key_package(&self, wallet_address: &str) -> Option<frost::keys::KeyPackage> {
        self.key_packages.read().get(wallet_address).cloned()
    }
    
    /// Get the group public key for a wallet
    pub fn get_public_key_package(&self, wallet_address: &str) -> Option<frost::keys::PublicKeyPackage> {
        self.group_public_keys.read().get(wallet_address).cloned()
    }
}

impl Default for FrostDKG {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dkg_round1_generation() {
        let dkg = FrostDKG::new();
        let result = dkg.start_round1("test-session", "alice");
        assert!(result.is_ok());
        
        let package = result.unwrap();
        assert_eq!(package.participant_id, SERVER_PARTICIPANT_ID);
        assert!(!package.package_hex.is_empty());
    }
}
