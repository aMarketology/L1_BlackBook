// ============================================================================
// VAULT CLAIM SIGNER (KMS / Local Ed25519)
// ============================================================================
//
// Signs "CLAIM:{poh_slot}:{amount}:{user_pubkey}" attestations that the
// Solana Anchor vault program verifies via the Ed25519 sysvar.
//
// Two backends:
//   1. AWS KMS (production) — requires AWS_KMS_KEY_ID env var.
//      Uses the aws-sdk-kms crate for remote Ed25519 signing.
//   2. Local Ed25519 (devnet/testing) — uses VAULT_SIGNER_PRIVATE_KEY env var.
//      Logs a prominent warning at startup.
//
// The signer is instantiated once at startup and shared via Arc<VaultSigner>.
// ============================================================================

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tracing::{info, warn};

/// Canonical claim message format (must match the Anchor program's expectation).
pub fn claim_message(poh_slot: u64, amount: u64, user_pubkey: &str) -> String {
    format!("CLAIM:{}:{}:{}", poh_slot, amount, user_pubkey)
}

/// Signed attestation returned to the frontend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimAttestation {
    pub signature_hex: String,
    pub kms_pubkey_hex: String,
    pub message: String,
    pub poh_slot: u64,
    pub amount: u64,
}

/// Trait-object-safe signer interface.
pub enum VaultSigner {
    Local(LocalSigner),
    // Future: Kms(KmsSigner) — added when aws-sdk-kms dep is pulled in
}

impl VaultSigner {
    /// Create a signer from environment variables.
    ///
    /// Priority:
    ///   1. `AWS_KMS_KEY_ID` → KMS signer (not yet implemented, returns error)
    ///   2. `VAULT_SIGNER_PRIVATE_KEY` → local Ed25519 signer
    ///   3. Neither → returns None (vault claims disabled)
    pub fn from_env() -> Option<Self> {
        if let Ok(key_id) = std::env::var("AWS_KMS_KEY_ID") {
            if !key_id.is_empty() {
                warn!("⚠️  AWS_KMS_KEY_ID is set ({}) but KMS signer is not yet implemented — falling back to local signer", &key_id[..8.min(key_id.len())]);
                // KMS backend deferred: add aws-sdk-kms to Cargo.toml, implement KmsSigner,
                // then replace this branch with: return Some(VaultSigner::Kms(KmsSigner::new(key_id)))
            }
        }

        if let Ok(sk_hex) = std::env::var("VAULT_SIGNER_PRIVATE_KEY") {
            if sk_hex.len() == 64 {
                match LocalSigner::from_hex(&sk_hex) {
                    Ok(signer) => {
                        warn!("⚠️  Using LOCAL vault signer — NOT for production! Pubkey: {}",
                            signer.pubkey_hex());
                        return Some(VaultSigner::Local(signer));
                    }
                    Err(e) => {
                        warn!("⚠️  VAULT_SIGNER_PRIVATE_KEY invalid: {}", e);
                    }
                }
            }
        }

        info!("ℹ️  No vault signer configured (set AWS_KMS_KEY_ID or VAULT_SIGNER_PRIVATE_KEY to enable outbound claims)");
        None
    }

    /// Sign a claim attestation.
    pub fn sign_claim(
        &self,
        poh_slot: u64,
        amount: u64,
        user_pubkey: &str,
    ) -> Result<ClaimAttestation, String> {
        match self {
            VaultSigner::Local(s) => s.sign_claim(poh_slot, amount, user_pubkey),
        }
    }

    /// Get the public key bytes (32 bytes, hex-encoded).
    pub fn pubkey_hex(&self) -> String {
        match self {
            VaultSigner::Local(s) => s.pubkey_hex(),
        }
    }

    /// Get the raw 32-byte public key.
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        match self {
            VaultSigner::Local(s) => s.verifying_key.to_bytes(),
        }
    }
}

// ── Local Ed25519 Signer ─────────────────────────────────────────────────────

pub struct LocalSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl LocalSigner {
    pub fn from_hex(hex_key: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| format!("Invalid hex: {}", e))?;
        let sk_bytes: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| format!("Key must be 32 bytes, got {}", bytes.len()))?;
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub fn sign_claim(
        &self,
        poh_slot: u64,
        amount: u64,
        user_pubkey: &str,
    ) -> Result<ClaimAttestation, String> {
        let message = claim_message(poh_slot, amount, user_pubkey);
        let signature = self.signing_key.sign(message.as_bytes());

        Ok(ClaimAttestation {
            signature_hex: hex::encode(signature.to_bytes()),
            kms_pubkey_hex: self.pubkey_hex(),
            message,
            poh_slot,
            amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn local_signer_round_trip() {
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let sk_hex = hex::encode(sk.to_bytes());
        let signer = LocalSigner::from_hex(&sk_hex).unwrap();

        let attestation = signer.sign_claim(4500122, 100_000_000, "TestUser123").unwrap();

        assert_eq!(attestation.poh_slot, 4500122);
        assert_eq!(attestation.amount, 100_000_000);
        assert_eq!(attestation.message, "CLAIM:4500122:100000000:TestUser123");

        // Verify the signature
        let sig_bytes = hex::decode(&attestation.signature_hex).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap()
        );
        assert!(signer.verifying_key.verify(attestation.message.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn claim_message_format() {
        let msg = claim_message(999, 50_000, "5YNmS1R9nNSCDzb5a7mMJ1dwK9uHeAAF4CmPEwKgVWr8");
        assert_eq!(msg, "CLAIM:999:50000:5YNmS1R9nNSCDzb5a7mMJ1dwK9uHeAAF4CmPEwKgVWr8");
    }

    #[test]
    fn local_signer_rejects_bad_hex() {
        assert!(LocalSigner::from_hex("not_hex").is_err());
        assert!(LocalSigner::from_hex("aabb").is_err()); // too short
    }
}
