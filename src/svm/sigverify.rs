// ============================================================================
// BLACKBOOK SVM — PARALLEL SIGNATURE VERIFICATION
// ============================================================================
//
// High-throughput Ed25519 signature verification using Rayon.
//
// At 100K TPS target, sequential verification is a bottleneck:
//   - Single Ed25519 verify ≈ 60–80μs
//   - Sequential 100K sigs ≈ 6–8 seconds (way over 400ms slot)
//   - Parallel on 8 cores ≈ 750ms–1s (fits in a slot)
//   - Parallel on 16 cores ≈ 375–500ms
//
// DESIGN:
//   - Rayon `par_chunks` splits work across all available cores
//   - Batch size is tunable per workload
//   - Results are returned in-order (same index as input)
//   - Invalid signatures are flagged, not panicked
//
// ============================================================================

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rayon::prelude::*;
use tracing::debug;

/// A pending signature verification request.
#[derive(Debug, Clone)]
pub struct SigVerifyRequest {
    /// Raw message bytes that were signed
    pub message: Vec<u8>,
    /// 32-byte Ed25519 public key
    pub pubkey_bytes: [u8; 32],
    /// 64-byte Ed25519 signature
    pub signature_bytes: [u8; 64],
}

/// Result of a single verification
#[derive(Debug, Clone)]
pub struct SigVerifyResult {
    /// Index in the original batch
    pub index: usize,
    /// Whether the signature is valid
    pub valid: bool,
}

/// Parallel Ed25519 signature verifier using Rayon thread pool.
pub struct ParallelSigVerifier {
    /// Number of items per parallel chunk (tunable)
    batch_size: usize,
}

impl ParallelSigVerifier {
    /// Create a new verifier with the given chunk size.
    /// Recommended: 256–1024 depending on core count.
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size: batch_size.max(1),
        }
    }

    /// Create with default batch size (512).
    pub fn default_batch() -> Self {
        Self::new(512)
    }

    /// Verify a batch of signatures in parallel using Rayon.
    ///
    /// Returns a `Vec<bool>` where `results[i]` corresponds to `requests[i]`.
    /// Order is preserved.
    pub fn verify_batch(&self, requests: &[SigVerifyRequest]) -> Vec<bool> {
        if requests.is_empty() {
            return vec![];
        }

        let results: Vec<bool> = requests
            .par_chunks(self.batch_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .map(|req| Self::verify_single(req))
                    .collect::<Vec<_>>()
            })
            .collect();

        debug!(
            total = requests.len(),
            valid = results.iter().filter(|&&v| v).count(),
            "Parallel sig verify complete"
        );

        results
    }

    /// Verify a batch and return detailed results with indices.
    pub fn verify_batch_detailed(&self, requests: &[SigVerifyRequest]) -> Vec<SigVerifyResult> {
        if requests.is_empty() {
            return vec![];
        }

        requests
            .par_iter()
            .enumerate()
            .map(|(index, req)| SigVerifyResult {
                index,
                valid: Self::verify_single(req),
            })
            .collect()
    }

    /// Verify a single Ed25519 signature.
    fn verify_single(req: &SigVerifyRequest) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&req.pubkey_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&req.signature_bytes);
        verifying_key.verify(&req.message, &signature).is_ok()
    }

    /// Get the configured batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    fn make_signed_request(message: &[u8]) -> SigVerifyRequest {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = signing_key.sign(message);
        SigVerifyRequest {
            message: message.to_vec(),
            pubkey_bytes: signing_key.verifying_key().to_bytes(),
            signature_bytes: signature.to_bytes(),
        }
    }

    #[test]
    fn test_single_valid_signature() {
        let verifier = ParallelSigVerifier::default_batch();
        let req = make_signed_request(b"hello blackbook");
        let results = verifier.verify_batch(&[req]);
        assert_eq!(results, vec![true]);
    }

    #[test]
    fn test_single_invalid_signature() {
        let verifier = ParallelSigVerifier::default_batch();
        let mut req = make_signed_request(b"hello blackbook");
        req.message = b"tampered message".to_vec();
        let results = verifier.verify_batch(&[req]);
        assert_eq!(results, vec![false]);
    }

    #[test]
    fn test_batch_mixed_valid_invalid() {
        let verifier = ParallelSigVerifier::new(2);
        let valid1 = make_signed_request(b"msg1");
        let valid2 = make_signed_request(b"msg2");

        let mut invalid = make_signed_request(b"msg3");
        invalid.signature_bytes[0] ^= 0xFF; // corrupt

        let results = verifier.verify_batch(&[valid1, invalid, valid2]);
        assert_eq!(results, vec![true, false, true]);
    }

    #[test]
    fn test_empty_batch() {
        let verifier = ParallelSigVerifier::default_batch();
        let results = verifier.verify_batch(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parallel_throughput() {
        let verifier = ParallelSigVerifier::new(64);
        let requests: Vec<SigVerifyRequest> = (0..500)
            .map(|i| make_signed_request(format!("tx_{}", i).as_bytes()))
            .collect();

        let start = std::time::Instant::now();
        let results = verifier.verify_batch(&requests);
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 500);
        assert!(results.iter().all(|&v| v));
        // On any modern machine, 500 sigs should verify in under 2 seconds
        assert!(elapsed.as_secs() < 5, "Too slow: {:?}", elapsed);
    }

    #[test]
    fn test_bad_pubkey() {
        let verifier = ParallelSigVerifier::default_batch();
        let req = SigVerifyRequest {
            message: b"hello".to_vec(),
            pubkey_bytes: [0xFF; 32], // invalid curve point
            signature_bytes: [0; 64],
        };
        let results = verifier.verify_batch(&[req]);
        assert_eq!(results, vec![false]);
    }

    // ────────────────────────────────────────────────────────────────────────
    // L1 MESSAGE FORMAT TESTS
    // Ensure each endpoint's canonical message string verifies correctly.
    // ────────────────────────────────────────────────────────────────────────

    fn l1_request(sk: &SigningKey, msg: String) -> SigVerifyRequest {
        let sig = sk.sign(msg.as_bytes());
        SigVerifyRequest {
            message: msg.into_bytes(),
            pubkey_bytes: sk.verifying_key().to_bytes(),
            signature_bytes: sig.to_bytes(),
        }
    }

    #[test]
    fn test_l1_transfer_message_format() {
        // POST /transfer/simple message: "TRANSFER:{from}:{to}:{amount}:{ts}:{nonce}"
        let sk = SigningKey::generate(&mut OsRng);
        let from = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let to = bs58::encode([0x22u8; 32]).into_string();
        let msg = format!("TRANSFER:{}:{}:{:.6}:{}:{}", from, to, 1.5_f64, 1_700_000_000u64, "abc");
        let req = l1_request(&sk, msg);
        let verifier = ParallelSigVerifier::default_batch();
        assert_eq!(verifier.verify_batch(&[req]), vec![true]);
    }

    #[test]
    fn test_l1_faucet_message_format() {
        // POST /faucet message: "FAUCET:{wallet}:{amount}:{ts}:{nonce}"
        let sk = SigningKey::generate(&mut OsRng);
        let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let msg = format!("FAUCET:{}:{:.6}:{}:{}", addr, 0.1_f64, 1_700_000_000u64, "xyz");
        let req = l1_request(&sk, msg);
        let verifier = ParallelSigVerifier::default_batch();
        assert_eq!(verifier.verify_batch(&[req]), vec![true]);
    }

    #[test]
    fn test_l1_escrow_deposit_message_format() {
        // POST /escrow/deposit message: "ESCROW_DEPOSIT:{wallet}:{amount}:{ts}:{nonce}"
        let sk = SigningKey::generate(&mut OsRng);
        let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let msg = format!("ESCROW_DEPOSIT:{}:{:.6}:{}:{}", addr, 50.0_f64, 1_700_000_000u64, "dep1");
        let req = l1_request(&sk, msg);
        let verifier = ParallelSigVerifier::default_batch();
        assert_eq!(verifier.verify_batch(&[req]), vec![true]);
    }

    #[test]
    fn test_l1_escrow_withdraw_message_format() {
        // POST /escrow/withdraw message: "ESCROW_WITHDRAW:{market}:{wallet}:{amount}:{ts}:{nonce}"
        let sk = SigningKey::generate(&mut OsRng);
        let addr = bs58::encode(sk.verifying_key().to_bytes()).into_string();
        let msg = format!("ESCROW_WITHDRAW:{}:{}:{:.6}:{}:{}", "market-bb-usdc", addr, 25.0_f64, 1_700_000_000u64, "wd1");
        let req = l1_request(&sk, msg);
        let verifier = ParallelSigVerifier::default_batch();
        assert_eq!(verifier.verify_batch(&[req]), vec![true]);
    }

    #[test]
    fn test_wrong_key_for_message_rejected() {
        // Sign with key A but present key B's pubkey — must reject
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let msg = b"TRANSFER:abc:def:1.000000:1700000000:nonce1";
        let sig_from_a = sk_a.sign(msg);
        let req = SigVerifyRequest {
            message: msg.to_vec(),
            pubkey_bytes: sk_b.verifying_key().to_bytes(), // wrong key
            signature_bytes: sig_from_a.to_bytes(),
        };
        let verifier = ParallelSigVerifier::default_batch();
        assert_eq!(verifier.verify_batch(&[req]), vec![false]);
    }

    #[test]
    fn test_detailed_results_preserve_index_order() {
        let verifier = ParallelSigVerifier::new(2);
        let valid = make_signed_request(b"ordered-1");
        let mut invalid = make_signed_request(b"ordered-2");
        invalid.signature_bytes[0] ^= 0xAB;
        let valid2 = make_signed_request(b"ordered-3");

        let detailed = verifier.verify_batch_detailed(&[valid, invalid, valid2]);
        assert_eq!(detailed.len(), 3);
        assert_eq!(detailed[0].index, 0);
        assert!(detailed[0].valid);
        assert_eq!(detailed[1].index, 1);
        assert!(!detailed[1].valid);
        assert_eq!(detailed[2].index, 2);
        assert!(detailed[2].valid);
    }

    #[test]
    fn test_batch_size_one_still_works() {
        // Edge: batch_size=1 forces each item through its own rayon chunk
        let verifier = ParallelSigVerifier::new(1);
        let requests: Vec<_> = (0..10)
            .map(|i| make_signed_request(format!("msg-{}", i).as_bytes()))
            .collect();
        let results = verifier.verify_batch(&requests);
        assert!(results.iter().all(|&v| v));
    }
}
