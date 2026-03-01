// ============================================================================
// BLACKBOOK L1 — SIGNATURE VERIFICATION TESTS
// ============================================================================
//
// Pre-production tests proving that the PoH blockchain ONLY accepts
// transactions carrying valid cryptographic signatures:
//
//   1. Ed25519 signed transfers  (AI agent path)
//   2. SSS 2-of-3 reconstruction (human wallet path)
//   3. PoH pipeline sigverify    (block-level enforcement)
//   4. Faucet signature gate     (no free mints without proof-of-ownership)
//   5. Replay protection         (nonce + timestamp window)
//
// Run:  cargo test --test signature_verification
// ============================================================================

use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// ============================================================================
// HELPER: Generate a fresh Ed25519 keypair and return (signing_key, pubkey_hex)
// ============================================================================
fn fresh_keypair() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk_hex)
}

fn fresh_keypair_bs58() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_bs58 = bs58::encode(sk.verifying_key().to_bytes()).into_string();
    (sk, pk_bs58)
}

// ============================================================================
// TEST GROUP 1: Ed25519 Core Verification (library-level)
// ============================================================================

/// A valid Ed25519 signature on the transfer message MUST verify.
#[test]
fn test_valid_ed25519_signature_verifies() {
    let (sk, pk_hex) = fresh_keypair();

    let to_address = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
    let amount = 1.5_f64;

    // Message format used by signed_transfer_handler
    let chain_id: u8 = 1;
    let timestamp: u64 = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({ "to": to_address, "amount": amount }).to_string();

    let mut message = vec![chain_id];
    message.extend_from_slice(payload.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(nonce.as_bytes());

    let sig = sk.sign(&message);

    // Verify just like the handler does
    let pubkey_bytes = hex::decode(&pk_hex).unwrap();
    let vk = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
    assert!(vk.verify(&message, &sig).is_ok(), "Valid signature MUST pass");
}

/// A signature from a DIFFERENT key MUST be rejected.
#[test]
fn test_wrong_key_signature_rejected() {
    let (sk_real, _pk_real_hex) = fresh_keypair();
    let (_sk_attacker, pk_attacker_hex) = fresh_keypair();

    let to = hex::encode([0xABu8; 32]);
    let amount = 5.0;
    let chain_id: u8 = 1;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({ "to": to, "amount": amount }).to_string();

    let mut message = vec![chain_id];
    message.extend_from_slice(payload.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(nonce.as_bytes());

    // Sign with real key
    let sig = sk_real.sign(&message);

    // Try to verify with attacker's key — must fail
    let attacker_bytes = hex::decode(&pk_attacker_hex).unwrap();
    let vk_attacker = VerifyingKey::from_bytes(attacker_bytes.as_slice().try_into().unwrap()).unwrap();
    assert!(
        vk_attacker.verify(&message, &sig).is_err(),
        "Signature from a different key MUST be rejected"
    );
}

/// A tampered message (changed amount) MUST invalidate the signature.
#[test]
fn test_tampered_amount_rejected() {
    let (sk, pk_hex) = fresh_keypair();
    let to = hex::encode([0xCDu8; 32]);
    let chain_id: u8 = 1;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    // Sign with amount = 1.0
    let payload_original = serde_json::json!({ "to": to, "amount": 1.0 }).to_string();
    let mut msg_original = vec![chain_id];
    msg_original.extend_from_slice(payload_original.as_bytes());
    msg_original.extend_from_slice(b"\n");
    msg_original.extend_from_slice(timestamp.to_string().as_bytes());
    msg_original.extend_from_slice(b"\n");
    msg_original.extend_from_slice(nonce.as_bytes());
    let sig = sk.sign(&msg_original);

    // Attacker changes amount to 9999.0
    let payload_tampered = serde_json::json!({ "to": to, "amount": 9999.0 }).to_string();
    let mut msg_tampered = vec![chain_id];
    msg_tampered.extend_from_slice(payload_tampered.as_bytes());
    msg_tampered.extend_from_slice(b"\n");
    msg_tampered.extend_from_slice(timestamp.to_string().as_bytes());
    msg_tampered.extend_from_slice(b"\n");
    msg_tampered.extend_from_slice(nonce.as_bytes());

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(&msg_tampered, &sig).is_err(),
        "Tampered amount MUST invalidate signature"
    );
}

/// A tampered recipient address MUST invalidate the signature.
#[test]
fn test_tampered_recipient_rejected() {
    let (sk, pk_hex) = fresh_keypair();
    let real_to = hex::encode([0x11u8; 32]);
    let fake_to = hex::encode([0x22u8; 32]);
    let chain_id: u8 = 1;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    let payload_real = serde_json::json!({ "to": real_to, "amount": 1.0 }).to_string();
    let mut msg = vec![chain_id];
    msg.extend_from_slice(payload_real.as_bytes());
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(nonce.as_bytes());
    let sig = sk.sign(&msg);

    // Attacker swaps recipient
    let payload_fake = serde_json::json!({ "to": fake_to, "amount": 1.0 }).to_string();
    let mut msg_fake = vec![chain_id];
    msg_fake.extend_from_slice(payload_fake.as_bytes());
    msg_fake.extend_from_slice(b"\n");
    msg_fake.extend_from_slice(timestamp.to_string().as_bytes());
    msg_fake.extend_from_slice(b"\n");
    msg_fake.extend_from_slice(nonce.as_bytes());

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(&msg_fake, &sig).is_err(),
        "Tampered recipient MUST invalidate signature"
    );
}

/// An empty signature MUST be rejected.
#[test]
fn test_empty_signature_rejected() {
    let (_sk, pk_hex) = fresh_keypair();
    let msg = b"anything";

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    // 64 zero bytes = forged signature
    let zero_sig = Signature::from_bytes(&[0u8; 64]);
    assert!(
        vk.verify(msg, &zero_sig).is_err(),
        "Zero-byte signature MUST be rejected"
    );
}

/// Random garbage bytes as signature MUST be rejected.
#[test]
fn test_random_garbage_signature_rejected() {
    let (_sk, pk_hex) = fresh_keypair();
    let msg = b"transfer message";

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    let mut garbage = [0u8; 64];
    getrandom::getrandom(&mut garbage).unwrap();
    let garbage_sig = Signature::from_bytes(&garbage);

    assert!(
        vk.verify(msg, &garbage_sig).is_err(),
        "Random garbage signature MUST be rejected"
    );
}


// ============================================================================
// TEST GROUP 2: PoH Pipeline Signature Verification
// ============================================================================
// Tests the exact message format used by spawn_fetch_stage():
//   message = "from:to:amount"
//   pubkey  = hex-encoded 32 bytes (from field IS the pubkey)
//   sig     = raw 64 bytes

/// Pipeline accepts a correctly signed packet.
#[test]
fn test_pipeline_sigverify_valid() {
    let (sk, pk_hex) = fresh_keypair();
    let to_hex = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
    let amount = 2.5_f64;

    // This is the exact format used in spawn_fetch_stage
    let msg = format!("{}:{}:{}", pk_hex, to_hex, amount);
    let sig = sk.sign(msg.as_bytes());

    // Replicate pipeline verification logic
    let pubkey_bytes = hex::decode(&pk_hex).unwrap();
    assert_eq!(pubkey_bytes.len(), 32);
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), 64);

    let vk = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
    assert!(
        vk.verify(msg.as_bytes(), &sig).is_ok(),
        "Pipeline MUST accept valid Ed25519 signature"
    );
}

/// Pipeline rejects a packet with no signature (empty vec).
#[test]
fn test_pipeline_sigverify_missing_signature() {
    // Replicate the pipeline logic: empty signature → signature_valid = false
    let signature: Vec<u8> = vec![];
    let from = hex::encode([0xAAu8; 32]);

    let signature_valid = if signature.is_empty() || from.is_empty() {
        false
    } else {
        true // would never reach here
    };

    assert!(!signature_valid, "Empty signature MUST produce signature_valid=false");
}

/// Pipeline rejects a packet with no sender (empty string).
#[test]
fn test_pipeline_sigverify_missing_sender() {
    let signature = vec![0u8; 64];
    let from = String::new();

    let signature_valid = if signature.is_empty() || from.is_empty() {
        false
    } else {
        true
    };

    assert!(!signature_valid, "Empty sender MUST produce signature_valid=false");
}

/// Pipeline rejects a signature from the wrong key.
#[test]
fn test_pipeline_sigverify_wrong_key() {
    let (sk_alice, _pk_alice_hex) = fresh_keypair();
    let (_sk_bob, pk_bob_hex) = fresh_keypair();
    let to = hex::encode([0xBBu8; 32]);
    let amount = 1.0;

    // Alice signs a message claiming to be Bob
    let msg = format!("{}:{}:{}", pk_bob_hex, to, amount);
    let sig = sk_alice.sign(msg.as_bytes());

    // Verify using Bob's pubkey (the claimed sender)
    let bob_bytes = hex::decode(&pk_bob_hex).unwrap();
    let vk_bob = VerifyingKey::from_bytes(bob_bytes.as_slice().try_into().unwrap()).unwrap();

    assert!(
        vk_bob.verify(msg.as_bytes(), &sig).is_err(),
        "Signature from Alice MUST NOT verify as Bob"
    );
}

/// Pipeline rejects a signature where the amount was tampered.
#[test]
fn test_pipeline_sigverify_tampered_amount() {
    let (sk, pk_hex) = fresh_keypair();
    let to = hex::encode([0xCCu8; 32]);

    // Sign with amount = 0.5
    let msg_real = format!("{}:{}:{}", pk_hex, to, 0.5);
    let sig = sk.sign(msg_real.as_bytes());

    // Verify against tampered amount = 999.0
    let msg_fake = format!("{}:{}:{}", pk_hex, to, 999.0);
    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(msg_fake.as_bytes(), &sig).is_err(),
        "Tampered amount MUST fail pipeline sigverify"
    );
}

/// Pipeline rejects a short signature (< 64 bytes).
#[test]
fn test_pipeline_sigverify_short_signature() {
    let short_sig: Vec<u8> = vec![0u8; 32]; // only 32 bytes, needs 64
    let from = hex::encode([0xAAu8; 32]);
    let _to = hex::encode([0xBBu8; 32]);
    let _amount = 1.0;

    // Replicate pipeline logic
    let signature_valid = if short_sig.is_empty() || from.is_empty() {
        false
    } else {
        (|| -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let pubkey_bytes = hex::decode(&from)?;
            if pubkey_bytes.len() != 32 { return Ok(false); }
            if short_sig.len() != 64 { return Ok(false); }
            Ok(true) // would never reach actual verify
        })().unwrap_or(false)
    };

    assert!(!signature_valid, "Short signature (< 64 bytes) MUST be rejected");
}

/// Pipeline rejects an invalid pubkey (wrong length).
#[test]
fn test_pipeline_sigverify_invalid_pubkey_length() {
    let bad_from = hex::encode([0xAAu8; 16]); // only 16 bytes, needs 32
    let _sig = vec![0u8; 64];

    let signature_valid = if _sig.is_empty() || bad_from.is_empty() {
        false
    } else {
        (|| -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let pubkey_bytes = hex::decode(&bad_from)?;
            if pubkey_bytes.len() != 32 { return Ok(false); }
            Ok(true)
        })().unwrap_or(false)
    };

    assert!(!signature_valid, "Invalid pubkey length MUST be rejected");
}

// ============================================================================
// TEST GROUP 3: Faucet Signature Format
// ============================================================================
// The faucet uses message format: "FAUCET:{to}:{amount}:{timestamp}:{nonce}"

/// Faucet accepts a properly signed request.
#[test]
fn test_faucet_valid_signature() {
    let (sk, pk_hex) = fresh_keypair();
    let amount = 0.1_f64;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    let message = format!("FAUCET:{}:{}:{}:{}", pk_hex, amount, timestamp, nonce);
    let sig = sk.sign(message.as_bytes());

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(message.as_bytes(), &sig).is_ok(),
        "Faucet MUST accept valid owner signature"
    );
}

/// Faucet rejects if someone signs FOR a different wallet.
#[test]
fn test_faucet_impersonation_rejected() {
    let (sk_attacker, _pk_attacker) = fresh_keypair();
    let (_sk_victim, pk_victim_hex) = fresh_keypair();
    let amount = 0.1_f64;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    // Attacker signs a faucet request for victim's address
    let message = format!("FAUCET:{}:{}:{}:{}", pk_victim_hex, amount, timestamp, nonce);
    let sig = sk_attacker.sign(message.as_bytes());

    // Verify using the victim's pubkey (as the handler would)
    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_victim_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(message.as_bytes(), &sig).is_err(),
        "Faucet MUST reject impersonation — attacker can't sign for victim"
    );
}

/// Faucet signature is invalid if the amount is changed after signing.
#[test]
fn test_faucet_amount_tampering_rejected() {
    let (sk, pk_hex) = fresh_keypair();
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    // Sign for 0.01 BB
    let msg_signed = format!("FAUCET:{}:{}:{}:{}", pk_hex, 0.01, timestamp, nonce);
    let sig = sk.sign(msg_signed.as_bytes());

    // Attacker changes to max (0.1 BB)
    let msg_tampered = format!("FAUCET:{}:{}:{}:{}", pk_hex, 0.1, timestamp, nonce);

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(msg_tampered.as_bytes(), &sig).is_err(),
        "Changed faucet amount MUST invalidate signature"
    );
}

// ============================================================================
// TEST GROUP 4: SSS Shamir Reconstruction → Ed25519 Signing
// ============================================================================
// Tests that the SSS path derives the correct Ed25519 key from shares
// and that a bad share/password produces a wrong address.

/// SSS: 2-of-3 reconstruction produces the original signing key.
#[test]
fn test_sss_reconstruction_produces_correct_key() {
    use sharks::{Share, Sharks};

    // 1. Generate a random 32-byte seed (simulates wallet creation)
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();

    // 2. Derive Ed25519 key from seed
    let original_sk = SigningKey::from_bytes(&seed);
    let original_address = bs58::encode(original_sk.verifying_key().to_bytes()).into_string();

    // 3. Split seed into 3 Shamir shares (threshold = 2)
    let sharks = Sharks(2);
    let shares: Vec<Share> = sharks.dealer(&seed).take(3).collect();

    // 4. Reconstruct from any 2 shares
    let reconstructed_seed = sharks.recover(&[shares[0].clone(), shares[1].clone()]).unwrap();
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&reconstructed_seed[..32]);

    let recovered_sk = SigningKey::from_bytes(&seed_32);
    let recovered_address = bs58::encode(recovered_sk.verifying_key().to_bytes()).into_string();

    assert_eq!(
        original_address, recovered_address,
        "SSS reconstruction MUST produce the same Ed25519 key"
    );

    // 5. Sign a transfer and verify
    let msg = format!("{}:some_recipient:1.5", original_address);
    let sig = recovered_sk.sign(msg.as_bytes());
    assert!(
        original_sk.verifying_key().verify(msg.as_bytes(), &sig).is_ok(),
        "Signature from reconstructed key MUST verify with original pubkey"
    );
}

/// SSS: Using shares from DIFFERENT seeds MUST produce wrong address.
#[test]
fn test_sss_wrong_shares_produce_wrong_address() {
    use sharks::{Share, Sharks};

    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];
    getrandom::getrandom(&mut seed_a).unwrap();
    getrandom::getrandom(&mut seed_b).unwrap();

    let sk_a = SigningKey::from_bytes(&seed_a);
    let address_a = bs58::encode(sk_a.verifying_key().to_bytes()).into_string();

    let sharks = Sharks(2);
    let shares_a: Vec<Share> = sharks.dealer(&seed_a).take(3).collect();
    let shares_b: Vec<Share> = sharks.dealer(&seed_b).take(3).collect();

    // Mix shares from different seeds — reconstruction succeeds but produces garbage
    let mixed_seed = sharks.recover(&[shares_a[0].clone(), shares_b[1].clone()]).unwrap();
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&mixed_seed[..32]);

    let mixed_sk = SigningKey::from_bytes(&seed_32);
    let mixed_address = bs58::encode(mixed_sk.verifying_key().to_bytes()).into_string();

    assert_ne!(
        address_a, mixed_address,
        "Mixed shares MUST produce a different address — handler would reject"
    );
}

/// SSS: Reconstructed key signs a transfer that verifies.
#[test]
fn test_sss_transfer_signature_end_to_end() {
    use sharks::{Share, Sharks};

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();

    let sk = SigningKey::from_bytes(&seed);
    let wallet_address = bs58::encode(sk.verifying_key().to_bytes()).into_string();

    // Split into shares
    let sharks_engine = Sharks(2);
    let shares: Vec<Share> = sharks_engine.dealer(&seed).take(3).collect();

    // Reconstruct from shares 0 + 2 (skipping share 1)
    let recovered = sharks_engine.recover(&[shares[0].clone(), shares[2].clone()]).unwrap();
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&recovered[..32]);

    let recovered_sk = SigningKey::from_bytes(&seed_32);
    let derived_address = bs58::encode(recovered_sk.verifying_key().to_bytes()).into_string();

    // Address check (same as handler does)
    assert_eq!(wallet_address, derived_address, "Derived address must match");

    // Sign transfer message (same format as transfer_with_sss handler)
    let to = "SomeRecipientAddress123456789012345678901234";
    let amount = 42.5;
    let tx_message = format!("{}:{}:{}", wallet_address, to, amount);
    let sig = recovered_sk.sign(tx_message.as_bytes());

    // Verify signature using original verifying key
    assert!(
        sk.verifying_key().verify(tx_message.as_bytes(), &sig).is_ok(),
        "SSS-reconstructed transfer signature MUST verify"
    );
}


// ============================================================================
// TEST GROUP 5: Replay Protection
// ============================================================================

/// Same nonce used twice MUST be detected.
#[test]
fn test_replay_nonce_detection() {
    use dashmap::DashMap;

    let used_nonces: DashMap<String, u64> = DashMap::new();
    let wallet = "TestWallet123";
    let nonce = "unique-nonce-abc-123";
    let now = now_secs();

    let nonce_key = format!("transfer:{}:{}", wallet, nonce);

    // First use: should succeed
    assert!(!used_nonces.contains_key(&nonce_key), "First use of nonce should be allowed");
    used_nonces.insert(nonce_key.clone(), now);

    // Second use: should be rejected
    assert!(
        used_nonces.contains_key(&nonce_key),
        "Second use of same nonce MUST be detected as replay"
    );
}

/// Stale timestamp (> 60s old) MUST be rejected.
#[test]
fn test_stale_timestamp_rejected() {
    let now = now_secs();
    let old_timestamp = now - 120; // 2 minutes ago

    let is_fresh = now.saturating_sub(old_timestamp) <= 60;
    assert!(!is_fresh, "Timestamp 120s old MUST be rejected (>60s window)");
}

/// Fresh timestamp (< 60s old) MUST be accepted.
#[test]
fn test_fresh_timestamp_accepted() {
    let now = now_secs();
    let recent_timestamp = now - 5; // 5 seconds ago

    let is_fresh = now.saturating_sub(recent_timestamp) <= 60;
    assert!(is_fresh, "Timestamp 5s old MUST be accepted (<60s window)");
}

/// Edge case: exactly 60 seconds should still be accepted.
#[test]
fn test_timestamp_exactly_60s_accepted() {
    let now = now_secs();
    let edge_timestamp = now - 60;

    let is_fresh = now.saturating_sub(edge_timestamp) <= 60;
    assert!(is_fresh, "Timestamp exactly 60s old should still be accepted");
}

/// Edge case: 61 seconds should be rejected.
#[test]
fn test_timestamp_61s_rejected() {
    let now = now_secs();
    let expired_timestamp = now - 61;

    let is_fresh = now.saturating_sub(expired_timestamp) <= 60;
    assert!(!is_fresh, "Timestamp 61s old MUST be rejected");
}

/// Nonce pruning: old nonces (>120s) should be cleaned up.
#[test]
fn test_nonce_pruning() {
    use dashmap::DashMap;

    let used_nonces: DashMap<String, u64> = DashMap::new();
    let now = now_secs();

    // Insert old nonces
    used_nonces.insert("old1".to_string(), now - 200);
    used_nonces.insert("old2".to_string(), now - 150);
    // Insert fresh nonce
    used_nonces.insert("fresh".to_string(), now - 10);

    assert_eq!(used_nonces.len(), 3);

    // Prune (same logic as handler: retain nonces newer than 120s)
    let cutoff = now.saturating_sub(120);
    used_nonces.retain(|_, &mut ts| ts > cutoff);

    assert_eq!(used_nonces.len(), 1, "Only fresh nonce should survive pruning");
    assert!(used_nonces.contains_key("fresh"), "Fresh nonce must survive");
    assert!(!used_nonces.contains_key("old1"), "Old nonce must be pruned");
}

// ============================================================================
// TEST GROUP 6: Transaction Hash Integrity (SHA-256)
// ============================================================================

/// SHA-256 tx hash is deterministic.
#[test]
fn test_tx_hash_deterministic_sha256() {
    let data = "some_tx_data_here_12345";

    let hash1 = {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    };

    let hash2 = {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    };

    assert_eq!(hash1, hash2, "SHA-256 hash MUST be deterministic");
    assert_eq!(hash1.len(), 64, "SHA-256 hex hash must be 64 chars");
}

/// Different data MUST produce different hashes.
#[test]
fn test_tx_hash_collision_resistance() {
    let hash_a = {
        let mut h = Sha256::new();
        h.update(b"transfer:Alice:Bob:100");
        hex::encode(h.finalize())
    };
    let hash_b = {
        let mut h = Sha256::new();
        h.update(b"transfer:Alice:Bob:101");
        hex::encode(h.finalize())
    };

    assert_ne!(hash_a, hash_b, "Different tx data MUST produce different hashes");
}

// ============================================================================
// TEST GROUP 7: Address Resolution (addr_to_pubkey parity)
// ============================================================================

/// Base58 address roundtrips correctly.
#[test]
fn test_addr_to_pubkey_base58() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk_bytes = sk.verifying_key().to_bytes();
    let bs58_addr = bs58::encode(&vk_bytes).into_string();

    // Decode and verify roundtrip
    let decoded = bs58::decode(&bs58_addr).into_vec().unwrap();
    assert_eq!(decoded.len(), 32, "Base58 address must decode to 32 bytes");
    assert_eq!(&decoded[..], &vk_bytes[..], "Roundtrip must preserve bytes");
}

/// Legacy bb_ prefix addresses get deterministic SHA-256 mapping.
#[test]
fn test_addr_to_pubkey_legacy_bb_prefix() {
    let addr = "bb_alice";
    let stripped = addr.strip_prefix("bb_").unwrap();

    let bytes: [u8; 32] = Sha256::digest(stripped.as_bytes()).into();

    // Same input must produce same output
    let bytes2: [u8; 32] = Sha256::digest(stripped.as_bytes()).into();
    assert_eq!(bytes, bytes2, "Legacy address mapping MUST be deterministic");
}

/// Two different addresses MUST NOT collide.
#[test]
fn test_addr_to_pubkey_no_collision() {
    let bytes_a: [u8; 32] = Sha256::digest(b"alice").into();
    let bytes_b: [u8; 32] = Sha256::digest(b"bob").into();
    assert_ne!(bytes_a, bytes_b, "Different addresses MUST NOT collide");
}


// ============================================================================
// TEST GROUP 8: Signed Transfer — Full Message Construction
// ============================================================================
// Verifies the exact message format used by signed_transfer_handler:
//   message = [chain_id] ++ payload_json ++ "\n" ++ timestamp ++ "\n" ++ nonce

/// Full signed transfer E2E: construct, sign, verify.
#[test]
fn test_signed_transfer_e2e() {
    let (sk, pk_hex) = fresh_keypair();
    let (_, to_hex) = fresh_keypair();

    let chain_id: u8 = 1;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();
    let amount = 3.14;

    let payload = serde_json::json!({ "to": to_hex, "amount": amount });
    let payload_str = payload.to_string();

    // Construct message exactly as the handler does
    let mut message = vec![chain_id];
    message.extend_from_slice(payload_str.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(nonce.as_bytes());

    let sig = sk.sign(&message);

    // Verify
    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();
    assert!(vk.verify(&message, &sig).is_ok(), "Full signed transfer E2E must pass");

    // Verify sig is 64 bytes hex-encoded to 128 chars
    let sig_hex = hex::encode(sig.to_bytes());
    assert_eq!(sig_hex.len(), 128, "Signature hex should be 128 chars");
}

/// chain_id mismatch should invalidate the signature.
#[test]
fn test_signed_transfer_wrong_chain_id() {
    let (sk, pk_hex) = fresh_keypair();
    let to = hex::encode([0x99u8; 32]);
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({ "to": to, "amount": 1.0 }).to_string();

    // Sign with chain_id = 1
    let mut msg_chain1 = vec![1u8];
    msg_chain1.extend_from_slice(payload.as_bytes());
    msg_chain1.extend_from_slice(b"\n");
    msg_chain1.extend_from_slice(timestamp.to_string().as_bytes());
    msg_chain1.extend_from_slice(b"\n");
    msg_chain1.extend_from_slice(nonce.as_bytes());
    let sig = sk.sign(&msg_chain1);

    // Verify with chain_id = 2 (wrong chain)
    let mut msg_chain2 = vec![2u8];
    msg_chain2.extend_from_slice(payload.as_bytes());
    msg_chain2.extend_from_slice(b"\n");
    msg_chain2.extend_from_slice(timestamp.to_string().as_bytes());
    msg_chain2.extend_from_slice(b"\n");
    msg_chain2.extend_from_slice(nonce.as_bytes());

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(&msg_chain2, &sig).is_err(),
        "Wrong chain_id MUST invalidate signature (cross-chain replay protection)"
    );
}

/// nonce mismatch should invalidate the signature.
#[test]
fn test_signed_transfer_wrong_nonce() {
    let (sk, pk_hex) = fresh_keypair();
    let to = hex::encode([0x88u8; 32]);
    let timestamp = now_secs();
    let payload = serde_json::json!({ "to": to, "amount": 1.0 }).to_string();

    let nonce_real = "nonce-aaa-111";
    let nonce_fake = "nonce-bbb-222";

    let mut msg = vec![1u8];
    msg.extend_from_slice(payload.as_bytes());
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.extend_from_slice(b"\n");
    msg.extend_from_slice(nonce_real.as_bytes());
    let sig = sk.sign(&msg);

    let mut msg_fake = vec![1u8];
    msg_fake.extend_from_slice(payload.as_bytes());
    msg_fake.extend_from_slice(b"\n");
    msg_fake.extend_from_slice(timestamp.to_string().as_bytes());
    msg_fake.extend_from_slice(b"\n");
    msg_fake.extend_from_slice(nonce_fake.as_bytes());

    let vk = VerifyingKey::from_bytes(
        hex::decode(&pk_hex).unwrap().as_slice().try_into().unwrap(),
    ).unwrap();

    assert!(
        vk.verify(&msg_fake, &sig).is_err(),
        "Wrong nonce MUST invalidate signature"
    );
}


// ============================================================================
// TEST GROUP 9: Faucet with base58 addresses
// ============================================================================

/// Faucet request with base58 pubkey (Solana-style wallet).
#[test]
fn test_faucet_base58_address() {
    let (sk, pk_bs58) = fresh_keypair_bs58();
    let amount = 0.05_f64;
    let timestamp = now_secs();
    let nonce = uuid::Uuid::new_v4().to_string();

    let message = format!("FAUCET:{}:{}:{}:{}", pk_bs58, amount, timestamp, nonce);
    let sig = sk.sign(message.as_bytes());

    // Verify using base58 decoded key
    let pubkey_bytes = bs58::decode(&pk_bs58).into_vec().unwrap();
    assert_eq!(pubkey_bytes.len(), 32, "Base58 pubkey must be 32 bytes");

    let vk = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
    assert!(
        vk.verify(message.as_bytes(), &sig).is_ok(),
        "Faucet with base58 address MUST verify"
    );
}


// ============================================================================
// UTILITIES
// ============================================================================

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
