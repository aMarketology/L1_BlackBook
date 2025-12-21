//! Domain Separation Tests - L1/L2 Replay Attack Prevention
//!
//! These tests verify that signatures created for L1 cannot be replayed on L2
//! and vice versa, providing mathematical protection against cross-chain attacks.

use layer1::integration::unified_auth::{
    sign_with_domain_separation, 
    create_signed_request,
    CHAIN_ID_L1, 
    CHAIN_ID_L2,
    SignedRequest,
};
use ed25519_dalek::{SigningKey, Signer};
use hex;

#[test]
fn test_domain_separation_prevents_l1_to_l2_replay() {
    // Setup: Create a wallet
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key = hex::encode(signing_key.to_bytes());
    
    // User creates a legitimate L1 transaction (e.g., "Withdraw 100 BB")
    let payload = r#"{"action":"withdraw","amount":100}"#.to_string();
    
    let l1_request = create_signed_request(
        &private_key,
        &public_key,
        payload.clone(),
        CHAIN_ID_L1,  // <--- Signed for L1
    ).expect("Failed to create L1 request");
    
    // Verify L1 request succeeds on L1
    assert!(l1_request.verify().is_ok(), "L1 signature should verify on L1");
    
    // ATTACK: Hacker intercepts the L1 signature and tries to replay it on L2
    let mut malicious_l2_request = l1_request.clone();
    malicious_l2_request.chain_id = CHAIN_ID_L2;  // Hacker changes chain_id
    
    // Verify L2 verification FAILS (signature doesn't match L2 domain)
    let result = malicious_l2_request.verify();
    assert!(result.is_err(), "L1 signature should NOT verify on L2");
    assert!(
        result.unwrap_err().contains("Invalid signature"),
        "Should fail with signature error"
    );
    
    println!("✅ L1→L2 replay attack PREVENTED");
}

#[test]
fn test_domain_separation_prevents_l2_to_l1_replay() {
    // Setup: Create a wallet
    let signing_key = SigningKey::from_bytes(&[2u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key = hex::encode(signing_key.to_bytes());
    
    // User creates a legitimate L2 transaction (e.g., "Bet 50 BB")
    let payload = r#"{"action":"bet","amount":50}"#.to_string();
    
    let l2_request = create_signed_request(
        &private_key,
        &public_key,
        payload.clone(),
        CHAIN_ID_L2,  // <--- Signed for L2
    ).expect("Failed to create L2 request");
    
    // Verify L2 request succeeds on L2
    assert!(l2_request.verify().is_ok(), "L2 signature should verify on L2");
    
    // ATTACK: Hacker intercepts the L2 signature and tries to replay it on L1
    let mut malicious_l1_request = l2_request.clone();
    malicious_l1_request.chain_id = CHAIN_ID_L1;  // Hacker changes chain_id
    
    // Verify L1 verification FAILS (signature doesn't match L1 domain)
    let result = malicious_l1_request.verify();
    assert!(result.is_err(), "L2 signature should NOT verify on L1");
    assert!(
        result.unwrap_err().contains("Invalid signature"),
        "Should fail with signature error"
    );
    
    println!("✅ L2→L1 replay attack PREVENTED");
}

#[test]
fn test_same_key_different_chains_different_signatures() {
    // Setup: One wallet
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key = hex::encode(signing_key.to_bytes());
    
    // Same message payload
    let payload = r#"{"action":"transfer","amount":100}"#;
    
    // Sign for L1
    let l1_sig = sign_with_domain_separation(&private_key, payload, CHAIN_ID_L1)
        .expect("Failed to sign for L1");
    
    // Sign for L2
    let l2_sig = sign_with_domain_separation(&private_key, payload, CHAIN_ID_L2)
        .expect("Failed to sign for L2");
    
    // The signatures MUST be different
    assert_ne!(l1_sig, l2_sig, "L1 and L2 signatures must differ");
    
    println!("✅ Same key + Same message = Different signatures per chain");
    println!("   L1 sig: {}...", &l1_sig[..16]);
    println!("   L2 sig: {}...", &l2_sig[..16]);
}

#[test]
fn test_invalid_chain_id_rejected() {
    let signing_key = SigningKey::from_bytes(&[4u8; 32]);
    let private_key = hex::encode(signing_key.to_bytes());
    
    let payload = "test";
    
    // Try to sign with invalid chain_id
    let result = sign_with_domain_separation(&private_key, payload, 0x99);
    
    assert!(result.is_err(), "Invalid chain_id should be rejected");
    assert!(
        result.unwrap_err().contains("Invalid chain_id"),
        "Should fail with chain_id error"
    );
    
    println!("✅ Invalid chain IDs rejected during signing");
}

#[test]
fn test_legitimate_cross_chain_usage() {
    // Demonstrates proper usage: User can sign for both chains using same key
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key = hex::encode(signing_key.to_bytes());
    
    // L1 operation: Deposit funds
    let l1_payload = r#"{"action":"deposit","amount":1000}"#.to_string();
    let l1_request = create_signed_request(
        &private_key,
        &public_key,
        l1_payload,
        CHAIN_ID_L1,
    ).expect("Failed to create L1 request");
    
    assert!(l1_request.verify().is_ok(), "L1 request should verify on L1");
    
    // L2 operation: Place bet
    let l2_payload = r#"{"action":"bet","market":"BTC_100K"}"#.to_string();
    let l2_request = create_signed_request(
        &private_key,
        &public_key,
        l2_payload,
        CHAIN_ID_L2,
    ).expect("Failed to create L2 request");
    
    assert!(l2_request.verify().is_ok(), "L2 request should verify on L2");
    
    println!("✅ Legitimate multi-chain usage works correctly");
}

#[test]
fn test_signature_format_includes_chain_id() {
    // Verify that the chain_id is actually embedded in the signed message
    let signing_key = SigningKey::from_bytes(&[6u8; 32]);
    let private_key = hex::encode(signing_key.to_bytes());
    
    let message = "test_message";
    
    // Manual signing to verify format
    let l1_sig = sign_with_domain_separation(&private_key, message, CHAIN_ID_L1)
        .expect("Failed to sign");
    
    // The signature should be for [0x01][message], not just [message]
    // We can't directly inspect the signature, but we can verify different inputs
    // produce different outputs
    let l2_sig = sign_with_domain_separation(&private_key, message, CHAIN_ID_L2)
        .expect("Failed to sign");
    
    assert_ne!(l1_sig, l2_sig, "Chain ID must affect signature");
    
    println!("✅ Chain ID is cryptographically embedded in signatures");
}
