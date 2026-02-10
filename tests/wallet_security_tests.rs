// ============================================================================
// WALLET SECURITY TESTS (Phase 4 Validation)
// ============================================================================
//
// Focus:
// 1. Shard A - Encryption/Decryption
// 2. Shard B - Persistence (Redb)
// 3. Shard B - Bouncer Protections (PIN)
// 4. Shard C - Vault Persistence (Mock Vault)
//
// Run: cargo test --test wallet_security_tests

mod test_helpers;

use layer1::storage::ConcurrentBlockchain;
use layer1::wallet_unified::handlers::{
    UnifiedWalletState, CreateResponse, CreateWalletRequest, SignRequest,
    create_hybrid_wallet, sign_hybrid_tx
};
use layer1::wallet_unified::security;
use std::sync::Arc;
use tempfile::tempdir;
use serde_json::json;
use test_helpers::{create_test_state, create_mock_jwt_headers, create_empty_headers, create_mock_supabase};
use zeroize::Zeroize;

// ============================================================================
// TEST 01: Shard A Encryption
// ============================================================================
#[tokio::test]
async fn test_01_shard_a_encryption() {
    let state = create_test_state();
    let password = "SuperSecurePassword123!".to_string();
    let pin = "123499".to_string();

    let create_req = CreateWalletRequest {
        password: Some(password.clone()),
        pin: Some(pin.clone()),
        daily_limit: Some(1000),
    };
    
    let result = create_hybrid_wallet(
        axum::extract::State(state.clone()), 
        create_mock_jwt_headers(),
        axum::Json(create_req)
    ).await;
    
    assert!(result.is_ok());
    let axum::Json(response) = result.unwrap();

    let shard_a_encrypted_hex = response.share_a;
    // let shard_a_bytes = hex::decode(&shard_a_encrypted_hex).expect("Failed to hex decode response share A");

    // 1. Verify we CANNOT decrypt with wrong password
    let wrong_password = "WrongPassword123!";
    let decrypted_fail = security::decrypt_with_secret(wrong_password, &shard_a_encrypted_hex);
    assert!(decrypted_fail.is_err(), "Should fail to decrypt Shard A with wrong password");

    // 2. Verify we CAN decrypt with correct password
    let decrypted_success = security::decrypt_with_secret(&password, &shard_a_encrypted_hex);
    assert!(decrypted_success.is_ok(), "Should successfull decrypt Shard A with correct password");
}

// ============================================================================
// TEST 02: Shard B Persistence (Redb)
// ============================================================================
#[tokio::test]
async fn test_02_shard_b_persistence() {
    let state = create_test_state();
    let password = "pass".to_string();
    
    let create_req = CreateWalletRequest {
        password: Some(password),
        pin: Some("1234".to_string()),
        daily_limit: Some(1000),
    };

    let result = create_hybrid_wallet(
        axum::extract::State(state.clone()),
        create_mock_jwt_headers(),
        axum::Json(create_req)
    ).await;
    let axum::Json(response) = result.unwrap();
    let wallet_id = response.wallet_id;

    // Verify Shard B is stored in Redb
    // The handlers store "ShardBContainer" encrypted with SERVER_KEY.
    // We check if the key exists in the blockchain store.
    
    // We can't access Redb directly easily without parsing helpers, but 'get_frost_share_b' should exist in Blockchain.
    let share_b_result = state.blockchain.get_frost_share_b(&wallet_id);
    assert!(share_b_result.is_ok(), "Blockchain should have Shard B stored");
    
    let share_b_bytes = share_b_result.unwrap();
    assert!(!share_b_bytes.is_empty(), "Shard B should not be empty");
}

// ============================================================================
// TEST 03: Shard B Bouncer (PIN)
// ============================================================================
#[tokio::test]
async fn test_03_shard_b_bouncer() {
    let state = create_test_state();
    let password = "pass".to_string();
    let pin = "999999".to_string();
    let limit = 500;

    // Create Wallet with Limit 500
    let create_req = CreateWalletRequest {
        password: Some(password.clone()),
        pin: Some(pin.clone()),
        daily_limit: Some(limit),
    };
    let result = create_hybrid_wallet(
        axum::extract::State(state.clone()),
        create_mock_jwt_headers(),
        axum::Json(create_req)
    ).await;
    let axum::Json(res) = result.unwrap();
    let wallet_id = res.wallet_id;
    let share_a = res.share_a;

    // 1. Transaction UNDER limit -> PIN NOT REQUIRED (Wait, is PIN Optional in API? Yes if < Threshold?)
    // Actually, 'pin' field is Option<String>.
    // Logic inside 'sign_hybrid_tx' checks threshold.
    
    // However, for newly created wallet or if no cached session, does it force PIN?
    // The current implementation of 'get_shard_b_handler' (bouncer) usually requires PIN unless cached.
    // But 'sign_hybrid_tx' calls 'unlock_shard_b' internally.
    
    // Let's test providing correct PIN for valid tx (AMOUNT > LIMIT)
    let sign_req_high = SignRequest {
        wallet_id: wallet_id.clone(),
        message: "High Value Tx".to_string(),
        share_a: share_a.clone(),
        password: password.clone(),
        pin: Some(pin.clone()),
        amount: 600, // > 500
    };
    let tx_high = sign_hybrid_tx(
        axum::extract::State(state.clone()),
        create_mock_jwt_headers(),
        axum::Json(sign_req_high)
    ).await;
    assert!(tx_high.is_ok(), "Should allow high value tx with correct PIN");

    // 2. Transaction OVER limit with WRONG PIN
    let sign_req_fail = SignRequest {
        wallet_id: wallet_id.clone(),
        message: "High Value Tx Fail".to_string(),
        share_a: share_a.clone(),
        password: password.clone(),
        pin: Some("000000".to_string()), // WRONG
        amount: 600, // > 500
    };
    let tx_fail = sign_hybrid_tx(
        axum::extract::State(state.clone()),
        create_mock_jwt_headers(),
        axum::Json(sign_req_fail)
    ).await;
    assert!(tx_fail.is_err(), "Should REJECT high value tx with WRONG PIN");
}

// ============================================================================
// TEST 04: Shard C Vault Storage
// ============================================================================
#[tokio::test]
async fn test_04_shard_c_vault() {
    let state = create_test_state();
    let password = "pass".to_string();
    let pin = "1234".to_string();

    let create_req = CreateWalletRequest {
        password: Some(password.clone()),
        pin: Some(pin.clone()),
        daily_limit: Some(1000),
    };
    
    // We need to use JWT headers because Vault storage is only triggered for authenticated users
    let headers = create_mock_jwt_headers();
    
    let result = create_hybrid_wallet(
        axum::extract::State(state.clone()), 
        headers, // contains user_id "test-user-id-123" (see test_helpers)
        axum::Json(create_req)
    ).await;
    
    assert!(result.is_ok());
    let axum::Json(res) = result.unwrap();
    let share_c_returned = res.share_c; // This is the raw C shard (hex encoded) returned to user
    
    // Verify it is stored in Mock Vault
    // The mock JWT user_id is "test-user-id-123" (from test_helpers.rs)
    let user_id = "test-user-id-123";
    
    // Retrieve via VaultManager directly
    let vault_result = state.vault.retrieve_shard_c(user_id).await;
    
    assert!(vault_result.is_ok(), "Shard C should be retrievable from Vault");
    let stored_c = vault_result.unwrap();
    
    assert_eq!(stored_c, share_c_returned, "Stored Shard C must match the one returned to user");
    println!("✅ Verified Shard C in Vault matches user backup!");
}
