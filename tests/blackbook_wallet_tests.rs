// ============================================================================
// BLACKBOOK WALLET - PHASE 1 INTEGRATION TESTS
// ============================================================================
//
// Tests for the 3-Shard Security System + Phase 2 Threshold Logic:
// - Shard A (Active): Encrypted with Password
// - Shard B (Cloud): Encrypted with Server Key, Gated by PIN/Threshold
// - Shard C (Recovery): For Vault storage
//
// ============================================================================

mod test_helpers; // Added mod

use layer1::storage::ConcurrentBlockchain;
use layer1::wallet_unified::handlers::{
    UnifiedWalletState, CreateWalletRequest, GetShareBRequest, SignRequest
};
use axum::http::HeaderMap;
use std::sync::Arc;
use tempfile::tempdir;
use test_helpers::create_mock_supabase; // Added import

fn create_test_state() -> Arc<UnifiedWalletState> {
    // Set mock env vars for testing
    std::env::set_var("SERVER_MASTER_KEY", "TEST_SERVER_KEY_1234567890_32BYTES_REQUIRED_MAYBE");
    std::env::set_var("SUPABASE_JWT_SECRET", "TEST_JWT_SECRET");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path_string = temp_dir.path().to_str().unwrap().to_string();
    std::mem::forget(temp_dir); // Leak to keep directory alive

    let blockchain = Arc::new(ConcurrentBlockchain::new(&db_path_string).unwrap());
    let supabase = test_helpers::create_mock_supabase();
    let vault = Arc::new(layer1::vault_manager::VaultManager::new_mock());
    Arc::new(UnifiedWalletState::new(blockchain, supabase, vault))
}

fn empty_headers() -> HeaderMap {
    HeaderMap::new()
}

#[tokio::test]
async fn test_create_wallet_v2() {
    println!("\n🧪 TEST: Create Wallet (V2 Check)");
    
    let state = create_test_state();
    let req = CreateWalletRequest {
        password: Some("my_secure_password_123".to_string()),
        pin: Some("1234".to_string()),
        daily_limit: Some(100_000), // 0.1 Dime
    };

    let result = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state),
        empty_headers(),
        axum::Json(req)
    ).await;

    assert!(result.is_ok(), "Wallet creation should succeed");
    
    let response = result.unwrap().0;
    assert!(!response.wallet_id.is_empty(), "Wallet ID should not be empty");
    assert!(response.share_a.contains(':'), "Share A should be encrypted");
}

#[tokio::test]
async fn test_sign_below_threshold_no_pin() {
    println!("\n🧪 TEST: Sign Below Threshold (No PIN Required)");
    
    let state = create_test_state();
    let limit = 500;
    
    // Create Wallet with limit 500
    let create_res = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(CreateWalletRequest {
            password: Some("pass".to_string()),
            pin: Some("1234".to_string()),
            daily_limit: Some(limit),
        })
    ).await.unwrap().0;

    // Sign transaction with amount 100 (< 500)
    let sign_req = SignRequest {
        wallet_id: create_res.wallet_id.clone(),
        message: "Small Tx".to_string(),
        share_a: create_res.share_a,
        password: "pass".to_string(),
        pin: None, // NO PIN Provided!
        amount: 100,
    };

    let result = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state),
        empty_headers(),
        axum::Json(sign_req)
    ).await;

    assert!(result.is_ok(), "Small TX should succeed without PIN");
    println!("✅ Small TX (<{}) signed without PIN", limit);
}

#[tokio::test]
async fn test_sign_above_threshold_requires_pin() {
    println!("\n🧪 TEST: Sign Above Threshold (PIN Required)");
    
    let state = create_test_state();
    let limit = 500;
    
    // Create
    let create_res = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(CreateWalletRequest {
            password: Some("pass".to_string()),
            pin: Some("1234".to_string()),
            daily_limit: Some(limit),
        })
    ).await.unwrap().0;

    // 1. Attempt High Value WITHOUT PIN -> Should Fail
    let fail_req = SignRequest {
        wallet_id: create_res.wallet_id.clone(),
        message: "Big Tx".to_string(),
        share_a: create_res.share_a.clone(),
        password: "pass".to_string(),
        pin: None,
        amount: 1000,
    };

    let fail_res = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(fail_req)
    ).await;

    assert!(fail_res.is_err(), "High value TX without PIN should fail");

    // 2. Attempt High Value WITH WRONG PIN -> Should Fail
    let wrong_pin_req = SignRequest {
        wallet_id: create_res.wallet_id.clone(),
        message: "Big Tx".to_string(),
        share_a: create_res.share_a.clone(),
        password: "pass".to_string(),
        pin: Some("0000".to_string()),
        amount: 1000,
    };

    let wrong_res = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(wrong_pin_req)
    ).await;

    assert!(wrong_res.is_err(), "High value TX with wrong PIN should fail");

    // 3. Attempt High Value WITH CORRECT PIN -> Should Pass
    let pass_req = SignRequest {
        wallet_id: create_res.wallet_id.clone(),
        message: "Big Tx".to_string(),
        share_a: create_res.share_a.clone(),
        password: "pass".to_string(),
        pin: Some("1234".to_string()),
        amount: 1000,
    };

    let pass_res = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(pass_req)
    ).await;

    assert!(pass_res.is_ok(), "High value TX with correct PIN should succeed");
    
    println!("✅ High TX (>{}) enforced PIN check correctly", limit);
}

#[tokio::test]
async fn test_share_b_storage_opaque() {
    println!("\n🧪 TEST: Share B Storage Opacity");
    // Verify client can fetch the blob but it's server-encrypted
    
    let state = create_test_state();
    let create_res = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(CreateWalletRequest {
            password: Some("p".to_string()),
            pin: Some("1".to_string()),
            daily_limit: None,
        })
    ).await.unwrap().0;

    let fetch_res = layer1::wallet_unified::handlers::get_share_b(
        axum::extract::State(state),
        empty_headers(),
        axum::Json(GetShareBRequest { wallet_id: create_res.wallet_id })
    ).await.unwrap().0;

    assert!(!fetch_res.encrypted_share_b.is_empty());
    // Should NOT be decryptable with user PIN anymore (Phase 2 change)
    let try_decrypt = layer1::wallet_unified::security::decrypt_with_secret(
        "1", 
        &fetch_res.encrypted_share_b
    );
    // This assumes decrypt_with_secret fails if key is wrong. 
    // Since "1" != SERVER_MASTER_KEY, this should fail.
    assert!(try_decrypt.is_err(), "Client PIN should NOT decrypt Server-stored Share B directly");
}

#[tokio::test]
async fn test_security_access_control() {
    println!("\n🧪 TEST: Security Access Control (Wrong Password)");
      let state = create_test_state();
    
    // Create Wallet
    let create_res = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone()),
        empty_headers(),
        axum::Json(CreateWalletRequest {
            password: Some("correct".to_string()),
            pin: Some("1234".to_string()),
            daily_limit: Some(100),
        })
    ).await.unwrap().0;
    
    // Wrong Password for Share A
    let req = SignRequest {
        wallet_id: create_res.wallet_id,
        message: "m".to_string(),
        share_a: create_res.share_a,
        password: "WRONG".to_string(), // <--- Error here
        pin: None,
        amount: 10,
    };

    let res = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state),
        empty_headers(),
        axum::Json(req)
    ).await;
    
    assert!(res.is_err(), "Should fail with wrong password");
}
