// ============================================================================
// FROST + SSS WALLET INTEGRATION TESTS
// ============================================================================
//
// Comprehensive test suite for the Hybrid Wallet system
// Tests: Creation, Signing, Recovery, ReDB Persistence
//
// Run: cargo test --test wallet_integration_tests

use layer1::storage::ConcurrentBlockchain;
use layer1::wallet_unified::handlers::{UnifiedWalletState, CreateResponse};
use std::sync::Arc;
use tempfile::tempdir;
use serde_json::json;

// ============================================================================
// TEST 01: Wallet Creation
// ============================================================================

#[tokio::test]
async fn test_01_create_frost_wallet() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create wallet
    let result = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await;

    assert!(result.is_ok(), "Wallet creation should succeed");
    
    let response = result.unwrap().0;
    
    // Validate response structure
    assert!(!response.wallet_id.is_empty(), "Wallet ID should be generated");
    assert!(!response.mnemonic.is_empty(), "Mnemonic should be generated");
    assert!(!response.share_a.is_empty(), "Share A should be provided");
    assert!(!response.share_c.is_empty(), "Share C should be provided");
    assert!(!response.public_key.is_empty(), "Public key should be derived");
    assert_eq!(response.wallet_id, response.public_key, "Wallet ID should match public key");
    
    // Verify mnemonic is valid BIP-39 (24 words)
    let word_count = response.mnemonic.split_whitespace().count();
    assert_eq!(word_count, 24, "Mnemonic should have 24 words");
    
    println!("✅ Test 01: Wallet creation successful");
    println!("   Wallet ID: {}", response.wallet_id);
    println!("   Mnemonic words: {}", word_count);
}

// ============================================================================
// TEST 02: ReDB Persistence (Share B Storage)
// ============================================================================

#[tokio::test]
async fn test_02_share_b_persistence() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create wallet
    let result = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await;
    
    let response = result.unwrap().0;
    let wallet_id = response.wallet_id.clone();

    // Verify Share B is stored in ReDB
    let share_b = blockchain.get_frost_share_b(&wallet_id);
    assert!(share_b.is_ok(), "Share B should be retrievable from ReDB");
    assert!(!share_b.unwrap().is_empty(), "Share B should contain data");

    // Verify PublicKeyPackage is stored
    let pk_pkg = blockchain.get_frost_pub_key_package(&wallet_id);
    assert!(pk_pkg.is_ok(), "PublicKeyPackage should be stored in ReDB");
    
    // Verify Public Key is stored
    let pub_key = blockchain.get_frost_pub_key(&wallet_id);
    assert!(pub_key.is_ok(), "Public key should be stored in ReDB");
    
    println!("✅ Test 02: ReDB persistence verified");
    println!("   Share B size: {} bytes", blockchain.get_frost_share_b(&wallet_id).unwrap().len());
}

// ============================================================================
// TEST 03: Signature Generation (FROST 2-of-3)
// ============================================================================

#[tokio::test]
async fn test_03_frost_signature_generation() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create wallet
    let create_result = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;
    
    let wallet_id = create_result.wallet_id;
    let share_a = create_result.share_a;

    // Sign a message
    let sign_request = layer1::wallet_unified::handlers::SignRequest {
        wallet_id: wallet_id.clone(),
        message: "test_transaction_data".to_string(),
        share_a: share_a.clone(),
    };

    let sign_result = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        axum::extract::Json(sign_request)
    ).await;

    assert!(sign_result.is_ok(), "Signature generation should succeed");
    
    let signature_json = sign_result.unwrap().0;
    assert!(signature_json.get("signature").is_some(), "Signature should be present");
    assert!(signature_json.get("status").is_some(), "Status should be present");
    
    let sig_hex = signature_json["signature"].as_str().unwrap();
    assert!(!sig_hex.is_empty(), "Signature should not be empty");
    assert_eq!(sig_hex.len(), 128, "Ed25519 signature should be 64 bytes (128 hex chars)");
    
    println!("✅ Test 03: FROST signature generated successfully");
    println!("   Signature: {}...", &sig_hex[..16]);
}

// ============================================================================
// TEST 04: Multiple Wallets (Isolation)
// ============================================================================

#[tokio::test]
async fn test_04_multiple_wallets_isolation() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create wallet 1
    let wallet1 = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;
    
    // Create wallet 2
    let wallet2 = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;

    // Verify wallets are different
    assert_ne!(wallet1.wallet_id, wallet2.wallet_id, "Wallet IDs should be unique");
    assert_ne!(wallet1.mnemonic, wallet2.mnemonic, "Mnemonics should be unique");
    assert_ne!(wallet1.share_a, wallet2.share_a, "Share A should be unique");
    
    // Verify both Share Bs are stored separately
    let share_b1 = blockchain.get_frost_share_b(&wallet1.wallet_id);
    let share_b2 = blockchain.get_frost_share_b(&wallet2.wallet_id);
    
    assert!(share_b1.is_ok(), "Wallet 1 Share B should exist");
    assert!(share_b2.is_ok(), "Wallet 2 Share B should exist");
    assert_ne!(share_b1.unwrap(), share_b2.unwrap(), "Share Bs should be different");
    
    println!("✅ Test 04: Multiple wallets isolated correctly");
    println!("   Wallet 1 ID: {}", wallet1.wallet_id);
    println!("   Wallet 2 ID: {}", wallet2.wallet_id);
}

// ============================================================================
// TEST 05: Invalid Share A (Error Handling)
// ============================================================================

#[tokio::test]
async fn test_05_invalid_share_a_rejection() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create wallet
    let wallet = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;

    // Attempt to sign with invalid Share A
    let sign_request = layer1::wallet_unified::handlers::SignRequest {
        wallet_id: wallet.wallet_id.clone(),
        message: "test".to_string(),
        share_a: "invalid_hex_data".to_string(),
    };

    let sign_result = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        axum::extract::Json(sign_request)
    ).await;

    assert!(sign_result.is_err(), "Invalid Share A should be rejected");
    
    println!("✅ Test 05: Invalid Share A correctly rejected");
}

// ============================================================================
// TEST 06: Non-existent Wallet (Error Handling)
// ============================================================================

#[tokio::test]
async fn test_06_nonexistent_wallet_rejection() {
    // Setup
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Attempt to sign with non-existent wallet
    let sign_request = layer1::wallet_unified::handlers::SignRequest {
        wallet_id: "nonexistent_wallet_id_12345".to_string(),
        message: "test".to_string(),
        share_a: "aabbccdd".to_string(),
    };

    let sign_result = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        axum::extract::Json(sign_request)
    ).await;

    assert!(sign_result.is_err(), "Non-existent wallet should be rejected");
    
    let error_response = sign_result.unwrap_err();
    assert_eq!(error_response.0, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    
    println!("✅ Test 06: Non-existent wallet correctly rejected");
}

// ============================================================================
// TEST 07: ReDB Durability (Restart Simulation)
// ============================================================================

#[tokio::test]
async fn test_07_redb_durability_after_restart() {
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().to_str().unwrap();
    
    let wallet_id: String;
    
    // Phase 1: Create wallet
    {
        let blockchain = Arc::new(ConcurrentBlockchain::new(path).unwrap());
        let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));
        
        let wallet = layer1::wallet_unified::handlers::create_hybrid_wallet(
            axum::extract::State(state.clone())
        ).await.unwrap().0;
        
        wallet_id = wallet.wallet_id.clone();
    } // Drop blockchain to simulate shutdown
    
    // Phase 2: Reopen database and verify data persists
    {
        let blockchain = Arc::new(ConcurrentBlockchain::new(path).unwrap());
        
        let share_b = blockchain.get_frost_share_b(&wallet_id);
        assert!(share_b.is_ok(), "Share B should persist after restart");
        
        let pub_key = blockchain.get_frost_pub_key(&wallet_id);
        assert!(pub_key.is_ok(), "Public key should persist after restart");
        
        println!("✅ Test 07: ReDB durability verified (data persists after restart)");
        println!("   Wallet ID: {}", wallet_id);
    }
}

// ============================================================================
// TEST 08: Concurrent Wallet Creation (Thread Safety)
// ============================================================================

#[tokio::test]
async fn test_08_concurrent_wallet_creation() {
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Create 10 wallets concurrently
    let mut handles = vec![];
    
    for _ in 0..10 {
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            layer1::wallet_unified::handlers::create_hybrid_wallet(
                axum::extract::State(state_clone)
            ).await
        });
        handles.push(handle);
    }

    // Wait for all to complete
    let mut wallet_ids = std::collections::HashSet::new();
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent wallet creation should succeed");
        let wallet = result.unwrap().0;
        wallet_ids.insert(wallet.wallet_id);
    }

    // Verify all wallet IDs are unique
    assert_eq!(wallet_ids.len(), 10, "All 10 wallets should have unique IDs");
    
    println!("✅ Test 08: Concurrent wallet creation successful");
    println!("   Created 10 unique wallets concurrently");
}

// ============================================================================
// TEST 09: Share Size Validation
// ============================================================================

#[tokio::test]
async fn test_09_share_size_validation() {
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    let wallet = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;

    // Verify Share A is hex-encoded and reasonable size
    let share_a_bytes = hex::decode(&wallet.share_a);
    assert!(share_a_bytes.is_ok(), "Share A should be valid hex");
    
    let share_a_len = share_a_bytes.unwrap().len();
    assert!(share_a_len > 32, "Share A should be substantial (> 32 bytes)");
    assert!(share_a_len < 1024, "Share A should be reasonable size (< 1KB)");
    
    // Verify Share C
    let share_c_bytes = hex::decode(&wallet.share_c);
    assert!(share_c_bytes.is_ok(), "Share C should be valid hex");
    
    println!("✅ Test 09: Share size validation passed");
    println!("   Share A size: {} bytes", share_a_len);
}

// ============================================================================
// TEST 10: Integration Test (Full Workflow)
// ============================================================================

#[tokio::test]
async fn test_10_full_wallet_workflow() {
    let temp_dir = tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let state = Arc::new(UnifiedWalletState::new(blockchain.clone()));

    // Step 1: Create wallet
    let wallet = layer1::wallet_unified::handlers::create_hybrid_wallet(
        axum::extract::State(state.clone())
    ).await.unwrap().0;
    
    println!("Created wallet: {}", wallet.wallet_id);

    // Step 2: Verify storage
    assert!(blockchain.get_frost_share_b(&wallet.wallet_id).is_ok());
    println!("Share B verified in ReDB");

    // Step 3: Sign message
    let sign_request = layer1::wallet_unified::handlers::SignRequest {
        wallet_id: wallet.wallet_id.clone(),
        message: "transfer:alice:bob:100".to_string(),
        share_a: wallet.share_a.clone(),
    };

    let signature = layer1::wallet_unified::handlers::sign_hybrid_tx(
        axum::extract::State(state.clone()),
        axum::extract::Json(sign_request)
    ).await.unwrap().0;
    
    println!("Signature generated: {}", signature["signature"].as_str().unwrap());

    // Step 4: Verify signature format
    let sig_hex = signature["signature"].as_str().unwrap();
    assert_eq!(sig_hex.len(), 128, "Ed25519 signature should be 128 hex chars");
    
    println!("✅ Test 10: Full wallet workflow completed successfully");
}
