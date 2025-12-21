//! Authentication Tests for Layer1
//! 
//! Tests for the unified ZK-based authentication system:
//! - JWT creation with create_jwt_for_user
//! - JWT verification with verify_jwt
//! - AuthClaims structure validation

use layer1::{AuthClaims, verify_jwt, create_jwt_for_user};

// ============================================================================
// JWT CREATION TESTS
// ============================================================================

#[test]
fn test_create_jwt_for_user() {
    let result = create_jwt_for_user(
        "testuser",
        "supabase_user_123",
        Some("0x1234567890abcdef".to_string()),
        "zk_verified",
        vec!["read".to_string(), "write".to_string()],
    );
    
    assert!(result.is_ok(), "JWT creation should succeed");
    
    let (token, session_id) = result.unwrap();
    assert!(!token.is_empty(), "Token should not be empty");
    assert!(!session_id.is_empty(), "Session ID should not be empty");
}

#[test]
fn test_jwt_without_wallet() {
    let result = create_jwt_for_user(
        "guest_user",
        "supabase_guest",
        None,  // No wallet
        "temp_wallet_creation",
        vec!["read".to_string()],
    );
    
    assert!(result.is_ok(), "JWT should be created without wallet");
    
    let (token, _) = result.unwrap();
    let claims = verify_jwt(&token).unwrap();
    
    assert!(claims.wallet_address.is_none(), "Wallet should be None");
}

// ============================================================================
// JWT VERIFICATION TESTS
// ============================================================================

#[test]
fn test_verify_valid_jwt() {
    let (token, _session_id) = create_jwt_for_user(
        "verify_user",
        "supabase_verify",
        Some("0xverify".to_string()),
        "zk_verified",
        vec!["read".to_string(), "sign".to_string()],
    ).unwrap();
    
    let verify_result = verify_jwt(&token);
    
    assert!(verify_result.is_ok(), "Valid JWT should verify successfully");
    
    let claims = verify_result.unwrap();
    assert_eq!(claims.sub, "verify_user");
    assert_eq!(claims.auth_level, "zk_verified");
    assert!(claims.permissions.contains(&"read".to_string()));
    assert!(claims.permissions.contains(&"sign".to_string()));
    assert_eq!(claims.wallet_address, Some("0xverify".to_string()));
}

#[test]
fn test_verify_invalid_jwt() {
    // Try to verify a completely invalid token
    let result = verify_jwt("invalid.token.here");
    
    assert!(result.is_err(), "Invalid JWT should fail verification");
}

// ============================================================================
// CLAIMS CONTENT TESTS
// ============================================================================

#[test]
fn test_jwt_claims_content() {
    let (token, session_id) = create_jwt_for_user(
        "claims_test_user",
        "supabase_claims_id",
        Some("0xABCDEF123456".to_string()),
        "admin",
        vec!["read".to_string(), "write".to_string(), "delete".to_string(), "sign".to_string()],
    ).unwrap();
    
    let claims = verify_jwt(&token).unwrap();
    
    // Verify all claims are properly set
    assert_eq!(claims.sub, "claims_test_user");
    assert_eq!(claims.session_id, session_id);
    assert_eq!(claims.wallet_address, Some("0xABCDEF123456".to_string()));
    assert_eq!(claims.auth_level, "admin");
    assert_eq!(claims.permissions.len(), 4);
    assert_eq!(claims.supabase_user_id, "supabase_claims_id");
    
    // Verify JTI (JWT ID) exists and is a UUID
    assert!(!claims.jti.is_empty(), "JTI should not be empty");
    assert!(claims.jti.contains('-'), "JTI should be a UUID format");
    
    // Verify timestamps
    assert!(claims.exp > claims.iat, "Expiration should be after issued at");
}

#[test]
fn test_claims_has_permission() {
    let (token, _) = create_jwt_for_user(
        "perm_user",
        "supabase_perm",
        None,
        "zk_verified",
        vec!["read".to_string(), "transfer".to_string()],
    ).unwrap();
    
    let claims = verify_jwt(&token).unwrap();
    
    assert!(claims.has_permission("read"), "Should have read permission");
    assert!(claims.has_permission("transfer"), "Should have transfer permission");
    assert!(!claims.has_permission("admin"), "Should not have admin permission");
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_empty_permissions() {
    let result = create_jwt_for_user(
        "minimal_user",
        "supabase_min",
        None,
        "guest",
        vec![], // Empty permissions
    );
    
    assert!(result.is_ok());
    
    let (token, _) = result.unwrap();
    let claims = verify_jwt(&token).unwrap();
    
    assert!(claims.permissions.is_empty());
    assert!(claims.wallet_address.is_none());
}

#[test]
fn test_special_characters_in_username() {
    let result = create_jwt_for_user(
        "user+special@domain.com",
        "supabase_special",
        None,
        "standard",
        vec![],
    );
    
    assert!(result.is_ok(), "Should handle special characters in username");
    
    let (token, _) = result.unwrap();
    let claims = verify_jwt(&token).unwrap();
    assert_eq!(claims.sub, "user+special@domain.com");
}

#[test]
fn test_long_wallet_address() {
    let long_wallet = "0x".to_string() + &"a".repeat(128);
    
    let result = create_jwt_for_user(
        "long_wallet_user",
        "supabase_long",
        Some(long_wallet.clone()),
        "zk_verified",
        vec!["transfer".to_string()],
    );
    
    assert!(result.is_ok(), "Should handle long wallet addresses");
    
    let (token, _) = result.unwrap();
    let claims = verify_jwt(&token).unwrap();
    assert_eq!(claims.wallet_address, Some(long_wallet));
}

#[test]
fn test_many_permissions() {
    let permissions: Vec<String> = (0..50)
        .map(|i| format!("permission_{}", i))
        .collect();
    
    let result = create_jwt_for_user(
        "many_perms_user",
        "supabase_many",
        None,
        "admin",
        permissions.clone(),
    );
    
    assert!(result.is_ok(), "Should handle many permissions");
    
    let (token, _) = result.unwrap();
    let claims = verify_jwt(&token).unwrap();
    assert_eq!(claims.permissions.len(), 50);
}
