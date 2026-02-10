// ============================================================================
// TEST HELPERS — Shared utilities for integration tests
// ============================================================================

use std::sync::Arc;
use axum::http::HeaderMap;
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use layer1::{
    storage::ConcurrentBlockchain,
    wallet_unified::handlers::UnifiedWalletState,
    supabase::SupabaseManager,
    vault_manager::VaultManager,
};

/// Create a mock Supabase manager for testing (bypasses actual API calls)
pub fn create_mock_supabase() -> Arc<SupabaseManager> {
    // Set mock environment variables if not already set
    std::env::set_var("SERVER_MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    std::env::set_var("SUPABASE_JWKS_URL", "https://mock.supabase.co/.well-known/jwks.json");
    std::env::set_var("SUPABASE_URL", "https://mock.supabase.co");
    std::env::set_var("SUPABASE_SERVICE_ROLE_KEY", "mock_service_role_key");
    std::env::set_var("SUPABASE_PROJECT_ID", "mock_project_id");
    std::env::set_var("SUPABASE_JWT_SECRET", "super-secret-jwt-token-with-at-least-32-bytes-long");
    
    Arc::new(SupabaseManager::new())
}

/// Create a test state with mock blockchain and supabase
pub fn create_test_state() -> Arc<UnifiedWalletState> {
    // Requires a temp path
    let temp_dir = tempfile::tempdir().unwrap();
    let blockchain = Arc::new(ConcurrentBlockchain::new(temp_dir.path().to_str().unwrap()).unwrap());
    let supabase = create_mock_supabase();
    let vault = Arc::new(VaultManager::new_mock());
    Arc::new(UnifiedWalletState::new(blockchain, supabase, vault))
}

/// Create empty headers (for unauthenticated tests)
pub fn create_empty_headers() -> HeaderMap {
    HeaderMap::new()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

/// Create mock JWT headers (for authenticated tests)
pub fn create_mock_jwt_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    
    let claims = Claims {
        sub: "test-user-id-123".to_string(),
        exp: 20000000000, // far future
    };
    
    let secret = "super-secret-jwt-token-with-at-least-32-bytes-long";
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap();

    headers.insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    headers
}
