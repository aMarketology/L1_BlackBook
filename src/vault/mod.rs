//! BlackBook L1 - HashiCorp Vault Client Module
//!
//! Secure on-demand pepper retrieval using AppRole authentication.
//! The pepper is NEVER stored in environment variables or the filesystem.
//!
//! ## Architecture
//! 1. Server starts → Authenticates to Vault with AppRole credentials
//! 2. Vault issues short-lived token (1-4 hours TTL)
//! 3. Server fetches pepper on-demand when needed for Share C encryption
//! 4. Token automatically refreshes before expiry
//! 5. Pepper is cached in memory for performance (never written to disk)
//!
//! ## Security Benefits
//! - No pepper in .env files or config files
//! - Vault audit logs all pepper access attempts
//! - Token-based auth with automatic expiry
//! - Network-isolated secret storage
//! - Encrypted at rest and in transit (TLS)

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault client error: {0}")]
    ClientError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Pepper not found in Vault")]
    PepperNotFound,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[derive(Debug, Clone, Deserialize)]
struct AppRoleAuthResponse {
    auth: AppRoleAuth,
}

#[derive(Debug, Clone, Deserialize)]
struct AppRoleAuth {
    client_token: String,
    lease_duration: u64,
}

#[derive(Debug, Deserialize)]
struct SecretDataWrapper {
    data: SecretData,
}

#[derive(Debug, Deserialize)]
struct SecretData {
    data: PepperSecret,
}

#[derive(Debug, Deserialize)]
struct PepperSecret {
    value: String,
}

/// Vault configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub addr: String,
    pub role_id: String,
    pub secret_id: String,
    pub pepper_cache_ttl: Duration,
}

impl VaultConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, VaultError> {
        let addr = std::env::var("VAULT_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
        
        let role_id = std::env::var("VAULT_ROLE_ID")
            .map_err(|_| VaultError::ConfigError("VAULT_ROLE_ID not set".to_string()))?;
        
        let secret_id = std::env::var("VAULT_SECRET_ID")
            .map_err(|_| VaultError::ConfigError("VAULT_SECRET_ID not set".to_string()))?;
        
        Ok(Self {
            addr,
            role_id,
            secret_id,
            pepper_cache_ttl: Duration::from_secs(5 * 60), // 5 minutes
        })
    }
}

/// Cached pepper with expiry
struct PepperCache {
    value: String,
    cached_at: Instant,
}

/// Vault client for secure pepper retrieval
pub struct VaultClient {
    config: VaultConfig,
    http_client: reqwest::Client,
    token: Arc<RwLock<Option<String>>>,
    token_expiry: Arc<RwLock<Option<Instant>>>,
    pepper_cache: Arc<RwLock<Option<PepperCache>>>,
}

impl VaultClient {
    /// Create a new Vault client
    pub fn new(config: VaultConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            config,
            http_client,
            token: Arc::new(RwLock::new(None)),
            token_expiry: Arc::new(RwLock::new(None)),
            pepper_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the client and authenticate
    pub async fn initialize(&self) -> Result<(), VaultError> {
        if self.is_token_valid().await {
            return Ok(()); // Already initialized
        }

        tracing::info!("🔐 Initializing Vault client...");
        self.authenticate().await?;
        tracing::info!("✅ Vault authentication successful");
        
        Ok(())
    }

    /// Authenticate to Vault using AppRole
    async fn authenticate(&self) -> Result<(), VaultError> {
        let url = format!("{}/v1/auth/approle/login", self.config.addr);
        
        let body = serde_json::json!({
            "role_id": self.config.role_id,
            "secret_id": self.config.secret_id,
        });

        let response = self.http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::AuthError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultError::AuthError(error_text));
        }

        let auth_response: AppRoleAuthResponse = response
            .json()
            .await
            .map_err(|e| VaultError::AuthError(format!("Failed to parse response: {}", e)))?;

        let token = auth_response.auth.client_token;
        let lease_duration = auth_response.auth.lease_duration;
        
        // Store token and calculate expiry
        *self.token.write().await = Some(token);
        *self.token_expiry.write().await = Some(Instant::now() + Duration::from_secs(lease_duration));
        
        tracing::info!("🎫 Vault token acquired (expires in {}s)", lease_duration);
        
        Ok(())
    }

    /// Check if current token is still valid
    async fn is_token_valid(&self) -> bool {
        let token = self.token.read().await;
        let expiry = self.token_expiry.read().await;
        
        if token.is_none() || expiry.is_none() {
            return false;
        }
        
        // Consider token invalid 5 minutes before actual expiry (safety margin)
        let safety_margin = Duration::from_secs(5 * 60);
        let now = Instant::now();
        let expiry_time = expiry.unwrap();
        
        now < expiry_time.checked_sub(safety_margin).unwrap_or(expiry_time)
    }

    /// Ensure we have a valid token
    async fn ensure_valid_token(&self) -> Result<(), VaultError> {
        if !self.is_token_valid().await {
            tracing::info!("🔄 Token expired, re-authenticating...");
            self.authenticate().await?;
        }
        Ok(())
    }

    /// Get pepper from Vault (with caching)
    pub async fn get_pepper(&self) -> Result<String, VaultError> {
        // Check cache first
        {
            let cache = self.pepper_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                let age = cached.cached_at.elapsed();
                if age < self.config.pepper_cache_ttl {
                    return Ok(cached.value.clone());
                }
            }
        }

        // Ensure client is initialized and token is valid
        self.initialize().await?;
        self.ensure_valid_token().await?;

        // Get current token
        let token = self.token.read().await;
        let token_str = token.as_ref()
            .ok_or_else(|| VaultError::ClientError("No token available".to_string()))?;

        // Read pepper from Vault
        let url = format!("{}/v1/blackbook/data/pepper", self.config.addr);
        
        let response = self.http_client
            .get(&url)
            .header("X-Vault-Token", token_str)
            .send()
            .await
            .map_err(|e| VaultError::ClientError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultError::ClientError(error_text));
        }

        let secret: SecretDataWrapper = response
            .json()
            .await
            .map_err(|e| VaultError::ClientError(format!("Failed to parse secret: {}", e)))?;

        let pepper = secret.data.data.value;
        
        // Update cache
        *self.pepper_cache.write().await = Some(PepperCache {
            value: pepper.clone(),
            cached_at: Instant::now(),
        });
        
        Ok(pepper)
    }

    /// Clear the in-memory pepper cache
    pub async fn clear_cache(&self) {
        *self.pepper_cache.write().await = None;
    }

    /// Get health status
    pub async fn health_check(&self) -> Result<bool, VaultError> {
        let url = format!("{}/v1/sys/health", self.config.addr);
        
        let response = self.http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| VaultError::ClientError(e.to_string()))?;

        Ok(response.status().is_success())
    }

    /// Revoke current token (logout)
    pub async fn revoke(&self) -> Result<(), VaultError> {
        let token = self.token.read().await;
        
        if let Some(token_str) = token.as_ref() {
            let url = format!("{}/v1/auth/token/revoke-self", self.config.addr);
            
            let _ = self.http_client
                .post(&url)
                .header("X-Vault-Token", token_str)
                .send()
                .await;
            
            tracing::info!("🔒 Vault token revoked");
        }
        
        self.clear_cache().await;
        *self.token.write().await = None;
        *self.token_expiry.write().await = None;
        
        Ok(())
    }
}

// Global singleton instance
static VAULT_CLIENT: once_cell::sync::OnceCell<Arc<VaultClient>> = once_cell::sync::OnceCell::new();

/// Get or initialize the global Vault client
pub fn get_vault_client() -> Result<Arc<VaultClient>, VaultError> {
    VAULT_CLIENT
        .get_or_try_init(|| {
            let config = VaultConfig::from_env()?;
            Ok(Arc::new(VaultClient::new(config)))
        })
        .map(|client| Arc::clone(client))
}

/// Helper function to get pepper (convenience method)
pub async fn get_pepper() -> Result<String, VaultError> {
    let client = get_vault_client()?;
    client.get_pepper().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Vault server running
    async fn test_vault_authentication() {
        let config = VaultConfig::from_env().expect("Vault config not set");
        let client = VaultClient::new(config);
        
        client.initialize().await.expect("Failed to initialize");
        assert!(client.is_token_valid().await);
    }

    #[tokio::test]
    #[ignore] // Requires Vault server running
    async fn test_get_pepper() {
        let config = VaultConfig::from_env().expect("Vault config not set");
        let client = VaultClient::new(config);
        
        let pepper = client.get_pepper().await.expect("Failed to get pepper");
        assert!(!pepper.is_empty());
    }
}
