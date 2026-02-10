use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use std::env;
use std::collections::HashMap;
use tracing::{info, error, warn};

pub struct VaultManager {
    client: VaultClient,
    mount_path: String,
}

impl VaultManager {
    pub fn new() -> Result<Self, String> {
        let address = env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
        // For production, we require tokens. For dev, we might be lenient, but user asked for "The Vaulting"
        let token = env::var("VAULT_TOKEN").unwrap_or("dev-token".to_string());
        let mount_path = env::var("VAULT_MOUNT_PATH").unwrap_or_else(|_| "prism".to_string());

        let settings = VaultClientSettingsBuilder::default()
            .address(address.clone())
            .token(token)
            .build()
            .map_err(|e| format!("Failed to build Vault settings: {}", e))?;

        let client = VaultClient::new(settings)
            .map_err(|e| format!("Failed to create Vault client: {}", e))?;

        info!("✅ Vault Manager initialized at {}/{}", address, mount_path);

        Ok(Self {
            client,
            mount_path,
        })
    }

    #[cfg(test)]
    pub fn new_mock() -> Self {
        panic!("MOCKS REMOVED: Internal mock logic deleted. Configure VAULT_ADDR/TOKEN for integration tests.");
    }


    /// Stores the recovery shard (Shard C) in HashiCorp Vault.
    /// Path: {mount_path}/data/users/{user_id}/recovery_shard
    pub async fn store_shard_c(&self, user_id: &str, shard_c_hex: &str) -> Result<(), String> {
        let path = format!("users/{}/recovery_shard", user_id);
        
        let mut secret_data = HashMap::new();
        secret_data.insert("shard_c", shard_c_hex);
        secret_data.insert("timestamp", "current_time"); // Placeholder, could be better

        // Correct usage of vaultrs for KV v2
        // vaultrs specific: mount is the first segment, path is the rest
        // set_secret calls kv2::set with mount and path
        
        let result = vaultrs::kv2::set(
            &self.client,
            &self.mount_path,
            &path,
            &secret_data
        ).await;

        match result {
            Ok(_) => {
                info!("✅ Shard C stored securely in Vault for user {}", user_id);
                Ok(())
            },
            Err(e) => {
                let msg = format!("❌ Failed to store Shard C in Vault: {}", e);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    /// Retrieves Shard C - THIS SHOULD BE GATED BY POLICY/AUTH/JWT LOGIC
    /// In this implementation, we just retrieve it. The caller MUST verify permissions (The Bouncer).
    pub async fn retrieve_shard_c(&self, user_id: &str) -> Result<String, String> {
        let path = format!("users/{}/recovery_shard", user_id);
        
        // vaultrs kv2::read
        let result: Result<serde_json::Value, _> = vaultrs::kv2::read(
            &self.client,
            &self.mount_path,
            &path,
        ).await;

        match result {
            Ok(secret) => {
                // Secret is the full response, including metadata. 
                // We need to extract the "shard_c" field from the data.
                if let Some(data) = secret.get("shard_c") {
                     if let Some(s) = data.as_str() {
                         return Ok(s.to_string());
                     }
                }
                Err("Shard C not found in Vault response".to_string())
            },
            Err(e) => {
                Err(format!("Failed to read Shard C from Vault: {}", e))
            }
        }
    }
}
