use supabase_jwt::{Claims, JwksCache};
use reqwest::Client;
use serde_json::Value;

#[derive(Clone)]
pub struct SupabaseManager {
    jwks_cache: JwksCache,
    project_id: String,
    client: Client,
    supabase_url: String,
    service_role_key: String,
}

impl SupabaseManager {
    pub fn new() -> Self {
        let jwks_url = std::env::var("SUPABASE_JWKS_URL").expect("Missing SUPABASE_JWKS_URL");
        let supabase_url = std::env::var("SUPABASE_URL").expect("Missing SUPABASE_URL");
        let service_role_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY").expect("Missing SUPABASE_SERVICE_ROLE_KEY");

        Self {
            jwks_cache: JwksCache::new(&jwks_url),
            project_id: std::env::var("SUPABASE_PROJECT_ID").expect("Missing SUPABASE_PROJECT_ID"),
            client: Client::new(),
            supabase_url,
            service_role_key,
        }
    }

    /// JOB 1: Verify the user is who they say they are
    pub async fn verify_user(&self, auth_header: &str) -> Result<String, String> {
        // Strip "Bearer " prefix if present
        let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header).trim();

        let claims = Claims::from_bearer_token(token, &self.jwks_cache)
            .await
            .map_err(|e| format!("JWT Auth Failed: {:?}", e))?;
        
        // Ensure the token was issued by your project
        let iss = claims.iss.as_deref().unwrap_or("");
        if !iss.contains(&self.project_id) {
             return Err(format!("Token issuer mismatch. Expected contains: {}, Got: {:?}", self.project_id, claims.iss));
        }

        Ok(claims.sub)
    }

    /// JOB 2: Retrieve encrypted Shard A from Supabase (User Vault)
    pub async fn fetch_encrypted_shard_a(&self, user_id: &str) -> Result<String, String> {
        let url = format!("{}/rest/v1/user_vault", self.supabase_url);
        
        let response = self.client.get(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .query(&[("id", format!("eq.{}", user_id)), ("select", "encrypted_shard_a_blob".to_string())])
            .send()
            .await
            .map_err(|e| format!("Supabase Request Failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Supabase Error (Fetch): {} - {}", status, body));
        }

        let rows: Vec<Value> = response.json()
            .await
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        if rows.is_empty() {
            return Err("User vault not found".to_string());
        }

        let shard_val = rows[0].get("encrypted_shard_a_blob")
            .ok_or("Field encrypted_shard_a_blob missing")?;
            
        shard_val.as_str()
            .map(|s| s.to_string())
            .ok_or("encrypted_shard_a_blob is not a string".to_string())
    }

    /// JOB 3: Store encrypted Shard A in Supabase (User Vault)
    pub async fn store_encrypted_shard_a(&self, user_id: &str, username: &str, wallet_address: &str, root_pubkey: &str, encrypted_shard_a: &str) -> Result<(), String> {
        let url = format!("{}/rest/v1/user_vault", self.supabase_url);
        
        // Extract Salt from "salt:nonce:ciphertext" format
        let parts: Vec<&str> = encrypted_shard_a.split(':').collect();
        let client_salt = if parts.len() >= 3 {
             parts[0]
        } else {
             "UNKNOWN_SALT"
        };
        
        // We only store Shard A now. Shard B is gone from here.
        let payload = serde_json::json!({
            "id": user_id,
            "username": username,
            "wallet_address": wallet_address,
            "root_pubkey": root_pubkey,
            "encrypted_shard_a_blob": encrypted_shard_a,
            "client_salt": client_salt,
            "updated_at": "now()"
        });

        let response = self.client.post(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .header("Prefer", "resolution=merge-duplicates") // UPSERT
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Supabase Connection Error (Shard A): {}", e))?;

        if !response.status().is_success() {
             let status = response.status();
             let body = response.text().await.unwrap_or_default();
             return Err(format!("Supabase Insert Failed (Shard A): {} - {}", status, body));
        }

        Ok(())
    }
}
