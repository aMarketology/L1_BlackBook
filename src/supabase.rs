use supabase_jwt::{Claims, JwksCache};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use hex;
use reqwest::Client;
use serde_json::Value;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};

#[derive(Clone)]
pub struct SupabaseManager {
    jwks_cache: JwksCache,
    master_key: Vec<u8>,
    project_id: String,
    client: Client,
    supabase_url: String,
    service_role_key: String,
}

impl SupabaseManager {
    pub fn new() -> Self {
        let master_key_hex = std::env::var("SERVER_MASTER_KEY").expect("Missing SERVER_MASTER_KEY");
        let jwks_url = std::env::var("SUPABASE_JWKS_URL").expect("Missing SUPABASE_JWKS_URL");
        let supabase_url = std::env::var("SUPABASE_URL").expect("Missing SUPABASE_URL");
        let service_role_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY").expect("Missing SUPABASE_SERVICE_ROLE_KEY");

        Self {
            jwks_cache: JwksCache::new(&jwks_url),
            master_key: hex::decode(master_key_hex).expect("Invalid Hex in Master Key"),
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

    /// JOB 2: Retrieve encrypted Shard B from Supabase
    pub async fn fetch_encrypted_shard_b(&self, user_id: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}/rest/v1/user_vault", self.supabase_url);
        
        // Query param: id=eq.{user_id}&select=encrypted_shard_b_blob
        let response = self.client.get(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .query(&[("id", format!("eq.{}", user_id)), ("select", "encrypted_shard_b_blob".to_string())])
            .send()
            .await
            .map_err(|e| format!("Supabase Request Failed: {}", e))?;

        if !response.status().is_success() {
            // Log body for debugging
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

        let shard_val = rows[0].get("encrypted_shard_b_blob")
            .ok_or("Field encrypted_shard_b_blob missing")?;
            
        let shard_str = shard_val.as_str()
            .ok_or("encrypted_shard_b_blob is not a string")?;
            
        // Handle postgres hex output prefix if present
        let clean_hex = shard_str.strip_prefix("\\x").unwrap_or(shard_str);
        
        hex::decode(clean_hex).map_err(|e| format!("Failed to decode hex shard: {}", e))
    }

    /// JOB 2b: Store encrypted Shard B in Supabase (Create Wallet)
    pub async fn store_encrypted_shard_b(
        &self, 
        user_id: &str, 
        username: &str, 
        wallet_address: &str, 
        root_pubkey: &str,
        daily_limit: f64, // Numeric in DB
        pin_hash: &str,
        encrypted_blob: &[u8]
    ) -> Result<(), String> {
        let url = format!("{}/rest/v1/user_vault", self.supabase_url);
        
        // Upsert logic (insert or update on conflict)
        let payload = serde_json::json!({
            "id": user_id,
            "username": username,
            "wallet_address": wallet_address,
            "root_pubkey": root_pubkey,
            "daily_spending_limit": daily_limit,
            "pin_hash": pin_hash, // Redundant but useful for queries
            "encrypted_shard_b_blob": hex::encode(encrypted_blob), 
            "client_salt": "TEMP_SALT_PLACEHOLDER", 
            "updated_at": "now()"
        });

        let response = self.client.post(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .header("Prefer", "resolution=merge-duplicates") // UPSERT
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Supabase Connection Error: {}", e))?;

        if !response.status().is_success() {
             let status = response.status();
             let body = response.text().await.unwrap_or_default();
             return Err(format!("Supabase Insert Failed: {} - {}", status, body));
        }

        Ok(())
    }

    /// JOB 2c: Store encrypted Shard A in Supabase (User Vault)
    pub async fn store_encrypted_shard_a(&self, user_id: &str, username: &str, wallet_address: &str, root_pubkey: &str, encrypted_shard_a: &str) -> Result<(), String> {
        let url = format!("{}/rest/v1/user_vault", self.supabase_url);
        
        // Extract Salt from "salt:nonce:ciphertext" format
        let parts: Vec<&str> = encrypted_shard_a.split(':').collect();
        let client_salt = if parts.len() >= 3 {
             parts[0]
        } else {
             "UNKNOWN_SALT"
        };
        
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

    /// JOB 2d: Store Recovery Shard C via RPC
    pub async fn store_recovery_shard_c(&self, user_id: &str, wallet_id: &str, shard_c: &str) -> Result<(), String> {
        let url = format!("{}/rest/v1/rpc/store_secret", self.supabase_url);

        let payload = serde_json::json!({
            "name": format!("{}_shard_c", wallet_id),
            "secret": shard_c,
            "user_id": user_id
        });

        let response = self.client.post(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Supabase Connection Error (Shard C): {}", e))?;

        if !response.status().is_success() {
             let status = response.status();
             let body = response.text().await.unwrap_or_default();
             return Err(format!("Supabase RPC Failed (store_secret): {} - {}", status, body));
        }

        Ok(())
    }

    /// JOB 3: Un-pepper Shard B
    pub fn decrypt_shard_b(&self, encrypted_blob: &[u8]) -> Result<Vec<u8>, String> {
        let key = Key::<Aes256Gcm>::from_slice(&self.master_key);
        let cipher = Aes256Gcm::new(key);

        // We assume the first 12 bytes of the blob are the Nonce (standard AES-GCM)
        if encrypted_blob.len() < 12 { return Err("Invalid encrypted data".into()); }
        let (nonce_bytes, ciphertext) = encrypted_blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: possible incorrect Master Key. Error: {:?}", e))
    }

    /// JOB 4: Verify PIN (The Bouncer)
    /// Verifies if the provided raw PIN matches the hash stored in Supabase (or retrieved from it).
    pub fn verify_pin(&self, raw_pin: &str, stored_hash: &str) -> Result<(), String> {
        // 1. Parse the stored hash string into a 'PasswordHash' object
        let parsed_hash = PasswordHash::new(stored_hash)
            .map_err(|_| "Invalid PIN hash format in database".to_string())?;

        // 2. Perform the verification
        // Argon2 handles the salt extraction and re-hashing automatically
        match Argon2::default().verify_password(raw_pin.as_bytes(), &parsed_hash) {
            Ok(_) => {
                // println!("✅ PIN Verified Successfully."); // Kept silent for prod logs unless tracing is used
                Ok(())
            },
            Err(_) => {
                // println!("❌ PIN Verification Failed.");
                Err("Incorrect PIN. Shard B remains locked.".to_string())
            }
        }
    }
}
