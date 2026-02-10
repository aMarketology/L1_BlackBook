use std::env;
use std::fs;
use serde_json::Value;
use reqwest::Client;
use dotenv::dotenv;
// Import local modules for decryption
// We need to access the security module. 
// Assuming library structure allows `layer1::wallet_unified::security` access

// COPYING SECURITY LOGIC LOCALLY TO AVOID VISIBILITY ISSUES if internal
// (It's safer for a standalone example script)
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

fn decrypt_with_secret(secret: &str, formatted_str: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = formatted_str.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid format. Expected salt:nonce:ciphertext".to_string());
    }

    let salt_str = parts[0];
    let nonce_b64 = parts[1];
    let ciphertext_b64 = parts[2];

    // Decode components
    let nonce_bytes = BASE64.decode(nonce_b64).map_err(|_| "Invalid nonce base64")?;
    let ciphertext = BASE64.decode(ciphertext_b64).map_err(|_| "Invalid ciphertext base64")?;
    
    // Derive Key
    let mut key_buffer = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(
        secret.as_bytes(),
        salt_str.as_bytes(),
        &mut key_buffer
    ).map_err(|e| format!("Key Derivation Failed: {}", e))?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_buffer);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption Failed (Wrong Password?): {}", e))
}

#[derive(serde::Deserialize, Debug)]
struct ShardBContainer {
    encrypted_blob: String, 
    // we ignore other fields
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    println!("🔐 MAX WALLET DECRYPTION & VALIDATION\n");

    // 1. SETUP
    let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL set");
    let service_key = env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY set");
    let master_key = env::var("SERVER_MASTER_KEY").expect("SERVER_MASTER_KEY set");
    let max_id = "4dc896ac-f9cf-4954-9ae1-3df6cda0c0b0";
    let max_pass = "password123";

    // 2. FETCH FROM SUPABASE
    let client = Client::new();
    let url = format!("{}/rest/v1/user_vault?id=eq.{}&select=*", supabase_url, max_id);
    println!("📡 Fetching Vault Row from Supabase...");
    let resp = client.get(&url)
        .header("apikey", &service_key)
        .header("Authorization", format!("Bearer {}", service_key))
        .send().await?;

    let rows: Vec<Value> = resp.json().await?;
    let row = &rows[0];

    // 3. SHARD A (USER ENCRYPTED)
    println!("\n🔷 SHARD A (User Managed)");
    let enc_shard_a = row["encrypted_shard_a_blob"].as_str().unwrap();
    println!("   Encrypted Blob: {}...", &enc_shard_a[0..30]);
    
    // Check against local JSON
    let json_content = fs::read_to_string("real_wallets/Max_wallet.json")?;
    let json: Value = serde_json::from_str(&json_content)?;
    let local_enc_a = json["wallet"]["share_a"].as_str().unwrap();

    if enc_shard_a == local_enc_a {
        println!("   ✅ MATCHES local Max_wallet.json");
    } else {
        println!("   ❌ MISMATCH with local JSON!");
    }

    // Decrypt Shard A
    println!("   🗝️  Attempting Decryption with password '{}'...", max_pass);
    match decrypt_with_secret(max_pass, enc_shard_a) {
        Ok(bytes) => {
            // It's a FROST share, usually serialized JSON or bytes.
            // Let's try to parse as JSON or just print hex
            let json_share: Result<Value, _> = serde_json::from_slice(&bytes);
            if let Ok(js) = json_share {
                 println!("   ✅ DECRYPTION SUCCESS! Valid JSON Share.");
                 println!("      Identifier: {}", js["identifier"]);
            } else {
                 println!("   ✅ DECRYPTION SUCCESS! (Raw Bytes: {} bytes)", bytes.len());
            }
        },
        Err(e) => println!("   ❌ DECRYPTION FAILED: {}", e),
    }

    // 4. SHARD B (SERVER ENCRYPTED)
    println!("\n🔶 SHARD B (Server Managed)");
    let enc_shard_b_hex = row["encrypted_shard_b_blob"].as_str().unwrap();
    
    // Decode Hex -> JSON Container
    let container_bytes = hex::decode(enc_shard_b_hex)?;
    let container: ShardBContainer = serde_json::from_slice(&container_bytes)?;
    
    println!("   Container unwrapped. Encrypted Blob: {}...", &container.encrypted_blob[0..30]);
    
    // Decrypt Shard B with Master Key
    println!("   🗝️  Attempting Decryption with SERVER_MASTER_KEY...");
    match decrypt_with_secret(&master_key, &container.encrypted_blob) {
        Ok(bytes) => {
             let json_share: Result<Value, _> = serde_json::from_slice(&bytes);
             if let Ok(js) = json_share {
                  println!("   ✅ DECRYPTION SUCCESS! Valid JSON Share.");
                  println!("      Identifier: {}", js["identifier"]);
             } else {
                  println!("   ✅ DECRYPTION SUCCESS! (Raw Bytes: {} bytes)", bytes.len());
             }
        },
        Err(e) => println!("   ❌ DECRYPTION FAILED: {}", e),
    }

    Ok(())
}
