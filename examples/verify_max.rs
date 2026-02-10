use reqwest::Client;
use serde_json::Value;
use std::env;
use std::fs;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    
    println!("🔍 Verifying Max's Production Readiness...");

    // 1. Load Local Wallet Artifact
    let wallet_path = "real_wallets/Max_wallet.json";
    if !std::path::Path::new(wallet_path).exists() {
        println!("❌ Max_wallet.json not found. Run creation script first.");
        return Ok(());
    }
    
    let wallet_content = fs::read_to_string(wallet_path)?;
    let wallet_json: Value = serde_json::from_str(&wallet_content)?;
    
    let user_id = wallet_json["user"]["id"].as_str().unwrap();
    let wallet_address = wallet_json["wallet"]["address"].as_str().unwrap();
    let email = wallet_json["user"]["email"].as_str().unwrap();
    let password = wallet_json["user"]["password"].as_str().unwrap();
    
    println!("   📂 Local Artifact Found:");
    println!("      - ID: {}", user_id);
    println!("      - Address: {}", wallet_address);
    println!("      - Password: {}", password); // Debug print

    // 2. Connect to Supabase
    let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL not set");
    let service_key = env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY not set");
    let client = Client::new();

    // 3. Verify Auth Login (Password Sync Check)
    println!("\n🔐 Verifying Auth & Password Sync...");
    let auth_url = format!("{}/auth/v1/token?grant_type=password", supabase_url);
    let login_resp = client.post(&auth_url)
        .header("apikey", &service_key)
        .json(&serde_json::json!({
            "email": email,
            "password": password
        }))
        .send().await?;
        
    if login_resp.status().is_success() {
        println!("   ✅ Auth Success: Password matches Supabase.");
    } else {
        println!("   ❌ Auth Failed: Password mismatch or user missing.");
        println!("      Status: {}", login_resp.status());
        return Ok(());
    }

    // 4. Verify User Vault Persistence
    println!("\n🏦 Verifying User Vault (Layer 1 Storage)...");
    let vault_url = format!("{}/rest/v1/user_vault?id=eq.{}&select=*", supabase_url, user_id);
    let vault_resp = client.get(&vault_url)
        .header("apikey", &service_key)
        .header("Authorization", format!("Bearer {}", service_key))
        .send().await?;

    if vault_resp.status().is_success() {
        let vault_data: Vec<Value> = vault_resp.json().await?;
        if let Some(row) = vault_data.first() {
            println!("   ✅ Vault Row Found.");
            
            // Check Critical Columns
            let db_address = row["wallet_address"].as_str().unwrap_or("MISSING");
            let db_pin_hash = row["pin_hash"].as_str().unwrap_or("MISSING");
            let db_shard_b = row["encrypted_shard_b_blob"].as_str().unwrap_or("MISSING");
            let db_root = row["root_pubkey"].as_str().unwrap_or("MISSING");
            
            if db_address == wallet_address {
                 println!("      - Address Match: OK");
            } else {
                 println!("      - ⚠️ Address Mismatch: DB={} Local={}", db_address, wallet_address);
            }
            
            if db_pin_hash != "MISSING" && db_pin_hash.len() > 10 {
                 println!("      - PIN Hash: Stored ({})", &db_pin_hash[0..10]);
            } else {
                 println!("      - ❌ PIN Hash: MISSING");
            }
            
            if db_shard_b != "MISSING" {
                 println!("      - Shard B: Stored");
            } else {
                 println!("      - ❌ Shard B: MISSING");
            }

            if db_root != "MISSING" {
                 println!("      - Root Pubkey: Stored");
            } else {
                 println!("      - ❌ Root Pubkey: MISSING");
            }

        } else {
            println!("   ❌ User Vault Empty: No record found for User ID.");
        }
    } else {
        println!("   ❌ Failed to query User Vault: {}", vault_resp.status());
    }

    Ok(())
}
