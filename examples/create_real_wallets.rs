use reqwest::Client;
use serde_json::json;
use std::env;
use std::fs;
use std::path::Path;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok(); // Load .env
    println!("🚀 Starting Real Wallet Creation (SSS 2-of-3) with Supabase");

    let output_dir = "real_wallets";
    if !Path::new(output_dir).exists() {
        fs::create_dir(output_dir)?;
    }

    let users = vec![
        ("Max", "max@blackbook.local", "password123", "9999"),
    ];

    let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL must be set");
    let service_role_key = env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY must be set");
    
    // Using Service Role for Admin/Auth operations to ensure we can bypass email checks/RLS if needed for seeding
    let client = Client::new();

    for (username, email, password, pin) in users {
        println!("\n---------------------------------------------------------");
        println!("👤 Processing User: {}", username);

        // 1. AUTHENTICATION (Ensure auth.users entry)
        let mut user_id = String::new();
        let mut access_token = String::new();

        // Try to Login first
        let login_url = format!("{}/auth/v1/token?grant_type=password", supabase_url);
        let login_resp = client.post(&login_url)
            .header("apikey", &service_role_key)
            .json(&json!({ "email": email, "password": password }))
            .send().await?;

        if login_resp.status().is_success() {
            println!("   ✅ User exists. Logged in.");
            let json: serde_json::Value = login_resp.json().await?;
            access_token = json["access_token"].as_str().unwrap().to_string();
            user_id = json["user"]["id"].as_str().unwrap().to_string();
            println!("   🔑 Access Token: {}", access_token); // Debug print
        } else {
            println!("   ⚠️ Login failed ({}), attempting creation...", login_resp.status());
            
            // Create User via Admin API
            let create_url = format!("{}/auth/v1/admin/users", supabase_url);
            let create_resp = client.post(&create_url)
                .header("apikey", &service_role_key)
                .header("Authorization", format!("Bearer {}", service_role_key))
                .json(&json!({
                    "email": email,
                    "password": password,
                    "email_confirm": true,
                    "user_metadata": { "username": username }
                }))
                .send().await?;

            if create_resp.status().is_success() {
                let json: serde_json::Value = create_resp.json().await?;
                user_id = json["id"].as_str().unwrap().to_string();
                println!("   ✅ Created new Auth User: {}", user_id);

                // Initial login to get token
                let login_retry = client.post(&login_url)
                    .header("apikey", &service_role_key)
                    .json(&json!({ "email": email, "password": password }))
                    .send().await?;
                let login_json: serde_json::Value = login_retry.json().await?;
                access_token = login_json["access_token"].as_str().unwrap().to_string();
            } else {
                println!("   ❌ Failed to create user: {:?}", create_resp.text().await?);
                continue;
            }
        }

        // 2. ENSURE PROFILE EXISTS (public.profiles)
        // We explicitly upsert into profiles to fix the "missing profile" issue
        println!("   ⚡ Syncing 'public.profiles'...");
        let profiles_url = format!("{}/rest/v1/profiles", supabase_url);
        let profile_resp = client.post(&profiles_url)
            .header("apikey", &service_role_key)
            .header("Authorization", format!("Bearer {}", service_role_key))
            .header("Prefer", "resolution=merge-duplicates") // Upsert
            .json(&json!({
                "id": user_id,
                "username": username,
                "updated_at": "now()"
            }))
            .send().await?;

        if profile_resp.status().is_success() {
             println!("   ✅ Profile synced.");
        } else {
             println!("   ⚠️ Failed to sync profile: {:?}", profile_resp.text().await?);
        }

        // 3. CREATE WALLET (Layer 1)
        println!("   💳 Creating BlackBook Wallet (SSS 2-of-3)...");
        let wallet_url = "http://localhost:8080/wallet/create";
        let wallet_resp = client.post(wallet_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "username": username,
                "password": password, // SAME as Supabase Auth Password
                "pin": pin,
                "daily_limit": 1000
            }))
            .send()
            .await?;

        if wallet_resp.status().is_success() {
            let wallet_data: serde_json::Value = wallet_resp.json().await?;
            
            // 4. SAVE ARTIFACTS
            let filename = format!("{}/{}_wallet.json", output_dir, username);
            let context = json!({
                "user": {
                    "username": username,
                    "id": user_id,
                    "email": email,
                    "password": password
                },
                "wallet": wallet_data,
                "note": "DO NOT SHARE. Contains Encrypted Shares and Recovery Information."
            });
            
            fs::write(&filename, serde_json::to_string_pretty(&context)?)?;
            println!("   💾 SAVED: {}", filename);
            println!("   🔑 Address: {}", wallet_data["address"]);
            println!("   🔐 Full Credential Set Stored locally.");

        } else {
            let err_text = wallet_resp.text().await?;
            if err_text.contains("duplicate key") || err_text.contains("Unique violation") {
                println!("   ⚠️ Wallet likely already exists for this address/user.");
                // If it exists, we can't easily retrieve the "CreateResponse" again because keys are generated ONCE.
                // We would need a "get_wallet_details" endpoint or similar, but getting the private mnemonic again is impossible.
                println!("   ❌ Could not regenerate secrets for existing wallet. (Security Feature)");
            } else {
                println!("   ❌ Wallet Creation Failed: {}", err_text);
            }
        }
    }
    
    Ok(())
}
