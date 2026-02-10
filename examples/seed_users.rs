use reqwest::Client;
use serde_json::json;
use std::env;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok(); // 🟢 Load .env file
    println!("🚀 Seeding Users: Alice, Bob, Dealer, Max, Apollo...");

    let users = vec![
        ("Alice", "alice@blackbook.local", "password123"),
        ("Bob", "bob@blackbook.local", "password123"),
        ("Dealer", "dealer@blackbook.local", "password123"),
        ("Max", "max@blackbook.local", "password123"),
        ("Apollo", "apollo@blackbook.local", "password123"),
    ];

    let supabase_url = env::var("SUPABASE_URL").unwrap_or_else(|_| "https://your-project.supabase.co".to_string());
    let supabase_key = env::var("SUPABASE_SERVICE_ROLE_KEY").expect("Need SUPABASE_SERVICE_ROLE_KEY to seed users properly"); // We use Key for Auth usually, or Anon. But for admin delete/create we ideally use service role or admin api.
    // Actually, to signup we can use Anon key. But then we need email confirmation.
    // If we have Service Role, we can use /auth/v1/admin/users
    
    let client = Client::new();

    for (name, email, password) in users {
        println!("\n👤 Processing User: {}", name);

        // 1. Check if user exists or Create (Admin)
        // We'll try to sign up via Admin API to auto-confirm
        let admin_url = format!("{}/auth/v1/admin/users", supabase_url);
        
        let create_body = json!({
            "email": email,
            "password": password,
            "email_confirm": true,
            "user_metadata": { "username": name }
        });

        println!("   Creating Auth User...");
        let resp = client.post(&admin_url)
            .header("apikey", &supabase_key)
            .header("Authorization", format!("Bearer {}", supabase_key))
            .json(&create_body)
            .send()
            .await?;
        
        // If 422/400, maybe already exists, try to Sign In
        let mut user_id = String::new();
        let mut access_token = String::new();

        if resp.status().is_success() {
             let json: serde_json::Value = resp.json().await?;
             user_id = json["id"].as_str().unwrap().to_string();
             println!("   ✅ Created: {}", user_id);
             
             // Sign In to get Token
             let login_url = format!("{}/auth/v1/token?grant_type=password", supabase_url);
             let login_resp = client.post(&login_url)
                .header("apikey", &supabase_key) // Or anon key
                .query(&[("grant_type", "password")])
                .json(&json!({ "email": email, "password": password }))
                .send().await?;
            
             if login_resp.status().is_success() {
                 let login_json: serde_json::Value = login_resp.json().await?;
                 access_token = login_json["access_token"].as_str().unwrap().to_string();
             } else {
                 println!("   ❌ Login failed after creation: {:?}", login_resp.text().await?);
                 continue;
             }

        } else {
             println!("   ⚠️ User might exist or error: {}. Trying Login...", resp.status());
                         
             // Try Login
             let login_url = format!("{}/auth/v1/token?grant_type=password", supabase_url);
             let login_resp = client.post(&login_url)
                .header("apikey", &supabase_key)
                .query(&[("grant_type", "password")])
                .json(&json!({ "email": email, "password": password }))
                .send().await?;
                
             if login_resp.status().is_success() {
                 let login_json: serde_json::Value = login_resp.json().await?;
                 access_token = login_json["access_token"].as_str().unwrap().to_string();
                 user_id = login_json["user"]["id"].as_str().unwrap().to_string(); // Maybe
                 println!("   ✅ Logged In: {}", user_id);
             } else {
                 println!("   ❌ Login Failed: {:?}", login_resp.text().await?);
                 continue;
             }
        }

        // 2. Create Wallet (Local Service)
        // Assume Local Service running at localhost:8080
        let wallet_url = "http://localhost:8080/wallet/create";
        println!("   Creating Wallet at {}...", wallet_url);
        
        let wallet_body = json!({
            "username": name,
            "password": format!("{}_secret_pass", name), // Different from Auth pass
            "pin": "1234",
            "daily_limit": 1000
        });

        let wallet_resp = client.post(wallet_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&wallet_body)
            .send()
            .await?;

        if wallet_resp.status().is_success() {
            let w_json: serde_json::Value = wallet_resp.json().await?;
            println!("   🎉 Wallet Created: {}", w_json["wallet_id"]);
            println!("      Address: {}", w_json["address"]);
        } else {
            let error_text = wallet_resp.text().await?;
            if error_text.contains("duplicate key value") {
                 println!("   ℹ️ Wallet already exists.");
            } else {
                 println!("   ❌ Wallet Creation Failed: {}", error_text);
            }
        }
    }

    Ok(())
}
