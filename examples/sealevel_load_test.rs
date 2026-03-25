// ============================================================================
// $BB L1 — SEALEVEL PARALLEL EXECUTION LOAD TEST
// ============================================================================
//
// Hammers the /sealevel/submit endpoint (Gulf Stream → Sealevel parallel
// execution) to stress-test the parallel transaction pipeline under load.
//
// Usage:
//   cargo run --features unsafe_admin   (in one terminal)
//   cargo run --example sealevel_load_test
//
// Pipeline exercised:
//   POST /sealevel/submit → Gulf Stream queue → Sealevel ParallelScheduler
//     → lock-free batch execution → SVM AccountsDB → PoH block recording
//
// NOTE: server must be running on localhost:8080
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use tokio::sync::Semaphore;

// ── Config ──────────────────────────────────────────────────────────────────

const BASE_URL: &str = "http://127.0.0.1:8080";
const NUM_WALLETS: usize = 200;     // distinct sender keypairs
const NUM_TXS:    usize = 20_000;   // total sealevel submissions
const CONCURRENCY: usize = 1_000;   // max in-flight at once
const AMOUNT_PER_TX: f64 = 0.00001; // 1 lamport per tx
const FUND_BB: f64 = 0.1;           // BB per faucet claim (max allowed)

// ── Wallet ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Wallet {
    sk: Arc<SigningKey>,
    address: String,
    pubkey_hex: String,
}

impl Wallet {
    fn new() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        Wallet {
            address: bs58::encode(&pk).into_string(),
            pubkey_hex: hex::encode(pk),
            sk: Arc::new(sk),
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   $BB L1 — SEALEVEL PARALLEL EXECUTION LOAD TEST    ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(CONCURRENCY)
        .build()?;

    // ── 1. Health check ─────────────────────────────────────────────────────
    match client.get(format!("{}/health", BASE_URL)).send().await {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await?;
            let slot = body["poh_clock"]["current_slot"].as_u64().unwrap_or(0);
            let accts = body["blockchain"]["svm_accounts"].as_u64().unwrap_or(0);
            println!("✅  Server UP — slot {} | {} SVM accounts", slot, accts);
        }
        Ok(r) => { eprintln!("❌  Server returned {}", r.status()); std::process::exit(1); }
        Err(e) => { eprintln!("❌  Cannot reach server: {}", e); std::process::exit(1); }
    }

    // ── 2. Snapshot health before ──────────────────────────────────────────
    let _stats_before: Option<serde_json::Value> = match client
        .get(format!("{}/health", BASE_URL))
        .send().await {
            Ok(r) => r.json().await.ok(),
            Err(_) => None,
        };

    // ── 3. Generate wallets ──────────────────────────────────────────────────
    println!("\n🔑  Generating {} Ed25519 keypairs...", NUM_WALLETS);
    let wallets: Vec<Wallet> = (0..NUM_WALLETS).map(|_| Wallet::new()).collect();
    let sink = Wallet::new().address;

    // ── 4. Fund via /faucet ──────────────────────────────────────────────────
    println!("💰  Funding {} wallets × {} BB via /faucet...", NUM_WALLETS, FUND_BB);
    let fund_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut funded = 0usize;
    for (idx, w) in wallets.iter().enumerate() {
        let nonce = format!("sealevel-fund-{}-{}", idx, fastrand::u64(..));
        let message = format!("FAUCET:{}:{}:{}:{}", w.address, FUND_BB, fund_ts, nonce);
        let sig_hex = hex::encode(w.sk.sign(message.as_bytes()).to_bytes());

        let resp = client
            .post(format!("{}/faucet", BASE_URL))
            .json(&serde_json::json!({
                "wallet_address": w.address,
                "amount": FUND_BB,
                "timestamp": fund_ts,
                "nonce": nonce,
                "signature": sig_hex,
                "public_key": w.pubkey_hex,
            }))
            .send().await;

        match resp {
            Ok(r) if r.status().is_success() => funded += 1,
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                if funded == 0 { eprintln!("  ⚠  Faucet: {}", body); }
            }
            Err(e) => { if funded == 0 { eprintln!("  ⚠  {}", e); } }
        }
    }
    println!("   Funded {}/{} wallets", funded, NUM_WALLETS);
    if funded == 0 {
        eprintln!("\n❌  No wallets funded — aborting.");
        std::process::exit(1);
    }

    // ── 5. Fire Sealevel submissions (Ed25519 signed) ──────────────────────
    println!(
        "\n⚡  Firing {} /sealevel/submit (Ed25519 signed)  |  concurrency {}  |  {} BB each\n",
        NUM_TXS, CONCURRENCY, AMOUNT_PER_TX
    );

    let sem       = Arc::new(Semaphore::new(CONCURRENCY));
    let ok        = Arc::new(AtomicU64::new(0));
    let err       = Arc::new(AtomicU64::new(0));
    let lat_total = Arc::new(AtomicU64::new(0));
    let lat_max   = Arc::new(AtomicU64::new(0));

    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let start = Instant::now();
    let mut handles = Vec::with_capacity(NUM_TXS);

    const CHAIN_ID: u8 = 1;

    for i in 0..NUM_TXS {
        let wallet   = wallets[i % funded].clone();
        let sink_c   = sink.clone();
        let client_c = client.clone();
        let sem_c    = sem.clone();
        let ok_c     = ok.clone();
        let err_c    = err.clone();
        let lat_c    = lat_total.clone();
        let lat_m    = lat_max.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire().await.unwrap();

            let priority = (i % 10) as u64;
            let nonce = format!("sealevel-{}-{}", i, fastrand::u64(..));

            // Build canonical message: [chain_id] || payload_json || \n || timestamp || \n || nonce
            let payload_json = format!(r#"{{"to":"{}","amount":{}}}"#, sink_c, AMOUNT_PER_TX);
            let mut message = vec![CHAIN_ID];
            message.extend_from_slice(payload_json.as_bytes());
            message.extend_from_slice(b"\n");
            message.extend_from_slice(base_ts.to_string().as_bytes());
            message.extend_from_slice(b"\n");
            message.extend_from_slice(nonce.as_bytes());

            let sig_hex = hex::encode(wallet.sk.sign(&message).to_bytes());

            let t0 = Instant::now();
            let result = client_c
                .post(format!("{}/sealevel/submit", BASE_URL))
                .json(&serde_json::json!({
                    "from":       wallet.address,
                    "to":         sink_c,
                    "amount":     AMOUNT_PER_TX,
                    "public_key": wallet.pubkey_hex,
                    "signature":  sig_hex,
                    "timestamp":  base_ts,
                    "nonce":      nonce,
                    "chain_id":   CHAIN_ID,
                    "priority":   priority,
                }))
                .send()
                .await;

            let elapsed_ms = t0.elapsed().as_millis() as u64;
            lat_c.fetch_add(elapsed_ms, Ordering::Relaxed);
            lat_m.fetch_max(elapsed_ms, Ordering::Relaxed);

            match result {
                Ok(r) => {
                    let body: serde_json::Value = r.json().await.unwrap_or_default();
                    if body.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                        ok_c.fetch_add(1, Ordering::Relaxed);
                    } else {
                        err_c.fetch_add(1, Ordering::Relaxed);
                        if err_c.load(Ordering::Relaxed) <= 5 {
                            eprintln!("  ✗ TX-{:05}: {}", i, body);
                        }
                    }
                }
                Err(e) => {
                    err_c.fetch_add(1, Ordering::Relaxed);
                    if err_c.load(Ordering::Relaxed) <= 5 {
                        eprintln!("  ✗ TX-{:05}: {}", i, e);
                    }
                }
            }
        }));
    }

    for h in handles { let _ = h.await; }
    let elapsed = start.elapsed();

    // ── 6. Wait for Sealevel to drain the Gulf Stream queue ──────────────────
    println!("\n⏳  Waiting for Sealevel to process queued txs...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // ── 7. Report ────────────────────────────────────────────────────────────
    let total_ok  = ok.load(Ordering::Relaxed);
    let total_err = err.load(Ordering::Relaxed);
    let avg_lat   = if NUM_TXS > 0 { lat_total.load(Ordering::Relaxed) / NUM_TXS as u64 } else { 0 };
    let max_lat   = lat_max.load(Ordering::Relaxed);
    let submit_tps = total_ok as f64 / elapsed.as_secs_f64();
    let success_pct = 100.0 * total_ok as f64 / NUM_TXS as f64;

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          SEALEVEL LOAD TEST RESULTS                  ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Total submissions : {:>8}                         ║", NUM_TXS);
    println!("║  Accepted          : {:>8}  ({:.1}%)              ║", total_ok, success_pct);
    println!("║  Rejected          : {:>8}                         ║", total_err);
    println!("║  Wallets used      : {:>8}                         ║", funded);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  ⏱  Submit elapsed  : {:>7.2}s                        ║", elapsed.as_secs_f64());
    println!("║  ⚡ Submit TPS       : {:>7.0}                         ║", submit_tps);
    println!("║  ⌛ Avg submit lat   : {:>7}ms                        ║", avg_lat);
    println!("║  ⌛ Max submit lat   : {:>7}ms                        ║", max_lat);
    println!("╠══════════════════════════════════════════════════════╣");

    // ── 8. Check Sealevel execution stats ────────────────────────────────────
    if let Ok(r) = client.get(format!("{}/health", BASE_URL)).send().await {
        if let Ok(body) = r.json::<serde_json::Value>().await {
            let slot = body["poh_clock"]["current_slot"].as_u64().unwrap_or(0);
            let accts = body["blockchain"]["svm_accounts"].as_u64().unwrap_or(0);
            let blocks = body["blockchain"]["block_count"].as_u64().unwrap_or(0);
            let confirmed = body["consensus"]["confirmed_slots"].as_u64().unwrap_or(0);

            println!("║  📦 Blocks produced  : {:>8}                        ║", blocks);
            println!("║  🗼 Confirmed slots  : {:>8}                        ║", confirmed);
            println!("║  💼 SVM accounts     : {:>8}                        ║", accts);
            println!("║  ⏰ Current slot      : {:>8}                        ║", slot);
        }
    }
    println!("╚══════════════════════════════════════════════════════╝");

    // ── 9. Verify sink received funds ────────────────────────────────────────
    if let Ok(r) = client.get(format!("{}/balance/{}", BASE_URL, sink)).send().await {
        if let Ok(body) = r.json::<serde_json::Value>().await {
            let actual = body["balance"].as_f64().unwrap_or(0.0);
            let expected = total_ok as f64 * AMOUNT_PER_TX;
            let delta = (actual - expected).abs();
            let ok_str = if delta < 0.01 { "✅ MATCH" } else { "⚠ DRIFT" };
            println!(
                "\n🔍  Sink balance: expected ≈ {:.5} BB  |  actual = {:.5} BB  →  {}",
                expected, actual, ok_str
            );
        }
    }

    if total_err > 0 {
        println!("\n⚠  {} submissions rejected — check server logs.", total_err);
    } else {
        println!("\n✅  All {} Sealevel submissions accepted.", total_ok);
    }

    Ok(())
}
