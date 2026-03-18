// ============================================================================
// $BB L1 — LOCAL LOAD TEST
// ============================================================================
//
// Hits a running BlackBook L1 node with a configurable burst of real
// Ed25519-signed transfers and reports TPS + latency percentiles.
//
// Usage:
//   cargo run              (in one terminal — starts the server)
//   cargo run --example load_test                        (defaults)
//   cargo run --example load_test -- --wallets 100 --txs 5000 --concurrency 500
//
// The test:
//   1. Generates N fresh Ed25519 keypairs (sender wallets)
//   2. Funds each via POST /admin/mint (100 BB each)
//   3. Fires M signed transfers (each 0.001 BB → a shared sink address)
//      with up to C concurrent in-flight at once
//   4. Prints a pass/fail summary table with TPS and avg latency
//
// NOTE: requires the server to be running on localhost:8080
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use tokio::sync::Semaphore;

// ── Config ──────────────────────────────────────────────────────────────────

const BASE_URL: &str = "http://127.0.0.1:8080";
const NUM_WALLETS: usize = 50;      // distinct sender keypairs
const NUM_TXS:    usize = 2_000;    // total transfers to fire
const CONCURRENCY: usize = 200;     // max in-flight at once
const AMOUNT_PER_TX: f64 = 0.001;  // BB per transfer (tiny, won't drain wallets)
const FUND_BB: f64 = 20.0;         // BB minted into each sender wallet upfront
const CHAIN_ID: u8 = 1;

// ── Sender wallet ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Wallet {
    sk: Arc<SigningKey>,
    address: String,   // bs58(pubkey_bytes)  — matches faucet derivation
    pubkey_hex: String, // hex(pubkey_bytes)
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

    /// Build + sign the exact message the transfer handler expects:
    ///   [chain_id] || payload_json || '\n' || timestamp_str || '\n' || nonce
    fn sign_transfer(&self, payload: &str, timestamp: u64, nonce: &str) -> String {
        let mut msg = vec![CHAIN_ID];
        msg.extend_from_slice(payload.as_bytes());
        msg.extend_from_slice(b"\n");
        msg.extend_from_slice(timestamp.to_string().as_bytes());
        msg.extend_from_slice(b"\n");
        msg.extend_from_slice(nonce.as_bytes());
        hex::encode(self.sk.sign(&msg).to_bytes())
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Check the server is up ───────────────────────────────────────────
    println!("╔══════════════════════════════════════════════════╗");
    println!("║         $BB L1  —  LOCAL LOAD TEST               ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(CONCURRENCY)
        .build()?;

    match client.get(format!("{}/health", BASE_URL)).send().await {
        Ok(r) if r.status().is_success() => println!("✅  Server is UP at {}", BASE_URL),
        Ok(r) => {
            eprintln!("❌  Server returned {} — is it running?", r.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌  Cannot reach server: {}", e);
            eprintln!("    Start it with:  cargo run");
            std::process::exit(1);
        }
    }

    // ── 2. Generate sender wallets ──────────────────────────────────────────
    println!("\n🔑  Generating {} Ed25519 keypairs...", NUM_WALLETS);
    let wallets: Vec<Wallet> = (0..NUM_WALLETS).map(|_| Wallet::new()).collect();

    // ── 3. Fund each sender via admin/mint ──────────────────────────────────
    println!("💰  Funding {} wallets × {} BB each...", NUM_WALLETS, FUND_BB);
    let mut funded = 0usize;
    for w in &wallets {
        let resp = client
            .post(format!("{}/admin/mint", BASE_URL))
            .json(&serde_json::json!({
                "to":               w.address,
                "amount":           FUND_BB,
                "dealer_signature": null,
                "l2_receipt_id":    null,
            }))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => funded += 1,
            Ok(r) => eprintln!("  ⚠  Mint failed for {}: {}", &w.address[..8], r.text().await?),
            Err(e) => eprintln!("  ⚠  Mint request error: {}", e),
        }
    }
    println!("   Funded {}/{} wallets", funded, NUM_WALLETS);

    if funded == 0 {
        eprintln!("\n❌  No wallets funded — aborting. Check admin/mint endpoint.");
        std::process::exit(1);
    }

    // ── 4. Sink address (receives all funds; never sends) ───────────────────
    let sink = Wallet::new().address;

    // ── 5. Shared timestamp (fresh enough for 60s window across the burst) ──
    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // ── 6. Fire! ───────────────────────────────────────────────────────────
    println!(
        "\n🚀  Firing {} transfers  |  concurrency {}  |  {} BB each\n",
        NUM_TXS, CONCURRENCY, AMOUNT_PER_TX
    );

    let sem          = Arc::new(Semaphore::new(CONCURRENCY));
    let ok           = Arc::new(AtomicU64::new(0));
    let err          = Arc::new(AtomicU64::new(0));
    let lat_total_ms = Arc::new(AtomicU64::new(0));
    let lat_max_ms   = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(NUM_TXS);

    for i in 0..NUM_TXS {
        let wallet    = wallets[i % NUM_WALLETS].clone();
        let sink_c    = sink.clone();
        let client_c  = client.clone();
        let sem_c     = sem.clone();
        let ok_c      = ok.clone();
        let err_c     = err.clone();
        let lat_c     = lat_total_ms.clone();
        let lat_max_c = lat_max_ms.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire().await.unwrap();

            // unique nonce per tx → guaranteed replay protection
            let nonce   = format!("load-{}-{}", i, fastrand::u64(..));
            let payload = format!(
                r#"{{"to":"{}","amount":{}}}"#,
                sink_c, AMOUNT_PER_TX
            );
            let sig_hex = wallet.sign_transfer(&payload, base_ts, &nonce);

            let t0 = Instant::now();
            let result = client_c
                .post(format!("{}/transfer/simple", BASE_URL))
                .json(&serde_json::json!({
                    "public_key":     wallet.pubkey_hex,
                    "wallet_address": wallet.address,
                    "payload":        payload,
                    "timestamp":      base_ts,
                    "nonce":          nonce,
                    "chain_id":       CHAIN_ID,
                    "signature":      sig_hex,
                }))
                .send()
                .await;

            let elapsed_ms = t0.elapsed().as_millis() as u64;
            lat_c.fetch_add(elapsed_ms, Ordering::Relaxed);
            lat_max_c.fetch_max(elapsed_ms, Ordering::Relaxed);

            match result {
                Ok(r) if r.status().is_success() => {
                    ok_c.fetch_add(1, Ordering::Relaxed);
                }
                Ok(r) => {
                    err_c.fetch_add(1, Ordering::Relaxed);
                    if err_c.load(Ordering::Relaxed) <= 5 {
                        let body = r.text().await.unwrap_or_default();
                        eprintln!("  ✗ TX-{:04}: {}", i, body);
                    }
                }
                Err(e) => {
                    err_c.fetch_add(1, Ordering::Relaxed);
                    if err_c.load(Ordering::Relaxed) <= 5 {
                        eprintln!("  ✗ TX-{:04}: {}", i, e);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    // ── 7. Report ──────────────────────────────────────────────────────────
    let elapsed   = start.elapsed();
    let total_ok  = ok.load(Ordering::Relaxed);
    let total_err = err.load(Ordering::Relaxed);
    let avg_lat   = if NUM_TXS > 0 { lat_total_ms.load(Ordering::Relaxed) / NUM_TXS as u64 } else { 0 };
    let max_lat   = lat_max_ms.load(Ordering::Relaxed);
    let tps       = total_ok as f64 / elapsed.as_secs_f64();
    let success_pct = 100.0 * total_ok as f64 / NUM_TXS as f64;

    println!();
    println!("╔══════════════════════════════════════════════════╗");
    println!("║              LOAD TEST RESULTS                   ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  Total txs    : {:>8}                          ║", NUM_TXS);
    println!("║  Success      : {:>8}  ({:.1}%)               ║", total_ok, success_pct);
    println!("║  Failed       : {:>8}                          ║", total_err);
    println!("║  Wallets used : {:>8}                          ║", funded);
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  ⏱  Elapsed   : {:>7.2}s                         ║", elapsed.as_secs_f64());
    println!("║  ⚡ TPS        : {:>7.0}                          ║", tps);
    println!("║  ⌛ Avg latency: {:>7}ms                         ║", avg_lat);
    println!("║  ⌛ Max latency: {:>7}ms                         ║", max_lat);
    println!("╚══════════════════════════════════════════════════╝");

    if total_err > 0 {
        println!("\n⚠  {} transfers failed — check server logs for details.", total_err);
    } else {
        println!("\n✅  All transfers succeeded.");
    }

    // Verify sink balance matches expected
    let expected_sink = total_ok as f64 * AMOUNT_PER_TX;
    let balance_resp = client
        .get(format!("{}/balance/{}", BASE_URL, sink))
        .send()
        .await;
    if let Ok(r) = balance_resp {
        if let Ok(body) = r.json::<serde_json::Value>().await {
            let actual: f64 = body.get("balance").and_then(|v| v.as_f64()).unwrap_or(0.0);
            println!(
                "\n🔍  Sink balance check:  expected ≈ {:.3} BB  |  actual = {:.3} BB  →  {}",
                expected_sink,
                actual,
                if (actual - expected_sink).abs() < 0.01 { "✅ MATCH" } else { "⚠  DRIFT" }
            );
        }
    }

    Ok(())
}
