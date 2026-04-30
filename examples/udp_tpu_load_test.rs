// ============================================================================
// $BB L1 — UDP TPU LOAD TEST (Bincode binary pipeline)
// ============================================================================
//
// Bypasses HTTP entirely. Blasts raw bincode-serialized transactions directly
// to the BlackBook TPU UDP socket on port 8003.
//
// This removes TCP handshake overhead, HTTP header parsing, and OS ephemeral
// port limits — targeting the raw throughput ceiling of the Sealevel engine.
//
// Usage:
//   cargo run --release             (server in terminal 1)
//   cargo run --release --example udp_tpu_load_test
//
// ============================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

// ── Config ──────────────────────────────────────────────────────────────────

const TPU_ADDR: &str = "127.0.0.1:8003";
const BASE_URL: &str = "http://127.0.0.1:8080";    // HTTP for health + faucet only
const NUM_WALLETS: usize = 2_000;
const NUM_TXS: usize = 500_000;
const CONCURRENCY: usize = 8_000;                  // UDP has no socket state — much higher is safe
const AMOUNT_PER_TX: u64 = 1_000;                  // 1_000 lamports = 0.01 BB
const FUND_BB: f64 = 0.1;
const CHAIN_ID: u8 = 1;

// ── Wire format must exactly match runtime::tpu::TpuPacket ──────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TpuPacket {
    from: String,
    to: String,
    amount: u64,        // lamports (1 BB = 100_000 lamports)
    public_key: String,
    signature: String,
    timestamp: u64,
    nonce: String,
    chain_id: u8,
    priority: u64,
    tx_type: Option<String>,
}

// ── Wallet ───────────────────────────────────────────────────────────────────

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

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║   $BB L1 — UDP TPU BINCODE LOAD TEST                ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // ── 1. Health check ──────────────────────────────────────────────────────
    match http.get(format!("{}/health", BASE_URL)).send().await {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await?;
            let slot = body["poh_clock"]["current_slot"].as_u64().unwrap_or(0);
            let accts = body["blockchain"]["svm_accounts"].as_u64().unwrap_or(0);
            println!("✅  Server UP — slot {} | {} SVM accounts", slot, accts);
        }
        Ok(r) => { eprintln!("❌  Server {}", r.status()); std::process::exit(1); }
        Err(e) => { eprintln!("❌  Cannot reach server: {}", e); std::process::exit(1); }
    }

    // ── 2. Generate wallets ──────────────────────────────────────────────────
    println!("\n🔑  Generating {} Ed25519 keypairs...", NUM_WALLETS);
    let wallets: Vec<Wallet> = (0..NUM_WALLETS).map(|_| Wallet::new()).collect();
    let sink = Wallet::new();

    // ── 3. Fund via HTTP /faucet ─────────────────────────────────────────────
    println!("💰  Funding {} wallets × {} BB via /faucet...", NUM_WALLETS, FUND_BB);
    let fund_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut funded = 0usize;
    for (idx, w) in wallets.iter().enumerate() {
        let nonce = format!("fund-{}-{}", idx, fastrand::u64(..));
        let message = format!("FAUCET:{}:{}:{}:{}", w.address, FUND_BB, fund_ts, nonce);
        let sig_hex = hex::encode(w.sk.sign(message.as_bytes()).to_bytes());
        let resp = http
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
            Ok(r) => { if funded == 0 { eprintln!("  ⚠  Faucet: {}", r.text().await.unwrap_or_default()); } }
            Err(e) => { if funded == 0 { eprintln!("  ⚠  {}", e); } }
        }
    }
    println!("   Funded {}/{} wallets", funded, NUM_WALLETS);
    if funded == 0 { eprintln!("❌  No wallets funded."); std::process::exit(1); }

    // ── 4. Bind local UDP socket ─────────────────────────────────────────────
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let tpu_addr: SocketAddr = TPU_ADDR.parse()?;
    udp.connect(tpu_addr).await?;
    println!("\n📡  UDP socket bound → {} connected to TPU {}", udp.local_addr()?, tpu_addr);

    // ── 5. Blast bincode packets ─────────────────────────────────────────────
    println!(
        "\n⚡  Firing {} UDP/bincode TpuPackets  |  concurrency {}  |  {} BB each\n",
        NUM_TXS, CONCURRENCY, AMOUNT_PER_TX
    );

    let sem     = Arc::new(Semaphore::new(CONCURRENCY));
    let ok      = Arc::new(AtomicU64::new(0));
    let err     = Arc::new(AtomicU64::new(0));
    let bytes_s = Arc::new(AtomicU64::new(0));

    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let start = Instant::now();
    let mut handles = Vec::with_capacity(NUM_TXS);

    for i in 0..NUM_TXS {
        let wallet   = wallets[i % funded].clone();
        let sink_addr = sink.address.clone();
        let udp_c    = udp.clone();
        let sem_c    = sem.clone();
        let ok_c     = ok.clone();
        let err_c    = err.clone();
        let bytes_c  = bytes_s.clone();

        // Each tx gets its own fresh timestamp so it never goes stale
        let tx_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        handles.push(tokio::spawn(async move {
            let _permit = sem_c.acquire().await.unwrap();

            let nonce = format!("udp-{}-{}", i, fastrand::u64(..));
            let priority = (i % 10) as u64;

            // Build canonical binary message — must exactly match runtime/tpu.rs verification:
            // chain_id(1) || from_utf8 || '|' || to_utf8 || '|' || amount_le8 || '|' || ts_le8 || '|' || nonce_utf8
            let mut message: Vec<u8> = Vec::with_capacity(128);
            message.push(CHAIN_ID);
            message.extend_from_slice(wallet.address.as_bytes());
            message.push(b'|');
            message.extend_from_slice(sink_addr.as_bytes());
            message.push(b'|');
            message.extend_from_slice(&AMOUNT_PER_TX.to_le_bytes());
            message.push(b'|');
            message.extend_from_slice(&tx_ts.to_le_bytes());
            message.push(b'|');
            message.extend_from_slice(nonce.as_bytes());

            let sig = wallet.sk.sign(&message);
            let sig_hex = hex::encode(sig.to_bytes());

            let pkt = TpuPacket {
                from: wallet.address.clone(),
                to: sink_addr,
                amount: AMOUNT_PER_TX,
                public_key: wallet.pubkey_hex.clone(),
                signature: sig_hex,
                timestamp: tx_ts,
                nonce,
                chain_id: CHAIN_ID,
                priority,
                tx_type: None,
            };

            match bincode::serialize(&pkt) {
                Ok(bytes) => {
                    match udp_c.send(&bytes).await {
                        Ok(sent) => {
                            ok_c.fetch_add(1, Ordering::Relaxed);
                            bytes_c.fetch_add(sent as u64, Ordering::Relaxed);
                        }
                        Err(_) => { err_c.fetch_add(1, Ordering::Relaxed); }
                    }
                }
                Err(_) => { err_c.fetch_add(1, Ordering::Relaxed); }
            }
        }));
    }

    for h in handles { let _ = h.await; }
    let elapsed = start.elapsed();

    // ── 6. Wait for TPU to drain the queue ───────────────────────────────────
    println!("\n⏳  Waiting for Sealevel to process queued txs...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // ── 7. Check final stats ─────────────────────────────────────────────────
    let stats_after: serde_json::Value = http
        .get(format!("{}/health", BASE_URL))
        .send().await?
        .json().await?;

    let total_ok        = ok.load(Ordering::Relaxed);
    let total_err       = err.load(Ordering::Relaxed);
    let total_bytes     = bytes_s.load(Ordering::Relaxed);
    let send_tps        = total_ok as f64 / elapsed.as_secs_f64();
    let mbps            = (total_bytes as f64 / elapsed.as_secs_f64()) / 1_000_000.0;
    let slots_after     = stats_after["poh_clock"]["current_slot"].as_u64().unwrap_or(0);
    let accts_after     = stats_after["blockchain"]["svm_accounts"].as_u64().unwrap_or(0);

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║         UDP TPU BINCODE LOAD TEST RESULTS            ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Total packets sent  : {:>8}                      ║", NUM_TXS);
    println!("║  Sent OK             : {:>8}                      ║", total_ok);
    println!("║  Send errors         : {:>8}                      ║", total_err);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  ⏱  Elapsed          : {:>7.2}s                      ║", elapsed.as_secs_f64());
    println!("║  ⚡ Send TPS          : {:>7.0} pkt/s                 ║", send_tps);
    println!("║  📦 Throughput        : {:>7.2} MB/s                  ║", mbps);
    println!("║  📬 Bytes sent        : {:>8} bytes                 ║", total_bytes);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  🏭 Current slot      : {:>8}                      ║", slots_after);
    println!("║  💼 SVM accounts      : {:>8}                      ║", accts_after);
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("  Note: UDP is fire-and-forget. 'Send TPS' = network injection rate.");
    println!("  Check server logs for confirmed on-chain execution count.");

    Ok(())
}
