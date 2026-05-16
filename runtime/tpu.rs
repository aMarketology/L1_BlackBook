//! BlackBook L1 — Transaction Processing Unit (TPU)
//!
//! UDP-based high-throughput transaction ingestion pipeline.
//!
//! Architecture:
//!   UDP:8003 → [QoS IP Rate-Limit] → [Bincode Deserialize] → [Ed25519 Verify]
//!              → [TTL + Chain-ID check] → [Replay-Nonce check]
//!              → GulfStreamService → Sealevel Parallel Execution
//!
//! Why UDP over HTTP:
//!   - No TCP 3-way handshake overhead
//!   - No HTTP header parsing cost
//!   - No OS ephemeral port exhaustion
//!   - Fire-and-forget enables 100k+ TPS burst ingestion

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{info, warn, error};

use crate::storage::ConcurrentBlockchain;
use super::consensus::GulfStreamService;
use super::core::{Transaction as RuntimeTx, TransactionType};
use super::poh_service::{TransactionPipeline, PipelinePacket, SharedPoHService};

// ── Constants ────────────────────────────────────────────────────────────────

/// Max UDP datagram size accepted (safe below MTU)
const MAX_PACKET_SIZE: usize = 1280;

/// Max UDP packets accepted per IP per second before silent drop
const QOS_MAX_RPS: u64 = 5_000;

/// Chain ID this node belongs to — reject all others
const EXPECTED_CHAIN_ID: u8 = 1;

/// Number of concurrent tokio worker tasks sharing the bound socket
const NUM_WORKERS: usize = 8;

// ── Wire Format (Bincode over UDP) ───────────────────────────────────────────

/// Compact binary transaction payload. Field order is fixed — bincode is positional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpuPacket {
    /// Sender BS58 address (must equal BS58(public_key))
    pub from: String,
    /// Recipient BS58 address
    pub to: String,
    /// Amount in lamports (1 BB = 100_000 lamports). Must be > 0.
    pub amount: u64,
    /// Ed25519 public key of sender — hex-encoded 32 bytes
    pub public_key: String,
    /// Ed25519 signature over canonical message — hex-encoded 64 bytes
    pub signature: String,
    /// Unix timestamp (seconds). Rejected if older than 60s.
    pub timestamp: u64,
    /// Unique nonce for replay protection
    pub nonce: String,
    /// Must equal EXPECTED_CHAIN_ID (1) — prevents cross-chain replay
    pub chain_id: u8,
    /// Priority fee lane (0 = standard)
    pub priority: u64,
    /// Optional tx type tag
    pub tx_type: Option<String>,
}

// ── Per-IP QoS State ─────────────────────────────────────────────────────────

struct IpState {
    count: u64,
    window_start: Instant,
}

// ── TpuService ───────────────────────────────────────────────────────────────

pub struct TpuService {
    gulf_stream: Arc<GulfStreamService>,
    pipeline: Arc<TransactionPipeline>,
    blockchain: ConcurrentBlockchain,
    used_nonces: Arc<DashMap<String, u64>>,
    /// Shared PoH service — used to stamp tx IDs into the hash chain BEFORE execution.
    poh: SharedPoHService,
}

impl TpuService {
    pub fn new(
        gulf_stream: Arc<GulfStreamService>,
        pipeline: Arc<TransactionPipeline>,
        blockchain: ConcurrentBlockchain,
        used_nonces: Arc<DashMap<String, u64>>,
        poh: SharedPoHService,
    ) -> Self {
        Self { gulf_stream, pipeline, blockchain, used_nonces, poh }
    }

    /// Bind the UDP socket and spin up NUM_WORKERS parallel receiver tasks.
    pub async fn run(self, addr: SocketAddr) {
        let socket = match UdpSocket::bind(addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("❌ TPU: could not bind UDP {} — {}", addr, e);
                return;
            }
        };

        info!("📡 TPU listening on UDP {} ({} workers, QoS: {}/s/ip)",
            addr, NUM_WORKERS, QOS_MAX_RPS);

        // Shared QoS table — IpAddr → window counter
        let qos: Arc<DashMap<std::net::IpAddr, IpState>> = Arc::new(DashMap::new());

        let gulf_stream = Arc::clone(&self.gulf_stream);
        let pipeline    = Arc::clone(&self.pipeline);
        let blockchain  = Arc::new(self.blockchain);
        let used_nonces = self.used_nonces;
        let poh_shared  = self.poh;

        for _ in 0..NUM_WORKERS {
            let sock    = socket.clone();
            let qos     = qos.clone();
            let gs      = gulf_stream.clone();
            let pl      = pipeline.clone();
            let bc      = blockchain.clone();
            let nn      = used_nonces.clone();
            let poh     = poh_shared.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PACKET_SIZE];

                loop {
                    let (size, peer) = match sock.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => { error!("❌ TPU recv: {}", e); continue; }
                    };

                    // ── 1. Stake-Weighted QoS: per-IP rate limiting ───────────
                    let ip = peer.ip();
                    let t  = Instant::now();
                    let allowed = {
                        let mut st = qos.entry(ip).or_insert_with(|| IpState {
                            count: 0,
                            window_start: t,
                        });
                        if st.window_start.elapsed().as_secs() >= 1 {
                            st.count = 0;
                            st.window_start = t;
                        }
                        st.count += 1;
                        st.count <= QOS_MAX_RPS
                    };
                    if !allowed { continue; } // silent drop — no CPU waste logging spam

                    // ── 2. Bincode deserialize ────────────────────────────────
                    let pkt: TpuPacket = match bincode::deserialize(&buf[..size]) {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("⚠ TPU malformed packet from {} ({} bytes)", peer, size);
                            continue;
                        }
                    };

                    // ── 3. Chain ID validation ────────────────────────────────
                    if pkt.chain_id != EXPECTED_CHAIN_ID {
                        warn!("⚠ TPU wrong chain_id {} from {}", pkt.chain_id, peer);
                        continue;
                    }

                    // ── 4. Basic field sanity ─────────────────────────────────
                    if pkt.from.is_empty() || pkt.to.is_empty() || pkt.amount == 0 {
                        warn!("⚠ TPU invalid fields from {}", peer);
                        continue;
                    }

                    // ── 5. TTL: reject stale transactions (> 60s) ────────────
                    let now_unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now_unix.saturating_sub(pkt.timestamp) > 60 {
                        warn!("⚠ TPU expired tx from {} (age={}s)", peer,
                            now_unix.saturating_sub(pkt.timestamp));
                        continue;
                    }

                    // ── 6. Ed25519 signature verification ────────────────────
                    // Canonical binary message (89 bytes, no JSON overhead):
                    //   chain_id(1) || from_bs58_utf8(var) || to_bs58_utf8(var)
                    //   || amount_le(8) || timestamp_le(8) || nonce_utf8(var)
                    // Separated by '|' to avoid ambiguity between fields.
                    let mut msg = Vec::with_capacity(128);
                    msg.push(pkt.chain_id);
                    msg.extend_from_slice(pkt.from.as_bytes());
                    msg.push(b'|');
                    msg.extend_from_slice(pkt.to.as_bytes());
                    msg.push(b'|');
                    msg.extend_from_slice(&pkt.amount.to_le_bytes());
                    msg.push(b'|');
                    msg.extend_from_slice(&pkt.timestamp.to_le_bytes());
                    msg.push(b'|');
                    msg.extend_from_slice(pkt.nonce.as_bytes());

                    let pubkey_bytes = match hex::decode(&pkt.public_key) {
                        Ok(b) if b.len() == 32 => b,
                        _ => { warn!("⚠ TPU bad pubkey from {}", peer); continue; }
                    };
                    let sig_bytes = match hex::decode(&pkt.signature) {
                        Ok(b) if b.len() == 64 => b,
                        _ => { warn!("⚠ TPU bad sig from {}", peer); continue; }
                    };
                    let pk_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
                        Ok(a) => a,
                        Err(_) => { warn!("⚠ TPU pk slice err from {}", peer); continue; }
                    };
                    let vk = match VerifyingKey::from_bytes(pk_arr) {
                        Ok(k) => k,
                        Err(_) => { warn!("⚠ TPU invalid vk from {}", peer); continue; }
                    };
                    let sig_arr: &[u8; 64] = match sig_bytes.as_slice().try_into() {
                        Ok(a) => a,
                        Err(_) => { warn!("⚠ TPU sig slice err from {}", peer); continue; }
                    };
                    if vk.verify(&msg, &Signature::from_bytes(sig_arr)).is_err() {
                        warn!("⚠ TPU INVALID SIGNATURE for {} from {}", pkt.from, peer);
                        continue;
                    }
                    // Verify public key matches claimed sender (prevents key substitution)
                    let derived = bs58::encode(vk.to_bytes()).into_string();
                    if derived != pkt.from {
                        warn!("⚠ TPU pubkey/address mismatch for {} from {}", pkt.from, peer);
                        continue;
                    }

                    // ── 7. Replay protection (atomic via entry API) ──────────
                    let nonce_key = format!("tpu:{}:{}", pkt.from, pkt.nonce);
                    match nn.entry(nonce_key) {
                        dashmap::mapref::entry::Entry::Occupied(_) => {
                            warn!("⚠ TPU replay attack detected from {}", peer);
                            continue;
                        }
                        dashmap::mapref::entry::Entry::Vacant(v) => {
                            v.insert(now_unix);
                        }
                    }

                    // ── 8. Balance check ──────────────────────────────────────
                    let balance_lamports = bc.get_balance_lamports(&pkt.from);
                    if balance_lamports < pkt.amount {
                        warn!("⚠ TPU insufficient balance {} < {} lamports for {}",
                            balance_lamports, pkt.amount, pkt.from);
                        continue;
                    }

                    // ── 9. Build & dispatch transaction ───────────────────────
                    // pkt.amount is already u64 lamports — pass through directly

                    let tx_type = match pkt.tx_type.as_deref() {
                        Some("SwapUsdcForBb") => TransactionType::SwapUsdcForBb,
                        Some("SwapBbForUsdc") => TransactionType::SwapBbForUsdc,
                        _ => TransactionType::Transfer,
                    };
                    let mut tx = RuntimeTx::new(
                        pkt.from.clone(), pkt.to.clone(), pkt.amount, tx_type
                    );
                    tx.nonce = pkt.priority;
                    let tx_id = tx.id.clone();

                    if let Err(e) = gs.submit(tx.clone()) {
                        warn!("⚠ TPU GulfStream submit error for {}: {}", pkt.from, e);
                        continue;
                    }

                    // Stamp tx_id into PoH BEFORE execution — ordering invariant.
                    // The tx_id is recorded in the hash chain now; the SVM executes it later.
                    poh.write().queue_transaction(tx_id.clone());

                    let packet = PipelinePacket::new(
                        tx_id, pkt.from.clone(), pkt.to.clone(), pkt.amount
                    );
                    let _ = pl.submit(packet).await;

                    info!("✅ TPU {}…→{}… {} lamports ({:.5} BB) via {}",
                        &pkt.from[..8.min(pkt.from.len())],
                        &pkt.to[..8.min(pkt.to.len())],
                        pkt.amount, pkt.amount as f64 / 100_000.0, peer);
                }
            });
        }

        // ── Background nonce pruner ───────────────────────────────────────
        // The used_nonces table is an unbounded DashMap that grows forever without
        // this pruner. Drop any nonce entry inserted more than 120 seconds ago —
        // well past the 60-second TTL, so no valid replay window is affected.
        let nonces_prune = used_nonces.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let cutoff = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(120);
                nonces_prune.retain(|_, inserted_at| *inserted_at > cutoff);
            }
        });
    }
}
