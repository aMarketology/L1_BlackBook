//! Turbine Tick Streaming — Phase 7A/7B/7C permissioned VIP mesh.
//!
//! The Writer node emits one `TickShred` per PoH tick (~9.375ms) over UDP on
//! port 8004.  Only nodes in the `ValidatorRegistry` whitelist receive shreds.
//!
//! Security layers applied in cheapest→costliest order on the Receiver:
//!
//! 1. **Source-IP gate (7B)** — `recv_from` drops packets whose source IP is
//!    not in the approved registry.  No data is ever parsed from unknown IPs.
//!
//! 2. **Signer-known check (7C)** — the `SignedTickShred.signer` pubkey must
//!    be in the registry.  Prevents impersonation from a whitelisted IP.
//!
//! 3. **Ed25519 signature verify (7C)** — the writer's signature over the raw
//!    shred bytes is verified before any PoH math.
//!
//! 4. **PoH chain verify** — SHA-256 replay confirms the hash chain integrity.
//!
//! The Writer signs in the async broadcaster thread, keeping the PoH OS thread
//! fully crypto-free so tick rate is never affected.
//!
//! `POST /turbine/register` and `POST /turbine/heartbeat` have been removed
//! (Phase 7A hard cutover).  The registry is static, loaded at startup from
//! `config.toml` or `APPROVED_VALIDATORS` env var.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::poh_service::TickShred;
use super::validator_registry::ValidatorRegistry;

// ── Constants ─────────────────────────────────────────────────────────────────

/// UDP port for PoH tick shred broadcasting.
pub const TURBINE_TICK_PORT: u16 = 8004;

/// Bounded channel capacity between the PoH OS thread and `TurbineTickService`.
pub const TICK_CHANNEL_CAPACITY: usize = 10_000;

// ── SignedTickShred (7C wire format) ──────────────────────────────────────────

/// Wire format for a signed PoH tick shred.
///
/// The receiver verifies the Ed25519 signature over `shred_bytes` before
/// deserializing the inner `TickShred`.  This means any tampering of the
/// payload is caught before PoH math runs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedTickShred {
    /// bincode-serialized [`TickShred`].
    pub shred_bytes: Vec<u8>,
    /// Ed25519 pubkey of the signer (32 bytes, must be in `ValidatorRegistry`).
    pub signer: Vec<u8>,
    /// Ed25519 signature over `shred_bytes` (64 bytes).
    pub signature: Vec<u8>,
}

// ── TurbineTickService (Writer-side broadcaster) ──────────────────────────────

/// Receives `TickShred` events from the PoH clock thread, signs them, and
/// UDP-broadcasts the `SignedTickShred` to every node in the registry.
pub struct TurbineTickService {
    tick_rx: mpsc::Receiver<TickShred>,
    registry: Arc<ValidatorRegistry>,
    signing_key: Arc<SigningKey>,
}

impl TurbineTickService {
    pub fn new(
        tick_rx: mpsc::Receiver<TickShred>,
        registry: Arc<ValidatorRegistry>,
        signing_key: Arc<SigningKey>,
    ) -> Self {
        Self { tick_rx, registry, signing_key }
    }

    /// Run the broadcaster.  Binds UDP on `0.0.0.0:TURBINE_TICK_PORT`.
    /// Long-running async task — spawn with `tokio::spawn`.
    pub async fn run(mut self) {
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", TURBINE_TICK_PORT)
            .parse()
            .expect("valid turbine tick bind addr");

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("❌ TurbineTickService: could not bind UDP {} — {}", bind_addr, e);
                return;
            }
        };

        let signer_pubkey = self.signing_key.verifying_key().to_bytes().to_vec();

        info!(
            "📡 TurbineTickService bound on UDP {} — {} approved target(s), signer={}",
            bind_addr,
            self.registry.len(),
            hex::encode(&signer_pubkey[..8])
        );

        if self.registry.is_empty() {
            warn!("⚠️  TurbineTickService: registry is empty — shreds will not be propagated");
        }

        let mut shreds_sent: u64 = 0;

        while let Some(shred) = self.tick_rx.recv().await {
            // Serialize the inner shred.
            let shred_bytes = match bincode::serialize(&shred) {
                Ok(b) => b,
                Err(e) => {
                    warn!("TurbineTickService: serialize TickShred error: {}", e);
                    continue;
                }
            };

            // Sign the raw shred bytes (7C).
            let sig: ed25519_dalek::Signature = self.signing_key.sign(&shred_bytes);

            let signed = SignedTickShred {
                shred_bytes,
                signer: signer_pubkey.clone(),
                signature: sig.to_bytes().to_vec(),
            };

            let wire_bytes = match bincode::serialize(&signed) {
                Ok(b) => b,
                Err(e) => {
                    warn!("TurbineTickService: serialize SignedTickShred error: {}", e);
                    continue;
                }
            };

            // Broadcast to all approved targets.
            for addr in self.registry.udp_targets() {
                if let Err(e) = socket.send_to(&wire_bytes, addr).await {
                    warn!("TurbineTickService: send_to {} failed: {}", addr, e);
                }
            }

            shreds_sent += 1;
            if shred.is_slot_end && shreds_sent % 1_000 == 0 {
                info!(
                    "⛓  TurbineTickService: {} slot-end shreds sent to {} target(s)",
                    shreds_sent,
                    self.registry.len()
                );
            }
        }
    }
}

// ── TurbineTickReceiver (Reader-side verifier) ────────────────────────────────

/// Listens on UDP `TURBINE_TICK_PORT`, enforces 7B IP gate + 7C signature
/// verify, then validates the PoH chain in real-time.
pub struct TurbineTickReceiver {
    listen_addr: SocketAddr,
    /// Rolling tip of the verified SHA-256 chain.
    expected_hash: std::sync::Mutex<String>,
    /// SHA-256 iterations per tick entry — must match the Writer's config.
    hashes_per_tick: u64,
    registry: Arc<ValidatorRegistry>,
}

impl TurbineTickReceiver {
    pub fn new(
        listen_addr: SocketAddr,
        genesis_hash: String,
        hashes_per_tick: u64,
        registry: Arc<ValidatorRegistry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            listen_addr,
            expected_hash: std::sync::Mutex::new(genesis_hash),
            hashes_per_tick,
            registry,
        })
    }

    /// Run the receiver.  Long-running async task — spawn with `tokio::spawn`.
    pub async fn run(self: Arc<Self>) {
        let socket = match UdpSocket::bind(self.listen_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "❌ TurbineTickReceiver: could not bind {} — {}",
                    self.listen_addr, e
                );
                return;
            }
        };

        info!(
            "👂 TurbineTickReceiver listening on UDP {} ({} approved source(s))",
            self.listen_addr,
            self.registry.len()
        );

        // Buffer sized for a SignedTickShred (~500 bytes serialized).
        let mut buf = vec![0u8; 8192];

        loop {
            // Use recv_from to obtain the sender address for IP gating (7B).
            let (size, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!("TurbineTickReceiver recv_from error: {}", e);
                    continue;
                }
            };

            // ── Phase 7B: Source-IP gate ─────────────────────────────────────
            // Drop before ANY deserialization — protects against parse-bomb DoS.
            if !self.registry.is_approved_ip(&src.ip()) {
                // Intentionally silent — do not log per-packet to avoid log flooding.
                continue;
            }

            // ── Deserialize signed envelope ──────────────────────────────────
            let signed: SignedTickShred = match bincode::deserialize(&buf[..size]) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "TurbineTickReceiver: malformed envelope ({} bytes) from {}: {}",
                        size, src, e
                    );
                    continue;
                }
            };

            // ── Phase 7C: Signer-known check ─────────────────────────────────
            if signed.signer.len() != 32 {
                warn!("TurbineTickReceiver: bad signer length from {}", src);
                continue;
            }
            let mut signer_bytes = [0u8; 32];
            signer_bytes.copy_from_slice(&signed.signer);

            if self.registry.get_by_pubkey(&signer_bytes).is_none() {
                warn!(
                    "TurbineTickReceiver: unknown signer {} from {} — dropping",
                    hex::encode(&signed.signer[..8]),
                    src
                );
                continue;
            }

            // ── Phase 7C: Ed25519 signature verify ───────────────────────────
            let vk = match VerifyingKey::from_bytes(&signer_bytes) {
                Ok(k) => k,
                Err(e) => {
                    warn!("TurbineTickReceiver: invalid verifying key from {}: {}", src, e);
                    continue;
                }
            };

            if signed.signature.len() != 64 {
                warn!("TurbineTickReceiver: bad signature length from {}", src);
                continue;
            }
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&signed.signature);
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            if let Err(e) = vk.verify(&signed.shred_bytes, &sig) {
                warn!(
                    "TurbineTickReceiver: signature verification FAILED from {} — {}",
                    src, e
                );
                continue;
            }

            // ── Deserialize inner shred ──────────────────────────────────────
            let shred: TickShred = match bincode::deserialize(&signed.shred_bytes) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "TurbineTickReceiver: malformed inner TickShred from {}: {}",
                        src, e
                    );
                    continue;
                }
            };

            // ── PoH chain verification ───────────────────────────────────────
            if !self.verify_entry(&shred) {
                warn!(
                    "⚠️  PoH chain break at slot={} tick={} — hash mismatch (src={}). \
                     gRPC relay will resync.",
                    shred.slot, shred.tick_index, src
                );
                continue;
            }

            // Advance the verified chain tip.
            {
                let mut tip = self.expected_hash.lock().unwrap();
                *tip = shred.entry.hash.clone();
            }
        }
    }

    /// Replay the PoH hash derivation from the current expected tip.
    fn verify_entry(&self, shred: &TickShred) -> bool {
        use sha2::{Digest, Sha256};

        let tip = {
            let guard = self.expected_hash.lock().unwrap();
            guard.clone()
        };
        let mut current = tip;

        for _ in 0..self.hashes_per_tick {
            let mut h = Sha256::new();
            h.update(current.as_bytes());
            current = format!("{:x}", h.finalize());
        }

        if !shred.entry.transactions.is_empty() {
            let mut h = Sha256::new();
            h.update(current.as_bytes());
            for tx_id in &shred.entry.transactions {
                h.update(tx_id.as_bytes());
            }
            current = format!("{:x}", h.finalize());
        }

        current == shred.entry.hash
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Current Unix timestamp in seconds.
#[inline]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

