//! Turbine Tick Streaming — per-tick PoH broadcast to Reader nodes.
//!
//! The Writer node emits one `TickShred` per PoH tick (~9.375ms) via UDP on
//! port 8004.  Reader nodes receive these shreds and re-derive the SHA-256
//! chain in real-time, verifying each tick *while the slot is still being
//! produced* rather than waiting for the full-block gRPC relay.
//!
//! Production invariants enforced here:
//!
//! * **Bounded channel** (10 000 capacity) between the PoH OS thread and this
//!   async broadcaster.  If the broadcaster is ever stalled, `try_send` fails
//!   silently and the shred is dropped — the PoH clock **never blocks** and the
//!   Writer node **never OOMs**.  Readers fall back to the existing gRPC
//!   full-block relay for any ticks they miss.
//!
//! * **Heartbeat TTL**: Readers that have not sent a heartbeat within
//!   `READER_TTL_SECS` are pruned from the registry by a background task that
//!   runs every 30 seconds.  The HTTP surface is two thin endpoints:
//!   `POST /turbine/register` and `POST /turbine/heartbeat`.
//!
//! * **Best-effort UDP**: no ACK, no retransmit, no ordered delivery.  Shreds
//!   are small (~200 bytes) and sent as single datagrams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::poh_service::TickShred;

// ── Constants ─────────────────────────────────────────────────────────────────

/// UDP port for PoH tick shred broadcasting.
/// Kept separate from the TPU ingest port (8003) to avoid mixing bincode formats.
pub const TURBINE_TICK_PORT: u16 = 8004;

/// Bounded channel capacity between the PoH OS thread and `TurbineTickService`.
/// At 64 ticks/slot × ~1.7 slots/sec = ~107 ticks/sec.  10 000 gives ~93s of
/// headroom before drops begin — vastly more than any reasonable stall window.
pub const TICK_CHANNEL_CAPACITY: usize = 10_000;

/// Seconds without a heartbeat before a Reader is pruned from the registry.
pub const READER_TTL_SECS: u64 = 60;

// ── ReaderRecord ──────────────────────────────────────────────────────────────

/// Registry entry for a connected Reader node.
#[derive(Debug, Clone)]
pub struct ReaderRecord {
    /// UDP address the Writer sends TickShreds to.
    pub udp_addr: SocketAddr,
    /// Unix timestamp (seconds) of the last registration or heartbeat.
    pub last_seen: u64,
}

// ── TurbineTickService (Writer-side broadcaster) ──────────────────────────────

/// Receives `TickShred` events from the PoH clock thread and UDP-broadcasts
/// them to all registered Reader nodes on port `TURBINE_TICK_PORT`.
pub struct TurbineTickService {
    tick_rx: mpsc::Receiver<TickShred>,
    /// Shared with the HTTP `/turbine/register` and `/turbine/heartbeat` handlers.
    pub readers: Arc<DashMap<String, ReaderRecord>>,
}

impl TurbineTickService {
    /// Create a new service.
    ///
    /// The caller is responsible for spawning the reader pruner via
    /// [`spawn_reader_pruner`] with the same `readers` handle.
    pub fn new(
        tick_rx: mpsc::Receiver<TickShred>,
        readers: Arc<DashMap<String, ReaderRecord>>,
    ) -> Self {
        Self { tick_rx, readers }
    }

    /// Run the broadcaster.  Binds UDP on `0.0.0.0:TURBINE_TICK_PORT`.
    /// This is a long-running async task — spawn with `tokio::spawn`.
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

        info!(
            "📡 TurbineTickService bound on UDP {} (capacity={})",
            bind_addr, TICK_CHANNEL_CAPACITY
        );

        let mut shreds_sent: u64 = 0;

        while let Some(shred) = self.tick_rx.recv().await {
            let bytes = match bincode::serialize(&shred) {
                Ok(b) => b,
                Err(e) => {
                    warn!("TurbineTickService: serialize error: {}", e);
                    continue;
                }
            };

            for entry in self.readers.iter() {
                let addr = entry.value().udp_addr;
                if let Err(e) = socket.send_to(&bytes, addr).await {
                    // Transient errors (ICMP unreachable, etc.) are expected.
                    // Do NOT remove the reader — let the heartbeat pruner handle TTL.
                    warn!("TurbineTickService: send_to {} failed: {}", addr, e);
                }
            }

            shreds_sent += 1;
            // Periodic log every 1000 slot-end shreds (~600 s)
            if shred.is_slot_end && shreds_sent % 1_000 == 0 {
                info!(
                    "⛓  TurbineTickService: {} slot-end shreds sent, {} active readers",
                    shreds_sent,
                    self.readers.len()
                );
            }
        }
    }
}

// ── TurbineTickReceiver (Reader-side verifier) ────────────────────────────────

/// Listens on UDP port `TURBINE_TICK_PORT` and verifies the SHA-256 PoH chain
/// in real-time as ticks arrive from the Writer.
///
/// A chain-break logs a warning and leaves `expected_hash` unchanged so the
/// Reader continues trying the next tick.  The gRPC full-block relay
/// (`WriterRelayService`) handles slot-level catch-up.
pub struct TurbineTickReceiver {
    listen_addr: SocketAddr,
    /// Rolling tip of the verified SHA-256 chain.
    expected_hash: std::sync::Mutex<String>,
    /// SHA-256 iterations per tick entry — must match the Writer's
    /// `PoHConfig.hashes_per_tick` (default 12 500).
    hashes_per_tick: u64,
}

impl TurbineTickReceiver {
    pub fn new(
        listen_addr: SocketAddr,
        genesis_hash: String,
        hashes_per_tick: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            listen_addr,
            expected_hash: std::sync::Mutex::new(genesis_hash),
            hashes_per_tick,
        })
    }

    /// Run the receiver.  Binds UDP on `listen_addr`.
    /// This is a long-running async task — spawn with `tokio::spawn`.
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

        info!("👂 TurbineTickReceiver listening on UDP {}", self.listen_addr);

        // 4 KiB is more than enough for a TickShred (~200 bytes serialized).
        let mut buf = vec![0u8; 4096];

        loop {
            let size = match socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("TurbineTickReceiver recv error: {}", e);
                    continue;
                }
            };

            let shred: TickShred = match bincode::deserialize(&buf[..size]) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "TurbineTickReceiver: malformed shred ({} bytes): {}",
                        size, e
                    );
                    continue;
                }
            };

            if !self.verify_entry(&shred) {
                warn!(
                    "⚠️  PoH chain break at slot={} tick={} — hash mismatch. \
                     gRPC relay will resync this slot.",
                    shred.slot, shred.tick_index
                );
                // Leave expected_hash unchanged; the next valid tick will fix it
                // or the gRPC relay will provide the authoritative slot hash.
                continue;
            }

            // Advance the verified chain tip
            {
                let mut tip = self.expected_hash.lock().unwrap();
                *tip = shred.entry.hash.clone();
            }
        }
    }

    /// Replay the PoH hash derivation from the current expected tip and compare
    /// against the incoming entry's hash.
    fn verify_entry(&self, shred: &TickShred) -> bool {
        use sha2::{Digest, Sha256};

        let tip = {
            let guard = self.expected_hash.lock().unwrap();
            guard.clone()
        };
        let mut current = tip;

        // Step 1: replay hashes_per_tick SHA-256 iterations (the VDF)
        for _ in 0..self.hashes_per_tick {
            let mut h = Sha256::new();
            h.update(current.as_bytes());
            current = format!("{:x}", h.finalize());
        }

        // Step 2: mix in any transaction IDs that were stamped into this entry
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

// ── Heartbeat pruner ──────────────────────────────────────────────────────────

/// Spawns a background Tokio task that removes stale Reader nodes from the
/// registry every 30 seconds.  A Reader is considered stale when its
/// `last_seen` timestamp is older than `READER_TTL_SECS`.
pub fn spawn_reader_pruner(readers: Arc<DashMap<String, ReaderRecord>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = now_unix_secs();
            let before = readers.len();
            readers.retain(|_, rec| now.saturating_sub(rec.last_seen) < READER_TTL_SECS);
            let pruned = before.saturating_sub(readers.len());
            if pruned > 0 {
                info!(
                    "🧹 Turbine pruner: removed {} stale reader(s), {} active",
                    pruned,
                    readers.len()
                );
            }
        }
    });
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
