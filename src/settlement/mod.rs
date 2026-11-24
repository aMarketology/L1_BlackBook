//! Settlement Service — gRPC server for L2↔L1 balance streaming & bridge sync
//!
//! Active RPCs:
//!   - SubscribeBalances: L2 subscribes to per-block BB balance updates.
//!   - GetBalance:        Single-address balance lookup for cache-miss lazy fills.
//!   - SyncBridge:        Heartbeat / slot monitoring.
//!
//! Legacy per-contest escrow RPCs (`InitContestReserve`, `SubmitMerkleRoot`,
//! `SubmitPendingRoot`, `GetContestStatus`, `DistributePayouts`) return
//! `Status::unimplemented` — all L2 fund locking and settlement exits use the
//! atomic rollup vault (`/rollup/L2/lock_bb`, `/submit_root`, `/exit`).

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::storage::ConcurrentBlockchain;

// Import generated protobuf types
pub mod proto {
    tonic::include_proto!("settlement");
}

use proto::settlement_service_server::{SettlementService, SettlementServiceServer};
use proto::{
    SubscribeBalancesRequest, BalanceUpdate,
    GetBalanceRequest, GetBalanceResponse,
    InitContestReserveRequest, InitContestReserveResponse,
    MerkleRootSubmission, MerkleRootResponse,
    SubmitPendingRootRequest, SubmitPendingRootResponse,
    ContestStatusRequest, ContestStatusResponse,
    SyncBridgeRequest, SyncBridgeResponse,
    DistributePayoutsRequest, DistributePayoutsResponse,
};

// ============================================================================
// BALANCE UPDATE EVENT
// ============================================================================

/// Internal event broadcast after each block finalization.
/// One event per unique BB address touched in a block.
/// Idempotency key for L2: (address, slot) — guaranteed unique per block.
/// `delta_lamports` is always 0 from L1; L2 computes it from its own cached value.
#[derive(Clone, Debug)]
pub struct BalanceUpdateEvent {
    pub address: String,
    pub new_balance_lamports: u64,
    pub delta_lamports: i64,
    pub slot: u64,
    pub timestamp: u64,
    pub block_hash: String,
}

// ============================================================================
// SERVICE STRUCT
// ============================================================================

pub struct BlackBookSettlementService {
    pub blockchain: ConcurrentBlockchain,
    pub current_slot: Arc<std::sync::atomic::AtomicU64>,
    pub l2_sequencer_allowlist: std::collections::HashSet<String>,
    /// Broadcast channel for per-block balance update events (L2 streaming feed).
    pub balance_event_tx: broadcast::Sender<BalanceUpdateEvent>,
    start_time: Instant,
}

impl BlackBookSettlementService {
    pub fn new(
        blockchain: ConcurrentBlockchain,
        current_slot: Arc<std::sync::atomic::AtomicU64>,
        l2_sequencer_allowlist: std::collections::HashSet<String>,
        balance_event_tx: broadcast::Sender<BalanceUpdateEvent>,
    ) -> Self {
        Self {
            blockchain,
            current_slot,
            l2_sequencer_allowlist,
            balance_event_tx,
            start_time: Instant::now(),
        }
    }

    /// Convert to a tonic gRPC server
    pub fn into_server(self) -> SettlementServiceServer<Self> {
        SettlementServiceServer::new(self)
    }
}

// ============================================================================
// gRPC IMPLEMENTATION
// ============================================================================

/// Type alias for the server-streaming balance subscription.
type BalanceStream = Pin<Box<dyn Stream<Item = Result<BalanceUpdate, Status>> + Send>>;

#[tonic::async_trait]
impl SettlementService for BlackBookSettlementService {
    type SubscribeBalancesStream = BalanceStream;

    // ── SubscribeBalances ─────────────────────────────────────────────────
    //
    // L2 opens this once at startup. L1 pushes one BalanceUpdate per (address,
    // slot) for every BB address whose balance changed in a finalized block.
    // Auth: Ed25519 over b"SUBSCRIBE_BALANCES" || timestamp.to_le_bytes(8).
    // Fail-closed: if `l2_sequencer_allowlist` is empty, reject with `unavailable`.

    async fn subscribe_balances(
        &self,
        request: Request<SubscribeBalancesRequest>,
    ) -> Result<Response<Self::SubscribeBalancesStream>, Status> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        if self.l2_sequencer_allowlist.is_empty() {
            return Err(Status::unavailable(
                "L2 sequencer allowlist is not configured on this L1 node"
            ));
        }

        let req = request.into_inner();

        if req.client_pubkey.len() != 32 {
            return Err(Status::invalid_argument("client_pubkey must be 32 bytes"));
        }
        if req.client_sig.len() != 64 {
            return Err(Status::invalid_argument("client_sig must be 64 bytes"));
        }

        // ── Allowlist check (fail-closed) ─────────────────────────────────
        let pubkey_hex = hex::encode(&req.client_pubkey);
        if !self.l2_sequencer_allowlist.contains(&pubkey_hex) {
            return Err(Status::permission_denied(format!(
                "Client pubkey {} is not in the L2 sequencer allowlist", pubkey_hex
            )));
        }

        // ── Timestamp freshness (±60s window) ─────────────────────────────
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(req.timestamp) > 60 {
            return Err(Status::unauthenticated(
                "Timestamp outside 60s freshness window"
            ));
        }

        // ── Ed25519 signature verification ────────────────────────────────
        // Canonical message: b"SUBSCRIBE_BALANCES" || timestamp.to_le_bytes(8)
        let verifying_key = VerifyingKey::from_bytes(
            req.client_pubkey.as_slice().try_into()
                .map_err(|_| Status::invalid_argument("client_pubkey must be 32 bytes"))?
        ).map_err(|e| Status::internal(format!("Bad client pubkey: {}", e)))?;

        let mut msg: Vec<u8> = Vec::with_capacity(26);
        msg.extend_from_slice(b"SUBSCRIBE_BALANCES");
        msg.extend_from_slice(&req.timestamp.to_le_bytes());

        let sig = Signature::from_bytes(
            req.client_sig.as_slice().try_into()
                .map_err(|_| Status::invalid_argument("client_sig must be 64 bytes"))?
        );
        verifying_key.verify(&msg, &sig)
            .map_err(|_| Status::unauthenticated("Signature verification failed"))?;

        info!("📡 L2 sequencer {}… subscribed to balance stream", &pubkey_hex[..16]);

        let address_filter: std::collections::HashSet<String> =
            req.address_filter.into_iter().collect();
        let mut rx = self.balance_event_tx.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(evt) => {
                        if !address_filter.is_empty() && !address_filter.contains(&evt.address) {
                            continue;
                        }
                        yield Ok(BalanceUpdate {
                            address: evt.address,
                            new_balance_lamports: evt.new_balance_lamports,
                            delta_lamports: evt.delta_lamports,
                            slot: evt.slot,
                            timestamp: evt.timestamp,
                            block_hash: evt.block_hash,
                        });
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            "L2 balance stream lagged by {} event(s) — L2 should \
                             flush cache and call GetBalance on next market-entry miss",
                            n
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };

        Ok(Response::new(Box::pin(stream) as Self::SubscribeBalancesStream))
    }

    // ── GetBalance ────────────────────────────────────────────────────────

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        let req = request.into_inner();
        if req.address.is_empty() {
            return Err(Status::invalid_argument("address is required"));
        }
        let balance_lamports = self.blockchain.get_balance_lamports(&req.address);
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        Ok(Response::new(GetBalanceResponse {
            address: req.address,
            balance_lamports,
            current_slot,
        }))
    }

    // ── SyncBridge ────────────────────────────────────────────────────────

    async fn sync_bridge(
        &self,
        request: Request<SyncBridgeRequest>,
    ) -> Result<Response<SyncBridgeResponse>, Status> {
        let req = request.into_inner();
        let latest_slot = self.current_slot.load(Ordering::Relaxed);
        let uptime_secs = self.start_time.elapsed().as_secs();
        info!("💓 SyncBridge from node={} slot={} uptime={}s", req.node_id, latest_slot, uptime_secs);
        Ok(Response::new(SyncBridgeResponse {
            node_id: req.node_id,
            latest_slot,
            uptime_secs,
        }))
    }

    // ── Removed Legacy Per-Contest Escrow RPCs ────────────────────────────

    async fn init_contest_reserve(
        &self,
        _request: Request<InitContestReserveRequest>,
    ) -> Result<Response<InitContestReserveResponse>, Status> {
        Err(Status::unimplemented(
            "Per-contest escrow removed; use /rollup/L2/* atomic lock/exit vault"
        ))
    }

    async fn submit_merkle_root(
        &self,
        _request: Request<MerkleRootSubmission>,
    ) -> Result<Response<MerkleRootResponse>, Status> {
        Err(Status::unimplemented(
            "Per-contest escrow removed; use POST /rollup/L2/submit_root"
        ))
    }

    async fn submit_pending_root(
        &self,
        _request: Request<SubmitPendingRootRequest>,
    ) -> Result<Response<SubmitPendingRootResponse>, Status> {
        Err(Status::unimplemented(
            "Legacy gRPC pending root removed; use POST /oracle/submit-pending-root or /rollup/L2/submit_root"
        ))
    }

    async fn get_contest_status(
        &self,
        _request: Request<ContestStatusRequest>,
    ) -> Result<Response<ContestStatusResponse>, Status> {
        Err(Status::unimplemented(
            "Per-contest escrow removed; use GET /rollup/L2/roots/:batch_id and /da/:market_id"
        ))
    }

    async fn distribute_payouts(
        &self,
        _request: Request<DistributePayoutsRequest>,
    ) -> Result<Response<DistributePayoutsResponse>, Status> {
        Err(Status::unimplemented(
            "Per-contest escrow removed; use POST /rollup/L2/exit"
        ))
    }
}
