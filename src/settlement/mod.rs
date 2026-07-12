//! Settlement Service — gRPC server for L2↔L1 contest lifecycle
//!
//! RPCs:
//!   - SubscribeBalances:   L2 subscribes to per-block balance updates (replaces VerifyDeposit).
//!   - GetBalance:          Single-address balance lookup for cache-miss lazy fills.
//!   - InitContestReserve:  Dealer locks prize reserve into per-contest escrow.
//!   - SubmitMerkleRoot:    L2 sequencer finalises a market with a 32-byte root.
//!   - GetContestStatus:    L2 queries live contest state.
//!   - SyncBridge:          Heartbeat / TPS monitoring.
//!
//! Runs on port 50052 (separate from validator_relay on 50051).
//!
//! Balance feed design:
//!   L2 keeps a local `Map<address, balance_lamports>` cache. It opens
//!   `SubscribeBalances` once at startup; L1 pushes one event per (address, slot)
//!   for each block that changed that address's BB balance. On reconnect, L2
//!   flushes its cache and lazily refills via `GetBalance` on the next cache miss.
//!   Idempotency key: (address, slot) — slot is ReDB-anchored, never resets.
pub mod sweep;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::poh_blockchain::BlockProducer;
use crate::storage::{ConcurrentBlockchain, ContestState, ContestStatus};
use crate::svm::escrow_vault_address_for;

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
    DistributePayoutsRequest, DistributePayoutsResponse, PayoutResult,
};
use crate::storage::{OracleSignature, PendingRoot, PendingRootStatus};

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

/// ~2h dispute window at 400 ms/slot: 2*60*60 / 0.4 = 18_000 slots.
/// Spec says 6_480 but oracle.md calls for ~2h; using 6_480 to match spec.
const DISPUTE_WINDOW_SLOTS: u64 = 6_480;
/// Minimum $BB lamports to open a dispute (100 BB = $10).
#[allow(dead_code)]
const MIN_DISPUTE_STAKE_BB_LAMPORTS: u64 = 100 * crate::svm::LAMPORTS_PER_BB;
/// Escalation threshold in $BB lamports (1 000 BB = $100).
#[allow(dead_code)]
const DISPUTE_ESCALATION_THRESHOLD_BB_LAMPORTS: u64 = 1_000 * crate::svm::LAMPORTS_PER_BB;

// ============================================================================
// SERVICE STRUCT
// ============================================================================

pub struct BlackBookSettlementService {
    pub blockchain: ConcurrentBlockchain,
    pub market_roots: Arc<dashmap::DashMap<String, [u8; 32]>>,
    pub contest_states: Arc<dashmap::DashMap<String, ContestState>>,
    pub current_slot: Arc<std::sync::atomic::AtomicU64>,
    pub l2_sequencer_pubkey: String,
    pub l2_sequencer_allowlist: std::collections::HashSet<String>,
    pub block_producer: Arc<BlockProducer>,
    pub deposit_requests: Arc<dashmap::DashMap<String, crate::storage::DepositRecord>>,
    /// Broadcast channel for per-block balance update events (L2 streaming feed).
    pub balance_event_tx: broadcast::Sender<BalanceUpdateEvent>,
    /// Shared double-payout guard (same `Arc` as the HTTP /escrow/withdraw path).
    /// Keyed by "{contest_id}:{wallet}" — prevents paying a winner twice across
    /// the dealer-push (DistributePayouts) and manual-withdraw paths.
    pub withdrawal_claims: Arc<dashmap::DashMap<String, bool>>,
    start_time: Instant,
}

impl BlackBookSettlementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blockchain: ConcurrentBlockchain,
        market_roots: Arc<dashmap::DashMap<String, [u8; 32]>>,
        contest_states: Arc<dashmap::DashMap<String, ContestState>>,
        current_slot: Arc<std::sync::atomic::AtomicU64>,
        l2_sequencer_pubkey: String,
        l2_sequencer_allowlist: std::collections::HashSet<String>,
        block_producer: Arc<BlockProducer>,
        deposit_requests: Arc<dashmap::DashMap<String, crate::storage::DepositRecord>>,
        balance_event_tx: broadcast::Sender<BalanceUpdateEvent>,
        withdrawal_claims: Arc<dashmap::DashMap<String, bool>>,
    ) -> Self {
        Self {
            blockchain,
            market_roots,
            contest_states,
            current_slot,
            l2_sequencer_pubkey,
            l2_sequencer_allowlist,
            block_producer,
            deposit_requests,
            balance_event_tx,
            withdrawal_claims,
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
    // On reconnect L2 must flush its cache; the broadcast buffer does not replay
    // missed slots — L2 uses GetBalance for cache-miss lazy fills instead.

    async fn subscribe_balances(
        &self,
        request: Request<SubscribeBalancesRequest>,
    ) -> Result<Response<Self::SubscribeBalancesStream>, Status> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        let req = request.into_inner();

        if req.client_pubkey.len() != 32 {
            return Err(Status::invalid_argument("client_pubkey must be 32 bytes"));
        }
        if req.client_sig.len() != 64 {
            return Err(Status::invalid_argument("client_sig must be 64 bytes"));
        }

        // ── Allowlist check ───────────────────────────────────────────────
        let pubkey_hex = hex::encode(&req.client_pubkey);
        if !self.l2_sequencer_allowlist.is_empty()
            && !self.l2_sequencer_allowlist.contains(&pubkey_hex)
        {
            return Err(Status::permission_denied(format!(
                "Client pubkey {} is not in the L2 sequencer allowlist", pubkey_hex
            )));
        }

        // ── Timestamp freshness (60s window) ──────────────────────────────
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
                        // L2 missed n events; log a warning. L2's gap-detection
                        // will see that addresses went stale and call GetBalance.
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
    //
    // Public read-only lookup. No auth. Used by L2 for cache-miss lazy fills
    // after a reconnect or lag event.

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

    // ── InitContestReserve ────────────────────────────────────────────────

    async fn init_contest_reserve(
        &self,
        request: Request<InitContestReserveRequest>,
    ) -> Result<Response<InitContestReserveResponse>, Status> {
        let req = request.into_inner();
        info!("🏦 InitContestReserve: contest={} dealer={} reserve={}", req.contest_id, req.dealer_address, req.bb_reserve);

        if req.contest_id.is_empty() || req.dealer_address.is_empty() {
            return Err(Status::invalid_argument("contest_id and dealer_address are required"));
        }
        if req.bb_reserve == 0 {
            return Err(Status::invalid_argument("bb_reserve must be > 0"));
        }

        // Check contest is not already Open or Settled
        if let Some(existing) = self.contest_states.get(&req.contest_id) {
            match existing.status {
                ContestStatus::Settled => {
                    return Ok(Response::new(InitContestReserveResponse {
                        confirmed: false,
                        l1_tx_hash: String::new(),
                        error_message: "Contest already settled".to_string(),
                    }));
                }
                ContestStatus::Open => {
                    return Ok(Response::new(InitContestReserveResponse {
                        confirmed: false,
                        l1_tx_hash: String::new(),
                        error_message: "Contest already initialized — duplicate InitContestReserve".to_string(),
                    }));
                }
                ContestStatus::Expired => {} // allow reinit on expired
            }
        }

        // Debit dealer → per-contest escrow vault PDA (not global vault)
        // Use debit_svm_lamports to avoid u64 → f64 → u64 precision loss.
        let escrow_addr = escrow_vault_address_for(&req.contest_id);
        if let Err(e) = self.blockchain.debit_svm_lamports(&req.dealer_address, req.bb_reserve) {
            return Ok(Response::new(InitContestReserveResponse {
                confirmed: false,
                l1_tx_hash: String::new(),
                error_message: format!("Dealer debit failed: {} (balance check passed?)", e),
            }));
        }
        let escrow_addr_credit = escrow_addr.clone();
        if let Err(e) = self.blockchain.credit_svm_lamports(&escrow_addr_credit, req.bb_reserve) {
            // Rollback
            let _ = self.blockchain.credit_svm_lamports(&req.dealer_address, req.bb_reserve);
            return Ok(Response::new(InitContestReserveResponse {
                confirmed: false,
                l1_tx_hash: String::new(),
                error_message: format!("Escrow credit failed: {}", e),
            }));
        }

        let l1_tx_hash = uuid::Uuid::new_v4().to_string();
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create Open ContestState
        let contest = ContestState {
            contest_id: req.contest_id.clone(),
            status: ContestStatus::Open,
            merkle_root: [0u8; 32],
            total_deposited: req.bb_reserve,
            total_claimed: 0,
            winner_count: 0,
            house_rake: 0,
            claim_deadline_slot: 0, // set when Settled
            l1_tx_hash: l1_tx_hash.clone(),
            last_l2_block: 0,
            created_at: now,
            vault_pda: escrow_addr.clone(),
            house_rake_swept_tx: None,
        };

        // ── PERSISTENCE GUARANTEE (ReDB FIRST) ──────────────────────────────
        if let Err(e) = self.blockchain.store_contest_state(&contest) {
            // Rollback the token transfer
            let _ = self.blockchain.credit_svm_lamports(&req.dealer_address, req.bb_reserve);
            let _ = self.blockchain.debit_svm_lamports(&escrow_addr, req.bb_reserve);
            return Ok(Response::new(InitContestReserveResponse {
                confirmed: false,
                l1_tx_hash: String::new(),
                error_message: format!("Failed to persist contest state to ReDB: {}", e),
            }));
        }
        // ── UPDATE CACHE ONLY AFTER SUCCESSFUL DURABLE WRITE ──────────────
        self.contest_states.insert(req.contest_id.clone(), contest);

        info!("✅ InitContestReserve OK: {} lamports locked for contest={} slot={}",
            req.bb_reserve, req.contest_id, current_slot);

        Ok(Response::new(InitContestReserveResponse {
            confirmed: true,
            l1_tx_hash,
            error_message: String::new(),
        }))
    }

    // ── SubmitMerkleRoot ──────────────────────────────────────────────────
    //
    // This is the canonical settlement path. It:
    //   1. Verifies the binary-packed Ed25519 sequencer signature
    //   2. Enforces the zero-sum invariant
    //   3. Stores the 32-byte root + ContestState in ReDB

    async fn submit_merkle_root(
        &self,
        request: Request<MerkleRootSubmission>,
    ) -> Result<Response<MerkleRootResponse>, Status> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        let req = request.into_inner();
        info!("📋 SubmitMerkleRoot: contest={} l2_block={}", req.contest_id, req.l2_block_number);

        // ── Validate ──────────────────────────────────────────────────────
        if req.contest_id.is_empty() {
            return Err(Status::invalid_argument("contest_id is required"));
        }
        if req.merkle_root.len() != 32 {
            return Err(Status::invalid_argument("merkle_root must be exactly 32 bytes"));
        }
        if req.sequencer_pubkey.len() != 32 {
            return Err(Status::invalid_argument("sequencer_pubkey must be 32 bytes"));
        }
        if req.sequencer_sig.len() != 64 {
            return Err(Status::invalid_argument("sequencer_sig must be 64 bytes"));
        }

        // ── Zero-sum invariant ────────────────────────────────────────────
        if req.total_deposited != req.total_payout.saturating_add(req.house_rake) {
            return Err(Status::invalid_argument(
                "zero-sum violated: total_deposited != total_payout + house_rake"
            ));
        }

        // ── Ed25519 signature verification (allowlist enforced) ────────────
        // The submitted sequencer_pubkey must be in the allowlist.
        let submitted_pubkey_hex = hex::encode(&req.sequencer_pubkey);
        if !self.l2_sequencer_allowlist.is_empty()
            && !self.l2_sequencer_allowlist.contains(&submitted_pubkey_hex)
        {
            return Err(Status::permission_denied(format!(
                "Sequencer pubkey {} is not in the allowlist", submitted_pubkey_hex
            )));
        }

        // Verify the Ed25519 signature over the canonical message
        {
            let verifying_key = VerifyingKey::from_bytes(
                req.sequencer_pubkey.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_pubkey must be 32 bytes"))?
            ).map_err(|e| Status::internal(format!("Bad sequencer key: {}", e)))?;

            let mut msg: Vec<u8> = Vec::with_capacity(req.contest_id.len() + 8 + 32);
            msg.extend_from_slice(req.contest_id.as_bytes());
            msg.extend_from_slice(&req.l2_block_number.to_le_bytes());
            msg.extend_from_slice(&req.merkle_root);

            let sig = Signature::from_bytes(
                req.sequencer_sig.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_sig must be 64 bytes"))?
            );
            verifying_key.verify(&msg, &sig)
                .map_err(|_| Status::unauthenticated("Sequencer signature verification failed"))?;
        }

        // ── Store root + ContestState ─────────────────────────────────────
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&req.merkle_root);

        // ── MONOTONICITY CHECK ────────────────────────────────────────────
        // Ensure incoming l2_block_number > stored last_l2_block to prevent
        // a buggy or malicious L2 sequencer from regressing chain state.
        if let Ok(Some(existing)) = self.blockchain.load_contest_state(&req.contest_id) {
            if req.l2_block_number <= existing.last_l2_block {
                return Err(Status::failed_precondition(format!(
                    "L2 block number must be strictly greater than previous submission: got {} <= stored {}",
                    req.l2_block_number, existing.last_l2_block
                )));
            }
        }

        const CLAIM_WINDOW_SLOTS: u64 = 6_480_000;
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let l1_tx_hash = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let contest = ContestState {
            contest_id: req.contest_id.clone(),
            status: ContestStatus::Settled,
            merkle_root: root_arr,
            total_deposited: req.total_deposited,
            total_claimed: 0,
            winner_count: req.winner_count,
            house_rake: req.house_rake,
            claim_deadline_slot: current_slot + CLAIM_WINDOW_SLOTS,
            l1_tx_hash: l1_tx_hash.clone(),
            last_l2_block: req.l2_block_number,
            created_at: now,
            vault_pda: crate::svm::escrow_vault_address_for(&req.contest_id),
            house_rake_swept_tx: None,
        };

        // ── PERSISTENCE GUARANTEE (ReDB FIRST) ──────────────────────────
        if let Err(e) = self.blockchain.store_escrow_market_root(&req.contest_id, &root_arr) {
            return Err(Status::internal(format!(
                "Failed to persist market root to ReDB: {}", e
            )));
        }
        if let Err(e) = self.blockchain.store_contest_state(&contest) {
            return Err(Status::internal(format!(
                "Failed to persist contest state to ReDB: {}", e
            )));
        }

        // ── UPDATE CACHE ONLY AFTER SUCCESSFUL DURABLE WRITE ────────────
        self.market_roots.insert(req.contest_id.clone(), root_arr);
        self.contest_states.insert(req.contest_id.clone(), contest);

        info!("✅ SubmitMerkleRoot OK: contest={} root={} deadline_slot={}",
            req.contest_id, hex::encode(root_arr), current_slot + CLAIM_WINDOW_SLOTS);

        Ok(Response::new(MerkleRootResponse {
            success: true,
            l1_tx_hash,
            l1_finalized_slot: current_slot,
            error_message: String::new(),
        }))
    }

    // ── SubmitPendingRoot ──────────────────────────────────────────────────
    //
    // Optimistic oracle path: root enters the dispute window before finalization.
    // Canonical signed message:
    //   contest_id_bytes ++ l2_block_number_le8 ++ merkle_root[32] ++ outcome_bytes

    async fn submit_pending_root(
        &self,
        request: Request<SubmitPendingRootRequest>,
    ) -> Result<Response<SubmitPendingRootResponse>, Status> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};

        let req = request.into_inner();
        info!("🔮 SubmitPendingRoot: contest={} outcome={} l2_block={}",
            req.contest_id, req.winning_outcome, req.l2_block_number);

        // ── Validate ──────────────────────────────────────────────────────
        if req.contest_id.is_empty() {
            return Err(Status::invalid_argument("contest_id is required"));
        }
        if req.merkle_root.len() != 32 {
            return Err(Status::invalid_argument("merkle_root must be exactly 32 bytes"));
        }
        if req.winning_outcome.is_empty() {
            return Err(Status::invalid_argument("winning_outcome is required"));
        }
        if req.sequencer_pubkey.len() != 32 {
            return Err(Status::invalid_argument("sequencer_pubkey must be 32 bytes"));
        }
        if req.sequencer_sig.len() != 64 {
            return Err(Status::invalid_argument("sequencer_sig must be 64 bytes"));
        }

        // ── Zero-sum invariant ────────────────────────────────────────────
        if req.total_deposited != req.total_payout.saturating_add(req.house_rake) {
            return Err(Status::invalid_argument(
                "zero-sum violated: total_deposited != total_payout + house_rake"
            ));
        }

        // ── Sequencer allowlist ───────────────────────────────────────────
        let submitted_pubkey_hex = hex::encode(&req.sequencer_pubkey);
        if !self.l2_sequencer_allowlist.is_empty()
            && !self.l2_sequencer_allowlist.contains(&submitted_pubkey_hex)
        {
            return Err(Status::permission_denied(format!(
                "Sequencer pubkey {} is not in the allowlist", submitted_pubkey_hex
            )));
        }

        // ── Ed25519 signature verification ────────────────────────────────
        // Canonical message: contest_id ++ l2_block_number_le8 ++ merkle_root[32] ++ outcome
        {
            let verifying_key = VerifyingKey::from_bytes(
                req.sequencer_pubkey.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_pubkey must be 32 bytes"))?)
                .map_err(|e| Status::internal(format!("Bad sequencer key: {}", e)))?;

            let mut msg: Vec<u8> = Vec::with_capacity(
                req.contest_id.len() + 8 + 32 + req.winning_outcome.len()
            );
            msg.extend_from_slice(req.contest_id.as_bytes());
            msg.extend_from_slice(&req.l2_block_number.to_le_bytes());
            msg.extend_from_slice(&req.merkle_root);
            msg.extend_from_slice(req.winning_outcome.as_bytes());

            let sig = Signature::from_bytes(
                req.sequencer_sig.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_sig must be 64 bytes"))?)
            ;
            verifying_key.verify(&msg, &sig)
                .map_err(|_| Status::unauthenticated("Sequencer signature verification failed"))?;
        }

        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let finalize_at_slot = current_slot + DISPUTE_WINDOW_SLOTS;

        // ── Guard: reject if a non-Discarded root already exists ─────────
        if let Some(existing) = self.blockchain.load_pending_root(&req.contest_id) {
            match existing.status {
                PendingRootStatus::Pending | PendingRootStatus::Disputed => {
                    return Err(Status::already_exists(format!(
                        "A pending root for contest {} is already in dispute window (finalize_at_slot={})",
                        req.contest_id, existing.finalize_at_slot
                    )));
                }
                PendingRootStatus::Finalized => {
                    return Err(Status::already_exists(format!(
                        "Contest {} is already finalized", req.contest_id
                    )));
                }
                PendingRootStatus::Discarded => {} // allow re-submission after discard
            }
        }

        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&req.merkle_root);

        // Convert proto OracleAttestationSig → storage OracleSignature
        let oracle_signatures: Vec<OracleSignature> = req.oracle_sigs.iter().map(|s| {
            OracleSignature {
                pubkey_hex: s.pubkey_hex.clone(),
                sig_hex: s.sig_hex.clone(),
            }
        }).collect();

        let pending = PendingRoot {
            market_id: req.contest_id.clone(),
            outcome: req.winning_outcome.clone(),
            merkle_root: root_arr,
            proposed_at_slot: current_slot,
            finalize_at_slot,
            dispute_stake_bb_lamports: 0,
            status: PendingRootStatus::Pending,
            proposer_pubkey: submitted_pubkey_hex.clone(),
            batch_id: 0,
            rollup_id: String::new(),
            oracle_signatures,
            disputers: Vec::new(),
            uphold_stake_lamports: 0,
            discard_stake_lamports: 0,
            voters: Vec::new(),
        };

        // ── PERSISTENCE: ReDB first ───────────────────────────────────────
        if let Err(e) = self.blockchain.store_pending_root(&pending) {
            return Err(Status::internal(format!(
                "Failed to persist pending root to ReDB: {}", e
            )));
        }

        info!("✅ SubmitPendingRoot stored: contest={} outcome={} finalize_at_slot={}",
            req.contest_id, req.winning_outcome, finalize_at_slot);

        Ok(Response::new(SubmitPendingRootResponse {
            success: true,
            market_id: req.contest_id,
            finalize_at_slot,
            error_message: String::new(),
        }))
    }

    // ── GetContestStatus ──────────────────────────────────────────────────

    async fn get_contest_status(
        &self,
        request: Request<ContestStatusRequest>,
    ) -> Result<Response<ContestStatusResponse>, Status> {
        let req = request.into_inner();

        if req.contest_id.is_empty() {
            return Err(Status::invalid_argument("contest_id is required"));
        }

        match self.contest_states.get(&req.contest_id) {
            None => Err(Status::not_found(format!("No contest found: {}", req.contest_id))),
            Some(c_ref) => {
                let mut c = c_ref.value().clone();
                drop(c_ref);
                let current_slot = self.current_slot.load(Ordering::Relaxed);
                // Auto-expire: transition Settled → Expired once the claim window closes
                if c.status == ContestStatus::Settled
                    && c.claim_deadline_slot > 0
                    && current_slot > c.claim_deadline_slot
                {
                    c.status = ContestStatus::Expired;
                    self.contest_states.insert(c.contest_id.clone(), c.clone());
                    let _ = self.blockchain.store_contest_state(&c);
                    info!("⏰ Contest {} expired at slot {}", c.contest_id, current_slot);
                }
                let status_str = match c.status {
                    ContestStatus::Open    => "OPEN",
                    ContestStatus::Settled => "SETTLED",
                    ContestStatus::Expired => "EXPIRED",
                };
                Ok(Response::new(ContestStatusResponse {
                    contest_id: c.contest_id.clone(),
                    status: status_str.to_string(),
                    total_deposited: c.total_deposited,
                    total_claimed: c.total_claimed,
                    merkle_root: c.merkle_root.to_vec(),
                    claim_deadline_slot: c.claim_deadline_slot,
                    l1_tx_hash: c.l1_tx_hash.clone(),
                }))
            }
        }
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

    // ── DistributePayouts ──────────────────────────────────────────────────
    //
    // Dealer-pushed automatic settlement. Mirrors the /escrow/withdraw claim
    // path, but the sequencer triggers it once for all winners instead of each
    // winner submitting their own tx.
    //
    // Security:
    //   1. Contest must be SETTLED (root already posted via SubmitMerkleRoot).
    //   2. Sequencer signs contest_id ++ STORED_root ++ timestamp_le8. L1 uses
    //      its OWN stored root, so the dealer can never sign against a forged
    //      root, and pubkey must be in the L2 sequencer allowlist.
    //   3. Each winner's payout is bound by a Merkle proof against the stored
    //      root (dealer can't alter amounts), and the wallet is inside the leaf
    //      hash (dealer can't redirect funds).
    //   4. The same `withdrawal_claims` guard as /escrow/withdraw prevents a
    //      winner from being paid twice across the push and manual paths.
    async fn distribute_payouts(
        &self,
        request: Request<DistributePayoutsRequest>,
    ) -> Result<Response<DistributePayoutsResponse>, Status> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        use sha2::{Sha256, Digest};

        let req = request.into_inner();
        info!("💸 DistributePayouts: contest={} winners={}", req.contest_id, req.payouts.len());

        // ── Validate ──────────────────────────────────────────────────────
        if req.contest_id.is_empty() {
            return Err(Status::invalid_argument("contest_id is required"));
        }
        if req.sequencer_pubkey.len() != 32 {
            return Err(Status::invalid_argument("sequencer_pubkey must be 32 bytes"));
        }
        if req.sequencer_sig.len() != 64 {
            return Err(Status::invalid_argument("sequencer_sig must be 64 bytes"));
        }
        if req.payouts.is_empty() {
            return Err(Status::invalid_argument("payouts must not be empty"));
        }

        // ── Load the settled contest + its STORED Merkle root ─────────────
        let contest = match self.contest_states.get(&req.contest_id) {
            Some(c) => c.clone(),
            None => match self.blockchain.load_contest_state(&req.contest_id) {
                Ok(Some(c)) => c,
                _ => return Err(Status::not_found("Contest not found")),
            },
        };
        if contest.status != ContestStatus::Settled {
            return Err(Status::failed_precondition(format!(
                "Contest not settled (status: {:?}) — root must be posted first",
                contest.status
            )));
        }
        let stored_root: [u8; 32] = contest.merkle_root;

        // ── Timestamp freshness (120s window) ─────────────────────────────
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if (now as i64 - req.timestamp).abs() > 120 {
            return Err(Status::unauthenticated("Timestamp outside 120s freshness window"));
        }

        // ── Sequencer allowlist ───────────────────────────────────────────
        let pubkey_hex = hex::encode(&req.sequencer_pubkey);
        if !self.l2_sequencer_allowlist.is_empty()
            && !self.l2_sequencer_allowlist.contains(&pubkey_hex)
        {
            return Err(Status::permission_denied(format!(
                "Sequencer pubkey {} is not in the allowlist", pubkey_hex
            )));
        }

        // ── Verify signature over contest_id ++ stored_root ++ timestamp_le8 ─
        {
            let verifying_key = VerifyingKey::from_bytes(
                req.sequencer_pubkey.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_pubkey must be 32 bytes"))?
            ).map_err(|e| Status::internal(format!("Bad sequencer key: {}", e)))?;

            let mut msg: Vec<u8> = Vec::with_capacity(req.contest_id.len() + 32 + 8);
            msg.extend_from_slice(req.contest_id.as_bytes());
            msg.extend_from_slice(&stored_root);
            msg.extend_from_slice(&req.timestamp.to_le_bytes());

            let sig = Signature::from_bytes(
                req.sequencer_sig.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("sequencer_sig must be 64 bytes"))?
            );
            verifying_key.verify(&msg, &sig)
                .map_err(|_| Status::unauthenticated("Sequencer signature verification failed"))?;
        }

        // ── Claim-window enforcement ──────────────────────────────────────
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        if contest.claim_deadline_slot > 0 && current_slot > contest.claim_deadline_slot {
            return Err(Status::failed_precondition("Claim window has expired for this contest"));
        }

        // Same escrow vault the /escrow/withdraw path pays from.
        #[allow(deprecated)]
        let escrow_addr = crate::svm::escrow_vault_address();

        // ── Per-winner: verify proof → guard → transfer ───────────────────
        let mut results: Vec<PayoutResult> = Vec::with_capacity(req.payouts.len());
        for leaf in req.payouts {
            // Decode wallet → raw 32-byte pubkey (must match L2 leaf format).
            let pubkey_raw_32: [u8; 32] = match bs58::decode(&leaf.wallet).into_vec() {
                Ok(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => {
                    results.push(PayoutResult {
                        wallet: leaf.wallet, success: false, tx_hash: String::new(),
                        error: "wallet must be a base58-encoded 32-byte pubkey".into(),
                    });
                    continue;
                }
            };

            // Leaf hash: SHA-256(pubkey_raw_32 ++ amount_bb.to_le_bytes(8)).
            let mut hasher = Sha256::new();
            hasher.update(pubkey_raw_32);
            hasher.update(leaf.amount_bb.to_le_bytes());
            let mut current: [u8; 32] = hasher.finalize().into();

            // Walk the proof — sorted-pair SHA-256 (smaller 32-byte hash first).
            let mut proof_valid = true;
            for sibling in &leaf.proof {
                if sibling.len() != 32 {
                    proof_valid = false;
                    break;
                }
                let mut sib = [0u8; 32];
                sib.copy_from_slice(sibling);
                let mut h = Sha256::new();
                if current <= sib {
                    h.update(current);
                    h.update(sib);
                } else {
                    h.update(sib);
                    h.update(current);
                }
                current = h.finalize().into();
            }
            if !proof_valid {
                results.push(PayoutResult {
                    wallet: leaf.wallet, success: false, tx_hash: String::new(),
                    error: "proof node must be exactly 32 bytes".into(),
                });
                continue;
            }
            if current != stored_root {
                results.push(PayoutResult {
                    wallet: leaf.wallet, success: false, tx_hash: String::new(),
                    error: "Invalid Merkle proof".into(),
                });
                continue;
            }

            // Double-claim guard (shared with /escrow/withdraw).
            let claim_key = format!("{}:{}", req.contest_id, leaf.wallet);
            if self.withdrawal_claims.contains_key(&claim_key) {
                results.push(PayoutResult {
                    wallet: leaf.wallet, success: false, tx_hash: String::new(),
                    error: "Already claimed".into(),
                });
                continue;
            }

            // amount_bb is in BB lamports (5 decimals, LAMPORTS_PER_BB = 100_000).
            // Pass directly — no unit conversion needed.
            let amount_lamports = leaf.amount_bb;
            if amount_lamports == 0 {
                results.push(PayoutResult {
                    wallet: leaf.wallet, success: false, tx_hash: String::new(),
                    error: "payout amount too small (< 1 lamport)".into(),
                });
                continue;
            }

            // Transfer escrow → winner and seal the claim in one atomic ReDB txn.
            match self.blockchain.atomic_escrow_claim_and_pay(
                &claim_key, &escrow_addr, &leaf.wallet, amount_lamports, now,
            ) {
                Ok(()) => {
                    self.withdrawal_claims.insert(claim_key.clone(), true);

                    // Update total_claimed (SPL units) on the ContestState.
                    if let Some(entry) = self.contest_states.get(&req.contest_id) {
                        let mut snap = entry.clone();
                        drop(entry);
                        snap.total_claimed = snap.total_claimed.saturating_add(leaf.amount_bb);
                        if self.blockchain.store_contest_state(&snap).is_ok() {
                            self.contest_states.insert(req.contest_id.clone(), snap);
                        }
                    }

                    let tx_hash = uuid::Uuid::new_v4().to_string();
                    info!("💸 payout {} lamports → {} (contest {})",
                        amount_lamports, leaf.wallet, req.contest_id);
                    results.push(PayoutResult {
                        wallet: leaf.wallet, success: true, tx_hash, error: String::new(),
                    });
                }
                Err(e) => {
                    results.push(PayoutResult {
                        wallet: leaf.wallet, success: false, tx_hash: String::new(),
                        error: format!("transfer failed: {}", e),
                    });
                }
            }
        }

        let all_success = results.iter().all(|r| r.success);
        Ok(Response::new(DistributePayoutsResponse {
            all_success,
            results,
            error_message: String::new(),
        }))
    }
}
