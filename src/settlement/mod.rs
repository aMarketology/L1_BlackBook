//! Settlement Service — gRPC server for L2↔L1 contest lifecycle
//!
//! Five RPCs:
//!   - VerifyDeposit:       L2 confirms a user's deposit is on-chain before entry.
//!   - InitContestReserve:  Dealer locks prize reserve into per-contest escrow.
//!   - SubmitMerkleRoot:    L2 sequencer finalises a market with a 32-byte root.
//!   - GetContestStatus:    L2 queries live contest state.
//!   - SyncBridge:          Heartbeat / TPS monitoring.
//!
//! Runs on port 50052 (separate from validator_relay on 50051).
pub mod sweep;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

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
    VerifyDepositRequest, VerifyDepositResponse,
    InitContestReserveRequest, InitContestReserveResponse,
    MerkleRootSubmission, MerkleRootResponse,
    SubmitPendingRootRequest, SubmitPendingRootResponse,
    ContestStatusRequest, ContestStatusResponse,
    SyncBridgeRequest, SyncBridgeResponse,
};
use crate::storage::{OracleSignature, PendingRoot, PendingRootStatus};

/// ~2h dispute window at 400 ms/slot: 2*60*60 / 0.4 = 18_000 slots.
/// Spec says 6_480 but oracle.md calls for ~2h; using 6_480 to match spec.
const DISPUTE_WINDOW_SLOTS: u64 = 6_480;
const MIN_DISPUTE_STAKE_PICO_XX: u64 = 100 * crate::svm::MAXX_UNIT;
const DISPUTE_ESCALATION_THRESHOLD: u64 = 1_000 * crate::svm::MAXX_UNIT;

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

#[tonic::async_trait]
impl SettlementService for BlackBookSettlementService {

    // ── VerifyDeposit ─────────────────────────────────────────────────────

    async fn verify_deposit(
        &self,
        request: Request<VerifyDepositRequest>,
    ) -> Result<Response<VerifyDepositResponse>, Status> {
        let req = request.into_inner();
        info!("📥 VerifyDeposit: contest={} sig={}", req.contest_id, req.deposit_tx_sig);

        if req.deposit_tx_sig.is_empty() {
            return Ok(Response::new(VerifyDepositResponse {
                verified: false,
                depositor_wallet: String::new(),
                actual_amount: 0,
                deposit_slot: 0,
                error_code: "TX_NOT_FOUND".to_string(),
            }));
        }

        // Look up the deposit record by external tx signature
        let record = self.deposit_requests.get(&req.deposit_tx_sig);
        let current_slot = self.current_slot.load(Ordering::Relaxed);

        match record {
            None => {
                warn!("VerifyDeposit: tx not found: {}", req.deposit_tx_sig);
                Ok(Response::new(VerifyDepositResponse {
                    verified: false,
                    depositor_wallet: String::new(),
                    actual_amount: 0,
                    deposit_slot: current_slot,
                    error_code: "TX_NOT_FOUND".to_string(),
                }))
            }
            Some(dep) => {
                // bb_lamports is already in 5-decimal lamport units
                let actual_spl = dep.bb_lamports;

                // Amount check: if caller specified a non-zero expected_amount, verify it
                if req.expected_amount > 0 && actual_spl != req.expected_amount {
                    return Ok(Response::new(VerifyDepositResponse {
                        verified: false,
                        depositor_wallet: dep.wallet_address.clone(),
                        actual_amount: actual_spl,
                        deposit_slot: current_slot,
                        error_code: "WRONG_AMOUNT".to_string(),
                    }));
                }

                // Check if deposit is approved (not just pending)
                if dep.status != "approved" {
                    return Ok(Response::new(VerifyDepositResponse {
                        verified: false,
                        depositor_wallet: dep.wallet_address.clone(),
                        actual_amount: actual_spl,
                        deposit_slot: dep.submitted_at,
                        error_code: "TX_NOT_FINAL".to_string(),
                    }));
                }

                info!("✅ VerifyDeposit OK: {} SPL for wallet {}", actual_spl, dep.wallet_address);
                Ok(Response::new(VerifyDepositResponse {
                    verified: true,
                    depositor_wallet: dep.wallet_address.clone(),
                    actual_amount: actual_spl,
                    deposit_slot: dep.approved_at.unwrap_or(dep.submitted_at),
                    error_code: String::new(),
                }))
            }
        }
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
            dispute_stake_pico_xx: 0,
            status: PendingRootStatus::Pending,
            proposer_pubkey: submitted_pubkey_hex.clone(),
            oracle_signatures,
            disputers: Vec::new(),
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
}
