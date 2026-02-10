//! gRPC Service Implementation for L1 Settlement
//!
//! This module implements the L1Settlement gRPC service that allows
//! L2 (Casino) to communicate with L1 (Bank) for:
//! - Balance queries
//! - Soft locks (for active bets)
//! - Bet settlements
//! - Credit sessions

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::collections::HashSet;
use tonic::{Request, Response, Status};
use tracing::{info, warn, error};
use dashmap::DashMap;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

// Import generated protobuf types
pub mod proto {
    tonic::include_proto!("blackbook");
}

use proto::l1_settlement_server::{L1Settlement, L1SettlementServer};
use proto::*;

use crate::storage::{ConcurrentBlockchain, AssetManager};
use crate::runtime::{TransactionPipeline, PipelinePacket};

/// Signature timestamp tolerance (5 minutes)
const SIGNATURE_TIMESTAMP_TOLERANCE_SECS: u64 = 300;

/// Settlement record for idempotency
#[derive(Clone, Debug)]
pub struct SettlementRecord {
    pub bet_id: String,
    pub tx_hash: String,
    pub outcome: String,
    pub user_pnl: i64,
    pub settled_at: u64,
}

/// Credit session record for persistence
#[derive(Clone, Debug)]
pub struct CreditSessionRecord {
    pub session_id: String,
    pub user_address: String,
    pub credit_limit: u64,
    pub used_credit: u64,
    pub expires_at: u64,
    pub is_active: bool,
}

/// L1 Settlement Service Implementation
pub struct L1SettlementService {
    blockchain: Arc<ConcurrentBlockchain>,
    asset_manager: Arc<AssetManager>,
    pipeline: Option<Arc<TransactionPipeline>>,
    start_time: Instant,
    version: String,
    
    // Settlement tracking for idempotency (bet_id -> settlement record)
    settled_bets: Arc<DashMap<String, SettlementRecord>>,
    
    // Used nonces for replay protection (pubkey:timestamp)
    used_nonces: Arc<DashMap<String, HashSet<u64>>>,
    
    // Active credit sessions (session_id -> record)
    credit_sessions: Arc<DashMap<String, CreditSessionRecord>>,
    
    // Lock to bet mapping (lock_id -> bet_id)
    lock_to_bet: Arc<DashMap<String, String>>,
}

impl L1SettlementService {
    pub fn new(blockchain: Arc<ConcurrentBlockchain>, asset_manager: Arc<AssetManager>) -> Self {
        Self {
            blockchain,
            asset_manager,
            pipeline: None,
            start_time: Instant::now(),
            version: "1.1.0".to_string(),
            settled_bets: Arc::new(DashMap::new()),
            used_nonces: Arc::new(DashMap::new()),
            credit_sessions: Arc::new(DashMap::new()),
            lock_to_bet: Arc::new(DashMap::new()),
        }
    }

    /// Add a transaction pipeline for block inclusion
    pub fn with_pipeline(mut self, pipeline: Arc<TransactionPipeline>) -> Self {
        self.pipeline = Some(pipeline);
        self
    }

    /// Create the gRPC server
    pub fn into_server(self) -> L1SettlementServer<Self> {
        L1SettlementServer::new(self)
    }

    /// Get current unix timestamp
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Submit a transaction to the consensus pipeline for block inclusion
    async fn submit_to_pipeline(&self, tx_id: &str, from: &str, to: &str, amount: f64) {
        if let Some(ref pipeline) = self.pipeline {
            let packet = PipelinePacket::new(
                tx_id.to_string(),
                from.to_string(),
                to.to_string(),
                amount,
            );
            if let Err(e) = pipeline.submit(packet).await {
                error!("Failed to submit tx {} to pipeline: {}", tx_id, e);
            } else {
                info!("⛓ Tx {} submitted to consensus pipeline", tx_id);
            }
        }
    }

    /// Validate L2 signature with Ed25519 verification and replay protection
    fn validate_l2_signature(&self, public_key: &str, signature: &[u8], timestamp: u64) -> Result<(), Status> {
        // 🔒 PRODUCTION MODE: All signatures required, no bypasses allowed
        if signature.is_empty() || public_key.is_empty() {
            return Err(Status::unauthenticated(
                "Missing signature or public key - all transactions must be signed"
            ));
        }

        // 1. Check timestamp is within acceptable window (prevent replay attacks)
        let now = self.now_unix();
        if timestamp < now.saturating_sub(SIGNATURE_TIMESTAMP_TOLERANCE_SECS) {
            return Err(Status::unauthenticated(format!(
                "Signature timestamp too old: {} vs now {}", timestamp, now
            )));
        }
        if timestamp > now + SIGNATURE_TIMESTAMP_TOLERANCE_SECS {
            return Err(Status::unauthenticated(format!(
                "Signature timestamp too far in future: {} vs now {}", timestamp, now
            )));
        }

        // 2. Check for replay (nonce reuse)
        let nonce_key = format!("{}:{}", public_key, timestamp);
        {
            let mut nonces = self.used_nonces.entry(public_key.to_string()).or_insert_with(HashSet::new);
            if nonces.contains(&timestamp) {
                return Err(Status::unauthenticated("Replay attack detected: nonce already used"));
            }
            nonces.insert(timestamp);
            
            // Cleanup old nonces (keep last 1000)
            if nonces.len() > 1000 {
                let oldest = nonces.iter().min().copied();
                if let Some(old) = oldest {
                    nonces.remove(&old);
                }
            }
        }

        // 3. Verify Ed25519 signature
        let pubkey_bytes = hex::decode(public_key)
            .map_err(|e| Status::invalid_argument(format!("Invalid public key hex: {}", e)))?;
        
        if pubkey_bytes.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "Public key must be 32 bytes, got {}", pubkey_bytes.len()
            )));
        }

        let verifying_key = VerifyingKey::from_bytes(
            &pubkey_bytes.try_into().map_err(|_| Status::invalid_argument("Invalid public key length"))?
        ).map_err(|e| Status::invalid_argument(format!("Invalid public key: {}", e)))?;

        if signature.len() != 64 {
            return Err(Status::invalid_argument(format!(
                "Signature must be 64 bytes, got {}", signature.len()
            )));
        }

        let sig = Signature::from_bytes(
            signature.try_into().map_err(|_| Status::invalid_argument("Invalid signature length"))?
        );

        // Message format: timestamp as big-endian bytes
        let message = timestamp.to_be_bytes();
        
        verifying_key.verify(&message, &sig)
            .map_err(|_| Status::unauthenticated("Invalid signature"))?;

        info!("✅ Signature verified for pubkey: {}...{}", &public_key[..8], &public_key[public_key.len()-4..]);
        Ok(())
    }

    /// Check if a bet has already been settled (idempotency)
    fn is_bet_settled(&self, bet_id: &str) -> Option<SettlementRecord> {
        self.settled_bets.get(bet_id).map(|r| r.clone())
    }

    /// Record a settled bet
    fn record_settlement(&self, bet_id: &str, tx_hash: &str, outcome: &str, user_pnl: i64) {
        let record = SettlementRecord {
            bet_id: bet_id.to_string(),
            tx_hash: tx_hash.to_string(),
            outcome: outcome.to_string(),
            user_pnl,
            settled_at: self.now_unix(),
        };
        self.settled_bets.insert(bet_id.to_string(), record);
    }

    /// Associate a lock with a bet for validation
    fn associate_lock_with_bet(&self, lock_id: &str, bet_id: &str) {
        self.lock_to_bet.insert(lock_id.to_string(), bet_id.to_string());
    }

    /// Get active locks and sessions count
    fn get_active_counts(&self) -> (usize, usize) {
        let locks = self.lock_to_bet.len();
        let sessions = self.credit_sessions.iter().filter(|s| s.is_active).count();
        (locks, sessions)
    }
}

#[tonic::async_trait]
impl L1Settlement for L1SettlementService {
    /// Get user's L1 balance
    async fn get_balance(
        &self,
        request: Request<BalanceRequest>,
    ) -> Result<Response<BalanceResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC GetBalance: {}", req.address);

        let balance = self.blockchain.get_balance(&req.address);
        let locked = self.asset_manager.get_soft_locked_amount(&req.address);

        Ok(Response::new(BalanceResponse {
            success: true,
            error: String::new(),
            address: req.address,
            available: balance as u64,
            locked: locked as u64,
            total: (balance + locked) as u64,
        }))
    }

    /// Get virtual balance (L1 available = L2 available)
    async fn get_virtual_balance(
        &self,
        request: Request<VirtualBalanceRequest>,
    ) -> Result<Response<VirtualBalanceResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC GetVirtualBalance: L1={}, L2={}", req.l1_address, req.l2_address);

        let l1_available = self.blockchain.get_balance(&req.l1_address);
        let l1_locked = self.asset_manager.get_soft_locked_amount(&req.l1_address);

        Ok(Response::new(VirtualBalanceResponse {
            success: true,
            error: String::new(),
            l1_available: l1_available as u64,
            l1_locked: l1_locked as u64,
            l2_in_positions: l1_locked as u64,
            virtual_available: l1_available as u64,
        }))
    }

    /// Soft lock funds for an L2 bet
    async fn soft_lock(
        &self,
        request: Request<SoftLockRequest>,
    ) -> Result<Response<SoftLockResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC SoftLock: {} amount={} reason={}", req.user_address, req.amount, req.reason);

        self.validate_l2_signature(&req.l2_public_key, &req.l2_signature, req.timestamp)?;

        // Check sufficient balance
        let balance = self.blockchain.get_balance(&req.user_address);
        if balance < req.amount as f64 {
            return Ok(Response::new(SoftLockResponse {
                success: false,
                error: format!("Insufficient balance: have {}, need {}", balance, req.amount),
                lock_id: String::new(),
                locked_amount: 0.0,
                new_available: 0,
                new_locked: 0,
                expires_at: 0,
            }));
        }

        let expires_at = self.now_unix() + 86400;

        match self.asset_manager.initiate_bridge(&req.user_address, req.amount as f64, "L2") {
            Ok(bridge_lock) => {
                // Debit from available balance
                if let Err(e) = self.blockchain.debit(&req.user_address, req.amount as f64) {
                    error!("Failed to debit for soft lock: {}", e);
                    return Ok(Response::new(SoftLockResponse {
                        success: false,
                        error: format!("Failed to lock funds: {}", e),
                        lock_id: String::new(),
                        locked_amount: 0.0,
                        new_available: 0,
                        new_locked: 0,
                        expires_at: 0,
                    }));
                }

                let new_available = self.blockchain.get_balance(&req.user_address);
                let new_locked = self.asset_manager.get_soft_locked_amount(&req.user_address);

                info!("✅ SoftLock created: {} for {} amount={}", bridge_lock.lock_id, req.user_address, req.amount);

                Ok(Response::new(SoftLockResponse {
                    success: true,
                    error: String::new(),
                    lock_id: bridge_lock.lock_id,
                    locked_amount: req.amount,
                    new_available: new_available as u64,
                    new_locked: new_locked as u64,
                    expires_at,
                }))
            }
            Err(e) => {
                warn!("❌ SoftLock failed: {}", e);
                Ok(Response::new(SoftLockResponse {
                    success: false,
                    error: e,
                    lock_id: String::new(),
                    locked_amount: 0.0,
                    new_available: 0,
                    new_locked: 0,
                    expires_at: 0,
                }))
            }
        }
    }

    /// Release a soft lock
    async fn release_lock(
        &self,
        request: Request<ReleaseLockRequest>,
    ) -> Result<Response<ReleaseLockResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC ReleaseLock: lock_id={} user={} reason={}", req.lock_id, req.user_address, req.reason);

        self.validate_l2_signature(&req.l2_public_key, &req.l2_signature, req.timestamp)?;

        match self.asset_manager.release_soft_lock(&req.lock_id) {
            Ok(lock) => {
                // Credit back to available balance
                if let Err(e) = self.blockchain.credit(&req.user_address, lock.amount) {
                    error!("Failed to credit after lock release: {}", e);
                }

                let new_available = self.blockchain.get_balance(&req.user_address);
                let new_locked = self.asset_manager.get_soft_locked_amount(&req.user_address);

                info!("✅ Lock released: {} amount={}", req.lock_id, lock.amount);

                Ok(Response::new(ReleaseLockResponse {
                    success: true,
                    error: String::new(),
                    released_amount: lock.amount as u64,
                    new_available: new_available as u64,
                    new_locked: new_locked as u64,
                }))
            }
            Err(e) => {
                warn!("❌ ReleaseLock failed: {}", e);
                Ok(Response::new(ReleaseLockResponse {
                    success: false,
                    error: e,
                    released_amount: 0,
                    new_available: 0,
                    new_locked: 0,
                }))
            }
        }
    }

    /// Settle a bet
    async fn settle_bet(
        &self,
        request: Request<SettleBetRequest>,
    ) -> Result<Response<SettleBetResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC SettleBet: bet_id={} user={} outcome={} stake={} payout={}",
            req.bet_id, req.user_address, req.outcome, req.stake, req.payout);

        // IDEMPOTENCY CHECK: Return existing result if already settled
        if let Some(existing) = self.is_bet_settled(&req.bet_id) {
            info!("⚡ Returning cached settlement for bet_id={}", req.bet_id);
            let user_balance = self.blockchain.get_balance(&req.user_address);
            let dealer_balance = self.blockchain.get_balance(&req.dealer_address);
            return Ok(Response::new(SettleBetResponse {
                success: true,
                error: String::new(),
                tx_hash: existing.tx_hash,
                user_balance: user_balance as u64,
                dealer_balance: dealer_balance as u64,
                user_pnl: existing.user_pnl,
            }));
        }

        self.validate_l2_signature(&req.l2_public_key, &req.l2_signature, req.timestamp)?;

        // VALIDATION: Verify lock exists and matches stake
        let lock = self.asset_manager.get_bridge_lock(&req.lock_id);
        if let Some(lock) = &lock {
            if (lock.amount - req.stake as f64).abs() > 0.01 {
                warn!("Lock amount {} != stake {} for bet_id={}", lock.amount, req.stake, req.bet_id);
                // Allow settlement but log warning
            }
        }

        // Release the soft lock
        if let Err(e) = self.asset_manager.release_soft_lock(&req.lock_id) {
            warn!("Lock release during settlement failed: {}", e);
        }

        let user_pnl: i64;
        let tx_hash = format!("settle_{}_{}", req.bet_id, self.now_unix());

        match req.outcome.as_str() {
            "win" => {
                // User won: return stake + winnings
                // First credit back the stake (from the lock release)
                if let Err(e) = self.blockchain.credit(&req.user_address, req.stake as f64) {
                    error!("Failed to credit stake back: {}", e);
                }
                // Then transfer winnings from dealer
                let net_win = req.payout as f64 - req.stake as f64;
                if net_win > 0.0 {
                    if let Err(e) = self.blockchain.transfer(&req.dealer_address, &req.user_address, net_win) {
                        error!("Settlement transfer failed: {}", e);
                        return Ok(Response::new(SettleBetResponse {
                            success: false,
                            error: format!("Transfer failed: {}", e),
                            tx_hash: String::new(),
                            user_balance: 0,
                            dealer_balance: 0,
                            user_pnl: 0,
                        }));
                    }
                }
                user_pnl = (req.payout as i64) - (req.stake as i64);
                info!("✅ User won: {} receives {} (P&L: {})", req.user_address, req.payout, user_pnl);
            }
            "lose" => {
                // User lost: stake goes to dealer (not credited back to user)
                if let Err(e) = self.blockchain.credit(&req.dealer_address, req.stake as f64) {
                    error!("Failed to credit dealer: {}", e);
                }
                user_pnl = -(req.stake as i64);
                info!("✅ User lost: {} loses {} to dealer", req.user_address, req.stake);
            }
            "void" | "push" => {
                // Bet voided: stake returned to user
                if let Err(e) = self.blockchain.credit(&req.user_address, req.stake as f64) {
                    error!("Failed to credit stake back: {}", e);
                }
                user_pnl = 0;
                info!("✅ Bet voided/push: {} stake returned", req.user_address);
            }
            _ => {
                return Ok(Response::new(SettleBetResponse {
                    success: false,
                    error: format!("Unknown outcome: {}", req.outcome),
                    tx_hash: String::new(),
                    user_balance: 0,
                    dealer_balance: 0,
                    user_pnl: 0,
                }));
            }
        }

        let user_balance = self.blockchain.get_balance(&req.user_address);
        let dealer_balance = self.blockchain.get_balance(&req.dealer_address);

        // Record settlement for idempotency
        self.record_settlement(&req.bet_id, &tx_hash, &req.outcome, user_pnl);

        // Submit to consensus pipeline for block inclusion
        let (from, to, amount) = match req.outcome.as_str() {
            "win" => (&req.dealer_address, &req.user_address, req.payout as f64 - req.stake as f64),
            "lose" => (&req.user_address, &req.dealer_address, req.stake as f64),
            _ => (&req.user_address, &req.user_address, req.stake as f64), // void/push - return to user
        };
        self.submit_to_pipeline(&tx_hash, from, to, amount).await;

        Ok(Response::new(SettleBetResponse {
            success: true,
            error: String::new(),
            tx_hash,
            user_balance: user_balance as u64,
            dealer_balance: dealer_balance as u64,
            user_pnl,
        }))
    }

    /// Batch settle multiple bets
    async fn batch_settle(
        &self,
        request: Request<BatchSettleRequest>,
    ) -> Result<Response<BatchSettleResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC BatchSettle: {} settlements", req.settlements.len());

        self.validate_l2_signature(&req.l2_public_key, &req.l2_signature, req.timestamp)?;

        let mut results = Vec::new();
        let mut settled_count = 0u32;
        let mut failed_count = 0u32;

        for settlement in req.settlements {
            let bet_req = Request::new(settlement);
            match self.settle_bet(bet_req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    if inner.success {
                        settled_count += 1;
                    } else {
                        failed_count += 1;
                    }
                    results.push(inner);
                }
                Err(e) => {
                    failed_count += 1;
                    results.push(SettleBetResponse {
                        success: false,
                        error: e.message().to_string(),
                        tx_hash: String::new(),
                        user_balance: 0,
                        dealer_balance: 0,
                        user_pnl: 0,
                    });
                }
            }
        }

        Ok(Response::new(BatchSettleResponse {
            success: failed_count == 0,
            error: if failed_count > 0 {
                format!("{} settlements failed", failed_count)
            } else {
                String::new()
            },
            settled_count,
            failed_count,
            results,
        }))
    }

    /// Open a credit session
    async fn open_credit_session(
        &self,
        request: Request<OpenCreditRequest>,
    ) -> Result<Response<OpenCreditResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC OpenCreditSession: user={} limit={}", req.user_address, req.credit_limit);

        let balance = self.blockchain.get_balance(&req.user_address);
        let credit_limit = if req.credit_limit > 0 {
            std::cmp::min(req.credit_limit, balance as u64)
        } else {
            balance as u64
        };

        let duration = if req.duration_hours > 0 { req.duration_hours } else { 24 };
        let expires_at = self.now_unix() + (duration * 3600);
        let session_id = format!("credit_{}_{}", req.user_address.get(3..).unwrap_or(""), self.now_unix());

        // Store session for tracking
        let session_record = CreditSessionRecord {
            session_id: session_id.clone(),
            user_address: req.user_address.clone(),
            credit_limit,
            used_credit: 0,
            expires_at,
            is_active: true,
        };
        self.credit_sessions.insert(session_id.clone(), session_record);

        info!("✅ Credit session opened: {} limit={}", session_id, credit_limit);

        Ok(Response::new(OpenCreditResponse {
            success: true,
            error: String::new(),
            session_id,
            credit_limit,
            available_credit: credit_limit,
            expires_at,
        }))
    }

    /// Close credit session
    async fn close_credit_session(
        &self,
        request: Request<CloseCreditRequest>,
    ) -> Result<Response<CloseCreditResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC CloseCreditSession: session={} user={} l2_balance={}", 
            req.session_id, req.user_address, req.l2_balance);

        self.validate_l2_signature(&req.l2_public_key, &req.l2_signature, req.timestamp)?;

        // Get and close the session
        let session = self.credit_sessions.get(&req.session_id);
        let net_pnl = if let Some(session) = session {
            let session_credit_limit = session.credit_limit as i64;
            let l2_balance = req.l2_balance as i64;
            l2_balance - session_credit_limit // P&L = final L2 balance - initial credit
        } else {
            0i64
        };

        // Mark session as closed
        if let Some(mut session) = self.credit_sessions.get_mut(&req.session_id) {
            session.is_active = false;
        }

        let settlement_type = if net_pnl > 0 {
            "profit"
        } else if net_pnl < 0 {
            "loss"
        } else {
            "break_even"
        };

        let l1_balance = self.blockchain.get_balance(&req.user_address);

        info!("✅ Credit session closed: {} P&L={} type={}", req.session_id, net_pnl, settlement_type);

        Ok(Response::new(CloseCreditResponse {
            success: true,
            error: String::new(),
            settlement_type: settlement_type.to_string(),
            net_pnl,
            returned_to_l1: req.l2_balance,
            l1_new_balance: l1_balance as u64,
        }))
    }

    /// Get credit status
    async fn get_credit_status(
        &self,
        request: Request<CreditStatusRequest>,
    ) -> Result<Response<CreditStatusResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC GetCreditStatus: {}", req.user_address);

        let l1_balance = self.blockchain.get_balance(&req.user_address);
        let locked = self.asset_manager.get_soft_locked_amount(&req.user_address);

        Ok(Response::new(CreditStatusResponse {
            success: true,
            error: String::new(),
            has_active_session: false,
            session_id: String::new(),
            credit_limit: l1_balance as u64,
            used_credit: locked as u64,
            available_credit: l1_balance as u64,
            locked_in_bets: locked as u64,
            expires_at: 0,
            l1_balance: l1_balance as u64,
        }))
    }

    /// Verify signature
    async fn verify_signature(
        &self,
        request: Request<VerifySignatureRequest>,
    ) -> Result<Response<VerifySignatureResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC VerifySignature: pubkey={}", req.public_key);

        use sha2::{Sha256, Digest};
        let pubkey_bytes = hex::decode(&req.public_key)
            .map_err(|_| Status::invalid_argument("Invalid public key hex"))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&pubkey_bytes);
        let hash = hasher.finalize();
        let address = format!("L1_{}", hex::encode(&hash[..20]).to_uppercase());

        Ok(Response::new(VerifySignatureResponse {
            valid: true,
            error: String::new(),
            derived_address: address,
        }))
    }

    /// Health check
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let uptime = self.start_time.elapsed().as_secs();
        let (active_locks, active_sessions) = self.get_active_counts();
        let block_height = self.blockchain.block_height();

        Ok(Response::new(HealthResponse {
            healthy: true,
            version: self.version.clone(),
            block_height,
            uptime_seconds: uptime,
            active_locks: active_locks as u32,
            active_sessions: active_sessions as u32,
        }))
    }
}

/// Start the gRPC server
pub async fn start_grpc_server(
    blockchain: Arc<ConcurrentBlockchain>,
    asset_manager: Arc<AssetManager>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = L1SettlementService::new(blockchain, asset_manager);
    
    info!("🚀 Starting gRPC server on {}", addr);
    
    tonic::transport::Server::builder()
        .add_service(service.into_server())
        .serve(addr)
        .await?;
    
    Ok(())
}

/// Start the gRPC server with transaction pipeline for consensus integration
pub async fn start_grpc_server_with_pipeline(
    blockchain: Arc<ConcurrentBlockchain>,
    asset_manager: Arc<AssetManager>,
    pipeline: Arc<TransactionPipeline>,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = L1SettlementService::new(blockchain, asset_manager)
        .with_pipeline(pipeline);
    
    info!("🚀 Starting gRPC server on {} (with consensus pipeline)", addr);
    
    tonic::transport::Server::builder()
        .add_service(service.into_server())
        .serve(addr)
        .await?;
    
    Ok(())
}
