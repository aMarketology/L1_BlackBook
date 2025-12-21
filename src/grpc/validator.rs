use tonic::{Request, Response, Status};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::protocol::blockchain::{EnhancedBlockchain, LockPurpose};

// Include the generated proto code
pub mod settlement {
    tonic::include_proto!("blackbook.settlement");
}

use settlement::settlement_node_server::{SettlementNode, SettlementNodeServer};
use settlement::*;

pub struct L1BankService {
    blockchain: Arc<Mutex<EnhancedBlockchain>>,
    start_time: SystemTime,
}

impl L1BankService {
    pub fn new(blockchain: Arc<Mutex<EnhancedBlockchain>>) -> Self {
        Self {
            blockchain,
            start_time: SystemTime::now(),
        }
    }

    pub fn into_server(self) -> SettlementNodeServer<Self> {
        SettlementNodeServer::new(self)
    }

    fn microtokens_to_bb(microtokens: u64) -> f64 {
        microtokens as f64 / 1_000_000.0
    }

    fn bb_to_microtokens(bb: f64) -> u64 {
        (bb * 1_000_000.0) as u64
    }
}

#[tonic::async_trait]
impl SettlementNode for L1BankService {
    // ========================================================================
    // CORE SETTLEMENT - Final bet resolution payout
    // ========================================================================
    async fn execute_settlement(
        &self,
        request: Request<SettlementRequest>,
    ) -> Result<Response<SettlementResponse>, Status> {
        let req = request.into_inner();
        
        println!("🎰 [L1 Bank] Settlement - {} bet on market {}", 
            req.bet_id, req.market_id);
        println!("   Payout: {} µBB to {}", req.payout_amount, req.beneficiary);

        let mut bc = self.blockchain.lock().unwrap();
        let payout_bb = Self::microtokens_to_bb(req.payout_amount);

        // Execute payout: Dealer → Beneficiary
        let tx_id = bc.create_transaction(
            req.dealer_address.clone(),
            req.beneficiary.clone(),
            payout_bb,
        );

        let block_hash = bc.mine_pending_transactions("grpc_settlement".to_string());
        let block_height = bc.chain.len() as u64;

        let dealer_balance = Self::bb_to_microtokens(bc.get_balance(&req.dealer_address));
        let user_balance = Self::bb_to_microtokens(bc.get_balance(&req.beneficiary));

        println!("✅ [L1 Bank] Settlement complete - TX: {}, Block: {}", 
            &tx_id[..16], block_height);

        Ok(Response::new(SettlementResponse {
            success: true,
            tx_hash: tx_id,
            error_message: String::new(),
            dealer_balance: dealer_balance,
            user_balance: user_balance,
            block_height,
            beneficiary_balance: user_balance,  // Same as user_balance
            error_code: 0,  // ERROR_NONE
        }))
    }

    // ========================================================================
    // REIMBURSEMENT - L2 fronted stake, now L1 pays back the Dealer
    // ========================================================================
    async fn request_reimbursement(
        &self,
        request: Request<ReimbursementRequest>,
    ) -> Result<Response<ReimbursementResponse>, Status> {
        let req = request.into_inner();
        
        println!("💰 [L1 Bank] Reimbursement request - Bet {}", req.bet_id);
        println!("   User {} → Dealer {} = {} µBB", 
            req.user_address, req.dealer_address, req.amount);

        let mut bc = self.blockchain.lock().unwrap();
        let amount_bb = Self::microtokens_to_bb(req.amount);

        // Check if user has sufficient balance
        let available = bc.get_spendable_balance(&req.user_address);
        if available < amount_bb {
            return Err(Status::failed_precondition(
                format!("Insufficient balance: user has {} BB, needs {} BB", 
                    available, amount_bb)
            ));
        }

        // Execute: User → Dealer (reimburse the fronted stake)
        let tx_id = bc.create_transaction(
            req.user_address.clone(),
            req.dealer_address.clone(),
            amount_bb,
        );

        bc.mine_pending_transactions("grpc_reimbursement".to_string());

        let user_balance = Self::bb_to_microtokens(bc.get_balance(&req.user_address));
        let dealer_credited = req.amount;

        println!("✅ [L1 Bank] Reimbursement complete - TX: {}", &tx_id[..16]);

        Ok(Response::new(ReimbursementResponse {
            success: true,
            tx_hash: tx_id,
            error_message: String::new(),
            user_remaining_locked: user_balance,
            dealer_credited,
            error_code: 0,  // ERROR_NONE
        }))
    }

    // ========================================================================
    // BRIDGE LOCK - User locks funds on L1 to use on L2
    // ========================================================================
    async fn initiate_bridge_lock(
        &self,
        request: Request<BridgeLockRequest>,
    ) -> Result<Response<BridgeLockResponse>, Status> {
        let req = request.into_inner();
        
        println!("🔒 [L1 Bank] Bridge lock - {} locking {} µBB for {}", 
            req.user_address, req.amount, req.target_layer);

        let mut bc = self.blockchain.lock().unwrap();
        let amount_bb = Self::microtokens_to_bb(req.amount);

        // Check sufficient balance
        if bc.get_spendable_balance(&req.user_address) < amount_bb {
            return Err(Status::failed_precondition("Insufficient balance"));
        }

        // Lock tokens
        let lock_id = match bc.lock_tokens(&req.user_address, amount_bb, LockPurpose::BridgeToL2, None) {
            Ok(id) => id,
            Err(e) => return Err(Status::internal(e)),
        };

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour expiry

        println!("✅ [L1 Bank] Bridge lock complete - Lock ID: {}", &lock_id[..16]);

        Ok(Response::new(BridgeLockResponse {
            success: true,
            lock_id,
            error_message: String::new(),
            locked_amount: req.amount,
            expires_at,
            available_balance: 0,  // Would need to query actual balance
            error_code: 0,  // ERROR_NONE
        }))
    }

    // ========================================================================
    // BRIDGE RELEASE - L2 settles, unlock funds on L1
    // ========================================================================
    async fn release_bridge_funds(
        &self,
        request: Request<BridgeReleaseRequest>,
    ) -> Result<Response<BridgeReleaseResponse>, Status> {
        let req = request.into_inner();
        
        println!("🔓 [L1 Bank] Bridge release - Lock {} → {}", 
            &req.lock_id[..16], req.beneficiary);

        let mut bc = self.blockchain.lock().unwrap();

        // Authorize release with L2 proof
        let proof = crate::protocol::blockchain::SettlementProof {
            market_id: req.market_id.clone(),
            outcome: req.outcome.clone(),
            l2_block_height: 0,
            l2_signature: "grpc_proof".to_string(),
            verified_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        if let Err(e) = bc.authorize_release(&req.lock_id, proof) {
            return Err(Status::internal(e));
        }

        // Release the lock
        match bc.release_tokens(&req.lock_id) {
            Ok((addr, amount)) => {
                println!("✅ [L1 Bank] Released {} BB to {}", amount, addr);
                
                Ok(Response::new(BridgeReleaseResponse {
                    success: true,
                    tx_hash: format!("release_{}", &req.lock_id[..16]),
                    error_message: String::new(),
                    released_amount: Self::bb_to_microtokens(amount),
                    recipient: addr,
                    error_code: 0,  // ERROR_NONE
                    recipient_new_balance: 0,  // Would need to query actual balance
                }))
            }
            Err(e) => Err(Status::internal(e)),
        }
    }

    // ========================================================================
    // VERIFY SETTLEMENT PROOF - Check if L2 proof is valid
    // ========================================================================
    async fn verify_settlement_proof(
        &self,
        request: Request<SettlementProofRequest>,
    ) -> Result<Response<SettlementProofResponse>, Status> {
        let req = request.into_inner();
        
        println!("🔍 [L1 Bank] Verifying settlement proof for lock {}", &req.lock_id[..16]);

        let bc = self.blockchain.lock().unwrap();

        // Check if lock exists
        let locks = bc.get_locks_for_address(&req.beneficiary);
        let lock_exists = locks.iter().any(|l| l.lock_id == req.lock_id);

        if !lock_exists {
            return Ok(Response::new(SettlementProofResponse {
                valid: false,
                release_authorized: false,
                error_message: "Lock not found".to_string(),
                error_code: 1,  // ERROR_INSUFFICIENT_BALANCE or ERROR_NOT_FOUND
            }));
        }

        // In production, verify L2 signature here
        // For now, accept all proofs
        println!("✅ [L1 Bank] Proof valid");

        Ok(Response::new(SettlementProofResponse {
            valid: true,
            release_authorized: true,
            error_code: 0,  // ERROR_NONE
            error_message: String::new(),
        }))
    }

    // ========================================================================
    // BALANCE QUERIES
    // ========================================================================
    async fn get_balance(
        &self,
        request: Request<BalanceRequest>,
    ) -> Result<Response<BalanceResponse>, Status> {
        let req = request.into_inner();
        let bc = self.blockchain.lock().unwrap();

        let total = bc.get_balance(&req.address);
        let available = bc.get_spendable_balance(&req.address);
        let locked = bc.get_locked_balance(&req.address);

        Ok(Response::new(BalanceResponse {
            address: req.address.clone(),
            available: Self::bb_to_microtokens(available),
            locked: Self::bb_to_microtokens(locked),
            total: Self::bb_to_microtokens(total),
            locked_for_l2: Self::bb_to_microtokens(locked),  // For now, all locked is for L2
            pending_settlement: 0,  // TODO: Track pending settlements
        }))
    }

    async fn check_sufficient_balance(
        &self,
        request: Request<SufficientBalanceRequest>,
    ) -> Result<Response<SufficientBalanceResponse>, Status> {
        let req = request.into_inner();
        let bc = self.blockchain.lock().unwrap();

        let available_bb = bc.get_spendable_balance(&req.address);
        let available_micro = Self::bb_to_microtokens(available_bb);
        let required = req.required_amount;

        let sufficient = available_micro >= required;
        let shortfall = if sufficient { 0 } else { required - available_micro };

        Ok(Response::new(SufficientBalanceResponse {
            sufficient,
            available: available_micro,
            shortfall,
        }))
    }

    // ========================================================================
    // HEALTH & STATUS
    // ========================================================================
    async fn health_check(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let bc = self.blockchain.lock().unwrap();
        let uptime = self.start_time.elapsed().unwrap().as_secs();

        Ok(Response::new(HealthResponse {
            status: "healthy".to_string(),
            block_height: bc.chain.len() as u64,
            version: "0.2.0".to_string(),
            uptime_seconds: uptime,
            pending_settlements: bc.pending_transactions.len() as u32,
            active_locks: 0,  // TODO: Track active locks
            total_locked_amount: 0,  // TODO: Track total locked
        }))
    }

    async fn get_block_height(
        &self,
        _request: Request<BlockHeightRequest>,
    ) -> Result<Response<BlockHeightResponse>, Status> {
        let bc = self.blockchain.lock().unwrap();
        let height = bc.chain.len() as u64;
        let last_block = bc.chain.last();

        let (blockhash, timestamp) = if let Some(block) = last_block {
            (block.hash.clone(), block.timestamp)
        } else {
            ("genesis".to_string(), 0)
        };

        let previous_blockhash = if bc.chain.len() > 1 {
            bc.chain.iter().rev().nth(1)
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "genesis".to_string())
        } else {
            "genesis".to_string()
        };

        Ok(Response::new(BlockHeightResponse {
            height,
            blockhash,
            timestamp,
            previous_blockhash,
        }))
    }

    // ========================================================================
    // VERIFY SIGNATURE - Cross-chain signature validation
    // ========================================================================
    async fn verify_signature(
        &self,
        request: Request<SignatureVerifyRequest>,
    ) -> Result<Response<SignatureVerifyResponse>, Status> {
        let req = request.into_inner();
        
        println!("🔐 [L1 Bank] Verifying signature");

        // In production, would verify Ed25519 signature here
        // Derive address from public key (SHA256 hash of pubkey)
        let derived_addr = format!("L1_{}", &req.public_key[..40.min(req.public_key.len())]);
        
        // For now, accept all signatures
        Ok(Response::new(SignatureVerifyResponse {
            valid: true,
            error_message: String::new(),
            error_code: 0,  // ERROR_NONE
            derived_address: derived_addr,
        }))
    }
}
