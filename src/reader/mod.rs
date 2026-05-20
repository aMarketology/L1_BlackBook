//! Reader Node — gRPC client that consumes blocks from a Writer node.
//!
//! Flow:
//!   1. Connect to Writer's gRPC relay
//!   2. Catchup: fetch missed blocks since our last stored slot
//!   3. Subscribe: receive live blocks as they're produced
//!   4. Verify: check hash chain + PoH linkage for each block
//!   5. Store: persist verified blocks to local ReDB + update DashMap cache
//!   6. Serve: reader's own RPC endpoint answers queries from local storage

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tonic::transport::Channel;
use tracing::{info, warn, error};

use crate::poh_blockchain::{FinalizedBlock, verify_block};
use crate::storage::ConcurrentBlockchain;
use crate::relay::proto_to_block;

// Import generated client
use crate::relay::proto::validator_relay_client::ValidatorRelayClient;
use crate::relay::proto::{CatchupRequest, SubscribeRequest, StatusRequest};

// ============================================================================
// READER NODE
// ============================================================================

pub struct ReaderNode {
    /// Writer node gRPC address (e.g., "http://127.0.0.1:50051")
    writer_addr: String,

    /// Local blockchain storage (ReDB)
    blockchain: ConcurrentBlockchain,

    /// Current slot (shared with local RPC server)
    current_slot: Arc<AtomicU64>,

    /// Reader identity
    reader_id: String,

    /// Last verified block hash (for chain verification)
    latest_hash: parking_lot::RwLock<String>,

    /// Blocks verified counter
    blocks_verified: AtomicU64,

    /// Blocks failed counter
    blocks_failed: AtomicU64,

    /// Channel to broadcast received blocks (e.g. for WebSockets)
    pub block_tx: tokio::sync::broadcast::Sender<crate::poh_blockchain::FinalizedBlock>,
}

impl ReaderNode {
    pub fn new(
        writer_addr: String,
        blockchain: ConcurrentBlockchain,
        current_slot: Arc<AtomicU64>,
        reader_id: String,
        block_tx: tokio::sync::broadcast::Sender<crate::poh_blockchain::FinalizedBlock>,
    ) -> Self {
        // Initialize latest_hash from storage (for chain continuity)
        let latest_hash = match blockchain.latest_block_slot() {
            Ok(Some(slot)) => {
                blockchain.load_block(slot)
                    .ok()
                    .flatten()
                    .map(|b| b.hash.clone())
                    .unwrap_or_else(|| "0".repeat(64))
            }
            _ => "0".repeat(64),
        };

        Self {
            writer_addr,
            blockchain,
            current_slot,
            reader_id,
            latest_hash: parking_lot::RwLock::new(latest_hash),
            blocks_verified: AtomicU64::new(0),
            blocks_failed: AtomicU64::new(0),
            block_tx,
        }
    }

    /// Connect to the Writer and start consuming blocks.
    /// This runs forever (reconnects on failure).
    pub async fn run(self: Arc<Self>) {
        loop {
            match self.connect_and_sync().await {
                Ok(()) => {
                    warn!("📡 Writer stream ended — reconnecting in 3s…");
                }
                Err(e) => {
                    error!("❌ Reader connection failed: {} — retrying in 5s…", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Single connection cycle: catchup + subscribe
    async fn connect_and_sync(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("📡 Connecting to writer at {}…", self.writer_addr);

        let channel = Channel::from_shared(self.writer_addr.clone())?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .connect()
            .await?;

        let mut client = ValidatorRelayClient::new(channel.clone());

        // 1. Check writer status
        let status = client.get_status(StatusRequest {}).await?.into_inner();
        info!(
            "📡 Connected to writer '{}' — latest slot {}, {} readers connected",
            status.node_id, status.latest_slot, status.connected_readers
        );

        // 2. Determine where to start catchup
        let our_latest = self.current_slot.load(Ordering::Relaxed);
        let writer_latest = status.latest_slot;

        if our_latest < writer_latest && writer_latest > 0 {
            info!("📥 Catching up: our slot {} → writer slot {}", our_latest, writer_latest);
            self.catchup(&mut client, our_latest, writer_latest).await?;
        }

        // 3. Subscribe to live blocks
        info!("📡 Subscribing to live block stream…");
        self.subscribe(&mut client).await?;

        Ok(())
    }

    /// Catch up on historical blocks
    async fn catchup(
        &self,
        client: &mut ValidatorRelayClient<Channel>,
        start: u64,
        end: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = CatchupRequest {
            reader_id: self.reader_id.clone(),
            start_slot: start,
            end_slot: end,
        };

        let mut stream = client.catchup_blocks(request).await?.into_inner();
        let mut count = 0u64;

        while let Some(block_data) = stream.message().await? {
            let block = proto_to_block(&block_data);
            self.process_block(block, "catchup")?;
            count += 1;
        }

        info!("📥 Catchup complete: {} blocks verified and stored", count);
        Ok(())
    }

    /// Subscribe to live block stream
    async fn subscribe(
        &self,
        client: &mut ValidatorRelayClient<Channel>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_slot = self.current_slot.load(Ordering::Relaxed);
        let request = SubscribeRequest {
            reader_id: self.reader_id.clone(),
            start_slot,
        };

        let mut stream = client.subscribe_blocks(request).await?.into_inner();

        while let Some(block_data) = stream.message().await? {
            let block = proto_to_block(&block_data);

            // ── Clock drift detection ──────────────────────────────────────
            // The Writer's broadcast ring-buffer is lossy (RecvError::Lagged).
            // If we receive block N but our local slot is < N-1, we missed at
            // least one block.  We cannot verify the gap, so we:
            //   1. Reset our hash-chain anchor to the incoming block's declared
            //      `previous_hash` so chain verification continues from here.
            //   2. Fast-forward the slot counter to N so GulfStream / pipeline
            //      downstream all see the correct slot immediately.
            let local_slot = self.current_slot.load(Ordering::Relaxed);
            if block.slot > local_slot + 1 {
                let delta = block.slot.saturating_sub(local_slot + 1);
                warn!(
                    "⚡ Clock drift: local_slot={local_slot}, received slot={}, \
                     {delta} slot(s) missed — resetting chain anchor and fast-forwarding",
                    block.slot
                );
                // Reset chain anchor to the incoming block's declared parent.
                // The next block after this one will be verified against block.hash
                // as normal.
                {
                    let mut h = self.latest_hash.write();
                    *h = block.previous_hash.clone();
                }
                // Advance slot counter to the incoming block's slot.
                // fetch_max: safe against a concurrent normal advance.
                // process_block will store slot + 1 after verification.
                self.current_slot.fetch_max(block.slot, Ordering::Relaxed);
            }
            // ── end drift detection ────────────────────────────────────────

            match self.process_block(block, "live") {
                Ok(()) => {}
                Err(e) => {
                    warn!("⚠️  Block processing error: {}", e);
                    // Continue — don't break the stream for one bad block
                }
            }
        }

        Ok(())
    }

    /// Verify + store a single block
    fn process_block(&self, block: FinalizedBlock, source: &str) -> Result<(), String> {
        let slot = block.slot;

        // 1. Verify block integrity (hash chain, PoH entries, tx count)
        let expected_prev = self.latest_hash.read().clone();

        if !verify_block(&block, &expected_prev) {
            self.blocks_failed.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "Block {} failed verification (expected prev_hash: {}…, got: {}…)",
                slot,
                &expected_prev[..expected_prev.len().min(16)],
                &block.previous_hash[..block.previous_hash.len().min(16)]
            ));
        }

        // 2. Store to local ReDB
        if let Err(e) = self.blockchain.store_block(slot, &block) {
            warn!("⚠️  Failed to store block {}: {}", slot, e);
            // Don't return error — we still accept the block for chain continuity
        }

        // 3. Apply balance changes from transactions to DashMap cache
        // (Reader doesn't re-execute — it trusts the writer's state_root after verification)
        self.apply_block_balances(&block);

        // 4. Update tracking state
        {
            let mut h = self.latest_hash.write();
            *h = block.hash.clone();
        }
        self.current_slot.store(slot + 1, Ordering::Relaxed);
        self.blocks_verified.fetch_add(1, Ordering::Relaxed);

        if block.tx_count > 0 {
            info!(
                "✅ [{source}] Block {slot} verified: {} txs, hash: {}…",
                block.tx_count,
                &block.hash[..block.hash.len().min(16)]
            );
        }

        // Broadcast for WebSockets
        let _ = self.block_tx.send(block);

        Ok(())
    }

    /// Apply balance changes from block transactions to the SVM AccountsDB.
    /// Reader nodes don't re-execute SVM — they trust the writer's state after
    /// verifying the block hash chain. We apply deltas directly to the SVM
    /// (the single source of truth) and mirror to the f64 DashMap cache.
    fn apply_block_balances(&self, block: &FinalizedBlock) {
        use crate::svm::types::LAMPORTS_PER_BB;
        use solana_sdk::account::AccountSharedData;
        use solana_sdk::account::ReadableAccount;

        for otx in &block.transactions {
            match &otx.tx.data {
                crate::protocol::blockchain::TxData::TransferBb { to, amount } => {
                    let lamports = *amount * LAMPORTS_PER_BB;

                    // Debit sender via SVM
                    let from_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&otx.tx.from);
                    let from_cur = self.blockchain.svm_accounts
                        .get_account(&from_pk)
                        .map(|a| a.lamports())
                        .unwrap_or(0);
                    let from_new = from_cur.saturating_sub(lamports);
                    let from_acct = AccountSharedData::new(
                        from_new, 0, &solana_sdk::system_program::id(),
                    );
                    self.blockchain.svm_accounts.store_account(&from_pk, from_acct);
                    self.blockchain.mirror_balance_to_cache(&otx.tx.from, from_new);

                    // Credit receiver via SVM
                    let to_pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(to);
                    let to_cur = self.blockchain.svm_accounts
                        .get_account(&to_pk)
                        .map(|a| a.lamports())
                        .unwrap_or(0);
                    let to_new = to_cur + lamports;
                    let to_acct = AccountSharedData::new(
                        to_new, 0, &solana_sdk::system_program::id(),
                    );
                    self.blockchain.svm_accounts.store_account(&to_pk, to_acct);
                    self.blockchain.mirror_balance_to_cache(to, to_new);
                }
                crate::protocol::blockchain::TxData::DepositUsdt { usdt_amount, .. } => {
                    // Mint: credit recipient at 10:1 ratio (10 BB per USDT)
                    let bb_amount = *usdt_amount * 10;
                    let add_lamports = bb_amount * LAMPORTS_PER_BB;

                    let pk = crate::storage::ConcurrentBlockchain::addr_to_pubkey(&otx.tx.from);
                    let cur = self.blockchain.svm_accounts
                        .get_account(&pk)
                        .map(|a| a.lamports())
                        .unwrap_or(0);
                    let new_lam = cur + add_lamports;
                    let acct = AccountSharedData::new(
                        new_lam, 0, &solana_sdk::system_program::id(),
                    );
                    self.blockchain.svm_accounts.store_account(&pk, acct);
                    self.blockchain.mirror_balance_to_cache(&otx.tx.from, new_lam);
                }
                // Escrow and vault transactions are state-managed by the writer node;
                // reader nodes replay balance effects only, not contract state.
                crate::protocol::blockchain::TxData::EscrowDeposit { .. }
                | crate::protocol::blockchain::TxData::EscrowStateRoot { .. }
                | crate::protocol::blockchain::TxData::EscrowWithdraw { .. }
                | crate::protocol::blockchain::TxData::VaultBurn { .. }
                | crate::protocol::blockchain::TxData::EscrowSweep { .. } => {}
            }
        }
    }

    /// Get verification stats
    #[allow(dead_code)]
    pub fn stats(&self) -> (u64, u64) {
        (
            self.blocks_verified.load(Ordering::Relaxed),
            self.blocks_failed.load(Ordering::Relaxed),
        )
    }
}
