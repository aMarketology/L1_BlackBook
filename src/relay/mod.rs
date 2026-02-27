//! Writer Relay Service — gRPC server for block streaming to Reader nodes
//!
//! The Writer node produces blocks and makes them available to Readers via:
//! - `SubscribeBlocks`: Server-streaming RPC for live block feed
//! - `CatchupBlocks`: Server-streaming RPC for historical block range
//! - `ForwardTransaction`: Reader→Writer tx forwarding into mempool
//! - `GetStatus`: Health/status check

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::poh_blockchain::{BlockProducer, FinalizedBlock, OrderedTransaction};
use crate::storage::ConcurrentBlockchain;
use crate::protocol::blockchain::Transaction;

// Import generated protobuf types
pub mod proto {
    tonic::include_proto!("validator_relay");
}

use proto::validator_relay_server::{ValidatorRelay, ValidatorRelayServer};
use proto::{BlockData, BlockTransaction, SubscribeRequest, CatchupRequest,
    ForwardTransactionRequest, ForwardTransactionResponse,
    StatusRequest, StatusResponse};

// ============================================================================
// CONVERSION: FinalizedBlock → proto::BlockData
// ============================================================================

fn tx_data_to_json(data: &crate::protocol::blockchain::TxData) -> String {
    serde_json::to_string(data).unwrap_or_default()
}

fn ordered_tx_to_proto(otx: &OrderedTransaction) -> BlockTransaction {
    BlockTransaction {
        hash: otx.tx.hash.clone(),
        from: otx.tx.from.clone(),
        data_json: tx_data_to_json(&otx.tx.data),
        signature: otx.tx.signature.clone(),
        signer_pubkey: otx.tx.signer_pubkey.clone(),
        timestamp: otx.tx.timestamp,
        poh_hash: otx.poh_hash.clone(),
        poh_sequence: otx.poh_sequence,
        position: otx.position,
    }
}

fn block_to_proto(block: &FinalizedBlock) -> BlockData {
    BlockData {
        slot: block.slot,
        timestamp: block.timestamp,
        previous_hash: block.previous_hash.clone(),
        hash: block.hash.clone(),
        state_root: block.state_root.clone(),
        accounts_hash: block.accounts_hash.clone(),
        poh_hash: block.poh_hash.clone(),
        poh_sequence: block.poh_sequence,
        poh_entries: block.poh_entries.iter().map(|e| proto::PoHEntry {
            hash: e.hash.clone(),
            num_hashes: e.num_hashes,
            slot: 0, // PoHEntry in runtime doesn't carry slot, blocks do
        }).collect(),
        transactions: block.transactions.iter().map(ordered_tx_to_proto).collect(),
        tx_count: block.tx_count,
        leader: block.leader.clone(),
        epoch: block.epoch,
        confirmations: block.confirmations,
    }
}

/// Reverse conversion: proto::BlockData → FinalizedBlock (for reader verification)
pub fn proto_to_block(pb: &BlockData) -> FinalizedBlock {
    use crate::runtime::PoHEntry as RuntimePoHEntry;

    let transactions: Vec<OrderedTransaction> = pb.transactions.iter().map(|ptx| {
        let tx_data: crate::protocol::blockchain::TxData =
            serde_json::from_str(&ptx.data_json).unwrap_or(
                crate::protocol::blockchain::TxData::TransferBb {
                    to: String::new(),
                    amount: 0,
                }
            );
        OrderedTransaction {
            tx: Transaction {
                hash: ptx.hash.clone(),
                from: ptx.from.clone(),
                timestamp: ptx.timestamp,
                data: tx_data,
                signature: ptx.signature.clone(),
                signer_pubkey: ptx.signer_pubkey.clone(),
            },
            poh_hash: ptx.poh_hash.clone(),
            poh_sequence: ptx.poh_sequence,
            slot: pb.slot,
            position: ptx.position,
        }
    }).collect();

    let poh_entries: Vec<RuntimePoHEntry> = pb.poh_entries.iter().map(|e| {
        RuntimePoHEntry {
            hash: e.hash.clone(),
            num_hashes: e.num_hashes,
            transactions: vec![],
        }
    }).collect();

    FinalizedBlock {
        slot: pb.slot,
        timestamp: pb.timestamp,
        previous_hash: pb.previous_hash.clone(),
        hash: pb.hash.clone(),
        state_root: pb.state_root.clone(),
        accounts_hash: pb.accounts_hash.clone(),
        poh_hash: pb.poh_hash.clone(),
        poh_sequence: pb.poh_sequence,
        poh_entries,
        transactions,
        tx_count: pb.tx_count,
        leader: pb.leader.clone(),
        epoch: pb.epoch,
        confirmations: pb.confirmations,
    }
}

// ============================================================================
// WRITER RELAY SERVICE
// ============================================================================

/// The Writer's gRPC service — streams produced blocks to Reader nodes.
pub struct WriterRelayService {
    /// Broadcast channel sender — block production loop sends here
    block_tx: broadcast::Sender<FinalizedBlock>,

    /// Reference to block producer (for catchup + status)
    block_producer: Arc<BlockProducer>,

    /// Reference to storage (for catchup of older blocks)
    blockchain: ConcurrentBlockchain,

    /// Node identity
    validator_id: String,

    /// Server start time (for uptime)
    start_time: Instant,

    /// Number of currently connected readers
    connected_readers: Arc<AtomicU32>,

    /// Latest slot (updated by broadcast receiver)
    latest_slot: Arc<AtomicU64>,
}

impl WriterRelayService {
    pub fn new(
        block_tx: broadcast::Sender<FinalizedBlock>,
        block_producer: Arc<BlockProducer>,
        blockchain: ConcurrentBlockchain,
        validator_id: String,
    ) -> Self {
        Self {
            block_tx,
            block_producer,
            blockchain,
            validator_id,
            start_time: Instant::now(),
            connected_readers: Arc::new(AtomicU32::new(0)),
            latest_slot: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get broadcast sender (for block production loop to call .send())
    #[allow(dead_code)]
    pub fn block_sender(&self) -> broadcast::Sender<FinalizedBlock> {
        self.block_tx.clone()
    }

    /// Convert to a tonic gRPC server
    pub fn into_server(self) -> ValidatorRelayServer<Self> {
        ValidatorRelayServer::new(self)
    }

    /// Get connected reader count
    #[allow(dead_code)]
    pub fn reader_count(&self) -> u32 {
        self.connected_readers.load(Ordering::Relaxed)
    }
}

// ============================================================================
// gRPC IMPLEMENTATION
// ============================================================================

type BlockStream = Pin<Box<dyn Stream<Item = Result<BlockData, Status>> + Send>>;

#[tonic::async_trait]
impl ValidatorRelay for WriterRelayService {

    type SubscribeBlocksStream = BlockStream;
    type CatchupBlocksStream = BlockStream;

    /// Live block subscription — server-streaming RPC
    async fn subscribe_blocks(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeBlocksStream>, Status> {
        let req = request.into_inner();
        let reader_id = req.reader_id.clone();
        info!("📡 Reader '{}' subscribed to block stream (start_slot={})", reader_id, req.start_slot);

        self.connected_readers.fetch_add(1, Ordering::Relaxed);
        let connected = self.connected_readers.clone();

        // Create a new receiver from the broadcast channel
        let mut rx = self.block_tx.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(block) => {
                        yield Ok(block_to_proto(&block));
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("📡 Reader '{}' lagged by {} blocks — some blocks skipped", reader_id, n);
                        // Continue receiving — reader should do catchup for missed blocks
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("📡 Reader '{}' stream closed (channel dropped)", reader_id);
                        break;
                    }
                }
            }
            // Decrement reader count when stream ends
            connected.fetch_sub(1, Ordering::Relaxed);
        };

        Ok(Response::new(Box::pin(stream) as Self::SubscribeBlocksStream))
    }

    /// Historical block catchup — server-streaming RPC
    async fn catchup_blocks(
        &self,
        request: Request<CatchupRequest>,
    ) -> Result<Response<Self::CatchupBlocksStream>, Status> {
        let req = request.into_inner();
        let reader_id = req.reader_id.clone();
        let start = req.start_slot;
        let end = if req.end_slot == 0 {
            // 0 means "up to latest"
            self.block_producer.total_blocks_produced()
                .saturating_sub(1)
                .max(start)
        } else {
            req.end_slot
        };

        info!("📥 Reader '{}' catchup: slots {}..{}", reader_id, start, end);

        // Clone references for the async stream
        let blockchain = self.blockchain.clone();
        let block_producer = self.block_producer.clone();

        let stream = async_stream::stream! {
            for slot in start..=end {
                // Try in-memory cache first, then storage
                let block = block_producer.get_block(slot)
                    .or_else(|| {
                        blockchain.load_block(slot).ok().flatten()
                    });

                if let Some(block) = block {
                    yield Ok(block_to_proto(&block));
                }
                // If block not found for this slot, skip (empty slots are normal)
            }
            info!("📥 Reader '{}' catchup complete: {} slots sent", reader_id, end.saturating_sub(start) + 1);
        };

        Ok(Response::new(Box::pin(stream) as Self::CatchupBlocksStream))
    }

    /// Forward a transaction from Reader → Writer's mempool
    async fn forward_transaction(
        &self,
        request: Request<ForwardTransactionRequest>,
    ) -> Result<Response<ForwardTransactionResponse>, Status> {
        let req = request.into_inner();

        let tx: Transaction = serde_json::from_str(&req.tx_json)
            .map_err(|e| Status::invalid_argument(format!("Invalid tx JSON: {}", e)))?;

        let tx_id = tx.hash.clone();
        info!("📨 Forwarded tx {} from reader '{}'", &tx_id[..tx_id.len().min(16)], req.reader_id);

        match self.block_producer.submit_transaction(tx) {
            Ok(id) => Ok(Response::new(ForwardTransactionResponse {
                success: true,
                error: String::new(),
                tx_id: id,
            })),
            Err(e) => Ok(Response::new(ForwardTransactionResponse {
                success: false,
                error: e,
                tx_id: String::new(),
            })),
        }
    }

    /// Status query
    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let latest = self.latest_slot.load(Ordering::Relaxed);
        let latest_hash = self.block_producer.get_block(latest)
            .map(|b| b.hash.clone())
            .unwrap_or_default();

        Ok(Response::new(StatusResponse {
            node_id: self.validator_id.clone(),
            mode: "writer".to_string(),
            latest_slot: latest,
            latest_hash,
            epoch: latest / 432000,
            uptime_secs: self.start_time.elapsed().as_secs(),
            connected_readers: self.connected_readers.load(Ordering::Relaxed),
        }))
    }
}

// ============================================================================
// STARTUP HELPER
// ============================================================================

/// Create the broadcast channel and relay service.
/// Returns (relay_service, block_sender) — wire block_sender into block production loop.
pub fn create_relay(
    block_producer: Arc<BlockProducer>,
    blockchain: ConcurrentBlockchain,
    validator_id: String,
) -> (WriterRelayService, broadcast::Sender<FinalizedBlock>) {
    // Buffer 256 blocks — readers that lag more than this must catchup
    let (tx, _rx) = broadcast::channel::<FinalizedBlock>(256);
    let service = WriterRelayService::new(
        tx.clone(),
        block_producer,
        blockchain,
        validator_id,
    );
    (service, tx)
}
