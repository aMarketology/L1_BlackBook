# L2 Connection Deep-Dive: Answers

---

## 1. The Blueprint: Your `.proto` Files

You have **two** `.proto` files. Each defines a completely separate gRPC service running on its own port.

---

### `proto/validator_relay.proto` — Port `50051` (Node-to-Node Block Streaming)

This file defines the contract for how the L1 Writer node streams blocks outward to any listener (including your L2).

**Messages:**

```protobuf
// A single transaction stamped with PoH ordering data
message BlockTransaction {
    string hash = 1;
    string from = 2;
    string data_json = 3;       // JSON-encoded TxData variant
    string signature = 4;
    string signer_pubkey = 5;
    uint64 timestamp = 6;
    string poh_hash = 7;        // PoH hash at time of inclusion
    uint64 poh_sequence = 8;    // Global PoH ordering number
    uint32 position = 9;        // Position within the block
}

// The full block — everything a Reader needs to verify and store it
message BlockData {
    uint64 slot = 1;
    uint64 timestamp = 2;
    string previous_hash = 3;   // Hash chain link — must match parent
    string hash = 4;            // This block's unique fingerprint
    string state_root = 5;
    string accounts_hash = 6;
    string poh_hash = 7;
    uint64 poh_sequence = 8;
    repeated PoHEntry poh_entries = 9;
    repeated BlockTransaction transactions = 10;
    uint32 tx_count = 11;
    string leader = 12;
    uint64 epoch = 13;
    uint64 confirmations = 14;
}

// Reader sends this to start receiving blocks
message SubscribeRequest {
    string reader_id = 1;   // Reader's identity string
    uint64 start_slot = 2;  // Resume from this slot (0 = latest)
}
```

**Service Definition:**

```protobuf
service ValidatorRelay {
    // Live block stream: Writer → Reader (server-streaming)
    rpc SubscribeBlocks(SubscribeRequest) returns (stream BlockData);

    // Historical catchup: Reader requests a range of past blocks
    rpc CatchupBlocks(CatchupRequest) returns (stream BlockData);

    // Transaction forwarding: Reader → Writer mempool
    rpc ForwardTransaction(ForwardTransactionRequest) returns (ForwardTransactionResponse);

    // Status / health query
    rpc GetStatus(StatusRequest) returns (StatusResponse);
}
```

**What this means for L2:** `SubscribeBlocks` is the live fire-hose. Your L2 calls this once and receives every new block in real time as binary Protobuf messages — no polling needed.

---

### `proto/settlement.proto` — Port `50052` (L2 ↔ L1 Game Lifecycle)

This file defines the contract for all contest-specific operations: deposits, prize locks, and payout finalization.

```protobuf
service SettlementService {
    // L2 calls this on user entry — verifies the deposit is on-chain
    rpc VerifyDeposit(VerifyDepositRequest) returns (VerifyDepositResponse);

    // Dealer calls this to lock prize reserve into per-contest escrow
    rpc InitContestReserve(InitContestReserveRequest) returns (InitContestReserveResponse);

    // L2 sequencer calls this after a market resolves — submits 32-byte Merkle root
    rpc SubmitMerkleRoot(MerkleRootSubmission) returns (MerkleRootResponse);

    // L2 queries live contest state
    rpc GetContestStatus(ContestStatusRequest) returns (ContestStatusResponse);

    // Heartbeat / TPS monitoring
    rpc SyncBridge(SyncBridgeRequest) returns (SyncBridgeResponse);
}
```

The `MerkleRootSubmission` message is the most critical — it carries the Ed25519 sequencer signature that L1 verifies before finalizing a market:

```protobuf
message MerkleRootSubmission {
    string contest_id       =  1;
    bytes  merkle_root      =  2;  // exactly 32 bytes (SHA-256 Merkle root)
    uint32 winner_count     =  3;
    uint64 total_deposited  =  4;  // SPL units
    uint64 total_payout     =  5;  // SPL units — net payout to all winners
    uint64 house_rake       =  6;  // SPL units — platform cut
    string winning_outcome  =  7;
    int64  resolved_at      =  8;  // Unix timestamp
    string receipt_hash     =  9;  // SHA-256 hex of key fields
    string oracle_proof     = 10;
    uint64 l2_block_number  = 11;  // Monotonic counter for replay protection
    bytes  signed_message   = 12;  // Binary packed canonical message
    bytes  sequencer_pubkey = 13;  // Ed25519 verifying key, 32 bytes
    bytes  sequencer_sig    = 14;  // Ed25519 signature over signed_message, 64 bytes
}
```

---

## 2. The L1 Server: The gRPC Host

The L1 hosts **two** gRPC servers, both started inside the Writer branch of `main()` in `src/main.rs` (around lines 2049–2088).

---

### Block Relay Server — `src/relay/mod.rs`

This is the `ValidatorRelay` tonic implementation. The service struct holds a `tokio::sync::broadcast::Sender<FinalizedBlock>`. The block production loop calls `.send()` on that channel every time it finalizes a block. Each connected reader has its own `broadcast::Receiver` that gets a copy instantly.

**The core service struct:**

```rust
pub struct WriterRelayService {
    block_tx: broadcast::Sender<FinalizedBlock>,   // Block production loop writes here
    block_producer: Arc<BlockProducer>,             // For catchup + status queries
    blockchain: ConcurrentBlockchain,               // ReDB storage (for historical blocks)
    validator_id: String,
    start_time: Instant,
    connected_readers: Arc<AtomicU32>,
    latest_slot: Arc<AtomicU64>,
}
```

**The live stream RPC — how the port translates ReDB updates into a binary stream:**

```rust
#[tonic::async_trait]
impl ValidatorRelay for WriterRelayService {

    async fn subscribe_blocks(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeBlocksStream>, Status> {
        let reader_id = request.into_inner().reader_id.clone();
        self.connected_readers.fetch_add(1, Ordering::Relaxed);

        // Each reader gets its own receiver from the broadcast channel
        let mut rx = self.block_tx.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(block) => {
                        // Converts FinalizedBlock (Rust struct) → proto::BlockData (Protobuf)
                        yield Ok(block_to_proto(&block));
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Reader fell behind — it should call CatchupBlocks for missed slots
                        warn!("Reader '{}' lagged by {} blocks", reader_id, n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => { break; }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}
```

**The catchup RPC — how historical blocks are served from ReDB:**

```rust
async fn catchup_blocks(&self, request: Request<CatchupRequest>) -> ... {
    // Walks slot range: tries in-memory cache first, then ReDB on disk
    let stream = async_stream::stream! {
        for slot in start..=end {
            let block = block_producer.get_block(slot)
                .or_else(|| blockchain.load_block(slot).ok().flatten());

            if let Some(block) = block {
                yield Ok(block_to_proto(&block));
            }
            // Empty slots are skipped silently — normal behaviour
        }
    };
    Ok(Response::new(Box::pin(stream)))
}
```

**Port binding in `src/main.rs`:**

```rust
// Writer mode: spawn relay gRPC server on port 50051 (grpc_port)
let addr = format!("0.0.0.0:{}", grpc_port).parse().unwrap();
tonic::transport::Server::builder()
    .add_service(relay_service.into_server())
    .serve(addr)
    .await;

// Spawn Settlement gRPC server on port 50052 (grpc_port + 1)
let settlement_port: u16 = std::env::var("SETTLEMENT_GRPC_PORT")
    .unwrap_or_else(|_| (config.grpc_port + 1).to_string())
    .parse().unwrap_or(config.grpc_port + 1);
```

---

### Settlement Server — `src/settlement/mod.rs`

This is the `SettlementService` tonic implementation. It handles all contest lifecycle calls from L2.

**`VerifyDeposit` — how L1 confirms a user's deposit before L2 grants entry:**

```rust
#[tonic::async_trait]
impl SettlementService for BlackBookSettlementService {

    async fn verify_deposit(&self, request: Request<VerifyDepositRequest>)
        -> Result<Response<VerifyDepositResponse>, Status>
    {
        let req = request.into_inner();

        // Looks up by external tx signature (the sig from Solana/BSC bridge tx)
        let record = self.deposit_requests.get(&req.deposit_tx_sig);

        match record {
            None => Ok(Response::new(VerifyDepositResponse {
                verified: false,
                error_code: "TX_NOT_FOUND".to_string(),
                ..Default::default()
            })),
            Some(dep) => {
                // Convert stablecoin amount → SPL units (1 BB = 1,000,000 SPL units)
                let actual_spl = (dep.amount_stablecoin * 1_000_000.0).round() as u64;

                // Amount check
                if req.expected_amount > 0 && actual_spl != req.expected_amount {
                    return Ok(Response::new(VerifyDepositResponse {
                        verified: false,
                        error_code: "WRONG_AMOUNT".to_string(),
                        actual_amount: actual_spl,
                        depositor_wallet: dep.wallet_address.clone(),
                        ..Default::default()
                    }));
                }

                // Status check — deposit must be "approved", not just "pending"
                if dep.status != "approved" {
                    return Ok(Response::new(VerifyDepositResponse {
                        verified: false,
                        error_code: "TX_NOT_FINAL".to_string(),
                        ..Default::default()
                    }));
                }

                // All checks passed
                Ok(Response::new(VerifyDepositResponse {
                    verified: true,
                    depositor_wallet: dep.wallet_address.clone(), // L2 uses this as canonical identity
                    actual_amount: actual_spl,
                    deposit_slot: dep.approved_at.unwrap_or(dep.submitted_at),
                    error_code: String::new(),
                }))
            }
        }
    }
}
```

**Key rule from the settlement service:** L2 must **always** use the `depositor_wallet` returned by `VerifyDeposit` as the canonical user identity — never the user's self-reported wallet address.

---

## 3. The L2 Client: The Listener

The block-consuming client lives in `src/reader/mod.rs`. It implements the full connection lifecycle: status check → catchup → live subscribe → reconnect loop.

---

### Connection Setup

```rust
pub struct ReaderNode {
    writer_addr: String,          // e.g. "http://writer-node:50051"
    blockchain: ConcurrentBlockchain,
    current_slot: Arc<AtomicU64>,
    reader_id: String,
    latest_hash: parking_lot::RwLock<String>,  // Last verified block hash
    blocks_verified: AtomicU64,
    blocks_failed: AtomicU64,
}
```

The `run()` method is a perpetual reconnect loop:

```rust
pub async fn run(self: Arc<Self>) {
    loop {
        match self.connect_and_sync().await {
            Ok(()) => {
                warn!("Writer stream ended — reconnecting in 3s…");
            }
            Err(e) => {
                error!("Reader connection failed: {} — retrying in 5s…", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
```

### Single Connection Cycle

```rust
async fn connect_and_sync(&self) -> Result<()> {
    // 1. Open the gRPC channel to the Writer's address
    let channel = Channel::from_shared(self.writer_addr.clone())?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .connect()
        .await?;

    let mut client = ValidatorRelayClient::new(channel);

    // 2. Handshake — get writer's current slot
    let status = client.get_status(StatusRequest {}).await?.into_inner();
    info!("Connected to writer '{}' — latest slot {}", status.node_id, status.latest_slot);

    // 3. Fill the gap between our local slot and the writer's current slot
    let our_latest = self.current_slot.load(Ordering::Relaxed);
    if our_latest < status.latest_slot {
        self.catchup(&mut client, our_latest, status.latest_slot).await?;
    }

    // 4. Subscribe to the live stream
    self.subscribe(&mut client).await?;
    Ok(())
}
```

### The Receive Loop — The Critical Part

This is the `while let Some(message) = stream.message().await?` loop you're looking for:

```rust
async fn subscribe(&self, client: &mut ValidatorRelayClient<Channel>) -> Result<()> {
    let request = SubscribeRequest {
        reader_id: self.reader_id.clone(),
        start_slot: self.current_slot.load(Ordering::Relaxed),
    };

    // Opens the server-streaming RPC
    let mut stream = client.subscribe_blocks(request).await?.into_inner();

    // Block-by-block receive loop
    while let Some(block_data) = stream.message().await? {
        let block = proto_to_block(&block_data);  // Protobuf → Rust struct
        match self.process_block(block, "live") {
            Ok(()) => {}
            Err(e) => {
                warn!("Block processing error: {}", e);
                // One bad block does NOT break the stream — continues listening
            }
        }
    }
    Ok(())
}
```

### What Happens to Each Block — `process_block()`

This is where binary data becomes a database update:

```rust
fn process_block(&self, block: FinalizedBlock, source: &str) -> Result<(), String> {
    // Step 1 — Cryptographic verification
    // Checks: previous_hash links correctly, PoH entries are valid, tx_count matches
    let expected_prev = self.latest_hash.read().clone();
    if !verify_block(&block, &expected_prev) {
        self.blocks_failed.fetch_add(1, Ordering::Relaxed);
        return Err(format!("Block {} failed verification", block.slot));
    }

    // Step 2 — Persist to local ReDB (durable storage)
    self.blockchain.store_block(block.slot, &block)?;

    // Step 3 — Apply balance deltas to the SVM AccountsDB (hot cache)
    // Reader does NOT re-execute SVM — it trusts the Writer's state_root
    // after verifying the hash chain, then applies balance changes directly
    self.apply_block_balances(&block);

    // Step 4 — Update tracking state for next block's verification
    *self.latest_hash.write() = block.hash.clone();
    self.current_slot.store(block.slot + 1, Ordering::Relaxed);
    self.blocks_verified.fetch_add(1, Ordering::Relaxed);

    Ok(())
}
```

**For your Supabase integration:** The `apply_block_balances()` call at Step 3 is where you hook in. Each `block.transactions` entry tells you exactly: who sent what, to whom, for how much, at which slot. That data maps directly to Supabase table updates (user balances, contest entry records, payout triggers).

---

## Summary: Port Map and Data Flow

| Service | Port | File | Direction |
|---|---|---|---|
| `ValidatorRelay` | `50051` | `src/relay/mod.rs` | Writer → Readers (block stream) |
| `SettlementService` | `50052` | `src/settlement/mod.rs` | L2 → L1 (contest RPCs) |

**Full data flow:**

```
[L1 BlockProducer]
       │ .send(FinalizedBlock) via broadcast channel
       ▼
[WriterRelayService] — src/relay/mod.rs
       │ block_to_proto() → proto::BlockData (binary Protobuf)
       │ streamed over gRPC port 50051
       ▼
[ReaderNode / Your L2 Client] — src/reader/mod.rs
       │ stream.message().await → proto::BlockData
       │ proto_to_block() → FinalizedBlock (Rust struct)
       │ verify_block() — hash chain + PoH check
       │ blockchain.store_block() — persisted to local ReDB
       │ apply_block_balances() — balance deltas applied
       ▼
[Your Supabase Sync Hook]
       │ Parse block.transactions
       │ For each tx: update user_balances, contest_entries, payout_queue
       ▼
[Supabase PostgreSQL]
```

**For L2 contest operations (separate from block streaming):**

```
[Your L2 Game Server]
       │ grpc VerifyDeposit(tx_sig) → get canonical depositor_wallet
       │ grpc InitContestReserve(contest_id, dealer, amount)
       │ grpc SubmitMerkleRoot(contest_id, root, sig) → finalize payout
       ▼
[BlackBookSettlementService] — src/settlement/mod.rs — port 50052
       │ Verifies Ed25519 sequencer signature
       │ Updates contest_states DashMap + ReDB
       │ Triggers on-chain payout routing
       ▼
[L1 ReDB + DashMap State]
```
