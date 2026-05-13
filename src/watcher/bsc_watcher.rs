// ============================================================================
// BNB CHAIN (BSC) CUSTODY WATCHER
// ============================================================================
//
// Background service that periodically polls the BSC custody wallet for
// incoming BEP-20 USDC and USDT transfers, auto-approving pending
// DepositRecords and minting BB to the user's L1 wallet.
//
// Flow (every BSC_WATCHER_POLL_SECS seconds):
//   1. Fetch latest block number via eth_blockNumber
//   2. Call eth_getLogs on USDC + USDT contracts, filtering for Transfer
//      events whose `to` topic matches our custody wallet
//   3. For each log, check the matching DepositRecord in `deposit_requests`
//      (keyed by the BSC tx hash, lower-cased)
//   4. Verify amount on-chain via eth_getTransactionReceipt then mint BB
//
// Config (env vars):
//   BSC_CUSTODY_WALLET      — 0x… EVM address
//   BSC_RPC_URL             — BSC JSON-RPC endpoint (default: Binance dataseed)
//   BSC_WATCHER_POLL_SECS   — poll interval (default: 30)
//   BSC_USDC_CONTRACT       — BEP-20 USDC address (default: BSC mainnet)
//   BSC_USDT_CONTRACT       — BEP-20 USDT address (default: BSC mainnet)
//
// Note: Both USDC and USDT on BSC mainnet have 18 decimals (Binance-Peg tokens).
// ============================================================================

use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::poh_blockchain::BlockProducer;
use crate::protocol::{Transaction as ProtoTx, TxData};
use crate::storage::{ConcurrentBlockchain, DepositRecord};

// ── Well-known BSC mainnet BEP-20 contract addresses ─────────────────────────

/// Binance-Peg USD Coin on BSC (USDC, 18 decimals).
pub const BSC_USDC_CONTRACT: &str = "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d";
/// Binance-Peg BSC-USD (USDT, 18 decimals).
pub const BSC_USDT_CONTRACT: &str = "0x55d398326f99059fF775485246999027B3197955";

/// ERC-20 / BEP-20 Transfer event topic (keccak256 of "Transfer(address,address,uint256)").
const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Both Binance-Peg USDC and USDT have 18 decimals on BSC mainnet.
const BSC_TOKEN_DECIMALS: u32 = 18;

/// Maximum block range per eth_getLogs call (BSC public nodes cap at ~5 000 blocks).
const MAX_LOG_RANGE: u64 = 2_000;

// ── Watcher struct ────────────────────────────────────────────────────────────

pub struct BscWatcher {
    /// BSC JSON-RPC endpoint URL.
    rpc_url: String,
    /// Checksummed "0x…" EVM custody wallet address.
    custody_address: String,
    /// Lower-cased address without "0x" prefix — used to build the topics[2] filter.
    custody_lower: String,
    /// BEP-20 USDC contract address (checksummed).
    usdc_contract: String,
    /// BEP-20 USDT contract address (checksummed).
    usdt_contract: String,
    /// Poll interval in seconds.
    poll_interval_secs: u64,
    /// BlackBook L1 storage layer.
    blockchain: ConcurrentBlockchain,
    /// Hot-cache of pending/approved deposit requests (keyed by ext_tx_hash).
    deposit_requests: Arc<DashMap<String, DepositRecord>>,
    /// PoH block producer — records minting events on-chain.
    block_producer: Arc<BlockProducer>,
    /// Connection-pooled HTTP client.
    http: reqwest::Client,
    /// Last BSC block number fully scanned (exclusive lower bound for next poll).
    last_block: tokio::sync::Mutex<Option<u64>>,
}

// ── JSON-RPC response types (minimal) ────────────────────────────────────────

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

/// A single decoded eth_getLogs entry.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct EthLog {
    address: String,
    topics: Vec<String>,
    data: String,
    transaction_hash: String,
    #[allow(dead_code)]
    block_number: String, // hex-encoded "0x…"
}

/// Stripped result of a receipt-level token transfer verification.
struct VerifiedTransfer {
    asset: String,
    amount: f64,
}

// ── Implementation ────────────────────────────────────────────────────────────

impl BscWatcher {
    pub fn new(
        rpc_url: String,
        custody_address: String,
        usdc_contract: String,
        usdt_contract: String,
        poll_interval_secs: u64,
        blockchain: ConcurrentBlockchain,
        deposit_requests: Arc<DashMap<String, DepositRecord>>,
        block_producer: Arc<BlockProducer>,
    ) -> Self {
        // Normalise address for on-chain comparison (lowercase, no 0x)
        let custody_lower = custody_address
            .trim_start_matches("0x")
            .to_lowercase();

        Self {
            rpc_url,
            custody_address,
            custody_lower,
            usdc_contract,
            usdt_contract,
            poll_interval_secs,
            blockchain,
            deposit_requests,
            block_producer,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest::Client::build"),
            last_block: tokio::sync::Mutex::new(None),
        }
    }

    /// Spawn a detached background task.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            info!(
                "⛓️  BSC watcher started — {} every {}s",
                self.custody_address, self.poll_interval_secs
            );
            // Seed last_block from current chain tip so we don't replay old history.
            if let Ok(tip) = self.get_latest_block().await {
                *self.last_block.lock().await = Some(tip.saturating_sub(50));
                info!("⛓️  BSC watcher seeded at block {}", tip.saturating_sub(50));
            }

            let mut interval =
                tokio::time::interval(Duration::from_secs(self.poll_interval_secs));
            loop {
                interval.tick().await;
                self.poll_once().await;
            }
        });
    }

    // ── Poll cycle ────────────────────────────────────────────────────────────

    async fn poll_once(&self) {
        let latest = match self.get_latest_block().await {
            Ok(b) => b,
            Err(e) => {
                warn!("⚠️  BSC eth_blockNumber failed: {}", e);
                return;
            }
        };

        let from_block = {
            let mut guard = self.last_block.lock().await;
            let from = guard.unwrap_or(latest.saturating_sub(50));
            *guard = Some(latest + 1); // advance before scanning so duplicate scans are safe
            from
        };

        if from_block > latest {
            // Nothing new yet
            return;
        }

        // Scan in chunks to stay within RPC block-range limits
        let mut cursor = from_block;
        while cursor <= latest {
            let chunk_end = (cursor + MAX_LOG_RANGE - 1).min(latest);
            match self.fetch_transfer_logs(cursor, chunk_end).await {
                Ok(logs) => {
                    if !logs.is_empty() {
                        info!(
                            "⛓️  BSC: {} Transfer logs [{}-{}]",
                            logs.len(),
                            cursor,
                            chunk_end
                        );
                    }
                    for log in &logs {
                        self.process_log(log).await;
                    }
                }
                Err(e) => {
                    warn!("⚠️  BSC eth_getLogs [{}-{}]: {}", cursor, chunk_end, e);
                }
            }
            cursor = chunk_end + 1;
        }

        // Scan the BlackBook Bridge contract for non-custodial UsdcDeposited events.
        // The l1Wallet is embedded directly in the event — no /deposit/request HTTP
        // call is required on this path (fully non-custodial).
        self.scan_bridge_contract_deposits(from_block, latest).await;
    }

    // ── Bridge contract: non-custodial deposit scanning ───────────────────────

    /// Scan the deployed `BlackbookBridge` contract for `UsdcDeposited` events and
    /// auto-mint BB.  Requires `BSC_BRIDGE_CONTRACT` to be set — silently returns
    /// if it is missing or empty.
    async fn scan_bridge_contract_deposits(&self, from: u64, to: u64) {
        use solana_sdk::keccak;

        let contract = match std::env::var("BSC_BRIDGE_CONTRACT") {
            Ok(v) if !v.trim().is_empty() && v.trim().starts_with("0x") => v.trim().to_string(),
            _ => return, // contract not yet deployed — skip
        };

        // keccak256("UsdcDeposited(address,string,address,uint256,uint256)")
        let topic0 = format!(
            "0x{}",
            hex::encode(
                keccak::hash(b"UsdcDeposited(address,string,address,uint256,uint256)")
                    .to_bytes()
            )
        );

        let mut cursor = from;
        while cursor <= to {
            let chunk_end = (cursor + MAX_LOG_RANGE - 1).min(to);
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_getLogs",
                "params": [{
                    "fromBlock": format!("0x{:x}", cursor),
                    "toBlock":   format!("0x{:x}", chunk_end),
                    "address":   contract,
                    "topics":    [topic0]
                }]
            });
            match self.rpc_call::<RpcEnvelope<Vec<EthLog>>>(body).await {
                Ok(env) => {
                    let logs = env.result.unwrap_or_default();
                    if !logs.is_empty() {
                        info!(
                            "⛓️  BSC Bridge: {} UsdcDeposited events [{}-{}]",
                            logs.len(), cursor, chunk_end
                        );
                    }
                    for log in &logs {
                        self.process_deposited_event(log).await;
                    }
                }
                Err(e) => {
                    warn!("⚠️  BSC Bridge eth_getLogs [{}-{}]: {}", cursor, chunk_end, e);
                    break;
                }
            }
            cursor = chunk_end + 1;
        }
    }

    /// Process a single `UsdcDeposited` event emitted by the BlackbookBridge contract.
    ///
    /// Decodes the ABI-encoded data to extract `l1Wallet`, `amount`, and `depositIndex`,
    /// then auto-creates a `DepositRecord` and mints BB without requiring any prior
    /// `/deposit/request` HTTP call.
    async fn process_deposited_event(&self, log: &EthLog) {
        let tx_hash = log.transaction_hash.to_lowercase();

        if self.blockchain.is_bridge_tx_processed(&tx_hash) {
            return;
        }

        if log.topics.len() < 3 {
            warn!(
                "⚠️  UsdcDeposited missing topics: {}",
                &tx_hash[..18.min(tx_hash.len())]
            );
            return;
        }

        let (l1_wallet, raw_amount, _deposit_index) = match self.decode_deposited_data(log) {
            Some(v) => v,
            None => {
                warn!(
                    "⚠️  UsdcDeposited ABI decode failed: {}",
                    &tx_hash[..18.min(tx_hash.len())]
                );
                return;
            }
        };

        // topics[2] is the `address indexed token`, padded to 32 bytes ("0x{24 zeros}{40 hex}")
        let topics2 = &log.topics[2];
        let raw_addr = topics2.trim_start_matches("0x");
        let token_addr =
            format!("0x{}", &raw_addr[raw_addr.len().saturating_sub(40)..]).to_lowercase();

        let asset = if token_addr == self.usdc_contract.to_lowercase() {
            "USDC"
        } else if token_addr == self.usdt_contract.to_lowercase() {
            "USDT"
        } else {
            warn!("⚠️  UsdcDeposited: unrecognised token {}", token_addr);
            return;
        };

        // BSC Binance-Peg tokens have 18 decimals; normalise to 6-decimal micro-units
        // then convert to BB lamports via the same integer math as the Solana path.
        if raw_amount == 0 {
            return;
        }
        let micro_stablecoin = (raw_amount / 1_000_000_000_000u128) as u64; // 18 → 6 dec
        let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(micro_stablecoin);
        if micro_stablecoin == 0 {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = crate::storage::DepositRecord {
            wallet_address: l1_wallet.clone(),
            external_tx_hash: tx_hash.clone(),
            asset: asset.to_string(),
            amount_micro_stablecoin: micro_stablecoin,
            bb_lamports,
            status: "pending".to_string(),
            submitted_at: now,
            approved_at: None,
            contest_id: None,
        };

        // Insert into hot-cache (no-op if the custodial path already registered this tx)
        self.deposit_requests
            .entry(tx_hash.clone())
            .or_insert_with(|| {
                let _ = self.blockchain.store_deposit_request(&record);
                record.clone()
            });

        match self.mint_and_record(&tx_hash, &record).await {
            Ok(bb) => info!(
                "✅ BSC Bridge auto-minted: {:.6} {} → {:.5} BB for {} (tx: {})",
                micro_stablecoin as f64 / 1_000_000.0,
                asset,
                bb,
                &l1_wallet[..8.min(l1_wallet.len())],
                &tx_hash[..18.min(tx_hash.len())]
            ),
            Err(e) => warn!(
                "⚠️  BSC Bridge mint failed ({}): {}",
                &tx_hash[..18.min(tx_hash.len())],
                e
            ),
        }
    }

    /// ABI-decode the `data` field of a `UsdcDeposited` event.
    ///
    /// ```text
    /// Solidity: UsdcDeposited(address indexed, string, address indexed, uint256, uint256)
    /// Non-indexed payload ABI-encoded as (string l1Wallet, uint256 amount, uint256 depositIndex):
    ///
    ///   bytes   0-31   offset to string (= 0x60 = 96)
    ///   bytes  32-63   amount     (uint256 BE — last 16 bytes taken as u128)
    ///   bytes  64-95   depositIndex (uint256 BE — last 8 bytes taken as u64)
    ///   bytes  96-127  string length
    ///   bytes 128+     string bytes (zero-padded to 32-byte boundary)
    /// ```
    fn decode_deposited_data(&self, log: &EthLog) -> Option<(String, u128, u64)> {
        let hex = log.data.trim_start_matches("0x");
        let data = hex::decode(hex).ok()?;
        if data.len() < 128 {
            return None;
        }

        // Word 1 (bytes 32-63): amount — last 16 bytes as u128
        let amount = u128::from_be_bytes(data[48..64].try_into().ok()?);

        // Word 2 (bytes 64-95): depositIndex — last 8 bytes as u64
        let deposit_index = u64::from_be_bytes(data[88..96].try_into().ok()?);

        // Word 3 (bytes 96-127): string length — last 8 bytes as u64
        let str_len = u64::from_be_bytes(data[120..128].try_into().ok()?) as usize;

        if data.len() < 128 + str_len {
            return None;
        }
        let str_bytes = &data[128..128 + str_len];
        let l1_wallet = String::from_utf8(str_bytes.to_vec()).ok()?;

        Some((l1_wallet, amount, deposit_index))
    }

    // ── Log fetching ──────────────────────────────────────────────────────────

    /// Fetch all Transfer events targeting our custody wallet on the USDC/USDT contracts.
    async fn fetch_transfer_logs(&self, from: u64, to: u64) -> Result<Vec<EthLog>, String> {
        // topics[2] = custody wallet padded to 32 bytes
        let to_topic = format!("0x000000000000000000000000{}", self.custody_lower);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": format!("0x{:x}", from),
                "toBlock":   format!("0x{:x}", to),
                "address":   [&self.usdc_contract, &self.usdt_contract],
                "topics":    [TRANSFER_TOPIC, null, to_topic]
            }]
        });

        let env: RpcEnvelope<Vec<EthLog>> = self.rpc_call(body).await?;
        if let Some(err) = env.error {
            return Err(format!("RPC error: {}", err));
        }
        Ok(env.result.unwrap_or_default())
    }

    // ── Log processing ────────────────────────────────────────────────────────

    async fn process_log(&self, log: &EthLog) {
        let tx_hash = log.transaction_hash.to_lowercase();

        // Only act on TXs with a matching pending deposit request (same as Solana watcher)
        if !self.deposit_requests.contains_key(&tx_hash) {
            return;
        }
        if self.blockchain.is_bridge_tx_processed(&tx_hash) {
            return;
        }

        match self.verify_and_approve_bsc(&tx_hash, log).await {
            Ok(bb) => info!(
                "✅ BSC auto-approved {} → {} BB",
                &tx_hash[..18.min(tx_hash.len())],
                bb
            ),
            Err(e) => warn!(
                "⚠️  BSC auto-approve failed ({}): {}",
                &tx_hash[..18.min(tx_hash.len())],
                e
            ),
        }
    }

    // ── Verification + minting ────────────────────────────────────────────────

    async fn verify_and_approve_bsc(
        &self,
        tx_hash: &str,
        log: &EthLog,
    ) -> Result<f64, String> {
        let record = self
            .deposit_requests
            .get(tx_hash)
            .ok_or("No matching deposit request")?
            .clone();

        if record.status != "pending" {
            return Err(format!("Already '{}'", record.status));
        }

        // Decode the amount from the log data
        let verified = self.decode_transfer(log)?;

        if verified.asset != record.asset {
            return Err(format!(
                "Asset mismatch: declared {} but log shows {}",
                record.asset, verified.asset
            ));
        }
        let tolerance = (record.amount_micro_stablecoin as f64 / 1_000_000.0 * 0.01_f64).max(0.01);
        let record_amount = record.amount_micro_stablecoin as f64 / 1_000_000.0;
        if (verified.amount - record_amount).abs() > tolerance {
            return Err(format!(
                "Amount mismatch: declared {:.4} but log shows {:.4} {}",
                record_amount, verified.amount, verified.asset
            ));
        }

        self.mint_and_record(tx_hash, &record).await
    }

    // ── Public: verify a specific BSC tx hash on-chain ───────────────────────

    /// Verify a BSC transaction by hash, then mint BB and record the deposit.
    /// Called directly from the HTTP deposit request handler for instant approvals.
    ///
    /// Looks up the deposit record by `tx_hash` (must already be in `deposit_requests`),
    /// fetches `eth_getTransactionReceipt` to confirm the transfer reached the custody
    /// wallet, then mints BB exactly as the background poller would.
    pub async fn verify_and_approve(&self, tx_hash: &str) -> Result<f64, String> {
        let record = self.deposit_requests.get(tx_hash)
            .ok_or("No matching deposit request")?
            .clone();

        if record.status != "pending" {
            return Err(format!("Already '{}'", record.status));
        }

        // Fetch + decode the receipt logs to confirm the transfer
        let verified = self.verify_receipt(tx_hash).await?;

        // Validate declared asset and amount
        if verified.asset != record.asset {
            return Err(format!(
                "Asset mismatch: declared {} but receipt shows {}",
                record.asset, verified.asset
            ));
        }
        let tolerance = (record.amount_micro_stablecoin as f64 / 1_000_000.0 * 0.01_f64).max(0.01);
        let record_amount = record.amount_micro_stablecoin as f64 / 1_000_000.0;
        if (verified.amount - record_amount).abs() > tolerance {
            return Err(format!(
                "Amount mismatch: declared {:.4} but receipt shows {:.4}",
                record_amount, verified.amount
            ));
        }

        self.mint_and_record(tx_hash, &record).await
    }

    /// Fetch `eth_getTransactionReceipt` and decode the incoming Transfer log for
    /// our custody wallet. Returns the asset name and human-readable amount.
    async fn verify_receipt(&self, tx_hash: &str) -> Result<VerifiedTransfer, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash]
        });

        #[derive(serde::Deserialize)]
        struct Receipt {
            logs: Option<Vec<ReceiptLog>>,
        }
        #[derive(serde::Deserialize)]
        struct ReceiptLog {
            address: String,
            topics: Vec<String>,
            data: String,
        }

        let env: RpcEnvelope<Receipt> = self.rpc_call(body).await?;
        let receipt = env.result.ok_or("Transaction not found (not yet mined?)")?;
        let logs = receipt.logs.unwrap_or_default();

        let to_padded = format!("0x000000000000000000000000{}", self.custody_lower);

        for log in &logs {
            // Must be USDC or USDT contract
            let contract_lower = log.address.to_lowercase();
            let asset = if contract_lower == self.usdc_contract.to_lowercase() { "USDC" }
                else if contract_lower == self.usdt_contract.to_lowercase() { "USDT" }
                else { continue };

            // topics[0] = Transfer sig, topics[2] = to address
            if log.topics.len() < 3 { continue; }
            if log.topics[0].to_lowercase()
                != "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" { continue; }
            if log.topics[2].to_lowercase() != to_padded { continue; }

            let hex_data = log.data.trim_start_matches("0x");
            let data_bytes = hex::decode(hex_data)
                .unwrap_or_default();
            if data_bytes.len() < 32 { continue; }
            let raw = u128::from_be_bytes(
                data_bytes[16..32].try_into().unwrap_or([0u8; 16])
            );
            let divisor = 10u128.pow(BSC_TOKEN_DECIMALS);
            let amount = raw as f64 / divisor as f64;
            return Ok(VerifiedTransfer { asset: asset.to_string(), amount });
        }
        Err("No matching Transfer event to custody wallet found in receipt".to_string())
    }

    /// Core mint-and-record logic used by both the background poller and the
    /// direct HTTP verification path.
    async fn mint_and_record(&self, tx_hash: &str, record: &crate::storage::DepositRecord) -> Result<f64, String> {
        // Bug #2: reserve-before-mint to eliminate the double-mint race window
        let mint_tx_id = Uuid::new_v4().to_string();
        self.blockchain.reserve_bridge_tx(tx_hash)
            .map_err(|e| format!("Reserve failed: {}", e))?;

        match self.blockchain.credit_lamports(&record.wallet_address, record.bb_lamports) {
            Ok(_) => {
                if let Err(e) = self.blockchain.commit_bridge_tx(tx_hash, &mint_tx_id) {
                    info!("⚠️  commit_bridge_tx: {}", e);
                }
            }
            Err(e) => {
                self.blockchain.cancel_bridge_tx(tx_hash);
                return Err(format!("BB mint failed: {}", e));
            }
        }

        // Update record
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(mut entry) = self.deposit_requests.get_mut(tx_hash) {
            entry.status = "approved".to_string();
            entry.approved_at = Some(now);
        }
        if let Some(updated) = self.deposit_requests.get(tx_hash) {
            let _ = self.blockchain.store_deposit_request(&*updated);
        }

        // PoH record
        let proto_tx = ProtoTx {
            hash: mint_tx_id,
            from: format!("BSC_DEPOSIT:{}", self.custody_address),
            timestamp: now,
            data: TxData::DepositUsdt {
                usdt_amount: record.amount_micro_stablecoin,
                external_tx_hash: Some(tx_hash.to_string()),
            },
            signature: "bsc_verified".to_string(),
            signer_pubkey: "BSC_WATCHER".to_string(),
        };
        self.block_producer.record_executed_transaction(proto_tx);

        info!("✅ BSC approved: {:.6} {} → {:.5} BB for {} (tx: {})",
            record.amount_micro_stablecoin as f64 / 1_000_000.0,
            record.asset,
            record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
            &record.wallet_address[..8.min(record.wallet_address.len())],
            &tx_hash[..18.min(tx_hash.len())]);

        Ok(record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64)
    }

    // ── Amount decoding ───────────────────────────────────────────────────────

    /// Decode the uint256 amount from a Transfer log and resolve the asset name.
    fn decode_transfer(&self, log: &EthLog) -> Result<VerifiedTransfer, String> {
        // Identify asset by contract address (case-insensitive compare)
        let contract_lower = log.address.to_lowercase();
        let asset = if contract_lower == self.usdc_contract.to_lowercase() {
            "USDC"
        } else if contract_lower == self.usdt_contract.to_lowercase() {
            "USDT"
        } else {
            return Err(format!("Unknown contract: {}", log.address));
        };

        // Bug #4: use hex::decode for bounds-checked binary decode (no string-slice panic)
        let hex_data = log.data.trim_start_matches("0x");
        let data_bytes = hex::decode(hex_data)
            .map_err(|e| format!("Bad hex in log data: {}", e))?;
        if data_bytes.len() < 32 {
            return Err(format!("Transfer data too short: {} bytes (expected ≥32)", data_bytes.len()));
        }
        // uint256 value is in the first 32 bytes (big-endian); take last 16 bytes as u128
        let raw = u128::from_be_bytes(
            data_bytes[16..32].try_into()
                .map_err(|_| "Amount slice error".to_string())?
        );

        let divisor = 10u128.pow(BSC_TOKEN_DECIMALS);
        let amount = raw as f64 / divisor as f64;

        Ok(VerifiedTransfer {
            asset: asset.to_string(),
            amount,
        })
    }

    // ── Public balance queries (for admin/status endpoints) ───────────────────

    /// Returns the on-chain BEP-20 USDC balance of the custody wallet.
    pub async fn fetch_usdc_balance(&self) -> Result<f64, String> {
        self.fetch_erc20_balance(&self.usdc_contract, BSC_TOKEN_DECIMALS).await
    }

    /// Returns the on-chain BEP-20 USDT balance of the custody wallet.
    pub async fn fetch_usdt_balance(&self) -> Result<f64, String> {
        self.fetch_erc20_balance(&self.usdt_contract, BSC_TOKEN_DECIMALS).await
    }

    async fn fetch_erc20_balance(&self, contract: &str, decimals: u32) -> Result<f64, String> {
        // balanceOf(address) selector = 0x70a08231, then address padded to 32 bytes
        let call_data = format!(
            "0x70a08231000000000000000000000000{}",
            self.custody_lower
        );
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                { "to": contract, "data": call_data },
                "latest"
            ]
        });
        let env: RpcEnvelope<String> = self.rpc_call(body).await?;
        let hex = env.result.ok_or("empty result")?.replace("0x", "");
        if hex.is_empty() || hex.chars().all(|c| c == '0') {
            return Ok(0.0);
        }
        let raw = u128::from_str_radix(hex.trim_start_matches('0'), 16)
            .map_err(|e| format!("Balance parse: {}", e))?;
        Ok(raw as f64 / 10u128.pow(decimals) as f64)
    }

    // ── Block number ──────────────────────────────────────────────────────────

    async fn get_latest_block(&self) -> Result<u64, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_blockNumber",
            "params": []
        });
        let env: RpcEnvelope<String> = self.rpc_call(body).await?;
        let hex = env.result.ok_or("empty result")?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Block parse: {}", e))
    }

    // ── RPC helper ────────────────────────────────────────────────────────────

    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        body: serde_json::Value,
    ) -> Result<T, String> {
        self.http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<T>()
            .await
            .map_err(|e| format!("JSON parse: {}", e))
    }
}
