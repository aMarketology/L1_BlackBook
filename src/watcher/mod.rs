pub mod bsc_watcher;
pub use bsc_watcher::{BscWatcher, BSC_USDC_CONTRACT, BSC_USDT_CONTRACT};
pub mod mayan;
pub mod solana_ws;
pub mod bsc_ws;

// ============================================================================
// CUSTODY WALLET WATCHER
// ============================================================================
//
// Background service that periodically polls the custody wallet's SPL token
// balances (USDC + USDT) on the external Solana chain, logging snapshots and
// auto-approving any pending DepositRecords whose transactions are finalized.
//
// Flow:
//   Every WATCHER_POLL_SECS seconds:
//     1. Fetch USDC balance of custody wallet  → log
//     2. Fetch USDT balance of custody wallet  → log
//     3. getSignaturesForAddress (last 20 txs)
//        For each finalized TX that matches a pending DepositRecord:
//          a. getTransaction → verify amount + asset
//          b. mint BB, mark processed, update status, record in PoH
//
// Config (env vars):
//   SOLANA_RPC_URL    — Solana JSON-RPC endpoint  (default: mainnet-beta)
//   WATCHER_POLL_SECS — poll interval in seconds  (default: 30)
//   USDC_MINT         — USDC SPL mint address     (default: mainnet USDC)
//   USDT_MINT         — USDT SPL mint address     (default: mainnet USDT)
// ============================================================================

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::storage::{ConcurrentBlockchain, DepositRecord};
use crate::poh_blockchain::BlockProducer;
use crate::protocol::{Transaction as ProtoTx, TxData};

// ── Well-known Solana mainnet SPL token mints ─────────────────────────────────

/// Solana mainnet USDC SPL token mint.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// Solana mainnet USDT SPL token mint.
pub const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

/// Exchange rate between stablecoins and BB (1 USDC = 10 BB — $0.10/BB).
#[allow(dead_code)]
const BB_PER_STABLECOIN: f64 = 10.0;

// ── Watcher struct ────────────────────────────────────────────────────────────

pub struct CustodyWatcher {
    /// External Solana JSON-RPC URL.
    pub rpc_url: String,
    /// Base58 address of the custody wallet that receives USDC/USDT on Solana.
    pub custody_address: String,
    /// SPL mint for USDC (configurable for devnet).
    pub usdc_mint: String,
    /// SPL mint for USDT (configurable for devnet).
    pub usdt_mint: String,
    /// How often (seconds) to poll.
    poll_interval_secs: u64,
    /// BlackBook L1 storage layer.
    blockchain: ConcurrentBlockchain,
    /// Shared hot-cache of pending/approved deposit requests.
    deposit_requests: Arc<DashMap<String, DepositRecord>>,
    /// PoH block producer — used to record minting events on-chain.
    block_producer: Arc<BlockProducer>,
    /// Persistent HTTP client (connection-pooled).
    http: reqwest::Client,
    /// Newest Solana signature already seen — used as `until` pagination param.
    last_signature: tokio::sync::Mutex<Option<String>>,
}

// ── Solana JSON-RPC response types (minimal — only fields we consume) ─────────

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
}

// getTokenAccountsByOwner
#[derive(Deserialize)]
struct TokenAccountsResult {
    value: Vec<TokenAccountEntry>,
}
#[derive(Deserialize)]
struct TokenAccountEntry {
    account: AccountOuter,
}
#[derive(Deserialize)]
struct AccountOuter {
    data: AccountDataField,
}
#[derive(Deserialize)]
struct AccountDataField {
    parsed: AccountParsed,
}
#[derive(Deserialize)]
struct AccountParsed {
    info: SplTokenInfo,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SplTokenInfo {
    token_amount: UiTokenAmount,
}
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UiTokenAmount {
    ui_amount: Option<f64>,
}

// getSignaturesForAddress
#[derive(Deserialize, Clone)]
struct SignatureInfo {
    signature: String,
    err: Option<serde_json::Value>,
    /// Solana memo program output (if any) — e.g. "BB:5YNmS1R9nNSCDzb5a7mMJ1dwK9uHeAAF4CmPEwKgVWr8"
    memo: Option<String>,
}

// getTransaction
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SolanaTx {
    meta: Option<TxMeta>,
    transaction: Option<SolTxBody>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxMeta {
    err: Option<serde_json::Value>,
    pre_token_balances: Option<Vec<TxTokenBalance>>,
    post_token_balances: Option<Vec<TxTokenBalance>>,
    /// CPI calls — Mayan's final USDT delivery may be inside a CPI
    inner_instructions: Option<Vec<SolInnerInstructionGroup>>,
}

/// Outer transaction body — holds the message with top-level instructions.
#[derive(Deserialize)]
struct SolTxBody {
    message: SolTxMessage,
}
#[derive(Deserialize)]
struct SolTxMessage {
    instructions: Vec<SolRawInstruction>,
}
/// A single instruction deserialized loosely.
/// Parsed instructions (SPL token etc) have no `data` field — we ignore them.
/// Raw Mayan / Wormhole instructions have a base58-encoded `data` field.
#[derive(Deserialize)]
struct SolRawInstruction {
    /// Base58-encoded instruction data (absent on `jsonParsed` SPL instructions).
    data: Option<String>,
}
/// A group of inner (CPI) instructions keyed by the outer instruction index.
#[derive(Deserialize)]
struct SolInnerInstructionGroup {
    instructions: Vec<SolRawInstruction>,
}
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TxTokenBalance {
    account_index: usize,
    mint: String,
    owner: Option<String>,
    ui_token_amount: UiTokenAmount,
}

// getProgramAccounts
#[derive(Deserialize)]
struct ProgramAccountEntry {
    pubkey: String,
    account: ProgramAccountBody,
}
#[derive(Deserialize)]
struct ProgramAccountBody {
    /// ["base64data", "base64"]
    data: Vec<String>,
}

/// Stripped result of a successful on-chain verification.
pub struct VerifiedDeposit {
    pub asset: String,
    pub amount: f64,
    /// L1 BB wallet decoded from a Mayan `customPayload` embedded in the transaction.
    /// `None` if no valid 0xBB01 payload was found in any instruction of this tx.
    pub mayan_wallet: Option<String>,
}

// ── Implementation ────────────────────────────────────────────────────────────

impl CustodyWatcher {
    pub fn new(
        rpc_url: String,
        custody_address: String,
        usdc_mint: String,
        usdt_mint: String,
        poll_interval_secs: u64,
        blockchain: ConcurrentBlockchain,
        deposit_requests: Arc<DashMap<String, DepositRecord>>,
        block_producer: Arc<BlockProducer>,
    ) -> Self {
        Self {
            rpc_url,
            custody_address,
            usdc_mint,
            usdt_mint,
            poll_interval_secs,
            blockchain,
            deposit_requests,
            block_producer,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest::Client::build"),
            last_signature: tokio::sync::Mutex::new(None),
        }
    }

    /// Spawn background tasks for deposit detection.
    ///
    /// **Event-driven mode** (when `SOLANA_WS_URL` is set):
    ///   - Spawns a persistent `logsSubscribe` WebSocket subscriber for real-time detection.
    ///   - Runs a slow fallback poll (default 300 s, override via `WATCHER_FALLBACK_POLL_SECS`)
    ///     that catches any events the WebSocket may have missed (e.g. during a reconnect
    ///     window) and scans the Bridge program for non-custodial deposits.
    ///
    /// **Legacy polling mode** (when `SOLANA_WS_URL` is absent):
    ///   - Falls back to the original `poll_interval_secs`-second polling loop.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("👀 Custody watcher started — {} (strict No-Seed mode)", self.custody_address);

            let ws_url = std::env::var("SOLANA_WS_URL")
                .ok()
                .filter(|s| s.starts_with("wss://"));

            if let Some(url) = ws_url {
                let fallback_secs = std::env::var("WATCHER_FALLBACK_POLL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(300);
                info!("👀 Solana WS mode active — fallback poll every {}s", fallback_secs);
                solana_ws::start_solana_ws(Arc::clone(&self), url);
                let mut interval = tokio::time::interval(Duration::from_secs(fallback_secs));
                loop {
                    interval.tick().await;
                    self.poll_once().await;
                }
            } else {
                info!("👀 Solana polling mode — interval {}s", self.poll_interval_secs);
                let mut interval =
                    tokio::time::interval(Duration::from_secs(self.poll_interval_secs));
                loop {
                    interval.tick().await;
                    self.poll_once().await;
                }
            }
        });
    }

    async fn poll_once(&self) {
        // 1. Balance snapshots
        match self.fetch_token_balance(&self.usdc_mint).await {
            Ok(bal) => info!("💵 Custody USDC: {:.6}", bal),
            Err(e)  => warn!("⚠️  USDC balance: {}", e),
        }
        match self.fetch_token_balance(&self.usdt_mint).await {
            Ok(bal) => info!("💵 Custody USDT: {:.6}", bal),
            Err(e)  => warn!("⚠️  USDT balance: {}", e),
        }

        // 2. Scan and auto-approve new finalized deposits
        self.scan_new_deposits().await;

        // 3. Scan BlackBook Bridge program for non-custodial deposits
        self.scan_bridge_program_deposits().await;
    }

    // ── Public: balance fetch ────────────────────────────────────────────────

    /// Returns the total SPL token balance for `mint` held by the custody wallet.
    pub async fn fetch_token_balance(&self, mint: &str) -> Result<f64, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                self.custody_address,
                { "mint": mint },
                { "encoding": "jsonParsed" }
            ]
        });
        let resp: RpcEnvelope<TokenAccountsResult> = self.rpc_call(body).await?;
        let accounts = resp.result.ok_or("empty result")?.value;
        Ok(accounts.iter()
            .filter_map(|e| e.account.data.parsed.info.token_amount.ui_amount)
            .sum())
    }

    // ── Private: signature scan ──────────────────────────────────────────────

    // ── Private: Anchor bridge program scan (non-custodial Solana deposits) ────

    /// Scan the BlackBook Bridge Anchor program for `DepositReceipt` PDAs that
    /// have not yet been acknowledged (`bb_minted = false`) and mint BB for them.
    ///
    /// Requires `BRIDGE_PROGRAM_ID` env var — silently skips if unset (program
    /// not yet deployed).
    async fn scan_bridge_program_deposits(&self) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;

        let program_id = match std::env::var("BRIDGE_PROGRAM_ID") {
            Ok(v) if !v.is_empty() => v,
            _ => return, // bridge program not deployed yet, skip silently
        };

        // DepositReceipt::LEN = 127 bytes (discriminator 8 + all fields)
        // bb_minted bool is at byte offset 117.
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getProgramAccounts",
            "params": [
                program_id,
                {
                    "encoding": "base64",
                    "filters": [
                        { "dataSize": 127 }
                    ]
                }
            ]
        });

        let resp: RpcEnvelope<Vec<ProgramAccountEntry>> = match self.rpc_call(body).await {
            Ok(r) => r,
            Err(e) => { warn!("⚠️  getProgramAccounts (bridge): {}", e); return; }
        };

        let accounts = match resp.result { Some(v) => v, None => return };
        if accounts.is_empty() { return; }

        for pa in &accounts {
            // Decode base64 account data
            let raw = match pa.account.data.first()
                .and_then(|s| B64.decode(s).ok())
            {
                Some(b) => b,
                None => continue,
            };
            if raw.len() < 127 { continue; }

            // Byte layout (after 8-byte discriminator):
            //   8..40  depositor Pubkey
            //  40..84  l1_wallet_bytes [u8;44]
            //     84   l1_wallet_len u8
            //  85..93  usdc_amount u64 LE
            //  93..101 deposit_index u64 LE
            // 101..109 solana_slot u64 LE
            // 109..117 created_at i64 LE
            //    117   bb_minted bool
            // 118..126 l1_mint_slot u64 LE
            //    126   bump u8
            let bb_minted = raw[117];
            if bb_minted != 0 { continue; } // already processed on-chain

            // Belt-and-suspenders: also check our local DB
            let receipt_key = pa.pubkey.clone();
            if self.blockchain.is_bridge_tx_processed(&receipt_key) { continue; }

            let wallet_len = (raw[84] as usize).min(44);
            let l1_wallet = match std::str::from_utf8(&raw[40..40 + wallet_len]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            let usdc_raw = u64::from_le_bytes(
                raw[85..93].try_into().unwrap_or_default()
            );
            let usdc_amount = usdc_raw as f64 / 1_000_000.0; // 6 decimals

            if usdc_raw == 0 { continue; }

            // Single-txn ACID mint + processed bridge seal
            let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(usdc_raw);
            let mint_tx_id = uuid::Uuid::new_v4().to_string();
            match self.blockchain.atomic_mint_bridge_deposit(
                &receipt_key,
                &l1_wallet,
                bb_lamports,
                &mint_tx_id,
                None,
                false,
            ) {
                Ok(_) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_secs();
                    let proto_tx = ProtoTx {
                        hash: mint_tx_id,
                        from: format!("BRIDGE_PROGRAM:{}", program_id),
                        timestamp: now,
                        data: TxData::DepositUsdt {
                            usdt_amount: usdc_raw,
                            external_tx_hash: Some(receipt_key.clone()),
                        },
                        signature: "bridge_program_scan".to_string(),
                        signer_pubkey: "WATCHER".to_string(),
                    };
                    self.block_producer.record_executed_transaction(proto_tx);

                    info!("✅ Bridge program: {:.6} USDC → {:.5} BB for {} (receipt: {})",
                        usdc_amount, bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
                        &l1_wallet[..8.min(l1_wallet.len())],
                        &receipt_key[..16.min(receipt_key.len())]);
                }
                Err(e) => {
                    warn!("⚠️  Bridge program mint failed ({}): {}", &receipt_key[..16.min(receipt_key.len())], e);
                }
            }
        }
    }

    async fn scan_new_deposits(&self) {
        let until_sig = self.last_signature.lock().await.clone();
        let mut params = serde_json::json!({ "limit": 20 });
        if let Some(ref sig) = until_sig {
            params["until"] = serde_json::Value::String(sig.clone());
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getSignaturesForAddress",
            "params": [self.custody_address, params]
        });
        let resp: RpcEnvelope<Vec<SignatureInfo>> = match self.rpc_call(body).await {
            Ok(r) => r,
            Err(e) => { warn!("⚠️  getSignaturesForAddress: {}", e); return; }
        };
        let sigs = match resp.result { Some(v) => v, None => return };
        if sigs.is_empty() { return; }

        // Advance pagination anchor (Solana returns newest-first)
        { *self.last_signature.lock().await = Some(sigs[0].signature.clone()); }

        for sig in sigs.iter().filter(|s| s.err.is_none()) {
            self.dispatch_signature(&sig.signature, sig.memo.as_deref()).await;
        }
    }

    /// Core per-signature deposit pipeline — shared by the WebSocket subscriber,
    /// the polling fallback, and webhook receivers.
    ///
    /// `memo` is the Solana memo string from `getSignaturesForAddress`.  The
    /// WebSocket and webhook paths pass `None` because their notifications do not
    /// include the memo; the slow fallback poller passes the real value.  Tier 2
    /// (memo-based attribution) is only reached when `memo` is `Some`.
    pub async fn dispatch_signature(&self, sig: &str, memo: Option<&str>) {
        // ── Tier 1: explicit /deposit/request was registered for this tx hash ────
        if self.deposit_requests.contains_key(sig) {
            if !self.blockchain.is_bridge_tx_processed(sig) {
                match self.verify_and_approve(sig).await {
                    Ok(bb) => info!("✅ Watcher auto-approved {} → {:.5} BB",
                        &sig[..16.min(sig.len())], bb),
                    Err(e) => warn!("⚠️  Auto-approve failed ({}): {}",
                        &sig[..16.min(sig.len())], e),
                }
            }
            return;
        }

        // Already committed from a previous run — idempotency guard.
        if self.blockchain.is_bridge_tx_processed(sig) { return; }

        // Fetch the full on-chain transfer details for Tiers 2 / 2.5 / 3.
        let verified = match self.verify_transaction(sig).await {
            Ok(v) => v,
            Err(_) => return, // not a stablecoin transfer to the custody wallet
        };
        let micro = (verified.amount * crate::svm::USDC_UNIT as f64).round() as u64;
        if micro == 0 { return; }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();

        // ── Tier 2.5: Mayan customPayload attribution ──────────────────────────
        if let Some(wallet) = verified.mayan_wallet.as_ref() {
            let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(micro);
            let record = crate::storage::DepositRecord {
                wallet_address: wallet.clone(),
                external_tx_hash: sig.to_string(),
                asset: verified.asset.clone(),
                amount_micro_stablecoin: micro,
                bb_lamports,
                status: "pending".to_string(),
                submitted_at: now,
                approved_at: None,
                contest_id: None,
            };
            let _ = self.blockchain.store_deposit_request(&record);
            self.deposit_requests.insert(sig.to_string(), record);
            match self.verify_and_approve(sig).await {
                Ok(bb) => info!(
                    "✅ Mayan payload deposit: {} {:.6} → {:.5} BB for {} (tx: {})",
                    verified.asset, verified.amount, bb,
                    &wallet[..8.min(wallet.len())], &sig[..16.min(sig.len())]
                ),
                Err(e) => warn!(
                    "⚠️  Mayan payload mint failed ({}): {}",
                    &sig[..16.min(sig.len())], e
                ),
            }
            return;
        }

        // ── Tier 2: memo-based attribution ─────────────────────────────────────
        if let Some(wallet) = Self::extract_wallet_from_memo(memo) {
            let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(micro);
            let record = crate::storage::DepositRecord {
                wallet_address: wallet.clone(),
                external_tx_hash: sig.to_string(),
                asset: verified.asset.clone(),
                amount_micro_stablecoin: micro,
                bb_lamports,
                status: "pending".to_string(),
                submitted_at: now,
                approved_at: None,
                contest_id: None,
            };
            let _ = self.blockchain.store_deposit_request(&record);
            self.deposit_requests.insert(sig.to_string(), record);
            match self.verify_and_approve(sig).await {
                Ok(bb) => info!(
                    "✅ Memo-attributed deposit: {} {:.6} → {:.5} BB (tx: {})",
                    verified.asset, verified.amount, bb, &sig[..16.min(sig.len())]
                ),
                Err(e) => warn!(
                    "⚠️  Memo-attributed mint failed ({}): {}",
                    &sig[..16.min(sig.len())], e
                ),
            }
            return;
        }

        // ── Tier 3: no attribution — queue for manual /deposit/claim ───────────
        let unattributed = crate::storage::UnattributedDeposit {
            external_tx_hash: sig.to_string(),
            asset: verified.asset.clone(),
            amount_micro_stablecoin: micro,
            observed_at: now,
            claimed_by: None,
        };
        match self.blockchain.write_unattributed_deposit(&unattributed) {
            Ok(_) => warn!(
                "📥 Unattributed deposit queued: {:.6} {} (tx: {}) — user must call /deposit/claim",
                verified.amount, verified.asset, &sig[..16.min(sig.len())]
            ),
            Err(e) => warn!(
                "⚠️  Failed to write unattributed deposit ({}): {}",
                &sig[..16.min(sig.len())], e
            ),
        }
    }

    /// Extract a BB wallet from a Solana memo string.
    ///
    /// Expects the memo to be exactly `"BB:<base58_wallet>"` or a string
    /// containing that prefix (Solana prepends program context sometimes).
    /// The wallet must be a valid 32-byte base58 public key.
    fn extract_wallet_from_memo(memo: Option<&str>) -> Option<String> {
        let text = memo?;
        // Handle both raw memo ("BB:...") and Memo-program-prefixed strings
        let wallet = text.split_whitespace()
            .find_map(|word| word.strip_prefix("BB:"))
            .unwrap_or_else(|| text.strip_prefix("BB:").unwrap_or(""));
        if wallet.is_empty() { return None; }
        // Validate: must decode to exactly 32 bytes
        if bs58::decode(wallet).into_vec().map(|v| v.len() == 32).unwrap_or(false) {
            Some(wallet.to_string())
        } else {
            None
        }
    }

    // ── Public: verify + mint ────────────────────────────────────────────────

    /// Verify a Solana transaction on-chain, then mint BB and record the deposit
    /// in the PoH ledger. Safe to call from HTTP handlers as well as the background task.
    ///
    /// Returns the number of BB minted, or an error if verification fails.
    pub async fn verify_and_approve(&self, tx_hash: &str) -> Result<f64, String> {
        let record = self.deposit_requests.get(tx_hash)
            .ok_or("No matching deposit request")?
            .clone();

        if record.status != "pending" {
            return Err(format!("Already '{}'", record.status));
        }

        // ── On-chain verification ─────────────────────────────────────────
        let verified = self.verify_transaction(tx_hash).await?;

        // Amount must match within 1% tolerance (or $0.01 minimum)
        let record_amount = record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64;
        let tolerance = (record_amount * 0.01_f64).max(0.01);
        if (verified.amount - record_amount).abs() > tolerance {
            return Err(format!(
                "Amount mismatch: claimed {:.2} but chain shows {:.2} {}",
                record_amount, verified.amount, verified.asset
            ));
        }
        if verified.asset != record.asset {
            return Err(format!(
                "Asset mismatch: claimed {} but chain shows {}",
                record.asset, verified.asset
            ));
        }

        // ── Single-txn ACID mint + deposit approval + processed seal ──────
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut updated = record.clone();
        updated.status = "approved".to_string();
        updated.approved_at = Some(now);

        let mint_tx_id = Uuid::new_v4().to_string();
        self.blockchain.atomic_mint_bridge_deposit(
            tx_hash,
            &record.wallet_address,
            record.bb_lamports,
            &mint_tx_id,
            Some(&updated),
            false,
        )?;
        self.deposit_requests.insert(tx_hash.to_string(), updated);

        // ── Record in PoH ledger ──────────────────────────────────────────
        {
            let proto_tx = ProtoTx {
                hash: mint_tx_id.clone(),
                from: "DEPOSIT_GATEWAY".to_string(),
                timestamp: now,
                data: TxData::DepositUsdt {
                    usdt_amount: record.amount_micro_stablecoin,
                    external_tx_hash: Some(tx_hash.to_string()),
                },
                signature: "auto_verified".to_string(),
                signer_pubkey: "WATCHER".to_string(),
            };
            self.block_producer.record_executed_transaction(proto_tx);
        }

        info!("✅ Auto-approved: {:.6} {} → {:.5} BB for {} (ext_tx: {})",
            record.amount_micro_stablecoin as f64 / crate::svm::USDC_UNIT as f64,
            record.asset,
            record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64,
            &record.wallet_address[..8.min(record.wallet_address.len())],
            &tx_hash[..16.min(tx_hash.len())]);

        Ok(record.bb_lamports as f64 / crate::svm::LAMPORTS_PER_BB as f64)
    }

    /// Fetch and verify a specific Solana transaction, returning the asset and
    /// amount of stablecoin received by the custody wallet.
    ///
    /// Also scans every instruction (outer + CPI) for a Mayan `customPayload`
    /// `[0xBB, 0x01, <32-byte pubkey>]` and returns it in `mayan_wallet`.
    pub async fn verify_transaction(&self, tx_sig: &str) -> Result<VerifiedDeposit, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getTransaction",
            "params": [
                tx_sig,
                {
                    "encoding": "jsonParsed",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });
        let resp: RpcEnvelope<SolanaTx> = self.rpc_call(body).await?;
        let tx = resp.result.ok_or("Transaction not found (not yet finalized?)")?;
        let meta = tx.meta.ok_or("Transaction has no metadata")?;
        if meta.err.is_some() {
            return Err("Transaction failed on-chain".to_string());
        }

        let pre  = meta.pre_token_balances.as_deref().unwrap_or_default();
        let post = meta.post_token_balances.as_deref().unwrap_or_default();

        // Find the custody wallet's incoming balance change for USDC or USDT
        let mut found: Option<VerifiedDeposit> = None;
        for post_entry in post {
            let owner = match &post_entry.owner { Some(o) => o.as_str(), None => continue };
            if owner != self.custody_address { continue; }

            let asset = if post_entry.mint == self.usdc_mint { "USDC" }
                else if post_entry.mint == self.usdt_mint   { "USDT" }
                else { continue };

            let post_amount = post_entry.ui_token_amount.ui_amount.unwrap_or(0.0);
            let pre_amount  = pre.iter()
                .find(|p| p.account_index == post_entry.account_index)
                .and_then(|p| p.ui_token_amount.ui_amount)
                .unwrap_or(0.0);

            let received = post_amount - pre_amount;
            if received > 0.0 {
                found = Some(VerifiedDeposit {
                    asset: asset.to_string(),
                    amount: received,
                    mayan_wallet: None, // filled below
                });
                break;
            }
        }

        let mut deposit = found.ok_or_else(|| {
            "No incoming USDC/USDT transfer to custody wallet found in this transaction".to_string()
        })?;

        // ── Scan every instruction for Mayan customPayload [0xBB, 0x01, <pubkey>] ──
        deposit.mayan_wallet = Self::scan_tx_instructions_for_mayan_payload(
            tx.transaction.as_ref(),
            meta.inner_instructions.as_deref(),
        );

        Ok(deposit)
    }

    /// Scan all outer instructions and CPI inner instructions for the BlackBook
    /// Mayan payload magic `[0xBB, 0x01]` followed by a 32-byte Ed25519 pubkey.
    ///
    /// Mayan embeds the caller's `customPayload` inside its program instruction
    /// data when it finalises a cross-chain swap on Solana (via Wormhole VAA or
    /// Swift fulfil call). The payload may appear at any byte offset inside the
    /// instruction data, so we use `scan_for_payload` which searches all offsets.
    fn scan_tx_instructions_for_mayan_payload(
        tx_body: Option<&SolTxBody>,
        inner_groups: Option<&[SolInnerInstructionGroup]>,
    ) -> Option<String> {
        use mayan::scan_for_payload;

        let try_decode = |raw: &[u8]| -> Option<String> {
            scan_for_payload(raw).map(|p| p.l1_wallet)
        };

        // Outer instructions
        if let Some(body) = tx_body {
            for ix in &body.message.instructions {
                if let Some(data_b58) = &ix.data {
                    if let Ok(raw) = bs58::decode(data_b58).into_vec() {
                        if let Some(wallet) = try_decode(&raw) {
                            return Some(wallet);
                        }
                    }
                }
            }
        }

        // Inner (CPI) instructions — Mayan's Swift/MCTP finalisation often
        // uses CPI into the Wormhole core bridge, which carries the VAA payload.
        if let Some(groups) = inner_groups {
            for group in groups {
                for ix in &group.instructions {
                    if let Some(data_b58) = &ix.data {
                        if let Ok(raw) = bs58::decode(data_b58).into_vec() {
                            if let Some(wallet) = try_decode(&raw) {
                                return Some(wallet);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    // ── Internal: HTTP helper ────────────────────────────────────────────────

    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        body: serde_json::Value,
    ) -> Result<T, String> {
        self.http
            .post(&self.rpc_url)
            .json(&body)
            .send().await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<T>().await
            .map_err(|e| format!("JSON parse: {}", e))
    }
}
