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
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::storage::{ConcurrentBlockchain, DepositRecord};
use crate::poh_blockchain::BlockProducer;
use crate::protocol::{Transaction as ProtoTx, TxData};

// ── Well-known Solana mainnet SPL token mints ─────────────────────────────────

/// Solana mainnet USDC SPL token mint.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// Solana mainnet USDT SPL token mint.
pub const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

/// Exchange rate between stablecoins and BB (1 USDC = 10 BB).
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
}

// getTransaction
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SolanaTx {
    meta: Option<TxMeta>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxMeta {
    err: Option<serde_json::Value>,
    pre_token_balances: Option<Vec<TxTokenBalance>>,
    post_token_balances: Option<Vec<TxTokenBalance>>,
}
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TxTokenBalance {
    account_index: usize,
    mint: String,
    owner: Option<String>,
    ui_token_amount: UiTokenAmount,
}

/// Stripped result of a successful on-chain verification.
pub struct VerifiedDeposit {
    pub asset: String,
    pub amount: f64,
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

    /// Spawn a detached tokio background task that polls every `poll_interval_secs`.
    /// On first boot, runs a startup balance sync before entering the regular poll loop.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("👀 Custody watcher started — {} every {}s",
                self.custody_address, self.poll_interval_secs);
            // Immediate startup sync — picks up any USDC/USDT already sitting in
            // the custody wallet before the first timed poll fires.
            self.startup_balance_sync().await;
            let mut interval = tokio::time::interval(Duration::from_secs(self.poll_interval_secs));
            loop {
                interval.tick().await;
                self.poll_once().await;
            }
        });
    }

    /// On first start, reads the live on-chain USDC + USDT balance of the custody wallet
    /// and auto-mints the equivalent BB + wUSDC to the dealer if the chain is fresh.
    /// Uses DEALER_PRIVATE_KEY from env to derive the dealer address.
    async fn startup_balance_sync(&self) {
        let dealer_sk_hex = match std::env::var("DEALER_PRIVATE_KEY") {
            Ok(v) if v.len() == 64 => v,
            _ => {
                info!("👀 Startup sync: DEALER_PRIVATE_KEY not set — skipping initial balance check");
                return;
            }
        };
        let sk_bytes_vec = match hex::decode(&dealer_sk_hex) {
            Ok(b) => b,
            Err(_) => { warn!("⚠️  Startup sync: DEALER_PRIVATE_KEY invalid hex"); return; }
        };
        let sk_bytes: [u8; 32] = match sk_bytes_vec.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => { warn!("⚠️  Startup sync: DEALER_PRIVATE_KEY wrong length"); return; }
        };
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let dealer_addr = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

        // Only run full sync if dealer has no BB yet (fresh chain)
        if self.blockchain.get_balance(&dealer_addr) > 0.0 {
            info!("👀 Startup sync: dealer {} already funded — checking wUSDC invariant", &dealer_addr[..8]);
            // Invariant reconciliation: if BB exists but wUSDC supply is 0, mint the missing wUSDC
            self.reconcile_wusdc_invariant(&dealer_addr, &signing_key.verifying_key().to_bytes()).await;
            return;
        }

        info!("👀 Startup sync: checking live balance on custody wallet {}", &self.custody_address);

        let usdc_bal = self.fetch_token_balance(&self.usdc_mint).await.unwrap_or(0.0);
        let usdt_bal = self.fetch_token_balance(&self.usdt_mint).await.unwrap_or(0.0);
        let total_stablecoin = usdc_bal + usdt_bal;

        if total_stablecoin <= 0.0 {
            info!("👀 Startup sync: custody wallet has no USDC/USDT — nothing to mint");
            return;
        }

        info!("👀 Startup sync: found {:.6} USDC + {:.6} USDT = {:.6} total → minting {} BB to dealer",
            usdc_bal, usdt_bal, total_stablecoin, total_stablecoin * 10.0);

        let bb_to_mint = total_stablecoin * 10.0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();

        // Create a synthetic deposit record so the full lifecycle is tracked
        let tx_key = format!("STARTUP_SYNC:{}:{}", self.custody_address, now);
        let record = DepositRecord {
            wallet_address: dealer_addr.clone(),
            external_tx_hash: tx_key.clone(),
            asset: "USDC+USDT".to_string(),
            amount_stablecoin: total_stablecoin,
            bb_to_mint,
            status: "pending".to_string(),
            submitted_at: now,
            approved_at: None,
        };
        let _ = self.blockchain.store_deposit_request(&record);
        self.deposit_requests.insert(tx_key.clone(), record);

        // Mint BB
        match self.blockchain.credit(&dealer_addr, bb_to_mint) {
            Ok(_) => info!("🪙  Startup sync: {} BB → dealer {}", bb_to_mint, &dealer_addr[..8]),
            Err(e) => { error!("❌ Startup sync BB mint failed: {}", e); return; }
        }

        // Mint wUSDC (if USDC balance > 0)
        if usdc_bal > 0.0 {
            use crate::svm::{SplTokenEngine, usdc_mint_bytes};
            let mint_bytes = usdc_mint_bytes();
            let dealer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(
                signing_key.verifying_key().to_bytes()
            );
            let usdc_units = (usdc_bal * 1_000_000.0).round() as u64;
            match SplTokenEngine::mint_to(&self.blockchain.svm_accounts, &mint_bytes, &dealer_pubkey, usdc_units) {
                Ok(r) => info!("💵  Startup sync: {:.6} wUSDC → dealer {} (ATA: {})",
                    usdc_bal, &dealer_addr[..8], bs58::encode(r.ata).into_string()),
                Err(e) => warn!("⚠️   Startup sync wUSDC mint skipped: {:?}", e),
            }
        }

        // Mark as processed + update record
        let mint_tx_id = uuid::Uuid::new_v4().to_string();
        let _ = self.blockchain.mark_bridge_tx_processed(&tx_key, &mint_tx_id);
        if let Some(mut entry) = self.deposit_requests.get_mut(&tx_key) {
            entry.status = "approved".to_string();
            entry.approved_at = Some(now);
        }
        if let Some(updated) = self.deposit_requests.get(&tx_key) {
            let _ = self.blockchain.store_deposit_request(&*updated);
        }

        // Record in PoH
        let proto_tx = ProtoTx {
            hash: mint_tx_id,
            from: format!("CUSTODY_WALLET:{}", self.custody_address),
            timestamp: now,
            data: TxData::DepositUsdt {
                usdt_amount: bb_to_mint as u64,
                external_tx_hash: Some(tx_key),
            },
            signature: "startup_sync".to_string(),
            signer_pubkey: dealer_addr,
        };
        self.block_producer.record_executed_transaction(proto_tx);
        info!("✅ Startup sync complete — custody balance minted to dealer");
    }

    /// Reconcile wUSDC supply against BB supply.
    ///
    /// Called when the dealer already has BB but wUSDC total supply is 0 (or
    /// less than expected).  This can happen when an existing chain is upgraded
    /// to the wUSDC-aware version for the first time.  The missing wUSDC is
    /// minted to the dealer so the 10:1 invariant is restored.
    async fn reconcile_wusdc_invariant(&self, dealer_addr: &str, dealer_pubkey_bytes: &[u8; 32]) {
        use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};
        let mint_bytes = usdc_mint_bytes();
        let dealer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(*dealer_pubkey_bytes);

        // Current wUSDC total supply on-chain
        let current_wusdc_supply = match SplTokenEngine::get_mint_supply(&self.blockchain.svm_accounts, &mint_bytes) {
            Ok(s) => s as f64 / USDC_UNIT as f64,
            Err(_) => 0.0,
        };

        // Expected wUSDC = total BB supply / 10
        let total_bb = self.blockchain.total_supply();
        let expected_wusdc = total_bb / 10.0;
        let missing_wusdc = expected_wusdc - current_wusdc_supply;

        if missing_wusdc <= 0.000_001 {
            info!("✅ Invariant OK — {:.6} BB backed by {:.6} wUSDC (ratio {:.2})",
                total_bb, current_wusdc_supply, if current_wusdc_supply > 0.0 { total_bb / current_wusdc_supply } else { 0.0 });
            return;
        }

        warn!("⚠️  Invariant broken: {:.6} BB but only {:.6} wUSDC — minting {:.6} wUSDC to dealer to reconcile",
            total_bb, current_wusdc_supply, missing_wusdc);

        let raw_units = (missing_wusdc * USDC_UNIT as f64).round() as u64;
        match SplTokenEngine::mint_to(&self.blockchain.svm_accounts, &mint_bytes, &dealer_pubkey, raw_units) {
            Ok(_) => info!("✅ Reconciled: minted {:.6} wUSDC to dealer {} — invariant restored",
                missing_wusdc, &dealer_addr[..8.min(dealer_addr.len())]),
            Err(e) => warn!("❌ Reconcile wUSDC mint failed: {:?}", e),
        }
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
            // Only act on TXs that have a matching pending deposit request
            if !self.deposit_requests.contains_key(&sig.signature) { continue; }
            if self.blockchain.is_bridge_tx_processed(&sig.signature) { continue; }

            match self.verify_and_approve(&sig.signature).await {
                Ok(bb) => info!("✅ Watcher auto-approved {} → {} BB",
                    &sig.signature[..16.min(sig.signature.len())], bb),
                Err(e) => warn!("⚠️  Auto-approve failed ({}): {}",
                    &sig.signature[..16.min(sig.signature.len())], e),
            }
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
        let tolerance = (record.amount_stablecoin * 0.01_f64).max(0.01);
        if (verified.amount - record.amount_stablecoin).abs() > tolerance {
            return Err(format!(
                "Amount mismatch: claimed {:.2} but chain shows {:.2} {}",
                record.amount_stablecoin, verified.amount, verified.asset
            ));
        }
        if verified.asset != record.asset {
            return Err(format!(
                "Asset mismatch: claimed {} but chain shows {}",
                record.asset, verified.asset
            ));
        }

        // ── Mint BB ───────────────────────────────────────────────────────
        self.blockchain.credit(&record.wallet_address, record.bb_to_mint)
            .map_err(|e| format!("BB mint failed: {}", e))?;

        // ── Mint wUSDC (1:1 with stablecoin deposited) ────────────────────
        {
            use crate::svm::{SplTokenEngine, usdc_mint_bytes, USDC_UNIT};
            use solana_sdk::pubkey::Pubkey;
            use std::str::FromStr;
            if let Ok(wallet_pubkey) = Pubkey::from_str(&record.wallet_address) {
                let mint = usdc_mint_bytes();
                let raw_units = (record.amount_stablecoin * USDC_UNIT as f64) as u64;
                match SplTokenEngine::mint_to(&self.blockchain.svm_accounts, &mint, &wallet_pubkey, raw_units) {
                    Ok(_) => info!("💵 wUSDC auto-minted: {:.6} → {}",
                        record.amount_stablecoin,
                        &record.wallet_address[..8.min(record.wallet_address.len())]),
                    Err(e) => warn!("⚠️  wUSDC auto-mint failed (BB already minted): {:?}", e),
                }
            }
        }

        // ── Double-mint lock ──────────────────────────────────────────────
        let mint_tx_id = Uuid::new_v4().to_string();
        if let Err(e) = self.blockchain.mark_bridge_tx_processed(tx_hash, &mint_tx_id) {
            warn!("⚠️  mark_bridge_tx_processed: {}", e);
        }

        // ── Update status in DashMap + ReDB ──────────────────────────────
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

        // ── Record in PoH ledger ──────────────────────────────────────────
        {
            let proto_tx = ProtoTx {
                hash: mint_tx_id.clone(),
                from: "DEPOSIT_GATEWAY".to_string(),
                timestamp: now,
                data: TxData::DepositUsdt {
                    usdt_amount: (record.amount_stablecoin / 10.0) as u64,
                    external_tx_hash: Some(tx_hash.to_string()),
                },
                signature: "auto_verified".to_string(),
                signer_pubkey: "WATCHER".to_string(),
            };
            self.block_producer.record_executed_transaction(proto_tx);
        }

        info!("✅ Auto-approved: {} {} → {} BB for {} (ext_tx: {})",
            record.amount_stablecoin, record.asset, record.bb_to_mint,
            &record.wallet_address[..8.min(record.wallet_address.len())],
            &tx_hash[..16.min(tx_hash.len())]);

        Ok(record.bb_to_mint)
    }

    /// Fetch and verify a specific Solana transaction, returning the asset and
    /// amount of stablecoin received by the custody wallet.
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

        let pre  = meta.pre_token_balances.unwrap_or_default();
        let post = meta.post_token_balances.unwrap_or_default();

        // Find the custody wallet's incoming balance change for USDC or USDT
        for post_entry in &post {
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
                return Ok(VerifiedDeposit { asset: asset.to_string(), amount: received });
            }
        }

        Err("No incoming USDC/USDT transfer to custody wallet found in this transaction".to_string())
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
