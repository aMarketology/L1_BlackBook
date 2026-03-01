// ============================================================================
// BLACKBOOK L1 — SOLANA JSON-RPC 2.0 SERVER  (Phase 2A)
// ============================================================================
//
// Exposes a Solana-compatible JSON-RPC endpoint on port 8899 so that any
// Solana wallet (OneKey, Phantom, Backpack, …) or tool (solana CLI, anchor,
// solscan) can connect to the BlackBook L1 node as if it were a Solana
// cluster.
//
// Phase 2A implements all READ-ONLY methods.
// Phase 2B will add sendTransaction, getTransaction, getBlock.
//
// Design principles:
//  - Return types mirror Solana mainnet-beta JSON-RPC responses exactly.
//  - No solana-account-decoder dependency; encode manually using base64/base58.
//  - All methods are async; the server is driven by tokio.
//  - Module is always compiled (no feature gate).
//
// Run:  cargo build --features svm
// Test: cargo test --features svm --test rpc_tests
// ============================================================================

use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use solana_sdk::{
    account::ReadableAccount,
    hash::Hash,
    pubkey::Pubkey,
};
use tracing::info;
use base64::engine::{Engine, general_purpose::STANDARD as B64};

use crate::svm::{SvmAccountsDB, BlackBookSVM};
use crate::poh_blockchain::BlockProducer;

// ─────────────────────────────────────────────────────────────────────────────
// Solana-compatible response wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Solana `RpcResponse<T>` — wraps every read-method result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse<T: Serialize + Clone> {
    pub context: RpcContext,
    pub value: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcContext {
    pub slot: u64,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
}

impl RpcContext {
    fn current(slot: u64) -> Self {
        Self { slot, api_version: "BB-5.0".into() }
    }
}

/// Solana `UiAccount` — returned by getAccountInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiAccount {
    pub lamports: u64,
    pub data: UiAccountData,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub space: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UiAccountData {
    /// [base64_data, encoding_string]
    Binary(String, String),
    /// Empty account has no data
    Empty([String; 0]),
}

/// getLatestBlockhash value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

/// getEpochInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcEpochInfo {
    pub epoch: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
    pub absolute_slot: u64,
    pub block_height: u64,
    pub transaction_count: u64,
}

/// getVersion
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RpcVersionInfo {
    pub solana_core: String,
    pub feature_set: u32,
}

/// Config objects (optional params — ignored in Phase 2A, accepted for compatibility)
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)] // Fields deserialized by serde for Solana client compat
pub struct RpcAccountInfoConfig {
    pub encoding: Option<String>,
    pub commitment: Option<String>,
    pub min_context_slot: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2B — Write method response types
// ─────────────────────────────────────────────────────────────────────────────

/// sendTransaction config (accepted for compatibility — encoding matters)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields deserialized by serde for Solana client compat
pub struct SendTransactionConfig {
    pub encoding: Option<String>,
    pub skip_preflight: Option<bool>,
    pub preflight_commitment: Option<String>,
    pub max_retries: Option<u64>,
    pub min_context_slot: Option<u64>,
}

/// getTransaction response — mirrors Solana's `EncodedConfirmedTransactionWithStatusMeta`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcConfirmedTransaction {
    pub slot: u64,
    pub transaction: RpcEncodedTransaction,
    pub meta: RpcTransactionMeta,
    pub block_time: Option<i64>,
}

/// Encoded transaction (simplified: we return account keys + signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcEncodedTransaction {
    pub signatures: Vec<String>,
    pub message: RpcTransactionMessage,
}

/// Transaction message (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionMessage {
    pub account_keys: Vec<String>,
    pub recent_blockhash: String,
    pub instructions: Vec<RpcCompiledInstruction>,
}

/// Compiled instruction (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcCompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: String,
}

/// Transaction metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionMeta {
    pub err: Option<RpcTransactionError>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    pub compute_units_consumed: Option<u64>,
}

/// Transaction error (Solana-compatible shape)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransactionError {
    #[serde(rename = "InstructionError")]
    pub instruction_error: Option<(u8, String)>,
}

/// getSignaturesForAddress response entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<RpcTransactionError>,
    pub memo: Option<String>,
    pub block_time: Option<i64>,
    pub confirmation_status: Option<String>,
}

/// getSignaturesForAddress config
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields deserialized by serde for Solana client compat
pub struct GetSignaturesConfig {
    pub limit: Option<usize>,
    pub before: Option<String>,
    pub until: Option<String>,
    pub commitment: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC trait (proc macro generates BlackBookRpcServer trait + RpcModule)
// ─────────────────────────────────────────────────────────────────────────────

/// Slots per epoch on BlackBook L1 (matches Solana mainnet).
pub const SLOTS_PER_EPOCH: u64 = 432_000;

/// Rent is disabled on BlackBook L1 — all accounts are permanently exempt.
/// Matches Solana's `minimum_balance` formula at 0 bytes plus overhead,
/// so wallets that call this don't break.
const LAMPORTS_PER_BYTE_YEAR: u64 = 3_480;
const RENT_EXEMPT_THRESHOLD: u64 = 2; // years before exempt

#[rpc(server)]
pub trait BlackBookRpc {
    /// Health probe. Returns `"ok"` when the node is running.
    #[method(name = "getHealth")]
    async fn get_health(&self) -> RpcResult<String>;

    /// Node software version.
    #[method(name = "getVersion")]
    async fn get_version(&self) -> RpcResult<RpcVersionInfo>;

    /// Network genesis hash — unique identifier for BlackBook L1.
    /// Wallets use this to detect they are talking to the right network.
    #[method(name = "getGenesisHash")]
    async fn get_genesis_hash(&self) -> RpcResult<String>;

    /// Latest confirmed slot.
    #[method(name = "getSlot")]
    async fn get_slot(&self) -> RpcResult<u64>;

    /// Block height (same as slot on BlackBook L1).
    #[method(name = "getBlockHeight")]
    async fn get_block_height(&self) -> RpcResult<u64>;

    /// Lamport balance for a base58-encoded public key.
    #[method(name = "getBalance")]
    async fn get_balance(&self, pubkey: String) -> RpcResult<RpcResponse<u64>>;

    /// Full account state for a base58-encoded public key.
    #[method(name = "getAccountInfo")]
    async fn get_account_info(
        &self,
        pubkey: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Option<UiAccount>>>;

    /// Latest valid blockhash and its last-valid block height.
    /// Wallets call this before building every transaction.
    #[method(name = "getLatestBlockhash")]
    async fn get_latest_blockhash(&self) -> RpcResult<RpcResponse<RpcBlockhash>>;

    /// Current epoch statistics.
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self) -> RpcResult<RpcEpochInfo>;

    /// Minimum lamports required to store `data_len` bytes rent-free.
    #[method(name = "getMinimumBalanceForRentExemption")]
    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> RpcResult<u64>;

    /// Check if one or more accounts exist.
    #[method(name = "getMultipleAccounts")]
    async fn get_multiple_accounts(
        &self,
        pubkeys: Vec<String>,
        config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Vec<Option<UiAccount>>>>;

    // ─────────────────────────────────────────────────────────────────────
    // Phase 2B — Write methods
    // ─────────────────────────────────────────────────────────────────────

    /// Submit a signed transaction for execution.
    ///
    /// Accepts a base64-encoded serialized transaction. Returns the
    /// transaction signature (base58) on success.
    ///
    /// The transaction is executed immediately (not queued) in Phase 2B.
    /// Phase 6 will add Gulf Stream forwarding for async submission.
    #[method(name = "sendTransaction")]
    async fn send_transaction(
        &self,
        data: String,
        config: Option<SendTransactionConfig>,
    ) -> RpcResult<String>;

    /// Retrieve a confirmed transaction by its signature (base58).
    #[method(name = "getTransaction")]
    async fn get_transaction(
        &self,
        signature: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<Option<RpcConfirmedTransaction>>;

    /// Get recent transaction signatures for an address.
    #[method(name = "getSignaturesForAddress")]
    async fn get_signatures_for_address(
        &self,
        address: String,
        config: Option<GetSignaturesConfig>,
    ) -> RpcResult<Vec<RpcSignatureInfo>>;

    // ─────────────────────────────────────────────────────────────────────
    // Phase 2C — Token & fee methods (OneKey / Phantom compatibility)
    // ─────────────────────────────────────────────────────────────────────

    /// SPL Token accounts owned by `pubkey` matching a filter.
    #[method(name = "getTokenAccountsByOwner")]
    async fn get_token_accounts_by_owner(
        &self,
        pubkey: String,
        filter: serde_json::Value,
        config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Vec<serde_json::Value>>>;

    /// Get the total supply of an SPL token mint.
    #[method(name = "getTokenSupply")]
    async fn get_token_supply(
        &self,
        mint: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>>;

    /// Get the token balance of a specific token account (ATA).
    #[method(name = "getTokenAccountBalance")]
    async fn get_token_account_balance(
        &self,
        account: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>>;

    /// Fee the network would charge for a given message.
    #[method(name = "getFeeForMessage")]
    async fn get_fee_for_message(
        &self,
        message: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<Option<u64>>>;

    /// Recent prioritization fees — empty on BlackBook L1.
    #[method(name = "getRecentPrioritizationFees")]
    async fn get_recent_prioritization_fees(
        &self,
        addresses: Option<Vec<String>>,
    ) -> RpcResult<Vec<serde_json::Value>>;

    /// Check if blockhashes are still valid.
    #[method(name = "isBlockhashValid")]
    async fn is_blockhash_valid(
        &self,
        blockhash: String,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<bool>>;

    /// Returns identity pubkey of the node.
    #[method(name = "getIdentity")]
    async fn get_identity(&self) -> RpcResult<serde_json::Value>;

    /// Supply info (total, circulating, non-circulating).
    #[method(name = "getSupply")]
    async fn get_supply(
        &self,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>>;

    /// Signature statuses for one or more tx signatures.
    #[method(name = "getSignatureStatuses")]
    async fn get_signature_statuses(
        &self,
        signatures: Vec<String>,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<Vec<Option<serde_json::Value>>>>;

    // ─────────────────────────────────────────────────────────────────────
    // BlackBook extensions — Backpack / custom dApps
    // ─────────────────────────────────────────────────────────────────────

    /// Full on-chain wallet profile: balance, slot, network.
    /// Call from Backpack via:
    ///   connection.request({ method: 'blackbook_getProfile', params: [pubkey] })
    #[method(name = "blackbook_getProfile")]
    async fn blackbook_get_profile(&self, pubkey: String) -> RpcResult<serde_json::Value>;

    /// Returns true if the address has a non-zero balance on-chain.
    #[method(name = "blackbook_isRegistered")]
    async fn blackbook_is_registered(&self, pubkey: String) -> RpcResult<bool>;

    // ─────────────────────────────────────────────────────────────────────
    // Phase 5 — Block query methods
    // ─────────────────────────────────────────────────────────────────────

    /// Returns an identity and transaction information about a confirmed block.
    #[method(name = "getBlock")]
    async fn get_block(
        &self,
        slot: u64,
        config: Option<serde_json::Value>,
    ) -> RpcResult<Option<serde_json::Value>>;

    /// Returns a list of confirmed blocks between two slots.
    #[method(name = "getBlocks")]
    async fn get_blocks(
        &self,
        start_slot: u64,
        end_slot: Option<u64>,
    ) -> RpcResult<Vec<u64>>;

    /// Returns recent block production information.
    #[method(name = "getBlockProduction")]
    async fn get_block_production(
        &self,
        config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation struct
// ─────────────────────────────────────────────────────────────────────────────

pub struct BlackBookRpcImpl {
    pub svm_db:       Arc<SvmAccountsDB>,
    pub svm:          Arc<Mutex<BlackBookSVM>>,
    pub current_slot: Arc<AtomicU64>,
    /// base58-encoded SHA256("BLACKBOOK_L1_GENESIS_2025")
    pub genesis_hash: String,
    /// Block access for getBlock / getBlocks RPC
    pub block_producer: Option<Arc<BlockProducer>>,
}

impl BlackBookRpcImpl {
    pub fn new(
        svm_db:       Arc<SvmAccountsDB>,
        svm:          Arc<Mutex<BlackBookSVM>>,
        current_slot: Arc<AtomicU64>,
    ) -> Self {
        // Compute genesis hash once at startup — BlackBook L1 identity
        let genesis_bytes: [u8; 32] = Sha256::digest(b"BLACKBOOK_L1_GENESIS_2025").into();
        let genesis_hash = bs58::encode(genesis_bytes).into_string();

        info!("🔌 BlackBookRpc created  genesis_hash={}", genesis_hash);

        Self { svm_db, svm, current_slot, genesis_hash, block_producer: None }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────

    fn slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    fn ctx(&self) -> RpcContext {
        RpcContext::current(self.slot())
    }

    /// Parse a base58 pubkey string into a `Pubkey`, returning a JSON-RPC error on bad input.
    fn parse_pubkey(s: &str) -> RpcResult<Pubkey> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| error_invalid_params(format!("Invalid base58 pubkey '{}': {}", s, e)))?;

        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| error_invalid_params(format!("Pubkey '{}' is not 32 bytes", s)))?;

        Ok(Pubkey::new_from_array(arr))
    }

    /// Encode a `Pubkey` as base58.
    fn pk_to_b58(pk: &Pubkey) -> String {
        bs58::encode(pk.to_bytes()).into_string()
    }

    /// Get the latest blockhash from the SVM.
    fn latest_blockhash(&self) -> Hash {
        self.svm.lock()
            .map(|svm| svm.current_blockhash())
            .unwrap_or_default()
    }

    /// Convert a blockhash `Hash` to base58 (matches Solana's `Hash::to_string()`).
    fn hash_to_b58(hash: &Hash) -> String {
        bs58::encode(hash.to_bytes()).into_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC method implementations
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl BlackBookRpcServer for BlackBookRpcImpl {
    async fn get_health(&self) -> RpcResult<String> {
        info!("📡 RPC ← getHealth");
        Ok("ok".into())
    }

    async fn get_version(&self) -> RpcResult<RpcVersionInfo> {
        info!("📡 RPC ← getVersion");
        Ok(RpcVersionInfo {
            solana_core: "BB-5.0.0-svm".into(),
            feature_set: 0xBB50_0000,
        })
    }

    async fn get_genesis_hash(&self) -> RpcResult<String> {
        info!("📡 RPC ← getGenesisHash");
        Ok(self.genesis_hash.clone())
    }

    async fn get_slot(&self) -> RpcResult<u64> {
        info!("📡 RPC ← getSlot → {}", self.slot());
        Ok(self.slot())
    }

    async fn get_block_height(&self) -> RpcResult<u64> {
        Ok(self.slot()) // block height == slot on single-chain BB L1
    }

    async fn get_balance(&self, pubkey: String) -> RpcResult<RpcResponse<u64>> {
        let pk = Self::parse_pubkey(&pubkey)?;
        let lamports = self.svm_db.get_lamports(&pk);
        info!("\u{1f4e1} RPC \u{2190} getBalance({pubkey}) \u{2192} {lamports} lamports");
        Ok(RpcResponse { context: self.ctx(), value: lamports })
    }

    async fn get_account_info(
        &self,
        pubkey: String,
        _config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Option<UiAccount>>> {
        let pk = Self::parse_pubkey(&pubkey)?;
        info!("\u{1f4e1} RPC \u{2190} getAccountInfo({pubkey})");
        let account = self.svm_db.get_account(&pk);

        let ui = account.map(|acct| {
            let data_bytes = acct.data().to_vec();
            let encoded = B64.encode(&data_bytes);
            UiAccount {
                lamports: acct.lamports(),
                data: if data_bytes.is_empty() {
                    UiAccountData::Binary(String::new(), "base64".into())
                } else {
                    UiAccountData::Binary(encoded, "base64".into())
                },
                owner: Self::pk_to_b58(acct.owner()),
                executable: acct.executable(),
                rent_epoch: acct.rent_epoch(),
                space: data_bytes.len(),
            }
        });

        Ok(RpcResponse { context: self.ctx(), value: ui })
    }

    async fn get_latest_blockhash(&self) -> RpcResult<RpcResponse<RpcBlockhash>> {
        info!("📡 RPC ← getLatestBlockhash");
        let hash = self.latest_blockhash();
        let slot  = self.slot();
        Ok(RpcResponse {
            context: self.ctx(),
            value: RpcBlockhash {
                blockhash: Self::hash_to_b58(&hash),
                last_valid_block_height: slot.saturating_add(150),
            },
        })
    }

    async fn get_epoch_info(&self) -> RpcResult<RpcEpochInfo> {
        info!("📡 RPC ← getEpochInfo");
        let slot       = self.slot();
        let epoch      = slot / SLOTS_PER_EPOCH;
        let slot_index = slot % SLOTS_PER_EPOCH;

        let transaction_count = self.block_producer.as_ref()
            .map(|bp| bp.total_transaction_count())
            .unwrap_or(0);

        Ok(RpcEpochInfo {
            epoch,
            slot_index,
            slots_in_epoch: SLOTS_PER_EPOCH,
            absolute_slot: slot,
            block_height: slot,
            transaction_count,
        })
    }

    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> RpcResult<u64> {
        // On BlackBook L1, all accounts are permanently rent-exempt (rent_epoch = u64::MAX).
        // Return the same formula Solana uses so wallets that need ≥ X lamports don't break.
        // Formula: minimum = (128 + data_len) * LAMPORTS_PER_BYTE_YEAR * RENT_EXEMPT_THRESHOLD
        let minimum = (128 + data_len as u64)
            .saturating_mul(LAMPORTS_PER_BYTE_YEAR)
            .saturating_mul(RENT_EXEMPT_THRESHOLD);
        Ok(minimum)
    }

    async fn get_multiple_accounts(
        &self,
        pubkeys: Vec<String>,
        _config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Vec<Option<UiAccount>>>> {
        let mut accounts = Vec::with_capacity(pubkeys.len());

        for pk_str in &pubkeys {
            let pk = Self::parse_pubkey(pk_str)?;
            let ui = self.svm_db.get_account(&pk).map(|acct| {
                let data_bytes = acct.data().to_vec();
                let encoded = B64.encode(&data_bytes);
                UiAccount {
                    lamports:   acct.lamports(),
                    data:       UiAccountData::Binary(encoded, "base64".into()),
                    owner:      Self::pk_to_b58(acct.owner()),
                    executable: acct.executable(),
                    rent_epoch: acct.rent_epoch(),
                    space:      data_bytes.len(),
                }
            });
            accounts.push(ui);
        }

        Ok(RpcResponse { context: self.ctx(), value: accounts })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Phase 2B — Write method implementations
    // ─────────────────────────────────────────────────────────────────────

    async fn send_transaction(
        &self,
        data: String,
        config: Option<SendTransactionConfig>,
    ) -> RpcResult<String> {
        use crate::svm::{TransferRequest, StoredTransactionResult};

        // 1. Determine encoding (default: base58 for Solana CLI, base64 for wallets)
        let encoding = config
            .as_ref()
            .and_then(|c| c.encoding.clone())
            .unwrap_or_else(|| "base58".into());

        let tx_bytes = match encoding.as_str() {
            "base64" => B64.decode(&data).map_err(|e|
                error_invalid_params(format!("Invalid base64 transaction: {}", e)))?,
            "base58" | _ => bs58::decode(&data).into_vec().map_err(|e|
                error_invalid_params(format!("Invalid base58 transaction: {}", e)))?,
        };

        // 2. Deserialize as a Solana VersionedTransaction
        let versioned_tx: solana_sdk::transaction::VersionedTransaction =
            bincode::deserialize(&tx_bytes).map_err(|e|
                error_invalid_params(format!("Failed to deserialize transaction: {}", e)))?;

        // 3. Extract the first signature as the transaction ID
        let signature = versioned_tx.signatures.first()
            .ok_or_else(|| error_invalid_params("Transaction has no signatures"))?;
        let sig_b58 = bs58::encode(signature.as_ref()).into_string();

        // 4. Check for replay — persistent dedup across restarts
        if self.svm_db.signature_exists(&sig_b58) {
            return Err(error_already_processed(format!(
                "Transaction {} already processed", sig_b58
            )));
        }

        // 5. Extract message fields
        let message = versioned_tx.message;
        let account_keys = message.static_account_keys();
        let recent_blockhash = *message.recent_blockhash();

        // 6. Validate blockhash
        {
            let svm = self.svm.lock().map_err(|e|
                error_internal(format!("SVM lock poisoned: {}", e)))?;
            let bh = Hash::new_from_array(recent_blockhash.to_bytes());
            if !svm.is_valid_blockhash(&bh) {
                return Err(error_invalid_params(
                    "Blockhash not found — transaction may be stale. Call getLatestBlockhash first."
                ));
            }
        }

        // 7. Parse instructions — route system transfers
        //    Phase 2B supports System Program transfers only.
        //    Future phases add SPL Token, Anchor programs, etc.
        let instructions = message.instructions();

        if instructions.is_empty() {
            return Err(error_invalid_params("Transaction contains no instructions"));
        }

        // For Phase 2B: support the System Program transfer instruction
        let ix = &instructions[0];
        let program_id = account_keys[ix.program_id_index as usize];

        if program_id != solana_sdk::system_program::id() {
            return Err(error_invalid_params(format!(
                "Unsupported program: {}. Phase 2B only supports System Program transfers.",
                bs58::encode(program_id.to_bytes()).into_string()
            )));
        }

        // System Program transfer: instruction data = [2,0,0,0] + u64 lamports LE
        // SystemInstruction::Transfer = index 2
        if ix.data.len() < 12 {
            return Err(error_invalid_params(
                "System instruction data too short for a transfer"
            ));
        }

        let ix_type = u32::from_le_bytes([ix.data[0], ix.data[1], ix.data[2], ix.data[3]]);
        if ix_type != 2 {
            return Err(error_invalid_params(format!(
                "Unsupported System instruction type: {}. Expected Transfer (2).",
                ix_type
            )));
        }

        let lamports = u64::from_le_bytes([
            ix.data[4], ix.data[5], ix.data[6], ix.data[7],
            ix.data[8], ix.data[9], ix.data[10], ix.data[11],
        ]);

        // Accounts for System transfer: [0] = from (signer), [1] = to
        if ix.accounts.len() < 2 {
            return Err(error_invalid_params(
                "System transfer requires at least 2 account keys"
            ));
        }
        let from = account_keys[ix.accounts[0] as usize];
        let to = account_keys[ix.accounts[1] as usize];

        // 8. Build TransferRequest and execute
        let slot = self.slot();
        let transfer_req = TransferRequest {
            tx_id: sig_b58.clone(),
            from,
            to,
            lamports,
            recent_blockhash: Hash::new_from_array(recent_blockhash.to_bytes()),
        };

        let result = {
            let svm = self.svm.lock().map_err(|e|
                error_internal(format!("SVM lock poisoned: {}", e)))?;
            svm.execute_transfer(&transfer_req)
        };

        // 9. If execution failed, return the error
        if !result.success {
            let err_msg = result.error.as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown execution error".into());
            return Err(error_transaction_failed(err_msg));
        }

        // 10. Persist the transaction result to the tx log + address index
        let account_keys_b58: Vec<String> = vec![
            bs58::encode(from.to_bytes()).into_string(),
            bs58::encode(to.to_bytes()).into_string(),
        ];

        let stored = StoredTransactionResult::from_execution(&result, slot, account_keys_b58);
        self.svm_db.store_transaction_result(&stored).map_err(|e|
            error_internal(format!("Failed to persist tx result: {}", e)))?;

        // 11. Flush dirty accounts to ReDB so the transfer is durable
        self.svm_db.flush_block().map_err(|e|
            error_internal(format!("Failed to flush accounts: {}", e)))?;

        info!(
            signature = %sig_b58,
            from = %bs58::encode(from.to_bytes()).into_string(),
            to = %bs58::encode(to.to_bytes()).into_string(),
            lamports = lamports,
            "✅ sendTransaction executed and persisted"
        );

        // Return the signature — this is what Solana wallets display
        Ok(sig_b58)
    }

    async fn get_transaction(
        &self,
        signature: String,
        _config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<Option<RpcConfirmedTransaction>> {
        let stored = self.svm_db.get_transaction_result(&signature)
            .map_err(|e| error_internal(format!("Failed to read tx log: {}", e)))?;

        let Some(tx) = stored else {
            return Ok(None);
        };

        // Build Solana-compatible response
        let meta = RpcTransactionMeta {
            err: if tx.success {
                None
            } else {
                Some(RpcTransactionError {
                    instruction_error: Some((0, tx.error_msg.clone())),
                })
            },
            fee: tx.fee,
            pre_balances: vec![], // Not tracked in Phase 2B — requires snapshot
            post_balances: vec![],
            compute_units_consumed: Some(tx.compute_units_consumed),
        };

        let resp = RpcConfirmedTransaction {
            slot: tx.slot,
            transaction: RpcEncodedTransaction {
                signatures: vec![tx.signature.clone()],
                message: RpcTransactionMessage {
                    account_keys: tx.account_keys.clone(),
                    recent_blockhash: String::new(), // Not stored in Phase 2B
                    instructions: vec![], // Simplified — tx already executed
                },
            },
            meta,
            block_time: Some(tx.block_time),
        };

        Ok(Some(resp))
    }

    async fn get_signatures_for_address(
        &self,
        address: String,
        config: Option<GetSignaturesConfig>,
    ) -> RpcResult<Vec<RpcSignatureInfo>> {
        let limit = config.as_ref().and_then(|c| c.limit).unwrap_or(1000).min(1000);

        let results = self.svm_db.get_signatures_for_address(&address, limit)
            .map_err(|e| error_internal(format!("Failed to query signatures: {}", e)))?;

        let infos: Vec<RpcSignatureInfo> = results.into_iter().map(|tx| {
            RpcSignatureInfo {
                signature: tx.signature,
                slot: tx.slot,
                err: if tx.success {
                    None
                } else {
                    Some(RpcTransactionError {
                        instruction_error: Some((0, tx.error_msg)),
                    })
                },
                memo: None,
                block_time: Some(tx.block_time),
                confirmation_status: Some("finalized".into()),
            }
        }).collect();

        Ok(infos)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Phase 2C — Token & fee stubs (OneKey / Phantom compatibility)
    // ─────────────────────────────────────────────────────────────────────

    async fn get_token_accounts_by_owner(
        &self,
        pubkey: String,
        filter: serde_json::Value,
        _config: Option<RpcAccountInfoConfig>,
    ) -> RpcResult<RpcResponse<Vec<serde_json::Value>>> {
        info!("📡 RPC ← getTokenAccountsByOwner({pubkey})");

        use crate::svm::spl_token::{SplTokenEngine, usdc_mint_bytes, SPL_TOKEN_PROGRAM_ID};

        // Parse the wallet pubkey
        let wallet_bytes = bs58::decode(&pubkey)
            .into_vec()
            .map_err(|_| error_invalid_params("Invalid base58 pubkey"))?;
        if wallet_bytes.len() != 32 {
            return Err(error_invalid_params("Pubkey must be 32 bytes"));
        }
        let mut wallet_arr = [0u8; 32];
        wallet_arr.copy_from_slice(&wallet_bytes);
        let wallet_pk = Pubkey::new_from_array(wallet_arr);

        // Determine which mint to filter by.
        // Solana clients send: { "mint": "<base58>" } or { "programId": "<base58>" }
        let mint_bytes = if let Some(mint_str) = filter.get("mint").and_then(|v| v.as_str()) {
            let mb = bs58::decode(mint_str).into_vec()
                .map_err(|_| error_invalid_params("Invalid mint base58"))?;
            if mb.len() != 32 {
                return Err(error_invalid_params("Mint must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&mb);
            arr
        } else {
            // Default to USDC mint (or return all known token accounts)
            usdc_mint_bytes()
        };

        let accounts = SplTokenEngine::get_token_accounts_for_owner(
            &self.svm_db,
            &mint_bytes,
            &wallet_pk,
        );

        // Format response exactly like Solana's getTokenAccountsByOwner
        let value: Vec<serde_json::Value> = accounts.into_iter().map(|acct| {
            let raw_base64 = B64.encode(&acct.raw_data);
            serde_json::json!({
                "pubkey": acct.address,
                "account": {
                    "data": [raw_base64, "base64"],
                    "executable": false,
                    "lamports": 100_000u64,
                    "owner": bs58::encode(SPL_TOKEN_PROGRAM_ID).into_string(),
                    "rentEpoch": 18446744073709551615u64,
                    "space": 165,
                },
                "parsed": {
                    "info": {
                        "isNative": false,
                        "mint": acct.mint,
                        "owner": acct.owner,
                        "state": "initialized",
                        "tokenAmount": {
                            "amount": acct.amount.to_string(),
                            "decimals": acct.decimals,
                            "uiAmount": acct.amount as f64 / 10f64.powi(acct.decimals as i32),
                            "uiAmountString": format!("{:.prec$}", acct.amount as f64 / 10f64.powi(acct.decimals as i32), prec = acct.decimals as usize),
                        }
                    },
                    "type": "account"
                }
            })
        }).collect();

        Ok(RpcResponse { context: self.ctx(), value })
    }

    async fn get_token_supply(
        &self,
        mint: String,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>> {
        info!("📡 RPC ← getTokenSupply({mint})");

        use crate::svm::spl_token::{SplTokenEngine, MintLayout, USDC_DECIMALS};

        let mint_bytes_vec = bs58::decode(&mint)
            .into_vec()
            .map_err(|_| error_invalid_params("Invalid base58 mint"))?;
        if mint_bytes_vec.len() != 32 {
            return Err(error_invalid_params("Mint must be 32 bytes"));
        }
        let mut mint_arr = [0u8; 32];
        mint_arr.copy_from_slice(&mint_bytes_vec);

        let supply = SplTokenEngine::get_mint_supply(&self.svm_db, &mint_arr)
            .map_err(|e| error_invalid_params(&format!("Mint error: {:?}", e)))?;

        // Read decimals from the actual mint account
        let decimals = self.svm_db.get_account(&Pubkey::new_from_array(mint_arr))
            .and_then(|acct| MintLayout::from_bytes(acct.data()).ok())
            .map(|m| m.decimals)
            .unwrap_or(USDC_DECIMALS);

        let ui_amount = supply as f64 / 10f64.powi(decimals as i32);

        Ok(RpcResponse {
            context: self.ctx(),
            value: serde_json::json!({
                "amount": supply.to_string(),
                "decimals": decimals,
                "uiAmount": ui_amount,
                "uiAmountString": format!("{:.prec$}", ui_amount, prec = decimals as usize),
            }),
        })
    }

    async fn get_token_account_balance(
        &self,
        account: String,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>> {
        info!("📡 RPC ← getTokenAccountBalance({account})");

        use crate::svm::spl_token::TokenAccountLayout;

        let acct_bytes = bs58::decode(&account)
            .into_vec()
            .map_err(|_| error_invalid_params("Invalid base58 account"))?;
        if acct_bytes.len() != 32 {
            return Err(error_invalid_params("Account must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&acct_bytes);
        let acct_pk = Pubkey::new_from_array(arr);

        let stored = self.svm_db.get_account(&acct_pk)
            .ok_or_else(|| error_invalid_params("Token account not found"))?;

        if stored.data().len() != 165 {
            return Err(error_invalid_params("Not a token account (data != 165 bytes)"));
        }

        let layout = TokenAccountLayout::from_bytes(stored.data())
            .map_err(|e| error_invalid_params(&format!("Parse error: {}", e)))?;

        // Read decimals from the mint
        use crate::svm::spl_token::{MintLayout, USDC_DECIMALS};
        let decimals = self.svm_db.get_account(&Pubkey::new_from_array(layout.mint))
            .and_then(|m| MintLayout::from_bytes(m.data()).ok())
            .map(|m| m.decimals)
            .unwrap_or(USDC_DECIMALS);

        let ui_amount = layout.amount as f64 / 10f64.powi(decimals as i32);

        Ok(RpcResponse {
            context: self.ctx(),
            value: serde_json::json!({
                "amount": layout.amount.to_string(),
                "decimals": decimals,
                "uiAmount": ui_amount,
                "uiAmountString": format!("{:.prec$}", ui_amount, prec = decimals as usize),
            }),
        })
    }

    async fn get_fee_for_message(
        &self,
        _message: String,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<Option<u64>>> {
        info!("📡 RPC ← getFeeForMessage");
        // BlackBook L1 tx fee: 5000 lamports (same as Solana)
        Ok(RpcResponse { context: self.ctx(), value: Some(5000) })
    }

    async fn get_recent_prioritization_fees(
        &self,
        _addresses: Option<Vec<String>>,
    ) -> RpcResult<Vec<serde_json::Value>> {
        info!("📡 RPC ← getRecentPrioritizationFees");
        // No priority fees on BlackBook L1
        Ok(vec![])
    }

    async fn is_blockhash_valid(
        &self,
        blockhash: String,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<bool>> {
        info!("📡 RPC ← isBlockhashValid({blockhash})");
        let hash_bytes = bs58::decode(&blockhash)
            .into_vec()
            .map_err(|_| error_invalid_params("Invalid base58 blockhash"))?;
        if hash_bytes.len() != 32 {
            return Err(error_invalid_params("Blockhash must be 32 bytes"));
        }
        let hash = Hash::new_from_array(hash_bytes.try_into().unwrap());
        let valid = self.svm.lock().unwrap().is_valid_blockhash(&hash);
        Ok(RpcResponse { context: self.ctx(), value: valid })
    }

    async fn get_identity(&self) -> RpcResult<serde_json::Value> {
        info!("📡 RPC ← getIdentity");
        // Use genesis hash as the node identity pubkey
        Ok(serde_json::json!({
            "identity": self.genesis_hash
        }))
    }

    async fn get_supply(
        &self,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>> {
        // Sum actual lamports across all on-chain accounts
        let total = self.svm_db.total_lamports();
        info!("📡 RPC ← getSupply → {} lamports ({:.2} BB)", total, total as f64 / 100_000.0);
        Ok(RpcResponse {
            context: self.ctx(),
            value: serde_json::json!({
                "total": total,
                "circulating": total,
                "nonCirculating": 0u64,
                "nonCirculatingAccounts": []
            }),
        })
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<String>,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<Vec<Option<serde_json::Value>>>> {
        info!("📡 RPC ← getSignatureStatuses({} sigs)", signatures.len());
        let mut statuses = Vec::with_capacity(signatures.len());
        for sig in &signatures {
            // Check if we have the tx in our DB
            let tx = self.svm_db.get_transaction_result(sig).ok().flatten();
            let status = tx.map(|t| serde_json::json!({
                "slot": t.slot,
                "confirmations": null,
                "err": null,
                "confirmationStatus": "finalized"
            }));
            statuses.push(status);
        }
        Ok(RpcResponse { context: self.ctx(), value: statuses })
    }

    // ─────────────────────────────────────────────────────────────────────
    // BlackBook extensions — Backpack / custom dApps
    // ─────────────────────────────────────────────────────────────────────

    async fn blackbook_get_profile(&self, pubkey: String) -> RpcResult<serde_json::Value> {
        info!("📡 RPC ← blackbook_getProfile({pubkey})");

        // Validate pubkey format first
        let pk       = Self::parse_pubkey(&pubkey)?;
        let lamports = self.svm_db.get_lamports(&pk);
        let bb       = lamports as f64 / 100_000.0;
        let slot     = self.slot();

        Ok(serde_json::json!({
            "registered":    lamports > 0,
            "walletAddress": pubkey,
            "balance": {
                "lamports": lamports,
                "bb":       bb,
            },
            "network": "BlackBook-L1-mainnet",
            "slot":    slot,
        }))
    }

    async fn blackbook_is_registered(&self, pubkey: String) -> RpcResult<bool> {
        info!("📡 RPC ← blackbook_isRegistered({pubkey})");
        let pk = Self::parse_pubkey(&pubkey)?;
        Ok(self.svm_db.get_lamports(&pk) > 0)
    }

    // ─── Phase 5: Block query methods ───────────────────────────────────

    async fn get_block(
        &self,
        slot: u64,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<Option<serde_json::Value>> {
        info!("📡 RPC ← getBlock({})", slot);
        let block = self.block_producer.as_ref()
            .and_then(|bp| bp.get_block(slot));
        match block {
            Some(b) => {
                let txs: Vec<serde_json::Value> = b.transactions.iter().map(|otx| {
                    serde_json::json!({
                        "hash": otx.tx.hash,
                        "from": otx.tx.from,
                        "slot": otx.slot,
                        "position": otx.position,
                        "poh_hash": otx.poh_hash,
                    })
                }).collect();
                Ok(Some(serde_json::json!({
                    "blockHeight": b.slot,
                    "blockTime": b.timestamp,
                    "blockhash": b.hash,
                    "parentSlot": b.slot.saturating_sub(1),
                    "previousBlockhash": b.previous_hash,
                    "transactions": txs,
                    "rewards": [],
                    "leader": b.leader,
                    "epoch": b.epoch,
                    "pohHash": b.poh_hash,
                    "stateRoot": b.state_root,
                    "txCount": b.tx_count,
                    "confirmations": b.confirmations,
                })))
            }
            None => Ok(None),
        }
    }

    async fn get_blocks(
        &self,
        start_slot: u64,
        end_slot: Option<u64>,
    ) -> RpcResult<Vec<u64>> {
        let end = end_slot.unwrap_or_else(|| self.slot());
        info!("📡 RPC ← getBlocks({}, {})", start_slot, end);
        let mut slots = Vec::new();
        if let Some(bp) = &self.block_producer {
            for s in start_slot..=end.min(start_slot + 500_000) {
                if bp.get_block(s).is_some() {
                    slots.push(s);
                }
            }
        }
        Ok(slots)
    }

    async fn get_block_production(
        &self,
        _config: Option<serde_json::Value>,
    ) -> RpcResult<RpcResponse<serde_json::Value>> {
        info!("📡 RPC ← getBlockProduction");
        let slot = self.slot();
        // Single-validator: use total_blocks_produced() O(1) instead of scanning every slot
        let total_leader_slots = slot.saturating_add(1); // slots 0..=slot
        let total_produced = self.block_producer.as_ref()
            .map(|bp| bp.total_blocks_produced())
            .unwrap_or(0);
        Ok(RpcResponse {
            context: self.ctx(),
            value: serde_json::json!({
                "byIdentity": {
                    "genesis_validator": [total_leader_slots, total_produced]
                },
                "range": {
                    "firstSlot": 0,
                    "lastSlot": slot,
                }
            }),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server lifecycle  
// ─────────────────────────────────────────────────────────────────────────────

/// Start the Solana JSON-RPC server on the given address (e.g. `"0.0.0.0:8899"`).
/// Returns the server handle — dropping it stops the server.
/// Call `tokio::spawn(async move { handle.stopped().await })` to run in background.
pub async fn start_rpc_server(
    rpc: BlackBookRpcImpl,
    addr: &str,
) -> Result<jsonrpsee::server::ServerHandle, Box<dyn std::error::Error>> {
    use jsonrpsee::server::Server;
    use tower_http::cors::{CorsLayer, Any};

    // Allow all origins so OneKey / Phantom desktop (Electron) can connect
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let middleware = tower::ServiceBuilder::new().layer(cors);

    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(addr)
        .await?;

    let module = rpc.into_rpc();
    let handle = server.start(module);

    info!("🔌 BlackBook L1 JSON-RPC server listening on {addr}  (CORS=*, Solana-compatible)");
    Ok(handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Error helpers
// ─────────────────────────────────────────────────────────────────────────────

fn error_invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.into(), None::<()>)
}

/// Transaction already processed (replay protection).
fn error_already_processed(msg: impl Into<String>) -> ErrorObjectOwned {
    // Solana uses -32002 for "Transaction simulation failed" class
    ErrorObjectOwned::owned(-32002, msg.into(), None::<()>)
}

/// Internal server error (storage failure, lock poison, etc.)
fn error_internal(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg.into(), None::<()>)
}

/// Transaction execution failed (insufficient funds, etc.)
fn error_transaction_failed(msg: impl Into<String>) -> ErrorObjectOwned {
    // -32003: "Transaction precompile verification failure" (Solana convention)
    ErrorObjectOwned::owned(-32003, msg.into(), None::<()>)
}
