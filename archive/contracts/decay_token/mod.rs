//! $DECAY — Value-Recapture Token
//!
//! Each $DECAY is an NFT-style on-chain object backed by wUSDT. Every "use"
//! leaks 1% of the **current** backing into the central treasury (geometric
//! decay: ~36.6% remains after 100 uses). After `MAX_USES` the token is dead
//! and must be **recharged** by burning $XX (MAXX) and paying a wUSDT
//! maintenance fee. Long-stake locks give a 25% recharge discount.
//!
//! ⚠ Trade endpoints (`mint`, `use`, `recharge`, `stake`) are currently
//!   unauthenticated — see `clean_blockchain.md` airtightness gap #1.
//!   Ed25519 verification must be added before mainnet alongside `/maxx/*`
//!   and `/transfer/simple` routes.

use axum::{
    extract::{Path, State, Json},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use tracing::{error, info};

use crate::AppState;
use crate::auth;
use crate::storage::{DECAY_TOKENS, DECAY_OWNER_INDEX, DECAY_META};
use crate::svm::{
    SplTokenEngine,
    usdc_mint_bytes, USDC_UNIT,
    maxx_mint_bytes, MAXX_UNIT,
    decay_vault_bytes, decay_treasury_bytes,
};

// ─────────────────────────── Economic constants ──────────────────────────────

/// Leak per use = 1% of the token's current backing (geometric decay).
pub const LEAK_PCT_DENOM: u128 = 100;

/// Maximum uses before the token must be recharged.
pub const MAX_USES: u32 = 100;

/// Standard recharge wUSDT maintenance fee (2 wUSDT, in microUSDT).
pub const RECHARGE_FEE_USDT: u128 = 2 * USDC_UNIT as u128;

/// Discounted recharge fee for long-staked tokens (25% off → 1.5 wUSDT).
pub const RECHARGE_FEE_USDT_DISCOUNTED: u128 = (RECHARGE_FEE_USDT * 75) / 100;

/// MAXX burn cost per recharge (5 MAXX, in picoMAXX).
pub const RECHARGE_BURN_MAXX: u128 = 5 * MAXX_UNIT as u128;

/// Minimum mint backing (1 wUSDT). Below this the leak rounds to zero.
pub const MIN_MINT_BACKING: u128 = USDC_UNIT as u128;

// ─────────────────────────── Per-token state ─────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecayToken {
    pub id: u64,
    /// Base58 owner address.
    pub owner: String,
    /// Wrapped USDT physically held in the decay vault for this token (microUSDT).
    pub backing_value: u128,
    /// 0..=MAX_USES.
    pub uses_count: u32,
    pub minted_slot: u64,
    pub last_use_slot: u64,
    /// 0 means unlocked. While `current_slot < lock_until_slot`, recharges are discounted.
    pub lock_until_slot: u64,
    pub recharge_count: u32,
}

impl DecayToken {
    pub fn is_dead(&self) -> bool { self.uses_count >= MAX_USES }
    pub fn is_locked(&self, current_slot: u64) -> bool { self.lock_until_slot > current_slot }
}

// ─────────────────────────── ReDB helpers ────────────────────────────────────

fn next_token_id(db: &redb::Database) -> Result<u64, redb::Error> {
    use redb::ReadableTable;
    let txn = db.begin_write()?;
    let id: u64 = {
        let mut meta = txn.open_table(DECAY_META)?;
        let current = meta.get("next_id")?.map(|v| v.value()).unwrap_or(1);
        meta.insert("next_id", current + 1)?;
        current
    };
    txn.commit()?;
    Ok(id)
}

fn put_token(db: &redb::Database, token: &DecayToken) -> Result<(), redb::Error> {
    let txn = db.begin_write()?;
    {
        let mut tbl = txn.open_table(DECAY_TOKENS)?;
        let bytes = serde_json::to_vec(token).expect("serialize DecayToken");
        tbl.insert(token.id, bytes.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

pub fn get_token(db: &redb::Database, id: u64) -> Option<DecayToken> {
    let txn = db.begin_read().ok()?;
    let tbl = txn.open_table(DECAY_TOKENS).ok()?;
    let val = tbl.get(id).ok()??;
    serde_json::from_slice(val.value()).ok()
}

fn add_to_owner_index(db: &redb::Database, owner: &str, id: u64) -> Result<(), redb::Error> {
    use redb::ReadableTable;
    let txn = db.begin_write()?;
    {
        let mut tbl = txn.open_table(DECAY_OWNER_INDEX)?;
        let mut ids: Vec<u64> = tbl
            .get(owner)?
            .and_then(|v| serde_json::from_slice(v.value()).ok())
            .unwrap_or_default();
        if !ids.contains(&id) {
            ids.push(id);
        }
        let bytes = serde_json::to_vec(&ids).expect("serialize owner index");
        tbl.insert(owner, bytes.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

pub fn get_owner_tokens(db: &redb::Database, owner: &str) -> Vec<u64> {
    let Ok(txn) = db.begin_read() else { return Vec::new(); };
    let Ok(tbl) = txn.open_table(DECAY_OWNER_INDEX) else { return Vec::new(); };
    tbl.get(owner)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(v.value()).ok())
        .unwrap_or_default()
}

// ─────────────────────────── Request/Response DTOs ───────────────────────────

fn parse_pubkey(s: &str) -> Result<Pubkey, &'static str> {
    let v = bs58::decode(s).into_vec().map_err(|_| "Invalid base58 address")?;
    if v.len() != 32 { return Err("Address must be 32 bytes"); }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Ok(Pubkey::new_from_array(k))
}

#[derive(Deserialize)]
pub struct MintDecayRequest {
    pub from: String,
    /// wUSDT to lock as backing, in microUSDT.
    pub backing_amount: u128,
    // ── Auth fields ──────────────────────────────────────────────
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct UseDecayRequest {
    pub from: String,
    pub token_id: u64,
    // ── Auth fields ──────────────────────────────────────────────
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct RechargeDecayRequest {
    pub from: String,
    pub token_id: u64,
    // ── Auth fields ──────────────────────────────────────────────
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct StakeDecayRequest {
    pub from: String,
    pub token_id: u64,
    /// How many slots to lock the token for.
    pub lock_slots: u64,
    // ── Auth fields ──────────────────────────────────────────────
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Serialize)]
pub struct DecayMintResponse {
    pub message: String,
    pub token: DecayToken,
    pub user_wusdt_balance: u64,
}

#[derive(Serialize)]
pub struct DecayUseResponse {
    pub message: String,
    pub token: DecayToken,
    pub leak_microusdt: u128,
    pub treasury_balance: u64,
}

#[derive(Serialize)]
pub struct DecayRechargeResponse {
    pub message: String,
    pub token: DecayToken,
    pub fee_paid_microusdt: u128,
    pub maxx_burned: u64,
    pub user_maxx_balance: u64,
    pub user_wusdt_balance: u64,
    pub treasury_balance: u64,
}

#[derive(Serialize)]
pub struct DecayStakeResponse {
    pub message: String,
    pub token: DecayToken,
}

// ─────────────────────────── Handlers ────────────────────────────────────────

/// POST /decay/mint — lock wUSDT as backing, issue a new $DECAY.
pub async fn mint_decay_handler(
    State(state): State<AppState>,
    Json(req): Json<MintDecayRequest>,
) -> impl IntoResponse {
    // ── Ed25519 authentication: "DECAY_MINT:{from}:{backing_amount}:{ts}:{nonce}" ──
    if let Err((code, body)) = auth::verify_signed_action(
        &state,
        "DECAY_MINT",
        &req.from,
        &req.public_key,
        &req.signature,
        req.timestamp,
        &req.nonce,
        &req.backing_amount.to_string(),
    ) {
        return (code, body).into_response();
    }

    // ── Per-wallet rate limiting ───────────────────────────────────────────
    if let Err(msg) = state.throttler.check_transaction(&req.from, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if req.backing_amount < MIN_MINT_BACKING {
        return (StatusCode::BAD_REQUEST, format!(
            "Backing must be ≥ {} microUSDT (1 wUSDT)", MIN_MINT_BACKING
        )).into_response();
    }
    let user_pk = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let backing_u64 = match u64::try_from(req.backing_amount) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Backing overflow").into_response(),
    };

    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let vault_pk = Pubkey::new_from_array(decay_vault_bytes());

    // 1. Move backing wUSDT from user → decay vault.
    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &user_pk, &vault_pk, backing_u64) {
        return (StatusCode::BAD_REQUEST, format!("wUSDT transfer failed: {:?}", e)).into_response();
    }

    // 2. Allocate token ID and persist.
    let id = match next_token_id(&state.blockchain.db) {
        Ok(i) => i,
        Err(e) => {
            // Rollback the wUSDT transfer.
            let _ = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &vault_pk, &user_pk, backing_u64);
            error!("Failed to allocate DECAY id: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "ID allocation failed").into_response();
        }
    };
    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let token = DecayToken {
        id,
        owner: req.from.clone(),
        backing_value: req.backing_amount,
        uses_count: 0,
        minted_slot: height,
        last_use_slot: height,
        lock_until_slot: 0,
        recharge_count: 0,
    };
    if let Err(e) = put_token(&state.blockchain.db, &token) {
        let _ = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &vault_pk, &user_pk, backing_u64);
        error!("Failed to persist DECAY token: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Persist failed").into_response();
    }
    if let Err(e) = add_to_owner_index(&state.blockchain.db, &req.from, id) {
        error!("Failed to update DECAY owner index for {}: {:?}", req.from, e);
        // Non-fatal — the token still exists; index can be rebuilt.
    }
    let _ = svm.flush_block();

    let user_wusdt_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &user_pk);
    info!("🟢 DECAY mint: id={} owner={} backing={} microUSDT", id, req.from, req.backing_amount);

    (StatusCode::OK, Json(DecayMintResponse {
        message: format!("Minted $DECAY #{} backed by {:.6} wUSDT", id, req.backing_amount as f64 / USDC_UNIT as f64),
        token,
        user_wusdt_balance,
    })).into_response()
}

/// POST /decay/use — leak 1% of current backing into the treasury.
pub async fn use_decay_handler(
    State(state): State<AppState>,
    Json(req): Json<UseDecayRequest>,
) -> impl IntoResponse {
    // ── Ed25519 authentication: "DECAY_USE:{from}:{token_id}:{ts}:{nonce}" ──
    if let Err((code, body)) = auth::verify_signed_action(
        &state,
        "DECAY_USE",
        &req.from,
        &req.public_key,
        &req.signature,
        req.timestamp,
        &req.nonce,
        &req.token_id.to_string(),
    ) {
        return (code, body).into_response();
    }

    // ── Per-wallet rate limiting ───────────────────────────────────────────
    if let Err(msg) = state.throttler.check_transaction(&req.from, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    let mut token = match get_token(&state.blockchain.db, req.token_id) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Token not found").into_response(),
    };
    if token.owner != req.from {
        return (StatusCode::FORBIDDEN, "Not the owner of this token").into_response();
    }
    if token.is_dead() {
        return (StatusCode::CONFLICT, "Token is dead — recharge required").into_response();
    }

    let leak = token.backing_value / LEAK_PCT_DENOM;
    if leak == 0 {
        return (StatusCode::BAD_REQUEST, "Backing too small to leak — recharge or mint a new token").into_response();
    }
    let leak_u64 = match u64::try_from(leak) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Leak overflow").into_response(),
    };

    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let vault_pk = Pubkey::new_from_array(decay_vault_bytes());
    let treasury_pk = Pubkey::new_from_array(decay_treasury_bytes());

    // Move leak from vault → treasury.
    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &vault_pk, &treasury_pk, leak_u64) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Vault → treasury failed: {:?}", e)).into_response();
    }

    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    token.backing_value -= leak;
    token.uses_count += 1;
    token.last_use_slot = height;
    if let Err(e) = put_token(&state.blockchain.db, &token) {
        // Best-effort rollback.
        let _ = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &treasury_pk, &vault_pk, leak_u64);
        error!("Failed to persist DECAY use: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Persist failed").into_response();
    }
    let _ = svm.flush_block();

    let treasury_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &treasury_pk);
    info!(
        "🟠 DECAY use: id={} owner={} uses={}/{} leak={} microUSDT (backing now {})",
        token.id, token.owner, token.uses_count, MAX_USES, leak, token.backing_value
    );

    (StatusCode::OK, Json(DecayUseResponse {
        message: format!(
            "Used $DECAY #{} — {:.6} wUSDT recaptured to treasury ({} uses left)",
            token.id, leak as f64 / USDC_UNIT as f64, MAX_USES - token.uses_count
        ),
        token,
        leak_microusdt: leak,
        treasury_balance,
    })).into_response()
}

/// POST /decay/recharge — burn 5 MAXX + pay wUSDT fee → reset uses to 0.
pub async fn recharge_decay_handler(
    State(state): State<AppState>,
    Json(req): Json<RechargeDecayRequest>,
) -> impl IntoResponse {
    // ── Ed25519 authentication: "DECAY_RECHARGE:{from}:{token_id}:{ts}:{nonce}" ──
    if let Err((code, body)) = auth::verify_signed_action(
        &state,
        "DECAY_RECHARGE",
        &req.from,
        &req.public_key,
        &req.signature,
        req.timestamp,
        &req.nonce,
        &req.token_id.to_string(),
    ) {
        return (code, body).into_response();
    }

    // ── Per-wallet rate limiting ───────────────────────────────────────────
    if let Err(msg) = state.throttler.check_transaction(&req.from, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    let mut token = match get_token(&state.blockchain.db, req.token_id) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Token not found").into_response(),
    };
    if token.owner != req.from {
        return (StatusCode::FORBIDDEN, "Not the owner of this token").into_response();
    }
    if !token.is_dead() {
        return (StatusCode::BAD_REQUEST, format!(
            "Token still has {} uses remaining — recharge only when uses = MAX",
            MAX_USES - token.uses_count
        )).into_response();
    }

    let user_pk = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let fee_microusdt = if token.is_locked(height) {
        RECHARGE_FEE_USDT_DISCOUNTED
    } else {
        RECHARGE_FEE_USDT
    };
    let fee_u64 = fee_microusdt as u64;
    let burn_maxx_u64 = RECHARGE_BURN_MAXX as u64;

    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let maxx_mint = maxx_mint_bytes();
    let treasury_pk = Pubkey::new_from_array(decay_treasury_bytes());

    // 1. Burn MAXX from user.
    if let Err(e) = SplTokenEngine::burn(svm, &maxx_mint, &user_pk, burn_maxx_u64) {
        return (StatusCode::BAD_REQUEST, format!("MAXX burn failed: {:?}", e)).into_response();
    }
    // 2. Transfer wUSDT fee user → treasury.
    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &user_pk, &treasury_pk, fee_u64) {
        // Rollback the burn.
        let _ = SplTokenEngine::mint_to(svm, &maxx_mint, &user_pk, burn_maxx_u64);
        return (StatusCode::BAD_REQUEST, format!("wUSDT fee transfer failed: {:?}", e)).into_response();
    }

    // 3. Reset token state.
    token.uses_count = 0;
    token.recharge_count += 1;
    if let Err(e) = put_token(&state.blockchain.db, &token) {
        // Best-effort rollback.
        let _ = SplTokenEngine::mint_to(svm, &maxx_mint, &user_pk, burn_maxx_u64);
        let _ = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &treasury_pk, &user_pk, fee_u64);
        error!("Failed to persist DECAY recharge: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Persist failed").into_response();
    }
    let _ = svm.flush_block();

    let user_maxx_balance = SplTokenEngine::get_token_balance(svm, &maxx_mint, &user_pk);
    let user_wusdt_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &user_pk);
    let treasury_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &treasury_pk);
    info!(
        "🔵 DECAY recharge: id={} owner={} fee={} microUSDT (burned {} picoMAXX, recharge #{})",
        token.id, token.owner, fee_microusdt, burn_maxx_u64, token.recharge_count
    );

    (StatusCode::OK, Json(DecayRechargeResponse {
        message: format!(
            "Recharged $DECAY #{} — fee {:.6} wUSDT, burned {:.6} MAXX",
            token.id,
            fee_microusdt as f64 / USDC_UNIT as f64,
            burn_maxx_u64 as f64 / MAXX_UNIT as f64
        ),
        token,
        fee_paid_microusdt: fee_microusdt,
        maxx_burned: burn_maxx_u64,
        user_maxx_balance,
        user_wusdt_balance,
        treasury_balance,
    })).into_response()
}

/// POST /decay/stake — extend `lock_until_slot` for a recharge discount.
pub async fn stake_decay_handler(
    State(state): State<AppState>,
    Json(req): Json<StakeDecayRequest>,
) -> impl IntoResponse {
    // ── Ed25519 authentication: "DECAY_STAKE:{from}:{token_id}:{lock_slots}:{ts}:{nonce}" ──
    let body_str = format!("{}:{}", req.token_id, req.lock_slots);
    if let Err((code, body)) = auth::verify_signed_action(
        &state,
        "DECAY_STAKE",
        &req.from,
        &req.public_key,
        &req.signature,
        req.timestamp,
        &req.nonce,
        &body_str,
    ) {
        return (code, body).into_response();
    }

    // ── Per-wallet rate limiting ───────────────────────────────────────────
    if let Err(msg) = state.throttler.check_transaction(&req.from, 0.0) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if req.lock_slots == 0 {
        return (StatusCode::BAD_REQUEST, "lock_slots must be > 0").into_response();
    }
    let mut token = match get_token(&state.blockchain.db, req.token_id) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Token not found").into_response(),
    };
    if token.owner != req.from {
        return (StatusCode::FORBIDDEN, "Not the owner of this token").into_response();
    }
    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let new_lock = height.saturating_add(req.lock_slots);
    if new_lock > token.lock_until_slot {
        token.lock_until_slot = new_lock;
    }
    if let Err(e) = put_token(&state.blockchain.db, &token) {
        error!("Failed to persist DECAY stake: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Persist failed").into_response();
    }
    info!("🟣 DECAY stake: id={} owner={} lock_until={}", token.id, token.owner, token.lock_until_slot);
    (StatusCode::OK, Json(DecayStakeResponse {
        message: format!("Staked $DECAY #{} until slot {}", token.id, token.lock_until_slot),
        token,
    })).into_response()
}

// ─────────────────────────── Read endpoints ──────────────────────────────────

#[derive(Serialize)]
pub struct DecayTreasuryResponse {
    pub treasury_address: String,
    pub treasury_wusdt_balance: u64,
    pub vault_address: String,
    pub vault_wusdt_balance: u64,
    pub total_minted: u64,
    pub reserve_currency: &'static str,
}

#[derive(Serialize)]
pub struct DecaySupplyResponse {
    pub ticker: &'static str,
    pub token_name: &'static str,
    pub total_minted: u64,
    pub max_uses_per_token: u32,
    pub leak_pct_per_use: u8,
}

#[derive(Serialize)]
pub struct DecayOwnerResponse {
    pub address: String,
    pub token_ids: Vec<u64>,
    pub tokens: Vec<DecayToken>,
}

pub async fn decay_token_handler(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match get_token(&state.blockchain.db, id) {
        Some(t) => (StatusCode::OK, Json(t)).into_response(),
        None => (StatusCode::NOT_FOUND, "Token not found").into_response(),
    }
}

pub async fn decay_owner_handler(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let ids = get_owner_tokens(&state.blockchain.db, &address);
    let tokens: Vec<DecayToken> = ids
        .iter()
        .filter_map(|id| get_token(&state.blockchain.db, *id))
        .collect();
    (StatusCode::OK, Json(DecayOwnerResponse {
        address,
        token_ids: ids,
        tokens,
    })).into_response()
}

pub async fn decay_treasury_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let treasury_pk = Pubkey::new_from_array(decay_treasury_bytes());
    let vault_pk = Pubkey::new_from_array(decay_vault_bytes());

    let total_minted: u64 = state.blockchain.db.begin_read()
        .ok()
        .and_then(|txn| txn.open_table(DECAY_META).ok().map(|tbl| {
            tbl.get("next_id").ok().flatten().map(|v| v.value().saturating_sub(1)).unwrap_or(0)
        }))
        .unwrap_or(0);

    (StatusCode::OK, Json(DecayTreasuryResponse {
        treasury_address: bs58::encode(decay_treasury_bytes()).into_string(),
        treasury_wusdt_balance: SplTokenEngine::get_token_balance(svm, &usdt_mint, &treasury_pk),
        vault_address: bs58::encode(decay_vault_bytes()).into_string(),
        vault_wusdt_balance: SplTokenEngine::get_token_balance(svm, &usdt_mint, &vault_pk),
        total_minted,
        reserve_currency: "wUSDT",
    })).into_response()
}

pub async fn decay_supply_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let total_minted: u64 = state.blockchain.db.begin_read()
        .ok()
        .and_then(|txn| txn.open_table(DECAY_META).ok().map(|tbl| {
            tbl.get("next_id").ok().flatten().map(|v| v.value().saturating_sub(1)).unwrap_or(0)
        }))
        .unwrap_or(0);
    (StatusCode::OK, Json(DecaySupplyResponse {
        ticker: "$DECAY",
        token_name: "DECAY",
        total_minted,
        max_uses_per_token: MAX_USES,
        leak_pct_per_use: 1,
    })).into_response()
}
