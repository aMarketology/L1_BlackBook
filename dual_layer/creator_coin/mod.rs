// ============================================================================
// LAYER 5 — CREATOR COIN LAUNCHPAD
// ============================================================================
//
// Constant-product AMM (Uniswap v2 style) for creator-launched tokens.
// Every creator coin trades against BB (the BlackBook base currency).
//
// LAUNCH FLOW:
//   POST /coin/launch
//     → creator deposits MIN_LAUNCH_BB (10,000 BB ≈ $1,000 USD)
//     → protocol mints TOTAL_SUPPLY coins (1,000,000,000 with 6 decimals)
//     → 50% (500M) to pool reserves  →  k = reserve_bb × reserve_coin
//     → 50% (500M) to creator wallet
//
// TRADE FLOW:
//   POST /coin/buy   — user pays BB_in, receives coins_out from pool
//   POST /coin/sell  — user pays coins_in, receives BB_out from pool
//
// FEE MODEL (1% per trade, charged on the input token):
//   0.3% → creator wallet (in the input token)
//   0.7% → stays in pool reserves (raises k, benefits all holders)
//
// AMM FORMULA (constant product):
//   buy:   coin_out = reserve_coin × bb_net / (reserve_bb + bb_net)
//   sell:  bb_out   = reserve_bb   × coin_net / (reserve_coin + coin_net)
//          where bb_net  = bb_in  × 9970 / 10_000   (fee deducted)
//                coin_net = coin_in × 9970 / 10_000
//
// SLIPPAGE PROTECTION:
//   Every trade request carries a min_out parameter (u64).
//   The handler rejects if actual output < min_out.
//
// STORAGE:
//   AppState.creator_coins:  ticker → CreatorCoinRecord  (metadata)
//   AppState.coin_pools:     ticker → CoinPoolState      (AMM state)
//   AppState.coin_balances:  "{ticker}:{wallet}" → u64   (user holdings)
//   All three are DashMap hot-caches backed by ReDB.
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use tracing::info;

use crate::{
    storage::{CreatorCoinRecord, CoinPoolState},
    AppState,
};
use crate::svm::types::LAMPORTS_PER_BB;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum BB required to launch a coin (10,000 BB ≈ $1,000 USD at 10 BB/$1).
pub const MIN_LAUNCH_BB: f64 = 10_000.0;

/// Total creator coin supply at launch (1 billion with 6 decimals).
pub const TOTAL_SUPPLY: u64 = 1_000_000_000 * COIN_UNIT;

/// Pool's initial share of total supply: 50%.
pub const POOL_INITIAL_COINS: u64 = TOTAL_SUPPLY / 2;

/// Creator's initial share: 50%.
pub const CREATOR_INITIAL_COINS: u64 = TOTAL_SUPPLY / 2;

/// One creator coin in base units (6 decimal places).
pub const COIN_UNIT: u64 = 1_000_000;

/// Total trade fee in basis points (1%).
const TRADE_FEE_BPS: u128 = 100;

/// Creator's share of the trade fee: 0.3% of input (30% of 1% fee).
const CREATOR_FEE_BPS: u128 = 30;

/// Pool's fee share retained in reserves: 0.7% of input (70% of 1% fee).
/// This stays in the AMM reserves and raises k over time.
const POOL_FEE_BPS: u128 = 70;

// Validate fee constants add up
const _: () = assert!(CREATOR_FEE_BPS + POOL_FEE_BPS == TRADE_FEE_BPS);

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LaunchRequest {
    /// 2–10 uppercase alphanumeric chars. e.g. "MAX", "XYZ".
    pub ticker: String,
    /// Human-readable name. e.g. "Max Token".
    pub name: String,
    /// Creator's BB wallet (base58).
    pub creator_wallet: String,
    /// BB to seed the pool with (must be ≥ MIN_LAUNCH_BB).
    pub initial_bb: f64,
    /// Optional description / tagline (max 280 chars).
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct BuyRequest {
    /// Ticker of the creator coin to buy. e.g. "MAX".
    pub ticker: String,
    /// Buyer's BB wallet (base58).
    pub wallet: String,
    /// Amount of BB to spend (human-readable, e.g. 100.0 = 100 BB).
    pub bb_amount: f64,
    /// Minimum coins to receive (slippage guard). 0 = no guard.
    pub min_coins_out: u64,
}

#[derive(Deserialize)]
pub struct SellRequest {
    /// Ticker of the creator coin to sell.
    pub ticker: String,
    /// Seller's BB wallet (base58).
    pub wallet: String,
    /// Amount of coins to sell (in base units, 6 decimals; e.g. 1_000_000 = 1 coin).
    pub coins_in: u64,
    /// Minimum BB to receive. 0 = no guard.
    pub min_bb_out: u64,
}

// ── AMM math ──────────────────────────────────────────────────────────────────

/// Compute coins_out and creator_fee_bb for a BB→coin buy.
///
/// Returns `(coins_out, creator_fee_bb, bb_net_to_pool)`.
fn amm_buy(reserve_bb: u64, reserve_coin: u64, bb_in: u64) -> (u64, u64, u64) {
    let r_bb   = reserve_bb as u128;
    let r_coin = reserve_coin as u128;
    let bb     = bb_in as u128;

    // Fees on the input (bb_in)
    let creator_fee = bb * CREATOR_FEE_BPS / 10_000;
    let pool_fee    = bb * POOL_FEE_BPS    / 10_000;

    // 99% of bb_in is used to quote the AMM price; pool_fee stays in reserves
    let bb_for_amm = bb - creator_fee - pool_fee;

    // constant-product: new_bb * new_coin = k  →  coin_out = r_coin * bb_for_amm / (r_bb + bb_for_amm)
    let coin_out = r_coin * bb_for_amm / (r_bb + bb_for_amm);

    // The 0.7% pool fee (bb) stays; full net = bb_for_amm + pool_fee enters reserve
    let bb_net_to_pool = bb - creator_fee; // = bb_for_amm + pool_fee

    (coin_out as u64, creator_fee as u64, bb_net_to_pool as u64)
}

/// Compute bb_out and creator_fee_coins for a coin→BB sell.
///
/// Returns `(bb_out, creator_fee_coins, coins_net_to_pool)`.
fn amm_sell(reserve_bb: u64, reserve_coin: u64, coins_in: u64) -> (u64, u64, u64) {
    let r_bb   = reserve_bb as u128;
    let r_coin = reserve_coin as u128;
    let ci     = coins_in as u128;

    let creator_fee = ci * CREATOR_FEE_BPS / 10_000;
    let pool_fee    = ci * POOL_FEE_BPS    / 10_000;
    let coins_for_amm = ci - creator_fee - pool_fee;

    let bb_out = r_bb * coins_for_amm / (r_coin + coins_for_amm);
    let coins_net_to_pool = ci - creator_fee;

    (bb_out as u64, creator_fee as u64, coins_net_to_pool as u64)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn validate_ticker(ticker: &str) -> bool {
    let t = ticker.trim();
    let len = t.len();
    len >= 2
        && len <= 10
        && t.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn validate_bb_address(addr: &str) -> bool {
    if addr.starts_with("0x") { return false; }
    matches!(bs58::decode(addr).into_vec(), Ok(b) if b.len() == 32)
}

fn balance_key(ticker: &str, wallet: &str) -> String {
    format!("{}:{}", ticker.to_uppercase(), wallet)
}

/// Convert BB f64 → lamports (u64). Returns None if non-positive or too large.
fn bb_to_lamports(bb: f64) -> Option<u64> {
    if bb <= 0.0 || bb > 1_000_000_000.0 { return None; }
    Some((bb * LAMPORTS_PER_BB as f64).round() as u64)
}

// ── POST /coin/launch ─────────────────────────────────────────────────────────

pub async fn launch_handler(
    State(state): State<AppState>,
    Json(req): Json<LaunchRequest>,
) -> impl IntoResponse {
    // ── Input validation ──────────────────────────────────────────────────────
    let ticker = req.ticker.trim().to_uppercase();

    if !validate_ticker(&ticker) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "ticker must be 2-10 uppercase alphanumeric characters" })),
        );
    }
    if req.name.trim().is_empty() || req.name.len() > 64 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "name required, max 64 chars" })));
    }
    if !validate_bb_address(&req.creator_wallet) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid creator_wallet" })));
    }
    if req.initial_bb < MIN_LAUNCH_BB {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("minimum initial_bb is {} (≈ $1,000 USD)", MIN_LAUNCH_BB)
            })),
        );
    }
    if let Some(desc) = &req.description {
        if desc.len() > 280 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "description max 280 chars" })));
        }
    }

    // ── Duplicate check ───────────────────────────────────────────────────────
    if state.creator_coins.contains_key(&ticker) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": format!("ticker ${} is already launched", ticker) })),
        );
    }

    // ── Balance check + debit ─────────────────────────────────────────────────
    let initial_bb_lamports = match bb_to_lamports(req.initial_bb) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid initial_bb amount" }))),
    };

    let creator_bb = state.blockchain.get_balance(&req.creator_wallet);
    if creator_bb < req.initial_bb {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("insufficient BB balance: have {:.4}, need {:.4}", creator_bb, req.initial_bb)
            })),
        );
    }

    // Debit the creator's BB (burned into the pool)
    if let Err(e) = state.blockchain.debit(&req.creator_wallet, req.initial_bb) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to debit creator BB: {}", e) })),
        );
    }

    // ── Create records ────────────────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = CreatorCoinRecord {
        ticker: ticker.clone(),
        name: req.name.trim().to_string(),
        creator_wallet: req.creator_wallet.clone(),
        launched_at: now,
        total_supply: TOTAL_SUPPLY,
        description: req.description.clone().map(|d| d.trim().to_string()),
    };

    let pool = CoinPoolState {
        ticker: ticker.clone(),
        reserve_bb: initial_bb_lamports,
        reserve_coin: POOL_INITIAL_COINS,
        total_fees_bb: 0,
        total_fees_coins: 0,
        volume_bb: 0,
        tx_count: 0,
        created_at: now,
        last_trade_at: now,
    };

    // ── Persist + populate hot caches ─────────────────────────────────────────
    let _ = state.blockchain.store_creator_coin(&record);
    let _ = state.blockchain.store_coin_pool(&pool);

    state.creator_coins.insert(ticker.clone(), record.clone());
    state.coin_pools.insert(ticker.clone(), pool.clone());

    // Credit 50% of supply to creator
    let creator_key = balance_key(&ticker, &req.creator_wallet);
    state.coin_balances.insert(creator_key.clone(), CREATOR_INITIAL_COINS);
    let _ = state.blockchain.store_coin_balance(&creator_key, CREATOR_INITIAL_COINS);

    let initial_price = initial_bb_lamports as f64 / LAMPORTS_PER_BB as f64
        / POOL_INITIAL_COINS as f64 * COIN_UNIT as f64;

    info!(
        "🚀 Creator coin launched: ${} by {} | pool={:.0} BB + {} coins | price={:.8} BB",
        ticker,
        &req.creator_wallet[..8.min(req.creator_wallet.len())],
        req.initial_bb,
        POOL_INITIAL_COINS,
        initial_price
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ticker": ticker,
            "name": record.name,
            "creator": req.creator_wallet,
            "total_supply": TOTAL_SUPPLY,
            "creator_balance": CREATOR_INITIAL_COINS,
            "pool_reserve_bb": req.initial_bb,
            "pool_reserve_coins": POOL_INITIAL_COINS,
            "initial_price_bb_per_coin": initial_price,
            "initial_price_usd_per_coin": initial_price / 10.0,
            "launched_at": now,
        })),
    )
}

// ── POST /coin/buy ────────────────────────────────────────────────────────────

pub async fn buy_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyRequest>,
) -> impl IntoResponse {
    let ticker = req.ticker.trim().to_uppercase();

    if !validate_bb_address(&req.wallet) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid wallet" })));
    }
    if req.bb_amount <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "bb_amount must be positive" })));
    }

    let bb_lamports = match bb_to_lamports(req.bb_amount) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid bb_amount" }))),
    };

    // Lookup pool (immutable first, then mutable)
    let creator_wallet = {
        let rec = match state.creator_coins.get(&ticker) {
            Some(r) => r.creator_wallet.clone(),
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("coin ${} not found", ticker) }))),
        };
        rec
    };

    // Check buyer balance
    let buyer_bb = state.blockchain.get_balance(&req.wallet);
    if buyer_bb < req.bb_amount {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("insufficient BB: have {:.4}, need {:.4}", buyer_bb, req.bb_amount)
            })),
        );
    }

    // Execute trade — hold pool RefMut for the full atomic update
    let (coins_out, creator_fee_bb, _bb_net_to_pool, new_reserve_bb, new_reserve_coin) = {
        let mut pool_ref = match state.coin_pools.get_mut(&ticker) {
            Some(p) => p,
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "pool not found" }))),
        };

        let (coins_out, creator_fee_bb, bb_net) =
            amm_buy(pool_ref.reserve_bb, pool_ref.reserve_coin, bb_lamports);

        if coins_out == 0 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "amount too small: zero coins out" })));
        }
        if coins_out < req.min_coins_out {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("slippage: expected ≥{} coins but would get {}", req.min_coins_out, coins_out)
                })),
            );
        }
        if coins_out > pool_ref.reserve_coin {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "insufficient pool liquidity" })));
        }

        pool_ref.reserve_bb    = pool_ref.reserve_bb.saturating_add(bb_net);
        pool_ref.reserve_coin  = pool_ref.reserve_coin.saturating_sub(coins_out);
        pool_ref.total_fees_bb = pool_ref.total_fees_bb.saturating_add(creator_fee_bb);
        pool_ref.volume_bb     = pool_ref.volume_bb.saturating_add(bb_lamports);
        pool_ref.tx_count     += 1;
        pool_ref.last_trade_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        (coins_out, creator_fee_bb, bb_net, pool_ref.reserve_bb, pool_ref.reserve_coin)
    };

    // Debit buyer BB
    if let Err(e) = state.blockchain.debit(&req.wallet, req.bb_amount) {
        // Rollback pool? In practice, log + alert. For MVP we debit first, adjust after.
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })));
    }

    // Credit creator fee in BB
    let creator_fee_bb_human = creator_fee_bb as f64 / LAMPORTS_PER_BB as f64;
    if creator_fee_bb > 0 {
        let _ = state.blockchain.credit(&creator_wallet, creator_fee_bb as f64 / LAMPORTS_PER_BB as f64);
    }

    // Credit buyer coins
    let buyer_key = balance_key(&ticker, &req.wallet);
    let new_coin_bal = {
        let mut entry = state.coin_balances
            .entry(buyer_key.clone())
            .or_insert(0);
        *entry = entry.saturating_add(coins_out);
        *entry
    };
    let _ = state.blockchain.store_coin_balance(&buyer_key, new_coin_bal);

    // Persist pool
    if let Some(pool) = state.coin_pools.get(&ticker) {
        let _ = state.blockchain.store_coin_pool(&*pool);
    }

    let new_price = new_reserve_bb as f64 / LAMPORTS_PER_BB as f64
        / new_reserve_coin as f64 * COIN_UNIT as f64;

    info!(
        "💹 Buy ${}: {} BB → {} coins | fee={:.4} BB to {} | price={:.8}",
        ticker, req.bb_amount, coins_out,
        creator_fee_bb_human,
        &creator_wallet[..8.min(creator_wallet.len())],
        new_price
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ticker": ticker,
            "bb_spent": req.bb_amount,
            "coins_received": coins_out,
            "creator_fee_bb": creator_fee_bb_human,
            "new_price_bb_per_coin": new_price,
            "new_price_usd_per_coin": new_price / 10.0,
            "pool_reserve_bb": new_reserve_bb as f64 / LAMPORTS_PER_BB as f64,
            "pool_reserve_coins": new_reserve_coin,
        })),
    )
}

// ── POST /coin/sell ───────────────────────────────────────────────────────────

pub async fn sell_handler(
    State(state): State<AppState>,
    Json(req): Json<SellRequest>,
) -> impl IntoResponse {
    let ticker = req.ticker.trim().to_uppercase();

    if !validate_bb_address(&req.wallet) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid wallet" })));
    }
    if req.coins_in == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "coins_in must be positive" })));
    }

    let creator_wallet = match state.creator_coins.get(&ticker) {
        Some(r) => r.creator_wallet.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("coin ${} not found", ticker) }))),
    };

    // Check seller coin balance
    let seller_key = balance_key(&ticker, &req.wallet);
    let seller_coins = state.coin_balances.get(&seller_key).map(|r| *r.value()).unwrap_or(0);
    if seller_coins < req.coins_in {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("insufficient ${} balance: have {}, need {}", ticker, seller_coins, req.coins_in)
            })),
        );
    }

    // Execute AMM sell — hold pool lock for the update
    let (bb_out, creator_fee_coins, new_reserve_bb, new_reserve_coin) = {
        let mut pool_ref = match state.coin_pools.get_mut(&ticker) {
            Some(p) => p,
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "pool not found" }))),
        };

        let (bb_out, creator_fee_coins, coins_net) =
            amm_sell(pool_ref.reserve_bb, pool_ref.reserve_coin, req.coins_in);

        if bb_out == 0 {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "amount too small: zero BB out" })));
        }
        if bb_out < req.min_bb_out {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("slippage: expected ≥{} lamports but would get {}", req.min_bb_out, bb_out)
                })),
            );
        }
        if bb_out > pool_ref.reserve_bb {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "insufficient pool BB liquidity" })));
        }

        pool_ref.reserve_coin   = pool_ref.reserve_coin.saturating_add(coins_net);
        pool_ref.reserve_bb     = pool_ref.reserve_bb.saturating_sub(bb_out);
        pool_ref.total_fees_coins = pool_ref.total_fees_coins.saturating_add(creator_fee_coins);
        pool_ref.volume_bb      = pool_ref.volume_bb.saturating_add(bb_out);
        pool_ref.tx_count      += 1;
        pool_ref.last_trade_at  = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        (bb_out, creator_fee_coins, pool_ref.reserve_bb, pool_ref.reserve_coin)
    };

    // Debit seller coins
    {
        let mut bal = state.coin_balances.entry(seller_key.clone()).or_insert(0);
        *bal = bal.saturating_sub(req.coins_in);
        let new_bal = *bal;
        drop(bal);
        let _ = state.blockchain.store_coin_balance(&seller_key, new_bal);
    }

    // Credit seller with BB
    let bb_out_human = bb_out as f64 / LAMPORTS_PER_BB as f64;
    if let Err(e) = state.blockchain.credit(&req.wallet, bb_out_human) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e })));
    }

    // Credit creator fee in coins
    if creator_fee_coins > 0 {
        let creator_key = balance_key(&ticker, &creator_wallet);
        let new_bal = {
            let mut bal = state.coin_balances.entry(creator_key.clone()).or_insert(0);
            *bal = bal.saturating_add(creator_fee_coins);
            *bal
        };
        let _ = state.blockchain.store_coin_balance(&creator_key, new_bal);
    }

    // Persist pool
    if let Some(pool) = state.coin_pools.get(&ticker) {
        let _ = state.blockchain.store_coin_pool(&*pool);
    }

    let new_price = new_reserve_bb as f64 / LAMPORTS_PER_BB as f64
        / new_reserve_coin as f64 * COIN_UNIT as f64;

    info!(
        "💹 Sell ${}: {} coins → {:.4} BB | fee={} coins to {} | price={:.8}",
        ticker, req.coins_in, bb_out_human, creator_fee_coins,
        &creator_wallet[..8.min(creator_wallet.len())],
        new_price
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ticker": ticker,
            "coins_sold": req.coins_in,
            "bb_received": bb_out_human,
            "creator_fee_coins": creator_fee_coins,
            "new_price_bb_per_coin": new_price,
            "new_price_usd_per_coin": new_price / 10.0,
            "pool_reserve_bb": new_reserve_bb as f64 / LAMPORTS_PER_BB as f64,
            "pool_reserve_coins": new_reserve_coin,
        })),
    )
}

// ── GET /coin/price/:ticker ───────────────────────────────────────────────────

pub async fn price_handler(
    State(state): State<AppState>,
    Path(ticker): Path<String>,
) -> impl IntoResponse {
    let ticker = ticker.trim().to_uppercase();
    match state.coin_pools.get(&ticker) {
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("coin ${} not found", ticker) })),
        ),
        Some(pool) => {
            let price_bb = pool.reserve_bb as f64 / LAMPORTS_PER_BB as f64
                / pool.reserve_coin as f64 * COIN_UNIT as f64;
            let market_cap_bb = price_bb * (TOTAL_SUPPLY as f64 / COIN_UNIT as f64);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ticker": ticker,
                    "price_bb_per_coin": price_bb,
                    "price_usd_per_coin": price_bb / 10.0,
                    "market_cap_bb": market_cap_bb,
                    "market_cap_usd": market_cap_bb / 10.0,
                    "pool_reserve_bb": pool.reserve_bb as f64 / LAMPORTS_PER_BB as f64,
                    "pool_reserve_coins": pool.reserve_coin,
                    "volume_bb": pool.volume_bb as f64 / LAMPORTS_PER_BB as f64,
                    "tx_count": pool.tx_count,
                    "last_trade_at": pool.last_trade_at,
                })),
            )
        }
    }
}

// ── GET /coin/balance/:ticker/:wallet ─────────────────────────────────────────

pub async fn balance_handler(
    State(state): State<AppState>,
    Path((ticker, wallet)): Path<(String, String)>,
) -> impl IntoResponse {
    let ticker = ticker.trim().to_uppercase();
    if !state.creator_coins.contains_key(&ticker) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("coin ${} not found", ticker) })));
    }
    let key = balance_key(&ticker, &wallet);
    let balance = state.coin_balances.get(&key).map(|r| *r.value()).unwrap_or(0);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ticker": ticker,
            "wallet": wallet,
            "balance_units": balance,
            "balance_coins": balance as f64 / COIN_UNIT as f64,
        })),
    )
}

// ── GET /coin/info/:ticker ────────────────────────────────────────────────────

pub async fn info_handler(
    State(state): State<AppState>,
    Path(ticker): Path<String>,
) -> impl IntoResponse {
    let ticker = ticker.trim().to_uppercase();
    let rec = match state.creator_coins.get(&ticker) {
        Some(r) => r.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("coin ${} not found", ticker) }))),
    };
    let pool = match state.coin_pools.get(&ticker) {
        Some(p) => p.clone(),
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "pool missing" }))),
    };

    let price_bb = pool.reserve_bb as f64 / LAMPORTS_PER_BB as f64
        / pool.reserve_coin as f64 * COIN_UNIT as f64;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ticker": rec.ticker,
            "name": rec.name,
            "description": rec.description,
            "creator": rec.creator_wallet,
            "launched_at": rec.launched_at,
            "total_supply": rec.total_supply,
            "price_bb_per_coin": price_bb,
            "price_usd_per_coin": price_bb / 10.0,
            "market_cap_bb": price_bb * (rec.total_supply as f64 / COIN_UNIT as f64),
            "pool": {
                "reserve_bb":    pool.reserve_bb as f64 / LAMPORTS_PER_BB as f64,
                "reserve_coins": pool.reserve_coin,
                "volume_bb":     pool.volume_bb as f64 / LAMPORTS_PER_BB as f64,
                "tx_count":      pool.tx_count,
                "total_fees_bb": pool.total_fees_bb as f64 / LAMPORTS_PER_BB as f64,
            },
            "exchange_listing": {
                "note": "Bridge to external chain for CEX/DEX listing.",
                "status": "not_yet_listed",
                "bridge_endpoint": format!("/coin/bridge/{}/request", rec.ticker),
            }
        })),
    )
}

// ── GET /coin/list ────────────────────────────────────────────────────────────

pub async fn list_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut coins: Vec<serde_json::Value> = state
        .creator_coins
        .iter()
        .map(|entry| {
            let rec = entry.value();
            let price_bb = state.coin_pools.get(&rec.ticker).map(|p| {
                p.reserve_bb as f64 / LAMPORTS_PER_BB as f64
                    / p.reserve_coin as f64 * COIN_UNIT as f64
            }).unwrap_or(0.0);
            let vol_bb = state.coin_pools.get(&rec.ticker).map(|p| {
                p.volume_bb as f64 / LAMPORTS_PER_BB as f64
            }).unwrap_or(0.0);
            let tx_count = state.coin_pools.get(&rec.ticker).map(|p| p.tx_count).unwrap_or(0);
            serde_json::json!({
                "ticker": rec.ticker,
                "name": rec.name,
                "creator": rec.creator_wallet,
                "launched_at": rec.launched_at,
                "price_bb_per_coin": price_bb,
                "price_usd_per_coin": price_bb / 10.0,
                "volume_bb": vol_bb,
                "tx_count": tx_count,
            })
        })
        .collect();

    // Sort by volume descending
    coins.sort_by(|a, b| {
        let va = a["volume_bb"].as_f64().unwrap_or(0.0);
        let vb = b["volume_bb"].as_f64().unwrap_or(0.0);
        vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
    });

    Json(serde_json::json!({
        "total": coins.len(),
        "coins": coins,
    }))
}
