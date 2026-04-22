use axum::{
    extract::{State, Json},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use solana_sdk::pubkey::Pubkey;

use crate::AppState;
use crate::storage::MAXX_TOKEN_MARKET;
use crate::svm::{
    SplTokenEngine,
    usdc_mint_bytes, USDC_UNIT,
    maxx_mint_bytes, maxx_vault_bytes, MAXX_UNIT,
};

const SLOPE: f64 = 0.00000005;
pub const MAXX_TICKER: &str = "$XX";
pub const MICRO_USDT: u128 = 1_000_000;
pub const PICO_MAXX: u128 = 1_000_000_000_000;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MaxxTokenState {
    pub ticker: String,
    pub total_supply: u128,
    pub vault_reserve: u128,
    pub spot_price: f64,
    pub last_update_height: u64,
    pub reserve_currency: String,
}

impl Default for MaxxTokenState {
    fn default() -> Self {
        Self {
            ticker: MAXX_TICKER.to_string(),
            total_supply: 0,
            vault_reserve: 0,
            spot_price: 0.0,
            last_update_height: 0,
            reserve_currency: "wUSDT".to_string(),
        }
    }
}

pub fn calculate_mint(current_supply: u128, deposit_amount: u128, a: f64) -> u128 {
    let s_old = (current_supply as f64) / (PICO_MAXX as f64);
    let delta_r = (deposit_amount as f64) / (MICRO_USDT as f64);
    let s_new = ((2.0 * delta_r / a) + s_old.powi(2)).sqrt();
    let minted_whole = s_new - s_old;
    (minted_whole * (PICO_MAXX as f64)) as u128
}

pub fn calculate_burn(current_supply: u128, burn_amount: u128, a: f64) -> u128 {
    let s_old = (current_supply as f64) / (PICO_MAXX as f64);
    let s_new = (current_supply.saturating_sub(burn_amount) as f64) / (PICO_MAXX as f64);
    let delta_r = (a / 2.0) * (s_old.powi(2) - s_new.powi(2));
    (delta_r * (MICRO_USDT as f64)) as u128
}

fn calculate_spot_price(supply_pico: u128, a: f64) -> f64 {
    let s_whole = (supply_pico as f64) / (PICO_MAXX as f64);
    s_whole * a
}

#[derive(Deserialize)]
pub struct BuyMaxxRequest {
    pub from: String,
    /// Amount of wUSDT to spend, in microUSDT (6 decimals).
    pub amount: u128,
    /// Optional slippage guard — minimum picoMAXX expected out.
    #[serde(default)]
    pub min_out: Option<u128>,
}

#[derive(Deserialize)]
pub struct SellMaxxRequest {
    pub from: String,
    /// Amount of MAXX to burn, in picoMAXX (12 decimals).
    pub amount: u128,
    /// Optional slippage guard — minimum microUSDT expected back.
    #[serde(default)]
    pub min_out: Option<u128>,
}

#[derive(Serialize)]
pub struct MaxxMarketResponse {
    pub message: String,
    pub state: MaxxTokenState,
    /// Amount of the output asset received (picoMAXX on buy, microUSDT on sell).
    pub out_amount: u128,
    /// User's new $XX balance after the trade (raw picoMAXX).
    pub user_maxx_balance: u64,
    /// User's new wUSDT balance after the trade (raw microUSDT).
    pub user_wusdt_balance: u64,
}

fn parse_pubkey(s: &str) -> Result<Pubkey, &'static str> {
    let v = bs58::decode(s).into_vec().map_err(|_| "Invalid base58 address")?;
    if v.len() != 32 { return Err("Address must be 32 bytes"); }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Ok(Pubkey::new_from_array(k))
}

pub fn get_maxx_state(db: &redb::Database) -> Option<MaxxTokenState> {
    use redb::ReadableTable;
    let read_txn = db.begin_read().ok()?;
    let table = read_txn.open_table(MAXX_TOKEN_MARKET).ok()?;
    let val = table.get(MAXX_TICKER).ok()??;
    serde_json::from_slice(val.value()).ok()
}

fn write_manifest_toml(state: &MaxxTokenState) {
    let total_supply_f64 = state.total_supply as f64 / PICO_MAXX as f64;
    let vault_reserve_f64 = state.vault_reserve as f64 / MICRO_USDT as f64;
    let toml_string = format!(
        "[MAXX_TOKEN_MARKET]\nticker = \"{}\"\nspot_price = {:.4}\ntotal_supply = {:.2}\nvault_reserve = {:.2}\nreserve_currency = \"{}\"\nlast_update_height = {}\n",
        state.ticker,
        state.spot_price,
        total_supply_f64,
        vault_reserve_f64,
        state.reserve_currency,
        state.last_update_height
    );
    if let Err(e) = std::fs::write("MAXX_TOKEN_MARKET.toml", toml_string) {
        tracing::error!("Failed to write MAXX_TOKEN_MARKET.toml: {:?}", e);
    }
}

pub fn set_maxx_state(db: &redb::Database, state_val: &MaxxTokenState) -> Result<(), redb::Error> {
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(MAXX_TOKEN_MARKET)?;
        let bytes = serde_json::to_vec(state_val).unwrap();
        table.insert(MAXX_TICKER, bytes.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

pub async fn buy_maxx_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyMaxxRequest>,
) -> impl IntoResponse {
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, "Amount must be > 0").into_response();
    }
    let user_pk = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let amount_u64 = match u64::try_from(req.amount) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Amount overflow (microUSDT must fit in u64)").into_response(),
    };

    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let maxx_mint = maxx_mint_bytes();
    let vault_pk = Pubkey::new_from_array(maxx_vault_bytes());

    // 1. Compute MAXX out from current SVM supply (source of truth)
    let current_supply_pico = SplTokenEngine::get_mint_supply(svm, &maxx_mint).unwrap_or(0) as u128;
    let maxx_minted_pico = calculate_mint(current_supply_pico, req.amount, SLOPE);
    if maxx_minted_pico == 0 {
        return (StatusCode::BAD_REQUEST, "Amount too small to mint any MAXX").into_response();
    }
    if let Some(min_out) = req.min_out {
        if maxx_minted_pico < min_out {
            return (StatusCode::BAD_REQUEST, format!("Slippage: would mint {} < min_out {}", maxx_minted_pico, min_out)).into_response();
        }
    }
    let maxx_minted_u64 = match u64::try_from(maxx_minted_pico) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "MAXX mint amount overflow").into_response(),
    };

    // 2. Transfer wUSDT user → vault
    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &user_pk, &vault_pk, amount_u64) {
        return (StatusCode::BAD_REQUEST, format!("wUSDT transfer failed: {:?}", e)).into_response();
    }

    // 3. Mint $XX to user
    if let Err(e) = SplTokenEngine::mint_to(svm, &maxx_mint, &user_pk, maxx_minted_u64) {
        // Best-effort rollback of the wUSDT transfer
        let _ = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &vault_pk, &user_pk, amount_u64);
        error!("MAXX mint failed: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "MAXX mint failed").into_response();
    }
    let _ = svm.flush_block();

    // 4. Update market projection in ReDB + manifest TOML
    let new_supply_pico = SplTokenEngine::get_mint_supply(svm, &maxx_mint).unwrap_or(0) as u128;
    let vault_usdt = SplTokenEngine::get_token_balance(svm, &usdt_mint, &vault_pk) as u128;
    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let new_state = MaxxTokenState {
        ticker: MAXX_TICKER.to_string(),
        total_supply: new_supply_pico,
        vault_reserve: vault_usdt,
        spot_price: calculate_spot_price(new_supply_pico, SLOPE),
        last_update_height: height,
        reserve_currency: "wUSDT".to_string(),
    };
    if let Err(e) = set_maxx_state(&state.blockchain.db, &new_state) {
        error!("Failed to save MAXX market state: {:?}", e);
    }
    write_manifest_toml(&new_state);

    let user_maxx_balance = SplTokenEngine::get_token_balance(svm, &maxx_mint, &user_pk);
    let user_wusdt_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &user_pk);

    info!(
        "🟣 BUY $XX: {} bought {} picoMAXX for {} microUSDT (spot ${:.6})",
        req.from, maxx_minted_pico, req.amount, new_state.spot_price
    );

    (StatusCode::OK, Json(MaxxMarketResponse {
        message: format!(
            "Bought {:.6} MAXX for {:.6} wUSDT",
            maxx_minted_pico as f64 / MAXX_UNIT as f64,
            req.amount as f64 / USDC_UNIT as f64
        ),
        state: new_state,
        out_amount: maxx_minted_pico,
        user_maxx_balance,
        user_wusdt_balance,
    })).into_response()
}

pub async fn sell_maxx_handler(
    State(state): State<AppState>,
    Json(req): Json<SellMaxxRequest>,
) -> impl IntoResponse {
    if req.amount == 0 {
        return (StatusCode::BAD_REQUEST, "Amount must be > 0").into_response();
    }
    let user_pk = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let burn_amount_u64 = match u64::try_from(req.amount) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Amount overflow (picoMAXX must fit in u64)").into_response(),
    };

    let svm = &state.blockchain.svm_accounts;
    let usdt_mint = usdc_mint_bytes();
    let maxx_mint = maxx_mint_bytes();
    let vault_pk = Pubkey::new_from_array(maxx_vault_bytes());

    // 1. Compute wUSDT return based on current SVM supply
    let current_supply_pico = SplTokenEngine::get_mint_supply(svm, &maxx_mint).unwrap_or(0) as u128;
    if req.amount > current_supply_pico {
        return (StatusCode::BAD_REQUEST, "Insufficient MAXX supply").into_response();
    }
    let usdt_return = calculate_burn(current_supply_pico, req.amount, SLOPE);
    if usdt_return == 0 {
        return (StatusCode::BAD_REQUEST, "Amount too small to redeem any wUSDT").into_response();
    }
    if let Some(min_out) = req.min_out {
        if usdt_return < min_out {
            return (StatusCode::BAD_REQUEST, format!("Slippage: would return {} < min_out {}", usdt_return, min_out)).into_response();
        }
    }
    let usdt_return_u64 = match u64::try_from(usdt_return) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "wUSDT return overflow").into_response(),
    };

    // 2. Sanity check vault has enough wUSDT
    let vault_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &vault_pk);
    if vault_balance < usdt_return_u64 {
        return (StatusCode::SERVICE_UNAVAILABLE, format!(
            "Vault temporarily under-collateralized: need {} have {}", usdt_return_u64, vault_balance
        )).into_response();
    }

    // 3. Burn $XX from user
    if let Err(e) = SplTokenEngine::burn(svm, &maxx_mint, &user_pk, burn_amount_u64) {
        return (StatusCode::BAD_REQUEST, format!("MAXX burn failed: {:?}", e)).into_response();
    }

    // 4. Transfer wUSDT vault → user
    if let Err(e) = SplTokenEngine::transfer_tokens(svm, &usdt_mint, &vault_pk, &user_pk, usdt_return_u64) {
        // Best-effort rollback of the burn (re-mint to user)
        let _ = SplTokenEngine::mint_to(svm, &maxx_mint, &user_pk, burn_amount_u64);
        error!("Vault → user wUSDT transfer failed: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "wUSDT transfer failed").into_response();
    }
    let _ = svm.flush_block();

    // 5. Update market projection in ReDB + manifest TOML
    let new_supply_pico = SplTokenEngine::get_mint_supply(svm, &maxx_mint).unwrap_or(0) as u128;
    let vault_usdt = SplTokenEngine::get_token_balance(svm, &usdt_mint, &vault_pk) as u128;
    let height = state.current_slot.load(std::sync::atomic::Ordering::Relaxed);
    let new_state = MaxxTokenState {
        ticker: MAXX_TICKER.to_string(),
        total_supply: new_supply_pico,
        vault_reserve: vault_usdt,
        spot_price: calculate_spot_price(new_supply_pico, SLOPE),
        last_update_height: height,
        reserve_currency: "wUSDT".to_string(),
    };
    if let Err(e) = set_maxx_state(&state.blockchain.db, &new_state) {
        error!("Failed to save MAXX market state: {:?}", e);
    }
    write_manifest_toml(&new_state);

    let user_maxx_balance = SplTokenEngine::get_token_balance(svm, &maxx_mint, &user_pk);
    let user_wusdt_balance = SplTokenEngine::get_token_balance(svm, &usdt_mint, &user_pk);

    info!(
        "🟣 SELL $XX: {} burned {} picoMAXX for {} microUSDT (spot ${:.6})",
        req.from, req.amount, usdt_return, new_state.spot_price
    );

    (StatusCode::OK, Json(MaxxMarketResponse {
        message: format!(
            "Sold {:.6} MAXX for {:.6} wUSDT",
            req.amount as f64 / MAXX_UNIT as f64,
            usdt_return as f64 / USDC_UNIT as f64
        ),
        state: new_state,
        out_amount: usdt_return,
        user_maxx_balance,
        user_wusdt_balance,
    })).into_response()
}

pub async fn maxx_market_manifest_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let db = &state.blockchain.db;
    let current_state = get_maxx_state(db).unwrap_or_default();
    (StatusCode::OK, Json(current_state)).into_response()
}