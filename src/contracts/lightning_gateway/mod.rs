// ============================================================================
// LIGHTNING GATEWAY — BTC → BB via BTCPayServer
// ============================================================================
//
// Flow:
//   1. User (wallet UI) calls POST /lightning/invoice with their BB wallet
//      address + USD amount they want to convert.
//   2. We call the BTCPayServer Greenfield API to create a Lightning invoice
//      priced in USD. BTCPayServer returns a BOLT11 payment request.
//   3. We persist a LightningInvoice record (status: "pending") and return
//      the BOLT11 string to the user. They pay it from any LN wallet.
//   4. When the invoice settles, BTCPayServer POSTs to /lightning/webhook
//      with HMAC-SHA256 signature. We verify, then mint BB at the locked
//      USD price (10 BB per USD — $0.10/BB) and mark the invoice "settled".
//   5. The invoice_id is recorded in the bridge-tx table as `ln:{invoice_id}`
//      — same double-mint protection as Solana / BSC deposits.
//
// Config (env vars):
//   BTCPAY_URL              — e.g. https://btcpay.blackbook.id
//   BTCPAY_API_KEY          — Greenfield API key (read+create invoice scope)
//   BTCPAY_STORE_ID         — your BTCPayServer store ID
//   BTCPAY_WEBHOOK_SECRET   — HMAC secret configured on the webhook
//
// Security:
//   - Webhook signature verified via HMAC-SHA256 (constant-time compare)
//   - Replay protected: invoice_id may only settle once (bridge-tx table)
//   - User signature on /lightning/invoice proves ownership of BB wallet
// ============================================================================

use axum::{extract::{State, Path}, response::IntoResponse, http::{StatusCode, HeaderMap}, Json};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::{info, warn, error};

use crate::AppState;

// Exchange rate is encoded in `micro_stable_to_bb_lamports` (see svm/types.rs).

/// Maximum age for a /lightning/invoice request signature.
const REQUEST_MAX_AGE_SECS: u64 = 60;

// ── In-memory record ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningInvoice {
    pub invoice_id: String,
    pub wallet_address: String,
    /// USD amount in cents (1 USD = 100 cents). e.g. $10.00 = 1000
    pub usd_cents: u64,
    /// BB to mint, in lamports (5-decimal units)
    pub bb_lamports: u64,
    pub bolt11: String,
    pub checkout_url: String,
    pub status: String, // "pending" | "settled" | "expired"
    pub created_at: u64,
    pub settled_at: Option<u64>,
}

// ── Request / Response bodies ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateInvoiceBody {
    /// BB wallet address (base58) that will receive the minted BB
    pub wallet_address: String,
    /// USD amount in cents (1 USD = 100 cents). e.g. $10.00 = 1000
    pub usd_cents: u64,
    /// Ed25519 public key (hex, 32 bytes)
    pub public_key: String,
    /// Ed25519 signature over "LN_INVOICE:{wallet}:{usd_cents}:{ts}:{nonce}"
    pub signature: String,
    pub timestamp: u64,
    pub nonce: String,
}

// BTCPayServer Greenfield API — minimal request body
#[derive(Serialize)]
struct BtcPayCreateInvoice<'a> {
    amount: String,
    currency: &'a str,
    metadata: BtcPayMetadata<'a>,
    checkout: BtcPayCheckout<'a>,
}

#[derive(Serialize)]
struct BtcPayMetadata<'a> {
    #[serde(rename = "buyerName")]
    buyer_name: &'a str,
    #[serde(rename = "orderId")]
    order_id: String,
}

#[derive(Serialize)]
struct BtcPayCheckout<'a> {
    #[serde(rename = "speedPolicy")]
    speed_policy: &'a str, // "HighSpeed" — accept on first conf
    #[serde(rename = "paymentMethods")]
    payment_methods: Vec<&'a str>, // ["BTC-LightningNetwork"]
    #[serde(rename = "redirectURL", skip_serializing_if = "Option::is_none")]
    redirect_url: Option<&'a str>,
}

// BTCPayServer Greenfield API — relevant response fields
#[derive(Deserialize)]
struct BtcPayInvoiceResponse {
    id: String,
    #[serde(rename = "checkoutLink")]
    checkout_link: String,
}

// Greenfield payment-method response (we hit it after invoice creation to get BOLT11)
#[derive(Deserialize)]
struct BtcPayPaymentMethod {
    destination: Option<String>,
    #[serde(rename = "paymentMethod")]
    payment_method: Option<String>,
}

// ── POST /lightning/invoice ───────────────────────────────────────────────

pub async fn create_invoice_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateInvoiceBody>,
) -> impl IntoResponse {
    // ── Config check ──
    if state.btcpay_config.url.is_empty()
        || state.btcpay_config.api_key.is_empty()
        || state.btcpay_config.store_id.is_empty()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Lightning gateway not configured"
        }))).into_response();
    }

    // ── Validation ──
    if req.usd_cents < 100 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Minimum invoice is $1.00 (100 cents)"
        }))).into_response();
    }
    if req.usd_cents > 1_000_000 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Maximum single invoice is $10,000 (1_000_000 cents)"
        }))).into_response();
    }
    if !crate::is_valid_bb_address(&req.wallet_address) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Invalid BB wallet address"
        }))).into_response();
    }

    // ── Replay protection ──
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(req.timestamp) > REQUEST_MAX_AGE_SECS {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Request too old (>60s)"
        }))).into_response();
    }
    let nonce_key = format!("ln_invoice:{}:{}", req.wallet_address, req.nonce);
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({
                "error": "Nonce already used"
            }))).into_response();
        }
        dashmap::mapref::entry::Entry::Vacant(v) => { v.insert(now); }
    }

    // ── Signature verification ──
    let message = format!(
        "LN_INVOICE:{}:{}:{}:{}",
        req.wallet_address, req.usd_cents, req.timestamp, req.nonce
    );
    if let Err(e) = verify_ed25519(&req.public_key, &req.signature, &message, &req.wallet_address) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": e }))).into_response();
    }

    // ── Call BTCPayServer Greenfield API ──
    let order_id = uuid::Uuid::new_v4().to_string();
    let create_url = format!(
        "{}/api/v1/stores/{}/invoices",
        state.btcpay_config.url.trim_end_matches('/'),
        state.btcpay_config.store_id
    );
    let body = BtcPayCreateInvoice {
        amount: format!("{:.2}", req.usd_cents as f64 / 100.0),
        currency: "USD",
        metadata: BtcPayMetadata {
            buyer_name: &req.wallet_address,
            order_id: order_id.clone(),
        },
        checkout: BtcPayCheckout {
            speed_policy: "HighSpeed",
            payment_methods: vec!["BTC-LightningNetwork"],
            redirect_url: None,
        },
    };

    let http = reqwest::Client::new();
    let resp = match http.post(&create_url)
        .header("Authorization", format!("token {}", state.btcpay_config.api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("BTCPayServer unreachable: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "Lightning gateway temporarily unavailable"
            }))).into_response();
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        warn!("BTCPayServer create-invoice failed: {} {}", status, text);
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": "Failed to create Lightning invoice",
            "btcpay_status": status.as_u16()
        }))).into_response();
    }

    let invoice_resp: BtcPayInvoiceResponse = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            error!("BTCPayServer invalid response: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": "Invalid response from Lightning gateway"
            }))).into_response();
        }
    };

    // Fetch BOLT11 for the LN payment method (best-effort)
    let bolt11 = fetch_bolt11(&http, &state.btcpay_config, &invoice_resp.id)
        .await
        .unwrap_or_default();

    // usd_cents → micro-USD for the exchange rate function
    // 1 USD = 100 cents, 1 USD = 1_000_000 micro-USD, so cents * 10_000 = micro-USD
    let micro_usd = req.usd_cents * 10_000;
    let bb_lamports = crate::svm::types::micro_stable_to_bb_lamports(micro_usd);
    let record = LightningInvoice {
        invoice_id: invoice_resp.id.clone(),
        wallet_address: req.wallet_address.clone(),
        usd_cents: req.usd_cents,
        bb_lamports,
        bolt11: bolt11.clone(),
        checkout_url: invoice_resp.checkout_link.clone(),
        status: "pending".to_string(),
        created_at: now,
        settled_at: None,
    };
    state.lightning_invoices.insert(record.invoice_id.clone(), record.clone());

    info!("⚡ LN INVOICE created: {} cents → {} BB-lamports for {} (id: {})",
        req.usd_cents, bb_lamports,
        &req.wallet_address[..8.min(req.wallet_address.len())],
        &record.invoice_id[..12.min(record.invoice_id.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "invoice_id": record.invoice_id,
        "wallet_address": record.wallet_address,
        "usd_cents": record.usd_cents,
        "bb_lamports": record.bb_lamports,
        "bolt11": record.bolt11,
        "checkout_url": record.checkout_url,
        "status": record.status,
        "expires_in_secs": 900,
    }))).into_response()
}

// ── GET /lightning/status/:invoice_id ─────────────────────────────────────

pub async fn invoice_status_handler(
    State(state): State<AppState>,
    Path(invoice_id): Path<String>,
) -> impl IntoResponse {
    if let Some(rec) = state.lightning_invoices.get(&invoice_id) {
        return Json(serde_json::json!({
            "found": true,
            "invoice_id": rec.invoice_id,
            "wallet_address": rec.wallet_address,
            "usd_cents": rec.usd_cents,
            "bb_lamports": rec.bb_lamports,
            "status": rec.status,
            "created_at": rec.created_at,
            "settled_at": rec.settled_at,
        })).into_response();
    }
    let bridge_key = format!("ln:{}", invoice_id);
    if state.blockchain.is_bridge_tx_processed(&bridge_key) {
        return Json(serde_json::json!({
            "found": true,
            "invoice_id": invoice_id,
            "status": "settled",
            "note": "Settled before this node session — record not in memory."
        })).into_response();
    }
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "found": false,
        "error": "Unknown invoice_id"
    }))).into_response()
}

// ── POST /lightning/webhook ───────────────────────────────────────────────

#[derive(Deserialize)]
struct BtcPayWebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "invoiceId")]
    invoice_id: String,
}

pub async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // ── HMAC verification ──
    let secret = state.btcpay_config.webhook_secret.as_bytes();
    if secret.is_empty() {
        warn!("LN webhook hit but BTCPAY_WEBHOOK_SECRET unset — rejecting");
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Webhook not configured"
        }))).into_response();
    }
    let sig_header = headers.get("BTCPay-Sig")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let expected_hex = match sig_header.strip_prefix("sha256=") {
        Some(h) => h,
        None => {
            warn!("LN webhook missing/malformed BTCPay-Sig header");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "error": "Missing signature"
            }))).into_response();
        }
    };
    let expected = match hex::decode(expected_hex) {
        Ok(v) => v,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Invalid signature encoding"
        }))).into_response(),
    };

    // BTCPayServer's HMAC-SHA256 over the raw body
    let computed = hmac_sha256(secret, &body);
    if !constant_time_eq(&computed, &expected) {
        warn!("LN webhook HMAC mismatch — possible spoofing attempt");
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "Bad signature"
        }))).into_response();
    }

    // ── Parse + handle ──
    let payload: BtcPayWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("LN webhook malformed body: {}", e);
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "Bad payload"
            }))).into_response();
        }
    };

    // Only act on settled invoices. BTCPayServer event names:
    //   "InvoiceSettled" — fully paid + confirmed (LN: instant)
    //   "InvoiceProcessing", "InvoiceCreated", "InvoiceExpired" → ignore
    if payload.event_type != "InvoiceSettled" {
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "ignored_event": payload.event_type
        }))).into_response();
    }

    let bridge_key = format!("ln:{}", payload.invoice_id);

    // ── Double-mint protection (atomic via bridge-tx table) ──
    if state.blockchain.is_bridge_tx_processed(&bridge_key) {
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "note": "Already minted"
        }))).into_response();
    }

    let mut record = match state.lightning_invoices.get(&payload.invoice_id) {
        Some(r) => r.clone(),
        None => {
            warn!("LN webhook for unknown invoice: {}", payload.invoice_id);
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": "Unknown invoice_id"
            }))).into_response();
        }
    };

    if record.status == "settled" {
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    }

    // ── Atomic reserve → mint → commit ──
    if let Err(e) = state.blockchain.reserve_bridge_tx(&bridge_key) {
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "note": format!("Already processing or settled: {}", e)
        }))).into_response();
    }

    let mint_tx_id = format!("ln_mint_{}", payload.invoice_id);
    let mint_result = state.blockchain.credit_lamports(&record.wallet_address, record.bb_lamports);
    match mint_result {
        Ok(_) => {
            if let Err(e) = state.blockchain.commit_bridge_tx(&bridge_key, &mint_tx_id) {
                error!("LN commit_bridge_tx failed (non-fatal, slot held): {}", e);
            }
        }
        Err(e) => {
            state.blockchain.cancel_bridge_tx(&bridge_key);
            error!("LN BB credit failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Mint failed: {}", e)
            }))).into_response();
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    record.status = "settled".to_string();
    record.settled_at = Some(now);
    state.lightning_invoices.insert(payload.invoice_id.clone(), record.clone());

    info!("⚡ LN SETTLED: minted {} BB-lamports to {} (invoice {})",
        record.bb_lamports,
        &record.wallet_address[..8.min(record.wallet_address.len())],
        &payload.invoice_id[..12.min(payload.invoice_id.len())]);

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "minted_bb_lamports": record.bb_lamports,
        "wallet": record.wallet_address,
    }))).into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────

async fn fetch_bolt11(
    http: &reqwest::Client,
    cfg: &BtcPayConfig,
    invoice_id: &str,
) -> Option<String> {
    let url = format!(
        "{}/api/v1/stores/{}/invoices/{}/payment-methods",
        cfg.url.trim_end_matches('/'), cfg.store_id, invoice_id
    );
    let resp = http.get(&url)
        .header("Authorization", format!("token {}", cfg.api_key))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() { return None; }
    let methods: Vec<BtcPayPaymentMethod> = resp.json().await.ok()?;
    methods.into_iter()
        .find(|m| m.payment_method.as_deref() == Some("BTC-LightningNetwork"))
        .and_then(|m| m.destination)
}

fn verify_ed25519(
    pubkey_hex: &str,
    sig_hex: &str,
    message: &str,
    expected_address: &str,
) -> Result<(), String> {
    let pk_bytes = hex::decode(pubkey_hex).map_err(|_| "Invalid public_key hex".to_string())?;
    if pk_bytes.len() != 32 { return Err("public_key must be 32 bytes".into()); }
    let sig_bytes = hex::decode(sig_hex).map_err(|_| "Invalid signature hex".to_string())?;
    if sig_bytes.len() != 64 { return Err("signature must be 64 bytes".into()); }
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| "pubkey len".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| "Bad public key".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| "sig len".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message.as_bytes(), &sig).map_err(|_| "Signature verification failed".to_string())?;
    let derived = bs58::encode(vk.to_bytes()).into_string();
    if derived != expected_address {
        return Err(format!("public_key does not match wallet_address (derived={})", derived));
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // RFC 2104 HMAC — minimal implementation (sha2 only, no extra deps).
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize().to_vec();
        let mut padded = vec![0u8; BLOCK];
        padded[..d.len()].copy_from_slice(&d);
        padded
    } else {
        let mut padded = vec![0u8; BLOCK];
        padded[..key.len()].copy_from_slice(key);
        padded
    };
    let mut o_pad = vec![0x5cu8; BLOCK];
    let mut i_pad = vec![0x36u8; BLOCK];
    for i in 0..BLOCK {
        o_pad[i] ^= k[i];
        i_pad[i] ^= k[i];
    }
    k.fill(0);
    let mut inner = Sha256::new();
    inner.update(&i_pad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&o_pad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

// ── BTCPayServer config (lives on AppState) ───────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct BtcPayConfig {
    pub url: String,
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

impl BtcPayConfig {
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("BTCPAY_URL").unwrap_or_default(),
            api_key: std::env::var("BTCPAY_API_KEY").unwrap_or_default(),
            store_id: std::env::var("BTCPAY_STORE_ID").unwrap_or_default(),
            webhook_secret: std::env::var("BTCPAY_WEBHOOK_SECRET").unwrap_or_default(),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.url.is_empty()
            && !self.api_key.is_empty()
            && !self.store_id.is_empty()
            && !self.webhook_secret.is_empty()
    }
}
