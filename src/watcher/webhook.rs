// ============================================================================
// WEBHOOK RECEIVERS — Helius (Solana) + Alchemy (BSC)
// ============================================================================
//
// These Axum handlers receive proactive HTTP POST payloads pushed by Helius
// and Alchemy the instant a relevant transaction is confirmed, completely
// eliminating polling latency for operators who prefer managed webhooks over
// self-hosted WebSocket connections.
//
// Routes (registered in main.rs):
//   POST /deposit/webhook/helius   — Helius Enhanced Transaction Webhook
//   POST /deposit/webhook/alchemy  — Alchemy Address Activity Webhook (BSC/EVM)
//
// Security model:
//   • Helius: caller must set `Authorization: Bearer <HELIUS_WEBHOOK_SECRET>`.
//     The secret is configured both here (env var) and in the Helius dashboard.
//   • Alchemy: HMAC-SHA256(signing_key, raw_body) is compared against the
//     `X-Alchemy-Signature` header using constant-time comparison.
//   Both verifications use constant-time equality to prevent timing attacks.
//
// Env vars:
//   HELIUS_WEBHOOK_SECRET   — Shared secret configured in Helius dashboard
//   ALCHEMY_WEBHOOK_SECRET  — Signing key from Alchemy webhook settings
// ============================================================================

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};

use crate::AppState;

// ── Helius webhook ────────────────────────────────────────────────────────────

/// Helius Enhanced Transaction Webhook — one array element per transaction.
/// We only need the signature; all other fields are ignored (verification is
/// done on-chain via the existing `verify_transaction` flow).
#[derive(serde::Deserialize)]
struct HeliusTx {
    signature: Option<String>,
}

/// `POST /deposit/webhook/helius`
///
/// Authenticated via `Authorization: Bearer <HELIUS_WEBHOOK_SECRET>`.
/// Extracts all transaction signatures from the payload and routes each one
/// through `CustodyWatcher::dispatch_signature`.
pub async fn helius_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ── Authentication ────────────────────────────────────────────────────────
    let expected = match std::env::var("HELIUS_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("⚠️  Helius webhook: HELIUS_WEBHOOK_SECRET not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "webhook not configured"})),
            )
                .into_response();
        }
    };

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim_start_matches("Bearer ")
        .trim();

    if !constant_time_eq(provided, &expected) {
        warn!("⚠️  Helius webhook: invalid authorization token");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    // ── Parse payload ─────────────────────────────────────────────────────────
    let txs: Vec<HeliusTx> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("⚠️  Helius webhook: JSON parse error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid JSON"})),
            )
                .into_response();
        }
    };

    let watcher = match &state.custody_watcher {
        Some(w) => w.clone(),
        None => {
            // Custody watcher not configured — ack but do nothing.
            return (
                StatusCode::OK,
                Json(serde_json::json!({"ok": true, "dispatched": 0})),
            )
                .into_response();
        }
    };

    let mut dispatched = 0u32;
    for tx in &txs {
        if let Some(sig) = tx.signature.as_deref().filter(|s| !s.is_empty()) {
            info!("📬 Helius webhook → sig {}", &sig[..sig.len().min(16)]);
            // memo = None: Helius payload does not include the Solana memo string.
            // The watcher handles this gracefully — Tier 1 (deposit request) and
            // Tier 2.5 (Mayan payload) still work; Tier 2 (memo) falls through to
            // the slow fallback poller.
            watcher.dispatch_signature(sig, None).await;
            dispatched += 1;
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "dispatched": dispatched})),
    )
        .into_response()
}

// ── Alchemy webhook ───────────────────────────────────────────────────────────

/// Top-level Alchemy ADDRESS_ACTIVITY webhook envelope.
#[derive(serde::Deserialize)]
struct AlchemyWebhook {
    event: Option<AlchemyEvent>,
}

#[derive(serde::Deserialize)]
struct AlchemyEvent {
    activity: Option<Vec<AlchemyActivity>>,
}

/// A single activity entry from Alchemy's address-activity webhook.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlchemyActivity {
    /// Transaction hash (BSC tx hash).
    hash: Option<String>,
}

/// `POST /deposit/webhook/alchemy`
///
/// Authenticated via HMAC-SHA256 of the raw request body, compared against
/// the `X-Alchemy-Signature` header (constant-time).
/// Extracts BSC transaction hashes and triggers `BscWatcher::verify_and_approve`
/// for any that have a matching pending deposit record.
pub async fn alchemy_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ── Authentication ────────────────────────────────────────────────────────
    let signing_key = match std::env::var("ALCHEMY_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("⚠️  Alchemy webhook: ALCHEMY_WEBHOOK_SECRET not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "webhook not configured"})),
            )
                .into_response();
        }
    };

    let provided_sig = match headers
        .get("x-alchemy-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            warn!("⚠️  Alchemy webhook: missing X-Alchemy-Signature header");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing signature"})),
            )
                .into_response();
        }
    };

    // HMAC-SHA256(signing_key, raw_body) → lowercase hex
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(signing_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "hmac init failed"})),
            )
                .into_response();
        }
    };
    mac.update(&body);
    let computed = hex::encode(mac.finalize().into_bytes());

    if !constant_time_eq(&computed, &provided_sig) {
        warn!("⚠️  Alchemy webhook: HMAC-SHA256 mismatch — possible spoofed request");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    // ── Parse payload ─────────────────────────────────────────────────────────
    let payload: AlchemyWebhook = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("⚠️  Alchemy webhook: JSON parse error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid JSON"})),
            )
                .into_response();
        }
    };

    let watcher = match &state.bsc_watcher {
        Some(w) => w.clone(),
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({"ok": true, "dispatched": 0})),
            )
                .into_response();
        }
    };

    let activity = payload.event.and_then(|e| e.activity).unwrap_or_default();
    let mut dispatched = 0u32;

    for act in &activity {
        let tx_hash = match act.hash.as_deref().filter(|h| !h.is_empty()) {
            Some(h) => h.to_lowercase(),
            None => continue,
        };
        info!(
            "📬 Alchemy webhook → BSC tx {}",
            &tx_hash[..tx_hash.len().min(18)]
        );
        // verify_and_approve returns Err("No matching deposit request") when the
        // tx_hash is not in deposit_requests — this is normal for bridge-contract
        // or non-custodial deposits and is not logged as a warning.
        match watcher.verify_and_approve(&tx_hash).await {
            Ok(bb) => {
                info!(
                    "✅ Alchemy webhook: {} → {:.5} BB",
                    &tx_hash[..18.min(tx_hash.len())],
                    bb
                );
                dispatched += 1;
            }
            Err(e) if e.contains("No matching deposit request") => {
                // Not a custodial deposit — silently ignore.
            }
            Err(e) => {
                warn!(
                    "⚠️  Alchemy webhook verify failed ({}): {}",
                    &tx_hash[..18.min(tx_hash.len())],
                    e
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "dispatched": dispatched})),
    )
        .into_response()
}

// ── Transak webhook ───────────────────────────────────────────────────────────
//
// Transak sends a JSON envelope where `webhookData` is a HS256-signed JWT.
// The JWT signing secret is the partner's API Secret (TRANSAK_API_SECRET env var).
//
// Raw body structure:
//   { "webhookData": "<hs256-jwt>", "eventID": "ORDER_COMPLETED" }
//
// JWT claims (after verify + decode) contain the full order object:
//   { "id": "...", "status": "COMPLETED", "partnerOrderId": "<bb_address>",
//     "cryptoTransactionId": "<solana_tx>", "cryptoCurrency": "USDT",
//     "network": "solana", "cryptoAmount": 10.5, ... }
//
// Register the webhook URL via Transak API (NOT the dashboard UI):
//   Staging:    POST https://api-stg.transak.com/partners/api/v2/update-webhook
//   Production: POST https://api.transak.com/partners/api/v2/update-webhook
//   Body: { "partnerAPISecret": "<your_secret>", "webhookURL": "https://layer1.blackbook.id/transak/webhook" }
// ─────────────────────────────────────────────────────────────────────────────

/// Outer Transak webhook envelope (before JWT decode).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransakEnvelope {
    /// HS256-signed JWT whose claims contain the full order object.
    webhook_data: Option<String>,
    /// e.g. "ORDER_COMPLETED"
    event_id: Option<String>,
}

/// Order claims decoded from the `webhookData` JWT.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TransakOrderClaims {
    partner_order_id:      Option<String>,
    status:                Option<String>,
    crypto_currency:       Option<String>,
    network:               Option<String>,
    crypto_amount:         Option<f64>,
    crypto_transaction_id: Option<String>,
}

/// Verify a Transak HS256 JWT and return the decoded `webhookData` claims.
///
/// JWT format: base64url(header) . base64url(payload) . base64url(sig)
/// Signature:  HMAC-SHA256( secret, "{header}.{payload}" )
fn verify_transak_jwt(
    token: &str,
    secret: &str,
) -> Result<TransakOrderClaims, &'static str> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("JWT must have 3 parts");
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // Verify signature: HMAC-SHA256(secret, "header.payload")
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "HMAC init failed")?;
    mac.update(format!("{header_b64}.{payload_b64}").as_bytes());
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(mac.finalize().into_bytes());

    if !constant_time_eq(&expected, sig_b64) {
        return Err("JWT signature mismatch");
    }

    // Decode payload
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "JWT payload base64 decode failed")?;

    // The JWT payload is a JSON object; `webhookData` inside it holds the order.
    // Transak embeds the order directly as JWT claims (not nested).
    let claims: TransakOrderClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "JWT payload JSON decode failed")?;

    Ok(claims)
}

/// `POST /transak/webhook`
///
/// Transak pushes this when an order reaches a terminal state.
/// The body contains a `webhookData` field — a HS256 JWT signed with your
/// API Secret (TRANSAK_API_SECRET env var).
///
/// On `ORDER_COMPLETED` for Solana USDT:
///   1. Verifies + decodes the JWT.
///   2. Pre-registers a Tier 1 DepositRecord (partnerOrderId → tx hash).
///   3. Dispatches to CustodyWatcher for immediate BB crediting.
pub async fn transak_webhook_handler(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // ── Check secret is configured ────────────────────────────────────────────
    let api_secret = match std::env::var("TRANSAK_API_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("⚠️  Transak webhook: TRANSAK_API_SECRET not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "TRANSAK_API_SECRET not set"})),
            )
                .into_response();
        }
    };

    // ── Parse outer envelope ──────────────────────────────────────────────────
    let envelope: TransakEnvelope = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("⚠️  Transak webhook: JSON parse error: {}", e);
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid JSON"}))).into_response();
        }
    };

    let event_id = envelope.event_id.as_deref().unwrap_or("").to_uppercase();

    // Only process terminal completed orders — ack everything else with 200.
    if event_id != "ORDER_COMPLETED" {
        return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": event_id}))).into_response();
    }

    let jwt_token = match envelope.webhook_data.as_deref().filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => {
            warn!("⚠️  Transak webhook: ORDER_COMPLETED missing webhookData JWT");
            return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": "no webhookData"}))).into_response();
        }
    };

    // ── Verify + decode JWT ───────────────────────────────────────────────────
    let order = match verify_transak_jwt(&jwt_token, &api_secret) {
        Ok(o) => o,
        Err(e) => {
            warn!("⚠️  Transak webhook: JWT verification failed: {}", e);
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e}))).into_response();
        }
    };

    // ── Only act on Solana USDT ───────────────────────────────────────────────
    let status   = order.status.as_deref().unwrap_or("").to_uppercase();
    let currency = order.crypto_currency.as_deref().unwrap_or("").to_uppercase();
    let network  = order.network.as_deref().unwrap_or("").to_lowercase();

    if status != "COMPLETED" {
        return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": status}))).into_response();
    }
    if currency != "USDT" || network != "solana" {
        return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": format!("{currency}/{network}")}))).into_response();
    }

    let bb_address = match order.partner_order_id.as_deref().filter(|s| !s.is_empty()) {
        Some(a) => a.to_string(),
        None => {
            warn!("⚠️  Transak webhook: ORDER_COMPLETED missing partnerOrderId");
            return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": "no partnerOrderId"}))).into_response();
        }
    };
    let tx_hash = match order.crypto_transaction_id.as_deref().filter(|s| !s.is_empty()) {
        Some(h) => h.to_string(),
        None => {
            // Transak fires webhook before the tx is confirmed on-chain in some states.
            return (StatusCode::OK, Json(serde_json::json!({"ok": true, "skipped": "no tx hash yet"}))).into_response();
        }
    };

    // Deposit rate: 1 USDT = 10 BB = 10 × 100_000 lamports (5-decimal system)
    let crypto_amount = order.crypto_amount.unwrap_or(0.0);
    let amount_micro  = (crypto_amount * 1_000_000.0).round() as u64;
    let bb_lamports   = amount_micro * 10;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── Pre-register Tier 1 deposit record ───────────────────────────────────
    let record = layer1::storage::DepositRecord {
        wallet_address:          bb_address.clone(),
        external_tx_hash:        tx_hash.clone(),
        asset:                   "USDT".to_string(),
        amount_micro_stablecoin: amount_micro,
        bb_lamports,
        status:                  "pending".to_string(),
        submitted_at:            now,
        approved_at:             None,
        contest_id:              None,
    };
    state.deposit_requests.insert(tx_hash.clone(), record);

    // ── Dispatch to CustodyWatcher for immediate processing ───────────────────
    if let Some(watcher) = state.custody_watcher.as_ref() {
        info!(
            "📬 Transak ORDER_COMPLETED → {} USDT → BB {} (tx {}…)",
            crypto_amount,
            &bb_address[..bb_address.len().min(12)],
            &tx_hash[..tx_hash.len().min(16)],
        );
        watcher.dispatch_signature(&tx_hash, None).await;
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok":          true,
        "credited":    bb_address,
        "tx_hash":     tx_hash,
        "bb_lamports": bb_lamports,
    })))
        .into_response()
}

// ── Constant-time string comparison ──────────────────────────────────────────

/// Compare two strings in constant time to prevent timing side-channel attacks
/// on secret tokens and HMAC digests.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
