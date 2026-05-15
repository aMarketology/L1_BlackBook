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
