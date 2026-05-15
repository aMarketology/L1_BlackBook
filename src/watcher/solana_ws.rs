// ============================================================================
// SOLANA WebSocket LOG SUBSCRIBER
// ============================================================================
//
// Event-driven replacement for the 30-second `getSignaturesForAddress` poll.
//
// Connects to a Solana WebSocket endpoint and subscribes to `logsSubscribe`
// with `{ "mentions": [custody_address] }`.  Every confirmed transaction that
// touches the custody wallet triggers a push notification containing the
// transaction signature.  The signature is immediately routed through the same
// `dispatch_signature` pipeline as the polling path, so all existing deposit
// logic (Tier 1/2/2.5/3) continues to work unchanged.
//
// Recovery:  on any disconnect or error, the task sleeps with exponential
// back-off (2 s → 4 s → … → 60 s cap) and reconnects automatically.
//
// When this subscriber is running, `CustodyWatcher::start()` downgrades the
// polling loop to a 5-minute catch-all (configurable via
// `WATCHER_FALLBACK_POLL_SECS`) instead of the default 30 seconds.
//
// Env vars:
//   SOLANA_WS_URL            — wss:// endpoint.  Examples:
//                              wss://api.mainnet-beta.solana.com
//                              wss://mainnet.helius-rpc.com/?api-key=<KEY>
//                              wss://solana-mainnet.g.alchemy.com/v2/<KEY>
// ============================================================================

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};

use super::CustodyWatcher;

// ── Solana logsNotification wire types ───────────────────────────────────────

#[derive(Deserialize)]
struct WsEnvelope {
    method: Option<String>,
    params: Option<LogsParams>,
}

#[derive(Deserialize)]
struct LogsParams {
    result: Option<LogsResult>,
}

#[derive(Deserialize)]
struct LogsResult {
    value: Option<LogsValue>,
}

#[derive(Deserialize)]
struct LogsValue {
    signature: String,
    err: Option<serde_json::Value>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Spawn a background task that maintains a persistent WebSocket subscription
/// to Solana `logsSubscribe` for the custody wallet address.
///
/// Automatically reconnects with exponential back-off on failure.
pub fn start_solana_ws(watcher: Arc<CustodyWatcher>, ws_url: String) {
    tokio::spawn(async move {
        info!(
            "🔌 Solana WS subscriber starting → {}",
            truncate(&ws_url, 72)
        );
        let mut backoff = Duration::from_secs(2);
        loop {
            match run_once(&watcher, &ws_url).await {
                Ok(()) => {
                    // Server closed cleanly — reconnect quickly.
                    backoff = Duration::from_secs(2);
                }
                Err(e) => {
                    warn!(
                        "⚠️  Solana WS error: {} — reconnecting in {}s",
                        e,
                        backoff.as_secs()
                    );
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
}

// ── Internal: single connection lifecycle ────────────────────────────────────

async fn run_once(watcher: &Arc<CustodyWatcher>, ws_url: &str) -> Result<(), String> {
    let (ws_stream, _) = connect_async(ws_url)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;

    info!("🔌 Solana WS connected → {}", truncate(ws_url, 72));

    let (mut write, mut read) = ws_stream.split();

    // Subscribe to all transactions that mention the custody wallet.
    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "logsSubscribe",
        "params": [
            { "mentions": [&watcher.custody_address] },
            { "commitment": "confirmed" }
        ]
    })
    .to_string();

    write
        .send(Message::Text(subscribe_msg))
        .await
        .map_err(|e| format!("send subscribe: {}", e))?;

    // Send a ping every 30 s to keep the connection alive through NAT/proxy
    // timeouts without waiting for a real transaction.
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.tick().await; // discard the immediate first tick

    loop {
        tokio::select! {
            msg_opt = read.next() => {
                match msg_opt {
                    Some(Ok(Message::Text(text))) => {
                        handle_text(watcher, &text).await;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // Reply to server-initiated pings.
                        let _ = write.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) => {
                        return Err("server closed the WebSocket".to_string());
                    }
                    Some(Err(e)) => {
                        return Err(format!("read error: {}", e));
                    }
                    None => {
                        return Err("stream ended unexpectedly".to_string());
                    }
                    _ => {} // Pong / binary — ignore
                }
            }
            _ = ping_interval.tick() => {
                if write.send(Message::Ping(vec![])).await.is_err() {
                    return Err("keepalive ping failed".to_string());
                }
            }
        }
    }
}

async fn handle_text(watcher: &Arc<CustodyWatcher>, text: &str) {
    let env: WsEnvelope = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return, // subscription confirmations etc. — ignore
    };
    if env.method.as_deref() != Some("logsNotification") {
        return;
    }
    let value = match env.params.and_then(|p| p.result).and_then(|r| r.value) {
        Some(v) => v,
        None => return,
    };
    // Skip failed transactions (on-chain error, not a successful deposit).
    if value.err.is_some() {
        return;
    }
    let sig = &value.signature;
    info!(
        "📡 Solana WS event → sig {}",
        truncate(sig, 16)
    );
    // `memo` is None because logsNotification does not carry the Solana memo
    // string — only `getSignaturesForAddress` includes it.  The fallback poll
    // will catch any memo-attributed deposits the WS path cannot resolve.
    watcher.dispatch_signature(sig, None).await;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
