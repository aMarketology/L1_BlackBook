// ============================================================================
// BSC (BNB CHAIN) WebSocket LOG SUBSCRIBER
// ============================================================================
//
// Event-driven replacement for the 30-second `eth_getLogs` block-range poll.
//
// Connects to a BSC-compatible WebSocket endpoint and issues an
// `eth_subscribe("logs", ...)` call targeting Transfer events on the USDC and
// USDT BEP-20 contracts whose `to` topic matches the custody wallet address.
// Each push notification is routed through `BscWatcher::dispatch_log` — the
// same processing path used by the polling fallback.
//
// Recovery: reconnects with exponential back-off (2 s → … → 60 s) on any
// disconnect or error.  When active, `BscWatcher::start()` drops the block
// polling to a slow fallback (default 300 s) that catches any edge-cases the
// WebSocket might miss (e.g., bridge-contract `UsdcDeposited` events, which
// use a separate contract address not covered by this subscription).
//
// Env vars:
//   BSC_WS_URL               — wss:// endpoint.  Examples:
//                              wss://bsc-mainnet.core.chainstack.com/<key>
//                              wss://bnb-mainnet.g.alchemy.com/v2/<key>
//                              wss://bsc.getblock.io/<key>/mainnet/
// ============================================================================

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};

use super::bsc_watcher::{BscWatcher, EthLog, TRANSFER_TOPIC};

// ── eth_subscription notification wire types ──────────────────────────────────

#[derive(Deserialize)]
struct EthSubEnvelope {
    method: Option<String>,
    params: Option<EthSubParams>,
}

#[derive(Deserialize)]
struct EthSubParams {
    result: Option<EthLog>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Spawn a background task that maintains a persistent `eth_subscribe("logs")`
/// WebSocket subscription for Transfer events to the BSC custody wallet.
///
/// Automatically reconnects with exponential back-off on failure.
pub fn start_bsc_ws(watcher: Arc<BscWatcher>, ws_url: String) {
    tokio::spawn(async move {
        info!("🔌 BSC WS subscriber starting → {}", truncate(&ws_url, 72));
        let mut backoff = Duration::from_secs(2);
        loop {
            match run_once(&watcher, &ws_url).await {
                Ok(()) => {
                    backoff = Duration::from_secs(2);
                }
                Err(e) => {
                    warn!(
                        "⚠️  BSC WS error: {} — reconnecting in {}s",
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

async fn run_once(watcher: &Arc<BscWatcher>, ws_url: &str) -> Result<(), String> {
    let (ws_stream, _) = connect_async(ws_url)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;

    info!("🔌 BSC WS connected → {}", truncate(ws_url, 72));

    let (mut write, mut read) = ws_stream.split();

    // topics[2] = custody wallet padded to 32 bytes (EVM ABI encoding for address)
    let to_topic = format!("0x000000000000000000000000{}", watcher.custody_lower);

    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": [
            "logs",
            {
                "address": [&watcher.usdc_contract, &watcher.usdt_contract],
                "topics": [TRANSFER_TOPIC, null, to_topic]
            }
        ]
    })
    .to_string();

    write
        .send(Message::Text(subscribe_msg))
        .await
        .map_err(|e| format!("send subscribe: {}", e))?;

    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.tick().await;

    loop {
        tokio::select! {
            msg_opt = read.next() => {
                match msg_opt {
                    Some(Ok(Message::Text(text))) => {
                        handle_text(watcher, &text).await;
                    }
                    Some(Ok(Message::Ping(data))) => {
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
                    _ => {}
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

async fn handle_text(watcher: &Arc<BscWatcher>, text: &str) {
    let env: EthSubEnvelope = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };
    if env.method.as_deref() != Some("eth_subscription") {
        return;
    }
    let log = match env.params.and_then(|p| p.result) {
        Some(l) => l,
        None => return,
    };
    info!(
        "📡 BSC WS event → tx {}",
        truncate(&log.transaction_hash, 18)
    );
    watcher.dispatch_log(log).await;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
