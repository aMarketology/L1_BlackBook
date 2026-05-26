//! Ed25519 signature verification + replay protection for action endpoints.
//!
//! Every state-changing endpoint uses the same message construction and
//! replay-protection scheme as `/transfer/simple` and `/faucet`.
//!
//! # Message format
//! ```text
//! "{ACTION}:{from_address}:{body_fields...}:{timestamp}:{nonce}"
//! ```
//! Encoded as UTF-8. The signature is a 64-byte Ed25519 signature over the
//! raw bytes of that string, produced by the wallet's private key.
//!
//! # Request envelope
//! All signed POST bodies include:
//! ```json
//! {
//!   "from":       "<base58 wallet address>",
//!   "public_key": "<32-byte hex pubkey>",
//!   "signature":  "<64-byte hex signature>",
//!   "timestamp":  <unix seconds u64>,
//!   "nonce":      "<random string>"
//! }
//! ```

use axum::http::StatusCode;
use axum::Json;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::AppState;

/// Maximum age of a signed request (seconds).
pub const MAX_TIMESTAMP_AGE_SECS: u64 = 60;

/// Error type returned by [`verify_signed_action`].
pub type AuthError = (StatusCode, Json<Value>);

/// Verify an Ed25519-signed action request.
///
/// # Parameters
/// - `state`      — app state (used_nonces DashMap access)
/// - `action`     — action label string (e.g. "TRANSFER")
/// - `from`       — base58 address from the request body
/// - `public_key` — hex-encoded 32-byte Ed25519 public key
/// - `signature`  — hex-encoded 64-byte Ed25519 signature
/// - `timestamp`  — Unix epoch seconds when the client signed
/// - `nonce`      — unique string to prevent replay
/// - `body`       — the signed message body (fields between action+address and timestamp)
///
/// The signed message is: `"{action}:{from}:{body}:{timestamp}:{nonce}"`
///
/// Returns `Ok(())` on success, or `Err(AuthError)` to be returned immediately.
pub fn verify_signed_action(
    state:      &AppState,
    action:     &str,
    from:       &str,
    public_key: &str,
    signature:  &str,
    timestamp:  u64,
    nonce:      &str,
    body:       &str,
) -> Result<(), AuthError> {
    let err = |code: StatusCode, msg: &str| -> AuthError {
        (code, Json(serde_json::json!({ "error": msg })))
    };

    // ── 1. Decode pubkey and verify it matches the `from` address ──────────
    let pubkey_bytes = hex::decode(public_key)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid public_key hex"))?;
    if pubkey_bytes.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "public_key must be 32 bytes"));
    }
    let pubkey_arr: &[u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid pubkey length"))?;
    let verifying_key = VerifyingKey::from_bytes(pubkey_arr)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Bad public key"))?;

    // Ensure public_key matches the claimed `from` address
    let decoded_addr = bs58::decode(from).into_vec()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid from address (bad base58)"))?;
    if decoded_addr != pubkey_bytes {
        return Err(err(StatusCode::UNAUTHORIZED, "public_key does not match from address"));
    }

    // ── 2. Decode signature ────────────────────────────────────────────────
    let sig_bytes = hex::decode(signature)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid signature hex"))?;
    if sig_bytes.len() != 64 {
        return Err(err(StatusCode::BAD_REQUEST, "Signature must be 64 bytes"));
    }
    let sig_arr: &[u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid signature length"))?;
    let sig = Signature::from_bytes(sig_arr);

    // ── 3. Reconstruct message and verify ──────────────────────────────────
    let message = format!("{action}:{from}:{body}:{timestamp}:{nonce}");
    if verifying_key.verify(message.as_bytes(), &sig).is_err() {
        return Err(err(StatusCode::UNAUTHORIZED, "Signature verification failed"));
    }

    // ── 4. Timestamp freshness ─────────────────────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(timestamp) > MAX_TIMESTAMP_AGE_SECS {
        return Err(err(StatusCode::BAD_REQUEST, "Request expired (>60s old)"));
    }

    // ── 5. Replay protection (atomic nonce insert) ─────────────────────────
    let nonce_key = format!("{action}:{from}:{nonce}");
    match state.used_nonces.entry(nonce_key) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            return Err(err(StatusCode::CONFLICT, "Nonce already used — possible replay"));
        }
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(now);
        }
    }

    // Prune stale nonces periodically
    if state.used_nonces.len() > 100_000 {
        let cutoff = now.saturating_sub(120);
        state.used_nonces.retain(|_, &mut ts| ts > cutoff);
    }

    Ok(())
}
