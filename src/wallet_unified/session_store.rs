// ============================================================================
// BLACKBOOK L1 — Wallet Session Store
// ============================================================================
//
// How this works (normal SVM wallet behavior):
//
//   1. User creates a wallet → POST /wallet/create
//      - Server generates BIP-39 mnemonic, derives Ed25519 keypair
//      - Splits private key into 3 Shamir shards (A, B, C)
//      - Encrypts Shard A with user's password (Argon2id → AES-256-GCM)
//      - Stores encrypted Shard B server-side
//      - Returns: wallet_id, address, mnemonic, encrypted_shard_a, shard_c
//      - Server creates a session → returns session_token
//      - Wallet is immediately unlocked — no re-login needed
//
//   2. User logs in → POST /wallet/login
//      - Server decrypts Shard A (password → Argon2id → AES-GCM)
//      - Server decrypts Shard B (SERVER_MASTER_KEY)
//      - Reconstructs the 32-byte seed via Lagrange interpolation
//      - Stores the seed in THIS session store, keyed by session_token
//      - Returns session_token to the browser
//      - Seed stays in server memory — user is "unlocked"
//
//   3. User sends BB → POST /transfer/session
//      - Browser sends session_token + to_address + amount
//      - Server looks up the seed by session_token
//      - Reconstructs keypair from seed, signs the tx, submits to SVM
//      - Refreshes the session TTL (keeps it alive while active)
//      - No password, no Argon2id, no shard decryption — instant
//
//   4. User logs out → POST /wallet/logout
//      - Server wipes the seed from memory, removes the session
//      - Browser clears localStorage
//
//   5. Session expires (30 min idle)
//      - Background sweeper removes stale sessions every 60 seconds
//      - User must log in again (re-enter password → re-derive seed)
//
// Security:
//   - The seed only lives in server RAM, never on disk
//   - The session_token is a random UUID — useless without the server process
//   - If the server restarts, all sessions are lost (users re-login)
//   - One session per wallet — new login revokes the old session
//   - TTL auto-expires idle sessions
//
// This is how Phantom, Solflare, and every normal SVM wallet works:
// unlock once, sign freely, lock on logout/timeout.
// ============================================================================

use dashmap::DashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

const SESSION_TTL: Duration = Duration::from_secs(30 * 60); // 30 minutes

/// A live wallet session — holds the 32-byte seed in memory.
pub struct WalletSessionEntry {
    seed: [u8; 32],              // The raw Ed25519 seed — ready to sign
    pub wallet_id: String,       // Which wallet this session belongs to
    last_active: Instant,        // Reset on every successful operation
    ttl: Duration,               // How long until idle-expiry
}

impl Drop for WalletSessionEntry {
    fn drop(&mut self) {
        self.seed.zeroize(); // Wipe seed from memory when session is dropped
    }
}

/// In-memory session store. One instance per L1 node.
/// Lives inside your `AppState` / `UnifiedWalletState`.
pub struct SessionStore {
    sessions: DashMap<String, WalletSessionEntry>, // session_token → entry
}

impl SessionStore {
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    // ─────────────────────────────────────────────────────────────────────
    // CREATE
    // ─────────────────────────────────────────────────────────────────────

    /// Store the reconstructed seed in memory after a successful login or
    /// wallet creation. Returns a session_token (UUID) for the browser.
    ///
    /// Call this right after Lagrange interpolation succeeds.
    pub fn create_session(
        &self,
        wallet_id: &str,
        seed: &[u8; 32],
    ) -> String {
        // One session per wallet — revoke any prior session
        self.revoke_by_wallet(wallet_id);

        let session_token = Uuid::new_v4().to_string();

        self.sessions.insert(session_token.clone(), WalletSessionEntry {
            seed: *seed,
            wallet_id: wallet_id.to_string(),
            last_active: Instant::now(),
            ttl: SESSION_TTL,
        });

        session_token
    }

    // ─────────────────────────────────────────────────────────────────────
    // USE (get seed for signing)
    // ─────────────────────────────────────────────────────────────────────

    /// Retrieve the seed for a session. Returns a copy of the 32-byte seed.
    /// Refreshes the TTL on access (keep-alive while active).
    /// Returns Err if the session doesn't exist or has expired.
    pub fn get_seed(&self, session_token: &str) -> Result<[u8; 32], String> {
        let mut entry = self.sessions.get_mut(session_token)
            .ok_or_else(|| "Session not found — please log in".to_string())?;

        // Check idle timeout
        if entry.last_active.elapsed() > entry.ttl {
            let wallet_id = entry.wallet_id.clone();
            drop(entry);
            self.sessions.remove(session_token);
            return Err(format!("Session expired for wallet {} — please log in again", wallet_id));
        }

        // Refresh TTL (keep-alive)
        entry.last_active = Instant::now();

        Ok(entry.seed)
    }

    // ─────────────────────────────────────────────────────────────────────
    // REVOKE
    // ─────────────────────────────────────────────────────────────────────

    /// Revoke a specific session by token (called on logout).
    /// The Drop impl on WalletSessionEntry will zeroize the seed.
    pub fn revoke(&self, session_token: &str) {
        self.sessions.remove(session_token);
    }

    /// Revoke all sessions for a wallet (called before creating a new one).
    pub fn revoke_by_wallet(&self, wallet_id: &str) {
        self.sessions.retain(|_, entry| entry.wallet_id != wallet_id);
    }

    // ─────────────────────────────────────────────────────────────────────
    // BACKGROUND SWEEPER
    // ─────────────────────────────────────────────────────────────────────

    /// Remove all expired sessions. Call from a tokio::spawn loop every 60s.
    /// Seeds are zeroized on drop.
    pub fn sweep_expired(&self) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, entry| entry.last_active.elapsed() <= entry.ttl);
        before - self.sessions.len()
    }

}

// ============================================================================
// USAGE IN YOUR HANDLERS
// ============================================================================
//
// ── AppState ────────────────────────────────────────────────────────────────
//
//   pub struct AppState {
//       // ... existing fields ...
//       pub session_store: Arc<SessionStore>,
//   }
//
// ── main() ──────────────────────────────────────────────────────────────────
//
//   let session_store = Arc::new(SessionStore::new());
//   let sweeper = session_store.clone();
//   tokio::spawn(async move {
//       loop {
//           tokio::time::sleep(Duration::from_secs(60)).await;
//           let removed = sweeper.sweep_expired();
//           if removed > 0 {
//               tracing::info!("Swept {} expired wallet sessions", removed);
//           }
//       }
//   });
//
// ── POST /wallet/login ──────────────────────────────────────────────────────
//
//   // After successful Shard A+B → Lagrange → seed:
//   let session_token = state.session_store.create_session(
//       &wallet_id, &address, &username, &seed
//   );
//   seed.zeroize(); // wipe the local copy
//
//   Json(json!({
//       "wallet_id": wallet_id,
//       "address": address,
//       "public_key": public_key,
//       "share_a": encrypted_shard_a,
//       "share_a_is_encrypted": true,
//       "session_token": session_token,   // ← browser stores this
//   }))
//
// ── POST /wallet/create ─────────────────────────────────────────────────────
//
//   // Same thing — after wallet creation, auto-login:
//   let session_token = state.session_store.create_session(
//       &wallet_id, &address, &username, &seed
//   );
//   seed.zeroize();
//
//   Json(json!({
//       "wallet_id": wallet_id,
//       "address": address,
//       "mnemonic": mnemonic,
//       "share_a": encrypted_shard_a,
//       "share_a_is_encrypted": true,
//       "share_c": shard_c_hex,
//       "public_key": public_key,
//       "session_token": session_token,   // ← auto-unlocked
//   }))
//
// ── POST /transfer/session ──────────────────────────────────────────────────
//
//   let seed = state.session_store.get_seed(&req.session_token)?;
//   let keypair = ed25519_dalek::SigningKey::from_bytes(&seed);
//   // ... build tx, sign, submit, get signature ...
//   // seed copy goes out of scope here (stack, not heap)
//
//   Json(json!({
//       "success": true,
//       "signature": signature,
//       "from": from_address,
//       "to": to_address,
//       "amount": amount,
//       "from_balance": from_balance,
//       "to_balance": to_balance,
//       "session_token": req.session_token,  // ← same token, still valid
//   }))
//
// ── POST /wallet/logout ─────────────────────────────────────────────────────
//
//   state.session_store.revoke(&req.session_token);
//   Json(json!({ "success": true }))
//
// ── Router ───────────────────────────────────────────────────────────────────
//
//   .route("/transfer/session", post(transfer_session_handler))
//   .route("/wallet/logout",    post(logout_handler))
//
// ============================================================================
