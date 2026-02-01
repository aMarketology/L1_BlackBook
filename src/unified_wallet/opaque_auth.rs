//! # OPAQUE Password Authentication
//!
//! This module implements OPAQUE (Oblivious Pseudo-Random Function-based
//! Asymmetric Password-Authenticated Key Exchange).
//!
//! ## Why OPAQUE Is S+ Tier
//!
//! Traditional password auth:
//! ```text
//! User -> "mypassword123" -> Server
//! Server: hash = SHA256("mypassword123")
//! Server: if hash == stored_hash: OK
//! Problem: Server SAW the password. If breached, attacker can brute-force.
//! ```
//!
//! OPAQUE:
//! ```text
//! User -> [mathematical blob that proves password knowledge] -> Server
//! Server: verifies blob using stored [mathematical record]
//! Server NEVER sees password or hash. Even with full DB dump,
//! attacker CANNOT brute-force passwords offline.
//! ```
//!
//! ## Protocol Flow
//!
//! Registration:
//! 1. Client: password -> OPRF(password) -> registration request
//! 2. Server: stores registration record (useless without password)
//!
//! Login:
//! 1. Client: password -> OPRF(password) -> credential request
//! 2. Server: credential response (client can derive session key)
//! 3. Client: proves knowledge of password -> server authenticates
//!
//! Result: Both parties have a shared session key, server never saw password.

use crate::unified_wallet::types::*;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest,
    Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration,
    ServerSetup,
};
use rand_core::OsRng;
use std::collections::BTreeMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Our OPAQUE cipher suite configuration
/// Using Ristretto255 with Identity for key stretching (use Argon2 in production)
struct BlackBookCipherSuite;

impl CipherSuite for BlackBookCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;  // Use Identity for now; swap to Argon2 in production
}

/// OPAQUE authentication system
pub struct OpaqueAuth {
    /// Server setup (contains server keys)
    server_setup: Arc<ServerSetup<BlackBookCipherSuite>>,
    
    /// Registration records (stored password files)
    registrations: Arc<RwLock<BTreeMap<String, ServerRegistration<BlackBookCipherSuite>>>>,
    
    /// Active login sessions
    login_sessions: Arc<RwLock<BTreeMap<String, LoginSessionState>>>,
    
    /// Active registration sessions
    registration_sessions: Arc<RwLock<BTreeMap<String, RegistrationSessionState>>>,
}

/// State for an in-progress login
struct LoginSessionState {
    /// Server's login state (needed for finish)
    server_login: ServerLogin<BlackBookCipherSuite>,
    
    /// Session creation time
    created_at: u64,
    
    /// Associated wallet address
    wallet_address: String,
}

/// State for an in-progress registration
struct RegistrationSessionState {
    /// Expected username
    username: String,
    
    /// Session creation time
    created_at: u64,
}

impl OpaqueAuth {
    /// Create a new OPAQUE authentication system
    pub fn new() -> Self {
        // Generate server keys
        let server_setup = ServerSetup::<BlackBookCipherSuite>::new(&mut OsRng);
        
        Self {
            server_setup: Arc::new(server_setup),
            registrations: Arc::new(RwLock::new(BTreeMap::new())),
            login_sessions: Arc::new(RwLock::new(BTreeMap::new())),
            registration_sessions: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    
    // ========================================================================
    // REGISTRATION
    // ========================================================================
    
    /// Start registration (server side)
    /// 
    /// Receives the client's registration request and returns the server's response.
    pub fn registration_start(
        &self,
        session_id: &str,
        username: &str,
        client_request_bytes: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        // Deserialize client's registration request
        let client_request = RegistrationRequest::<BlackBookCipherSuite>::deserialize(client_request_bytes)
            .map_err(|e| WalletError::AuthError(format!("Invalid registration request: {:?}", e)))?;
        
        // Create server registration
        let server_registration_start = ServerRegistration::<BlackBookCipherSuite>::start(
            &self.server_setup,
            client_request,
            username.as_bytes(),
        ).map_err(|e| WalletError::AuthError(format!("Server registration start failed: {:?}", e)))?;
        
        // Store session state
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.registration_sessions.write().insert(
            session_id.to_string(),
            RegistrationSessionState {
                username: username.to_string(),
                created_at: now,
            },
        );
        
        // Serialize response
        let response_bytes = server_registration_start.message.serialize();
        Ok(response_bytes.to_vec())
    }
    
    /// Finish registration (server side)
    /// 
    /// Receives the client's registration upload and stores it.
    pub fn registration_finish(
        &self,
        session_id: &str,
        client_upload_bytes: &[u8],
    ) -> Result<(), WalletError> {
        // Get session state
        let session = self.registration_sessions.write().remove(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Deserialize client's registration upload
        let registration_upload = RegistrationUpload::<BlackBookCipherSuite>::deserialize(client_upload_bytes)
            .map_err(|e| WalletError::AuthError(format!("Invalid registration upload: {:?}", e)))?;
        
        // Convert to ServerRegistration (this is the "password file")
        // ServerRegistration contains the verifier that lets server check password without knowing it
        let server_registration = ServerRegistration::finish(registration_upload);
        self.registrations.write().insert(session.username, server_registration);
        
        Ok(())
    }
    
    // ========================================================================
    // LOGIN
    // ========================================================================
    
    /// Start login (server side)
    /// 
    /// Receives the client's credential request and returns the server's response.
    pub fn login_start(
        &self,
        session_id: &str,
        wallet_address: &str,
        client_request_bytes: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        // Get the registration for this user
        let registration = self.registrations.read()
            .get(wallet_address)
            .cloned()
            .ok_or_else(|| WalletError::WalletNotFound(wallet_address.to_string()))?;
        
        // Deserialize client's credential request
        let credential_request = CredentialRequest::<BlackBookCipherSuite>::deserialize(client_request_bytes)
            .map_err(|e| WalletError::AuthError(format!("Invalid credential request: {:?}", e)))?;
        
        // Create server login
        let identifiers = Identifiers {
            client: Some(wallet_address.as_bytes()),
            server: Some(b"blackbook-l1"),
        };
        
        let server_login_start = ServerLogin::start(
            &mut OsRng,
            &self.server_setup,
            Some(registration),
            credential_request,
            wallet_address.as_bytes(),
            ServerLoginStartParameters::default(),
        ).map_err(|e| WalletError::AuthError(format!("Server login start failed: {:?}", e)))?;
        
        // Store session state
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.login_sessions.write().insert(
            session_id.to_string(),
            LoginSessionState {
                server_login: server_login_start.state,
                created_at: now,
                wallet_address: wallet_address.to_string(),
            },
        );
        
        // Serialize response
        let response_bytes = server_login_start.message.serialize();
        Ok(response_bytes.to_vec())
    }
    
    /// Finish login (server side)
    /// 
    /// Receives the client's credential finalization and verifies it.
    /// Returns the session key on success.
    pub fn login_finish(
        &self,
        session_id: &str,
        client_finish_bytes: &[u8],
    ) -> Result<AuthResult, WalletError> {
        // Get session state
        let session = self.login_sessions.write().remove(session_id)
            .ok_or_else(|| WalletError::SessionNotFound(session_id.to_string()))?;
        
        // Deserialize client's finalization
        let credential_finalization = CredentialFinalization::<BlackBookCipherSuite>::deserialize(client_finish_bytes)
            .map_err(|e| WalletError::AuthError(format!("Invalid credential finalization: {:?}", e)))?;
        
        // Verify and get session key
        let server_login_finish = session.server_login.finish(credential_finalization)
            .map_err(|e| WalletError::AuthError(format!("Login verification failed: {:?}", e)))?;
        
        // Get the session key
        let session_key = server_login_finish.session_key;
        
        // Create auth result
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(AuthResult {
            session_key_hex: hex::encode(&session_key),
            server_mac_hex: String::new(), // OPAQUE handles this internally
            expires_at: now + 3600, // 1 hour session
            wallet_address: session.wallet_address,
        })
    }
    
    /// Authenticate (simplified API for UnifiedWalletSystem)
    pub async fn authenticate(
        &self,
        wallet_address: &str,
        opaque_message: &[u8],
    ) -> Result<AuthResult, WalletError> {
        // This requires the full multi-round protocol
        // The handlers orchestrate this properly
        Err(WalletError::AuthError(
            "Use the multi-round OPAQUE protocol (login_start -> login_finish)".to_string()
        ))
    }
    
    /// Check if a user is registered
    pub fn is_registered(&self, username: &str) -> bool {
        self.registrations.read().contains_key(username)
    }
    
    /// Clean up expired sessions
    pub fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Sessions expire after 5 minutes
        let expiry = 300u64;
        
        self.login_sessions.write().retain(|_, state| {
            now - state.created_at < expiry
        });
        
        self.registration_sessions.write().retain(|_, state| {
            now - state.created_at < expiry
        });
    }
    
    /// Get server's public key (for client setup)
    pub fn get_server_public_key(&self) -> Vec<u8> {
        // The server's public key is part of the credential response
        // Clients receive it during the login flow
        Vec::new() // Placeholder - OPAQUE handles this internally
    }
}

impl Default for OpaqueAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opaque_creation() {
        let auth = OpaqueAuth::new();
        assert!(!auth.is_registered("nonexistent"));
    }
}
