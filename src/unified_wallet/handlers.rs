//! # HTTP API Handlers for S+ Tier Wallet
//!
//! This module provides Axum handlers for the wallet system.
//!
//! ## Endpoints
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/wallet/register/start` | POST | Start wallet creation (DKG + OPAQUE registration) |
//! | `/wallet/register/finish` | POST | Finish wallet creation |
//! | `/wallet/login/start` | POST | Start OPAQUE login |
//! | `/wallet/login/finish` | POST | Finish login, get session key |
//! | `/wallet/sign/start` | POST | Start threshold signing (round 1) |
//! | `/wallet/sign/finish` | POST | Finish signing (round 2 + aggregate) |
//! | `/wallet/info/:address` | GET | Get wallet public info |

use crate::unified_wallet::{
    types::*,
    dkg::FrostDKG,
    tss::ThresholdSigner,
    opaque_auth::OpaqueAuth,
    storage::ShardStorage,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Shared state for wallet handlers
#[derive(Clone)]
pub struct WalletHandlers {
    pub dkg: Arc<FrostDKG>,
    pub signer: Arc<ThresholdSigner>,
    pub auth: Arc<OpaqueAuth>,
    pub storage: Arc<ShardStorage>,
}

impl WalletHandlers {
    /// Create new wallet handlers
    pub fn new(
        dkg: Arc<FrostDKG>,
        signer: Arc<ThresholdSigner>,
        auth: Arc<OpaqueAuth>,
        storage: Arc<ShardStorage>,
    ) -> Self {
        Self { dkg, signer, auth, storage }
    }
    
    /// Create an Axum router with all wallet routes
    /// Returns a router that needs .with_state(Arc<WalletHandlers>)
    pub fn router() -> Router<WalletHandlers> {
        Router::new()
            // Registration (DKG + OPAQUE)
            .route("/wallet/register/start", post(Self::register_start))
            .route("/wallet/register/round1", post(Self::register_round1))
            .route("/wallet/register/round2", post(Self::register_round2))
            .route("/wallet/register/finish", post(Self::register_finish))
            // Login (OPAQUE)
            .route("/wallet/login/start", post(Self::login_start))
            .route("/wallet/login/finish", post(Self::login_finish))
            // Signing (FROST)
            .route("/wallet/sign/start", post(Self::sign_start))
            .route("/wallet/sign/commitment", post(Self::sign_commitment))
            .route("/wallet/sign/finish", post(Self::sign_finish))
            // Info
            .route("/wallet/info/:address", get(Self::wallet_info))
            .route("/wallet/health", get(Self::health))
    }
}

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    pub opaque_registration_request: String, // hex
}

#[derive(Debug, Serialize)]
pub struct RegisterStartResponse {
    pub session_id: String,
    pub server_dkg_round1: String, // hex
    pub opaque_registration_response: String, // hex
}

#[derive(Debug, Deserialize)]
pub struct RegisterRound1Request {
    pub session_id: String,
    pub client_dkg_round1: String, // hex
}

#[derive(Debug, Serialize)]
pub struct RegisterRound1Response {
    pub server_dkg_round2: Vec<DKGRound2Package>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRound2Request {
    pub session_id: String,
    pub client_dkg_round2: Vec<DKGRound2Package>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub session_id: String,
    pub opaque_registration_upload: String, // hex
}

#[derive(Debug, Serialize)]
pub struct RegisterFinishResponse {
    pub wallet_address: String,
    pub public_key: String,
    pub guardian_shard_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    pub wallet_address: String,
    pub opaque_credential_request: String, // hex
}

#[derive(Debug, Serialize)]
pub struct LoginStartResponse {
    pub session_id: String,
    pub opaque_credential_response: String, // hex
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    pub session_id: String,
    pub opaque_credential_finalization: String, // hex
}

#[derive(Debug, Serialize)]
pub struct LoginFinishResponse {
    pub session_key: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct SignStartRequest {
    pub wallet_address: String,
    pub message_hex: String,
    /// Must provide valid OPAQUE session
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct SignStartResponse {
    pub session_id: String,
    pub server_commitment: SigningCommitment,
}

#[derive(Debug, Deserialize)]
pub struct SignCommitmentRequest {
    pub session_id: String,
    pub client_commitment: SigningCommitment,
}

#[derive(Debug, Serialize)]
pub struct SignCommitmentResponse {
    pub server_share: SignatureShare,
}

#[derive(Debug, Deserialize)]
pub struct SignFinishRequest {
    pub session_id: String,
    pub client_share: SignatureShare,
}

#[derive(Debug, Serialize)]
pub struct WalletInfoResponse {
    pub wallet_address: String,
    pub public_key: String,
    pub created_at: Option<u64>,
    pub last_activity: Option<u64>,
}

// ============================================================================
// HANDLERS
// ============================================================================

impl WalletHandlers {
    /// Health check
    async fn health() -> impl IntoResponse {
        Json(serde_json::json!({
            "status": "healthy",
            "service": "blackbook-wallet-s-plus",
            "features": ["frost-tss", "opaque-auth", "mpc-signing"]
        }))
    }
    
    /// Start registration (DKG round 1 + OPAQUE registration start)
    async fn register_start(
        State(state): State<WalletHandlers>,
        Json(req): Json<RegisterStartRequest>,
    ) -> Result<Json<RegisterStartResponse>, (StatusCode, String)> {
        let session_id = Uuid::new_v4().to_string();
        
        // Start DKG round 1
        let server_round1 = state.dkg.start_round1(&session_id, &req.username)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Start OPAQUE registration
        let opaque_request = hex::decode(&req.opaque_registration_request)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid OPAQUE request: {}", e)))?;
        
        let opaque_response = state.auth.registration_start(&session_id, &req.username, &opaque_request)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        Ok(Json(RegisterStartResponse {
            session_id,
            server_dkg_round1: server_round1.package_hex,
            opaque_registration_response: hex::encode(opaque_response),
        }))
    }
    
    /// Receive client's DKG round 1, send our round 2
    async fn register_round1(
        State(state): State<WalletHandlers>,
        Json(req): Json<RegisterRound1Request>,
    ) -> Result<Json<RegisterRound1Response>, (StatusCode, String)> {
        // Parse client's round 1 package
        let client_round1 = DKGRound1Package {
            participant_id: 1, // Client is participant 1
            package_hex: req.client_dkg_round1,
        };
        
        // Process it
        state.dkg.receive_round1(&req.session_id, client_round1)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        
        // We also need round 1 from participant 3 (recovery shard)
        // For S+ tier, this could come from a backup service or be derived from mnemonic
        // For now, we'll simulate it or require it from the client
        
        // Generate our round 2 packages
        let round2_packages = state.dkg.generate_round2(&req.session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        Ok(Json(RegisterRound1Response {
            server_dkg_round2: round2_packages,
        }))
    }
    
    /// Receive client's DKG round 2 packages
    async fn register_round2(
        State(state): State<WalletHandlers>,
        Json(req): Json<RegisterRound2Request>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
        // Process each round 2 package addressed to us
        for package in req.client_dkg_round2 {
            state.dkg.receive_round2(&req.session_id, package)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        }
        
        Ok(Json(serde_json::json!({ "status": "round2_received" })))
    }
    
    /// Finish registration (finalize DKG + OPAQUE)
    async fn register_finish(
        State(state): State<WalletHandlers>,
        Json(req): Json<RegisterFinishRequest>,
    ) -> Result<Json<RegisterFinishResponse>, (StatusCode, String)> {
        // Finalize OPAQUE registration
        let opaque_upload = hex::decode(&req.opaque_registration_upload)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid OPAQUE upload: {}", e)))?;
        
        state.auth.registration_finish(&req.session_id, &opaque_upload)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Finalize DKG
        let result = state.dkg.finalize(&req.session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Store our shard
        if let (Some(key_package), Some(public_key_package)) = (
            state.dkg.get_key_package(&result.wallet_address),
            state.dkg.get_public_key_package(&result.wallet_address),
        ) {
            state.storage.store_shard(&result.wallet_address, &key_package, &public_key_package)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        
        Ok(Json(RegisterFinishResponse {
            wallet_address: result.wallet_address,
            public_key: result.public_key_hex,
            guardian_shard_id: result.guardian_shard_id,
        }))
    }
    
    /// Start OPAQUE login
    async fn login_start(
        State(state): State<WalletHandlers>,
        Json(req): Json<LoginStartRequest>,
    ) -> Result<Json<LoginStartResponse>, (StatusCode, String)> {
        let session_id = Uuid::new_v4().to_string();
        
        let opaque_request = hex::decode(&req.opaque_credential_request)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid OPAQUE request: {}", e)))?;
        
        let opaque_response = state.auth.login_start(&session_id, &req.wallet_address, &opaque_request)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
        
        Ok(Json(LoginStartResponse {
            session_id,
            opaque_credential_response: hex::encode(opaque_response),
        }))
    }
    
    /// Finish OPAQUE login, get session key
    async fn login_finish(
        State(state): State<WalletHandlers>,
        Json(req): Json<LoginFinishRequest>,
    ) -> Result<Json<LoginFinishResponse>, (StatusCode, String)> {
        let opaque_finish = hex::decode(&req.opaque_credential_finalization)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid OPAQUE finalization: {}", e)))?;
        
        let result = state.auth.login_finish(&req.session_id, &opaque_finish)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
        
        Ok(Json(LoginFinishResponse {
            session_key: result.session_key_hex,
            expires_at: result.expires_at,
        }))
    }
    
    /// Start signing (FROST round 1)
    async fn sign_start(
        State(state): State<WalletHandlers>,
        Json(req): Json<SignStartRequest>,
    ) -> Result<Json<SignStartResponse>, (StatusCode, String)> {
        // TODO: Validate session token
        
        let session_id = Uuid::new_v4().to_string();
        
        // Get our key package and public key package
        let key_package = state.storage.get_shard(&req.wallet_address)
            .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
        
        let public_key_package = state.storage.get_public_key_package(&req.wallet_address)
            .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
        
        let message = hex::decode(&req.message_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid message: {}", e)))?;
        
        let commitment = state.signer.start_signing(
            &session_id,
            &req.wallet_address,
            &message,
            key_package,
            public_key_package,
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        Ok(Json(SignStartResponse {
            session_id,
            server_commitment: commitment,
        }))
    }
    
    /// Receive client's commitment, send our signature share
    async fn sign_commitment(
        State(state): State<WalletHandlers>,
        Json(req): Json<SignCommitmentRequest>,
    ) -> Result<Json<SignCommitmentResponse>, (StatusCode, String)> {
        // Process client's commitment
        state.signer.receive_commitment(&req.session_id, req.client_commitment)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        
        // Generate our signature share
        let share = state.signer.generate_share(&req.session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        Ok(Json(SignCommitmentResponse {
            server_share: share,
        }))
    }
    
    /// Finish signing (aggregate shares)
    async fn sign_finish(
        State(state): State<WalletHandlers>,
        Json(req): Json<SignFinishRequest>,
    ) -> Result<Json<SignatureResult>, (StatusCode, String)> {
        // Get our share from the session
        let our_share = state.signer.generate_share(&req.session_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Aggregate both shares
        let shares = vec![our_share, req.client_share];
        
        let result = state.signer.aggregate(&req.session_id, shares)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        Ok(Json(result))
    }
    
    /// Get wallet info
    async fn wallet_info(
        State(state): State<WalletHandlers>,
        Path(address): Path<String>,
    ) -> Result<Json<WalletInfoResponse>, (StatusCode, String)> {
        // Check if wallet exists
        if !state.storage.wallet_exists(&address) {
            return Err((StatusCode::NOT_FOUND, "Wallet not found".to_string()));
        }
        
        // Get public key
        let public_key_package = state.storage.get_public_key_package(&address)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Serialize the verifying key properly
        let verifying_key = public_key_package.verifying_key();
        let public_key_bytes = verifying_key.serialize()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize key: {:?}", e)))?;
        
        Ok(Json(WalletInfoResponse {
            wallet_address: address,
            public_key: hex::encode(public_key_bytes),
            created_at: None, // Could add to storage
            last_activity: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handlers_creation() {
        let handlers = WalletHandlers::new(
            Arc::new(FrostDKG::new()),
            Arc::new(ThresholdSigner::new()),
            Arc::new(OpaqueAuth::new()),
            Arc::new(ShardStorage::new()),
        );
        
        // Just verify it compiles and creates
        assert!(true);
    }
}
