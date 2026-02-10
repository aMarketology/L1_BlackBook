use opaque_ke::{
    ciphersuite::CipherSuite,
    ClientRegistration, ServerRegistration,
    ClientLogin, ServerLogin,
    ClientLoginFinishParameters,
    ServerLoginParameters,
    ClientRegistrationFinishParameters,
    keypair::{KeyPair},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use lazy_static::lazy_static;

// Define the cipher suite
pub type OpaqueCipherSuite = opaque_ke::Ristretto255;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OpaqueSharedState {
    pub registration_record: Vec<u8>, // Serialized ServerRegistration
    pub encrypted_shard_b: Vec<u8>,   // Encrypted by export_key
    pub pepper_id: String,            // Identification of the pepper used (e.g. "vault-v1")
}

lazy_static! {
    static ref SERVER_KP: KeyPair<OpaqueCipherSuite> = {
        let mut rng = OsRng;
        KeyPair::<OpaqueCipherSuite>::generate_random(&mut rng).unwrap()
    };
}

// Helper for encryption using the OPAQUE export key
// The export key is 64 bytes (usually). AES-256 needs 32 bytes.
fn encrypt_payload(export_key: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    if export_key.len() < 32 {
        return Err("Export key too short".to_string());
    }
    let key_bytes = &export_key[0..32];
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, payload)
        .map_err(|e| format!("AES Encryption failed: {}", e))?;
    
    // Prepend nonce to ciphertext
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

fn decrypt_payload(export_key: &[u8], combined: &[u8]) -> Result<Vec<u8>, String> {
    if export_key.len() < 32 {
        return Err("Export key too short".to_string());
    }
    if combined.len() < 12 {
        return Err("Ciphertext too short".to_string());
    }
    let key_bytes = &export_key[0..32];
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    let nonce = Nonce::from_slice(&combined[0..12]);
    let ciphertext = &combined[12..];
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES Decryption failed: {}", e))
}


// Full flow simulation for "Trusted Dealer" setup where server knows password temporarily
// Returns the Storage Record to create in DB
pub fn server_side_registration_simulation(
    password: &str,
    shard_b: &[u8],
) -> Result<OpaqueSharedState, String> {
    let mut rng = OsRng;

    // 1. Client Start
    let client_start_result = ClientRegistration::<OpaqueCipherSuite>::start(
        &mut rng,
        password.as_bytes(),
    ).map_err(|e| format!("Client start failed: {:?}", e))?;

    // 2. Server Start
    let server_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
        &mut rng,
        client_start_result.message,
        password.as_bytes(), 
    ).map_err(|e| format!("Server start failed: {:?}", e))?;

    // 3. Client Finish
    let client_finish_result = client_start_result.state.finish(
        &mut rng,
        password.as_bytes(),
        server_start_result.message,
        ClientRegistrationFinishParameters::default(),
    ).map_err(|e| format!("Client finish failed: {:?}", e))?;

    // 4. Server Finish
    let server_registration = ServerRegistration::<OpaqueCipherSuite>::finish(
        client_finish_result.message
    );
    
    // 5. Get Export Key
    let export_key = client_finish_result.export_key;

    // 6. Encrypt Shard B
    let encrypted_b = encrypt_payload(&export_key, shard_b)?;

    // Serialize registration
    let registration_bytes = server_registration.serialize()
        .map_err(|_| "Failed to serialize server registration".to_string())?;

    Ok(OpaqueSharedState {
        registration_record: registration_bytes,
        encrypted_shard_b: encrypted_b,
        pepper_id: "vault-v1".to_string(),
    })
}

// Verify password and recover Shard B
pub fn server_side_login_simulation(
    password: &str,
    storage: &OpaqueSharedState,
) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;

    // Deserialize Server Record
    let server_record = ServerRegistration::<OpaqueCipherSuite>::deserialize(&storage.registration_record)
        .map_err(|_| "Failed to deserialize server record".to_string())?;

    // 1. Client Login Start
    let client_login_start_result = ClientLogin::<OpaqueCipherSuite>::start(
        &mut rng,
        password.as_bytes(),
    ).map_err(|e| format!("Client login start failed: {:?}", e))?;

    // 2. Server Login Start
    let server_login_start_result = ServerLogin::start(
        &mut rng,
        server_record,
        &SERVER_KP,
        client_login_start_result.message,
        &[], // Server ID
        ServerLoginParameters::default(),
    ).map_err(|e| format!("Server login start failed: {:?}", e))?;

    // 3. Client Login Finish
    let client_login_finish_result = client_login_start_result.state.finish(
        &mut rng,
        password.as_bytes(),
        server_login_start_result.message,
        ClientLoginFinishParameters::default(),
    ).map_err(|e| format!("Client login finish failed: {:?}", e))?;

    // 4. Server Login Finish
    let _ = server_login_start_result.state.finish(
        client_login_finish_result.message,
        ServerLoginParameters::default(),
    ).map_err(|e| format!("Server login finish failed: {:?}", e))?;

    // 5. Decrypt using Client secret export key
    let export_key = client_login_finish_result.export_key;
    let decrypted_shard_b = decrypt_payload(&export_key, &storage.encrypted_shard_b)?;

    Ok(decrypted_shard_b)
}
