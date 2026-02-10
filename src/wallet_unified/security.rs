use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString, PasswordHash, PasswordVerifier
    },
    Argon2
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce
};
use rand::RngCore;

/// Hashes a secret (PIN/Password) using Argon2id. Returns PHC string.
pub fn hash_secret(secret: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(secret.as_bytes(), &salt)
        .expect("Argon2 hashing failed")
        .to_string()
}

/// Verifies a secret against a PHC hash.
pub fn verify_secret(secret: &str, hash: &str) -> bool {
    // If hash is empty (e.g. no pin set), return false
    if hash.is_empty() { return false; }
    
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    
    Argon2::default().verify_password(secret.as_bytes(), &parsed_hash).is_ok()
}

/// Encrypts data using a key derived from a password/pin via Argon2id.
/// Returns a formatted string: `salt_b64:nonce_b64:ciphertext_b64`
pub fn encrypt_with_secret(secret: &str, data: &[u8]) -> Result<String, String> {
    // 1. Generate Salt
    let salt = SaltString::generate(&mut OsRng); // 128-bit salt

    // 2. Derive Key (Argon2id)
    // We use the salt to derive a 32-byte key for AES-256
    let mut key_buffer = [0u8; 32];
    let argon2 = Argon2::default();
    
    argon2.hash_password_into(
        secret.as_bytes(),
        salt.as_str().as_bytes(),
        &mut key_buffer
    ).map_err(|e| format!("Argon2 derivation failed: {}", e))?;

    // 3. Encrypt (AES-256-GCM)
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_buffer);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit nonce
    
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|e| format!("AES encryption failed: {}", e))?;

    // 4. Encode Output
    // Format: salt:nonce:ciphertext (all hex or base64? Hex is easier for debug, B64 is smaller)
    // Let's use HEX for consistency with existing codebase
    let salt_str = salt.as_str(); // This is B64 style from the library
    let nonce_hex = hex::encode(nonce);
    let cipher_hex = hex::encode(ciphertext);

    Ok(format!("{}:{}:{}", salt_str, nonce_hex, cipher_hex))
}

/// Decrypts data using a key derived from a password/pin via Argon2id.
/// Expects format: `salt_str:nonce_hex:ciphertext_hex`
pub fn decrypt_with_secret(secret: &str, formatted_data: &str) -> Result<Vec<u8>, String> {
    // 1. Parse Parts
    let parts: Vec<&str> = formatted_data.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid format. Expected: salt:nonce:ciphertext".to_string());
    }
    let salt_str = parts[0];
    let nonce_hex = parts[1];
    let cipher_hex = parts[2];

    // 2. Derive Key (Must match encryption params)
    let mut key_buffer = [0u8; 32];
    let argon2 = Argon2::default();
    
    argon2.hash_password_into(
        secret.as_bytes(),
        salt_str.as_bytes(),
        &mut key_buffer
    ).map_err(|e| format!("Argon2 derivation failed: {}", e))?;

    // 3. Decrypt
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_buffer);
    let cipher = Aes256Gcm::new(key);
    
    let nonce_bytes = hex::decode(nonce_hex).map_err(|_| "Invalid nonce hex")?;
    let cipher_bytes = hex::decode(cipher_hex).map_err(|_| "Invalid ciphertext hex")?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| format!("AES decryption failed (Wrong PIN/Password?): {}", e))?;

    Ok(plaintext)
}
