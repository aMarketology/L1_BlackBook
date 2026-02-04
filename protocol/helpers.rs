//! Layer1 Helper Functions (V2 - Pure Signature Auth)
//!
//! Common utilities used across route handlers to reduce code duplication.
//! NO Supabase, NO JWT - just pure cryptographic signature verification.
//!
//! NOTE: Many utilities here are for future use in routes. Suppressing dead_code
//! warnings until they're wired into the API.
#![allow(dead_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};

// ============================================================================
// ADDRESS GENERATION
// ============================================================================

/// Generate L1 address from Ed25519 public key
/// Format: L1_ + 40 hex chars (e.g., L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD)
/// 
/// Algorithm:
/// 1. SHA256(public_key) -> 32 bytes
/// 2. Take first 20 bytes (40 hex chars) = 160-bit security (same as Bitcoin RIPEMD160)
/// 3. Prepend "L1_" -> L1_XXXX...XXXX (43 chars total)
/// 
/// Properties:
/// - Deterministic (same pubkey = same address)
/// - Collision-resistant (160-bit space = 1.46 × 10^48 addresses)
/// - Human readable (43 characters, similar to Ethereum)
/// - L1_ prefix for Layer 1, L2_ prefix for Layer 2
/// - L1 and L2 addresses share the same hash (just different prefix)
/// 
/// # Example
/// ```
/// let pubkey_hex = "c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705";
/// let address = generate_l1_address(pubkey_hex);
/// // Returns: "L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD"
/// ```
pub fn generate_l1_address(public_key_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_hex.as_bytes());
    let hash = hasher.finalize();
    
    // Take first 20 bytes (40 hex characters) = 160-bit security (same as Bitcoin RIPEMD160)
    let address_hash: String = hash.iter()
        .take(20)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .to_uppercase();
    
    format!("L1_{}", address_hash)
}

/// Validate L1 address format
/// Valid formats:
/// - bb_XXXX...XXXX (35 chars: bb_ + 32 hex lowercase) - unified wallet (mnemonic-based)
/// - L1_XXXX...XXXX (43 chars: L1_ + 40 hex uppercase) - FROST institutional wallet
/// - L1XXXX...XXXX (42 chars: L1 + 40 hex) - legacy format without underscore
/// - Raw public key hex (64 chars)
pub fn validate_l1_address(address: &str) -> bool {
    if address.len() == 35 && address.starts_with("bb_") {
        // Unified wallet format: bb_ + 32 hex chars (lowercase)
        address[3..].chars().all(|c| c.is_ascii_hexdigit() && c.is_lowercase())
    } else if address.len() == 43 && address.starts_with("L1_") {
        // FROST format: L1_ + 40 hex chars (uppercase)
        address[3..].chars().all(|c| c.is_ascii_hexdigit())
    } else if address.len() == 42 && address.starts_with("L1") {
        // Legacy format without underscore
        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    } else if address.len() == 64 {
        // Raw public key hex
        address.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

// ============================================================================
// WALLET VALIDATION HELPERS
// ============================================================================

/// Error returned when wallet validation fails
#[derive(Debug, Clone)]
pub struct WalletRequired {
    pub message: String,
}

impl WalletRequired {
    pub fn new(msg: &str) -> Self {
        Self { message: msg.to_string() }
    }
}

/// Validates that a wallet address is valid and returns it.
/// With signature-based auth, we derive wallet address from public key.
/// This is a simple validation helper.
/// 
/// # Example
/// ```ignore
/// validate_wallet_address("bb_6b7665632e4d8284c9ff288b6cab2f94")?;
/// ```
pub fn validate_wallet_address(address: &str) -> Result<String, String> {
    if address.is_empty() {
        Err("Wallet address cannot be empty".to_string())
    } else if !address.starts_with("bb_") && !address.starts_with("0x") && !address.starts_with("L1_") {
        Err("Invalid wallet address format".to_string())
    } else {
        Ok(address.to_string())
    }
}

// ============================================================================
// JSON RESPONSE HELPERS
// ============================================================================

/// Standard success response structure
#[derive(Debug, Clone, Serialize)]
pub struct SuccessResponse<T: Serialize> {
    pub success: bool,
    #[serde(flatten)]
    pub data: T,
}

/// Standard error response structure
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
    pub message: String,
}

/// Creates a JSON success response with arbitrary data.
/// 
/// # Example
/// ```ignore
/// json_success_data(serde_json::json!({
///     "balance": 100.0,
///     "wallet": "0x123..."
/// }))
/// ```
pub fn json_success_data<T: Serialize>(data: T) -> warp::reply::Json {
    warp::reply::json(&serde_json::json!({
        "success": true,
        "data": data
    }))
}

/// Creates a simple JSON success response with a message.
/// 
/// # Example
/// ```ignore
/// json_success("wallet_created", "Wallet created successfully")
/// ```
pub fn json_success(action: &str, message: &str) -> warp::reply::Json {
    warp::reply::json(&serde_json::json!({
        "success": true,
        "action": action,
        "message": message,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Creates a JSON error response.
/// 
/// # Example
/// ```ignore
/// json_error("invalid_amount", "Amount must be greater than 0")
/// ```
pub fn json_error(error_code: &str, message: &str) -> warp::reply::Json {
    warp::reply::json(&serde_json::json!({
        "success": false,
        "error": error_code,
        "message": message,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Creates a JSON error response with additional details.
pub fn json_error_with_details<T: Serialize>(error_code: &str, message: &str, details: T) -> warp::reply::Json {
    warp::reply::json(&serde_json::json!({
        "success": false,
        "error": error_code,
        "message": message,
        "details": details,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ============================================================================
// TIMESTAMP HELPERS
// ============================================================================

/// Formats a Unix timestamp into a human-readable string.
/// 
/// # Example
/// ```ignore
/// let formatted = format_timestamp(1701864000);
/// // Returns: "2023-12-06 12:00:00 UTC"
/// ```
pub fn format_timestamp(timestamp: u64) -> String {
    match chrono::DateTime::from_timestamp(timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Unknown date".to_string()
    }
}

/// Gets the current Unix timestamp.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Formats a relative time description (e.g., "2 hours ago").
pub fn format_relative_time(timestamp: u64) -> String {
    let now = current_timestamp();
    let diff = now.saturating_sub(timestamp);
    
    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}

// ============================================================================
// STRING HELPERS
// ============================================================================

/// Safely slices a string to a maximum length without panicking.
/// 
/// # Example
/// ```ignore
/// let short = safe_slice("long_session_id_here", 8);
/// // Returns: "long_ses"
/// ```
pub fn safe_slice(s: &str, max_len: usize) -> String {
    if s.len() >= max_len {
        s[..max_len].to_string()
    } else {
        s.to_string()
    }
}

/// Truncates a wallet address for display (e.g., "0x1234...5678").
pub fn truncate_address(address: &str, prefix_len: usize, suffix_len: usize) -> String {
    if address.len() <= prefix_len + suffix_len + 3 {
        address.to_string()
    } else {
        format!(
            "{}...{}",
            &address[..prefix_len],
            &address[address.len() - suffix_len..]
        )
    }
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/// Validates that an amount is positive.
pub fn validate_amount(amount: f64) -> Result<(), String> {
    if amount <= 0.0 {
        Err("Amount must be greater than 0".to_string())
    } else {
        Ok(())
    }
}

/// Validates content length for social posts.
pub fn validate_post_content(content: &str) -> Result<(), String> {
    if content.is_empty() {
        Err("Content cannot be empty".to_string())
    } else if content.len() > 280 {
        Err("Content must be 280 characters or less".to_string())
    } else {
        Ok(())
    }
}

/// Checks if an identifier looks like a wallet address (starts with 0x or L1_).
pub fn is_wallet_address(identifier: &str) -> bool {
    identifier.starts_with("0x") || 
    identifier.starts_with("L1_") ||
    identifier.len() == 42 // Ethereum-style address length
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        let ts = 1701864000;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2023"));
        assert!(formatted.contains("UTC"));
    }

    #[test]
    fn test_safe_slice() {
        assert_eq!(safe_slice("hello world", 5), "hello");
        assert_eq!(safe_slice("hi", 5), "hi");
        assert_eq!(safe_slice("", 5), "");
    }

    #[test]
    fn test_truncate_address() {
        let addr = "0x1234567890abcdef1234567890abcdef12345678";
        let truncated = truncate_address(addr, 6, 4);
        assert_eq!(truncated, "0x1234...5678");
    }

    #[test]
    fn test_validate_amount() {
        assert!(validate_amount(100.0).is_ok());
        assert!(validate_amount(0.01).is_ok());
        assert!(validate_amount(0.0).is_err());
        assert!(validate_amount(-10.0).is_err());
    }

    #[test]
    fn test_validate_post_content() {
        assert!(validate_post_content("Hello!").is_ok());
        assert!(validate_post_content("").is_err());
        let long_content = "x".repeat(300);
        assert!(validate_post_content(&long_content).is_err());
    }

    #[test]
    fn test_is_wallet_address() {
        assert!(is_wallet_address("0x1234567890abcdef1234567890abcdef12345678"));
        assert!(is_wallet_address("L1_user123_wallet"));
        assert!(!is_wallet_address("username"));
        assert!(!is_wallet_address("@handle"));
    }

    #[test]
    fn test_format_relative_time() {
        let now = current_timestamp();
        assert_eq!(format_relative_time(now), "just now");
        assert!(format_relative_time(now - 120).contains("minutes"));
        assert!(format_relative_time(now - 7200).contains("hours"));
        assert!(format_relative_time(now - 172800).contains("days"));
    }
}
