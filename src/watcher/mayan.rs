// ============================================================================
// MAYAN CROSS-CHAIN SWAP — CUSTOM PAYLOAD CODEC
// ============================================================================
//
// Wire format:  [0xBB] [0x01] [32-byte Ed25519 pubkey]  =  34 bytes total
//
// The 0xBB01 magic header versions the payload so future formats (e.g. with
// contest_id or referral codes) can coexist without breaking older deposits.
//
// Flow:
//   1. React frontend encodes the user's L1 wallet into this payload.
//   2. Frontend passes it as `customPayload` in the Mayan SDK swap call.
//   3. Mayan routes the swap; USDT lands in the Solana custody wallet.
//   4. CustodyWatcher fetches the tx, scans instructions for 0xBB01 magic.
//   5. Decoded wallet → auto-attribute the deposit → mint $BB.
//
// Config (env vars):
//   MAYAN_PROGRAM_ID   — Mayan Swap program ID on Solana (optional)
//   MAYAN_FORWARDER_ID — Mayan Forwarder program ID      (optional)
//
// If neither env var is set, the scanner still works — it searches ALL
// non-parsed instructions for the magic bytes, which is safe because the
// 0xBB01 prefix is unique to BlackBook payloads.
// ============================================================================

pub const MAYAN_PAYLOAD_MAGIC: [u8; 2] = [0xBB, 0x01];
pub const MAYAN_PAYLOAD_LEN: usize = 34;

pub struct MayanPayload {
    pub l1_wallet: String,
}

/// Mayan Swap program ID (env-overridable).
pub fn mayan_program_id() -> Option<String> {
    std::env::var("MAYAN_PROGRAM_ID").ok().filter(|s| !s.is_empty())
}

/// Mayan Forwarder program ID (env-overridable).
pub fn mayan_forwarder_id() -> Option<String> {
    std::env::var("MAYAN_FORWARDER_ID").ok().filter(|s| !s.is_empty())
}

/// Encode an L1 wallet address into a Mayan `customPayload`.
pub fn encode_custom_payload(l1_wallet: &str) -> Result<Vec<u8>, String> {
    let pubkey_bytes = bs58::decode(l1_wallet)
        .into_vec()
        .map_err(|e| format!("Invalid base58 wallet: {}", e))?;
    if pubkey_bytes.len() != 32 {
        return Err(format!("Wallet must be 32 bytes, got {}", pubkey_bytes.len()));
    }
    let mut payload = Vec::with_capacity(MAYAN_PAYLOAD_LEN);
    payload.extend_from_slice(&MAYAN_PAYLOAD_MAGIC);
    payload.extend_from_slice(&pubkey_bytes);
    Ok(payload)
}

/// Decode a Mayan `customPayload` back into an L1 wallet address.
pub fn decode_custom_payload(raw: &[u8]) -> Option<MayanPayload> {
    if raw.len() < MAYAN_PAYLOAD_LEN {
        return None;
    }
    if raw[0..2] != MAYAN_PAYLOAD_MAGIC {
        return None;
    }
    let pubkey_bytes = &raw[2..34];
    if pubkey_bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let wallet = bs58::encode(pubkey_bytes).into_string();
    match bs58::decode(&wallet).into_vec() {
        Ok(v) if v.len() == 32 => Some(MayanPayload { l1_wallet: wallet }),
        _ => None,
    }
}

/// Scan a byte slice for the `[0xBB, 0x01]` magic header and attempt to
/// decode the payload. Mayan may wrap the custom payload inside its own
/// instruction encoding, so we search all valid offsets.
pub fn scan_for_payload(data: &[u8]) -> Option<MayanPayload> {
    if data.len() < MAYAN_PAYLOAD_LEN {
        return None;
    }
    if let Some(p) = decode_custom_payload(data) {
        return Some(p);
    }
    for i in 1..=data.len().saturating_sub(MAYAN_PAYLOAD_LEN) {
        if data[i] == MAYAN_PAYLOAD_MAGIC[0]
            && i + 1 < data.len()
            && data[i + 1] == MAYAN_PAYLOAD_MAGIC[1]
        {
            if let Some(p) = decode_custom_payload(&data[i..]) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WALLET: &str = "5YNmS1R9nNSCDzb5a7mMJ1dwK9uHeAAF4CmPEwKgVWr8";

    #[test]
    fn encode_decode_round_trip() {
        let encoded = encode_custom_payload(TEST_WALLET).unwrap();
        assert_eq!(encoded.len(), MAYAN_PAYLOAD_LEN);
        assert_eq!(&encoded[0..2], &MAYAN_PAYLOAD_MAGIC);
        let decoded = decode_custom_payload(&encoded).unwrap();
        assert_eq!(decoded.l1_wallet, TEST_WALLET);
    }

    #[test]
    fn decode_rejects_short_payload() {
        assert!(decode_custom_payload(&[]).is_none());
        assert!(decode_custom_payload(&[0xBB, 0x01]).is_none());
        assert!(decode_custom_payload(&[0xBB, 0x01, 1, 2, 3]).is_none());
        assert!(decode_custom_payload(&vec![0xBB; 33]).is_none());
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut payload = vec![0xFF, 0x01];
        payload.extend_from_slice(&[1u8; 32]);
        assert!(decode_custom_payload(&payload).is_none());

        let mut payload2 = vec![0xBB, 0x02];
        payload2.extend_from_slice(&[1u8; 32]);
        assert!(decode_custom_payload(&payload2).is_none());
    }

    #[test]
    fn decode_rejects_zero_pubkey() {
        let mut payload = vec![0xBB, 0x01];
        payload.extend_from_slice(&[0u8; 32]);
        assert!(decode_custom_payload(&payload).is_none());
    }

    #[test]
    fn scan_finds_payload_at_offset_zero() {
        let encoded = encode_custom_payload(TEST_WALLET).unwrap();
        let found = scan_for_payload(&encoded).unwrap();
        assert_eq!(found.l1_wallet, TEST_WALLET);
    }

    #[test]
    fn scan_finds_payload_wrapped_with_prefix() {
        let inner = encode_custom_payload(TEST_WALLET).unwrap();
        let mut wrapped = vec![0xAA; 16]; // 16 bytes of prefix junk
        wrapped.extend_from_slice(&inner);
        wrapped.extend_from_slice(&[0x00; 8]); // suffix padding
        let found = scan_for_payload(&wrapped).unwrap();
        assert_eq!(found.l1_wallet, TEST_WALLET);
    }

    #[test]
    fn scan_returns_none_for_no_magic() {
        let garbage = vec![0x00; 100];
        assert!(scan_for_payload(&garbage).is_none());
    }

    #[test]
    fn encode_rejects_invalid_wallet() {
        assert!(encode_custom_payload("not_valid_base58!!!").is_err());
        assert!(encode_custom_payload("").is_err());
    }

    #[test]
    fn encode_rejects_wrong_length_key() {
        // "2Q" is valid base58 but decodes to < 32 bytes
        assert!(encode_custom_payload("2Q").is_err());
    }
}
