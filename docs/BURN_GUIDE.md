# Secure Token Burn Guide

This guide explains how to use the secure `/admin/burn` endpoint to permanently destroy BlackBook ($BB) tokens.
Unlike the previous dev-only endpoint, this V3 implementation **requires a cryptographic signature** from the token owner to authorize the burn.

## Endpoint Details

- **URL**: `POST /admin/burn`
- **Content-Type**: `application/json`
- **Method**: `POST`

## Request Payload

The request follows the standard BlackBook V2 SDK Signed Request format.

```json
{
  "public_key": "hex_encoded_public_key_32_bytes",
  "payload_hash": "sha256_hash_of_canonical_payload",
  "payload_fields": {
    "from": "L1_ADDRESS_HERE",
    "amount": 100.0,
    "timestamp": 1234567890,
    "nonce": "random_string"
  },
  "operation_type": "burn",
  "chain_id": 1,
  "request_path": "/admin/burn",
  "signature": "hex_encoded_ed25519_signature_64_bytes",
  "timestamp": 1234567890,
  "nonce": "random_string"
}
```

## Signing Process

To generate a valid request, follow these steps:

1.  **Construct Payload**: Create the `payload_fields` object.
2.  **Canonical String**: Concatenate fields with `|` delimiter:
    ```
    canonical = from|amount|timestamp|nonce
    // Example: "L1_ALICE|100.0|1700000000|xc9f87s"
    ```
3.  **Payload Hash**: Compute SHA-256 of the canonical string (hex output).
4.  **Signing Message**: Construct the message to sign:
    ```
    domain_prefix = "BLACKBOOK_L" + chain_id + request_path
    // Example: "BLACKBOOK_L1/admin/burn"
    
    message = domain_prefix + "\n" + payload_hash + "\n" + timestamp + "\n" + nonce
    ```
5.  **Sign**: Sign the `message` bytes using the owner's Ed25519 private key.
6.  **Submit**: Send the JSON with the signature and public key.

## Example (JavaScript SDK)

```javascript
const { sign } = require('tweetnacl');
const { createHash } = require('crypto');

function burnTokens(wallet, amount) {
    const timestamp = Date.now();
    const nonce = Math.random().toString(36).substring(7);
    
    // 1. Canonical
    const canonical = `${wallet.address}|${amount}|${timestamp}|${nonce}`;
    const payloadHash = createHash('sha256').update(canonical).digest('hex');
    
    // 2. Message
    const path = '/admin/burn';
    const domainPrefix = `BLACKBOOK_L1${path}`;
    const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
    
    // 3. Sign
    const signature = Buffer.from(sign.detached(
        Buffer.from(message),
        wallet.secretKey
    )).toString('hex');
    
    // 4. Send
    return axios.post('http://localhost:8080/admin/burn', {
        public_key: wallet.publicKey,
        payload_hash: payloadHash,
        payload_fields: {
            from: wallet.address,
            amount: amount,
            timestamp: timestamp,
            nonce: nonce
        },
        operation_type: 'burn',
        chain_id: 1,
        request_path: path,
        timestamp: timestamp,
        nonce: nonce,
        signature: signature
    });
}
```

## Security Guarantees

- **Ownership**: Only the holder of the private key matching `from` address can initiate a burn.
- **Replay Protection**: The `nonce` and `timestamp` prevent replaying old burn requests.
- **Integrity**: `payload_hash` ensures the amount and target cannot be tampered with.
