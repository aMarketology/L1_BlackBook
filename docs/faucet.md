# BlackBook L1 — Faucet

> **Endpoint:** `POST /faucet`
> **Max mint:** `0.1 BB` per request (server hard-caps `amount`)
> **Auth:** Ed25519 signature verification only

---

## How It Works

The faucet mints BB tokens to a wallet address. Because L1 is a pure signature-verifying blockchain, it requires a signed payload instead of a session token. The wallet (or a separate wallet service) must create a deterministic string, sign it with its Ed25519 private key, and submit it to the node.

---

## Step 1 — Sign the Payload

The client must construct exactly this message string:
`FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}`

| Property | Value |
|---|---|
| `wallet_address` | Base58 encoded Ed25519 public key |
| `amount` | Requested float amount (e.g., `0.10`) |
| `timestamp` | Current Unix time in seconds |
| `nonce` | Unique string (UUID or random hex) to prevent replay attacks |

The signature is generated over the ASCII bytes of this string.

---

## Step 2 — Call the Faucet

Submit the signed payload to the L1 node:

```http
POST /faucet
Content-Type: application/json

{
  "public_key": "3CTtQi...",
  "wallet_address": "3CTtQi...",
  "amount": 0.1,
  "timestamp": 1709403842,
  "nonce": "tx-992a-41d4-a716-44665",
  "signature": "3wKzHk8xG... (hex or base58 encoded signature)"
}
```

### Request Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `public_key` | string | Yes | The Base58 Ed25519 pubkey (must match `wallet_address`) |
| `wallet_address` | string | Yes | The account to continuously credit |
| `amount` | number | Yes | BB amount (Max 0.1 server-side) |
| `timestamp` | number | Yes | Current seconds (must be within ~5 mins) |
| `nonce` | string | Yes | Replay protection token |
| `signature` | string | Yes | Hex signature of the payload message |

### Success Response

```json
{
  "success": true,
  "minted": 0.1,
  "to": "3CTtQi...",
  "new_balance": 0.1
}
```

### Error Responses

| Status | Cause |
|---|---|
| `400` | Missing fields or malformed payload |
| `401` | Invalid Signature or pubkey mismatch |
| `403` | Nonce already used |
| `500` | Internal blockchain error |
