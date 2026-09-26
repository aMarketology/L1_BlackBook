# Authentication & Signing

Every state-changing endpoint on BlackBook L1 is Ed25519-signed. This document
is the **canonical** reference for how to construct, sign, and send those
requests. Source: `src/auth.rs`.

---

## Key material

- Keys are **Ed25519**.
- **Public key**: 32 bytes, hex-encoded (64 chars) in the request body; also
  expressed as a **base58 Solana-style address** (the `from` / `wallet_address`
  field).
- **Signature**: 64 bytes, hex-encoded (128 chars).

The 32-byte public key and the base58 address are the **same bytes**:
`address = base58(pubkey_bytes)`.

---

## Request envelope

Signed POST bodies carry these fields (JSON):

```json
{
  "from":       "<base58 wallet address>",
  "public_key": "<32-byte hex pubkey>",
  "signature":  "<64-byte hex signature>",
  "timestamp":  "<unix seconds u64>",
  "nonce":      "<unique random string>"
}
```

> Some endpoints name the address field `wallet_address` instead of `from`.
> The envelope is otherwise identical.

## Signed message format

The signature is over the UTF-8 bytes of:

```text
"{ACTION}:{from}:{body_fields...}:{timestamp}:{nonce}"
```

Where `body_fields...` is the endpoint-specific middle portion (everything
between the address and the timestamp). Each endpoint's exact `ACTION` string
and body layout is listed in [Endpoint Reference](endpoints.md).

### Canonical messages by action

```
TRANSFER:        "{from}:{to}:{amount}:{ts}:{nonce}"
SWAP_BB_USDC:    "SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}"
SWAP_USDC_BB:    "SWAP_USDC_BB:{wallet}:{usdc_amount}:{ts}:{nonce}"
FAUCET:          "FAUCET:{addr}:{amount}:{ts}:{nonce}"
ESCROW_DEPOSIT:  "ESCROW_DEPOSIT:{wallet}:{amount_lamports}:{ts}:{nonce}"
ESCROW_WITHDRAW: "ESCROW_WITHDRAW:{market_id}:{wallet}:{amount_lamports}:{ts}:{nonce}"
DEPOSIT_REQUEST: "DEPOSIT_REQUEST:{wallet}:{external_tx_hash}:{amount_micro}:{asset}:{ts}:{nonce}"
CLAIM_DEPOSIT:   "CLAIM_DEPOSIT:{wallet}:{external_tx_hash}:{ts}:{nonce}"
WITHDRAW_REQUEST:"WITHDRAW_REQUEST:{wallet}:{solana_dest}:{wusdt_amount_micro}:{ts}:{nonce}"
VAULT_BURN:      "VAULT_BURN:{wallet}:{bb_lamports}:{ts}:{nonce}"
CLAIM_ATTESTATION:"CLAIM_ATTESTATION:{wallet}:{poh_slot}:{amount_usdt_micro}:{ts}:{nonce}"
NFT_TRANSFER:    "NFT_TRANSFER:{from}:{collection_id}:{token_id}:{from}:{to}:{ts}:{nonce}"

# Rollup Hub
ROLLUP_LOCK_BB:   "ROLLUP_LOCK_BB:{rollup_id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"
ROLLUP_SUBMIT_ROOT:"ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{ts}"
ROLLUP_EXIT:      "ROLLUP_EXIT:{rollup_id}:{asset_type}:{address}:{batch_id}:{ts}:{nonce}"
CONSUME_LOCK:     "CONSUME_LOCK:{rollup_id}:{lock_id}:{ts}"

# Oracle
ORACLE_SUBMIT:    "ORACLE_SUBMIT:{rollup_id}:{market_id}:{outcome}:{merkle_root_hex}:{batch_id}:{ts}:{nonce}"
ORACLE_DISPUTE:   "ORACLE_DISPUTE:{market_id}:{bb_stake_lamports}:{ts}:{nonce}"
ORACLE_VOTE:      "ORACLE_VOTE:{market_id}:{vote}:{ts}:{nonce}"
```

> **Exact string matters.** A single wrong character, extra space, or different
> integer formatting (e.g. `"1e6"` vs `"1000000"`) breaks the signature. Always
> format integers as plain decimal strings.

---

## Verification order (what the L1 actually checks)

`verify_signed_action` performs these steps in order — a request can fail at any:

1. **Decode pubkey** — must be 32 bytes of valid hex.
2. **Pubkey ↔ address binding** — `bs58_decode(from)` must equal the pubkey
   bytes. Prevents "sign with my key, claim another account" attacks.
3. **Decode signature** — must be 64 bytes of valid hex.
4. **Verify signature** over the reconstructed message.
5. **Timestamp freshness** — `now - timestamp ≤ 60s`, else `400 Request expired`.
6. **Replay protection** — atomic nonce check+insert; a reused nonce returns
   `409 Conflict`.

---

## The transfer signing scheme (special case)

`POST /transfer` and `/transfer/simple` use a **different** message layout than
the `"{ACTION}:{from}:..."` scheme — they sign a byte sequence:

```text
message = [chain_id_byte] || payload_bytes || "\n" || timestamp_decimal || "\n" || nonce
```

Where `payload = {"to": "...", "amount": <f64 BB>}` and `chain_id` is a `u8`
in the request body. The payload amount here is a `f64` **whole-BB** value (this
is the legacy display-boundary exception — internal accounting is still
lamports).

---

## Replay & nonce rules

- Nonce key: `"{ACTION}:{from}:{nonce}"` (or `transfer:{addr}:{nonce}`,
  `faucet:{addr}:{nonce}`).
- Stored in `state.used_nonces: DashMap<String, u64>` using the atomic `entry()`
  API — no TOCTOU window.
- Nonces are pruned when the map exceeds 100k entries (older than 120s).
- Generate a fresh nonce (e.g. `crypto.randomUUID()`) per request.

## Rate limiting

After auth, state-changing endpoints may hit the throttler:
`NetworkThrottler.max_per_window = 10` per wallet per window → HTTP `429`.

---

## Public key ↔ address helpers

```text
address (base58) = base58_encode(pubkey_bytes[0..32])
pubkey (hex)     = hex_encode(address decoded from base58)
```

Both must be supplied and must agree. The L1 derives one from the other and
rejects mismatches with `401 public_key does not match wallet_address`.
