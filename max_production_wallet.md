# Max Production Wallet — Status & Reference

> **Max's wallet is LIVE on BlackBook L1 v5.0.0 with Shamir SSS 2-of-3.**
> **Last Updated: February 21, 2026**

---

## Wallet Details

| Field | Value |
|-------|-------|
| **Name** | Max |
| **Address** | `GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV` |
| **Balance** | 10,000 BB |
| **Password** | `BlackBook2026!` |
| **Wallet File** | `real_wallets/Max_v2_wallet.json` |
| **Wallet Version** | v2 (Shamir SSS) |
| **Key Scheme** | Ed25519 on BIP-39 seed |
| **Shard Split** | Shamir 2-of-3 (`sharks = "0.5"`, threshold = 2) |

---

## Shard Architecture

```
BIP-39 mnemonic → 32-byte seed → Ed25519 keypair
  │
  ├── Share A → Argon2id + AES-256-GCM encrypted → returned to client (wallet JSON)
  ├── Share B → Server master key encrypted → stored in ReDB + Supabase
  └── Share C → Hex plaintext → offline cold storage backup
```

**Any 2 of 3 shares** reconstruct the full secret. A single shard is cryptographically useless.

---

## Completed Milestones

- [x] **Secure Configuration**: `SERVER_MASTER_KEY` and `SUPABASE_JWT_SECRET` injected at runtime
- [x] **Wallet Created**: Shamir SSS 2-of-3 via `POST /wallet/create`
- [x] **Triple-Write Persistence**: Share B stored to ReDB + Supabase simultaneously
- [x] **Argon2id Password**: Password hashed with Argon2id, not plain text
- [x] **AES-256-GCM Encryption**: Share A encrypted before returning to client
- [x] **JSON Export**: `real_wallets/Max_v2_wallet.json` contains full credentials (dev only)
- [x] **Funded**: 10,000 BB balance (Dealer minted → Max)
- [x] **Transfers Verified**: Max → Alice 25 BB transfer completed and confirmed
- [x] **USDC SPL Token**: USDC mint/transfer/balance endpoints live
- [x] **SVM Always-On**: No feature flags — `cargo build` just works

---

## All Production Wallets (v2 — Shamir SSS)

| Name | Address | Balance | Password |
|------|---------|---------|----------|
| **Max** | `GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV` | **10,000 BB** | `BlackBook2026!` |
| Alice | `EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk` | 1,325 BB | `AlicePass2026!` |
| Bob | `mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd` | 1,650 BB | `BobPass2026!` |
| Apollo | `EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb` | 775 BB | `ApolloPass2026!` |
| Dealer | `3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp` | 98,750 BB | `DealerPass2026!` |

Wallet JSON files: `real_wallets/*_v2_wallet.json`

---

## Operations Reference

### Start the Server
```powershell
$env:SERVER_MASTER_KEY = "your_master_key_here"
$env:SUPABASE_JWT_SECRET = "your_jwt_secret_here"
cargo run
# Server starts on ports 8080 (HTTP) + 8899 (JSON-RPC)
```

### Check Balance
```bash
curl http://localhost:8080/balance/GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV
```

### Sign & Send Transfer (SSS)
```bash
curl -X POST http://localhost:8080/wallet/sign \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_id": "Max",
    "password": "BlackBook2026!",
    "to": "EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk",
    "amount": 25
  }'
```

### Check USDC Balance
```bash
curl http://localhost:8080/usdc/balance/GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV
```

---

## Verified Transfers

| From | To | Amount | Result |
|------|----|--------|--------|
| Dealer → Max | Initial funding | 10,025 BB | ✅ |
| Max → Alice | SSS-signed transfer | 25 BB | ✅ (Max 10,025→10,000, Alice 1,400→1,425) |

---

## Implementation Files

| File | Role |
|------|------|
| `src/wallet_unified/handlers.rs` | Wallet create/sign/share_b API handlers |
| `src/wallet_unified/security.rs` | Argon2id + AES-256-GCM encryption |
| `src/wallet_unified/migration.rs` | Hot upgrade v1→v2 balance migration |
| `src/wallet_unified/opaque_impl.rs` | OPAQUE password-authenticated key exchange |
| `src/svm/spl_token.rs` | USDC SPL Token engine (620 lines) |
| `src/main.rs` | All HTTP handlers + USDC bootstrap |

---

*Status: COMPLETE — wallet is live and funded on BlackBook L1 v5.0.0*
