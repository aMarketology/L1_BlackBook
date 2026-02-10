# Max Production Wallet: 100% SSS Implementation Plan

This document outlines the roadmap to creating a fully production-ready, Shamir Secret Sharing (SSS) 2-of-3 wallet for the user "Max". This implementation ensures strict security compliance (FROST, Argon2 hashing, encrypted storage) while maintaining local JSON artifacts for testing and development speed.

## 🎯 Goal
Create a specialized, highly secure wallet for "Max" that demonstrates:
1. **2-of-3 SSS Splitting**: Key is never fully assembled on the server.
2. **Database Persistence**: All metadata (`pin_hash`, `root_pubkey`) stored in `user_vault`.
3. **Testing Accessibility**: Full credentials exported to `real_wallets/Max_wallet.json`.

---

## 📅 Milestones & Steps

### Milestone 1: Environment & Infrastructure 
**Objective**: Ensure the Layer 1 Server resembles a production environment.
- [x] **Secure Configuration**: Define `SERVER_MASTER_KEY` and `SUPABASE_JWT_SECRET`.
- [ ] **Runtime Injection**: Inject these secrets into the running process (Powershell) to prevent unauthorized access.
- [ ] **Service Restart**: Restart Layer 1 to apply new security config.

### Milestone 2: Wallet Generation (FROST)
**Objective**: Generate the mathematical components of the wallet.
- [ ] **Entropy Generation**: Use CSPRNG to create the master secret.
- [ ] **Sharding**: Split secret into 3 shares:
  - **Share A**: User's Active Key (Password Encrypted).
  - **Share B**: Server's Co-Signing Key (Master Key Encrypted).
  - **Share C**: Offline Recovery Key (Cold Storage).

### Milestone 3: Data Persistence Strategy
**Objective**: Persist data to Supabase `user_vault` with correct schema.
- [ ] **Schema Validation**: Ensure `user_vault` columns (`pin_hash`, `daily_spending_limit`) match Rust structs.
- [ ] **Atomic Upsert**: Use `resolution=merge-duplicates` to update existing Max profile if he exists.
- [ ] **Validation**: Confirm `pin_hash` is Argon2 validated, not plain text.

### Milestone 4: Artifact Generation (Testing)
**Objective**: Export credentials for integration tests.
- [ ] **JSON Export**: Write `real_wallets/Max_wallet.json` containing:
  - Full Mnemonic (for emergency usage).
  - Encrypted Share A.
  - Plaintext Password (DEV ONLY - for automated tests).
  - Wallet Address & Public Keys.

---

## 🚀 Execution Guide (PowerShell)

### Step 1: Stop Existing Server
Ensure no stale processes are locking the ports.
```powershell
Stop-Process -Name "layer1" -Force -ErrorAction SilentlyContinue
```

### Step 2: Inject Secrets & Start Server
Load secrets from `.env` and launch the server in the background.
```powershell
$env:SERVER_MASTER_KEY = "your_master_key_here" # (Loaded dynamically from .env)
$env:SUPABASE_JWT_SECRET = "your_jwt_secret_here"
./target/debug/layer1.exe
``

### Step 3: Run Generation Script
Execute the specialized `create_real_wallets` script targeting Max.
```powershell
cargo run --example create_real_wallets

```
