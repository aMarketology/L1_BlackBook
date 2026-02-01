# 🔐 BlackBook Wallet Implementation Checklist
## Hidden Mnemonic Architecture with SSS + HashiCorp Vault

**Status:** 🚧 In Progress  
**Last Updated:** January 31, 2026  

---

## Quick Status

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Dependencies & Setup | ✅ Complete | 100% |
| Phase 2: Mnemonic Generation | ✅ Complete | 100% |
| Phase 3: Wallet Creation Flow | ⏳ Pending | 0% |
| Phase 4: Transaction Signing | ⏳ Pending | 0% |
| Phase 5: Export Recovery Phrase | ⏳ Pending | 0% |
| Phase 6: Migration Strategy | ⏳ Pending | 0% |

---

## Phase 1: Dependencies & Setup ✅

### HashiCorp Vault
- [x] Install Vault binary (`C:\Users\Allied Gaming\vault\vault.exe`)
- [x] Start dev server: `vault server -dev -dev-root-token-id="root"`
- [x] Enable KV v2 secrets engine at `blackbook/`
- [x] Store pepper: `blackbook/pepper`
- [x] Enable AppRole authentication
- [x] Create `wallet-server` role
- [x] Generate credentials (ROLE_ID + SECRET_ID)
- [x] Update `.env` with Vault credentials
- [ ] **Fix policy permissions** (currently getting "permission denied")

**Vault Credentials (Dev):**
```
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=26384ee8-46c6-53d1-7815-f4f171ea9cca
VAULT_SECRET_ID=83c33060-8235-896d-d8bc-7461910bac3a
Pepper: BlackBook_L1_Pepper_20260131134716_StrongKey_2026
```

**Test Command:**
```powershell
$env:VAULT_ADDR="http://127.0.0.1:8200"; $env:VAULT_TOKEN="root"
& "$env:USERPROFILE\vault\vault.exe" kv get blackbook/pepper
```

### Node.js Dependencies ✅
- [x] `bip39` - 12-word mnemonic generation
- [x] `hdkey` - HD wallet derivation (BIP-32/44)
- [x] `secrets.js-grempe` - Shamir's Secret Sharing
- [x] `node-vault` - Vault client
- [x] `argon2` - Password hashing
- [x] `tweetnacl` - Signing

### Rust Dependencies
- [ ] Add `bip39 = "2.0"` to Cargo.toml
- [ ] Add `bip32 = "0.5"` to Cargo.toml  
- [ ] Add `shamir = "3.0"` to Cargo.toml
- [ ] Run `cargo check` to verify

---

## Phase 2: Mnemonic Generation & Splitting 🚧

### Rust Implementation
- [ ] Create `src/wallet/mod.rs` (module declaration)
- [ ] Create `src/wallet/mnemonic.rs`:
  - [ ] `generate_entropy()` - 128-bit random bytes
  - [ ] `entropy_to_mnemonic()` - bytes → 12 words
  - [ ] `mnemonic_to_entropy()` - 12 words → bytes
  - [ ] `validate_mnemonic()` - check BIP-39 validity
- [ ] Create `src/wallet/sss_mnemonic.rs`:
  - [ ] `split_entropy()` - SSS 2-of-3 split
  - [ ] `reconstruct_entropy()` - combine shares
  - [ ] `derive_share_a()` - password + share seed
  - [ ] `generate_wallet()` - full pipeline

### Node.js Implementation
- [ ] Create `sdk/mnemonic-wallet.js`:
  - [ ] `generateEntropy()` - 128-bit random bytes
  - [ ] `entropyToMnemonic()` - bytes → 12 words
  - [ ] `mnemonicToEntropy()` - 12 words → bytes
  - [ ] `splitEntropy()` - SSS 2-of-3 split
  - [ ] `reconstructEntropy()` - combine shares
  - [ ] `deriveShareA()` - password-bound share
  - [ ] `deriveAddressFromMnemonic()` - BIP-44 path
  - [ ] `generateWallet()` - full pipeline

### Unit Tests
- [ ] `test_entropy_round_trip` - entropy → words → entropy
- [ ] `test_sss_reconstruct_ab` - Share A + B works
- [ ] `test_sss_reconstruct_ac` - Share A + C works
- [ ] `test_sss_reconstruct_bc` - Share B + C FAILS (no password)

---

## Phase 3: Wallet Creation Flow ⏳

### Backend (Rust)
- [ ] Update `POST /wallet/create` endpoint
- [ ] Generate mnemonic entropy (hidden from user)
- [ ] Split entropy into 3 shares
- [ ] Store Share B on L1 blockchain
- [ ] Encrypt Share C with Vault pepper
- [ ] Store encrypted Share C in Supabase
- [ ] Return only wallet address (NOT mnemonic)

### SDK (Node.js)
- [ ] Update `createZKPWallet()` function
- [ ] Integrate Vault pepper retrieval
- [ ] Test wallet creation end-to-end

### Validation
- [ ] Create wallet returns valid L1_ address
- [ ] Mnemonic is NOT logged or returned
- [ ] Share C is encrypted in Supabase

---

## Phase 4: Transaction Signing ⏳

### Flow Implementation
- [ ] User enters password
- [ ] Derive Share A from password
- [ ] Generate ZK-proof
- [ ] Request Share B from L1 (with proof)
- [ ] Reconstruct entropy → mnemonic
- [ ] Derive private key (BIP-44)
- [ ] Sign transaction
- [ ] ZEROIZE mnemonic & key from memory
- [ ] Submit signed tx to L1

### Memory Safety
- [ ] Add `zeroize` crate to Rust
- [ ] Implement secure memory wiping
- [ ] Test that secrets don't persist

---

## Phase 5: Export Recovery Phrase ⏳

### "Safety Hatch" Feature
- [ ] Create `POST /wallet/export` endpoint
- [ ] Require password + 2FA
- [ ] Reconstruct mnemonic from shares
- [ ] Return 12 words with security warning
- [ ] Audit log all export attempts

### MetaMask Compatibility
- [ ] Use BIP-44 path: `m/44'/60'/0'/0/0`
- [ ] Test: export → import to MetaMask → same address
- [ ] Document for users

---

## Phase 6: Migration Strategy ⏳

### Existing Wallets
- [ ] Identify wallets using old system (random key)
- [ ] Design migration flow
- [ ] Create `migrateToMnemonicWallet()` function
- [ ] Test with sample wallet
- [ ] Document upgrade process for users

---

## Commands Reference

### Start Vault Dev Server
```powershell
& "$env:USERPROFILE\vault\vault.exe" server -dev -dev-root-token-id="root"
```

### Fix Vault Policy (Run Once)
```powershell
$env:VAULT_ADDR="http://127.0.0.1:8200"
$env:VAULT_TOKEN="root"
$policy = @"
path "blackbook/data/*" {
  capabilities = ["read", "list"]
}
path "blackbook/metadata/*" {
  capabilities = ["read", "list"]
}
"@
$policy | Out-File -Encoding UTF8 "$env:TEMP\policy.hcl"
& "$env:USERPROFILE\vault\vault.exe" policy write blackbook-policy "$env:TEMP\policy.hcl"
```

### Test Vault Pepper (Root Token)
```powershell
$env:VAULT_ADDR="http://127.0.0.1:8200"
$env:VAULT_TOKEN="root"
& "$env:USERPROFILE\vault\vault.exe" kv get blackbook/pepper
```

### Test Node.js Vault Client
```powershell
cd sdk
node -e "require('dotenv').config({path:'../.env'}); require('./vault-client').getPepper().then(console.log)"
```

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    HIDDEN MNEMONIC FLOW                          │
└─────────────────────────────────────────────────────────────────┘

CREATION (User sees: "Creating wallet..."):
  1. Generate 128-bit entropy
  2. Entropy → 12-word mnemonic (NEVER shown)
  3. Split entropy into 3 shares (SSS 2-of-3)
  4. Share A: XOR with password hash (memory only)
  5. Share B: Store on L1 blockchain (ZK-gated)
  6. Share C: Encrypt with Vault pepper → Supabase

DAILY USE (User enters: password):
  1. Derive Share A from password
  2. ZK-proof → Get Share B from L1
  3. Reconstruct entropy → mnemonic → private key
  4. Sign transaction
  5. WIPE mnemonic & key from memory

EXPORT (User clicks: "Export Recovery Phrase"):
  1. Verify password + 2FA
  2. Reconstruct mnemonic from shares
  3. Display 12 words (user writes down)
  4. User can import to MetaMask/Ledger anytime
```

---

## Current Blockers 🚫

### 1. Vault Policy Permission Denied
**Issue:** AppRole token can authenticate but cannot read `blackbook/data/pepper`

**Status:** Need to run the "Fix Vault Policy" command above

**Symptom:**
```
🎫 Vault token acquired (expires in 3600s)
✅ Vault authentication successful
❌ Failed to retrieve pepper from Vault: permission denied
```

---

## Next Steps 👉

1. **Fix Vault policy** - Run the policy fix command
2. **Test Vault client** - Confirm `getPepper()` works
3. **Add Rust dependencies** - bip39, bip32 crates to Cargo.toml
4. **Create mnemonic-wallet.js** - Start Node.js implementation
5. **Write unit tests** - Verify entropy round-trip works

---

## Success Criteria ✅

When complete, users will:
- Create wallet with just email + password (no seed phrase shown)
- Sign transactions seamlessly (mnemonic reconstructed internally)
- Export 12-word phrase anytime (MetaMask compatible)
- Have full Web3 sovereignty while enjoying Web2 simplicity

---

**Document Version:** 2.0 (Checklist Format)  
**Author:** BlackBook L1 Core Team
