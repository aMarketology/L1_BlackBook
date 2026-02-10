# BlackBook Wallet Implementation Plan

## Current State Assessment (Feb 8, 2026)

### ✅ Completed Components
1. **FROST 2-of-3 Threshold Signatures** - Working implementation using `frost-ed25519`
2. **BIP-39 Mnemonic Generation** - 256-bit entropy with 24-word recovery phrase
3. **ReDB Storage Layer** - Production-ready persistence for Share B
4. **Security Module** (`security.rs`) - Argon2id + AES-256-GCM encryption/decryption
5. **Basic Wallet State** - UnifiedWalletState with blockchain storage

### 🚧 In Progress
1. **Handlers.rs** - Partially updated with new request types
2. **Module Registration** - `security` module added to `mod.rs`

### ❌ Missing Components
1. **Threshold Logic System** - PIN requirement determination
2. **User Configuration Storage** - ReDB tables for user settings
3. **PIN-Gated Share B Endpoint** - Separate endpoint for high-value transactions
4. **Shard A Client-side Encryption Flow** - Password-based protection
5. **New Device Sync Endpoint** - Using B + C to generate new A
6. **Password Change/Re-encryption Endpoint**

---

## Implementation Roadmap

### Phase 1: Core Shard Storage & Retrieval ⚡ (Current Focus)

#### Milestone 1.1: Complete Create Wallet Endpoint
**File**: `src/wallet_unified/handlers.rs`

**Implementation**:
```rust
POST /wallet/create
Body: { "password": "user_pass", "pin": "1234" }
Response: {
  "wallet_id": "...",
  "mnemonic": "24 words...",
  "share_a": "salt:nonce:cipher", // Encrypted with password
  "share_a_is_encrypted": true,
  "share_c": "hex_encoded", // For Supabase Vault
  "public_key": "...",
  "address": "..."
}
```

**Logic**:
- Generate BIP-39 mnemonic (24 words)
- FROST 2-of-3 keygen (IDs: 1=A, 2=B, 3=C)
- **Shard A**: Encrypt with `password` via Argon2+AES → Return to client
- **Shard B**: Encrypt with `pin` via Argon2+AES → Store in ReDB
- **Shard C**: Return as hex (client uploads to Supabase Vault)
- Store PublicKeyPackage in ReDB

**Success Criteria**:
- ✅ Wallet creation returns encrypted Shard A
- ✅ Shard B stored encrypted in ReDB
- ✅ Shard C returned for Vault upload
- ✅ `cargo test` passes

---

#### Milestone 1.2: Get Share B Endpoint (Basic)
**File**: `src/wallet_unified/handlers.rs`

**Implementation**:
```rust
POST /wallet/share_b
Body: { "wallet_id": "..." }
Response: { "encrypted_share_b": "salt:nonce:cipher" }
```

**Logic**:
- Fetch encrypted Shard B from ReDB
- Return as-is (encrypted with PIN)
- Client decrypts using their PIN

**Success Criteria**:
- ✅ Endpoint returns encrypted blob
- ✅ Test: Create wallet → Fetch Share B → Decrypt with PIN → Match original

---

#### Milestone 1.3: Sign Transaction Endpoint
**File**: `src/wallet_unified/handlers.rs`

**Implementation**:
```rust
POST /wallet/sign
Body: {
  "wallet_id": "...",
  "message": "Hello World",
  "share_a": "encrypted_a",
  "password": "user_pass",
  "pin": "1234"
}
Response: { "signature": "..." }
```

**Logic**:
- Decrypt Share A using password
- Fetch + Decrypt Share B using PIN
- FROST Round 1: Generate commitments
- FROST Round 2: Generate signature shares
- Aggregate signature
- Zeroize shards from memory

**Success Criteria**:
- ✅ Signature verifies against public key
- ✅ Test: Create → Sign → Verify
- ✅ Memory wiped after signing

---

### Phase 2: Threshold Logic & PIN Gating 🔐

#### Milestone 2.1: User Configuration Storage
**File**: `src/storage/mod.rs`

**Add ReDB Table**:
```rust
const USER_CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("user_config");

struct UserConfig {
    pub wallet_id: String,
    pub pin_threshold: u64, // Amount in smallest unit
    pub known_addresses: Vec<String>,
}
```

**New Methods**:
- `store_user_config(wallet_id, config)`
- `get_user_config(wallet_id)`

**Success Criteria**:
- ✅ Config persists across restarts
- ✅ Default threshold = 1_000_000 (arbitrary)

---

#### Milestone 2.2: Threshold Check Logic
**File**: `src/wallet_unified/handlers.rs`

**New Endpoint**:
```rust
POST /wallet/check_threshold
Body: { "wallet_id": "...", "amount": 5000, "recipient": "addr..." }
Response: { "requires_pin": true }
```

**Logic**:
```rust
if amount > config.pin_threshold || !config.known_addresses.contains(recipient) {
    return true; // High-value gate
} else {
    return false; // Low-value gate
}
```

**Success Criteria**:
- ✅ Small tx to known address = false
- ✅ Large tx = true
- ✅ Unknown recipient = true

---

#### Milestone 2.3: System Pepper (Low-Value Fast Path)
**File**: `src/wallet_unified/handlers.rs`

**Environment Variable**: `BLACKBOOK_SYSTEM_PEPPER=<random_32_bytes>`

**New Endpoint**:
```rust
POST /wallet/share_b_fast
Body: { "wallet_id": "...", "jwt": "..." }
Response: { "decrypted_share_b": "json_blob" }
```

**Logic**:
- Verify JWT (placeholder for now)
- Check if request is low-value
- Decrypt Share B server-side using SYSTEM_PEPPER
- Return decrypted shard (over HTTPS)

**Success Criteria**:
- ✅ Fast signing (no PIN prompt)
- ✅ Only works for low-value tx

---

### Phase 3: Advanced Workflows 🔄

#### Milestone 3.1: Password Change & Re-encryption
**Endpoint**: `POST /wallet/change_password`

**Flow**:
1. User provides: `old_password`, `new_password`, `pin`
2. Decrypt Share A with `old_password`
3. Fetch + Decrypt Share B with `pin`
4. Re-encrypt Share A with `new_password`
5. Return new Share A

---

#### Milestone 3.2: New Device Sync (B + C Recovery)
**Endpoint**: `POST /wallet/sync_device`

**Flow**:
1. User provides: `wallet_id`, `share_c` (from Vault), `pin`, `new_password`
2. Decrypt Share B with `pin`
3. Decrypt Share C with Vault credentials
4. Combine B + C to reconstruct secret
5. Generate new Share A set
6. Encrypt with `new_password`
7. Return new Share A

---

#### Milestone 3.3: Emergency Recovery (A Lost, B + C Available)
**Endpoint**: `POST /wallet/recover`

**Same as 3.2** - Uses Shard B + C to regenerate the wallet

---

### Phase 4: Security Hardening 🛡️

#### Milestone 4.1: Rate Limiting
- Max 5 PIN attempts per hour per wallet_id
- Lockout after 10 failed attempts

#### Milestone 4.2: Audit Logging
- Log all Share B fetches
- Log all high-value transaction attempts
- Store in ReDB with timestamp

#### Milestone 4.3: Memory Safety
- Use `zeroize` crate for all key material
- Wrap shares in `Zeroizing<Vec<u8>>`
- Audit for key leakage

---

## Testing Strategy

### Unit Tests
- ✅ `security::encrypt_with_secret` roundtrip
- ✅ FROST 2-of-3 signing
- ✅ Threshold logic (amount + address checking)

### Integration Tests
1. **Happy Path**:
   - Create wallet → Sign low-value tx → Sign high-value tx → Verify
2. **Password Change**:
   - Create → Change password → Sign with new password
3. **Device Sync**:
   - Create on Device A → Sync to Device B → Sign on Device B
4. **Recovery**:
   - Create → Simulate phone loss → Recover with B + C → Sign

### Load Tests
- 1000 concurrent wallet creations
- 10,000 signatures/sec

---

## Current Implementation Files

### 📁 `src/wallet_unified/`
- ✅ `mod.rs` - Module exports
- ✅ `security.rs` - Argon2 + AES-GCM
- 🚧 `handlers.rs` - Endpoints (80% complete)

### 📁 `src/storage/`
- ✅ `mod.rs` - ReDB storage for Share B
- ⏳ TODO: Add `USER_CONFIG` table

### 📁 `tests/`
- ✅ `wallet_tests.rs` - Basic FROST tests
- ⏳ TODO: `wallet_security_tests.rs`
- ⏳ TODO: `wallet_threshold_tests.rs`

---

## Dependencies Status

```toml
[dependencies]
frost-ed25519 = "2.2.0"      # ✅ Installed
bip39 = "2.0"                # ✅ Installed
argon2 = "0.5"               # ✅ Installed (Phase 1)
aes-gcm = "0.10"             # ✅ Installed (Phase 1)
rand = "0.8.5"               # ✅ Installed (Phase 1)
# zeroize = "1.7"            # ⏳ TODO (Phase 4)
```

---

## Timeline

### Week 1 (Current)
- ✅ Day 1: Complete Phase 1.1-1.3 (Core endpoints)
- Day 2: Phase 2.1-2.2 (Threshold logic)
- Day 3: Phase 2.3 (System Pepper)

### Week 2
- Day 4-5: Phase 3 (Advanced workflows)
- Day 6-7: Phase 4 (Security hardening)

---

## Success Definition

**BlackBook Wallet is complete when**:
1. ✅ User can create wallet with password + PIN
2. ✅ Shard A encrypted client-side (returned)
3. ✅ Shard B encrypted server-side (PIN-gated)
4. ✅ Shard C ready for Supabase Vault
5. ✅ Signing works with A + B (PIN required for high-value)
6. ✅ Password change works
7. ✅ New device sync works (B + C → new A)
8. ✅ All tests pass
9. ✅ No HashiCorp Vault dependency

---

## Next Actions (Immediate)

1. Complete `create_hybrid_wallet` implementation in handlers.rs
2. Add `get_share_b` endpoint
3. Add basic `sign_transaction` endpoint
4. Write integration test: create → fetch → sign
5. Verify memory safety

**Let's ship Phase 1 today! 🚀**
