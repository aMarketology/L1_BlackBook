# BlackBook L1 - Next Steps

## 🎯 Priority #1: S+ Tier Wallet System (FROST + OPAQUE)

**Current Status:** Module structure complete, needs integration + testing

**Goal:** 100% operational MPC wallet where the private key **NEVER EXISTS**.

---

## Milestones to 100%

### 🚩 Milestone 1: OPAQUE Handshake (0% → 30%)

**Goal:** Server recognizes user without seeing password or hash.

| Task | Status | File |
|------|--------|------|
| Client generates `RegistrationRequest` | ⬜ TODO | `sdk/opaque-client.js` |
| Server stores `RegistrationRecord` without knowing password | ⬜ TODO | `src/unified_wallet/opaque_auth.rs` |
| Login flow derives identical `export_key` on both sides | ⬜ TODO | Integration test |
| **Shadow Attack Test**: DB contains only 32-byte blob, not crackable | ⬜ TODO | Manual verification |

**Pass Criteria:** Database inspection shows ONLY opaque records (random bytes), NO password hashes.

---

### 🚩 Milestone 2: FROST DKG (30% → 60%)

**Goal:** Create wallet where private key is born in pieces.

| Task | Status | File |
|------|--------|------|
| Generate Group Public Key (L1 Address) | ⬜ TODO | `src/unified_wallet/dkg.rs` |
| Create Share 1 (Device Shard - stays local) | ⬜ TODO | `sdk/frost-client.js` |
| Create Share 2 (Guardian Shard - sent to server) | ⬜ TODO | `src/unified_wallet/dkg.rs` |
| Store Share 2 inside OPAQUE-protected envelope | ⬜ TODO | `src/unified_wallet/storage.rs` |
| **Key Non-Existence Test** (see below) | ⬜ TODO | `tests/wallet_tests.rs` |

**Key Non-Existence Unit Test:**
```rust
#[test]
fn test_key_non_existence() {
    // 1. Generate FROST shards
    // 2. Assert that Share 1 != Private Key
    // 3. Assert that Share 2 != Private Key
    // 4. Assert that (Share 1 + Share 2) via addition DOES NOT equal Private Key 
    //    (TSS uses Lagrange interpolation, not simple addition!)
}
```

---

### 🚩 Milestone 3: Threshold Signing (60% → 90%)

**Goal:** Produce valid L1 signature using two partial signatures.

| Task | Status | File |
|------|--------|------|
| Client signs message with Share 1 | ⬜ TODO | `sdk/frost-client.js` |
| Server signs message with Share 2 | ⬜ TODO | `src/unified_wallet/tss.rs` |
| Client aggregates both partial signatures | ⬜ TODO | `sdk/frost-client.js` |
| L1 Validator accepts the aggregated signature | ⬜ TODO | Integration test |

**Integration Test Flow:**
```bash
# 1. Get the signing challenge
CHALLENGE=$(curl -X POST http://localhost:8080/wallet/login/start \
  -H "Content-Type: application/json" \
  -d '{"wallet_address": "bb_alice..."}')

# 2. Submit partial signature (The "Ceremony")
RESULT=$(curl -X POST http://localhost:8080/wallet/sign/finish \
  -H "Content-Type: application/json" \
  -d "{\"session_id\": \"$SESSION\", \"client_share\": {...}}")

# 3. Verify signature
echo $RESULT | jq '.signature_hex'
```

---

### 🚩 Milestone 4: Production Polish (90% → 100%)

| Task | Status | File |
|------|--------|------|
| Wire `/wallet/*` routes into main server | ⬜ TODO | `src/main_v3.rs` |
| Performance benchmarks pass | ⬜ TODO | `benches/` |
| SDK documentation | ⬜ TODO | `sdk/README.md` |
| Recovery flow (24-word mnemonic) | ⬜ TODO | `sdk/mnemonic-wallet.js` |

---

## 📊 Performance Targets

| Metric | Target | Why |
|--------|--------|-----|
| OPAQUE Latency | < 150ms | Must feel like normal login |
| Signing Latency | < 300ms | FROST is math-heavy; >1s too slow |
| RAM Overhead | < 50MB | No memory leaks during ceremony |

---

## 🗂️ Code Structure

```
src/unified_wallet/
├── mod.rs           ✅ Main module structure
├── types.rs         ✅ Error types, results, sessions
├── dkg.rs           ✅ FROST Distributed Key Generation
├── tss.rs           ✅ Threshold Signature Scheme
├── opaque_auth.rs   ✅ OPAQUE authentication
├── storage.rs       ✅ Guardian shard storage (encrypted)
└── handlers.rs      ✅ Axum HTTP handlers

sdk/
├── frost-client.js  ⬜ TODO: Client-side FROST
├── opaque-client.js ⬜ TODO: Client-side OPAQUE
└── mnemonic-wallet.js ✅ 24-word backup generation
```

---

## 🔧 Immediate Next Actions

1. **Wire unified_wallet handlers into main_v3.rs**
2. **Add unit tests for FROST DKG**
3. **Create SDK client for OPAQUE registration**
4. **Integration test: full wallet creation flow**

---

## Dependencies Added to Cargo.toml

```toml
# S+ Tier Wallet (FROST + OPAQUE)
frost-ed25519 = "2.0.0"
frost-core = "2.0.0"
opaque-ke = "3.0.0"
vsss-rs = "4.0"
```

---

## Security Guarantees When Complete

| Attack Vector | Result |
|---------------|--------|
| Server database breach | **0 funds stolen** (only have Shard 2) |
| User device stolen | **0 funds stolen** (need OPAQUE proof for Shard 2) |
| Both compromised | **0 funds stolen** (need password AND device) |
| User loses device | **Recoverable** with 24-word mnemonic |

---

*Last Updated: January 31, 2026*
