# BlackBook L1 Simplification — What We're Axing

## The Core Principle

**L1 is a pure signature-verifying blockchain.** It does NOT sign transactions, hold private keys, reconstruct seeds, or manage sessions. That is the wallet's job.

Everything below violates this principle and gets removed from L1.

---

## ALREADY DONE (commit `a3322bb`)

These changes were already applied in the last session:

| Change | Status |
|--------|--------|
| `session_store` field removed from `AppState` | ✅ Done |
| `SessionStore` import removed from `main.rs` | ✅ Done |
| `mod wallet_unified` removed from `main.rs` | ✅ Done |
| `UnifiedWalletState` import removed from `main.rs` | ✅ Done |
| Faucet handler refactored from SSS session → Ed25519 signature | ✅ Done |
| Wallet router merge removed from `build_router()` | ✅ Done |
| Session store creation + sweeper task removed from `main()` | ✅ Done |
| Unified wallet state creation removed from `main()` | ✅ Done |
| Banner updated: "SSS 2-of-3 + ZKP" → "Ed25519 Signature Verification" | ✅ Done |
| Wallet endpoint log block removed from startup output | ✅ Done |
| File header updated to "PURE SIGNATURE-VERIFYING BLOCKCHAIN" | ✅ Done |

---

## STILL REMAINING — What Gets Axed

### 1. `src/wallet_unified/` — THE ENTIRE FOLDER (1,354 lines)

This folder contains server-side wallet logic. **None of it belongs in L1.**

| File | Lines | What It Does | Why It Goes |
|------|-------|-------------|-------------|
| `handlers.rs` | 675 | Wallet create/login/logout, SSS transfers, session transfers, shard retrieval, SSS verify | L1 doesn't create wallets or hold seeds |
| `session_store.rs` | 253 | DashMap-based in-memory seed cache, 15-min TTL, background sweeper | L1 doesn't cache private keys |
| `security.rs` | 106 | Argon2id KDF + AES-256-GCM encrypt/decrypt for shard encryption | Wallet-side crypto, not blockchain |
| `migration.rs` | 316 | Balance migration between old→new wallet addresses | **EXCEPTION — see below** |
| `mod.rs` | 4 | Module declarations | Goes with the folder |

#### What each handler did (now removed):
```
POST /wallet/create      → BIP-39 mnemonic → Ed25519 keypair → Shamir 2-of-3 split → store Share B in ReDB
POST /wallet/login       → Decrypt Share A + Share B → reconstruct seed → cache in session store
POST /wallet/logout      → Wipe seed from memory, revoke session
POST /transfer           → Decrypt shares, reconstruct seed, sign tx server-side, execute transfer
POST /transfer/session   → Lookup cached seed by session_token, sign tx server-side, execute transfer
POST /wallet/secure/shard-b → Return encrypted Share B from ReDB
POST /wallet/verify-sss  → Verify 2-of-3 shard reconstruction matches wallet address
```

**All 7 routes are gone from L1.** Wallets will be a separate service.

#### `migration.rs` — Special Case
This file handles admin balance migration (`POST /admin/wallet/migrate`). It only depends on `storage::ConcurrentBlockchain` (not on sessions, shards, or SSS). Two options:
- **Option A:** Move it into `src/migration.rs` as a standalone L1 module (keeps the admin endpoint)
- **Option B:** Remove it entirely (migration is a one-time operation that's already been run)

---

### 2. `src/lib.rs` — One Line

```rust
pub mod wallet_unified; // SSS 2-of-3 Shamir wallets  // ← DELETE THIS
```

The lib.rs still exports `wallet_unified` for test/benchmark crates. Must be removed.

---

### 3. `src/main.rs` — One Remaining Reference

```rust
// Line 1004, inside wallet_migrate_handler:
use wallet_unified::migration::*;
```

This `use` statement will break compilation since `wallet_unified` is no longer a module. Fix depends on whether we keep or remove the migration handler.

---

### 4. `src/storage/mod.rs` — Wallet-Specific Tables & Methods

These ReDB tables and methods exist solely for wallet shard storage:

| Item | What It Is |
|------|-----------|
| `WALLET_SHARD_B` table | ReDB table storing encrypted Share B blobs |
| `WALLET_ED25519_PUBKEY` table | ReDB table storing wallet public keys |
| `store_shard_b()` | Write Share B to ReDB |
| `get_shard_b()` | Read Share B from ReDB |
| `store_ed25519_pubkey()` | Write pubkey to ReDB |
| `AuthType::SSS` variant | SSS auth type in ledger entries |
| `AuthType::SessionKey` variant | Session-based auth type |
| `transfer_with_receipt()` | Transfer with auth-type tracking (used by wallet handlers) |

**Decision:** These can stay dormant in storage for now (they don't hurt L1 and the ReDB tables already exist on disk). Removing them is a cosmetic cleanup, not a functional requirement. The wallet service will need its own storage later.

---

### 5. SDK Files — Wallet-Specific

These JavaScript SDK files call wallet endpoints that no longer exist on L1:

| File | Lines | What It Does |
|------|-------|-------------|
| `sdk/wallet_sdk.js` | ~400 | Full SSS wallet SDK (create, login, transfer, faucet, verify, recover) |
| `sdk/test_wallet_sdk.mjs` | ~100 | Test script for wallet SDK |
| `sdk/test_wallet_collision.mjs` | ~170 | Collision test for shard uniqueness |
| `sdk/test/test_wallet_sdk.mjs` | ~100 | Another wallet test |
| `sdk/test/test_wallet_collision.mjs` | ~100 | Duplicate collision test |

**Decision:** These move to the wallet service repo, not deleted. They still work — just against the wallet service instead of L1.

---

### 6. Documentation — Outdated References

| File | Issue |
|------|-------|
| `docs/faucet.md` | References SSS session flow — needs update to Ed25519 |
| `docs/SSS_and_localsigning.md` | Describes SSS as part of L1 — needs to reference wallet service |
| `docs/UNIFIED_WALLET.md` | Full wallet architecture doc — moves to wallet service |
| `docs/ENDPOINT_GUIDE.md` | Lists wallet endpoints — needs cleanup |

---

## WHAT STAYS IN L1 (29 routes → 22 routes after cleanup)

### Pure Blockchain (read-only)
```
GET  /health                     → Node health, block production status
GET  /stats                      → Pipeline, Gulf Stream, parallel execution stats
GET  /balance/:address           → Account balance lookup
GET  /ledger                     → Transaction history (ASCII art)
```

### Signature-Verified Writes
```
POST /transfer/simple            → Ed25519 signed transfer (already done ✅)
POST /faucet                     → Ed25519 signed faucet mint (already done ✅)
POST /escrow/deposit             → Ed25519 signed escrow lock (already done ✅)
POST /escrow/submit-state-root   → Ed25519 signed L2 merkle root (already done ✅)
POST /escrow/withdraw            → Ed25519 signed + merkle proof withdrawal (already done ✅)
```

### Consensus Infrastructure
```
GET  /poh/status                 → PoH clock state
GET  /poh/block/latest           → Latest finalized block
GET  /poh/block/:slot            → Block by slot number
GET  /poh/tx/:tx_id/status       → Transaction finality status
GET  /consensus/tower            → Tower BFT vote tower
GET  /turbine/status             → Turbine shred propagation
POST /sealevel/submit            → Gulf Stream parallel execution
```

### Admin
```
POST /admin/mint                 → Mint $BB (dealer)
POST /admin/burn                 → Burn $BB (dealer)
POST /admin/dealer/settle        → Batch L2 settlement
POST /admin/wallet/migrate       → Balance migration (keep or remove?)
GET  /admin/accounts             → All account balances
GET  /admin/security/stats       → Throttler, circuit breaker, fee market
```

### USDC SPL Token
```
POST /admin/usdc/mint            → Mint USDC to wallet
POST /usdc/transfer              → Transfer USDC
GET  /usdc/balance/:address      → USDC balance
GET  /usdc/supply                → Total USDC supply
GET  /usdc/accounts/:address     → Token accounts
```

---

## EXECUTION PLAN (Step by Step)

### Step 1: Fix `wallet_migrate_handler` dependency
Move `migration.rs` out of `wallet_unified/` into `src/migration.rs` as a standalone module. Update the `use` in `main.rs`.

### Step 2: Remove `wallet_unified` from `lib.rs`
Delete `pub mod wallet_unified;` from `src/lib.rs`. Update the lib header comment.

### Step 3: Delete `src/wallet_unified/` folder
Remove: `handlers.rs`, `session_store.rs`, `security.rs`, `mod.rs`
(migration.rs already moved in Step 1)

### Step 4: Remove dead code comment in `main.rs`
Clean up the `// [REMOVED] Legacy SSS Transfer Handler` comment and the empty `// TRANSFER — SSS 2-of-3 Authenticated` section header.

### Step 5: `cargo build` — verify clean compilation
No wallet_unified references should remain. L1 compiles as a pure blockchain.

### Step 6: Move SDK wallet files to `/wallet` folder
Move `sdk/wallet_sdk.js` and related test files to a `wallet/` folder (future wallet service home).

### Step 7: Update docs
Update `docs/faucet.md` to reflect Ed25519-only auth.

---

## SUMMARY

| Category | Lines Removed | Files Affected |
|----------|--------------|----------------|
| `wallet_unified/` (minus migration) | ~1,038 | 4 files deleted |
| `lib.rs` cleanup | 1 line | 1 file |
| `main.rs` dead refs | ~5 lines | 1 file |
| **Total** | **~1,044 lines** | **6 files** |

The L1 goes from a hybrid blockchain+wallet server to a **pure signature-verifying blockchain**. All wallet logic (SSS, FROST, sessions, shard management) will live in a separate `/wallet` service that submits signed transactions to L1 like any other client.
