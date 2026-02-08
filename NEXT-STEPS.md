# BlackBook L1 - Next Steps

## 🎯 Current Focus: L1 Settlement Layer (Job 1 & 2 Only)

See [MANIFESTO.md](MANIFESTO.md) for the philosophy.  
See [MANIFESTO_context.md](MANIFESTO_context.md) for file mappings.

**Architecture Update:** L2 now handles the "Time Machine" (Tier 2). L1 is pure settlement.

---

## ✅ COMPLETED

### Job 2: Invisible Security (SSS Wallet)
- [x] BIP-39 24-word mnemonic generation
- [x] Shamir 2-of-3 secret sharing
- [x] Ed25519 signing
- [x] Wallet API handlers
- [x] Charlie & David test wallets verified

### Job 1: Gatekeeper (Settlement Only)
- [x] Tier1Gateway struct with solvency invariant
- [x] TxData enum cleaned (removed L2 responsibilities)
- [x] Compilation passes (`cargo check` succeeds)
- [x] Old module directories cleaned up (integration, rpc, routes_v2, settlement, unified_wallet)

---

## 🔨 IMMEDIATE ACTIONS (Execute Now)

### Step 1: Run Unit Tests
```powershell
cargo test tier --lib
```
**Goal:** Verify Tier 1 and Tier 2 vault logic passes tests in `protocol/blockchain.rs`

### Step 2: Run Full Test Suite
```powershell
cargo test --lib 2>&1 | Select-Object -Last 50
```
**Goal:** Ensure no regressions from codebase cleanup

### Step 3: Start Server & Manual Test
```powershell
cargo run
```
**Goal:** Verify server starts and endpoints respond

### Step 4: Test Wallet Flow End-to-End
```powershell
.\test-mnemonic-wallet.ps1
```
**Goal:** Confirm SSS wallet creation → signing → reconstruction works

---

## 📋 REMAINING WORK (Priority Order)

### 1. Simplify TxData to L1-Only Operations
**Status:** Remove Tier 2 logic from protocol/blockchain.rs

**Action:**
- Remove `Tier2Vault`, `DimeVintage` structs
- Remove TxData variants: `LockBbForDime`, `RedeemDimeVintage`, `UpdateCpi`, `TransferDime`
- Add `BridgeLockToL2`, `BridgeUnlockFromL2` variants
- Keep only: `DepositUsdt`, `RedeemBbForUsdt`, `TransferBb`, `CreateAccount`, `RotateOpKey`

### 2. HTTP API for L1 Settlement Operations
**Status:** TxData simplified, need Axum routes

| Endpoint | TxData | Purpose |
|----------|--------|---------|
| `POST /deposit` | DepositUsdt | USDT → $BB (mint) |
| `POST /redeem` | RedeemBbForUsdt | $BB → USDT (burn) |
| `POST /bridge/lock` | BridgeLockToL2 | Lock $BB for L2 (emit event) |
| `POST /bridge/unlock` | BridgeUnlockFromL2 | Unlock $BB from L2 |
| `POST /transfer` | TransferBb | Send $BB |
| `GET /balance/:address` | - | $BB balance |
| `GET /stats` | - | Vault stats, bb_locked_on_l2 |

### 3. Bridge Event System
**Status:** Need event emission for L2 to listen

**Action:**
- Emit `BridgeLockEvent { user, amount, l2_address }` when locking
- Emit `BridgeUnlockEvent { user, amount, l1_tx_hash }` when unlocking
- L2 subscribes to these events via gRPC

### 4. Integrate L1State with PoH Blockchain
**Status:** `poh_blockchain.rs` execute_transaction logs but doesn't modify L1State

**Action:** Wire up L1State.apply_transaction() calls

### L1 MVP Complete When:
- [ ] Can deposit USDT and receive $BB (1:10 ratio)
- [ ] Can redeem $BB for USDT (burn $BB)
- [ ] Can bridge (lock) $BB to L2 with event emission
- [ ] Can unlock $BB from L2 (upon L2 burn event)
- [ ] Solvency invariant enforced: `vault_usdt × 10 = total_bb`
- [ ] Bridge invariant enforced: `total_bb = bb_in_wallets + bb_locked_on_l2`
- [ ] SSS wallet signs all transactions
- [ ] State persists across restarts

### L1 Production Ready When:
- [ ] 65,000+ TPS verified
- [ ] Full audit trail
- [ ] Bridge event system hardened (signature verification)
- [ ] External security audit passed
- [ ] Multi-validator consensus working
STATUS

### ✅ Removed (L2 Responsibilities):
- ✅ `src/settlement/` - Batch settlements (L2 handles)
- ✅ `src/unified_wallet/` - FROST/OPAQUE (Phase 2)
- ✅ `src/integration/` - Legacy integration code
- ✅ `src/rpc/` - Unused RPC layer
- ✅ `src/routes_v2/` - Legacy auth routes

### ⏳ To Remove Next:
- [ ] Tier2Vault logic from `protocol/blockchain.rs`
- [ ] TxData variants: `LockBbForDime`, `RedeemDimeVintage`, `UpdateCpi`, `TransferDime`
- [ ] `DimeVintage` struct
- [ ] `DimeLedger` tracking on L1

### ✅ Kept (L1 Core):
- ✅ `src/wallet_mnemonic/` - SSS wallet (Job 2)
- ✅ `src/storage/` - ReDB persistence
- ✅ `src/grpc/` - L1↔L2 bridge communication
- ✅ `src/vault/` - HashiCorp Vault for secrets
- ✅ `src/usdc/` - Simple USDT bridge
- ✅ `protocol/blockchain.rs` - Will be simplified to Tier 1 only
- ✅ `runtime/` - PoH consensus engine

### 📦 Future (Phase 2):
- Social mining rewards
- FROST/OPAQUE advanced wallet
- Multi-chain bridges
### Production Ready When:
- [ ] CPI oracle updates monthly
- [ ] 65,000+ TPS verified
- [ ] Full audit trail
- [ ] External security audit passed

---

## 🗑️ CLEANUP (Deferred)

These items are NOT core jobs and should be removed or archived:

| Item | Reason |
|------|--------|
| L2 prediction market code | Separate repo |
| Batch settlement / Merkle | L2 concern |
| Market escrow | L2 concern |
| FROST/OPAQUE wallet | Phase 2 |
| Social mining | Phase 2 |

---

*Last Updated: February 7, 2026*
