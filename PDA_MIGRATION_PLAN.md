# BlackBook L1 — PDA Migration & Hardening Plan

> **Goal:** Eliminate the dealer hot-key from the critical path of BlackBook L1
> by replacing it with **Program-Derived Addresses (PDAs)** native to our SVM.
> Combine in-flight workstreams (TPU binary pipeline, float removal, persistence,
> rate limits) into a single, sequenced execution plan.
>
> **Why PDAs over Vault:** BlackBook is custom Rust SVM. Our handlers ARE the
> runtime — there is no BPF, no CPI, no upgrade authority. A PDA on BlackBook is
> just a deterministic 32-byte address with **no private key in existence**. The
> only code that can move funds from a PDA is the specific Rust function that
> owns it. This is structurally stronger than Solana mainnet PDAs (no upgrade
> authority risk) and removes the need for HashiCorp Vault for swap/mint custody.
>
> **Authored:** April 23, 2026 — supersedes Workstream A in `back_from_turkey.md`.

---

## Executive Summary

| Subsystem | Today (dealer key custody) | After PDA Migration |
|-----------|----------------------------|---------------------|
| BB ↔ wUSDT swap pool | Dealer keypair holds liquidity | `bb_swap_pool_v1` PDA holds liquidity — no key |
| wUSDT mint authority | `DEALER_PRIVATE_KEY` | `bb_swap_pool_v1` PDA — only swap logic can mint |
| $XX (MAXX) mint authority | Genesis dealer key fallback | `bb_maxx_curve_v1` PDA — only bonding curve can mint |
| L2 settlement payouts | Dealer signs each payout tx | Merkle proof — already trustless ✅ |
| L2 state-root submission | Dealer key signs root | L2 sequencer pubkey **allowlist** (no secret) |
| Bridge in/out (BSC, Solana) | Dealer key signs external txs | **Still needs key** — only place a hot key remains |

**Net result:** the dealer key shrinks to a single, narrow purpose (cross-chain
bridge signing). Everything on-chain becomes program-owned. Vault becomes
optional, not load-bearing.

---

## What's Already Done (Don't Redo These)

This plan picks up from a known-good state. Already shipped:

- ✅ `Transaction.amount: u64` lamports natively (RuntimeTx, GulfStream, Sealevel)
- ✅ `TpuPacket.amount: u64` + 89-byte binary canonical signed message
- ✅ `dealer.sdk.ts` `signTpuPacket()` matching binary format
- ✅ `getAllBalances()` + `GET /dealer/balances` endpoint
- ✅ TPU nonce pruner (drops entries > 120s old, runs every 60s)
- ✅ UDP 8003 in `setup-hetzner.sh` UFW rules
- ✅ Phase 1 critical security: panics, atomic replay, sealevel deadlock, swap auth
- ✅ Phase 2.1–2.4: float removal (storage), persistence guarantee (ReDB-before-DashMap), L2 root monotonicity
- ✅ Phase 3.1: rate limiting on all write endpoints (HTTP 429)
- ✅ Phase 5.1: Dealer SDK + Merkle settlement
- ✅ 6/6 BB ↔ wUSDT ↔ $XX integration test passing

---

## Phase 0 — PDA Foundation (Day 1, ~2 hours)

### 0.1 — Define a `pda` module

**New file:** `src/svm/pda.rs`

```rust
//! Program-Derived Addresses for BlackBook native programs.
//!
//! Unlike Solana mainnet PDAs, these addresses have NO private key — there is
//! no `find_program_address` bump because there is no BPF program_id. The
//! addresses are just `SHA256(seed)` of a domain-separated, versioned string.
//!
//! Authority: only the specific Rust handler that holds the seed constant can
//! credit/debit these addresses. There is no key to steal, no upgrade authority.

use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

/// Owns the wUSDT liquidity pool and is the wUSDT mint authority.
pub const SWAP_POOL_SEED: &[u8] = b"bb_swap_pool_v1";

/// Owns the $XX (MAXX) bonding curve reserve and is the MAXX mint authority.
pub const MAXX_CURVE_SEED: &[u8] = b"bb_maxx_curve_v1";

/// Owns the global escrow vault (L2 prediction market settlement pool).
pub const ESCROW_VAULT_SEED: &[u8] = b"bb_escrow_vault_v1";

/// Owns the $DECAY treasury (already exists as `decay_treasury_bytes()` —
/// migrate to this constant for consistency).
pub const DECAY_TREASURY_SEED: &[u8] = b"bb_decay_treasury_v1";

/// Deterministically derive a 32-byte address from a seed.
#[inline]
pub fn derive_pda(seed: &[u8]) -> [u8; 32] {
    Sha256::digest(seed).into()
}

#[inline] pub fn swap_pool_pda()      -> Pubkey { Pubkey::new_from_array(derive_pda(SWAP_POOL_SEED)) }
#[inline] pub fn maxx_curve_pda()     -> Pubkey { Pubkey::new_from_array(derive_pda(MAXX_CURVE_SEED)) }
#[inline] pub fn escrow_vault_pda()   -> Pubkey { Pubkey::new_from_array(derive_pda(ESCROW_VAULT_SEED)) }
#[inline] pub fn decay_treasury_pda() -> Pubkey { Pubkey::new_from_array(derive_pda(DECAY_TREASURY_SEED)) }

/// Base58 string form of a PDA — useful for HTTP responses and logs.
pub fn swap_pool_address()    -> String { bs58::encode(swap_pool_pda().to_bytes()).into_string() }
pub fn maxx_curve_address()   -> String { bs58::encode(maxx_curve_pda().to_bytes()).into_string() }
pub fn escrow_vault_address() -> String { bs58::encode(escrow_vault_pda().to_bytes()).into_string() }
```

Add `pub mod pda;` and re-export in `src/svm/mod.rs`.

### 0.2 — Genesis bootstrap update

In `src/main.rs`, the wUSDT/MAXX mint bootstrap currently uses
`state.dealer_address` (or a fallback genesis key) as `mint_authority`.
Switch the authority to the PDA:

```rust
// BEFORE
let mint_authority = if !state.dealer_address.is_empty() { /* dealer pubkey */ } else { reserve_key };
SplTokenEngine::bootstrap_usdc_mint(&svm, &mint_authority)?;

// AFTER
use crate::svm::pda::{swap_pool_pda, maxx_curve_pda};
SplTokenEngine::bootstrap_usdc_mint(&svm, &swap_pool_pda())?;
SplTokenEngine::bootstrap_maxx_mint(&svm, &maxx_curve_pda())?;
```

**Important:** existing chains have wUSDT/MAXX mints already bootstrapped with
the dealer authority. Add a one-shot **mint-authority migration** at startup:

```rust
// On every boot, idempotently rotate mint authority to PDA if not already
SplTokenEngine::set_mint_authority(&svm, &usdc_mint_bytes(), &swap_pool_pda())?;
SplTokenEngine::set_mint_authority(&svm, &maxx_mint_bytes(), &maxx_curve_pda())?;
```

(`set_mint_authority` is a small new helper in `spl_token.rs` — direct write to
the mint account's `mint_authority` field.)

---

## Phase 1 — Swap Pool PDA Migration (Day 1, ~3 hours)

**Files touched:** `src/contracts/token_swap/mod.rs`

### 1.1 — Replace `state.dealer_address` with `swap_pool_pda()`

Both `swap_bb_for_usdc_handler` and `swap_usdc_for_bb_handler`:

```rust
// BEFORE
if state.dealer_address.is_empty() { return /* 503 */; }
let dealer_pubkey = Pubkey::from_str(&state.dealer_address)?;
// ... transfer to/from dealer

// AFTER
use crate::svm::pda::{swap_pool_pda, swap_pool_address};
let pool_pubkey = swap_pool_pda();
let pool_address = swap_pool_address();
// ... transfer to/from pool — no key, no env var, no failure mode
```

The handler still requires the **user's** Ed25519 signature (proving they
authorize their own funds to move). The pool side requires no signature
because it has no key — it's just an account the swap function is hardcoded
to credit/debit.

### 1.2 — Pool reserve invariant check

Add a per-swap invariant assertion:

```rust
let bb_reserve   = state.blockchain.get_balance_lamports(&pool_address);
let usdt_reserve = SplTokenEngine::get_token_balance(&svm, &mint, &pool_pubkey);
// 10 BB = 1 wUSDT  →  10 * usdt_reserve_in_wusdt should equal bb_reserve_in_BB
// (after the swap completes, this must still hold within rounding tolerance)
```

If the invariant breaks, **abort and rollback**. This catches bugs that
slowly drain the pool.

### 1.3 — Lift `f64` from swap path

Change `bb_amount: f64` and `usdc_amount: f64` to integer fields at the
HTTP boundary. Existing wallet SDK already sends decimals-aware values; just
multiply at the request struct level:

```rust
pub struct SwapBbToUsdcRequest {
    pub wallet_address: String,
    pub bb_lamports: u64,        // was bb_amount: f64
    pub timestamp: u64,
    pub nonce: String,
    pub public_key: String,
    pub signature: String,
}
```

Backwards-compat shim: accept both `bb_amount` and `bb_lamports` for one
release. (`#[serde(alias)]` on the field.)

### 1.4 — `/swap/pool/balances` health endpoint

```rust
async fn swap_pool_balances_handler(State(state): State<AppState>) -> impl IntoResponse {
    let pool_pubkey  = swap_pool_pda();
    let pool_address = swap_pool_address();
    let bb_lamports  = state.blockchain.get_balance_lamports(&pool_address);
    let usdt_raw     = SplTokenEngine::get_token_balance(&svm, &usdc_mint_bytes(), &pool_pubkey);
    Json(json!({
        "pool_address": pool_address,
        "bb": { "lamports": bb_lamports, "balance": bb_lamports as f64 / 100_000.0 },
        "wusdt": { "raw": usdt_raw, "balance": usdt_raw as f64 / 1_000_000.0 },
        "ratio": (bb_lamports as f64 / 100_000.0) / (usdt_raw as f64 / 1_000_000.0).max(1e-9),
        "expected_ratio": 10.0,
    }))
}
```

### 1.5 — Initial pool seeding (`unsafe_admin` only)

```rust
#[cfg(feature = "unsafe_admin")]
async fn admin_seed_swap_pool_handler(/* State, Json(req) */) -> impl IntoResponse {
    // Mint wUSDT directly to swap_pool_pda() and credit BB to swap_pool_pda().
    // This is the ONLY code path that adds liquidity. After bootstrap, the pool
    // is closed-system — funds only enter via swaps.
}
```

This replaces the current `/admin/dealer/send_wusdt` workflow.

---

## Phase 2 — MAXX Bonding Curve PDA Migration (Day 1, ~2 hours)

**Files touched:** `src/contracts/maxx_token/mod.rs`

The bonding curve is conceptually cleaner than the swap pool because it's a
**one-sided reserve** (wUSDT in, MAXX out via formula).

### 2.1 — Curve reserve PDA

Replace any "dealer holds wUSDT reserve" logic with `maxx_curve_pda()`. The
curve PDA holds the wUSDT collateral; the curve PDA mints MAXX into the user's
ATA on buy and burns MAXX from the user's ATA on sell.

### 2.2 — Mint authority enforcement

`bootstrap_maxx_mint(&maxx_curve_pda())` at genesis means **only this module
can call `mint_to` on the MAXX mint**. Even if the dealer key is leaked, the
attacker cannot mint MAXX out of thin air — the SPL engine will reject it.

### 2.3 — Curve invariant check

`reserve_wusdt == ∫₀ˢ P(s) ds = ½ × SLOPE × s²` (in raw units, with overflow
guards using `u128`). Verify on every buy/sell. Abort on mismatch.

---

## Phase 3 — Escrow PDA + L2 Sequencer Allowlist (Day 2, ~3 hours)

**Files touched:** `src/contracts/global_escrow/mod.rs`, `src/main.rs`

### 3.1 — Escrow vault PDA

Currently L2-bet collateral lives in user accounts; the escrow contract just
records claims. Move the actual collateral to `escrow_vault_pda()`:

- `POST /escrow/deposit` → user's BB debited, escrow PDA credited
- `POST /escrow/withdraw` (with Merkle proof) → escrow PDA debited, user credited
- `POST /escrow/submit-state-root` → only writes the root; no fund movement

### 3.2 — L2 sequencer allowlist (replaces dealer signing)

```rust
// src/auth.rs — new helper
pub fn verify_l2_sequencer_signature(
    state: &AppState,
    market_id: &str,
    root: &[u8; 32],
    timestamp: u64,
    signature: &str,
    public_key: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // 1. The pubkey MUST be in state.l2_sequencer_allowlist (HashSet<String>)
    if !state.l2_sequencer_allowlist.contains(public_key) {
        return Err(/* 401 unauthorized sequencer */);
    }
    // 2. Standard Ed25519 verify of "L2_ROOT:{market_id}:{hex(root)}:{timestamp}"
    // 3. Timestamp freshness, nonce reuse via state.used_nonces
}
```

Allowlist is loaded at startup from `L2_SEQUENCER_ALLOWLIST` env var
(comma-separated base58 pubkeys) — these are **public keys, not secrets**. No
Vault needed.

### 3.3 — Monotonicity (already done) + slot-bound roots

Roots already have to monotonically increase per market (Phase 5 ✅). Add a
slot-bound check: a root from sequencer-A cannot overwrite a root from
sequencer-B for the same market within the same L1 slot. Prevents two
sequencers from racing.

---

## Phase 4 — TPU + Float Cleanup (Day 2, ~1 hour)

The TPU pipeline is already binary u64 end-to-end. Remaining cleanups:

- [x] `TpuPacket.amount: u64` ✅
- [x] Binary 89-byte canonical sig ✅
- [x] Nonce pruner ✅
- [x] `RuntimeTx.amount: u64` ✅
- [ ] Run load test: `cargo run --release --example udp_tpu_load_test`
  - Target: 50k+ packet/s send rate, zero packet loss, flat memory
- [ ] Confirm `PipelinePacket.amount: u64` matches RuntimeTx (already done)

---

## Phase 5 — Decommission the Dealer Hot Path (Day 3, ~2 hours)

Once Phases 1–3 are live, the dealer key is **only** used by:

- `src/contracts/withdrawal_gateway/mod.rs` — signing BSC/Solana withdrawal txs
- `src/watcher/mod.rs` — startup balance check on the bridge custody wallet

Everything else can ignore `state.dealer_address`. Specifically remove:

- ✂️ Dealer-as-mint-authority code path in startup invariant reconcile
- ✂️ `state.dealer_address.is_empty()` 503 guards in the swap handlers
- ✂️ `/admin/dealer/send_wusdt` (replaced by `/admin/seed_swap_pool` from 1.5)

Update `state.dealer_address` doc comment:

```rust
/// Bridge dealer pubkey (base58) — used ONLY for cross-chain withdrawal
/// signing (BSC, Solana). All on-chain custody (swap pool, MAXX curve,
/// escrow vault) is held by PDAs and requires no key.
pub dealer_address: String,
```

---

## Phase 6 — Bridge Hot Wallet Hardening (Day 3, ~2 hours)

The bridge dealer key is the **last** hot key. It cannot be eliminated (you
need to actually sign BSC transactions), but it can be tightly scoped:

1. **Per-window withdrawal cap** — the dealer key can only sign withdrawals up
   to N wUSDT per 24h. Enforced server-side by `NetworkThrottler` style window.
2. **Multi-sig before key release** — large withdrawals (> 10k wUSDT) require a
   second signature from a cold key.
3. **Key kept in env var, not file** — already the case. Optionally Vault for
   audit-logged retrieval, but no longer load-bearing for the chain's solvency.
4. **Withdrawal queue with replay window** — user requests withdrawal, request
   sits for 1 hour, can be cancelled by a 2-of-3 multisig if suspicious.

**This is the only remaining place Vault adds real value.** And it's optional.

---

## Phase 7 — Verification & Release (Day 3, ~2 hours)

### 7.1 — Full integration test sweep

```powershell
# L1 dev node
cd C:\Users\maxd1\Documents\GitHub\L1_BlackBook
cargo build --features unsafe_admin
.\target\debug\layer1.exe

# In another terminal — full lifecycle test
cd blackbook-wallet
npx tsx test_scripts/test_xx_bb.ts        # 6/6 must pass
npx tsx test_scripts/test_swap_pool.ts    # NEW — verifies pool PDA invariants
npx tsx test_scripts/test_pda_authority.ts # NEW — verifies dealer key cannot mint
```

### 7.2 — Pool drainage attack test

Attempt to drain the swap pool by:

1. Creating a fake "swap" tx with the dealer key as signer → must fail (no
   dealer in critical path)
2. Sending raw BB transfer from pool PDA → must fail (no signing keypair exists
   for the PDA address; ed25519 has no preimage of `SHA256("bb_swap_pool_v1")`)
3. Calling `mint_to` on the wUSDT mint with the dealer key → must fail
   (authority is now the swap pool PDA)

### 7.3 — Load test confirmation

```powershell
cargo run --release --example udp_tpu_load_test
```

Expected: ≥50k pkt/s send, ≥30k pkt/s on-chain confirms, flat memory, zero
signature failures.

### 7.4 — Update docs

- Mark `back_from_turkey.md` Workstream A as **superseded by PDA migration**
- Mark `security_step_by_step.md` Phase 1 "Vault Integration" as
  **N/A — replaced by PDA architecture**
- Mark Phase 5 "L2 Sequencer Allowlist" as `[x]`
- Update `.github/copilot-instructions.md` with PDA section

---

## Day-by-Day Execution Order

### Day 1 — PDA Foundation + Swap Pool

1. **Phase 0.1** — Create `src/svm/pda.rs` with all four PDA derivations
2. **Phase 0.2** — Bootstrap mints with PDA authorities + idempotent migration
3. **Phase 1.1–1.5** — Migrate swap handlers from dealer to swap pool PDA
4. **Phase 2.1–2.3** — Migrate MAXX curve from dealer to curve PDA
5. **Build & test** — `cargo build --features unsafe_admin`, run `test_xx_bb.ts`

### Day 2 — Escrow + Sequencer + TPU Validation

1. **Phase 3.1** — Move escrow collateral to escrow vault PDA
2. **Phase 3.2** — Implement L2 sequencer allowlist
3. **Phase 3.3** — Slot-bound monotonicity for state roots
4. **Phase 4** — Run TPU load test, confirm metrics

### Day 3 — Decommission + Harden + Ship

1. **Phase 5** — Remove dealer-as-custody code paths
2. **Phase 6** — Add bridge withdrawal cap + queue
3. **Phase 7** — Full integration + drainage attack tests
4. **Phase 7.4** — Update docs and commit

---

## File Map (after migration)

| What | Where |
|------|-------|
| PDA derivation module | `src/svm/pda.rs` (NEW) |
| Swap pool PDA usage | `src/contracts/token_swap/mod.rs` |
| MAXX curve PDA usage | `src/contracts/maxx_token/mod.rs` |
| Escrow vault PDA usage | `src/contracts/global_escrow/mod.rs` |
| L2 sequencer allowlist | `src/auth.rs`, `src/main.rs` (AppState) |
| Mint-authority migration | `src/svm/spl_token.rs` (`set_mint_authority`) |
| Genesis bootstrap | `src/main.rs` (~line 2940 reconcile block) |
| Bridge withdrawal cap | `src/contracts/withdrawal_gateway/mod.rs` |
| Pool seed admin endpoint | `src/main.rs` (`unsafe_admin` only) |
| New tests | `blackbook-wallet/test_scripts/test_swap_pool.ts`, `test_pda_authority.ts` |

---

## Why This Beats Vault

| Vault Approach | PDA Approach |
|---------------|--------------|
| Hides the key better | **Removes the key entirely** |
| Still a single point of compromise (the Vault unseal keys) | No key exists in any form, anywhere |
| Adds infra cost (~$50/mo HCP or extra Hetzner CX11) | Zero infra cost |
| Adds operational complexity (rotation, agent, sync) | Zero ops — it's just code |
| Protects against SSH breach only | Protects against SSH breach, insider, supply chain |
| Doesn't help if the BlackBook binary is malicious | Same — but binary is reproducible & open |

Vault remains useful for the **bridge hot key only** (Phase 6), where a real
signing key is unavoidable because we have to sign external chain txs.

---

## Risk & Rollback

**Risk:** A bug in PDA-handler code can drain the pool because there's no
external authority to ask. Mitigations:

1. Per-swap invariant check (Phase 1.2) — abort if reserves diverge
2. Bootstrap-only liquidity injection (no live mint path)
3. Drainage attack tests (Phase 7.2)
4. Reserve cap: pool can hold at most N wUSDT — overflow goes to a separate
   "overflow PDA" that requires multi-sig to release

**Rollback:** Revert the migration commit. PDA addresses are deterministic, so
any future re-enable is bit-identical (no lost funds, no orphaned accounts).

---

*Ship it.*
