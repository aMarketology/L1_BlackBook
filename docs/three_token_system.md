# BlackBook L1 — Three-Token System

> Native gas + bonding-curve speculation + value-recapture utility.
> All three live on the same chain, share the same SVM accounts DB, and settle in 400ms slots.

---

## 0. Cast of characters

| # | Ticker | Name | Decimals | Role | On-chain type |
|---|--------|------|----------|------|---------------|
| 1 | **`$BB`** | BlackBook native | 5 | Gas, validator stake, native value | Native lamport-style account |
| 2 | **`$XX`** | MAXX | 12 | Bonding-curve speculation token | SPL-Token mint |
| 3 | **`$DECAY`** | DECAY | n/a (NFT-style) | Per-instance utility token, leaks backing → treasury | Custom ReDB-backed object |

**Reserve currency for everything quoted in dollars: `wUSDT`** (SPL-Token, 6 decimals, microUSDT = 10⁶). wUSDT is *not* one of "our" three tokens — it is the bridged stablecoin used as the price reference.

---

## 1. `$BB` — Native gas & value token

### Purpose
The thing the chain itself is denominated in. Pays for transactions, secures the network via stake, and is the unit validators are rewarded in.

### Tickers / units
- **Symbol**: `$BB`
- **Decimals**: 5
- **Smallest unit**: 1 lamport = `1e-5 BB`

### How the code works
- Stored directly in the SVM accounts DB ([src/svm/](src/svm)) as native account lamports — same model as Solana's SOL.
- Transferred via [src/main.rs](src/main.rs) routes:
  - `POST /transfer/simple` — Ed25519-signed native transfer
  - `GET /balance/:address` — read native balance
- Genesis allocation handled at boot in `Blockchain::new`.
- No bonding curve, no minting after genesis (fixed supply outside of validator emission, if enabled).

### Mental model
> `$BB` is the chain's blood. Every other token (including `$XX` and `$DECAY`) is a contract that *sits on top of* `$BB`'s gas accounting.

---

## 2. `$XX` (MAXX) — Bonding-curve speculation token

### Purpose
A pure on-chain market for upside. Anyone can mint `$XX` by paying wUSDT into a vault; the price rises with each mint along a deterministic curve. Anyone can burn `$XX` back to wUSDT at the curve's current price. No order book, no LPs, no oracle — just one math function and one vault.

### Tickers / units
- **Symbol**: `$XX` (constant: `MAXX_TICKER = "$XX"`)
- **Internal name**: MAXX
- **Decimals**: 12
- **Smallest unit**: 1 picoMAXX = `1e-12 XX`
- **Reserve unit**: microUSDT = `1e-6 wUSDT`

### Bonding-curve math
Defined in [src/contracts/maxx_token/mod.rs](src/contracts/maxx_token/mod.rs):

$$
P(s) = a \cdot s
$$

with slope `a = SLOPE = 5 × 10⁻⁸`. The price is a linear function of supply `s`. Integrating:

- **Buy** (deposit `Δu` USDT, receive `Δm` MAXX):
  $$\Delta m = \frac{-s + \sqrt{s^2 + 2 \cdot \Delta u / a}}{1}$$
- **Sell** (burn `Δm` MAXX, receive `Δu` USDT):
  $$\Delta u = a \cdot s \cdot \Delta m - \tfrac{1}{2} a \cdot \Delta m^2$$

Since the vault is *exactly* the integral of the curve, every `$XX` in circulation is fully backed by wUSDT in the vault. **Solvency is a math identity, not a promise.**

### How the code works

| Endpoint | Handler | Effect |
|---|---|---|
| `POST /maxx/buy` | `buy_maxx_handler` | wUSDT user → `maxx_vault`, mint `$XX` to user |
| `POST /maxx/sell` | `sell_maxx_handler` | burn `$XX` from user, wUSDT `maxx_vault` → user |
| `GET  /maxx/manifest` | `maxx_market_manifest_handler` | curve params, slope, current price |
| `GET  /maxx/supply` | `maxx_supply_handler` | total minted picoMAXX |
| `GET  /maxx/vault` | `maxx_vault_handler` | wUSDT held as reserve |
| `GET  /maxx/balance/:addr` | `maxx_balance_handler` | per-account `$XX` balance |

Internally:
- Mint/burn go through `SplTokenEngine::mint_to` / `::burn` against `maxx_mint_bytes()` ([src/svm/spl_token.rs](src/svm/spl_token.rs)).
- Reserve transfers use `SplTokenEngine::transfer_tokens` against `usdc_mint_bytes()` and the deterministic PDA `maxx_vault_address()` (seed: `BlackBook_MAXX_Vault_v1`).
- Market state (cumulative supply, all-time wUSDT in/out) is persisted in ReDB table `MAXX_TOKEN_MARKET` ([src/storage/mod.rs](src/storage/mod.rs)).

### Wallet integration
- SDK: [blackbook-wallet/src/lib/sdk/wallet.sdk.ts](blackbook-wallet/src/lib/sdk/wallet.sdk.ts) — `buyMaxx`, `sellMaxx`, `getMaxxBalance`, `getMaxxSupply`.
- UI: [blackbook-wallet/src/components/SwapModal.tsx](blackbook-wallet/src/components/SwapModal.tsx) routes wUSDT ↔ `$XX` with live curve preview + slippage warning > 1%.
- Token registry: [blackbook-wallet/src/lib/tokens.ts](blackbook-wallet/src/lib/tokens.ts).

### Mental model
> `$XX` is a vending machine. Insert wUSDT, math gives you tokens. Insert tokens, math gives you wUSDT. The reserve is always exactly right because the math says so.

---

## 3. `$DECAY` — Per-instance value-recapture token

### Purpose
A new design: each `$DECAY` is **NFT-like** — its own object on chain, with its own backing balance and use-counter. Every time the owner "uses" it, **1 % of its current backing leaks to a central treasury**. After 100 uses the token is dead and must be **recharged** by burning `$XX` and paying a wUSDT maintenance fee. This creates a token whose value provably decays with use, redirecting that value into a treasury that can be allocated to yield, buy-backs, or public goods.

### Tickers / units
- **Symbol**: `$DECAY`
- **Quantity model**: NFT-style — each token has a unique `u64` ID, an owner, and its own `backing_value` (microUSDT)
- **Reserve unit**: microUSDT = `1e-6 wUSDT`

### Economic constants
Defined in [src/contracts/decay_token/mod.rs](src/contracts/decay_token/mod.rs):

| Constant | Value | Meaning |
|---|---|---|
| `LEAK_PCT_DENOM` | `100` | Each use leaks `backing / 100` (1 %) → geometric decay |
| `MAX_USES` | `100` | Uses before recharge required |
| `RECHARGE_BURN_MAXX` | `5 × 10¹²` picoMAXX (5 `$XX`) | Burned per recharge |
| `RECHARGE_FEE_USDT` | `2 × 10⁶` microUSDT (2 wUSDT) | Standard recharge fee |
| `RECHARGE_FEE_USDT_DISCOUNTED` | `1.5 × 10⁶` microUSDT | Fee while staked (locked) |
| `MIN_MINT_BACKING` | `1 × 10⁶` microUSDT (1 wUSDT) | Minimum mint backing |

### Decay curve
After `n` uses, remaining backing is:
$$B_n = B_0 \cdot \left(\tfrac{99}{100}\right)^n$$

So at `n = 100`: `B₁₀₀ ≈ 0.366 · B₀` — about **63 %** of the initial backing has been recaptured by the treasury.

### State (per token)
```rust
pub struct DecayToken {
    pub id: u64,
    pub owner: String,         // base58 pubkey
    pub backing_value: u128,   // microUSDT held in the decay vault for this token
    pub uses_count: u32,       // 0..=MAX_USES
    pub minted_slot: u64,
    pub last_use_slot: u64,
    pub lock_until_slot: u64,  // 0 = unlocked; > current_slot = staked
    pub recharge_count: u32,
}
```

### How the code works

| Endpoint | Handler | Effect |
|---|---|---|
| `POST /decay/mint` | `mint_decay_handler` | wUSDT user → `decay_vault`; create token with `backing = N`, `uses = 0` |
| `POST /decay/use` | `use_decay_handler` | leak 1 % of current backing: `decay_vault` → `decay_treasury`; `uses += 1` |
| `POST /decay/recharge` | `recharge_decay_handler` | requires `is_dead()`; burn 5 `$XX` + pay 2 wUSDT (1.5 if staked) → reset `uses = 0` |
| `POST /decay/stake` | `stake_decay_handler` | extend `lock_until_slot`; unlocks 25 % recharge discount |
| `GET  /decay/token/:id` | `decay_token_handler` | full token state |
| `GET  /decay/owner/:address` | `decay_owner_handler` | all tokens owned by an address |
| `GET  /decay/treasury` | `decay_treasury_handler` | vault balance, treasury balance, total minted |
| `GET  /decay/supply` | `decay_supply_handler` | global stats |

### Storage
Three ReDB tables ([src/storage/mod.rs](src/storage/mod.rs)):
- `DECAY_TOKENS`: `u64 → DecayToken JSON` (the canonical token store)
- `DECAY_OWNER_INDEX`: `owner → Vec<u64>` (so wallets can list "my tokens" cheaply)
- `DECAY_META`: `"next_id" → u64` (monotonic ID allocator)

### SVM accounts
Two deterministic PDAs ([src/svm/spl_token.rs](src/svm/spl_token.rs)), both holding wUSDT:
- `decay_vault_address()` — seed `BlackBook_DECAY_Vault_v1`. Holds the **live backing** of every active `$DECAY` token.
- `decay_treasury_address()` — seed `BlackBook_DECAY_Treasury_v1`. Receives the leaked 1 % per use *plus* recharge fees.

Atomicity: each handler does the SVM transfer first, then commits the ReDB state. On persist failure the SVM transfer is rolled back. After success: `svm_accounts.flush_block()`.

### Mental model
> `$DECAY` is a depreciating gift card. It works for ~100 swipes, leaking value into the treasury each swipe. To bring it back to life, you burn `$XX` (deflationary pressure on the bonding curve) plus a small wUSDT fee. Stake it long enough and the recharge gets cheaper.

---

## 4. How the three tokens interact

```
                     ┌───────────────────────────────┐
                     │            wUSDT              │
                     │   (bridged reserve, 6 dec)    │
                     └──────────┬───────────┬────────┘
                                │           │
                       buy/sell │           │ mint / leak / recharge fee
                                ▼           ▼
                    ┌───────────────┐   ┌────────────────────────────┐
                    │   $XX (MAXX)  │   │           $DECAY            │
                    │ bonding curve │   │  per-token NFT-style state  │
                    │  vault = ∫P   │   │  vault: live backing        │
                    └──────┬────────┘   │  treasury: recaptured value │
                           │            └──────────┬─────────────────┘
                           │  burn 5 XX            │
                           └────── recharge ───────┘

           All txs paid for in $BB gas, settled in 400ms PoH slots,
           parallel-executed by Sealevel.
```

### Value loops
1. **Speculation loop** — wUSDT → `$XX` → wUSDT. Pure curve, fully reserved.
2. **Utility loop** — wUSDT → `$DECAY` (locked as backing) → leaks → treasury (held in wUSDT).
3. **Bridge loop** — `$DECAY` recharge **burns `$XX`** ⇒ removes `$XX` supply ⇒ along the curve `P = a·s`, **lowers price for sellers** but **leaves wUSDT vault untouched**. Net effect: every recharge is a small buy-back-and-burn for `$XX` holders.
4. **Discount loop** — staking `$DECAY` (lock_until_slot) reduces recharge fee 25 %, encouraging long holds.

### What each token gets you that the others don't
- **`$BB`**: ability to *do anything* on the chain (gas).
- **`$XX`**: directional exposure to "more activity = more curve depth = higher price".
- **`$DECAY`**: a utility object that *predictably* funnels real wUSDT into a treasury, with a built-in `$XX` burn flywheel.

---

## 5. Where to read the code

| Concern | Path |
|---|---|
| Native `$BB` accounting | [src/svm/](src/svm), `Blockchain::new` in [src/protocol/blockchain.rs](src/protocol/blockchain.rs) |
| `$XX` bonding curve | [src/contracts/maxx_token/mod.rs](src/contracts/maxx_token/mod.rs) |
| `$DECAY` token | [src/contracts/decay_token/mod.rs](src/contracts/decay_token/mod.rs) |
| SPL engine (mint / burn / transfer / balance) | [src/svm/spl_token.rs](src/svm/spl_token.rs) |
| ReDB tables | [src/storage/mod.rs](src/storage/mod.rs) |
| Route registration | [src/main.rs](src/main.rs) |
| Wallet SDK | [blackbook-wallet/src/lib/sdk/wallet.sdk.ts](blackbook-wallet/src/lib/sdk/wallet.sdk.ts) |
| Swap UI | [blackbook-wallet/src/components/SwapModal.tsx](blackbook-wallet/src/components/SwapModal.tsx) |

---

## 6. Production status (April 2026)

- ✅ All three tokens live on chain, `cargo check` clean.
- ✅ `$XX` end-to-end (chain + SDK + UI).
- ✅ `$DECAY` Phase 1 on chain (mint / use / recharge / stake / reads).
- ⚠ **Auth gap (tracked in [clean_blockchain.md](clean_blockchain.md) #1)**: `/maxx/*` and `/decay/*` POST handlers are currently *unauthenticated* — same as `/transfer/simple`. Phase 2 of [decay_token.md](decay_token.md) adds Ed25519 verification before mainnet.
- ⏳ `$DECAY` wallet SDK + inventory UI (Phase 3) and treasury yield routing (Phase 4) pending.
