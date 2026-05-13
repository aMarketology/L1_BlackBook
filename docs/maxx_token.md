# MAXX Token — Integration Plan

The `MAXX` token (ticker: **$XX**) is a bonding-curve-priced asset native to the BlackBook L1.
It exists as an SPL token (12 decimals) backed by a `wUSDT` reserve vault.
Linear curve: `price = a * supply` with slope `a = 5e-8`.
Genesis seed of `$1,000` wUSDT mints `200,000 MAXX` at exactly `$0.01`.

> Token name: **MAXX** | Ticker: **$XX** | Module/symbol prefix: `maxx`

---

## Phase 0 — Rename `$MAX` → `$MAXX` (✅ this commit)

Apply scoped find/replace **only** in files touched for the bonding curve.
Do **not** rename unrelated `MAX_*` identifiers (e.g. `u64::MAX`).

Files in scope:
- `src/contracts/max_token/` → `src/contracts/maxx_token/` (rename dir)
- `src/contracts/mod.rs` (module decl)
- `src/svm/spl_token.rs` (only the `MAX MINT CONSTANTS` section + `bootstrap_max_mint`)
- `src/storage/mod.rs` (only `MAX_TOKEN_MARKET` table line)
- `src/main.rs` (only the `/max/...` routes)
- `MAX_TOKEN_MARKET.toml` filename + `[MAX_TOKEN_MARKET]` section

Symbol mapping:

| Old                          | New                            |
| ---------------------------- | ------------------------------ |
| `$MAX`                       | `$MAXX`                        |
| `max_token` (module)         | `maxx_token`                   |
| `MAX_TICKER`                 | `MAXX_TICKER`                  |
| `PICO_MAX`                   | `PICO_MAXX`                    |
| `MAX_TOKEN_MARKET` (table)   | `MAXX_TOKEN_MARKET`            |
| `MaxTokenState`              | `MaxxTokenState`               |
| `BuyMaxRequest`              | `BuyMaxxRequest`               |
| `SellMaxRequest`             | `SellMaxxRequest`              |
| `MaxMarketResponse`          | `MaxxMarketResponse`           |
| `buy_max_handler`            | `buy_maxx_handler`             |
| `sell_max_handler`           | `sell_maxx_handler`            |
| `max_market_manifest_handler`| `maxx_market_manifest_handler` |
| `get_max_state`              | `get_maxx_state`               |
| `set_max_state`              | `set_maxx_state`               |
| `MAX_MINT_SEED`              | `MAXX_MINT_SEED`               |
| `MAX_DECIMALS`               | `MAXX_DECIMALS`                |
| `MAX_UNIT`                   | `MAXX_UNIT`                    |
| `MAX_VAULT_SEED`             | `MAXX_VAULT_SEED`              |
| `max_mint_bytes`             | `maxx_mint_bytes`              |
| `max_mint_address`           | `maxx_mint_address`            |
| `max_vault_bytes`            | `maxx_vault_bytes`             |
| `max_vault_address`          | `maxx_vault_address`           |
| `bootstrap_max_mint`         | `bootstrap_maxx_mint`          |
| `MAX_MINT_SEED = "BlackBook_MAX_Mint_v1"` | `"BlackBook_MAXX_Mint_v1"` |
| `MAX_VAULT_SEED = "BlackBook_MAX_Vault_v1"` | `"BlackBook_MAXX_Vault_v1"` |
| Routes `/max/buy`, `/max/sell`, `/max/manifest` | `/maxx/buy`, `/maxx/sell`, `/maxx/manifest` |

Verify with `cargo check` (zero new warnings, zero errors).

---

## Phase 1 — L1 Chain SPL Integration ✅

1. ✅ Bootstrap the `$MAXX` SPL Mint at node startup
   (`SplTokenEngine::bootstrap_maxx_mint`) inside `src/main.rs`,
   adjacent to the existing `bootstrap_usdc_mint` call.
2. ✅ Vault uses a deterministic `MAXX_VAULT_SEED` pubkey; SVM SPL
   transfers create the wUSDT ATA on first deposit (lazy-init).
3. ✅ Public read endpoints:
   - `GET /maxx/balance/:address` — user's `$MAXX` SPL balance
   - `GET /maxx/supply` — total `$MAXX` minted
   - `GET /maxx/vault` — vault wUSDT balance + bonding-curve state
   - `GET /maxx/manifest` — full market manifest

## Phase 2 — Bonding-Curve Trade Execution (SVM-backed) ✅

`buy_maxx_handler` / `sell_maxx_handler` now treat the SVM AccountsDB as
the canonical source of truth; the ReDB `MAXX_TOKEN_MARKET` row + TOML
are derived projections.

- **Buy** (`POST /maxx/buy`): parse `from` (base58 pubkey) → compute
  MAXX out from current SVM mint supply → `transfer_tokens` wUSDT
  user→vault → `mint_to` `$MAXX` to user → flush block → recompute
  spot/state from on-chain supply + vault balance → write ReDB row +
  manifest TOML. Best-effort rollback if the second step fails.
- **Sell** (`POST /maxx/sell`): parse `from` → compute wUSDT return →
  vault solvency check → `burn` `$MAXX` from user → `transfer_tokens`
  wUSDT vault→user → flush → recompute → write ReDB + TOML. Re-mint
  rollback on failure.
- All math stays in `u128` with `calculate_mint` / `calculate_burn`.
- ✅ Slippage guard: optional `min_out` field on each request rejects
  trades that would breach the threshold.
- Response includes new user $XX + wUSDT balances and the resulting
  market state.

## Phase 3 — Wallet SDK + Context ✅

In `blackbook-wallet/src/`:
1. ✅ `lib/sdk/explorer.sdk.ts`: `getMaxxBalance`, `getMaxxSupply`,
   `getMaxxVault`, `getMaxxMarketManifest`. `WalletSnapshot` extended
   with `maxx_balance`, `maxx_raw`, `maxx_mint`.
2. ✅ `lib/sdk/wallet.sdk.ts`: `getMaxxBalance/Supply/Vault/Manifest`
   plus `buyMaxx(amountMicroUsdt, minOutPicoMaxx?)` and
   `sellMaxx(amountPicoMaxx, minOutMicroUsdt?)`.
3. ✅ `context/BlackBookContext.tsx`: `refreshBalance()` now fetches
   $XX in parallel and exposes it under both `tokenBalances.MAXX`
   and `tokenBalances['$XX']`. `swap()` routes wUSDC↔MAXX through the
   new SDK methods with proper unit conversion (whole→pico/micro).
4. ✅ `lib/tokens.ts`: registered `MAXX` token (12 decimals, $XX accent).

## Phase 4 — Unified Swap UI ✅

1. ✅ `MAXX` appears in the Swap modal's token dropdown automatically
   via `TOKEN_LIST`.
2. ✅ `lib/bondingCurve.ts` provides client-side `previewBuyMaxx`,
   `previewSellMaxx`, `spotPrice`, and `slippagePct` helpers using the
   exact L1 formula (`a = 5e-8`).
3. ✅ Modal lazy-loads `getMaxxVault()` only when the active pair is
   wUSDC↔MAXX and recomputes preview + slippage on amount change.
4. ✅ Slippage line shown under the output box; turns red and warns to
   split the trade when slippage exceeds 1%.
5. ✅ Submit goes through `BlackBookContext.swap()` → `walletSdk.buyMaxx`
   / `sellMaxx`.

## Phase 5 — Future: Gas-Fee Abstraction

Out of scope for this PR but tracked here:
- Extend `runtime/sealevel.rs` fee-payer logic so a tx may declare
  `fee_token = "MAXX"`; deduct equivalent `$MAXX` SPL based on the current
  bonding-curve spot price.

---

## Verification

1. `cargo check` clean after Phase 0.
2. Node startup logs `✅ $MAXX SPL Token Mint bootstrapped` after Phase 1.
3. `POST /maxx/buy {amount: 1_000_000_000}` (1,000 wUSDT in microUSDT) on a
   fresh chain returns `200,000 * 10^12` picoMAXX and spot price `0.01`.
4. `GET /maxx/balance/:address` reports the user's SPL balance after a buy.
5. Wallet UI lists `$MAXX` alongside `BB` and `wUSDT` and can swap both
   directions with accurate previewed output.
