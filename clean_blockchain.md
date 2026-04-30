# BlackBook L1 — Production Clean-Up & Airtight Build Plan
> Target: ship a production chain that supports only $BB (native, 5 decimals) and $XX / MAXX (bonding-curve SPL, 12 decimals, backed by wUSDT vault). Nothing else.

---

## What the chain actually is

### Core engine — KEEP all of this

| Layer | Files | Purpose |
|---|---|---|
| Consensus | `runtime/consensus.rs`, `runtime/poh_service.rs` | Tower BFT + SHA-256 PoH (12.5k hashes/tick, 64 ticks/slot, 400 ms slots) |
| Execution | `runtime/sealevel.rs`, `runtime/tpu.rs`, `runtime/core.rs` | Rayon parallel Sealevel + UDP TPU on :8003 |
| Storage | `src/storage/mod.rs`, `src/poh_blockchain.rs` | ReDB ACID KV + DashMap lock-free hot cache |
| SVM | `src/svm/` | Native SPL Token — binary-compatible with Solana. Mints: wUSDT (6 dec) + MAXX (12 dec) |
| Solana RPC | `src/solana_rpc/mod.rs` | JSON-RPC 2.0 on :8899 — Phantom / OneKey wallets connect directly |
| Validator relay | `src/relay/mod.rs`, `src/reader/mod.rs`, `proto/` | gRPC Writer→Reader fanout (`validator_relay.proto` + `settlement.proto`) |
| Bridge watcher | `src/watcher/` | BSC deposit polling (optional, can be feature-gated) |
| Protocol types | `protocol/` | `Transaction` / `TxData` primitives shared across engine layers |

### Contracts — current state

| Module | Routes wired | Keep for BB+XX-only? |
|---|---|---|
| `src/contracts/maxx_token/` | `/maxx/{buy,sell,balance,supply,vault,manifest}` | ✅ CORE |
| `src/contracts/token_swap/` | `/swap/{bb-to-usdc, usdc-to-bb}` (10 BB ↔ 1 wUSDT) | ✅ keep — BB on-ramp |
| `src/contracts/global_escrow/` | 6 `/escrow/*` routes | ⚠️ L2 betting only — archive if not shipping L2 |
| `src/contracts/deposit_gateway/` | 2 `/deposit/*` routes | ⚠️ external bridge only — archive if not shipping bridge |
| `src/contracts/withdrawal_gateway/` | 2 `/withdraw/*` routes | ⚠️ same as above |
| `src/contracts/layer2_market/` | **0 routes — never called** | ❌ DELETE NOW |

### Route inventory (48 total in `src/main.rs`)

**Essential — always on (~22 routes)**
- `/health`, `/stats`, `/supply/audit`
- `/balance/:address`, `/transfer/simple`
- `/maxx/buy`, `/maxx/sell`, `/maxx/balance/:address`, `/maxx/supply`, `/maxx/vault`, `/maxx/manifest`
- `/poh/status`, `/poh/block/latest`, `/poh/block/:slot`, `/poh/tx/:tx_id/status`
- `/sealevel/submit`
- `/swap/bb-to-usdc`, `/swap/usdc-to-bb`
- `/usdc/balance/:address`, `/usdc/supply`, `/usdc/transfer`
- `/ws`, `/ledger`, `/address/:address/transactions`, `/consensus/tower`, `/turbine/status`

**Testnet only (already feature-gated? gate it)**
- `/faucet`

**Admin (already behind `--features unsafe_admin`)** ✅
- `/admin/*` (~7 routes)

**L2 / Bridge — feature-gate or archive**
- `/escrow/*` (6 routes)
- `/deposit/*` (2 routes)
- `/withdraw/*` (2 routes)
- `/usdc/accounts/:address` (can go with bridge)

---

## Delete NOW — zero risk, nothing references these

### A. Repo root junk

| Path | Reason |
|---|---|
| `=` | Accidental shell artifact (literally the equals sign) |
| `spawn_account_notification_broadcaster(state.clone());/` | Malformed directory name from a botched command |
| `code.replace` | Scratch file, nothing reads it |
| `proto.txt` | Redundant — real protos are in `proto/` |
| `escrow_code.txt` | Stale dev notes |
| `plan.txt` | Stale dev notes |
| `claim.mjs` | Superseded by `/faucet` endpoint |
| `mls_sdk.js` | Legacy, not referenced by wallet |
| `server.log`, `server_err.log` | Runtime artifacts — add both to `.gitignore` |
| `test_keys.json` | Hardcoded keys are a security footgun in prod |
| `ledger.json` | Dev-time snapshot — add to `.gitignore` |
| `node_modules/` (root) | Root-level Node deps that serve nothing — wallet has its own |
| `package.json` (root) | Same — root has no Node build target |
| `package-lock.json` (root) | Same |
| `wallet.sdk.ts` (root copy) | Duplicate of `blackbook-wallet/src/lib/sdk/wallet.sdk.ts` |
| `deposit.sdk.ts` (root copy) | Duplicate of wallet SDK |
| `back_from_turkey.md` | Personal notes |
| `hotprediction.md` | Research notes |
| `0to100.md` | Vision notes |
| `answers.md` | Q&A scratch |
| `upgrade.md` | Outdated notes |

### B. Root-level `sdk/` directory (entirely duplicated)

`sdk/dealer.sdk.ts`, `sdk/deposit.sdk.ts`, `sdk/escrow.sdk.ts`, `sdk/explorer.sdk.ts`, `sdk/swap.sdk.ts`, `sdk/wallet.sdk.ts` — all superseded by the canonical copies in `blackbook-wallet/src/lib/sdk/`. Delete the entire `sdk/` directory.

### C. Wallet throwaway scripts

All of these in `blackbook-wallet/` are git-squash / codemod artifacts:
- `fix.cjs`, `fix2.cjs`, `fix3.cjs`, `fix4.cjs`, `fix-final.cjs`
- `plan.cjs`
- `test_sig.cjs`
- `temp_crypto.ts`

### D. Dead Rust code

- **`src/contracts/layer2_market/`** — entire directory. Has types and stubs but zero routes and zero internal callers. Delete the dir and the `pub mod layer2_market;` line in `src/contracts/mod.rs`.
- **`Cargo.toml` broken example stanza** — `[[example]] name = "export_keypair" path = "examples/export_keypair.rs"` points to a file that does not exist. Either remove the stanza entirely, or add proper entries for the two files that do exist (`examples/sealevel_load_test.rs`, `examples/udp_tpu_load_test.rs`).
- **`Cargo.toml` commented quinn line** — `# quinn = "0.11"` — just delete it.

---

## Conditional excess (depends on launch scope)

| Module | Ship BB+XX MVP only | Ship with L2 betting | Ship with external bridge |
|---|---|---|---|
| `src/contracts/global_escrow/` | Comment out 6 escrow routes in `main.rs`; keep code | Keep everything | Keep |
| `src/contracts/deposit_gateway/` | Comment out `/deposit/*` routes | Keep | Keep |
| `src/contracts/withdrawal_gateway/` | Comment out `/withdraw/*` routes | Keep | Keep |
| `src/watcher/` (BSC poller) | Disable via feature flag | Keep | Keep |
| `src/settlement/mod.rs` | Optional for L2 root submissions | Keep | Keep |

**Recommended approach:** add two Cargo features — `l2_escrow` and `bridge` — and gate the relevant routes behind `#[cfg(feature = "l2_escrow")]` so the production binary has no dead surface area.

---

## Docs consolidation (35 files → 5 canonical)

Current `docs/` has 35 files with heavy overlap. Merge into:

| New file | Sources to merge |
|---|---|
| `docs/ARCHITECTURE.md` | `CORE_ARCHITECTURE_AND_ONBOARDING.md`, `blackbook_chainspecs.md`, `poh_sealevel_turbine.md`, `DISTRIBUTED_CONSENSUS_NETWORK.md` |
| `docs/ENDPOINTS.md` | `ENDPOINT_GUIDE.md`, `FAUCET_ENDPOINT.md`, `L1-microtx.md`, `l1_capability_summary.md` |
| `docs/L2_INTEGRATION.md` | `L2_INTEGRATION_GUIDE.md`, `L2_INTEGRATION_GUIDEv2.md`, `L2_INTEGRATION_STEP_BY_STEP.md`, `L2_BETTING_REQUIREMENTS.md`, `L2_TEST_GUIDE.md`, `L2_CONNECT.md` |
| `docs/WALLET.md` | `UNIFIED_WALLET.md`, `wallet_addresses_blackbook.md`, `zeWallet.md`, `SSS_and_localsigning.md` |
| `docs/DEPLOYMENT.md` | `production_ready.md`, `HOT_UPGRADE_GUIDE.md` |

Move remaining narrative/draft files to `docs/notes/` or delete.

---

## 5 airtightness gaps that must be fixed before shipping

These are real security / correctness problems on the live chain.

### 🔴 #1 — $XX buy/sell is UNAUTHENTICATED (critical)

**File:** `src/contracts/maxx_token/mod.rs`  
**Problem:** `buy_maxx_handler` and `sell_maxx_handler` trust `req.from` as a plain string. There is no Ed25519 signature check. Any caller can pass any address as `from` and drain that address's wUSDT into MAXX, or burn that address's MAXX for wUSDT.  
**Fix:** Add the same signed-request pattern used by `/transfer/simple` — require `public_key`, `signature`, `timestamp`, `nonce` fields; verify Ed25519 before executing any SVM token ops.

### 🔴 #2 — MAXX vault solvency is unmonitored

**File:** `src/main.rs` (`supply_audit_handler`)  
**Problem:** `/supply/audit` checks `BB supply == wUSDT_reserve * 10` but does not check that the MAXX bonding-curve vault holds at least `R(supply) = (a/2) * supply²` wUSDT. A buggy mint could silently break collateralization.  
**Fix:** Extend the audit to compute the required reserve from current MAXX supply and compare against actual vault balance. Return `"maxx_vault_solvent": true/false` in the response.

### 🟠 #3 — ReDB written AFTER DashMap (crash-safety)

**File:** `src/contracts/global_escrow/mod.rs`  
**Problem:** `escrow_submit_state_root_handler` does `market_roots.insert()` (DashMap, in-memory) **before** `store_escrow_market_root()` (ReDB, durable). On a crash between those two lines, the cache holds state that ReDB does not. On restart the cache is rebuilt from ReDB — state regresses.  
**Fix:** Reverse the order: persist to ReDB first, return error if it fails, only then update DashMap. Same pattern applies to `contest_states.insert()` / `store_contest_state()` and any withdrawal claim writes.  
*(Can skip if global_escrow is archived for MVP.)*

### 🟠 #4 — No L2 block number monotonicity guard

**File:** `src/contracts/global_escrow/mod.rs`  
**Problem:** `EscrowSubmitStateRootRequest.l2_block_number` is stored but never checked against the existing `ContestState.last_l2_block`. A replay or a rollback attack can overwrite a new state root with an old one.  
**Fix:** Before storing: load the existing `ContestState`, reject with `409 CONFLICT` if `req.l2_block_number <= existing.last_l2_block`.  
*(Can skip if global_escrow is archived for MVP.)*

### 🟡 #5 — f64 in the ledger (precision loss at scale)

**Files:** `src/storage/mod.rs`, `src/poh_blockchain.rs`  
**Problem:** `TransactionRecord.amount`, `.gas_fee`, `.balance_before`, `.balance_after` are `f64`. f64 loses precision above ~9 quadrillion — fine now, bad as supply grows. More importantly, on-chain math that accumulates in f64 is non-deterministic across CPUs.  
**Fix:** Change those fields to `u64` (lamports). Convert to `f64` only at JSON serialization boundaries (`amount_bb() -> f64` helper). No math should ever happen in f64.

---

## Dependency audit (Cargo.toml)

All ~40 current dependencies are justified. Two items to clean:

| Item | Action |
|---|---|
| `# quinn = "0.11"` (commented out) | Delete the comment line |
| `[[example]] export_keypair` (file doesn't exist) | Remove stanza or fix path |

No `solana-rpc-client`, no `rocksdb`, no `sled` — Cargo.toml is already well-curated.

`proto/` and `build.rs` are active: `tonic_build` compiles both `.proto` files into gRPC stubs used by `src/relay/` and `src/reader/`. Do not delete these.

---

## Implementation order

| Step | Task | Priority | Risk |
|---|---|---|---|
| 1 | Delete root junk (`=`, `spawn_…/`, `*.txt`, `*.log`, `node_modules/`, `sdk/`, root TS copies) | 🔴 Do first | None |
| 2 | Delete `src/contracts/layer2_market/` + mod decl + fix Cargo.toml stanza | 🔴 Do first | None |
| 3 | Delete wallet `fix*.cjs`, `plan.cjs`, `test_sig.cjs`, `temp_crypto.ts` | 🔴 Do first | None |
| 4 | **Add Ed25519 auth to `/maxx/buy` and `/maxx/sell`** | 🔴 Must before launch | Medium |
| 5 | **Extend `/supply/audit` with MAXX vault solvency check** | 🔴 Must before launch | Low |
| 6 | Feature-gate `l2_escrow` and `bridge` modules so prod binary is minimal | 🟠 Before deploy | Low |
| 7 | Fix ReDB-before-DashMap write order in escrow (if escrow ships) | 🟠 | Low |
| 8 | Add L2 block monotonicity guard (if escrow ships) | 🟠 | Low |
| 9 | Purge f64 from `TransactionRecord` fields | 🟡 | Medium |
| 10 | Consolidate docs/ to 5 canonical files | 🟡 | None |

Steps 1–3 are pure deletions — no code changes, no compile risk.  
Step 4 is the most important code change before any user touches the chain.  
Steps 6–9 can be deferred if escrow/bridge are not in the initial launch.
