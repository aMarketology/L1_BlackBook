# L1 BlackBook — Session Log

---

## Session: 2026-05-21 — Infrastructure Audit + gRPC Fix + Doc Update

> **Goal:** Fix gRPC reconnect stale-anchor bug in Reader. Full infrastructure audit of all 5 layers. Document the dual L2 settlement system. Update all docs. Set next steps for dealer.sdk.ts System B expansion.

### Status: ✅ Complete

### What Was Done

| Item | Result |
|------|--------|
| Fixed Reader gRPC reconnect anchor bug (`session_anchor_reset` flag) | ✅ `src/reader/mod.rs` |
| Verified fix live: `📡 Session anchor reset → slot 175316 prev_hash d6f21391…` | ✅ No more "failed verification" errors after reconnect |
| Full infrastructure audit — all 5 layers, all contracts, all SDKs | ✅ |
| Documented dual L2 systems (System A legacy vs System B Rollup Hub) | ✅ |
| Confirmed `layer2_market/mod.rs` is dead code (`#![allow(dead_code)]`) | ✅ |
| Confirmed wrong comment in `token_swap/mod.rs` line 18 (cosmetic bug) | ✅ |
| Confirmed `TokenFactory.ts` calls non-existent `POST /l5/launch-coin` | ✅ |
| Archived outdated docs: `three_token_system.md`, `upgrade.md` → `docs/archive/` | ✅ |
| Rewrote `docs/NEXT-STEPS.md` with current P0/P1/P2 priorities | ✅ |
| Updated `docs/Manifesto.md` — removed MAXX/DECAY/OZ references | ✅ |
| Updated `docs/ROLLUP_LAYERS_ROADMAP.md` — dual system table + deprecation plan | ✅ |

### Key Architecture Findings

| Finding | Detail |
|---------|--------|
| **Two incompatible L2 settlement systems** | System A (binary leaf, `/escrow/*`) vs System B (UTF-8 leaf, `/rollup/L2/*`) — proofs cannot be shared |
| **System A leaf** | `SHA256(bs58_decode(wallet)[32] \|\| payout_spl_u64_le[8])` |
| **System B leaf** | `SHA256("L2:BB:{address}:{balance_lamports}")` — plain UTF-8 string |
| **`layer2_market/mod.rs`** | Dead code — never called. Real Merkle build is in `dealer.sdk.ts::buildMerkleTree()` |
| **`token_swap/mod.rs` line 18** | Comment says "1 BB = 1 wUSDT" but constants say 10:1. Comment is wrong |
| **`TokenFactory.ts`** | Calls `POST /l5/launch-coin` which has no Rust handler |
| **L5 exit golden rule** | Creator Coins cannot exit to L1 directly — must swap to $BB on L5 first |
| **BB price** | $0.10 USD (10 BB = 1 wUSDT). The `BB_TO_USDC_RATE = 10` constant is correct |

### gRPC Reconnect Bug Details

**Root cause:** After h2 disconnect + 5s retry, the Reader's local PoH clock had advanced ~12 slots past the Writer's live slot. The existing drift detection (`block.slot > local_slot + 1`) only handles forward gaps. Backward drift never fires → hundreds of "Block N failed verification" errors until a lucky 2-slot gap triggered a reset.

**Fix:** Added `let mut session_anchor_reset = true;` before the subscribe while-loop. On first block of each gRPC session, unconditionally resets `self.latest_hash` to `block.previous_hash` and snaps the slot counter, logs `📡 Session anchor reset → slot {N}`.

---

## Next Session Priorities

### Step 1 (P0): Expand `dealer.sdk.ts` — System B SDK

Add two methods to `sdk/dealer.sdk.ts` (after the existing `buildMerkleTree()` around line 850):

1. **`buildRollupMerkleTree(rollupId, entries)`**
   - Leaf: `SHA256("L2:BB:{address}:{lamports}")` — plain UTF-8, no bs58 decode
   - Same `merkleHash()` sorted-pair combiner as existing tree
   - Returns `MerkleTreeResult`

2. **`submitRollupRoot(rollupId, batchId, tree)`**
   - Sig (UTF-8): `"ROLLUP_SUBMIT_ROOT:{rollupId}:{batchId}:{root_hex}:{ts}"`
   - Uses `signMessage()` — NOT `signBinaryMessage()`
   - POST to `POST /rollup/{rollupId}/submit_root`

### Step 2 (P0): TypeScript L2 Sequencer
Node.js server. Polls lock records, accepts bets, resolves markets with `buildRollupMerkleTree()`, submits roots, stores proofs. Sequencer pubkey registered as `L2_SEQUENCER_PUBKEY` on L1.

### Step 3 (P0): Freeze System A New Entries
No new `/escrow/deposit` calls. All new markets via `/rollup/L2/lock_bb`. Keep `/escrow/withdraw` alive forever (30-day claim windows).

### P1 Items
- Fix `TokenFactory.ts` to use two-step lock_bb flow
- Fix wrong comment in `token_swap/mod.rs` line 18
- Strip MAXX/DECAY/$oz UI components from `blackbook-wallet/`

---

## Session: 2026-05-20 — Reader Sync Fixes + CI/CD Hot-Upgrade

> **Goal:** Fix two Reader sync bugs causing balance parity failures, verify both nodes agree on state, and set up automatic hot-upgrade CI/CD so every `git push` to `master` auto-deploys to Hetzner.

### Status: ✅ Complete

### What Was Done

| Item | Result |
|------|--------|
| Fixed Reader double-multiply bug (`let lamports = *amount` — was `* LAMPORTS_PER_BB`) | ✅ `src/reader/mod.rs` |
| Fixed faucet encoding wrong TxData (`TransferBb` not `DepositUsdt`) | ✅ `src/main.rs` |
| Committed + pushed both fixes as `d3ff2ec` | ✅ |
| Rebuilt Hetzner Docker container from `d3ff2ec` | ✅ ~9 min compile |
| Restarted local Reader from genesis (`reader.redb` wiped) | ✅ |
| Verified parity: Bob = 0.105 BB on **both** nodes (exact match) | ✅ |
| CI/CD: two-job GitHub Actions pipeline (build on GHA → GHCR → pull on Hetzner) | ✅ `.github/workflows/deploy.yml` |
| First successful CI/CD end-to-end deploy confirmed | ✅ commit `a8ef9ad` |

### Issues Found & Resolved

| Issue | Fix |
|-------|-----|
| Reader was treating `TransferBb.amount` as BB units, multiplying by `LAMPORTS_PER_BB` again (double-multiply) | `let lamports = *amount;` (amount is already lamports) |
| Faucet recorded `DepositUsdt { usdt_amount: 0 }` (f64→u64 truncation) — Reader credited zero | Changed faucet to `TxData::TransferBb { to: wallet, amount: lamports }` |
| GitHub Actions image tag `ghcr.io/aMarketology/...` uppercase — Docker rejected it | Hardcoded `ghcr.io/amarketology/l1-blackbook` (lowercase) in `env.IMAGE` |
| GitHub secret `HETZNER_SSH_KEY` pasted with Windows `\r\n` line endings — SSH auth failed | Re-copied key with `(Get-Content ~/.ssh/id_ed25519 -Raw) -replace "\`r\`n", "\`n"` |

### Known Gaps (Not Regressions)

| Gap | Location | Detail |
|-----|----------|--------|
| Swap transactions not recorded in blocks | `src/contracts/token_swap/mod.rs` | Reader permanently blind to BB↔wUSDT swaps — Alice Reader=0.095 vs Hetzner=0.075 (0.02 BB = one swap). Fix: add `SwapBbForUsdc { user, bb_lamports, usdc_micro }` variant to `TxData`. |

---

## Next Session Priorities

1. **Swap block recording** — add `SwapBbForUsdc` / `SwapUsdcForBb` variants to `protocol/blockchain.rs::TxData`, record in `token_swap/mod.rs` handlers, handle in `src/reader/mod.rs::apply_block_balances`
2. **Phase 6 launch prep** — see root_next_steps.md Phase 6.1–6.6
3. **UptimeRobot** — ping `/health` every 60s on Hetzner (free tier, 15 min setup)
4. **ReDB backup** — cron job on Hetzner to snapshot `blockchain_data/blockchain.redb` daily

---

## Session: 2026-05-19 — Dual-Node Testing & Stability

> **Goal:** Run the node, validate all BB functionality against both live nodes (localhost + Hetzner), confirm tests pass, identify remaining issues.

### Status: ✅ Complete

### What Was Done

| Item | Result |
|------|--------|
| Local node running (`cargo run --features unsafe_admin`) | ✅ Slot ~869k, epoch 1, 12,694 accounts, 2.26M BB supply |
| Hetzner node (`layer1.blackbook.id`) live | ✅ Slot ~3.73M, epoch 0, 3 accounts (empty/fresh) |
| `node tests/full_flow_test.mjs` → localhost | ✅ **47/47 passed** — faucet, transfers, escrow, swaps, USDC, RPC, security |
| `smoke.ps1` → localhost | ✅ **12/12 passed** — health, balance, admin mint, faucet auth, Turbine UDP 8004, USDC |
| `smoke.ps1` → Hetzner | ✅ **12/12 passed** — admin mint correctly 404 (prod build, no unsafe_admin) |
| Phase A/B/C commit `aff8378` pushed | ✅ f64→u64 migration, persistence ordering, monotonicity tests, nginx POST fix, smoke.ps1 |
| `cargo check` — zero errors | ✅ Warnings only (unused imports, 1 deprecated `credit(f64)` in faucet) |

### Issues Found

| Issue | Location | Severity | Status |
|-------|----------|----------|--------|
| Deprecated `credit(f64)` still used in faucet handler | `src/main.rs:1390` | Low | Pending |
| Hetzner node is empty — no test accounts seeded | `layer1.blackbook.id` | Medium | Pending |
| `full_flow_test.mjs` hardcoded to `localhost:8080` — can't target Hetzner | `tests/full_flow_test.mjs` | Low | Pending |
| `Invoke-WebRequest` in smoke.ps1 triggers security prompt (needs `-UseBasicParsing`) | `tests/smoke.ps1` | Low | Pending |

---

## Next Session Priorities

1. **Faucet credit fix** — swap `credit(f64)` at `main.rs:1390` → `credit_svm_lamports(u64)`
2. **Seed Hetzner** — run admin mint / faucet against live node to bootstrap test wallets
3. **Parameterize full_flow_test** — accept `API_URL` env var so it can run against any node
4. **PDA onboarding ramp** — anon custodial wallet: user deposits → gets BB (deposit_gateway flow review)
5. **Per-contest escrow PDAs** — Phase 1 from the 7-day plan below (pda.rs, storage.rs, depositor ledger)

---

## Original 7-Day Build Plan (Per-Contest Escrow PDAs)

> **Goal:** Finish §2 of the smart contract spec. Replace the single global `escrow_vault_pda()` with **per-contest vault + state PDAs**, add a per-contest depositor ledger, wire the gRPC surface end-to-end (`InitContest`, `VerifyDeposit`, `SubmitMerkleRoot`, `ClaimWinnings`, `GetContestStatus`, new `RegisterSequencer`), execute on-settle house-rake sweep, and add a periodic **pro-rata refund sweep** for expired contests.
>
> Outcome: real $BB liquidity on testnet, trustless winner claims via Merkle proof on our custom L1, verifiable settlement that mirrors Polymarket's on-chain redemption — secured by the $BB chain.

---

## Decisions Confirmed

| Topic | Choice |
|---|---|
| Vault model | **Per-contest PDAs** (vault + state). Seeds: `bb_escrow_vault_v2:{contest_id}` and `bb_contest_state_v1:{contest_id}`. |
| `RegisterSequencer` | New **gRPC RPC + HTTP admin endpoint**, persisted to ReDB. Authority = `L1_ROOT_AUTHORITY_PUBKEY`. |
| House rake | **Swept on `SubmitMerkleRoot`** to `BB_TREASURY_ADDRESS`; idempotent via `house_rake_swept_tx`. |
| Expired contests | **Pro-rata refund** to known depositors (requires per-contest depositor ledger). Dust → treasury. |

---

## Scope Boundaries

**In scope**
- BB token only.
- Per-contest vault/state PDAs + depositor ledger.
- gRPC + HTTP surface for the full lifecycle.
- House-rake sweep + expired-contest pro-rata refund.
- One end-to-end integration test.

**Out of scope**
- L2 changes (SDK gets type updates only, no business logic).
- wUSDT / $XX / $DECAY contracts.
- eBPF conversion.
- Migration of legacy global vault on mainnet (testnet only — old helper kept `#[deprecated]`).
- Changes to the canonical signed-message layout (`contest_id ++ l2_block_le8 ++ root32`).

---

## Phase 1 — Per-Contest PDAs + Depositor Ledger (Day 1–2)

### 1.1 New PDA derivations
File: [src/svm/pda.rs](src/svm/pda.rs)
- Add seeds:
  - `ESCROW_VAULT_CONTEST_SEED = b"bb_escrow_vault_v2"`
  - `CONTEST_STATE_SEED = b"bb_contest_state_v1"`
- Add functions:
  - `escrow_vault_pda(contest_id: &str) -> Pubkey` = `Pubkey(SHA256(seed ++ b":" ++ contest_id_bytes))`
  - `contest_state_pda(contest_id: &str) -> Pubkey` (parallel derivation)
  - `escrow_vault_address(contest_id: &str) -> String`
  - `contest_state_pda_address(contest_id: &str) -> String`
- Keep legacy global `escrow_vault_pda()` exported but mark `#[deprecated]`.
- Tests: distinct `contest_id` → distinct PDAs; deterministic; never collides with `swap_pool_pda`/`maxx_curve_pda`/`decay_treasury_pda`/global escrow.

### 1.2 Re-exports
File: [src/svm/mod.rs](src/svm/mod.rs)
- Re-export the new helpers.

### 1.3 Depositor ledger (ReDB)
File: [src/storage/mod.rs](src/storage/mod.rs)
- New struct:
  ```rust
  pub struct EscrowDepositorEntry {
      pub contest_id: String,
      pub wallet: String,
      pub deposit_tx_sig: String,
      pub amount_lamports: u64,
      pub deposited_at: u64,
      pub used: bool,
      pub refunded: bool,
  }
  ```
- New tables:
  - `ESCROW_DEPOSITORS: TableDefinition<&str, &[u8]>` keyed by `"{contest_id}:{deposit_tx_sig}"` → JSON.
  - `ESCROW_DEPOSITORS_BY_CONTEST: TableDefinition<&str, &[u8]>` keyed by `contest_id` → JSON `Vec<deposit_tx_sig>` (index for sweep iteration).
- Methods on `ConcurrentBlockchain`: `store_depositor_entry`, `load_depositor_entry`, `mark_depositor_used`, `mark_depositor_refunded`, `list_depositors_for_contest`.

### 1.4 ContestState extensions
File: [src/storage/mod.rs](src/storage/mod.rs)
- Add to `ContestState` (back-compat with `#[serde(default)]`):
  - `vault_pda: String` (bs58 of per-contest PDA)
  - `house_rake_swept_tx: Option<String>`

### 1.5 DepositRecord extension
File: [src/storage/mod.rs](src/storage/mod.rs)
- Add `contest_id: Option<String>` to existing `DepositRecord` (back-compat serde).

---

## Phase 2 — InitContest + VerifyDeposit (Day 3) — depends on Phase 1

### 2.1 `init_contest_reserve` gRPC
File: [src/settlement/mod.rs](src/settlement/mod.rs)
- Reject if `contest_state_pda(contest_id)` already exists in ReDB and status ≠ `Open`.
- Debit `dealer_address` → credit `escrow_vault_pda(contest_id)` (no longer global).
- Persist `ContestState { vault_pda, status: Open, ... }` to ReDB **before** updating DashMap cache (apply existing ReDB-first pattern).
- Record on PoH block.

### 2.2 HTTP mirror
File: [src/main.rs](src/main.rs), [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs)
- Add `POST /escrow/init-contest` — same auth as `SubmitMerkleRoot` (sequencer-signed) so L2 can call without gRPC.

### 2.3 `escrow_deposit_handler`
File: [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs)
- Add **required** `contest_id` field to `EscrowDepositRequest`.
- Canonical signed message becomes:
  `"ESCROW_DEPOSIT:{contest_id}:{wallet}:{amount}:{ts}:{nonce}"`
- Reject if no `ContestState` for `contest_id`, or `status != Open`.
- Credit `escrow_vault_pda(contest_id)` instead of global.
- Persist `EscrowDepositorEntry { used:false, refunded:false }` to ReDB **before** mutating DashMap.
- Update `ContestState.total_deposited += amount_lamports` (ReDB-first, then cache).

### 2.4 `verify_deposit` gRPC
File: [src/settlement/mod.rs](src/settlement/mod.rs)
- Look up `EscrowDepositorEntry` by `(contest_id, deposit_tx_sig)`.
- Enforce:
  - Entry exists → else `TX_NOT_FOUND`
  - `entry.contest_id == req.contest_id` → else `WRONG_CONTEST`
  - `expected_amount` matches when non-zero → else `WRONG_AMOUNT`
  - `!entry.used` → else `ALREADY_USED`
  - `ContestState.status == Open` → else `CONTEST_CLOSED`
- On success, `mark_depositor_used(...)` (ReDB-first), then return canonical `depositor_wallet` from the ledger (never echo caller-supplied wallet).

### 2.5 SDK
File: [sdk/dealer.sdk.ts](sdk/dealer.sdk.ts)
- Add `contest_id` on deposit/verify payload types. Type-only, no logic change.

---

## Phase 3 — RegisterSequencer (Day 4) — parallel with Phase 2

### 3.1 Proto extension
File: [proto/settlement.proto](proto/settlement.proto)
- Add 6th RPC:
  ```proto
  rpc RegisterSequencer(RegisterSequencerRequest) returns (RegisterSequencerResponse);

  message RegisterSequencerRequest {
      bytes  sequencer_pubkey = 1; // 32 bytes
      string label            = 2;
      bytes  authority_pubkey = 3; // 32 bytes — must match L1_ROOT_AUTHORITY_PUBKEY
      bytes  authority_sig    = 4; // 64 bytes Ed25519
      string nonce            = 5;
      int64  timestamp        = 6;
  }
  message RegisterSequencerResponse {
      bool   success = 1;
      string error_message = 2;
  }
  ```
- Authority signs:
  `b"REGISTER_SEQUENCER:" ++ sequencer_pubkey ++ label_bytes ++ timestamp_le8 ++ nonce_bytes`

### 3.2 Persistence
File: [src/storage/mod.rs](src/storage/mod.rs)
- New table `SEQUENCER_ALLOWLIST: TableDefinition<&str /*hex pk*/, &[u8] /*JSON*/>` storing `{label, registered_at, registered_by}`.
- Methods: `store_sequencer`, `list_sequencers`, `remove_sequencer`.

### 3.3 Live allowlist
File: [src/main.rs](src/main.rs)
- Promote `AppState.l2_sequencer_allowlist` from `HashSet<String>` → `Arc<DashMap<String, SequencerEntry>>`.
- Bootstrap = (env `L2_SEQUENCER_PUBKEY`/`L2_SEQUENCER_ALLOWLIST`) ∪ (ReDB table).
- Update read sites in [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs) and [src/settlement/mod.rs](src/settlement/mod.rs).

### 3.4 HTTP mirrors
- `POST /admin/sequencer/register` (mirror of RPC)
- `POST /admin/sequencer/revoke`
- `GET /admin/sequencer/list`
- Gated by `L1_ROOT_AUTHORITY_PUBKEY` env. If unset → 503.
- Replay protection via `used_nonces` with `register_sequencer:` prefix.

---

## Phase 4 — SubmitMerkleRoot Hardening + Rake Sweep (Day 5) — depends on Phases 1–3

### 4.1 gRPC `submit_merkle_root` parity
File: [src/settlement/mod.rs](src/settlement/mod.rs)
- Add **monotonicity check** (load `ContestState.last_l2_block`, reject `<=`). HTTP already has it; gRPC does not.
- Switch `let _ = self.blockchain.store_*` to explicit error returns (`Status::internal`) — **ReDB-first**.

### 4.2 Receipt-hash integrity
- Verify `receipt_hash == hex(SHA-256("{contest_id}:{winning_outcome}:{resolved_at}:{total_deposited}:{total_payout}:{house_rake}"))`.
- Binds the trusted-but-unsigned proto fields to the audit trail.

### 4.3 House-rake sweep
- Read `BB_TREASURY_ADDRESS` env (validate base58, 32 bytes). If unset → hard-fail with clear log.
- Debit `escrow_vault_pda(contest_id)` by `house_rake` (lamports) → credit treasury. ReDB-first; rollback on credit failure.
- Stamp `ContestState.house_rake_swept_tx = Some(tx_hash)` so it cannot run twice.
- Record one PoH tx for the root submission and a second for the rake transfer.

### 4.4 HTTP mirror
File: [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs)
- `escrow_submit_state_root_handler` already has monotonicity + ReDB-first; just add the rake sweep.

---

## Phase 5 — ClaimWinnings + GetContestStatus + Heartbeat (Day 6) — depends on Phase 4

### 5.1 `escrow_withdraw_handler`
File: [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs)
- Switch balance-check, debit, and rollback to `escrow_vault_pda(contest_id)`.
- Keep existing drain-guard but compute against the per-contest vault balance as a second backstop.
- Persist explicit `EscrowClaim { contest_id, wallet, amount, ts }` audit record in addition to the existing claim flag.

### 5.2 gRPC `ClaimWinnings`
File: [proto/settlement.proto](proto/settlement.proto), [src/settlement/mod.rs](src/settlement/mod.rs)
- New RPC delegating to the same internal flow as the HTTP handler.
- Proto:
  ```proto
  message ClaimWinningsRequest {
      string contest_id      = 1;
      string wallet          = 2;
      uint64 amount_lamports = 3;
      repeated bytes proof   = 4; // each 32 bytes
      bytes  pubkey          = 5; // 32 bytes
      bytes  signature       = 6; // 64 bytes
      int64  timestamp       = 7;
      string nonce           = 8;
  }
  message ClaimWinningsResponse {
      bool   success = 1;
      string l1_tx_hash = 2;
      uint64 new_balance_lamports = 3;
      string error_message = 4;
  }
  ```

### 5.3 GetContestStatus extensions
- Extend `ContestStatusResponse` with `vault_balance_lamports` and `last_l2_block` (additive fields).

### 5.4 SyncBridge extensions
- Extend `SyncBridgeResponse` with `sequencer_count`, `open_contest_count`, `settled_contest_count`.

---

## Phase 6 — Expired Sweep + Integration Test (Day 7) — depends on Phase 5

### 6.1 Real expiry sweep
File: [src/main.rs](src/main.rs) (~line 3787, replaces cache-prune loop)
- Every 60s, iterate contests where `status == Settled && current_slot > claim_deadline_slot`.
- For each:
  1. Compute `unclaimed_lamports = total_deposited - total_claimed - house_rake` (in lamports — handle SPL/lamport units consistently).
  2. List depositors via `list_depositors_for_contest(contest_id)`. Eligible = `used == true && refunded == false`.
  3. Pro-rata refund: `refund_i = unclaimed * (entry_i.amount_lamports / sum_of_eligible_amounts)` using integer math.
  4. Debit `escrow_vault_pda(contest_id)` → credit each depositor wallet, ReDB-first per refund, mark `refunded = true`.
  5. Route rounding remainder (dust) to `BB_TREASURY_ADDRESS`.
  6. Set `ContestState.status = Expired`, persist; only then evict from cache.
  7. Record one PoH tx per refund (small N at first; batch later if needed).

### 6.2 Integration test
File: `tests/escrow_lifecycle_integration.rs` (new)
- Bootstrap `AppState` in-process (no HTTP), generate sequencer keypair + treasury PDA.
- Flow:
  1. `RegisterSequencer` (root authority signed)
  2. `InitContestReserve` (dealer locks reserve into per-contest vault)
  3. 3× `escrow_deposit_handler` (3 distinct user wallets, each with `contest_id`)
  4. 3× `verify_deposit` (each succeeds, marks used)
  5. `submit_merkle_root` with 1 winner + non-zero rake
  6. Assert: `BB_TREASURY_ADDRESS` balance increased by exactly `rake_lamports`
  7. Winner calls `escrow_withdraw_handler` with valid Merkle proof
  8. Fast-forward `current_slot` past `claim_deadline_slot`
  9. Trigger sweep manually (extract sweep into testable fn)
  10. Assert: 2 losers refunded pro-rata, treasury keeps dust, `status == Expired` in ReDB

### 6.3 Unit test
- Focused gRPC `submit_merkle_root` monotonicity test (HTTP already covered in [tests/escrow_e2e.rs](tests/escrow_e2e.rs)).

---

## Relevant Files

| File | Change |
|---|---|
| [src/svm/pda.rs](src/svm/pda.rs) | Per-contest PDA derivations + tests; deprecate global vault helper |
| [src/svm/mod.rs](src/svm/mod.rs) | Re-export new helpers |
| [src/storage/mod.rs](src/storage/mod.rs) | `EscrowDepositorEntry`, 2 new ReDB tables, sequencer table, `ContestState` fields, `DepositRecord.contest_id` |
| [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs) | Deposit handler `contest_id`, withdraw per-contest vault, rake-sweep mirror |
| [src/settlement/mod.rs](src/settlement/mod.rs) | Wire init/verify/submit/claim/register to per-contest PDAs + ReDB-first; add monotonicity + rake sweep |
| [proto/settlement.proto](proto/settlement.proto) | Add `RegisterSequencer`, `ClaimWinnings`; extend `ContestStatusResponse`, `SyncBridgeResponse` |
| [src/main.rs](src/main.rs) | Bootstrap env+ReDB allowlist; new HTTP routes; replace cache-prune with real expiry sweep; read `BB_TREASURY_ADDRESS` + `L1_ROOT_AUTHORITY_PUBKEY` |
| [sdk/dealer.sdk.ts](sdk/dealer.sdk.ts) | Add `contest_id`; expose `registerSequencer`, `claimWinnings` |
| `tests/escrow_lifecycle_integration.rs` | New end-to-end test |

---

## Verification

1. `cargo build --features unsafe_admin` — clean, no warnings on changed files.
2. `cargo test --test escrow_e2e` (existing) **and** `cargo test --test escrow_lifecycle_integration` (new) pass.
3. PDA determinism + uniqueness unit tests.
4. Manual smoke (PowerShell against running node — extend [tests/l1_smoke.ps1](tests/l1_smoke.ps1)):
   - `RegisterSequencer` → `InitContest` → 2 deposits with `contest_id` → submit root with non-zero rake → `GET /balance/:treasury` increased by exactly `rake_lamports` → winner claim → fast-forward slot or wait → losers receive refund credits.
5. Crash test: kill node between ReDB write and DashMap insert in deposit/init/submit; restart; cache rebuilds match ReDB; no double-counting; no funds lost.
6. `grpcurl -plaintext localhost:50052 settlement.SettlementService/GetContestStatus` returns `vault_balance_lamports`, `last_l2_block`.

---

## Environment Variables (new/used)

| Var | Purpose | Required |
|---|---|---|
| `L2_SEQUENCER_PUBKEY` | Bootstrap sequencer (legacy) | No (env ∪ ReDB) |
| `L2_SEQUENCER_ALLOWLIST` | Comma-sep bootstrap allowlist | No |
| `L1_ROOT_AUTHORITY_PUBKEY` | Authorises `RegisterSequencer` | **Yes** for register/revoke |
| `BB_TREASURY_ADDRESS` | Receives rake + expired-contest dust | **Yes** for `SubmitMerkleRoot` |

---

## Open Items for Confirmation

1. **Treasury address kind.** Recommend `treasury_pda()` (no signing key) so rake + dust are equally untouchable. Alternative: ops-controlled wallet. Default if no answer: PDA.
2. **Pro-rata rounding.** Plan routes remainder to treasury. Alternative: largest-depositor remainder.
3. **Sequencer self-rotation.** Plan limits register/revoke to root authority only. Self-rotation could be a Day 8+ follow-up if ops needs it.

---

## Day-by-Day Summary

| Day | Phase | Ship |
|---|---|---|
| 1–2 | Phase 1 | Per-contest PDAs + depositor ledger + ContestState fields |
| 3 | Phase 2 | InitContest + VerifyDeposit live against per-contest vaults |
| 4 | Phase 3 | RegisterSequencer (gRPC + HTTP + ReDB) |
| 5 | Phase 4 | SubmitMerkleRoot hardening + house-rake sweep |
| 6 | Phase 5 | ClaimWinnings RPC + extended status/heartbeat |
| 7 | Phase 6 | Expired pro-rata sweep + integration test green |

> After Day 7: rotate `DEALER_JWT`, point `L1_GRPC_URL`, run the first live BB market with real deposits and trustless Merkle claims on our custom L1.
