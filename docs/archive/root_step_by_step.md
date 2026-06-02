# L1 BlackBook Escrow — Step-by-Step Build Log

> Companion to [root_session.md](root_session.md). Each step is a single, atomic action with a verification command. Mark `[x]` as you complete. Do **not** skip the verification line — that's the gate before moving on.

Conventions:
- ⏱ = expected wall time (rough)
- ✅ = verification command (must pass before proceeding)
- 🔒 = touches money paths — extra care, run crash test
- All terminal commands are PowerShell from repo root unless noted.

---

## Day 1 — Per-Contest PDA Derivations + Storage Skeleton

### Step 1.1.1 — Add seeds + per-contest PDA functions
- [ ] Edit [src/svm/pda.rs](src/svm/pda.rs):
  - Add `pub const ESCROW_VAULT_CONTEST_SEED: &[u8] = b"bb_escrow_vault_v2";`
  - Add `pub const CONTEST_STATE_SEED: &[u8] = b"bb_contest_state_v1";`
  - Add `pub fn escrow_vault_pda_for(contest_id: &str) -> Pubkey` — `SHA256(seed ++ b":" ++ contest_id_bytes)`.
  - Add `pub fn contest_state_pda(contest_id: &str) -> Pubkey`.
  - Add string helpers `escrow_vault_address_for(contest_id)` and `contest_state_pda_address(contest_id)`.
  - Mark legacy `escrow_vault_pda()` with `#[deprecated(note = "Use escrow_vault_pda_for(contest_id)")]`.
- ✅ `cargo check --features unsafe_admin` passes (deprecation warnings expected on existing call sites — that's OK for this step).
- ⏱ 30 min

### Step 1.1.2 — PDA tests
- [ ] Append to `#[cfg(test)] mod tests` in [src/svm/pda.rs](src/svm/pda.rs):
  - `per_contest_vault_is_deterministic`
  - `distinct_contest_ids_yield_distinct_pdas`
  - `per_contest_vault_does_not_collide_with_global_pdas` (vs swap_pool, maxx_curve, decay_treasury, legacy escrow)
  - `contest_state_pda_distinct_from_vault_pda` (same contest_id)
- ✅ `cargo test -p layer1 --lib svm::pda::tests`
- ⏱ 30 min

### Step 1.2.1 — Re-export new helpers
- [ ] Edit [src/svm/mod.rs](src/svm/mod.rs) to re-export `escrow_vault_pda_for`, `contest_state_pda`, `escrow_vault_address_for`, `contest_state_pda_address`.
- ✅ `cargo check --features unsafe_admin`
- ⏱ 5 min

### Step 1.3.1 — Define `EscrowDepositorEntry` struct
- [ ] In [src/storage/mod.rs](src/storage/mod.rs) add struct (Serialize/Deserialize/Debug/Clone) with fields per [root_session.md §1.3](root_session.md).
- ⏱ 10 min

### Step 1.3.2 — Add ReDB table definitions
- [ ] Add `ESCROW_DEPOSITORS: TableDefinition<&str, &[u8]>` near the existing table defs.
- [ ] Add `ESCROW_DEPOSITORS_BY_CONTEST: TableDefinition<&str, &[u8]>`.
- [ ] Open both in the `init_tables`/equivalent path so ReDB creates them on first run.
- ✅ `cargo check`
- ⏱ 20 min

### Step 1.3.3 — Implement CRUD methods on `ConcurrentBlockchain`
- [ ] `store_depositor_entry(&EscrowDepositorEntry)` — ReDB-first; updates BY_CONTEST index transactionally in same write txn.
- [ ] `load_depositor_entry(contest_id, sig) -> Option<EscrowDepositorEntry>`.
- [ ] `mark_depositor_used(contest_id, sig) -> Result<(), String>`.
- [ ] `mark_depositor_refunded(contest_id, sig) -> Result<(), String>`.
- [ ] `list_depositors_for_contest(contest_id) -> Vec<EscrowDepositorEntry>`.
- ✅ `cargo check` + add 3 unit tests in `#[cfg(test)] mod tests` at the bottom of `storage/mod.rs`:
  - `depositor_entry_round_trip`
  - `mark_used_then_refunded_persists`
  - `list_depositors_returns_only_target_contest`
- ✅ `cargo test -p layer1 --lib storage::tests::depositor`
- ⏱ 90 min

### Step 1.4.1 — Extend `ContestState` (back-compat)
- [ ] Add `#[serde(default)] pub vault_pda: String,` and `#[serde(default)] pub house_rake_swept_tx: Option<String>,` to `ContestState` in [src/storage/mod.rs](src/storage/mod.rs).
- [ ] Update every constructor of `ContestState` in the codebase (search for `ContestState {`) to populate `vault_pda` (use `String::new()` for now; Phase 2 wires real values) and `house_rake_swept_tx: None`.
- ✅ `cargo check --features unsafe_admin` — zero errors.
- ⏱ 30 min

### Step 1.5.1 — Add `contest_id` to `DepositRecord`
- [ ] Add `#[serde(default)] pub contest_id: Option<String>,` to `DepositRecord`.
- [ ] Search for `DepositRecord {` constructors and add `contest_id: None` (or `Some(...)` where the contest is known).
- ✅ `cargo check --features unsafe_admin`
- ⏱ 20 min

### Step 1.x — Day 1 close-out
- [ ] `cargo build --features unsafe_admin` clean.
- [ ] `cargo test` — all existing tests still green.
- [ ] `git add -A && git commit -m "feat(escrow): phase 1 — per-contest PDAs + depositor ledger + ContestState extensions"`
- 🔒 No money-path changes shipped today; only types and storage primitives.

---

## Day 2 — Wire Storage Migration + Backfill

### Step 1.6.1 — ReDB schema upgrade safety
- [ ] On startup in [src/main.rs](src/main.rs), open the new tables inside the same write txn as the existing schema bootstrap. ReDB creates missing tables idempotently — confirm by running on an existing `blockchain_data/blockchain.redb` and observing no panic.
- ✅ `Remove-Item -Recurse blockchain_data; .\target\debug\layer1.exe` — boots clean (then Ctrl-C). Then `.\target\debug\layer1.exe` again on the existing DB — boots clean.
- ⏱ 30 min

### Step 1.6.2 — Smoke: legacy ContestState load
- [ ] Pre-existing ReDB rows lack `vault_pda` and `house_rake_swept_tx` — `#[serde(default)]` handles them. Add a regression unit test that deserializes a JSON blob without the new fields.
- ✅ `cargo test -p layer1 --lib storage::tests::contest_state_legacy_deserialize`
- ⏱ 20 min

### Step 1.6.3 — Day 2 close-out
- [ ] `git commit -m "test(escrow): contest_state legacy deserialization regression test"`

---

## Day 3 — InitContest + VerifyDeposit (Phase 2)

### Step 2.1.1 🔒 — `init_contest_reserve` rewrite
- [ ] In [src/settlement/mod.rs](src/settlement/mod.rs):
  - Look up `load_contest_state(contest_id)`. If exists with status ≠ `Open` → reject `"Contest already initialized"`.
  - Compute `vault = escrow_vault_address_for(&req.contest_id)`.
  - Debit `req.dealer_address` → credit `vault` (replace current global escrow call).
  - Build `ContestState { vault_pda: vault.clone(), ... }` with status=Open.
  - **ReDB-first**: replace `let _ = self.blockchain.store_contest_state(...)` with explicit error → `Status::internal`. Only on success update DashMap.
- ✅ `cargo check`
- ⏱ 60 min

### Step 2.2.1 — HTTP mirror `POST /escrow/init-contest`
- [ ] Add handler `escrow_init_contest_handler` in [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs).
  - Auth = sequencer-signed payload. Canonical msg: `b"INIT_CONTEST:" ++ contest_id_bytes ++ dealer_address_bytes ++ bb_reserve_le8 ++ ts_le8 ++ nonce_bytes`.
  - Reuse the allowlist verify pattern from `escrow_submit_state_root_handler`.
  - Internally calls the same shared function as the gRPC variant (extract a `pub(crate) fn init_contest_internal(...)` to avoid duplication).
- [ ] Register route in [src/main.rs](src/main.rs).
- ✅ `cargo check --features unsafe_admin`
- ⏱ 60 min

### Step 2.3.1 🔒 — `escrow_deposit_handler` add `contest_id`
- [ ] Add `pub contest_id: String,` to `EscrowDepositRequest`.
- [ ] Update canonical signed message to `"ESCROW_DEPOSIT:{contest_id}:{wallet}:{amount}:{ts}:{nonce}"`.
- [ ] Look up `ContestState` by `contest_id`. If missing or `status != Open` → 400.
- [ ] Replace `escrow_addr = escrow_vault_address()` with `escrow_vault_address_for(&req.contest_id)`.
- [ ] Build `EscrowDepositorEntry { used: false, refunded: false, deposit_tx_sig: tx_hash, ... }`.
- [ ] **ReDB-first**: persist depositor entry, then update `ContestState.total_deposited += amount_lamports` (also ReDB-first), only then DashMap caches.
- ✅ Crash test: insert a `panic!()` between the depositor write and the cache write, run a deposit, restart, confirm ReDB has the entry and cache rebuilds correctly. Then remove the panic.
- ⏱ 90 min

### Step 2.4.1 🔒 — `verify_deposit` gRPC against ledger
- [ ] In [src/settlement/mod.rs](src/settlement/mod.rs):
  - Replace lookup-by-`deposit_requests` with `load_depositor_entry(req.contest_id, req.deposit_tx_sig)`.
  - Enforce all 5 error codes per [root_session.md §2.4](root_session.md).
  - `mark_depositor_used` ReDB-first on success.
  - Return canonical `depositor_wallet` from the ledger entry.
- ✅ Add gRPC unit test (in-process tonic client) — `verify_deposit_rejects_wrong_contest`, `verify_deposit_rejects_double_use`.
- ⏱ 90 min

### Step 2.5.1 — SDK type updates
- [ ] Add `contest_id: string` to deposit/verify request types in [sdk/dealer.sdk.ts](sdk/dealer.sdk.ts). No business-logic change.
- ✅ `cd blackbook-wallet ; npx tsc --noEmit` (or whichever script the wallet uses for type-check) is clean.
- ⏱ 15 min

### Step 2.x — Day 3 close-out
- [ ] `cargo test --test escrow_e2e` still green (the test fixtures may need a `contest_id` field — update tests, do not relax the requirement).
- [ ] `git commit -m "feat(escrow): phase 2 — per-contest deposit + verify ledger"`

---

## Day 4 — RegisterSequencer (Phase 3)

### Step 3.1.1 — Extend proto
- [ ] Edit [proto/settlement.proto](proto/settlement.proto): add `RegisterSequencer` RPC + request/response messages per [root_session.md §3.1](root_session.md).
- ✅ `cargo check` triggers `tonic_build`; new types compile.
- ⏱ 20 min

### Step 3.2.1 — Sequencer ReDB table + methods
- [ ] In [src/storage/mod.rs](src/storage/mod.rs): add `SEQUENCER_ALLOWLIST: TableDefinition<&str, &[u8]>` and `SequencerEntry { label, registered_at, registered_by }` struct.
- [ ] Methods: `store_sequencer`, `list_sequencers`, `remove_sequencer`, `load_sequencer`.
- ✅ Round-trip unit test.
- ⏱ 60 min

### Step 3.3.1 🔒 — Live allowlist (`AppState` change)
- [ ] In [src/main.rs](src/main.rs) change `pub l2_sequencer_allowlist: HashSet<String>` to `pub l2_sequencer_allowlist: Arc<DashMap<String, SequencerEntry>>`.
- [ ] Bootstrap = union of env vars + `list_sequencers()` from ReDB.
- [ ] Update the two read sites:
  - [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs) — replace `.iter().find(...)` with DashMap iteration.
  - [src/settlement/mod.rs](src/settlement/mod.rs) — `BlackBookSettlementService.l2_sequencer_allowlist` becomes the same `Arc<DashMap>`.
- ✅ `cargo check --features unsafe_admin`
- ⏱ 90 min

### Step 3.3.2 — `register_sequencer` gRPC handler
- [ ] Implement in [src/settlement/mod.rs](src/settlement/mod.rs):
  - Read `L1_ROOT_AUTHORITY_PUBKEY` env. If unset → `Status::failed_precondition("Root authority not configured")`.
  - Verify `req.authority_pubkey == env_pubkey` (binary equality).
  - Verify Ed25519 sig over canonical authority message.
  - Reject `timestamp` > 60 s old.
  - Atomic nonce check via `state.used_nonces` with key `register_sequencer:{nonce}`.
  - **ReDB-first**: `store_sequencer(...)`, then `allowlist.insert(...)`.
- ⏱ 60 min

### Step 3.4.1 — HTTP mirrors
- [ ] Add `POST /admin/sequencer/register` (calls same internal fn as RPC).
- [ ] Add `POST /admin/sequencer/revoke` — same auth model.
- [ ] Add `GET /admin/sequencer/list` — returns `[{ pubkey_hex, label, registered_at, registered_by }]`. **No auth needed** (allowlist is public information).
- ✅ Smoke with curl/Invoke-RestMethod.
- ⏱ 60 min

### Step 3.x — Day 4 close-out
- [ ] `cargo test` clean.
- [ ] `git commit -m "feat(escrow): phase 3 — RegisterSequencer (gRPC + HTTP + ReDB)"`

---

## Day 5 — SubmitMerkleRoot Hardening + Rake Sweep (Phase 4)

### Step 4.1.1 🔒 — gRPC monotonicity + ReDB-first
- [ ] In [src/settlement/mod.rs](src/settlement/mod.rs) `submit_merkle_root`:
  - After zero-sum check, load `ContestState` via `load_contest_state`. If `req.l2_block_number <= existing.last_l2_block` → `Status::aborted("L2 block monotonicity violated")`.
  - Replace `let _ = self.blockchain.store_*` with explicit error → `Status::internal`.
- ⏱ 30 min

### Step 4.2.1 — Receipt-hash integrity
- [ ] Compute expected = `hex(SHA-256("{contest_id}:{winning_outcome}:{resolved_at}:{total_deposited}:{total_payout}:{house_rake}"))`.
- [ ] Compare to `req.receipt_hash`. Mismatch → `Status::invalid_argument("receipt_hash mismatch")`.
- ⏱ 20 min

### Step 4.3.1 🔒 — House-rake sweep
- [ ] Read `BB_TREASURY_ADDRESS` env once at startup, store on `AppState.bb_treasury_address: Option<String>`.
- [ ] Validate base58 → 32 bytes. If unset → log warn at startup; `submit_merkle_root` rejects with `Status::failed_precondition("BB_TREASURY_ADDRESS not configured")`.
- [ ] Convert `house_rake` (SPL units, 6 decimals) → lamports (5 decimals): `house_rake / 10`.
- [ ] If already swept (`existing.house_rake_swept_tx.is_some()`) → skip. Otherwise:
  - Debit `escrow_vault_address_for(contest_id)` by rake_lamports.
  - Credit treasury.
  - Rollback debit if credit fails.
  - Stamp `contest.house_rake_swept_tx = Some(uuid)` before persisting.
- [ ] Record TWO PoH txs (root submission + rake transfer).
- ✅ Manual smoke with non-zero rake; check treasury balance increased by exact amount.
- ⏱ 90 min

### Step 4.4.1 — Mirror in HTTP
- [ ] Apply same rake-sweep block to `escrow_submit_state_root_handler` (HTTP path) in [src/contracts/global_escrow/mod.rs](src/contracts/global_escrow/mod.rs). Extract a shared `fn settle_and_sweep_internal(...)` to avoid drift.
- ✅ `cargo test --test escrow_e2e`
- ⏱ 60 min

### Step 4.x — Day 5 close-out
- [ ] `git commit -m "feat(escrow): phase 4 — SubmitMerkleRoot monotonicity, receipt hash, rake sweep"`

---

## Day 6 — ClaimWinnings + Status/Heartbeat (Phase 5)

### Step 5.1.1 🔒 — `escrow_withdraw_handler` per-contest vault
- [ ] Replace every `escrow_vault_address()` with `escrow_vault_address_for(&req.market_id)` in the withdraw handler.
- [ ] Persist `EscrowClaim { contest_id, wallet, amount, ts }` audit record (new ReDB row in existing claims table).
- ⏱ 45 min

### Step 5.2.1 — gRPC `ClaimWinnings`
- [ ] Extract HTTP withdraw logic into `pub(crate) async fn claim_winnings_internal(state: AppState, req: ClaimWinningsRequest) -> Result<ClaimResult, ClaimError>`.
- [ ] HTTP handler calls it; new gRPC handler calls it.
- [ ] Add proto messages per [root_session.md §5.2](root_session.md).
- ⏱ 90 min

### Step 5.3.1 — Extend `ContestStatusResponse`
- [ ] Add `uint64 vault_balance_lamports = 8;` and `uint64 last_l2_block = 9;` (additive, safe).
- [ ] Populate from `get_balance_lamports(escrow_vault_address_for(...))` and `contest.last_l2_block`.
- ⏱ 20 min

### Step 5.4.1 — Extend `SyncBridgeResponse`
- [ ] Add `uint32 sequencer_count = 4; uint32 open_contest_count = 5; uint32 settled_contest_count = 6;`.
- ⏱ 15 min

### Step 5.x — Day 6 close-out
- [ ] `cargo test --test escrow_e2e` green.
- [ ] `git commit -m "feat(escrow): phase 5 — ClaimWinnings RPC + extended status/heartbeat"`

---

## Day 7 — Expired Sweep + Integration Test (Phase 6)

### Step 6.1.1 🔒 — Real expiry sweep
- [ ] Replace the housekeeping loop in [src/main.rs](src/main.rs) (~line 3787).
- [ ] Extract sweep logic into `pub fn sweep_expired_contests(state: &AppState) -> SweepReport` so the integration test can drive it deterministically.
- [ ] Implementation per [root_session.md §6.1](root_session.md):
  1. Iterate Settled & past-deadline contests.
  2. List depositors, filter `used && !refunded`.
  3. Compute pro-rata per depositor with integer math: `refund_i = unclaimed * amount_i / sum_eligible_amounts`.
  4. Debit vault → credit each, ReDB-first per refund. `mark_depositor_refunded`.
  5. Send remainder to `BB_TREASURY_ADDRESS`.
  6. Set `status = Expired`, persist; evict cache last.
  7. PoH tx per refund.
- ⏱ 180 min

### Step 6.2.1 — Integration test
- [ ] Create `tests/escrow_lifecycle_integration.rs` per [root_session.md §6.2](root_session.md). Run flow in-process.
- ✅ `cargo test --test escrow_lifecycle_integration -- --nocapture`
- ⏱ 180 min

### Step 6.3.1 — gRPC monotonicity unit test
- [ ] Single-function test that submits two roots with descending `l2_block_number`; second is rejected.
- ⏱ 30 min

### Step 6.x — Day 7 close-out
- [ ] `cargo test` — full suite green.
- [ ] `cargo build --release --features unsafe_admin`
- [ ] Update [tests/l1_smoke.ps1](tests/l1_smoke.ps1) with the new lifecycle commands.
- [ ] `git commit -m "feat(escrow): phase 6 — expired pro-rata sweep + e2e integration test"`
- [ ] Tag: `git tag -a v5.1.0-escrow-complete -m "L1 escrow §2 complete: per-contest PDAs, rake sweep, pro-rata refund, full lifecycle"`

---

## Cross-Cutting Verification (Run After Each Day)

```powershell
# Type & lint gate
cargo check --features unsafe_admin 2>&1 | Select-String -Pattern "error|warning" | Select-Object -First 20

# Test gate
cargo test --features unsafe_admin

# Boot gate (fresh DB)
Remove-Item -Recurse -Force blockchain_data -ErrorAction SilentlyContinue
$env:RUST_LOG = "info"
$env:L1_ROOT_AUTHORITY_PUBKEY = "<hex32>"
$env:BB_TREASURY_ADDRESS = "<base58_32>"
.\target\debug\layer1.exe
# Ctrl-C after observing clean startup logs.

# Boot gate (existing DB — schema migration safety)
.\target\debug\layer1.exe
```

## Rollback / Safety

- After each `git commit`, `git tag dayN-checkpoint` so a single `git reset --hard dayN-checkpoint` recovers.
- Never push force. Never use `--no-verify`.
- Treasury env vars must be set on production before any `SubmitMerkleRoot` is accepted; otherwise the contract self-rejects (intentional).
- The legacy global `escrow_vault_pda()` keeps existing testnet funds reachable; do **not** remove it during these 7 days.

## When You Get Stuck

- Type errors first: `cargo check --message-format=short --features unsafe_admin | Select-Object -First 30`.
- Re-read the relevant phase in [root_session.md](root_session.md). The step-by-step here is the *how*; that doc is the *why*.
- Crash-test pattern: insert `panic!("CRASH_TEST")` between ReDB write and DashMap update. Restart. Cache must rebuild correctly; no funds lost.
