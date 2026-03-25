# NEXT-STEPS-INTEGRATION.md — Integration Milestones

> Specific, actionable milestones with file paths, method signatures, and acceptance criteria.
> Each milestone is independently testable and builds on the previous.
> Last updated: 2025-06-25

---

## Milestone 1: Graceful Shutdown & Data Integrity

**Goal**: Zero data loss on Writer restart. Dirty SVM accounts flushed to ReDB on SIGTERM/SIGINT.

### What Exists
- `flush_final_block()` method at [src/poh_blockchain.rs](src/poh_blockchain.rs) (~line 672) — produces a final empty block and calls `store_block()`
- `restore_chain_state()` method at [src/poh_blockchain.rs](src/poh_blockchain.rs) (~line 657) — reads last block from ReDB on startup
- Shutdown handler in [src/main.rs](src/main.rs) — currently just logs "Shutdown signal received"
- `BlackBookSVM.end_of_block()` flushes dirty accounts, but only called inside normal block production

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 1.1 | Wire `flush_final_block()` in shutdown handler | `src/main.rs` | In the `tokio::signal::ctrl_c()` handler, call `block_producer.flush_final_block()` before exit |
| 1.2 | Call `svm.end_of_block()` in shutdown path | `src/main.rs` | Ensures dirty DashMap entries persist to ReDB even if mid-slot |
| 1.3 | Verify `restore_chain_state()` on restart | `src/main.rs` | Already called at startup — verify it reads the flushed block slot + hash correctly |
| 1.4 | Add integration test: kill Writer, restart, verify slot continuity | `tests/` | Start Writer → produce 10 blocks → SIGTERM → restart → `getSlot` >= 10 |

### Acceptance Criteria
- [ ] Writer handles SIGTERM without data loss
- [ ] Restart picks up at correct slot + hash (no gap, no duplicate)
- [ ] `getBalance` returns correct post-shutdown values after restart
- [ ] Test passes in CI

---

## Milestone 2: `simulateTransaction` RPC

**Goal**: Wallets like Phantom and Backpack can pre-flight check transactions before signing.

### What Exists
- 28 RPC methods in [src/solana_rpc/mod.rs](src/solana_rpc/mod.rs)
- `BlackBookSVM.execute_transfer()` in [src/svm/runtime.rs](src/svm/runtime.rs) processes real transfers
- `SvmAccountsDB` snapshot capability — DashMap is read-only safe for simulation

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 2.1 | Add `simulateTransaction` to the RPC trait | `src/solana_rpc/mod.rs` | `#[method(name = "simulateTransaction")] async fn simulate_transaction(&self, tx: String, config: Option<Value>) -> RpcResult<Value>` |
| 2.2 | Implement simulation logic | `src/solana_rpc/mod.rs` | Decode base64 tx → extract from/to/amount + recent_blockhash → validate blockhash → check sender balance → return `{ err: null, logs: [...], unitsConsumed: 21000 }` without mutating state |
| 2.3 | Return Solana-compatible response | `src/solana_rpc/mod.rs` | Must match Solana's `SimulateTransactionResponse` shape: `{ context: { slot }, value: { err, logs, accounts, unitsConsumed, returnData } }` |
| 2.4 | Add `replaceRecentBlockhash` config support | `src/solana_rpc/mod.rs` | If `config.replaceRecentBlockhash == true`, skip blockhash validation (Phantom uses this) |

### Acceptance Criteria
- [ ] `simulateTransaction` returns `{ err: null }` for valid transfers with sufficient balance
- [ ] Returns `{ err: "InsufficientFunds" }` for transfers exceeding balance
- [ ] Returns `{ err: "BlockhashNotFound" }` for expired blockhash (unless `replaceRecentBlockhash`)
- [ ] Phantom/Backpack pre-flight check passes when connected to BB RPC
- [ ] State is NOT mutated by simulation (balances unchanged)

---

## Milestone 3: Reader `sendTransaction` Forwarding

**Goal**: Users submitting transactions to a Reader have them forwarded to the Writer and executed.

### What Exists
- `ForwardTransaction` gRPC RPC in [proto/validator_relay.proto](proto/validator_relay.proto)
- `WriterRelayService` handles `forward_transaction()` in [src/relay/mod.rs](src/relay/mod.rs)
- Reader `sendTransaction` RPC method in [src/solana_rpc/mod.rs](src/solana_rpc/mod.rs) — currently executes locally (only works on Writer)

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 3.1 | Add `node_mode` to Solana RPC server context | `src/solana_rpc/mod.rs` | Pass `NodeMode` and `writer_addr` into the RPC impl struct |
| 3.2 | Branch `sendTransaction` by mode | `src/solana_rpc/mod.rs` | If Writer: execute locally (current behavior). If Reader: gRPC `ForwardTransaction(tx_json)` to Writer |
| 3.3 | Create gRPC client in Reader RPC context | `src/solana_rpc/mod.rs` | `ValidatorRelayClient::connect(writer_addr)` — reuse connection, not per-request |
| 3.4 | Return tx signature to caller | `src/solana_rpc/mod.rs` | Writer responds with `tx_id` in `ForwardTransactionResponse` → Reader returns it as the RPC result |
| 3.5 | Handle Writer-down gracefully | `src/solana_rpc/mod.rs` | Return `RpcError` with message "Writer unavailable" if gRPC fails |

### Acceptance Criteria
- [ ] `sendTransaction` on Reader #2 (Oregon) forwards tx to Writer (Virginia)
- [ ] Writer executes tx, includes in next block
- [ ] Block propagates back to Reader #2 — balance updates within 1 slot (600 ms)
- [ ] User receives a valid transaction signature from Reader's RPC response
- [ ] If Writer is down, Reader returns a clear error (not a hang/timeout)

---

## Milestone 4: Dead Code Cleanup & Dependency Pruning

**Goal**: Remove ~2,600 lines of unreachable code and 3–4 unused crate dependencies. Faster compile times, smaller binary.

### Work Required

| # | Task | File | Action |
|---|------|------|--------|
| 4.1 | Delete `src/main_v4.rs` | `src/main_v4.rs` | 1,651 lines. Legacy v4 binary. Not a `[[bin]]` target. |
| 4.2 | Delete `src/consensus/mod.rs` | `src/consensus/mod.rs` | 5 lines. Empty stub — consensus lives in `runtime/consensus.rs` |
| 4.3 | Delete or fix `src/wallet_unified/opaque_impl.rs` | `src/wallet_unified/opaque_impl.rs` | 171 lines. Imports `opaque_ke` which is not in `Cargo.toml`. Will not compile if touched. |
| 4.4 | Remove `consensus` from `lib.rs` and `main.rs` module declarations | `src/lib.rs`, `src/main.rs` | Matches 4.2 |
| 4.5 | Remove `libp2p` from `Cargo.toml` | `Cargo.toml` | Full P2P stack (~9 sub-features) but zero code references it. Adds 30+ seconds to compile. |
| 4.6 | Remove `memmap2` from `Cargo.toml` | `Cargo.toml` | Listed for "Cloudbreak accounts" but no code references it |
| 4.7 | Evaluate `frost-ed25519` | `Cargo.toml` | Only referenced by the broken `opaque_impl.rs`. Remove if 4.3 deletes that file. |
| 4.8 | Remove stale `[[example]]` entries | `Cargo.toml` | References `stress_test`, `create_and_fund_wallets` — files don't exist. Keep only `export_keypair` |

### Acceptance Criteria
- [ ] `cargo build --release` succeeds
- [ ] No warnings about dead code from deleted modules
- [ ] Compile time reduced (measure before/after `cargo build --release --timings`)
- [ ] Binary size reduced
- [ ] `cargo clippy` clean

---

## Milestone 5: Restore Test Suite

**Goal**: Recreate the 26+ tests documented in `BB_SVM_integration_checklist.md` that are missing from the repo.

### Context
The checklist references these test files, none of which exist:
- `tests/svm_accounts_tests.rs` (5 tests)
- `tests/svm_runtime_tests.rs` (5 tests)  
- `tests/svm_block_production_tests.rs` (3 tests)
- `tests/svm_parallel_tests.rs` (4 tests)
- `tests/svm_invariant_tests.rs` (3 tests)
- `tests/rpc_tests.rs` (9 tests)
- `tests/rpc_send_tests.rs` (5 tests)

Only `tests/litesvm_integration.rs` (5 tests) and 4 inline tests in `poh_blockchain.rs` currently exist.

### Work Required

| # | File | Tests to Write | What They Verify |
|---|------|----------------|-----------------|
| 5.1 | `tests/svm_accounts_tests.rs` | `create_account`, `get_nonexistent`, `update_lamports`, `flush_to_redb`, `reload_from_redb` | SvmAccountsDB two-layer store |
| 5.2 | `tests/svm_runtime_tests.rs` | `execute_transfer_success`, `execute_transfer_insufficient`, `blockhash_validation`, `dedup_replay`, `advance_slot` | BlackBookSVM execution |
| 5.3 | `tests/svm_block_production_tests.rs` | `produce_empty_block`, `produce_block_with_txs`, `block_hash_chain` | BlockProducer + FinalizedBlock |
| 5.4 | `tests/svm_parallel_tests.rs` | `parallel_non_overlapping`, `parallel_conflicting`, `batch_sizing`, `rayon_pool` | Sealevel parallel execution |
| 5.5 | `tests/svm_invariant_tests.rs` | `total_lamports_constant`, `no_float_in_path`, `lamport_overflow_check` | Money path integrity |
| 5.6 | `tests/rpc_tests.rs` | `get_balance`, `get_account_info`, `get_slot`, `get_block_height`, `get_epoch_info`, `get_latest_blockhash`, `get_genesis_hash`, `get_version`, `get_health` | Read RPC methods |
| 5.7 | `tests/rpc_send_tests.rs` | `send_transaction`, `get_transaction`, `get_signatures_for_address`, `simulate_transaction`, `is_blockhash_valid` | Write + simulate RPC methods |

### Acceptance Criteria
- [ ] `cargo test` runs 35+ tests (9 existing + 26 new)
- [ ] All tests pass on clean state (fresh ReDB)
- [ ] Tests can run in CI without external dependencies (no Supabase, no Vault)
- [ ] Test output matches the documented results in `BB_SVM_integration_checklist.md`

---

## Milestone 6: Health Monitoring & Metrics

**Goal**: Production observability. Prometheus scrape endpoint, structured logging, alerting hooks.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 6.1 | Add `/metrics` Prometheus endpoint | `src/main.rs` | Expose: `blackbook_slot_height`, `blackbook_blocks_produced`, `blackbook_txs_total`, `blackbook_svm_accounts_total`, `blackbook_rpc_requests_total{method}`, `blackbook_relay_connected_readers` |
| 6.2 | Add `metrics` + `prometheus` crates | `Cargo.toml` | `prometheus = "0.13"` or `metrics = "0.23"` + `metrics-exporter-prometheus` |
| 6.3 | Instrument RPC methods | `src/solana_rpc/mod.rs` | Increment counter per method call, histogram for latency |
| 6.4 | Instrument block production | `src/main.rs` | Timer for `produce_block()` duration, counter for tx/block |
| 6.5 | Expose Writer `GetStatus` as REST | `src/main.rs` | `GET /status` → `{ node_id, mode, slot, hash, epoch, uptime, connected_readers }` |
| 6.6 | Reader health: blocks behind Writer | `src/reader/mod.rs` | Track `writer_slot - local_slot` as a gauge metric |

### Acceptance Criteria
- [ ] `curl http://localhost:8080/metrics` returns Prometheus-formatted text
- [ ] Grafana dashboard can scrape all 5 nodes
- [ ] Alert fires if any Reader falls >10 slots behind
- [ ] Alert fires if Writer stops producing blocks for >5 seconds

---

## Milestone 7: WebSocket Subscriptions

**Goal**: Real-time push notifications for wallets and explorers. No more polling.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 7.1 | Add WebSocket server on port 8900 (or upgrade existing RPC) | `src/solana_rpc/mod.rs` | `jsonrpsee` supports WS natively — enable `ServerBuilder::default().ws()` |
| 7.2 | Implement `accountSubscribe` | `src/solana_rpc/mod.rs` | Client subscribes to a `Pubkey`. On balance change (post-block), push `{ method: "accountNotification", params: { subscription, result: { lamports, ... } } }` |
| 7.3 | Implement `slotSubscribe` | `src/solana_rpc/mod.rs` | Push `{ slot, parent, root, status }` after every block |
| 7.4 | Implement `signatureSubscribe` | `src/solana_rpc/mod.rs` | Client subscribes to a tx signature. Push notification when the tx is confirmed (included in a block) |
| 7.5 | Broadcast hook in block production loop | `src/main.rs` | After `produce_block()`, push slot/account/signature notifications to all active WS subscribers |

### Acceptance Criteria
- [ ] `wscat -c ws://localhost:8900` connects
- [ ] `accountSubscribe` fires within 600 ms of a balance change
- [ ] `slotSubscribe` fires every slot (600 ms)
- [ ] `signatureSubscribe` fires when the target tx is confirmed
- [ ] `@solana/web3.js` `onAccountChange()` works against BlackBook WS

---

## Milestone 8: Proof of Reserves Endpoint

**Goal**: Wire the existing `proof_of_reserves.rs` (588 lines) to a public REST endpoint.

### What Exists
- `ProofOfReserves` struct in [src/proof_of_reserves.rs](src/proof_of_reserves.rs) — Merkle tree over all account balances, USDC backing ratio, inclusion proofs
- The module is **not imported** anywhere — 588 lines of working dead code

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 8.1 | Import `proof_of_reserves` in `main.rs` and `lib.rs` | `src/main.rs`, `src/lib.rs` | `mod proof_of_reserves;` |
| 8.2 | Initialize `ProofOfReserves` at startup | `src/main.rs` | Pass `SvmAccountsDB` reference for balance scanning |
| 8.3 | Update after each block | `src/main.rs` | In block production loop, call `por.update_tree()` after `end_of_block()` |
| 8.4 | Add `GET /reserves` endpoint | `src/main.rs` | Returns `{ total_bb_supply, total_usdc_backing, backing_ratio, merkle_root, timestamp }` |
| 8.5 | Add `GET /reserves/proof/{address}` endpoint | `src/main.rs` | Returns Merkle inclusion proof for a specific address |

### Acceptance Criteria
- [ ] `curl http://localhost:8080/reserves` returns current supply + backing ratio
- [ ] `curl http://localhost:8080/reserves/proof/{addr}` returns verifiable Merkle proof
- [ ] Merkle root updates after every block
- [ ] Third party can independently verify inclusion proof

---

## Milestone 9: 5-Node Deployment Automation

**Goal**: One-command deployment of the 5-node cluster defined in `first-100-users.md`.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 9.1 | Create `docker-compose.yml` for local 5-node testing | `deploy/docker-compose.yml` | 1 Writer + 4 Readers, different ports, shared Docker network |
| 9.2 | Create `deploy/Makefile` | `deploy/Makefile` | `make build`, `make up`, `make down`, `make logs`, `make status` |
| 9.3 | Create Terraform/Pulumi for cloud deployment | `deploy/terraform/` | AWS/Railway provisioning for Virginia, Oregon, Dallas, Sydney |
| 9.4 | Create WireGuard config templates | `deploy/wireguard/` | Private network between Writer ↔ Readers for gRPC :50051 |
| 9.5 | Create GitHub Actions workflow | `.github/workflows/ci.yml` | Build → test → Docker push → (optional) deploy to staging |
| 9.6 | Create health check script | `deploy/healthcheck.sh` | Loops all 5 nodes, checks `getSlot`, reports sync status |

### Acceptance Criteria
- [ ] `docker compose up` starts 5 nodes locally, all sync within 10 seconds
- [ ] `deploy/healthcheck.sh` reports all 5 nodes healthy
- [ ] GitHub Actions CI passes on every push to `master`
- [ ] Cloud deployment covers 4 US regions + 1 Sydney

---

## Milestone 10: L2 Settlement Integration

**Goal**: Wire the existing `grpc/mod.rs` L2 Settlement service for casino/DeFi settlement use cases.

### What Exists
- Full `L1Settlement` gRPC service in [src/grpc/mod.rs](src/grpc/mod.rs) (757 lines) — `SoftLock`, `ReleaseLock`, `SettleBet`, `BatchSettle`, `CreateCredit`, `CloseCredit`, `CheckHealth`
- Proto definition in [proto/settlement.proto](proto/settlement.proto)
- Service is **not imported** — completely dead code

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 10.1 | Import `grpc` module in `main.rs` and `lib.rs` | `src/main.rs`, `src/lib.rs` | `mod grpc;` |
| 10.2 | Start settlement gRPC server alongside relay server | `src/main.rs` | Writer mode: add `L1SettlementService` to the tonic server on a separate port (50052) or same server |
| 10.3 | Wire `SoftLock` to SVM balance holds | `src/grpc/mod.rs` | Lock N lamports on a Pubkey → move to a hold account → release on settle/cancel |
| 10.4 | Wire `SettleBet` / `BatchSettle` to SVM transfers | `src/grpc/mod.rs` | Execute lamport transfers from locked pool to winner accounts |
| 10.5 | Write integration tests | `tests/settlement_tests.rs` | `soft_lock`, `settle_bet`, `batch_settle`, `cancel_lock`, `credit_lifecycle` |

### Acceptance Criteria
- [ ] L2 client can `SoftLock` 100 BB on an address
- [ ] `SettleBet` moves locked funds to winner
- [ ] `BatchSettle` processes multiple bets atomically
- [ ] All settlement operations appear as on-chain transactions in blocks
- [ ] Tests cover the full lock → settle → verify cycle

---

## Milestone 11: Localized Fee Markets & Priority Fee Model 

**Goal**: Introduce micro-fees to prevent spam and create economic incentive for validators. Crucial for throttling runaway AI loops (Anti-Spam).

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 11.1 | Define fee constants | `src/svm/types.rs` | `BASE_FEE_LAMPORTS = 5_000` (0.000005 BB), `PRIORITY_FEE_PER_CU = 1` (lamport per compute unit) |
| 11.2 | Localized Fee tracking | `runtime/core.rs` | Enable `LocalizedFeeMarket`. Throttles specific highly-contended state without globally hiking fees. |
| 11.3 | Deduct fee in `execute_transfer()` | `src/svm/runtime.rs` | Before transfer: `sender.lamports -= base_fee + priority_fee`. |
| 11.4 | Update `getRecentPrioritizationFees` RPC | `src/solana_rpc/mod.rs` | Track and return per-slot, per-market fee stats. |
| 11.5 | Gulf Stream priority sorting by fee | `runtime/consensus.rs` | Higher-fee txs execute first within a slot. |

### Acceptance Criteria
- [ ] Spamming a single agent/account exponentially raises fees for just that state.
- [ ] Fee collector account accumulates fees.
- [ ] Safe AI transactions function normally despite a localized spam event.

---

## Milestone 12: Session Keys & Account Abstraction

**Goal**: Allow human users to sign a delegated allowance for an AI Agent to spend a metered amount of BB without exposing the human's main private key.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 12.1 | Implement `DelegateInstruction` | `src/contracts/system/mod.rs` | Define `Delegate { agent_pubkey, max_amount, expiration, allowed_programs }`. |
| 12.2 | Add Token Allowance Tracking | `src/svm/accounts_db.rs` | Track active delegated session keys directly in the `AccountSharedData` or an associated PDA. |
| 12.3 | Signature Verification | `src/svm/sigverify.rs` | Support mapping an AI Agent's signature to the delegated allowance of the origin human wallet. |
| 12.4 | Support in SDK | `sdk/wallet.sdk.ts` | Add `.createSessionKey(agentPubkey, constraints)` method. |

### Acceptance Criteria
- [ ] User grants AI Agent 50 BB budget. Agent signs tx and spends 10 BB. Main wallet loses 10 BB.
- [ ] Agent attempts to spend 60 BB, tx fails (exceeded allowance).
- [ ] Allowance expires automatically after X hours based on block timestamp.

---

## Milestone 13: Archiver Nodes & State Pruning

**Goal**: Ensure Validator nodes don't bloat from 600,000 TPS of AI micro-chatter. Shift old tx history to cold-storage.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 13.1 | Implement `ReDB` Garbage Collection | `src/poh_blockchain.rs`| Drop blocks older than X epochs from primary `blockchain.redb`. |
| 13.2 | Create `Archiver` Node Mode | `src/main.rs` | CLI mode `--mode archiver`. Subscribes to Writer but writes directly to massive cold storage. |
| 13.3 | RPC Historical Routing | `src/solana_rpc/mod.rs` | Return `RpcError::HistoryPrecluded` if a Validator is asked for an old pruned signature, directing them to an Archiver. |

### Acceptance Criteria
- [ ] Writer Node natively deletes block hashes > 3 days old from its `ReDB` tree.
- [ ] Archiver Node successfully ingests and stores the entire unbroken epoch history.

---

## Milestone 14: L2 Payment Channels (State Streaming)

**Goal**: AI agents charging per LLM token need thousands of updates per second off-chain before settling on-chain.

### Work Required

| # | Task | File | Details |
|---|------|------|---------|
| 14.1 | Channel Open Instruction | `src/contracts/global_escrow/mod.rs` | Users lock X amount of BB in a multi-sig escrow on L1. |
| 14.2 | Off-Chain SDK Module | `sdk/channels.sdk.ts` | AI agents pass signed Lamport updates back and forth directly via HTTP/WebRTC. |
| 14.3 | Channel Close / Settlement | `src/contracts/global_escrow/mod.rs` | Either party submits the newest jointly-signed off-chain state. L1 unwinds the escrow and pays exact final balances. |

### Acceptance Criteria
- [ ] 2 entities lock 100 BB. 
- [ ] They generate 10,000 off-chain micro-payments without hitting the RPC.
- [ ] Final state (e.g., 80 BB / 20 BB) is settled to L1 flawlessly in exactly one on-chain tx.

---

## Milestone Summary & Dependencies

```
Milestone 1 (Shutdown) ──────────────┐
Milestone 2 (simulateTransaction) ───┤
Milestone 3 (Reader tx forwarding) ──┼── All required before 5-node launch
Milestone 4 (Dead code cleanup) ─────┤
Milestone 5 (Test suite) ────────────┘
                                      │
                                      ▼
Milestone 6 (Metrics) ───────────────┐
Milestone 9 (Deploy automation) ─────┼── Required for production cluster
                                      │
                                      ▼
Milestone 7 (WebSockets) ────────────┐
Milestone 8 (Proof of Reserves) ─────┼── Required for 100 users
Milestone 11 (Fee model limits) ─────┘
                                      │
                                      ▼
Milestone 10 (L2 Settlement) ────────┐
Milestone 12 (Session Keys) ─────────┼── Required for AI Agent Economy Scale (600k TPS targeted)
Milestone 13 (State Pruning) ────────┤
Milestone 14 (L2 Payment Channels) ──┘
```

---

## Estimated Total Effort

| Milestones | Combined Estimate | Blocker For |
|------------|-------------------|-------------|
| 1 + 2 + 3 + 4 | **3–5 days** | 5-node launch |
| 5 | **1–2 days** | CI/CD, quality gate |
| 6 + 9 | **2–3 days** | Production cluster |
| 7 + 8 + 11 | **5–7 days** | 100-user onboarding |
| 10 | **3–5 days** | L2 settlement products |

**Total to production-ready 5-node cluster with 100 users: ~3–4 weeks of focused work.**
