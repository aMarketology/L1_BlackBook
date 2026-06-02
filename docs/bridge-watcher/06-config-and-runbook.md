# 06 — Configuration & Runbook

Everything needed to configure, run, observe, and recover the Bridge Watcher.

> **Environment policy:** This service is **local / staging only** for now. It
> must never be pointed at the production custody wallet or production L1
> (`91.98.196.34`) without a separate, explicit review.

---

## 1. Environment variables

| Var | Required | Default | Meaning |
|---|---|---|---|
| `L1_WRITER_URL` | ✅ | `http://localhost:8080` | Base URL of the **writer** node (mints are writes) |
| `SOLANA_RPC_URL` | ✅ | `https://api.mainnet-beta.solana.com` | Primary Solana JSON-RPC |
| `SOLANA_RPC_FALLBACKS` | — | _(empty)_ | Comma-separated backup RPC URLs |
| `CUSTODY_WALLET_ADDRESS` | ✅ | — | Base58 Solana wallet being watched |
| `USDC_MINT` | — | `EPjFWdd5…TDt1v` | USDC SPL mint (override for devnet) |
| `USDT_MINT` | — | `Es9vMFrz…wNYB` | USDT SPL mint (override for devnet) |
| `BRIDGE_AUTHORITY_SECRET` | Model A | — | Ed25519 secret (hex) — **secret store in prod** |
| `BRIDGE_GENESIS_SIGNATURE` | — | _(none)_ | Oldest signature to backfill to on cold start |
| `POLL_INTERVAL_MS` | — | `3000` | Solana poll cadence |
| `RECONCILE_INTERVAL_MS` | — | `30000` | Stuck-item re-drive cadence |
| `MIN_DEPOSIT_MICRO` | — | `10000` | Dust floor (0.01 stablecoin) below which → `Ignored` |
| `MIN_CONFIRMATION_SLOTS` | — | `0` | Extra slot-depth guard on top of `finalized` |
| `MAX_INFLIGHT_RPC` | — | `4` | Bounded RPC concurrency |
| `RPC_TIMEOUT_MS` | — | `10000` | Per-RPC-call timeout |
| `MAX_BACKOFF_MS` | — | `60000` | Retry backoff cap |
| `BRIDGE_DB_PATH` | — | `./bridge.db` | SQLite cursor/idempotency store |
| `HTTP_PORT` | — | `8090` | Port for `/health` + `/metrics` |
| `LOG_LEVEL` | — | `info` | `trace`|`debug`|`info`|`warn`|`error` |

> Mirror these in a gitignored `.env`. The corresponding L1 side must set
> `CUSTODY_WALLET_ADDRESS` and (for Model A) `BRIDGE_AUTHORITY_PUBKEY`.

---

## 2. Local bring-up (Model B, dev)

```powershell
# 1. Start L1 writer with admin endpoints (dev only)
Set-Location 'c:\Users\maxd1\Documents\GitHub\L1_BlackBook'
cargo build --features unsafe_admin
$env:CUSTODY_WALLET_ADDRESS = "<devnet custody wallet>"
.\target\debug\layer1.exe

# 2. In another terminal, start the watcher
Set-Location 'c:\Users\maxd1\Documents\GitHub\L1_BlackBook\sequencer'
npm install
npm run dev:bridge        # to be added in package.json (workspace=bridge-watcher)
```

Health check:

```powershell
curl.exe -s http://localhost:8090/health   # watcher
curl.exe -s http://localhost:8080/health   # L1
```

---

## 3. Observability

### `GET /health`
```jsonc
{
  "status": "ok",
  "l1": "reachable",
  "solana_rpc": "reachable",
  "cursor": "<last signature>",
  "lag_slots": 12,
  "inflight": 0,
  "uptime_s": 3600
}
```

### `GET /metrics` (Prometheus text)
| Metric | Type | Meaning |
|---|---|---|
| `bridge_deposits_processed_total{asset}` | counter | Successful mints driven |
| `bridge_deposits_ignored_total{reason}` | counter | Ignored (dust/bad_memo/not_deposit/failed_tx) |
| `bridge_submit_failures_total{code}` | counter | L1 submit failures by status |
| `bridge_already_processed_total` | counter | `409` idempotent no-ops |
| `bridge_finality_wait_seconds` | histogram | Time from seen → finalized |
| `bridge_cursor_lag_slots` | gauge | Tip slot − cursor slot |
| `bridge_rpc_errors_total{provider}` | counter | RPC failures by provider |

### Logs
Structured JSON, one line per state transition, keyed by `sig` and (when known)
`tx_hash` + truncated `wallet`. **Never** log secrets or full memos.

---

## 4. Alerts (recommended thresholds)

| Alert | Condition |
|---|---|
| Watcher down | `/health` unreachable > 1 min |
| Cursor stalled | `bridge_cursor_lag_slots` rising for > 5 min |
| Submit failures | `bridge_submit_failures_total` rate > 0 for > 2 min (excl. 409) |
| RPC degraded | `bridge_rpc_errors_total` rate high / all providers failing |
| Bad-memo spike | `bridge_deposits_ignored_total{reason="bad_memo"}` surge (manual attribution backlog) |

---

## 5. Runbook — common incidents

### A. "A user says they deposited but have no BB"
1. Find the Solana signature for their transfer.
2. `GET /deposit/status/:tx_hash` on L1 — is it `approved`?
3. Check watcher logs for that `sig`. States:
   - `AwaitingFinality` → wait; confirm the tx is actually finalized on an explorer.
   - `Ignored(bad_memo)` → the memo was missing/invalid → **manual attribution**
     (operator calls the approve/bridge endpoint with the correct wallet).
   - `Retry` → L1 or RPC was down; verify both are up; reconciler will re-drive.
4. Confirm the seal: if L1 shows `is_bridge_tx_processed = true`, the mint
   happened — check the destination wallet, not the watcher.

### B. "Watcher restarted / DB lost"
- It will backfill from `BRIDGE_GENESIS_SIGNATURE` (or last local `Processed`).
- Re-mints are impossible (L1 seal) — let it catch up; watch `cursor_lag_slots`
  return to baseline.

### C. "Suspected double credit"
- Should be impossible. Verify via L1: each mint has a unique `tx_hash` in
  `PROCESSED_BRIDGE_TXS`. Two credits ⇒ two *distinct* finalized transfers
  (correct) **or** a true L1 bug (escalate — not a watcher issue).

### D. "Need to pause the bridge"
- Stop the watcher process. No funds are at risk; deposits queue on-chain and are
  picked up via backfill when it resumes. (The embedded Rust backstop may still
  drive Model B; disable it too if a full freeze is required.)

---

## 6. What must be true before pointing at real funds

- [ ] `/bridge/deposit` + bridge-authority verification implemented on L1 (M3).
- [ ] `unsafe_admin` approve endpoint **not** exposed publicly.
- [ ] Bridge authority key sourced from a secret manager, rotatable.
- [ ] Alerts wired; runbook validated in staging with real finalized devnet txs.
- [ ] Backfill tested from a cold DB against historical custody activity.
