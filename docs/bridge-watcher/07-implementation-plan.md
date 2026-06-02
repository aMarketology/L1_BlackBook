# 07 — Implementation Plan

The concrete build order. Each milestone is independently shippable and testable.
We build **Model B first** (reuses the fully-hardened, user-signed path with zero
new trust assumptions), then add **Model A** behind a reviewed bridge-authority key.

---

## 1. File layout

New npm workspace under the existing `sequencer/` monorepo:

```
sequencer/
  package.json                 # add "bridge-watcher" to workspaces + dev:bridge script
  bridge-watcher/
    package.json               # name "@bb/bridge-watcher"
    tsconfig.json              # extends shared base
    .env.example
    src/
      index.ts                 # entrypoint: load config, start poller + reconciler + server
      config.ts                # parse + validate env (fail fast)
      logger.ts                # structured JSON logger
      db/
        sqlite.ts              # open bridge.db, migrations
        cursor.ts              # get/advance durable cursor
        processed.ts           # local idempotency mirror + per-sig state
      solana/
        rpc.ts                 # pooled client, fallbacks, timeouts, retries
        poller.ts              # getSignaturesForAddress loop
        finality.ts            # getTransaction(finalized) gate
        parse.ts               # pre/postTokenBalances transfer extraction
        memo.ts                # "bb:<addr>" memo parse + is_valid_bb_address check
      attribution.ts           # transfer + memo → { wallet, asset, amount_micro }
      l1/
        client.ts              # HTTP client for L1 endpoints
        sign.ts                # bridge-authority Ed25519 signing (Model A)
        messages.ts            # canonical message builders
      reconciler.ts            # periodic re-drive of non-terminal items
      server.ts                # /health + /metrics
      metrics.ts               # Prometheus counters/gauges/histograms
    test/
      parse.test.ts            # transfer/memo parsing fixtures
      lifecycle.test.ts        # state machine transitions
      idempotency.test.ts      # 409 → Processed, crash-replay
```

Reuse from `sequencer/shared/` where possible (logger, base tsconfig, address
validation to match L1's `is_valid_bb_address`).

---

## 2. Milestones

### M0 — Scaffold (no behavior)
- Create the workspace, `package.json`, `tsconfig.json`, `.env.example`.
- `index.ts` boots, loads/validates config, starts `/health` returning `status:ok`.
- Wire `npm run dev:bridge` in `sequencer/package.json`.
- **Done when:** `npx tsc --noEmit` clean; `GET /health` responds.

### M1 — Read-only Solana observer
- Implement `rpc.ts`, `poller.ts`, `finality.ts`, `parse.ts`, `memo.ts`.
- SQLite cursor + per-sig state; **log only**, no L1 calls, no mint.
- **Done when:** pointed at a devnet custody wallet, it correctly logs each
  finalized USDC/USDT transfer with parsed amount/asset/memo and advances the
  cursor crash-safely. Unit tests for `parse`/`memo` pass.

### M2 — Model B driver (uses existing L1 endpoints)
- `l1/client.ts`: `GET /deposit/status/:tx_hash`, poll until `approved`.
- For deposits that already have a user-signed `/deposit/request`, ensure
  finalization + observe approval; mark `Processed`. Reconciler re-drives.
- **Done when:** an end-to-end devnet deposit (user-signed request) is observed,
  finalized, and confirmed minted; restart mid-flight re-drives idempotently.

### M3 — Bridge authority + Model A (L1 change required)
- **L1 (Rust):** add `POST /bridge/deposit` with `BRIDGE_DEPOSIT:...` canonical
  message, `BRIDGE_AUTHORITY_PUBKEY` env, nonce/timestamp checks, on-chain
  re-verify, and the existing `reserve → credit → commit/cancel` mint sequence
  (mirror `deposit_approve_handler`). Replaces reliance on `unsafe_admin` approve.
- **Watcher:** `l1/sign.ts` + `messages.ts`; submit memo-attributed deposits to
  `/bridge/deposit`.
- **Done when:** a deposit with **only a memo** (no user-signed request) mints
  correctly; replays/forgeries are rejected; `409` treated as success.

### M4 — Hardening & ops
- `metrics.ts` + `/metrics`; alerts; backfill from `BRIDGE_GENESIS_SIGNATURE`.
- Dust floor, bounded inflight, RPC fallbacks, structured logs scrubbed of secrets.
- **Done when:** runbook ([06](06-config-and-runbook.md)) scenarios validated in staging.

---

## 3. L1-side changes required (tracked explicitly)

| Change | File | Milestone |
|---|---|---|
| `POST /bridge/deposit` handler | `src/contracts/deposit_gateway/mod.rs` | M3 |
| `BRIDGE_DEPOSIT` canonical message + verify | `src/auth.rs` / deposit gateway | M3 |
| `BRIDGE_AUTHORITY_PUBKEY` in `AppState` + env load | `src/main.rs` | M3 |
| Route registration | `src/main.rs` | M3 |

> Everything M0–M2 needs **already exists** in L1 — no Rust changes. That is why
> Model B is the first shippable target.

---

## 4. Testing strategy

| Layer | How |
|---|---|
| Unit | `parse.ts` (transfer fixtures incl. router/inner txs), `memo.ts` (valid/invalid/`0x`), message builders |
| State machine | Simulated sequence streams → assert terminal states + cursor invariant |
| Idempotency | Inject `409`; kill-and-restart mid-`Submitting`; assert single mint |
| Integration (devnet) | Real finalized devnet transfers → assert L1 balance delta == expected lamports |
| Negative | Unfinalized tx (no mint), bad memo (`Ignored`), inflated amount (L1 rejects), replay (rejected) |

---

## 5. Definition of done (whole project)

- [ ] M0–M4 complete; `npx tsc --noEmit` and tests green.
- [ ] The one-sentence contract from the [README](README.md#the-one-sentence-contract)
      holds under crash, RPC outage, and L1 downtime in staging.
- [ ] No `f64`/JS-`number` in any money path — `BigInt`/`u64` strings only.
- [ ] Secrets sourced from env/secret store, never logged, never committed.
- [ ] Runbook validated; alerts firing correctly in staging.

---

## 6. Open questions to confirm before M0

1. **Source asset(s):** Solana `USDC` + `USDT` both, or one first?
2. **Custody wallet:** which devnet/staging address do we watch for M1?
3. **Attribution:** confirm `bb:<address>` memo format (vs. a pre-registered
   intent table)?
4. **RPC provider:** which devnet/mainnet RPC (and do we have a fallback)?
5. **Model A timing:** build `/bridge/deposit` now (M3) or stay on Model B until
   the wallet UI emits user-signed requests?

Once these are answered, we start at **M0 — Scaffold**.
