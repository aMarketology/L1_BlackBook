# 05 — Security Model

The Bridge Watcher moves real value into the system. This document enumerates
every threat and the control that neutralizes it. The governing principle:

> **The watcher is untrusted-by-design. The L1 writer re-verifies everything and
> owns the at-most-once seal. A fully compromised watcher can waste L1 CPU but
> cannot forge, inflate, or double-mint.**

---

## 1. Threat model

| # | Threat | Vector | Control(s) | Enforced by |
|---|---|---|---|---|
| T1 | **Double mint** | Same deposit submitted twice (retry, restart, racing drivers) | `reserve_bridge_tx` before credit + `PROCESSED_BRIDGE_TXS` permanent seal; watcher treats `409` as success | **L1** |
| T2 | **Phantom mint** (no real deposit) | Watcher buggy/compromised submits fake tx_hash | L1 re-runs `getTransaction(finalized)` + checks amount/asset/dest=custody | **L1** |
| T3 | **Amount inflation** | Submit larger amount than transferred | L1 reads on-chain amount; tolerance 1%/$0.01; watcher submits chain amount only | **L1 + watcher** |
| T4 | **Reorg / unfinalized credit** | Act on a tx that later disappears | Only `finalized` commitment triggers submission | **Watcher + L1** |
| T5 | **Replay** | Resubmit an old signed bridge request | Per-request `nonce` (atomic `entry()`), `timestamp` ≤ 60s freshness | **L1** |
| T6 | **Mis-attribution** | Credit wrong wallet | Memo validated with `is_valid_bb_address`; bad/missing → `Ignored`, never guessed | **Watcher** |
| T7 | **Bridge-authority key theft** | Attacker signs `/bridge/deposit` | Key in KMS/secret store; still bounded by T1/T2 (can't mint without a *real* finalized deposit) | **Ops + L1** |
| T8 | **RPC poisoning** | Malicious RPC returns fake tx data | L1 uses its **own** RPC to re-verify, not the watcher's claim | **L1** |
| T9 | **Cursor corruption / loss** | Local DB wiped | Cursor is reconstructable by backfill; idempotency seal prevents re-mint | **Watcher + L1** |
| T10 | **Dust / spam deposits** | Flood of tiny transfers | `MIN_DEPOSIT_MICRO` floor → `Ignored`; bounded inflight | **Watcher** |

---

## 2. The at-most-once seal (the keystone) <a id="defense-in-depth"></a>

Every mint path on L1 funnels through the same sequence (already implemented in
`deposit_approve_handler` / `verify_and_approve`):

```
reserve_bridge_tx(tx_hash)        // claim hash atomically — fails if already claimed
  └─ credit_lamports(wallet, bb)  // integer mint, no f64
       ├─ ok  → commit_bridge_tx(tx_hash, mint_id)   // permanent seal
       └─ err → cancel_bridge_tx(tx_hash)            // release claim, no partial state
```

Because the **seal is keyed by the Solana signature** and lives in ReDB, it does
not matter how many drivers (TS watcher, embedded Rust watcher, manual admin
call) race on the same deposit — **exactly one** wins, the rest get `409`. This
is what lets us run the external watcher and the embedded backstop simultaneously
with zero risk (see [01-architecture.md](01-architecture.md#why-externalize)).

---

## 3. Key handling <a id="key-handling"></a>

| Key | Holder | Storage | Scope |
|---|---|---|---|
| User wallet key | User | User's wallet | Signs Model B `/deposit/request` only |
| **Bridge authority key** | Bridge Watcher | **Secret store / KMS, never in repo or plain env in prod** | Signs Model A `/bridge/deposit` |
| Custody wallet key | Treasury ops | Cold/HSM, **never on the watcher host** | Moving custody funds (out of scope) |

Rules:
- The watcher host holds the **bridge authority** key only. It is a *minting
  authorizer*, not a *fund custodian* — it cannot move user money on Solana.
- In local/staging, the key may be a dev key in `.env` (gitignored). For any real
  deployment it must come from a secret manager and be rotatable
  (`BRIDGE_AUTHORITY_PUBKEY` configured on L1 side; rotating = update both).
- **Never** log the private key, signatures over secrets, or full memos that might
  contain PII.

> ⚠️ Until `/bridge/deposit` + bridge-authority verification exist (milestone M3),
> Model A relies on `/admin/deposit/approve` which is gated behind the
> `unsafe_admin` **build feature** — acceptable for **local testing only** and
> never to be exposed publicly. This is called out explicitly in
> [03-l1-api-contract.md](03-l1-api-contract.md#bridge-authority).

---

## 4. Reorg safety (T4 in depth)

- Solana `finalized` commitment means a supermajority has rooted the slot; it is
  not subject to normal reorg. The watcher **only submits on `finalized`**.
- A tx seen at `confirmed` that never finalizes (dropped/reorged pre-finality)
  simply stays `AwaitingFinality` until it ages out — it is never minted.
- L1 independently requires `finalized` in its own re-verification, so even a
  watcher bug that submits early is caught at the boundary.

---

## 5. Idempotency & crash-safety (T1, T9)

- Local `processed_txs` table mirrors the L1 seal for fast skip, but is **advisory
  only** — correctness comes from L1, not the local mirror.
- Cursor advances only past terminal states ([04](04-solana-watcher-internals.md#2-cursor--pagination)),
  so a crash re-scans in-flight work.
- Re-submitting an already-minted deposit returns `409`, which the watcher records
  as `Processed` — **idempotent by construction**.

---

## 6. Input validation (OWASP-aligned)

- All RPC responses are schema-validated before use; missing/oddly-typed fields →
  treat tx as `AwaitingFinality`/`Ignored`, never crash.
- Memo content is length-bounded and strictly prefix-matched; no `eval`, no
  dynamic address construction.
- Amounts are parsed as `BigInt`/`u64` strings — **never** through JS `number`
  (avoids the 2^53 precision cliff, consistent with L1's integer discipline).
- L1 base URL and RPC URLs are validated as `https?://` and pinned via config; no
  URL is ever taken from chain data.

---

## 7. Blast radius summary

| If compromised | Worst case |
|---|---|
| Watcher process | Submits garbage to L1 → all rejected (T2/T5/T8); can spam writer CPU (mitigated by L1 rate limiting + bounded inflight) |
| Bridge authority key | Can *authorize* mints — but only for **real, finalized, not-yet-processed** deposits at the correct amount (T1/T2 still bind). Cannot invent value. |
| Local SQLite | Re-mint prevented by L1 seal; only effect is a re-scan |

The design deliberately ensures the **catastrophic** outcomes (forge value,
double mint, inflate amount) are **all** owned by L1 controls, not the watcher.
