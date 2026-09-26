# Liquidity Pools & L2 Events

How $BB liquidity moves into the system, gets locked on L1, and is used by the
**L2 sequencer** to run prediction-market events. This is the money-flow story
behind "deposit → lock → bet → resolve → payout."

> **Scope note:** NFT minting/anchoring is handled by **Layer 3**, not L2.
> L2's only asset type is `$BB`. Everything here concerns $BB liquidity.

---

## The three liquidity surfaces

| Surface | Where | Role |
|---------|-------|------|
| **Swap pool** | L1 `token_swap` | Fixed-rate BB ↔ wUSDT conversion (10 BB = 1 wUSDT) |
| **Rollup vault** | L1 `rollup` | Per-rollup PDA holding locked $BB for L2/L3/L5 |
| **L2 off-chain ledger** | Sequencer SQLite | Fast, signed bets settled pro-rata in lamports |

The flow is one-directional at each step:

```
wUSDT ──swap──► $BB ──lock_bb──► L1 vault ──register-lock──► L2 balance ──bet──► market pool
                                                                                   │
                          ┌────────────────────────────────────────────────────────┘
                          ▼ resolve
                    winners credited (L2) ──push_payouts──► L1 wallets
```

---

## Step 1 — Get $BB (swap pool)

The swap pool is a **fixed-rate AMM** backed by the swap-pool PDA on L1. The PDA
holds both $BB and wUSDT; no private key exists for it — only the swap handlers
can move funds.

| Endpoint | Direction | Signed message |
|----------|-----------|----------------|
| `POST /swap/bb-to-usdc` | $BB → wUSDT | `SWAP_BB_USDC:{wallet}:{bb_lamports}:{ts}:{nonce}` |
| `POST /swap/usdc-to-bb` | wUSDT → $BB | `SWAP_USDC_BB:{wallet}:{usdc_micro}:{ts}:{nonce}` |
| `GET /swap/pool/balances` | — | read BB + wUSDT reserves |

Rate: **10 BB = 1 wUSDT** (baseline `BB_PER_USDT_DEFAULT`; live rate in ReDB
`"BB_USDT"`). `get_swap_rate` zero-guards against a tampered rate.

> Both swap directions require an Ed25519 signature over the exact message and
> are replay-protected by nonce + 60s freshness. See
> [Authentication](authentication.md).

---

## Step 2 — Lock $BB into the L2 vault

`POST /rollup/L2/lock_bb` debits the user's L1 $BB and credits the **L2 vault
PDA**. This is the atomic bridge-in.

```
signed message: "ROLLUP_LOCK_BB:L2:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"
```

The lock returns a `lock_id` (UUID). The L1 stores the record in `ROLLUP_LOCKS`.

---

## Step 3 — Register the lock on L2 (credit off-chain balance)

The user calls the **L2 sequencer** `POST /register-lock` with the `lock_id`.
The sequencer:

1. Checks idempotency (already registered?).
2. Reads the lock from L1 (`GET /rollup/L2/locks/:lock_id`).
3. Crash-recovers if needed.
4. Consumes the lock on L1 (`POST /rollup/L2/locks/:lock_id/consume`, sequencer-signed).
5. Credits the user's **L2 balance** in SQLite.

After this, the user bets at L2 speed (<1ms), off-chain. Their funds are
represented by L1's vault (locked $BB) and the L2 ledger (spendable balance).

---

## Step 4 — Create an event (market)

`POST /markets` on the sequencer:

```json
{ "market_id": "mls-survivor-week-1", "question": "Will Team X be eliminated?" }
```

Creates a market in state `OPEN`. **(TODO in code: creation is not yet
restricted to an oracle/admin key.)**

Market lifecycle:

```
OPEN ──lock──► LOCKED ──resolve──► RESOLVED
```

- `POST /markets/:id/lock` — freeze betting (OPEN → LOCKED).
- `POST /markets/:id/resolve` — settle the market (sequencer-signed).

---

## Step 5 — Place bets (signed, off-chain)

`POST /markets/:id/bet` on the sequencer. Signed by the bettor:

```
signed message: "L2_BET:{market_id}:{wallet}:{side}:{amount_lamports}:{ts}:{nonce}"
```

`sides` are **binary: `YES` or `NO`** (see [Pitfalls](pitfalls.md) for the N-way
limitation). Rules enforced atomically in one SQLite transaction:

- Market must be `OPEN`.
- Wallet balance must cover the stake.
- **No side-switching** — a wallet can hold only one side per market.
- Same-side bets accumulate into one position row.

The stake is **debited immediately**; payouts are credited only on resolution.

---

## Step 6 — Resolve & distribute

`POST /markets/:id/resolve` (sequencer-signed, `L2_RESOLVE:{market_id}:{outcome}:{ts}:{nonce}`):

1. Compute the **zero-sum** payout: every lamport staked returns to winners.
2. **Dealer house fee** = `floor(totalPool * DEALER_FEE_BPS / 10_000)` (default 100 bps = 1%), credited to `DEALER_ADDRESS`.
3. Pro-rata payout: `payout_i = (stake_i / winningPool) * distributedPool` — pure integer arithmetic.
4. **Edge case** — nobody bet the winning side: the losing side is fully refunded, **no** dealer fee.
5. Integer-division dust (≤1 lamport per winner) stays in the L2 operational reserve.

### Settlement anchoring

After resolution the sequencer immediately:

1. **Seals a Merkle batch** (`submit_root` → L1 `ROLLUP_STATE_ROOTS`), anchoring the updated balances.
2. **Pushes payouts to L1** via `pushPayoutsToL1` → `POST /escrow/push_payouts`, so winnings land in each winner's **native L1 wallet** with no manual claim.
3. **Opens the Oracle dispute window** (`submitOraclePendingRoot`) — non-blocking.

> **Ordering guarantee:** L1 `submit_root` succeeds **before** the SQLite
> `sealBatch` write. On crash between the two, the next seal re-snapshots the
> same state and re-submits (L1 rejects a duplicate `batch_id` with 409; the
> sequencer increments and continues).

---

## The invariant that keeps it honest

```
Σ(L2 ledger balances) == L1 L2-vault balance
```

Every $BB in the L2 ledger is backed 1:1 by $BB locked in the L1 L2 vault.
Bets, fees, and payouts all stay inside this closed loop — the only way out is a
Merkle-proof exit back to L1. See [Rollup Hub](rollup-hub.md) and
[Merkle Proofs](merkle-proofs.md).

---

## Schema (L2 sequencer)

```sql
l2_markets(market_id, question, status, outcome,
           total_yes_pool INTEGER, total_no_pool INTEGER,   -- lamports
           created_at_ts, resolved_at_ts, batch_id, merkle_root)

l2_positions(market_id, wallet_address, bet_side,            -- one row per (market, wallet)
             amount_lamports INTEGER, placed_at_ts,
             PRIMARY KEY (market_id, wallet_address))

-- shared: locks, balances, batches, slot_watermark
```

All monetary values are `INTEGER` lamports — never `REAL`/`FLOAT`. Bet amounts
are passed as `BigInt` so `node:sqlite` maps them to SQLite `INTEGER` (exact)
rather than `REAL` (lossy above 2^53 lamports ≈ 90B BB).

## Config (env)

| Var | Default | Purpose |
|-----|---------|---------|
| `DEALER_FEE_BPS` | `100` | House fee in basis points (1%) |
| `DEALER_ADDRESS` | `dealer_reserve` | Receives house fee; L2-internal, not a real L1 wallet |
| `SLOTS_PER_BATCH` | `25` | Slots between batch seals |
