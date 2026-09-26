# Universal Rollup Hub Integration

The Rollup Hub is how every rollup layer (L2, L3, L5) anchors state on L1.
Source: `src/contracts/rollup/mod.rs`.

The `:rollup_id` path parameter is one of `"L2"`, `"L3"`, or `"L5"`.

## The core invariant

> **Σ(L2/L3/L5 ledger balances) == L1 vault balance.**

The L1 vault holds $BB locked by users. Sequencers credit those users an
off-chain balance. When users exit, L1 releases lamports from the vault **only
after** verifying a Merkle proof against a sequencer-submitted root. This is the
single invariant that makes the "closed loop" secure.

## Lifecycle

```
User on rollup            L1 Rollup Hub              Sequencer
     │                        │                          │
     │── lock_bb (signed) ──► │                          │
     │                        │ store ROLLUP_LOCKS ─────► │  read lock
     │                        │                          │  credit balance (SQLite)
     │  [bet / transfer] ──────────────────────────────► │  (<1ms local)
     │                        │◄── submit_root ────────── │  (sequencer-signed)
     │                        │ store ROLLUP_STATE_ROOTS  │
     │── exit (Merkle proof)► │                          │
     │                        │ verify proof vs root     │
     │                        │ release BB from vault    │
     │◄──── BB credited ────── │                          │
```

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/rollup/:id/lock_bb` | User Ed25519 | Lock $BB into vault PDA |
| GET | `/rollup/:id/locks/:lock_id` | — | Sequencer reads lock record |
| POST | `/rollup/:id/locks/:lock_id/consume` | Sequencer Ed25519 | Mark lock spent |
| POST | `/rollup/:id/submit_root` | Sequencer Ed25519 | Anchor Merkle state root |
| GET | `/rollup/:id/roots/:batch_id` | — | Retrieve anchored root |
| POST | `/rollup/:id/exit` | User Ed25519 + proof | Exit assets to L1 |

## Signed messages

```
lock_bb:       "ROLLUP_LOCK_BB:{id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"
consume_lock:  "CONSUME_LOCK:{id}:{lock_id}:{ts}"                 (no nonce)
submit_root:   "ROLLUP_SUBMIT_ROOT:{id}:{batch_id}:{merkle_root_hex}:{ts}"
exit BB:       "ROLLUP_EXIT:{id}:BB:{address}:{batch_id}:{ts}:{nonce}"
exit NFT:      "ROLLUP_EXIT:{id}:NFT:{address}:{batch_id}:{ts}:{nonce}"
```

## Sequencer authorization

`submit_root` and `consume_lock` are verified against the **registered sequencer
pubkey** for that rollup (`state.authorized_sequencers: DashMap<String, String>`
mapping `rollup_id → 64-char hex pubkey`).

The pubkeys come from env vars:

| Env var | Rollup |
|---------|--------|
| `L2_SEQUENCER_PUBKEY` | L2 |
| `L3_SEQUENCER_PUBKEY` | L3 |
| `L5_SEQUENCER_PUBKEY` | L5 |

> **Pitfall:** if a sequencer env var is unset, that rollup's `submit_root` and
> `consume_lock` return HTTP `503` (sequencer disabled), but `lock_bb` and
> `exit` still work. `L5_SEQUENCER_PUBKEY` is commonly unset in local setups →
> L5 effectively disabled.

## Monotonicity

`store_rollup_state_root` enforces **strictly increasing** `batch_id` per
rollup:

```
if batch_id <= latest { → error "monotonicity violation" }
```

Each rollup (L2, L3, L5) has an independent sequence, stored under zero-padded
keys `"{rollup_id}:{batch_id:020}"`.

## Double-exit prevention

Every successful exit burns a **permanent seal** into ReDB:

```
ROLLUP_CONSUMED_EXITS: key = SHA-256("{id}:{batch_id}:{asset_type}:{address|collection:token}")
```

A second exit with the same proof returns `409 Conflict` before any state change.

## Vault address

The per-rollup vault is a PDA derived via `rollup_vault_address(rollup_id)`
(`src/svm/pda.rs`).

## ReDB tables

| Table | Key → Value |
|-------|-------------|
| `ROLLUP_STATE_ROOTS` | `"{id}:{batch_id:020}"` → root bytes |
| `ROLLUP_CONSUMED_EXITS` | SHA-256 exit key → `u64` seal |
| `ROLLUP_LOCKS` | lock UUID → `RollupLockRecord` JSON |
