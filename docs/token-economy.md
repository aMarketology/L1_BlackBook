# Token Economy & Math

The unit model and the arithmetic rules that keep BlackBook L1's accounting
exact. Source: `src/svm/types.rs`.

## Units

| Token | Decimals | Unit constant | Smallest unit |
|-------|----------|---------------|---------------|
| `$BB` | 5 | `LAMPORTS_PER_BB = 100_000` | 1 lamport = 0.00001 BB |
| `wUSDT` | 6 | `USDT_UNIT = 1_000_000` | 1 micro-USDT |

## Immutable invariants (compile-time asserted)

```rust
const _: () = assert!(BB_USD_CENTS    == 10,       "$BB = exactly 10 US cents");
const _: () = assert!(LAMPORTS_PER_BB == 100_000,  "BB always 5 decimals");
```

- `BB_USD_CENTS = 10` — the internal ledger value of 1 BB is exactly $0.10 of
  network compute value. **Never changes.**
- `LAMPORTS_PER_BB = 100_000` — 5 decimal places. **Never changes.**

The only thing that may flex is the **external exchange rate**:

```rust
BB_PER_USDT_DEFAULT = 10   // baseline: 10 BB = 1 wUSDT
```

The live rate is stored in ReDB (key `"BB_USDT"`) and read at runtime via
`get_swap_rate("BB_USDT")`. It can be adjusted by the Oracle/Dealer if wUSDT
depegs. The default is `10`.

## Conversion formula

Micro-stablecoin → BB lamports at a given rate:

```
bb_lamports = micro * LAMPORTS_PER_BB * rate / USDT_UNIT
           = micro * 100_000 * rate / 1_000_000
```

Uses `u128` intermediate to avoid overflow (safe to ~$18 trillion).

## The hard math rules

1. **All financial math is integer** (`u64` / `u128`). No `f64` for balances,
   amounts, or arithmetic.
2. **Convert to `f64` only at the display/API boundary.**
3. `get_balance()` returns `f64` **whole BB** (legacy). Use lamports endpoints /
   `get_balance_lamports()` for logic.
4. `TpuPacket.amount` is `u64` **lamports** (not BB float). Divide by
   `100_000.0` only at RuntimeTx/PipelinePacket dispatch.
5. SPL token amounts are raw micro-units (`u64`).
6. `TransactionRecord::with_id()` takes `u64` amount/balance params — never
   `f64`.

## Where `f64` is allowed (the exception)

- `/transfer` and `/transfer/simple` accept a `f64` `amount` in whole BB (legacy
  display-boundary). Internally it is converted to lamports before execution.
- `/balance/:address` returns a whole-BB `f64`.

Everything downstream of those boundaries is integer.

## Swap (fixed-rate example)

`SWAP_BB_USDC` converts at the active rate. With the default rate `10`:

```
10 BB → 1 wUSDT
1 BB  → 0.1 wUSDT
```

`get_swap_rate` has a zero-guard: if the stored rate is `0` (tampered DB), it
returns `BB_PER_USDT_DEFAULT` instead of dividing by zero.

## Rent

`RENT_EPOCH_EXEMPT = u64::MAX` — accounts never pay rent. No account balance is
silently reduced over time.
