# BlackBook L1 — Developer Documentation

Forward-facing documentation for building **on** BlackBook Layer 1: a
permissioned, high-frequency settlement chain for rollup layers (L2, L3, L5).

> **Who this is for.** You are building a wallet, an SDK, a rollup sequencer, an
> oracle client, a bridge, or an explorer against the L1 HTTP/JSON-RPC/gRPC/UDP
> surface. These docs describe the *actual deployed protocol* — every signed
> message format, Merkle encoding, and endpoint here is verified against source.

---

## Reading order

| Doc | What it covers |
|-----|----------------|
| [1. Getting Started](getting-started.md) | Run a node locally, reach it from other devices, first faucet + transfer |
| [2. Authentication & Signing](authentication.md) | Ed25519 envelope, canonical message formats, replay protection |
| [3. Endpoint Reference](endpoints.md) | Every HTTP/JSON-RPC/gRPC/UDP endpoint with auth + signed message |
| [4. Rollup Hub Integration](rollup-hub.md) | lock_bb → submit_root → exit lifecycle for L2/L3/L5 sequencers |
| [5. Merkle Leaves & Proofs](merkle-proofs.md) | Borsh leaf encoding, sorted-pair hashing, exit proof format |
| [6. Token Economy & Math](token-economy.md) | $BB / wUSDT units, integer-math rules, swap rate |
| [7. Liquidity Pools & L2 Events](liquidity-pools.md) | Swap pool, lock_bb → bet → resolve lifecycle, payout flow |
| [8. Pitfalls & Gotchas](pitfalls.md) | Known traps, footguns, and doc-vs-code discrepancies |

---

## The one-sentence mental model

BlackBook L1 is an **asset-custody ledger, state machine, and transaction
execution environment — nothing else.** It stores balances against public keys,
accepts Ed25519-signed transactions, and verifies the signature before
executing. It **never** generates, holds, or transmits user private keys or
mnemonics. Keys are created and kept client-side only.

The L1's relationship with keys is exactly three things:

1. Store a balance against a public key.
2. Receive an Ed25519-signed transaction.
3. Verify the signature before executing.

Do not ask the L1 to generate keys, sign, or custody anything.

---

## Quick reference

| Surface | Transport | Address | Purpose |
|---------|-----------|---------|---------|
| HTTP REST | Axum 0.7 | `:8080` | Wallets, faucet, transfers, swaps, rollup hub, escrow, oracle |
| Solana JSON-RPC | Axum | `:8899` | Solana-compatible RPC (`getBalance`, `getHealth`, …) |
| gRPC relay | tonic | `:50051` | Validator relay (`GetBalance`, `SoftLock`, `SettleBet`, …) |
| gRPC settlement | tonic | `:50052` | Dealer settlement stream |
| UDP TPU | bincode | `:8003` | High-throughput tx ingestion (8 workers) |
| Turbine tick | UDP | `:8004` | Permissioned shred gossip |
| WebSocket | Axum | `:8080/ws` | Live balance / block subscriptions |

Tokens:

| Token | Decimals | Unit constant |
|-------|----------|---------------|
| `$BB` | 5 | `LAMPORTS_PER_BB = 100_000` |
| `wUSDT` | 6 | `USDT_UNIT = 1_000_000` |

Fixed baseline rate: **10 BB = 1 wUSDT**.

---

## Hard rules (do not break)

1. **All financial math uses integers** (`u64` / `u128`). `f64` only at the
   display/API boundary.
2. `get_balance()` returns `f64` (whole BB). Use `get_balance_lamports()` / the
   lamports endpoints for financial logic.
3. SPL token amounts are raw micro-units (`u64`).
4. Every state-changing POST is Ed25519-signed. Replay is blocked by nonce +
   60-second timestamp freshness.
5. ReDB writes precede DashMap hot-state updates (durability first).

---

## Ecosystem Consumer Alignment (2026-11-25)

`blvkprism` (Next.js frontend) and `L2_BlackBook` (Rust/Axum market & fantasy engine) organize reality TV and sports around two product modes:

1. **Mode 1 — Global Last-One-Standing Pools** (`global_survivor`, `global_amazing_race`, `global_mls`): Users pick who lasts the longest; an eliminated pick knocks out the entry and survivors split the pot. Anchored to L2 parent hubs (`SURVIVOR-S51-MAIN-V2`, `TAR-S39-MAIN-V2`, `MLS-2026-MAIN-V2`).
2. **Mode 2 — Custom Fantasy Leagues**: Commissioner-hosted BB/FC leagues (defaulting to strict `0 / 1 / 2` scoring + Perplexity Sonar / ClearSports oracles in `blvkprism`) backed by user-signed L1 rollup locks (`ROLLUP_LOCK_BB`).

### Pure Custody Boundary (Unified Rollup Hub)
- L1 stores **zero game logic, rosters, or fantasy scoring rules** — those remain strictly in `blvkprism` / `L2_BlackBook`.
- Legacy per-contest gRPC escrow RPCs (`InitContestReserve`, `SubmitMerkleRoot`, `SubmitPendingRoot`, `GetContestStatus`, `DistributePayouts`) are **retired** (`Status::unimplemented` in `src/settlement/mod.rs`).
- All L2 `$BB` custody flows use **Lock-Only Rollup Custody**:
  - **Inbound:** `POST /rollup/L2/lock_bb` → `GET /rollup/L2/locks/:lock_id` → `POST /rollup/L2/locks/:lock_id/consume`
  - **Settlement & Exit:** `POST /rollup/L2/submit_root` → `POST /rollup/L2/exit` (cumulative Merkle proof + permanent ReDB exit seal)
  - **Disputes:** `POST /oracle/submit-pending-root` (`src/contracts/oracle/mod.rs`, 15-min / `2,250`-slot window + `$BB`-staked voting & auto-finalization)
  - **Live Balances:** gRPC `SubscribeBalances`, `GetBalance`, `SyncBridge` (`:50052`)
- Never mint or seed unapproved balances.

---

## Layer 1 Production Next Steps

1. **Phase 1 — Guarded Production Launch *(Immediate)***
   - Execute the **Cold Treasury Split**: move ~90% of `DEALER_WALLET` (`939,562.50192 BB`) to an offline Cold Treasury Wallet on L1 via `POST /transfer/simple`, leaving a `25,000–50,000 BB` operational float.
   - Verify end-to-end **Rollup Hub loop** with L2 once L2 finishes migrating off the retired gRPC escrow RPCs (`lock_bb` → `consume` → `submit_root` → `exit`).
   - Confirm production build runs **without** `--features unsafe_admin` and with `L2_SEQUENCER_PUBKEY` strictly enforced.
2. **Phase 2 — Supervised Non-Custodial *(30–60 Days)***
   - Connect L2 resolutions to L1's **Optimistic Dispute Window** (`POST /oracle/submit-pending-root` + `oracle/finalize.rs`) so disputed roots pause exit finalization automatically.
   - Expose L1 Rollup Vault balance metrics to **L0 telemetry** & Glass Pane for automated solvency alarms (`vault_balance >= sum(unclaimed_lifetime_exits)`).
3. **Phase 3 — Fully Non-Custodial *(End State)***
   - Enforce **Multi-Oracle Quorum (`2-of-3` / `3-of-5`)** on L1 before accepting Rollup Hub settlement roots.
   - Launch the **Multi-Node L1 + L0 Validator Ring** (`--mode validator`, rotating 4-slot leader schedule, Tower BFT, and `manifest.json` genesis ceremony).
