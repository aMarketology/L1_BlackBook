# BlackBook Bridge Watcher — Design Documentation

> **Status:** Design / pre-build. This folder is the complete specification for the
> **TypeScript Bridge Watcher** — the external relayer that turns real Solana
> `USDC`/`USDT` deposits into minted `$BB` on the BlackBook L1.
>
> Nothing here is built yet. These documents define **what** we are building,
> **why**, **when** each step runs, and **how** it stays safe. Implementation
> begins only after this design is agreed.

---

## TL;DR — What is the Bridge Watcher?

The Bridge Watcher is a small, independently-deployable **Node.js + TypeScript
service** that:

1. **Watches** a custody wallet on Solana for incoming `USDC` / `USDT` SPL transfers.
2. **Attributes** each deposit to a BlackBook L1 wallet (via an on-chain memo).
3. **Drives** the L1 deposit gateway to **mint `$BB`** to that wallet, exactly once.

It is the **critical path to a usable system**: until value can flow *into*
BlackBook, the hardened ledger has nothing to settle. The watcher is also the
natural end-to-end validation of the integer-exact deposit/mint code that was
just hardened in L1.

---

## Why a *separate* TypeScript service?

L1 already contains an embedded Rust `CustodyWatcher` (`src/watcher/mod.rs`).
The Bridge Watcher does **not** replace its on-chain verification logic — it
**moves the polling/attribution driver out of the consensus-critical writer**.
Full rationale in [01-architecture.md](01-architecture.md#why-externalize), but the
short version:

| Concern | Embedded Rust watcher | External TS Bridge Watcher |
|---|---|---|
| Couples Solana RPC uptime to the L1 writer | Yes — RPC stalls touch the writer | No — isolated process, crash/restart independently |
| Deploy / iterate cadence | Requires rebuilding + restarting L1 | Independent deploy, zero L1 downtime |
| Deposit UX | User must self-submit their `tx_hash` first | "Just send to this address" via memo attribution |
| Fits 1-writer/N-reader topology | Adds load to the writer | Keeps the writer lean (per topology plan) |
| Observability / runbook | Buried in L1 logs | Dedicated metrics, logs, alerts |

The embedded Rust verifier remains as a **defense-in-depth backstop** (see
[05-security-model.md](05-security-model.md#defense-in-depth)). The L1 endpoints are the
**trust boundary** — the watcher is a *privileged client*, never a source of truth.

---

## Reading order

| # | Document | Answers |
|---|---|---|
| 1 | [01-architecture.md](01-architecture.md) | What are the components and how do they fit the topology? |
| 2 | [02-deposit-lifecycle.md](02-deposit-lifecycle.md) | What happens, step by step, when a user deposits? |
| 3 | [03-l1-api-contract.md](03-l1-api-contract.md) | Exactly which L1 endpoints/signatures does the watcher call? |
| 4 | [04-solana-watcher-internals.md](04-solana-watcher-internals.md) | How does it watch Solana? Finality, cursors, attribution. |
| 5 | [05-security-model.md](05-security-model.md) | How is it safe? Reorg, double-mint, replay, key handling. |
| 6 | [06-config-and-runbook.md](06-config-and-runbook.md) | How is it configured, deployed, monitored, recovered? |
| 7 | [07-implementation-plan.md](07-implementation-plan.md) | What is the file layout and the build order? |

---

## The one-sentence contract

> **For every finalized stablecoin transfer into the custody wallet that carries a
> valid BlackBook memo, the watcher mints the correct amount of `$BB` to the
> referenced wallet exactly once, and never mints for any transfer that is
> unconfirmed, mis-attributed, replayed, or already processed.**

Everything in this folder exists to make that sentence true under failure.

---

## Scope boundaries (what this is NOT)

- **Not** the withdrawal / off-ramp path — that is `withdrawal_gateway` and is out of scope here.
- **Not** an AMM or price oracle — the BB↔stablecoin rate lives in L1 ReDB (`SWAP_RATES` key `BB_USDT`).
- **Not** a custody/key-management system — it never holds user funds; it observes a wallet it does not control.
- **Not** a consensus participant — it is a privileged HTTP client of the L1 writer.
