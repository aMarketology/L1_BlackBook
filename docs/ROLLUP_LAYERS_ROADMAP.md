# BlackBook — Rollup Layers 2–5 Roadmap

> **L1 is the settlement layer. Layers 2–5 are rollup execution environments that post state roots back to L1.**
> Last updated: 2026-04-26

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    BLACKBOOK L1 (Settlement)                 │
│  PoH Clock · Tower BFT · Sealevel · Gulf Stream · Turbine   │
│  Global Escrow Contract · Merkle Root Verification          │
│  Three-token economy: BB · wUSDT · $XX                      │
└────────┬────────────┬────────────┬────────────┬─────────────┘
         │            │            │            │
    ┌────▼────┐  ┌────▼────┐  ┌───▼───┐  ┌────▼────┐
    │  L2     │  │  L3     │  │  L4   │  │  L5     │
    │ Predict │  │ DEX /   │  │ Yield │  │ Govern  │
    │ Market  │  │ Trading │  │ Vault │  │ -ance   │
    └─────────┘  └─────────┘  └───────┘  └─────────┘
```

**How every L2–5 layer talks to L1:**
1. Users lock BB in the L1 Global Escrow contract via `POST /escrow/deposit`
2. Layer runs autonomously (its own DB, own execution)
3. On settlement: layer submits a SHA-256 Merkle root via `POST /escrow/submit-state-root`
4. L1 enforces: valid sequencer signature, zero-sum invariant, monotonically increasing block number
5. Users claim winnings via `POST /escrow/withdraw` with a Merkle proof — L1 verifies, releases BB

---

## Layer 2 — Prediction Market ⭐ PRIORITY

**Status:** Running at `:1234`. Frontend wallet integrated. **Settlement end-to-end not yet confirmed.**

### What L1 Provides
| Feature | L1 Endpoint | Status |
|---|---|---|
| BB lock-in | `POST /escrow/deposit` | ✅ Working |
| State root anchoring | `POST /escrow/submit-state-root` | ✅ Working |
| Monotonicity enforcement | Auto-reject if `l2_block_number <=` last seen | ✅ Implemented |
| Zero-sum check | `total_deposited == total_payout + house_rake` | ✅ Implemented |
| Claim window (30 days) | `6_480_000 slots` from settlement | ✅ Implemented |
| User withdrawal via Merkle | `POST /escrow/withdraw` | ✅ Working |
| Double-claim prevention | DashMap + ReDB atomic write | ✅ Implemented |
| ReDB-first writes | Persist to disk before DashMap update | ✅ Implemented |
| Contest state query | `GET /escrow/contest/:id` | ✅ Working |

### L2 ← L1 Integration Contract (What L2 Must Send)

**Deposit verification:**
The L2 receives a `deposit_tx` UUID from the L1 escrow response. The L2 must:
1. Trust the deposit_tx ref only after validating via `GET /deposit/status/:tx_hash`
2. Lock user into the market entry only once `status == "approved"`

**State root submission** (after market resolution):
```json
POST /escrow/submit-state-root
{
  "market_id": "MLS-W8-LAFC",
  "merkle_root": "<64 hex chars — 32 bytes>",
  "signature": "<Ed25519 signature over: market_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]>",
  "l2_block_number": 101,          // strictly > last submitted
  "total_deposited": 5000000,       // SPL units (6 dec) — sum of all deposits
  "total_payout": 4750000,          // SPL units — sum of winner payouts
  "house_rake": 250000,             // SPL units — must equal deposited - payout
  "winner_count": 3
}
```

**Merkle leaf format** (must match L1 verify logic exactly):
```
leaf = SHA256( pubkey_raw_32_bytes || payout_spl_u64_le_bytes )
```
- `pubkey_raw_32_bytes` = bs58-decoded user wallet address (32 bytes)
- `payout_spl_u64_le_bytes` = `(payout_bb * 1_000_000).round() as u64` in little-endian

**Claim proof format** (returned by L2 to user frontend):
```json
{
  "market_id": "MLS-W8-LAFC",
  "wallet": "<base58 address>",
  "proof": ["<32-byte hex node>", "<32-byte hex node>", ...],
  "payout_spl": 1500000,
  "payout_bb": 1.5,
  "claim_deadline_slot": 7012345
}
```

### What Needs to Be Built / Verified

- [ ] **L2 deposit_tx validation** — L2 must call `GET /deposit/status/:tx_hash` before accepting entry
- [ ] **L2 state root bridge** — `settlement_bridge.rs` must build the correct Merkle tree (sorted SHA-256) and call L1 `/submit-state-root` with the correct binary signed message format
- [ ] **L2 proof endpoint** — `GET /proof/:market_id/:wallet_address` must return the claim proof in the format above
- [ ] **End-to-end test** — deposit → play → resolve → claim (see `docs/L2_TEST_GUIDE.md` for the 9-step test suite)
- [ ] **Claim deadline display** — frontend `PredictPage.tsx` should show days remaining to claim from `claim_deadline_slot`

---

## Layer 3 — DEX / Trading Layer

**Status:** Not started. Architecture defined below.

### Purpose
An on-chain automated market maker (AMM) or order book DEX allowing users to trade between BB, wUSDT, and $XX using funds locked in L1 escrow.

### How It Uses L1
- Users deposit into the **same Global Escrow PDA** as L2 (single escrow, multi-layer)
- Trade execution happens off-chain in the L3 engine
- At the end of each epoch (every N slots), the L3 submits a net-settlement root to L1
- Net: only the differences are settled, not every individual trade

### L1 Changes Required
- [ ] **Contest namespace** — escrow market_ids should be prefixed: `L2:market_id`, `L3:epoch_id` to prevent cross-layer ID collisions
- [ ] **Multi-layer escrow routing** — `GET /escrow/contest/:id` should return the layer prefix so UIs can route correctly

### Estimated Effort
Medium. The L1 settlement primitives are already in place. L3 needs its own execution engine (Rust or Node) and a settlement bridge.

---

## Layer 4 — Yield Vault

**Status:** Not started. Architecture defined below.

### Purpose
Users lock BB/wUSDT into yield strategies. Strategies run on L4 (e.g. lending, liquidity provision). Returns are settled back to user wallets on L1 via the escrow → merkle claim pattern.

### How It Uses L1
- Deposits: same `POST /escrow/deposit`
- Settlement: `POST /escrow/submit-state-root` with the final yield distribution Merkle root
- Withdrawals: same `POST /escrow/withdraw`

### Key Difference from L2
Yield vaults are **continuous** (rolling epochs) rather than event-driven (single market resolution). The L4 needs to:
1. Submit a state root every epoch (e.g. weekly)
2. Allow partial claims — users can claim yield without closing their principal position

### L1 Changes Required
- [ ] **Partial claims** — current withdraw marks the whole market as claimed. Need `claim_partial` variant that allows claiming yield without burning the full position.
- [ ] **Re-deposit on claim** — allow a claim to auto-re-lock into the next epoch (compound).

---

## Layer 5 — Governance

**Status:** Not started. Architecture defined below.

### Purpose
$XX holders vote on platform parameters: house rake %, LMSR b-parameter, fee rates, oracle sources, new layer approvals.

### How It Uses L1
- Vote weight = $XX balance at snapshot slot (from `GET /usdc/balance/:address`)
- Proposal execution calls admin endpoints on L1 (guarded by governance multisig)
- Vote tallying happens off-chain (L5 engine), result anchored to L1 as a state root

### L1 Changes Required
- [ ] **Snapshot balance** — `GET /balance/snapshot/:address/:slot` — read historical balance from ReDB for a specific past slot
- [ ] **Governance timelock** — a new escrow type with a time-delay before execution
- [ ] **Multisig sequencer** — governance layer needs M-of-N sequencer keys (vs. single key for L2)

---

## L1 Shared Infrastructure Status

These items are needed by ALL rollup layers.

| Feature | Status | Notes |
|---|---|---|
| Global Escrow deposit | ✅ Done | `POST /escrow/deposit` |
| Merkle root verification | ✅ Done | Sorted SHA-256, 32-byte nodes |
| Monotonicity enforcement | ✅ Done | Rejects stale l2_block_number |
| Zero-sum invariant | ✅ Done | `deposited == payout + rake` |
| ReDB-first persistence | ✅ Done | Disk before DashMap cache |
| Atomic double-claim | ✅ Done | DashMap entry() + ReDB |
| Claim deadline (30d) | ✅ Done | 6,480,000 slots |
| `simulateTransaction` | ❌ Needed | Milestone 2 in integration plan |
| WebSocket subscriptions | ❌ Needed | Milestone 7 in integration plan |
| Partial claims | ❌ Needed | Required for L4 yield vaults |
| Balance snapshots | ❌ Needed | Required for L5 governance voting |
| Layer-prefixed market IDs | ❌ Needed | Required when L3+ go live |

---

## Implementation Priority

```
IMMEDIATE (L2 prediction market — already running):
  1. Confirm L2 settlement_bridge.rs sends correctly signed state root
  2. Confirm L2 proof endpoint returns correct Merkle leaf format
  3. Run T1–T9 test suite from docs/L2_TEST_GUIDE.md end-to-end
  4. Add claim deadline display in PredictPage.tsx

NEXT (make L2 production-hardened):
  5. L2 deposit_tx validation before accepting market entry
  6. WebSocket subscription for live balance updates post-claim
  7. simulateTransaction RPC for Phantom/wallet pre-flight

MEDIUM TERM (L3 DEX foundation):
  8. Market ID namespace prefix (`L2:`, `L3:`, `L4:`, `L5:`)
  9. Build L3 execution engine (order book or AMM)
  10. L3 epoch settlement bridge (same pattern as L2)

LONG TERM (L4 + L5):
  11. Partial claim variant in escrow withdraw
  12. Balance snapshot endpoint for governance
  13. Multi-sig sequencer allowlist for governance
```

---

---

## LI.FI Integration & $XX Token Strategy

### LI.FI Widget (Track A — Live)
Embedded in the wallet `DepositModal`. No signup required. Bridges any source token on any chain to **native Solana USDT** in our custody wallet. The existing `CustodyWatcher` picks it up unchanged.

```tsx
// Lock destination: native Solana USDT into our custody wallet
const config: WidgetConfig = {
  integrator: 'BlackBook',
  toChain: 1151111081099710,   // Solana chainId in LI.FI
  toToken: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  toAddress: import.meta.env.VITE_CUSTODY_WALLET,
  hiddenUI: ['toAddress', 'toToken', 'toChain'],
};
```

### Native Chain Listing (Track B — 3–6 months)
Sequence: stable Railway RPC → apply to Mayan Finance → LI.FI partner portal → get BB chain ID → update widget config.

Requirements: high-uptime JSON-RPC, chain ID registration, bridge partner, block explorer, token list JSON.

### $XX / MAXXCOIN — Legal Framework

**$XX is a utility token, not a security, if:**
- It provides on-chain utility (governance votes, fee discounts, $DECAY redemption)
- Price is algorithmic (bonding curve `P(s) = 5×10⁻⁸ × s`) — not issuer-set
- No promises of profits or returns

**Key rules:**
- Describe as: *"utility token for platform governance and fee access"*
- Do NOT promise returns, profits, or yield in fiat
- Do NOT market to US persons without Reg D/S exemption
- Keep KYC/AML for purchases > $10,000
- First buyer sets the curve — no pre-mine, no team allocation

**Full swap path:**
```
Any chain → LI.FI → native Solana USDT → custody wallet
  → watcher mints wUSDT 1:1 → BB at 10:1 dealer rate
  → POST /sealevel/submit SwapBbForUsdc  (BB → wUSDT)
  → POST /maxx/buy                       (wUSDT → $XX at curve)
```

---

## Reference Documents

| Doc | What It Covers |
|---|---|
| [L2_INTEGRATION.md](L2_INTEGRATION.md) | Full L2 protocol spec: gRPC, HTTP, crypto, error codes, test guide |
| [ENDPOINT_GUIDE.md](ENDPOINT_GUIDE.md) | Full L1 API reference (76 endpoints) |
| [CHAIN_REFERENCE.md](CHAIN_REFERENCE.md) | Technical spec: tokens, crypto, PoH, SVM, storage |
| [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) | 14 milestones + onramp hardening phases |
