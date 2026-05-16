# Balance Push Migration — Delivery Receipt

**Sprint goal**: Decouple L2's market-entry gate from a synchronous L1 round-trip.  
**Outcome**: L1 now pushes live balance updates to L2 over a persistent gRPC stream.  
L2 checks its local cache instantly; the old `VerifyDeposit` RPC is gone entirely.

---

## Why This Change

The old flow forced L2 to pause every user deposit behind a synchronous
`VerifyDeposit` gRPC call to L1.  This created a serial bottleneck on the hot path
and a single point of failure: if L1 was slow or the connection blipped, market entry
stalled.

The new flow inverts control:

```
OLD  User bets → L2 asks L1 "did they deposit?" → L1 answers → L2 gates entry
NEW  L1 mints BB → L1 pushes BalanceUpdate to L2 → L2 caches → User bets instantly
```

---

## Files Changed

### `proto/settlement.proto`

| What | Detail |
|------|--------|
| **Removed** | `rpc VerifyDeposit`, `VerifyDepositRequest`, `VerifyDepositResponse` |
| **Added** | `rpc SubscribeBalances(SubscribeBalancesRequest) returns (stream BalanceUpdate)` |
| **Added** | `rpc GetBalance(GetBalanceRequest) returns (GetBalanceResponse)` |

**`SubscribeBalancesRequest`** — fields:
- `address_filter` (repeated string) — if non-empty, stream only these addresses  
- `timestamp` (uint64) — Unix seconds; L1 rejects requests older than 60 s  
- `client_pubkey` (bytes, 32) — Ed25519 public key  
- `client_sig` (bytes, 64) — signs `b"SUBSCRIBE_BALANCES" || timestamp_le8`

**`BalanceUpdate`** — fields:
- `address`, `new_balance_lamports`, `delta_lamports` (always 0 from L1; L2 computes from cache), `slot`, `timestamp`, `block_hash`
- **No** `resume_from_slot` / `intra_block_idx` — see design decisions below

**`GetBalanceRequest / GetBalanceResponse`** — unauthenticated; returns `{ address, balance_lamports, current_slot }`

---

### `src/settlement/mod.rs`

| What | Detail |
|------|--------|
| **New struct** | `pub BalanceUpdateEvent` — Rust broadcast payload mirroring `BalanceUpdate` proto |
| **Extended struct** | `BlackBookSettlementService` gains `pub balance_event_tx: broadcast::Sender<BalanceUpdateEvent>` |
| **Extended ctor** | `BlackBookSettlementService::new(…, balance_event_tx)` |
| **Removed** | `verify_deposit` handler (entire `impl` branch) |
| **Added** | `subscribe_balances` — allowlist check → 60 s timestamp freshness → Ed25519 verify → `BroadcastStream` → optional address filter → `async_stream::stream!` yielding `BalanceUpdate` |
| **Added** | `get_balance` — unauthenticated; reads `get_balance_lamports(&req.address)` |
| **Kept** | `deposit_requests` DashMap (still used by deposit gateway double-mint guard) |

`subscribe_balances` error handling:
- `RecvError::Lagged` → log warning, continue (lossy is acceptable; L2 self-heals on reconnect)
- gRPC `Status` errors are returned to the client as `Status::internal`

---

### `src/main.rs`

| What | Detail |
|------|--------|
| **Added to `AppState`** | `pub balance_event_tx: tokio::sync::broadcast::Sender<BalanceUpdateEvent>` |
| **Channel creation** | `broadcast::channel::<BalanceUpdateEvent>(4096)` — capacity 4 096 events (ring buffer) |
| **Block production loop** | After each block with `tx_count > 0`, collects all touched addresses from `block.transactions`, reads `get_balance_lamports` for each, sends one `BalanceUpdateEvent` per address using `block.slot` as the sequence key |
| **Settlement svc ctor** | `BlackBookSettlementService::new(…, balance_event_tx.clone())` |
| **AppState ctor** | `balance_event_tx: balance_event_tx.clone()` |

Touched-address detection covers all `TxData` variants:
`TransferBb`, `DepositUsdt`, `EscrowDeposit`, `EscrowWithdraw`, `VaultBurn`, `EscrowSweep`.  
`EscrowStateRoot` carries no balance change.

---

### `tests/balance_subscription_e2e.rs` *(new file)*

Six unit tests exercising the broadcast mechanics without a live server:

| Test | Asserts |
|------|---------|
| `test_balance_event_broadcast_delivers` | Basic send → recv |
| `test_balance_event_fanout_to_multiple_subscribers` | All receivers get every event |
| `test_one_event_per_address_per_slot` | `(address, slot)` uniqueness contract holds |
| `test_lagged_receiver_gets_lagged_error` | Lossy ring buffer does not block fast senders |
| `test_no_receivers_does_not_panic` | `send()` with zero subscribers is safe |
| `test_address_filter_suppresses_unmatched` | Filter logic matches handler behaviour |

---

### `sdk/dealer.sdk.ts`

| What | Detail |
|------|--------|
| **Updated** | Class JSDoc settlement-cycle step 2: `verifyDeposit()` → `SubscribeBalances stream / getBalanceCached()` |
| **Removed** | `GrpcVerifyDepositResponse` interface (dead type) |
| **Added** | `GrpcGetBalanceResponse` interface — maps `GetBalanceResponse` proto |
| **Added** | `GrpcBalanceUpdate` interface — maps `BalanceUpdate` proto |
| **Added** | `DealerSDK.getL1Balance(address)` — HTTP fallback for cache misses, returns `{ lamports, bb }` |
| **Added** | `BalanceCache` standalone class — L2-side self-healing balance mirror (see below) |

---

### Stale-comment cleanup

| File | Line | Change |
|------|------|--------|
| `src/contracts/global_escrow/mod.rs` | 188 | `VerifyDeposit gRPC` → `GetBalance gRPC / double-mint guard` |
| `src/storage/mod.rs` | ESCROW_DEPOSITORS table doc | `VerifyDeposit replay protection` → `deposit double-mint protection` |
| `src/storage/mod.rs` | `EscrowDepositorEntry` struct doc | `VerifyDeposit replay protection` → `deposit double-mint protection` |
| `src/storage/mod.rs` | `EscrowDepositorEntry.used` field | `consumed by a successful VerifyDeposit` → `deposit has been processed` |
| `deployment/docker-compose.prod.yml` | port 50052 comment | `SubmitMerkleRoot / VerifyDeposit` → `SubscribeBalances / SubmitMerkleRoot` |

---

## Design Decisions

### No `resume_from_slot`

`tokio::broadcast` is a lossy ring buffer — it cannot replay past events.  Adding
`resume_from_slot` would require a ReDB historical scan plus race-condition handling.
Instead the L2 uses the **Self-Healing Cache (Path A)**:

> On reconnect → flush entire cache.  
> On cache miss at bet entry → call `GetBalance` (unary, unauthenticated) to lazy-fill.  
> Live stream events overwrite stale HTTP-filled entries (slot 0 → any slot ≥ 1).

### Slot as the only sequence identifier

`block.slot` is stored in ReDB and survives L1 restarts monotonically.  There is no
in-memory `AtomicU64` sequence counter, so there is no "counter resets to 0 on restart"
trap that would trigger false gap alarms on the L2 side.

### One event per address per block

Events are deduplicated inside the block-production loop using a `HashSet<String>`.
The `(address, slot)` pair is therefore a perfect idempotency key — L2 can safely
ignore any duplicate with `slot <= cached_slot`.

### `intra_block_idx` dropped

Because there is exactly one event per `(address, slot)`, a secondary index inside the
block was unnecessary.

---

## How L2 Connects

```ts
import * as grpc from "@grpc/grpc-js";
import * as proto from "./generated/settlement_grpc_pb"; // tonic-generated stubs
import { DealerSDK, BalanceCache, GrpcBalanceUpdate } from "../sdk/dealer.sdk";

const sdk   = new DealerSDK(L1_HTTP_URL, sequencerKeypair, L1_GRPC_URL);
const cache = new BalanceCache(sdk);

const stub = new proto.SettlementServiceClient(
  "l1-node:50052",
  grpc.credentials.createInsecure()
);

function connectFeed(addressFilter: string[]) {
  const ts  = Math.floor(Date.now() / 1000);
  // canonical: b"SUBSCRIBE_BALANCES" || timestamp_le8
  const msg = concatBytes(TEXT_ENC.encode("SUBSCRIBE_BALANCES"), toLe8(ts));
  const sig = ed25519Sign(sequencerPrivKey, msg);

  const stream = stub.subscribeBalances({
    address_filter: addressFilter,
    timestamp:      ts,
    client_pubkey:  sequencerPubkeyBytes,
    client_sig:     sig,
  });

  stream.on("data",  (ev: GrpcBalanceUpdate) => cache.update(ev));
  stream.on("error", () => {
    cache.flush();                              // ← self-heal: discard stale data
    setTimeout(() => connectFeed(addressFilter), 2_000);
  });
}

// Market entry gate (replaces old verifyDeposit round-trip):
async function canEnterMarket(address: string, minLamports: number): Promise<boolean> {
  const balance = await cache.getOrFetch(address); // instant if cached, HTTP if miss
  return balance >= minLamports;
}
```

---

## Build Verification

```powershell
cargo check --features unsafe_admin
# Result: zero errors (2 unused-constant warnings — pre-existing, unrelated)
```
