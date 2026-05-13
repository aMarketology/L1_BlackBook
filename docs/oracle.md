# BlackBook — Optimistic Oracle System (Option B)

> Last updated: 2026-05-04

---

## The Problem

BlackBook's prediction markets need real-world event resolution at scale. The current model
(Perplexity AI → human approval) requires manual intervention for every market. At 500+
concurrent markets, this breaks.

**Goal:** Trustless, automated resolution where you never touch a bet, but any user can
challenge a wrong result by staking $XX — with the PoH clock as the only timekeeper.

---

## Full Architecture

```
REAL WORLD
  Sports APIs, crypto price feeds, L3 on-chain events
       │
       │  (each oracle node independently queries, signs result)
       ▼
┌─────────────────────────────────────────────────────────────┐
│  ORACLE COMMITTEE  (3 independent nodes, M-of-N threshold) │
│                                                             │
│  Each node has Ed25519 keypair registered on L1             │
│  Signs: ORACLE_ATTEST:{market_id}:{outcome}:{ts}:{nonce}   │
│  Posts to L2:  POST /oracle/attest                         │
└─────────────────────────┬───────────────────────────────────┘
                          │ 2-of-3 sigs collected
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  L2 DEALER  (aggregator, removes human from critical path) │
│                                                             │
│  NEW: POST /oracle/attest                                  │
│    - Validates each sig against oracle pubkeys from L1      │
│    - Waits for M-of-N threshold                            │
│    - Calls resolve_bb() → builds Merkle tree               │
│    - gRPC SubmitPendingRoot (NOT immediate commit)         │
└─────────────────────────┬───────────────────────────────────┘
                          │ SubmitPendingRoot gRPC
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  L1 — PENDING_ROOTS  (2h optimistic dispute window)        │
│                                                             │
│  Proposed root stored with:                                │
│    - finalize_at_slot = current_slot + 6_480               │
│    - stake_pool = 0 (grows if challenged)                  │
│                                                             │
│  Anyone can:  POST /oracle/dispute { market_id, xx_stake } │
│    → stakes $XX against the root                           │
│    → if stake > dispute_threshold → triggers $XX vote      │
│                                                             │
│  No dispute at finalize_at_slot                            │
│    → root moves to ESCROW_MARKET_ROOTS ✅                  │
│    → disputer stake returned + reward from house           │
│                                                             │
│  Dispute + $XX vote passes (wrong root)                    │
│    → root DISCARDED                                        │
│    → oracle nodes who signed wrong outcome SLASHED         │
│    → disputer receives slashed $XX                         │
└─────────────────────────┬───────────────────────────────────┘
                          │ root finalized
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  L1 ESCROW_MARKET_ROOTS  (already built)                   │
│  Users withdraw via POST /escrow/withdraw + Merkle proof   │
└─────────────────────────────────────────────────────────────┘
                          │ event finality signal
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  L3 NFT ENGINE  (consumer only — no new oracle logic)      │
│                                                             │
│  Poll: GET /oracle/event/:market_id                        │
│  On finality: AnchorNft gRPC → L1 with oracle_event_hash  │
│  NFT metadata.oracle_attestation = sha256(oracle_message)  │
│  Provably tied to a real, multi-signed event on-chain      │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer Responsibilities

| Layer | Owns | Builds |
|-------|------|--------|
| **L1** | `ORACLE_REGISTRY`, `PENDING_ROOTS`, dispute window timer (PoH), $XX staking/slashing, finalize → `ESCROW_MARKET_ROOTS` | 4 new ReDB tables, 3 new endpoints, 1 PoH background task |
| **L2** | M-of-N oracle sig collection, auto-resolve trigger, `SubmitPendingRoot` gRPC | 1 new endpoint, update gRPC call |
| **L3** | NFT provenance via `oracle_event_hash` in metadata | 0 new endpoints — just reads L1 |
| **Oracle nodes** | External binaries (separate repo) — query APIs, sign, POST to L2 | New binary (can start as 1 node you run) |

---

## Data Structures

### L1: `ORACLE_REGISTRY` table
```
key:   oracle_pubkey_hex (64 char hex)
value: OracleNode JSON {
  pubkey_hex: String,          // Ed25519 public key (32 bytes)
  name: String,                // human label e.g. "oracle-node-1"
  registered_at_slot: u64,
  active: bool,
  total_resolutions: u64,      // track record
  correct_resolutions: u64,    // correct track record
  slash_balance_pico_xx: u64,  // $XX held as bond (slashable on wrong attestation)
}
```

### L1: `PENDING_ROOTS` table
```
key:   market_id (String)
value: PendingRoot JSON {
  market_id: String,
  merkle_root: [u8; 32],
  proposed_at_slot: u64,
  finalize_at_slot: u64,        // proposed_at_slot + DISPUTE_WINDOW_SLOTS (6_480)
  outcome: String,              // e.g. "Yes" or "Manchester City"
  oracle_signatures: Vec<{
    pubkey_hex: String,
    sig_hex: String,
  }>,
  dispute_stake_pico_xx: u64,   // total $XX staked against this root
  disputers: Vec<{
    wallet: String,
    stake_pico_xx: u64,
  }>,
  status: PendingRootStatus,    // Pending | Disputed | Finalized | Discarded
}
```

### L1: `ORACLE_DISPUTES` table
```
key:   "{market_id}:{disputer_wallet}" (String)
value: OracleDispute JSON {
  market_id: String,
  disputer: String,             // BB wallet address
  stake_pico_xx: u64,          // $XX locked
  filed_at_slot: u64,
  resolved: bool,
}
```

### L1: `ORACLE_VOTES` table
```
key:   "{market_id}:{voter_wallet}" (String)
value: OracleVote JSON {
  market_id: String,
  voter: String,
  vote: bool,                   // true = uphold root, false = discard
  xx_weight: u64,               // voter's $XX balance at time of vote
  voted_at_slot: u64,
}
```

---

## Canonical Message Formats

Oracle nodes sign:
```
ORACLE_ATTEST:{market_id}:{outcome}:{timestamp}:{nonce}
```

L2 submits to L1 gRPC as `SubmitPendingRoot`:
```
canonical_message = market_id_bytes ++ l2_block_number.le_bytes(8) ++ merkle_root[32] ++ outcome_bytes
```
(Same as current `SubmitMerkleRoot` — add `outcome_bytes` field.)

Dispute staking signed message:
```
ORACLE_DISPUTE:{market_id}:{xx_stake_pico}:{timestamp}:{nonce}
```

Governance vote signed message:
```
ORACLE_VOTE:{market_id}:{vote_bool}:{timestamp}:{nonce}
```

---

## Constants

```rust
// In src/svm/types.rs or src/main.rs — to be added:
const DISPUTE_WINDOW_SLOTS: u64 = 6_480;       // ~2h at 400ms/slot
const ORACLE_THRESHOLD_NUMERATOR: u64 = 2;     // 2-of-3 required
const ORACLE_THRESHOLD_DENOMINATOR: u64 = 3;
const MIN_ORACLE_BOND_PICO_XX: u64 = 1_000 * MAXX_UNIT; // 1,000 $XX bond per oracle node
const MIN_DISPUTE_STAKE_PICO_XX: u64 = 100 * MAXX_UNIT; // 100 $XX minimum to file dispute
const DISPUTE_ESCALATION_THRESHOLD: u64 = 1_000 * MAXX_UNIT; // 1,000 $XX triggers $XX governance vote
```

---

## New L1 Endpoints

### `POST /oracle/register`  *(admin-only, `unsafe_admin` feature)*
Register a new oracle node pubkey. Oracle must bond $XX.
```json
Request: { "pubkey_hex": "...", "name": "oracle-node-1", "bond_pico_xx": 1000000000000 }
Response: { "success": true, "registered_at_slot": 99812 }
```

### `GET /oracle/nodes`
List all active oracle node registrations and their track records.

### `GET /oracle/event/:market_id`
Returns the current resolution state for a market — used by L3 NFT engine.
```json
Response: {
  "market_id": "market_123",
  "status": "Finalized",              // Pending | Disputed | Finalized | Discarded
  "outcome": "Yes",
  "merkle_root": "a1b2...",
  "finalized_at_slot": 100293,
  "oracle_event_hash": "sha256(oracle_message)"   // L3 uses this as NFT provenance
}
```

### `POST /oracle/dispute`
Any user stakes $XX to challenge a pending root.
```json
Request: {
  "market_id": "market_123",
  "xx_stake_pico": 100000000000000,   // 100 $XX in pico units
  "public_key": "...",
  "signature": "...",
  "timestamp": 1746393600,
  "nonce": "abc123"
}
Response: { "success": true, "total_dispute_stake": "...", "escalated_to_vote": false }
```

### `POST /oracle/vote`
$XX holders vote on escalated disputes (only callable when `status == Disputed`).
```json
Request: {
  "market_id": "market_123",
  "vote": false,                      // false = discard root (oracle was wrong)
  "public_key": "...",
  "signature": "...",
  "timestamp": 1746393600,
  "nonce": "xyz789"
}
Response: { "success": true, "current_tally": { "uphold": 45000, "discard": 80000 } }
```

---

## New L1 Background Task

A PoH-driven background task (alongside the existing PoH tick loop in `runtime/poh_service.rs`)
checks every N slots for expired dispute windows:

```rust
// Pseudo-code — fires every 100 slots
async fn finalize_expired_pending_roots(state: AppState) {
    let current_slot = state.current_slot.load(Ordering::Relaxed);
    for pending in state.blockchain.load_all_pending_roots() {
        if pending.status == PendingRootStatus::Pending
            && current_slot >= pending.finalize_at_slot
        {
            // Move to ESCROW_MARKET_ROOTS
            state.blockchain.finalize_pending_root(&pending.market_id)?;
            // Return any disputer stakes (no valid dispute was filed)
            // Emit PoH event: TxData::OracleFinalized { market_id, merkle_root, slot }
        }
    }
}
```

---

## New L2 Endpoint

### `POST /oracle/attest`  *(L2 Dealer only)*
Receives a signed oracle attestation from a node. Collects until M-of-N threshold is met,
then auto-fires `resolve_bb()` and calls `SubmitPendingRoot` gRPC.
```json
Request: {
  "market_id": "market_123",
  "outcome": "Yes",
  "oracle_pubkey_hex": "...",
  "oracle_signature_hex": "...",  // over ORACLE_ATTEST canonical message
  "timestamp": 1746393600,
  "nonce": "abc123"
}
Response: {
  "accepted": true,
  "signatures_collected": 2,
  "threshold": 2,
  "auto_resolved": true           // true once threshold met
}
```

---

## L3 NFT Provenance

When an oracle event is finalized on L1, the `oracle_event_hash` is available at
`GET /oracle/event/:market_id`. L3 embeds this in the NFT metadata before calling
`AnchorNft` gRPC:

```json
// NFT metadata (stored on IPFS/Arweave)
{
  "name": "Haaland Hat-Trick #0042",
  "description": "Minted because oracle attested hat-trick in Match #4421",
  "oracle_event_hash": "a3f9b2...",    // sha256 of oracle canonical message
  "market_id": "match_4421_haaland_hattrick",
  "finalized_at_l1_slot": 100293,
  "merkle_root": "c7d1e4..."
}
```

Anyone can verify this NFT by:
1. Calling `GET /oracle/event/:market_id` on BlackBook L1
2. Confirming `oracle_event_hash` matches the NFT metadata
3. Confirming the slot and root match

---

## $XX Tokenomics Integration

The dispute system gives $XX **real utility beyond speculation**:

| Action | $XX Flow |
|--------|----------|
| Oracle node registers | Bonds `MIN_ORACLE_BOND_PICO_XX` (locked) |
| Correct oracle finalization | Bond returned + small $XX reward |
| Wrong oracle (dispute upheld by vote) | Bond **slashed** → goes to disputer |
| Disputer wins | Stake returned + slashed oracle bond |
| Disputer loses | Stake **slashed** → goes to house / burns |
| $XX holder votes correctly | No stake required — voting is free |

This makes $XX a **governance + insurance token**, not just a bonding curve token.

---

## Build Order

```
Step 1 — L1 ORACLE_REGISTRY + admin endpoint (1h)
  - New ReDB table: ORACLE_REGISTRY
  - POST /oracle/register (unsafe_admin feature gate)
  - GET /oracle/nodes

Step 2 — L1 PENDING_ROOTS table + dispute window (1 day)
  - New ReDB tables: PENDING_ROOTS, ORACLE_DISPUTES, ORACLE_VOTES
  - SubmitPendingRoot gRPC variant (or flag on existing SubmitMerkleRoot)
  - Background task: finalize_expired_pending_roots()
  - POST /oracle/dispute
  - GET /oracle/event/:market_id
  - TxData::OracleFinalized variant added to protocol/blockchain.rs

Step 3 — L1 $XX voting + slashing (1 day)
  - POST /oracle/vote
  - Vote tally + finalize/discard logic
  - Oracle bond slashing via SplTokenEngine::burn()
  - Disputer reward distribution

Step 4 — L2 oracle aggregation (half day)
  - POST /oracle/attest
  - Fetch oracle pubkeys from L1 GET /oracle/nodes
  - M-of-N verification
  - Auto-trigger resolve_bb() → SubmitPendingRoot (not SubmitMerkleRoot)

Step 5 — Oracle node binary (half day)
  - Simple binary: query data source → sign canonical message → POST to L2
  - Start with 1 node (yourself) → grow to 3

Step 6 — L3 integration (2h)
  - Read GET /oracle/event/:market_id before AnchorNft gRPC call
  - Embed oracle_event_hash in NFT metadata JSON
```

Total: ~3.5 days

---

## Files to Create / Modify

### New files
- `src/contracts/oracle/mod.rs` — all oracle endpoints + PendingRoot CRUD
- `src/contracts/oracle/dispute.rs` — dispute + vote handlers
- `src/contracts/mod.rs` — add `pub mod oracle;`

### Modified files
- `src/storage/mod.rs` — 4 new ReDB table constants + CRUD methods
- `protocol/blockchain.rs` — `TxData::OracleFinalized { market_id, merkle_root, outcome, slot }` variant
- `src/poh_blockchain.rs` — add `VaultBurn` pattern arm for `OracleFinalized`
- `src/reader/mod.rs` — add `OracleFinalized` catch-all arm
- `src/main.rs` — wire oracle routes + background finalization task
- `runtime/poh_service.rs` — trigger `finalize_expired_pending_roots` hook

### NOT modified
- `src/contracts/global_escrow/mod.rs` — `ESCROW_MARKET_ROOTS` consumer unchanged
- `src/contracts/maxx_token/mod.rs` — $XX mint/burn unchanged (slashing calls `SplTokenEngine::burn` directly)
- L2 `svm_settlement.rs` — Merkle generation unchanged
- L3 NFT bridge proto — `AnchorNftRequest` unchanged (just gains `oracle_event_hash` in metadata JSON)

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Oracle can't lie unilaterally | 2-of-3 threshold required |
| All oracles can't collude silently | 2h public dispute window — anyone can challenge |
| Disputes can't be spammed | Minimum $XX stake required to file |
| Wrong oracle is economically punished | $XX bond slashed on upheld dispute |
| False disputes are economically punished | $XX stake slashed on failed dispute |
| PoH clock is the only authority | No admin override on finalize_at_slot |
| Double-resolution impossible | PendingRoot status transitions are one-way: Pending → Finalized/Discarded |
