# L1 Smart Contract Specification
## BlackBook L2 Rollup — Full Integration Guide

> **Target chain:** Solana  
> **L2 runtime:** Rust / Axum (`src/main_v3.rs`)  
> **Settlement bridge:** gRPC (`grpc/settlement.proto`)  
> **Last updated:** March 2026

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [The Three L1 Endpoints](#2-the-three-l1-endpoints)
3. [Full End-to-End Flow](#3-full-end-to-end-flow)
4. [L1 Smart Contract: What It Must Implement](#4-l1-smart-contract-what-it-must-implement)
5. [Merkle Tree Specification](#5-merkle-tree-specification)
6. [Sequencer Key & Signing Protocol](#6-sequencer-key--signing-protocol)
7. [The One Missing Piece: L2_SEQUENCER_PUBKEY](#7-the-one-missing-piece-l2_sequencer_pubkey)
8. [Gap Analysis: What's Built vs What's Needed](#8-gap-analysis-whats-built-vs-whats-needed)
9. [Environment Variables Reference](#9-environment-variables-reference)
10. [Wire Format Reference](#10-wire-format-reference)

---

## 1. Architecture Overview

BlackBook operates two completely isolated subsystems on two separate layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1  (Solana)                                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Global Escrow Program (PDA)                             │   │
│  │                                                          │   │
│  │  • Holds ALL BB tokens for all open markets              │   │
│  │  • Verifies user deposits before L2 accepts entries      │   │
│  │  • Receives Merkle root from L2 after settlement         │   │
│  │  • Pays winners who submit valid Merkle proofs           │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────┘
                gRPC (5 RPCs)│
┌──────────────────────────▼──────────────────────────────────────┐
│  LAYER 2  (BlackBook Rust Server)                               │
│                                                                  │
│  ┌─────────────────────┐    ┌────────────────────────────────┐  │
│  │  SEQUENCER          │    │  GAME ENGINE                   │  │
│  │                     │    │                                │  │
│  │  • Ed25519 key mgmt │    │  • BB Markets (L1-settled)     │  │
│  │  • Deposit verify   │    │  • FC Contests (Supabase)      │  │
│  │  • Merkle tree build│    │  • 5 game types                │  │
│  │  • Root signing     │    │  • Auto-resolve via oracle     │  │
│  │  • gRPC → L1        │    │  • Agent deployment            │  │
│  └─────────────────────┘    └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Key invariants — never break these:**

| Invariant | Rule |
|-----------|------|
| Currency isolation | BB is Market-only. FC is Contest-only. Never cross-convert. |
| Custody | L2 holds **zero** BB. All BB lives in the L1 escrow PDA. |
| Identity | L2 never trusts a user's self-reported wallet. L1 echoes the real depositor wallet. |
| Zero-sum | `total_payout + house_rake == total_deposited` — enforced by both L2 and L1. |

---

## 2. The Three L1 Endpoints

These are the three user-facing on-chain interactions. The L2 R is involved in steps 1b and 2 only — step 3 (claim) happens entirely between the user and L1.

### Endpoint 1 — `POST /escrow/deposit` *(User → L1 directly)*

The user signs a Solana transaction that transfers BB tokens into the contest's escrow vault (PDA). The L2 never touches this transaction — the user calls L1 directly.

After the transaction finalises, the user submits the **Solana tx signature** to the L2 when entering a market. The L2 then calls L1's `VerifyDeposit` RPC to confirm it.

**What L1 must do:**
- Accept SPL token transfers to a per-contest PDA vault (`escrow_vault_pda(contest_id)`)
- Record `(tx_sig → depositor_wallet, amount, contest_id, used=false)` in a deposit ledger
- Reject calls where `used=true` — prevents double-spend

---

### Endpoint 2 — `POST /escrow/submit-state-root` *(L2 Sequencer → L1)*

After a BB market resolves, the L2 builds a Merkle tree over all winning wallets and submits the 32-byte root to L1 via gRPC (`SubmitMerkleRoot`). L1 stores this root on-chain in the `ContestState` PDA.

**What L1 must do:**
- Verify the Ed25519 signature on the submission (see §6)
- Verify `sequencer_pubkey` is in the L1 allowlist
- Enforce `l2_block_number > last_seen_for_sequencer` (replay protection)
- Verify zero-sum: `total_deposited == total_payout + house_rake`
- Post the `merkle_root` to the `ContestState` PDA on-chain
- Mark the contest as `SETTLED`

---

### Endpoint 3 — `POST /escrow/withdraw` *(User → L1 directly)*

After a contest is settled, winners retrieve their Merkle inclusion proof from the L2 (`GET /proof/:market/:wallet`) and submit it directly to L1. L1 verifies the proof against the stored root and releases the payout.

**What L1 must do:**
- Look up `merkle_root` from the `ContestState` PDA for the given `contest_id`
- Reconstruct the expected leaf: `SHA-256(wallet_bytes_32 ++ payout_amount_u64_le8)`
- Walk the Merkle proof and verify it reaches the stored root
- Pay exactly `payout_amount` from the escrow vault to the caller's wallet
- Mark the leaf as claimed (prevent double-claim)
- Enforce `claim_deadline_slot` — unclaimed funds expire to platform treasury

---

## 3. Full End-to-End Flow

```
USER                     L2 SERVER                    L1 ESCROW
 │                            │                            │
 │  1. Deposit BB on-chain ───────────────────────────────►│
 │     (Solana tx, no L2      │                            │
 │      involvement)          │                            │ PDA vault receives BB
 │                            │                            │ Deposit ledger: tx→wallet
 │                            │                            │
 │  2. POST /bb/:id/enter ───►│                            │
 │     { deposit_tx: "5xAb…" }│                            │
 │                            │  VerifyDeposit(tx_sig) ───►│
 │                            │◄── { wallet, amount, ok } ─│
 │                            │                            │
 │                            │  Entry recorded with       │
 │                            │  L1-verified wallet as     │
 │                            │  canonical identity        │
 │                            │                            │
 │  3. [Event occurs]         │
 │                            │  Oracle resolves outcome    │
 │                            │  → score_entries()          │
 │                            │  → generate_svm_receipts()  │
 │                            │    Build Merkle tree        │
 │                            │    leaf = SHA-256(pk||amt)  │
 │                            │    Sort leaves by pubkey    │
 │                            │    Compute root             │
 │                            │    Cache proofs per wallet  │
 │                            │                            │
 │                            │  SubmitMerkleRoot ─────────►│
 │                            │    contest_id               │ Verify Ed25519 sig
 │                            │    merkle_root (32 bytes)   │ Check sequencer allowlist
 │                            │    l2_block_number          │ Replay protection
 │                            │    total_deposited          │ Zero-sum check
 │                            │    total_payout             │ Store root in ContestState
 │                            │    house_rake               │ Mark SETTLED
 │                            │    sequencer_sig (64 bytes) │
 │                            │◄── { success, l1_tx_hash } ─│
 │                            │                            │
 │  4. GET /proof/:id/:wallet►│                            │
 │◄── { proof: [hash, …],     │                            │
 │      amount: 1500000 }     │                            │
 │                            │                            │
 │  5. claimWinnings ─────────────────────────────────────►│
 │     { proof, amount }      │                            │ Verify proof vs root
 │                            │                            │ Reconstruct leaf hash
 │                            │                            │ Pay amount to caller
 │                            │                            │ Mark leaf claimed
```

---

## 4. L1 Smart Contract: What It Must Implement

### 4.1 — Program Derived Addresses (PDAs)

The escrow program needs two PDA types:

```
// Per-contest vault — holds all BB deposited by entrants
escrow_vault_pda(contest_id) → token account (SPL)

// Per-contest state — tracks root, status, totals
contest_state_pda(contest_id) → ContestState account
```

`ContestState` account structure:
```
ContestState {
    contest_id:          [u8; 64],
    status:              enum { Open, Settled, Expired },
    merkle_root:         [u8; 32],      // zero until settled
    total_deposited:     u64,           // SPL units, 6 decimals
    total_claimed:       u64,           // running sum of paid-out claims
    winner_count:        u32,
    house_rake:          u64,
    claim_deadline_slot: u64,           // slot after which funds expire
    l1_tx_hash:          [u8; 64],      // tx that posted the root
    last_l2_block:       u64,           // highest seen block number from sequencer
}
```

---

### 4.2 — Instruction: `InitContest`

Called by the dealer via `InitContestReserve` gRPC RPC when funding a BB market.

```
Inputs:
  contest_id:     string
  dealer_address: Pubkey (base58)
  bb_reserve:     u64 (SPL units)

Actions:
  1. Create escrow_vault_pda(contest_id) — an SPL token account
  2. Create contest_state_pda(contest_id) with status=Open
  3. Transfer bb_reserve from dealer_address to vault
  4. Record total_deposited = 0 (user entries come later)

Returns:
  confirmed: bool
  l1_tx_hash: string
```

---

### 4.3 — Instruction: `VerifyDeposit`

Called by L2 every time a user enters a BB market (`enter_bb()`). L2 will **refuse to record the entry** if this returns `verified=false`.

```
Inputs:
  contest_id:       string
  deposit_tx_sig:   string (Solana tx signature, base58, 88 chars)
  expected_amount:  u64 (SPL units)

Actions:
  1. Look up deposit_tx_sig in the deposit ledger
  2. Check tx is finalized (not pending)
  3. Verify tx transferred to escrow_vault_pda(contest_id), not elsewhere
  4. Verify transferred amount == expected_amount
  5. Verify this tx_sig has not been used before (used=false)
  6. Mark tx_sig as used=true (prevents double-spend)
  7. Increment ContestState.total_deposited += amount

Returns:
  verified:          bool
  depositor_wallet:  string  ← L2 uses this as canonical identity, ignores user claim
  actual_amount:     u64
  deposit_slot:      u64
  error_code:        TX_NOT_FOUND | WRONG_CONTEST | WRONG_AMOUNT | ALREADY_USED |
                     CONTEST_CLOSED | TX_NOT_FINAL
```

**Critical:** The L2 uses `depositor_wallet` from this response as the wallet identity for the Merkle tree leaf. The user's self-reported wallet is ignored. This is the anti-fraud guarantee.

---

### 4.4 — Instruction: `SubmitMerkleRoot`

Called by L2 after every BB market resolves. This is the "rollup finality" moment.

```
Inputs (the full 14-field MerkleRootSubmission proto):
  contest_id:       string
  merkle_root:      bytes[32]
  winner_count:     u32
  total_deposited:  u64 (SPL units)
  total_payout:     u64 (SPL units)
  house_rake:       u64 (SPL units)
  winning_outcome:  string
  resolved_at:      i64 (unix timestamp)
  receipt_hash:     string (hex SHA-256 audit trail)
  oracle_proof:     string
  l2_block_number:  u64
  signed_message:   bytes  ← tightly packed canonical message
  sequencer_pubkey: bytes[32]
  sequencer_sig:    bytes[64]

L1 Verification Steps (in order — reject on any failure):

  Step 1 — Signature verification:
    expected_msg = contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root_bytes(32)
    ed25519_verify(sequencer_pubkey, expected_msg, sequencer_sig) → must pass

  Step 2 — Allowlist check:
    sequencer_pubkey must be in the L1's registered sequencer allowlist

  Step 3 — Replay protection:
    l2_block_number > ContestState.last_l2_block → must be true
    Update ContestState.last_l2_block = l2_block_number

  Step 4 — Zero-sum check:
    total_deposited == total_payout + house_rake → must be true

  Step 5 — State transition:
    Store merkle_root in ContestState PDA
    Set ContestState.status = Settled
    Set ContestState.claim_deadline_slot = current_slot + CLAIM_WINDOW (e.g. 30 days)
    Transfer house_rake from vault to platform treasury wallet

Returns:
  success:             bool
  l1_tx_hash:          string
  l1_finalized_slot:   u64
  error_message:       string (non-empty if success=false)
```

---

### 4.5 — Instruction: `ClaimWinnings`

Called directly by users — the L2 has no involvement here once the proof is served.

```
Inputs:
  contest_id:    string
  wallet:        Pubkey (must match tx signer)
  amount:        u64 (SPL units — must match leaf)
  proof:         Vec<[u8; 32]> (Merkle inclusion proof hashes)

L1 Verification Steps:

  Step 1 — Look up settled root:
    root = ContestState.merkle_root (must be non-zero — contest must be Settled)

  Step 2 — Reconstruct the leaf:
    leaf = SHA-256(wallet.as_bytes()[32] ++ amount.to_le_bytes()[8])
    // Note: amount is u64 SPL units, 8 bytes little-endian

  Step 3 — Verify the Merkle proof:
    Walk proof hashes: at each step, combine (smaller_hash ++ larger_hash) and SHA-256
    Final hash must equal root

  Step 4 — Anti-double-claim:
    claimed_set[contest_id][wallet] must be false
    Set claimed_set[contest_id][wallet] = true

  Step 5 — Check deadline:
    current_slot <= ContestState.claim_deadline_slot

  Step 6 — Pay out:
    Transfer amount SPL tokens from escrow_vault_pda(contest_id) to wallet
    Increment ContestState.total_claimed += amount
```

---

### 4.6 — Instruction: `GetContestStatus`

Called by L2 via the `GetContestStatus` gRPC RPC to query live on-chain state.

```
Returns:
  contest_id:           string
  status:               OPEN | SETTLED | EXPIRED
  total_deposited:      u64
  total_claimed:        u64
  merkle_root:          bytes[32]
  claim_deadline_slot:  u64
  l1_tx_hash:           string
```

---

## 5. Merkle Tree Specification

The Merkle tree must be constructed identically on both L2 (where it is built) and L1 (where leaves are verified). Any deviation causes every claim to fail.

### Leaf Hash

```
leaf = SHA-256( pubkey_bytes[32] ++ payout_amount.to_le_bytes()[8] )
```

- `pubkey_bytes` — the raw 32-byte Ed25519 public key of the winner's Solana wallet
- `payout_amount` — a **`u64`** in SPL token units (1 BB = 1,000,000 SPL units, 6 decimals)
- Concatenate directly — no delimiters, no encoding

**Current L2 implementation** (`layer_2/svm_settlement.rs`):
```rust
fn leaf_hash(pk: &Pubkey, payout_amount: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pk.as_ref());                  // 32 bytes
    h.update(&payout_amount.to_le_bytes()); // 8 bytes LE u64
    h.finalize().into()
}
```

> ⚠️ **Type alert:** The amount is `u64` (SPL units). Your L1 spec mentioned `f64_le_bytes`. These are **not the same byte representation**. The L2 uses `u64`. Your L1 must also use `u64.to_le_bytes()`, not `f64.to_le_bytes()`. If they differ, every proof will fail.

### Tree Structure

- Leaves are sorted by the raw pubkey bytes before building the tree: `sorted_by(|a, b| a.as_ref().cmp(b.as_ref()))`
- The tree uses SHA-256 as the hashing algorithm (`rs_merkle::algorithms::Sha256`)
- At each internal node: `SHA-256(smaller_child_hash ++ larger_child_hash)` — sorted so smaller hash comes first
- This is the standard "sorted-pair Merkle tree" used by most EVM and SVM contracts

### Payout Per Winner

```
pool = sum of all entry fees collected
rake = pool × (rake_bps / 10000)       // default rake_bps = 500 = 5%
net_prize_pool = pool - rake
payout_per_winner = net_prize_pool / winner_count   // equal split
payout_per_winner_spl = round(payout_per_winner × 1_000_000)
```

Every winner in the same market receives an identical payout (equal split). The same `payout_per_winner_spl` value is baked into every leaf.

---

## 6. Sequencer Key & Signing Protocol

### Key Generation

```sh
# Generate the sequencer keypair once, store securely
openssl rand -hex 32     # → 64 hex chars = 32-byte seed
```

Set on L2:
```
L2_SEQUENCER_KEY=<64 hex chars>   # private — never expose
```

Set on L1 allowlist:
```
L2_SEQUENCER_PUBKEY=<64 hex chars>  # public — the derived Ed25519 verifying key
```

The L2 logs its pubkey on startup:
```
🔑 [L2] Sequencer pubkey: a1b2c3d4...  (set L2_SEQUENCER_PUBKEY=<this> on L1)
```

### Signed Message Format

The L2 packs a canonical binary message before signing. L1 must reconstruct the **exact same bytes** from the proto fields to verify:

```
signed_message = contest_id_bytes ++ l2_block_number_le8 ++ merkle_root_bytes32
```

- `contest_id_bytes` — raw UTF-8 bytes of the contest ID string (variable length)
- `l2_block_number_le8` — the monotonic block counter as 8 bytes, little-endian u64
- `merkle_root_bytes32` — the 32-byte Merkle root

> ⚠️ **Format mismatch:** The user-provided L1 spec expected the string `"STATE_ROOT:{market_id}:{merkle_root}:{l2_block_number}"`. The L2 uses **binary packing**, not a string. One side must change to match the other. The binary format is unambiguous and recommended — update the L1 to verify using the binary layout above.

### Signature Algorithm

Ed25519 using `ed25519_dalek`:
```rust
// L2 signs:
sig = sequencer_key.sign(&signed_message_bytes)  // → 64-byte signature

// L1 verifies:
verifying_key = VerifyingKey::from_bytes(&sequencer_pubkey_32)?;
verifying_key.verify(&signed_message_bytes, &Signature::from_bytes(&sig_64))?;
```

### Replay Protection

The `l2_block_number` is an `AtomicU64` incremented by 1 on every BB market resolution. L1 must enforce:

```
new_block_number > ContestState.last_l2_block_for_sequencer
```

This guarantees that even if a `MerkleRootSubmission` message is intercepted and retransmitted (e.g. by a network attacker), L1 will reject it because the block number is no longer higher than what was last seen.

---

## 7. The One Missing Piece: L2_SEQUENCER_PUBKEY

The L1 contract has an allowlist of trusted sequencer public keys. The gate check in the `SubmitMerkleRoot` handler is:

```
if sequencer_pubkey NOT IN allowlist → reject
```

**This is the only hard block between your L2 and a working settlement flow.** Everything else is implemented.

**Steps to unblock:**

```sh
# Step 1 — Generate keypair (if not done)
openssl rand -hex 32 > sequencer_seed.hex

# Step 2 — Set on L2 server (Railway / Render env var)
L2_SEQUENCER_KEY=<contents of sequencer_seed.hex>

# Step 3 — Start L2 server, read the logged pubkey:
# 🔑 [L2] Sequencer pubkey: a1b2c3...  ← copy this

# Step 4 — Register pubkey on L1 allowlist
# (how you do this depends on your L1 admin instruction —
#  likely a tx calling RegisterSequencer(pubkey))
```

The L2's pubkey derivation:
```rust
// From settlement_bridge.rs
pub fn sequencer_pubkey_hex(&self) -> Option<String> {
    self.sequencer_key.as_ref()
        .map(|k| hex::encode(k.verifying_key().as_bytes()))
}
```

---

## 8. Gap Analysis: What's Built vs What's Needed

### What the L2 already has ✅

| Feature | File | Status |
|---------|------|--------|
| Merkle tree builder | `layer_2/svm_settlement.rs` | ✅ Complete |
| Leaf hash: `SHA-256(pubkey \|\| u64_amount_le)` | `layer_2/svm_settlement.rs:81` | ✅ Complete |
| Leaves sorted by pubkey before tree build | `layer_2/svm_settlement.rs:114` | ✅ Complete |
| Per-winner proof generation | `layer_2/svm_settlement.rs:127` | ✅ Complete |
| Proof cache: `settlement_proofs[market][wallet]` | `src/main_v3.rs:347` | ✅ Complete |
| Monotonic `AtomicU64` block counter | `src/main_v3.rs:343` | ✅ Complete |
| Ed25519 sequencer key loading | `src/settlement_bridge.rs:80` | ✅ Complete |
| Binary-packed signed message | `src/settlement_bridge.rs:221` | ✅ Complete |
| gRPC `SubmitMerkleRoot` call | `src/settlement_bridge.rs:208` | ✅ Complete |
| gRPC `VerifyDeposit` call | `src/settlement_bridge.rs:151` | ✅ Complete |
| gRPC `InitContestReserve` call | `src/settlement_bridge.rs` | ✅ Complete |
| Zero-sum enforcement (payout + rake = deposited) | `src/main_v3.rs:1195` | ✅ Complete |
| Receipt hash (SHA-256 audit trail) | `src/main_v3.rs:1185` | ✅ Complete |
| Depositor wallet from L1 (not self-reported) | `src/main_v3.rs:931` | ✅ Complete |

### What's missing ❌

#### Gap 1 — `GET /proof/:market/:wallet` HTTP endpoint

**Impact:** Users cannot call `/escrow/withdraw` (claim winnings) without their Merkle proof.

**What exists:** Proofs are built and cached in `self.settlement_proofs` at resolution time. The data is there. There is just no HTTP route to serve it.

**What's in the route table:** No `/proof` route exists in the router (`src/main_v3.rs:2791`).

**What to add:**
```rust
.route("/proof/:market/:wallet", get(h_get_proof))
```

Handler logic:
```rust
async fn h_get_proof(
    State(state): State<AppState>,
    Path((market, wallet)): Path<(String, String)>,
) -> impl IntoResponse {
    let dealer = state.read().await;
    match dealer.settlement_proofs.get(&market).and_then(|m| m.get(&wallet)) {
        Some(proof) => Json(serde_json::json!({
            "market": market,
            "wallet": wallet,
            "proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
            "payout_spl": dealer.bb_markets.get(&market)
                .map(|m| /* payout_per_winner_spl */ 0u64)  // store this at resolve time
        })).into_response(),
        None => (StatusCode::NOT_FOUND, "No proof found").into_response(),
    }
}
```

> Note: You also need to store `payout_per_winner_spl` at resolution time (it's in the `Settlement` struct returned by `generate_svm_receipts`) so the proof endpoint can return the amount the user should pass to `claimWinnings`.

---

#### Gap 2 — Signed message format must match L1

**Impact:** Every `SubmitMerkleRoot` call will fail signature verification if L1 and L2 use different formats.

**L2 signs (binary packing):**
```
contest_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]
```

**L1 expected (string):**
```
"STATE_ROOT:{market_id}:{merkle_root_hex}:{l2_block_number}"
```

**Resolution:** Update the L1 verifier to use the binary format. The binary format is strictly better — no encoding ambiguity, no delimiter injection surface.

---

#### Gap 3 — Leaf amount type must match L1

**Impact:** Every `ClaimWinnings` call will fail Merkle proof verification.

**L2 leaf:** `SHA-256(pubkey[32] ++ payout_u64.to_le_bytes()[8])` — `u64` SPL units  
**L1 spec says:** `amount_as_f64_le_bytes` — `f64`

A `u64` of `1500000` encodes as `0x00000000001640` in LE. An `f64` of `1500000.0` encodes as `0x4136D78000000000`. They are different bytes — completely different leaves — proofs won't verify.

**Resolution:** Both sides must use `u64` SPL units in `to_le_bytes()`. Update the L1 to match the L2.

---

#### Gap 4 — Transport: gRPC vs REST

**Impact:** If the L1 is a REST service, the L2's tonic gRPC client will fail to connect.

**L2 expects:** A gRPC server at `GRPC_URL` implementing `SettlementService` (see `grpc/settlement.proto`)  
**L1 might be:** A REST server exposing `POST /escrow/submit-state-root`

**Resolution options:**
- **Option A (recommended):** Implement the gRPC server on L1 using the existing `grpc/settlement.proto`. Import the proto, generate server stubs, implement the handlers. This is the cleanest path since the entire proto contract is already designed.
- **Option B:** Rewrite `src/settlement_bridge.rs` to use `reqwest` HTTP calls instead of tonic gRPC. This is more work on the L2 side.

---

## 9. Environment Variables Reference

### L2 Server

| Variable | Required | Description |
|----------|----------|-------------|
| `L2_SEQUENCER_KEY` | **Yes** for prod | 64 hex chars — 32-byte Ed25519 private seed. Generate with `openssl rand -hex 32`. Without this, submissions are unsigned and L1 will reject them. |
| `GRPC_URL` | **Yes** for BB | gRPC address of the L1 settlement service (e.g. `http://my-l1-host:50051`) |
| `DEALER_WALLET` | Yes for BB fund | Dealer's Solana wallet address (base58) — used when locking reserve on L1 |
| `SUPABASE_URL` | Yes | Supabase project URL — FC balance operations |
| `SUPABASE_KEY` | Yes | Supabase service role key |
| `SUPABASE_JWT_SECRET` | Yes | JWT secret for validating user tokens |
| `DEALER_JWT` | Yes | Static dealer authentication token |
| `PORT` | No | HTTP listen port (default varies) |

### L1 Contract / Admin

| Variable | Required | Description |
|----------|----------|-------------|
| `L2_SEQUENCER_PUBKEY` | **Yes** | 64 hex chars — the Ed25519 verifying key derived from `L2_SEQUENCER_KEY`. The L2 logs this on startup. Register this in the L1 allowlist. |

---

## 10. Wire Format Reference

### gRPC Service Definition

The full interface is defined in `grpc/settlement.proto`. The five RPCs:

| RPC | Direction | When Called |
|-----|-----------|-------------|
| `VerifyDeposit` | L2 → L1 | On every `POST /bb/:id/enter` — before recording the entry |
| `InitContestReserve` | L2 → L1 | On `POST /dealer/:id/fund` for BB markets |
| `SubmitMerkleRoot` | L2 → L1 | On `POST /dealer/:id/resolve` for BB markets |
| `GetContestStatus` | L2 → L1 | Optional — query on-chain state |
| `SyncBridge` | Bidirectional | Optional — heartbeat / TPS monitoring |

### MerkleRootSubmission fields (14 total)

| Field | Tag | Type | Description |
|-------|-----|------|-------------|
| `contest_id` | 1 | string | Market/contest identifier |
| `merkle_root` | 2 | bytes[32] | SHA-256 Merkle root |
| `winner_count` | 3 | uint32 | Number of winning leaves |
| `total_deposited` | 4 | uint64 | Total BB in, SPL units |
| `total_payout` | 5 | uint64 | Net to winners after rake, SPL units |
| `house_rake` | 6 | uint64 | Platform cut, SPL units |
| `winning_outcome` | 7 | string | Human-readable outcome |
| `resolved_at` | 8 | int64 | Unix timestamp |
| `receipt_hash` | 9 | string | `SHA-256("id:outcome:ts:deposited:payout:rake")` |
| `oracle_proof` | 10 | string | Oracle source identifier |
| `l2_block_number` | 11 | uint64 | Monotonic replay-protection counter |
| `signed_message` | 12 | bytes | Binary: `contest_id_bytes ++ block_le8 ++ root[32]` |
| `sequencer_pubkey` | 13 | bytes[32] | Ed25519 verifying key — must be in L1 allowlist |
| `sequencer_sig` | 14 | bytes[64] | Ed25519 signature over `signed_message` |
