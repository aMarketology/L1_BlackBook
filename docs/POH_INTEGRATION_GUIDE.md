# PoH Integration Guide - BlackBook L1 Blockchain

## Overview

The BlackBook L1 blockchain now includes a **production-ready Proof of History (PoH)** integration that provides:

- ✅ **Deterministic Transaction Ordering** - PoH timestamps ensure globally consistent transaction order
- ✅ **Verifiable State Roots** - Merkle trees provide cryptographic proofs of account state
- ✅ **Block Production** - Leader-based block production with PoH linkage
- ✅ **Transaction Finality** - 2-block confirmation threshold for finality
- ✅ **Chain Verification** - Full chain integrity verification

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         POH-INTEGRATED BLOCKCHAIN                         │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Transactions ──▶ PoH Mix ──▶ Block Producer ──▶ State Root ──▶ Commit   │
│        │              │              │                │                   │
│        │         (ordering)    (leader check)   (merkle tree)             │
│        ▼              ▼              ▼                ▼                   │
│   Gulf Stream    PoH Entry      Finalized        Verifiable               │
│   (forwarding)   (timestamp)      Block            Proof                  │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

### Components

1. **PoH Service** (`runtime/poh_service.rs`)
   - Continuous hash chain generation
   - Transaction mixing for ordering
   - Slot/epoch management

2. **Block Producer** (`src/poh_blockchain.rs`)
   - Leader-based block production
   - PoH-ordered transaction execution
   - Merkle state root computation

3. **Finality Tracker** (`src/poh_blockchain.rs`)
   - Tracks confirmation counts per transaction
   - Finality threshold: 2 block confirmations

4. **Merkle Tree** (`src/poh_blockchain.rs`)
   - Generates state roots from account balances
   - Provides inclusion proofs for any account

## API Endpoints

### Block Queries

#### GET `/poh/block/latest`
Returns the most recently produced block.

**Response:**
```json
{
  "success": true,
  "block": {
    "slot": 42,
    "timestamp": 1699500000,
    "hash": "abc123...",
    "previous_hash": "xyz789...",
    "state_root": "def456...",
    "poh_hash": "ghi012...",
    "poh_sequence": 5250000,
    "tx_count": 15,
    "leader": "genesis_validator",
    "epoch": 0,
    "confirmations": 3,
    "finality_status": "Finalized"
  }
}
```

#### GET `/poh/block/:slot`
Get a specific block by slot number.

**Response includes transactions:**
```json
{
  "success": true,
  "block": {
    "slot": 5,
    "transactions": [
      {
        "id": "tx_abc123",
        "from": "L1_ALICE...",
        "to": "L1_BOB...",
        "amount": 100.0,
        "poh_hash": "abc...",
        "poh_sequence": 125000,
        "position": 0
      }
    ]
  }
}
```

### Chain Verification

#### GET `/poh/block/verify/:slot`
Verify integrity of a specific block.

**Response:**
```json
{
  "success": true,
  "slot": 5,
  "is_valid": true,
  "checks": {
    "hash_chain": true,
    "hash_computed": true,
    "tx_count_match": true
  }
}
```

#### GET `/poh/chain/verify`
Verify entire chain integrity.

**Response:**
```json
{
  "success": true,
  "chain_valid": true,
  "block_count": 100,
  "latest_slot": 99,
  "latest_hash": "abc..."
}
```

#### GET `/poh/chain/stats`
Get comprehensive chain statistics.

**Response:**
```json
{
  "success": true,
  "blocks": {
    "produced": 100,
    "pending_txs": 5
  },
  "consensus": {
    "current_slot": 100,
    "confirmations_required": 2
  },
  "poh": {
    "num_hashes": 1250000,
    "current_hash": "abc123...",
    "current_slot": 100,
    "current_epoch": 0,
    "entries_in_slot": 64
  }
}
```

### Transaction Finality

#### GET `/poh/tx/:tx_id/status`
Check finality status of a transaction.

**Response:**
```json
{
  "success": true,
  "tx_id": "tx_abc123",
  "status": "Finalized",
  "is_finalized": true,
  "confirmations_required": 2
}
```

**Status Values:**
- `Pending` - Not yet included in a block
- `Processing { confirmations: N }` - In block but not finalized (N < 2)
- `Finalized` - Has 2+ confirmations, immutable

### State Proofs

#### GET `/poh/proof/:address`
Generate a merkle inclusion proof for an account.

**Response:**
```json
{
  "success": true,
  "address": "L1_52882D768C0F3E7932AAD1813CF8B19058D507A8",
  "balance": 1000.0,
  "proof": {
    "leaf_index": 0,
    "root": "abc123...",
    "path_length": 3,
    "proof_nodes": [
      {"hash": "def...", "is_left": false},
      {"hash": "ghi...", "is_left": true},
      {"hash": "jkl...", "is_left": false}
    ]
  }
}
```

**Verification:**
The proof can be verified client-side by:
1. Hash the leaf: `SHA256(address || balance_le_bytes)`
2. Walk up the tree using proof nodes
3. Compare final hash with the `root`

### Block Production

#### POST `/poh/produce`
Produce a new block (validator endpoint).

**Response (success):**
```json
{
  "success": true,
  "block": {
    "slot": 101,
    "hash": "abc...",
    "state_root": "def...",
    "poh_hash": "ghi...",
    "tx_count": 10,
    "timestamp": 1699500100
  }
}
```

**Response (not leader):**
```json
{
  "success": false,
  "error": "Not the current leader",
  "current_slot": 101,
  "expected_leader": "validator_xyz"
}
```

### Leader Schedule

#### GET `/poh/leader/current`
Get current leader information.

**Response:**
```json
{
  "success": true,
  "current_slot": 100,
  "current_leader": "genesis_validator",
  "next_leader": "genesis_validator",
  "is_our_slot": true,
  "epoch": 0
}
```

#### GET `/poh/leader/schedule?count=10`
Get upcoming leader schedule.

**Response:**
```json
{
  "success": true,
  "current_slot": 100,
  "upcoming_leaders": [
    {"slot": 100, "leader": "genesis_validator"},
    {"slot": 101, "leader": "genesis_validator"}
  ],
  "validators": ["genesis_validator"]
}
```

## Key Data Structures

### FinalizedBlock
```rust
pub struct FinalizedBlock {
    // Block header
    pub slot: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    
    // State commitment
    pub state_root: String,      // Merkle root of all accounts
    pub accounts_hash: String,
    
    // PoH linkage
    pub poh_hash: String,        // PoH hash at block time
    pub poh_sequence: u64,       // Global PoH sequence number
    pub poh_entries: Vec<PoHEntry>,
    
    // Transactions
    pub transactions: Vec<OrderedTransaction>,
    pub tx_count: u32,
    
    // Consensus
    pub leader: String,
    pub epoch: u64,
    pub confirmations: u64,
}
```

### OrderedTransaction
```rust
pub struct OrderedTransaction {
    pub tx: Transaction,
    pub poh_hash: String,       // PoH hash when tx was mixed
    pub poh_sequence: u64,      // Global ordering
    pub slot: u64,
    pub position: u32,          // Position within block
}
```

### MerkleProof
```rust
pub struct MerkleProof {
    pub leaf_index: usize,
    pub proof: Vec<ProofNode>,
    pub root: String,
}
```

## Security Properties

### 1. Deterministic Ordering
Transactions are ordered by their PoH sequence number, ensuring:
- All validators see the same order
- No front-running possible (order is cryptographically committed)
- Replay attacks prevented (unique PoH hash per transaction)

### 2. Immutability
Each block includes:
- Previous block hash (chain linkage)
- PoH hash (timing commitment)
- State root (account state commitment)

Modifying any block requires re-computing all subsequent blocks.

### 3. Finality
With `CONFIRMATIONS_REQUIRED = 2`:
- Transactions in a block with 2+ confirmations are considered final
- Reorganization of finalized blocks would require controlling the PoH clock

### 4. Verifiable State
Merkle proofs allow light clients to verify:
- An account exists with a specific balance
- Without downloading the full blockchain

## Configuration

### PoH Configuration
```rust
let poh_config = PoHConfig {
    slot_duration_ms: 1000,      // 1 second slots
    hashes_per_tick: 12500,      // ~125K hashes/slot
    ticks_per_slot: 64,          // 64 tick entries per slot
    slots_per_epoch: 432000,     // ~5 days per epoch
};
```

### Block Constants
```rust
const MAX_TXS_PER_BLOCK: usize = 1000;
const BLOCK_INTERVAL_MS: u64 = 1000;
const CONFIRMATIONS_REQUIRED: u64 = 2;
```

## Usage Example

### Submit Transaction and Wait for Finality
```javascript
// 1. Submit transaction
const submitRes = await fetch('/transfer', {
  method: 'POST',
  body: JSON.stringify({
    from: 'L1_ALICE...',
    to: 'L1_BOB...',
    amount: 100.0,
    signature: '...'
  })
});
const { tx_id } = await submitRes.json();

// 2. Poll for finality
let finalized = false;
while (!finalized) {
  const statusRes = await fetch(`/poh/tx/${tx_id}/status`);
  const { is_finalized } = await statusRes.json();
  finalized = is_finalized;
  if (!finalized) await sleep(1000);
}

// 3. Transaction is now immutable
console.log('Transaction finalized!');
```

### Verify Account State
```javascript
// Get merkle proof for account
const proofRes = await fetch('/poh/proof/L1_ALICE...');
const { balance, proof } = await proofRes.json();

// Verify proof locally (pseudo-code)
const leaf = sha256(address + balance_le_bytes);
let current = leaf;
for (const node of proof.proof_nodes) {
  if (node.is_left) {
    current = sha256(node.hash + current);
  } else {
    current = sha256(current + node.hash);
  }
}
assert(current === proof.root);
```

## Testing

```bash
# Get current PoH status
curl http://localhost:8080/poh/status

# Get chain stats
curl http://localhost:8080/poh/chain/stats

# Get current leader
curl http://localhost:8080/poh/leader/current

# Produce a block (if you're the leader)
curl -X POST http://localhost:8080/poh/produce

# Get latest block
curl http://localhost:8080/poh/block/latest

# Verify chain integrity
curl http://localhost:8080/poh/chain/verify

# Get state proof for an account
curl http://localhost:8080/poh/proof/L1_52882D768C0F3E7932AAD1813CF8B19058D507A8
```

## Future Enhancements

1. **Validator Network** - Multi-validator consensus with stake-weighted leader election
2. **Persistent Block Storage** - Store finalized blocks to ReDB
3. **Light Client Protocol** - SPV-style verification using merkle proofs
4. **Snapshot System** - Periodic state snapshots for fast sync
5. **Fork Choice Rule** - Handle temporary forks during network partitions
