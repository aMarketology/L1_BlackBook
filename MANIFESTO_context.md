# BlackBook L1 - Code Context Map

> **This document maps the Two Core Jobs (L1 responsibilities) to their implementing files.**

---

## The Two Core Jobs → File Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      BLACKBOOK L1 CODEBASE (Settlement Layer)               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  JOB 1: GATEKEEPER ──────────────► protocol/blockchain.rs                   │
│  (USDT → $BB)                      └── Tier1Gateway struct                  │
│                                    └── deposit_usdt()                       │
│                                    └── redeem_bb_for_usdt()                 │
│                                    └── check_solvency() invariant           │
│                                    └── bb_locked_on_l2 tracking             │
│                                                                             │
│  JOB 2: INVISIBLE SECURITY ──────► src/wallet_mnemonic/                     │
│  (SSS Wallet)                      └── mnemonic.rs (BIP-39)                 │
│                                    └── sss.rs (Shamir 2-of-3)               │
│                                    └── signer.rs (Ed25519)                  │
│                                    └── handlers.rs (API)                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      BLACKBOOK L2 (Application Layer - Separate Repo)       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIME MACHINE (L2 Responsibility): $BB → $DIME with vintage stamps          │
│                                    └── Listens for L1 lock events           │
│                                    └── Mints $DIME with CPI stamp            │
│                                    └── Handles all betting in $DIME         │
│                                    └── Burn $DIME → Unlock $BB on L1        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Structure & Responsibilities

### `/protocol/` - Core Blockchain Logic (Jobs 1 & 2)

| File | Responsibility |
|------|----------------|
| [blockchain.rs](protocol/blockchain.rs) | **THE HEART** - L1State, Tier1Gateway, Tier2Vault, TxData enum, all transaction processing |
| [mod.rs](protocol/mod.rs) | Public exports for protocol types |
| [helpers.rs](protocol/helpers.rs) | Utility functions |

**Key Types in `blockchain.rs`:**

```rust
// Job 1: Gatekeeper (L1 Settlement Only)
pub struct Tier1Gateway {
    pub vault_usdt_balance: u64,  // USDT locked in vault
    pub total_bb_minted: u64,     // Total $BB in circulation
    pub bb_locked_on_l2: u64,     // $BB bridged to L2
}
// INVARIANTS: 
//   vault_usdt_balance * 10 == total_bb_minted
//   total_bb_minted == bb_in_wallets + bb_locked_on_l2
```

**L2 Types (Not in this repo):**

```rust
// Job 2: Time Machine (L2 Application Layer)
pub struct Tier2Vault {
    pub bb_locked_from_l1: u64,           // Total $BB locked on L1
    pub vintages: HashMap<String, DimeVintage>,
    pub current_cpi: f64,
    pub active_bets: HashMap<BetId, Bet>,
}

pub struct DimeVintage {
    pub owner: String,
    pub bb_locked: u64,        // Original $BB amount (never changes)
    pub cpi_at_lock: f64,      // CPI when locked (timestamp)
    pub dime_issued: u64,      // $DIME given to user
}
```

---

### `/src/wallet_mnemonic/` - SSS Wallet (Job 3)

| File | Responsibility |
|------|----------------|
| [mnemonic.rs](src/wallet_mnemonic/mnemonic.rs) | BIP-39 24-word generation, entropy management |
| [sss.rs](src/wallet_mnemonic/sss.rs) | Shamir Secret Sharing (2-of-3 split/reconstruct) |
| [signer.rs](src/wallet_mnemonic/signer.rs) | Ed25519 signing, key derivation |
| [handlers.rs](src/wallet_mnemonic/handlers.rs) | Axum HTTP handlers for wallet API |
| [mod.rs](src/wallet_mnemonic/mod.rs) | Module exports |

**Key Functions:**

```rust
// Generate new wallet
generate_wallet() -> (mnemonic, keypair, shares)

// Split into 3 shards
split_secret(entropy) -> [ShareA, ShareB, ShareC]

// Reconstruct from any 2
reconstruct_from_ab(share_a, share_b) -> entropy
reconstruct_from_ac(share_a, share_c) -> entropy  
reconstruct_from_bc(share_b, share_c) -> entropy

// Sign transaction
sign_transaction(message, private_key) -> signature
```

---

### `/runtime/` - PoH & Consensus Engine

| File | Responsibility |
|------|----------------|
| [core.rs](runtime/core.rs) | Runtime coordination, slot management |
| [consensus.rs](runtime/consensus.rs) | Validator consensus logic |
| [poh_service.rs](runtime/poh_service.rs) | Proof of History tick generation |
| [mod.rs](runtime/mod.rs) | Module exports |

---

### `/src/` - Application Layer

| File | Responsibility |
|------|----------------|
| [main_v4.rs](src/main_v4.rs) | Server entry point, Axum router setup |
| [lib.rs](src/lib.rs) | Library exports |
| [poh_blockchain.rs](src/poh_blockchain.rs) | PoH-integrated block execution |
| [social_mining.rs](src/social_mining.rs) | Engagement rewards (future) |

---

### `/src/storage/` - Persistence

| File | Responsibility |
|------|----------------|
| [mod.rs](src/storage/mod.rs) | ReDB persistence, blockchain state |

---

### `/src/grpc/` - L2 Communication

| File | Responsibility |
|------|----------------|
| [mod.rs](src/grpc/mod.rs) | gRPC server for L2 settlement |

---

### `/src/routes_v2/` - HTTP API

| Directory | Responsibility |
|-----------|----------------|
| routes_v2/ | Axum route handlers for REST API |

---

### `/sdk/` - Client SDK

| File | Responsibility |
|------|----------------|
| [blackbook-wallet-sdk.js](sdk/blackbook-wallet-sdk.js) | JavaScript SDK for wallet operations |

---

### `/tests/` - Test Suite

| File | Responsibility |
|------|----------------|
| wallet_tests.rs | Wallet flow tests |
| wallet_production_tests.rs | Production readiness tests |
| bridge_escrow_tests.rs | Bridge/escrow tests |
| blockchain_core_tests.rs | Core blockchain tests |

---

## Transaction Flow

```
User Request
     │
     ▼
┌─────────────────┐
│  main_v4.rs     │  ◄── HTTP/gRPC entry
│  (Axum Router)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ handlers.rs     │  ◄── Parse request, extract shard
│ (Wallet API)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ sss.rs          │  ◄── Reconstruct key from 2 shards
│ (Shamir)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ signer.rs       │  ◄── Sign transaction with Ed25519
│ (Ed25519)       │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ protocol/blockchain.rs  │  ◄── Process transaction
│ (L1State)               │
│                         │
│  TxData::DepositUsdt    │  ◄── Job 1: Mint $BB
│  TxData::LockBbForDime  │  ◄── Job 2: Create vintage
│  TxData::Transfer*      │  ◄── Move tokens
└────────┬────────────────┘
         │
         ▼
┌─────────────────┐
│ poh_blockchain  │  ◄── Add to PoH chain
│ (PoH Service)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ stL1 Solvency (protocol/blockchain.rs)
```rust
// Must ALWAYS be true
tier1.vault_usdt_balance * 10 == tier1.total_bb_minted

// Bridge accounting
tier1.total_bb_minted == bb_in_l1_wallets + tier1.bb_locked_on_l2
```

### L2 Conservation (Enforced on L2, validated by L1 bridge)
```rust
// L2 can only mint $DIME for $BB actually locked on L1
l2.bb_locked_from_l1 == l1.bb_locked_on_l2  // Verified via bridge events

// Sum of all $BB in vintages == Total $BB locked from L1
sum(vintage.bb_locked for all vintages) == l2.bb_locked_from_l1
```rust
// Must ALWAYS be true
tier1.vault_usdt_balance * 10 == tier1.total_bb_minted
```

### Tier 2 Conservation (protocol/blockchain.rs)
```rustL1 Core Jobs (Removed or L2 Responsibility)

| Directory | Status | Notes |
|-----------|--------|-------|
| ~~src/usdc/~~ | Kept | Simple USDT bridge for deposits/withdrawals |
| ~~src/unified_wallet/~~ | Removed | FROST/MPC wallet (Phase 2) |
| ~~src/settlement/~~ | Removed | L2 batch settlement (L2 responsibility) |
| ~~src/routes_v2/~~ | Removed | Legacy auth routes |
| ~~src/integration/~~ | Removed | Legacy integration code |
| ~~src/rpc/~~ | Removed | Unused RPC layer |
| src/vault/ | Kept | HashiCorp Vault integration for secrets |

## L2 Responsibilities (Separate Repository)

**What L2 handles:**
- **Tier 2 Vault**: $BB → $DIME conversion with vintage stamps
- **CPI Oracle Integration**: Monthly inflation updates
- **Betting Engine**: All prediction market logic
- **Batch Settlements**: Merkle proof-based multi-winner payouts
- **Vintage Tracking**: Per-user inflation protection
// Any single shard is cryptographically useless
```

---

## Files NOT Part of Core Jobs (Can Be Cleaned Up)

These directories exist but are not essential to the Three Core Jobs:

| Directory | Status | Notes |
|-----------|--------|-------|
| src/usdc/ | Legacy | Old bridge code, can be removed |
| src/unified_wallet/ | Future | FROST/MPC wallet (deferred) |
| src/settlement/ | Future | L2 batch settlement (not Job 1-3) |
| src/vault/ | Legacy | Old vault config, now inline |

---

*Last Updated: February 7, 2026*
