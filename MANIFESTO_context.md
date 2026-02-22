# BlackBook L1 — Code Context Map

> **This document maps the core system responsibilities to their implementing files.**
> **Last Updated: February 21, 2026**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   BLACKBOOK L1 v5.0.0 (Settlement Layer)                    │
│                   Rust · PoH + Sealevel · ReDB · SVM                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  GATEKEEPER (USDT → $BB) ─────────► protocol/blockchain.rs                 │
│                                      └── Tier1Gateway struct                │
│                                      └── deposit / redeem / solvency        │
│                                                                             │
│  WALLET (SSS 2-of-3) ────────────► src/wallet_unified/                     │
│                                      └── handlers.rs (create, sign, share)  │
│                                      └── security.rs (Argon2, AES-256-GCM) │
│                                      └── migration.rs (v1→v2 hot upgrade)  │
│                                      └── opaque_impl.rs (OPAQUE PWA)       │
│                                                                             │
│  SVM (Solana Virtual Machine) ───► src/svm/                                │
│                                      └── accounts_db.rs (DashMap + ReDB)    │
│                                      └── runtime.rs (BlackBookSVM engine)   │
│                                      └── spl_token.rs (USDC SPL mint)      │
│                                      └── types.rs (StoredAccount, errors)   │
│                                      └── tx_adapter.rs (legacy→SVM bridge) │
│                                                                             │
│  USDC SPL TOKEN ─────────────────► src/svm/spl_token.rs                    │
│                                      └── MintLayout (82-byte, Solana-compat)│
│                                      └── TokenAccountLayout (165-byte)      │
│                                      └── SplTokenEngine (bootstrap/mint/    │
│                                          transfer/balance/supply)           │
│                                      └── Auto-bootstraps at startup         │
│                                                                             │
│  JSON-RPC (port 8899) ───────────► src/solana_rpc/mod.rs                   │
│                                      └── getAccountInfo, getBalance         │
│                                      └── sendTransaction                    │
│                                      └── getTokenAccountsByOwner (USDC!)    │
│                                      └── getTokenSupply                     │
│                                      └── getTokenAccountBalance             │
│                                                                             │
│  HTTP API (port 8080) ───────────► src/main.rs                             │
│                                      └── /health, /balance, /transfer       │
│                                      └── /admin/mint, /admin/burn           │
│                                      └── /admin/usdc/mint (USDC minting)    │
│                                      └── /usdc/transfer, /usdc/balance      │
│                                      └── /usdc/supply, /usdc/accounts       │
│                                      └── /wallet/create, /wallet/sign       │
│                                                                             │
│  PROOF OF RESERVES ──────────────► src/proof_of_reserves.rs                │
│                                      └── Merkle tree snapshots              │
│                                      └── BB + USDC reserve tracking         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Build & Run

```bash
# SVM is always-on — no feature flags needed
cargo build          # compiles everything including SVM + SPL Token + RPC
cargo run            # starts server on ports 8080 (HTTP) + 8899 (JSON-RPC)
```

---

## Directory Structure & Responsibilities

### `/src/svm/` — Solana Virtual Machine (Always-On)

| File | Responsibility |
|------|----------------|
| mod.rs | Module root, re-exports all SVM types |
| types.rs | `StoredAccount`, `SvmError`, `LAMPORTS_PER_BB` (1e9), constants |
| accounts_db.rs | `SvmAccountsDB` — DashMap hot-state + ReDB ACID persistence |
| runtime.rs | `BlackBookSVM` — execution engine, blockhash queue, transfer execution |
| spl_token.rs | **USDC SPL Token** — `SplTokenEngine`, mint/transfer/balance ops, ATA derivation |
| tx_adapter.rs | Legacy `TxData` → SVM `TransferRequest` routing |

**Key Constants:**
- `LAMPORTS_PER_BB = 1_000_000_000` (9 decimals)
- `USDC_DECIMALS = 6` / `USDC_UNIT = 1_000_000`
- `SPL_TOKEN_PROGRAM_ID` = `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
- USDC Mint Authority = Dealer v2 wallet (`3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp`)

### `/src/wallet_unified/` — SSS Wallet System (Shamir 2-of-3)

| File | Responsibility |
|------|----------------|
| handlers.rs | Wallet create/sign/share_b API handlers, `Sharks(2u8)` SSS |
| security.rs | Argon2id password hashing, AES-256-GCM share encryption |
| migration.rs | Hot upgrade engine: FROST v1 → Shamir v2 balance migration |
| opaque_impl.rs | OPAQUE password-authenticated key exchange |
| mod.rs | Module exports |

**Wallet Creation Flow:**
```
BIP-39 mnemonic → 32-byte seed → Ed25519 keypair → Shamir 2-of-3 split
  Share A → encrypted (Argon2id + AES-256-GCM) → returned to client
  Share B → encrypted (server master key) → stored in ReDB + Supabase
  Share C → hex plaintext → offline cold storage backup
```

### `/src/solana_rpc/` — Solana-Compatible JSON-RPC

| File | Responsibility |
|------|----------------|
| mod.rs | Full JSON-RPC 2.0 server (jsonrpsee) on port 8899 |

**Implemented RPC Methods:**
- `getAccountInfo`, `getBalance`, `getMultipleAccounts`
- `getLatestBlockhash`, `sendTransaction`, `getTransaction`
- `getSignaturesForAddress`, `getSignatureStatuses`
- `getTokenAccountsByOwner` (returns real USDC ATAs!)
- `getTokenSupply`, `getTokenAccountBalance`
- `getFeeForMessage`, `isBlockhashValid`, `getSupply`

### `/protocol/` — Core Blockchain Logic

| File | Responsibility |
|------|----------------|
| blockchain.rs | L1State, Tier1Gateway, TxData enum, transaction processing |
| mod.rs | Public exports |
| helpers.rs | Utility functions |

### `/runtime/` — PoH & Consensus Engine

| File | Responsibility |
|------|----------------|
| core.rs | `ParallelScheduler` — parallel tx execution via SVM |
| consensus.rs | Validator consensus logic |
| poh_service.rs | Proof of History tick generation |

### `/src/` — Application Layer

| File | Responsibility |
|------|----------------|
| main.rs | **Server entry point** — Axum router, all HTTP handlers, USDC bootstrap, RPC server start |
| lib.rs | Library exports (all modules) |
| poh_blockchain.rs | `BlockProducer` — PoH-integrated block execution, SVM transfer routing |
| proof_of_reserves.rs | Merkle tree PoR with BB + USDC reserve tracking |
| storage/mod.rs | `ConcurrentBlockchain` — ReDB persistence, `svm_accounts: Arc<SvmAccountsDB>` |
| wallet_page.rs | Embedded HTML wallet served at `GET /wallet` |

### `/sdk/` — Client SDK

| File | Responsibility |
|------|----------------|
| blackbook_sdk.js | Production JavaScript SDK for wallet operations |

---

## Production Wallets (v2 — Shamir SSS)

| Name | Address | BB Balance | Password |
|------|---------|-----------|----------|
| Max | `GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV` | 10,000 BB | `BlackBook2026!` |
| Alice | `EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk` | 1,325 BB | `AlicePass2026!` |
| Bob | `mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd` | 1,650 BB | `BobPass2026!` |
| Apollo | `EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb` | 775 BB | `ApolloPass2026!` |
| Dealer | `3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp` | 98,750 BB | `DealerPass2026!` |

Wallet JSON files: `real_wallets/*_v2_wallet.json`

---

## HTTP API Endpoints (port 8080)

### Public
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check + network stats |
| GET | `/balance/{address}` | Balance lookup |
| GET | `/ledger` | Transaction history |
| POST | `/transfer/simple` | Broadcast signed transaction |

### Wallet (SSS 2-of-3)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/wallet/create` | Create wallet (triple-write: ReDB + Supabase + client) |
| POST | `/wallet/sign` | Sign transaction (reconstruct from 2 shares) |
| POST | `/wallet/share_b` | Get server shard from ReDB |

### USDC SPL Token
| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/usdc/mint` | Mint USDC to a wallet's ATA |
| POST | `/usdc/transfer` | Transfer USDC between wallets |
| GET | `/usdc/balance/{address}` | USDC balance for a wallet |
| GET | `/usdc/supply` | Total USDC supply on chain |
| GET | `/usdc/accounts/{address}` | All token accounts for wallet |

### Admin (Dealer)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/mint` | Mint $BB tokens |
| POST | `/admin/burn` | Burn $BB tokens |
| POST | `/admin/dealer/settle` | Batch L2 settlement |
| GET | `/admin/accounts` | All account balances |

### Engine
| Method | Path | Description |
|--------|------|-------------|
| GET | `/poh/status` | PoH clock status |
| GET | `/poh/block/latest` | Latest block |
| POST | `/sealevel/submit` | Gulf Stream parallel execution |

---

## Transfer Flow (SSS-signed)

```
Client: POST /wallet/sign
  { wallet_id, password, to, amount }
    │
    ▼
handlers.rs: reconstruct from Share A (client) + Share B (server, ReDB)
    │  Argon2id verify → AES-256-GCM decrypt → Sharks(2).recover()
    ▼
Ed25519 keypair derived from 32-byte seed
    │
    ▼
Transaction signed → broadcast to BlockProducer
    │
    ▼
poh_blockchain.rs: execute_transfer_via_svm()
    │  legacy_addr_to_pubkey() → SVM system_transfer()
    ▼
accounts_db.rs: debit sender, credit recipient (DashMap → flush to ReDB)
    │
    ▼
✅ Signature verified, balances updated, block committed
```

---

## Solvency Invariants

```rust
// L1 Core (protocol/blockchain.rs)
tier1.vault_usdt_balance * 10 == tier1.total_bb_minted
tier1.total_bb_minted == bb_in_l1_wallets + tier1.bb_locked_on_l2

// Proof of Reserves (proof_of_reserves.rs)
// Merkle tree snapshot — includes BB balances + USDC SPL supply
PoRSnapshot {
    total_reserves: u64,     // sum of all BB balances
    usdc_spl_supply: u64,    // total USDC minted on chain
    merkle_root: String,     // SHA-256 Merkle root
}
```

---

## USDC SPL Token System

```
USDC Mint Seed:      "BlackBook_USDC_Mint_v1" (deterministic)
USDC Decimals:       6 (1 USDC = 1,000,000 units)
Mint Authority:      Dealer v2 (3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp)
Token Program ID:    TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
ATA Program ID:      ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL

Bootstrap:           Automatic at server startup (idempotent)
Mint Layout:         82 bytes (binary-compatible with Solana SPL Token)
Token Account:       165 bytes (binary-compatible with Solana SPL Token)
```

---

## Node Configuration

```
Name:       BlackBook L1 — Digital Central Bank
Version:    5.0.0 (Mainnet)
Genesis:    BUWkCKtL8JdbhfNsJDERS7vrL6c6H8TPWBg8d3SAuJXR
HTTP API:   0.0.0.0:8080 (axum)
JSON-RPC:   0.0.0.0:8899 (jsonrpsee, Solana-compatible)
gRPC:       0.0.0.0:50051
Slot Tick:  600ms
DB:         ReDB (blockchain.redb)
Build:      cargo build / cargo run (no feature flags)
```

---

## Session History (Feb 21, 2026)

1. FROST → Shamir SSS migration (handlers.rs rewritten)
2. 5 production wallets created (Max, Alice, Bob, Apollo, Dealer)
3. SSS transfers tested and verified (Max→Alice, Alice→Bob)
4. Hot upgrade migration system built (migration.rs)
5. USDC SPL Token engine implemented (spl_token.rs — 620 lines)
6. USDC HTTP endpoints wired (mint/transfer/balance/supply/accounts)
7. getTokenAccountsByOwner RPC returns real USDC data
8. getTokenSupply + getTokenAccountBalance RPC methods added
9. Proof of Reserves extended for USDC tracking
10. SVM feature flag removed — SVM is always-on

---

*Last Updated: February 21, 2026*
