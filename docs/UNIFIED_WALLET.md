# UNIFIED_WALLET.md — BlackBook Wallet Architecture

> How the BlackBook unified wallet works, why the architecture was redesigned,  
> and how it serves both human users and AI agents transacting on the PoH chain.  
> Last updated: 2026-02-27

---

## 1. The Problem With the Old Design

The original wallet system mixed two radically different concerns inside the L1 node:

| Old Responsibility | Why It Was Wrong |
|--------------------|-----------------|
| L1 validates Supabase JWT on every request | JWT expiry = a valid blockchain account can't transact. A cloud outage takes down the chain. |
| L1 calls Supabase REST API to store Shard A | A blockchain node should never make outbound HTTP calls at transaction time. That adds 50–200 ms of latency per wall creation. |
| L1 calls HashiCorp Vault to store Shard C | Vault requires separate infrastructure, credentials, and network access. A node restart or Vault seal = loss of Shard C. |
| L1 maintains a parallel `f64` balance cache | Two sources of truth = drift. Which number is real? Reconciliation loops add CPU overhead and introduce race conditions. |
| `/wallet` dashboard route on the L1 server | The L1 is a consensus engine, not a UI server. Mixing them makes both worse. |

The core issue: **the L1 was acting as a Web2 backend with a blockchain bolted on**, rather than being a pure blockchain that the Web2 frontend optionally reads from.

---

## 2. The New Design — Pure SVM, Zero Cloud Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                   CLIENT / FRONTEND                     │
│                                                         │
│  Stores Shard A  ──→  Local device / secure enclave     │
│  Stores Shard C  ──→  User email / cold storage / IPFS  │
│  Reads balance   ──→  HTTP GET /balance/{pubkey}        │
│  Submits tx      ──→  HTTP POST /transfer/simple        │
│  Receives funds  ──→  WebSocket accountSubscribe (soon) │
└────────────────────────┬────────────────────────────────┘
                         │  Cryptographic proof only
                         │  (Ed25519 signature, no JWT)
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  BlackBook L1 Node                      │
│                                                         │
│  Verifies Ed25519 signature                             │
│  Executes transaction in BlackBookSVM                   │
│  Writes account delta to SvmAccountsDB (DashMap+ReDB)   │
│  Records tx hash in PoH block                           │
│  Stores Shard B  ──→  ReDB (on-chain, durable)          │
│                                                         │
│  NO Supabase. NO Vault. NO JWT. NO outbound HTTP.       │
└─────────────────────────────────────────────────────────┘
```

**The L1 now has one job:** verify signatures, execute SVM state transitions, and persist them atomically to the PoH ledger. Everything else is the frontend's responsibility.

---

## 3. Shamir Secret Sharing — How Wallet Recovery Still Works

The wallet uses a **2-of-3 Shamir Secret Sharing** scheme. The secret is the BIP-39 mnemonic seed phrase that derives the Ed25519 keypair. Any 2 of the 3 shards reconstruct it; no single shard alone reveals the seed.

```
Mnemonic Seed (256 bits)
        │
        ▼
  Shamir Split (2-of-3)
  ┌─────┴──────┬──────────────┐
  │            │              │
Shard A     Shard B        Shard C
(User)      (Server)       (Cold)
  │            │              │
  ▼            ▼              ▼
Frontend     ReDB on        User's email /
device /     the L1         printed backup /
browser      node           IPFS / trusted friend
localStorage
```

### Recovery Scenarios

| Scenario | Shards Available | How to Recover |
|----------|-----------------|----------------|
| Normal login | A (device) + B (server) | 2-of-3 met. Reconstruct seed in-browser, sign transactions client-side. |
| Lost device | C (cold) + B (server) | User provides Shard C. Frontend fetches Shard B from L1 `/shard/{pubkey}`. 2-of-3 met. |
| Server outage | A (device) + C (cold) | User combines their two off-chain shards locally. No L1 needed to recover. |
| All three lost | — | Cannot recover. This is correct: if you lose all backups of a self-custodial wallet, the funds are gone. |

### What the L1 Returns at Wallet Creation

```json
{
  "public_key": "DJLoGms6Uo533XcZayLEge9rMSbT6N8S2AhjNaCnvgHY",
  "shard_a": "<hex>",
  "shard_a_encrypted": "<aes-256-gcm encrypted with user password>",
  "shard_c": "<hex>",
  "shard_c_encrypted": "<aes-256-gcm encrypted with recovery passphrase>",
  "shard_b_stored": true,
  "mnemonic": "word1 word2 ... word24"
}
```

The L1 returns Shards A and C to the frontend **once, at creation time**, and immediately discards them from memory. Only Shard B is retained on-chain. The frontend is responsible for persisting A and C.

---

## 4. Why This Architecture Is Optimal for AI Agents

AI agents operating on a microtransaction network have fundamentally different constraints than human users:

### Agents Authenticate by Signature, Not Password

A human user logs in with email/password → JWT → session cookie.  
An AI agent authenticates by signing a transaction payload with its Ed25519 private key.

The L1 never needs to know anything about the agent's identity beyond:  
**"Does the signature over this transaction match the public key of the sending account?"**

This is a single `verify_signature()` call — sub-microsecond. No database lookup, no network call, no token expiry.

### Agents Need Push, Not Poll

```
Old way (REST polling):
  Agent → GET /balance (every 100ms) → wait → check → wait → ...
  Latency to detect payment: 0ms to 100ms average 50ms

New way (WebSocket push — coming in v2):
  Agent → WS accountSubscribe(pubkey)
  L1 → pushes delta the nanosecond SvmAccountsDB writes
  Latency to detect payment: <1ms
```

For an agent routing 10,000 microtransactions per second across a payment graph, the difference between 50 ms reaction time and <1 ms reaction time is everything.

### Agents Pre-Calculate Payment Paths

When an AI agent decides to pay another agent, it must know **exactly** what the transaction will cost before sending it. Dynamic gas auctions (EVM style) make this impossible — the fee you calculated when you built the transaction might be wrong by the time it lands.

BlackBook's deterministic fee model (flat `0.0001 BB` per transaction, encoded in genesis) means:

```
cost_of_10_hops = 10 * 0.0001 BB = 0.001 BB
```

An agent can calculate this once, cache it forever, and never worry about fee spikes.

### Agents Don't Have Browsers

Agents don't have web sessions, they can't complete OAuth flows, and they don't store cookies. By removing JWT validation from the L1, an agent can call any endpoint directly with nothing but:

1. Its Ed25519 keypair (the wallet)
2. The target public key
3. The amount

That's the entire interface. Three fields.

---

## 5. Human User Flow (SSS Wallet)

Human users interact through the frontend application (web/mobile), which handles Shard A/C storage and communicates with the L1 on their behalf.

### Create Wallet

```
1. Frontend calls POST /wallet/create
2. L1 generates:
   - BIP-39 mnemonic
   - Ed25519 keypair from mnemonic
   - Shamir 2-of-3 split
   - Encrypts Shard A with user's password (AES-256-GCM)
   - Encrypts Shard C with recovery passphrase
   - Stores Shard B in ReDB
3. L1 returns { public_key, shard_a_encrypted, shard_c_encrypted, mnemonic }
4. Frontend stores shard_a_encrypted in localStorage / Supabase / device keychain
5. Frontend displays shard_c_encrypted to user for cold backup
6. Frontend shows mnemonic once, user writes it down
```

### Send Payment (Human)

```
1. User opens frontend, enters recipient address + amount
2. Frontend reconstructs keypair (Shard A from device + Shard B from L1)
3. Frontend signs transaction client-side (never sends private key to L1)
4. Frontend calls POST /transfer/simple with { from, to, amount, signature }
5. L1 verifies signature, executes SVM transfer, records in PoH block
6. Frontend polls /balance or (soon) receives WebSocket push
```

### Send Payment (AI Agent)

```
1. Agent has keypair in memory (loaded from Shard A at boot)
2. Agent builds transaction payload: { from, to, amount, nonce }
3. Agent signs with Ed25519 private key
4. Agent calls POST /transfer/simple
5. L1 verifies, executes, records
6. Agent receives WebSocket push confirming settlement (sub-millisecond)
```

The flow is identical. The difference is the agent does it 10,000 times per second, autonomously, without a human in the loop.

---

## 6. Security Model

| Threat | Protection |
|--------|-----------|
| Stolen Shard A (device compromised) | Attacker has 1-of-3. Cannot reconstruct seed. Cannot transact (no private key). |
| Stolen Shard B (L1 database breach) | Attacker has 1-of-3. Cannot reconstruct seed. |
| Man-in-the-middle on L1 API | All transactions are Ed25519-signed client-side. The L1 only receives the signature, never the private key. A MITM can replay or drop transactions, but cannot forge them. |
| L1 goes offline | Funds are safe. The seed is derived from the mnemonic which the user holds. Come back online, funds are there. |
| Frontend goes offline | Agent uses keypair directly. No frontend dependency for programmatic use. |
| Supabase goes offline | **No impact.** Supabase is no longer in the L1's critical path. |
| Vault goes offline | **No impact.** Vault has been removed from the system entirely. |

---

## 7. Files Changed in This Refactor

| File | Action | Reason |
|------|--------|--------|
| `src/supabase.rs` | Deleted | L1 should not make outbound HTTP calls to a cloud database |
| `src/vault_manager.rs` | Deleted | Vault adds operational complexity with zero blockchain benefit |
| `src/wallet_page.rs` | Deleted | L1 is not a UI server |
| `src/wallet_unified/handlers.rs` | Refactored | Removed JWT auth, SupabaseManager, VaultManager. `create_hybrid_wallet` now returns Shards A+C to client directly |
| `src/solana_rpc/mod.rs` | Refactored | `blackbook_getProfile` now derives account state purely from `SvmAccountsDB` lamport balance |
| `src/main.rs` | Refactored | Removed 45-line legacy→SVM sync bridge, removed `/wallet` route, removed AppState cloud fields |
| `Cargo.toml` | Pruned | Removed `vaultrs`, `reqwest`, `supabase-jwt`, `jsonwebtoken`, `frost-ed25519` |

---

## 8. What the Frontend Must Do (New Responsibilities)

Since the L1 no longer handles cloud persistence, the frontend application must:

1. **Store `shard_a_encrypted`** — in Supabase, device keychain, or localStorage with user password protection.
2. **Store `shard_c_encrypted`** — presented to user for cold backup (email, print, IPFS).
3. **Fetch Shard B for recovery** — `GET /shard/{public_key}` when user needs to reconstruct from cold backup.
4. **Perform keypair reconstruction client-side** — combine Shard A + B in-browser using the SSS library; never send the reconstructed seed to the server.
5. **Sign transactions client-side** — use `@blackbook/sdk` `signTransaction()` before posting to the L1.
6. **Handle Supabase profile storage** — user display names, avatars, social metadata are a frontend/Supabase concern, not a blockchain concern.

---

*This document reflects the state of the codebase as of 2026-02-27 after the Supabase/Vault decoupling refactor.*
