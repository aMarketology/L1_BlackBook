# BlackBook L1 â€” HTTP Endpoint Guide

> **Base URL:** `https://blackbook.id`  
> **Engine:** Solana-style PoH + Sealevel parallel execution  
> **Auth:** Ed25519 signatures + SSS 2-of-3 Shamir wallets  
> **Storage:** ReDB (ACID, MVCC, zero-copy reads)

---

blackbook.id					BlackBook L1: Blockchain HTTP API Reference

	/health		GET	Health check, node status	BlackBook L1 â€” Node Health & Status Endpoint
		â†’ Send: nothing (no body)
		â† 200:  { status, version, network, blockchain: { total_supply, account_count, block_count, svm_accounts }, poh_clock, consensus, block_production, infrastructure }

	/stats		GET	Pipeline + execution stats	BlackBook L1 â€” Blockchain Statistics Endpoint
		â†’ Send: nothing (no body)
		â† 200:  { blockchain: { total_accounts, block_count, total_supply, cache_hit_rate }, pipeline, gulf_stream, parallel_execution }

	/balance/:address		GET	$BB balance lookup	Check $BB Balance by Address | BlackBook L1
		â†’ Send: :address in URL path (base58 public key)
		â† 200:  { address, name, balance, unit: "BB" }

	/ledger		GET	Paginated transaction ledger	Transaction Ledger & Audit Log | BlackBook L1
		â†’ Send: ?page=1&limit=50 (query params, both optional)
		â† 200:  text/plain â€” ASCII table of all transactions

	/transfer/simple		POST	Ed25519 signed transfer	Signed Transfer â€” Send $BB Tokens | BlackBook L1
		â†’ Send: { public_key: hex64, wallet_address: base58, payload: "{\"to\":\"...\",\"amount\":50.0}", timestamp: u64, nonce: string, chain_id: u8, signature: hex128 }
		â† 200:  { success, from, to, amount, from_balance, to_balance }

	/faucet		POST	Public testnet faucet	Faucet â€” Free Test Tokens | BlackBook L1
		â†’ Send: { to: base58, amount: f64 }
		â† 200:  { success, minted, to, new_balance, epoch, remaining_this_epoch }
		â† 429:  epoch limit reached

	/poh
		/status	GET	PoH clock state	Proof of History Status | BlackBook L1
			â†’ Send: nothing
			â† 200:  { current_slot, num_hashes, current_hash, is_running }

		/block/latest	GET	Latest block	Get Latest Block | BlackBook L1
			â†’ Send: nothing
			â† 200:  { success, block: { slot, timestamp, hash, previous_hash, tx_count, leader, epoch } }

		/block/:slot	GET	Block by slot number	Get Block by Slot | BlackBook L1
			â†’ Send: :slot in URL path (u64)
			â† 200:  { success, block: { slot, timestamp, hash, previous_hash, poh_hash, poh_sequence, state_root, tx_count, transactions[], leader, epoch, confirmations } }

		/tx/:tx_id/status	GET	Transaction status	Transaction Status Lookup | BlackBook L1
			â†’ Send: :tx_id in URL path (string)
			â† 200:  { tx_id, status, is_finalized }

	/consensus
		/tower	GET	Tower BFT vote state	Tower BFT Consensus State | BlackBook L1
			â†’ Send: nothing
			â† 200:  { validator_count, total_stake, global_root, confirmed_slots, active_forks, supermajority_threshold, max_tower_depth, current_slot, best_fork }

	/turbine
		/status	GET	Shred propagation stats	Turbine Shred Propagation | BlackBook L1
			â†’ Send: nothing
			â† 200:  { current_slot, latest_shredded_slot, data_shreds, fec_shreds, block_bytes, validator_count, propagation_max_hops, turbine_fanout }

	/sealevel
		/submit	POST	Gulf Stream parallel submit	Sealevel â€” Submit Transaction | BlackBook L1
			â†’ Send: { from: base58, to: base58, amount: f64, priority?: u64 }
			â† 200:  { success, tx_id, status: "pending" }

	/credit
		/open	POST	Lock tokens for L2 session	Open L2 Credit Session | BlackBook L1
			â†’ Send: { wallet: base58, amount: f64, session_id?: string }
			â† 200:  { success, session_id, locked_amount }

		/settle	POST	Settle L2 session Â± PnL	Settle L2 Credit Session | BlackBook L1
			â†’ Send: { session_id: string, net_pnl: f64 }
			â† 200:  { success, session_id, net_pnl, returned, new_balance }

	/wallet
		/create	POST	Create SSS 2-of-3 wallet	Create Wallet â€” SSS + BIP-39 | BlackBook L1
			â†’ Send: { username: string, password?: string, pin?: string, daily_limit?: u64 }
			â† 200:  { wallet_id, mnemonic, share_a, share_a_is_encrypted, share_c, public_key, address, session_token }

		/login	POST	Reconstruct seed, start session	Wallet Login â€” Session Auth | BlackBook L1
			â†’ Send: { wallet_id: string, shard_1: hex|encrypted, shard_2: hex|encrypted, password?: string, shard_2_is_server_encrypted?: bool }
			â† 200:  { success, wallet_id, session_token }

		/logout	POST	Revoke session, wipe seed	Wallet Logout â€” Revoke Session | BlackBook L1
			â†’ Send: { session_token?: string, wallet_id?: string } (at least one required)
			â† 200:  { success: true }

		/secure/shard-b	POST	Retrieve server shard	Retrieve Shard B | BlackBook L1
			â†’ Send: { wallet_id: string, pin?: string }
			â† 200:  { shard_b: hex, status: "Released" }

		/verify-sss	POST	Verify 2-of-3 reconstruction	Verify SSS Shares | BlackBook L1
			â†’ Send: { wallet_id: string, shard_1: hex, shard_2: hex, password?: string, shard_2_is_server_encrypted?: bool }
			â† 200:  { success, wallet_id, derived_address, matches: bool, message }

	/transfer		POST	SSS shard-authenticated transfer	Transfer with SSS Shares | BlackBook L1
		â†’ Send: { from_wallet_id: string, to_address: base58, amount: f64, share_a: hex|encrypted, password?: string }
		â† 200:  { success, signature, from, to, amount, from_balance, to_balance, session_token }

	/transfer/session		POST	Session-authenticated transfer	Session Transfer â€” Fast Path | BlackBook L1
		â†’ Send: { from_wallet_id: string, to_address: base58, amount: f64, session_token: uuid }
		â† 200:  { success, signature, from, to, amount, from_balance, to_balance, session_token }

	/admin
		/mint	POST	Mint $BB (Dealer)	Admin Mint $BB Tokens | BlackBook L1
			â†’ Send: { to: base58, amount: f64, dealer_signature?: hex, l2_receipt_id?: string }
			â† 200:  { success, minted, to, new_balance, l2_receipt_id }

		/burn	POST	Burn $BB (Dealer)	Admin Burn $BB Tokens | BlackBook L1
			â†’ Send: { from: base58, amount: f64, dealer_signature?: hex, l2_receipt_id?: string }
			â† 200:  { success, burned, from, new_balance, l2_receipt_id }

		/dealer/settle	POST	Batch L2 settlement	Dealer Batch Settlement | BlackBook L1
			â†’ Send: { payouts: [{ address: base58, amount: f64 }], batch_receipt_id: string }
			â† 200:  { success, batch_receipt_id, total_paid, payout_count, results[] }

		/wallet/migrate	POST	Migrate wallet balances	Admin Wallet Migration | BlackBook L1
			â†’ Send: { mappings: [{ name, old_address, new_address }], drain_old?: bool (default true), migrate_shares?: bool }
			â† 200:  MigrationReport { success_count, failed_count, results[] }

		/accounts	GET	All account balances	Admin â€” All Accounts | BlackBook L1
			â†’ Send: nothing
			â† 200:  { accounts: [{ name, address, balance, version, role, active }], total_supply, dealer_address, wallet_version }

		/security/stats	GET	Throttle + circuit breaker	Admin â€” Security Stats | BlackBook L1
			â†’ Send: nothing
			â† 200:  { throttler, circuit_breaker, fee_market }

		/usdc/mint	POST	Mint USDC SPL tokens	Admin Mint USDC | BlackBook L1
			â†’ Send: { to: base58, amount: f64 }
			â† 200:  { success, minted_usdc, raw_amount, to, ata, mint, new_total_supply }

	/usdc
		/transfer	POST	Transfer USDC between wallets	USDC Transfer | BlackBook L1
			â†’ Send: { from: base58, to: base58, amount: f64 }
			â† 200:  { success, amount_usdc, raw_amount, from, to, from_ata, to_ata, from_balance, to_balance }

		/balance/:address	GET	USDC balance for wallet	USDC Balance Lookup | BlackBook L1
			â†’ Send: :address in URL path (base58)
			â† 200:  { address, usdc_balance, raw_balance, decimals: 6, mint }

		/supply	GET	Total USDC supply	USDC Total Supply | BlackBook L1
			â†’ Send: nothing
			â† 200:  { mint, total_supply, raw_supply, decimals: 6 }

		/accounts/:address	GET	USDC token accounts	USDC Token Accounts | BlackBook L1
			â†’ Send: :address in URL path (base58)
			â† 200:  { owner, token_accounts: [{ address, mint, owner, balance_usdc, raw_balance, decimals }] }

	/solana-rpc (port 8899)		All POST JSON-RPC 2.0 â†’ { "jsonrpc":"2.0", "id":1, "method":"...", "params":[...] }

		getHealth	POST JSON-RPC	Health probe	Solana RPC â€” getHealth | BlackBook L1
			â†’ Send: { method: "getHealth", params: [] }
			â† 200:  "ok"

		getBalance	POST JSON-RPC	Lamport balance	Solana RPC â€” getBalance | BlackBook L1
			â†’ Send: { method: "getBalance", params: ["<pubkey>"] }
			â† 200:  { value: u64 (lamports) }

		getAccountInfo	POST JSON-RPC	Full account state	Solana RPC â€” getAccountInfo | BlackBook L1
			â†’ Send: { method: "getAccountInfo", params: ["<pubkey>", { encoding?: "base64" }] }
			â† 200:  { value: { lamports, data, owner, executable, rentEpoch } }

		sendTransaction	POST JSON-RPC	Submit signed tx	Solana RPC â€” sendTransaction | BlackBook L1
			â†’ Send: { method: "sendTransaction", params: ["<base64_tx>", { encoding?: "base64" }] }
			â† 200:  "<signature_base58>"

		getBlock	POST JSON-RPC	Block by slot	Solana RPC â€” getBlock | BlackBook L1
			â†’ Send: { method: "getBlock", params: [<slot_u64>, { encoding?: "json", transactionDetails?: "full" }] }
			â† 200:  { blockHeight, blockTime, blockhash, transactions[] }

		blackbook_getProfile	POST JSON-RPC	Wallet profile	BB Extension â€” getProfile | BlackBook L1
			â†’ Send: { method: "blackbook_getProfile", params: ["<pubkey>"] }
			â† 200:  { registered, walletAddress, balance: { lamports, bb }, network, slot }

	/grpc (port 50051)		Protocol: blackbook.L1Settlement â€” all require Ed25519 sig + timestamp replay protection

		GetBalance	gRPC unary	L1 balance (available + locked)	gRPC â€” GetBalance | BlackBook L1
			â†’ Send: BalanceRequest { address, signature, timestamp }
			â† OK:   BalanceResponse { success, address, available, locked, total }

		SoftLock	gRPC unary	Lock funds for L2	gRPC â€” SoftLock | BlackBook L1
			â†’ Send: SoftLockRequest { address, amount, lock_duration_secs, signature, timestamp }
			â† OK:   SoftLockResponse { success, lock_id, locked_amount, new_available, new_locked, expires_at }

		SettleBet	gRPC unary	Settle single bet	gRPC â€” SettleBet | BlackBook L1
			â†’ Send: SettleBetRequest { user_address, dealer_address, amount, direction, bet_id, signature, timestamp }
			â† OK:   SettleBetResponse { success, tx_hash, user_balance, dealer_balance, user_pnl }

		BatchSettle	gRPC unary	Settle multiple bets	gRPC â€” BatchSettle | BlackBook L1
			â†’ Send: BatchSettleRequest { settlements: [SettleBetRequest], batch_id, signature, timestamp }
			â† OK:   BatchSettleResponse { success, results[], total_settled }

		SubscribeBlocks	gRPC stream	Live block feed	gRPC â€” SubscribeBlocks | BlackBook L1
			â†’ Send: SubscribeRequest { reader_id, start_slot }
			â† Stream: BlockData { slot, hash, previous_hash, transactions[], timestamp, leader, epoch }

---

## Table of Contents

1. [Public Endpoints](#1-public-endpoints)
2. [Transfer Endpoints](#2-transfer-endpoints)
3. [Proof of History & Consensus](#3-proof-of-history--consensus)
4. [Sealevel & Gulf Stream](#4-sealevel--gulf-stream)
5. [Credit / L2 Bridge Sessions](#5-credit--l2-bridge-sessions)
6. [Unified Wallet (SSS 2-of-3)](#6-unified-wallet-sss-2-of-3)
7. [Admin Endpoints](#7-admin-endpoints)
8. [USDC SPL Token](#8-usdc-spl-token)
9. [Solana JSON-RPC 2.0 (Port 8899)](#9-solana-json-rpc-20-port-8899)
10. [gRPC Settlement Service (Port 50051)](#10-grpc-settlement-service-port-50051)
11. [gRPC Validator Relay (Port 50051)](#11-grpc-validator-relay-port-50051)

---

## 1. Public Endpoints

These require no authentication. Use them to check node health, query balances, and browse the ledger.

---

### `GET /health`

**Node Health & Status Endpoint | BlackBook L1**

Returns full node status including blockchain state, PoH clock, consensus, and infrastructure.

```bash
curl https://blackbook.id/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "5.0.0",
  "network": "blackbook-mainnet",
  "blockchain": {
    "total_supply": 1000000.0,
    "account_count": 42,
    "block_count": 98712,
    "svm_accounts": 156
  },
  "poh_clock": {
    "current_slot": 98712,
    "current_epoch": 24,
    "slot_duration_ms": 400
  },
  "consensus": {
    "tower_root": 98700,
    "confirmed_slots": 98710,
    "validator_count": 1
  },
  "block_production": {
    "latest_block_age_s": 0.4,
    "is_producing": true
  },
  "infrastructure": {
    "gulf_stream": { "pending": 0 },
    "sealevel": { "threads": 4 },
    "pipeline": { "stage": "execute" }
  }
}
```

---

### `GET /stats`

**Blockchain Statistics Endpoint | BlackBook L1**

Detailed pipeline, Gulf Stream, and parallel execution stats.

```bash
curl https://blackbook.id/stats
```

**Response:**
```json
{
  "blockchain": {
    "total_accounts": 42,
    "block_count": 98712,
    "total_supply": 1000000.0,
    "cache_hit_rate": 0.97
  },
  "pipeline": { "..." },
  "gulf_stream": { "..." },
  "parallel_execution": { "..." }
}
```

---

### `GET /balance/:address`

**Check $BB Balance by Address | BlackBook L1**

Look up the $BB token balance for any wallet address.

```bash
curl https://blackbook.id/balance/5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS
```

**Response:**
```json
{
  "address": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
  "name": "Max",
  "balance": 25000.0,
  "unit": "BB"
}
```

---

### `GET /ledger`

**Transaction Ledger & Audit Log | BlackBook L1**

Paginated ASCII-art audit trail of all on-chain transactions.

```bash
curl "https://blackbook.id/ledger?page=1&limit=50"
```

| Query Param | Type | Default | Max | Description |
|-------------|------|---------|-----|-------------|
| `page` | int | 1 | â€” | Page number |
| `limit` | int | 50 | 100 | Results per page |

**Response:** `text/plain` â€” formatted table of transactions with sender, receiver, amount, slot, and timestamp.

---

### `POST /faucet`

**Faucet â€” Free Test Tokens | BlackBook L1**

Mint free $BB tokens for testing. Rate-limited to 99,999 BB per epoch.

```bash
curl -X POST https://blackbook.id/faucet \
  -H "Content-Type: application/json" \
  -d '{"to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS", "amount": 100.0}'
```

**Request Body:**
```json
{
  "to": "string â€” recipient base58 address",
  "amount": "float â€” amount of $BB to mint"
}
```

**Response:**
```json
{
  "success": true,
  "minted": 100.0,
  "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
  "new_balance": 25100.0,
  "epoch": 24,
  "remaining_this_epoch": 99899.0
}
```

**Error:** `429 Too Many Requests` if epoch limit reached.

---

## 2. Transfer Endpoints

Three ways to move $BB tokens: signed, shard-authenticated, and session-based.

---

### `POST /transfer/simple`

**Signed Transfer â€” Send $BB Tokens | BlackBook L1**

Submit an Ed25519-signed transfer. The client signs the payload offline; the server verifies the signature and executes the transfer atomically.

```bash
curl -X POST https://blackbook.id/transfer/simple \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "a1b2c3...hex64",
    "wallet_address": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
    "payload": "{\"to\":\"3xK9...\",\"amount\":50.0}",
    "timestamp": 1740700000,
    "nonce": "abc123",
    "chain_id": 1,
    "signature": "deadbeef...hex128"
  }'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string | Hex-encoded Ed25519 public key (32 bytes) |
| `wallet_address` | string | Sender base58 address |
| `payload` | string | JSON-serialized `{ to, amount }` |
| `timestamp` | u64 | Unix timestamp (replay protection) |
| `nonce` | string | Unique nonce (replay protection) |
| `chain_id` | u8 | Network chain ID |
| `signature` | string | Hex-encoded Ed25519 signature (64 bytes) |

**Response:**
```json
{
  "success": true,
  "from": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
  "to": "3xK9vBNZfA...",
  "amount": 50.0,
  "from_balance": 24950.0,
  "to_balance": 150.0
}
```

---

### `POST /transfer`

**Transfer with SSS Shares | BlackBook L1**

Transfer using Shamir Secret Sharing shard reconstruction. Requires Share A (user-held) and the server reconstructs with Share B.

```bash
curl -X POST https://blackbook.id/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_wallet_id": "wallet_abc123",
    "to_address": "3xK9vBNZfA...",
    "amount": 50.0,
    "share_a": "encrypted_blob_or_raw_hex",
    "password": "user_password"
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from_wallet_id` | string | yes | Sender wallet ID |
| `to_address` | string | yes | Recipient base58 address |
| `amount` | float | yes | Amount of $BB |
| `share_a` | string | yes | Share A â€” encrypted blob or raw hex |
| `password` | string | if encrypted | Password to decrypt Share A |

**Response:**
```json
{
  "success": true,
  "signature": "ed25519_sig_hex",
  "from": "5FHneW46...",
  "to": "3xK9vBNZ...",
  "amount": 50.0,
  "from_balance": 24950.0,
  "to_balance": 150.0,
  "session_token": "uuid-auto-login"
}
```

---

### `POST /transfer/session`

**Session Transfer â€” Fast Path | BlackBook L1**

Transfer using an active session token. No password, no Argon2id, no shard decryption â€” the seed is already in server memory.

```bash
curl -X POST https://blackbook.id/transfer/session \
  -H "Content-Type: application/json" \
  -d '{
    "from_wallet_id": "wallet_abc123",
    "to_address": "3xK9vBNZfA...",
    "amount": 50.0,
    "session_token": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `from_wallet_id` | string | Sender wallet ID |
| `to_address` | string | Recipient base58 address |
| `amount` | float | Amount of $BB |
| `session_token` | string | Active session UUID |

**Response:** Same shape as `/transfer`.

---

## 3. Proof of History & Consensus

Query the PoH clock, blocks, transaction confirmations, Tower BFT state, and Turbine shred propagation.

---

### `GET /poh/status`

**Proof of History Status | BlackBook L1**

Current state of the PoH clock.

```bash
curl https://blackbook.id/poh/status
```

**Response:**
```json
{
  "current_slot": 98712,
  "num_hashes": 4935600,
  "current_hash": "a1b2c3d4e5f6...",
  "is_running": true
}
```

---

### `GET /poh/block/latest`

**Get Latest Block | BlackBook L1**

Retrieve the most recently produced block.

```bash
curl https://blackbook.id/poh/block/latest
```

**Response:**
```json
{
  "success": true,
  "block": {
    "slot": 98712,
    "timestamp": 1740700000,
    "hash": "abc123...",
    "previous_hash": "def456...",
    "tx_count": 14,
    "leader": "genesis_validator",
    "epoch": 24
  }
}
```

---

### `GET /poh/block/:slot`

**Get Block by Slot | BlackBook L1**

Retrieve a specific block by slot number, including full transaction list.

```bash
curl https://blackbook.id/poh/block/98712
```

**Response:**
```json
{
  "success": true,
  "block": {
    "slot": 98712,
    "timestamp": 1740700000,
    "hash": "abc123...",
    "previous_hash": "def456...",
    "poh_hash": "789abc...",
    "poh_sequence": 4935600,
    "state_root": "fedcba...",
    "tx_count": 14,
    "transactions": ["..."],
    "leader": "genesis_validator",
    "epoch": 24,
    "confirmations": 32
  }
}
```

---

### `GET /poh/tx/:tx_id/status`

**Transaction Status Lookup | BlackBook L1**

Check whether a transaction has been finalized.

```bash
curl https://blackbook.id/poh/tx/tx_abc123def/status
```

**Response:**
```json
{
  "tx_id": "tx_abc123def",
  "status": "confirmed",
  "is_finalized": true
}
```

---

### `GET /consensus/tower`

**Tower BFT Consensus State | BlackBook L1**

Full Tower BFT vote tower state â€” validators, stake, forks, supermajority.

```bash
curl https://blackbook.id/consensus/tower
```

**Response:**
```json
{
  "validator_count": 1,
  "total_stake": 1000000,
  "global_root": 98700,
  "confirmed_slots": 98710,
  "active_forks": 1,
  "supermajority_threshold": 0.667,
  "max_tower_depth": 32,
  "current_slot": 98712,
  "best_fork": { "..." }
}
```

---

### `GET /turbine/status`

**Turbine Shred Propagation | BlackBook L1**

Turbine shred propagation stats â€” data shreds, FEC recovery, fanout topology.

```bash
curl https://blackbook.id/turbine/status
```

**Response:**
```json
{
  "current_slot": 98712,
  "latest_shredded_slot": 98712,
  "data_shreds": 14,
  "fec_shreds": 4,
  "block_bytes": 8192,
  "validator_count": 1,
  "propagation_max_hops": 3,
  "turbine_fanout": 200
}
```

---

## 4. Sealevel & Gulf Stream

---

### `POST /sealevel/submit`

**Sealevel â€” Submit Transaction | BlackBook L1**

Submit a transaction to Gulf Stream for Sealevel parallel execution. Transactions are pre-forwarded to the leader before the slot begins.

```bash
curl -X POST https://blackbook.id/sealevel/submit \
  -H "Content-Type: application/json" \
  -d '{
    "from": "5FHneW46...",
    "to": "3xK9vBNZ...",
    "amount": 50.0,
    "priority": 1
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | yes | Sender base58 address |
| `to` | string | yes | Recipient base58 address |
| `amount` | float | yes | Amount of $BB |
| `priority` | u64 | no | Priority fee (higher = faster) |

**Response:**
```json
{
  "success": true,
  "tx_id": "tx_gulf_abc123",
  "status": "pending"
}
```

---

## 5. Credit / L2 Bridge Sessions

Lock tokens on L1 for off-chain L2 sessions, then settle back with profit/loss.

---

### `POST /credit/open`

**Open L2 Credit Session | BlackBook L1**

Lock $BB tokens on L1 to back an L2 session.

```bash
curl -X POST https://blackbook.id/credit/open \
  -H "Content-Type: application/json" \
  -d '{
    "wallet": "5FHneW46...",
    "amount": 500.0,
    "session_id": "optional-custom-id"
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet` | string | yes | Wallet base58 address |
| `amount` | float | yes | Amount to lock |
| `session_id` | string | no | Custom session ID (auto-generated if omitted) |

**Response:**
```json
{
  "success": true,
  "session_id": "session_abc123",
  "locked_amount": 500.0
}
```

---

### `POST /credit/settle`

**Settle L2 Credit Session | BlackBook L1**

Close an L2 session and return tokens Â± net PnL.

```bash
curl -X POST https://blackbook.id/credit/settle \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session_abc123",
    "net_pnl": 75.0
  }'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Session ID from `/credit/open` |
| `net_pnl` | float | Net profit/loss (positive = user won) |

**Response:**
```json
{
  "success": true,
  "session_id": "session_abc123",
  "net_pnl": 75.0,
  "returned": 575.0,
  "new_balance": 25575.0
}
```

---

## 6. Unified Wallet (SSS 2-of-3)

The wallet system uses Shamir Secret Sharing with a 2-of-3 threshold. Three shares are created from the BIP-39 seed:

- **Share A** â€” User-held (encrypted with password via Argon2id â†’ AES-GCM)
- **Share B** â€” Server-held (encrypted with `SERVER_MASTER_KEY`)
- **Share C** â€” Cold backup (raw hex, stored offline)

Any 2 of 3 shares reconstruct the Ed25519 signing key.

---

### `POST /wallet/create`

**Create Wallet â€” SSS + BIP-39 | BlackBook L1**

Generate a new wallet with BIP-39 mnemonic, split into SSS 2-of-3 shares.

```bash
curl -X POST https://blackbook.id/wallet/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "strong_password_here",
    "pin": "1234",
    "daily_limit": 10000
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | yes | Display name |
| `password` | string | no | Encrypts Share A |
| `pin` | string | no | Hashed for auth; encrypts Share B if present |
| `daily_limit` | u64 | no | Threshold for PIN requirement |

**Response:**
```json
{
  "wallet_id": "wallet_abc123",
  "mnemonic": "abandon ability able about above absent absorb ...",
  "share_a": "encrypted_hex_blob",
  "share_a_is_encrypted": true,
  "share_c": "raw_hex_cold_share",
  "public_key": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
  "address": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS",
  "session_token": "550e8400-e29b-41d4-a716-446655440000"
}
```

> **Critical:** Save the `mnemonic` and `share_c` offline. They are shown once and cannot be recovered.

---

### `POST /wallet/login`

**Wallet Login â€” Session Auth | BlackBook L1**

Reconstruct the Ed25519 seed from any 2 shares and create an in-memory session.

```bash
curl -X POST https://blackbook.id/wallet/login \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_id": "wallet_abc123",
    "shard_1": "share_a_encrypted_or_hex",
    "shard_2": "share_b_encrypted",
    "password": "strong_password_here",
    "shard_2_is_server_encrypted": true
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet_id` | string | yes | Target wallet ID |
| `shard_1` | string | yes | Share A (hex or password-encrypted) |
| `shard_2` | string | yes | Share B (hex or server-encrypted) |
| `password` | string | if encrypted | Password to decrypt Share A |
| `shard_2_is_server_encrypted` | bool | no | Indicates Share B needs server decryption |

**Response:**
```json
{
  "success": true,
  "wallet_id": "wallet_abc123",
  "session_token": "550e8400-e29b-41d4-a716-446655440000"
}
```

> The seed lives in server RAM only. If the server restarts, all sessions are lost (users re-login).

---

### `POST /wallet/logout`

**Wallet Logout â€” Revoke Session | BlackBook L1**

Wipe the seed from server memory and revoke the session token.

```bash
curl -X POST https://blackbook.id/wallet/logout \
  -H "Content-Type: application/json" \
  -d '{"session_token": "550e8400-e29b-41d4-a716-446655440000"}'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_token` | string | no | Session to revoke |
| `wallet_id` | string | no | Revoke all sessions for this wallet |

**Response:**
```json
{ "success": true }
```

---

### `POST /wallet/secure/shard-b`

**Retrieve Shard B | BlackBook L1**

Retrieve the server-held Share B. Requires PIN if the wallet was created with one.

```bash
curl -X POST https://blackbook.id/wallet/secure/shard-b \
  -H "Content-Type: application/json" \
  -d '{"wallet_id": "wallet_abc123", "pin": "1234"}'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet_id` | string | yes | Target wallet ID |
| `pin` | string | no | Required if wallet has a PIN |

**Response:**
```json
{
  "shard_b": "hex_encoded_share_b",
  "status": "Released"
}
```

---

### `POST /wallet/verify-sss`

**Verify SSS Shares | BlackBook L1**

Test that any 2 of 3 shares correctly reconstruct the wallet's Ed25519 key.

```bash
curl -X POST https://blackbook.id/wallet/verify-sss \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_id": "wallet_abc123",
    "shard_1": "hex_share_a",
    "shard_2": "hex_share_b",
    "password": "if_encrypted",
    "shard_2_is_server_encrypted": true
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wallet_id` | string | yes | Expected wallet ID |
| `shard_1` | string | yes | Share A (hex or encrypted) |
| `shard_2` | string | yes | Share B (hex or server-encrypted) |
| `password` | string | if encrypted | Password for Share A |
| `shard_2_is_server_encrypted` | bool | no | Share B needs server decryption |

**Response:**
```json
{
  "success": true,
  "wallet_id": "wallet_abc123",
  "derived_address": "5FHneW46...",
  "matches": true,
  "message": "SSS reconstruction verified â€” derived address matches wallet"
}
```

---

## 7. Admin Endpoints

Protected endpoints for the Dealer role. In production these require a `dealer_signature`.

---

### `POST /admin/mint`

**Admin Mint $BB Tokens | BlackBook L1**

Mint new $BB tokens into a wallet. Dealer-only in production.

```bash
curl -X POST https://blackbook.id/admin/mint \
  -H "Content-Type: application/json" \
  -d '{
    "to": "5FHneW46...",
    "amount": 10000.0,
    "dealer_signature": "hex_sig",
    "l2_receipt_id": "receipt_001"
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | yes | Recipient base58 address |
| `amount` | float | yes | Amount to mint |
| `dealer_signature` | string | no | Ed25519 dealer sig (required in production) |
| `l2_receipt_id` | string | no | L2 receipt correlation ID |

**Response:**
```json
{
  "success": true,
  "minted": 10000.0,
  "to": "5FHneW46...",
  "new_balance": 35000.0,
  "l2_receipt_id": "receipt_001"
}
```

---

### `POST /admin/burn`

**Admin Burn $BB Tokens | BlackBook L1**

Destroy $BB tokens from a wallet. Dealer-only.

```bash
curl -X POST https://blackbook.id/admin/burn \
  -H "Content-Type: application/json" \
  -d '{
    "from": "5FHneW46...",
    "amount": 5000.0,
    "dealer_signature": "hex_sig",
    "l2_receipt_id": "receipt_002"
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | yes | Wallet to burn from |
| `amount` | float | yes | Amount to burn |
| `dealer_signature` | string | no | Dealer signature |
| `l2_receipt_id` | string | no | L2 receipt correlation ID |

**Response:**
```json
{
  "success": true,
  "burned": 5000.0,
  "from": "5FHneW46...",
  "new_balance": 20000.0,
  "l2_receipt_id": "receipt_002"
}
```

---

### `POST /admin/dealer/settle`

**Dealer Batch Settlement | BlackBook L1**

Settle multiple L2 receipts in a single atomic batch.

```bash
curl -X POST https://blackbook.id/admin/dealer/settle \
  -H "Content-Type: application/json" \
  -d '{
    "payouts": [
      {"address": "5FHneW46...", "amount": 100.0},
      {"address": "3xK9vBNZ...", "amount": 250.0}
    ],
    "batch_receipt_id": "batch_001"
  }'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `payouts` | array | `[{ address: string, amount: float }]` |
| `batch_receipt_id` | string | Unique batch ID (idempotent) |

**Response:**
```json
{
  "success": true,
  "batch_receipt_id": "batch_001",
  "total_paid": 350.0,
  "payout_count": 2,
  "results": ["..."]
}
```

---

### `POST /admin/wallet/migrate`

**Admin Wallet Migration | BlackBook L1**

Migrate balances from old wallet addresses to new ones. Safe to run while the server is live (ReDB MVCC). Idempotent.

```bash
curl -X POST https://blackbook.id/admin/wallet/migrate \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": [
      {"name": "Alice", "old_address": "old_abc...", "new_address": "new_xyz..."}
    ],
    "drain_old": true,
    "migrate_shares": true
  }'
```

**Request Body:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mappings` | array | â€” | `[{ name, old_address, new_address }]` |
| `drain_old` | bool | true | Zero out old wallet after migration |
| `migrate_shares` | bool | false | Also migrate SSS shard data |

**Response:** `MigrationReport` JSON with success/failed counts.

---

### `GET /admin/accounts`

**Admin â€” All Accounts | BlackBook L1**

View every known account with balances, roles, and wallet version.

```bash
curl https://blackbook.id/admin/accounts
```

**Response:**
```json
{
  "accounts": [
    {
      "name": "Max",
      "address": "5FHneW46...",
      "balance": 25000.0,
      "version": "v2",
      "role": "admin",
      "active": true
    }
  ],
  "total_supply": 1000000.0,
  "dealer_address": "DealerAddr...",
  "wallet_version": "v2"
}
```

---

### `GET /admin/security/stats`

**Admin â€” Security Stats | BlackBook L1**

Rate limiter, circuit breaker, and fee market status.

```bash
curl https://blackbook.id/admin/security/stats
```

**Response:**
```json
{
  "throttler": { "..." },
  "circuit_breaker": { "..." },
  "fee_market": { "..." }
}
```

---

## 8. USDC SPL Token

Native SPL-compatible USDC token on BlackBook L1. Each wallet gets an Associated Token Account (ATA) automatically.

---

### `POST /admin/usdc/mint`

**Admin Mint USDC | BlackBook L1**

Mint USDC tokens to a wallet's ATA. Admin-only.

```bash
curl -X POST https://blackbook.id/admin/usdc/mint \
  -H "Content-Type: application/json" \
  -d '{"to": "5FHneW46...", "amount": 1000.0}'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `to` | string | Recipient base58 address |
| `amount` | float | USDC amount (6 decimals internally) |

**Response:**
```json
{
  "success": true,
  "minted_usdc": 1000.0,
  "raw_amount": 1000000000,
  "to": "5FHneW46...",
  "ata": "ATA_address...",
  "mint": "USDC_mint_address...",
  "new_total_supply": 50000.0
}
```

---

### `POST /usdc/transfer`

**USDC Transfer | BlackBook L1**

Transfer USDC between wallets.

```bash
curl -X POST https://blackbook.id/usdc/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from": "5FHneW46...",
    "to": "3xK9vBNZ...",
    "amount": 250.0
  }'
```

**Request Body:**

| Field | Type | Description |
|-------|------|-------------|
| `from` | string | Sender base58 address |
| `to` | string | Recipient base58 address |
| `amount` | float | USDC amount |

**Response:**
```json
{
  "success": true,
  "amount_usdc": 250.0,
  "raw_amount": 250000000,
  "from": "5FHneW46...",
  "to": "3xK9vBNZ...",
  "from_ata": "ATA_from...",
  "to_ata": "ATA_to...",
  "from_balance": 750.0,
  "to_balance": 250.0
}
```

---

### `GET /usdc/balance/:address`

**USDC Balance Lookup | BlackBook L1**

Get the USDC balance for any wallet.

```bash
curl https://blackbook.id/usdc/balance/5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS
```

**Response:**
```json
{
  "address": "5FHneW46...",
  "usdc_balance": 1000.0,
  "raw_balance": 1000000000,
  "decimals": 6,
  "mint": "USDC_mint_address..."
}
```

---

### `GET /usdc/supply`

**USDC Total Supply | BlackBook L1**

Total USDC minted on BlackBook L1.

```bash
curl https://blackbook.id/usdc/supply
```

**Response:**
```json
{
  "mint": "USDC_mint_address...",
  "total_supply": 50000.0,
  "raw_supply": 50000000000,
  "decimals": 6
}
```

---

### `GET /usdc/accounts/:address`

**USDC Token Accounts | BlackBook L1**

List all USDC token accounts owned by a wallet.

```bash
curl https://blackbook.id/usdc/accounts/5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS
```

**Response:**
```json
{
  "owner": "5FHneW46...",
  "token_accounts": [
    {
      "address": "ATA_address...",
      "mint": "USDC_mint...",
      "owner": "5FHneW46...",
      "balance_usdc": 1000.0,
      "raw_balance": 1000000000,
      "decimals": 6
    }
  ]
}
```

---

## 9. Solana JSON-RPC 2.0 (Port 8899)

Full Solana-compatible JSON-RPC on **port 8899**. Works with Phantom, OneKey, and the standard `@solana/web3.js` SDK.

All requests are `POST /` with JSON-RPC 2.0 format:

```bash
curl -X POST https://blackbook.id:8899 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"METHOD_NAME","params":[...]}'
```

---

### Read-Only Methods

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `getHealth` | none | `"ok"` | Node health probe |
| `getVersion` | none | `{ solana_core, feature_set }` | Node version (BB-5.0.0-svm) |
| `getGenesisHash` | none | base58 hash | Network identity hash |
| `getSlot` | none | `u64` | Current slot number |
| `getBlockHeight` | none | `u64` | Current block height |
| `getBalance` | `[pubkey]` | `RpcResponse<u64>` | Balance in lamports |
| `getAccountInfo` | `[pubkey, config?]` | `RpcResponse<UiAccount>` | Full account state |
| `getLatestBlockhash` | none | `RpcResponse<{ blockhash, lastValidBlockHeight }>` | Current blockhash |
| `getEpochInfo` | none | `{ epoch, slotIndex, slotsInEpoch, ... }` | Epoch statistics |
| `getMinimumBalanceForRentExemption` | `[dataLen]` | `u64` | Rent-exempt minimum |
| `getMultipleAccounts` | `[pubkeys, config?]` | `RpcResponse<Vec<UiAccount>>` | Batch account lookup |
| `getIdentity` | none | `{ identity }` | Node identity pubkey |
| `getSupply` | `[config?]` | `RpcResponse<{ total, circulating }>` | Total supply info |

---

### Write Methods

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `sendTransaction` | `[data, config?]` | base58 signature | Submit signed transaction |
| `getTransaction` | `[signature, config?]` | `RpcConfirmedTransaction` | Lookup tx by signature |
| `getSignaturesForAddress` | `[address, config?]` | `Vec<RpcSignatureInfo>` | Recent tx sigs for address |
| `getSignatureStatuses` | `[signatures, config?]` | `RpcResponse<Vec<status>>` | Batch confirmation status |
| `isBlockhashValid` | `[blockhash, config?]` | `RpcResponse<bool>` | Blockhash validity check |

---

### Token & Fee Methods (Phantom / OneKey Compatible)

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `getTokenAccountsByOwner` | `[pubkey, filter, config?]` | `RpcResponse<Vec<...>>` | SPL token accounts |
| `getTokenSupply` | `[mint, config?]` | `RpcResponse<{ amount, decimals, uiAmount }>` | Mint total supply |
| `getTokenAccountBalance` | `[account, config?]` | `RpcResponse<{ amount, decimals, uiAmount }>` | Single ATA balance |
| `getFeeForMessage` | `[message, config?]` | `RpcResponse<5000>` | Tx fee (always 5000 lamports) |
| `getRecentPrioritizationFees` | `[addresses?]` | `[]` | No priority fees |

---

### Block Query Methods

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `getBlock` | `[slot, config?]` | Block with transactions | Block by slot |
| `getBlocks` | `[startSlot, endSlot?]` | `Vec<u64>` | List confirmed slot numbers |
| `getBlockProduction` | `[config?]` | `RpcResponse<{ byIdentity, range }>` | Block production stats |

---

### BlackBook Extensions

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `blackbook_getProfile` | `[pubkey]` | `{ registered, walletAddress, balance, network, slot }` | Full wallet profile |
| `blackbook_isRegistered` | `[pubkey]` | `bool` | Non-zero balance check |

**Example â€” `blackbook_getProfile`:**

```bash
curl -X POST https://blackbook.id:8899 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "blackbook_getProfile",
    "params": ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUey6p5H7RPLiS"]
  }'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "registered": true,
    "walletAddress": "5FHneW46...",
    "balance": { "lamports": 25000000, "bb": 25.0 },
    "network": "blackbook-mainnet",
    "slot": 98712
  }
}
```

---

## 10. gRPC Settlement Service (Port 50051)

Binary protocol for high-performance L2 â†” L1 settlement. All methods require Ed25519 signature + timestamp replay protection.

**Protocol:** `blackbook.L1Settlement`

| RPC Method | Type | Description |
|------------|------|-------------|
| `GetBalance` | Unary | L1 balance â€” available + locked |
| `GetVirtualBalance` | Unary | L1 â†” L2 virtual balance |
| `SoftLock` | Unary | Lock funds for L2 bet/session |
| `ReleaseLock` | Unary | Release a soft lock |
| `SettleBet` | Unary | Settle a single bet (idempotent) |
| `BatchSettle` | Unary | Settle multiple bets atomically |
| `OpenCreditSession` | Unary | Open L2 credit session |
| `CloseCreditSession` | Unary | Close + settle credit session |
| `GetCreditStatus` | Unary | Query credit session state |
| `VerifySignature` | Unary | Verify Ed25519 + derive address |
| `Health` | Unary | Service health check |

**Key Response Shapes:**

```
BalanceResponse      â†’ { success, address, available, locked, total }
SoftLockResponse     â†’ { success, lock_id, locked_amount, new_available, expires_at }
SettleBetResponse    â†’ { success, tx_hash, user_balance, dealer_balance, user_pnl }
HealthResponse       â†’ { healthy, version, block_height, uptime_seconds, active_locks }
```

---

## 11. gRPC Validator Relay (Port 50051)

Block propagation between writer and reader nodes.

**Protocol:** `validator_relay.ValidatorRelay`

| RPC Method | Type | Description |
|------------|------|-------------|
| `SubscribeBlocks` | Server-streaming | Live block feed from writer â†’ reader |
| `CatchupBlocks` | Server-streaming | Historical block range for catch-up |
| `ForwardTransaction` | Unary | Reader forwards tx to writer for inclusion |
| `GetStatus` | Unary | Writer node status + connected readers |

**Example â€” `SubscribeBlocks`:**

```
Request:  { reader_id: "reader-01", start_slot: 98700 }
Stream:   BlockData { slot, hash, previous_hash, transactions, timestamp, leader, epoch }
```

**Example â€” `ForwardTransaction`:**

```
Request:  { reader_id: "reader-01", tx_json: "{...}" }
Response: { success: true, tx_id: "tx_abc123" }
```

---

## Quick Reference â€” Full Endpoint Map

| # | Method | Path | Auth | Category |
|---|--------|------|------|----------|
| 1 | GET | `/health` | Public | Status |
| 2 | GET | `/stats` | Public | Status |
| 3 | GET | `/balance/:address` | Public | Query |
| 4 | GET | `/ledger` | Public | Query |
| 5 | POST | `/faucet` | Public | Tokens |
| 6 | POST | `/transfer/simple` | Ed25519 Sig | Transfer |
| 7 | POST | `/transfer` | SSS Shards | Transfer |
| 8 | POST | `/transfer/session` | Session Token | Transfer |
| 9 | GET | `/poh/status` | Public | PoH |
| 10 | GET | `/poh/block/latest` | Public | PoH |
| 11 | GET | `/poh/block/:slot` | Public | PoH |
| 12 | GET | `/poh/tx/:tx_id/status` | Public | PoH |
| 13 | GET | `/consensus/tower` | Public | Consensus |
| 14 | GET | `/turbine/status` | Public | Consensus |
| 15 | POST | `/sealevel/submit` | Public | Sealevel |
| 16 | POST | `/credit/open` | Public | L2 Bridge |
| 17 | POST | `/credit/settle` | Public | L2 Bridge |
| 18 | POST | `/wallet/create` | Public | Wallet |
| 19 | POST | `/wallet/login` | SSS Shards | Wallet |
| 20 | POST | `/wallet/logout` | Session Token | Wallet |
| 21 | POST | `/wallet/secure/shard-b` | PIN | Wallet |
| 22 | POST | `/wallet/verify-sss` | Public | Wallet |
| 23 | POST | `/admin/mint` | Dealer Sig | Admin |
| 24 | POST | `/admin/burn` | Dealer Sig | Admin |
| 25 | POST | `/admin/dealer/settle` | Dealer Sig | Admin |
| 26 | POST | `/admin/wallet/migrate` | Admin | Admin |
| 27 | GET | `/admin/accounts` | Admin | Admin |
| 28 | GET | `/admin/security/stats` | Admin | Admin |
| 29 | POST | `/admin/usdc/mint` | Admin | USDC |
| 30 | POST | `/usdc/transfer` | Public | USDC |
| 31 | GET | `/usdc/balance/:address` | Public | USDC |
| 32 | GET | `/usdc/supply` | Public | USDC |
| 33 | GET | `/usdc/accounts/:address` | Public | USDC |

**Ports:**
- **8080** â€” REST API (all endpoints above)
- **8899** â€” Solana JSON-RPC 2.0 (28 methods)
- **50051** â€” gRPC Settlement + Validator Relay (15 methods)

**Total: 76 callable methods across 3 protocols.**


---

## Deposit Gateway

### POST /deposit/request

Register an intent to deposit stablecoin. The watcher uses the returned 	x_hash key to match the on-chain transfer.

**Request body:**
`json
{
  "wallet_address": "base58 BB wallet",
  "source_chain": "solana | bsc",
  "amount_stablecoin": 10.0
}
`

**Response:**
`json
{ "tx_hash": "...", "wallet_address": "...", "amount_stablecoin": 10.0 }
`

---

### GET /deposit/status/:tx_hash

Poll the status of a deposit by its tx hash key.

**Response:**
`json
{ "tx_hash": "...", "status": "pending | credited | failed", "bb_minted": 1.0, "created_at": 1720000000 }
`

---

### POST /deposit/claim

Claim an **unattributed deposit** — funds sent to the custody wallet without first calling /deposit/request and without a BB:<wallet> memo. Proves wallet ownership via Ed25519 to receive the BB.

**Request body:**
`json
{
  "wallet_address": "base58 BB wallet receiving the BB",
  "external_tx_hash": "on-chain tx hash of the custody-wallet deposit",
  "public_key": "hex-encoded Ed25519 pubkey (32 bytes = 64 hex chars)",
  "signature": "hex-encoded Ed25519 signature (64 bytes = 128 hex chars)",
  "timestamp": 1720000000,
  "nonce": "random-string-for-replay-protection"
}
`

**Signed message format:**
`
CLAIM_DEPOSIT:{wallet_address}:{external_tx_hash}:{timestamp}:{nonce}
`

**Success response (200):**
`json
{
  "success": true,
  "external_tx_hash": "...",
  "wallet_address": "...",
  "asset": "USDT",
  "amount_stablecoin": 10.0,
  "bb_minted": 1.0,
  "new_balance": 1.0,
  "mint_tx_id": "uuid"
}
`

**Error codes:**
- 400 — Bad request (missing fields, invalid address, expired timestamp)
- 401 — Signature verification failed or pubkey/address mismatch
- 404 — No unattributed deposit found for this tx hash
- 409 — Deposit already claimed or nonce reused
- 429 — Rate limited
