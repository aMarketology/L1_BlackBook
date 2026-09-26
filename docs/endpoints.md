# Endpoint Reference

The complete L1 surface. Auth column: **Ed25519** = signed request per
[Authentication](authentication.md); **—** = unauthenticated read; **feature** =
gated behind `--features unsafe_admin`.

> This table is the source of truth (mirrors `endpoints.csv`). Signed-message
> strings are the exact server-verified format.

## Node Health & Observability

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | — | Full status: version, slot, PoH hash, block age, leader, supply |
| GET | `/live` | — | Liveness probe (200 while process up) |
| GET | `/ready` | — | Readiness probe (200 when synced + healthy) |
| GET | `/metrics` | — | Prometheus metrics |
| GET | `/ws` | — | WebSocket upgrade — live balance/tx events |
| GET | `/stats` | — | Pipeline + Sealevel stats |
| GET | `/chain/volume` | — | 24h rolling $BB volume |
| GET | `/supply/audit` | — | Minted, circulating, locked supply breakdown |

## Accounts & Balances

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/balance/:address` | — | $BB balance (whole-BB `f64`, legacy). **Use lamports for financial logic.** |
| GET | `/usdc/balance/:address` | — | wUSDT balance (u64 micro-units) |
| GET | `/usdc/supply` | — | Total wUSDT supply |
| GET | `/usdc/accounts/:address` | — | SPL token accounts |
| GET | `/wusdt/…` , `/wusdc/…` | — | Aliases → `/usdc/…` |

## Transaction Ledger & Explorer

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/ledger` | — | Paginated ledger (`?page=&limit=`) |
| GET | `/tx/:tx_id` | — | Tx detail by ID |
| GET | `/address/:address/transactions` | — | All txs for an address |
| GET | `/txs/:address` | — | Alias |

## Transfers

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/transfer` | Ed25519 | `[chain_id_byte] + payload + "\n" + ts + "\n" + nonce` |
| POST | `/transfer/simple` | Ed25519 | Same scheme |
| POST | `/usdc/transfer` | Ed25519 | `USDC_TRANSFER:{from}:{from}:{to}:{raw_micro_usdt}:{ts}:{nonce}` |
| POST | `/wusdt/transfer` | Ed25519 | Alias → `/usdc/transfer` |

## Faucet

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/faucet` | Ed25519 | `FAUCET:{wallet}:{amount}:{ts}:{nonce}` — rate-limited per epoch |

## PoH & Blocks

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/poh/status` | — | Current PoH hash, tick, slot, epoch |
| GET | `/poh/block/latest` | — | Most recent finalized block |
| GET | `/poh/block/:slot` | — | Block by slot |
| GET | `/poh/transactions/recent` | — | Recent txs |
| GET | `/poh/tx/:tx_id/status` | — | Tx confirmation status |
| GET | `/blocks`, `/blocks/latest` | — | Alias → `/poh/block/latest` |

## Consensus & Network

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/consensus/tower` | — | Tower BFT vote state, lockout, commitment |
| GET | `/turbine/status` | — | Turbine shred gossip stats |
| GET | `/validators` | — | Validator set, stake weights, scheduled leader |

## Sealevel (Gulf Stream)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/sealevel/submit` | Ed25519 | Submit tx → Gulf Stream → Sealevel parallel execution |

## Swap BB ↔ wUSDT

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/swap/bb-to-usdc` | Ed25519 | `SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}` |
| POST | `/swap/usdc-to-bb` | Ed25519 | `SWAP_USDC_BB:{wallet}:{usdc_amount}:{ts}:{nonce}` |
| GET | `/swap/pool/balances` | — | BB + wUSDT reserves |

## Global Escrow (L2 settlement)

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/escrow/deposit` | Ed25519 | `ESCROW_DEPOSIT:{wallet}:{amount_lamports}:{ts}:{nonce}` |
| POST | `/escrow/submit-state-root` | L2 Sequencer | Binary: `market_id || l2_block_number.to_le_bytes(8) || root[32]` |
| POST | `/escrow/withdraw` | Ed25519 + proof | `ESCROW_WITHDRAW:{market_id}:{wallet}:{amount_lamports}:{ts}:{nonce}` |
| GET | `/escrow/status`, `/escrow/market/:id`, `/escrow/contest/:id` | — | State overview |

## Deposit Gateway (bridge-in)

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/deposit/request` | Ed25519 | `DEPOSIT_REQUEST:{wallet}:{external_tx_hash}:{amount_micro}:{asset}:{ts}:{nonce}` |
| GET | `/deposit/status/:tx_hash` | — | Confirmation status |
| POST | `/deposit/claim` | Ed25519 | `CLAIM_DEPOSIT:{wallet}:{external_tx_hash}:{ts}:{nonce}` |
| POST | `/deposit/webhook/helius` | Helius HMAC | Server-to-server |
| POST | `/deposit/webhook/alchemy` | Alchemy sig | Server-to-server |

## Withdrawal Gateway (bridge-out)

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/withdraw/request` | Ed25519 | `WITHDRAW_REQUEST:{wallet}:{solana_dest}:{wusdt_amount_micro}:{ts}:{nonce}` |
| GET | `/withdraw/status/:id` | — | Status by ID |
| GET | `/withdraw/since/:seq` | — | Records since seq (relayer sync) |

## Vault Gateway

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| GET | `/vault/kms-pubkey` | — | Vault signer pubkey |
| POST | `/vault/burn` | Ed25519 | `VAULT_BURN:{wallet}:{bb_lamports}:{ts}:{nonce}` |
| POST | `/vault/claim-attestation` | Ed25519 | `CLAIM_ATTESTATION:{wallet}:{poh_slot}:{amount_usdt_micro}:{ts}:{nonce}` |

## Oracle

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| GET | `/oracle/nodes` | — | Registered nodes + $BB bond |
| GET | `/oracle/event/:market_id` | — | Finalized result |
| POST | `/oracle/submit-pending-root` | Oracle | `ORACLE_SUBMIT:{rollup_id}:{market_id}:{outcome}:{merkle_root_hex}:{batch_id}:{ts}:{nonce}` |
| POST | `/oracle/dispute` | Ed25519 | `ORACLE_DISPUTE:{market_id}:{bb_stake_lamports}:{ts}:{nonce}` |
| POST | `/oracle/vote` | Oracle | `ORACLE_VOTE:{market_id}:{vote}:{ts}:{nonce}` |

## L3 NFT Bridge

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| GET | `/nft/:collection_id/:token_id` | — | Anchored NFT metadata |
| GET | `/nft/:collection_id/:token_id/owner` | — | Current owner |
| POST | `/nft/transfer` | Ed25519 | `NFT_TRANSFER:{from}:{collection_id}:{token_id}:{from}:{to}:{ts}:{nonce}` |

## Universal Rollup Hub (L2/L3/L5)

See [Rollup Hub Integration](rollup-hub.md) for the full lifecycle.

| Method | Path | Auth | Signed message |
|--------|------|------|----------------|
| POST | `/rollup/:id/lock_bb` | Ed25519 | `ROLLUP_LOCK_BB:{id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}` |
| GET | `/rollup/:id/locks/:lock_id` | — | Fetch lock record |
| POST | `/rollup/:id/locks/:lock_id/consume` | Sequencer | `CONSUME_LOCK:{id}:{lock_id}:{ts}` |
| POST | `/rollup/:id/submit_root` | Sequencer | `ROLLUP_SUBMIT_ROOT:{id}:{batch_id}:{merkle_root_hex}:{ts}` |
| GET | `/rollup/:id/roots/:batch_id` | — | Anchored root |
| POST | `/rollup/:id/exit` | Ed25519 + proof | `ROLLUP_EXIT:{id}:{asset_type}:{address}:{batch_id}:{ts}:{nonce}` |

## DA Settlement Layer

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/da/:market_id` | — | Oracle-finalized state root |
| GET | `/da/:rollup_id/pool` | — | Dealer vault $BB balance |
| POST | `/da/claim` | Ed25519 + proof | Merkle proof → vault BB release |

## Admin (unsafe_admin feature only)

`POST /admin/mint`, `POST /admin/burn`, `POST /admin/usdc/mint`,
`POST /admin/seed_swap_pool`, `POST /admin/swap/set_rate`,
`POST /admin/dealer/settle`, `POST /admin/deposit/approve`,
`POST /admin/withdraw/release`, `POST /oracle/register`,
`GET /admin/accounts`, `GET /admin/security/stats`,
`POST /admin/backup`, `GET /admin/backup/status`.

> These are **dev/test only** and do not exist in a release build without the
> `unsafe_admin` feature flag.

## Off-chain transport

| Transport | Address | Protocol | Notes |
|-----------|---------|----------|-------|
| UDP TPU | `:8003` | bincode | 8 workers. `TpuPacket.amount` is **u64 lamports** (not BB float) |
| gRPC relay | `:50051` | protobuf | `GetBalance`, `SoftLock`, `SettleBet`, `BatchSettle`, `SubscribeBlocks` |
| gRPC settlement | `:50052` | protobuf | Dealer settlement stream |
| WebSocket | `:8080/ws` | JSON | Balance subscriptions + block events |
| Solana JSON-RPC | `:8899` | JSON-RPC | `getHealth`, `getBalance`, … |
