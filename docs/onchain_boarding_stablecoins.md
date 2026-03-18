# BlackBook L1 — On-Chain Stablecoin Boarding (Interim Model)

> **Status:** Live on `master`. Verified `invariant_ok: true` as of March 14 2026.  
> This document describes the bridge model in effect until direct integration with Circle (USDC) or Tether (USDT) is obtained.

---

## Overview

BlackBook L1 mints its own wrapped stablecoin representations — **wUSDC** and **wUSDT** — on its internal SVM accounts layer. These are not issued by Circle or Tether directly. Until a formal issuer integration is in place, bridging is handled through a **custody-wallet model** operated by the BlackBook dealer.

The 10:1 invariant is enforced at the protocol level:

```
BB total supply == wUSDC total supply × 10
```

This is verified live at any time via:

```
GET /supply/audit
```

---

## How wUSDC / wUSDT Gets On-Chain (Deposit Flow)

### Step 1 — User sends real stablecoins to the custody wallet

The user transfers real USDC or USDT (on Solana or another supported chain) to the **BlackBook custody wallet address**. This is a standard on-chain transfer. The user retains the resulting transaction hash as proof.

### Step 2 — User submits a deposit request to L1

```
POST /deposit/request
```

Request body:

| Field | Description |
|---|---|
| `wallet_address` | BlackBook wallet (base58) where tokens will be minted |
| `external_tx_hash` | On-chain tx hash proving the real stablecoin transfer |
| `asset` | `"USDC"` or `"USDT"` |
| `amount_stablecoin` | Amount sent to custody wallet |
| `public_key` | Ed25519 public key (hex, 32 bytes) |
| `signature` | Ed25519 signature over `"DEPOSIT_REQUEST:{wallet}:{tx_hash}:{amount}:{asset}:{timestamp}:{nonce}"` |
| `timestamp` | Unix timestamp (must be within 60s of server time) |
| `nonce` | Random nonce for replay protection |

The tx hash is checked against the `PROCESSED_BRIDGE_TXS` table in ReDB. If already seen, the request is rejected immediately — no double-minting is possible.

### Step 3 — Dealer approves the deposit

The dealer verifies the real on-chain transfer occurred, then calls:

```
POST /admin/deposit/approve
{ "external_tx_hash": "..." }
```

On approval, the L1 atomically:

1. **Mints BB** at 10:1 — 10 USDC = 1 BB, credited to the user's L1 account
2. **Mints wUSDC** at 1:1 with the stablecoin — credited to the user's SVM Associated Token Account (ATA)
3. **Records the tx hash** permanently in `PROCESSED_BRIDGE_TXS` — can never be re-approved

---

## The 10:1 Invariant

Every unit of BB in existence is backed by 0.1 wUSDC. Every unit of wUSDC is backed by real USDC sitting in the custody wallet.

```
Real USDC (custody wallet)
    └── 1:1 ──► wUSDC on L1 SVM
                    └── 10:1 ──► BB on L1
```

On every server boot, the startup reconciler checks the invariant and automatically:
- **Mints** deficit wUSDC if BB supply > wUSDC supply × 10 (e.g. first boot after upgrade)
- **Burns** excess wUSDC if wUSDC supply × 10 > BB supply (e.g. data inconsistency)
- **Flushes** corrected state to ReDB so it survives the next restart

---

## How wUSDC Gets Off-Chain (Withdrawal Flow)

When a user wants to redeem wUSDC for real USDC:

### Step 1 — User requests a withdrawal

```
POST /withdraw/request
```

| Field | Description |
|---|---|
| `wallet_address` | BlackBook wallet holding the wUSDC |
| `solana_destination` | Solana wallet address to receive real USDC |
| `wusdc_amount` | Amount to redeem (1 wUSDC = 1 real USDC) |
| `public_key` | Ed25519 public key |
| `signature` | Signs `"WITHDRAW_REQUEST:{wallet}:{solana_dest}:{amount}:{ts}:{nonce}"` |
| `timestamp` | Unix timestamp |
| `nonce` | Replay protection nonce |

On receipt:
- wUSDC is **burned** from the user's SVM ATA (transferred to dealer, reducing supply)
- A `WithdrawalRecord` with `status: "pending"` is created in ReDB and the in-memory index

### Step 2 — User checks withdrawal status

```
GET /withdraw/status/{withdrawal_id}
```

Returns the current status: `pending` → `released`.

### Step 3 — Dealer releases real USDC on Solana

The dealer manually (or via relayer) sends real USDC from the custody wallet to the user's `solana_destination` address on Solana, then records it:

```
POST /admin/withdraw/release
{ "withdrawal_id": "...", "solana_tx_hash": "..." }
```

The record is updated to `status: "released"` with the Solana tx hash stored as an immutable audit trail.

---

## Trust Model (During Interim Period)

| Layer | Controller | Risk |
|---|---|---|
| Real USDC / USDT on Solana | Circle / Tether | None — standard SPL tokens |
| Custody wallet (holds real assets) | BlackBook dealer hot wallet | Key compromise exposes all bridged funds |
| wUSDC / wUSDT on L1 | BlackBook L1 mint (startup reconciler) | Invariant enforced on-chain; auditable at `/supply/audit` |
| Deposit approval | Dealer (manual or relayer) | Dealer could approve a fabricated tx hash — mitigated by external tx hash dedup |

**The primary risk is the custody wallet.** All real stablecoins sit in a single dealer-controlled address during this phase. This is the same operational model as a centralised exchange running before obtaining direct issuer permissions.

### Mitigations in place now

- **Tx hash dedup** — every external tx hash is one-time-use; stored permanently in `PROCESSED_BRIDGE_TXS`
- **Ed25519 signature verification** — only the owner of a BB wallet can submit deposit or withdrawal requests for it
- **Replay protection** — all signed requests include a timestamp (60s window) and a random nonce stored in `used_nonces`
- **Audit endpoint** — `GET /supply/audit` exposes BB supply, wUSDC supply, backing ratio, and invariant status at any time
- **Withdrawal burn** — wUSDC is burned at the moment of withdrawal request, not after dealer release, so the user cannot double-redeem

---

## Path to Direct Issuer Integration

Once Circle (USDC) or Tether (USDT) grant a direct integration:

1. **Replace custody wallet** with Circle's CCTP cross-chain transfer protocol (or Tether's equivalent), eliminating manual custody
2. **Replace dealer approval** with an on-chain relayer that verifies CCTP burn proofs automatically — no human in the loop
3. **Transfer mint authority** from the dealer key to a multisig or program-controlled PDA
4. **Add wUSDT** as a second SVM mint using the same `SplTokenEngine` infrastructure already in place

Until then, the system is functional, replay-protected, and fully auditable — suitable for controlled early access and internal testing.

---

## Key Addresses (Live)

| Entity | Address |
|---|---|
| wUSDC Mint (L1 internal) | `CsLe5TZuKVVxDwyvibKez2BzYmSTCC9FkSzzXZfzUCkR` |
| Supply audit endpoint | `GET http://<node>:8080/supply/audit` |
| Deposit request | `POST http://<node>:8080/deposit/request` |
| Deposit approve (dealer) | `POST http://<node>:8080/admin/deposit/approve` |
| Withdrawal request | `POST http://<node>:8080/withdraw/request` |
| Withdrawal release (dealer) | `POST http://<node>:8080/admin/withdraw/release` |
