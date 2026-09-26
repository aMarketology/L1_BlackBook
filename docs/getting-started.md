# Getting Started

Run a BlackBook L1 node locally, expose it on your network, and make your first
signed request.

## Prerequisites

- Rust toolchain (edition 2021+; the workspace targets a 2026 edition toolchain)
- PowerShell (Windows) or bash (Linux/macOS)
- A way to generate an Ed25519 keypair (see [Authentication](authentication.md))

## 1. Build

```powershell
# Development — enables unsafe_admin endpoints (dev/test minting, seeding)
cargo build --features unsafe_admin

# Production — no unsafe admin endpoints
cargo build --release
```

The binary is `target/debug/layer1.exe` (or `target/release/layer1.exe`).

## 2. Run

Node mode is selected with the **`--mode` CLI flag**, not an environment
variable:

| Mode | Flag | Behavior |
|------|------|----------|
| Writer | `--mode writer` | Single writer — always produces blocks (legacy/dev) |
| Reader | `--mode reader` | Always syncs from a writer via gRPC (legacy/dev) |
| Validator | `--mode validator` | Production — consults `LeaderSchedule` each slot |

```powershell
# Writer (simplest local dev)
.\target\debug\layer1.exe --mode writer --redb-path blockchain_data/dev.redb

# Validator (production — --identity must match a label in config.toml)
.\target\debug\layer1.exe --mode validator --identity cherry-writer
```

### Key CLI flags

| Flag | Purpose |
|------|---------|
| `--mode` | writer / reader / validator |
| `--identity` | validator label, must match `config.toml` `[[validators]]` |
| `--redb-path` | ReDB database path (default `blockchain_data/blockchain.redb`) |

## 3. Verify it is up

```powershell
curl.exe http://localhost:8080/health
```

A healthy node returns `status: "healthy"` with `slot`, `version`, `total_supply`,
and PoH clock info. See [Endpoint Reference](endpoints.md#node-health) for the
full shape.

## 4. Reach it from other devices (LAN / bare-metal)

The node binds `0.0.0.0` on all ports, so it is reachable on your LAN IP:

```powershell
# Find your LAN IP
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*'}
# → e.g. 192.168.1.188

curl.exe http://192.168.1.188:8080/health
```

For browser / cross-origin clients, add the client origin to CORS:

```powershell
$env:CORS_EXTRA_ORIGINS = "https://my-wallet.vercel.app"
# dev only: $env:CORS_ALLOW_ALL = "true"
```

### Exposing to the public internet

To broadcast globally you need to forward ports on your router (or use a reverse
proxy / tunnel):

| Port | Proto | Service |
|------|-------|---------|
| 8080 | TCP | HTTP REST + WS |
| 8899 | TCP | Solana JSON-RPC |
| 50051 | TCP | gRPC relay |
| 50052 | TCP | gRPC settlement |
| 8003 | UDP | TPU (bincode) |
| 8004 | UDP | Turbine tick |

> **Pitfall:** UDP ports (8003/8004) do **not** traverse consumer NAT without
> explicit forwarding and generally should not be exposed to the public
> internet. For production, front the HTTP API with TLS (e.g. nginx) and leave
> UDP confined to the consortium mesh. See [Pitfalls](pitfalls.md).

## 5. Get test tokens (faucet)

`POST /faucet` mints up to **0.1 BB** per address per epoch. It is Ed25519-signed.

```text
signed message: "FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"
```

The faucet caps at 0.1 BB — far too small for real multi-token testing. Seed
larger amounts with a genesis balance or `unsafe_admin` mint instead (see
[Pitfalls](pitfalls.md#faucet-cap)).

## 6. Make a signed transfer

See [Authentication](authentication.md) for the full signing spec. The transfer
flow is `POST /transfer` with a `[chain_id_byte] + payload + "\n" + timestamp +
"\n" + nonce` signed message.

## 7. Read the endpoint reference

The full surface — HTTP, JSON-RPC, gRPC, UDP — is in
[Endpoint Reference](endpoints.md).
