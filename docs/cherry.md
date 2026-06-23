# BlackBook L1 — Cherry Bare-Metal Migration Guide  (v1.0.2)

## Why Cherry?
Hetzner has been flagged as rejecting blockchain workloads. Cherry provides
bare-metal servers with no blockchain restrictions, low-latency European
colocation, and NVMe storage suitable for ReDB's write throughput.

## What's New in v1.0.2

- **Rotating Leader Schedule** — run `--mode validator` for multi-validator consensus.
  Leaders rotate in contiguous 4-slot tenures (1.6s each), stake-proportional.
- **`config.toml`** now has `stake_lamports` and `http_port` per validator.
- **`GET /validators`** returns the full validator set with stakes + current leader.
- **Dynamic reader proxy** — non-leader POSTs auto-forward to the current leader.
- **Zero log spam** — leadership transitions logged once, not every slot.

---

## Pre-Migration Checklist

- [ ] Provision Cherry server (recommend: 32-core, 64 GB RAM, NVMe SSD, 1 Gbps unmetered)
- [ ] Note the server's **public IPv4** — you'll need it in two places below
- [ ] Open firewall ports:
  - `TCP 8080` — HTTP RPC (public)
  - `TCP 50051` — gRPC relay (public)
  - `TCP 8899` — Solana JSON-RPC (public)
  - `UDP 8003` — TPU ingest (public)
  - `UDP 8004` — Turbine tick shreds (**whitelist only — see Phase 7A**)

---

## Keypairs (generated 2026-06-06)

These keypairs were generated for Phase 7A permissioned Turbine mesh.
**Keep the seed files out of git** — add `keys/` to `.gitignore`.

| Role | Key file | Pubkey (first 16 chars) |
|---|---|---|
| Cherry Writer | `keys/writer.key` | `61e5b4a8d2cd192…` |
| Local Reader | `keys/reader-local.key` | `7b6b3abf0e8e7a1…` |

Full pubkeys:
```
WRITER  = 61e5b4a8d2cd1927eef7f2d43c1624039848311a218f5e5325bfde9e371d24ee
READER  = 7b6b3abf0e8e7a199fef3caf2e44d9b576201d1f9067366a4073d6a69db406bd
```

> **Security note**: `keys/*.key` files contain 64-hex-char Ed25519 seed bytes.
> Treat them like private keys — never commit, never log, never paste in chat.

---

## config.toml — Update Before Deploy

File: `config.toml` (already created in repo root with placeholders)

Replace both placeholder values:

```toml
[[validators]]
label  = "cherry-writer"
pubkey = "61e5b4a8d2cd1927eef7f2d43c1624039848311a218f5e5325bfde9e371d24ee"
addr   = "CHERRY_SERVER_IP:8004"       ← replace with Cherry public IP

[[validators]]
label  = "local-reader"
pubkey = "7b6b3abf0e8e7a199fef3caf2e44d9b576201d1f9067366a4073d6a69db406bd"
addr   = "YOUR_LOCAL_PUBLIC_IP:8004"   ← replace with your dev machine's public IP
```

This file must be **identical on both nodes**.

---

## Cherry Server Setup Steps

### 1. Copy binary + config

```bash
scp target/release/layer1            root@<CHERRY_IP>:/opt/blackbook/layer1
scp config.toml                      root@<CHERRY_IP>:/opt/blackbook/config.toml
scp keys/writer.key                  root@<CHERRY_IP>:/opt/blackbook/keys/writer.key
chmod 600 /opt/blackbook/keys/writer.key
```

### 2. Environment variables (Cherry Writer)

Create `/opt/blackbook/.env` on the Cherry server:

```env
# Node identity
NODE_MODE=writer
VALIDATOR_KEYPAIR_PATH=/opt/blackbook/keys/writer.key
VALIDATOR_CONFIG_PATH=/opt/blackbook/config.toml

# Sequencer keys (copy from current Hetzner .env)
L2_SEQUENCER_PUBKEY=fb78242e...
L3_SEQUENCER_PUBKEY=26538a99...

# ReDB storage
REDB_PATH=/opt/blackbook/blockchain_data/blockchain.redb

# Vault signer (if using local key)
VAULT_SIGNER_PRIVATE_KEY=<hex>

# Optional
WITHDRAWAL_DAILY_CAP_WUSDT=10000
```

### 3. Migrate blockchain data

```bash
# On Hetzner — copy the live ReDB file
rsync -avz /opt/blackbook/blockchain_data/ root@<CHERRY_IP>:/opt/blackbook/blockchain_data/
```

Stop the Hetzner node **first**, then rsync, then start Cherry. This avoids
dual-write corruption.

### 4. Start the Writer node

```bash
cd /opt/blackbook
./layer1
# or with systemd — see deployment/deploy.sh
```

Verify Turbine is live:
```bash
# Should see: "📡 TurbineTickService bound on UDP 0.0.0.0:8004 — 2 approved target(s)"
journalctl -u blackbook -f | grep Turbine
```

---

## Local Reader Setup

Set these env vars on your dev machine before starting a reader node:

```powershell
$env:NODE_MODE = "reader"
$env:VALIDATOR_KEYPAIR_PATH = "keys/reader-local.key"
$env:VALIDATOR_CONFIG_PATH  = "config.toml"
$env:WRITER_HTTP_URL        = "http://CHERRY_SERVER_IP:8080"
```

Then run:
```powershell
.\target\debug\layer1.exe
```

The reader will:
- Listen on UDP `:8004` for signed shreds from the Cherry writer
- Verify IP gate + Ed25519 sig + PoH chain on every packet
- Fall back to gRPC relay (`:50051`) for any missed slots

---

## Smoke Test After Migration

```powershell
# Run against Cherry
$env:BASE_URL = "http://CHERRY_SERVER_IP:8080"
.\tests\smoke.ps1

# Turbine checks: /turbine/register → 404 (Phase 7A active)
#                 /turbine/status  → 200 with shred stats
```

---

## DNS / Nginx

Update `nginx-blackbook.conf` proxy_pass targets to `127.0.0.1:8080` (unchanged).
Point your A records at Cherry's IP after verifying the node is healthy.

---

## Rollback Plan

Keep Hetzner in standby (don't destroy) until Cherry has produced 1000+ confirmed
blocks and all smoke tests pass. Hetzner can be reactivated in ~2 minutes if needed.

---

## Status

- [ ] Cherry server provisioned
- [ ] Cherry public IP known → update `config.toml` + this doc
- [ ] Keys deployed to Cherry + local
- [ ] Hetzner → Cherry data migration completed
- [ ] DNS records updated
- [ ] Smoke test passing on Cherry
- [ ] Hetzner decommissioned
