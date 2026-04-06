# Production Security & Infrastructure — Step-by-Step

Three subjects are covered here in full detail:

1. **HashiCorp Vault** — keep `.env` secrets off every server, readable only by you
2. **gRPC Port Lockdown** — restrict ports 50051/50052 so only your L2 game servers (Rollup 2 and Rollup 3) can reach them
3. **Multi-Node Global Network** — how to run multiple BlackBook L1 nodes around the world

---

## Part 1: HashiCorp Vault — Only You Can See the Secrets

### The Problem Right Now

`deployment/setup-hetzner.sh` expects you to `scp .env root@<SERVER_IP>:/opt/blackbook/.env` before startup. That `.env` file contains:

- `DEALER_PRIVATE_KEY` — signs mints, burns, and dealer settlements
- `L2_SEQUENCER_PUBKEY` — the trusted public key for L2 state root submissions
- `SERVER_MASTER_KEY` — chain signing key
- `SOLANA_RPC_URL` — your paid RPC endpoint
- `BSC_CUSTODY_WALLET` — BSC bridge wallet

With the current approach the file lives on every server, any person with SSH access can `cat /opt/blackbook/.env` and read everything.

---

### How HashiCorp Vault Solves This

Vault is a secrets server. Instead of a flat `.env` file on each machine, secrets live in one encrypted Vault instance. At startup each node authenticates to Vault (using a short-lived token or an AWS/GCP role) and fetches only the secrets it is allowed to read. The plaintext never touches disk on the application server.

```
Your laptop / CI             Vault Server              Hetzner Node
─────────────────            ─────────────             ────────────────
vault write kv/blackbook     stores encrypted          on startup:
  DEALER_PRIVATE_KEY=...     secret                    vault agent fetches
  L2_SEQUENCER_PUBKEY=...                              DEALER_PRIVATE_KEY,
  SERVER_MASTER_KEY=...                                L2_SEQUENCER_PUBKEY,
                                                       injects as env vars
                                                       into the container
```

---

### Step-by-Step Setup

#### Step 1: Run Vault (single small server or HCP Vault)

The simplest production path is **HCP Vault Dedicated** (HashiCorp's managed offering) — no server to maintain. Alternatively spin a `vault` Docker container on a separate Hetzner CX11 (€4/mo).

```bash
# On a separate small Hetzner server — NOT the node server
docker run -d \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  --name vault \
  -e VAULT_ADDR=http://0.0.0.0:8200 \
  -e VAULT_LOCAL_CONFIG='{"storage":{"file":{"path":"/vault/data"}},"listener":[{"tcp":{"address":"0.0.0.0:8200","tls_cert_file":"/certs/cert.pem","tls_key_file":"/certs/key.pem"}}],"ui":true}' \
  hashicorp/vault server

# Initialise (run once, save the unseal keys somewhere safe — e.g. 1Password)
vault operator init
vault operator unseal   # paste unseal keys
vault login             # paste root token
```

> **Important:** Keep the root token and unseal keys in a password manager. Do **not** put them in any repository or `.env` file.

#### Step 2: Write BlackBook Secrets into Vault

```bash
# Enable KV v2 engine
vault secrets enable -path=blackbook kv-v2

# Write all BlackBook secrets (you do this from YOUR laptop, once)
vault kv put blackbook/node \
  DEALER_PRIVATE_KEY="your_hex_key_here" \
  L2_SEQUENCER_PUBKEY="your_base58_pubkey_here" \
  SERVER_MASTER_KEY="your_master_key_here" \
  SOLANA_RPC_URL="https://your-helius-rpc-url" \
  BSC_RPC_URL="https://bsc-dataseed.binance.org/" \
  BSC_CUSTODY_WALLET="your_bsc_wallet_address"
```

#### Step 3: Create a Policy — Nodes Get Read-Only Access

```hcl
# blackbook-node-policy.hcl
path "blackbook/data/node" {
  capabilities = ["read"]
}
```

```bash
vault policy write blackbook-node blackbook-node-policy.hcl
```

This means even if someone compromises a node token, they can only **read** this one path. They cannot write, delete, or read any other secret.

#### Step 4: Create AppRole Authentication for Each Node

AppRole is the standard machine-to-machine auth method. Each node gets a `RoleID` (not secret, like a username) and a `SecretID` (secret, rotated periodically).

```bash
vault auth enable approle

vault write auth/approle/role/blackbook-node \
  token_policies="blackbook-node" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h

# Get the RoleID (not secret — can be in docker-compose.prod.yml)
vault read auth/approle/role/blackbook-node/role-id

# Generate a SecretID (secret — treat like a password, rotate daily via cron)
vault write -f auth/approle/role/blackbook-node/secret-id
```

#### Step 5: Install Vault Agent on Each Node Server

Vault Agent is a small sidecar that authenticates, retrieves secrets, and writes them into a `.env` file (or injects them directly as environment variables). It handles token renewal automatically.

```bash
# On each Hetzner node
apt-get install -y vault

# /etc/vault-agent/config.hcl
cat <<'EOF' > /etc/vault-agent/config.hcl
vault {
  address = "https://YOUR_VAULT_SERVER_IP:8200"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/etc/vault-agent/role-id"
      secret_id_file_path = "/etc/vault-agent/secret-id"
    }
  }

  sink "file" {
    config = {
      path = "/etc/vault-agent/.vault-token"
    }
  }
}

template {
  source      = "/etc/vault-agent/blackbook.env.tpl"
  destination = "/opt/blackbook/.env"
  perms       = "0600"
}
EOF

# /etc/vault-agent/blackbook.env.tpl
cat <<'EOF' > /etc/vault-agent/blackbook.env.tpl
{{ with secret "blackbook/data/node" }}
DEALER_PRIVATE_KEY={{ .Data.data.DEALER_PRIVATE_KEY }}
L2_SEQUENCER_PUBKEY={{ .Data.data.L2_SEQUENCER_PUBKEY }}
SERVER_MASTER_KEY={{ .Data.data.SERVER_MASTER_KEY }}
SOLANA_RPC_URL={{ .Data.data.SOLANA_RPC_URL }}
BSC_RPC_URL={{ .Data.data.BSC_RPC_URL }}
BSC_CUSTODY_WALLET={{ .Data.data.BSC_CUSTODY_WALLET }}
{{ end }}
EOF
```

Put the `RoleID` into `/etc/vault-agent/role-id` (not secret). Put the `SecretID` into `/etc/vault-agent/secret-id` (rotate this daily).

```bash
# Start as a systemd service
vault agent -config=/etc/vault-agent/config.hcl &
```

When Vault Agent starts it writes `/opt/blackbook/.env` with decrypted values, then your existing `docker-compose.prod.yml` picks it up via `env_file: - ../.env`. It re-renders the file when the token approaches expiry, seamlessly.

#### Step 6: Rotate the SecretID Daily (cron on your laptop)

```bash
# Run this daily from YOUR machine — the node never has write access
vault write -f auth/approle/role/blackbook-node/secret-id \
  | grep secret_id | awk '{print $2}' \
  | ssh root@NODE_IP "cat > /etc/vault-agent/secret-id && pkill -HUP vault"
```

#### What This Achieves

| Before Vault | After Vault |
|---|---|
| `.env` sits in plaintext on every server | `.env` rendered from encrypted Vault for 1h TTL |
| Any SSH user can `cat .env` | Server never stores secrets beyond TTL window |
| Rotating `DEALER_PRIVATE_KEY` requires SSH to every node | One `vault kv put` command, all nodes get it on next token refresh |
| Secrets in memory of anyone who pulled the repo | Secrets only in Vault, pulled at runtime |

---

## Part 2: Restricting gRPC Ports to L2 Servers Only (50051 / 50052)

### What These Ports Do

| Port | Service | Who Should Connect |
|---|---|---|
| 50051 | gRPC Validator Relay (writer → reader block streaming) | Rollup 2 & Rollup 3 L2 game servers only |
| 50052 | Settlement gRPC (L2 submits state roots + claims) | Rollup 2 & Rollup 3 L2 game servers only |

Right now `setup-hetzner.sh` opens both with `ufw allow 50051/tcp` — visible to the entire internet. Any machine can attempt to connect.

---

### The Fix: UFW Source-IP Whitelisting

Replace the open `ufw allow 50051/tcp` with source-restricted rules. You need the static IP addresses of both L2 servers first. Call them:

- `L2_ROLLUP2_IP` = the public IP of your Rollup 2 server
- `L2_ROLLUP3_IP` = the public IP of your Rollup 3 server

```bash
# Remove the open rules
ufw delete allow 50051/tcp
ufw delete allow 50052/tcp

# Allow ONLY from Rollup 2
ufw allow from L2_ROLLUP2_IP to any port 50051 proto tcp comment 'gRPC relay — Rollup 2'
ufw allow from L2_ROLLUP2_IP to any port 50052 proto tcp comment 'gRPC settlement — Rollup 2'

# Allow ONLY from Rollup 3
ufw allow from L2_ROLLUP3_IP to any port 50051 proto tcp comment 'gRPC relay — Rollup 3'
ufw allow from L2_ROLLUP3_IP to any port 50052 proto tcp comment 'gRPC settlement — Rollup 3'

ufw reload
ufw status numbered
```

This is the primary firewall layer. Any IP not in that list is silently dropped at the kernel — the connection never reaches the Rust process.

---

### Update `deployment/setup-hetzner.sh`

Replace:
```bash
ufw allow 50051/tcp comment 'gRPC Validator Relay'
```

With:
```bash
# gRPC ports are restricted to known L2 game servers — see docs/security_step_by_step.md
# Fill in your actual L2 server IPs before running
L2_ROLLUP2_IP="${L2_ROLLUP2_IP:?Set L2_ROLLUP2_IP before running setup}"
L2_ROLLUP3_IP="${L2_ROLLUP3_IP:?Set L2_ROLLUP3_IP before running setup}"

ufw allow from "$L2_ROLLUP2_IP" to any port 50051 proto tcp comment 'gRPC relay — Rollup 2'
ufw allow from "$L2_ROLLUP2_IP" to any port 50052 proto tcp comment 'gRPC settlement — Rollup 2'
ufw allow from "$L2_ROLLUP3_IP" to any port 50051 proto tcp comment 'gRPC relay — Rollup 3'
ufw allow from "$L2_ROLLUP3_IP" to any port 50052 proto tcp comment 'gRPC settlement — Rollup 3'
```

The `:?` bash syntax aborts the script with a clear error if the variable is not exported — prevents accidentally opening the ports to everyone while testing.

---

### Update `deployment/docker-compose.prod.yml`

The compose file currently exposes `50051:50051` to all interfaces. Change it to bind on `127.0.0.1` only — UFW handles the external allow list, Docker should not re-expose ports independently.

Replace:
```yaml
ports:
  - "50051:50051"  # gRPC relay (writer → reader streaming)
```

With:
```yaml
ports:
  - "127.0.0.1:50051:50051"  # gRPC relay — external access via UFW whitelist only
  - "127.0.0.1:50052:50052"  # gRPC settlement — external access via UFW whitelist only
```

> **Why both?** Docker has its own iptables rules that can bypass UFW on some Ubuntu configurations. Binding to `127.0.0.1` in compose ensures Docker never exposes the port on the external interface regardless of iptables ordering. UFW's `from IP to any port 50051` rules still reach the port because UFW operates at the routing level above the loopback binding for external traffic. If you find this blocks the L2 connections, switch to `"0.0.0.0:50051:50051"` and rely solely on the UFW rules.

---

### Second Layer: mTLS on the gRPC Endpoints

UFW is the firewall layer. For defence-in-depth, add mutual TLS (mTLS) to the gRPC server so even a compromised machine at an allowed IP cannot connect without a client certificate.

The gRPC server in `src/main.rs` line 2452 currently binds with no TLS:
```rust
let addr = format!("0.0.0.0:{}", grpc_port).parse().unwrap();
```

To add mTLS:
1. Generate a CA cert and two client certs (one for Rollup 2, one for Rollup 3).
2. Pass the CA cert and server cert to `tonic::transport::Server::tls_config()`.
3. Distribute client certs to each L2 server — they pass them in their gRPC channel config.

This is a future hardening step. UFW source-IP whitelisting is sufficient for the initial Hetzner launch.

---

## Part 3: Multi-Node Global Network

### Architecture Overview

BlackBook L1 at scale runs one **Writer** node and multiple **Reader** nodes globally. The Writer is the single block producer (leader-based like Solana). Readers stream blocks from the Writer via gRPC (port 50051) and serve read-only queries locally with zero latency for their region.

```
                         ┌─────────────────────────────────┐
                         │      Writer Node (Primary)       │
                         │  Hetzner Helsinki / Frankfurt    │
                         │  Port 8080 HTTP, 50051 gRPC      │
                         │  Produces blocks, signs PoH      │
                         └───────────────┬─────────────────┘
                                         │ gRPC block stream
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                     ▼
         ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
         │  Reader — US East │  │  Reader — Asia   │  │  Reader — EU West│
         │  Hetzner / AWS   │  │  Hetzner / DO    │  │  Hetzner          │
         │  Port 8080 HTTP  │  │  Port 8080 HTTP  │  │  Port 8080 HTTP  │
         │  Read-only API   │  │  Read-only API   │  │  Read-only API   │
         └──────────────────┘  └──────────────────┘  └──────────────────┘
```

---

### Node Roles

#### Writer Node (one, globally)

- Runs with `--mode writer` (configured via `NODE_MODE=writer` in `.env`)
- Owns the `DEALER_PRIVATE_KEY` and `SERVER_MASTER_KEY`
- Produces blocks every slot, signs PoH entries, runs the SVM executor
- Hosts the gRPC relay server on port 50051 — readers connect to it
- Should NOT be publicly DNS-advertised; only exposed to readers and L2 servers

#### Reader Nodes (as many as needed)

- Run with `NODE_MODE=reader` and `WRITER_GRPC_ADDR=http://<WRITER_IP>:50051`
- No private keys — read-only
- Stream every finalized block from the Writer via the gRPC relay
- Apply balance updates locally and serve the HTTP API (port 8080) to wallets
- Can be torn down and restarted freely — they re-sync from the Writer on startup

---

### Launching a Second Node (step by step)

#### 1. Provision a new Hetzner server

Recommended: CX22 (4 vCPU, 8 GB RAM) for a reader node.

Regions to consider:
| Node | Hetzner Location | Rationale |
|---|---|---|
| Writer | Helsinki or Frankfurt | Low EU latency, stable datacenter |
| Reader — US | Hillsboro (Oregon) or Ashburn | US wallet users |
| Reader — Asia | Singapore | Asian wallet users |
| Reader — EU backup | Nuremberg | Failover for EU |

#### 2. Run `setup-hetzner.sh` on the new server

The same script works for reader nodes. Before running, export:

```bash
export NODE_MODE=reader
export WRITER_GRPC_ADDR="http://<WRITER_IP>:50051"
export L2_ROLLUP2_IP="<rollup2_ip>"
export L2_ROLLUP3_IP="<rollup3_ip>"
```

Reader nodes do not need `DEALER_PRIVATE_KEY` or `SERVER_MASTER_KEY` in their Vault policy. Create a separate, more restricted Vault policy for readers:

```hcl
# blackbook-reader-policy.hcl
path "blackbook/data/reader" {
  capabilities = ["read"]
}
```

```bash
vault kv put blackbook/reader \
  SOLANA_RPC_URL="https://your-rpc" \
  WRITER_GRPC_ADDR="http://<WRITER_IP>:50051"
```

The reader node's `.env` only ever contains non-sensitive connection config — no private keys.

#### 3. Update docker-compose for reader mode

In the reader's `.env`:
```bash
NODE_MODE=reader
WRITER_GRPC_ADDR=http://<WRITER_IP>:50051
```

The existing `docker-compose.prod.yml` passes these through to the binary, which checks `NODE_MODE` at startup and enters reader mode automatically.

#### 4. Open the Writer's firewall to accept the new Reader

On the **Writer** node:
```bash
ufw allow from <READER_IP> to any port 50051 proto tcp comment 'gRPC stream — Reader EU backup'
ufw reload
```

#### 5. Verify the reader is syncing

```bash
# On the reader node
docker logs -f blackbook-l1 | grep "Block"
# Should show: "📦 Block <N> applied from Writer"

# Or via HTTP
curl http://<READER_IP>:8080/health | jq .blockchain.block_count
# Should be equal to the writer's block count within a few seconds
```

---

### Global DNS & Load Balancing

Once you have two or more reader nodes, use a GeoDNS provider (Cloudflare, AWS Route 53 Latency Routing, or Hetzner's DNS with health checks) to point `rpc.blackbook.io` to the nearest reader:

```
rpc.blackbook.io → US users    → US Reader IP
rpc.blackbook.io → Asian users → Asia Reader IP
rpc.blackbook.io → EU users    → EU Reader IP (or Writer directly)
```

Point write traffic (wallet transfers, faucet) to the Writer node directly or proxy through the nearest reader to the Writer.

---

### Network Topology Summary

```
Internet Users (wallets, agents)
         │
    Cloudflare GeoDNS
    rpc.blackbook.io
         │
    ┌────┴──────────────────────────┐
    │                               │
  Reader (US)                  Reader (Asia)
  8080 → local RPC             8080 → local RPC
    │                               │
    └──────────────┬────────────────┘
                   │ gRPC 50051 (whitelisted)
              ┌────▼────────────┐
              │  Writer (EU)    │◄─── L2 Rollup 2 (50051/50052)
              │  50051/50052    │◄─── L2 Rollup 3 (50051/50052)
              │  8080 HTTP      │◄─── Admin / Dealer (HTTPS only)
              └─────────────────┘
```

---

### Checklist Before Adding Each New Node

- [ ] Vault AppRole created for the node with the minimal required policy (reader or writer)
- [ ] SecretID delivered to server, Vault Agent running and `/opt/blackbook/.env` rendered
- [ ] UFW rules on Writer updated to allow the new reader's IP on port 50051
- [ ] Reader `.env` contains `NODE_MODE=reader` and correct `WRITER_GRPC_ADDR`
- [ ] `docker-compose.prod.yml` gRPC ports bound to `127.0.0.1` (not `0.0.0.0`)
- [ ] GeoDNS record added pointing regional traffic at this node
- [ ] `/health` endpoint returning `"status": "healthy"` with matching `block_count`
