# Hosting & Node Operations

> **TL;DR:** Hetzner terminates blockchain nodes without warning. Move the writer to
> **Latitude.sh Dallas, TX** — same setup scripts, same Docker workflow, crypto-explicit ToS,
> and you're in the same state as the team. Migration is zero-downtime because of the
> reader/writer architecture already built into the L1 node.

---

## Why Not Hetzner Long-Term

Hetzner's AUP explicitly prohibits "cryptocurrency mining" and their abuse team applies
it broadly to any workload that looks like a blockchain node: sustained high CPU (PoH
ticking), persistent NVMe writes (ReDB), and open ports on known validator ranges
(8003 UDP TPU, 8004 UDP Turbine, 50051 gRPC).

Documented incidents in the Solana ecosystem:
- Solana validator nodes terminated mid-epoch with no prior notice
- Ethereum archive nodes shut down for "network abuse"
- Custom chain nodes flagged by automated traffic analysis

Hetzner is appropriate for development and early staging. It should not be the
permanent home for a production writer node.

---

## Two-Node Mental Model

Think of the network as nodes, not servers. Every server runs one L1 binary in either
Writer or Reader mode:

```
Node 1 — Writer (block producer)
  • Runs the PoH clock
  • Produces and signs every block
  • Serves HTTP :8080, Solana RPC :8899, gRPC relay :50051
  • THIS is the node that needs a stable, crypto-friendly host

Node 2 — Reader (block consumer)
  • Subscribes to Node 1 via gRPC :50051
  • Verifies and stores every block locally
  • Serves HTTP :8080 (proxies writes to Node 1)
  • Can be promoted to Writer in < 2 minutes (zero-downtime failover)
  • Fine on Hetzner, a laptop, or any VPS — it's stateless relative to Node 1
```

Starting with two nodes (Hetzner + localhost) is correct.
The writer should move to a US bare-metal provider. The reader can stay anywhere.

---

## US Hosting Comparison

Team is based in **Texas**. Providers are ranked for: bare-metal performance, proximity,
crypto-friendly ToS, and price parity with Hetzner.

| Provider | Server | vCPU | RAM | Storage | $/mo | DC closest to TX | Crypto ToS |
|---|---|---|---|---|---|---|---|
| **Hetzner** (current) | CX42 | 8 vCPU | 16 GB | 160 GB NVMe | ~$28 | ❌ Germany | ❌ Hostile |
| **Latitude.sh** ⭐ | c2.small.x86 | 8 physical | 32 GB | 480 GB NVMe | ~$100 | ✅ Dallas, TX | ✅ Explicit |
| **Vultr** | HF-8 | 8 vCPU | 32 GB | 320 GB NVMe | $96 | ✅ Dallas, TX | ✅ Tolerant |
| **Psychz** | Dedicated | 8 physical | 32 GB | 500 GB SSD | ~$80 | ✅ Dallas, TX | ✅ Explicit |
| **OVHcloud US** | Rise-3 | 6 physical | 64 GB | 2×480 GB SSD | ~$105 | ⚠️ Virginia | ✅ Tolerant |
| **AWS EC2** | c5.2xlarge | 8 vCPU | 16 GB | EBS (extra $) | ~$280 | ✅ us-east-1/2 | ✅ Neutral |

### Why Latitude.sh is the Recommendation

1. **Dallas, TX datacenter** — lowest latency for a Texas-based team and Texas-based users.
2. **Blockchain-explicit ToS** — Latitude markets directly to Solana validators. Their product
   pages mention validator infrastructure. No ToS risk.
3. **Bare metal, not VPS** — UDP ports (8003 TPU, 8004 Turbine) perform reliably on real
   hardware. Shared hypervisors throttle UDP in ways that hurt block propagation.
4. **Same OS / same toolchain** — Ubuntu 22.04, `ufw`, Docker, `systemd`. Your existing
   `setup-hetzner.sh` and `deploy.sh` run without modification.
5. **32 GB RAM** — 2× Hetzner CX42. Headroom for chain growth, LMSR market state, and
   increased deposit watcher concurrency.

### Vultr as a Backup Option

If Latitude is unavailable or you want a second provider for redundancy:
- Vultr High Frequency (HF-8) in Dallas is $96/mo
- Same Docker + `ufw` setup
- No documented blockchain termination history
- VPS (not bare metal) — UDP performance is slightly lower but acceptable

---

## Migration Playbook (Zero Downtime)

Because the L1 node already has a Reader/Writer split, migration is a promotion,
not a migration. The chain never stops.

### Phase 1 — Provision & Sync (≈ 30 minutes)

```bash
# 1. Provision Latitude Dallas c2.small.x86
#    OS: Ubuntu 22.04 LTS

# 2. Run existing setup script — no changes needed
bash deployment/setup-hetzner.sh <LATITUDE_IP>

# 3. Push secrets
bash deployment/deploy.sh <LATITUDE_IP> --push-env

# 4. Start new node as a Reader, syncing from Hetzner
ssh root@<LATITUDE_IP> "
  cd /opt/blackbook
  # Start in reader mode pointing at the existing Hetzner writer
  docker run --rm -d \
    --env-file .env \
    -e RUST_LOG=info \
    blackbook-l1 --mode reader --writer-addr http://<HETZNER_IP>:50051
"

# 5. Confirm sync: slot on Latitude should match Hetzner within 1-2 slots
curl https://layer1.blackbook.id/health   # Hetzner (current writer)
curl http://<LATITUDE_IP>:8080/health     # Latitude (new reader, syncing)
```

### Phase 2 — Promote (≈ 2 minutes, zero downtime)

```bash
# 1. Restart Latitude node as Writer (full block producer)
bash deployment/deploy.sh <LATITUDE_IP>

# 2. Update DNS in Cloudflare:
#    layer1.blackbook.id  A  <LATITUDE_IP>  (TTL: 60s)
#    Wait for propagation (< 60 seconds with low TTL)

# 3. Confirm the new writer is healthy
curl https://layer1.blackbook.id/health
# Expect: {"ok":true,"online":true,"slot":...}

# 4. Open gRPC port on Latitude for any remaining Reader nodes
ufw allow from <HETZNER_IP> to any port 50051 comment 'hetzner-reader'
ufw allow from <YOUR_LOCAL_IP> to any port 50051 comment 'local-reader'
```

### Phase 3 — Decommission Hetzner

```bash
# Option A: Keep Hetzner as a Reader (adds redundancy for < $28/mo)
ssh root@<HETZNER_IP> "
  cd /opt/blackbook
  docker compose -f deployment/docker-compose.prod.yml down
  # Restart as reader pointing at new Latitude writer
  layer1 --mode reader --writer-addr http://<LATITUDE_IP>:50051
"

# Option B: Shut down entirely
# Cancel in Hetzner Cloud Console → Project → Servers → Delete
# Data volume is separate — delete explicitly if desired
```

---

## Firewall Rules (same on any provider)

```bash
# Run on the new server after provisioning
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp      # SSH
ufw allow 80/tcp      # HTTP (nginx → HTTPS redirect)
ufw allow 443/tcp     # HTTPS (nginx TLS termination)
ufw allow 8080/tcp    # L1 HTTP API (direct access)
ufw allow 8899/tcp    # Solana JSON-RPC (Phantom, agents)
ufw allow 8003/udp    # UDP TPU (transaction ingestion)
ufw allow 8004/udp    # Turbine tick shreds (Reader nodes)
ufw allow 50051/tcp   # gRPC relay (Writer → Reader sync)
ufw allow 50052/tcp   # gRPC settlement (L2 SubmitMerkleRoot)
ufw enable
```

---

## Port Reference

| Port | Protocol | Service | Who connects |
|---|---|---|---|
| 8080 | TCP | HTTP API | Wallet, bridge watcher, admin |
| 8899 | TCP | Solana JSON-RPC | Phantom, OneKey, agents |
| 8003 | UDP | TPU (transaction ingestion) | Clients submitting raw txs |
| 8004 | UDP | Turbine shreds | Reader nodes (block propagation) |
| 50051 | TCP | gRPC relay | Reader nodes syncing from Writer |
| 50052 | TCP | gRPC settlement | L2 sequencer → L1 |
| 50053 | TCP | gRPC NFT bridge | L3 → L1 NFT anchoring |

---

## Environment Variables — No Changes Required for Provider Switch

All secrets live in `/opt/blackbook/.env` on the server. The deployment script
pushes this file with `--push-env`. No variable names, values, or formats change
when switching providers. The only thing that changes is the IP address you pass
to `deploy.sh`.

```bash
# Switch provider in one command (after DNS update):
bash deployment/deploy.sh <NEW_PROVIDER_IP> --push-env
```

---

## Multi-Node Roadmap

As the network grows, the same two roles scale horizontally:

```
[Writer — Latitude Dallas]
      │ gRPC :50051
      ├──▶ [Reader — Vultr Dallas]      # US East failover
      ├──▶ [Reader — OVH Virginia]      # US East coast
      ├──▶ [Reader — Localhost (dev)]   # Developer machines
      └──▶ [Reader — Bridge Watcher]    # TS bridge-watcher process
```

Each Reader can be promoted to Writer in < 2 minutes by restarting with `--mode writer`
and updating DNS. No data migration. No downtime.

The writer is the only node that needs:
- Crypto-friendly ToS
- Bare metal (UDP performance)
- Stable public IP
- Let's Encrypt TLS (nginx)

Readers can run anywhere — VPS, laptops, CI machines — because their state is fully
reconstructable by replaying the writer's gRPC stream.

---

## Recommended Immediate Action

1. **Sign up at [latitude.sh](https://latitude.sh)**
2. **Provision:** Dallas, TX → `c2.small.x86` → Ubuntu 22.04
3. **Run Phase 1 above** (30 minutes, Hetzner stays live)
4. **Run Phase 2** (2 minutes, DNS flip)
5. **Keep Hetzner as a Reader** for 30 days to confirm stability, then cancel
