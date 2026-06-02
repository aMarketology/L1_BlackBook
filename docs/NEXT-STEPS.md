# BlackBook — Next Steps

> **Updated: June 2026 — v1.0.0 shipped. L2 sequencer live on Hetzner.**
> All pre-v1.0 P0 items are COMPLETE. These are the new priorities.

---

## P0 — NOW: Wire React Frontend to L2 (1–2 weeks)

The `blackbook-wallet/` React app already talks to L1. It needs to talk to L2 as well.

**What to build:**

1. **`VITE_L2_URL` env variable** — `blackbook-wallet/.env.local`: `VITE_L2_URL=http://localhost:7072`
2. **L2 balance display** — call `GET {L2_URL}/balances/{address}` and show alongside L1 balance.
3. **Lock BB into L2** — button calls `POST /rollup/L2/lock_bb` on L1 (Ed25519 signed by user wallet).
4. **Market list page** — fetch `GET {L2_URL}/markets`, display active markets with current odds.
5. **Place bet flow** — user picks outcome, wallet signs, `POST {L2_URL}/markets/:id/bet`.
6. **Exit / Claim page** — user calls `POST /rollup/L2/exit` on L1 with Merkle proof fetched from L2.
7. **Transaction history** — pull recent transfers from `GET /history/:address` on L1.

**Files to touch:**
- `blackbook-wallet/src/` — add `l2.ts` service client, new pages: `MarketsPage`, `BetPage`, `ClaimPage`
- `blackbook-wallet/.env.local` — add `VITE_L2_URL`
- `sdk/wallet.sdk.ts` — add `lockBB`, `exitL2` helper functions

**Definition of done:** A logged-in user can see their L1 balance, lock BB into L2, place a bet, and claim winnings back to L1 — all from the wallet UI.

---

## P1 — NOW: Deploy L2 Sequencer to Hetzner (2 days)

The L2 sequencer currently only runs locally. It needs to be on the server.

**Steps:**

1. **Create `sequencer/Dockerfile`** — Node 20 base, `npm ci`, `npm run build`, `ENTRYPOINT ["node", "l2/dist/index.js"]`
2. **Add L2 service to `deployment/docker-compose.prod.yml`:**
   ```yaml
   l2-sequencer:
     build: ../sequencer
     env_file: .env
     ports: ["7072:7072"]
     restart: unless-stopped
     volumes: ["l2_data:/app/l2/data"]
   ```
3. **Add env vars to `/opt/blackbook/.env` on Hetzner:**
   - `L2_SEQUENCER_PRIVKEY=47d8d397...`
   - `DB_PATH=/app/l2/data/l2.sqlite`
   - `L1_URL=http://l1-node:8080`
4. **Nginx proxy** — route `https://api.blackbook.gg/l2/` → `http://l2-sequencer:7072/`
5. **Health endpoint** — add `GET /health` to L2 that returns `{"status":"ok","slot":N}`

---

## P2 — HIGH: XDP Kernel Bypass on UDP TPU (:8003)

Current bottleneck: Linux kernel processes every UDP packet before Rust sees it. This adds ~50µs per packet and caps throughput.

**What to implement:**

1. **`AF_XDP` socket** — replace `tokio::net::UdpSocket` in `runtime/tpu.rs` with an `AF_XDP` ring buffer socket.
2. **eBPF loader** — small C eBPF program (`tpu_filter.c`) that passes port-8003 UDP to the XDP socket, drops everything else.
3. **Zero-copy receive** — UMEM ring mapped directly into Rust heap. No memcpy from kernel to userspace.
4. **Metrics** — expose `tpu_packets_received`, `tpu_drop_rate` via Prometheus endpoint.

**Expected impact:** Latency: ~50ms → sub-millisecond. Throughput ceiling: 240K+ TPS (limited by Sealevel execution, not network).

**Prerequisite:** Test on Hetzner CX42 that NIC supports `XDP_FLAGS_DRV_MODE` (most do).

**File:** New `runtime/tpu_xdp.rs`, replace `UdpSocket` binding in `runtime/tpu.rs`.

---

## P3 — HIGH: ZK Validity Proofs on L2 Batch Submission

Currently the L2 sequencer is trusted by authority (Ed25519 key). ZK proofs replace that with mathematics.

**What to implement:**

1. **Pick proving stack** — `risc0` (Rust-native RISC-V zkVM) is the simplest integration.
2. **LMSR payout circuit** — prove that for each market: `sum(payouts) == sum(locked_bb)`, outcomes were determined by oracle vote, every winner received correct LMSR payout.
3. **Merkle root circuit** — prove the submitted state root is the SHA-256 Merkle root of the claimed payout list.
4. **L1 verifier** — in `src/contracts/rollup/mod.rs`, add `verify_zkproof(proof_bytes, public_inputs)` before accepting a `submit_root`.
5. **L2 prover** — after each batch, run `risc0::prove(circuit, witness)` and include proof in `submit_root` payload.

**Expected impact:** The L2 sequencer key being compromised can no longer fabricate payouts. The chain is trustless.

**Estimated effort:** 4–8 weeks for single-circuit MVP.

---

## P4 — MEDIUM: DA Layer + State Pruning

At 502 tx/s, ReDB grows ~100MB/day. At scale, it will fill the Hetzner disk.

**What to implement:**

1. **State pruning thread** — background Tokio task in `src/storage/mod.rs` that deletes ReDB records for finalized blocks older than 48 hours.
2. **Epoch snapshots** — every 432,000 slots, serialize full `DashMap` state to a `.snapshot.bin` file, upload to S3 or Arweave.
3. **Fast sync** — new nodes download the latest snapshot instead of replaying from genesis.
4. **DA posting** — post block headers (hash, slot, tx_count, state_root) to Celestia or EigenDA for historical auditability without local storage.

**Files:** `src/storage/pruner.rs` (new), updates to `src/main.rs` startup, `deployment/` for S3 config.

---

## P5 — MEDIUM: Active-Passive L2 Sequencer HA

The L2 sequencer is a single SQLite process. If the Hetzner server reboots, L2 is down for minutes.

**What to implement:**

1. **Litestream** — stream SQLite WAL in real-time to S3 (or second Hetzner server). Litestream is a Go binary, no code changes needed to the sequencer.
2. **Secondary standby** — second Hetzner server runs L2 sequencer in read-only mode, applying WAL from S3.
3. **Health monitor** — Cloudflare Worker or simple script pings L2 `/health` every 5s. On failure, flips DNS to secondary.
4. **Promotion script** — on promotion, secondary switches from read-only WAL consumer to active writer.

**Target:** < 500ms failover, zero data loss (Litestream flushes WAL every 1s).

**Files:** `deployment/litestream.yml` (new), `deployment/docker-compose.prod.yml` (Litestream sidecar).

---

## Completed (v1.0.0)

- ✅ PoH + Tower BFT + Gulf Stream + Sealevel
- ✅ Sealevel O(N) scheduler + Local Fee Market
- ✅ `Transaction.priority` plumbed from UDP TPU
- ✅ Universal Rollup Hub (L2/L3/L5 lock/root/exit)
- ✅ L2 sequencer npm workspace (TypeScript, compiled JS)
- ✅ 8-step L2→L1 smoke test passing on live Hetzner
- ✅ Ed25519 on all write endpoints + nonce replay protection
- ✅ `unsafe_admin` production compile-time gate
- ✅ 502 tx/s validated (UDP TPU, 10,060 packets, 0 errors)
- ✅ v1.0.0 tagged and pushed (`aMarketology/L1_BlackBook`)
