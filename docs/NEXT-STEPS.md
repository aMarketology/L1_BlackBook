# BlackBook — Next Steps

> **Updated: June 2026 — v1.0.2. Rotating Leader Schedule (Phase 1) live. Multi-validator consensus.**
> L2 sequencer live on Hetzner. Permissioned Turbine 7A/7B/7C live.
>
> **The L1 is an asset-custody ledger, state machine, and transaction execution environment** —
> nothing more. It stores balances against public keys, advances state via PoH, and executes
> Ed25519-signed transactions after verifying them. It never touches user private keys.

---

## ✅ P0 — DONE: Rotating Leader Schedule (Phase 1)

**Multi-validator consensus is live.** Every validator runs `--mode validator`, consults the
same deterministic `LeaderSchedule` from `config.toml`, and dynamically switches between
Writer (produce blocks) and Reader (sync + verify) at slot boundaries.

| Item | Status |
|------|--------|
| `--mode validator` CLI flag | ✅ |
| `stake_lamports` + `http_port` in `config.toml` `[[validators]]` | ✅ |
| `LeaderSchedule` populated from `ValidatorRegistry` (not hardcoded) | ✅ |
| `TowerBFT` multi-validator from registry stakes | ✅ |
| Contiguous leader tenures (4 slots = 1.6s per leader) | ✅ |
| `GET /validators` endpoint (pubkeys, stakes, current leader) | ✅ |
| `GET /health` shows `current_leader`, `is_leader`, `validators_registered` | ✅ |
| Zero log spam — leadership transitions logged once, not every slot | ✅ |
| Dynamic reader proxy — non-leader POSTs forward to current leader | ✅ |
| Gulf Stream tx forwarding to upcoming leaders | ✅ |
| Leader handoff — Validator syncs as Reader when not leader, state always current | ✅ |

**How to run multi-validator:**
```powershell
# Node 1 (Cherry)
.\target\release\layer1.exe --mode validator --identity cherry-writer --http-port 8080

# Node 2 (Reader)
.\target\release\layer1.exe --mode validator --identity local-reader --http-port 8081 --redb-path blockchain_data/reader.redb
```

---

## P0 — NOW: Cherry Bare-Metal Migration (2–3 days)

Hetzner flagged blockchain workloads. Move the L1 node to the Cherry bare-metal host.

**What to do:**

1. **Provision Cherry** — 32-core / 64 GB / NVMe, EU colocation (see [docs/cherry.md](docs/cherry.md)).
2. **Open firewall** — TCP `8080` (RPC), `50051` (gRPC relay), `8899` (JSON-RPC), UDP `8003` (TPU) all public; UDP `8004` (Turbine) **whitelist only**.
3. **Populate `config.toml`** — copy `config.toml.example`, set `[[validators]]` to the Cherry Writer pubkey (`keys/writer.key`) + `addr` on `:8004`. Add reader nodes.
4. **Set `VALIDATOR_KEYPAIR_PATH`** — point at `keys/writer.key` so the Writer signs tick-shreds with its consortium identity.
5. **Deploy** — `deployment/setup-cherry.sh` + `docker-compose.prod.yml`; verify `GET /health` and Turbine identity in startup logs.
6. **Repoint DNS / wallet** — update `blackbook-wallet` L1 URL and L2 sequencer `L1_URL` to the Cherry IP once healthy.

**Definition of done:** L1 node runs on Cherry, Writer signs shreds with `keys/writer.key`, the local reader receives and PoH-verifies them, and the wallet/L2 talk to the new host.

---

## P1 — NEXT: Leader Timeout & Auto-Skip (Phase 6) (1–2 days)

When a scheduled leader is offline, the network should detect the timeout and advance
to the next leader automatically. Foundation is laid (leadership tracking in block loop).

**What to build:**

1. **Leader timeout detection** — if no block received within `slot_duration * 1.5` (600ms),
   declare the current leader as timed out.
2. **Skip-to-next-leader** — advance `current_slot` past the dead leader's tenure.
   Next leader detects it's now leader and starts producing.
3. **Rejoin detection** — when the dead leader comes back online, it syncs as Reader
   then resumes when its next turn comes.

**Files:** `src/main.rs` (block loop), `runtime/consensus.rs` (LeaderSchedule).

---

## P2 — HIGH: Finish the Block-Shred VIP Mesh (Phase 7D) (1–2 weeks)

Phases 7A (registry), 7B (IP gate), 7C (signed tick-shreds + u64 stake) are live. Remaining:

**What to build:**

1. **Round-robin shred assignment** — Writer assigns each 1,232-byte block shred to a different approved node instead of broadcasting every tick-shred to all targets.
2. **Peer re-broadcast** — each receiving node re-signs and blasts its shred to all other whitelisted peers (turning the star into a mesh).
3. **Block reassembly + Reed-Solomon FEC decode** — receivers buffer shreds per slot, reconstruct the block once the FEC threshold is met, then feed the Reader ingest pipeline.
4. **`GET /validators`** — ✅ DONE (Phase 1). Returns full validator set with stakes + current leader.
5. **`POST /admin/validators/add` + `DELETE /admin/validators/:pubkey`** — `unsafe_admin`-gated hot registry edits (optional; static config is the default).

**Files:** `runtime/turbine.rs`, new `runtime/shred_reassembly.rs`, `src/main.rs` (route wiring).

**Definition of done:** Two approved nodes propagate a block among themselves via round-robin + re-broadcast, reassemble it via FEC, and `GET /validators` lists the set.

---

## P3 — HIGH: Rollup Trust-Minimization (Phase 12) (1–2 weeks)

Phase 3.5 stopped double-spend/insolvency, but a malicious sequencer can still sign a
*false* root. Close that without waiting for full ZK.

**What to build:**

1. **Challenge/dispute window on `submit_root`** — reuse the `settlement/mod.rs` 2h `SubmitPendingRoot` pattern; roots are pending, not final, until the window elapses.
2. **Forced-inclusion / escape hatch** — users can exit against the last *finalized* root even if the sequencer censors them, so funds are never trapped.
3. **Sequencer bond** — sequencer stakes `$BB`, slashed on a proven invalid root.
4. **DA publication** — sequencer publishes the full balance set behind each root so anyone can reconstruct proofs and detect fraud.

**Files:** `src/contracts/rollup/mod.rs`, `src/settlement/mod.rs`, `src/storage/mod.rs`.

---

## P4 — HIGH: XDP Kernel Bypass on UDP TPU (:8003)

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

## P5 — HIGH: ZK Validity Proofs on L2 Batch Submission

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

## P6 — MEDIUM: DA Layer + State Pruning

At 502 tx/s, ReDB grows ~100MB/day. At scale, it will fill the Hetzner disk.

**What to implement:**

1. **State pruning thread** — background Tokio task in `src/storage/mod.rs` that deletes ReDB records for finalized blocks older than 48 hours.
2. **Epoch snapshots** — every 432,000 slots, serialize full `DashMap` state to a `.snapshot.bin` file, upload to S3 or Arweave.
3. **Fast sync** — new nodes download the latest snapshot instead of replaying from genesis.
4. **DA posting** — post block headers (hash, slot, tx_count, state_root) to Celestia or EigenDA for historical auditability without local storage.

**Files:** `src/storage/pruner.rs` (new), updates to `src/main.rs` startup, `deployment/` for S3 config.

---

## P7 — MEDIUM: Active-Passive L2 Sequencer HA

The L2 sequencer is a single SQLite process. If the Hetzner server reboots, L2 is down for minutes.

**What to implement:**

1. **Litestream** — stream SQLite WAL in real-time to S3 (or second Hetzner server). Litestream is a Go binary, no code changes needed to the sequencer.
2. **Secondary standby** — second Hetzner server runs L2 sequencer in read-only mode, applying WAL from S3.
3. **Health monitor** — Cloudflare Worker or simple script pings L2 `/health` every 5s. On failure, flips DNS to secondary.
4. **Promotion script** — on promotion, secondary switches from read-only WAL consumer to active writer.

**Target:** < 500ms failover, zero data loss (Litestream flushes WAL every 1s).

**Files:** `deployment/litestream.yml` (new), `deployment/docker-compose.prod.yml` (Litestream sidecar).

---

## Completed (through v1.0.2)

- ✅ **Rotating Leader Schedule** — `--mode validator`, multi-validator `LeaderSchedule` from `config.toml`, contiguous 4-slot tenures, dynamic role switching, `GET /validators`
- ✅ PoH + Tower BFT + Gulf Stream + Sealevel
- ✅ Sealevel O(N) scheduler + Local Fee Market
- ✅ `Transaction.priority` plumbed from UDP TPU
- ✅ Universal Rollup Hub (L2/L3/L5 lock/root/exit)
- ✅ L2 sequencer npm workspace (TypeScript, compiled JS)
- ✅ 8-step L2→L1 smoke test passing on live Hetzner
- ✅ Ed25519 on all write endpoints + nonce replay protection
- ✅ `unsafe_admin` production compile-time gate
- ✅ 502 tx/s validated (UDP TPU, 10,060 packets, 0 errors)
- ✅ v1.0.2 tagged and pushed (`aMarketology/L1_BlackBook`)
- ✅ React wallet wired to live L2 sequencer (`layer2.blackbook.id/seq`)
- ✅ L2 sequencer Dockerized + deployed to Hetzner (compose + nginx HTTPS)
- ✅ Rollup exit path hardened (batch-agnostic keys, cumulative accounting, atomic exit)
- ✅ Permissioned Turbine 7A/7B/7C: `ValidatorRegistry`, UDP IP gate, signed tick-shreds
- ✅ `LeaderSchedule` f64 → u64 lamport rewrite (deterministic integer schedule)
- ✅ **v1.0.2 rotating leader consensus** — `--mode validator`, multi-validator `LeaderSchedule` from `config.toml`, contiguous 4-slot tenures, dynamic role switching, `GET /validators`, zero log spam
- ✅ **v1.0.1 pure-L1 cleanup** — removed dead fiat-onramp code (Lightning/BTCPay gateway + Transak webhook) and the server-side keygen endpoint; build is warning-clean
