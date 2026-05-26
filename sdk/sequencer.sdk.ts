/**
 * BlackBook L1 — Sequencer SDK (PoH Tick Loop + Batch Sealing)
 * ============================================================================
 * Used by external L2 / L3 / L5 Sequencers to:
 *   1. Subscribe to L1 PoH slot notifications via WebSocket
 *   2. Count slots to trigger deterministic batch-seal intervals
 *   3. Sign and submit Merkle state roots to the Universal Rollup Hub
 *
 * Architecture:
 *   - The L1 WebSocket at ws://host:8080/ws broadcasts a `slotNotification`
 *     every 400 ms (one PoH slot). Sequencers count slots instead of using
 *     wall-clock timers so their batch cadence is locked to L1 consensus time.
 *   - When the slot counter reaches SLOTS_PER_BATCH, the sequencer seals the
 *     current batch, builds a Merkle root, and calls POST /rollup/:id/submit_root.
 *   - If the WebSocket drops, PoHTickLoop reconnects automatically with
 *     exponential back-off and resumes counting from where it left off.
 *
 * Canonical Merkle leaf encoding (must match L1 Rust):
 *   BB  leaf: SHA-256( `{rollup_id}:BB:{address}:{balance_lamports}` )
 *   NFT leaf: SHA-256( `{rollup_id}:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}` )
 *
 * Signed message for submit_root:
 *   `ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{timestamp}:{nonce}`
 *
 * Constants:
 *   POH_SLOT_MS      = 400  (one slot = 400 ms)
 *   LAMPORTS_PER_BB  = 100_000  (5 decimals)
 *
 * Dependencies: npm install @noble/ed25519 @noble/hashes
 * ============================================================================
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

// ── Constants ──────────────────────────────────────────────────────────────

export const POH_SLOT_MS = 400;
export const LAMPORTS_PER_BB = 100_000n;

// ── Types ──────────────────────────────────────────────────────────────────

export interface SequencerKeypair {
  /** 64-char hex Ed25519 public key registered as L2/L3/L5_SEQUENCER_PUBKEY on L1 */
  publicKeyHex: string;
  /** 64-char hex Ed25519 private key — NEVER log or transmit */
  privateKeyHex: string;
}

export interface SequencerConfig {
  rollupId: "L2" | "L3" | "L5" | string;
  /** Slots per batch cycle. Default: 25 (= 10 s at 400 ms/slot) */
  slotsPerBatch?: number;
  /** L1 HTTP base URL, e.g. "http://localhost:8080" */
  l1HttpUrl: string;
  /** L1 WebSocket URL, e.g. "ws://localhost:8080/ws" */
  l1WsUrl: string;
  keypair: SequencerKeypair;
}

/** A BB balance entry for Merkle tree construction */
export interface BbLeaf {
  address: string;
  /** Raw lamports (u64). 1 BB = 100_000 lamports. */
  balanceLamports: bigint;
}

/** An NFT entry for Merkle tree construction */
export interface NftLeaf {
  collectionId: string;
  tokenId: string;
  owner: string;
  /** 64-char hex SHA-256 of off-chain metadata */
  metadataHash: string;
}

export type RollupLeaf = { type: "BB"; data: BbLeaf } | { type: "NFT"; data: NftLeaf };

// ── Merkle Helpers ─────────────────────────────────────────────────────────

function sha256Hex(input: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}

/** Build the canonical leaf preimage string (must match L1 Rust exactly). */
export function buildLeafPreimage(rollupId: string, leaf: RollupLeaf): string {
  if (leaf.type === "BB") {
    const { address, balanceLamports } = leaf.data;
    return `${rollupId}:BB:${address.toLowerCase()}:${balanceLamports}`;
  } else {
    const { collectionId, tokenId, owner, metadataHash } = leaf.data;
    return `${rollupId}:NFT:${collectionId}:${tokenId}:${owner.toLowerCase()}:${metadataHash}`;
  }
}

/** Hash a leaf preimage to get the 32-byte leaf hash. */
export function hashLeaf(rollupId: string, leaf: RollupLeaf): Uint8Array {
  return sha256(new TextEncoder().encode(buildLeafPreimage(rollupId, leaf)));
}

/** Combine two sibling hashes (sorted to be deterministic, matching L1). */
function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  // min(a,b) || max(a,b) — lexicographic byte comparison
  const cmp = Buffer.compare(Buffer.from(a), Buffer.from(b));
  const [lo, hi] = cmp <= 0 ? [a, b] : [b, a];
  const combined = new Uint8Array(64);
  combined.set(lo, 0);
  combined.set(hi, 32);
  return sha256(combined);
}

/**
 * Build a sorted-pair Merkle tree from leaf hashes and return the root (hex).
 * This is the same algorithm used in `layer2_market/mod.rs` and the Dealer SDK.
 */
export function buildMerkleRoot(leaves: Uint8Array[]): string {
  if (leaves.length === 0) throw new Error("Cannot build Merkle tree from 0 leaves");
  if (leaves.length === 1) return bytesToHex(leaves[0]);

  let level = [...leaves];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashPair(level[i], level[i + 1]));
      } else {
        // Odd node: promote as-is
        next.push(level[i]);
      }
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/** Convenience: build root directly from RollupLeaf array. */
export function buildMerkleRootFromLeaves(rollupId: string, leaves: RollupLeaf[]): string {
  return buildMerkleRoot(leaves.map((l) => hashLeaf(rollupId, l)));
}

// ── Signing Helpers ────────────────────────────────────────────────────────

async function signMessage(message: string, privateKeyHex: string): Promise<string> {
  const privBytes = hexToBytes(privateKeyHex);
  const msgBytes = new TextEncoder().encode(message);
  const sig = await ed.signAsync(msgBytes, privBytes);
  return bytesToHex(sig);
}

function generateNonce(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

// ── submit_root ────────────────────────────────────────────────────────────

export interface SubmitRootResult {
  ok: boolean;
  batchId: number;
  merkleRoot: string;
  slot?: number;
  error?: string;
}

/**
 * Sign and submit a Merkle state root to `POST /rollup/:rollup_id/submit_root`.
 *
 * Canonical signed message:
 *   `ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{timestamp}:{nonce}`
 */
export async function submitStateRoot(
  config: SequencerConfig,
  batchId: number,
  merkleRoot: string
): Promise<SubmitRootResult> {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  const { rollupId, l1HttpUrl, keypair } = config;

  const message = `ROLLUP_SUBMIT_ROOT:${rollupId}:${batchId}:${merkleRoot}:${timestamp}:${nonce}`;
  const signature = await signMessage(message, keypair.privateKeyHex);

  const body = {
    batch_id: batchId,
    merkle_root_hex: merkleRoot,
    public_key: keypair.publicKeyHex,
    signature,
    timestamp,
    nonce,
  };

  const res = await fetch(`${l1HttpUrl}/rollup/${rollupId}/submit_root`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.text().catch(() => res.statusText);
    return { ok: false, batchId, merkleRoot, error: err };
  }

  const json = await res.json();
  return { ok: true, batchId, merkleRoot, slot: json.slot };
}

// ── PoH Tick Loop ──────────────────────────────────────────────────────────

export type BatchSealCallback = (ctx: {
  rollupId: string;
  batchId: number;
  slotSealed: number;
}) => Promise<RollupLeaf[]>;

/**
 * Listens to PoH slot notifications from L1 WebSocket and triggers batch sealing
 * every `slotsPerBatch` slots (default: 25 = 10 s at 400 ms/slot).
 *
 * Usage:
 * ```ts
 * const loop = new PoHTickLoop(config);
 *
 * // Register a callback that returns the current leaves to seal.
 * loop.onBatchReady(async ({ rollupId, batchId, slotSealed }) => {
 *   const leaves = mySequencer.drainPendingLeaves();
 *   const root   = buildMerkleRootFromLeaves(rollupId, leaves);
 *   await submitStateRoot(config, batchId, root);
 *   return leaves; // returned for logging/auditing only
 * });
 *
 * loop.start();
 * // ... later:
 * loop.stop();
 * ```
 */
export class PoHTickLoop {
  private ws: WebSocket | null = null;
  private running = false;
  private reconnectDelay = 1_000; // ms, doubles on each failure

  private slotCount = 0;
  private batchId: number;
  private lastSealedSlot = 0;

  private readonly slotsPerBatch: number;
  private callback: BatchSealCallback | null = null;

  constructor(private readonly config: SequencerConfig) {
    this.slotsPerBatch = config.slotsPerBatch ?? 25;
    this.batchId = 0;
  }

  /** Register the callback invoked when a batch is ready to be sealed. */
  onBatchReady(cb: BatchSealCallback): this {
    this.callback = cb;
    return this;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.connect();
  }

  stop(): void {
    this.running = false;
    this.ws?.close();
    this.ws = null;
  }

  private connect(): void {
    const ws = new WebSocket(this.config.l1WsUrl);
    this.ws = ws;

    ws.onopen = () => {
      this.reconnectDelay = 1_000; // reset back-off on success
      // Subscribe to slot notifications
      ws.send(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "slotSubscribe", params: [] }));
      console.log(
        `[${this.config.rollupId}] PoHTickLoop connected. Batch interval: ${this.slotsPerBatch} slots (${(this.slotsPerBatch * POH_SLOT_MS) / 1000}s)`
      );
    };

    ws.onmessage = (event) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(event.data as string);
      } catch {
        return;
      }

      if (msg.method !== "slotNotification") return;

      const params = msg.params as { result?: { slot?: number } } | undefined;
      const slot = params?.result?.slot;
      if (typeof slot !== "number") return;

      this.slotCount++;

      if (this.slotCount >= this.slotsPerBatch) {
        this.slotCount = 0;
        this.lastSealedSlot = slot;
        const sealBatchId = ++this.batchId;
        this.sealBatch(sealBatchId, slot);
      }
    };

    ws.onerror = (err) => {
      console.error(`[${this.config.rollupId}] PoHTickLoop WS error:`, err);
    };

    ws.onclose = () => {
      if (!this.running) return;
      console.warn(
        `[${this.config.rollupId}] PoHTickLoop disconnected. Reconnecting in ${this.reconnectDelay}ms…`
      );
      setTimeout(() => {
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000);
        this.connect();
      }, this.reconnectDelay);
    };
  }

  private sealBatch(batchId: number, slotSealed: number): void {
    if (!this.callback) {
      console.warn(`[${this.config.rollupId}] No onBatchReady callback registered — skipping seal.`);
      return;
    }

    const { rollupId } = this.config;
    console.log(`[${rollupId}] Sealing batch #${batchId} at slot ${slotSealed}`);

    this.callback({ rollupId, batchId, slotSealed }).catch((err) => {
      console.error(`[${rollupId}] Batch seal error (batch #${batchId}):`, err);
    });
  }
}

// ── Example: Minimal L2 Sequencer ─────────────────────────────────────────
// (Copy and adapt this pattern for your L2/L3/L5 sequencer process)

/*
import { PoHTickLoop, buildMerkleRootFromLeaves, submitStateRoot } from "./sequencer.sdk.js";

const SEQUENCER_CONFIG = {
  rollupId: "L2",
  slotsPerBatch: 25,                          // 10 s batches
  l1HttpUrl: "http://localhost:8080",
  l1WsUrl:   "ws://localhost:8080/ws",
  keypair: {
    publicKeyHex:  process.env.L2_SEQUENCER_PUBKEY!,
    privateKeyHex: process.env.L2_SEQUENCER_PRIVKEY!,
  },
};

// In-memory trade queue (your sequencer appends here as trades arrive)
const pendingLeaves: RollupLeaf[] = [];

const loop = new PoHTickLoop(SEQUENCER_CONFIG);

loop.onBatchReady(async ({ rollupId, batchId, slotSealed }) => {
  // 1. Drain current pending state
  const snapshot = pendingLeaves.splice(0);
  if (snapshot.length === 0) {
    console.log(`[${rollupId}] Slot ${slotSealed}: no trades this batch — skipping root submission.`);
    return snapshot;
  }

  // 2. Build root
  const merkleRoot = buildMerkleRootFromLeaves(rollupId, snapshot);
  console.log(`[${rollupId}] Batch #${batchId}: ${snapshot.length} leaves → root ${merkleRoot}`);

  // 3. Anchor to L1
  const result = await submitStateRoot(SEQUENCER_CONFIG, batchId, merkleRoot);
  if (!result.ok) {
    console.error(`[${rollupId}] submit_root failed:`, result.error);
    // Re-queue on failure (optional: your retry strategy)
    pendingLeaves.unshift(...snapshot);
  } else {
    console.log(`[${rollupId}] Root anchored at L1 slot ${result.slot}`);
  }

  return snapshot;
});

loop.start();
*/
