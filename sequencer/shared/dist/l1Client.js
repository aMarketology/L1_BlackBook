import { signMessage } from './signing.js';
// ─── Error type ────────────────────────────────────────────────────────────────
export class L1Error extends Error {
    status;
    body;
    constructor(message, status, body) {
        super(message);
        this.status = status;
        this.body = body;
        this.name = 'L1Error';
    }
}
// ─── Internal POST helper ──────────────────────────────────────────────────────
async function httpPost(url, body) {
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) {
        throw new L1Error(json.error ?? `L1 returned HTTP ${res.status}`, res.status, json);
    }
    return json;
}
// ─── Public API ────────────────────────────────────────────────────────────────
/**
 * Read a lock record directly from L1.
 * `GET /rollup/:rollupId/locks/:lockId`
 *
 * Use this to verify a lock exists and is unconsumed before crediting the
 * user's off-chain balance in the local DB.
 */
export async function getLock(config, lockId) {
    const url = `${config.l1HttpUrl}/rollup/${config.rollupId}/locks/${lockId}`;
    const res = await fetch(url);
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new L1Error(`getLock(${lockId}) returned HTTP ${res.status}`, res.status, body);
    }
    return res.json();
}
/**
 * Mark a lock as consumed on L1 (idempotent — safe to retry).
 * `POST /rollup/:rollupId/locks/:lockId/consume`
 *
 * Canonical signed message (no nonce):
 *   `"CONSUME_LOCK:{rollup_id}:{lock_id}:{timestamp}"`
 *
 * Workflow: credit the user's local balance first, then call this.
 * If L1 returns 2xx or 409 (already consumed), treat as success.
 * After success call `consumeLockLocal()` in the local DB.
 */
export async function consumeLock(config, lockId) {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `CONSUME_LOCK:${config.rollupId}:${lockId}:${timestamp}`;
    const signature = signMessage(message, config.keypair.privateKeyHex);
    await httpPost(`${config.l1HttpUrl}/rollup/${config.rollupId}/locks/${lockId}/consume`, {
        sequencer_public_key: config.keypair.publicKeyHex,
        signature,
        timestamp,
    });
}
/**
 * Anchor a Merkle state root on L1.
 * `POST /rollup/:rollupId/submit_root`
 *
 * Canonical signed message (no nonce):
 *   `"ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{timestamp}"`
 *
 * @param batchId        Monotonically increasing batch identifier (per rollup).
 * @param merkleRootHex  64-char lowercase hex SHA-256 Merkle root.
 */
export async function submitRoot(config, batchId, merkleRootHex) {
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `ROLLUP_SUBMIT_ROOT:${config.rollupId}:${batchId}:${merkleRootHex}:${timestamp}`;
    const signature = signMessage(message, config.keypair.privateKeyHex);
    await httpPost(`${config.l1HttpUrl}/rollup/${config.rollupId}/submit_root`, {
        batch_id: batchId,
        merkle_root_hex: merkleRootHex,
        sequencer_public_key: config.keypair.publicKeyHex,
        signature,
        timestamp,
    });
}
/**
 * Submit a market outcome to the L1 Oracle dispute window.
 * `POST /oracle/submit-pending-root`
 *
 * Call this AFTER `submitRoot()` succeeds for a resolved market.
 * The L1 Oracle opens a 60-second dispute window; if no discard supermajority
 * forms the outcome auto-finalizes and becomes queryable via GET /oracle/event/:id.
 *
 * Canonical signed message (no separate nonce — batchId + timestamp is unique):
 *   `"ORACLE_SUBMIT:{rollup_id}:{market_id}:{outcome}:{merkle_root_hex}:{batch_id}:{ts}:{nonce}"`
 *
 * @param marketId       L2 market ID (same as used in createMarket / resolveMarket).
 * @param outcome        "YES" | "NO" | "REFUND"
 * @param merkleRootHex  64-char hex root — must match the submitRoot call exactly.
 * @param batchId        Rollup Hub batch_id from the sealAndSubmit result.
 */
export async function submitOraclePendingRoot(config, marketId, outcome, merkleRootHex, batchId) {
    const timestamp = Math.floor(Date.now() / 1000);
    // Use batchId as the nonce — monotonically increasing, unique per market + rollup.
    const nonce = String(batchId);
    const message = `ORACLE_SUBMIT:${config.rollupId}:${marketId}:${outcome}:${merkleRootHex}:${batchId}:${timestamp}:${nonce}`;
    const signature = signMessage(message, config.keypair.privateKeyHex);
    await httpPost(`${config.l1HttpUrl}/oracle/submit-pending-root`, {
        rollup_id: config.rollupId,
        market_id: marketId,
        outcome,
        merkle_root_hex: merkleRootHex,
        batch_id: batchId,
        public_key: config.keypair.publicKeyHex,
        signature,
        timestamp,
        nonce,
    });
}
/**
 * Push winner payouts to L1 wallets after market resolution.
 *
 * Calls `POST /escrow/push_payouts` on the L1 node, which verifies each
 * winner's Merkle proof against the already-anchored rollup state root and
 * transfers BB lamports from the shared escrow vault into each winner's
 * native L1 wallet atomically.
 *
 * Must be called AFTER `submitRoot()` so the stored root exists on L1.
 *
 * Canonical signed message (UTF-8):
 *   `"PUSH_PAYOUTS:{contest_id}:{batch_id}:{timestamp}:{nonce}"`
 *
 * @param contestId   L2 market ID.
 * @param batchId     Rollup batch_id returned by sealAndSubmit.
 * @param payouts     Array of { wallet (base58), amountBb (lamports), proof (hex strings) }.
 */
export async function pushPayoutsToL1(config, contestId, batchId, payouts) {
    if (payouts.length === 0)
        return;
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = `${batchId}-${timestamp}`;
    const message = `PUSH_PAYOUTS:${contestId}:${batchId}:${timestamp}:${nonce}`;
    const signature = signMessage(message, config.keypair.privateKeyHex);
    await httpPost(`${config.l1HttpUrl}/escrow/push_payouts`, {
        contest_id: contestId,
        batch_id: batchId,
        public_key: config.keypair.publicKeyHex,
        signature,
        timestamp,
        nonce,
        payouts: payouts.map(p => ({
            wallet: p.wallet,
            amount_bb: Number(p.amountBb),
            proof: p.proof,
        })),
    });
}
//# sourceMappingURL=l1Client.js.map