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
//# sourceMappingURL=l1Client.js.map