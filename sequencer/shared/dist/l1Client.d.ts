import type { SequencerConfig, L1LockRecord } from './types.js';
export declare class L1Error extends Error {
    readonly status: number;
    readonly body: unknown;
    constructor(message: string, status: number, body: unknown);
}
/**
 * Read a lock record directly from L1.
 * `GET /rollup/:rollupId/locks/:lockId`
 *
 * Use this to verify a lock exists and is unconsumed before crediting the
 * user's off-chain balance in the local DB.
 */
export declare function getLock(config: SequencerConfig, lockId: string): Promise<L1LockRecord>;
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
export declare function consumeLock(config: SequencerConfig, lockId: string): Promise<void>;
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
export declare function submitRoot(config: SequencerConfig, batchId: number, merkleRootHex: string): Promise<void>;
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
export declare function submitOraclePendingRoot(config: SequencerConfig, marketId: string, outcome: 'YES' | 'NO' | 'REFUND', merkleRootHex: string, batchId: number): Promise<void>;
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
export declare function pushPayoutsToL1(config: SequencerConfig, contestId: string, batchId: number, payouts: Array<{
    wallet: string;
    amountBb: bigint;
    proof: string[];
}>): Promise<void>;
//# sourceMappingURL=l1Client.d.ts.map