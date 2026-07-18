// ─── Shared types ─────────────────────────────────────────────────────────────
export * from './types.js';
// ─── Ed25519 signing ──────────────────────────────────────────────────────────
export { signMessage } from './signing.js';
// ─── Merkle tree ──────────────────────────────────────────────────────────────
export { buildLeafBytes, hashLeafBytes, buildMerkleTree, verifyProof } from './merkle.js';
// ─── L1 HTTP client ───────────────────────────────────────────────────────────
// getLock     = read a lock record from L1 (network call)
// consumeLock = mark a lock consumed on L1 (authenticated, network call)
// submitRoot  = anchor a Merkle root on L1  (authenticated, network call)
// submitOraclePendingRoot = submit market outcome to Oracle dispute window
export { L1Error, getLock, consumeLock, submitRoot, submitOraclePendingRoot, pushPayoutsToL1 } from './l1Client.js';
// ─── Local SQLite helpers ─────────────────────────────────────────────────────
// "Local" prefix distinguishes DB reads from the L1 network calls above.
export { openDb, upsertLock, getLocalLock, consumeLockLocal, creditBalance, getBalance, sealBatch, getLatestBatchId, getSlotWatermark, setSlotWatermark, } from './db.js';
//# sourceMappingURL=index.js.map