export * from './types.js';
export { signMessage } from './signing.js';
export { buildLeafPreimage, hashLeaf, buildMerkleTree, verifyProof } from './merkle.js';
export { L1Error, getLock, consumeLock, submitRoot } from './l1Client.js';
export { openDb, upsertLock, getLocalLock, consumeLockLocal, creditBalance, getBalance, sealBatch, getLatestBatchId, getSlotWatermark, setSlotWatermark, } from './db.js';
export type { LockRow, DatabaseType } from './db.js';
//# sourceMappingURL=index.d.ts.map