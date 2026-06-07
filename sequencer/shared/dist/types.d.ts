/** Rollup layer identifiers recognized by the L1 Universal Rollup Hub. */
export type RollupId = 'L2' | 'L3' | 'L5';
/**
 * Ed25519 keypair using 32-byte keys as lowercase hex strings.
 * Compatible with @noble/curves — private key is the 32-byte seed, NOT the
 * 64-byte NaCl concatenated format.
 */
export interface SequencerKeypair {
    /** 32-byte Ed25519 seed — 64-char lowercase hex. */
    privateKeyHex: string;
    /** 32-byte Ed25519 public key — 64-char lowercase hex. */
    publicKeyHex: string;
}
/** Runtime configuration passed to every sequencer function. */
export interface SequencerConfig {
    /** Which rollup this sequencer manages. */
    rollupId: RollupId;
    /** BlackBook L1 HTTP API base URL, e.g. "https://layer1.blackbook.id". */
    l1HttpUrl: string;
    /**
     * BlackBook L1 WebSocket URL for slot notifications.
     * e.g. "wss://layer1.blackbook.id/ws"
     * Sends `slotSubscribe` → receives `slotNotification` push events.
     */
    l1WsUrl: string;
    /** Absolute path to the per-rollup SQLite database file. */
    dbPath: string;
    /**
     * Sequencer Ed25519 keypair.
     * publicKeyHex must match the value in the L1 env var
     * (L2_SEQUENCER_PUBKEY / L3_SEQUENCER_PUBKEY / L5_SEQUENCER_PUBKEY).
     */
    keypair: SequencerKeypair;
    /** HTTP port this sequencer listens on. Recommended: L2=7072, L3=7073, L5=7075. */
    port: number;
    /** Seal a new batch every N L1 slots. Default: 25. */
    slotsPerBatch: number;
}
/** $BB balance entry — becomes a BB Merkle leaf. */
export interface BbEntry {
    type: 'BB';
    address: string;
    /** Off-chain balance in lamports (1 BB = 100_000 lamports). */
    lamports: bigint;
}
/** NFT ownership entry — becomes an NFT Merkle leaf. */
export interface NftEntry {
    type: 'NFT';
    collectionId: string;
    tokenId: string;
    owner: string;
    metadataHash: string;
}
export type MerkleEntry = BbEntry | NftEntry;
/** Lock record as returned by `GET /rollup/:rollup_id/locks/:lock_id`. */
export interface L1LockRecord {
    lock_id: string;
    rollup_id: string;
    /** L1 wallet (base58) that locked the $BB. L1 serializes this as creator_address. */
    creator_address: string;
    bb_lamports: number;
    token_symbol_hint: string | null;
    locked_at: number;
    vault_address: string;
    consumed: boolean;
}
/** Merkle tree output produced by `buildMerkleTree`. */
export interface MerkleTree {
    /** 64-char lowercase hex SHA-256 root. */
    root: string;
    /** Hashed leaves (64-char lowercase hex) in original input order (not padded). */
    leaves: string[];
    /** proofs[i] = ordered sibling hex digests for leaf i (leaf → root). */
    proofs: string[][];
}
//# sourceMappingURL=types.d.ts.map