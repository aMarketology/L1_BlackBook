/**
 * Sign a canonical BlackBook L1 message with an Ed25519 private key.
 *
 * Uses @noble/curves — compatible with the L1 Rust `ed25519-dalek` verifier.
 * The private key must be the 32-byte seed (NOT the 64-byte NaCl combined format).
 *
 * @param message       UTF-8 canonical message string.
 * @param privateKeyHex 32-byte Ed25519 seed as 64-char lowercase hex.
 * @returns             64-byte signature as 128-char lowercase hex.
 */
export declare function signMessage(message: string, privateKeyHex: string): string;
//# sourceMappingURL=signing.d.ts.map