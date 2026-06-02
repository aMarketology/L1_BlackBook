/**
 * Bridge-authority Ed25519 signing — M3 stub.
 *
 * In M3, the watcher will load a dedicated Ed25519 keypair
 * (BRIDGE_AUTHORITY_PRIVATE_KEY env) and sign the canonical deposit message.
 * The L1 node verifies the signature against BRIDGE_AUTHORITY_PUBKEY before minting.
 *
 * This file is a stub for M0–M2 where Model B (user-signed) is used.
 * Replace the body of `sign()` when implementing M3.
 */

export async function sign(_message: string): Promise<string> {
  throw new Error(
    "Bridge-authority signing not yet implemented (M3). " +
    "For now, use Model B: user submits POST /deposit/request and the watcher drives finalization."
  );
}

export async function loadPublicKey(): Promise<string> {
  throw new Error("Bridge-authority public key not yet configured (M3).");
}
