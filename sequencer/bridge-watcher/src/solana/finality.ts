import type { SolanaRpcClient, SolanaTransaction } from "./rpc.js";

/**
 * Fetch a transaction at `finalized` commitment.
 * Returns null if the tx is not yet finalized (caller should retry later).
 * Throws if the Solana RPC call itself fails.
 */
export async function getFinalized(
  rpc: SolanaRpcClient,
  sig: string
): Promise<SolanaTransaction | null> {
  const tx = await rpc.getTransaction(sig);
  if (!tx) return null;                 // Not finalized yet
  if (tx.meta?.err) return null;        // Tx failed on-chain — treat as non-existent
  return tx;
}
