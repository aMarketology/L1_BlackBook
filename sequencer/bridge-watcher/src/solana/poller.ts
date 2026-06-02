import type { SolanaRpcClient, SignatureInfo } from "./rpc.js";

/**
 * Fetch all signatures for `address` that are newer than `cursor`.
 *
 * Solana's `getSignaturesForAddress` returns signatures newest-first.
 * We paginate backwards until we reach `cursor` (the last processed sig),
 * then reverse so we process oldest-first.
 *
 * Returns an empty array if nothing new is found.
 */
export async function fetchNewSignatures(
  rpc: SolanaRpcClient,
  address: string,
  cursor: string | null,
  pageSize: number
): Promise<SignatureInfo[]> {
  const collected: SignatureInfo[] = [];
  let before: string | undefined = undefined;

  while (true) {
    const page = await rpc.getSignaturesForAddress(address, {
      limit: pageSize,
      before,
      ...(cursor ? { until: cursor } : {}),
    });

    if (page.length === 0) break;

    // Filter out errors (failed transactions)
    const valid = page.filter((s) => s.err === null);
    collected.push(...valid);

    // If we got fewer results than pageSize we've reached the end
    if (page.length < pageSize) break;

    // Continue pagination from the oldest sig in this page
    before = page[page.length - 1].signature;
  }

  // Return oldest-first so we process in chronological order
  return collected.reverse();
}
