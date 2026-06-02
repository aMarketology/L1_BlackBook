import type { SolanaTransaction, TokenBalance } from "./rpc.js";

export interface TokenTransfer {
  /** SPL mint address */
  mint: string;
  /** Owner of the destination token account (i.e. who received the tokens) */
  toOwner: string;
  /** Net increase in micro-units (postAmount - preAmount). Always positive. */
  amountMicro: bigint;
  /** Slot the transfer was included in */
  slot: number;
}

/**
 * Extract all SPL token inflows to `custodyWallet` from a finalized transaction.
 *
 * Strategy: compare preTokenBalances vs postTokenBalances.
 * For each account index where:
 *   - owner == custodyWallet
 *   - post > pre  (net inflow)
 * we emit a TokenTransfer.
 *
 * This handles routed transfers (e.g. via associated token programs) transparently
 * because `preTokenBalances` / `postTokenBalances` always reflect the final state
 * of each token account regardless of instruction complexity.
 */
export function extractInflows(
  tx: SolanaTransaction,
  custodyWallet: string,
  watchedMints: Set<string>
): TokenTransfer[] {
  const { meta, slot } = tx;
  if (!meta) return [];

  const preMap = new Map<number, TokenBalance>();
  for (const b of meta.preTokenBalances) {
    preMap.set(b.accountIndex, b);
  }

  const transfers: TokenTransfer[] = [];

  for (const post of meta.postTokenBalances) {
    if (!post.owner) continue;
    if (post.owner !== custodyWallet) continue;
    if (!watchedMints.has(post.mint)) continue;

    const pre = preMap.get(post.accountIndex);
    const postAmt = BigInt(post.uiTokenAmount.amount);
    const preAmt  = pre ? BigInt(pre.uiTokenAmount.amount) : 0n;

    if (postAmt <= preAmt) continue;  // No net inflow

    transfers.push({
      mint: post.mint,
      toOwner: post.owner,
      amountMicro: postAmt - preAmt,
      slot,
    });
  }

  return transfers;
}
