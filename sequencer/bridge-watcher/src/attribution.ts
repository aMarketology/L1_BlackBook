import type { SolanaTransaction } from "./solana/rpc.js";
import { extractInflows, type TokenTransfer } from "./solana/parse.js";
import { extractMemoText, parseBBMemo } from "./solana/memo.js";

export interface AttributedDeposit {
  /** Solana transaction signature */
  sig: string;
  /** PoH slot the tx was included in */
  slot: number;
  /** BB wallet address that should receive the minted $BB */
  bbWallet: string;
  /** "USDC" | "USDT" */
  asset: string;
  /** Amount in micro-units (e.g. 1 USDC = 1_000_000) */
  amountMicro: bigint;
  /** Solana SPL mint address */
  mint: string;
}

export interface AttributionResult {
  deposit: AttributedDeposit | null;
  /** Reason for null when ignored */
  ignoreReason?: string;
}

/**
 * Given a finalized transaction, try to attribute it to a BB wallet via memo.
 *
 * Returns:
 *   - `{ deposit }` — valid, attributable deposit
 *   - `{ deposit: null, ignoreReason }` — not a valid custody deposit
 */
export function attributeTx(
  sig: string,
  tx: SolanaTransaction,
  custodyWallet: string,
  watchedMints: Set<string>,
  mintLabels: Map<string, string>,
  minDepositMicro: bigint
): AttributionResult {
  // 1. Extract all token inflows to the custody wallet
  const inflows = extractInflows(tx, custodyWallet, watchedMints);
  if (inflows.length === 0) {
    return { deposit: null, ignoreReason: "no_custody_inflow" };
  }

  // Pick the largest inflow (handles multi-instruction txs gracefully)
  const inflow = inflows.reduce((a, b) => (a.amountMicro > b.amountMicro ? a : b));

  // 2. Dust check
  if (inflow.amountMicro < minDepositMicro) {
    return { deposit: null, ignoreReason: `dust:${inflow.amountMicro}` };
  }

  // 3. Memo attribution
  const memoText = extractMemoText(tx);
  const bbWallet = parseBBMemo(memoText);
  if (!bbWallet) {
    return { deposit: null, ignoreReason: `bad_memo:${JSON.stringify(memoText)}` };
  }

  const asset = mintLabels.get(inflow.mint) ?? inflow.mint.slice(0, 4);

  return {
    deposit: {
      sig,
      slot: inflow.slot,
      bbWallet,
      asset,
      amountMicro: inflow.amountMicro,
      mint: inflow.mint,
    },
  };
}
