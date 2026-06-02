import type { AttributedDeposit } from "../attribution.js";

/**
 * Canonical deposit message sent to the L1 bridge endpoint (M3 — Model A).
 * Format: `BRIDGE_DEPOSIT:{tx_hash}:{wallet}:{asset}:{amount_micro}:{timestamp}:{nonce}`
 *
 * The L1 node verifies the bridge-authority signature over this exact string
 * before minting any $BB. Change any field and the signature is invalid.
 */
export function buildBridgeDepositMessage(dep: AttributedDeposit, nonce: string): string {
  const ts = Date.now();
  return `BRIDGE_DEPOSIT:${dep.sig}:${dep.bbWallet}:${dep.asset}:${dep.amountMicro}:${ts}:${nonce}`;
}

/**
 * Body for `POST /bridge/deposit` (Model A — M3).
 */
export interface BridgeDepositBody {
  tx_hash: string;
  wallet: string;
  asset: string;
  amount_micro: string;   // BigInt serialised as decimal string — no JS float
  slot: number;
  message: string;        // canonical string above
  signature: string;      // hex Ed25519 signature of message
  nonce: string;
}

export function buildDepositBody(
  dep: AttributedDeposit,
  message: string,
  signature: string,
  nonce: string
): BridgeDepositBody {
  return {
    tx_hash: dep.sig,
    wallet: dep.bbWallet,
    asset: dep.asset,
    amount_micro: dep.amountMicro.toString(),
    slot: dep.slot,
    message,
    signature,
    nonce,
  };
}
