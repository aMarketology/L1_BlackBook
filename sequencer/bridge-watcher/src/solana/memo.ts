import type { SolanaTransaction } from "./rpc.js";

// Both v1 and v2 Solana Memo program IDs
const MEMO_PROGRAMS = new Set([
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
]);

// Base58 decode table (Bitcoin alphabet)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_MAP = new Map<string, number>(
  [...BASE58_ALPHABET].map((c, i) => [c, i])
);

function decodeBase58(encoded: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of encoded) {
    const digit = BASE58_MAP.get(char);
    if (digit === undefined) throw new Error(`Invalid base58 char: ${char}`);
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading zeros
  for (const char of encoded) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

/**
 * Extract the first memo instruction data from a transaction as a UTF-8 string.
 * Returns null if no memo instruction is present.
 */
export function extractMemoText(tx: SolanaTransaction): string | null {
  const { transaction } = tx;
  const keys = transaction.message.accountKeys;

  for (const ix of transaction.message.instructions) {
    const programPubkey = keys[ix.programIdIndex]?.pubkey;
    if (!programPubkey || !MEMO_PROGRAMS.has(programPubkey)) continue;

    // The instruction data IS the memo — base58-encoded UTF-8 bytes
    try {
      const bytes = decodeBase58(ix.data);
      return new TextDecoder("utf-8").decode(bytes);
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Expected memo format: `bb:<BB_wallet_address>` (case-insensitive prefix).
 * Returns the wallet address portion, or null if the memo doesn't match.
 */
export function parseBBMemo(memo: string | null): string | null {
  if (!memo) return null;
  const trimmed = memo.trim();
  const lower = trimmed.toLowerCase();
  if (!lower.startsWith("bb:")) return null;
  const addr = trimmed.slice(3).trim();
  return isValidBBAddress(addr) ? addr : null;
}

/**
 * Validates a BlackBook L1 wallet address.
 * Must be a non-empty string of printable ASCII, 32–64 chars.
 * The L1 node enforces the definitive check; this is a fast pre-filter.
 */
export function isValidBBAddress(addr: string): boolean {
  return /^[A-Za-z0-9]{32,64}$/.test(addr);
}
