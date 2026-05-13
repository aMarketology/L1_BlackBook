// ============================================================================
// BLACKBOOK × MAYAN CROSS-CHAIN DEPOSIT SDK
// ============================================================================
//
// Wraps @mayanfinance/swap-sdk so the frontend can swap ETH/USDT from any
// EVM chain → Solana custody wallet WITH the user's BB L1 address embedded
// as a 34-byte customPayload.
//
// Wire format (must match src/watcher/mayan.rs exactly):
//   Byte 0:    0xBB   ← magic[0]
//   Byte 1:    0x01   ← magic[1] (version)
//   Bytes 2-33: Ed25519 pubkey (32 bytes, big-endian raw)
//
// Backend path:
//   1. Mayan routes ETH-side swap → USDT lands in Solana custody wallet
//   2. CustodyWatcher fetches tx via getTransaction (jsonParsed)
//   3. scan_tx_instructions_for_mayan_payload() scans every instruction's
//      base58 data for 0xBB01 magic → decodes BB wallet → mints $BB
//
// Usage (React / TypeScript):
//   const payload = encodeBBWalletPayload(bbWallet);  // Uint8Array (34 bytes)
//   const quote   = await fetchBBDepositQuote({ ... });
//   const txHash  = await executeBBDeposit({ quote, signer, payload, ... });
//
// Env vars needed at runtime (set in .env):
//   VITE_SOLANA_CUSTODY_ADDRESS  — Solana wallet that receives the USDT
//   VITE_MAYAN_API_KEY           — optional, prevents IP rate-limiting
//   VITE_MAYAN_REFERRER_SOLANA   — optional, base58 Solana referrer address
// ============================================================================

import {
  fetchQuote,
  swapFromEvm,
  getSwapFromEvmTxPayload,
  type Quote,
  type QuoteParams,
  type ReferrerAddresses,
  type Erc20Permit,
  type ChainName,
} from "@mayanfinance/swap-sdk";
import type { Signer, Overrides } from "ethers";

// ── Constants ─────────────────────────────────────────────────────────────────

/** Magic header that identifies a BlackBook customPayload (2 bytes). */
export const BB_PAYLOAD_MAGIC = new Uint8Array([0xbb, 0x01]);

/** Total payload length: 2-byte magic + 32-byte Ed25519 pubkey. */
export const BB_PAYLOAD_LEN = 34;

// ── Codec (mirrors src/watcher/mayan.rs) ─────────────────────────────────────

/**
 * Encode a base58 BB L1 wallet address into a 34-byte Mayan customPayload.
 *
 * Throws if `l1Wallet` is not a valid 32-byte base58 pubkey.
 */
export function encodeBBWalletPayload(l1Wallet: string): Uint8Array {
  const raw = base58Decode(l1Wallet);
  if (raw.length !== 32) {
    throw new Error(
      `BB wallet must decode to 32 bytes; got ${raw.length} bytes for "${l1Wallet}"`
    );
  }
  const payload = new Uint8Array(BB_PAYLOAD_LEN);
  payload[0] = 0xbb;
  payload[1] = 0x01;
  payload.set(raw, 2);
  return payload;
}

/**
 * Decode a 34-byte Mayan customPayload back into a BB L1 wallet address.
 * Returns `null` if the magic header is missing or the pubkey is all-zero.
 */
export function decodeBBWalletPayload(raw: Uint8Array): string | null {
  if (raw.length < BB_PAYLOAD_LEN) return null;
  if (raw[0] !== 0xbb || raw[1] !== 0x01) return null;
  const pubkeyBytes = raw.slice(2, 34);
  if (pubkeyBytes.every((b) => b === 0)) return null;
  return base58Encode(pubkeyBytes);
}

// ── Quote helper ──────────────────────────────────────────────────────────────

export interface BBDepositQuoteParams {
  /** Amount of the input token, as a decimal string in base units.
   *  E.g. "1000000" for 1 USDT (6 decimals). */
  amountIn64: string;
  /** EVM token contract address of the asset to swap FROM (e.g. USDT on ETH). */
  fromTokenContract: string;
  /** Source EVM chain name (e.g. "ethereum", "bsc", "arbitrum"). */
  fromChain: ChainName;
  /** Optional slippage in basis points.  Defaults to "auto". */
  slippageBps?: number | "auto";
  /** Optional Mayan API key (prevents IP-based rate limiting). */
  apiKey?: string;
}

/**
 * Fetch all available Mayan quotes for a USDT/USDC → Solana deposit.
 *
 * The destination is always native USDC on Solana (the custody wallet receives
 * USDT/USDC, and the watcher mints BB from the on-chain amount).
 *
 * Returns the full sorted array from Mayan — the caller should pick [0] for
 * the best route or let the user choose.
 */
export async function fetchBBDepositQuotes(
  params: BBDepositQuoteParams
): Promise<Quote[]> {
  const custodyAddress = getCustodyAddress();

  const quoteParams: QuoteParams = {
    amountIn64: params.amountIn64,
    fromToken: params.fromTokenContract,
    fromChain: params.fromChain,
    // Native USDC on Solana — the custody wallet holds USDC/USDT.
    toToken: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    toChain: "solana",
    slippageBps: params.slippageBps ?? "auto",
    referrer: getMayanReferrer() ?? undefined,
    apiKey: params.apiKey ?? getMayanApiKey() ?? undefined,
  };

  return fetchQuote(quoteParams);
}

// ── Swap execution ────────────────────────────────────────────────────────────

export interface BBDepositParams {
  /** Best quote (element [0] from fetchBBDepositQuotes). */
  quote: Quote;
  /** Ethers.js v6 Signer connected to the user's EVM wallet. */
  signer: Signer;
  /** The user's BlackBook L1 wallet address (base58, 32 bytes).
   *  This is embedded as the Mayan customPayload so the watcher can
   *  auto-attribute the incoming USDT → mint $BB with zero user friction. */
  bbL1Wallet: string;
  /** Optional ERC-20 permit (for tokens that support EIP-2612). */
  permit?: Erc20Permit;
  /** Optional Ethers gas overrides (gasLimit, maxFeePerGas, etc.). */
  gasOverrides?: Overrides;
  /** Optional Mayan API key. */
  apiKey?: string;
}

/**
 * Build and send a cross-chain swap via Mayan with the BB wallet embedded
 * as a `customPayload`.
 *
 * Returns the EVM transaction hash (string) for SWIFT gasless swaps, or a
 * TransactionResponse for all other quote types.
 *
 * After the swap completes (track via Mayan Explorer API or `pollBBDepositStatus`),
 * the BlackBook L1 CustodyWatcher will detect the `customPayload` in the
 * Solana delivery transaction and automatically mint $BB to `bbL1Wallet`.
 */
export async function executeBBDeposit(
  params: BBDepositParams
): Promise<string> {
  const custodyAddress = getCustodyAddress();
  const payload = encodeBBWalletPayload(params.bbL1Wallet);

  const referrerAddresses: ReferrerAddresses = {
    solana: getMayanReferrer() ?? undefined,
    evm: undefined,
  };

  const result = await swapFromEvm(
    params.quote,
    await params.signer.getAddress(), // swapperAddress (EVM sender)
    custodyAddress,                   // destinationAddress = Solana custody
    referrerAddresses,
    params.signer,
    params.permit ?? null,
    params.gasOverrides ?? null,
    payload,                          // ← 34-byte BB customPayload
    params.apiKey ? { apiKey: params.apiKey } : undefined
  );

  // For SWIFT gasless, Mayan returns the orderHash string directly.
  // For all other types, result is an ethers TransactionResponse.
  if (typeof result === "string") return result;
  return result.hash;
}

/**
 * Build the raw EVM transaction payload without sending.
 * Useful when the caller wants to inspect or bundle the transaction manually.
 */
export async function buildBBDepositTxPayload(params: BBDepositParams) {
  const custodyAddress = getCustodyAddress();
  const payload = encodeBBWalletPayload(params.bbL1Wallet);
  const signerAddress = await params.signer.getAddress();
  const chainId = Number((await params.signer.provider!.getNetwork()).chainId);

  const referrerAddresses: ReferrerAddresses = {
    solana: getMayanReferrer() ?? undefined,
    evm: undefined,
  };

  return getSwapFromEvmTxPayload(
    params.quote,
    signerAddress,
    custodyAddress,
    referrerAddresses,
    signerAddress,
    chainId,
    payload,
    params.permit ?? null,
    params.apiKey ? { apiKey: params.apiKey } : undefined
  );
}

// ── Tracking ──────────────────────────────────────────────────────────────────

export type MayanSwapStatus = "INPROGRESS" | "COMPLETED" | "REFUNDED";

export interface MayanTrackResult {
  clientStatus: MayanSwapStatus;
  sourceTxHash: string | null;
  destTxHash: string | null;
  sourceChain: string | null;
  destChain: string | null;
}

/**
 * Fetch the current status of a cross-chain swap from the Mayan Explorer API.
 *
 * @param evmTxHash  The EVM transaction hash returned by `executeBBDeposit`.
 */
export async function trackBBDeposit(
  evmTxHash: string
): Promise<MayanTrackResult> {
  const url = `https://explorer-api.mayan.finance/v3/swap/trx/${evmTxHash}`;
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Mayan Explorer API error ${resp.status}: ${await resp.text()}`);
  }
  const data = await resp.json();
  return {
    clientStatus: data.clientStatus ?? "INPROGRESS",
    sourceTxHash: data.sourceTxHash ?? null,
    destTxHash: data.destTxHash ?? null,
    sourceChain: data.sourceChain ?? null,
    destChain: data.destChain ?? null,
  };
}

/**
 * Poll `trackBBDeposit` every `intervalMs` until status is COMPLETED or
 * REFUNDED, or until `timeoutMs` elapses.
 *
 * @returns Final `MayanTrackResult` when complete.
 * @throws  If the timeout elapses before completion.
 */
export async function pollBBDepositStatus(
  evmTxHash: string,
  intervalMs = 5_000,
  timeoutMs = 10 * 60_000
): Promise<MayanTrackResult> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = await trackBBDeposit(evmTxHash);
    if (status.clientStatus === "COMPLETED" || status.clientStatus === "REFUNDED") {
      return status;
    }
    await sleep(intervalMs);
  }
  throw new Error(`BB deposit ${evmTxHash} did not complete within ${timeoutMs / 1000}s`);
}

// ── Convenience re-exports ────────────────────────────────────────────────────

/** Full deposit flow in one call: quote best route → execute with BB payload. */
export async function depositBBOneShot(params: {
  amountIn64: string;
  fromTokenContract: string;
  fromChain: ChainName;
  signer: Signer;
  bbL1Wallet: string;
  slippageBps?: number | "auto";
  apiKey?: string;
}): Promise<{ txHash: string; quote: Quote }> {
  const quotes = await fetchBBDepositQuotes({
    amountIn64: params.amountIn64,
    fromTokenContract: params.fromTokenContract,
    fromChain: params.fromChain,
    slippageBps: params.slippageBps,
    apiKey: params.apiKey,
  });

  if (!quotes.length) {
    throw new Error("No Mayan routes available for this token/chain combination");
  }

  const quote = quotes[0];
  const txHash = await executeBBDeposit({
    quote,
    signer: params.signer,
    bbL1Wallet: params.bbL1Wallet,
    apiKey: params.apiKey,
  });

  return { txHash, quote };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function getCustodyAddress(): string {
  // Vite env var (build-time injection from .env)
  const addr =
    (typeof import.meta !== "undefined" &&
      (import.meta as Record<string, unknown>).env &&
      ((import.meta as Record<string, unknown>).env as Record<string, string>)
        .VITE_SOLANA_CUSTODY_ADDRESS) ||
    process.env.SOLANA_CUSTODY_ADDRESS ||
    "";
  if (!addr) {
    throw new Error(
      "VITE_SOLANA_CUSTODY_ADDRESS (or SOLANA_CUSTODY_ADDRESS) is not set — " +
        "set it to the Solana address that receives cross-chain deposits"
    );
  }
  return addr;
}

function getMayanApiKey(): string | null {
  try {
    return (
      ((import.meta as Record<string, unknown>).env as Record<string, string>)
        ?.VITE_MAYAN_API_KEY ?? null
    );
  } catch {
    return process.env.MAYAN_API_KEY ?? null;
  }
}

function getMayanReferrer(): string | null {
  try {
    return (
      ((import.meta as Record<string, unknown>).env as Record<string, string>)
        ?.VITE_MAYAN_REFERRER_SOLANA ?? null
    );
  } catch {
    return process.env.MAYAN_REFERRER_SOLANA ?? null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Minimal base58 codec (no external dep required) ──────────────────────────
// Matches the alphabet used by Solana / bs58 crate.

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(input: string): Uint8Array {
  let result = BigInt(0);
  const base = BigInt(58);
  for (const char of input) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) throw new Error(`Invalid base58 character: '${char}'`);
    result = result * base + BigInt(digit);
  }
  // Convert BigInt → bytes (big-endian)
  const hex = result.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  // Trim leading zeros added by padding, but keep leading-zero bytes for
  // base58 leading '1' characters.
  const leadingOnes = [...input].filter((c) => c === "1").length;
  const trimmed = bytes.slice(bytes.findIndex((b) => b !== 0));
  return new Uint8Array([...new Uint8Array(leadingOnes), ...trimmed]);
}

function base58Encode(bytes: Uint8Array): string {
  let num = BigInt("0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""));
  let result = "";
  const base = BigInt(58);
  while (num > BigInt(0)) {
    const mod = Number(num % base);
    result = BASE58_ALPHABET[mod] + result;
    num = num / base;
  }
  // Leading zero bytes → leading '1'
  for (const b of bytes) {
    if (b !== 0) break;
    result = "1" + result;
  }
  return result;
}
