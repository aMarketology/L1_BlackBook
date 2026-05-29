/**
 * BlackBook L5 Token Factory SDK
 *
 * Allows a creator to configure and launch a new Creator Coin on Layer 5.
 * The L1 enforces hard guardrails at launch time:
 *   - tax_rate_bps ≤ 1 000 (10%) — honeypot prevention
 *   - symbol: 2–10 uppercase alphanumeric
 *   - initial_liquidity_bb ≥ 100_000 (1 BB = $0.10)
 *   - bancor_weight_ppm ∈ [10_000, 1_000_000] when curveType == BANCOR_VAMM
 *
 * @example
 * ```ts
 * import { TokenFactory } from './sdk/TokenFactory';
 *
 * const factory = new TokenFactory('http://localhost:8080');
 * const result = await factory.launchCoin(keypair, {
 *   name: 'Agent X Token',
 *   symbol: 'AGENTX',
 *   taxRateBps: 100,           // 1%
 *   taxDestination: 'BURN',
 *   initialLiquidityBB: 500_000n,  // 5 BB
 *   curveType: 'CONSTANT_PRODUCT',
 * });
 * console.log(result.symbol, 'launched at', result.launched_at);
 * ```
 */

import nacl from 'tweetnacl';

// ── CONSTANTS (must match L1 Rust guardrails) ─────────────────────────────────

/** Maximum allowed tax rate in basis points (1 000 bps = 10 %). */
export const MAX_TAX_BPS = 1_000;

/** Minimum $BB lamports required as initial pool liquidity (1 BB). */
export const MIN_INITIAL_LIQUIDITY_BB = 100_000n;

/** Fixed total supply for every Creator Coin (6 decimals, 1 quad base units). */
export const TOTAL_SUPPLY = 1_000_000_000_000_000n;

/** $BB lamports per whole BB (5 decimals: 1 BB = 100_000 lamports). */
export const LAMPORTS_PER_BB = 100_000n;

// ── TYPES ─────────────────────────────────────────────────────────────────────

/** AMM curve type for a Creator Coin pool. */
export type CurveType = 'CONSTANT_PRODUCT' | 'BANCOR_VAMM';

/**
 * Configuration for launching a new Creator Coin on L5.
 *
 * All fields map 1-to-1 to the L1 `POST /l5/launch-coin` request body.
 */
export interface CreatorCoinConfig {
  /** Human-readable coin name, e.g. "Agent X Token". Max 64 chars. */
  name: string;
  /**
   * Ticker symbol (becomes the primary key on L1). 2–10 uppercase alphanumeric.
   * e.g. "AGENTX". Will be uppercased automatically before submission.
   */
  symbol: string;
  /**
   * Transfer tax in basis points. 0 = no tax. Max 1 000 (= 10 %).
   * The L1 will reject values above 1 000 with HTTP 400 ("honeypot prevention").
   */
  taxRateBps: number;
  /**
   * Destination for collected tax.
   * - `"BURN"` — coins/BB are burned on every transfer
   * - A valid L1 wallet address — tax is sent there (e.g. creator's marketing wallet)
   */
  taxDestination: string;
  /**
   * $BB lamports to lock as initial pool liquidity.
   * Must be ≥ MIN_INITIAL_LIQUIDITY_BB (100_000 lamports = 1 BB = $0.10).
   */
  initialLiquidityBB: bigint;
  /** AMM bonding curve model. */
  curveType: CurveType;
  /**
   * Bancor connector weight in parts-per-million. Required when curveType is
   * `"BANCOR_VAMM"`. Valid range: 10_000–1_000_000 (1 %–100 %).
   *
   * Common values:
   * - `333_333` — classic Bancor (1/3 connector weight, moderate growth curve)
   * - `100_000` — aggressive growth curve (10% connector weight)
   * - `500_000` — linear-ish price growth (50% connector weight)
   */
  bancorWeightPpm?: number;
  /** Optional description / tagline. Max 280 chars. */
  description?: string;
}

/** Response from a successful `POST /l5/launch-coin`. */
export interface LaunchCoinResponse {
  success: true;
  symbol: string;
  name: string;
  creator_wallet: string;
  total_supply: string;
  creator_share: string;
  pool_share: string;
  tax_rate_bps: number;
  tax_destination: string;
  curve_type: CurveType;
  bancor_weight_ppm: number | null;
  initial_liquidity_bb_lamports: number;
  initial_liquidity_bb: number;
  initial_price_bb_per_coin: number;
  launched_at: number;
  message: string;
}

/** Minimal Ed25519 keypair interface. Compatible with @solana/web3.js `Keypair`. */
export interface Ed25519Keypair {
  /** 32-byte public key. */
  publicKey: Uint8Array;
  /** 64-byte secret key (seed + public key, NaCl format). */
  secretKey: Uint8Array;
}

// ── SDK CLASS ─────────────────────────────────────────────────────────────────

export class TokenFactory {
  private readonly baseUrl: string;
  private readonly l5SequencerUrl: string;

  /**
   * @param l1BaseUrl       BlackBook L1 HTTP API, e.g. "http://localhost:8080"
   * @param l5SequencerUrl  L5 Sequencer HTTP URL, e.g. "http://localhost:7075"
   */
  constructor(l1BaseUrl: string, l5SequencerUrl: string) {
    this.baseUrl = l1BaseUrl.replace(/\/$/, '');
    this.l5SequencerUrl = l5SequencerUrl.replace(/\/$/, '');
  }

  /**
   * Step 1: Lock $BB in the L5 rollup vault on L1.
   *
   * Must be called before launching a coin. The L1 holds the BB before the L5
   * prints any tokens — this is the trust anchor of the two-step flow.
   *
   * Signed message: "ROLLUP_LOCK_BB:L5:{wallet}:{lamports}:{symbolHint}:{ts}:{nonce}"
   *
   * @param keypair     Creator's Ed25519 keypair (NaCl format).
   * @param lamports    $BB lamports to lock (≥ MIN_INITIAL_LIQUIDITY_BB).
   * @param symbolHint  Token symbol being launched (informational, sent to L1).
   * @returns           `{ lock_id }` from L1 on success.
   */
  async lockBb(
    keypair: Ed25519Keypair,
    lamports: bigint,
    symbolHint: string
  ): Promise<{ lock_id: string }> {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce();
    const wallet = bytesToHex(keypair.publicKey);
    const sym = symbolHint.trim().toUpperCase();

    const message = ['ROLLUP_LOCK_BB', 'L5', wallet, lamports.toString(), sym, timestamp, nonce].join(':');
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = nacl.sign.detached(messageBytes, keypair.secretKey);

    const body = {
      wallet_address: wallet,
      bb_lamports: Number(lamports),
      token_symbol_hint: sym,
      public_key: bytesToHex(keypair.publicKey),
      signature: bytesToHex(signatureBytes),
      timestamp,
      nonce,
    };

    const response = await fetch(`${this.baseUrl}/rollup/L5/lock_bb`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const json = await response.json();

    if (!response.ok) {
      throw new TokenFactoryError(
        (json as { error?: string }).error ?? `L1 lock_bb returned HTTP ${response.status}`,
        'LOCK_BB_FAILED',
        response.status,
        json
      );
    }

    return json as { lock_id: string };
  }

  /**
   * Launch a new Creator Coin on L5.
   *
   * Two-step flow (handled transparently by this method):
   *   1. Lock `initialLiquidityBB` on L1 via `POST /rollup/L5/lock_bb` — L1 holds the BB.
   *   2. POST coin config + `lock_id` to the L5 Sequencer `POST {l5SequencerUrl}/launch-coin`.
   *
   * The L5 Sequencer verifies the lock exists on L1 before activating the coin.
   *
   * ⚠️  Creator Coins CANNOT be exited to L1 directly. To recover $BB, users must
   *     swap their Creator Coins back to $BB inside L5 first (via the L5 bonding
   *     curve), then exit via the standard `POST /rollup/L5/exit` path.
   *
   * @param keypair  Creator's Ed25519 keypair (NaCl format).
   * @param config   Coin configuration (see `CreatorCoinConfig`).
   * @returns        The `LaunchCoinResponse` from the L5 Sequencer on success.
   * @throws         `TokenFactoryError` on validation failure, L1 rejection, or sequencer rejection.
   */
  async launchCoin(
    keypair: Ed25519Keypair,
    config: CreatorCoinConfig
  ): Promise<LaunchCoinResponse> {
    // ── Client-side guardrail validation ──────────────────────────────────
    const symbol = config.symbol.trim().toUpperCase();
    if (symbol.length < 2 || symbol.length > 10 || !/^[A-Z0-9]+$/.test(symbol)) {
      throw new TokenFactoryError(
        `symbol "${config.symbol}" is invalid — must be 2–10 uppercase alphanumeric chars.`,
        'INVALID_SYMBOL'
      );
    }

    if (config.name.trim().length === 0 || config.name.length > 64) {
      throw new TokenFactoryError('name is required and must be ≤ 64 chars.', 'INVALID_NAME');
    }

    if (config.taxRateBps < 0 || config.taxRateBps > MAX_TAX_BPS) {
      throw new TokenFactoryError(
        `taxRateBps ${config.taxRateBps} exceeds maximum ${MAX_TAX_BPS} (10%). ` +
        'Tokens with taxes above 10% are honeypots and will be rejected by L1.',
        'TAX_TOO_HIGH'
      );
    }

    if (!config.taxDestination || config.taxDestination.trim().length === 0) {
      throw new TokenFactoryError(
        'taxDestination is required — set to a wallet address or "BURN".',
        'MISSING_TAX_DESTINATION'
      );
    }

    if (config.initialLiquidityBB < MIN_INITIAL_LIQUIDITY_BB) {
      throw new TokenFactoryError(
        `initialLiquidityBB ${config.initialLiquidityBB} is below minimum ` +
        `${MIN_INITIAL_LIQUIDITY_BB} (${MIN_INITIAL_LIQUIDITY_BB / LAMPORTS_PER_BB} BB). ` +
        'This prevents spam coin launches.',
        'INSUFFICIENT_LIQUIDITY'
      );
    }

    if (config.curveType === 'BANCOR_VAMM') {
      if (config.bancorWeightPpm === undefined) {
        throw new TokenFactoryError(
          'bancorWeightPpm is required when curveType is BANCOR_VAMM.',
          'MISSING_BANCOR_WEIGHT'
        );
      }
      if (config.bancorWeightPpm < 10_000 || config.bancorWeightPpm > 1_000_000) {
        throw new TokenFactoryError(
          `bancorWeightPpm ${config.bancorWeightPpm} is out of range [10_000, 1_000_000]. ` +
          'Classic Bancor uses 333_333 (1/3 weight).',
          'INVALID_BANCOR_WEIGHT'
        );
      }
    }

    if (config.description && config.description.length > 280) {
      throw new TokenFactoryError('description must be ≤ 280 chars.', 'DESCRIPTION_TOO_LONG');
    }

    // ── Build nonce + timestamp ───────────────────────────────────────────
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce();

    // ── Canonical message ─────────────────────────────────────────────────
    // Verified by the L5 Sequencer (not L1). Signed by the creator so the
    // sequencer can confirm the request is authentic:
    // "L5_LAUNCH:{creator_wallet}:{symbol}:{tax_rate_bps}:{initial_liquidity_bb}:{timestamp}:{nonce}"
    const creatorWallet = bytesToHex(keypair.publicKey);
    const message = [
      'L5_LAUNCH',
      creatorWallet,
      symbol,
      config.taxRateBps,
      config.initialLiquidityBB.toString(),
      timestamp,
      nonce,
    ].join(':');

    // ── Sign ──────────────────────────────────────────────────────────────
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = nacl.sign.detached(messageBytes, keypair.secretKey);

    // ── Build request body ────────────────────────────────────────────────
    const body = {
      creator_wallet: creatorWallet,
      name: config.name.trim(),
      symbol,
      description: config.description ?? null,
      tax_rate_bps: config.taxRateBps,
      tax_destination: config.taxDestination.trim(),
      initial_liquidity_bb: Number(config.initialLiquidityBB),
      curve_type: config.curveType,
      bancor_weight_ppm: config.bancorWeightPpm ?? null,
      public_key: bytesToHex(keypair.publicKey),
      signature: bytesToHex(signatureBytes),
      timestamp,
      nonce,
    };

    // ── Step 1: Lock $BB on L1 ────────────────────────────────────────────
    const { lock_id } = await this.lockBb(keypair, config.initialLiquidityBB, symbol);

    // ── Step 2: Submit coin config to L5 Sequencer ───────────────────────
    const response = await fetch(`${this.l5SequencerUrl}/launch-coin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, lock_id }),
    });

    const json = await response.json();

    if (!response.ok) {
      throw new TokenFactoryError(
        (json as { error?: string }).error ?? `L5 Sequencer returned HTTP ${response.status}`,
        'SEQUENCER_REJECTED',
        response.status,
        json
      );
    }

    return json as LaunchCoinResponse;
  }
}

// ── ERROR CLASS ───────────────────────────────────────────────────────────────

export class TokenFactoryError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly httpStatus?: number,
    public readonly body?: unknown
  ) {
    super(message);
    this.name = 'TokenFactoryError';
  }
}

// ── UTILITIES ─────────────────────────────────────────────────────────────────

/** Convert a Uint8Array to a lowercase hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Generate a cryptographically random nonce string. */
function generateNonce(): string {
  const arr = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(arr);
  } else {
    // Node.js fallback
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { randomFillSync } = require('crypto');
    randomFillSync(arr);
  }
  return bytesToHex(arr);
}
