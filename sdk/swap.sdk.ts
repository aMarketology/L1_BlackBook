/**
 * BlackBook L1 — Token Swap / AMM Contract SDK
 * ============================================================================
 * Covers all interactions with the on-chain Token Swap smart contract.
 *
 * Architecture:
 *   - Fixed-rate liquidity pool: 1 BB = 10 USDC
 *   - Treasury holds both $BB (native) and USDC (SPL token)
 *   - Swaps are atomic — both legs execute in the same request or neither does
 *   - No signing required from the user (treasury handles all legs)
 *
 * Treasury address: SwapTreasuryAuthority1111111111111111111111
 *
 * Rates:
 *   BB  → USDC :  1 BB   = 10 USDC
 *   USDC → BB  :  10 USDC = 1 BB
 *
 * Endpoints:
 *   POST /swap/bb-to-usdc
 *   POST /swap/usdc-to-bb
 *   GET  /usdc/balance/:address
 *   GET  /usdc/supply
 *   GET  /usdc/accounts/:address
 *   POST /usdc/transfer
 *
 * Dependencies: npm install @noble/ed25519 @noble/hashes bs58
 * ============================================================================
 */

// ── Constants ──────────────────────────────────────────────────────────────

export const TREASURY_ADDRESS = "SwapTreasuryAuthority1111111111111111111111";

/** Fixed exchange rate: 1 BB = BB_TO_USDC_RATE USDC */
export const BB_TO_USDC_RATE = 10;

/** USDC has 6 decimal places (1 USDC = 1_000_000 raw units) */
export const USDC_DECIMALS = 6;

// ── Types ──────────────────────────────────────────────────────────────────

export interface Keypair {
  address: string;       // base58 public key (IS the wallet address)
  privateKeyHex: string; // hex 32-byte private key — never send this
  publicKeyHex: string;  // hex 32-byte public key
}

// ── Response types ─────────────────────────────────────────────────────────

export interface SwapBbToUsdcResponse {
  success: boolean;
  message: string;
  /** Amount of BB taken from the wallet */
  bb_debited: number;
  /** Amount of USDC credited to the wallet */
  usdc_credited: number;
}

export interface SwapUsdcToBbResponse {
  success: boolean;
  message: string;
  /** Amount of USDC taken from the wallet */
  usdc_debited: number;
  /** Amount of BB credited to the wallet */
  bb_credited: number;
}

export interface UsdcBalanceResponse {
  address: string;
  /** Human-readable USDC balance (e.g. 100.5) */
  usdc_balance: number;
  /** Raw token units (usdc_balance * 1_000_000) */
  raw_balance: number;
  decimals: number;
  /** Base58 mint address of the USDC token on BlackBook L1 */
  mint: string;
}

export interface UsdcSupplyResponse {
  mint: string;
  total_supply: number;
  raw_supply: number;
  decimals: number;
}

export interface UsdcAccountsResponse {
  address: string;
  token_accounts: Array<{
    ata: string;
    mint: string;
    balance: number;
    raw_balance: number;
  }>;
}

export interface UsdcTransferResponse {
  success: boolean;
  amount_usdc: number;
  raw_amount: number;
  from: string;
  to: string;
  from_ata: string;
  to_ata: string;
  from_balance: number;
  to_balance: number;
}

/** Pre-swap quote — computed locally without a network call */
export interface SwapQuote {
  direction: "BB→USDC" | "USDC→BB";
  amountIn: number;
  amountOut: number;
  rate: string;
  /** Reminder about no slippage (fixed-rate pool) */
  slippage: "0% (fixed-rate pool)";
}

// ── SwapSDK ───────────────────────────────────────────────────────────────

export class SwapSDK {
  private rpcUrl: string;
  private wallet?: Keypair;

  /**
   * @param rpcUrl  BlackBook L1 node URL, e.g. "http://localhost:8080"
   * @param wallet  Keypair for the user wallet — required for swap/transfer calls
   */
  constructor(rpcUrl: string, wallet?: Keypair) {
    this.rpcUrl = rpcUrl.replace(/\/$/, "");
    this.wallet = wallet;
  }

  /** Swap the active wallet (e.g. after session unlock) */
  setWallet(wallet: Keypair): void {
    this.wallet = wallet;
  }

  private requireWallet(): Keypair {
    if (!this.wallet) {
      throw new Error("No wallet set. Call setWallet(keypair) first.");
    }
    return this.wallet;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) {
      throw new Error(
        `${path} failed (${res.status}): ${json.error ?? JSON.stringify(json)}`
      );
    }
    return json as T;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`);
    const json = await res.json();
    if (!res.ok) {
      throw new Error(
        `${path} failed (${res.status}): ${json.error ?? JSON.stringify(json)}`
      );
    }
    return json as T;
  }

  // ── Quotes (local, no network) ────────────────────────────────────────────

  /**
   * Calculate a swap quote locally without hitting the network.
   * Use this to show the user what they will receive before confirming.
   *
   * @param direction  "BB→USDC" or "USDC→BB"
   * @param amountIn   Amount of the input token
   *
   * @example
   * const q = SwapSDK.quote("BB→USDC", 5);
   * // → { amountIn: 5, amountOut: 50, rate: "1 BB = 10 USDC", ... }
   */
  static quote(direction: "BB→USDC" | "USDC→BB", amountIn: number): SwapQuote {
    if (amountIn <= 0) throw new Error("amountIn must be > 0");
    if (direction === "BB→USDC") {
      return {
        direction,
        amountIn,
        amountOut: amountIn * BB_TO_USDC_RATE,
        rate: `1 BB = ${BB_TO_USDC_RATE} USDC`,
        slippage: "0% (fixed-rate pool)",
      };
    } else {
      return {
        direction,
        amountIn,
        amountOut: amountIn / BB_TO_USDC_RATE,
        rate: `${BB_TO_USDC_RATE} USDC = 1 BB`,
        slippage: "0% (fixed-rate pool)",
      };
    }
  }

  // ── Read ─────────────────────────────────────────────────────────────────

  /**
   * GET /usdc/balance/:address
   * Returns the USDC SPL token balance for a wallet.
   * Omit address to check the loaded wallet's own balance.
   *
   * @example
   * const bal = await swap.getUsdcBalance();
   * console.log(`${bal.usdc_balance} USDC`);
   */
  getUsdcBalance(address?: string): Promise<UsdcBalanceResponse> {
    const addr = address ?? this.requireWallet().address;
    return this.get(`/usdc/balance/${addr}`);
  }

  /**
   * GET /usdc/supply
   * Returns the total USDC minted on BlackBook L1.
   */
  usdcSupply(): Promise<UsdcSupplyResponse> {
    return this.get("/usdc/supply");
  }

  /**
   * GET /usdc/accounts/:address
   * Returns all SPL token accounts (ATAs) owned by a wallet.
   * Omit address to inspect the loaded wallet.
   */
  usdcAccounts(address?: string): Promise<UsdcAccountsResponse> {
    const addr = address ?? this.requireWallet().address;
    return this.get(`/usdc/accounts/${addr}`);
  }

  // ── Writes ────────────────────────────────────────────────────────────────

  /**
   * POST /swap/bb-to-usdc — Swap $BB tokens for USDC.
   *
   * Rate: 1 BB = 10 USDC (fixed, no slippage)
   * Synchronous — executes atomically and returns final balances immediately.
   * Signs: `SWAP_BB_USDC:<wallet>:<bb_amount>:<timestamp>:<nonce>`
   *
   * @param bbAmount  Amount of $BB to sell (must be > 0, must not exceed balance)
   *
   * @example
   * const q = SwapSDK.quote("BB→USDC", 10);  // preview: 100 USDC
   * const r = await swap.bbToUsdc(10);
   * console.log(`Received ${r.usdc_credited} USDC`);
   */
  async bbToUsdc(bbAmount: number): Promise<SwapBbToUsdcResponse> {
    if (bbAmount <= 0) throw new Error("bbAmount must be > 0");
    const kp = this.requireWallet();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    const message = `SWAP_BB_USDC:${kp.address}:${bbAmount}:${timestamp}:${nonce}`;
    const { ed, hexToBytes, bytesToHex } = await import("@noble/ed25519").then(
      async (ed) => ({
        ed,
        hexToBytes: (await import("@noble/hashes/utils")).hexToBytes,
        bytesToHex: (await import("@noble/hashes/utils")).bytesToHex,
      })
    );
    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );
    return this.post<SwapBbToUsdcResponse>("/swap/bb-to-usdc", {
      wallet_address: kp.address,
      bb_amount: bbAmount,
      timestamp,
      nonce,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
    });
  }

  /**
   * POST /swap/usdc-to-bb — Swap USDC for $BB tokens.
   *
   * Rate: 10 USDC = 1 BB (fixed, no slippage)
   * Synchronous — executes atomically and returns final balances immediately.
   * Signs: `SWAP_USDC_BB:<wallet>:<usdc_amount>:<timestamp>:<nonce>`
   *
   * @param usdcAmount  Amount of USDC to sell (must be > 0, must not exceed balance)
   *
   * @example
   * const q = SwapSDK.quote("USDC→BB", 50);  // preview: 5 BB
   * const r = await swap.usdcToBb(50);
   * console.log(`Received ${r.bb_credited} BB`);
   */
  async usdcToBb(usdcAmount: number): Promise<SwapUsdcToBbResponse> {
    if (usdcAmount <= 0) throw new Error("usdcAmount must be > 0");
    const kp = this.requireWallet();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    const message = `SWAP_USDC_BB:${kp.address}:${usdcAmount}:${timestamp}:${nonce}`;
    const { ed, hexToBytes, bytesToHex } = await import("@noble/ed25519").then(
      async (ed) => ({
        ed,
        hexToBytes: (await import("@noble/hashes/utils")).hexToBytes,
        bytesToHex: (await import("@noble/hashes/utils")).bytesToHex,
      })
    );
    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );
    return this.post<SwapUsdcToBbResponse>("/swap/usdc-to-bb", {
      wallet_address: kp.address,
      usdc_amount: usdcAmount,
      timestamp,
      nonce,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
    });
  }

  /**
   * POST /usdc/transfer — Transfer USDC to another wallet.
   *
   * Moves USDC between two Associated Token Accounts (ATAs).
   * The recipient ATA is auto-created if it does not exist.
   *
   * Note: This endpoint does not currently require an Ed25519 signature.
   * Validate on your frontend that `from` matches the loaded wallet.
   *
   * @param to      Recipient base58 wallet address
   * @param amount  Amount of USDC in human units (e.g. 100.5)
   *
   * @example
   * const r = await swap.transferUsdc("RecipientBase58Addr...", 25.0);
   * console.log(`Sent ${r.amount_usdc} USDC, sender balance: ${r.from_balance}`);
   */
  async transferUsdc(to: string, amount: number): Promise<UsdcTransferResponse> {
    if (amount <= 0) throw new Error("amount must be > 0");
    if (!to) throw new Error("recipient address is required");
    const kp = this.requireWallet();
    return this.post<UsdcTransferResponse>("/usdc/transfer", {
      from: kp.address,
      to,
      amount,
    });
  }

  // ── Utility ───────────────────────────────────────────────────────────────

  /**
   * Convert a USDC human amount to raw token units (6 decimal places).
   * @example toRawUsdc(1.5) === 1_500_000
   */
  static toRawUsdc(humanAmount: number): number {
    return Math.round(humanAmount * 10 ** USDC_DECIMALS);
  }

  /**
   * Convert raw USDC token units back to a human-readable amount.
   * @example fromRawUsdc(1_500_000) === 1.5
   */
  static fromRawUsdc(rawAmount: number): number {
    return rawAmount / 10 ** USDC_DECIMALS;
  }

  /**
   * Given a BB amount, returns how much USDC you would receive.
   * @example bbToUsdcAmount(5) === 50
   */
  static bbToUsdcAmount(bb: number): number {
    return bb * BB_TO_USDC_RATE;
  }

  /**
   * Given a USDC amount, returns how much BB you would receive.
   * @example usdcToBbAmount(50) === 5
   */
  static usdcToBbAmount(usdc: number): number {
    return usdc / BB_TO_USDC_RATE;
  }
}
