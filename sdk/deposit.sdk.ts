/**
 * BlackBook L1 — Deposit Gateway SDK (Buy BB with Solana USDC)
 * ============================================================================
 * Frontend SDK for purchasing $BB tokens by sending USDC on Solana to the
 * BlackBook custody wallet. Works with any Solana wallet adapter (Phantom,
 * OneKey, Solflare, Backpack, etc.)
 *
 * Rate: 1 USDC = 10 BB  (fixed)
 *
 * Flow:
 *   1. User connects Solana wallet via adapter
 *   2. SDK builds a Solana USDC transfer to the custody wallet
 *   3. User signs & sends via their wallet
 *   4. SDK calls POST /deposit/request on BlackBook L1
 *   5. L1 verifies the Solana tx on-chain and auto-mints BB + wUSDC
 *
 * Dependencies:
 *   npm install @solana/web3.js @solana/spl-token @noble/ed25519 @noble/hashes bs58
 *
 * Quick start:
 *   import { BlackBookDeposit } from "./deposit.sdk";
 *
 *   const deposit = new BlackBookDeposit({
 *     l1Url: "https://your-l1-node.com",
 *     solanaRpcUrl: "https://api.mainnet-beta.solana.com",
 *   });
 *
 *   // With Solana wallet adapter
 *   const result = await deposit.buyBB(wallet, 5.0); // 5 USDC → 50 BB
 * ============================================================================
 */

// ── Constants ──────────────────────────────────────────────────────────────

/** BlackBook custody wallet — users send USDC here */
export const CUSTODY_WALLET = "9KXSLbgbzemok7VFpEb4KSdNq75qNKYCtijWDZTXfWwT";

/** USDC mint on Solana mainnet */
export const SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/** BB per stablecoin (fixed rate) */
export const BB_PER_USDC = 10;

/** USDC has 6 decimals on Solana */
export const USDC_DECIMALS = 6;

// ── Types ──────────────────────────────────────────────────────────────────

export interface DepositConfig {
  /** BlackBook L1 node URL, e.g. "https://l1.blackbook.bet" */
  l1Url: string;
  /** Solana RPC URL, e.g. "https://api.mainnet-beta.solana.com" */
  solanaRpcUrl?: string;
  /** Override custody wallet address (defaults to production) */
  custodyWallet?: string;
  /** Override USDC mint (defaults to mainnet USDC) */
  usdcMint?: string;
}

/** Minimal Solana wallet adapter interface (compatible with @solana/wallet-adapter) */
export interface SolanaWalletAdapter {
  publicKey: { toBase58(): string; toBytes(): Uint8Array };
  signTransaction(tx: any): Promise<any>;
  signMessage?(message: Uint8Array): Promise<Uint8Array>;
}

export interface DepositResult {
  success: boolean;
  /** Solana transaction signature (base58) */
  solanaTxHash: string;
  /** Amount of USDC sent */
  usdcAmount: number;
  /** Amount of BB minted (or pending) */
  bbAmount: number;
  /** "approved" = instant mint, "pending" = dealer will approve shortly */
  status: "approved" | "pending";
  /** New BB balance after mint (if approved) */
  newBalance?: number;
  /** BlackBook L1 mint transaction ID */
  mintTxId?: string;
  /** wUSDC also minted */
  wusdcMinted?: number;
}

export interface DepositStatusResult {
  status: "pending" | "approved" | "not_found";
  wallet_address?: string;
  asset?: string;
  amount_stablecoin?: number;
  bb_to_mint?: number;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function randomNonce(): string {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── SDK ────────────────────────────────────────────────────────────────────

export class BlackBookDeposit {
  private l1Url: string;
  private solanaRpcUrl: string;
  private custodyWallet: string;
  private usdcMint: string;

  constructor(config: DepositConfig) {
    this.l1Url = config.l1Url.replace(/\/$/, "");
    this.solanaRpcUrl =
      config.solanaRpcUrl || "https://api.mainnet-beta.solana.com";
    this.custodyWallet = config.custodyWallet || CUSTODY_WALLET;
    this.usdcMint = config.usdcMint || SOLANA_USDC_MINT;
  }

  // ── Main entry point ───────────────────────────────────────────────────

  /**
   * Buy BB tokens by sending USDC on Solana.
   *
   * This is the single function your frontend needs to call.
   * It handles everything: building the Solana tx, sending USDC,
   * then calling the L1 deposit gateway.
   *
   * @param wallet  Connected Solana wallet adapter
   * @param usdcAmount  Amount of USDC to send (e.g. 5.0 = $5)
   * @returns DepositResult with tx hashes and new balance
   *
   * @example
   * ```ts
   * import { useWallet } from "@solana/wallet-adapter-react";
   * import { BlackBookDeposit } from "@blackbook/sdk/deposit";
   *
   * const { wallet } = useWallet();
   * const deposit = new BlackBookDeposit({ l1Url: "https://l1.blackbook.bet" });
   *
   * const result = await deposit.buyBB(wallet.adapter, 5.0);
   * console.log(`Got ${result.bbAmount} BB!`); // "Got 50 BB!"
   * ```
   */
  async buyBB(
    wallet: SolanaWalletAdapter,
    usdcAmount: number
  ): Promise<DepositResult> {
    if (usdcAmount <= 0) throw new Error("Amount must be > 0");
    if (!wallet.publicKey) throw new Error("Wallet not connected");

    // Step 1: Send USDC on Solana to custody wallet
    const solanaTxHash = await this.sendUsdcOnSolana(wallet, usdcAmount);

    // Step 2: Register deposit on BlackBook L1
    const l1Result = await this.registerDeposit(
      wallet,
      solanaTxHash,
      usdcAmount
    );

    return {
      success: true,
      solanaTxHash,
      usdcAmount,
      bbAmount: l1Result.bb_minted ?? usdcAmount * BB_PER_USDC,
      status: l1Result.status === "approved" ? "approved" : "pending",
      newBalance: l1Result.new_balance,
      mintTxId: l1Result.mint_tx_id,
      wusdcMinted: l1Result.wusdc_minted,
    };
  }

  // ── Step 1: Send USDC on Solana ────────────────────────────────────────

  /**
   * Build and send a Solana USDC transfer to the custody wallet.
   * Returns the Solana transaction signature (base58).
   */
  private async sendUsdcOnSolana(
    wallet: SolanaWalletAdapter,
    usdcAmount: number
  ): Promise<string> {
    const {
      Connection,
      PublicKey,
      Transaction,
    } = await import("@solana/web3.js");
    const {
      getAssociatedTokenAddress,
      createTransferInstruction,
      createAssociatedTokenAccountInstruction,
      getAccount,
    } = await import("@solana/spl-token");

    const connection = new Connection(this.solanaRpcUrl, "confirmed");
    const userPubkey = new PublicKey(wallet.publicKey.toBase58());
    const custodyPubkey = new PublicKey(this.custodyWallet);
    const mintPubkey = new PublicKey(this.usdcMint);

    // Resolve ATAs (Associated Token Accounts)
    const userAta = await getAssociatedTokenAddress(mintPubkey, userPubkey);
    const custodyAta = await getAssociatedTokenAddress(
      mintPubkey,
      custodyPubkey
    );

    const rawAmount = Math.round(usdcAmount * 10 ** USDC_DECIMALS);

    // Check user has enough USDC
    try {
      const userAccount = await getAccount(connection, userAta);
      if (BigInt(userAccount.amount) < BigInt(rawAmount)) {
        throw new Error(
          `Insufficient USDC: have ${Number(userAccount.amount) / 10 ** USDC_DECIMALS}, need ${usdcAmount}`
        );
      }
    } catch (e: any) {
      if (e.name === "TokenAccountNotFoundError") {
        throw new Error(
          "No USDC token account found. You have no USDC in this wallet."
        );
      }
      throw e;
    }

    // Build transaction
    const tx = new Transaction();

    // Create custody ATA if it doesn't exist yet
    try {
      await getAccount(connection, custodyAta);
    } catch {
      tx.add(
        createAssociatedTokenAccountInstruction(
          userPubkey, // payer
          custodyAta, // ATA to create
          custodyPubkey, // owner of the ATA
          mintPubkey // USDC mint
        )
      );
    }

    // USDC transfer instruction
    tx.add(
      createTransferInstruction(
        userAta, // source ATA
        custodyAta, // destination ATA
        userPubkey, // owner (signer)
        rawAmount // raw lamports (6 decimals)
      )
    );

    // Set recent blockhash and fee payer
    const { blockhash, lastValidBlockHeight } =
      await connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.lastValidBlockHeight = lastValidBlockHeight;
    tx.feePayer = userPubkey;

    // Sign with wallet adapter
    const signed = await wallet.signTransaction(tx);
    const sig = await connection.sendRawTransaction(signed.serialize(), {
      skipPreflight: false,
      preflightCommitment: "confirmed",
    });

    // Wait for confirmation
    await connection.confirmTransaction(
      { signature: sig, blockhash, lastValidBlockHeight },
      "confirmed"
    );

    return sig;
  }

  // ── Step 2: Register deposit on BlackBook L1 ──────────────────────────

  /**
   * Call POST /deposit/request on BlackBook L1.
   * Signs the deposit message with the wallet's Ed25519 key.
   */
  private async registerDeposit(
    wallet: SolanaWalletAdapter,
    solanaTxHash: string,
    usdcAmount: number
  ): Promise<any> {
    const walletAddress = wallet.publicKey.toBase58();
    const publicKeyHex = Buffer.from(wallet.publicKey.toBytes()).toString("hex");
    const timestamp = nowSecs();
    const nonce = randomNonce();

    // Construct the L1 signature message
    // Must match: "DEPOSIT_REQUEST:{wallet}:{tx_hash}:{amount}:{asset}:{ts}:{nonce}"
    const message = `DEPOSIT_REQUEST:${walletAddress}:${solanaTxHash}:${usdcAmount}:USDC:${timestamp}:${nonce}`;
    const messageBytes = new TextEncoder().encode(message);

    // Sign with the wallet (same Ed25519 key used for Solana)
    let signatureHex: string;

    if (wallet.signMessage) {
      // Preferred: wallet adapter signMessage (Phantom, OneKey, Backpack, etc.)
      const sigBytes = await wallet.signMessage(messageBytes);
      signatureHex = Buffer.from(sigBytes).toString("hex");
    } else {
      throw new Error(
        "Wallet must support signMessage() for deposit verification. " +
        "Most Solana wallets (Phantom, OneKey, Solflare) support this."
      );
    }

    // Call L1 deposit endpoint
    const res = await fetch(`${this.l1Url}/deposit/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet_address: walletAddress,
        external_tx_hash: solanaTxHash,
        asset: "USDC",
        amount_stablecoin: usdcAmount,
        public_key: publicKeyHex,
        signature: signatureHex,
        timestamp,
        nonce,
      }),
    });

    const json = await res.json();
    if (!res.ok && !json.success) {
      throw new Error(
        `Deposit request failed: ${json.error ?? JSON.stringify(json)}`
      );
    }
    return json;
  }

  // ── Status check ──────────────────────────────────────────────────────

  /**
   * Check the status of a pending deposit by its Solana tx hash.
   */
  async getDepositStatus(solanaTxHash: string): Promise<DepositStatusResult> {
    const res = await fetch(
      `${this.l1Url}/deposit/status/${solanaTxHash}`
    );
    if (res.status === 404) return { status: "not_found" };
    return res.json();
  }

  /**
   * Get a price quote — how much BB you'll get for a given USDC amount.
   */
  quote(usdcAmount: number): { usdcAmount: number; bbAmount: number; rate: number } {
    return {
      usdcAmount,
      bbAmount: usdcAmount * BB_PER_USDC,
      rate: BB_PER_USDC,
    };
  }

  /**
   * Get the custody wallet address (for display / manual transfers).
   */
  getCustodyWallet(): string {
    return this.custodyWallet;
  }
}
