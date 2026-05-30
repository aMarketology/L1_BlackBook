/**
 * BlackBook L1 — Wallet SDK
 * ============================================================================
 * A fully typed TypeScript SDK for interacting with the BlackBook L1 node
 * from a frontend wallet.
 *
 * Address format : base58-encoded 32-byte Ed25519 public key
 *                  (Solana-style — NOT Ethereum 0x addresses)
 * Auth model     : Every state-changing action is signed with the user's
 *                  Ed25519 private key. L1 never holds private keys.
 *
 * Dependencies (install before use):
 *   npm install @noble/ed25519 @noble/hashes bs58 @scure/bip39
 *
 * Quick start:
 *   const kp  = await BlackBookWallet.generate();
 *   const sdk = new BlackBookSDK({ rpcUrl: "http://localhost:8080", wallet: kp });
 *   await sdk.faucet(0.1);
 *   const bal = await sdk.getBalance(kp.address);
 * ============================================================================
 */

// ── Types ──────────────────────────────────────────────────────────────────

export interface Keypair {
  /** base58-encoded 32-byte Ed25519 public key — this IS your wallet address */
  address: string;
  /** hex-encoded 32-byte private key (keep secret, never send) */
  privateKeyHex: string;
  /** hex-encoded 32-byte public key */
  publicKeyHex: string;
}

export interface SDKConfig {
  /** URL of the running BlackBook L1 node, e.g. "http://localhost:8080" */
  rpcUrl: string;
  /** Wallet keypair — required for any signing operation */
  wallet?: Keypair;
}

// ── Response types ─────────────────────────────────────────────────────────

/** Raw GET /health JSON (nested + flat compat fields from L1). */
export interface HealthResponse {
  status: string;
  ok?: boolean;
  online?: boolean;
  version: string;
  network: string;
  slot?: number;
  total_supply?: number;
  uptime_seconds?: number;
  blockchain?: { total_supply?: number; block_count?: number };
  poh_clock?: { current_slot?: number };
  volume?: { uptime_secs?: number };
}

export function parseHealth(raw: HealthResponse): {
  online: boolean;
  healthy: boolean;
  slot: number;
  totalSupply: number;
  uptimeSeconds: number;
  version: string;
  network: string;
} {
  const slot = raw.slot ?? raw.poh_clock?.current_slot ?? 0;
  const totalSupply = raw.total_supply ?? raw.blockchain?.total_supply ?? 0;
  const uptimeSeconds = raw.uptime_seconds ?? raw.volume?.uptime_secs ?? 0;
  const healthy =
    raw.ok === true || raw.status === "healthy" || raw.status === "ok";
  return {
    online: raw.online !== false,
    healthy,
    slot,
    totalSupply,
    uptimeSeconds,
    version: raw.version,
    network: raw.network,
  };
}

export function isNodeOnline(health: HealthResponse): boolean {
  return parseHealth(health).online;
}

export interface BalanceResponse {
  address: string;
  balance: number;
  unit: "BB";
}

export interface TransferResponse {
  success: boolean;
  from: string;
  to: string;
  amount: number;
  from_balance: number;
  to_balance: number;
}

export interface FaucetResponse {
  success: boolean;
  minted: number;
  wallet_address: string;
  new_balance: number;
}

export interface EscrowDepositResponse {
  success: boolean;
  deposited: number;
  wallet_address: string;
  escrow_address: string;
  user_balance: number;
  escrow_balance: number;
}

export interface EscrowWithdrawResponse {
  success: boolean;
  withdrawn: number;
  wallet_address: string;
  new_balance: number;
}

export interface SwapResponse {
  success: boolean;
  message: string;
  bb_debited?: number;
  usdc_credited?: number;
  usdc_debited?: number;
  bb_credited?: number;
}

export interface UsdcBalanceResponse {
  address: string;
  usdc_balance: number;
  raw_balance: number;
  decimals: number;
  mint: string;
}

export interface UsdcTransferResponse {
  success: boolean;
  amount_usdc: number;
  from: string;
  to: string;
  from_balance: number;
  to_balance: number;
}

export interface PohStatusResponse {
  slot: number;
  hash: string;
  tick: number;
  epoch: number;
  leader: string;
}

export interface BlockResponse {
  slot: number;
  hash: string;
  parent_hash: string;
  timestamp: number;
  transactions: Array<{
    hash: string;
    from: string;
    type: string;
  }>;
}

export interface EscrowStatusResponse {
  escrow_address: string;
  escrow_balance: number;
  total_markets: number;
  l2_sequencer_configured: boolean;
}

export interface EscrowMarketResponse {
  market_id: string;
  merkle_root: string;
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

/**
 * Lazily-loaded crypto — imports @noble/ed25519, @noble/hashes, and bs58.
 * These are peer dependencies that must be installed in your project.
 */
async function getCrypto() {
  const [
    ed, 
    { bytesToHex, hexToBytes }, 
    bs58, 
    bip39, 
    english, 
    { hmac }, 
    { sha512 }
  ] = await Promise.all([
    import("@noble/ed25519"),
    import("@noble/hashes/utils"),
    import("bs58"),
    import("@scure/bip39"),
    import("@scure/bip39/wordlists/english.js"),
    import("@noble/hashes/hmac.js"),
    import("@noble/hashes/sha2.js")
  ]);
  
  return { 
    ed, 
    bytesToHex, 
    hexToBytes, 
    bs58: (bs58 as any).default || bs58, 
    bip39, 
    wordlist: english.wordlist, 
    hmac, 
    sha512 
  };
}

/** Returns the current Unix timestamp in seconds */
function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

/** Generates a random nonce string */
function randomNonce(): string {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── BlackBookWallet ────────────────────────────────────────────────────────

export class BlackBookWallet {
  /**
   * Generate a completely new 24-word BIP39 mnemonic phrase.
   * This is the standard way to create secure human-readable wallet backups.
   */
  static async generateMnemonicPhrase(): Promise<string> {
    const { bip39, wordlist } = await getCrypto();
    return bip39.generateMnemonic(wordlist, 256);
  }

  /**
   * Derive a keypair directly from a valid 24-word BIP39 mnemonic.
   * It uses SLIP-0010 hardened paths ("m/44'/1984'/0'/0'") under the hood.
   */
  static async fromMnemonic(phrase: string): Promise<Keypair> {
    const { ed, bytesToHex, bs58, bip39, wordlist, hmac, sha512 } = await getCrypto();
    
    // Validate
    if (!bip39.validateMnemonic(phrase.trim().toLowerCase(), wordlist)) {
      throw new Error("Invalid BIP39 mnemonic phrase.");
    }

    // Convert to Seed
    const seed = bip39.mnemonicToSeedSync(phrase.trim().toLowerCase());

    // SLIP-0010 Hardened Path derivation
    const master = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
    let privKey = master.slice(0, 32);
    let chainCode = master.slice(32);

    // Derivation path "m/44'/1984'/0'/0'"
    const path = "m/44'/1984'/0'/0'";
    const segments = path.split('/').slice(1);
    
    for (const seg of segments) {
      const idx = (parseInt(seg, 10) >>> 0) + 0x80000000;
      const data = new Uint8Array(37);
      data[0] = 0x00;
      data.set(privKey, 1);
      new DataView(data.buffer).setUint32(33, idx, false);
      const child = hmac(sha512, chainCode, data);
      privKey = child.slice(0, 32);
      chainCode = child.slice(32);
    }

    const pubBytes = await ed.getPublicKeyAsync(privKey);
    return {
      address: bs58.encode(pubBytes),
      privateKeyHex: bytesToHex(privKey),
      publicKeyHex: bytesToHex(pubBytes),
    };
  }

  /**
   * Generate a new random keypair (raw, no mnemonic backup).
   * Store privateKeyHex securely — it cannot be recovered if lost.
   */
  static async generate(): Promise<Keypair> {
    const { ed, bytesToHex, bs58 } = await getCrypto();
    const privBytes = ed.utils.randomSecretKey();
    const pubBytes = await ed.getPublicKeyAsync(privBytes);
    return {
      address: bs58.encode(pubBytes),
      privateKeyHex: bytesToHex(privBytes),
      publicKeyHex: bytesToHex(pubBytes),
    };
  }

  /**
   * Restore a keypair from a saved private key hex string.
   */
  static async fromPrivateKey(privateKeyHex: string): Promise<Keypair> {
    const { ed, hexToBytes, bytesToHex, bs58 } = await getCrypto();
    const privBytes = hexToBytes(privateKeyHex);
    const pubBytes = await ed.getPublicKeyAsync(privBytes);
    return {
      address: bs58.encode(pubBytes),
      privateKeyHex,
      publicKeyHex: bytesToHex(pubBytes),
    };
  }

  /** Sign an arbitrary message string, returns hex-encoded 64-byte signature */
  static async sign(message: string, privateKeyHex: string): Promise<string> {
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const privBytes = hexToBytes(privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    const sigBytes = await ed.signAsync(msgBytes, privBytes);
    return bytesToHex(sigBytes);
  }
}

// ── BlackBookSDK ───────────────────────────────────────────────────────────

export class BlackBookSDK {
  private rpcUrl: string;
  private wallet?: Keypair;

  constructor(config: SDKConfig) {
    this.rpcUrl = config.rpcUrl.replace(/\/$/, "");
    this.wallet = config.wallet;
  }

  /** Swap out the active wallet (e.g. after unlock) */
  setWallet(wallet: Keypair) {
    this.wallet = wallet;
  }

  private requireWallet(): Keypair {
    if (!this.wallet) {
      throw new Error("No wallet loaded. Call sdk.setWallet(keypair) first.");
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

  // ── READ endpoints ───────────────────────────────────────────────────────

  /** GET /health — Node health and chain stats */
  health(): Promise<HealthResponse> {
    return this.get("/health");
  }

  async ping(): Promise<{ online: boolean; healthy: boolean; health: HealthResponse }> {
    const health = await this.health();
    const parsed = parseHealth(health);
    return { online: parsed.online, healthy: parsed.healthy, health };
  }

  /** GET /stats — Detailed node metrics */
  stats(): Promise<Record<string, unknown>> {
    return this.get("/stats");
  }

  /**
   * GET /balance/:address — $BB balance for any wallet.
   * Omit address to query the loaded wallet's own balance.
   */
  getBalance(address?: string): Promise<BalanceResponse> {
    const addr = address ?? this.requireWallet().address;
    return this.get(`/balance/${addr}`);
  }

  /** GET /ledger — Full on-chain transaction ledger */
  getLedger(): Promise<Record<string, unknown>> {
    return this.get("/ledger");
  }

  /** GET /poh/status — Current PoH clock (slot, hash, tick, epoch) */
  pohStatus(): Promise<PohStatusResponse> {
    return this.get("/poh/status");
  }

  /** GET /poh/block/latest — Most recently finalized block */
  latestBlock(): Promise<BlockResponse> {
    return this.get("/poh/block/latest");
  }

  /** GET /poh/block/:slot — Block at a specific slot */
  blockBySlot(slot: number): Promise<BlockResponse> {
    return this.get(`/poh/block/${slot}`);
  }

  /** GET /poh/tx/:tx_id/status — Status of a submitted transaction */
  txStatus(txId: string): Promise<Record<string, unknown>> {
    return this.get(`/poh/tx/${txId}/status`);
  }

  /** GET /consensus/tower — Tower BFT vote state */
  towerBft(): Promise<Record<string, unknown>> {
    return this.get("/consensus/tower");
  }

  /** GET /turbine/status — Turbine block propagation stats */
  turbineStatus(): Promise<Record<string, unknown>> {
    return this.get("/turbine/status");
  }

  /** GET /escrow/status — Global escrow vault info */
  escrowStatus(): Promise<EscrowStatusResponse> {
    return this.get("/escrow/status");
  }

  /** GET /escrow/market/:market_id — Merkle root for a specific L2 market */
  escrowMarket(marketId: string): Promise<EscrowMarketResponse> {
    return this.get(`/escrow/market/${marketId}`);
  }

  /** GET /usdc/balance/:address — USDC SPL token balance */
  getUsdcBalance(address?: string): Promise<UsdcBalanceResponse> {
    const addr = address ?? this.requireWallet().address;
    return this.get(`/usdc/balance/${addr}`);
  }

  /** GET /usdc/supply — Total USDC supply on BlackBook L1 */
  usdcSupply(): Promise<Record<string, unknown>> {
    return this.get("/usdc/supply");
  }

  /** GET /usdc/accounts/:address — All token accounts for a wallet */
  usdcAccounts(address?: string): Promise<Record<string, unknown>> {
    const addr = address ?? this.requireWallet().address;
    return this.get(`/usdc/accounts/${addr}`);
  }

  // ── SIGNED write endpoints ───────────────────────────────────────────────

  /**
   * POST /transfer/simple — Transfer $BB tokens to another wallet.
   *
   * Signs: `\x01{payloadJson}\n{timestamp}\n{nonce}`
   * The `\x01` byte is the chain_id (mainnet = 1).
   *
   * @param to    Recipient base58 address
   * @param amount Amount of $BB to send
   */
  async transfer(to: string, amount: number): Promise<TransferResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();

    const timestamp = nowSecs();
    const nonce = randomNonce();
    const payload = JSON.stringify({ to, amount });

    // message = chainId(1 byte) || payload || "\n" || timestamp || "\n" || nonce
    const chainId = new Uint8Array([1]);
    const encoder = new TextEncoder();
    const message = new Uint8Array([
      ...Array.from(chainId),
      ...Array.from(encoder.encode(payload)),
      ...Array.from(encoder.encode("\n")),
      ...Array.from(encoder.encode(String(timestamp))),
      ...Array.from(encoder.encode("\n")),
      ...Array.from(encoder.encode(nonce)),
    ]);

    const sigBytes = await ed.signAsync(message, hexToBytes(kp.privateKeyHex));

    return this.post<TransferResponse>("/transfer/simple", {
      public_key: kp.publicKeyHex,
      wallet_address: kp.address,
      payload,
      timestamp,
      nonce,
      chain_id: 1,
      signature: bytesToHex(sigBytes),
    });
  }

  /**
   * POST /faucet — Claim free $BB tokens (rate-limited, up to 0.1 BB).
   *
   * Signs: `"FAUCET:{wallet_address}:{amount}:{timestamp}:{nonce}"`
   *
   * @param amount Amount to claim — capped at 0.1 BB by the node
   */
  async faucet(amount: number = 0.1): Promise<FaucetResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();

    const timestamp = nowSecs();
    const nonce = randomNonce();
    const capped = Math.min(amount, 0.1);
    const message = `FAUCET:${kp.address}:${capped.toFixed(6)}:${timestamp}:${nonce}`;

    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );

    return this.post<FaucetResponse>("/faucet", {
      wallet_address: kp.address,
      amount: capped,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
      timestamp,
      nonce,
    });
  }

  /**
   * POST /escrow/deposit — Lock $BB into the global escrow vault.
   *
   * Signs: `"ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"`
   *
   * Tokens move: user wallet → escrow PDA.
   * Used before placing bets on L2 markets.
   *
   * @param amount Amount of $BB to lock
   */
  async escrowDeposit(amount: number): Promise<EscrowDepositResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();

    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `ESCROW_DEPOSIT:${kp.address}:${amount}:${timestamp}:${nonce}`;

    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );

    return this.post<EscrowDepositResponse>("/escrow/deposit", {
      wallet_address: kp.address,
      amount,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
      timestamp,
      nonce,
    });
  }

  /**
   * POST /escrow/withdraw — Withdraw from escrow via merkle proof.
   *
   * Signs: `"ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"`
   *
   * The merkle proof is obtained from the L2 sequencer after market settlement.
   * Tokens move: escrow PDA → user wallet.
   *
   * @param marketId    L2 market identifier
   * @param amount      Amount entitled (must match merkle leaf)
   * @param merkleProof Array of 64-char hex sibling hashes from L2
   */
  async escrowWithdraw(
    marketId: string,
    amount: number,
    merkleProof: string[]
  ): Promise<EscrowWithdrawResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();

    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `ESCROW_WITHDRAW:${marketId}:${kp.address}:${amount}:${timestamp}:${nonce}`;

    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );

    return this.post<EscrowWithdrawResponse>("/escrow/withdraw", {
      market_id: marketId,
      amount,
      wallet_address: kp.address,
      merkle_proof: merkleProof,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
      timestamp,
      nonce,
    });
  }

  // ── SWAP endpoints ────────────────────────────────────────────────────────

  /**
   * POST /swap/bb-to-usdc — Swap $BB for USDC at the fixed 1:10 rate.
   *
   * Synchronous — executes atomically and returns final balances immediately.
   * Signs: `SWAP_BB_USDC:<wallet>:<bb_amount>:<timestamp>:<nonce>`
   *
   * @param bbAmount Amount of $BB to sell
   */
  async swapBbToUsdc(bbAmount: number): Promise<SwapResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `SWAP_BB_USDC:${kp.address}:${bbAmount}:${timestamp}:${nonce}`;
    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );
    return this.post<SwapResponse>("/swap/bb-to-usdc", {
      wallet_address: kp.address,
      bb_amount: bbAmount,
      timestamp,
      nonce,
      public_key: kp.publicKeyHex,
      signature: bytesToHex(sigBytes),
    });
  }

  /**
   * POST /swap/usdc-to-bb — Swap USDC for $BB at the fixed 10:1 rate.
   *
   * Synchronous — executes atomically and returns final balances immediately.
   * Signs: `SWAP_USDC_BB:<wallet>:<usdc_amount>:<timestamp>:<nonce>`
   *
   * @param usdcAmount Amount of USDC to sell
   */
  async swapUsdcToBb(usdcAmount: number): Promise<SwapResponse> {
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `SWAP_USDC_BB:${kp.address}:${usdcAmount}:${timestamp}:${nonce}`;
    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(kp.privateKeyHex)
    );
    return this.post<SwapResponse>("/swap/usdc-to-bb", {
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
   * Note: This endpoint currently does not require a signature.
   * Production use should add Ed25519 signing (planned upgrade).
   *
   * @param to     Recipient base58 address
   * @param amount Amount of USDC
   */
  async transferUsdc(to: string, amount: number): Promise<UsdcTransferResponse> {
    const kp = this.requireWallet();
    return this.post<UsdcTransferResponse>("/usdc/transfer", {
      from: kp.address,
      to,
      amount,
    });
  }

  // ── Gulf Stream (advanced) ───────────────────────────────────────────────

  /**
   * POST /sealevel/submit — Submit a transaction to the Gulf Stream
   * mempool for Sealevel parallel execution.
   *
   * @param to       Recipient address
   * @param amount   Amount of $BB
   * @param priority Optional priority fee (higher = faster scheduling)
   */
  async sealevelSubmit(
    to: string,
    amount: number,
    priority?: number
  ): Promise<Record<string, unknown>> {
    const kp = this.requireWallet();
    return this.post("/sealevel/submit", {
      from: kp.address,
      to,
      amount,
      priority,
    });
  }
}

// ── Convenience factory ────────────────────────────────────────────────────

/**
 * Create a fully ready SDK instance with a freshly generated wallet.
 *
 * @example
 * const { sdk, wallet } = await createWallet("http://localhost:8080");
 * console.log("Your address:", wallet.address);
 * console.log("Save your key:", wallet.privateKeyHex);
 */
export async function createWallet(
  rpcUrl: string
): Promise<{ sdk: BlackBookSDK; wallet: Keypair }> {
  const wallet = await BlackBookWallet.generate();
  const sdk = new BlackBookSDK({ rpcUrl, wallet });
  return { sdk, wallet };
}

/**
 * Restore an SDK instance from a saved private key.
 *
 * @example
 * const { sdk, wallet } = await loadWallet("http://localhost:8080", savedPrivKey);
 */
export async function loadWallet(
  rpcUrl: string,
  privateKeyHex: string
): Promise<{ sdk: BlackBookSDK; wallet: Keypair }> {
  const wallet = await BlackBookWallet.fromPrivateKey(privateKeyHex);
  const sdk = new BlackBookSDK({ rpcUrl, wallet });
  return { sdk, wallet };
}
