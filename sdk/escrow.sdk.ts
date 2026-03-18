/**
 * BlackBook L1 — Global Escrow Contract SDK
 * ============================================================================
 * Covers all interactions with the on-chain Global Escrow smart contract.
 *
 * Architecture (trustless, non-custodial):
 *   1. User calls deposit()       → BB tokens locked in escrow PDA on L1
 *   2. User plays on L2           → bets settled in L2 state
 *   3. L2 Sequencer calls submitStateRoot() → merkle root anchored on L1
 *   4. User calls withdraw()      → proves payout with merkle proof → gets BB
 *
 * Signing model:
 *   - deposit()  signs: "ESCROW_DEPOSIT:{wallet}:{amount}:{ts}:{nonce}"
 *   - withdraw() signs: "ESCROW_WITHDRAW:{market}:{wallet}:{amount}:{ts}:{nonce}"
 *   - submitStateRoot() is L2 Sequencer only (server-side, not frontend)
 *
 * Merkle leaf format (must match L2 tree builder):
 *   SHA256( walletAddress_bytes || amount_f64_le_bytes )
 *   Parent nodes: SHA256( sort(left, right) )  — smaller 32-byte hash first
 *
 * Dependencies: npm install @noble/ed25519 @noble/hashes bs58
 * ============================================================================
 */

// ── Types ──────────────────────────────────────────────────────────────────

export interface Keypair {
  address: string;       // base58 public key (IS the wallet address)
  privateKeyHex: string; // hex 32-byte private key — never send this
  publicKeyHex: string;  // hex 32-byte public key
}

// ── Response types ─────────────────────────────────────────────────────────

export interface EscrowDepositResponse {
  success: boolean;
  /** Amount of BB locked */
  deposited: number;
  wallet_address: string;
  escrow_address: string;
  /** User's BB balance after deposit */
  user_balance: number;
  /** Total BB held by the escrow PDA */
  escrow_balance: number;
}

export interface EscrowWithdrawResponse {
  success: boolean;
  /** Amount of BB released */
  withdrawn: number;
  market_id: string;
  wallet_address: string;
  /** User's BB balance after withdrawal */
  new_balance: number;
}

/**
 * Returned by the L2 Sequencer after state root submission.
 * The frontend SDK exposes this for completeness; in production the L2
 * backend calls this — not the user's browser.
 */
export interface StateRootResponse {
  success: boolean;
  market_id: string;
  /** Hex-encoded 32-byte SHA256 merkle root */
  merkle_root: string;
  /** Monotonic block counter from L2 */
  l2_block_number: number;
  /** L1 slot at which the root was anchored */
  slot: number;
}

export interface EscrowStatusResponse {
  escrow_address: string;
  /** BB locked in the escrow vault */
  escrow_balance_lamports: number;
  /** Number of markets with a settled state root */
  total_markets_settled: number;
  /** Whether the L2_SEQUENCER_PUBKEY env var is configured */
  l2_sequencer_configured: boolean;
}

export interface EscrowMarketResponse {
  success: boolean;
  market_id: string;
  /** Hex-encoded 32-byte merkle root submitted by the sequencer */
  merkle_root: string;
}

/**
 * A single node in a merkle proof path.
 * Obtain this array from the L2 API after market settlement.
 */
export type MerkleProof = string[]; // array of 64-char hex sibling hashes

// ── Internal helpers ───────────────────────────────────────────────────────

async function getCrypto() {
  const [ed, { hexToBytes, bytesToHex }] = await Promise.all([
    import("@noble/ed25519"),
    import("@noble/hashes/utils"),
  ]);
  return { ed, hexToBytes, bytesToHex };
}

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

// ── EscrowSDK ─────────────────────────────────────────────────────────────

export class EscrowSDK {
  private rpcUrl: string;
  private wallet?: Keypair;

  /**
   * @param rpcUrl  BlackBook L1 node URL, e.g. "http://localhost:8080"
   * @param wallet  Keypair for the user wallet (required for deposit/withdraw)
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

  // ── Read ─────────────────────────────────────────────────────────────────

  /**
   * GET /escrow/status
   * Returns the escrow vault address, locked balance, and settled market count.
   */
  status(): Promise<EscrowStatusResponse> {
    return this.get("/escrow/status");
  }

  /**
   * GET /escrow/market/:market_id
   * Returns the merkle root anchored on L1 for a specific L2 market.
   * Use this to confirm the L2 has settled before calling withdraw().
   *
   * @param marketId  L2 market identifier (e.g. "market_btc_42")
   */
  marketRoot(marketId: string): Promise<EscrowMarketResponse> {
    return this.get(`/escrow/market/${encodeURIComponent(marketId)}`);
  }

  // ── Writes (Ed25519 signed) ───────────────────────────────────────────────

  /**
   * POST /escrow/deposit — Lock $BB into the global escrow vault.
   *
   * Call this before placing bets on L2.
   * Tokens move:  user wallet  →  escrow PDA
   *
   * Signs: "ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"
   *
   * @param amount  Amount of $BB to lock (must be > 0, must not exceed balance)
   *
   * @example
   * const result = await escrow.deposit(50);
   * console.log("Escrow balance:", result.escrow_balance);
   */
  async deposit(amount: number): Promise<EscrowDepositResponse> {
    if (amount <= 0) throw new Error("amount must be > 0");
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
   * POST /escrow/withdraw — Claim winnings from escrow using a merkle proof.
   *
   * Tokens move:  escrow PDA  →  user wallet
   *
   * Prerequisites:
   *   1. The L2 must have settled the market (call marketRoot() to confirm)
   *   2. You must obtain a merkle proof from the L2 API for your wallet + amount
   *   3. Each (market_id, wallet_address) pair can only withdraw ONCE
   *
   * Signs: "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
   *
   * Merkle leaf built by L1:  SHA256( walletAddress_bytes || amount_f64_le_bytes )
   * Parent nodes:              SHA256( smaller_child || larger_child )
   *
   * @param marketId    L2 market identifier — must match root on L1
   * @param amount      Exact amount you are entitled to (must match merkle leaf)
   * @param merkleProof Array of 64-char hex sibling hashes (obtained from L2 API)
   *
   * @example
   * const proof = await l2Api.getMerkleProof(marketId, wallet.address);
   * const result = await escrow.withdraw("market_btc_42", 25.5, proof);
   * console.log("New balance:", result.new_balance);
   */
  async withdraw(
    marketId: string,
    amount: number,
    merkleProof: MerkleProof
  ): Promise<EscrowWithdrawResponse> {
    if (!marketId) throw new Error("marketId is required");
    if (amount <= 0) throw new Error("amount must be > 0");
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

  // ── L2 Sequencer only (server-side, not for end users) ───────────────────

  /**
   * POST /escrow/submit-state-root — Anchor an L2 market's merkle root on L1.
   *
   * ⚠️  This is called by the L2 Sequencer backend, NOT by end-user wallets.
   *     Exposed here for completeness and for sequencer SDK use.
   *
   * L1 verifies the signature against the hardcoded L2_SEQUENCER_PUBKEY.
   * No timestamp window — the l2BlockNumber carried inside the signed message
   * makes this replay-proof without a time window.
   *
   * Signs: "STATE_ROOT:{market_id}:{merkle_root}:{l2_block_number}"
   *
   * @param marketId       L2 market identifier
   * @param merkleRoot     64-char hex (32-byte SHA256 merkle root)
   * @param l2BlockNumber  Monotonically incrementing L2 block counter
   * @param sequencerPrivKeyHex  Sequencer's 32-byte private key (hex)
   *
   * @example — L2 backend only
   * await escrow.submitStateRoot("market_btc_42", rootHex, 1001, seqPrivKey);
   */
  async submitStateRoot(
    marketId: string,
    merkleRoot: string,
    l2BlockNumber: number,
    sequencerPrivKeyHex: string
  ): Promise<StateRootResponse> {
    if (merkleRoot.length !== 64)
      throw new Error("merkleRoot must be 64 hex chars (32 bytes)");

    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const message = `STATE_ROOT:${marketId}:${merkleRoot}:${l2BlockNumber}`;

    const sigBytes = await ed.signAsync(
      new TextEncoder().encode(message),
      hexToBytes(sequencerPrivKeyHex)
    );

    return this.post<StateRootResponse>("/escrow/submit-state-root", {
      market_id: marketId,
      merkle_root: merkleRoot,
      l2_block_number: l2BlockNumber,
      signature: bytesToHex(sigBytes),
    });
  }

  // ── Utility ───────────────────────────────────────────────────────────────

  /**
   * Build the SHA256 merkle leaf for a wallet + amount pair.
   * Use this to verify your leaf is present in the tree before calling withdraw().
   *
   * Leaf = SHA256( UTF8(walletAddress) || Float64LE(amount) )
   *
   * @returns 64-char hex string
   */
  static async buildLeaf(walletAddress: string, amount: number): Promise<string> {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");

    const addrBytes = new TextEncoder().encode(walletAddress);
    const amountBuffer = new ArrayBuffer(8);
    new DataView(amountBuffer).setFloat64(0, amount, true); // little-endian
    const amountBytes = new Uint8Array(amountBuffer);

    const leaf = new Uint8Array(addrBytes.length + 8);
    leaf.set(addrBytes, 0);
    leaf.set(amountBytes, addrBytes.length);

    return bytesToHex(sha256(leaf));
  }

  /**
   * Compute the merkle root from a leaf and its proof path.
   * Compare the result against marketRoot().merkle_root to verify
   * your proof is correct before submitting to withdraw().
   *
   * Uses sorted-pair hashing: SHA256( smaller_sibling || larger_sibling )
   *
   * @param leafHex    64-char hex leaf (from buildLeaf)
   * @param proof      Array of 64-char hex sibling hashes
   * @returns          64-char hex computed root
   */
  static async verifyProof(leafHex: string, proof: MerkleProof): Promise<string> {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");

    let current = hexToBytes(leafHex);

    for (const siblingHex of proof) {
      const sibling = hexToBytes(
        siblingHex.startsWith("0x") ? siblingHex.slice(2) : siblingHex
      );
      // Sort: smaller [u8;32] goes first — matches L1 verification logic
      let a: Uint8Array, b: Uint8Array;
      if (compareBytes(current, sibling) <= 0) {
        a = current; b = sibling;
      } else {
        a = sibling; b = current;
      }
      const combined = new Uint8Array(64);
      combined.set(a, 0);
      combined.set(b, 32);
      current = sha256(combined);
    }

    return bytesToHex(current);
  }
}

/** Lexicographic compare of two equal-length Uint8Arrays. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}
