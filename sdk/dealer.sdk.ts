/**
 * BlackBook L1 — Dealer + Escrow SDK (combined)
 * ============================================================================
 * The Dealer is the L2 operator hot-wallet that:
 *   - Manages its own BB balance (the "house bankroll")
 *   - Locks contest reserves into the global escrow before markets open
 *   - Approves user deposits (Solana USDC → BB minting)
 *   - Submits Merkle state roots after L2 market resolution
 *   - Batch-settles winner payouts
 *   - Releases withdrawals (BB → Solana USDC cashout)
 *   - Mints / burns BB tokens as needed
 *   - Sends wUSDT to user ATAs
 *   - Monitors L1 node health, escrow invariants, and supply audits
 *
 * EscrowSDK (also in this file) is the end-user counterpart:
 *   - User calls escrow.deposit()  → lock BB into escrow PDA
 *   - User plays on L2
 *   - Sequencer calls DealerSDK.submitStateRoot()
 *   - User calls escrow.withdraw() with Merkle proof → receive BB
 *
 * Dealer settlement cycle:
 *   1. lockBB()              → lock dealer BB into rollup vault PDA
 *   2. (L2 game plays out)
 *   3. buildMerkleTree()     → build Rollup Hub leaf tree (SHA256 string preimage)
 *   4. submitStateRoot()     → anchor Merkle root to Universal Rollup Hub
 *   5. settleWinners()       → batch-pay winners from dealer balance
 *   6. getProofForWinner()   → hand proof to each winner for on-chain exit
 *
 * Merkle tree format (must match L1 rollup/mod.rs verification):
 *   BB  Leaf: SHA256( "{rollup_id}:BB:{address}:{balance_lamports}" )
 *   Parent:   SHA256( min(left, right) || max(left, right) )   ← sorted pair
 *
 * Token units:
 *   BB  : 5 decimals, 1 BB = 100,000 lamports (LAMPORTS_PER_BB)
 *   wUSDT: 6 decimals; rate 10 BB = 1 wUSDT
 *
 * Dependencies: npm install @noble/ed25519 @noble/hashes bs58
 * ============================================================================
 */

// ── Types ──────────────────────────────────────────────────────────────────

export interface Keypair {
  /** base58-encoded Ed25519 public key (IS the wallet address on L1) */
  address: string;
  /** hex-encoded 32-byte Ed25519 private key — NEVER log or transmit */
  privateKeyHex: string;
  /** hex-encoded 32-byte Ed25519 public key */
  publicKeyHex: string;
}
  
// ── Response Types ─────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  network: string;
  blockchain: {
    total_supply: number;
    account_count: number;
    block_count: number;
  };
  poh_clock: Record<string, unknown>;
  consensus: Record<string, unknown>;
  block_production: Record<string, unknown>;
  infrastructure: Record<string, unknown>;
}

export interface BalanceResponse {
  address: string;
  balance: number;
  unit: string;
}

export interface UsdcBalanceResponse {
  address: string;
  usdc_balance: number;
  raw_balance: number;
  decimals: number;
  mint: string;
}

export interface SupplyAuditResponse {
  bb_total_supply: number;
  wusdc_total_supply: number;
  backing_ratio: number;
  invariant_ok: boolean;
}

export interface EscrowStatusResponse {
  escrow_address: string;
  escrow_balance_lamports: number;
  total_markets_settled: number;
  l2_sequencer_configured: boolean;
}

export interface ContestStatusResponse {
  contest_id: string;
  status: "OPEN" | "SETTLED" | "EXPIRED";
  total_deposited: number;
  total_claimed: number;
  merkle_root: string;
  claim_deadline_slot: number;
  l1_tx_hash: string;
}

export interface DepositStatusResponse {
  status: "pending" | "approved" | "not_found";
}

export interface WithdrawalStatusResponse {
  status: "pending" | "released" | "not_found";
}

export interface MintResponse {
  success: boolean;
  to: string;
  amount: number;
  new_balance: number;
}

export interface BurnResponse {
  success: boolean;
  from: string;
  amount: number;
  new_balance: number;
}

export interface SettlePayoutEntry {
  address: string;
  amount: number;
}

export interface SettleResponse {
  success: boolean;
  total_paid: number;
  results: Array<{
    address: string;
    amount: number;
    success: boolean;
    error?: string;
  }>;
}

export interface DepositApproveResponse {
  success: boolean;
  bb_minted: number;
  wusdc_minted: number;
  new_balance: number;
}

export interface WithdrawalReleaseResponse {
  success: boolean;
  status: string;
}

export interface SendWusdcResponse {
  success: boolean;
  from_ata: string;
  to_ata: string;
  to_balance: number;
}

export interface TransferResponse {
  success: boolean;
  tx_id: string;
  from: string;
  to: string;
  amount: number;
}

export interface EscrowDepositResponse {
  success: boolean;
  deposited: number;
  wallet_address: string;
  escrow_address: string;
  user_balance: number;
  escrow_balance: number;
}

/** Returned when a user withdraws winnings from the escrow contract. */
export interface EscrowWithdrawResponse {
  success: boolean;
  withdrawn: number;
  market_id: string;
  wallet_address: string;
  /** User's BB balance after the withdrawal */
  new_balance: number;
}

/** Array of 64-char hex sibling hashes that form a Merkle path. */
export type MerkleProof = string[];

export interface StateRootResponse {
  success: boolean;
  market_id: string;
  merkle_root: string;
  l2_block_number: number;
  slot: number;
}

export interface EscrowMarketResponse {
  success: boolean;
  market_id: string;
  merkle_root: string;
}

export interface TransactionResponse {
  success: boolean;
  transaction: Record<string, unknown>;
  status: string;
}

export interface TransactionHistoryResponse {
  address: string;
  transactions: Array<Record<string, unknown>>;
  total: number;
  page: number;
}

// ── gRPC response types (settlement service, port 50052) ───────────────────

/** Response from GetBalance unary RPC (gRPC :50052, unauthenticated cache-miss fill). */
export interface GrpcGetBalanceResponse {
  address: string;
  balance_lamports: number;
  current_slot: number;
}

/** One event pushed by SubscribeBalances server-streaming RPC. */
export interface GrpcBalanceUpdate {
  address: string;
  new_balance_lamports: number;
  /** L1 always emits 0; L2 computes delta from its own cache. */
  delta_lamports: number;
  slot: number;
  timestamp: number;
  block_hash: string;
}

export interface GrpcInitContestResponse {
  confirmed: boolean;
  l1_tx_hash: string;
  error_message: string;
}

export interface GrpcSubmitMerkleRootResponse {
  success: boolean;
  l1_tx_hash: string;
  l1_finalized_slot: number;
  error_message: string;
}

export interface GrpcContestStatusResponse {
  status: string;
  total_deposited: number;
  total_claimed: number;
  merkle_root: Uint8Array;
  claim_deadline_slot: number;
  l1_tx_hash: string;
}

export interface GrpcSyncBridgeResponse {
  node_id: string;
  latest_slot: number;
  uptime_secs: number;
}

// ── Merkle types ───────────────────────────────────────────────────────────

/** BB payout entry for Merkle tree construction. Amounts in lamports (u64). */
export interface MerkleLeafData {
  walletAddress: string;
  /** Raw lamports (1 BB = 100,000). Use bbToLamports() to convert. */
  balanceLamports: bigint;
}

export interface MerkleTreeResult {
  root: Uint8Array;
  rootHex: string;
  leaves: Uint8Array[];
  proofs: Map<string, string[]>;
}

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

/** Convert raw lamports back to whole-BB (display boundary only). */
export function fromSplUnits(lamports: bigint): number {
  return lamportsToBb(lamports);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

// ── DealerSDK ──────────────────────────────────────────────────────────────

/**
 * Master SDK for an L2 Prediction Market Dealer operating against BlackBook L1.
 *
 * The Dealer is the house — it holds a hot wallet with enough BB to bankroll
 * all active markets, locks reserves into the global escrow, approves deposits,
 * settles winners, and manages the full lifecycle of prediction contests.
 *
 * ```ts
 * const dealer = new DealerSDK("http://l1-node:8080", dealerKeypair);
 *
 * // Check bankroll
 * const { balance } = await dealer.getBalance();
 *
 * // Lock reserve for a new prediction market
 * await dealer.escrowDeposit(500); // 500 BB locked into escrow
 *
 * // After L2 resolves the market — submit state root
 * const tree = await dealer.buildMerkleTree(winners);
 * await dealer.submitStateRoot("market_btc_42", tree, 1001n);
 *
 * // Batch-pay winners
 * await dealer.settleWinners(payouts);
 * ```
 */
export class DealerSDK {
  private rpcUrl: string;
  private grpcUrl: string;
  private wallet: Keypair;

  /**
   * @param rpcUrl   L1 HTTP API, e.g. "http://localhost:8080"
   * @param wallet   Dealer hot wallet keypair (from DEALER_PRIVATE_KEY)
   * @param grpcUrl  L1 gRPC settlement service, e.g. "http://localhost:50052"
   */
  constructor(rpcUrl: string, wallet: Keypair, grpcUrl?: string) {
    this.rpcUrl = rpcUrl.replace(/\/$/, "");
    this.grpcUrl = (grpcUrl ?? rpcUrl.replace(/:\d+$/, ":50052")).replace(
      /\/$/,
      ""
    );
    this.wallet = wallet;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  HTTP helpers
  // ═══════════════════════════════════════════════════════════════════════════

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) {
      throw new Error(
        `${path} failed (${res.status}): ${(json as any).error ?? JSON.stringify(json)}`
      );
    }
    return json as T;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`);
    const json = await res.json();
    if (!res.ok) {
      throw new Error(
        `${path} failed (${res.status}): ${(json as any).error ?? JSON.stringify(json)}`
      );
    }
    return json as T;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  Signing
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Sign a UTF-8 message with the dealer's Ed25519 private key.
   * All signed messages on BlackBook L1 are UTF-8 strings.
   */
  private async signMessage(message: string): Promise<string> {
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const privBytes = hexToBytes(this.wallet.privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    const sigBytes = await ed.signAsync(msgBytes, privBytes);
    return bytesToHex(sigBytes);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  1. WALLET MANAGEMENT — Dealer's own balance & health
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the dealer wallet's BB balance. */
  async getBalance(): Promise<BalanceResponse> {
    return this.get(`/balance/${this.wallet.address}`);
  }

  /** Get the dealer wallet's wUSDT balance. */
  async getUsdtBalance(): Promise<UsdcBalanceResponse> {
    return this.get(`/usdc/balance/${this.wallet.address}`);
  }

  /**
   * Get the dealer's BB and wUSDT balances.
   */
  async getAllBalances(): Promise<{
    bb: { balance: number; unit: string };
    wusdt: { balance: number; unit: string };
  }> {
    const [bb, wusdt] = await Promise.all([
      this.getBalance(),
      this.getUsdtBalance(),
    ]);
    return {
      bb: { balance: bb.balance, unit: "BB" },
      wusdt: { balance: wusdt.usdc_balance, unit: "wUSDT" },
    };
  }

  /**
   * Check if the dealer has enough BB to bankroll a market.
   * @param requiredBB  Minimum BB balance needed
   * @returns true if balance >= requiredBB
   */
  async hasSufficientBankroll(requiredBB: number): Promise<boolean> {
    const { balance } = await this.getBalance();
    return balance >= requiredBB;
  }

  /** L1 node health, version, PoH clock, consensus state. */
  async health(): Promise<HealthResponse> {
    return this.get("/health");
  }

  /** BB/wUSDC supply invariant check — backing_ratio should be >= 1.0. */
  async supplyAudit(): Promise<SupplyAuditResponse> {
    return this.get("/supply/audit");
  }

  /** Dealer's transaction history (paginated). */
  async getTransactionHistory(
    page = 1,
    limit = 50
  ): Promise<TransactionHistoryResponse> {
    return this.get(
      `/address/${this.wallet.address}/transactions?page=${page}&limit=${limit}`
    );
  }

  /** Look up a specific transaction by ID. */
  async getTransaction(txId: string): Promise<TransactionResponse> {
    return this.get(`/tx/${encodeURIComponent(txId)}`);
  }

  /** Get any wallet's BB balance (for checking user balances). */
  async getWalletBalance(address: string): Promise<BalanceResponse> {
    return this.get(`/balance/${encodeURIComponent(address)}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  2. DEPOSIT GATEWAY — Approve Solana USDC → BB minting
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Approve a pending deposit after verifying the Solana USDC transaction.
   * This mints BB + wUSDC to the user's L1 wallet.
   *
   * Rate: 1 USDC = 10 BB (hardcoded in L1 contract)
   *
   * @param externalTxHash  The Solana transaction signature (base58)
   */
  async approveDeposit(
    externalTxHash: string
  ): Promise<DepositApproveResponse> {
    return this.post("/admin/deposit/approve", {
      external_tx_hash: externalTxHash,
    });
  }

  /** Check the status of a user's deposit by Solana tx hash. */
  async getDepositStatus(txHash: string): Promise<DepositStatusResponse> {
    return this.get(`/deposit/status/${encodeURIComponent(txHash)}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  3. WITHDRAWAL GATEWAY — Release USDC after user burns wUSDC
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Mark a pending withdrawal as released after sending real USDC on Solana.
   *
   * Flow:
   *   1. User calls POST /withdraw/request → burns wUSDC on L1
   *   2. Dealer sees pending withdrawal
   *   3. Dealer sends real USDC on Solana
   *   4. Dealer calls releaseWithdrawal() with the Solana tx sig
   *
   * @param withdrawalId  L1 withdrawal UUID
   * @param solanaTxHash  Solana transaction signature proving USDC was sent
   */
  async releaseWithdrawal(
    withdrawalId: string,
    solanaTxHash: string
  ): Promise<WithdrawalReleaseResponse> {
    return this.post("/admin/withdraw/release", {
      withdrawal_id: withdrawalId,
      solana_tx_hash: solanaTxHash,
    });
  }

  /** Check the status of a user's withdrawal. */
  async getWithdrawalStatus(
    withdrawalId: string
  ): Promise<WithdrawalStatusResponse> {
    return this.get(`/withdraw/status/${encodeURIComponent(withdrawalId)}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  4. MINT / BURN — BB token supply management
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Mint BB tokens to any address. Used for:
   *   - Funding the dealer's own bankroll
   *   - Airdropping promotional BB to users
   *   - Correcting ledger discrepancies
   *
   * @param to      Recipient base58 address
   * @param amount  BB amount (human-readable, e.g. 100.5)
   */
  async mint(to: string, amount: number): Promise<MintResponse> {
    return this.post("/admin/mint", { to, amount });
  }

  /**
   * Burn BB tokens from any address.
   *
   * @param from    Address to debit
   * @param amount  BB amount to destroy
   */
  async burn(from: string, amount: number): Promise<BurnResponse> {
    return this.post("/admin/burn", { from, amount });
  }

  /**
   * Mint wUSDC SPL tokens to a user's ATA.
   *
   * @param to      Recipient base58 address
   * @param amount  wUSDC amount (human-readable)
   */
  async mintUsdc(to: string, amount: number): Promise<{ success: boolean }> {
    return this.post("/admin/usdc/mint", { to, amount });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  5. ESCROW — Lock / unlock BB in the global escrow PDA
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the global escrow vault status (balance, settled markets). */
  async escrowStatus(): Promise<EscrowStatusResponse> {
    return this.get("/escrow/status");
  }

  /** Get the Merkle root for a settled market. */
  async escrowMarketRoot(marketId: string): Promise<EscrowMarketResponse> {
    return this.get(`/escrow/market/${encodeURIComponent(marketId)}`);
  }

  /** Get full contest state including deposits, claims, deadline. */
  async escrowContestStatus(
    contestId: string
  ): Promise<ContestStatusResponse> {
    return this.get(`/escrow/contest/${encodeURIComponent(contestId)}`);
  }

  /**
   * Deposit the dealer's BB into the global escrow PDA.
   * This locks the bankroll before a market opens so users know the prize
   * pool is backed on-chain.
   *
   * Signs: "ESCROW_DEPOSIT:{wallet}:{amount}:{timestamp}:{nonce}"
   *
   * @param amountBB  BB to lock (human-readable)
   */
  async escrowDeposit(amountBB: number): Promise<EscrowDepositResponse> {
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `ESCROW_DEPOSIT:${this.wallet.address}:${amountBB}:${timestamp}:${nonce}`;
    const signature = await this.signMessage(message);

    return this.post("/escrow/deposit", {
      wallet_address: this.wallet.address,
      amount: amountBB,
      public_key: this.wallet.publicKeyHex,
      signature,
      timestamp,
      nonce,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  6. STATE ROOT SUBMISSION — Anchor L2 market resolution on L1
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Submit a Merkle state root to the Universal Rollup Hub after L2 resolves a batch.
   *
   * This replaces the old `/escrow/submit-state-root` endpoint. The L1 enforces:
   *   - Ed25519 signature from the configured rollup sequencer
   *   - Monotonically increasing batch_id (replays rejected with 409)
   *   - Signature is a UTF-8 string (not binary)
   *
   * Canonical signed message (must match L1 Rust exactly):
   *   `"ROLLUP_SUBMIT_ROOT:{rollupId}:{batchId}:{merkleRootHex}:{timestamp}"`
   *
   * @param rollupId     "L2", "L3", or "L5"
   * @param batchId      Monotonically increasing batch counter
   * @param merkleRoot   64-char hex SHA-256 Merkle root from buildRollupMerkleRoot()
   */
  async submitStateRoot(
    rollupId: string,
    batchId: number,
    merkleRoot: string
  ): Promise<StateRootResponse> {
    const timestamp = nowSecs();
    const message = `ROLLUP_SUBMIT_ROOT:${rollupId}:${batchId}:${merkleRoot}:${timestamp}`;
    const signature = await this.signMessage(message);

    return this.post(`/rollup/${rollupId}/submit_root`, {
      batch_id: batchId,
      merkle_root_hex: merkleRoot,
      sequencer_public_key: this.wallet.publicKeyHex,
      signature,
      timestamp,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  7. UNIVERSAL ROLLUP HUB — Lock BB into vault, track lock status
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Lock BB into the rollup vault PDA (dealer-side entry point).
   *
   * Signs: `"ROLLUP_LOCK_BB:{rollupId}:{wallet}:{bbLamports}:{symbolHint}:{ts}:{nonce}"`
   *
   * @param rollupId    "L2", "L3", or "L5"
   * @param bbLamports  Amount in lamports (use bbToLamports() helper)
   * @param symbolHint  Optional market hint e.g. "BTC-USD"
   */
  async lockBB(
    rollupId: string,
    bbLamports: bigint,
    symbolHint = ""
  ): Promise<{ success: boolean; lock_id: string; slot: number }> {
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message =
      `ROLLUP_LOCK_BB:${rollupId}:${this.wallet.address}:${bbLamports}:${symbolHint}:${timestamp}:${nonce}`;
    const signature = await this.signMessage(message);

    return this.post(`/rollup/${rollupId}/lock_bb`, {
      wallet: this.wallet.address,
      bb_lamports: Number(bbLamports),
      symbol_hint: symbolHint,
      public_key: this.wallet.publicKeyHex,
      signature,
      timestamp,
      nonce,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  8. SETTLEMENT — Batch-pay winners from dealer balance
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Batch-settle winner payouts after L2 market resolution.
   *
   * This transfers BB from the dealer's balance directly to each winner.
   * Use this for immediate payouts; for trustless claims, submit a state root
   * and let users withdraw with Merkle proofs via the escrow contract.
   *
   * @param payouts         Array of { address, amount } pairs
   * @param batchReceiptId  Optional idempotency key (prevents duplicate settlement)
   */
  async settleWinners(
    payouts: SettlePayoutEntry[],
    batchReceiptId?: string
  ): Promise<SettleResponse> {
    return this.post("/admin/dealer/settle", {
      payouts,
      batch_receipt_id: batchReceiptId,
    });
  }

  /**
   * Send wUSDT to a user's associated token account.
   *
   * @param to           Recipient base58 address
   * @param wusdtAmount  wUSDT amount (human-readable)
   */
  async sendWusdt(
    to: string,
    wusdtAmount: number
  ): Promise<SendWusdcResponse> {
    return this.post("/admin/dealer/send_wusdt", {
      to,
      wusdt_amount: wusdtAmount,
    });
  }

  /**
   * Transfer BB from the dealer wallet to another address (signed).
   *
   * Signs: `"TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}"`
   *
   * @param to      Recipient base58 address
   * @param amount  BB amount (human-readable, e.g. 10.5)
   */
  async transfer(to: string, amount: number): Promise<TransferResponse> {
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `TRANSFER:${this.wallet.address}:${to}:${amount}:${timestamp}:${nonce}`;
    const signature = await this.signMessage(message);

    return this.post("/transfer/simple", {
      public_key: this.wallet.publicKeyHex,
      wallet_address: this.wallet.address,
      payload: JSON.stringify({ to, amount }),
      timestamp,
      nonce,
      chain_id: 1,
      signature,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  8. MERKLE TREE — Build proofs for L2 market resolution
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Build a Merkle tree from user balances for the Universal Rollup Hub.
   *
   * Leaf format (must match L1 Rust `rollup/mod.rs` exactly):
   *   BB leaf:  SHA256( "{rollupId}:BB:{address}:{balance_lamports}" )
   *
   * Parent hashing (sorted-pair, deterministic):
   *   SHA256( min(left, right) || max(left, right) )
   *
   * @param rollupId  "L2", "L3", or "L5"
   * @param winners   Array of { walletAddress, balanceLamports } — lamports (u64 bigint)
   * @returns         MerkleTreeResult with root, leaves, and per-wallet proofs
   */
  async buildMerkleTree(
    rollupId: string,
    winners: Array<{ walletAddress: string; balanceLamports: bigint }>
  ): Promise<MerkleTreeResult> {
    if (winners.length === 0) {
      throw new Error("Cannot build Merkle tree with zero winners");
    }

    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");
    const enc = new TextEncoder();

    // ── Build leaves (canonical string preimage) ──────────────────────────
    const leaves: Uint8Array[] = [];
    const walletToIndex = new Map<string, number>();

    for (let i = 0; i < winners.length; i++) {
      const { walletAddress, balanceLamports } = winners[i];
      // Canonical: "{rollupId}:BB:{address}:{balance_lamports}"
      const preimage = `${rollupId}:BB:${walletAddress}:${balanceLamports}`;
      leaves.push(sha256(enc.encode(preimage)));
      walletToIndex.set(walletAddress, i);
    }

    // ── Build tree bottom-up ─────────────────────────────────────────────
    const layers: Uint8Array[][] = [leaves.slice()];

    while (layers[layers.length - 1].length > 1) {
      const current = layers[layers.length - 1];
      const next: Uint8Array[] = [];

      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(this.merkleHash(sha256, current[i], current[i + 1]));
        } else {
          // Odd node — promote to next level
          next.push(current[i]);
        }
      }
      layers.push(next);
    }

    const root = layers[layers.length - 1][0];

    // ── Extract proofs for each winner ───────────────────────────────────
    const proofs = new Map<string, string[]>();

    for (const [walletAddress, leafIndex] of walletToIndex) {
      const proof: string[] = [];
      let idx = leafIndex;

      for (let level = 0; level < layers.length - 1; level++) {
        const layer = layers[level];
        const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;

        if (siblingIdx < layer.length) {
          proof.push(bytesToHex(layer[siblingIdx]));
        }
        idx = Math.floor(idx / 2);
      }

      proofs.set(walletAddress, proof);
    }

    return {
      root,
      rootHex: bytesToHex(root),
      leaves,
      proofs,
    };
  }

  /** Sorted-pair Merkle hash: SHA256( min(a,b) || max(a,b) ) */
  private merkleHash(
    sha256Fn: (data: Uint8Array) => Uint8Array,
    a: Uint8Array,
    b: Uint8Array
  ): Uint8Array {
    let left = a;
    let right = b;
    if (compareBytes(left, right) > 0) {
      [left, right] = [right, left];
    }
    const combined = new Uint8Array(64);
    combined.set(left, 0);
    combined.set(right, 32);
    return sha256Fn(combined);
  }

  /**
   * Get the Merkle proof for a specific wallet address in a tree.
   */
  getProofForWinner(
    tree: MerkleTreeResult,
    walletAddress: string
  ): string[] {
    const proof = tree.proofs.get(walletAddress);
    if (!proof) {
      throw new Error(`No proof found for wallet ${walletAddress}`);
    }
    return proof;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  9. FULL MARKET LIFECYCLE — Convenience orchestrators
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Open a new prediction market: verify bankroll and lock the reserve.
   *
   * @param contestId   Unique market identifier (e.g. "market_btc_42")
   * @param reserveBB   BB to lock as prize pool (human-readable)
   * @returns           Escrow deposit receipt
   */
  async openMarket(
    contestId: string,
    reserveBB: number
  ): Promise<{ contestId: string; escrowReceipt: EscrowDepositResponse }> {
    // Pre-flight: check dealer has enough
    const sufficient = await this.hasSufficientBankroll(reserveBB);
    if (!sufficient) {
      const { balance } = await this.getBalance();
      throw new Error(
        `Insufficient bankroll: need ${reserveBB} BB, have ${balance} BB`
      );
    }

    const escrowReceipt = await this.escrowDeposit(reserveBB);
    return { contestId, escrowReceipt };
  }

  /**
   * Resolve a market end-to-end:
   *   1. Build Merkle tree from winner list
   *   2. Submit state root to L1 via Universal Rollup Hub
   *   3. Return the tree (with proofs for each winner)
   *
   * @param rollupId      "L2", "L3", or "L5"
   * @param batchId       Monotonically increasing batch counter
   * @param winners       Array of { walletAddress, balanceLamports }
   */
  async resolveMarket(
    rollupId: string,
    batchId: number,
    winners: MerkleLeafData[]
  ): Promise<{
    tree: MerkleTreeResult;
    stateRootReceipt: StateRootResponse;
  }> {
    const tree = await this.buildMerkleTree(rollupId, winners);
    const stateRootReceipt = await this.submitStateRoot(rollupId, batchId, tree.rootHex);
    return { tree, stateRootReceipt };
  }

  /**
   * Full settlement pipeline for a resolved market:
   *   1. Resolve market (build tree + submit state root)
   *   2. Batch-settle winners via dealer balance transfers
   *   3. Return all receipts
   *
   * @param rollupId          "L2", "L3", or "L5"
   * @param batchId           Monotonically increasing batch counter
   * @param winners           Array of { walletAddress, balanceLamports }
   * @param batchReceiptId    Optional idempotency key
   */
  async settleMarket(
    rollupId: string,
    batchId: number,
    winners: MerkleLeafData[],
    batchReceiptId?: string
  ): Promise<{
    tree: MerkleTreeResult;
    stateRootReceipt: StateRootResponse;
    settleReceipt: SettleResponse;
  }> {
    const { tree, stateRootReceipt } = await this.resolveMarket(
      rollupId,
      batchId,
      winners
    );

    const payouts: SettlePayoutEntry[] = winners.map((w) => ({
      address: w.walletAddress,
      amount: lamportsToBb(w.balanceLamports),
    }));

    const settleReceipt = await this.settleWinners(
      payouts,
      batchReceiptId ?? `settle_${rollupId}_${batchId}_${Date.now()}`
    );

    return { tree, stateRootReceipt, settleReceipt };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  10. MONITORING — Health checks & invariant validation
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Run a full pre-flight check before opening a new market.
   * Verifies: L1 is healthy, supply invariant holds, dealer has enough BB,
   * and the escrow is properly configured.
   *
   * @param requiredBB  Minimum dealer BB balance needed for the market
   */
  async preflight(requiredBB: number): Promise<{
    healthy: boolean;
    balance: number;
    sufficient: boolean;
    supplyInvariant: boolean;
    escrowConfigured: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    const [healthRes, balanceRes, auditRes, escrowRes] = await Promise.all([
      this.health().catch((e) => {
        errors.push(`Health check failed: ${e.message}`);
        return null;
      }),
      this.getBalance().catch((e) => {
        errors.push(`Balance check failed: ${e.message}`);
        return null;
      }),
      this.supplyAudit().catch((e) => {
        errors.push(`Supply audit failed: ${e.message}`);
        return null;
      }),
      this.escrowStatus().catch((e) => {
        errors.push(`Escrow status failed: ${e.message}`);
        return null;
      }),
    ]);

    const healthy = healthRes !== null;
    const balance = balanceRes?.balance ?? 0;
    const sufficient = balance >= requiredBB;
    const supplyInvariant = auditRes?.invariant_ok ?? false;
    const escrowConfigured = escrowRes?.l2_sequencer_configured ?? false;

    if (!sufficient) {
      errors.push(
        `Insufficient bankroll: need ${requiredBB} BB, have ${balance} BB`
      );
    }
    if (!supplyInvariant) {
      errors.push("Supply invariant check failed — BB/wUSDC backing mismatch");
    }
    if (!escrowConfigured) {
      errors.push("L2 sequencer pubkey not configured on L1 node");
    }

    return { healthy, balance, sufficient, supplyInvariant, escrowConfigured, errors };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  11. L2 BALANCE CACHE — Local balance mirror fed by SubscribeBalances
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Fetch an address's BB balance directly from L1 via the HTTP REST API.
   * Use this as a cache-miss fallback when the SubscribeBalances stream has
   * not yet delivered a value for the requested address.
   *
   * @param address  Base58 wallet address
   * @returns        BB balance in lamports and human-readable BB
   */
  async getL1Balance(address: string): Promise<{ lamports: number; bb: number }> {
    const res: BalanceResponse = await this.get(`/balance/${encodeURIComponent(address)}`);
    // /balance/:addr returns { balance: number } in whole BB units
    const lamports = Math.round(res.balance * 100_000); // 1 BB = 100_000 lamports
    return { lamports, bb: res.balance };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  UDP TPU — High-throughput binary transaction submission
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Build the canonical binary message that must be signed for a TPU packet.
   *
   * Format (matches runtime/tpu.rs Ed25519 verification):
   *   chain_id(1) | from_utf8 | '|' | to_utf8 | '|' | amount_le(8) | '|' | timestamp_le(8) | '|' | nonce_utf8
   *
   * @param from       Sender base58 address
   * @param to         Recipient base58 address
   * @param lamports   Amount in lamports (1 BB = 100_000 lamports)
   * @param timestamp  Unix seconds
   * @param nonce      Replay-protection nonce string
   * @param chainId    Must be 1 for BlackBook mainnet
   */
  buildTpuPacketBytes(
    from: string,
    to: string,
    lamports: bigint,
    timestamp: number,
    nonce: string,
    chainId = 1,
  ): Uint8Array {
    const enc = new TextEncoder();
    const sep = new Uint8Array([0x7c]); // '|'
    const amountBuf = new Uint8Array(8);
    const tsBuf = new Uint8Array(8);
    // Write lamports as little-endian u64
    let v = lamports;
    for (let i = 0; i < 8; i++) { amountBuf[i] = Number(v & 0xffn); v >>= 8n; }
    // Write timestamp as little-endian u64
    let t = BigInt(timestamp);
    for (let i = 0; i < 8; i++) { tsBuf[i] = Number(t & 0xffn); t >>= 8n; }

    const parts = [
      new Uint8Array([chainId]),
      enc.encode(from), sep,
      enc.encode(to), sep,
      amountBuf, sep,
      tsBuf, sep,
      enc.encode(nonce),
    ];
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) { out.set(p, offset); offset += p.length; }
    return out;
  }

  /**
   * Sign a TPU packet and return the hex signature.
   * The canonical message is binary (not JSON) — see buildTpuPacketBytes().
   *
   * @param to        Recipient base58 address
   * @param lamports  Amount in lamports (1 BB = 100_000 lamports)
   * @param nonce     Unique nonce string for replay protection
   * @param chainId   Must be 1 for BlackBook mainnet
   * @returns { signature, timestamp, nonce } ready to embed in TpuPacket
   */
  async signTpuPacket(
    to: string,
    lamports: bigint,
    nonce?: string,
    chainId = 1,
  ): Promise<{ signature: string; timestamp: number; nonce: string }> {
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const ts = nowSecs();
    const n = nonce ?? randomNonce();
    const msg = this.buildTpuPacketBytes(this.wallet.address, to, lamports, ts, n, chainId);
    const privBytes = hexToBytes(this.wallet.privateKeyHex);
    const sigBytes = await ed.signAsync(msg, privBytes);
    return { signature: bytesToHex(sigBytes), timestamp: ts, nonce: n };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  L2 Balance Cache — Self-Healing Mirror of L1 Balances
// ═══════════════════════════════════════════════════════════════════════════

/**
 * L2-side balance cache populated by the SubscribeBalances gRPC stream.
 *
 * Self-Healing Cache (Path A) pattern:
 *   - On reconnect: flush ALL entries (stale data is worse than a cache miss).
 *   - On bet entry cache miss: call `getOrFetch()` to lazy-fill via HTTP.
 *   - Idempotency key: `(address, slot)` — ignore events with slot <= stored slot.
 *
 * Typical wiring (Node.js L2 sequencer with @grpc/grpc-js):
 *
 * ```ts
 * import * as grpc from "@grpc/grpc-js";
 * import * as proto from "./generated/settlement_grpc_pb";  // tonic generated stubs
 *
 * const stub = new proto.SettlementServiceClient(
 *   "localhost:50052", grpc.credentials.createInsecure()
 * );
 * const cache = new BalanceCache(sdk);
 *
 * function connectFeed(addressFilter: string[]) {
 *   const stream = stub.subscribeBalances({
 *     address_filter: addressFilter,
 *     timestamp: Math.floor(Date.now() / 1000),
 *     client_pubkey: sequencerPubkeyBytes,
 *     client_sig: ed25519Sign("SUBSCRIBE_BALANCES" + timestamp_le8),
 *   });
 *   stream.on("data", (ev: GrpcBalanceUpdate) => cache.update(ev));
 *   stream.on("error", () => { cache.flush(); setTimeout(() => connectFeed(addressFilter), 2000); });
 * }
 * ```
 */
export class BalanceCache {
  /** address → { lamports, slot } */
  private entries = new Map<string, { lamports: number; slot: number }>();
  private sdk: DealerSDK;

  constructor(sdk: DealerSDK) {
    this.sdk = sdk;
  }

  /**
   * Apply an inbound SubscribeBalances event.
   * Silently ignores stale events (slot <= stored slot).
   */
  update(event: GrpcBalanceUpdate): void {
    const current = this.entries.get(event.address);
    if (current && current.slot >= event.slot) return;
    this.entries.set(event.address, {
      lamports: event.new_balance_lamports,
      slot: event.slot,
    });
  }

  /**
   * Get balance from cache; if not present, fill from L1 via HTTP and cache result.
   * Returns lamports.
   */
  async getOrFetch(address: string): Promise<number> {
    const cached = this.entries.get(address);
    if (cached) return cached.lamports;

    // Cache miss — lazy fill from L1 HTTP endpoint
    const { lamports } = await this.sdk.getL1Balance(address);
    // Slot 0 means "filled from HTTP, not from broadcast" — a real broadcast event
    // will always carry slot >= 1 and will overwrite this entry.
    this.entries.set(address, { lamports, slot: 0 });
    return lamports;
  }

  /**
   * Flush the entire cache.
   * Call this whenever the SubscribeBalances stream disconnects and reconnects
   * to prevent serving stale data during the reconnect window.
   */
  flush(): void {
    this.entries.clear();
  }

  /** Peek at a cached value without triggering an HTTP fallback. Returns null on miss. */
  peek(address: string): { lamports: number; slot: number } | null {
    return this.entries.get(address) ?? null;
  }

  /** Current number of addresses in the cache. */
  get size(): number {
    return this.entries.size;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  EscrowSDK — End-user escrow interactions (deposit, withdraw, verify proof)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * User-facing SDK for the BlackBook Global Escrow contract.
 *
 * This is the counterpart to DealerSDK — used by *end-users* to:
 *   1. Lock BB into the escrow vault before playing on L2
 *   2. Withdraw winnings with a Merkle proof after the sequencer settles
 *
 * ```ts
 * const escrow = new EscrowSDK("http://localhost:8080", userKeypair);
 * await escrow.deposit(50);                                    // lock 50 BB
 * const proof = await l2Api.getMerkleProof(marketId, wallet);  // from L2
 * await escrow.withdraw("market_btc_42", 75, proof);           // claim 75 BB
 * ```
 */
export class EscrowSDK {
  private rpcUrl: string;
  private wallet?: Keypair;

  constructor(rpcUrl: string, wallet?: Keypair) {
    this.rpcUrl = rpcUrl.replace(/\/$/, "");
    this.wallet = wallet;
  }

  setWallet(wallet: Keypair): void { this.wallet = wallet; }

  private requireWallet(): Keypair {
    if (!this.wallet) throw new Error("No wallet set. Call setWallet(keypair) first.");
    return this.wallet;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(`${path} failed (${res.status}): ${(json as any).error ?? JSON.stringify(json)}`);
    return json as T;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.rpcUrl}${path}`);
    const json = await res.json();
    if (!res.ok) throw new Error(`${path} failed (${res.status}): ${(json as any).error ?? JSON.stringify(json)}`);
    return json as T;
  }

  // ── Read ─────────────────────────────────────────────────────────────────

  /** GET /escrow/status — Vault address, locked balance, settled market count. */
  status(): Promise<EscrowStatusResponse> {
    return this.get("/escrow/status");
  }

  /**
   * GET /escrow/market/:market_id — Merkle root anchored on L1 for a market.
   * Use this to confirm the L2 has settled before calling withdraw().
   */
  marketRoot(marketId: string): Promise<EscrowMarketResponse> {
    return this.get(`/escrow/market/${encodeURIComponent(marketId)}`);
  }

  // ── Writes (Ed25519 signed) ───────────────────────────────────────────────

  /**
   * POST /escrow/deposit — Lock $BB into the global escrow vault.
   *
   * Tokens move: user wallet → escrow PDA.
   * Signs: `"ESCROW_DEPOSIT:{wallet}:{amount}:{timestamp}:{nonce}"`
   */
  async deposit(amount: number): Promise<EscrowDepositResponse> {
    if (amount <= 0) throw new Error("amount must be > 0");
    const kp = this.requireWallet();
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const message = `ESCROW_DEPOSIT:${kp.address}:${amount}:${timestamp}:${nonce}`;
    const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));
    return this.post<EscrowDepositResponse>("/escrow/deposit", {
      wallet_address: kp.address, amount,
      public_key: kp.publicKeyHex, signature: bytesToHex(sigBytes), timestamp, nonce,
    });
  }

  /**
   * POST /escrow/withdraw — Claim winnings with a Merkle proof.
   *
   * Tokens move: escrow PDA → user wallet.
   * Each (market_id, wallet) pair can only withdraw once.
   * Signs: `"ESCROW_WITHDRAW:{market_id}:{wallet}:{amount}:{timestamp}:{nonce}"`
   *
   * @param marketId    L2 market identifier (must match a settled state root)
   * @param amount      Exact amount entitled (must match the Merkle leaf)
   * @param merkleProof Array of 64-char hex sibling hashes from L2
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
    const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));
    return this.post<EscrowWithdrawResponse>("/escrow/withdraw", {
      market_id: marketId, amount,
      wallet_address: kp.address, merkle_proof: merkleProof,
      public_key: kp.publicKeyHex, signature: bytesToHex(sigBytes), timestamp, nonce,
    });
  }

  // ── Proof Utilities ───────────────────────────────────────────────────────

  /**
   * Build the SHA-256 Merkle leaf for the GLOBAL ESCROW contract (legacy format).
   *
   * Leaf = SHA256( UTF8(walletAddress) || Float64LE(amount) )
   *
   * For Universal Rollup Hub exits use:
   *   SHA256( "{rollupId}:BB:{address}:{balance_lamports}" )
   *
   * @returns 64-char hex string
   */
  static async buildLeaf(walletAddress: string, amount: number): Promise<string> {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = await import("@noble/hashes/utils");
    const addrBytes = new TextEncoder().encode(walletAddress);
    const amountBuffer = new ArrayBuffer(8);
    new DataView(amountBuffer).setFloat64(0, amount, true);
    const amountBytes = new Uint8Array(amountBuffer);
    const leaf = new Uint8Array(addrBytes.length + 8);
    leaf.set(addrBytes, 0);
    leaf.set(amountBytes, addrBytes.length);
    return bytesToHex(sha256(leaf));
  }

  /**
   * Compute the Merkle root from a leaf + proof path.
   * Compare against marketRoot().merkle_root to validate before calling withdraw().
   *
   * Uses sorted-pair hashing: SHA256( min(a,b) || max(a,b) )
   *
   * @param leafHex  64-char hex leaf hash (from buildLeaf or sequencer API)
   * @param proof    Sibling proof path (from L2 sequencer)
   * @returns 64-char hex computed root
   */
  static async verifyProof(leafHex: string, proof: MerkleProof): Promise<string> {
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex, hexToBytes } = await import("@noble/hashes/utils");
    let current = hexToBytes(leafHex);
    for (const sibHex of proof) {
      const sibling = hexToBytes(sibHex.startsWith("0x") ? sibHex.slice(2) : sibHex);
      let a: Uint8Array, b: Uint8Array;
      if (compareBytes(current, sibling) <= 0) { a = current; b = sibling; }
      else                                      { a = sibling; b = current; }
      const combined = new Uint8Array(64);
      combined.set(a, 0);
      combined.set(b, 32);
      current = sha256(combined);
    }
    return bytesToHex(current);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Keypair Generation Utility
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a fresh Ed25519 keypair for the dealer hot wallet.
 * Store privateKeyHex securely (e.g. HashiCorp Vault, not .env files).
 */
export async function generateDealerKeypair(): Promise<Keypair> {
  const { default: bs58 } = await import("bs58");
  const { ed, hexToBytes, bytesToHex } = await getCrypto();

  const privBytes = new Uint8Array(32);
  crypto.getRandomValues(privBytes);

  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  const address = bs58.encode(pubBytes);

  return {
    address,
    privateKeyHex: bytesToHex(privBytes),
    publicKeyHex: bytesToHex(pubBytes),
  };
}

/**
 * Reconstruct a Keypair from a hex-encoded private key
 * (e.g. from DEALER_PRIVATE_KEY environment variable).
 */
export async function keypairFromPrivateKey(
  privateKeyHex: string
): Promise<Keypair> {
  const { default: bs58 } = await import("bs58");
  const { ed, hexToBytes, bytesToHex } = await getCrypto();

  const privBytes = hexToBytes(privateKeyHex);
  if (privBytes.length !== 32) {
    throw new Error(
      `Invalid private key: expected 32 bytes, got ${privBytes.length}`
    );
  }

  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  const address = bs58.encode(pubBytes);

  return {
    address,
    privateKeyHex,
    publicKeyHex: bytesToHex(pubBytes),
  };
}
