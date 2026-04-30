/**
 * BlackBook L1 — Dealer SDK (Layer 2 Prediction Market Operator)
 * ============================================================================
 * The Dealer is the L2 operator hot-wallet that:
 *   - Manages its own BB balance (the "house bankroll")
 *   - Locks contest reserves into the global escrow before markets open
 *   - Approves user deposits (Solana USDC → BB minting)
 *   - Submits Merkle state roots after L2 market resolution
 *   - Batch-settles winner payouts
 *   - Releases withdrawals (BB → Solana USDC cashout)
 *   - Mints / burns BB tokens as needed
 *   - Sends wUSDC to user ATAs
 *   - Monitors L1 node health, escrow invariants, and supply audits
 *
 * Settlement cycle:
 *   1. initContestReserve()   → lock dealer BB into escrow PDA
 *   2. verifyDeposit()        → confirm user's L1 deposit before L2 entry
 *   3. (L2 game plays out)
 *   4. submitStateRoot()      → anchor Merkle root + zero-sum proof
 *   5. settleWinners()        → batch-pay winners from dealer balance
 *   6. getContestStatus()     → poll until all claims are resolved
 *
 * Merkle tree format (must match L1 verification):
 *   Leaf:   SHA256( bs58_decode(wallet)[32] || amount_spl_u64_le[8] )
 *   Parent: SHA256( min(left, right) || max(left, right) )
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

// ── Constants ──────────────────────────────────────────────────────────────

/** 1 BB = 1,000,000 SPL units (6 decimals, same as USDC on Solana) */
const BB_DECIMALS = 6;
const SPL_MULTIPLIER = 10 ** BB_DECIMALS;

/** Deposit gateway rate: 1 USDC = 10 BB */
const BB_PER_USDC = 10;

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

export interface GrpcVerifyDepositResponse {
  verified: boolean;
  depositor_wallet: string;
  actual_amount: number;
  deposit_slot: number;
  error_code: string;
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

export interface MerkleLeafData {
  walletAddress: string;
  amountBB: number;
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

/** Convert human-readable BB to raw SPL u64 */
export function toSplUnits(bb: number): bigint {
  return BigInt(Math.round(bb * SPL_MULTIPLIER));
}

/** Convert raw SPL u64 to human-readable BB */
export function fromSplUnits(spl: bigint): number {
  return Number(spl) / SPL_MULTIPLIER;
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
   * Used for escrow deposits, withdrawals, and transfer signing.
   */
  private async signMessage(message: string): Promise<string> {
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const privBytes = hexToBytes(this.wallet.privateKeyHex);
    const msgBytes = new TextEncoder().encode(message);
    const sigBytes = await ed.signAsync(msgBytes, privBytes);
    return bytesToHex(sigBytes);
  }

  /**
   * Sign a binary-packed message (for state root submission).
   * Format: contest_id_bytes ++ l2_block_number_le(8) ++ merkle_root(32)
   */
  private async signBinaryMessage(payload: Uint8Array): Promise<string> {
    const { ed, hexToBytes, bytesToHex } = await getCrypto();
    const privBytes = hexToBytes(this.wallet.privateKeyHex);
    const sigBytes = await ed.signAsync(payload, privBytes);
    return bytesToHex(sigBytes);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  1. WALLET MANAGEMENT — Dealer's own balance & health
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the dealer wallet's BB balance. */
  async getBalance(): Promise<BalanceResponse> {
    return this.get(`/balance/${this.wallet.address}`);
  }

  /** Get the dealer wallet's wUSDC balance. */
  async getUsdcBalance(): Promise<UsdcBalanceResponse> {
    return this.get(`/usdc/balance/${this.wallet.address}`);
  }

  /**
   * Get the dealer's BB, wUSDT, $XX, and $DECAY balances in a single call.
   * Returns HTTP 503 if DEALER_PRIVATE_KEY is not set on the node.
   */
  async getAllBalances(): Promise<{
    dealer_address: string;
    bb: { balance: number; lamports: number; unit: string };
    wusdt: { balance: number; raw: number; unit: string };
    maxx: { balance: number; raw: number; unit: string };
    decay: { token_count: number; token_ids: number[]; unit: string };
  }> {
    return this.get("/dealer/balances");
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
   * Submit a Merkle state root to L1 after an L2 prediction market resolves.
   *
   * This is the critical finalization step. L1 enforces:
   *   - Ed25519 signature from the configured L2 sequencer
   *   - Zero-sum invariant: total_deposited == total_payout + house_rake
   *   - Merkle root is stored permanently; opens a 30-day claim window
   *
   * The signed message is BINARY (not UTF-8):
   *   contest_id_bytes ++ l2_block_number_le(8) ++ merkle_root(32)
   *
   * @param marketId        L2 market identifier (e.g. "market_btc_42")
   * @param tree            MerkleTreeResult from buildMerkleTree()
   * @param l2BlockNumber   Monotonic L2 block counter
   * @param totalDeposited  Total BB deposited by all users (SPL units)
   * @param totalPayout     Total BB going to winners (SPL units)
   * @param houseRake       Dealer's commission (SPL units)
   */
  async submitStateRoot(
    marketId: string,
    tree: MerkleTreeResult,
    l2BlockNumber: bigint,
    totalDeposited: bigint,
    totalPayout: bigint,
    houseRake: bigint
  ): Promise<StateRootResponse> {
    // Enforce zero-sum before sending to L1
    if (totalDeposited !== totalPayout + houseRake) {
      throw new Error(
        `Zero-sum violation: deposited(${totalDeposited}) != payout(${totalPayout}) + rake(${houseRake})`
      );
    }

    // Binary-pack the signing payload
    const contestIdBytes = new TextEncoder().encode(marketId);
    const blockNumberBytes = new Uint8Array(8);
    new DataView(blockNumberBytes.buffer).setBigUint64(
      0,
      l2BlockNumber,
      true // little-endian
    );

    const payload = new Uint8Array(
      contestIdBytes.length + 8 + 32
    );
    payload.set(contestIdBytes, 0);
    payload.set(blockNumberBytes, contestIdBytes.length);
    payload.set(tree.root, contestIdBytes.length + 8);

    const signature = await this.signBinaryMessage(payload);

    return this.post("/escrow/submit-state-root", {
      market_id: marketId,
      merkle_root: tree.rootHex,
      signature,
      l2_block_number: Number(l2BlockNumber),
      total_deposited: Number(totalDeposited),
      total_payout: Number(totalPayout),
      house_rake: Number(houseRake),
      winner_count: tree.leaves.length,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  7. SETTLEMENT — Batch-pay winners from dealer balance
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
   * Send wUSDC to a user's associated token account.
   *
   * @param to           Recipient base58 address
   * @param wusdcAmount  wUSDC amount (human-readable)
   */
  async sendWusdc(
    to: string,
    wusdcAmount: number
  ): Promise<SendWusdcResponse> {
    return this.post("/admin/dealer/send_wusdc", {
      to,
      wusdc_amount: wusdcAmount,
    });
  }

  /**
   * Transfer BB from the dealer wallet to another address (signed).
   *
   * Signs: the JSON payload { "to": "...", "amount": ... }
   *
   * @param to      Recipient base58 address
   * @param amount  BB amount (human-readable)
   */
  async transfer(to: string, amount: number): Promise<TransferResponse> {
    const timestamp = nowSecs();
    const nonce = randomNonce();
    const payload = JSON.stringify({ to, amount });
    const signature = await this.signMessage(payload);

    return this.post("/transfer/simple", {
      public_key: this.wallet.publicKeyHex,
      wallet_address: this.wallet.address,
      payload,
      timestamp,
      nonce,
      chain_id: "blackbook-mainnet",
      signature,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  8. MERKLE TREE — Build proofs for L2 market resolution
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Build a Merkle tree from L2 winner payouts.
   *
   * Leaf format (matches L1 verification exactly):
   *   SHA256( bs58_decode(wallet_address)[32] || amount_spl_u64_le[8] )
   *
   * Parent hashing (sorted-pair, deterministic):
   *   SHA256( min(left, right) || max(left, right) )
   *
   * @param winners  Array of { walletAddress, amountBB } — BB in human units
   * @returns        MerkleTreeResult with root, leaves, and per-wallet proofs
   */
  async buildMerkleTree(winners: MerkleLeafData[]): Promise<MerkleTreeResult> {
    if (winners.length === 0) {
      throw new Error("Cannot build Merkle tree with zero winners");
    }

    const { default: bs58 } = await import("bs58");
    const { sha256 } = await import("@noble/hashes/sha256");
    const { bytesToHex } = (await import("@noble/hashes/utils"));

    // ── Build leaves ─────────────────────────────────────────────────────
    const leaves: Uint8Array[] = [];
    const walletToIndex = new Map<string, number>();

    for (let i = 0; i < winners.length; i++) {
      const { walletAddress, amountBB } = winners[i];
      const walletRaw = bs58.decode(walletAddress);
      if (walletRaw.length !== 32) {
        throw new Error(
          `Wallet ${walletAddress} decodes to ${walletRaw.length} bytes, expected 32`
        );
      }

      const amountSpl = toSplUnits(amountBB);
      const amountBytes = new Uint8Array(8);
      new DataView(amountBytes.buffer).setBigUint64(0, amountSpl, true);

      const preimage = new Uint8Array(40);
      preimage.set(walletRaw, 0);
      preimage.set(amountBytes, 32);

      leaves.push(sha256(preimage));
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
   * Get the Merkle proof for a specific winner in a tree.
   * Returns the proof array ready to submit to POST /escrow/withdraw.
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
   *   2. Verify zero-sum invariant
   *   3. Submit state root to L1
   *   4. Return the tree (with proofs for each winner)
   *
   * @param marketId          L2 market identifier
   * @param winners           Array of { walletAddress, amountBB }
   * @param l2BlockNumber     Monotonic L2 block counter
   * @param totalDepositedBB  Total BB deposited by all users (human-readable)
   * @param houseRakeBB       Dealer's commission (human-readable)
   */
  async resolveMarket(
    marketId: string,
    winners: MerkleLeafData[],
    l2BlockNumber: bigint,
    totalDepositedBB: number,
    houseRakeBB: number
  ): Promise<{
    tree: MerkleTreeResult;
    stateRootReceipt: StateRootResponse;
  }> {
    const tree = await this.buildMerkleTree(winners);

    const totalPayoutBB = winners.reduce((sum, w) => sum + w.amountBB, 0);
    const totalDeposited = toSplUnits(totalDepositedBB);
    const totalPayout = toSplUnits(totalPayoutBB);
    const houseRake = toSplUnits(houseRakeBB);

    const stateRootReceipt = await this.submitStateRoot(
      marketId,
      tree,
      l2BlockNumber,
      totalDeposited,
      totalPayout,
      houseRake
    );

    return { tree, stateRootReceipt };
  }

  /**
   * Full settlement pipeline for a resolved market:
   *   1. Resolve market (build tree + submit state root)
   *   2. Batch-settle winners via dealer balance
   *   3. Return all receipts
   *
   * @param marketId          L2 market identifier
   * @param winners           Array of { walletAddress, amountBB }
   * @param l2BlockNumber     Monotonic L2 block counter
   * @param totalDepositedBB  Total pool (human-readable)
   * @param houseRakeBB       Dealer commission (human-readable)
   * @param batchReceiptId    Optional idempotency key
   */
  async settleMarket(
    marketId: string,
    winners: MerkleLeafData[],
    l2BlockNumber: bigint,
    totalDepositedBB: number,
    houseRakeBB: number,
    batchReceiptId?: string
  ): Promise<{
    tree: MerkleTreeResult;
    stateRootReceipt: StateRootResponse;
    settleReceipt: SettleResponse;
  }> {
    const { tree, stateRootReceipt } = await this.resolveMarket(
      marketId,
      winners,
      l2BlockNumber,
      totalDepositedBB,
      houseRakeBB
    );

    const payouts: SettlePayoutEntry[] = winners.map((w) => ({
      address: w.walletAddress,
      amount: w.amountBB,
    }));

    const settleReceipt = await this.settleWinners(
      payouts,
      batchReceiptId ?? `settle_${marketId}_${Date.now()}`
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
