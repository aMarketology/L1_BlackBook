/**
 * BlackBook L1 — Explorer SDK
 * ============================================================================
 * Everything a wallet UI or block explorer needs:
 *   - Wallet activity & balance (BB + USDC)
 *   - Transaction history per address (REST + JSON-RPC fast path)
 *   - Transaction & block detail lookup
 *   - Chain & PoH status
 *   - Supply audit
 *
 * Two transports:
 *   1. REST  — http(s)://blackbook.id           (port 8080 by default)
 *   2. RPC   — http(s)://blackbook.id:8899      (Solana JSON-RPC 2.0)
 *
 * The JSON-RPC path (getSignaturesForAddress) is the fastest way to get
 * recent activity for a single wallet — use it for your live activity feed.
 *
 * Usage:
 *   const explorer = new ExplorerSDK({
 *     restUrl: "https://blackbook.id",
 *     rpcUrl:  "https://blackbook.id:8899",
 *   });
 *
 *   const history = await explorer.getAddressActivity("5FHne...");
 *   const balance = await explorer.getWalletSnapshot("5FHne...");
 * ============================================================================
 */

// ── Config ──────────────────────────────────────────────────────────────────

export interface ExplorerConfig {
  /** Base URL of the BlackBook REST API, e.g. "https://blackbook.id" */
  restUrl: string;
  /**
   * URL of the Solana JSON-RPC endpoint, e.g. "https://blackbook.id:8899".
   * Defaults to `restUrl + ":8899"` if omitted.
   */
  rpcUrl?: string;
}

// ── Shared primitives ────────────────────────────────────────────────────────

/** A finalized on-chain transaction record from /tx/:id or /address/:addr/transactions */
export interface TransactionRecord {
  tx_id: string;
  tx_type: string;              // "transfer" | "mint" | "burn" | "SWAP_BB_FOR_USDC" | …
  from_address: string;
  to_address: string;
  amount: number;
  timestamp: number;            // Unix seconds
  status: string;               // "completed" | "finalized" | "pending" | "failed"
  block_height: number;
  tx_hash: string;
  prev_tx_hash: string;
  merkle_root: string;
  auth_type: string;
  nonce: number;
  balance_before: number;
  balance_after: number;
  recipient_balance_after: number;
  from_username: string | null;
  to_username: string | null;
  signature: string | null;
  metadata: unknown | null;
}

// ── REST response shapes ─────────────────────────────────────────────────────

export interface NodeHealth {
  status: string;
  version: string;
  network: string;
  blockchain: {
    total_supply: number;
    account_count: number;
    block_count: number;
    svm_accounts: number;
  };
  poh_clock: unknown;
  consensus: unknown;
  block_production: unknown;
  infrastructure: unknown;
}

export interface NodeStats {
  blockchain: {
    total_accounts: number;
    block_count: number;
    total_supply: number;
    cache_hit_rate: number;
  };
  pipeline: unknown;
  gulf_stream: unknown;
  parallel_execution: unknown;
}

export interface SupplyAudit {
  bb_total_supply: number;
  wusdc_total_supply: number;
  wusdc_mint: string;
  backing_ratio: number;
  target_ratio: number;
  delta_from_target: number;
  invariant_ok: boolean;
  note: string;
}

export interface BbBalance {
  address: string;
  name: string | null;
  balance: number;
  unit: "BB";
}

export interface UsdcBalance {
  address: string;
  usdc_balance: number;
  raw_balance: number;
  decimals: number;
  mint: string;
}

export interface UsdcTokenAccount {
  address: string;
  mint: string;
  owner: string;
  balance_usdc: number;
  raw_balance: number;
  decimals: number;
}

export interface UsdcAccounts {
  owner: string;
  token_accounts: UsdcTokenAccount[];
}

/** Combined wallet snapshot returned by getWalletSnapshot() */
export interface WalletSnapshot {
  address: string;
  bb_balance: number;
  usdc_balance: number;
  usdc_raw: number;
  usdc_mint: string;
}

export interface AddressTxPage {
  success: boolean;
  address: string;
  page: number;
  limit: number;
  total: number;
  transactions: TransactionRecord[];
}

export interface TxDetail {
  success: boolean;
  status: "Finalized" | "Pending" | string;
  transaction: TransactionRecord | null;
}

export interface PohStatus {
  current_slot: number;
  num_hashes: number;
  current_hash: string;
  is_running: boolean;
}

export interface BlockSummary {
  slot: number;
  timestamp: number;
  hash: string;
  previous_hash: string;
  tx_count: number;
  leader: string;
  epoch: number;
}

export interface BlockFull extends BlockSummary {
  poh_hash: string;
  poh_sequence: number;
  state_root: string;
  transactions: Array<{
    hash: string;
    from: string;
    data: unknown;
    timestamp: number;
    slot: number;
    position: number;
    poh_hash: string;
  }>;
  confirmations: number;
}

export interface TxStatus {
  tx_id: string;
  status: string;
  is_finalized: boolean;
}

export interface TowerBft {
  validator_count: number;
  total_stake: number;
  global_root: number;
  confirmed_slots: number;
  active_forks: number;
  supermajority_threshold: number;
  max_tower_depth: number;
  current_slot: number;
  best_fork: { slot: number; hash: string } | null;
}

export interface TurbineStatus {
  current_slot: number;
  latest_shredded_slot: number;
  data_shreds: number;
  fec_shreds: number;
  block_bytes: number;
  validator_count: number;
  propagation_max_hops: number;
  turbine_fanout: number;
}

// ── JSON-RPC response shapes ─────────────────────────────────────────────────

interface RpcResponse<T> {
  jsonrpc: "2.0";
  id: number;
  result: T;
  error?: { code: number; message: string };
}

export interface RpcSignatureInfo {
  signature: string;
  slot: number;
  err: unknown | null;
  memo: string | null;
  blockTime: number | null;
  confirmationStatus: "processed" | "confirmed" | "finalized";
}

export interface RpcConfirmedTransaction {
  slot: number;
  transaction: {
    message: {
      accountKeys: string[];
      instructions: unknown[];
    };
    signatures: string[];
  };
  meta: {
    err: unknown | null;
    fee: number;
    preBalances: number[];
    postBalances: number[];
    logMessages: string[];
  } | null;
  blockTime: number | null;
}

export interface RpcBalanceLamports {
  context: { slot: number };
  value: number;  // lamports (1 BB = 1_000_000_000 lamports)
}

export interface RpcWalletProfile {
  registered: boolean;
  walletAddress: string;
  balance: number;
  network: string;
  slot: number;
}

export interface RpcEpochInfo {
  epoch: number;
  slotIndex: number;
  slotsInEpoch: number;
  absoluteSlot: number;
  blockHeight: number;
  transactionCount: number;
}

export interface RpcBlockProduction {
  context: { slot: number };
  value: {
    byIdentity: Record<string, [number, number]>;
    range: { firstSlot: number; lastSlot: number };
  };
}

// ── Pagination helper ────────────────────────────────────────────────────────

export interface PageOptions {
  /** 1-based page number (default: 1) */
  page?: number;
  /** Results per page, max 100 (default: 50) */
  limit?: number;
}

export interface SignaturesOptions {
  /** Max signatures to return, max 1000 (default: 20) */
  limit?: number;
  /** Return only sigs before this one (for pagination) */
  before?: string;
  /** Return only sigs at or after this one */
  until?: string;
}

// ── ExplorerSDK ──────────────────────────────────────────────────────────────

export class ExplorerSDK {
  private restUrl: string;
  private rpcUrl: string;
  private rpcId = 0;

  constructor(config: ExplorerConfig) {
    this.restUrl = config.restUrl.replace(/\/$/, "");
    this.rpcUrl = config.rpcUrl
      ? config.rpcUrl.replace(/\/$/, "")
      : this.restUrl + ":8899";
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  private async restGet<T>(path: string): Promise<T> {
    const res = await fetch(`${this.restUrl}${path}`);
    const json = await res.json();
    if (!res.ok) {
      throw new Error(
        `GET ${path} failed (${res.status}): ${(json as any).error ?? JSON.stringify(json)}`
      );
    }
    return json as T;
  }

  private async rpc<T>(method: string, params: unknown[] = []): Promise<T> {
    const id = ++this.rpcId;
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const json: RpcResponse<T> = await res.json();
    if (json.error) {
      throw new Error(`RPC ${method} error ${json.error.code}: ${json.error.message}`);
    }
    return json.result;
  }

  // ── Node status ────────────────────────────────────────────────────────────

  /**
   * GET /health — Full node health including PoH, consensus, pipeline stats.
   */
  health(): Promise<NodeHealth> {
    return this.restGet("/health");
  }

  /**
   * GET /stats — Execution pipeline, Gulf Stream, and blockchain counters.
   */
  stats(): Promise<NodeStats> {
    return this.restGet("/stats");
  }

  /**
   * GET /supply/audit — BB / wUSDC supply invariant check.
   * Confirms backing_ratio stays at 10:1.
   */
  supplyAudit(): Promise<SupplyAudit> {
    return this.restGet("/supply/audit");
  }

  // ── Wallet balances ────────────────────────────────────────────────────────

  /**
   * GET /balance/:address — $BB token balance for an address.
   */
  getBbBalance(address: string): Promise<BbBalance> {
    return this.restGet(`/balance/${address}`);
  }

  /**
   * GET /usdc/balance/:address — USDC SPL token balance for an address.
   */
  getUsdcBalance(address: string): Promise<UsdcBalance> {
    return this.restGet(`/usdc/balance/${address}`);
  }

  /**
   * GET /usdc/accounts/:address — All USDC token accounts (ATAs) for a wallet.
   */
  getUsdcAccounts(address: string): Promise<UsdcAccounts> {
    return this.restGet(`/usdc/accounts/${address}`);
  }

  /**
   * Fetch BB and USDC balances in parallel and return as a single snapshot.
   * Ideal for rendering a wallet dashboard.
   */
  async getWalletSnapshot(address: string): Promise<WalletSnapshot> {
    const [bb, usdc] = await Promise.all([
      this.getBbBalance(address),
      this.getUsdcBalance(address),
    ]);
    return {
      address,
      bb_balance: bb.balance,
      usdc_balance: usdc.usdc_balance,
      usdc_raw: usdc.raw_balance,
      usdc_mint: usdc.mint,
    };
  }

  // ── Transaction history (REST) ─────────────────────────────────────────────

  /**
   * GET /address/:address/transactions — Paginated transaction history for an address.
   *
   * Returns all txs where the address is sender or receiver, ordered by most recent.
   * Use this for a full history page with pagination controls.
   *
   * @param address  Base58 wallet address
   * @param options  Pagination — page (1-based) and limit (max 100)
   *
   * @example
   * const page1 = await explorer.getAddressActivity("5FHne...", { limit: 20 });
   */
  getAddressActivity(
    address: string,
    options: PageOptions = {}
  ): Promise<AddressTxPage> {
    const page = options.page ?? 1;
    const limit = Math.min(options.limit ?? 50, 100);
    return this.restGet(`/address/${address}/transactions?page=${page}&limit=${limit}`);
  }

  /**
   * GET /tx/:tx_id — Full transaction detail by tx_id.
   *
   * Returns the finalized TransactionRecord, or status "Pending" if still in flight.
   *
   * @example
   * const detail = await explorer.getTx("abc123-uuid...");
   */
  getTx(txId: string): Promise<TxDetail> {
    return this.restGet(`/tx/${txId}`);
  }

  /**
   * GET /ledger — Paginated global on-chain ledger.
   *
   * Returns all transactions across all wallets, sorted newest-first.
   * Use for a chain-wide activity feed / block explorer home page.
   *
   * @example
   * const page = await explorer.getLedger({ page: 1, limit: 50 });
   */
  async getLedger(options: PageOptions = {}): Promise<{
    page: number;
    limit: number;
    total_pages: number;
    transactions: TransactionRecord[];
  }> {
    const page = options.page ?? 1;
    const limit = Math.min(options.limit ?? 50, 100);
    // /ledger returns text/plain; we normalise it via a JSON alternative
    const res = await fetch(
      `${this.restUrl}/address/all/transactions?page=${page}&limit=${limit}`
    );
    if (res.ok) {
      return res.json();
    }
    // Fallback: /ledger (text) — return raw text under a wrapper
    const text = await fetch(
      `${this.restUrl}/ledger?page=${page}&limit=${limit}`
    ).then((r) => r.text());
    return {
      page,
      limit,
      total_pages: 0,
      transactions: text as unknown as TransactionRecord[], // raw ASCII for display
    };
  }

  // ── Transaction history (JSON-RPC — fastest path) ──────────────────────────

  /**
   * RPC getSignaturesForAddress — Recent transaction signatures for a wallet.
   *
   * **Fastest method for a live activity feed.** Returns lightweight signature
   * objects with slot + blockTime. Follow up with getRpcTransaction() per sig
   * for full details only if needed.
   *
   * Runs on port 8899 (Solana JSON-RPC 2.0).
   *
   * @param address  Base58 wallet address
   * @param options  limit (max 1000, default 20), before, until cursors
   *
   * @example
   * const sigs = await explorer.getSignatures("5FHne...", { limit: 10 });
   * // → [{ signature, slot, blockTime, confirmationStatus }, ...]
   */
  getSignatures(
    address: string,
    options: SignaturesOptions = {}
  ): Promise<RpcSignatureInfo[]> {
    const config: Record<string, unknown> = {
      limit: Math.min(options.limit ?? 20, 1000),
    };
    if (options.before) config.before = options.before;
    if (options.until) config.until = options.until;
    return this.rpc<RpcSignatureInfo[]>("getSignaturesForAddress", [
      address,
      config,
    ]);
  }

  /**
   * RPC getTransaction — Full confirmed transaction by signature.
   *
   * @param signature  Base58-encoded signature from getSignatures()
   *
   * @example
   * const tx = await explorer.getRpcTransaction("5FHne...");
   */
  getRpcTransaction(
    signature: string
  ): Promise<RpcConfirmedTransaction | null> {
    return this.rpc<RpcConfirmedTransaction | null>("getTransaction", [
      signature,
      { encoding: "json", maxSupportedTransactionVersion: 0 },
    ]);
  }

  /**
   * Batch-fetch the N most recent transactions for an address — signatures +
   * full details — in the fewest round trips.
   *
   * Returns an array of `{ sig, tx }` pairs. Uses the RPC fast path for
   * signatures, then fetches details in parallel.
   *
   * @param address  Base58 wallet address
   * @param limit    Number of transactions to return (max 50)
   *
   * @example
   * const recent = await explorer.getRecentActivity("5FHne...", 10);
   * recent.forEach(({ sig, tx }) => console.log(sig.slot, tx?.meta?.postBalances));
   */
  async getRecentActivity(
    address: string,
    limit = 20
  ): Promise<Array<{ sig: RpcSignatureInfo; tx: RpcConfirmedTransaction | null }>> {
    const sigs = await this.getSignatures(address, {
      limit: Math.min(limit, 50),
    });
    const txs = await Promise.all(
      sigs.map((s) => this.getRpcTransaction(s.signature))
    );
    return sigs.map((sig, i) => ({ sig, tx: txs[i] }));
  }

  /**
   * RPC getSignatureStatuses — Confirm multiple signatures in one call.
   *
   * @param signatures  Array of base58 signature strings
   *
   * @example
   * const statuses = await explorer.getSignatureStatuses(["sig1", "sig2"]);
   */
  getSignatureStatuses(signatures: string[]): Promise<{
    context: { slot: number };
    value: Array<{
      slot: number;
      confirmations: number | null;
      err: unknown | null;
      confirmationStatus: string;
    } | null>;
  }> {
    return this.rpc("getSignatureStatuses", [signatures]);
  }

  // ── RPC balance & account info ─────────────────────────────────────────────

  /**
   * RPC getBalance — $BB balance in lamports (1 BB = 1,000,000,000 lamports).
   *
   * For UI display use: `lamports / 1_000_000_000`
   * Or just use `getBbBalance()` which returns human-readable $BB.
   */
  getRpcBalance(address: string): Promise<RpcBalanceLamports> {
    return this.rpc<RpcBalanceLamports>("getBalance", [address]);
  }

  /**
   * RPC blackbook_getProfile — Full wallet profile in one call.
   *
   * Returns registered status, address, balance (human), network, and slot.
   * Useful for wallet login screens and profile pages.
   *
   * @example
   * const profile = await explorer.getProfile("5FHne...");
   * if (profile.registered) { /* show wallet dashboard *\/ }
   */
  getProfile(address: string): Promise<RpcWalletProfile> {
    return this.rpc<RpcWalletProfile>("blackbook_getProfile", [address]);
  }

  /**
   * RPC blackbook_isRegistered — Returns true if the address has a non-zero balance.
   */
  isRegistered(address: string): Promise<boolean> {
    return this.rpc<boolean>("blackbook_isRegistered", [address]);
  }

  /**
   * RPC getAccountInfo — Low-level SVM account state (lamports, data, owner).
   */
  getAccountInfo(address: string): Promise<{
    context: { slot: number };
    value: {
      lamports: number;
      owner: string;
      data: unknown;
      executable: boolean;
      rentEpoch: number;
    } | null;
  }> {
    return this.rpc("getAccountInfo", [address, { encoding: "base64" }]);
  }

  /**
   * RPC getMultipleAccounts — Batch account lookup (max ~100 addresses).
   *
   * @example
   * const accounts = await explorer.getMultipleAccounts(["addr1", "addr2"]);
   */
  getMultipleAccounts(addresses: string[]): Promise<{
    context: { slot: number };
    value: Array<{ lamports: number; owner: string } | null>;
  }> {
    return this.rpc("getMultipleAccounts", [addresses]);
  }

  // ── Block data (PoH & RPC) ─────────────────────────────────────────────────

  /**
   * GET /poh/status — Current PoH clock state.
   */
  pohStatus(): Promise<PohStatus> {
    return this.restGet("/poh/status");
  }

  /**
   * GET /poh/block/latest — Most recently produced block (summary).
   */
  async latestBlock(): Promise<BlockSummary> {
    const res = await this.restGet<{ success: boolean; block: BlockSummary }>(
      "/poh/block/latest"
    );
    return res.block;
  }

  /**
   * GET /poh/block/:slot — Full block including all transactions at a slot.
   *
   * @example
   * const block = await explorer.blockBySlot(98712);
   * console.log(block.transactions.length, "txs in block");
   */
  async blockBySlot(slot: number): Promise<BlockFull> {
    const res = await this.restGet<{ success: boolean; block: BlockFull }>(
      `/poh/block/${slot}`
    );
    return res.block;
  }

  /**
   * GET /poh/tx/:tx_id/status — PoH finality status for a tx.
   *
   * Use after submitting a transfer to poll for confirmation.
   * Prefer `isFinalized()` for a simple boolean check.
   */
  txStatus(txId: string): Promise<TxStatus> {
    return this.restGet(`/poh/tx/${txId}/status`);
  }

  /**
   * Poll /poh/tx/:tx_id/status until finalized or timeout.
   *
   * @param txId      Transaction ID to wait on
   * @param timeoutMs Max wait time in milliseconds (default: 10 000)
   * @param pollMs    Poll interval in milliseconds (default: 500)
   *
   * @example
   * const { is_finalized } = await explorer.waitForFinality("tx_abc...");
   */
  async waitForFinality(
    txId: string,
    timeoutMs = 10_000,
    pollMs = 500
  ): Promise<TxStatus> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = await this.txStatus(txId);
      if (status.is_finalized) return status;
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new Error(`Tx ${txId} not finalized within ${timeoutMs}ms`);
  }

  /**
   * RPC getBlock — Block with transactions via JSON-RPC (Phantom-compatible).
   */
  getRpcBlock(slot: number): Promise<{
    blockTime: number | null;
    blockhash: string;
    parentSlot: number;
    transactions: unknown[];
  } | null> {
    return this.rpc("getBlock", [
      slot,
      { encoding: "json", transactionDetails: "full", maxSupportedTransactionVersion: 0 },
    ]);
  }

  /**
   * RPC getBlocks — List of confirmed slot numbers in a range.
   *
   * @example
   * const slots = await explorer.getBlocks(98700, 98712);
   */
  getBlocks(startSlot: number, endSlot?: number): Promise<number[]> {
    const params: unknown[] = [startSlot];
    if (endSlot !== undefined) params.push(endSlot);
    return this.rpc<number[]>("getBlocks", params);
  }

  // ── Chain info ─────────────────────────────────────────────────────────────

  /**
   * RPC getSlot — Current slot number.
   */
  getSlot(): Promise<number> {
    return this.rpc<number>("getSlot");
  }

  /**
   * RPC getBlockHeight — Current block height.
   */
  getBlockHeight(): Promise<number> {
    return this.rpc<number>("getBlockHeight");
  }

  /**
   * RPC getEpochInfo — Current epoch, slot index, slots in epoch.
   */
  getEpochInfo(): Promise<RpcEpochInfo> {
    return this.rpc<RpcEpochInfo>("getEpochInfo");
  }

  /**
   * RPC getLatestBlockhash — Current blockhash (required for tx construction).
   */
  getLatestBlockhash(): Promise<{
    context: { slot: number };
    value: { blockhash: string; lastValidBlockHeight: number };
  }> {
    return this.rpc("getLatestBlockhash");
  }

  /**
   * RPC getSupply — Total and circulating $BB supply.
   */
  getRpcSupply(): Promise<{
    context: { slot: number };
    value: { total: number; circulating: number; nonCirculating: number };
  }> {
    return this.rpc("getSupply");
  }

  /**
   * RPC getVersion — Node version string.
   */
  getVersion(): Promise<{ solana_core: string; feature_set: number }> {
    return this.rpc("getVersion");
  }

  /**
   * RPC getIdentity — Node identity pubkey.
   */
  getIdentity(): Promise<{ identity: string }> {
    return this.rpc("getIdentity");
  }

  /**
   * RPC getGenesisHash — Network genesis hash (chain identity).
   */
  getGenesisHash(): Promise<string> {
    return this.rpc<string>("getGenesisHash");
  }

  /**
   * RPC getBlockProduction — Block production stats by validator.
   */
  getBlockProduction(): Promise<RpcBlockProduction> {
    return this.rpc<RpcBlockProduction>("getBlockProduction");
  }

  // ── Consensus & propagation ────────────────────────────────────────────────

  /**
   * GET /consensus/tower — Tower BFT vote state (validators, stake, forks).
   */
  towerBft(): Promise<TowerBft> {
    return this.restGet("/consensus/tower");
  }

  /**
   * GET /turbine/status — Turbine shred propagation stats.
   */
  turbineStatus(): Promise<TurbineStatus> {
    return this.restGet("/turbine/status");
  }

  // ── SPL Token (USDC) ──────────────────────────────────────────────────────

  /**
   * RPC getTokenAccountsByOwner — All SPL token accounts for an address.
   *
   * @example
   * const accounts = await explorer.getTokenAccounts("5FHne...", "USDC_mint...");
   */
  getTokenAccounts(
    ownerAddress: string,
    mintAddress: string
  ): Promise<{
    context: { slot: number };
    value: Array<{
      pubkey: string;
      account: { lamports: number; owner: string; data: unknown };
    }>;
  }> {
    return this.rpc("getTokenAccountsByOwner", [
      ownerAddress,
      { mint: mintAddress },
      { encoding: "jsonParsed" },
    ]);
  }

  /**
   * RPC getTokenSupply — Total USDC supply from the mint.
   *
   * @param mintAddress  USDC mint address
   */
  getTokenSupply(mintAddress: string): Promise<{
    context: { slot: number };
    value: { amount: string; decimals: number; uiAmount: number };
  }> {
    return this.rpc("getTokenSupply", [mintAddress]);
  }

  /**
   * RPC getTokenAccountBalance — USDC balance for a specific ATA.
   *
   * @param ataAddress  Associated Token Account address
   */
  getTokenAccountBalance(ataAddress: string): Promise<{
    context: { slot: number };
    value: { amount: string; decimals: number; uiAmount: number };
  }> {
    return this.rpc("getTokenAccountBalance", [ataAddress]);
  }
}
