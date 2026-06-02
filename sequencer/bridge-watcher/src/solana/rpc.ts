import { log } from "../logger.js";

export interface SolanaRpcConfig {
  primaryUrl: string;
  fallbackUrl?: string;
  timeoutMs?: number;
}

interface RpcResponse<T> {
  result: T;
  error?: { code: number; message: string };
}

// ── Minimal Solana JSON-RPC types (only fields we consume) ───────────────────

export interface SignatureInfo {
  signature: string;
  slot: number;
  confirmationStatus: "processed" | "confirmed" | "finalized" | null;
  err: unknown | null;
  memo: string | null;
}

export interface TokenBalance {
  accountIndex: number;
  mint: string;
  owner?: string;
  uiTokenAmount: {
    amount: string;       // raw u64 as string
    decimals: number;
    uiAmount: number | null;
  };
}

export interface ParsedInstruction {
  programId: string;
  data?: string;          // base58-encoded for unparsed instructions
  parsed?: unknown;
}

export interface TransactionMeta {
  err: unknown | null;
  preTokenBalances: TokenBalance[];
  postTokenBalances: TokenBalance[];
  logMessages: string[] | null;
}

export interface TransactionMessage {
  accountKeys: Array<{ pubkey: string; signer: boolean; writable: boolean }>;
  instructions: Array<{
    programIdIndex: number;
    accounts: number[];
    data: string;        // base58-encoded
  }>;
}

export interface SolanaTransaction {
  slot: number;
  meta: TransactionMeta | null;
  transaction: {
    message: TransactionMessage;
    signatures: string[];
  };
}

// ── Client ───────────────────────────────────────────────────────────────────

export class SolanaRpcClient {
  private primaryUrl: string;
  private fallbackUrl?: string;
  private timeoutMs: number;
  private primaryFailures = 0;
  private readonly FAILOVER_THRESHOLD = 3;
  private id = 0;

  constructor(cfg: SolanaRpcConfig) {
    this.primaryUrl = cfg.primaryUrl;
    this.fallbackUrl = cfg.fallbackUrl;
    this.timeoutMs = cfg.timeoutMs ?? 10_000;
  }

  private nextId(): number {
    return ++this.id;
  }

  private async call<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const body = JSON.stringify({ jsonrpc: "2.0", id: this.nextId(), method, params });
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      const json = (await res.json()) as RpcResponse<T>;
      if (json.error) throw new Error(`RPC error ${json.error.code}: ${json.error.message}`);
      return json.result;
    } finally {
      clearTimeout(timer);
    }
  }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const useFallback = this.fallbackUrl && this.primaryFailures >= this.FAILOVER_THRESHOLD;
    const url = useFallback ? this.fallbackUrl! : this.primaryUrl;
    try {
      const result = await this.call<T>(url, method, params);
      if (!useFallback) this.primaryFailures = 0;
      return result;
    } catch (err) {
      if (!useFallback) {
        this.primaryFailures++;
        log.warn("solana rpc primary failure", { failures: this.primaryFailures, err: String(err) });
        if (this.fallbackUrl && this.primaryFailures >= this.FAILOVER_THRESHOLD) {
          log.warn("switching to fallback rpc", { fallback: this.fallbackUrl });
        }
      }
      throw err;
    }
  }

  /** `getSignaturesForAddress` — newest to oldest. */
  async getSignaturesForAddress(
    address: string,
    opts: { limit?: number; before?: string; until?: string } = {}
  ): Promise<SignatureInfo[]> {
    const params: unknown[] = [
      address,
      {
        limit: opts.limit ?? 50,
        ...(opts.before ? { before: opts.before } : {}),
        ...(opts.until  ? { until:  opts.until  } : {}),
        commitment: "finalized",
      },
    ];
    return this.rpc<SignatureInfo[]>("getSignaturesForAddress", params);
  }

  /** `getTransaction` at `finalized` commitment. Returns null if not yet finalized. */
  async getTransaction(sig: string): Promise<SolanaTransaction | null> {
    const params: unknown[] = [
      sig,
      { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 },
    ];
    return this.rpc<SolanaTransaction | null>("getTransaction", params);
  }
}
