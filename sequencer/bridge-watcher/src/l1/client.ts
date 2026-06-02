import { log } from "../logger.js";
import type { BridgeDepositBody } from "./messages.js";

export type DepositStatus = "pending" | "approved" | "rejected" | "not_found";

export interface L1DepositStatusResponse {
  status: DepositStatus;
  tx_hash?: string;
  minted_bb?: number;
  new_balance?: number;
  error?: string;
}

export interface L1SubmitResult {
  /** "processed" = L1 minted or confirmed already-minted (409) */
  outcome: "processed" | "rejected" | "retry";
  detail: string;
}

export class L1Client {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(baseUrl: string, timeoutMs = 10_000) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
  }

  private async get<T>(path: string): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, { signal: ctrl.signal });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`L1 ${res.status}: ${body}`);
      }
      return res.json() as Promise<T>;
    } finally {
      clearTimeout(timer);
    }
  }

  private async post<T>(path: string, body: unknown): Promise<{ status: number; data: T }> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      const data = await res.json() as T;
      return { status: res.status, data };
    } finally {
      clearTimeout(timer);
    }
  }

  // ── M2: Poll deposit status (Model B — user-signed request already submitted) ──

  /**
   * Poll `GET /deposit/status/:tx_hash` until the deposit is in a terminal state.
   * Returns the final status, or throws after `maxAttempts`.
   */
  async pollDepositStatus(
    txHash: string,
    opts: { pollMs?: number; maxAttempts?: number } = {}
  ): Promise<L1DepositStatusResponse> {
    const pollMs = opts.pollMs ?? 3_000;
    const maxAttempts = opts.maxAttempts ?? 20;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const data = await this.get<L1DepositStatusResponse>(`/deposit/status/${txHash}`);
      log.debug("deposit status poll", { txHash, status: data.status, attempt });

      if (data.status === "approved" || data.status === "rejected") {
        return data;
      }
      if (attempt < maxAttempts - 1) {
        await new Promise<void>((r) => setTimeout(r, pollMs));
      }
    }
    throw new Error(`deposit ${txHash} did not reach terminal state after ${maxAttempts} polls`);
  }

  // ── M3: Bridge-authority signed deposit (Model A) ────────────────────────────

  /**
   * Submit a bridge-authority-signed deposit to `POST /bridge/deposit`.
   * 200 → minted; 409 → already minted (idempotent OK); 4xx → rejected; 5xx → retry.
   */
  async submitBridgeDeposit(body: BridgeDepositBody): Promise<L1SubmitResult> {
    let status: number;
    let data: { error?: string; minted_bb?: number };

    try {
      const res = await this.post<{ error?: string; minted_bb?: number }>(
        "/bridge/deposit",
        body
      );
      status = res.status;
      data = res.data;
    } catch (err) {
      return { outcome: "retry", detail: String(err) };
    }

    if (status === 200) {
      log.info("bridge deposit minted", { tx: body.tx_hash, bb: data.minted_bb });
      return { outcome: "processed", detail: `minted ${data.minted_bb} BB` };
    }
    if (status === 409) {
      log.info("bridge deposit already processed (idempotent)", { tx: body.tx_hash });
      return { outcome: "processed", detail: "already_processed" };
    }
    if (status >= 400 && status < 500) {
      log.warn("bridge deposit rejected by L1", { tx: body.tx_hash, status, error: data.error });
      return { outcome: "rejected", detail: data.error ?? `HTTP ${status}` };
    }
    // 5xx or unexpected
    return { outcome: "retry", detail: `HTTP ${status}: ${data.error ?? ""}` };
  }

  // ── Health check ──────────────────────────────────────────────────────────────

  async isL1Healthy(): Promise<boolean> {
    try {
      const data = await this.get<{ ok?: boolean; online?: boolean }>("/health");
      return data.ok === true || data.online === true;
    } catch {
      return false;
    }
  }
}
