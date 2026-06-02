import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

// Load .env manually (no dotenv dependency — keeps the footprint tiny)
function loadEnvFile(path: string): void {
  if (!existsSync(path)) return;
  const lines = readFileSync(path, "utf8").split("\n");
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    if (!(key in process.env)) process.env[key] = val;
  }
}

loadEnvFile(resolve(process.cwd(), ".env"));

const MintEntry = z.object({
  mint: z.string().min(32),
  label: z.string().min(1),
});

const Schema = z.object({
  solanaRpcUrl: z.string().url(),
  solanaRpcFallbackUrl: z.string().url().optional(),
  custodyWallet: z.string().min(32).max(44),
  watchedMints: z.array(MintEntry).min(1),
  pollIntervalMs: z.coerce.number().int().min(500).default(3000),
  pollPageSize: z.coerce.number().int().min(1).max(1000).default(50),
  reconcileIntervalMs: z.coerce.number().int().min(5000).default(30_000),
  maxBackoffMs: z.coerce.number().int().min(1000).default(60_000),
  minDepositMicro: z.coerce.bigint().default(1_000_000n),
  l1Url: z.string().url(),
  l1TimeoutMs: z.coerce.number().int().min(1000).default(10_000),
  port: z.coerce.number().int().min(1).max(65535).default(3400),
  dbPath: z.string().min(1).default("./data/bridge.db"),
  logLevel: z.enum(["debug", "info", "warn", "error"]).default("info"),
  genesisSignature: z.string().optional(),
});

export type Config = z.infer<typeof Schema>;

function parseMints(): Array<{ mint: string; label: string }> {
  const mints = (process.env.WATCHED_MINTS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const labels = (process.env.MINT_LABELS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (mints.length === 0) {
    // Default to Solana mainnet USDC + USDT
    return [
      { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", label: "USDC" },
      { mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", label: "USDT" },
    ];
  }
  return mints.map((mint, i) => ({ mint, label: labels[i] ?? mint.slice(0, 4) }));
}

export function loadConfig(): Config {
  const raw = {
    solanaRpcUrl: process.env.SOLANA_RPC_URL,
    solanaRpcFallbackUrl: process.env.SOLANA_RPC_FALLBACK_URL,
    custodyWallet: process.env.CUSTODY_WALLET,
    watchedMints: parseMints(),
    pollIntervalMs: process.env.POLL_INTERVAL_MS,
    pollPageSize: process.env.POLL_PAGE_SIZE,
    reconcileIntervalMs: process.env.RECONCILE_INTERVAL_MS,
    maxBackoffMs: process.env.MAX_BACKOFF_MS,
    minDepositMicro: process.env.MIN_DEPOSIT_MICRO,
    l1Url: process.env.L1_URL,
    l1TimeoutMs: process.env.L1_TIMEOUT_MS,
    port: process.env.PORT,
    dbPath: process.env.DB_PATH,
    logLevel: process.env.LOG_LEVEL,
    genesisSignature: process.env.BRIDGE_GENESIS_SIGNATURE || undefined,
  };

  const result = Schema.safeParse(raw);
  if (!result.success) {
    console.error("[config] Invalid configuration:\n", result.error.format());
    process.exit(1);
  }
  return result.data;
}
