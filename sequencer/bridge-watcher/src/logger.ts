type Level = "debug" | "info" | "warn" | "error";

const LEVELS: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

let minLevel: number = LEVELS.info;

export function setLogLevel(level: Level): void {
  minLevel = LEVELS[level];
}

function emit(level: Level, msg: string, meta?: Record<string, unknown>): void {
  if (LEVELS[level] < minLevel) return;
  const entry: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...meta,
  };
  // Scrub any accidental key material
  for (const key of Object.keys(entry)) {
    if (/private|secret|key|seed|mnemonic/i.test(key)) {
      entry[key] = "[REDACTED]";
    }
  }
  process.stdout.write(JSON.stringify(entry) + "\n");
}

export const log = {
  debug: (msg: string, meta?: Record<string, unknown>) => emit("debug", msg, meta),
  info:  (msg: string, meta?: Record<string, unknown>) => emit("info",  msg, meta),
  warn:  (msg: string, meta?: Record<string, unknown>) => emit("warn",  msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => emit("error", msg, meta),
};

export type Logger = typeof log;
