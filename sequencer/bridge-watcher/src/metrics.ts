/** Lightweight in-process counters — no external dependency. */

const counters: Record<string, number> = {};
const gauges: Record<string, number> = {};

export function inc(name: string, by = 1): void {
  counters[name] = (counters[name] ?? 0) + by;
}

export function gauge(name: string, value: number): void {
  gauges[name] = value;
}

export function snapshot(): Record<string, number> {
  return { ...counters, ...gauges };
}

/** Prometheus text-format export */
export function renderPrometheus(): string {
  const lines: string[] = [];
  for (const [k, v] of Object.entries(counters)) {
    lines.push(`bridge_watcher_${k}_total ${v}`);
  }
  for (const [k, v] of Object.entries(gauges)) {
    lines.push(`bridge_watcher_${k} ${v}`);
  }
  return lines.join("\n") + "\n";
}
