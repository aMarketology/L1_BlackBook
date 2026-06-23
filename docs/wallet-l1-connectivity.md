# Wallet ↔ L1 connectivity (OFFLINE indicator)

## Production node URL

**TLS is live.** Use `https://` — the server now redirects `http://` → `https://` (301).

```
https://layer1.blackbook.id
```

Direct IP (bypasses nginx, no TLS — local / server-side use only):

```
http://91.98.196.34:8080
```

> **Note:** Browser / Tauri WebView requests **must** use `https://layer1.blackbook.id`.
> `http://91.98.196.34:8080` bypasses TLS and CORS; use only from scripts or curl.

## What `/health` returns (L1 v5+)

```json
{
  "status": "healthy",
  "ok": true,
  "online": true,
  "slot": 3730123,
  "total_supply": 1000.0,
  "uptime_seconds": 86400,
  "version": "5.0.2",
  "network": "mainnet",
  "blockchain": { ... },
  "poh_clock": { "current_slot": 3730123, ... }
}
```

- **`online: true`** — HTTP API reachable → show **ONLINE** in the UI.
- **`ok: true`** / **`status: "healthy"`** — PoH producing blocks (<10s since last block).
- **`status: "degraded"`** — node is up but block production is stale; show a warning, not OFFLINE.

## Wallet health check (recommended)

```ts
import { parseHealth } from "../sdk/wallet.sdk"; // or copy parseHealth into the wallet

async function checkNode(rpcUrl: string): Promise<"online" | "degraded" | "offline"> {
  try {
    const res = await fetch(`${rpcUrl.replace(/\/$/, "")}/health`);
    if (!res.ok) return "offline";
    const json = await res.json();
    const h = parseHealth(json);
    if (!h.online) return "offline";
    return h.healthy ? "online" : "degraded";
  } catch {
    return "offline";
  }
}
```

**Common mistake:** treating `status !== "ok"` as offline. L1 uses `"healthy"` / `"degraded"`, not `"ok"`.

**Common mistake:** using `GET /ready` for the indicator — returns **503** when block age >30s even though the node is alive.

## CORS (browser / Vite)

Allowed by default:

- `http://localhost:5173`, `http://127.0.0.1:5173`
- `tauri://localhost`, `https://tauri.localhost`
- `http://layer1.blackbook.id`, `https://layer1.blackbook.id`
- `https://blackbook.id`, `https://wallet.blackbook.id`

Extra origins: `CORS_EXTRA_ORIGINS=https://my-wallet.vercel.app`

Dev only: `CORS_ALLOW_ALL=true`

## Tauri HTTP permissions

If the desktop app uses `@tauri-apps/plugin-http`, allow the L1 host in `src-tauri/capabilities/default.json`:

```json
{
  "permissions": [
    {
      "identifier": "http:default",
      "allow": [
        { "url": "http://layer1.blackbook.id/**" },
        { "url": "http://91.98.196.34:8080/**" },
        { "url": "http://localhost:8080/**" },
        { "url": "http://127.0.0.1:8080/**" }
      ]
    }
  ]
}
```

If the app uses `fetch()` from the WebView, CORS on L1 applies (see above).

## Quick smoke tests

```powershell
# 1. Basic health (must return 200 + JSON with "status":"healthy")
curl.exe -s https://layer1.blackbook.id/health | ConvertFrom-Json | Select-Object status, ok, online, slot

# 2. CORS preflight — Vite dev origin
curl.exe -sv -X OPTIONS https://layer1.blackbook.id/health `
  -H "Origin: http://localhost:5173" `
  -H "Access-Control-Request-Method: GET" 2>&1 | Select-String "access-control-allow-origin"

# 3. CORS preflight — Tauri Windows WebView origin
curl.exe -sv -X OPTIONS https://layer1.blackbook.id/health `
  -H "Origin: https://tauri.localhost" `
  -H "Access-Control-Request-Method: GET" 2>&1 | Select-String "access-control-allow-origin"

# 4. Null origin (some Tauri builds send this)
curl.exe -sv https://layer1.blackbook.id/health `
  -H "Origin: null" 2>&1 | Select-String "access-control-allow-origin"
```

Each CORS check should respond with:
```
access-control-allow-origin: <origin-you-sent>
```
