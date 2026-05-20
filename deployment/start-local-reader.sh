#!/bin/bash
# ============================================================================
# BlackBook L1 — Start Local Reader Node (syncs from Hetzner Writer)
# ============================================================================
# Usage:
#   bash deployment/start-local-reader.sh <HETZNER_IP> [--release]
#
# Prerequisites:
#   - Port 50051 on Hetzner must allow your local IP:
#       ssh root@<HETZNER_IP> "ufw allow from $(curl -s ifconfig.me) to any port 50051"
#   - .env exists with GENESIS_SEEDS filled in (same as Hetzner .env)
# ============================================================================
set -euo pipefail

WRITER_IP="${1:?Usage: bash deployment/start-local-reader.sh <HETZNER_IP> [--release]}"
RELEASE=false
for arg in "$@"; do case $arg in --release) RELEASE=true ;; esac; done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$REPO/.env"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook L1 — Local Reader Node                  ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Writer : http://$WRITER_IP:50051"
echo "║  Local  : http://localhost:8080"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Load .env ──────────────────────────────────────────────
[ -f "$ENV_FILE" ] || { echo "❌  .env not found — cp .env.template .env"; exit 1; }
set -a; source "$ENV_FILE"; set +a
echo "✅ Loaded .env"

# ── 2. Open firewall on server for local IP (optional helper) ─
LOCAL_IP="$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo '')"
if [ -n "$LOCAL_IP" ]; then
    echo "   Your public IP: $LOCAL_IP"
    echo "   If gRPC connection fails, run on the server:"
    echo "     ufw allow from $LOCAL_IP to any port 50051 comment 'local reader'"
    echo ""
fi

# ── 3. Build binary ───────────────────────────────────────────
cd "$REPO"
if [ "$RELEASE" = true ]; then
    BIN="$REPO/target/release/layer1"
    [ -f "$BIN" ] || { echo "Building release binary..."; cargo build --release --bin layer1; }
else
    BIN="$REPO/target/debug/layer1"
    [ -f "$BIN" ] || { echo "Building debug binary..."; cargo build --bin layer1; }
fi
echo "✅ Binary: $BIN"

# ── 4. Start Reader ───────────────────────────────────────────
echo "[Starting Reader node — Ctrl+C to stop]"
echo ""
export REDB_PATH="$REPO/blockchain_data/reader.redb"

"$BIN" --mode reader --writer-addr "http://$WRITER_IP:50051"
