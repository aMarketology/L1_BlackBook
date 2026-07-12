#!/bin/bash
# ============================================================================
# BlackBook L1 — Deploy to production server (run from your local machine)
# ============================================================================
# Usage (first deploy OR after secrets change):
#   bash deployment/deploy.sh <SERVER_IP> --push-env
#
# Usage (code update only — .env already on server):
#   bash deployment/deploy.sh <SERVER_IP>
#
# What it does:
#   1. Optionally push local .env (which includes GENESIS_SEEDS)
#   2. Pull latest code on server
#   3. Rebuild Docker image and restart container
#   4. Wait for the node to come up (health check)
#   5. Verify GENESIS_SEEDS wallets are funded
# ============================================================================
set -euo pipefail

SERVER_IP="${1:?Usage: bash deployment/deploy.sh <SERVER_IP> [--push-env]}"
SSH_USER="${SSH_USER:-root}"
APP_DIR="/opt/blackbook"
ENV_FILE="$(dirname "$0")/../.env"
PUSH_ENV=false

for arg in "$@"; do
    case $arg in --push-env) PUSH_ENV=true ;; esac
done

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook L1 — Deploy to production server         ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Target : $SERVER_IP"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Push .env (first deploy or --push-env) ────────────────
if [ "$PUSH_ENV" = true ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "❌  .env not found at $ENV_FILE"
        echo "    cp .env.template .env  →  fill in SERVER_MASTER_KEY + L2_SEQUENCER_PUBKEY"
        exit 1
    fi
    if ! grep -q "^SERVER_MASTER_KEY=." "$ENV_FILE" 2>/dev/null; then
        echo "❌  SERVER_MASTER_KEY is empty in .env — fill it in before deploying"
        exit 1
    fi
    echo "⚠️  Pushing .env to $SERVER_IP:$APP_DIR/.env"
    read -rp "    Continue? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
    ssh "$SSH_USER@$SERVER_IP" "mkdir -p $APP_DIR"
    scp "$ENV_FILE" "$SSH_USER@$SERVER_IP:$APP_DIR/.env"
    echo "✅ .env pushed"
fi

# ── 2. Verify .env exists on server ─────────────────────────
if ! ssh "$SSH_USER@$SERVER_IP" "test -f $APP_DIR/.env"; then
    echo ""
    echo "❌  $APP_DIR/.env not found on server!"
    echo "    Run: bash deployment/deploy.sh $SERVER_IP --push-env"
    exit 1
fi

# ── 3. Pull latest code ──────────────────────────────────────
echo "[1/3] Pulling latest code on server..."
ssh "$SSH_USER@$SERVER_IP" "
    cd $APP_DIR
    git fetch origin master
    git reset --hard origin/master
    echo 'Code updated to: '$(git log -1 --oneline)
"

# ── 4. Rebuild + restart ─────────────────────────────────────
echo "[2/3] Building Docker image and starting container..."
ssh "$SSH_USER@$SERVER_IP" "
    cd $APP_DIR
    docker compose -f deployment/docker-compose.prod.yml up -d --build 2>&1 | tail -30
"

# ── 5. Health check + genesis seed verification ──────────────
echo "[3/3] Waiting for node to come up..."
MAX_WAIT=120
ELAPSED=0
until curl -sf "http://$SERVER_IP:8080/live" >/dev/null 2>&1; do
    sleep 5; ELAPSED=$((ELAPSED + 5))
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "❌  Node did not respond after ${MAX_WAIT}s. Check logs:"
        echo "    ssh $SSH_USER@$SERVER_IP 'docker logs --tail 50 blackbook-l1'"
        exit 1
    fi
    echo "    ... waiting (${ELAPSED}s)"
done
echo "✅ Node is live"

# Give it a few more seconds for genesis seeds to flush to ReDB
sleep 5

# Verify genesis-seeded wallets (extract from .env GENESIS_SEEDS if set)
SEEDS_LINE=$(ssh "$SSH_USER@$SERVER_IP" "grep '^GENESIS_SEEDS=' $APP_DIR/.env 2>/dev/null | head -1" || true)
if [ -n "$SEEDS_LINE" ]; then
    SEEDS_VAL="${SEEDS_LINE#GENESIS_SEEDS=}"
    echo ""
    echo "── Genesis seed verification ────────────────────────────"
    IFS=',' read -ra ENTRIES <<< "$SEEDS_VAL"
    ALL_OK=true
    for ENTRY in "${ENTRIES[@]}"; do
        ADDR="${ENTRY%%:*}"
        EXPECTED_LAMPORTS="${ENTRY##*:}"
        EXPECTED_BB=$(echo "scale=5; $EXPECTED_LAMPORTS / 100000" | bc 2>/dev/null || echo "?")
        RESPONSE=$(curl -sf "http://$SERVER_IP:8080/balance/$ADDR" 2>/dev/null || echo '{"balance":0}')
        ACTUAL_BB=$(echo "$RESPONSE" | grep -o '"balance":[0-9.]*' | cut -d: -f2 || echo "0")
        if [ "${ACTUAL_BB%.*}" -gt 0 ] 2>/dev/null; then
            echo "  ✅ $ADDR  →  $ACTUAL_BB BB"
        else
            echo "  ⚠️  $ADDR  →  $ACTUAL_BB BB  (expected ~$EXPECTED_BB BB — may need a restart)"
            ALL_OK=false
        fi
    done
    if [ "$ALL_OK" = false ]; then
        echo ""
        echo "  Some seeds show 0 — this can happen if the node was already"
        echo "  running with an old binary (no GENESIS_SEEDS support)."
        echo "  Force a clean restart:"
        echo "    ssh $SSH_USER@$SERVER_IP 'cd $APP_DIR && docker compose -f deployment/docker-compose.prod.yml restart'"
    fi
fi

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ✅ Deploy complete!                                  ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Health  :  http://$SERVER_IP:8080/health"
echo "║  Balance :  http://$SERVER_IP:8080/balance/<addr>"
echo "║  gRPC    :  $SERVER_IP:50051  (Reader node sync)"
echo "║"
echo "║  Logs: ssh $SSH_USER@$SERVER_IP 'docker logs -f blackbook-l1'"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "To run a local Reader node syncing from Hetzner:"
echo "  bash deployment/start-local-reader.sh $SERVER_IP"
