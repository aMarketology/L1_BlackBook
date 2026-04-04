#!/bin/bash
# ============================================================================
# BlackBook L1 — Quick Deploy / Update (run from your local machine)
# ============================================================================
# Usage:
#   ./deploy/deploy.sh <SERVER_IP> [--push-env]
#
# Options:
#   --push-env   Also push your local .env to the server (first deploy or
#                when secrets change). You will be prompted to confirm.
#
# Prerequisites:
#   - SSH key already added to Hetzner server
#   - Server bootstrapped with setup-hetzner.sh
#   - .env filled out (copy .env.template → .env)
# ============================================================================
set -euo pipefail

SERVER_IP="${1:?Usage: ./deploy/deploy.sh <SERVER_IP> [--push-env]}"
SSH_USER="root"
APP_DIR="/opt/blackbook"
ENV_FILE="$(dirname "$0")/../.env"
PUSH_ENV=false

# Parse flags
for arg in "$@"; do
    case $arg in
        --push-env) PUSH_ENV=true ;;
    esac
done

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook L1 — Deploy to Hetzner                  ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Target:  $SERVER_IP"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Push .env secrets if requested ───────────────────────
if [ "$PUSH_ENV" = true ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "❌  .env not found at $ENV_FILE"
        echo "    Copy .env.template → .env and fill in SERVER_MASTER_KEY + L2_SEQUENCER_PUBKEY"
        exit 1
    fi

    # Sanity check — ensure required vars are actually set
    if ! grep -q "^SERVER_MASTER_KEY=." "$ENV_FILE"; then
        echo "❌  SERVER_MASTER_KEY is empty in .env — cannot deploy"
        exit 1
    fi

    echo "⚠️  About to push .env to $SERVER_IP:$APP_DIR/.env"
    read -rp "    Continue? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

    scp "$ENV_FILE" "$SSH_USER@$SERVER_IP:$APP_DIR/.env"
    echo "✅ .env pushed"
fi

# ── 2. Verify .env exists on server ─────────────────────────
if ! ssh "$SSH_USER@$SERVER_IP" "test -f $APP_DIR/.env"; then
    echo ""
    echo "❌  $APP_DIR/.env not found on server!"
    echo "    Run: ./deploy/deploy.sh $SERVER_IP --push-env"
    exit 1
fi

# ── 3. Pull latest code ──────────────────────────────────────
echo "[1/2] Pulling latest code..."
ssh "$SSH_USER@$SERVER_IP" "cd $APP_DIR && git pull origin master"

# ── 4. Rebuild and restart ───────────────────────────────────
echo "[2/2] Building and restarting container..."
ssh "$SSH_USER@$SERVER_IP" "
    cd $APP_DIR &&
    docker compose -f deploy/docker-compose.prod.yml up -d --build 2>&1 | tail -20
"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ✅ Deploy complete!                                  ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Health:  http://$SERVER_IP:8080/health"
echo "║  RPC:     http://$SERVER_IP:8899"
echo "║  gRPC:    $SERVER_IP:50051"
echo "║"
echo "║  Logs:  ssh $SSH_USER@$SERVER_IP 'docker logs -f blackbook-l1'"
echo "╚═══════════════════════════════════════════════════════╝"
