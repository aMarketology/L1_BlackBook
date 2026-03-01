#!/bin/bash
# ============================================================================
# BlackBook L1 — Quick Deploy / Update (run from your local machine)
# ============================================================================
# Usage:
#   ./deploy/deploy.sh <SERVER_IP>
#
# Prerequisites:
#   - SSH key already added to Hetzner server
#   - Server bootstrapped with setup-hetzner.sh
# ============================================================================
set -euo pipefail

SERVER_IP="${1:?Usage: ./deploy/deploy.sh <SERVER_IP>}"
SSH_USER="root"
APP_DIR="/opt/blackbook"

echo "═══ Deploying BlackBook L1 to $SERVER_IP ═══"

# Pull latest code on server
ssh "$SSH_USER@$SERVER_IP" "cd $APP_DIR && git pull origin master"

# Rebuild and restart
ssh "$SSH_USER@$SERVER_IP" "cd $APP_DIR && docker compose -f deploy/docker-compose.prod.yml up -d --build"

echo ""
echo "═══ Deploy complete! ═══"
echo "Health: http://$SERVER_IP:8080/health"
echo "RPC:    http://$SERVER_IP:8899"
echo "Logs:   ssh $SSH_USER@$SERVER_IP 'docker logs -f blackbook-l1'"
