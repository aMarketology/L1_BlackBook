#!/bin/bash
# ============================================================================
# BlackBook L1 — Hetzner Server Bootstrap (run as root on fresh Ubuntu 24.04)
# ============================================================================
# This script:
#   1. Updates the system
#   2. Installs Docker
#   3. Configures firewall (UFW)
#   4. Creates a dedicated blackbook user
#   5. Sets up swap (2 GB — helps during Docker builds)
#   6. Clones the repo and launches the node
# ============================================================================
set -euo pipefail

REPO_URL="https://github.com/aMarketology/L1_BlackBook.git"
BRANCH="master"
APP_DIR="/opt/blackbook"

# ── Pre-flight: require .env to be present (scp'd before running this script)
# Run on your LOCAL machine first:
#   scp .env root@<SERVER_IP>:/opt/blackbook-env.tmp
# Then this script moves it into place after cloning.
PRE_ENV="/opt/blackbook-env.tmp"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook L1 — Hetzner Server Setup  v1.0.2       ║"
echo "╚═══════════════════════════════════════════════════════╝"

# ── 1. System update ─────────────────────────────────────────
echo "[1/7] Updating system packages..."
apt-get update && apt-get upgrade -y
apt-get install -y curl git ufw fail2ban unattended-upgrades

# ── 2. Create swap (helps Docker build not OOM) ──────────────
echo "[2/7] Setting up 2 GB swap..."
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p
fi

# ── 3. Install Docker ────────────────────────────────────────
echo "[3/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# ── 4. Firewall ──────────────────────────────────────────────
echo "[4/7] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH'
ufw allow 8080/tcp  comment 'BlackBook HTTP API'
ufw allow 8899/tcp  comment 'Solana JSON-RPC'
ufw allow 8003/udp  comment 'BlackBook TPU (binary transaction ingestion)'
ufw allow 8004/udp  comment 'Turbine tick shred broadcast (PoH real-time, Reader nodes)'
# gRPC relay: only allow from trusted reader-node IP (set READER_NODE_IP env var before running)
if [ -n "${READER_NODE_IP:-}" ]; then
    ufw allow from "${READER_NODE_IP}" to any port 50051 proto tcp comment 'gRPC Validator Relay (trusted reader)'
else
    echo "[WARN] READER_NODE_IP not set — gRPC port 50051 is NOT opened. Set READER_NODE_IP and re-run to allow reader nodes."
fi
echo "y" | ufw enable

# ── 5. Security hardening ────────────────────────────────────
echo "[5/7] Hardening SSH..."
# Disable password auth (you should already have SSH keys)
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd || true

# Enable automatic security updates
dpkg-reconfigure -plow unattended-upgrades || true

# ── 6. Clone and deploy ──────────────────────────────────────
echo "[6/7] Cloning BlackBook L1..."
mkdir -p "$APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR" && git pull origin "$BRANCH"
else
    git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

# Move pre-loaded .env into place (if it was scp'd before this script ran)
if [ -f "$PRE_ENV" ]; then
    mv "$PRE_ENV" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "✅ .env installed from $PRE_ENV"
elif [ ! -f "$APP_DIR/.env" ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  NO .env FILE FOUND — NODE REQUIRES SECRETS TO START    ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  On your LOCAL machine, run:                                 ║"
    echo "║    cp .env.template .env                                     ║"
    echo "║    # Fill in SERVER_MASTER_KEY and L2_SEQUENCER_PUBKEY       ║"
    echo "║    scp .env root@<SERVER_IP>:$APP_DIR/.env                   ║"
    echo "║  Then re-run step 7 manually:                                ║"
    echo "║    cd $APP_DIR && docker compose -f deploy/docker-compose.prod.yml up -d --build ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Bootstrap complete — START SKIPPED until .env is provided."
    exit 0
fi

# ── 7. Build and launch ──────────────────────────────────────
echo "[7/7] Building and launching BlackBook L1..."
cd "$APP_DIR"
docker compose -f deployment/docker-compose.prod.yml up -d --build

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║    ✅ BlackBook L1 is LIVE!                           ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Health:    http://$(curl -4 -s ifconfig.me):8080/health  ║"
echo "║  RPC:       http://$(curl -4 -s ifconfig.me):8899        ║"
echo "║  Logs:      docker logs -f blackbook-l1               ║"
echo "║  Status:    docker ps                                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
