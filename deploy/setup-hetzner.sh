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

echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook L1 — Hetzner Server Setup               ║"
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
ufw allow 50051/tcp comment 'gRPC Validator Relay'
echo "y" | ufw enable

# ── 5. Security hardening ────────────────────────────────────
echo "[5/7] Hardening SSH..."
# Disable password auth (you should already have SSH keys)
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

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

# Copy real_wallets if they exist locally (you'll scp them separately)
mkdir -p "$APP_DIR/deploy/real_wallets"

# ── 7. Build and launch ──────────────────────────────────────
echo "[7/7] Building and launching BlackBook L1..."
cd "$APP_DIR"
docker compose -f deploy/docker-compose.prod.yml up -d --build

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║    ✅ BlackBook L1 is LIVE!                           ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║  Health:    http://$(curl -4 -s ifconfig.me):8080/health  ║"
echo "║  RPC:       http://$(curl -4 -s ifconfig.me):8899        ║"
echo "║  Logs:      docker logs -f blackbook-l1               ║"
echo "║  Status:    docker ps                                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
