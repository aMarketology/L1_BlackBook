#!/bin/bash
# ============================================================================
# BlackBook — Cherry Servers Bootstrap (run as root on fresh Ubuntu 24.04)
# ============================================================================
# Replaces setup-hetzner.sh. Cherry Servers uses identical Ubuntu 24.04 base.
#
# Pre-flight (run on YOUR LOCAL machine before SSHing in):
#   scp .env root@<CHERRY_SERVER_IP>:/opt/blackbook-env.tmp
#
# Then on the server:
#   bash setup-cherry.sh
# ============================================================================
set -euo pipefail

REPO_URL="https://github.com/aMarketology/L1_BlackBook.git"
L2_REPO_URL="https://github.com/aMarketology/L2_BlackBook.git"
BRANCH="master"
APP_DIR="/opt/blackbook"
L2_DIR="/opt/blackbook/L2_BlackBook"
PRE_ENV="/opt/blackbook-env.tmp"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║    BlackBook — Cherry Servers Setup                  ║"
echo "╚═══════════════════════════════════════════════════════╝"

# ── 1. System update ─────────────────────────────────────────
echo "[1/8] Updating system packages..."
apt-get update && apt-get upgrade -y
apt-get install -y curl git ufw fail2ban unattended-upgrades wget

# ── 2. Swap (helps Docker builds not OOM; Cherry bare-metal may not need it)
echo "[2/8] Setting up 4 GB swap..."
if [ ! -f /swapfile ]; then
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p
fi

# ── 3. Docker ────────────────────────────────────────────────
echo "[3/8] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# ── 4. Firewall ──────────────────────────────────────────────
echo "[4/8] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp     comment 'SSH'
ufw allow 80/tcp     comment 'HTTP (Nginx → Certbot / redirect)'
ufw allow 443/tcp    comment 'HTTPS (Nginx TLS)'
ufw allow 8080/tcp   comment 'BlackBook L1 HTTP API'
ufw allow 8899/tcp   comment 'Solana JSON-RPC'
ufw allow 8003/udp   comment 'UDP TPU'
ufw allow 8004/udp   comment 'Turbine tick shreds'
ufw allow 50051/tcp  comment 'gRPC relay (writer→reader)'
ufw allow 50052/tcp  comment 'gRPC settlement (L2→L1)'
# Port 7072 is NOT opened publicly — Nginx proxies it internally
ufw --force enable
echo "UFW enabled."

# ── 5. fail2ban ──────────────────────────────────────────────
echo "[5/8] Enabling fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# ── 6. Clone repo ────────────────────────────────────────────
echo "[6/8] Cloning BlackBook repository..."
mkdir -p "${APP_DIR}"
if [ -d "${APP_DIR}/.git" ]; then
    echo "  Repo already cloned — pulling latest..."
    git -C "${APP_DIR}" fetch origin
    git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
else
    git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
fi

# Place the pre-copied .env file
if [ -f "${PRE_ENV}" ]; then
    mv "${PRE_ENV}" "${APP_DIR}/.env"
    chmod 600 "${APP_DIR}/.env"
    echo "  .env placed at ${APP_DIR}/.env"
else
    echo "  ⚠️  WARNING: ${PRE_ENV} not found."
    echo "       Run: scp .env root@<SERVER_IP>:${PRE_ENV}"
    echo "       Then re-run this script or place manually."
fi

# ── 7. Nginx (reverse proxy) ─────────────────────────────────
echo "[7/8] Installing and configuring Nginx..."
apt-get install -y nginx certbot python3-certbot-nginx

# Deploy our custom config
cp "${APP_DIR}/deployment/nginx-blackbook.conf" /etc/nginx/sites-available/blackbook
ln -sf /etc/nginx/sites-available/blackbook /etc/nginx/sites-enabled/blackbook
rm -f /etc/nginx/sites-enabled/default

nginx -t && systemctl reload nginx
echo "  Nginx configured."

# ── 8. Launch stack ──────────────────────────────────────────
echo "[8/9] Launching L1 + TS L2 sequencer stack..."
cd "${APP_DIR}"
docker compose -f deployment/docker-compose.prod.yml pull 2>/dev/null || true
docker compose -f deployment/docker-compose.prod.yml up -d --build

# ── 9. Clone and launch L2 BlackBook (Rust prediction market engine) ────
echo "[9/9] Deploying L2 BlackBook (Rust dealer)..."
if [ -d "${L2_DIR}/.git" ]; then
    echo "  L2_BlackBook already cloned — pulling latest..."
    git -C "${L2_DIR}" fetch origin
    git -C "${L2_DIR}" reset --hard "origin/${BRANCH}"
else
    git clone --branch "${BRANCH}" "${L2_REPO_URL}" "${L2_DIR}"
fi

# Copy the same .env (L2_BlackBook reads its own keys from it)
if [ -f "${APP_DIR}/.env" ]; then
    cp "${APP_DIR}/.env" "${L2_DIR}/.env"
    chmod 600 "${L2_DIR}/.env"
    echo "  .env copied to ${L2_DIR}/.env"
fi

mkdir -p "${APP_DIR}/data/l2"
cd "${L2_DIR}"
docker compose up -d --build

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Setup complete!                                      ║"
echo "║                                                       ║"
echo "║  Check status:                                        ║"
echo "║    docker compose -f /opt/blackbook/deployment/       ║"
echo "║      docker-compose.prod.yml ps                       ║"
echo "║    docker compose -C /opt/blackbook/L2_BlackBook ps   ║"
echo "║                                                       ║"
echo "║  TLS certificates (run once DNS is pointed here):    ║"
echo "║    certbot --nginx -d layer1.blackbook.id             ║"
echo "║               -d layer2.blackbook.id                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
