#!/usr/bin/env bash
# seed_hetzner.sh — Idempotent genesis balance seeder for the BlackBook L1
#                   Hetzner production node.
#
# WHAT IT DOES
#   Appends a GENESIS_SEEDS line to the server's .env file, then restarts the
#   service.  On the next boot the node reads GENESIS_SEEDS and credits each
#   address ONCE — if the address already has a non-zero balance it is skipped.
#   Subsequent restarts are safe (idempotent).
#
# USAGE
#   1. Set HETZNER_HOST (or pass it as the first arg).
#   2. Optionally set HETZNER_USER (default: root) and ENV_PATH (default below).
#   3. Set L2_ORACLE_ADDRESS to the base58 pubkey of your L2 oracle/sequencer.
#   4. Run:  bash deployment/seed_hetzner.sh [<ssh-host>]
#
# REQUIREMENTS
#   - SSH access to the Hetzner node (key-based auth recommended).
#   - The node must be running with the binary built WITHOUT --features unsafe_admin
#     (production mode).  If you need /admin/mint use the dev build instead.
#
# LAMPORT CONVERSION
#   1 BB = 100_000 lamports (LAMPORTS_PER_BB)
#   Examples:
#     100 BB  =    10_000_000 lamports
#   1,000 BB  =   100_000_000 lamports
#  10,000 BB  = 1_000_000_000 lamports

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

HETZNER_HOST="${1:-${HETZNER_HOST:-YOUR_HETZNER_IP_OR_HOSTNAME}}"
HETZNER_USER="${HETZNER_USER:-root}"
ENV_PATH="${ENV_PATH:-/opt/blackbook/.env}"       # Adjust to your deployment path
SERVICE_NAME="${SERVICE_NAME:-blackbook-l1}"       # systemd service name

# ─── Seed addresses ──────────────────────────────────────────────────────────
#
# Personal wallet (EJYsHB4zZ5J5fmtk61Ge9BYDuA1QMtC8j9Dm7q8jWbmo)
PERSONAL_WALLET="EJYsHB4zZ5J5fmtk61Ge9BYDuA1QMtC8j9Dm7q8jWbmo"
PERSONAL_LAMPORTS="1000000000"    # 10,000 BB = 1_000_000_000 lamports

# House / rake treasury PDA (SHA256("bb_house_treasury_v1") → base58)
# This is a deterministic PDA — no private key. Receives expired contest rakes.
HOUSE_TREASURY="FHLDZvGVq8doU4sKAfQ6nCMr8azkEpucCwk1L1jNJAmy"
HOUSE_TREASURY_LAMPORTS="5000000000"  # 50,000 BB (reserve for sweeps / gas)

# L2 Oracle / Sequencer address
# Set this to the base58 address DERIVED from your L2_SEQUENCER_PUBKEY env var.
# The pubkey is a 64-hex-char Ed25519 public key; the address is its base58 form.
# Leave as empty string to skip seeding the oracle wallet.
L2_ORACLE_ADDRESS="${L2_ORACLE_ADDRESS:-}"
L2_ORACLE_LAMPORTS="1000000000"   # 10,000 BB

# ─── Build GENESIS_SEEDS value ───────────────────────────────────────────────

SEEDS="${PERSONAL_WALLET}:${PERSONAL_LAMPORTS},${HOUSE_TREASURY}:${HOUSE_TREASURY_LAMPORTS}"

if [[ -n "${L2_ORACLE_ADDRESS}" ]]; then
    SEEDS="${SEEDS},${L2_ORACLE_ADDRESS}:${L2_ORACLE_LAMPORTS}"
    echo "[seed] Including L2 oracle: ${L2_ORACLE_ADDRESS}"
else
    echo "[seed] L2_ORACLE_ADDRESS not set — oracle wallet will NOT be seeded"
    echo "       Set L2_ORACLE_ADDRESS=<base58 addr> to include it."
fi

echo ""
echo "Seeds to apply:"
echo "  Personal wallet:   ${PERSONAL_WALLET} → $((PERSONAL_LAMPORTS / 100000)) BB"
echo "  House treasury:    ${HOUSE_TREASURY} → $((HOUSE_TREASURY_LAMPORTS / 100000)) BB"
[[ -n "${L2_ORACLE_ADDRESS}" ]] && echo "  L2 oracle:         ${L2_ORACLE_ADDRESS} → $((L2_ORACLE_LAMPORTS / 100000)) BB"
echo ""

if [[ "${HETZNER_HOST}" == "YOUR_HETZNER_IP_OR_HOSTNAME" ]]; then
    echo "ERROR: Set HETZNER_HOST or pass the server address as the first argument."
    echo "       Example: HETZNER_HOST=1.2.3.4 bash deployment/seed_hetzner.sh"
    echo ""
    echo "To apply manually, add this line to your .env on the server:"
    echo "  GENESIS_SEEDS=${SEEDS}"
    exit 1
fi

# ─── Apply on server ─────────────────────────────────────────────────────────

echo "[seed] Connecting to ${HETZNER_USER}@${HETZNER_HOST} ..."

ssh -o StrictHostKeyChecking=no "${HETZNER_USER}@${HETZNER_HOST}" bash <<EOF
set -euo pipefail

ENV_FILE="${ENV_PATH}"

# Ensure .env file exists
if [[ ! -f "\${ENV_FILE}" ]]; then
    echo "[seed] .env not found at \${ENV_FILE}, creating it ..."
    touch "\${ENV_FILE}"
fi

# Remove any existing GENESIS_SEEDS line (so we don't accumulate duplicates)
if grep -q '^GENESIS_SEEDS=' "\${ENV_FILE}" 2>/dev/null; then
    echo "[seed] Removing old GENESIS_SEEDS line from \${ENV_FILE}"
    sed -i '/^GENESIS_SEEDS=/d' "\${ENV_FILE}"
fi

# Append new GENESIS_SEEDS
echo "GENESIS_SEEDS=${SEEDS}" >> "\${ENV_FILE}"
echo "[seed] Added GENESIS_SEEDS to \${ENV_FILE}"

# Restart service so the node reads the new env var and seeds at startup
echo "[seed] Restarting systemd service '${SERVICE_NAME}' ..."
systemctl restart "${SERVICE_NAME}" && echo "[seed] Restart OK" || {
    # Docker Compose fallback
    cd "\$(dirname "\${ENV_FILE}")" && docker compose restart && echo "[seed] Docker restart OK"
}

echo "[seed] Done. Wait ~5 seconds for the node to boot, then verify with:"
echo "  curl https://your-node/balance/${PERSONAL_WALLET}"
EOF

echo ""
echo "[seed] Seeding script complete."
echo "Verify balances after the node restarts:"
echo "  curl http://${HETZNER_HOST}:8080/balance/${PERSONAL_WALLET}"
echo "  curl http://${HETZNER_HOST}:8080/balance/${HOUSE_TREASURY}"
