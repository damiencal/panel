#!/bin/bash
# =============================================================================
# Sandbox entrypoint — runs as PID 1 inside the Docker container.
#
# Responsibilities:
#   1. Mount cgroups (required for systemd in Docker)
#   2. Run install.sh once (idempotent)
#   3. Write panel.toml with correct paths
#   4. Apply DB migrations + seed data
#   5. Install WordPress via WP-CLI
#   6. Start the panel binary
#   7. Signal readiness; keep container alive
# =============================================================================
set -euo pipefail

PANEL_DIR=/opt/panel
PANEL_DB="${PANEL_DIR}/panel.db"
SEED_STAMP="${PANEL_DIR}/.seeded"
INSTALL_STAMP="${PANEL_DIR}/.installed"
LOG="${PANEL_DIR}/sandbox.log"

mkdir -p "${PANEL_DIR}"
exec > >(tee -a "${LOG}") 2>&1

echo "[entrypoint] $(date -u +%Y-%m-%dT%H:%M:%SZ) starting sandbox..."

# ─── 1. cgroup v2 mounts (needed inside privileged container) ────────────────
mount -t tmpfs tmpfs /sys/fs/cgroup 2>/dev/null || true
for subsys in cpu cpuset memory blkio; do
    mkdir -p "/sys/fs/cgroup/${subsys}"
    mount -t cgroup -o "rw,nosuid,nodev,noexec,relatime,${subsys}" \
          cgroup "/sys/fs/cgroup/${subsys}" 2>/dev/null || true
done

# ─── 2. Start dbus (needed by systemctl) ─────────────────────────────────────
mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null || true
sleep 1

# ─── 3. Install hosting services (idempotent) ────────────────────────────────
if [[ ! -f "${INSTALL_STAMP}" ]]; then
    echo "[entrypoint] Running install.sh (first boot)..."
    DEBIAN_FRONTEND=noninteractive bash /opt/panel/install.sh \
        --hostname=panel.test 2>&1 | tee -a "${LOG}" || true
    touch "${INSTALL_STAMP}"
else
    echo "[entrypoint] Services already installed; starting them..."
fi

# ── Start required services ───────────────────────────────────────────────────
for svc in mariadb postfix dovecot pure-ftpd redis-server openlitespeed; do
    service "${svc}" start 2>/dev/null || systemctl start "${svc}" 2>/dev/null || \
        echo "[entrypoint] WARNING: could not start ${svc}"
done
sleep 3

# ─── 4. Apply DB migrations ───────────────────────────────────────────────────
echo "[entrypoint] Applying SQLite migrations..."
for sql_file in "${PANEL_DIR}"/migrations/*.sql; do
    sqlite3 "${PANEL_DB}" < "${sql_file}" 2>/dev/null || true
done

# ─── 5. Seed panel data ───────────────────────────────────────────────────────
if [[ ! -f "${SEED_STAMP}" ]]; then
    echo "[entrypoint] Seeding panel database..."
    bash "${PANEL_DIR}/scripts/seed-panel.sh"
    touch "${SEED_STAMP}"
else
    echo "[entrypoint] Database already seeded."
fi

# ─── 6. Install WordPress ─────────────────────────────────────────────────────
if [[ ! -f "${PANEL_DIR}/.wordpress_installed" ]]; then
    echo "[entrypoint] Installing WordPress test site..."
    bash "${PANEL_DIR}/scripts/install-wordpress.sh" 2>&1 | tee -a "${LOG}" || \
        echo "[entrypoint] WARNING: WordPress install failed (non-fatal)"
    touch "${PANEL_DIR}/.wordpress_installed"
else
    echo "[entrypoint] WordPress already installed."
fi

# ─── 7. Restore sandbox panel config ────────────────────────────────────────
# install.sh writes its own panel.toml (127.0.0.1:3030) which would break
# Docker port-forwarding.  Always restore the sandbox-correct version.
echo "[entrypoint] Restoring sandbox panel.toml (host=0.0.0.0, port=8080)..."
cp "${PANEL_DIR}/panel.toml.sandbox" "${PANEL_DIR}/panel.toml"

# ─── 8. Start panel binary ───────────────────────────────────────────────────
echo "[entrypoint] Starting panel on :8080..."
cd "${PANEL_DIR}"
PANEL_CONFIG="${PANEL_DIR}/panel.toml" \
    "${PANEL_DIR}/panel" &
PANEL_PID=$!
echo "[entrypoint] panel PID=${PANEL_PID}"

# ─── 9. Wait for panel to be healthy ─────────────────────────────────────────
echo "[entrypoint] Waiting for panel health endpoint..."
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1; then
        echo "[entrypoint] Panel is up after ${i} seconds."
        break
    fi
    sleep 1
done

echo "[entrypoint] Sandbox ready. Panel running at http://localhost:8080"
echo "[entrypoint] WordPress: http://wp.panel.test (resolve via /etc/hosts)"

# ─── 10. Write readiness file (polled by wait-for-services.sh) ───────────────
touch "${PANEL_DIR}/.ready"

# ─── 11. Keep container alive ────────────────────────────────────────────────
tail -f "${LOG}" &
# Forward SIGTERM to panel
trap "kill ${PANEL_PID} 2>/dev/null; exit 0" SIGTERM SIGINT
wait ${PANEL_PID}
