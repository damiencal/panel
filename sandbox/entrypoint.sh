#!/bin/bash
# =============================================================================
# Sandbox entrypoint — runs as PID 1 inside the Docker container.
#
# Startup order is optimised for CI: the panel must respond on :8080 within
# the wait-for-services.sh timeout (300s).  Slow one-time operations
# (install.sh apt upgrade, WordPress install) are deferred to the background
# so they never block the health-check window.
#
# Fast path  (<90s):  cgroups → dbus → start services → DB migrate → seed
#                     → restore panel.toml → launch panel → .ready flag
# Background:         install.sh (full service config, apt ops)
#                     WordPress installation
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

# ─── 3. Start hosting services ───────────────────────────────────────────────
# All packages are pre-installed in the Docker image. Start them now, before
# any long-running setup, so the wait-for-services.sh checks can pass early.
echo "[entrypoint] Starting hosting services..."
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

# ─── 6. Restore sandbox panel config ─────────────────────────────────────────
# Always restore the sandbox-correct panel.toml (host=0.0.0.0, port=8080).
# install.sh would overwrite it with 127.0.0.1:3030, which breaks Docker
# port-forwarding.  We keep a .sandbox backup in the image for this purpose.
echo "[entrypoint] Restoring sandbox panel.toml (host=0.0.0.0, port=8080)..."
cp "${PANEL_DIR}/panel.toml.sandbox" "${PANEL_DIR}/panel.toml"

# ─── 7. Start panel binary ───────────────────────────────────────────────────
echo "[entrypoint] Starting panel on :8080..."
cd "${PANEL_DIR}"
PANEL_CONFIG="${PANEL_DIR}/panel.toml" \
    "${PANEL_DIR}/panel" &
PANEL_PID=$!
echo "[entrypoint] panel PID=${PANEL_PID}"

# ─── 8. Wait for panel to be healthy ─────────────────────────────────────────
echo "[entrypoint] Waiting for panel health endpoint..."
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1; then
        echo "[entrypoint] Panel is up after ${i} seconds."
        break
    fi
    sleep 1
done

echo "[entrypoint] Sandbox ready. Panel running at http://localhost:8080"

# ─── 9. Write readiness file (polled by wait-for-services.sh) ────────────────
touch "${PANEL_DIR}/.ready"

# ─── 10. Deferred: full service configuration via install.sh ─────────────────
# install.sh runs apt-get upgrade and fully configures postfix/dovecot/OLS/FTP.
# It takes 5-10 minutes, so we run it in the background AFTER the readiness
# flag is written — this never blocks the CI health-check window.
if [[ ! -f "${INSTALL_STAMP}" ]]; then
    echo "[entrypoint] Launching install.sh in background for full service configuration..."
    (
        DEBIAN_FRONTEND=noninteractive bash /opt/panel/install.sh \
            --hostname=panel.test >> "${LOG}" 2>&1
        # Restore the sandbox panel.toml again in case install.sh overwrote it
        cp "${PANEL_DIR}/panel.toml.sandbox" "${PANEL_DIR}/panel.toml"
        touch "${INSTALL_STAMP}"
        echo "[entrypoint] install.sh complete."
    ) &
fi

# ─── 11. Deferred: WordPress installation ────────────────────────────────────
if [[ ! -f "${PANEL_DIR}/.wordpress_installed" ]]; then
    (
        bash "${PANEL_DIR}/scripts/install-wordpress.sh" >> "${LOG}" 2>&1 || \
            echo "[entrypoint] WARNING: WordPress install failed (non-fatal)"
        touch "${PANEL_DIR}/.wordpress_installed"
    ) &
fi

# ─── 12. Keep container alive ────────────────────────────────────────────────
tail -f "${LOG}" &
# Forward SIGTERM to panel
trap "kill ${PANEL_PID} 2>/dev/null; exit 0" SIGTERM SIGINT
wait ${PANEL_PID}
