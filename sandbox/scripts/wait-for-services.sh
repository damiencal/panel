#!/bin/bash
# =============================================================================
# wait-for-services.sh
#
# Polls the sandbox container until the panel and all hosting services are
# healthy. Called by the CI workflow and local test scripts before running
# Playwright.
#
# Usage:
#   ./sandbox/scripts/wait-for-services.sh [container_name] [timeout_secs]
#   ./sandbox/scripts/wait-for-services.sh panel-sandbox 300
# =============================================================================
set -euo pipefail

CONTAINER="${1:-panel-sandbox}"
TIMEOUT="${2:-300}"
POLL_INTERVAL=5
elapsed=0

wait_for() {
    local label="$1"
    local cmd="$2"
    local t=0
    printf "  [wait] %-30s " "${label}..."
    while ! eval "${cmd}" >/dev/null 2>&1; do
        sleep "${POLL_INTERVAL}"
        t=$((t + POLL_INTERVAL))
        if [[ $t -ge $TIMEOUT ]]; then
            echo "TIMEOUT after ${TIMEOUT}s"
            return 1
        fi
        printf "."
    done
    echo " OK (${t}s)"
}

echo "=== Waiting for sandbox container '${CONTAINER}' to be ready ==="
echo "    Timeout: ${TIMEOUT}s | Poll interval: ${POLL_INTERVAL}s"
echo ""

# ── 1. Container must be running ─────────────────────────────────────────────
wait_for "Container running" \
    "docker inspect -f '{{.State.Running}}' ${CONTAINER} | grep -q true"

# ── 2. Panel HTTP endpoint ────────────────────────────────────────────────────
wait_for "Panel HTTP (:8080)" \
    "curl -sf --max-time 4 http://localhost:8080/"

# ── 3. MariaDB ────────────────────────────────────────────────────────────────
wait_for "MariaDB" \
    "docker exec ${CONTAINER} mysqladmin ping --silent"

# ── 4. OpenLiteSpeed ─────────────────────────────────────────────────────────
wait_for "OpenLiteSpeed (:80)" \
    "curl -sf --max-time 4 -o /dev/null http://localhost:8180/"

# ── 5. Postfix ────────────────────────────────────────────────────────────────
wait_for "Postfix (SMTP :25)" \
    "docker exec ${CONTAINER} bash -c 'ss -tlnp | grep -q :25'"

# ── 6. Pure-FTPd ─────────────────────────────────────────────────────────────
wait_for "Pure-FTPd (:21)" \
    "docker exec ${CONTAINER} bash -c 'ss -tlnp | grep -q :21'"

# ── 7. Redis ─────────────────────────────────────────────────────────────────
wait_for "Redis" \
    "docker exec ${CONTAINER} redis-cli ping | grep -q PONG"

# ── 8. Seed / readiness flag ─────────────────────────────────────────────────
wait_for "Seed complete (.ready flag)" \
    "docker exec ${CONTAINER} test -f /opt/panel/.ready"

echo ""
echo "=== All services healthy. Ready to run Playwright tests. ==="
