#!/bin/bash
# =============================================================================
# seed-panel.sh
#
# Populates the panel SQLite database with reproducible test data.
# Called by entrypoint.sh on first boot.
#
# Test credentials (all portals):
#   Admin:    username=admin     password=TestPass123!
#   Reseller: username=reseller  password=TestPass123!
#   Client:   username=client    password=TestPass123!
#   Mailbox:  password=MailPass123!
#   FTP:      password=FtpPass123!
# =============================================================================
set -euo pipefail

PANEL_DB="${PANEL_DB:-/opt/panel/panel.db}"
SEED_DIR="$(dirname "$0")/../seed"

log() { echo "[seed-panel] $*"; }

# ─── Ensure sqlite3 is available ─────────────────────────────────────────────
if ! command -v sqlite3 &>/dev/null; then
    apt-get install -y sqlite3 >/dev/null 2>&1
fi

# ─── Ensure argon2 CLI is available ──────────────────────────────────────────
if ! command -v argon2 &>/dev/null; then
    apt-get install -y argon2 >/dev/null 2>&1
fi

# ─── Generate Argon2id hashes ────────────────────────────────────────────────
# These use m=65536 (64 MB), t=3 iterations, p=4 threads — equivalent to
# Argon2::default() as used by the panel's Rust code.
log "Generating Argon2id password hashes..."

hash_password() {
    local password="$1"
    local salt
    salt=$(openssl rand -hex 8)
    # argon2 CLI: echo PASSWORD | argon2 SALT -id -m 16 -t 3 -p 4 -e
    # -m 16 → 2^16 = 65536 KiB memory cost (matches Rust default m_cost=65536)
    echo -n "${password}" | argon2 "${salt}" -id -m 16 -t 3 -p 4 -e
}

ADMIN_HASH=$(hash_password "TestPass123!")
RESELLER_HASH=$(hash_password "TestPass123!")
CLIENT_HASH=$(hash_password "TestPass123!")
MAILBOX_HASH=$(hash_password "MailPass123!")
FTP_HASH=$(hash_password "FtpPass123!")

log "Hashes generated."

# ─── Insert users ────────────────────────────────────────────────────────────
log "Seeding users..."
sqlite3 "${PANEL_DB}" <<SQL
INSERT OR IGNORE INTO users
    (id, username, email, password_hash, role, status, parent_id, package_id)
VALUES
(1, 'admin',    'admin@panel.test',    '${ADMIN_HASH}',    'Admin',    'Active', NULL, NULL),
(2, 'reseller', 'reseller@panel.test', '${RESELLER_HASH}', 'Reseller', 'Active',  1,    2),
(3, 'client',   'client@panel.test',   '${CLIENT_HASH}',   'Client',   'Active',  2,    4);
SQL

# ─── Apply static seed files ─────────────────────────────────────────────────
for seed_file in "${SEED_DIR}"/0[0-9][2-9]_*.sql "${SEED_DIR}"/01[0-9]_*.sql; do
    [[ -f "${seed_file}" ]] || continue
    log "Applying $(basename ${seed_file})..."
    sqlite3 "${PANEL_DB}" < "${seed_file}" 2>/dev/null || \
        log "WARNING: ${seed_file} had errors (may be safe to ignore)"
done

# ─── Insert mailboxes with hashed password ───────────────────────────────────
log "Seeding mailboxes..."
sqlite3 "${PANEL_DB}" <<SQL
INSERT OR IGNORE INTO mailboxes
    (id, domain_id, local_part, password_hash, quota_mb, status)
VALUES
(1, 1, 'admin',   '${MAILBOX_HASH}', 256, 'Active'),
(2, 1, 'client',  '${MAILBOX_HASH}', 512, 'Active'),
(3, 2, 'wp-admin','${MAILBOX_HASH}', 256, 'Active');
SQL

# ─── Insert FTP account with hashed password ─────────────────────────────────
log "Seeding FTP accounts..."
sqlite3 "${PANEL_DB}" <<SQL
INSERT OR IGNORE INTO ftp_accounts
    (id, owner_id, site_id, username, password_hash,
     home_dir, quota_size_mb, status)
VALUES
(1, 3, 1, 'client_ftp', '${FTP_HASH}',
    '/var/www/wp.panel.test', 1024, 'Active');
SQL

# ─── Create site document roots ──────────────────────────────────────────────
log "Creating site document root directories..."
for dir in \
    /var/www/wp.panel.test \
    /var/www/static.panel.test \
    /var/www/reseller-site.panel.test; do
    mkdir -p "${dir}"
    # Create a simple index file so the file manager has something to list
    if [[ ! -f "${dir}/index.html" ]]; then
        echo "<html><body><h1>Test site: ${dir##*/}</h1></body></html>" > "${dir}/index.html"
    fi
done

# static.panel.test: create a sample CSS file too for variety
mkdir -p /var/www/static.panel.test/css
echo "body { font-family: sans-serif; }" > /var/www/static.panel.test/css/main.css

# ─── Create MariaDB databases and users ──────────────────────────────────────
log "Creating MariaDB databases and users..."
mysql -u root <<MYSQL 2>/dev/null || true
CREATE DATABASE IF NOT EXISTS \`client_wp\`  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS \`client_dev\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'client_wp_user'@'localhost'  IDENTIFIED BY 'DBPass123!';
CREATE USER IF NOT EXISTS 'client_dev_user'@'localhost' IDENTIFIED BY 'DBPass123!';
GRANT ALL PRIVILEGES ON \`client_wp\`.*  TO 'client_wp_user'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`client_dev\`.* TO 'client_dev_user'@'localhost';
FLUSH PRIVILEGES;
MYSQL

# ─── Add /etc/hosts entries for test domains ─────────────────────────────────
log "Adding /etc/hosts entries..."
HOSTS_ENTRIES=(
    "127.0.0.1 panel.test"
    "127.0.0.1 wp.panel.test"
    "127.0.0.1 static.panel.test"
    "127.0.0.1 reseller-site.panel.test"
    "127.0.0.1 reseller.panel.test"
    "127.0.0.1 mail.panel.test"
)
for entry in "${HOSTS_ENTRIES[@]}"; do
    grep -qF "${entry}" /etc/hosts || echo "${entry}" >> /etc/hosts
done

log "Seeding complete."
