#!/bin/bash
# =============================================================================
# install-wordpress.sh
#
# Installs a real WordPress site (wp.panel.test) in the sandbox using WP-CLI.
# Requires MariaDB and OpenLiteSpeed to already be running.
#
# Output: /var/www/wp.panel.test with a fully installed WordPress instance.
# =============================================================================
set -euo pipefail

WP_DOMAIN="wp.panel.test"
WP_DIR="/var/www/${WP_DOMAIN}"
WP_DB="client_wp"
WP_DB_USER="client_wp_user"
WP_DB_PASS="DBPass123!"
WP_ADMIN_USER="wpadmin"
WP_ADMIN_PASS="WpAdmin123!"
WP_ADMIN_EMAIL="admin@panel.test"
WP_TITLE="Panel Test Site"

log() { echo "[install-wp] $*"; }

# ─── Download WP-CLI ─────────────────────────────────────────────────────────
if [[ ! -f /usr/local/bin/wp ]]; then
    log "Downloading WP-CLI..."
    curl -sS https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
         -o /usr/local/bin/wp
    chmod +x /usr/local/bin/wp
fi

WP="wp --allow-root --path=${WP_DIR}"

# ─── Verify DB is accepting connections ──────────────────────────────────────
log "Checking MariaDB connection..."
for i in $(seq 1 30); do
    mysqladmin ping --silent && break
    sleep 2
done

# ─── Create WordPress DB (idempotent) ────────────────────────────────────────
log "Creating WordPress database..."
mysql -u root <<MYSQL 2>/dev/null || true
CREATE DATABASE IF NOT EXISTS \`${WP_DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';
GRANT ALL PRIVILEGES ON \`${WP_DB}\`.* TO '${WP_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
MYSQL

# ─── Download WordPress core ─────────────────────────────────────────────────
mkdir -p "${WP_DIR}"
if [[ ! -f "${WP_DIR}/wp-includes/version.php" ]]; then
    log "Downloading WordPress core..."
    ${WP} core download --locale=en_US --version=latest
else
    log "WordPress core already downloaded."
fi

# ─── Create wp-config.php ────────────────────────────────────────────────────
if [[ ! -f "${WP_DIR}/wp-config.php" ]]; then
    log "Creating wp-config.php..."
    ${WP} config create \
        --dbname="${WP_DB}" \
        --dbuser="${WP_DB_USER}" \
        --dbpass="${WP_DB_PASS}" \
        --dbhost="127.0.0.1" \
        --dbprefix="wp_" \
        --skip-check
fi

# ─── Install WordPress ────────────────────────────────────────────────────────
if ! ${WP} core is-installed 2>/dev/null; then
    log "Running WordPress install..."
    ${WP} core install \
        --url="http://${WP_DOMAIN}" \
        --title="${WP_TITLE}" \
        --admin_user="${WP_ADMIN_USER}" \
        --admin_password="${WP_ADMIN_PASS}" \
        --admin_email="${WP_ADMIN_EMAIL}" \
        --skip-email
else
    log "WordPress already installed."
fi

# ─── Install & activate a test plugin (for plugin tests) ─────────────────────
log "Installing Hello Dolly plugin..."
${WP} plugin install hello-dolly --activate 2>/dev/null || true

# ─── Create sample content ───────────────────────────────────────────────────
log "Creating sample WordPress content..."

# Sample post
POST_COUNT=$(${WP} post list --post_type=post --format=count 2>/dev/null || echo 0)
if [[ "${POST_COUNT}" -lt 2 ]]; then
    ${WP} post create \
        --post_title='Hello World from Panel Test' \
        --post_content='This is a test post created by the panel sandbox.' \
        --post_status=publish 2>/dev/null || true
    ${WP} post create \
        --post_title='Sample Page' \
        --post_type=page \
        --post_content='This is a sample page.' \
        --post_status=publish 2>/dev/null || true
fi

# ─── Set file permissions ─────────────────────────────────────────────────────
log "Setting file permissions..."
chown -R www-data:www-data "${WP_DIR}" 2>/dev/null || true
find "${WP_DIR}" -type d -exec chmod 755 {} \;
find "${WP_DIR}" -type f -exec chmod 644 {} \;
chmod 600 "${WP_DIR}/wp-config.php"

# ─── Configure OpenLiteSpeed virtual host for WordPress ──────────────────────
log "Configuring OpenLiteSpeed virtual host..."
OLS_VHOST_DIR="/usr/local/lsws/conf/vhosts/${WP_DOMAIN}"
mkdir -p "${OLS_VHOST_DIR}"

cat > "${OLS_VHOST_DIR}/vhconf.conf" <<OLS_CONF
docRoot                   \$VH_ROOT/html/
vhDomain                  ${WP_DOMAIN}
vhAliases                 www.${WP_DOMAIN}
adminEmails               ${WP_ADMIN_EMAIL}
enableGzip                1

index  {
  useServer               0
  indexFiles              index.php, index.html
}

context / {
  type                    NULL
  location                ${WP_DIR}
  allowBrowse             1

  rewrite  {
    enable                1
    rules                 <<<END_RULES
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
    END_RULES
  }
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

phpIniOverride  {
}
OLS_CONF

# Add virtual host to OLS listeners config if not already present
OLS_HTTPD_CONF="/usr/local/lsws/conf/httpd_config.conf"
if [[ -f "${OLS_HTTPD_CONF}" ]] && ! grep -q "${WP_DOMAIN}" "${OLS_HTTPD_CONF}"; then
    log "Registering virtual host in OLS httpd_config.conf..."
    cat >> "${OLS_HTTPD_CONF}" <<VHOST_ENTRY

virtualHost ${WP_DOMAIN} {
  vhRoot                  ${WP_DIR}
  configFile              ${OLS_VHOST_DIR}/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
  maxKeepAliveReq         10000
}
VHOST_ENTRY

    # Map domain to listener (port 80)
    grep -q "map.*${WP_DOMAIN}" "${OLS_HTTPD_CONF}" || \
    sed -i "/^listener HTTP {/,/^}/ s/map.*$/&\n  map ${WP_DOMAIN} ${WP_DOMAIN}/" \
        "${OLS_HTTPD_CONF}" 2>/dev/null || true
fi

# Graceful OLS reload
/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || \
    service openlitespeed restart 2>/dev/null || true

log "WordPress installation complete."
log "  URL:          http://${WP_DOMAIN}"
log "  Admin:        http://${WP_DOMAIN}/wp-admin"
log "  Admin user:   ${WP_ADMIN_USER}"
log "  Admin pass:   ${WP_ADMIN_PASS}"
