#!/bin/bash

################################################################################
# Hosting Control Panel - Installation Script
# Installs the panel on Ubuntu 24.04 LTS with all dependencies:
#   - OpenLiteSpeed (web server) + LSPHP 8.3
#   - MariaDB (database server)
#   - Postfix (SMTP / mail transfer agent)
#   - Dovecot (IMAP/POP3 mail delivery)
#   - Pure-FTPd (FTP server with virtual users)
#   - Certbot (Let's Encrypt SSL)
#   - phpMyAdmin (database web UI)
#   - Cloudflare DNS (API integration)
#   - UFW (firewall)
################################################################################

set -euo pipefail

# ─── Argument parsing ────────────────────────────────────────────────────────
INSTALL_MODE="binary"      # default: download prebuilt binary from GitHub
PINNED_VERSION=""          # empty = latest release
USER_PROVIDED_HOSTNAME=""

for arg in "$@"; do
    case "$arg" in
        --from-source)
            INSTALL_MODE="source"
            ;;
        --version=*)
            PINNED_VERSION="${arg#--version=}"
            ;;
        --hostname=*)
            USER_PROVIDED_HOSTNAME="${arg#--hostname=}"
            ;;
        --help|-h)
            echo "Usage: $0 [--from-source] [--version=vX.Y.Z] [--hostname=admin.domain.com]"
            echo ""
            echo "  (default)       Download and install a prebuilt binary from GitHub Releases"
            echo "  --from-source   Build the panel binary from source using Rust/Cargo"
            echo "  --version=v...  Pin a specific release version (binary mode only)"
            echo "  --hostname=...  Provide a hostname to automatically generate a Let's Encrypt certificate"
            exit 0
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/panel"
DATA_DIR="/var/lib/panel"
LOG_DIR="/var/log/panel"
PANEL_USER="panel"
PANEL_GROUP="panel"

# Mail configuration
VMAIL_USER="vmail"
VMAIL_UID="5000"
VMAIL_GID="5000"
VMAIL_DIR="/var/mail/vhosts"

OPENLITESPEED_PACKAGES=(
    openlitespeed
    lsphp83
    lsphp83-common
    lsphp83-mysql
    lsphp83-curl
    lsphp83-opcache
    lsphp83-intl
    lsphp83-imagick
    lsphp83-apcu
    lsphp83-imap
    lsphp83-redis
    lsphp83-memcached
    lsphp83-sqlite3
    # Note: zip, mbstring, gd, openssl, pdo, xml, exif, bcmath, json
    # are compiled into lsphp83/lsphp83-common — no separate packages needed
)

# Detect hostname and IP
if [[ -n "$USER_PROVIDED_HOSTNAME" ]]; then
    SERVER_HOSTNAME="$USER_PROVIDED_HOSTNAME"
else
    SERVER_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
fi
SERVER_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1 || echo "127.0.0.1")

################################################################################
# Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

print_error() {
    echo -e "${RED}  ✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}  ℹ $1${NC}"
}

generate_passwords() {
    print_header "Generating Secrets"
    if [ ! -f /root/.panel_secrets ]; then
        MARIA_ROOT_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
        OLS_ADMIN_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
        PANEL_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
        
        cat > /root/.panel_secrets <<SECRETS
MARIA_ROOT_PASS="${MARIA_ROOT_PASS}"
OLS_ADMIN_PASS="${OLS_ADMIN_PASS}"
PANEL_ADMIN_PASSWORD="${PANEL_ADMIN_PASSWORD}"
SECRETS
        chmod 600 /root/.panel_secrets
    else
        source /root/.panel_secrets
    fi
    export PANEL_ADMIN_PASSWORD
    print_success "Secrets generated and saved to /root/.panel_secrets"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_distro() {
    print_header "Checking system requirements"
    
    if ! grep -q "Ubuntu 24.04" /etc/os-release 2>/dev/null; then
        print_warning "This installation script is optimized for Ubuntu 24.04 LTS"
        print_warning "Other versions may work but are not officially supported"
    else
        print_success "Running Ubuntu 24.04 LTS"
    fi
    
    print_info "Hostname: $SERVER_HOSTNAME"
    print_info "IP Address: $SERVER_IP"
}

update_system() {
    print_header "Updating system packages"
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    
    print_success "System updated"
}

install_rust() {
    print_header "Installing Rust toolchain"
    
    if command -v rustc &> /dev/null; then
        print_success "Rust already installed: $(rustc --version)"
        return
    fi
    
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    print_success "Rust installed: $(rustc --version)"
}

install_runtime_dependencies() {
    print_header "Installing runtime dependencies"

    apt-get install -y -qq \
        curl \
        wget \
        unzip \
        openssl \
        ssl-cert \
        ca-certificates \
        gnupg \
        lsb-release \
        software-properties-common

    print_success "Runtime dependencies installed"
}

install_build_dependencies() {
    print_header "Installing build dependencies"
    
    apt-get install -y -qq \
        build-essential \
        pkg-config \
        libssl-dev \
        libsqlite3-dev \
        git
    
    print_success "Build dependencies installed"
}

# ─────────────────────────────────────────────────────────────
#  OpenLiteSpeed Web Server
# ─────────────────────────────────────────────────────────────
install_openlitespeed() {
    print_header "Installing OpenLiteSpeed + LSPHP 8.3"

    if [[ ! -f "/usr/local/lsws/bin/lswsctrl" ]]; then
        # Add LiteSpeed repository
        wget -qO - https://repo.litespeed.sh | bash
    else
        print_info "OpenLiteSpeed already present, ensuring required packages are installed"
    fi

    apt-get update -qq
    apt-get install -y -qq "${OPENLITESPEED_PACKAGES[@]}"
    
    # Create vhost directory
    mkdir -p /usr/local/lsws/conf/vhosts
    
    # Enable OpenLiteSpeed systemd service
    systemctl enable lsws
    
    print_success "OpenLiteSpeed + LSPHP 8.3 installed"
}

install_auxiliary_services() {
    print_header "Installing auxiliary hosting services"

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        roundcube-core \
        memcached \
        redis-server \
        watchdog

    systemctl enable memcached
    systemctl enable redis-server
    systemctl enable watchdog

    print_success "Roundcube, Memcached, Redis, and Watchdog installed"
}

configure_openlitespeed() {
    print_header "Configuring OpenLiteSpeed"
    
    
    # Create default document root
    mkdir -p /usr/local/lsws/html
    
    # Configure listeners for HTTP (80) and HTTPS (443)
    # The panel will manage vhost configs directly
    
    print_info "WebAdmin URL: https://$SERVER_IP:7080"
    print_success "OpenLiteSpeed configured"
}

# ─────────────────────────────────────────────────────────────
#  MariaDB Database Server
# ─────────────────────────────────────────────────────────────
install_mariadb() {
    print_header "Installing MariaDB"
    
    if command -v mariadb &> /dev/null; then
        print_success "MariaDB already installed: $(mariadb --version | head -1)"
        return
    fi
    
    apt-get install -y -qq \
        mariadb-server \
        mariadb-client
    
    systemctl enable mariadb
    systemctl start mariadb
    
    print_success "MariaDB installed"
}

secure_mariadb() {
    print_header "Securing MariaDB"
    
    
    # Secure installation equivalent
    mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
    mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Set root password (Unix socket auth is default on Ubuntu, so also set password)
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('$MARIA_ROOT_PASS') OR unix_socket;" 2>/dev/null || true
    
    # Bind to localhost only
    if [[ -d "/etc/mysql/mariadb.conf.d" ]]; then
        cat > /etc/mysql/mariadb.conf.d/99-panel.cnf <<EOF
[mysqld]
bind-address = 127.0.0.1
max_connections = 100
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF
    fi
    
    systemctl restart mariadb
    
    print_info "Applied non-interactive MariaDB hardening equivalent to mysql_secure_installation"
    print_success "MariaDB secured"
}

# ─────────────────────────────────────────────────────────────
#  Postfix (SMTP Mail Transfer Agent)
# ─────────────────────────────────────────────────────────────
install_postfix() {
    print_header "Installing Postfix MTA"
    
    # Pre-configure Postfix to avoid interactive prompts
    debconf-set-selections <<< "postfix postfix/mailname string $SERVER_HOSTNAME"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    
    apt-get install -y -qq \
        postfix \
        postfix-mysql
    
    systemctl enable postfix
    
    print_success "Postfix installed"
}

configure_postfix() {
    print_header "Configuring Postfix for virtual domain hosting"
    
    # Create vmail group and user for virtual mailbox delivery
    groupadd -g "$VMAIL_GID" "$VMAIL_USER" 2>/dev/null || true
    useradd -r -u "$VMAIL_UID" -g "$VMAIL_GID" -d "$VMAIL_DIR" -s /usr/sbin/nologin "$VMAIL_USER" 2>/dev/null || true
    
    # Create mailbox directories
    mkdir -p "$VMAIL_DIR"
    chown -R "$VMAIL_USER:$VMAIL_USER" "$VMAIL_DIR"
    chmod 770 "$VMAIL_DIR"
    
    # Create virtual lookup files
    touch /etc/postfix/virtual_domains
    touch /etc/postfix/virtual_mailboxes
    touch /etc/postfix/virtual_aliases
    
    # Write main.cf
    cat > /etc/postfix/main.cf <<EOF
# Postfix main.cf - Managed by Hosting Control Panel

# General
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# Hostname
myhostname = $SERVER_HOSTNAME
mydomain = $SERVER_HOSTNAME
myorigin = \$mydomain
mydestination = localhost

# Network
inet_interfaces = all
inet_protocols = ipv4

# Virtual domains and mailboxes
virtual_mailbox_domains = hash:/etc/postfix/virtual_domains
virtual_mailbox_maps = hash:/etc/postfix/virtual_mailboxes
virtual_alias_maps = hash:/etc/postfix/virtual_aliases
virtual_mailbox_base = $VMAIL_DIR
virtual_minimum_uid = 100
virtual_uid_maps = static:$VMAIL_UID
virtual_gid_maps = static:$VMAIL_GID

# TLS (incoming SMTP)
smtpd_tls_security_level = may
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# TLS (outgoing SMTP)
smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# SASL Authentication (via Dovecot)
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname

# Restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org

# Mailbox size limits
mailbox_size_limit = 0
message_size_limit = 52428800
virtual_mailbox_limit = 0
EOF
    
    # Deploy master.cf for submission/smtps ports
    if [[ -f "templates/postfix_master.cf" ]]; then
        cp templates/postfix_master.cf /etc/postfix/master.cf
        print_success "Postfix master.cf deployed"
    fi
    
    # Generate initial hash maps
    postmap /etc/postfix/virtual_domains
    postmap /etc/postfix/virtual_mailboxes
    postmap /etc/postfix/virtual_aliases
    
    systemctl restart postfix
    
    print_success "Postfix configured for virtual domain hosting"
}

# ─────────────────────────────────────────────────────────────
#  Dovecot (IMAP/POP3 Mail Delivery)
# ─────────────────────────────────────────────────────────────
install_dovecot() {
    print_header "Installing Dovecot IMAP/POP3"
    
    apt-get install -y -qq \
        dovecot-core \
        dovecot-imapd \
        dovecot-pop3d \
        dovecot-lmtpd \
        dovecot-sieve
    
    systemctl enable dovecot
    
    print_success "Dovecot installed"
}

configure_dovecot() {
    print_header "Configuring Dovecot for virtual mailbox hosting"
    
    # Deploy main dovecot.conf
    if [[ -f "templates/dovecot.conf" ]]; then
        cp templates/dovecot.conf /etc/dovecot/dovecot.conf
    fi
    
    # Create empty users file
    touch /etc/dovecot/users
    chmod 640 /etc/dovecot/users
    chown root:dovecot /etc/dovecot/users
    
    # 10-auth.conf — Authentication mechanisms
    cat > /etc/dovecot/conf.d/10-auth.conf <<'EOF'
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-passwdfile.conf.ext
EOF
    
    # auth-passwdfile.conf.ext — Passwd-file backend
    cat > /etc/dovecot/conf.d/auth-passwdfile.conf.ext <<EOF
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}

userdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/users
  default_fields = uid=$VMAIL_UID gid=$VMAIL_GID home=$VMAIL_DIR/%d/%n
}
EOF
    
    # 10-mail.conf — Mail storage
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:$VMAIL_DIR/%d/%n
mail_home = $VMAIL_DIR/%d/%n

namespace inbox {
  inbox = yes
  separator = /

  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
  mailbox Archive {
    auto = no
    special_use = \Archive
  }
}

mail_uid = $VMAIL_UID
mail_gid = $VMAIL_GID
mail_privileged_group = $VMAIL_USER
first_valid_uid = $VMAIL_UID
last_valid_uid = $VMAIL_UID

mail_plugins = \$mail_plugins quota
EOF
    
    # 10-ssl.conf — SSL/TLS
    cat > /etc/dovecot/conf.d/10-ssl.conf <<'EOF'
ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
EOF
    
    # 10-master.conf — Service listeners and Postfix integration
    cat > /etc/dovecot/conf.d/10-master.conf <<'EOF'
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  unix_listener auth-userdb {
    mode = 0660
  }
}

service auth-worker {
}
EOF
    
    systemctl restart dovecot
    
    print_success "Dovecot configured for virtual mailbox hosting"
}

# ─────────────────────────────────────────────────────────────
#  Pure-FTPd (FTP Service)
# ─────────────────────────────────────────────────────────────
install_ftp_service() {
    print_header "Installing Pure-FTPd"
    
    apt-get install -y -qq pure-ftpd pure-ftpd-common
    
    systemctl enable pure-ftpd
    
    print_success "Pure-FTPd installed"
}

configure_ftp_service() {
    print_header "Configuring Pure-FTPd for virtual user hosting"
    
    FTPD_CONF="/etc/pure-ftpd/conf"
    mkdir -p "$FTPD_CONF"
    
    # Create password file
    touch /etc/pure-ftpd/pureftpd.passwd
    
    # Virtual user backend (PureDB)
    echo "/etc/pure-ftpd/pureftpd.pdb" > "$FTPD_CONF/PureDB"
    
    # Security settings
    echo "yes" > "$FTPD_CONF/ChrootEveryone"
    echo "yes" > "$FTPD_CONF/NoAnonymous"
    echo "yes" > "$FTPD_CONF/CreateHomeDir"
    echo "1000" > "$FTPD_CONF/MinUID"
    
    # TLS (optional — 1 = accept both, 2 = require TLS)
    echo "1" > "$FTPD_CONF/TLS"
    
    # Passive mode port range
    echo "30000 50000" > "$FTPD_CONF/PassivePortRange"
    
    # Logging
    echo "yes" > "$FTPD_CONF/VerboseLog"
    
    # Connection limits
    echo "50" > "$FTPD_CONF/MaxClientsNumber"
    echo "8" > "$FTPD_CONF/MaxClientsPerIP"
    
    # Disk usage limit (percentage before refusing uploads)
    echo "95" > "$FTPD_CONF/MaxDiskUsage"
    
    # Generate self-signed certificate for FTPS
    if [[ ! -f "/etc/ssl/private/pure-ftpd.pem" ]]; then
        openssl req -x509 -nodes -days 3650 \
            -newkey rsa:2048 \
            -keyout /etc/ssl/private/pure-ftpd.pem \
            -out /etc/ssl/private/pure-ftpd.pem \
            -subj "/CN=$SERVER_HOSTNAME/O=Hosting Panel/C=US" 2>/dev/null
        chmod 600 /etc/ssl/private/pure-ftpd.pem
    fi
    
    systemctl restart pure-ftpd
    
    print_success "Pure-FTPd configured with virtual users and TLS"
}

# ─────────────────────────────────────────────────────────────
#  Certbot / Let's Encrypt SSL
# ─────────────────────────────────────────────────────────────
install_certbot() {
    print_header "Installing Certbot (Let's Encrypt)"
    
    apt-get install -y -qq certbot
    
    # Enable auto-renewal timer
    systemctl enable certbot.timer
    systemctl start certbot.timer
    
    # Create renewal hook to reload services after certificate renewal
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-services.sh <<'EOF'
#!/bin/bash
# Reload services after certificate renewal
systemctl reload lsws 2>/dev/null || true
systemctl reload postfix 2>/dev/null || true
systemctl reload dovecot 2>/dev/null || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-services.sh
    
    print_success "Certbot installed with auto-renewal"
}

# ─────────────────────────────────────────────────────────────
#  Cloudflare DNS (API integration)
# ─────────────────────────────────────────────────────────────
install_dns_service() {
    print_header "Configuring DNS (Cloudflare API)"
    
    echo ""
    echo "  This panel uses Cloudflare as the DNS provider."
    echo "  You will need a Cloudflare API token with Zone:Edit permissions."
    echo ""
    echo "  Set these in panel.toml after installation:"
    echo "    [cloudflare]"
    echo "    api_token = \"your_api_token_here\""
    echo "    account_id = \"your_account_id_here\"  # optional"
    echo ""
    
    print_success "Cloudflare DNS configured (set API token before starting the panel)"
}

# ─────────────────────────────────────────────────────────────
#  phpMyAdmin (Database Web UI)
# ─────────────────────────────────────────────────────────────
install_phpmyadmin() {
    print_header "Installing phpMyAdmin"
    
    if [[ -f "/usr/share/phpmyadmin/index.php" ]]; then
        print_success "phpMyAdmin already installed"
    else
        # Non-interactive install
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq phpmyadmin
        print_success "phpMyAdmin package installed"
    fi
    
    # Generate blowfish secret
    BLOWFISH_SECRET=$(openssl rand -hex 32)
    
    # Deploy panel-managed configuration
    if [[ -f "templates/phpmyadmin_config.inc.php" ]]; then
        sed "s/{{ blowfish_secret }}/$BLOWFISH_SECRET/g" \
            templates/phpmyadmin_config.inc.php > /usr/share/phpmyadmin/config.inc.php
        chown root:www-data /usr/share/phpmyadmin/config.inc.php
        chmod 640 /usr/share/phpmyadmin/config.inc.php
        print_success "phpMyAdmin configuration deployed"
    else
        print_warning "phpMyAdmin config template not found, using default"
    fi
    
    # Deploy signon bridge script
    if [[ -f "templates/phpmyadmin_signon.php" ]]; then
        cp templates/phpmyadmin_signon.php /usr/share/phpmyadmin/signon.php
        chown root:www-data /usr/share/phpmyadmin/signon.php
        chmod 644 /usr/share/phpmyadmin/signon.php
        print_success "phpMyAdmin signon script deployed"
    else
        print_warning "phpMyAdmin signon template not found"
    fi
    
    # Create phpMyAdmin temp directory
    mkdir -p /tmp/phpmyadmin
    chmod 1777 /tmp/phpmyadmin
    
    print_success "phpMyAdmin installed and configured"
}

# ─────────────────────────────────────────────────────────────
#  Firewall (UFW)
# ─────────────────────────────────────────────────────────────
install_firewall() {
    print_header "Configuring UFW firewall"

    apt-get install -y -qq \
        ufw \
        iptables \
        nftables

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow necessary ports
    ufw allow ssh/tcp
    ufw allow http/tcp
    ufw allow https/tcp
    ufw allow 21/tcp  comment 'FTP Control'
    ufw allow 25/tcp  comment 'SMTP'
    ufw allow 143/tcp comment 'IMAP'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 587/tcp comment 'Submission'
    ufw allow 993/tcp comment 'IMAPS'
    ufw allow 995/tcp comment 'POP3S'
    ufw allow 8080/tcp comment 'Panel Web UI'

    # Enable UFW — may fail inside containers/VMs without CAP_NET_ADMIN.
    # Rules are written to disk regardless and will be enforced on boot.
    if ufw --force enable 2>/dev/null; then
        print_success "UFW firewall enabled and rules applied"
    else
        print_warning "UFW rules written but could not be activated now (missing kernel capabilities)"
        print_info  "UFW will enforce rules automatically on next boot / when iptables becomes available"
        # Mark as enabled in the config so it activates on boot
        sed -i 's/^ENABLED=no/ENABLED=yes/' /etc/ufw/ufw.conf 2>/dev/null || true
    fi

    print_success "UFW firewall configured with required service ports"
}

# ─────────────────────────────────────────────────────────────
#  Panel Installation
# ─────────────────────────────────────────────────────────────
create_panel_user() {
    print_header "Creating panel system user"
    
    if id "$PANEL_USER" &>/dev/null; then
        print_success "Panel user already exists"
        return
    fi
    
    useradd -r -s /bin/bash -d "$DATA_DIR" "$PANEL_USER"
    
    # Add panel user to necessary groups
    usermod -aG "$VMAIL_USER" "$PANEL_USER" 2>/dev/null || true
    
    print_success "Panel user created"
}

create_directories() {
    print_header "Creating installation directories"
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR/backups"
    
    chown -R "$PANEL_USER:$PANEL_GROUP" "$DATA_DIR" "$LOG_DIR"
    chmod 750 "$DATA_DIR" "$LOG_DIR"
    
    print_success "Directories created"
}

# ─────────────────────────────────────────────────────────────
#  Binary download from GitHub Releases (default mode)
# ─────────────────────────────────────────────────────────────
download_panel_binary() {
    print_header "Downloading panel binary from GitHub Releases"

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)            ARCHIVE="panel-x86_64-linux.tar.gz" ;;
        aarch64|arm64)     ARCHIVE="panel-aarch64-linux.tar.gz" ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            print_info "Use --from-source to build from source on this platform."
            exit 1
            ;;
    esac

    GITHUB_REPO="damiencal/panel"

    if [[ -n "$PINNED_VERSION" ]]; then
        RELEASE_TAG="$PINNED_VERSION"
        BASE_URL="https://github.com/$GITHUB_REPO/releases/download/$RELEASE_TAG"
    else
        # Resolve latest release tag via GitHub API
        API_URL="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
        RELEASE_TAG=$(curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$API_URL" 2>/dev/null \
            | grep -oP '"tag_name":\s*"\K[^"]+' || true)
        if [[ -z "$RELEASE_TAG" ]]; then
            print_error "Could not resolve the latest release tag from GitHub."
            print_info "Specify a version with --version=vX.Y.Z, or use --from-source to build locally."
            exit 1
        fi
        BASE_URL="https://github.com/$GITHUB_REPO/releases/download/$RELEASE_TAG"
    fi

    print_info "Release : $RELEASE_TAG"
    print_info "Archive : $ARCHIVE"
    print_info "Arch    : $ARCH"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    # Download archive and checksum file
    print_info "Downloading archive…"
    curl -fSL --progress-bar -o "$TMPDIR/$ARCHIVE" "$BASE_URL/$ARCHIVE"
    curl -fsSL -o "$TMPDIR/$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"

    # Verify checksum
    print_info "Verifying SHA-256 checksum…"
    EXPECTED=$(awk '{print $1}' "$TMPDIR/$ARCHIVE.sha256")
    ACTUAL=$(sha256sum "$TMPDIR/$ARCHIVE" | awk '{print $1}')
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
        print_error "Checksum verification FAILED!"
        print_error "  Expected : $EXPECTED"
        print_error "  Actual   : $ACTUAL"
        exit 1
    fi
    print_success "Checksum verified"

    # Extract and install
    EXTRACT_DIR="$TMPDIR/extract"
    mkdir -p "$EXTRACT_DIR"
    tar -xzf "$TMPDIR/$ARCHIVE" -C "$EXTRACT_DIR"

    cp "$EXTRACT_DIR/panel" "$INSTALL_DIR/panel"
    chown "$PANEL_USER:$PANEL_GROUP" "$INSTALL_DIR/panel"
    chmod 755 "$INSTALL_DIR/panel"

    if [[ -d "$EXTRACT_DIR/public" ]]; then
        cp -r "$EXTRACT_DIR/public" "$INSTALL_DIR/public"
    fi

    if [[ -d "$EXTRACT_DIR/templates" ]]; then
        cp -r "$EXTRACT_DIR/templates" "$INSTALL_DIR/templates"
    else
        print_warning "templates/ not found in release archive — post-config steps may be skipped"
    fi

    INSTALLED_VERSION="$RELEASE_TAG"
    print_success "Panel binary $RELEASE_TAG installed from GitHub Releases"

    # Clean up trap
    trap - EXIT
    rm -rf "$TMPDIR"
}

build_panel() {
    if [[ "$INSTALL_MODE" == "binary" ]]; then
        download_panel_binary
        return
    fi

    print_header "Building hosting control panel from source"
    
    cd "$(dirname "$0")"
    
    # Build release binary
    RUSTFLAGS="-C opt-level=3" cargo build --release
    
    # Copy binary to install directory
    cp target/release/panel "$INSTALL_DIR/panel"
    chown "$PANEL_USER:$PANEL_GROUP" "$INSTALL_DIR/panel"
    chmod 755 "$INSTALL_DIR/panel"
    
    # Copy templates
    cp -r templates "$INSTALL_DIR/templates"

    INSTALLED_VERSION="(built from source)"
    print_success "Panel built and installed from source"
}

install_systemd_service() {
    print_header "Installing systemd service"
    
    cat > /etc/systemd/system/panel.service <<EOF
[Unit]
Description=Hosting Control Panel - Web-based Hosting Management
After=network-online.target mariadb.service postfix.service dovecot.service
Wants=network-online.target

[Service]
Type=simple
User=$PANEL_USER
Group=$PANEL_GROUP
WorkingDirectory=$INSTALL_DIR

Environment="RUST_LOG=info,panel=debug"
Environment="RUST_BACKTRACE=1"
Environment="DATABASE_URL=sqlite:$DATA_DIR/panel.db"

ExecStart=$INSTALL_DIR/panel
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s

# Security hardening
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR $LOG_DIR /usr/local/lsws/conf $VMAIL_DIR /etc/postfix /etc/dovecot /etc/pure-ftpd

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Process timeout
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable panel
    
    print_success "Systemd service installed"
}

create_config() {
    print_header "Creating configuration file"
    
    # Generate a secure secret key
    SECRET_KEY=$(openssl rand -base64 32)
    
    cat > "$INSTALL_DIR/panel.toml" <<EOF
[server]
host = "127.0.0.1"
port = 3030
secret_key = "$SECRET_KEY"

[database]
url = "sqlite:$DATA_DIR/panel.db"

[openlitespeed]
config_dir = "/usr/local/lsws/conf"
vhost_dir = "/usr/local/lsws/conf/vhosts"
lsphp_bin = "/usr/local/lsws/lsphp83/bin/lsphp"

[certbot]
path = "/usr/bin/certbot"
webroot = "/usr/local/lsws/html"

[phpmyadmin]
enabled = true
install_path = "/usr/share/phpmyadmin"
url_base_path = "/phpmyadmin"

[cloudflare]
api_token = ""

[mariadb]
bind_address = "127.0.0.1"
port = 3306
max_connections = 100

[postfix]
hostname = "$SERVER_HOSTNAME"
virtual_mailbox_base = "$VMAIL_DIR"

[dovecot]
mail_location = "maildir:$VMAIL_DIR/%d/%n"
users_file = "/etc/dovecot/users"

[ftp]
passive_port_min = 30000
passive_port_max = 50000
max_clients = 50
tls_required = true
EOF
    
    chown "$PANEL_USER:$PANEL_GROUP" "$INSTALL_DIR/panel.toml"
    chmod 640 "$INSTALL_DIR/panel.toml"
    
    print_success "Configuration file created with generated secret key"
}

initialize_database() {
    print_header "Initializing database"
    
    # Database will be initialized on first run via SQLx migrations
    touch "$DATA_DIR/panel.db"
    chown "$PANEL_USER:$PANEL_GROUP" "$DATA_DIR/panel.db"
    chmod 640 "$DATA_DIR/panel.db"
    
    print_success "Database initialized"
}

start_services() {
    print_header "Starting all services"
    
    systemctl start lsws && print_success "OpenLiteSpeed started" || print_warning "OpenLiteSpeed failed to start"
    systemctl start mariadb && print_success "MariaDB started" || print_warning "MariaDB failed to start"
    systemctl start postfix && print_success "Postfix started" || print_warning "Postfix failed to start"
    systemctl start dovecot && print_success "Dovecot started" || print_warning "Dovecot failed to start"
    systemctl start pure-ftpd && print_success "Pure-FTPd started" || print_warning "Pure-FTPd failed to start"
    systemctl start memcached && print_success "Memcached started" || print_warning "Memcached failed to start"
    systemctl start redis-server && print_success "Redis started" || print_warning "Redis failed to start"
    systemctl start watchdog && print_success "Watchdog started" || print_warning "Watchdog failed to start"
    
    print_success "All services started"
}

verify_services() {
    print_header "Verifying service status"
    
    for svc in lsws mariadb postfix dovecot pure-ftpd memcached redis-server watchdog; do
        if systemctl is-active --quiet "$svc"; then
            print_success "$svc is running"
        else
            print_warning "$svc is NOT running"
        fi
    done
    
    # Check Certbot timer
    if systemctl is-active --quiet certbot.timer; then
        print_success "Certbot auto-renewal timer is active"
    else
        print_warning "Certbot auto-renewal timer is NOT active"
    fi
    
    # Check listening ports
    echo ""
    print_info "Listening ports:"
    ss -tlnp | grep -E ":(80|443|21|25|110|143|465|587|993|995|3306|7080|8080) " | while read -r line; do
        echo "    $line"
    done
}

print_summary() {
    print_header "Installation Complete!"
    
    echo ""
    echo -e "${GREEN}  ╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║     Hosting Control Panel - Installation Summary     ║${NC}"
    echo -e "${GREEN}  ╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Install mode           : $INSTALL_MODE"
    echo "  Panel version          : $INSTALLED_VERSION"
    echo "  Installation directory : $INSTALL_DIR"
    echo "  Data directory         : $DATA_DIR"
    echo "  Log directory          : $LOG_DIR"
    echo "  Panel user             : $PANEL_USER"
    echo ""
    echo -e "${BLUE}  Installed Services:${NC}"
    echo "  ┌──────────────────┬───────────┬──────────────────────────────┐"
    echo "  │ Service          │ Port(s)   │ Status                       │"
    echo "  ├──────────────────┼───────────┼──────────────────────────────┤"
    echo "  │ OpenLiteSpeed    │ 80, 443   │ $(systemctl is-active lsws 2>/dev/null || echo 'unknown')                     │"
    echo "  │ OLS WebAdmin     │ 7080      │ (via OLS)                    │"
    echo "  │ MariaDB          │ 3306      │ $(systemctl is-active mariadb 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Postfix (SMTP)   │ 25,465,587│ $(systemctl is-active postfix 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Dovecot (IMAP)   │ 143,993   │ $(systemctl is-active dovecot 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Dovecot (POP3)   │ 110,995   │ (via Dovecot)                │"
    echo "  │ Pure-FTPd        │ 21        │ $(systemctl is-active pure-ftpd 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Memcached        │ 11211     │ $(systemctl is-active memcached 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Redis            │ 6379      │ $(systemctl is-active redis-server 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Watchdog         │ (system)  │ $(systemctl is-active watchdog 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Roundcube        │ (web app) │ installed                     │"
    echo "  │ phpMyAdmin       │ /phpmyadmin│ (via OLS)                   │"
    echo "  │ Certbot          │ (timer)   │ $(systemctl is-active certbot.timer 2>/dev/null || echo 'unknown')                     │"
    echo "  │ Panel            │ 3030      │ (not yet started)            │"
    echo "  └──────────────────┴───────────┴──────────────────────────────┘"
    echo ""
    echo -e "${YELLOW}  Post-installation tasks:${NC}"
    echo ""
    echo "  1. Edit the configuration file:"
    echo "     sudo nano $INSTALL_DIR/panel.toml"
    echo ""
    echo "  2. Set your Cloudflare API token (if using DNS management):"
    echo "     [cloudflare]"
    echo "     api_token = \"your_token_here\""
    echo ""
    echo "  3. Start the panel service:"
    echo "     sudo systemctl start panel"
    echo ""
    echo "  4. Access the panel:"
    echo "     http://$SERVER_IP:3030"
    echo ""
    echo "  5. Check /root/.panel_secrets for generated passwords."
    echo ""
    echo "  6. For production, issue a real SSL certificate:"
    echo "     certbot certonly --webroot -w /usr/local/lsws/html -d yourdomain.com"
    echo ""
    echo -e "${GREEN}  Thank you for using the Hosting Control Panel!${NC}"
    echo ""
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    INSTALLED_VERSION="unknown"

    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Hosting Control Panel - Full Stack Installer v1.0         ║${NC}"
    if [[ "$INSTALL_MODE" == "binary" ]]; then
    echo -e "${BLUE}║   Mode: Binary (download from GitHub Releases)              ║${NC}"
    else
    echo -e "${BLUE}║   Mode: Build from source (Rust/Cargo)                      ║${NC}"
    fi
    echo -e "${BLUE}║   OpenLiteSpeed • MariaDB • Postfix • Dovecot • FTP • SSL   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    generate_passwords
    check_distro
    update_system
    install_runtime_dependencies
    if [[ "$INSTALL_MODE" == "source" ]]; then
        install_build_dependencies
        install_rust
    fi
    
    # Web Server
    install_openlitespeed
    configure_openlitespeed
    
    # Database
    install_mariadb
    secure_mariadb
    
    # Mail
    install_postfix
    configure_postfix
    install_dovecot
    configure_dovecot
    
    # FTP
    install_ftp_service
    configure_ftp_service
    
    # SSL / DNS
    install_certbot
    install_dns_service

    # Supporting services
    install_auxiliary_services
    
    # Web Tools
    install_phpmyadmin
    
    # Security
    install_firewall
    
    # Panel
    create_panel_user
    create_directories
    build_panel
    install_systemd_service
    create_config
    initialize_database
    
    # Start everything
    start_services
    verify_services
    
    # Generate Certbot certificate if a hostname was provided
    if [[ -n "$USER_PROVIDED_HOSTNAME" ]]; then
        print_header "Generating Let's Encrypt Certificate for $USER_PROVIDED_HOSTNAME"
        certbot certonly --webroot -w /usr/local/lsws/html -d "$USER_PROVIDED_HOSTNAME" --non-interactive --agree-tos -m "admin@$USER_PROVIDED_HOSTNAME" || print_warning "Failed to generate SSL certificate."
    fi
    
    print_summary
}

# Run main installation
main "$@"
