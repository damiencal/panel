# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Build the panel binary
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

WORKDIR /src
COPY . .

# Install wasm32 target + Dioxus CLI for the WASM frontend build
RUN rustup target add wasm32-unknown-unknown && \
    cargo install dioxus-cli --locked --version "0.7.3"

# Install Node/npm for Tailwind CSS compilation
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    npm install

# Build everything: Tailwind CSS + Dioxus fullstack (WASM + server binary)
# dx places the server binary inside target/dx/panel/release/web/ with a hash
# suffix (e.g. panel-30d2382e).  Copy it to a predictable path so stage-2 can
# reference it without knowing the hash.
RUN npx @tailwindcss/cli -i input.css -o assets/tailwind.css --minify && \
    dx build --release --platform web --fullstack true && \
    bin=$(find target/dx/panel/release/web -maxdepth 1 -type f -executable | head -1) && \
    cp "$bin" target/dx/panel/release/panel-server

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Ubuntu 24.04 sandbox with systemd
# Installs hosting services at image-build time (apt layers cached by Docker).
# The entrypoint.sh handles configuration and seeding at container start.
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PANEL_SANDBOX=1 \
    PANEL_DB=/opt/panel/panel.db \
    PANEL_DIR=/opt/panel

# ── Base system packages ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release systemd systemd-sysv \
        dbus dbus-user-session sudo locales tzdata \
        sqlite3 python3 python3-pip argon2 \
        openssl git wget unzip jq \
        # MariaDB
        mariadb-server mariadb-client \
        # Postfix + Dovecot
        postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d \
        # Pure-FTPd
        pure-ftpd pure-ftpd-common \
        # UFW
        ufw \
        # ClamAV (daemon)
        clamav clamav-daemon \
        # Redis
        redis-server \
        # Certbot + nginx (used by certbot webroot)
        certbot python3-certbot \
        # WP-CLI deps
        php8.3-cli php8.3-mysql php8.3-xml php8.3-curl php8.3-mbstring php8.3-zip \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# ── OpenLiteSpeed ─────────────────────────────────────────────────────────────
RUN wget -qO - https://rpms.litespeedtech.com/debian/enable_lst_debian_repo.sh | bash && \
    apt-get update && apt-get install -y --no-install-recommends \
        openlitespeed lsphp83 lsphp83-common lsphp83-mysql lsphp83-curl \
    && rm -rf /var/lib/apt/lists/* \
    && (systemctl disable openlitespeed 2>/dev/null || true)

# ── phpMyAdmin ────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends phpmyadmin \
    && rm -rf /var/lib/apt/lists/*

# ── Copy compiled panel binary and web assets ─────────────────────────────────
RUN mkdir -p ${PANEL_DIR}
COPY --from=builder /src/target/dx/panel/release/web          ${PANEL_DIR}/web
COPY --from=builder /src/target/dx/panel/release/panel-server ${PANEL_DIR}/panel

# ── Copy sandbox configuration and scripts ────────────────────────────────────
COPY sandbox/panel.toml                  ${PANEL_DIR}/panel.toml
# Backup copy — entrypoint.sh restores this after install.sh may overwrite the live config
COPY sandbox/panel.toml                  ${PANEL_DIR}/panel.toml.sandbox
COPY sandbox/entrypoint.sh               /entrypoint.sh
COPY sandbox/scripts/                    /opt/panel/scripts/
COPY sandbox/seed/                       /opt/panel/seed/
COPY migrations/                         /opt/panel/migrations/
COPY install.sh                          /opt/panel/install.sh

RUN chmod +x /entrypoint.sh \
             /opt/panel/scripts/*.sh \
             /opt/panel/install.sh \
             /opt/panel/panel

# ── Clean up systemd units that break in container ────────────────────────────
RUN find /etc/systemd/system /lib/systemd/system \
         -name "getty*" -o -name "display-manager*" -o \
         -name "dbus.service" 2>/dev/null \
    | xargs -r rm -f ; \
    systemctl mask --now \
        systemd-logind.service \
        dm-event.socket \
        multipathd.socket 2>/dev/null || true

# ── Expose ports ──────────────────────────────────────────────────────────────
# 8080 = panel, 80/443 = OLS web, 25/587/993 = mail, 21 = FTP
EXPOSE 8080 80 443 25 587 993 21

# Tini-style: systemd as PID 1, entrypoint.sh as ExecStartPost
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/entrypoint.sh"]
