-- =============================================================================
-- Initial schema – all tables created in their final form.
-- Consolidated from all previous incremental migrations.
-- =============================================================================

-- ─── Users ───────────────────────────────────────────────────────────────────
-- Created first; packages and reseller_branding reference it via FK,
-- and it references them back – SQLite defers FK validation to DML time,
-- so the circular dependency is fine.
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
    username            TEXT     NOT NULL UNIQUE,
    email               TEXT     NOT NULL UNIQUE,
    password_hash       TEXT     NOT NULL,
    role                TEXT     NOT NULL CHECK(role IN ('Admin', 'Reseller', 'Client', 'Developer')),
    status              TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended', 'Pending')) DEFAULT 'Active',
    parent_id           INTEGER,
    package_id          INTEGER,
    branding_id         INTEGER,
    totp_secret         TEXT,
    totp_enabled        BOOLEAN  DEFAULT FALSE,
    system_uid          INTEGER,
    system_gid          INTEGER,
    company             TEXT,
    address             TEXT,
    phone               TEXT,
    city                TEXT,
    state               TEXT,
    postal_code         TEXT,
    country             TEXT,
    -- NULL means "never changed"; JWTs issued before this timestamp are invalid.
    password_changed_at TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(parent_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(package_id)  REFERENCES packages(id),
    FOREIGN KEY(branding_id) REFERENCES reseller_branding(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_system_uid  ON users(system_uid);
CREATE INDEX        IF NOT EXISTS idx_users_username    ON users(username);
CREATE INDEX        IF NOT EXISTS idx_users_email       ON users(email);
CREATE INDEX        IF NOT EXISTS idx_users_role        ON users(role);
CREATE INDEX        IF NOT EXISTS idx_users_parent_id   ON users(parent_id);

-- ─── Packages ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS packages (
    id                   INTEGER  PRIMARY KEY AUTOINCREMENT,
    name                 TEXT     NOT NULL,
    description          TEXT,
    created_by           INTEGER  NOT NULL,
    max_sites            INTEGER  NOT NULL DEFAULT 1,
    max_databases        INTEGER  NOT NULL DEFAULT 1,
    max_email_accounts   INTEGER  NOT NULL DEFAULT 10,
    max_ftp_accounts     INTEGER  NOT NULL DEFAULT 1,
    disk_limit_mb        INTEGER  NOT NULL DEFAULT 10240,
    bandwidth_limit_mb   INTEGER  NOT NULL DEFAULT 102400,
    max_subdomains       INTEGER  NOT NULL DEFAULT 0,
    max_addon_domains    INTEGER  NOT NULL DEFAULT 0,
    php_enabled          BOOLEAN  DEFAULT TRUE,
    ssl_enabled          BOOLEAN  DEFAULT TRUE,
    shell_access         BOOLEAN  DEFAULT FALSE,
    backup_enabled       BOOLEAN  DEFAULT TRUE,
    is_active            BOOLEAN  DEFAULT TRUE,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packages_created_by ON packages(created_by);
CREATE INDEX IF NOT EXISTS idx_packages_active     ON packages(is_active);

-- ─── Reseller Branding ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reseller_branding (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    reseller_id    INTEGER  NOT NULL UNIQUE,
    panel_name     TEXT     NOT NULL,
    logo_path      TEXT,
    accent_color   TEXT     NOT NULL DEFAULT '#F43F5E',
    custom_domain  TEXT,
    custom_ns1     TEXT,
    custom_ns2     TEXT,
    footer_text    TEXT,
    theme_preset   TEXT     NOT NULL DEFAULT 'Default',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reseller_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reseller_branding_reseller_id ON reseller_branding(reseller_id);

-- ─── Resource Quotas & Usage ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resource_quotas (
    id                   INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER  NOT NULL UNIQUE,
    max_clients          INTEGER,
    max_sites            INTEGER  NOT NULL DEFAULT 10,
    max_databases        INTEGER  NOT NULL DEFAULT 5,
    max_email_accounts   INTEGER  NOT NULL DEFAULT 100,
    disk_limit_mb        INTEGER  NOT NULL DEFAULT 102400,
    bandwidth_limit_mb   INTEGER  NOT NULL DEFAULT 1048576,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS resource_usage (
    id                    INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id               INTEGER  NOT NULL,
    sites_used            INTEGER  DEFAULT 0,
    databases_used        INTEGER  DEFAULT 0,
    email_accounts_used   INTEGER  DEFAULT 0,
    disk_used_mb          INTEGER  DEFAULT 0,
    bandwidth_used_mb     INTEGER  DEFAULT 0,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_resource_usage_user_id  ON resource_usage(user_id);
CREATE INDEX        IF NOT EXISTS idx_resource_quotas_user_id ON resource_quotas(user_id);

-- ─── Sites ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
    id                      INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id                INTEGER  NOT NULL,
    domain                  TEXT     NOT NULL UNIQUE,
    doc_root                TEXT     NOT NULL,
    site_type               TEXT     NOT NULL CHECK(site_type IN ('Static', 'PHP', 'ReverseProxy', 'NodeJS')) DEFAULT 'Static',
    status                  TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',

    -- SSL/TLS
    ssl_enabled             BOOLEAN  DEFAULT FALSE,
    ssl_certificate         TEXT,
    ssl_private_key         TEXT,
    ssl_issuer              TEXT,
    ssl_expiry_date         DATETIME,
    force_https             BOOLEAN  DEFAULT FALSE,

    -- HSTS (only meaningful when ssl_enabled AND force_https are TRUE)
    hsts_enabled            BOOLEAN  NOT NULL DEFAULT FALSE,
    hsts_max_age            INTEGER  NOT NULL DEFAULT 31536000,
    hsts_include_subdomains BOOLEAN  NOT NULL DEFAULT FALSE,
    hsts_preload            BOOLEAN  NOT NULL DEFAULT FALSE,

    -- HTTP Basic Authentication
    basic_auth_enabled      BOOLEAN  NOT NULL DEFAULT FALSE,
    basic_auth_realm        TEXT     NOT NULL DEFAULT 'Restricted',

    -- PHP settings
    php_version             TEXT,
    php_handler             TEXT,

    -- Reverse proxy settings
    proxy_target            TEXT,

    -- OpenLiteSpeed configuration
    ols_vhost_name          TEXT     UNIQUE,
    ols_listener_ports      TEXT     DEFAULT '80,443',

    -- Resource limits
    max_connections         INTEGER  DEFAULT 100,

    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sites_owner_id      ON sites(owner_id);
CREATE INDEX IF NOT EXISTS idx_sites_domain        ON sites(domain);
CREATE INDEX IF NOT EXISTS idx_sites_status        ON sites(status);
CREATE INDEX IF NOT EXISTS idx_sites_ols_vhost_name ON sites(ols_vhost_name);

-- ─── Databases ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS databases (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER  NOT NULL,
    name          TEXT     NOT NULL,
    database_type TEXT     NOT NULL CHECK(database_type IN ('MySQL', 'PostgreSQL', 'MariaDB')) DEFAULT 'MariaDB',
    status        TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(owner_id, name, database_type)
);

CREATE TABLE IF NOT EXISTS database_users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    database_id   INTEGER  NOT NULL,
    username      TEXT     NOT NULL,
    password_hash TEXT     NOT NULL,
    privileges    TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(database_id) REFERENCES databases(id) ON DELETE CASCADE,
    UNIQUE(database_id, username)
);

CREATE INDEX IF NOT EXISTS idx_databases_owner_id         ON databases(owner_id);
CREATE INDEX IF NOT EXISTS idx_databases_name             ON databases(name);
CREATE INDEX IF NOT EXISTS idx_database_users_database_id ON database_users(database_id);

-- ─── DNS Zones & Records ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dns_zones (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER  NOT NULL,
    domain      TEXT     NOT NULL UNIQUE,
    zone_type   TEXT     NOT NULL CHECK(zone_type IN ('Primary', 'Secondary')) DEFAULT 'Primary',
    status      TEXT     NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    nameserver1 TEXT,
    nameserver2 TEXT,
    cf_zone_id  TEXT,
    sync_status TEXT     NOT NULL CHECK(sync_status IN ('Synced', 'Pending', 'Error')) DEFAULT 'Pending',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_records (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    zone_id      INTEGER  NOT NULL,
    name         TEXT     NOT NULL,
    type         TEXT     NOT NULL CHECK(type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'NS')),
    value        TEXT     NOT NULL,
    priority     INTEGER  DEFAULT 10,
    ttl          INTEGER  DEFAULT 3600,
    cf_record_id TEXT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(zone_id) REFERENCES dns_zones(id) ON DELETE CASCADE,
    UNIQUE(zone_id, name, type)
);

CREATE INDEX IF NOT EXISTS idx_dns_zones_owner_id      ON dns_zones(owner_id);
CREATE INDEX IF NOT EXISTS idx_dns_zones_domain        ON dns_zones(domain);
CREATE INDEX IF NOT EXISTS idx_dns_zones_cf_zone_id    ON dns_zones(cf_zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_zone_id     ON dns_records(zone_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_cf_record_id ON dns_records(cf_record_id);

-- ─── Email ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_domains (
    id                      INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id                INTEGER  NOT NULL,
    domain                  TEXT     NOT NULL UNIQUE,
    status                  TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended', 'Inactive')) DEFAULT 'Active',
    send_limit_per_hour     INTEGER  NOT NULL DEFAULT 0,
    send_limit_per_day      INTEGER  NOT NULL DEFAULT 0,
    catch_all_address       TEXT,
    plus_addressing_enabled INTEGER  NOT NULL DEFAULT 0,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mailboxes (
    id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_id           INTEGER  NOT NULL,
    local_part          TEXT     NOT NULL,
    password_hash       TEXT     NOT NULL,
    quota_mb            INTEGER  DEFAULT 256,
    status              TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended')) DEFAULT 'Active',
    send_limit_per_hour INTEGER  NOT NULL DEFAULT 0,
    send_limit_per_day  INTEGER  NOT NULL DEFAULT 0,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE,
    UNIQUE(domain_id, local_part)
);

CREATE TABLE IF NOT EXISTS email_forwarders (
    id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_id  INTEGER  NOT NULL,
    local_part TEXT     NOT NULL,
    forward_to TEXT     NOT NULL,
    status     TEXT     NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE,
    UNIQUE(domain_id, local_part)
);

-- Regex-based forwarders (Postfix regexp map)
CREATE TABLE IF NOT EXISTS email_regex_forwarders (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_id   INTEGER  NOT NULL,
    pattern     TEXT     NOT NULL,
    forward_to  TEXT     NOT NULL,
    description TEXT,
    status      TEXT     NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);

-- Rolling send-rate counters per domain (single row, updated in-place)
CREATE TABLE IF NOT EXISTS domain_send_counts (
    domain_id    INTEGER PRIMARY KEY,
    hourly_count INTEGER NOT NULL DEFAULT 0,
    daily_count  INTEGER NOT NULL DEFAULT 0,
    hour_window  TEXT    NOT NULL DEFAULT '',   -- "YYYY-MM-DD-HH"
    day_window   TEXT    NOT NULL DEFAULT '',   -- "YYYY-MM-DD"
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);

-- DKIM signing keys (one per email domain)
CREATE TABLE IF NOT EXISTS dkim_keys (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_id      INTEGER  NOT NULL UNIQUE,
    domain         TEXT     NOT NULL UNIQUE,
    selector       TEXT     NOT NULL DEFAULT 'default',
    public_key_dns TEXT     NOT NULL,
    status         TEXT     NOT NULL CHECK(status IN ('Active', 'Inactive')) DEFAULT 'Active',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(domain_id) REFERENCES email_domains(id) ON DELETE CASCADE
);

-- Daily email statistics per domain (populated by log parsing)
CREATE TABLE IF NOT EXISTS email_stats (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    stat_date      DATE     NOT NULL,
    domain         TEXT,
    sent_count     INTEGER  NOT NULL DEFAULT 0,
    received_count INTEGER  NOT NULL DEFAULT 0,
    rejected_count INTEGER  NOT NULL DEFAULT 0,
    spam_count     INTEGER  NOT NULL DEFAULT 0,
    bounced_count  INTEGER  NOT NULL DEFAULT 0,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stat_date, domain)
);

CREATE INDEX IF NOT EXISTS idx_email_domains_owner_id     ON email_domains(owner_id);
CREATE INDEX IF NOT EXISTS idx_mailboxes_domain_id        ON mailboxes(domain_id);
CREATE INDEX IF NOT EXISTS idx_email_forwarders_domain_id ON email_forwarders(domain_id);
CREATE INDEX IF NOT EXISTS idx_regex_fwd_domain           ON email_regex_forwarders(domain_id);

-- ─── Support Tickets ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS support_tickets (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    subject     TEXT     NOT NULL,
    status      TEXT     NOT NULL CHECK(status IN ('Open', 'Answered', 'ClientReply', 'Closed')) DEFAULT 'Open',
    priority    TEXT     NOT NULL CHECK(priority IN ('Low', 'Medium', 'High', 'Critical')) DEFAULT 'Medium',
    department  TEXT     NOT NULL DEFAULT 'General',
    created_by  INTEGER  NOT NULL,
    assigned_to INTEGER,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by)  REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    ticket_id   INTEGER  NOT NULL,
    sender_id   INTEGER  NOT NULL,
    body        TEXT     NOT NULL,
    is_internal BOOLEAN  DEFAULT FALSE,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_created_by  ON support_tickets(created_by);
CREATE INDEX IF NOT EXISTS idx_support_tickets_assigned_to ON support_tickets(assigned_to);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status      ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket_id   ON ticket_messages(ticket_id);

-- ─── Audit Log ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER  NOT NULL,
    action           TEXT     NOT NULL,
    target_type      TEXT,
    target_id        INTEGER,
    target_name      TEXT,
    description      TEXT,
    status           TEXT     NOT NULL CHECK(status IN ('Success', 'Failure')) DEFAULT 'Success',
    error_message    TEXT,
    ip_address       TEXT,
    impersonation_by INTEGER,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id)          REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(impersonation_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target     ON audit_logs(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- ─── Usage Tracking ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usage_logs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER  NOT NULL,
    site_id     INTEGER,
    metric_type TEXT     NOT NULL CHECK(metric_type IN ('Bandwidth', 'Storage', 'CPU', 'Memory')),
    value_mb    INTEGER  NOT NULL DEFAULT 0,
    recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS daily_usage_aggregates (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER  NOT NULL,
    date              DATE     NOT NULL,
    bandwidth_used_mb INTEGER  DEFAULT 0,
    storage_used_mb   INTEGER  DEFAULT 0,
    UNIQUE(user_id, date),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monthly_usage_snapshots (
    id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER  NOT NULL,
    year                INTEGER  NOT NULL,
    month               INTEGER  NOT NULL,
    bandwidth_used_mb   INTEGER  DEFAULT 0,
    storage_peak_mb     INTEGER  DEFAULT 0,
    UNIQUE(user_id, year, month),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_id       ON usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_logs_recorded_at   ON usage_logs(recorded_at);
CREATE INDEX IF NOT EXISTS idx_daily_aggregates_date    ON daily_usage_aggregates(date);
CREATE INDEX IF NOT EXISTS idx_monthly_snapshots_month  ON monthly_usage_snapshots(year, month);

-- ─── FTP Accounts ────────────────────────────────────────────────────────────
-- Virtual accounts backed by Pure-FTPd puredb.
CREATE TABLE IF NOT EXISTS ftp_accounts (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id       INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id        INTEGER  REFERENCES sites(id) ON DELETE CASCADE,
    username       TEXT     NOT NULL UNIQUE,
    password_hash  TEXT     NOT NULL,  -- Argon2id, also written to puredb
    home_dir       TEXT     NOT NULL,
    quota_size_mb  INTEGER  DEFAULT 1024,
    quota_files    INTEGER  DEFAULT 0,
    allowed_ip     TEXT,               -- CIDR/range; NULL = unrestricted
    status         TEXT     NOT NULL CHECK(status IN ('Active', 'Suspended')) DEFAULT 'Active',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ftp_accounts_owner ON ftp_accounts(owner_id);
CREATE INDEX IF NOT EXISTS idx_ftp_accounts_site  ON ftp_accounts(site_id);

-- FTP transfer log (one row per completed upload or download)
CREATE TABLE IF NOT EXISTS ftp_session_stats (
    id                   INTEGER  PRIMARY KEY AUTOINCREMENT,
    account_id           INTEGER  REFERENCES ftp_accounts(id) ON DELETE SET NULL,
    username             TEXT     NOT NULL,
    remote_host          TEXT,
    direction            TEXT     NOT NULL CHECK(direction IN ('Upload', 'Download')),
    filename             TEXT     NOT NULL,
    bytes_transferred    INTEGER  NOT NULL DEFAULT 0,
    transfer_time_secs   REAL     NOT NULL DEFAULT 0,
    completed_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ftp_stats_username   ON ftp_session_stats(username);
CREATE INDEX IF NOT EXISTS idx_ftp_stats_account_id ON ftp_session_stats(account_id);
CREATE INDEX IF NOT EXISTS idx_ftp_stats_completed  ON ftp_session_stats(completed_at);

-- ─── Git Repositories ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS site_git_repos (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    site_id          INTEGER  NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    repo_url         TEXT     NOT NULL,
    branch           TEXT     NOT NULL DEFAULT 'main',
    -- Ed25519 deploy key for private SSH repos (public key shown to user)
    deploy_key_priv  TEXT,
    deploy_key_pub   TEXT,
    -- Atomic symlink-swap deployment strategy
    atomic_deploy    INTEGER  NOT NULL DEFAULT 0,
    retain_releases  INTEGER  NOT NULL DEFAULT 5,
    deploy_script    TEXT,
    -- Last-known sync state
    last_synced_at   DATETIME,
    last_commit_hash TEXT,
    last_commit_msg  TEXT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_site_git_repos_site ON site_git_repos(site_id);

-- ─── Cron Jobs ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cron_jobs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id     INTEGER  NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    schedule    TEXT     NOT NULL,   -- 5-field cron expression or @alias
    command     TEXT     NOT NULL,   -- runs as the site's system user
    description TEXT     NOT NULL DEFAULT '',
    enabled     INTEGER  NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_run    DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cron_jobs_owner ON cron_jobs(owner_id);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_site  ON cron_jobs(site_id);

-- ─── Anti-Spam ───────────────────────────────────────────────────────────────
-- Global spam-filter configuration (always a single row with id = 1)
CREATE TABLE IF NOT EXISTS spam_filter_settings (
    id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
    engine              TEXT     NOT NULL DEFAULT 'none' CHECK(engine IN ('none', 'spamassassin', 'rspamd')),
    spam_threshold      REAL     NOT NULL DEFAULT 5.0,
    add_header_enabled  INTEGER  NOT NULL DEFAULT 1,
    quarantine_enabled  INTEGER  NOT NULL DEFAULT 0,
    quarantine_mailbox  TEXT,
    reject_score        REAL     NOT NULL DEFAULT 15.0,
    clamav_enabled      INTEGER  NOT NULL DEFAULT 0,
    mailscanner_enabled INTEGER  NOT NULL DEFAULT 0,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO spam_filter_settings (id, engine) VALUES (1, 'none');

-- ─── Firewall Rules ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS firewall_rules (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    rule_number INTEGER,
    action      TEXT     NOT NULL CHECK(action IN ('allow', 'deny', 'reject', 'limit')),
    direction   TEXT     NOT NULL DEFAULT 'in' CHECK(direction IN ('in', 'out', 'both')),
    protocol    TEXT     CHECK(protocol IN ('tcp', 'udp', 'any')),
    from_ip     TEXT,
    to_port     TEXT,
    comment     TEXT,
    is_active   INTEGER  NOT NULL DEFAULT 1,
    created_at  TEXT     NOT NULL DEFAULT (datetime('now')),
    created_by  INTEGER  REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_active ON firewall_rules(is_active);

-- ─── Web Statistics ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS web_stats_configs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER  NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    domain      TEXT     NOT NULL,
    tool        TEXT     NOT NULL CHECK(tool IN ('Webalizer', 'GoAccess', 'AwStats')),
    enabled     BOOLEAN  NOT NULL DEFAULT TRUE,
    output_dir  TEXT     NOT NULL,
    last_run_at DATETIME,
    last_status TEXT     CHECK(last_status IN ('Success', 'Failed', 'Running')),
    last_error  TEXT,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(site_id, tool)
);

CREATE INDEX IF NOT EXISTS idx_web_stats_site_id ON web_stats_configs(site_id);

-- ─── Backups ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS backup_schedules (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    owner_id        INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Exactly one of site_id / mailbox_id must be set
    site_id         INTEGER  REFERENCES sites(id) ON DELETE CASCADE,
    mailbox_id      INTEGER  REFERENCES mailboxes(id) ON DELETE CASCADE,
    name            TEXT     NOT NULL,
    schedule        TEXT     NOT NULL DEFAULT '@daily',
    storage_type    TEXT     NOT NULL DEFAULT 'local',
    destination     TEXT     NOT NULL DEFAULT '/var/backups/panel',
    retention_count INTEGER  NOT NULL DEFAULT 7,
    compress        INTEGER  NOT NULL DEFAULT 1,
    enabled         INTEGER  NOT NULL DEFAULT 1,
    last_run        DATETIME,
    next_run        DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((site_id IS NOT NULL) != (mailbox_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS backup_runs (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    schedule_id   INTEGER  NOT NULL REFERENCES backup_schedules(id) ON DELETE CASCADE,
    owner_id      INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    started_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   DATETIME,
    status        TEXT     NOT NULL DEFAULT 'running',  -- 'running' | 'success' | 'failed'
    size_bytes    INTEGER,
    archive_path  TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_schedules_owner ON backup_schedules(owner_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_site  ON backup_schedules(site_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_mail  ON backup_schedules(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_schedule   ON backup_runs(schedule_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_owner      ON backup_runs(owner_id);

-- ─── Team / Developer Access ─────────────────────────────────────────────────
-- One-time invitation tokens (raw token shown once; only SHA-256 hash stored)
CREATE TABLE IF NOT EXISTS team_invitations (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    client_id   INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT     NOT NULL,
    token_hash  TEXT     NOT NULL UNIQUE,
    site_ids    TEXT     NOT NULL DEFAULT '[]',  -- JSON array of site IDs
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS team_site_access (
    developer_id INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id      INTEGER  NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    granted_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (developer_id, site_id)
);

CREATE INDEX IF NOT EXISTS idx_team_inv_client   ON team_invitations(client_id);
CREATE INDEX IF NOT EXISTS idx_team_inv_token    ON team_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_team_access_dev   ON team_site_access(developer_id);
CREATE INDEX IF NOT EXISTS idx_team_access_site  ON team_site_access(site_id);

-- ─── HTTP Basic Auth Users ───────────────────────────────────────────────────
-- APR1-MD5 ($apr1$…) or bcrypt ($2y$…) hashes in Apache htpasswd format.
CREATE TABLE IF NOT EXISTS basic_auth_users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER  NOT NULL,
    username      TEXT     NOT NULL,
    password_hash TEXT     NOT NULL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE,
    UNIQUE(site_id, username)
);

CREATE INDEX IF NOT EXISTS idx_basic_auth_users_site_id ON basic_auth_users(site_id);

-- ─── Background Tasks ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS background_tasks (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    name         TEXT     NOT NULL,
    status       TEXT     NOT NULL DEFAULT 'Pending',
    log_output   TEXT,
    triggered_by INTEGER  REFERENCES users(id) ON DELETE SET NULL,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    completed_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_background_tasks_status     ON background_tasks(status);
CREATE INDEX IF NOT EXISTS idx_background_tasks_created_at ON background_tasks(created_at DESC);

-- ─── Used TOTP Codes ─────────────────────────────────────────────────────────
-- Persists used TOTP codes across process restarts to prevent replay attacks.
-- Rows are pruned during maintenance once older than the validity window (~90 s).
CREATE TABLE IF NOT EXISTS used_totp_codes (
    code_key TEXT PRIMARY KEY,
    used_at  TEXT NOT NULL  -- RFC-3339 UTC timestamp
);

CREATE INDEX IF NOT EXISTS idx_used_totp_codes_used_at ON used_totp_codes (used_at);
