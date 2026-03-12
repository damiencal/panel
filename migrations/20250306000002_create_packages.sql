-- Create hosting packages table
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_by INTEGER NOT NULL,
    max_sites INTEGER NOT NULL DEFAULT 1,
    max_databases INTEGER NOT NULL DEFAULT 1,
    max_email_accounts INTEGER NOT NULL DEFAULT 10,
    max_ftp_accounts INTEGER NOT NULL DEFAULT 1,
    disk_limit_mb INTEGER NOT NULL DEFAULT 10240,
    bandwidth_limit_mb INTEGER NOT NULL DEFAULT 102400,
    max_subdomains INTEGER NOT NULL DEFAULT 0,
    max_addon_domains INTEGER NOT NULL DEFAULT 0,
    php_enabled BOOLEAN DEFAULT TRUE,
    ssl_enabled BOOLEAN DEFAULT TRUE,
    shell_access BOOLEAN DEFAULT FALSE,
    backup_enabled BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packages_created_by ON packages(created_by);
CREATE INDEX IF NOT EXISTS idx_packages_active ON packages(is_active);
