-- FTP virtual account table (Pure-FTPd puredb backend)
CREATE TABLE IF NOT EXISTS ftp_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    -- Argon2id hash stored by the panel (also written to puredb)
    password_hash TEXT NOT NULL,
    home_dir TEXT NOT NULL,
    quota_size_mb INTEGER DEFAULT 1024,
    quota_files INTEGER DEFAULT 0,
    -- Allowed IP CIDR/range (NULL = unrestricted)
    allowed_ip TEXT,
    status TEXT NOT NULL CHECK(status IN ('Active', 'Suspended')) DEFAULT 'Active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ftp_accounts_owner ON ftp_accounts(owner_id);
CREATE INDEX IF NOT EXISTS idx_ftp_accounts_site  ON ftp_accounts(site_id);
