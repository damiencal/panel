-- Create resource quotas table
CREATE TABLE IF NOT EXISTS resource_quotas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    max_clients INTEGER,
    max_sites INTEGER NOT NULL DEFAULT 10,
    max_databases INTEGER NOT NULL DEFAULT 5,
    max_email_accounts INTEGER NOT NULL DEFAULT 100,
    disk_limit_mb INTEGER NOT NULL DEFAULT 102400,
    bandwidth_limit_mb INTEGER NOT NULL DEFAULT 1048576,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create resource usage tracking table
CREATE TABLE IF NOT EXISTS resource_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sites_used INTEGER DEFAULT 0,
    databases_used INTEGER DEFAULT 0,
    email_accounts_used INTEGER DEFAULT 0,
    disk_used_mb INTEGER DEFAULT 0,
    bandwidth_used_mb INTEGER DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_resource_usage_user_id ON resource_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_resource_quotas_user_id ON resource_quotas(user_id);
