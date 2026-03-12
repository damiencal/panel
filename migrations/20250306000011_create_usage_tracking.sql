-- Create usage tracking table for bandwidth and storage
CREATE TABLE IF NOT EXISTS usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    site_id INTEGER,
    metric_type TEXT NOT NULL CHECK(metric_type IN ('Bandwidth', 'Storage', 'CPU', 'Memory')),
    value_mb INTEGER NOT NULL DEFAULT 0,
    recorded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE SET NULL
);

-- Daily aggregated usage (for reports)
CREATE TABLE IF NOT EXISTS daily_usage_aggregates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date DATE NOT NULL,
    bandwidth_used_mb INTEGER DEFAULT 0,
    storage_used_mb INTEGER DEFAULT 0,
    UNIQUE(user_id, date),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Monthly usage snapshots (for billing)
CREATE TABLE IF NOT EXISTS monthly_usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    year INTEGER NOT NULL,
    month INTEGER NOT NULL,
    bandwidth_used_mb INTEGER DEFAULT 0,
    storage_peak_mb INTEGER DEFAULT 0,
    UNIQUE(user_id, year, month),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_id ON usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_logs_recorded_at ON usage_logs(recorded_at);
CREATE INDEX IF NOT EXISTS idx_daily_aggregates_date ON daily_usage_aggregates(date);
CREATE INDEX IF NOT EXISTS idx_monthly_snapshots_month ON monthly_usage_snapshots(year, month);
