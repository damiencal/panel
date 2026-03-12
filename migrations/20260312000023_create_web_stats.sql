-- Web statistics configuration per hosted domain.
-- Tracks which stats tools (Webalizer, GoAccess, AWStats) are enabled
-- for each site and records the last execution result.

CREATE TABLE IF NOT EXISTS web_stats_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    domain          TEXT    NOT NULL,
    tool            TEXT    NOT NULL CHECK (tool IN ('Webalizer', 'GoAccess', 'AwStats')),
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    output_dir      TEXT    NOT NULL,
    last_run_at     DATETIME,
    last_status     TEXT    CHECK (last_status IN ('Success', 'Failed', 'Running')),
    last_error      TEXT,
    created_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at      DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE (site_id, tool)
);

CREATE INDEX IF NOT EXISTS idx_web_stats_site_id ON web_stats_configs (site_id);
