-- Background task tracking: stores queued/running/completed operations
-- so users and admins can follow exactly what happened (SSL issuance,
-- git pulls, janitor runs, etc.) instead of getting opaque "failed" errors.

CREATE TABLE IF NOT EXISTS background_tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'Pending',
    log_output   TEXT,
    triggered_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    completed_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_background_tasks_status
    ON background_tasks (status);

CREATE INDEX IF NOT EXISTS idx_background_tasks_created_at
    ON background_tasks (created_at DESC);
