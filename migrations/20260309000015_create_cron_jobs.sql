-- Cron job table: per-site scheduled task management.
-- Each job is owned by a user, scoped to a site, and installed into the
-- site's system-user crontab when enabled.
CREATE TABLE IF NOT EXISTS cron_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    site_id     INTEGER NOT NULL REFERENCES sites(id)  ON DELETE CASCADE,
    -- Standard 5-field cron expression (e.g. "*/5 * * * *") or @alias
    schedule    TEXT    NOT NULL,
    -- Command to execute (no newlines; runs as the site's system user)
    command     TEXT    NOT NULL,
    -- Human-readable label
    description TEXT    NOT NULL DEFAULT '',
    -- 1 = active, 0 = disabled
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_run    DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cron_jobs_owner ON cron_jobs(owner_id);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_site  ON cron_jobs(site_id);
