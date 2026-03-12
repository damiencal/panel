-- Backup schedules: configures automated per-domain and per-mailuser backups.
CREATE TABLE IF NOT EXISTS backup_schedules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Mutually exclusive: either a site backup or a mail-user backup.
    site_id         INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    mailbox_id      INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,
    -- Human-readable name for the schedule.
    name            TEXT    NOT NULL,
    -- 5-field cron expression or @daily / @weekly / @monthly.
    schedule        TEXT    NOT NULL DEFAULT '@daily',
    -- Where to store the archive: 'local' | 's3' | 'sftp'
    storage_type    TEXT    NOT NULL DEFAULT 'local',
    -- Destination path / bucket prefix / remote path.
    destination     TEXT    NOT NULL DEFAULT '/var/backups/panel',
    -- How many snapshots to keep before rotating (0 = unlimited).
    retention_count INTEGER NOT NULL DEFAULT 7,
    -- Whether gzip compression is applied to the archive.
    compress        INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_run        DATETIME,
    next_run        DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Exactly one of site_id / mailbox_id must be set.
    CHECK ((site_id IS NOT NULL) != (mailbox_id IS NOT NULL))
);

-- Backup run records (one row per executed backup).
CREATE TABLE IF NOT EXISTS backup_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id     INTEGER NOT NULL REFERENCES backup_schedules(id) ON DELETE CASCADE,
    owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     DATETIME,
    -- 'running' | 'success' | 'failed'
    status          TEXT    NOT NULL DEFAULT 'running',
    -- Size of the produced archive in bytes (NULL while running or on failure).
    size_bytes      INTEGER,
    -- Path / URL to the archive file.
    archive_path    TEXT,
    -- Human-readable error message on failure.
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_schedules_owner ON backup_schedules(owner_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_site  ON backup_schedules(site_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_mail  ON backup_schedules(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_schedule   ON backup_runs(schedule_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_owner      ON backup_runs(owner_id);
