-- =============================================================================
-- 014_backups.sql — Seed backup schedule + completed run records
-- Depends on: 001_users.sql (client id=3), 003_sites.sql (site id=1)
-- =============================================================================

INSERT OR IGNORE INTO backup_schedules
    (id, owner_id, site_id, mailbox_id, name, schedule,
     storage_type, destination, retention_count, compress, enabled,
     last_run, next_run)
VALUES
(1, 3, 1, NULL,
    'WP Daily Backup', '@daily',
    'local', '/var/backups/panel', 7, 1, 1,
    datetime('now', '-1 day'),
    datetime('now', '+23 hours'));

INSERT OR IGNORE INTO backup_runs
    (id, schedule_id, owner_id, started_at, finished_at, status, size_bytes, archive_path)
VALUES
(1, 1, 3,
    datetime('now', '-1 day', '-5 minutes'),
    datetime('now', '-1 day'),
    'success', 52428800,
    '/var/backups/panel/wp.panel.test_20260312_030000.tar.gz'),
(2, 1, 3,
    datetime('now', '-2 days', '-5 minutes'),
    datetime('now', '-2 days'),
    'success', 51200000,
    '/var/backups/panel/wp.panel.test_20260311_030000.tar.gz'),
(3, 1, 3,
    datetime('now', '-3 days', '-5 minutes'),
    datetime('now', '-3 days'),
    'failed', NULL,
    NULL);
