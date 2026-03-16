-- =============================================================================
-- 008_cron.sql — Seed cron jobs
-- Depends on: 001_users.sql (client id=3), 003_sites.sql (site id=1)
-- =============================================================================

INSERT OR IGNORE INTO cron_jobs
    (id, owner_id, site_id, schedule, command, description, enabled)
VALUES
(1, 3, 1, '*/5 * * * *',  'php /var/www/wp.panel.test/wp-cron.php', 'WordPress Cron',      1),
(2, 3, 1, '0 3 * * *',    '/usr/bin/find /tmp -name "sess_*" -mtime +1 -delete',
                                                                      'Clean PHP sessions',   1),
(3, 3, 1, '@weekly',       'wp --path=/var/www/wp.panel.test db optimize', 'WP DB optimize', 0);
