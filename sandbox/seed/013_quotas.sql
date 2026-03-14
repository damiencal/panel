-- =============================================================================
-- 013_quotas.sql — Seed resource quotas and initial usage tracking
-- Depends on: 001_users.sql (client id=3)
-- =============================================================================

INSERT OR IGNORE INTO resource_quotas
    (user_id, max_sites, max_databases, max_email_accounts,
     max_ftp_accounts, disk_limit_mb, bandwidth_limit_mb)
VALUES
-- Admin: unlimited (very high limits)
(1, 9999, 9999, 9999, 9999, 10485760, 104857600),
-- Reseller: Pro-level
(2,   20,   20,  200,   20,   204800,  2048000),
-- Client: Basic package limits
(3,    2,    2,   20,    2,    10240,   102400);

INSERT OR IGNORE INTO resource_usage
    (user_id, sites_count, databases_count, email_accounts_count,
     ftp_accounts_count, disk_used_mb, bandwidth_used_mb)
VALUES
(1, 0, 0, 0, 0, 0, 0),
(2, 1, 0, 0, 0, 128, 10240),
(3, 2, 2, 1, 1, 512, 25600);
