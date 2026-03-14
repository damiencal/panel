-- =============================================================================
-- 002_packages.sql — Seed hosting packages
-- Depends on: 001_users.sql (admin id=1, reseller id=2)
-- =============================================================================

INSERT OR IGNORE INTO packages
    (id, name, description, created_by,
     max_sites, max_databases, max_email_accounts, max_ftp_accounts,
     disk_limit_mb, bandwidth_limit_mb,
     max_subdomains, max_addon_domains,
     php_enabled, ssl_enabled, shell_access, backup_enabled, is_active)
VALUES
-- Admin-owned packages available to resellers
(1, 'Basic',    'Basic shared hosting plan',    1,  2,  2, 20,  2, 10240,  102400, 2, 1, 1, 1, 0, 1, 1),
(2, 'Pro',      'Professional hosting plan',    1,  5,  5, 50,  5, 51200,  512000, 5, 3, 1, 1, 0, 1, 1),
(3, 'Business', 'Business-class hosting plan',  1, 20, 20,200, 20,204800, 2048000,20,10, 1, 1, 1, 1, 1),

-- Reseller-created packages for their clients
(4, 'Starter',  'Reseller starter plan',        2,  1,  1, 10,  1,  5120,   51200, 1, 0, 1, 1, 0, 1, 1),
(5, 'Growth',   'Reseller growth plan',         2,  3,  3, 30,  3, 20480,  204800, 3, 2, 1, 1, 0, 1, 1);
