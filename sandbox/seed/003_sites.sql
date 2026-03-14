-- =============================================================================
-- 003_sites.sql — Seed test websites
-- Depends on: 001_users.sql (client id=3)
-- =============================================================================

INSERT OR IGNORE INTO sites
    (id, owner_id, domain, doc_root, site_type, status,
     ssl_enabled, ssl_issuer,
     php_version, php_handler,
     ols_vhost_name, ols_listener_ports, max_connections)
VALUES
-- Primary WordPress site owned by client
(1, 3, 'wp.panel.test',
    '/var/www/wp.panel.test',
    'PHP', 'Active',
    0, NULL,
    '8.3', 'lsphp83',
    'wp.panel.test', '80,443', 100),

-- Static site for SSL / HTTPS tests
(2, 3, 'static.panel.test',
    '/var/www/static.panel.test',
    'Static', 'Active',
    1, 'Self-Signed',
    NULL, NULL,
    'static.panel.test', '80,443', 50),

-- PHP site owned by reseller (admin scenario: see all sites)
(3, 2, 'reseller-site.panel.test',
    '/var/www/reseller-site.panel.test',
    'PHP', 'Active',
    0, NULL,
    '8.3', 'lsphp83',
    'reseller-site.panel.test', '80,443', 50);

-- Create the document roots so the file-manager tests have a real directory
-- (executed by seed-panel.sh, not here — directories need shell commands)
