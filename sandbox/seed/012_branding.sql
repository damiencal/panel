-- =============================================================================
-- 012_branding.sql — Seed reseller branding
-- Depends on: 001_users.sql (reseller id=2)
-- =============================================================================

INSERT OR IGNORE INTO reseller_branding
    (id, reseller_id, panel_name, logo_path, accent_color, custom_domain, footer_text)
VALUES
(1, 2,
    'MyHost Control Panel',
    '/assets/sandbox-logo.png',
    '#6366F1',
    'panel.myhost.test',
    '© 2026 MyHost. Powered by web.com.do');

-- Also set branding_id on the reseller user so the panel loads it
UPDATE users SET branding_id = 1 WHERE id = 2;
