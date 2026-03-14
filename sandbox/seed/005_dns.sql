-- =============================================================================
-- 005_dns.sql — Seed DNS zones and records
-- Depends on: 001_users.sql (client id=3, reseller id=2)
-- sync_status=Synced but cf_zone_id is blank → panel skips live CF API calls
-- =============================================================================

INSERT OR IGNORE INTO dns_zones
    (id, owner_id, domain, zone_type, status, nameserver1, nameserver2, cf_zone_id, sync_status)
VALUES
(1, 3, 'panel.test',          'Primary', 'Active', 'ns1.panel.test', 'ns2.panel.test', NULL, 'Synced'),
(2, 3, 'wp.panel.test',       'Primary', 'Active', 'ns1.panel.test', 'ns2.panel.test', NULL, 'Synced'),
(3, 2, 'reseller.panel.test', 'Primary', 'Active', 'ns1.panel.test', 'ns2.panel.test', NULL, 'Synced');

INSERT OR IGNORE INTO dns_records
    (id, zone_id, name, type, value, priority, ttl)
VALUES
-- panel.test
(1,  1, '@',          'A',   '127.0.0.1',          10,  300),
(2,  1, 'www',        'A',   '127.0.0.1',          10,  300),
(3,  1, '@',          'MX',  'mail.panel.test',    10, 3600),
(4,  1, '@',          'TXT', 'v=spf1 mx ~all',     10, 3600),
(5,  1, 'ns1',        'A',   '127.0.0.1',          10, 3600),
(6,  1, 'ns2',        'A',   '127.0.0.1',          10, 3600),
-- wp.panel.test
(7,  2, '@',          'A',   '127.0.0.1',          10,  300),
(8,  2, 'www',        'CNAME','wp.panel.test',      10, 3600),
-- reseller.panel.test
(9,  3, '@',          'A',   '127.0.0.1',          10,  300);
