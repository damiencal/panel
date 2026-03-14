-- =============================================================================
-- 010_firewall.sql — Seed UFW firewall rule records
-- Depends on: 001_users.sql (admin id=1)
-- =============================================================================

INSERT OR IGNORE INTO firewall_rules
    (id, rule_number, action, direction, protocol, from_ip, to_port, comment, is_active, created_by)
VALUES
(1, 21, 'allow', 'in', 'tcp', NULL,         '22',   'SSH',               1, 1),
(2, 22, 'allow', 'in', 'tcp', NULL,         '80',   'HTTP',              1, 1),
(3, 23, 'allow', 'in', 'tcp', NULL,         '443',  'HTTPS',             1, 1),
(4, 24, 'allow', 'in', 'tcp', NULL,         '8080', 'Panel UI',          1, 1),
(5, 25, 'allow', 'in', 'tcp', NULL,         '25',   'SMTP',              1, 1),
(6, 26, 'allow', 'in', 'tcp', NULL,         '993',  'IMAPS',             1, 1),
(7, 27, 'allow', 'in', 'tcp', NULL,         '21',   'FTP',               1, 1),
(8, 28, 'allow', 'in', 'tcp', '10.0.0.0/8', NULL,  'Internal network',  1, 1),
(9, 29, 'deny',  'in', 'tcp', NULL,         '8888', 'Block test port',   1, 1);
