-- =============================================================================
-- 015_audit_log.sql — Seed recent audit log entries
-- =============================================================================

-- Only insert if audit_log table exists (it may have a different name)
INSERT OR IGNORE INTO audit_log
    (user_id, action, target_type, target_id, details, ip_address, created_at)
VALUES
(1, 'login',           'user',     1, '{"method":"password"}',              '127.0.0.1', datetime('now', '-2 hours')),
(3, 'login',           'user',     3, '{"method":"password"}',              '127.0.0.1', datetime('now', '-1 hour')),
(3, 'site_created',    'site',     1, '{"domain":"wp.panel.test"}',         '127.0.0.1', datetime('now', '-1 hour', '+5 minutes')),
(3, 'dns_record_added','dns_record',7,'{"type":"A","name":"@","value":"127.0.0.1"}','127.0.0.1', datetime('now', '-50 minutes')),
(1, 'user_suspended',  'user',     4, '{"reason":"test suspension"}',       '127.0.0.1', datetime('now', '-30 minutes')),
(1, 'user_activated',  'user',     4, '{"reason":"test restore"}',          '127.0.0.1', datetime('now', '-29 minutes')),
(3, 'ftp_created',     'ftp',      1, '{"username":"client_ftp"}',          '127.0.0.1', datetime('now', '-20 minutes')),
(3, 'backup_run',      'backup',   1, '{"status":"success","bytes":52428800}','127.0.0.1', datetime('now', '-10 minutes'));
