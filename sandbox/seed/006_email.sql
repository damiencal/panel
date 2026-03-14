-- =============================================================================
-- 006_email.sql — Seed email domains, mailboxes, forwarders, DKIM keys
-- Depends on: 001_users.sql (client id=3)
-- Mailbox password hashes are replaced by seed-panel.sh at runtime.
-- =============================================================================

INSERT OR IGNORE INTO email_domains
    (id, owner_id, domain, status)
VALUES
(1, 3, 'panel.test',    'Active'),
(2, 3, 'wp.panel.test', 'Active');

-- seed-panel.sh replaces __MAILBOX_HASH__ with argon2id hash of 'MailPass123!'
-- and writes these INSERT statements dynamically.
-- This file is kept as documentation; actual inserts are emitted by seed-panel.sh.

-- email_forwarders
INSERT OR IGNORE INTO email_forwarders
    (id, domain_id, local_part, forward_to, status)
VALUES
(1, 1, 'info',    'admin@panel.test',  'Active'),
(2, 1, 'support', 'admin@panel.test',  'Active');
