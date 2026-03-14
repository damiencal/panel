-- =============================================================================
-- 011_tickets.sql — Seed support tickets
-- Depends on: 001_users.sql (admin id=1, reseller id=2, client id=3)
-- =============================================================================

INSERT OR IGNORE INTO support_tickets
    (id, subject,                           status,       priority, department, created_by, assigned_to)
VALUES
(1, 'How do I add a subdomain?',           'Open',        'Low',      'General',     3, 1),
(2, 'SSL certificate not renewing',        'Answered',    'High',     'Technical',   3, 1),
(3, 'Request: increase disk quota',        'Closed',      'Medium',   'Billing',     3, 1),
(4, 'Reseller billing question',           'Open',        'Medium',   'Billing',     2, 1),
(5, 'Critical: database connection error', 'ClientReply', 'Critical', 'Technical',   3, 1);

INSERT OR IGNORE INTO ticket_messages
    (id, ticket_id, sender_id, body, is_internal)
VALUES
(1,  1, 3, 'I need to add a subdomain blog.wp.panel.test. How do I do this in the panel?', 0),
(2,  1, 1, 'Go to DNS → Add Record → Type: CNAME, Name: blog, Value: your domain.', 0),
(3,  2, 3, 'My SSL cert shows as expired in the panel but certbot says it is valid.', 0),
(4,  2, 1, 'Please run: certbot renew --force-renewal. I have initiated a renewal from the admin panel.', 0),
(5,  2, 3, 'Thank you, the renewal worked!', 0),
(6,  3, 3, 'Please double my disk quota. I need more space for media uploads.', 0),
(7,  3, 1, 'Quota upgraded to 20 GB. Ticket closed.', 0),
(8,  4, 2, 'Am I billed per client or per plan?', 0),
(9,  5, 3, 'My WordPress site is showing DB connection errors since 2 AM.', 0),
(10, 5, 1, 'MariaDB was restarted due to OOM. Site is back online. Investigating.', 0),
(11, 5, 3, 'Site is back! Please let me know when the investigation is complete.', 0);
