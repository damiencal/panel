-- =============================================================================
-- 004_databases.sql — Seed test MariaDB database records
-- Depends on: 001_users.sql (client id=3), 003_sites.sql (site id=1)
-- Note: actual MariaDB databases are created by seed-panel.sh shell commands.
-- =============================================================================

INSERT OR IGNORE INTO databases
    (id, owner_id, name, database_type, status)
VALUES
(1, 3, 'client_wp', 'MySQL', 'Active'),
(2, 3, 'client_dev', 'MySQL', 'Active');

INSERT OR IGNORE INTO database_users
    (id, database_id, username, password_hash, privileges)
VALUES
-- password: 'DBPass123!' — stored as plain text for MariaDB GRANT
-- The actual MariaDB user is created by seed-panel.sh
(1, 1, 'client_wp_user',  'DBPass123!', 'ALL'),
(2, 2, 'client_dev_user', 'DBPass123!', 'SELECT,INSERT,UPDATE,DELETE');
